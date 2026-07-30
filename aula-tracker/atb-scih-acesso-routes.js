// atb-scih-acesso-routes.js
// Gestão de acesso da equipe do SCIH, reaproveitando a tabela access_requests.
// Fluxo: enfermeira pede acesso em /scih/solicitar -> super admin aprova em
// /atb/admin/scih -> sistema gera um link de ativação (token de uso único) ->
// a pessoa define a PRÓPRIA senha em /definir-senha?token=...
//
// Registrar em atb-routes.js (o 3º arg já é o scihRequired vindo do app.js):
//   import { registerScihAcessoRoutes, ensureScihAcessoSchema } from './atb-scih-acesso-routes.js';
//   ensureScihAcessoSchema(pool).catch(e => console.error('[atb] ensureScihAcessoSchema:', e.message));
//   registerScihAcessoRoutes(app, pool, adminRequired);   // adminRequired aqui = scihRequired

import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { tenantMode, tenantFromReq } from './atb-tenant.js';
import { MODULOS, SOLICITAVEIS, moduloPorChave } from './acesso-modulos.js';
import { sendAcessoAprovadoEmail, mailerConfigurado } from './mailer.js';

const TOKEN_TTL_DIAS = 7;

const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

// Página leve, fiel à paleta do app (claro, azul institucional #0c447c)
function page(title, body) {
  return `<!doctype html><html lang="pt-br"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${esc(title)}</title>
<style>
  :root{--bg:#f4f6f9;--card:#fff;--txt:#1b2330;--mut:#5b6472;--pri:#0c447c;--bd:#e0e2e6}
  *{box-sizing:border-box} body{margin:0;font-family:system-ui,Segoe UI,Arial;background:var(--bg);color:var(--txt)}
  .wrap{max-width:880px;margin:40px auto;padding:0 16px}
  .card{background:var(--card);border:1px solid var(--bd);border-radius:16px;padding:24px;box-shadow:0 1px 3px rgba(16,24,40,.06),0 6px 18px rgba(16,24,40,.05);margin-bottom:16px}
  h1{font-size:22px;margin:0 0 4px} h2{font-size:16px;margin:0 0 12px}
  label{display:block;margin:10px 0 4px;font-size:14px}
  input{width:100%;padding:12px;border-radius:10px;border:1px solid #cdd3db;background:#fff;color:var(--txt);font-size:14px}
  input:focus{outline:none;border-color:var(--pri);box-shadow:0 0 0 3px rgba(12,68,124,.12)}
  button{background:var(--pri);color:#fff;border:0;border-radius:12px;padding:11px 16px;cursor:pointer;font-weight:600;font-size:14px}
  button.ghost{background:#fff;color:var(--pri);border:1px solid var(--bd)}
  button.danger{background:#fff;color:#8a1414;border:1px solid #f0c0c0}
  a{color:var(--pri)} .mut{color:var(--mut)} .mt{margin-top:14px}
  table{width:100%;border-collapse:collapse;font-size:14px} th,td{padding:9px 8px;border-bottom:1px solid var(--bd);text-align:left;vertical-align:middle}
  th{font-size:12px;text-transform:uppercase;letter-spacing:.03em;color:var(--mut)}
  .pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600}
  .pill.on{background:#e6f1fb;color:#0c447c} .pill.off{background:#f1efe8;color:#5f5e5a}
  form.inline{display:inline} .row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
  .linkbox{background:#f4f6f9;border:1px dashed #b5c6dc;border-radius:10px;padding:12px;word-break:break-all;font-size:13px}
  .hub{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:12px}
  .hubcard{display:flex;align-items:center;gap:10px;padding:16px;border:1px solid var(--bd);border-radius:12px;background:#fff;color:var(--pri);font-weight:600;font-size:14px;text-decoration:none}
  .hubcard:hover{background:#f4f6f9}
  .hubcard.soon{color:#8a93a3;cursor:default;border-style:dashed}
  .hubcard.soon:hover{background:#fff}
  .sec{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--mut);margin:18px 0 8px;font-weight:600}
  .sec.op{border-left:3px solid #85B7EB;padding-left:10px}
  .sec.vig{border-left:3px solid #5DCAA5;padding-left:10px}
  .sec.cfg{border-left:3px solid #EF9F27;padding-left:10px}
  .sec.man{border-left:3px solid #B4B2A9;padding-left:10px}
  .tag{margin-left:auto;font-size:11px;background:#f1efe8;color:#5f5e5a;border-radius:999px;padding:2px 8px;font-weight:600}
  .ext{margin-left:auto;font-size:13px;color:#8a93a3}
</style></head><body><div class="wrap">${body}</div></body></html>`;
}

export async function ensureScihAcessoSchema(pool) {
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS pront BOOLEAN DEFAULT false`);
  await pool.query(`ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS kind TEXT DEFAULT 'curso'`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS set_pw_token TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS set_pw_expires TIMESTAMPTZ`);
  await pool.query(`CREATE INDEX IF NOT EXISTS users_set_pw_token_idx ON users(set_pw_token)`);
  // Fase 3: vínculo de instituição. Usuários SCIH/micro atuais → HUSF (operam o
  // portal do HUSF idêntico a hoje). super_admin fica sem vínculo (cruza tudo).
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS instituicao TEXT`);
  await pool.query(`UPDATE users SET instituicao='HUSF'
                     WHERE instituicao IS NULL AND (scih=true OR micro=true)`);
  await pool.query(`ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS instituicao TEXT`);
  // dados adicionais pedidos por módulo (ver campos[] em acesso-modulos.js)
  await pool.query(`ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS dados JSONB`);
  // quando o e-mail com o link de senha saiu (nulo = não saiu)
  await pool.query(`ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS email_enviado_at TIMESTAMPTZ`);
}

function novoToken() { return crypto.randomBytes(24).toString('hex'); }
function baseUrl(req) { return `${req.protocol}://${req.get('host')}`; }

export function registerScihAcessoRoutes(app, pool, scihRequired) {
  // gate: precisa estar logado como super_admin (ou break-glass via cookie adm)
  const ensureSuper = (req, res, next) => {
    const isSuper = (req.user && req.user.super_admin) || req.cookies?.adm === '1';
    if (!isSuper) return res.status(403).send(page('Sem acesso',
      `<div class="card"><h1>Acesso restrito</h1><p class="mut">Apenas o super admin gerencia os acessos do SCIH.</p><a href="/inicio">Início</a></div>`));
    next();
  };
  const adminSuper = [scihRequired, ensureSuper];

  // ───────────────────────── portal pessoal (super admin) ─────────────────
  // Relatórios de vigilância publicados no GitHub Pages (repo vigilancia_husf).
  // Para mudar a base é só editar VIG.
  const VIG = 'https://doutorleandromendes.github.io/vigilancia_husf';
  app.get('/scih', adminSuper, async (req, res) => {
    const nome = (req.user && req.user.full_name) || 'Dr. Leandro';
    // O 6º parâmetro (kw) são palavras-chave/sinônimos para a busca do portal.
    // O texto buscável (label + kw, sem acento, minúsculo) vai em data-busca.
    const _semAcento = (t) => String(t || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
    const card = (href, icon, label, ext, badge, kw) => {
      const busca = _semAcento(String(label).replace(/&amp;/g, 'e') + ' ' + (kw || ''));
      return `<a class="hubcard" href="${href}" data-busca="${busca}"${ext ? ' target="_blank" rel="noopener"' : ''}>${icon} ${label}${
        badge ? ` <span style="background:#e85d5d;color:#fff;border-radius:9px;padding:1px 7px;font-size:11px;font-weight:700;margin-left:4px">${badge}</span>` : ''
      }${ext ? ' <span class="ext">↗</span>' : ''}</a>`;
    };

    // Contadores ao vivo do ISC. Um portal diário sem número é só lista de links.
    // Nunca deixa o portal cair por causa disto: se a query falhar, os cards vão
    // sem badge (o módulo pode nem estar migrado ainda no primeiro boot).
    const sigISC = tenantFromReq(req);
    let iscVenc = 0, iscTriagem = 0, iscOk = true;
    try {
      const { rows } = await pool.query(`
        SELECT
          count(*) FILTER (WHERE f.status_vigilancia = 'em_vigilancia'
                             AND f.proximo_contato_em <= CURRENT_DATE)::int AS vencidos,
          count(*) FILTER (WHERE f.tem_alerta AND f.isc_classificacao = 'nao_avaliada')::int AS triagem
          FROM isc_fichas f
          LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
         WHERE ($1::text IS NULL OR i.sigla = $1)`, [sigISC || null]);
      iscVenc = rows[0]?.vencidos || 0;
      iscTriagem = rows[0]?.triagem || 0;
    } catch (e) { iscOk = false; }

    // Triagens de IA aguardando julgamento (narrativa sinalizada, sem revisão).
    // Tenant-aware: checagens gravam a sigla em `inst`, legado NULL conta como
    // HUSF. Em try/catch — a tabela pode não existir num boot novo.
    let iaPend = 0;
    try {
      const { rows } = await pool.query(`
        SELECT count(*)::int AS n
          FROM atb_historia_checagens
         WHERE narrativa = false AND revisao IS NULL
           AND (inst = $1 OR (inst IS NULL AND $1 = 'HUSF'))`, [sigISC || 'HUSF']);
      iaPend = rows[0]?.n || 0;
    } catch { /* módulo ainda não migrado — segue sem badge */ }

    // Fase 1 do ISC é só HUSF (equipes, regras e perfil são semeados lá). Em
    // modo legado (sem tenant) também mostra. Some no SCMI até a fase 2.
    const mostrarISC = !sigISC || String(sigISC).toUpperCase() === 'HUSF';
    res.send(page('Portal do SCIH', `
      <div class="card">
        <h1>Portal do SCIH — HUSF</h1>
        <p class="mut">Olá, ${esc(nome)}. Atalhos dos sistemas do SCIH, dos relatórios de
        vigilância e da gestão de acessos.</p>
        <div style="margin-top:14px;position:relative">
          <input id="buscaPortal" type="search" autocomplete="off"
            placeholder="Buscar… (ex.: exportar, hemocultura, regras, csv, pav)"
            style="width:100%;padding:12px 14px;border:1px solid var(--bd);border-radius:12px;font-size:15px;background:#fff;box-sizing:border-box"
            oninput="filtrarPortal(this.value)">
          <div id="buscaVazia" style="display:none;color:var(--mut);font-size:13px;margin-top:8px">Nada encontrado. Tente outra palavra.</div>
        </div>
      </div>
      <div class="card">
        <div class="sec op" style="margin-top:0">Operação diária — ATB</div>
        <div class="hub">
          ${card('/grade', '📋', 'Grade de controle', false, null, 'grade tabela fichas lista pacientes controle atb prescricoes')}
          ${card('/atb/admin/ficha-retrospectiva', '➕', 'Nova ficha retrospectiva', false, null, 'retrospectiva adicionar criar ficha nova passado')}
          ${card('/consulta', '🔎', 'Consulta / Farmácia', false, null, 'consulta farmacia buscar paciente parecer dispensacao liberar')}
          ${card('/ficha', '📝', 'Formulário do prescritor', false, null, 'formulario prescritor preencher solicitar atb nova prescricao')}
        </div>

        ${mostrarISC ? `
        <div class="sec op">Vigilância pós-alta — ISC</div>
        <div class="hub">
          ${card('/isc/admin/agenda', '📞', 'Agenda de contatos', false, iscVenc || null, 'agenda contatos ligacao telefone isc pos-alta seguimento vigilancia')}
          ${card('/isc/admin/grid', '🩹', 'Grid de vigilância', false, iscTriagem || null, 'grid vigilancia isc infeccao sitio cirurgico pos-alta')}
          ${card('/isc/admin/nova', '➕', 'Nova ficha (manual)', false, null, 'isc nova ficha manual adicionar cirurgia')}
          ${card('/isc/admin/importar', '📥', 'Importar mapa cirúrgico', false, null, 'importar mapa cirurgico tasy planilha upload isc')}
        </div>` : ''}

        <div class="sec op">Bundle de prevenção — PAV</div>
        <div class="hub">
          ${card('/pav/admin/grid', '🫁', 'Grid do bundle', false, null, 'pav bundle prevencao pneumonia ventilador grid checklist')}
          ${card('/pav/m', '📱', 'Coleta à beira-leito', false, null, 'pav coleta beira leito mobile celular bundle checklist')}
        </div>

        <div class="sec vig">Indicadores &amp; consumo</div>
        <div class="hub">
          ${card('/atb/admin/adesao', '📈', 'Adesão aos pareceres', false, null, 'adesao pareceres seguimento indicador desfecho mantido suspenso')}
          ${card(VIG + '/atb_dots.html', '💊', 'Consumo de ATB (DOTs)', true, null, 'consumo dots dose atb antibiotico ddd densidade')}
          ${card('/atb/admin/pergunta', '💬', 'Pergunta ao banco (SQL)', false, null, 'pergunta sql banco query consulta dados nlq linguagem natural')}
          ${card('/atb/admin/indicadores', '📉', 'Pergunta aos indicadores', false, null, 'indicadores pergunta relatorio narrativa iras taxa')}
          ${card('/atb/admin/export', '📤', 'Exportar dados (CSV completo)', false, null, 'exportar csv completo dados planilha download admin backup')}
          ${card('/atb/export', '📄', 'Exportar resumo (prescritores & IrAS)', false, null, 'exportar csv resumo prescritores iras planilha download sumario')}
          ${card('/atb/admin/cve-painel', '📋', 'Painel CVE (IrAS & ISC)', false, null, 'cve painel iras isc notificacao especialidade procedimento peso neonatal')}
        </div>

        <div class="sec vig">Vigilância — relatórios HUSF</div>
        <div class="hub">
          ${card(VIG + '/', '🦠', 'Respiratória (SG/SRAG)', true, null, 'respiratoria sg srag gripe influenza sindrome respiratoria')}
          ${card(VIG + '/indicadores.html', '📊', 'IrAS &amp; determinantes', true, null, 'iras determinantes indicadores taxa densidade infeccao relatorio')}
          ${card(VIG + '/mdr_mensal.html', '🧫', 'MDR mensal', true, null, 'mdr multirresistente resistencia mensal relatorio kpc')}
          ${card(VIG + '/isc_v4.html', '🩹', 'ISC — histórico (JotForm)', true, null, 'isc historico jotform sitio cirurgico antigo')}
          ${card(VIG + '/micro.html', '🔬', 'Microbiologia', true, null, 'microbiologia micro cultura germe bacteria relatorio')}
          ${card(VIG + '/sciet.html', '🧭', 'Algoritmo empírico UTI', true, null, 'algoritmo empirico uti sciet antibiotico escolha terapia')}
        </div>

        <div class="sec cfg">Gestão &amp; governança</div>
        <div class="hub">
          ${card('/gov', '🏛️', 'Painel do Comitê de Governança', false, null, 'governanca gestao comite gov painel estrategico mortalidade')}
        </div>

        <div class="sec cfg">Acessos &amp; configuração</div>
        <div class="hub">
          ${card('/atb/admin/scih', '👥', 'Aprovar pedidos de acesso', false, null, 'aprovar acesso pedidos solicitacao usuarios permissao scih')}
          ${card('/admin/usuarios', '🗂️', 'Usuários e papéis', false, null, 'usuarios papeis perfil permissao acesso admin roles')}
          ${card('/atb/admin/regras', '🧠', 'Regras de triagem', false, null, 'regras triagem classificacao iras descarte automatico')}
          ${card('/atb/admin/monitoramento', '🔁', 'Regras de monitoramento', false, null, 'regras monitoramento periodico automatico cron alerta')}
          ${card('/atb/admin/form', '🧩', 'Editar opções do formulário', false, null, 'editar formulario campos opcoes form-editor atb dropdown')}
          ${card('/atb/admin/regras-form', '🔀', 'Regras do formulário', false, null, 'regras formulario visibilidade condicional obrigatorio campos')}
          ${card('/atb/admin/historia/revisao', '🤖', 'Triagens de IA — revisão', false, iaPend || null, 'triagem ia revisao narrativa isc historia telegrafica ilegivel llm')}
          ${card('/atb/admin/parecer-frases', '💬', 'Frases do Parecer', false, null, 'frases parecer texto modelo template recomendacao')}
          ${card('/acesso/solicitar', '✉️', 'Formulário público de solicitação', false, null, 'formulario publico solicitacao acesso link externo')}
          ${card('/atb/admin/config', '⚙️', 'Configurar ATB', false, null, 'configurar config atb ajustes parametros sistema')}
        </div>

        <div class="sec man">Diagnóstico &amp; manutenção</div>
        <div class="hub">
          ${card('/atb/admin/regras-check/painel', '🩺', 'Saúde do sistema', false, null, 'saude sistema diagnostico regras-check status monitoramento')}
          ${card('/atb/admin/healthcheck/painel', '🩹', 'Healthcheck do formulário', false, null, 'healthcheck formulario saude verificacao integridade')}
          ${card('/atb/admin/integridade/painel', '🛡️', 'Integridade dos dados', false, null, 'integridade dados verificacao probe jotform consistencia')}
        </div>

        <div class="sec man">Ferramentas &amp; checks</div>
        <div class="hub">
          ${card('/atb/admin/culturas', '🧫', 'Culturas — conferência', false, null, 'culturas conferencia microbiologia cultura verificar')}
          ${card('/atb/admin/hemocultura', '🩸', 'Hemoculturas', false, null, 'hemocultura sangue bacteremia alerta precoce')}
          ${card('/atb/admin/mdr', '⚠️', 'Alertas MDR', false, null, 'mdr multirresistente alerta resistencia kpc token')}
          ${card('/atb/admin/nomes/backcheck', '🔤', 'Backcheck de nomes', false, null, 'backcheck nomes pacs verificacao divergencia paciente')}
          ${card('/atb/admin/pacs-nome/teste', '🖼️', 'Teste do worker PACS', false, null, 'pacs worker teste imagem exame animati puppeteer')}
          ${card('/atb/admin/posologia/normalizar', '⚗️', 'Normalizar posologia', false, null, 'posologia normalizar dose unidade estruturar converter')}
        </div>

        <div class="sec man">Formulário — teste e promoção</div>
        <div class="hub">
          ${card('/atb/admin/form-teste', '🧪', 'Ambiente de teste', false, null, 'teste ambiente formulario sandbox experimentar')}
          ${card('/atb/admin/form-transportador', '🚚', 'Transportador (promover)', false, null, 'transportador promover publicar engine schema deploy formulario')}
        </div>
        ${mostrarISC ? `
        <div class="sec cfg">Configuração — ISC</div>
        <div class="hub">
          ${card('/isc/admin/triagem', '🔀', 'Regras de triagem (o que entra)', false, null, 'isc triagem regras entra vigilancia procedimento')}
          ${card('/isc/admin/templates', '💬', 'Mensagens do WhatsApp', false, null, 'whatsapp mensagens templates isc contato texto')}
          ${card('/isc/admin/export.csv', '📄', 'Exportar CSV', false, null, 'exportar csv isc planilha download')}
        </div>
        ${iscOk ? '' : '<p class="mut" style="font-size:12px;margin-top:8px">⚠ Não consegui ler os contadores do ISC — se acabou de subir, confira o log das migrações.</p>'}` : ''}
        ${(() => {
          // Atalhos para as OUTRAS instituições do ATB_TENANT_MAP (links absolutos,
          // pois cada tenant é um subdomínio). Inerte no modo legado/env (sem mapa).
          const { mapa } = tenantMode();
          if (!mapa) return '';
          const atual = tenantFromReq(req);
          const baseDe = (sig) => {
            const hosts = Object.keys(mapa).filter(h => mapa[h] === sig);
            const pub = hosts.find(h => !/onrender\.com$/i.test(h)) || hosts[0];
            return pub ? `https://${pub}` : null;
          };
          const outras = [...new Set(Object.values(mapa))].filter(s => s && s !== atual);
          return outras.map(sig => {
            const b = baseDe(sig);
            if (!b) return '';
            return `
        <div class="sec">Atalhos ${esc(sig)} <span class="mut" style="font-weight:400">— abre em nova aba</span></div>
        <div class="hub">
          ${card(b + '/atb/admin/grid', '📋', 'Grade de controle', true)}
          ${card(b + '/atb/admin/ficha-retrospectiva', '➕', 'Nova ficha retrospectiva', true)}
          ${card(b + '/consulta', '🔎', 'Consulta / Farmácia', true)}
          ${card(b + '/atb/admin/adesao', '📈', 'Adesão aos pareceres', true)}
          ${card(b + '/atb/admin/scih', '👥', 'Aprovar acessos', true)}
          ${card(b + '/atb/admin/regras', '🧠', 'Regras de triagem', true)}
          ${card(b + '/atb/admin/form', '🧩', 'Editar opções do formulário', true)}
          ${card(b + '/atb/admin/regras-form', '🔀', 'Regras do formulário', true)}
          ${card(b + '/atb/admin/parecer-frases', '💬', 'Frases do Parecer', true)}
          ${card(b + '/atb/admin/config', '⚙️', 'Configurar ATB', true)}
          ${card(b + '/atb/admin/regras-check/painel', '🩺', 'Saúde do sistema', true)}
        </div>`;
          }).join('');
        })()}
      </div>
      <script>
        function filtrarPortal(q){
          var termo = (q||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase().trim();
          var cards = document.querySelectorAll('.hubcard');
          for (var i=0;i<cards.length;i++){
            var busca = cards[i].getAttribute('data-busca') || '';
            cards[i].style.display = (!termo || busca.indexOf(termo) !== -1) ? '' : 'none';
          }
          // esconde seções (o .sec e o .hub) que ficaram sem nenhum card visível
          var hubs = document.querySelectorAll('.hub');
          var algum = false;
          for (var j=0;j<hubs.length;j++){
            var visiveis = hubs[j].querySelectorAll('.hubcard:not([style*="display: none"])').length;
            var sec = hubs[j].previousElementSibling;
            hubs[j].style.display = visiveis ? '' : 'none';
            if (sec && sec.classList && sec.classList.contains('sec')) sec.style.display = visiveis ? '' : 'none';
            if (visiveis) algum = true;
          }
          var vazia = document.getElementById('buscaVazia');
          if (vazia) vazia.style.display = (termo && !algum) ? '' : 'none';
        }
      </script>`));
  });

  // ───────────────────────── público: solicitar acesso (SCIH) ─────────────
  // ───────────────────── público: solicitar acesso (qualquer módulo) ────────
  // Uma página só, dirigida pelo registro em acesso-modulos.js. As rotas antigas
  // /scih/solicitar e /pront/solicitar continuam válidas: redirecionam para cá
  // com o módulo já escolhido, para não quebrar link impresso nem atalho salvo.
  const RADIO = (m, sel) => `
    <label class="opt${m.chave === sel ? ' sel' : ''}">
      <input type="radio" name="modulo" value="${esc(m.chave)}" ${m.chave === sel ? 'checked' : ''} required>
      <span class="opt-t">${esc(m.rotulo)}</span>
      <span class="opt-p">${esc(m.publico)}</span>
      <span class="opt-d">${esc(m.descricao)}</span>
    </label>`;

  // Campos que só aparecem quando o módulo correspondente está escolhido.
  const CAMPO = (m, c) => {
    const nome = `campo_${esc(m.chave)}_${esc(c.nome)}`;
    const entrada = c.tipo === 'select'
      ? `<select name="${nome}"><option value="">(selecione)</option>${
          c.opcoes.map(([v, r]) => `<option value="${esc(v)}">${esc(r)}</option>`).join('')}</select>`
      : `<input name="${nome}" placeholder="${esc(c.dica || '')}">`;
    return `<label>${esc(c.rotulo)}</label>${entrada}`;
  };

  const EXTRAS = (sel) => SOLICITAVEIS.map(m => {
    const partes = (m.campos || []).map(c => CAMPO(m, c));
    if (!partes.length) return '';
    return `<div class="extra" data-para="${esc(m.chave)}" ${m.chave === sel ? '' : 'hidden'}>${partes.join('')}</div>`;
  }).join('');

  function paginaSolicitar(sel, erro) {
    return page('Solicitar acesso', `
      <div class="card">
        <h1>Solicitar acesso</h1>
        <p class="mut">Escolha o sistema, informe seus dados e envie. O pedido é revisado
        por quem coordena aquele módulo; ao ser aprovado, você recebe um link para
        definir a própria senha.</p>
        ${erro ? `<p class="erro">${esc(erro)}</p>` : ''}
        <form method="POST" action="/acesso/solicitar" class="mt" id="frm">
          <div class="opts">${SOLICITAVEIS.map(x => RADIO(x, sel)).join('')}</div>
          <label>Nome completo</label><input name="full_name" required>
          <label>E-mail</label><input name="email" type="email" required>
          ${EXTRAS(sel)}
          <button class="mt">Enviar solicitação</button>
        </form>
        <p class="mut mt" style="border-top:1px solid var(--bd);padding-top:14px;margin-top:20px">
          Procura acesso a um curso do InfectoAulas? O pedido é outro:
          <a href="/solicitar-acesso">solicitar acesso a curso</a>.
        </p>
      </div>
      <style>
        .opts{display:grid;gap:10px;margin-bottom:18px}
        .opt{display:grid;grid-template-columns:auto 1fr;gap:2px 10px;align-items:start;
             border:1px solid var(--bd);border-radius:12px;padding:14px 16px;cursor:pointer;margin:0}
        .opt:hover{background:#f7f9fc}
        .opt.sel{border-color:var(--pri);box-shadow:0 0 0 3px rgba(12,68,124,.10)}
        .opt input{width:auto;grid-row:1/4;margin-top:3px}
        .opt-t{font-weight:600;font-size:15px}
        .opt-p{font-size:12px;color:var(--pri)}
        .opt-d{font-size:13px;color:var(--mut)}
        select{width:100%;padding:12px;border-radius:10px;border:1px solid #cdd3db;background:#fff;font-size:14px}
        .extra label:first-child{margin-top:10px}
        .erro{background:#fdeceb;border:1px solid #f0c0c0;color:#8a1414;
              border-radius:10px;padding:10px 12px;font-size:14px}
      </style>
      <script>
        var f = document.getElementById('frm');
        f.addEventListener('change', function (ev) {
          if (ev.target.name !== 'modulo') return;
          Array.prototype.forEach.call(f.querySelectorAll('.opt'), function (o) {
            o.classList.toggle('sel', o.contains(ev.target));
          });
          Array.prototype.forEach.call(f.querySelectorAll('.extra'), function (j) {
            j.hidden = j.getAttribute('data-para') !== ev.target.value;
          });
        });
      </script>`);
  }

  app.get('/acesso/solicitar', (req, res) => {
    const sel = moduloPorChave(String(req.query.m || '')) ? String(req.query.m) : null;
    res.send(paginaSolicitar(sel, null));
  });

  // compatibilidade com os endereços antigos
  app.get('/scih/solicitar',  (req, res) => res.redirect(302, '/acesso/solicitar?m=scih'));
  // O consultório não usa formulário público: o acesso é concedido diretamente.
  app.get('/pront/solicitar', (req, res) => res.send(page('Acesso ao prontuário', `
    <div class="card">
      <h1>Acesso ao prontuário</h1>
      <p class="mut">O acesso ao prontuário do consultório é concedido diretamente pelo
      Dr. Leandro, sem formulário. Fale com ele.</p>
      <p class="mut mt">Se você procurava acesso a um sistema do hospital,
      o pedido é em <a href="/acesso/solicitar">/acesso/solicitar</a>.</p>
    </div>`)));

  app.post('/acesso/solicitar', async (req, res) => {
    try {
      const mod = moduloPorChave(String(req.body?.modulo || ''));
      if (!mod) return res.status(400).send(paginaSolicitar(null, 'Escolha um sistema.'));

      const full_name = String(req.body?.full_name || '').trim();
      const email = String(req.body?.email || '').trim().toLowerCase();
      if (!full_name || !email || !email.includes('@'))
        return res.status(400).send(paginaSolicitar(mod.chave, 'Informe nome e e-mail válidos.'));

      const dom = (process.env.ALLOWED_EMAIL_DOMAIN || '').toLowerCase();
      if (mod.dominio && dom && !email.endsWith('@' + dom))
        return res.status(400).send(paginaSolicitar(mod.chave,
          `Para ${mod.rotulo}, use um endereço @${dom}.`));

      if (!mod.solicitavel)
        return res.status(400).send(paginaSolicitar(null,
          `${mod.rotulo} não aceita pedido por este formulário.`));

      // Campos adicionais do módulo. A lista vem do registro; o corpo só fornece
      // valores, nunca nomes de campo nem de coluna.
      const dados = {};
      for (const c of (mod.campos || [])) {
        const v = String(req.body?.[`campo_${mod.chave}_${c.nome}`] || '').trim();
        if (c.obrigatorio && !v)
          return res.status(400).send(paginaSolicitar(mod.chave,
            `${c.rotulo}: campo obrigatório para ${mod.rotulo}.`));
        if (c.tipo === 'select' && v && !c.opcoes.some(([op]) => op === v))
          return res.status(400).send(paginaSolicitar(mod.chave,
            `${c.rotulo}: valor inválido.`));
        if (v) dados[c.nome] = v.slice(0, 120);
      }

      // pedido pendente duplicado não gera segunda linha (resposta é a mesma,
      // para não revelar se aquele e-mail já pediu acesso)
      const dup = await pool.query(
        `SELECT 1 FROM access_requests WHERE LOWER(email)=$1 AND status='pending' AND kind=$2 LIMIT 1`,
        [email, mod.chave]);
      if (!dup.rowCount) {
        const inst = mod.vinculo ? (req.atbTenant || 'HUSF') : null;
        await pool.query(
          `INSERT INTO access_requests(full_name,email,kind,justification,status,instituicao,dados)
           VALUES ($1,$2,$3,$4,'pending',$5,$6)`,
          [full_name, email, mod.chave, mod.publico, inst,
           Object.keys(dados).length ? dados : null]);
      }

      res.send(page('Solicitação enviada', `
        <div class="card">
          <h1>Solicitação enviada</h1>
          <p>Obrigado, <strong>${esc(full_name)}</strong>. Seu pedido de acesso a
             <strong>${esc(mod.rotulo)}</strong> foi registrado.</p>
          <p class="mut">A revisão é feita pela ${esc(mod.aprovadoPor)}. Quando for aprovado,
             você recebe um link para definir a senha — ele vale ${TOKEN_TTL_DIAS} dias e
             só funciona uma vez.</p>
        </div>`));
    } catch (err) {
      console.error('[acesso] solicitar:', err);
      res.status(500).send(page('Erro',
        `<div class="card"><h1>Falha ao enviar solicitação</h1><p class="mut">${esc(err.message)}</p></div>`));
    }
  });

  app.get('/atb/admin/scih', adminSuper, async (req, res) => {
    try {
      // Uma consulta só: as filas por módulo saem do registro, não de queries copiadas.
      const pendentes = (await pool.query(
        `SELECT id, full_name, email, kind, instituicao, dados, created_at
           FROM access_requests
          WHERE status='pending' AND kind = ANY($1)
          ORDER BY created_at ASC`, [MODULOS.map(m => m.chave)])).rows;

      const usuarios = (await pool.query(
        `SELECT id, full_name, email, scih, super_admin, pront, agenda, recepcao,
                (set_pw_token IS NOT NULL AND (set_pw_expires IS NULL OR set_pw_expires > now())) AS pendente_senha
           FROM users
          WHERE scih = true OR super_admin = true OR pront = true OR agenda = true OR recepcao = true
          ORDER BY super_admin DESC, LOWER(email) ASC`)).rows;

      const blocosPendentes = MODULOS.map(m => {
        const fila = pendentes.filter(r => r.kind === m.chave);
        const linhas = fila.map(r => `
          <tr>
            <td>${esc(r.full_name)}</td>
            <td>${esc(r.email)}</td>
            <td class="mut">${(() => {
              // dados específicos do módulo (ex.: categoria e conselho no PAV)
              const d = r.dados || {};
              const partes = (m.campos || [])
                .filter(c => d[c.nome])
                .map(c => {
                  const v = c.tipo === 'select'
                    ? (c.opcoes.find(([op]) => op === d[c.nome]) || [null, d[c.nome]])[1]
                    : d[c.nome];
                  return `${esc(c.rotulo)}: ${esc(v)}`;
                });
              if (r.instituicao) partes.push(esc(r.instituicao));
              return partes.join(' · ') || '—';
            })()}</td>
            <td class="mut">${new Date(r.created_at).toLocaleDateString('pt-BR')}</td>
            <td class="row">
              <form method="POST" action="/atb/admin/acesso/aprovar/${r.id}" class="inline"><button>Aprovar</button></form>
              <form method="POST" action="/atb/admin/scih/rejeitar/${r.id}" class="inline" onsubmit="return confirm('Rejeitar este pedido?')"><button class="danger">Rejeitar</button></form>
            </td>
          </tr>`).join('') || `<tr><td colspan="5" class="mut">Nenhum pedido pendente.</td></tr>`;
        return `
        <div class="card">
          <h2>Pedidos pendentes — ${esc(m.rotulo)}${fila.length ? ` <span class="pill on">${fila.length}</span>` : ''}</h2>
          <p class="mut" style="margin:-6px 0 12px;font-size:13px">${esc(m.publico)} · aprovação pela ${esc(m.aprovadoPor)}</p>
          <table>
            <thead><tr><th>Nome</th><th>E-mail</th><th>Dados do pedido</th><th>Data</th><th>Ações</th></tr></thead>
            <tbody>${linhas}</tbody>
          </table>
        </div>`;
      }).join('');

      const linhasUsr = usuarios.map(u => `
        <tr>
          <td>${esc(u.full_name || '—')}</td>
          <td>${esc(u.email)}</td>
          <td>${u.super_admin ? '<span class="pill on">super admin</span>' : (u.scih ? '<span class="pill on">SCIH</span>' : '<span class="pill off">—</span>')}</td>
          <td>${u.super_admin ? '<span class="pill on">sempre</span>' : (u.pront ? '<span class="pill on">liberado</span>' : '<span class="pill off">—</span>')}</td>
          <td>${u.super_admin ? '<span class="pill on">sempre</span>' : (u.agenda ? '<span class="pill on">secretaria</span>' : (u.recepcao ? '<span class="pill on">recepção</span>' : '<span class="pill off">—</span>'))}</td>
          <td>${u.pendente_senha ? '<span class="pill off">aguardando definir senha</span>' : '<span class="mut">ativa</span>'}</td>
          <td class="row">
            ${u.super_admin ? '<span class="mut">protegido</span>' : `
              <form method="POST" action="/atb/admin/scih/toggle/${u.id}" class="inline"><button class="ghost">${u.scih ? 'Remover SCIH' : 'Tornar SCIH'}</button></form>
              <form method="POST" action="/atb/admin/scih/pront-toggle/${u.id}" class="inline"><button class="ghost">${u.pront ? 'Remover prontuário' : 'Liberar prontuário'}</button></form>
              <form method="POST" action="/atb/admin/scih/agenda-toggle/${u.id}" class="inline"><button class="ghost">${u.agenda ? 'Remover secretaria' : 'Agenda: secretaria'}</button></form>
              <form method="POST" action="/atb/admin/scih/recepcao-toggle/${u.id}" class="inline"><button class="ghost">${u.recepcao ? 'Remover recepção' : 'Agenda: recepção'}</button></form>
              <form method="POST" action="/atb/admin/scih/link/${u.id}" class="inline"><button class="ghost">Gerar link de senha</button></form>`}
          </td>
        </tr>`).join('');

      res.send(page('Acessos', `
        <div class="card">
          <h1>Acessos</h1>
          <p class="mut">Aprove os pedidos pendentes e gerencie quem tem acesso a cada sistema.
             O formulário público fica em <a href="/acesso/solicitar">/acesso/solicitar</a>.</p>
          ${mailerConfigurado() ? '' : `<p style="background:#fff6e5;border:1px solid #f0d9a8;color:#7a4c00;
             border-radius:10px;padding:12px 14px;margin-top:12px">
             <strong>Envio de e-mail desligado neste servidor.</strong> Ao aprovar, o link de
             definição de senha aparece na tela e precisa ser enviado à mão.
             Para automatizar, configure MAIL_USER e MAIL_PASS.</p>`}
        </div>

        ${blocosPendentes}

        <div class="card">
          <h2>Usuários com acesso</h2>
          <table>
            <thead><tr><th>Nome</th><th>E-mail</th><th>Papel</th><th>Prontuário</th><th>Agenda</th><th>Senha</th><th>Ações</th></tr></thead>
            <tbody>${linhasUsr}</tbody>
          </table>
          <div class="mt">
            <h2 style="margin-top:18px">Tornar um e-mail já cadastrado em SCIH</h2>
            <form method="POST" action="/atb/admin/scih/marcar" class="row">
              <input name="email" type="email" placeholder="email@dominio" required style="max-width:340px">
              <button class="ghost">Marcar como SCIH</button>
            </form>
            <h2 style="margin-top:18px">Liberar acesso ao prontuário por e-mail</h2>
            <form method="POST" action="/atb/admin/scih/pront-marcar" class="row">
              <input name="email" type="email" placeholder="email@dominio" required style="max-width:340px">
              <button class="ghost">Liberar prontuário</button>
            </form>
            <h2 style="margin-top:18px">Agenda: liberar papel por e-mail</h2>
            <form method="POST" action="/atb/admin/scih/agenda-marcar" class="row">
              <input name="email" type="email" placeholder="email@dominio" required style="max-width:340px">
              <select name="papel" style="max-width:180px"><option value="agenda">Secretaria</option><option value="recepcao">Recepção</option></select>
              <button class="ghost">Liberar agenda</button>
            </form>
            <p class="mut" style="font-size:13px">Use isto só para contas que já existem. Para gente nova, cadastre primeiro em /admin/alunos.</p>
          </div>
        </div>`));
    } catch (err) {
      console.error('[scih] painel:', err);
      res.status(500).send(page('Erro', `<div class="card"><h1>Falha ao carregar</h1><p class="mut">${esc(err.message)}</p></div>`));
    }
  });

  // ─────────────────────────── aprovar (qualquer módulo) ───────────────────
  // Uma rota só. O módulo vem do kind do pedido e o registro diz qual flag
  // conceder — antes eram duas cópias da mesma transação, uma por módulo.
  // A coluna da flag NUNCA vem da requisição: sai do registro, que é código.
  async function aprovarPedido(req, res) {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return res.status(400).send(page('Inválido',
      `<div class="card"><h1>Pedido inválido</h1><a href="/atb/admin/scih">Voltar</a></div>`));

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const r = (await client.query(
        `SELECT id, full_name, email, kind, instituicao, dados FROM access_requests
          WHERE id=$1 AND status='pending' FOR UPDATE`, [id])).rows[0];
      if (!r) {
        await client.query('ROLLBACK');
        return res.status(404).send(page('Não encontrado',
          `<div class="card"><h1>Pedido não encontrado ou já processado</h1><a href="/atb/admin/scih">Voltar</a></div>`));
      }

      const mod = moduloPorChave(r.kind);
      if (!mod) {
        await client.query('ROLLBACK');
        return res.status(422).send(page('Módulo desconhecido',
          `<div class="card"><h1>Módulo desconhecido</h1>
           <p class="mut">O pedido pede acesso a "${esc(r.kind)}", que não está no registro de módulos.</p>
           <a href="/atb/admin/scih">Voltar</a></div>`));
      }

      const email = r.email.toLowerCase().trim();
      const inst = mod.vinculo ? (r.instituicao || 'HUSF') : null;
      const token = novoToken();
      const expira = new Date(Date.now() + TOKEN_TTL_DIAS * 86400000);
      const flag = mod.flag;                     // vem do registro, nunca do corpo

      // Colunas adicionais (ex.: categoria_pav, conselho). Os NOMES saem do
      // registro; do pedido vêm apenas os valores.
      const dados = r.dados || {};
      const extras = (mod.campos || [])
        .filter(c => c.coluna && dados[c.nome])
        .map(c => ({ coluna: c.coluna, valor: String(dados[c.nome]).slice(0, 120) }));

      const existente = (await client.query('SELECT id FROM users WHERE email=$1', [email])).rows[0];
      if (existente) {
        const sets = [`full_name=COALESCE($1,full_name)`, `${flag}=true`,
                      `instituicao=COALESCE(instituicao,$2)`, `set_pw_token=$3`, `set_pw_expires=$4`];
        const vals = [r.full_name || null, inst, token, expira];
        extras.forEach(e => { vals.push(e.valor); sets.push(`${e.coluna}=$${vals.length}`); });
        vals.push(existente.id);
        await client.query(`UPDATE users SET ${sets.join(', ')} WHERE id=$${vals.length}`, vals);
      } else {
        // sem password_hash: login impossível até a pessoa definir a senha pelo link
        const cols = ['full_name', 'email', flag, 'instituicao', 'set_pw_token', 'set_pw_expires'];
        const vals = [r.full_name, email, true, inst, token, expira];
        extras.forEach(e => { cols.push(e.coluna); vals.push(e.valor); });
        await client.query(
          `INSERT INTO users(${cols.join(',')}) VALUES(${vals.map((_, i) => '$' + (i + 1)).join(',')})`,
          vals);
      }

      await client.query(`UPDATE access_requests SET status='approved', processed_at=now() WHERE id=$1`, [id]);
      await client.query('COMMIT');

      const link = `${baseUrl(req)}/definir-senha?token=${token}`;

      // Envio depois do commit e fora da transação: aprovação concedida não pode
      // ser desfeita nem escondida por falha de e-mail. O link continua na tela
      // em qualquer cenário, para envio manual.
      let envio;
      try {
        await sendAcessoAprovadoEmail({
          to: email,
          nome: r.full_name,
          modulo: mod.rotulo,
          link,
          dias: TOKEN_TTL_DIAS,
          aprovadoPor: mod.aprovadoPor,
        });
        await pool.query(`UPDATE access_requests SET email_enviado_at = now() WHERE id=$1`, [id]);
        envio = { ok: true };
      } catch (e) {
        // nunca registrar o link em log: é credencial de uso único
        console.error('[acesso] e-mail de aprovação falhou:', e.code || e.message);
        envio = { ok: false, semConfig: e.code === 'SEM_CONFIG', motivo: e.message };
      }

      const aviso = envio.ok
        ? `<p class="ok">E-mail enviado para <strong>${esc(email)}</strong> com o link de definição de senha.</p>`
        : envio.semConfig
          ? `<p class="alerta"><strong>Envio de e-mail não configurado</strong> neste servidor
             (MAIL_USER e MAIL_PASS). <strong>Envie o link abaixo manualmente</strong>, ou o acesso
             fica aprovado sem que a pessoa consiga entrar.</p>`
          : `<p class="alerta"><strong>Não foi possível enviar o e-mail.</strong>
             O acesso está aprovado, mas a pessoa não recebeu nada —
             <strong>copie o link abaixo e envie manualmente</strong>.
             <span class="mut">(${esc(envio.motivo || 'falha no envio')})</span></p>`;

      res.send(page('Pedido aprovado', `
        <div class="card">
          <h1>Acesso aprovado</h1>
          <p><strong>${esc(r.full_name)}</strong> (${esc(email)}) agora tem acesso a
             <strong>${esc(mod.rotulo)}</strong>${inst ? ` — unidade ${esc(inst)}` : ''}.</p>
          ${aviso}
          <p class="mut">O link expira em ${TOKEN_TTL_DIAS} dias e só funciona uma vez:</p>
          <div class="linkbox" id="lk">${esc(link)}</div>
          <div class="row mt">
            <button class="ghost" onclick="navigator.clipboard.writeText(document.getElementById('lk').innerText).then(()=>{this.innerText='Copiado!'})">Copiar link</button>
            <a href="/atb/admin/scih">Voltar ao painel</a>
          </div>
        </div>
        <style>
          .ok{background:#eaf7ee;border:1px solid #bfe3c9;color:#175c2c;border-radius:10px;padding:10px 12px}
          .alerta{background:#fff6e5;border:1px solid #f0d9a8;color:#7a4c00;border-radius:10px;padding:12px 14px}
        </style>`));
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch {}
      console.error('[acesso] aprovar:', err);
      res.status(500).send(page('Erro',
        `<div class="card"><h1>Falha ao aprovar</h1><p class="mut">${esc(err.message)}</p></div>`));
    } finally { client.release(); }
  }

  app.post('/atb/admin/acesso/aprovar/:id',     adminSuper, aprovarPedido);
  // endereços antigos: formulários já impressos e histórico do navegador
  app.post('/atb/admin/scih/aprovar/:id',       adminSuper, aprovarPedido);
  app.post('/atb/admin/scih/pront-aprovar/:id', adminSuper, aprovarPedido);

  app.post('/atb/admin/scih/rejeitar/:id', adminSuper, async (req, res) => {
    try {
      await pool.query(`UPDATE access_requests SET status='rejected', processed_at=now() WHERE id=$1 AND status='pending'`, [parseInt(req.params.id, 10)]);
      res.redirect('/atb/admin/scih');
    } catch (err) { console.error('[scih] rejeitar:', err); res.status(500).send('Falha ao rejeitar'); }
  });

  // liga/desliga scih de um usuário (super_admin é protegido)
  app.post('/atb/admin/scih/toggle/:userId', adminSuper, async (req, res) => {
    try {
      const uid = parseInt(req.params.userId, 10);
      const u = (await pool.query('SELECT scih, super_admin FROM users WHERE id=$1', [uid])).rows[0];
      if (u && !u.super_admin) {
        await pool.query('UPDATE users SET scih=$1 WHERE id=$2', [!u.scih, uid]);
      }
      res.redirect('/atb/admin/scih');
    } catch (err) { console.error('[scih] toggle:', err); res.status(500).send('Falha ao alternar'); }
  });

  // marca um e-mail já existente como SCIH
  app.post('/atb/admin/scih/marcar', adminSuper, async (req, res) => {
    try {
      const email = String(req.body?.email || '').trim().toLowerCase();
      const r = await pool.query('UPDATE users SET scih=true WHERE email=$1 RETURNING id', [email]);
      if (!r.rowCount) {
        return res.status(404).send(page('Não encontrado', `<div class="card"><h1>E-mail não cadastrado</h1><p class="mut">${esc(email)} não existe em usuários. Peça para a pessoa solicitar acesso em /scih/solicitar.</p><a href="/atb/admin/scih">Voltar</a></div>`));
      }
      res.redirect('/atb/admin/scih');
    } catch (err) { console.error('[scih] marcar:', err); res.status(500).send('Falha ao marcar'); }
  });

  // liga/desliga o acesso ao prontuário de um usuário (super_admin é sempre liberado)
  app.post('/atb/admin/scih/pront-toggle/:userId', adminSuper, async (req, res) => {
    try {
      const uid = parseInt(req.params.userId, 10);
      const u = (await pool.query('SELECT pront, super_admin FROM users WHERE id=$1', [uid])).rows[0];
      if (u && !u.super_admin) {
        await pool.query('UPDATE users SET pront=$1 WHERE id=$2', [!u.pront, uid]);
      }
      res.redirect('/atb/admin/scih');
    } catch (err) { console.error('[scih] pront-toggle:', err); res.status(500).send('Falha ao alternar prontuário'); }
  });

  // liga/desliga o papel de SECRETARIA na agenda (agenda/edita/cancela/fatura)
  app.post('/atb/admin/scih/agenda-toggle/:userId', adminSuper, async (req, res) => {
    try {
      const uid = parseInt(req.params.userId, 10);
      const u = (await pool.query('SELECT agenda, super_admin FROM users WHERE id=$1', [uid])).rows[0];
      if (u && !u.super_admin) {
        await pool.query('UPDATE users SET agenda=$1 WHERE id=$2', [!u.agenda, uid]);
      }
      res.redirect('/atb/admin/scih');
    } catch (err) { console.error('[scih] agenda-toggle:', err); res.status(500).send('Falha ao alternar agenda'); }
  });

  // liga/desliga o papel de RECEPÇÃO na agenda (vê o dia + check-in)
  app.post('/atb/admin/scih/recepcao-toggle/:userId', adminSuper, async (req, res) => {
    try {
      const uid = parseInt(req.params.userId, 10);
      const u = (await pool.query('SELECT recepcao, super_admin FROM users WHERE id=$1', [uid])).rows[0];
      if (u && !u.super_admin) {
        await pool.query('UPDATE users SET recepcao=$1 WHERE id=$2', [!u.recepcao, uid]);
      }
      res.redirect('/atb/admin/scih');
    } catch (err) { console.error('[scih] recepcao-toggle:', err); res.status(500).send('Falha ao alternar recepção'); }
  });

  // libera acesso ao prontuário para um e-mail já existente
  app.post('/atb/admin/scih/pront-marcar', adminSuper, async (req, res) => {
    try {
      const email = String(req.body?.email || '').trim().toLowerCase();
      const r = await pool.query('UPDATE users SET pront=true WHERE email=$1 RETURNING id', [email]);
      if (!r.rowCount) {
        return res.status(404).send(page('Não encontrado', `<div class="card"><h1>E-mail não cadastrado</h1><p class="mut">${esc(email)} não existe em usuários. Cadastre primeiro em /admin/alunos.</p><a href="/atb/admin/scih">Voltar</a></div>`));
      }
      res.redirect('/atb/admin/scih');
    } catch (err) { console.error('[scih] pront-marcar:', err); res.status(500).send('Falha ao liberar prontuário'); }
  });

  // libera papel da agenda (secretaria ou recepção) para um e-mail já existente
  app.post('/atb/admin/scih/agenda-marcar', adminSuper, async (req, res) => {
    try {
      const email = String(req.body?.email || '').trim().toLowerCase();
      const papel = req.body?.papel === 'recepcao' ? 'recepcao' : 'agenda';
      const r = await pool.query(`UPDATE users SET ${papel}=true WHERE email=$1 RETURNING id`, [email]);
      if (!r.rowCount) {
        return res.status(404).send(page('Não encontrado', `<div class="card"><h1>E-mail não cadastrado</h1><p class="mut">${esc(email)} não existe em usuários. Cadastre primeiro em /admin/alunos.</p><a href="/atb/admin/scih">Voltar</a></div>`));
      }
      res.redirect('/atb/admin/scih');
    } catch (err) { console.error('[scih] agenda-marcar:', err); res.status(500).send('Falha ao liberar agenda'); }
  });

  // (re)gera link de definição de senha para um usuário existente
  app.post('/atb/admin/scih/link/:userId', adminSuper, async (req, res) => {
    try {
      const uid = parseInt(req.params.userId, 10);
      const u = (await pool.query('SELECT full_name, email FROM users WHERE id=$1', [uid])).rows[0];
      if (!u) return res.status(404).send('Usuário não encontrado');
      const token = novoToken();
      const expira = new Date(Date.now() + TOKEN_TTL_DIAS * 86400000);
      await pool.query('UPDATE users SET set_pw_token=$1, set_pw_expires=$2 WHERE id=$3', [token, expira, uid]);
      const link = `${baseUrl(req)}/definir-senha?token=${token}`;
      res.send(page('Link gerado', `
        <div class="card">
          <h1>Link de senha gerado</h1>
          <p>Para <strong>${esc(u.full_name || u.email)}</strong> (${esc(u.email)}):</p>
          <div class="linkbox" id="lk">${esc(link)}</div>
          <div class="row mt">
            <button class="ghost" onclick="navigator.clipboard.writeText(document.getElementById('lk').innerText).then(()=>{this.innerText='Copiado!'})">Copiar link</button>
            <a href="/atb/admin/scih">Voltar ao painel</a>
          </div>
        </div>`));
    } catch (err) { console.error('[scih] link:', err); res.status(500).send('Falha ao gerar link'); }
  });

  // ───────────────────────── público: definir senha via token ─────────────
  app.get('/definir-senha', async (req, res) => {
    const token = String(req.query.token || '');
    const u = token ? (await pool.query(
      'SELECT email, set_pw_expires FROM users WHERE set_pw_token=$1', [token])).rows[0] : null;
    if (!u || (u.set_pw_expires && new Date() > new Date(u.set_pw_expires))) {
      return res.status(400).send(page('Link inválido', `
        <div class="card"><h1>Link inválido ou expirado</h1>
        <p class="mut">Peça à coordenação um novo link de acesso.</p></div>`));
    }
    res.send(page('Definir senha', `
      <div class="card">
        <h1>Defina sua senha</h1>
        <p class="mut">Conta: <strong>${esc(u.email)}</strong></p>
        <form method="POST" action="/definir-senha" class="mt" onsubmit="return validar()">
          <input type="hidden" name="token" value="${esc(token)}">
          <label>Nova senha (mínimo 8 caracteres)</label>
          <input id="p1" name="password" type="password" minlength="8" required>
          <label>Confirme a senha</label>
          <input id="p2" name="password2" type="password" minlength="8" required>
          <p id="erro" class="mut" style="color:#8a1414"></p>
          <button class="mt">Salvar senha e ativar conta</button>
        </form>
      </div>
      <script>
        function validar(){
          var a=document.getElementById('p1').value, b=document.getElementById('p2').value;
          if(a.length<8){document.getElementById('erro').innerText='A senha precisa ter ao menos 8 caracteres.';return false;}
          if(a!==b){document.getElementById('erro').innerText='As senhas não conferem.';return false;}
          return true;
        }
      </script>`));
  });

  app.post('/definir-senha', async (req, res) => {
    try {
      const token = String(req.body?.token || '');
      const password = String(req.body?.password || '');
      const password2 = String(req.body?.password2 || '');
      if (password.length < 8 || password !== password2) {
        return res.status(400).send(page('Senha inválida', `<div class="card"><h1>Senha inválida</h1><p class="mut">Verifique o tamanho (mín. 8) e a confirmação.</p><a href="/definir-senha?token=${esc(token)}">Voltar</a></div>`));
      }
      const u = token ? (await pool.query(
        'SELECT id, set_pw_expires FROM users WHERE set_pw_token=$1', [token])).rows[0] : null;
      if (!u || (u.set_pw_expires && new Date() > new Date(u.set_pw_expires))) {
        return res.status(400).send(page('Link inválido', `<div class="card"><h1>Link inválido ou expirado</h1><p class="mut">Peça um novo link à coordenação.</p></div>`));
      }
      const hash = await bcrypt.hash(password, 10);
      await pool.query(
        `UPDATE users SET password_hash=$1, temp_password=NULL, set_pw_token=NULL, set_pw_expires=NULL WHERE id=$2`,
        [hash, u.id]);
      res.send(page('Senha definida', `
        <div class="card">
          <h1>Pronto! Senha definida</h1>
          <p>Sua conta está ativa. Você já pode entrar no sistema.</p>
          <a href="/"><button class="mt">Ir para o login</button></a>
        </div>`));
    } catch (err) {
      console.error('[scih] definir-senha:', err);
      res.status(500).send(page('Erro', `<div class="card"><h1>Falha ao salvar senha</h1><p class="mut">${esc(err.message)}</p></div>`));
    }
  });
}
