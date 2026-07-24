// isc-import-routes.js
// ──────────────────────────────────────────────────────────────────────────
// Importador de MAPA CIRÚRGICO — provisão que corre LADO A LADO com o
// cadastro manual (/isc/admin/nova), sem substituí-lo.
//
// FLUXO: colar/soltar arquivo → mapear colunas → PRÉVIA → gravar em lote.
// Nunca grava sem prévia. Todo lote é reversível enquanto ninguém tocou nas
// fichas (ficha com contato registrado ou já classificada jamais é apagada).
//
// ENTRADA: colar (Ctrl+C do Excel = TSV), arquivo CSV/TXT (lido no browser) ou
// XLSX (lido no browser como base64 e parseado aqui com a lib xlsx, que já é
// dependência do projeto — sem multipart, sem dependência nova).
// ──────────────────────────────────────────────────────────────────────────

import * as XLSX from 'xlsx';
import { tenantFromReq, getTenantLogo, sanitizeSigla } from './atb-tenant.js';
import {
  CAMPOS_IMPORTAVEIS, CAMPOS_COMPLEMENTAVEIS, parseTabular, adivinhaMapeamento,
  montarPrevia, chaveDedup, chavesDedup, detectaDelimitador,
} from './isc-import.js';
import { toISODate, dataBR, janelasDe, recomputarEstado, CHECKLIST } from './isc-core.js';
import { normalizaAoA } from './isc-import-relatorio.js';

function safe(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const CORES = { HUSF: '#0c447c', SCMI: '#F0D000' };

// XLSX (base64) → texto TSV, para cair no MESMO caminho do colar/CSV.
// Converter em vez de bifurcar mantém uma só rota de normalização.
export function xlsxParaTexto(b64) {
  const wb = XLSX.read(Buffer.from(String(b64), 'base64'), { type: 'buffer', cellDates: false });
  const ws = wb.Sheets[wb.SheetNames[0]];
  if (!ws) return '';
  const linhas = XLSX.utils.sheet_to_json(ws, { header: 1, raw: true, defval: '', blankrows: false });
  return linhas.map(l => l.map(c => String(c ?? '').replace(/[\t\r\n]+/g, ' ')).join('\t')).join('\n');
}

// Toda entrada (colar, CSV, XLSX) vira a MESMA estrutura: array de arrays.
// Ter um só formato interno é o que permite o normalizador de relatório tratar
// Tasy_Rel e CSV comum sem dois caminhos de código.
function entradaParaAoA(b) {
  const texto = b.xlsx_b64 ? xlsxParaTexto(b.xlsx_b64) : String(b.texto || '');
  if (!texto.trim()) return { aoa: [], texto: '', delim: '\t' };
  const { header, linhas, delim } = parseTabular(texto, b.delim || undefined);
  return { aoa: [header, ...linhas], texto, delim };
}

export function registerIscImportRoutes(app, pool, scihRequired, renderShell) {

  // Regra de triagem define o DENOMINADOR da taxa de ISC, e desfazer lote apaga
  // ficha: os dois são do médico do SCIH, não da operação. Mesmo gate do
  // isc-routes.js (incl. break-glass pelo cookie adm).
  function ehMedico(req) {
    return !!((req.user && req.user.super_admin) || req.cookies?.adm === '1');
  }
  function ensureMedico(req, res, next) {
    if (ehMedico(req)) return next();
    return res.status(403).send(renderShell('Sem permissão', `<div class="card">
      <h1>Restrito ao médico do SCIH</h1>
      <p class="mut">As regras de triagem definem quais cirurgias entram na vigilância — e portanto
      o denominador da taxa de ISC. Desfazer um lote apaga fichas. Sua conta importa e opera, mas não altera isto.</p>
      <a href="/isc/admin/importar">← Voltar</a></div>`));
  }
  const medicoRequired = [scihRequired, ensureMedico];

  const _instCache = new Map();
  async function instIdDeSigla(sigla) {
    const key = sanitizeSigla(sigla);
    if (!key) return null;
    if (_instCache.has(key)) return _instCache.get(key);
    const { rows } = await pool.query('SELECT id FROM atb_instituicoes WHERE sigla = $1', [key]);
    const id = rows[0]?.id ?? null;
    if (id) _instCache.set(key, id);
    return id;
  }
  async function resolveInst(req) {
    const travado = tenantFromReq(req);
    const sigla = travado || sanitizeSigla(req.query?.inst || req.body?.inst || '') || null;
    return { sigla, instId: sigla ? await instIdDeSigla(sigla) : null, travado: !!travado };
  }
  async function equipesDe(instId) {
    const { rows } = await pool.query(
      `SELECT id, nome, sigla, implante_default, janelas_default, janelas_implante
         FROM isc_equipes WHERE ativo = true AND ($1::int IS NULL OR instituicao_id = $1)
        ORDER BY ordem, nome`, [instId]);
    return rows;
  }

  // Regras de triagem do tenant (o que entra na vigilância).
  async function regrasDe(instId) {
    const { rows } = await pool.query(
      `SELECT * FROM isc_triagem_regras
        WHERE ativo = true AND ($1::int IS NULL OR instituicao_id = $1)
        ORDER BY ordem, id`, [instId]);
    return rows;
  }

  // Chaves atendimento|data já existentes, para a prévia marcar duplicata.
  // Map chave→ficha (não só as chaves): a prévia precisa do CONTEÚDO da ficha
  // existente para saber o que dá para complementar. Guarda as duas formas de
  // chave — ficha antiga pode ter entrado sem o nº da cirurgia (cadastro manual).
  async function fichasExistentes(instId) {
    const cols = ['id', 'cirurgia_id', 'atendimento', 'prontuario', 'data_cirurgia', ...CAMPOS_COMPLEMENTAVEIS]
      .filter((c, i, a) => a.indexOf(c) === i).join(', ');
    const { rows } = await pool.query(
      `SELECT ${cols} FROM isc_fichas WHERE ($1::int IS NULL OR instituicao_id = $1)`, [instId]);
    // Registra TODAS as chaves de cada ficha: ela pode ter sido criada por um
    // layout do relatório e reencontrada por outro (ver chavesDedup).
    const m = new Map();
    for (const r of rows) for (const k of chavesDedup(r)) if (!m.has(k)) m.set(k, r);
    return m;
  }

  function chrome(sigla, titulo, sub, med) {
    const cor = CORES[String(sigla).toUpperCase()] || '#0c447c';
    const logo = sigla ? getTenantLogo(sigla) : '';
    return `
      ${sigla ? `<div style="height:5px;background:${cor};border-radius:3px;margin-bottom:14px"></div>` : ''}
      <div style="display:flex;justify-content:space-between;align-items:baseline;flex-wrap:wrap;gap:10px;margin-bottom:14px">
        <div style="display:flex;align-items:baseline;gap:14px">
          <h1 style="margin:0;color:#202124">${safe(titulo)}${sigla ? ` <span style="color:#00469e;font-weight:600">— ${safe(sigla)}</span>` : ''}</h1>
          <span style="color:#80868b;font-size:13px">${safe(sub)}</span>
        </div>
        ${sigla && logo ? `<img src="${logo}" alt="${safe(sigla)}" style="height:40px;width:auto;max-width:230px;object-fit:contain">` : ''}
        <div style="display:flex;gap:14px"><a href="/isc/admin/grid">Grid</a><a href="/isc/admin/agenda">Agenda</a><a href="/isc/admin/nova">+ Manual</a><a href="/isc/admin/importar">Importar</a>${med ? '<a href="/isc/admin/triagem">Triagem</a><a href="/isc/admin/alertas">Alertas</a>' : ''}</div>
      </div>`;
  }

  const CSS = `<style>
    .isc{position:relative;left:50%;right:50%;margin-left:-49vw;margin-right:-49vw;width:98vw;background:#f5f6f8;min-height:100vh;margin-top:-40px;padding:28px 24px 60px}
    .isc h1{font-weight:600}.isc a{color:#3b6fd4;text-decoration:none}
    .isc .card2{background:#fff;border:1px solid #e8eaed;border-radius:10px;padding:18px;margin-bottom:14px}
    .isc .card2 h2{margin:0 0 12px;font-size:15px;color:#202124}
    .isc label.l{display:block;font-size:11px;color:#5f6368;text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px;font-weight:600}
    .isc input,.isc select,.isc textarea{width:100%;padding:8px 10px;border:1px solid #dadce0;border-radius:7px;font-size:13px;background:#fff;color:#202124;font-family:inherit}
    .isc .btn{padding:9px 18px;background:#2bb673;color:#fff;border:0;border-radius:7px;font-size:13px;cursor:pointer;font-weight:600}
    .isc .btn-sec{background:#fff;color:#3b6fd4;border:1px solid #dadce0}
    .isc .btn-red{background:#c0392b}
    .isc .sub{font-size:11px;color:#9aa0a6}
    .isc .metric{background:#fff;border:1px solid #e8eaed;border-left:3px solid;border-radius:8px;padding:10px 14px}
    .isc .metric .mv{font-size:20px;font-weight:600}
    .isc .metric .ml{font-size:10px;color:#80868b;text-transform:uppercase;letter-spacing:.05em}
    .isc table.p{border-collapse:separate;border-spacing:0;width:100%;font-size:12px;background:#fff}
    .isc table.p th{position:sticky;top:0;background:#fff;color:#5f6368;font-size:11px;text-align:left;padding:9px 10px;border-bottom:1px solid #e0e2e6;white-space:nowrap}
    .isc table.p td{padding:7px 10px;border-bottom:1px solid #f0f1f3;vertical-align:top}
    .isc tr.erro td{background:#fdf3f2}.isc tr.dup td{background:#f7f8f9;color:#80868b}
    .isc .pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600}
    .isc .drop{border:2px dashed #dadce0;border-radius:10px;padding:22px;text-align:center;color:#80868b;font-size:13px;background:#fafbfc}
    .isc .drop.on{border-color:#2bb673;background:#f2fbf6}
  </style>`;

  const erro = (res, e) => {
    console.error('[isc-import]', e);
    res.status(500).send(renderShell('ISC · Erro', `<div class="card"><p class="mut">${safe(e.message)}</p></div>`));
  };

  // ── Passo 1: entrada ────────────────────────────────────────────────────
  app.get('/isc/admin/importar', scihRequired, async (req, res) => {
    try {
      const { sigla, instId } = await resolveInst(req);
      const admin = ehMedico(req);
      const { rows: perfis } = await pool.query(
        `SELECT id, nome FROM isc_import_perfis WHERE ($1::int IS NULL OR instituicao_id = $1) ORDER BY nome`, [instId]);
      const { rows: lotes } = await pool.query(
        `SELECT l.*, (SELECT count(*)::int FROM isc_fichas f WHERE f.import_lote_id = l.id) AS vivas
           FROM isc_import_lotes l
          WHERE ($1::int IS NULL OR l.instituicao_id = $1)
          ORDER BY l.id DESC LIMIT 10`, [instId]);

      const histo = lotes.map(l => `<tr>
        <td>${l.id}</td>
        <td>${dataBR(l.created_at)}</td>
        <td>${safe(l.arquivo_nome || '—')}</td>
        <td>${l.criadas} criadas${l.complementadas ? ` · ${l.complementadas} complementadas` : ''} · ${l.ignoradas} ignoradas</td>
        <td>${l.vivas} no grid</td>
        <td>${l.desfeito_em
          ? `<span class="sub">desfeito em ${toISODate(l.desfeito_em)}</span>`
          : (l.vivas > 0 && ehMedico(req)
            ? `<form method="post" action="/isc/admin/importar/lote/${l.id}/desfazer" style="display:inline" onsubmit="return confirm('Desfazer o lote ${l.id}?\n\nApaga apenas as ${l.criadas} ficha(s) que ELE criou — e só as que ainda não receberam contato nem classificação.\n\nCampos complementados por ele NÃO voltam atrás.')">
                 <button class="btn btn-sec" style="padding:4px 10px;font-size:11px">Desfazer</button></form>`
            : '<span class="sub">—</span>')}</td>
      </tr>`).join('');

      const html = `<div class="isc">
        ${chrome(sigla, 'Importar mapa cirúrgico', 'Cria fichas em lote — convive com o cadastro manual', ehMedico(req))}
        <div class="card2" style="background:#f8f9fa">
          <b style="font-size:13px">Como funciona</b>
          <p class="sub" style="margin:6px 0 0;line-height:1.6">
            Cole o mapa direto do Excel (Ctrl+C → Ctrl+V) ou solte um arquivo <b>.xlsx</b>, <b>.csv</b> ou <b>.txt</b>.
            A primeira linha tem que ser o cabeçalho. Você confere o mapeamento das colunas na tela seguinte e vê a
            prévia antes de qualquer coisa ser gravada. <b>Nada é gravado sem a sua confirmação.</b>
          </p>
        </div>
        <form method="post" action="/isc/admin/importar/previa" id="fm">
          <input type="hidden" name="inst" value="${safe(sigla || '')}">
          <input type="hidden" name="xlsx_b64" id="xb">
          <input type="hidden" name="arquivo_nome" id="an">
          <div class="card2">
            <div class="drop" id="dz">
              Solte o arquivo aqui (.xlsx · .csv · .txt) ou <label style="color:#3b6fd4;cursor:pointer;text-transform:none;letter-spacing:0;display:inline;font-size:13px"><u>escolha um arquivo</u><input type="file" id="fi" accept=".xlsx,.xls,.csv,.txt" style="display:none"></label>
              <div class="sub" id="fn" style="margin-top:6px"></div>
            </div>
            <p style="text-align:center;color:#9aa0a6;font-size:12px;margin:12px 0">— ou cole aqui —</p>
            <textarea name="texto" id="tx" rows="10" placeholder="Cole o mapa cirúrgico (a primeira linha deve ser o cabeçalho)" style="font-family:ui-monospace,Menlo,monospace;font-size:12px"></textarea>
            <div style="display:flex;gap:12px;align-items:center;margin-top:12px;flex-wrap:wrap">
              <div><label class="l">Perfil de mapeamento</label>
                <select name="perfil_id" style="min-width:220px" ${admin ? '' : 'required'}>
                  ${admin ? '<option value="">Adivinhar pelas colunas</option>' : (perfis.length === 1 ? '' : '<option value="">— escolha —</option>')}
                  ${perfis.map((p, k) => `<option value="${p.id}" ${!admin && perfis.length === 1 ? 'selected' : ''}>${safe(p.nome)}</option>`).join('')}</select>
                ${admin ? '' : '<div class="sub" style="margin-top:3px">O administrador configurou o mapeamento das colunas.</div>'}</div>
              <button class="btn" type="submit" style="margin-top:16px">Ler e mapear →</button>
            </div>
          </div>
        </form>
        ${lotes.length ? `<div class="card2"><h2>Importações recentes</h2>
          <table class="p"><thead><tr><th>Lote</th><th>Data</th><th>Arquivo</th><th>Resultado</th><th>Fichas</th><th></th></tr></thead>
          <tbody>${histo}</tbody></table></div>` : ''}
        <script>
          (function(){
            var dz=document.getElementById('dz'),fi=document.getElementById('fi'),tx=document.getElementById('tx'),
                xb=document.getElementById('xb'),an=document.getElementById('an'),fn=document.getElementById('fn');
            function lidar(f){
              if(!f) return;
              an.value=f.name; fn.textContent='Arquivo: '+f.name;
              var r=new FileReader();
              if(/\\.xlsx?$/i.test(f.name)){
                // XLSX é binário: manda em base64 e o servidor converte (lib xlsx já existe no projeto).
                r.onload=function(){ xb.value=String(r.result).split(',')[1]; tx.value=''; tx.placeholder='Planilha "'+f.name+'" carregada — clique em Ler e mapear.'; };
                r.readAsDataURL(f);
              } else {
                r.onload=function(){ tx.value=String(r.result); xb.value=''; };
                r.readAsText(f,'UTF-8');
              }
            }
            fi.addEventListener('change',function(){ lidar(this.files[0]); });
            ['dragenter','dragover'].forEach(function(e){ dz.addEventListener(e,function(ev){ev.preventDefault();dz.classList.add('on');}); });
            ['dragleave','drop'].forEach(function(e){ dz.addEventListener(e,function(ev){ev.preventDefault();dz.classList.remove('on');}); });
            dz.addEventListener('drop',function(ev){ lidar(ev.dataTransfer.files[0]); });
            tx.addEventListener('input',function(){ if(tx.value){ xb.value=''; fn.textContent=''; } });
          })();
        </script>
      </div>${CSS}`;
      res.send(renderShell('ISC · Importar', html, sigla ? getTenantLogo(sigla) : undefined));
    } catch (e) { erro(res, e); }
  });

  // ── Passo 2: mapear + prévia ────────────────────────────────────────────
  app.post('/isc/admin/importar/previa', scihRequired, async (req, res) => {
    try {
      const { sigla, instId } = await resolveInst(req);
      const b = req.body || {};
      const ent = entradaParaAoA(b);
      const texto = ent.texto, delim = ent.delim;
      if (!texto.trim()) return res.redirect('/isc/admin/importar');

      // Reconstrói registros (layout de impressão do Tasy) ou lê tabela plana.
      const modo = ['plano', 'relatorio'].includes(b.modo) ? b.modo : 'auto';
      const norm = normalizaAoA(ent.aoa, modo);
      const header = norm.rotulos, linhas = norm.linhas;
      const diag = norm.diagnostico;
      if (!linhas.length) {
        return res.send(renderShell('ISC · Importar', `<div class="card"><h1>Nada para importar</h1>
          <p class="mut">${safe(diag?.erro || 'Não encontrei registros neste arquivo.')}</p>
          <a href="/isc/admin/importar">← Voltar</a></div>`));
      }

      // Mapeamento. Para o ADMIN: o que ele mandou na tela > perfil > palpite.
      // Para a colaboradora (não-admin): mapa_json do browser é IGNORADO — o
      // mapeamento é ato de configuração, dela vem só o arquivo. Só entra perfil
      // salvo (que o admin montou) ou, na falta, o palpite. Esconder o editor na
      // tela não bastaria: um POST forjado passaria. A guarda é aqui.
      const podeMapear = ehMedico(req);
      let mapa = null;
      let mapaOrigem = 'palpite';
      if (podeMapear && b.mapa_json) {
        try { mapa = JSON.parse(b.mapa_json); mapaOrigem = 'editor'; } catch { /* cai no perfil/palpite */ }
      }
      if (!mapa && b.perfil_id) {
        const { rows } = await pool.query(
          `SELECT nome, mapeamento FROM isc_import_perfis WHERE id=$1 AND ($2::int IS NULL OR instituicao_id=$2)`,
          [Number(b.perfil_id), instId]);
        if (rows[0]) { mapa = rows[0].mapeamento; mapaOrigem = `perfil "${rows[0].nome}"`; }
      }
      if (!mapa) { mapa = adivinhaMapeamento(header, linhas); mapaOrigem = 'palpite automático'; }

      const equipes = await equipesDe(instId);
      const existentes = await fichasExistentes(instId);
      const regras = b.sem_triagem === '1' ? null : await regrasDe(instId);
      const { itens, resumo } = montarPrevia(linhas, mapa, equipes, existentes, regras);

      const opts = i => `<option value="">— ignorar —</option>` + CAMPOS_IMPORTAVEIS.map(c =>
        `<option value="${c.key}" ${mapa[i] === c.key ? 'selected' : ''}>${safe(c.label)}${c.obrigatorio ? ' *' : ''}</option>`).join('');

      const rotuloCampo = k => (CAMPOS_IMPORTAVEIS.find(c => c.key === k) || {}).label || k;
      const mapaUI = norm.colunasUteis.map(i => { const h = header[i]; return `
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;align-items:center;padding:6px 0;border-bottom:1px solid #f0f1f3">
          <div style="font-size:12px"><b>${safe(h || '(coluna ' + (i + 1) + ')')}</b>
            <div class="sub">ex.: ${safe(String(linhas[0]?.[i] ?? '').slice(0, 30) || '—')}</div></div>
          ${podeMapear
            ? `<select class="mp" data-i="${i}">${opts(i)}</select>`
            : `<div style="font-size:12px;color:${mapa[i] ? '#202124' : '#9aa0a6'}">${mapa[i] ? safe(rotuloCampo(mapa[i])) : '— não usada —'}</div>`}
        </div>`; }).join('');

      const PILL = { nova: ['#e6f4ea', '#1e7e34', 'nova'], duplicada: ['#f1f3f4', '#80868b', 'já existe'],
                     complementa: ['#e8f0fe', '#1a73e8', 'complementa'],
                     erro: ['#fdecea', '#c0392b', 'erro'], fora_recorte: ['#eceff3', '#8e9aaf', 'fora do recorte'] };
      const rotulo = Object.fromEntries(CAMPOS_IMPORTAVEIS.map(c => [c.key, c.label]));
      rotulo.telefone = 'Telefone'; rotulo.telefone_raw = 'Telefone (original)';
      rotulo.telefone_presumido = 'DDD presumido'; rotulo.equipe_id = 'Equipe'; rotulo.especialidade = 'Especialidade';
      const linhasUI = itens.slice(0, 300).map(it => {
        const [bg, fg, tx] = PILL[it.status];
        const compl = it.complemento
          ? `<span style="color:#1a73e8">Vai preencher: <b>${safe(Object.keys(it.complemento.campos).map(k => rotulo[k] || k).join(', '))}</b></span>`
          : '';
        const msgs = [
          compl,
          it.motivo ? `<span style="color:#5f6368">${safe(it.motivo)}</span>` : '',
          ...it.erros.map(e => `<span style="color:#c0392b">${safe(e)}</span>`),
          ...it.avisos.map(a => `<span style="color:#b06000">${safe(a)}</span>`)].filter(Boolean).join('<br>');
        return `<tr class="${it.status === 'erro' ? 'erro' : (it.status === 'duplicada' || it.status === 'fora_recorte') ? 'dup' : ''}">
          <td>${it.linha}</td>
          <td><span class="pill" style="background:${bg};color:${fg}">${tx}</span></td>
          <td>${safe(it.ficha.paciente_nome || '—')}</td>
          <td>${safe(it.ficha.atendimento || '—')}</td>
          <td>${safe(dataBR(it.ficha.data_cirurgia) || '—')}</td>
          <td>${safe(it.ficha.procedimento || '—')}</td>
          <td>${msgs || '<span class="sub">ok</span>'}</td>
        </tr>`;
      }).join('');

      const html = `<div class="isc">
        ${chrome(sigla, 'Prévia da importação', `${resumo.total} linha(s) lidas · separador ${delim === '\t' ? 'TAB' : `"${delim}"`}`, ehMedico(req))}
        <div style="display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-bottom:14px">
          <div class="metric" style="border-left-color:#74c47d"><div class="mv" style="color:#3a8a4a">${resumo.novas}</div><div class="ml">Serão criadas</div></div>
          <div class="metric" style="border-left-color:#3b6fd4"><div class="mv" style="color:#2c5aa8">${resumo.complementa || 0}</div><div class="ml">Serão complementadas</div></div>
          <div class="metric" style="border-left-color:#8e9aaf"><div class="mv" style="color:#5f6368">${resumo.fora_recorte || 0}</div><div class="ml">Fora do recorte</div></div>
          <div class="metric" style="border-left-color:#a9b0c7"><div class="mv" style="color:#5f6368">${resumo.duplicadas}</div><div class="ml">Já existem, nada a somar</div></div>
          <div class="metric" style="border-left-color:#e85d5d"><div class="mv" style="color:#c0392b">${resumo.erros}</div><div class="ml">Com erro (puladas)</div></div>
          <div class="metric" style="border-left-color:#f0a500"><div class="mv" style="color:#b06000">${resumo.avisos}</div><div class="ml">Com aviso</div></div>
        </div>
        ${regras ? `<p class="sub" style="margin:-6px 0 12px">Triagem ativa: <b>${regras.filter(x => x.vigiar).length} regra(s) de vigilância</b> e ${regras.filter(x => !x.vigiar).length} de exclusão. ${ehMedico(req) ? '<a href="/isc/admin/triagem">Ajustar regras</a>' : ''}</p>` : ''}

        <div class="card2" style="background:${diag.modo === 'relatorio' ? '#f2f7fd' : '#f8f9fa'};border-left:3px solid ${diag.modo === 'relatorio' ? '#3b6fd4' : '#dadce0'}">
          <b style="font-size:13px">${diag.modo === 'relatorio' ? 'Relatório em layout de impressão detectado' : 'Tabela plana'}</b>
          <p class="sub" style="margin:6px 0 0;line-height:1.6">
            ${safe(diag.deteccao?.motivo || '')}${diag.modo === 'relatorio' ? ` · cabeçalho na linha ${diag.linhaCabecalho} · <b>${diag.registros} registros</b> reconstruídos de ${diag.linhasLidas} linhas (${diag.linhasDescartadas} eram continuação de texto ou rodapé) · ${diag.colunasDescartadas} colunas vazias descartadas` : ` · ${diag.registros} registros`}
            <br>Os rótulos abaixo são <b>dica</b>: no layout de impressão o título raramente cai na coluna do dado. <b>Confira pelas amostras</b> e salve como perfil — aí não precisa mapear de novo.
          </p>
        </div>
        <div class="card2"><h2>Mapeamento das colunas</h2>
          ${podeMapear
            ? `<p class="sub" style="margin-top:-8px">* obrigatório. Mudou algo? Clique em <b>Recalcular</b> para atualizar a prévia.</p>`
            : `<p class="sub" style="margin-top:-8px">Definido pelo administrador (${safe(mapaOrigem)}). Se as colunas não baterem, avise o administrador do SCIH.</p>`}
          <div style="max-height:280px;overflow:auto">${mapaUI}</div>
          ${podeMapear ? `
          <form method="post" action="/isc/admin/importar/previa" id="fr" style="margin-top:12px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            <input type="hidden" name="inst" value="${safe(sigla || '')}">
            <input type="hidden" name="texto" value="${safe(texto)}">
            <input type="hidden" name="delim" value="${safe(delim)}">
            <input type="hidden" name="arquivo_nome" value="${safe(b.arquivo_nome || '')}">
            <input type="hidden" name="mapa_json" id="mj">
            <label class="chk" title="Use para importar uma planilha própria que não seja o mapa cirúrgico do Tasy."><input type="checkbox" name="sem_triagem" value="1" ${b.sem_triagem === '1' ? 'checked' : ''}> ignorar triagem</label>
            <select class="fil" name="modo" style="width:auto;padding:7px 10px;border:1px solid #dadce0;border-radius:7px">
              <option value="auto" ${modo === 'auto' ? 'selected' : ''}>Layout: detectar</option>
              <option value="relatorio" ${modo === 'relatorio' ? 'selected' : ''}>Layout: relatório impresso</option>
              <option value="plano" ${modo === 'plano' ? 'selected' : ''}>Layout: tabela plana</option>
            </select>
            <button class="btn btn-sec" type="submit">Recalcular prévia</button>
            <input name="perfil_nome" placeholder="Salvar mapeamento como…" style="max-width:230px">
            <button class="btn btn-sec" type="submit" name="salvar_perfil" value="1">Salvar perfil</button>
          </form>` : ''}
        </div>

        <div class="card2"><h2>Linhas</h2>
          <div style="max-height:420px;overflow:auto">
            <table class="p"><thead><tr><th>#</th><th>Status</th><th>Paciente</th><th>Atend.</th><th>Cirurgia</th><th>Procedimento</th><th>Observações</th></tr></thead>
            <tbody>${linhasUI}</tbody></table>
          </div>
          ${itens.length > 300 ? `<p class="sub">Mostrando as 300 primeiras de ${itens.length}. Todas serão processadas.</p>` : ''}
        </div>

        <form method="post" action="/isc/admin/importar/gravar" ${podeMapear ? `onsubmit="document.getElementById('mj2').value=window.mapaAtual()"` : ''}>
          <input type="hidden" name="inst" value="${safe(sigla || '')}">
          <input type="hidden" name="texto" value="${safe(texto)}">
          <input type="hidden" name="delim" value="${safe(delim)}">
          <input type="hidden" name="arquivo_nome" value="${safe(b.arquivo_nome || '')}">
          <input type="hidden" name="modo" value="${safe(modo)}">
          <input type="hidden" name="sem_triagem" value="${b.sem_triagem === '1' ? '1' : ''}">
          ${podeMapear ? '<input type="hidden" name="mapa_json" id="mj2">' : `<input type="hidden" name="perfil_id" value="${safe(b.perfil_id || '')}">`}
          <button class="btn" ${(resumo.novas + (resumo.complementa || 0)) === 0 ? 'disabled style="opacity:.5"' : ''} type="submit">
            ${[resumo.novas ? `Criar ${resumo.novas} ficha(s)` : '', resumo.complementa ? `complementar ${resumo.complementa}` : ''].filter(Boolean).join(' · ') || 'Nada a fazer'}
          </button>
          <a class="btn btn-sec" href="/isc/admin/importar" style="text-decoration:none;margin-left:8px;display:inline-block">Cancelar</a>
          ${(resumo.novas + (resumo.complementa || 0)) === 0 ? '<span class="sub" style="margin-left:10px">Nada novo para gravar.</span>' : ''}
          ${resumo.complementa ? '<p class="sub" style="margin-top:8px">Complementar só <b>preenche campo vazio</b> — nunca sobrescreve o que já está na ficha, nem toca na classificação.</p>' : ''}
        </form>

        ${podeMapear ? `<script>
          window.mapaAtual = function(){
            var o={}; document.querySelectorAll('.mp').forEach(function(s){ if(s.value) o[s.dataset.i]=s.value; });
            return JSON.stringify(o);
          };
          document.getElementById('fr').addEventListener('submit',function(){ document.getElementById('mj').value=window.mapaAtual(); });
        </script>` : ''}
      </div>${CSS}`;

      // Salvar perfil (o próprio submit da prévia traz o nome).
      if (podeMapear && b.salvar_perfil && String(b.perfil_nome || '').trim()) {
        await pool.query(
          `INSERT INTO isc_import_perfis (instituicao_id, nome, mapeamento, delim)
           VALUES ($1,$2,$3,$4)
           ON CONFLICT (instituicao_id, nome) DO UPDATE SET mapeamento=EXCLUDED.mapeamento, delim=EXCLUDED.delim, updated_at=now()`,
          [instId, String(b.perfil_nome).trim(), JSON.stringify(mapa), delim]);
      }

      res.send(renderShell('ISC · Prévia', html, sigla ? getTenantLogo(sigla) : undefined));
    } catch (e) { erro(res, e); }
  });

  // ── Passo 3: gravar ─────────────────────────────────────────────────────
  app.post('/isc/admin/importar/gravar', scihRequired, async (req, res) => {
    try {
      const { sigla, instId } = await resolveInst(req);
      const b = req.body || {};
      const ent = entradaParaAoA(b);
      if (!ent.texto.trim()) return res.redirect('/isc/admin/importar');
      const modo = ['plano', 'relatorio'].includes(b.modo) ? b.modo : 'auto';
      const norm = normalizaAoA(ent.aoa, modo);
      const linhas = norm.linhas;

      // MESMA guarda do passo da prévia: o mapa da colaboradora vem do PERFIL,
      // nunca do browser. Reconstruir aqui — e não confiar no que o form enviou
      // — é o que impede um POST forjado de gravar com mapeamento arbitrário.
      const podeMapear = ehMedico(req);
      let mapa = null;
      if (podeMapear && b.mapa_json) {
        try { mapa = JSON.parse(b.mapa_json); } catch { mapa = null; }
      }
      if (!mapa && b.perfil_id) {
        const { rows } = await pool.query(
          `SELECT mapeamento FROM isc_import_perfis WHERE id=$1 AND ($2::int IS NULL OR instituicao_id=$2)`,
          [Number(b.perfil_id), instId]);
        if (rows[0]) mapa = rows[0].mapeamento;
      }
      if (!mapa) mapa = adivinhaMapeamento(norm.rotulos, norm.linhas);

      const equipes = await equipesDe(instId);
      const existentes = await fichasExistentes(instId);
      const regras = b.sem_triagem === '1' ? null : await regrasDe(instId);
      // Recalcula a prévia no servidor: o que a tela mostrou é dica, não
      // autorização. Nunca confiar na classificação que veio do browser —
      // inclusive a triagem, senão dava para forçar a entrada de uma cirurgia
      // fora do recorte mexendo no HTML.
      const { itens } = montarPrevia(linhas, mapa, equipes, existentes, regras);
      const novas = itens.filter(i => i.status === 'nova');

      const aComplementar = itens.filter(i => i.status === 'complementa');

      const { rows: [lote] } = await pool.query(
        `INSERT INTO isc_import_lotes (instituicao_id, criado_por, arquivo_nome, mapeamento, total_linhas, criadas, complementadas, ignoradas)
         VALUES ($1,$2,$3,$4,$5,0,0,$6) RETURNING id`,
        [instId, b.criado_por || null, b.arquivo_nome || null, JSON.stringify(mapa),
         itens.length, itens.length - novas.length - aComplementar.length]);

      let criadas = 0;
      const ids = [];
      for (const it of novas) {
        const f = it.ficha;
        const eq = equipes.find(e => e.id === f.equipe_id) || null;
        const janelas = janelasDe({ implante: f.implante, janelas: null }, eq);
        try {
          const { rows } = await pool.query(
            `INSERT INTO isc_fichas
               (instituicao_id, paciente_nome, paciente_iniciais, paciente_dn, prontuario, atendimento,
                telefone, telefone_raw, contato_alternativo, equipe_id, especialidade, procedimento,
                cirurgiao, data_cirurgia, data_alta, implante, potencial_contaminacao, duracao_min,
                asa, antibioticoprofilaxia, janelas, observacao, telefone_presumido, cirurgia_id,
                origem, import_lote_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,'import',$25)
             RETURNING id`,
            [instId, f.paciente_nome || null, f.paciente_iniciais || null, f.paciente_dn || null,
             f.prontuario || null, f.atendimento || null, f.telefone || null, f.telefone_raw || null,
             f.contato_alternativo || null, f.equipe_id || null, f.especialidade || null,
             f.procedimento || null, f.cirurgiao || null, f.data_cirurgia, f.data_alta || null,
             f.implante === true, f.potencial_contaminacao || null, f.duracao_min ?? null,
             f.asa || null, f.antibioticoprofilaxia || null, JSON.stringify(janelas),
             f.observacao || null, f.telefone_presumido === true,
             f.cirurgia_id ? String(f.cirurgia_id) : null, lote.id]);
          ids.push(rows[0].id);
          criadas++;
        } catch (e) {
          // 23505 = corrida com outra sessão criando a mesma ficha. Ignora.
          if (e.code !== '23505') console.error('[isc-import] linha', it.linha, e.message);
        }
      }

      // Materializa o estado das fichas novas (proximo_contato_em etc.).
      // Reusa o cron de sincronização em vez de duplicar a lógica aqui.
      for (const id of ids) {
        try {
          const { rows: [f] } = await pool.query('SELECT * FROM isc_fichas WHERE id=$1', [id]);
          const eq = equipes.find(e => e.id === f.equipe_id) || null;
          const est = recomputarEstado(f, [], eq);
          await pool.query(
            `UPDATE isc_fichas SET janelas=$2, janelas_estado=$3, proxima_janela=$4,
               proximo_contato_em=$5, status_vigilancia=$6, updated_at=now() WHERE id=$1`,
            [id, JSON.stringify(est.janelas), JSON.stringify(est.janelas_estado),
             est.proxima_janela, est.proximo_contato_em, est.status_vigilancia]);
        } catch (e) { console.error('[isc-import] sync', id, e.message); }
      }

      // ── Complementação ────────────────────────────────────────────────────
      // UPDATE só nas colunas de CAMPOS_COMPLEMENTAVEIS. O nome da coluna NUNCA
      // vem de fora: é filtrado contra a whitelist antes de entrar no SQL — o
      // valor vai parametrizado, mas identificador não parametriza.
      const PERMITIDAS = new Set([...CAMPOS_COMPLEMENTAVEIS, 'telefone_raw', 'telefone_presumido']);
      let complementadas = 0;
      for (const it of aComplementar) {
        const campos = Object.entries(it.complemento.campos).filter(([k]) => PERMITIDAS.has(k));
        if (!campos.length) continue;
        try {
          const sets = campos.map(([k], i) => `${k} = $${i + 2}`);
          const vals = campos.map(([, v]) => v);
          const { rowCount } = await pool.query(
            `UPDATE isc_fichas SET ${sets.join(', ')}, updated_at = now()
              WHERE id = $1 AND ($${campos.length + 2}::int IS NULL OR instituicao_id = $${campos.length + 2})`,
            [it.complemento.id, ...vals, instId]);
          if (rowCount) complementadas++;
        } catch (e) { console.error('[isc-import] complementar ficha', it.complemento.id, e.message); }
      }

      await pool.query(
        `UPDATE isc_import_lotes SET criadas=$2, complementadas=$3, ignoradas=$4 WHERE id=$1`,
        [lote.id, criadas, complementadas, itens.length - criadas - complementadas]);

      console.log(`[isc-import] lote ${lote.id}: ${criadas} criada(s), ${complementadas} complementada(s) de ${itens.length} linha(s)`);
      res.redirect(`/isc/admin/grid?${new URLSearchParams({ inst: sigla || '', lote: String(lote.id) })}`);
    } catch (e) { erro(res, e); }
  });

  // ── Desfazer lote ───────────────────────────────────────────────────────
  // SÓ apaga ficha intocada: sem contato registrado e sem classificação.
  // Se alguém já trabalhou a ficha, o dado é dela — não do importador.
  app.post('/isc/admin/importar/lote/:id/desfazer', medicoRequired, async (req, res) => {
    try {
      const { instId } = await resolveInst(req);
      const id = Number(req.params.id);
      const { rows: [lote] } = await pool.query(
        `SELECT * FROM isc_import_lotes WHERE id=$1 AND ($2::int IS NULL OR instituicao_id=$2)`, [id, instId]);
      if (!lote) return res.status(404).send('Lote não encontrado');

      const { rowCount } = await pool.query(
        `DELETE FROM isc_fichas f
          WHERE f.import_lote_id = $1
            AND f.isc_classificacao = 'nao_avaliada'
            AND f.suspeita_isc = false
            AND NOT EXISTS (SELECT 1 FROM isc_contatos c WHERE c.ficha_id = f.id)`, [id]);
      await pool.query(`UPDATE isc_import_lotes SET desfeito_em = now() WHERE id = $1`, [id]);
      console.log(`[isc-import] lote ${id} desfeito: ${rowCount} ficha(s) removida(s)`);
      res.redirect('/isc/admin/importar');
    } catch (e) { erro(res, e); }
  });

  // ── Regras de triagem ───────────────────────────────────────────────────
  // A tela existe para a implantação escalonada não depender de deploy:
  // ampliar para o rol do CVE = adicionar linhas aqui.
  app.get('/isc/admin/triagem', medicoRequired, async (req, res) => {
    try {
      const { sigla, instId } = await resolveInst(req);
      const { rows } = await pool.query(
        `SELECT r.*, e.nome AS equipe_nome FROM isc_triagem_regras r
           LEFT JOIN isc_equipes e ON e.id = r.equipe_id
          WHERE ($1::int IS NULL OR r.instituicao_id = $1) ORDER BY r.ordem, r.id`, [instId]);
      const equipes = await equipesDe(instId);
      const eqOpts = (sel) => `<option value="">— sem equipe —</option>` +
        equipes.map(e => `<option value="${e.id}" ${String(sel) === String(e.id) ? 'selected' : ''}>${safe(e.nome)}</option>`).join('');

      const linha = (t = {}) => `
        <form method="post" action="/isc/admin/triagem" class="card2" style="border-left:3px solid ${t.id ? (t.vigiar === false ? '#c0392b' : '#2bb673') : '#dadce0'}">
          <input type="hidden" name="inst" value="${safe(sigla || '')}">
          ${t.id ? `<input type="hidden" name="id" value="${t.id}">` : ''}
          <div class="ff">
            <div><label class="l">Nome da regra</label><input name="nome" value="${safe(t.nome || '')}" required></div>
            <div><label class="l">Ordem (menor roda antes)</label><input type="number" name="ordem" value="${t.ordem ?? 100}"></div>
            <div><label class="l">Equipe de destino</label><select name="equipe_id">${eqOpts(t.equipe_id)}</select></div>
            <div><label class="l">Código CVE</label><input name="codigo_cve" value="${safe(t.codigo_cve || '')}" placeholder="CNEURO"></div>
          </div>
          <div style="margin-top:10px"><label class="l">Procedimento contém (separe por | · casa palavra inteira, sem acento)</label>
            <input name="match_proc" value="${safe(t.match_proc || '')}" placeholder="craniotomia|intracraniano|coluna"></div>
          <div style="margin-top:8px"><label class="l">…mas NÃO contém</label>
            <input name="nao_match_proc" value="${safe(t.nao_match_proc || '')}" placeholder="infiltracao|bloqueio"></div>
          <div class="ff" style="margin-top:8px">
            <div><label class="l">Cirurgião contém</label><input name="match_cirurgiao" value="${safe(t.match_cirurgiao || '')}" placeholder="Sobrenome"></div>
            <div><label class="l">Tipo de anestesia contém</label><input name="match_tipo" value="${safe(t.match_tipo || '')}" placeholder="Geral"></div>
          </div>
          <div style="display:flex;gap:18px;align-items:center;margin-top:12px;flex-wrap:wrap">
            <label class="chk"><input type="checkbox" name="vigiar" value="1" ${t.id ? (t.vigiar !== false ? 'checked' : '') : 'checked'}> <b>Entra na vigilância</b> (desmarque para EXCLUIR)</label>
            <label class="chk"><input type="checkbox" name="ativo" value="1" ${t.id ? (t.ativo ? 'checked' : '') : 'checked'}> Ativa</label>
            <select name="implante" class="fil" style="width:auto;padding:7px 10px;border:1px solid #dadce0;border-radius:7px">
              <option value="" ${t.implante == null ? 'selected' : ''}>Implante: não definir</option>
              <option value="1" ${t.implante === true ? 'selected' : ''}>Implante: sim (vigiar 90d)</option>
              <option value="0" ${t.implante === false ? 'selected' : ''}>Implante: não</option>
            </select>
            <button class="btn">${t.id ? 'Salvar' : 'Criar regra'}</button>
            ${t.id ? `<button class="btn btn-sec btn-red" style="background:#fff;color:#c0392b;border:1px solid #f0c0bb" name="excluir" value="1" onclick="return confirm('Excluir a regra &quot;${safe(t.nome)}&quot;?')">Excluir</button>` : ''}
          </div>
        </form>`;

      const html = `<div class="isc">
        ${chrome(sigla, 'Regras de triagem', 'O que do mapa cirúrgico entra na vigilância', true)}
        <div class="card2" style="background:#f8f9fa">
          <b style="font-size:13px">Como funciona</b>
          <p class="sub" style="margin:6px 0 0;line-height:1.6">
            A <b>primeira regra que casa vence</b> — por isso as exclusões têm ordem menor. Cada termo casa como
            <b>palavra inteira</b>, ignorando acento: <code>raque</code> não pega <i>TRAQUEOSTOMIA</i>.
            Cirurgia que não casa com nenhuma regra fica <b>fora do recorte</b>: aparece na prévia e não vira ficha.
            <br>Para ampliar a vigilância (rol do CVE), adicione regras aqui — não precisa de deploy.
          </p>
        </div>
        ${rows.map(t => linha(t)).join('')}
        <h2 style="font-size:15px;margin:22px 0 10px">Nova regra</h2>
        ${linha()}
      </div>${CSS}`;
      res.send(renderShell('ISC · Triagem', html, sigla ? getTenantLogo(sigla) : undefined));
    } catch (e) { erro(res, e); }
  });

  app.post('/isc/admin/triagem', medicoRequired, async (req, res) => {
    try {
      const { instId } = await resolveInst(req);
      const b = req.body || {};
      const impl = b.implante === '1' ? true : b.implante === '0' ? false : null;
      const bool = v => v === '1' || v === 'on' || v === true;
      if (b.excluir && b.id) {
        await pool.query(`DELETE FROM isc_triagem_regras WHERE id=$1 AND ($2::int IS NULL OR instituicao_id=$2)`,
          [Number(b.id), instId]);
        return res.redirect('/isc/admin/triagem');
      }
      const vals = [b.nome, Number(b.ordem || 100), bool(b.ativo), b.match_proc || null,
                    b.nao_match_proc || null, b.match_cirurgiao || null, b.match_tipo || null,
                    bool(b.vigiar), b.equipe_id ? Number(b.equipe_id) : null, b.codigo_cve || null, impl];
      if (b.id) {
        await pool.query(
          `UPDATE isc_triagem_regras SET nome=$2, ordem=$3, ativo=$4, match_proc=$5, nao_match_proc=$6,
             match_cirurgiao=$7, match_tipo=$8, vigiar=$9, equipe_id=$10, codigo_cve=$11, implante=$12,
             updated_at=now()
           WHERE id=$1 AND ($13::int IS NULL OR instituicao_id=$13)`, [Number(b.id), ...vals, instId]);
      } else {
        await pool.query(
          `INSERT INTO isc_triagem_regras
             (instituicao_id, nome, ordem, ativo, match_proc, nao_match_proc, match_cirurgiao, match_tipo,
              vigiar, equipe_id, codigo_cve, implante)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
           ON CONFLICT (instituicao_id, nome) DO NOTHING`, [instId, ...vals]);
      }
      res.redirect('/isc/admin/triagem');
    } catch (e) { erro(res, e); }
  });

  // ── Regras de ALERTA (flag de possível ISC conforme as respostas) ─────────
  // Ato médico: definir o que conta como suspeita de ISC alimenta o trabalho de
  // classificação. Some para a colaboradora. Combinação E/OU, liga/desliga,
  // escopo por equipe. TODAS as regras são editáveis — as regras clínicas
  // mínimas foram semeadas no banco no primeiro boot e podem ser ajustadas ou
  // apagadas como qualquer outra.
  function opcoesDoCampo(key) {
    const c = CHECKLIST.find(x => x.key === key);
    if (!c) return ['Sim', 'Não'];
    if (c.tipo === 'sim_nao') return ['Sim', 'Não'];
    if (c.tipo === 'multi' && Array.isArray(c.opcoes)) return c.opcoes;
    return ['Sim', 'Não'];
  }

  app.get('/isc/admin/alertas', medicoRequired, async (req, res) => {
    try {
      const { sigla, instId } = await resolveInst(req);
      const { rows } = await pool.query(
        `SELECT * FROM isc_alerta_regras WHERE ($1::int IS NULL OR instituicao_id=$1) ORDER BY ordem, id`, [instId]);
      const equipes = await equipesDe(instId);

      // Dados para o editor dinâmico no browser (campos → opções válidas).
      const campos = CHECKLIST.map(c => ({ key: c.key, label: c.label, opcoes: opcoesDoCampo(c.key) }));

      const escopoTxt = (r) => {
        const eqs = Array.isArray(r.equipe_ids) ? r.equipe_ids : [];
        if (!eqs.length) return 'todas as equipes';
        return equipes.filter(e => eqs.map(Number).includes(e.id)).map(e => e.nome).join(', ') || 'equipes removidas';
      };
      const gruposTxt = (r) => (Array.isArray(r.grupos) ? r.grupos : []).map(g =>
        '(' + g.map(c => {
          const lbl = (CHECKLIST.find(x => x.key === c.campo) || {}).label || c.campo;
          return `${safe(lbl)} = ${safe((Array.isArray(c.valores) ? c.valores : [c.valores]).join(' ou '))}`;
        }).join(' <b>E</b> ') + ')').join(' <b>OU</b> ');

      const regraCard = (r) => `
        <div class="card2" style="border-left:3px solid ${r.ativo ? '#e85d5d' : '#c9ccd1'}">
          <div style="display:flex;justify-content:space-between;gap:10px;align-items:baseline">
            <b>${safe(r.nome)}</b>
            <span class="sub">${r.ativo ? '' : 'desligada · '}${safe(escopoTxt(r))}</span>
          </div>
          <p class="sub" style="margin:6px 0 10px;line-height:1.6">Acende quando: ${gruposTxt(r) || '<i>sem condições</i>'}</p>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <form method="post" action="/isc/admin/alertas/${r.id}/toggle" style="display:inline">
              <input type="hidden" name="inst" value="${safe(sigla || '')}">
              <button class="btn btn-sec" style="padding:4px 10px;font-size:12px">${r.ativo ? 'Desligar' : 'Ligar'}</button></form>
            <button class="btn btn-sec" style="padding:4px 10px;font-size:12px" onclick="editar(${r.id})">Editar</button>
            <form method="post" action="/isc/admin/alertas/${r.id}/excluir" style="display:inline" onsubmit="return confirm('Excluir a regra &quot;${safe(r.nome)}&quot;?')">
              <input type="hidden" name="inst" value="${safe(sigla || '')}">
              <button class="btn btn-sec" style="padding:4px 10px;font-size:12px;background:#fff;color:#c0392b;border:1px solid #f0c0bb">Excluir</button></form>
          </div>
          <script type="application/json" id="regra-${r.id}">${JSON.stringify({ nome: r.nome, grupos: r.grupos || [], equipe_ids: r.equipe_ids || [], ordem: r.ordem })}</script>
        </div>`;

      const html = `<div class="isc">
        ${chrome(sigla, 'Regras de alerta', 'Quando as respostas do paciente acendem suspeita de ISC', true)}
        <div class="card2" style="background:#f8f9fa">
          <b style="font-size:13px">Como funciona</b>
          <p class="sub" style="margin:6px 0 0;line-height:1.6">
            Uma regra acende o alerta quando <b>algum grupo</b> casa. Dentro de um grupo, <b>todas</b> as condições
            precisam casar (E); entre grupos, basta <b>uma</b> (OU). Escopo vazio = todas as equipes.
            Todas as regras são ajustáveis. As regras clínicas iniciais já vêm carregadas — edite ou apague à vontade.
          </p>
        </div>

        <h2 style="font-size:15px;margin:18px 0 8px">Suas regras</h2>
        ${rows.map(regraCard).join('') || '<p class="sub" style="color:#c0392b">Nenhuma regra ativa — nenhuma resposta vai acender alerta. Crie ao menos uma abaixo.</p>'}

        <h2 style="font-size:15px;margin:22px 0 8px">Nova regra <span class="sub" id="modo-edicao"></span></h2>
        <div class="card2">
          <form method="post" action="/isc/admin/alertas" id="fr">
            <input type="hidden" name="inst" value="${safe(sigla || '')}">
            <input type="hidden" name="id" id="rid">
            <input type="hidden" name="grupos" id="grupos-json">
            <div class="ff">
              <div><label class="l">Nome da regra</label><input name="nome" id="nome" required placeholder="Febre + secreção purulenta"></div>
              <div><label class="l">Ordem</label><input name="ordem" id="ordem" type="number" value="100"></div>
            </div>
            <div style="margin-top:10px">
              <label class="l">Equipes (nenhuma marcada = todas)</label>
              <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:4px">
                ${equipes.map(e => `<label class="chk"><input type="checkbox" class="eq" value="${e.id}"> ${safe(e.nome)}</label>`).join('')}
              </div>
            </div>
            <div style="margin-top:14px">
              <label class="l">Condições</label>
              <p class="sub" style="margin:2px 0 8px">Cada <b>grupo</b> é um E. Adicione grupos para fazer OU.</p>
              <div id="grupos"></div>
              <button type="button" class="btn btn-sec" style="margin-top:8px" onclick="addGrupo()">+ Grupo (OU)</button>
            </div>
            <div style="margin-top:14px;display:flex;gap:8px">
              <button class="btn" type="submit">Salvar regra</button>
              <button class="btn btn-sec" type="button" onclick="resetForm()">Limpar</button>
            </div>
          </form>
        </div>

      </div>
      <script>
        const CAMPOS = ${JSON.stringify(campos)};
        function optsCampo(sel){ return CAMPOS.map(c=>'<option value="'+c.key+'"'+(c.key===sel?' selected':'')+'>'+c.label+'</option>').join(''); }
        function optsValor(campoKey, sel){
          const c=CAMPOS.find(x=>x.key===campoKey)||CAMPOS[0];
          const vals=Array.isArray(sel)?sel:(sel?[sel]:[]);
          return c.opcoes.map(o=>'<option value="'+o.replaceAll('"','&quot;')+'"'+(vals.includes(o)?' selected':'')+'>'+o+'</option>').join('');
        }
        function condRow(cond){
          const k=cond&&cond.campo||CAMPOS[0].key;
          const div=document.createElement('div');
          div.className='cond'; div.style.cssText='display:flex;gap:6px;margin:4px 0;align-items:center';
          div.innerHTML='<select class="c-campo" style="flex:1;padding:6px;border:1px solid #dadce0;border-radius:6px">'+optsCampo(k)+'</select>'
            +'<span class="sub">=</span>'
            +'<select class="c-valor" multiple size="1" style="flex:1;padding:6px;border:1px solid #dadce0;border-radius:6px">'+optsValor(k, cond&&cond.valores)+'</select>'
            +'<button type="button" class="btn btn-sec c-del" style="padding:2px 8px">×</button>';
          div.querySelector('.c-campo').addEventListener('change',function(){
            div.querySelector('.c-valor').innerHTML=optsValor(this.value);
          });
          div.querySelector('.c-del').addEventListener('click',function(){ div.remove(); });
          return div;
        }
        function grupoBox(grupo){
          const box=document.createElement('div');
          box.className='grupo'; box.style.cssText='border:1px solid #e8eaed;border-radius:8px;padding:10px;margin:6px 0;background:#fafbfc';
          box.innerHTML='<div class="sub" style="margin-bottom:4px">Grupo (todas as condições = E)</div>';
          const conds=document.createElement('div'); conds.className='conds'; box.appendChild(conds);
          (grupo&&grupo.length?grupo:[null]).forEach(c=>conds.appendChild(condRow(c)));
          const add=document.createElement('button'); add.type='button'; add.className='btn btn-sec';
          add.style.cssText='padding:2px 8px;margin-top:4px'; add.textContent='+ Condição (E)';
          add.onclick=function(){ conds.appendChild(condRow()); };
          box.appendChild(add);
          return box;
        }
        function addGrupo(grupo){ document.getElementById('grupos').appendChild(grupoBox(grupo)); }
        function coletar(){
          return [...document.querySelectorAll('#grupos .grupo')].map(g=>
            [...g.querySelectorAll('.cond')].map(c=>({
              campo:c.querySelector('.c-campo').value,
              valores:[...c.querySelector('.c-valor').selectedOptions].map(o=>o.value)
            })).filter(c=>c.valores.length)
          ).filter(g=>g.length);
        }
        function resetForm(){
          document.getElementById('rid').value=''; document.getElementById('nome').value='';
          document.getElementById('ordem').value='100'; document.getElementById('grupos').innerHTML='';
          document.querySelectorAll('.eq').forEach(c=>c.checked=false);
          document.getElementById('modo-edicao').textContent=''; addGrupo();
        }
        function editar(id){
          const d=JSON.parse(document.getElementById('regra-'+id).textContent);
          document.getElementById('rid').value=id; document.getElementById('nome').value=d.nome;
          document.getElementById('ordem').value=d.ordem||100;
          document.querySelectorAll('.eq').forEach(c=>{ c.checked=(d.equipe_ids||[]).map(String).includes(c.value); });
          document.getElementById('grupos').innerHTML='';
          (d.grupos&&d.grupos.length?d.grupos:[null]).forEach(g=>addGrupo(g));
          document.getElementById('modo-edicao').textContent='· editando regra #'+id;
          document.getElementById('nome').scrollIntoView({behavior:'smooth'});
        }
        document.getElementById('fr').addEventListener('submit',function(e){
          const g=coletar();
          if(!g.length){ e.preventDefault(); alert('Adicione ao menos uma condição.'); return; }
          document.getElementById('grupos-json').value=JSON.stringify(g);
          const eqs=[...document.querySelectorAll('.eq:checked')].map(c=>c.value);
          let h=document.getElementById('fr').querySelector('input[name=equipe_ids]');
          if(!h){ h=document.createElement('input'); h.type='hidden'; h.name='equipe_ids'; document.getElementById('fr').appendChild(h); }
          h.value=JSON.stringify(eqs);
        });
        resetForm();
      </script>${CSS}`;
      res.send(renderShell('ISC · Regras de alerta', html, sigla ? getTenantLogo(sigla) : undefined));
    } catch (e) { erro(res, e); }
  });

  app.post('/isc/admin/alertas', medicoRequired, async (req, res) => {
    try {
      const { sigla, instId } = await resolveInst(req);
      const b = req.body || {};
      let grupos = [], equipe_ids = [];
      try { grupos = JSON.parse(b.grupos || '[]'); } catch { grupos = []; }
      try { equipe_ids = JSON.parse(b.equipe_ids || '[]'); } catch { equipe_ids = []; }

      // Saneia contra o CHECKLIST: campo e valores têm de existir. Não confia no
      // browser — condição forjada com campo inexistente nunca casaria, mas
      // guardar lixo no banco confunde a próxima edição.
      const validKeys = new Set(CHECKLIST.map(c => c.key));
      grupos = (Array.isArray(grupos) ? grupos : [])
        .map(g => (Array.isArray(g) ? g : []).filter(c => c && validKeys.has(c.campo) && Array.isArray(c.valores) && c.valores.length)
          .map(c => ({ campo: c.campo, valores: c.valores.map(String) })))
        .filter(g => g.length);
      equipe_ids = (Array.isArray(equipe_ids) ? equipe_ids : []).map(Number).filter(Number.isInteger);
      const nome = String(b.nome || '').trim();
      if (!nome || !grupos.length) {
        return res.status(400).send(renderShell('ISC · Alerta', `<div class="card">
          <h1>Regra incompleta</h1><p class="mut">Informe um nome e ao menos uma condição.</p>
          <a href="/isc/admin/alertas">← Voltar</a></div>`));
      }
      const ordem = Number.isFinite(Number(b.ordem)) ? Number(b.ordem) : 100;
      const gj = JSON.stringify(grupos), ej = JSON.stringify(equipe_ids);

      if (b.id) {
        await pool.query(
          `UPDATE isc_alerta_regras SET nome=$2, grupos=$3, equipe_ids=$4, ordem=$5, updated_at=now()
            WHERE id=$1 AND ($6::int IS NULL OR instituicao_id=$6)`,
          [Number(b.id), nome, gj, ej, ordem, instId]);
      } else {
        await pool.query(
          `INSERT INTO isc_alerta_regras (instituicao_id, nome, grupos, equipe_ids, ordem)
           VALUES ($1,$2,$3,$4,$5) ON CONFLICT (instituicao_id, nome) DO UPDATE
             SET grupos=EXCLUDED.grupos, equipe_ids=EXCLUDED.equipe_ids, ordem=EXCLUDED.ordem, updated_at=now()`,
          [instId, nome, gj, ej, ordem]);
      }
      res.redirect(`/isc/admin/alertas?${new URLSearchParams({ inst: sigla || '' })}`);
    } catch (e) { erro(res, e); }
  });

  app.post('/isc/admin/alertas/:id/toggle', medicoRequired, async (req, res) => {
    try {
      const { sigla, instId } = await resolveInst(req);
      await pool.query(
        `UPDATE isc_alerta_regras SET ativo = NOT ativo, updated_at=now()
          WHERE id=$1 AND ($2::int IS NULL OR instituicao_id=$2)`, [Number(req.params.id), instId]);
      res.redirect(`/isc/admin/alertas?${new URLSearchParams({ inst: sigla || '' })}`);
    } catch (e) { erro(res, e); }
  });

  app.post('/isc/admin/alertas/:id/excluir', medicoRequired, async (req, res) => {
    try {
      const { sigla, instId } = await resolveInst(req);
      await pool.query(
        `DELETE FROM isc_alerta_regras WHERE id=$1 AND ($2::int IS NULL OR instituicao_id=$2)`,
        [Number(req.params.id), instId]);
      res.redirect(`/isc/admin/alertas?${new URLSearchParams({ inst: sigla || '' })}`);
    } catch (e) { erro(res, e); }
  });

  console.log('[isc-import-routes] rotas de importação registradas');
}
