// ════════════════════════════════════════════════════════════════════════════
//  ADESÃO AOS PARECERES  —  /atb/admin/adesao
//
//  Tela dedicada (SCIH / adminRequired) para registrar a adesão aos pareceres
//  NEGATIVOS ("Não") emitidos há mais de 3 dias. Base dos indicadores mensais.
//
//  Para cada ficha da worklist, o SCIH preenche inline:
//    • Desfecho da adesão: Mantido | Suspenso_troca | Suspenso_alta |
//      Suspenso_semATB | Suspenso_obito
//    • ATB de troca (só quando Suspenso_troca)
//
//  Worklist = veredito "Não"  E  parecer há > 3 dias, escopada por mês
//  (padrão: mês atual; seletor permite fechar meses anteriores).
//
//  Integração em atb-routes.js:
//    import { ensureAdesaoSchema, registerAdesaoRoutes } from './atb-adesao-routes.js';
//    // no boot:               ensureAdesaoSchema(pool).catch(...);
//    // em registerAtbRoutes:  registerAdesaoRoutes(app, pool, adminRequired);
//  Link na grade (admin): <a href="/atb/admin/adesao">Adesão</a>
//
//  A tabulação dos indicadores é um esqueleto (contagem por desfecho) — será
//  refinada depois conforme orientação.
// ════════════════════════════════════════════════════════════════════════════

export const ADESAO_DESFECHOS = ['Mantido', 'Suspenso_troca', 'Suspenso_alta', 'Suspenso_semATB', 'Suspenso_obito'];

// lista de ATB de troca (alfabética, com Levofloxacina incluída)
export const ATB_TROCA = [
  'Amicacina', 'Amoxicilina/Clavulanato', 'Ampicilina', 'Ampicilina/Sulbactam',
  'Cefazolina', 'Cefepime', 'Ceftriaxone', 'Ciprofloxacina', 'Fosfomicina',
  'Gentamicina', 'Levofloxacina', 'Meropenem', 'Oxacilina', 'Piperacilina/Tazobactam',
  'Sulfametoxazol/Trimetoprim', 'Teicoplanina', 'Vancomicina',
];

// Escala de espectro (amplitude) — usada para classificar descalonamento vs escalonamento.
// Gram-positivos entram na mesma régua: Oxacilina(2) < Vanco/Teico/Dapto(3).
const ESPECTRO = {
  'Ampicilina': 1, 'Cefazolina': 1, 'Oxacilina': 1,
  'Amoxicilina/Clavulanato': 2, 'Ampicilina/Sulbactam': 2, 'Ciprofloxacina': 2,
  'Levofloxacina': 2, 'Fosfomicina': 2, 'Gentamicina': 2, 'Sulfametoxazol/Trimetoprim': 2,
  'Ceftriaxone': 3, 'Vancomicina': 3, 'Teicoplanina': 3, 'Daptomicina': 3,
  'Cefepime': 4, 'Piperacilina/Tazobactam': 4,
  'Meropenem': 5, 'Amicacina': 5,
  'Polimixina B': 6, 'Polimixina E (colestimetato)': 6, 'Tigeciclina': 6,
};
const ANTIFUNGICOS = new Set(['Anfotericina B', 'Micafungina']);

// Classifica a adesão de uma ficha. Retorna um código:
//   'adesao' | 'nao_adesao' | 'alta' | 'obito' | 'revisar' | 'pendente'
export function classificarAdesao(desfecho, solicitados, troca) {
  if (!desfecho) return 'pendente';
  if (desfecho === 'Mantido') return 'nao_adesao';
  if (desfecho === 'Suspenso_semATB') return 'adesao';
  if (desfecho === 'Suspenso_alta') return 'alta';
  if (desfecho === 'Suspenso_obito') return 'obito';
  if (desfecho === 'Suspenso_troca') {
    // não classificável pela régua → revisar manualmente
    if (!troca || ANTIFUNGICOS.has(troca) || ESPECTRO[troca] == null) return 'revisar';
    const sol = (solicitados || []);
    if (sol.some(a => ANTIFUNGICOS.has(a))) return 'revisar';
    const tiers = sol.map(a => ESPECTRO[a]).filter(t => t != null);
    if (!tiers.length) return 'revisar';            // solicitado só "NÃO PADRONIZADO"/não mapeado
    const solTier = Math.max(...tiers);             // compara com o mais amplo solicitado
    return ESPECTRO[troca] < solTier ? 'adesao' : 'nao_adesao';  // descalonamento : (escalonamento|mesmo nível)
  }
  return 'revisar';
}

const ADESAO_LABEL = {
  adesao: 'Adesão', nao_adesao: 'Não adesão', alta: 'Alta <72h',
  obito: 'Óbito', revisar: 'Revisar', pendente: 'A avaliar',
};

function _safe(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
const _arr = v => Array.isArray(v) ? v : (v == null ? [] : (typeof v === 'string'
  ? (() => { try { const x = JSON.parse(v); return Array.isArray(x) ? x : []; } catch { return []; } })()
  : []));

export async function ensureAdesaoSchema(pool) {
  await pool.query(`ALTER TABLE atb_fichas ADD COLUMN IF NOT EXISTS adesao_desfecho TEXT`);
  await pool.query(`ALTER TABLE atb_fichas ADD COLUMN IF NOT EXISTS adesao_troca_atb TEXT`);
  await pool.query(`ALTER TABLE atb_fichas ADD COLUMN IF NOT EXISTS adesao_por INTEGER REFERENCES users(id)`);
  await pool.query(`ALTER TABLE atb_fichas ADD COLUMN IF NOT EXISTS adesao_em TIMESTAMPTZ`);
}

// data de referência do parecer (emissão; cai pra data da ficha nas históricas)
const DATA_PARECER_SQL = `COALESCE(f.parecer_emitido_at, f.jotform_created_at, f.data_referencia, f.created_at)`;

function _selDesfecho(id, sel) {
  const opts = ['<option value="">— desfecho —</option>']
    .concat(ADESAO_DESFECHOS.map(o => `<option value="${o}" ${o === sel ? 'selected' : ''}>${o}</option>`)).join('');
  return `<select class="ad-desf" data-id="${id}">${opts}</select>`;
}
function _selTroca(id, sel, ativo) {
  const opts = ['<option value="">— troca —</option>']
    .concat(ATB_TROCA.map(o => `<option value="${_safe(o)}" ${o === sel ? 'selected' : ''}>${_safe(o)}</option>`)).join('');
  return `<select class="ad-troca" data-id="${id}" ${ativo ? '' : 'disabled'}>${opts}</select>`;
}

function paginaAdesao(rows, mes, somentePendentes) {
  const dt = d => d ? new Date(d).toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit', year: 'numeric' }) : '—';
  const tresDiasAtras = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000);

  // ── INDICADORES (sobre TODOS os negativos do mês) ──
  const c = { adesao: 0, nao_adesao: 0, alta: 0, obito: 0, revisar: 0, a_avaliar: 0, aguardando: 0 };
  rows.forEach(f => {
    const ehVelho = f.data_parecer && new Date(f.data_parecer) <= tresDiasAtras;
    const cl = classificarAdesao(f.adesao_desfecho, _arr(f.atb_solicitado), f.adesao_troca_atb);
    if (cl === 'pendente') { if (ehVelho) c.a_avaliar++; else c.aguardando++; }
    else c[cl]++;
  });
  const total = rows.length;
  const denom = c.adesao + c.nao_adesao;                 // avaliáveis resolvidos
  const taxa = denom ? Math.round((c.adesao / denom) * 1000) / 10 : null;

  const card = (rotulo, valor, cor, destaque) =>
    `<div class="ind ${destaque ? 'ind-d' : ''}" ${cor ? `style="border-left-color:${cor}"` : ''}>
       <div class="iv">${valor}</div><div class="il">${rotulo}</div></div>`;
  const painel = `
    ${card('Negativos no mês', total, '#5f6368')}
    ${card('Adesão' + (taxa != null ? ` · ${taxa}%` : ''), c.adesao, '#1a8a5a', true)}
    ${card('Não adesão', c.nao_adesao, '#c0392b')}
    ${card('Alta &lt;72h', c.alta, '#d98a3d', true)}
    ${card('Óbito', c.obito, '#8a1414')}
    ${card('Revisar', c.revisar, '#7a5cc0')}
    ${card('A avaliar', c.a_avaliar, '#b0b6bf')}
    ${card('Aguardando 72h', c.aguardando, '#cfd4da')}`;

  // ── WORKLIST (linhas do mês; <3d aguardam; toggle "só pendentes") ──
  const sitInfo = { adesao: ['Adesão', '#1a8a5a'], nao_adesao: ['Não adesão', '#c0392b'],
    alta: ['Alta &lt;72h', '#d98a3d'], obito: ['Óbito', '#8a1414'], revisar: ['Revisar', '#7a5cc0'] };

  const linhas = rows.filter(f => !somentePendentes || !f.adesao_desfecho).map(f => {
    const nome = f.paciente_nome || f.paciente_nome_raw || '—';
    const atb = _arr(f.atb_solicitado).join(', ');
    const ehTroca = f.adesao_desfecho === 'Suspenso_troca';
    const ehVelho = f.data_parecer && new Date(f.data_parecer) <= tresDiasAtras;
    const cl = classificarAdesao(f.adesao_desfecho, _arr(f.atb_solicitado), f.adesao_troca_atb);
    let situacao;
    if (cl === 'pendente') situacao = ehVelho
      ? '<span class="sit" style="color:#5f6368">A avaliar</span>'
      : '<span class="sit" style="color:#b0b6bf">Aguardando 72h</span>';
    else { const [lbl, cor] = sitInfo[cl] || [ADESAO_LABEL[cl], '#5f6368']; situacao = `<span class="sit" style="color:${cor}">${lbl}</span>`; }

    const campos = ehVelho
      ? `<td>${_selDesfecho(f.id, f.adesao_desfecho || '')}</td><td>${_selTroca(f.id, f.adesao_troca_atb || '', ehTroca)}</td>`
      : `<td colspan="2" class="aguard">aguardando 72h</td>`;

    return `<tr data-id="${f.id}">
      <td class="dt">${dt(f.data_parecer)}</td>
      <td><a href="/atb/admin/ficha/${f.id}" class="nome">${_safe(nome)}</a></td>
      <td>${_safe(f.prontuario || '')}</td>
      <td>${_safe(f.setor || '')}</td>
      <td class="atb">${_safe(atb)}</td>
      ${campos}
      <td>${situacao}</td>
      <td class="acao"><a href="/atb/admin/parecer/${f.id}/imagem" target="_blank" title="Imagem do parecer">🖼️</a></td>
    </tr>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="pt-BR"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Adesão aos pareceres</title>
<style>
  :root{--azul:#00469e;--azul-claro:#e6eef8;--borda:#d8dee6;--fundo:#f4f6f9;--tinta:#202124;--mut:#5f6368}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--fundo);color:var(--tinta);font-size:13px}
  .cab{background:#fff;border-bottom:2px solid var(--azul);padding:14px 22px;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
  .cab h1{font-size:17px;color:var(--azul)}
  .cab a{font-size:13px;color:var(--azul);text-decoration:none}
  .controles{display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding:12px 22px;background:#fff;border-bottom:1px solid var(--borda)}
  .controles label{font-size:12px;color:var(--mut)}
  .controles input,.controles select{padding:7px 10px;border:1px solid var(--borda);border-radius:7px;font-size:13px;font-family:inherit}
  .painel{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;padding:14px 22px}
  .ind{background:#fff;border:1px solid var(--borda);border-left:4px solid var(--mut);border-radius:8px;padding:10px 14px}
  .ind-d{box-shadow:0 1px 6px rgba(0,0,0,.06)}
  .ind .iv{font-size:22px;font-weight:700;color:var(--tinta)}
  .ind .il{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.03em;margin-top:2px}
  .sit{font-size:12px;font-weight:600}
  .aguard{color:#b0b6bf;font-size:12px;font-style:italic}
  @media(max-width:820px){.painel{grid-template-columns:repeat(2,1fr)}}
  .wrap{padding:0 16px 60px}
  table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--borda);border-radius:10px;overflow:hidden}
  th{background:#fff;color:var(--mut);text-align:left;font-size:11px;font-weight:600;padding:10px 12px;border-bottom:1px solid var(--borda);white-space:nowrap}
  td{padding:8px 12px;border-bottom:1px solid #f0f1f3;vertical-align:middle}
  tr:hover td{background:#fafbfc}
  td.dt{white-space:nowrap;color:var(--mut)}
  td.atb{max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .nome{font-weight:600;color:var(--tinta);text-decoration:none}
  td select{padding:6px 8px;border:1px solid var(--borda);border-radius:7px;font-size:12px;font-family:inherit;background:#fafbfc;max-width:200px}
  td select:disabled{opacity:.5;background:#f0f1f3}
  td.acao a{text-decoration:none;font-size:15px}
  .vazio{padding:30px;text-align:center;color:var(--mut)}
  .saved{outline:2px solid #1a8a5a55}
</style></head>
<body>
  <div class="cab">
    <h1>Adesão aos pareceres</h1>
    <a href="/atb/admin/grid">← voltar à grade</a>
  </div>
  <form class="controles" method="GET" action="/atb/admin/adesao">
    <label>Mês <input type="month" name="mes" value="${_safe(mes)}" onchange="this.form.submit()"></label>
    <label><input type="checkbox" name="status" value="pendente" ${somentePendentes ? 'checked' : ''} onchange="this.form.submit()"> só pendentes</label>
    <a href="/atb/admin/adesao.csv?mes=${encodeURIComponent(mes)}" style="margin-left:auto">⬇ CSV do mês</a>
  </form>
  <div class="painel">${painel}</div>
  <div class="wrap">
    <table>
      <thead><tr>
        <th>Data parecer</th><th>Paciente</th><th>Prontuário</th><th>Setor</th>
        <th>ATB solicitado</th><th>Desfecho da adesão</th><th>ATB de troca</th><th>Situação</th><th></th>
      </tr></thead>
      <tbody>${linhas || `<tr><td colspan="9" class="vazio">Nenhum parecer negativo neste mês.</td></tr>`}</tbody>
    </table>
  </div>

  <script>
  (function(){
    function salvar(tr){
      var id = tr.getAttribute('data-id');
      var desf = tr.querySelector('.ad-desf');
      var troca = tr.querySelector('.ad-troca');
      var ehTroca = desf.value === 'Suspenso_troca';
      troca.disabled = !ehTroca;
      if(!ehTroca) troca.value = '';
      var body = new URLSearchParams({ desfecho: desf.value, troca: troca.value });
      fetch('/atb/admin/api/adesao/' + id, {
        method:'POST', headers:{ 'Content-Type':'application/x-www-form-urlencoded' }, body: body.toString()
      }).then(function(r){ return r.json(); }).then(function(j){
        if(j && j.ok){ tr.classList.add('saved'); setTimeout(function(){ tr.classList.remove('saved'); }, 700); }
      }).catch(function(){});
    }
    document.querySelector('tbody').addEventListener('change', function(ev){
      var sel = ev.target;
      if(sel.classList.contains('ad-desf') || sel.classList.contains('ad-troca')){
        salvar(sel.closest('tr'));
      }
    });
  })();
  </script>
</body></html>`;
}

async function buscarNegativosMes(pool, ano, m) {
  const { rows } = await pool.query(`
    SELECT f.id, f.paciente_nome, f.paciente_nome_raw, f.prontuario, f.setor,
           f.atb_solicitado, f.adesao_desfecho, f.adesao_troca_atb,
           ${DATA_PARECER_SQL} AS data_parecer
    FROM atb_fichas f
    WHERE jsonb_typeof(f.recomendacao_scih)='array'
      AND f.recomendacao_scih @> '["Não"]'::jsonb
      AND EXTRACT(YEAR FROM ${DATA_PARECER_SQL}) = $1
      AND EXTRACT(MONTH FROM ${DATA_PARECER_SQL}) = $2
    ORDER BY ${DATA_PARECER_SQL} DESC`, [ano, m]);
  return rows;
}

export function registerAdesaoRoutes(app, pool, adminRequired) {

  app.get('/atb/admin/adesao', adminRequired, async (req, res) => {
    try {
      const agora = new Date();
      const mesAtual = agora.getFullYear() + '-' + String(agora.getMonth() + 1).padStart(2, '0');
      const mes = /^\d{4}-\d{2}$/.test(req.query.mes || '') ? req.query.mes : mesAtual;
      const [ano, m] = mes.split('-').map(Number);
      const somentePendentes = req.query.status === 'pendente';
      const rows = await buscarNegativosMes(pool, ano, m);

      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(paginaAdesao(rows, mes, somentePendentes));
    } catch (e) {
      console.error('[atb] adesao page error:', e.message);
      res.status(500).send('Erro: ' + _safe(e.message));
    }
  });

  app.get('/atb/admin/adesao.csv', adminRequired, async (req, res) => {
    try {
      const agora = new Date();
      const mesAtual = agora.getFullYear() + '-' + String(agora.getMonth() + 1).padStart(2, '0');
      const mes = /^\d{4}-\d{2}$/.test(req.query.mes || '') ? req.query.mes : mesAtual;
      const [ano, m] = mes.split('-').map(Number);
      const rows = await buscarNegativosMes(pool, ano, m);

      const esc = v => { const s = String(v ?? ''); return /[",;\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
      const dt = d => d ? new Date(d).toLocaleDateString('pt-BR') : '';
      const linhas = [['Data parecer', 'Paciente', 'Prontuário', 'Setor', 'ATB solicitado', 'Desfecho', 'ATB troca', 'Situação'].join(';')];
      rows.forEach(f => {
        const cl = classificarAdesao(f.adesao_desfecho, _arr(f.atb_solicitado), f.adesao_troca_atb);
        linhas.push([dt(f.data_parecer), f.paciente_nome || f.paciente_nome_raw || '', f.prontuario || '',
          f.setor || '', _arr(f.atb_solicitado).join(' + '), f.adesao_desfecho || '',
          f.adesao_troca_atb || '', ADESAO_LABEL[cl] || cl].map(esc).join(';'));
      });
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="adesao_${mes}.csv"`);
      res.send('\uFEFF' + linhas.join('\n'));  // BOM p/ acentos no Excel
    } catch (e) {
      console.error('[atb] adesao csv error:', e.message);
      res.status(500).send('Erro: ' + _safe(e.message));
    }
  });

  app.post('/atb/admin/api/adesao/:id', adminRequired, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      let desfecho = (req.body.desfecho || '').trim();
      let troca = (req.body.troca || '').trim();
      if (desfecho && !ADESAO_DESFECHOS.includes(desfecho)) return res.status(400).json({ ok: false, error: 'desfecho inválido' });
      if (troca && !ATB_TROCA.includes(troca)) return res.status(400).json({ ok: false, error: 'ATB de troca inválido' });
      if (desfecho !== 'Suspenso_troca') troca = '';  // troca só faz sentido em Suspenso_troca

      await pool.query(`
        UPDATE atb_fichas
           SET adesao_desfecho = $1, adesao_troca_atb = $2, adesao_por = $3, adesao_em = now()
         WHERE id = $4`,
        [desfecho || null, troca || null, req.user?.id || null, id]);

      res.json({ ok: true });
    } catch (e) {
      console.error('[atb] adesao save error:', e.message);
      res.status(500).json({ ok: false, error: e.message });
    }
  });
}
