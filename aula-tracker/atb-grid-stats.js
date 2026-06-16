// ════════════════════════════════════════════════════════════════════════════
//  ESTATÍSTICAS DESCRITIVAS DO RECORTE  (fechamento mensal)
//  Roda sobre o MESMO recorte filtrado da grade (buildGridWhere) — não só a
//  página visível. Tudo read-only.
//
//  - Categóricos / Sim-Não            → frequências (n, %)
//  - Listas (jsonb array: ATB, comorbidades, veredito, dispositivos, IR) → freq por item
//  - IrAS                             → freq por classe (separa duplas por \n)
//  - Texto codificado (Etiol/Prescritor/Micro) → freq, top N
//  - Numéricos                        → n, média, mediana, mín, máx, soma
//
//  Wiring (em atb-routes.js):
//    import { computeGridStats, renderStatsHTML } from './atb-grid-stats.js';
//    app.get('/atb/admin/grid/stats', adminRequired, async (req,res) => {
//      try { res.send(renderStatsHTML(await computeGridStats(pool, req.query), req.query)); }
//      catch (e) { console.error('[atb] stats:', e); res.status(500).send('Erro: '+e.message); }
//    });
//  Depende de buildGridWhere() e getColsCatalog() exportados por atb-grid-filters.js.
// ════════════════════════════════════════════════════════════════════════════
import { buildGridWhere, getColsCatalog } from './atb-grid-filters.js';

const FROM = `
  FROM atb_fichas f
  LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
  LEFT JOIN atb_avaliacoes a ON a.ficha_id = f.id`;

// quais colunas (chaves do catálogo COLS) entram em cada bloco
const PLANO = {
  categoricos: ['setor','instituicao','tipo_terapia','foco_infeccao','desfecho_iras','status','acesso_dialise'],
  simNao:      ['sepse','obito','dialise','faz_quimio','gestante','uso_atb_7d'],
  listas:      ['atb_solicitado','comorbidades','veredito','dispositivos_invasivos','insuficiencia_renal'],
  iras:        ['iras'],
  texto:       ['etiol_iras','prescritor_nome','micro'],
  numericos:   ['sofa','saps3','tempo_previsto','clcr','peso','altura','peso_nascimento'],
};
const TOP_TEXTO = 30;

function esc(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// ── cálculo ──────────────────────────────────────────────────────────────────
export async function computeGridStats(pool, query) {
  const { whereSql, params } = buildGridWhere(query);
  const COLS = getColsCatalog();
  const out = { total: 0, periodo: null, blocos: [] };

  // total + período (data de referência)
  const tot = await pool.query(
    `SELECT COUNT(*) n,
            MIN(COALESCE(f.data_referencia, f.jotform_created_at, f.created_at))::date mn,
            MAX(COALESCE(f.data_referencia, f.jotform_created_at, f.created_at))::date mx
     ${FROM} WHERE ${whereSql}`, params);
  out.total   = parseInt(tot.rows[0].n, 10);
  out.periodo = { de: tot.rows[0].mn, ate: tot.rows[0].mx };
  if (out.total === 0) return out;

  // helpers de agregação (todos reusam whereSql + params)
  async function freq(expr) {
    const r = await pool.query(
      `SELECT COALESCE(NULLIF(btrim(${expr}::text), ''), '(vazio)') AS v, COUNT(*) n
       ${FROM} WHERE ${whereSql} GROUP BY 1 ORDER BY n DESC, v ASC`, params);
    return r.rows;
  }
  async function freqBool(expr) {
    const r = await pool.query(
      `SELECT CASE WHEN ${expr} IS TRUE THEN 'Sim'
                   WHEN ${expr} IS FALSE THEN 'Não'
                   ELSE '(vazio)' END AS v, COUNT(*) n
       ${FROM} WHERE ${whereSql} GROUP BY 1 ORDER BY n DESC`, params);
    return r.rows;
  }
  async function freqArray(expr) {
    const r = await pool.query(
      `SELECT elem AS v, COUNT(*) n FROM (
         SELECT jsonb_array_elements_text(${expr}) AS elem
         ${FROM} WHERE ${whereSql} AND jsonb_typeof(${expr}) = 'array'
       ) t GROUP BY 1 ORDER BY n DESC, v ASC`, params);
    return r.rows;
  }
  async function freqIras(expr) {
    const r = await pool.query(
      `SELECT btrim(elem) AS v, COUNT(*) n FROM (
         SELECT unnest(string_to_array(${expr}, E'\\n')) AS elem
         ${FROM} WHERE ${whereSql} AND ${expr} IS NOT NULL AND btrim(${expr}) <> ''
       ) t WHERE btrim(elem) <> '' GROUP BY 1 ORDER BY n DESC, v ASC`, params);
    return r.rows;
  }
  async function freqTexto(expr) {
    const r = await pool.query(
      `SELECT COALESCE(NULLIF(btrim(${expr}), ''), '(vazio)') AS v, COUNT(*) n
       ${FROM} WHERE ${whereSql} GROUP BY 1 ORDER BY n DESC, v ASC LIMIT ${TOP_TEXTO + 1}`, params);
    return r.rows;
  }
  async function resumoNum(expr) {
    const r = await pool.query(
      `SELECT COUNT(${expr}) n,
              ROUND(AVG(${expr})::numeric, 1) media,
              ROUND(percentile_cont(0.5) WITHIN GROUP (ORDER BY ${expr})::numeric, 1) mediana,
              MIN(${expr}) mn, MAX(${expr}) mx, ROUND(SUM(${expr})::numeric, 1) soma
       ${FROM} WHERE ${whereSql} AND ${expr} IS NOT NULL`, params);
    return r.rows[0];
  }

  // bloco: categóricos + sim/não
  const catItens = [];
  for (const k of PLANO.categoricos) if (COLS[k]) catItens.push({ label: COLS[k].label, rows: await freq(COLS[k].expr) });
  for (const k of PLANO.simNao)      if (COLS[k]) catItens.push({ label: COLS[k].label, rows: await freqBool(COLS[k].expr) });
  out.blocos.push({ titulo: 'Categóricos & Sim/Não', tipo: 'freq', itens: catItens });

  // bloco: listas + IrAS
  const listaItens = [];
  for (const k of PLANO.listas) if (COLS[k]) listaItens.push({ label: COLS[k].label, rows: await freqArray(COLS[k].expr) });
  for (const k of PLANO.iras)   if (COLS[k]) listaItens.push({ label: COLS[k].label + ' (por classe)', rows: await freqIras(COLS[k].expr) });
  out.blocos.push({ titulo: 'Listas & IrAS', tipo: 'freq', itens: listaItens });

  // bloco: texto codificado (top N)
  const txtItens = [];
  for (const k of PLANO.texto) if (COLS[k]) {
    const rows = await freqTexto(COLS[k].expr);
    txtItens.push({ label: COLS[k].label, rows: rows.slice(0, TOP_TEXTO), truncado: rows.length > TOP_TEXTO });
  }
  out.blocos.push({ titulo: 'Texto codificado (Etiologia · Prescritor · Micro)', tipo: 'freq', itens: txtItens });

  // bloco: numéricos
  const numItens = [];
  for (const k of PLANO.numericos) if (COLS[k]) numItens.push({ label: COLS[k].label, resumo: await resumoNum(COLS[k].expr) });
  out.blocos.push({ titulo: 'Numéricos', tipo: 'num', itens: numItens });

  return out;
}

// ── render (página leve, amigável a impressão) ───────────────────────────────
export function renderStatsHTML(stats, query) {
  const t = stats.total;
  const pct = n => t ? ((n * 100 / t).toFixed(1) + '%') : '—';
  const qs = new URLSearchParams(
    Object.fromEntries(Object.entries(query || {}).filter(([k, v]) => v && k !== 'page'))
  ).toString();

  const tabelaFreq = (item) => {
    const linhas = (item.rows || []).map(r =>
      `<tr><td>${esc(r.v)}</td><td class="n">${r.n}</td><td class="pct">${pct(parseInt(r.n, 10))}</td></tr>`).join('');
    const trunc = item.truncado ? `<tr><td colspan="3" class="mut">… top ${TOP_TEXTO}</td></tr>` : '';
    return `<div class="card">
      <div class="card-h">${esc(item.label)}</div>
      <table class="t"><thead><tr><th>Valor</th><th class="n">n</th><th class="pct">%</th></tr></thead>
      <tbody>${linhas || '<tr><td colspan="3" class="mut">—</td></tr>'}${trunc}</tbody></table>
    </div>`;
  };
  const cardNum = (item) => {
    const s = item.resumo || {};
    const row = (lbl, val) => `<tr><td>${lbl}</td><td class="n">${val ?? '—'}</td></tr>`;
    return `<div class="card">
      <div class="card-h">${esc(item.label)}</div>
      <table class="t num"><tbody>
        ${row('n', s.n || 0)}${row('Média', s.media)}${row('Mediana', s.mediana)}
        <tr><td>Mín–Máx</td><td class="n">${s.mn ?? '—'} – ${s.mx ?? '—'}</td></tr>
        ${row('Soma', s.soma)}
      </tbody></table>
    </div>`;
  };

  const blocos = stats.blocos.map(b => `
    <h2 class="sec">${esc(b.titulo)}</h2>
    <div class="grid">${(b.itens || []).map(it => b.tipo === 'num' ? cardNum(it) : tabelaFreq(it)).join('')}</div>`).join('');

  const periodo = stats.periodo && stats.periodo.de
    ? `${new Date(stats.periodo.de).toLocaleDateString('pt-BR')} – ${new Date(stats.periodo.ate).toLocaleDateString('pt-BR')}`
    : '—';

  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Estatísticas do recorte</title>
<style>
  body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f6f8fa;color:#202124;margin:0;padding:24px}
  .wrap{max-width:1120px;margin:0 auto}
  .top{display:flex;justify-content:space-between;align-items:baseline;flex-wrap:wrap;gap:10px}
  h1{margin:0;font-size:22px}
  .meta{color:#5f6368;font-size:13px;margin:6px 0 18px}
  .meta b{color:#202124}
  .sec{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:#3b6fd4;border-bottom:1px solid #e3e6ea;padding-bottom:6px;margin:26px 0 12px}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(258px,1fr));gap:14px;align-items:start}
  .card{background:#fff;border:1px solid #e3e6ea;border-radius:10px;padding:12px 14px;box-shadow:0 2px 8px rgba(60,80,120,.05)}
  .card-h{font-weight:600;font-size:14px;margin-bottom:8px}
  .t{width:100%;border-collapse:collapse;font-size:13px}
  .t th{text-align:left;color:#80868b;font-weight:500;font-size:11px;text-transform:uppercase;border-bottom:1px solid #eee;padding:3px 4px}
  .t td{padding:3px 4px;border-bottom:1px solid #f3f4f6}
  .t td.n,.t th.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
  .t td.pct,.t th.pct{text-align:right;color:#80868b;width:52px}
  .num td:first-child{color:#5f6368}
  .mut{color:#9aa0a6}
  a.voltar{font-size:13px;text-decoration:none;color:#3b6fd4}
  @media print{body{background:#fff;padding:0}.card{box-shadow:none}a.voltar{display:none}}
</style></head>
<body><div class="wrap">
  <div class="top">
    <h1>Estatísticas do recorte</h1>
    <a class="voltar" href="/atb/admin/grid${qs ? ('?' + qs) : ''}">← voltar à grade</a>
  </div>
  <div class="meta"><b>${stats.total}</b> fichas · período ${periodo}${qs ? ' · (filtros do recorte aplicados)' : ''}</div>
  ${stats.total === 0 ? '<p class="mut">Nenhuma ficha no recorte.</p>' : blocos}
</div></body></html>`;
}
