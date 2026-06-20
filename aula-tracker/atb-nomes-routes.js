// atb-nomes-routes.js — AUDITORIA de nomes (read-only, p/ navegador)
//   GET /atb/admin/nomes/backcheck       → relatório HTML (resumo + amostras)
//   GET /atb/admin/nomes/backcheck.csv   → download do diff completo (antes→depois)
// Não grava nada. A normalização de fato (fase 2) é um script Shell com --execute.
//
// Wire (em registerAtbRoutes):
//   import { registerNomesRoutes } from './atb-nomes-routes.js';
//   registerNomesRoutes(app, pool, adminRequired);

// ── normalização CANDIDATA (transformações SEGURAS apenas) ───────────────────
function normalizeNome(raw) {
  if (raw == null) return '';
  let s = String(raw).replace(/[\u00A0\s]+/g, ' ').trim().toLocaleUpperCase('pt-BR');
  let toks = s.split(' ').filter(Boolean);
  toks = toks.filter((t, i) => i === 0 || t !== toks[i - 1]);          // dedup consecutivo
  if (toks.length >= 2 && toks.length % 2 === 0) {                      // repetição total P P
    const h = toks.length / 2;
    if (toks.slice(0, h).join(' ') === toks.slice(h).join(' ')) toks = toks.slice(0, h);
  }
  return toks.join(' ');
}
const ABERRANTE = /[^A-Za-zÀ-ÖØ-öø-ÿ '.\-]/;
function problemas(raw) {
  const p = [];
  if (raw == null || String(raw).trim() === '') { p.push('vazio'); return p; }
  const s = String(raw);
  if (s !== s.trim() || /\s{2,}/.test(s) || /\u00A0/.test(s)) p.push('espacos');
  if (s !== s.toLocaleUpperCase('pt-BR')) p.push('caixa');
  if (ABERRANTE.test(s)) p.push('aberracao');
  const toks = s.replace(/\s+/g, ' ').trim().split(' ').filter(Boolean);
  if (toks.some((t, i) => i > 0 && t === toks[i - 1])) p.push('repeticao_token');
  if (toks.length >= 2 && toks.length % 2 === 0) {
    const h = toks.length / 2;
    if (toks.slice(0, h).join(' ').toUpperCase() === toks.slice(h).join(' ').toUpperCase()) p.push('repeticao_total');
  }
  if (toks.length === 1) p.push('token_unico');
  if (s.replace(/\s/g, '').length < 3) p.push('muito_curto');
  return p;
}

async function coletar(pool) {
  const { rows } = await pool.query(`
    SELECT id, paciente_nome, paciente_nome_raw,
           (jotform_submission_id LIKE 'form_%') AS nativo
    FROM atb_fichas WHERE deletado_em IS NULL`);
  const cats = {}, exemplos = {}, mudancas = [];
  let totalRaw = 0, semRaw = 0, nomeNull = 0, nomeDifereRaw = 0;
  for (const f of rows) {
    if (f.paciente_nome == null) nomeNull++;
    else if (f.paciente_nome !== f.paciente_nome_raw) nomeDifereRaw++;
    const raw = f.paciente_nome_raw;
    if (raw == null || String(raw).trim() === '') { semRaw++; continue; }
    totalRaw++;
    const probs = problemas(raw);
    for (const c of probs) {
      cats[c] = (cats[c] || 0) + 1;
      (exemplos[c] = exemplos[c] || []);
      if (exemplos[c].length < 8) exemplos[c].push(`#${f.id} «${raw}»`);
    }
    const norm = normalizeNome(raw);
    if (norm !== raw) mudancas.push({ id: f.id, problemas: probs, antes: raw, depois: norm });
  }
  return { total: rows.length, totalRaw, semRaw, nomeNull, nomeDifereRaw, cats, exemplos, mudancas };
}

function esc(v) { return String(v == null ? '' : v).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }

export function registerNomesRoutes(app, pool, adminRequired) {
  // relatório HTML
  app.get('/atb/admin/nomes/backcheck', adminRequired, async (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    try {
      const r = await coletar(pool);
      const catLin = Object.keys(r.cats).sort((a, b) => r.cats[b] - r.cats[a]).map(c =>
        `<tr><td style="padding:6px 10px;border-top:1px solid #eee"><strong>${esc(c)}</strong></td>
             <td style="padding:6px 10px;border-top:1px solid #eee;text-align:right">${r.cats[c]}</td>
             <td style="padding:6px 10px;border-top:1px solid #eee;color:#5f6368;font-size:12px">${(r.exemplos[c] || []).slice(0, 4).map(esc).join('<br>')}</td></tr>`).join('');
      const amostra = r.mudancas.slice(0, 40).map(m =>
        `<tr><td style="padding:5px 10px;border-top:1px solid #eee">#${m.id}</td>
             <td style="padding:5px 10px;border-top:1px solid #eee">«${esc(m.antes)}»</td>
             <td style="padding:5px 10px;border-top:1px solid #eee">«${esc(m.depois)}»</td></tr>`).join('');
      res.send(`<!doctype html><html lang="pt-br"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1"><title>Backcheck de nomes</title></head>
        <body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:920px;margin:24px auto;padding:0 16px;color:#202124">
        <h1 style="font-size:18px;margin:0">Backcheck de nomes (read-only)</h1>
        <p style="font-size:13px;color:#5f6368">Não grava nada. Mostra problemas em <code>paciente_nome_raw</code> e o que a normalização segura faria.</p>
        <div style="margin:10px 0"><a href="/atb/admin/nomes/backcheck.csv" style="font-size:13px;padding:8px 14px;border:1px solid #d0d3d9;border-radius:8px;text-decoration:none;color:#1a73e8;background:#f8fafe">⬇ Baixar CSV completo (antes→depois)</a></div>
        <table style="border-collapse:collapse;font-size:13px;margin:10px 0">
          <tr><td style="padding:4px 10px">Fichas não deletadas</td><td style="padding:4px 10px"><strong>${r.total}</strong></td></tr>
          <tr><td style="padding:4px 10px">com paciente_nome_raw</td><td style="padding:4px 10px">${r.totalRaw}</td></tr>
          <tr><td style="padding:4px 10px">paciente_nome NULL (migrados)</td><td style="padding:4px 10px">${r.nomeNull}</td></tr>
          <tr><td style="padding:4px 10px">paciente_nome ≠ raw</td><td style="padding:4px 10px">${r.nomeDifereRaw}</td></tr>
          <tr><td style="padding:4px 10px"><strong>Normalização mudaria</strong></td><td style="padding:4px 10px"><strong>${r.mudancas.length}</strong> nome(s)</td></tr>
        </table>
        <h2 style="font-size:15px">Problemas por categoria</h2>
        <p style="font-size:12px;color:#5f6368">Auto-corrige: espacos, caixa, repeticao_token, repeticao_total. Só FLAG: aberracao, token_unico, muito_curto.</p>
        <table style="border-collapse:collapse;width:100%;font-size:13px"><thead><tr style="text-align:left;color:#80868b">
          <th style="padding:6px 10px">Categoria</th><th style="padding:6px 10px">Qtd</th><th style="padding:6px 10px">Exemplos</th></tr></thead>
          <tbody>${catLin}</tbody></table>
        <h2 style="font-size:15px;margin-top:22px">Amostra de mudanças (até 40 — CSV tem tudo)</h2>
        <table style="border-collapse:collapse;width:100%;font-size:13px"><thead><tr style="text-align:left;color:#80868b">
          <th style="padding:5px 10px">Ficha</th><th style="padding:5px 10px">Antes</th><th style="padding:5px 10px">Depois</th></tr></thead>
          <tbody>${amostra || '<tr><td colspan="3" style="padding:8px 10px;color:#5f6368">Nenhuma mudança.</td></tr>'}</tbody></table>
        </body></html>`);
    } catch (e) { res.status(500).send('Erro: ' + esc(e.message)); }
  });

  // CSV completo (download)
  app.get('/atb/admin/nomes/backcheck.csv', adminRequired, async (req, res) => {
    try {
      const r = await coletar(pool);
      const q = (v) => `"${String(v).replace(/"/g, '""')}"`;
      const linhas = ['id;problemas;antes;depois'];
      for (const m of r.mudancas) linhas.push(`${m.id};${q(m.problemas.join('|'))};${q(m.antes)};${q(m.depois)}`);
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="backcheck-nomes.csv"');
      res.send('\uFEFF' + linhas.join('\r\n'));   // BOM p/ Excel abrir UTF-8 certo
    } catch (e) { res.status(500).send('Erro: ' + esc(e.message)); }
  });
}
