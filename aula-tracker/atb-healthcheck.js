// ════════════════════════════════════════════════════════════════════════════
//  atb-healthcheck.js — verificação diária do envio da ficha + card de status
//  Roda os mesmos casos do harness, mas SERVER-SIDE e sem HTTP/fichas dummy:
//  chama direto validarObrigatoriosServidor + parseFormPayload em loop (dry-run
//  puro, nada é gravado em atb_fichas). Coleta as regras condicionais vigentes do
//  schema e gera 1 caso por regra (+ mínimo e máximo). Grava o resultado em
//  atb_healthcheck; o /consulta lê o último e pinta "Sistema NORMAL/SUSPENSO".
//
//  Wire (em registerAtbRoutes, junto de registerConsultaRoutes):
//    import { ensureHealthcheckTable, startHealthcheckSchedule, registerHealthcheckRoutes } from './atb-healthcheck.js';
//    ensureHealthcheckTable(pool).then(() => startHealthcheckSchedule(pool)).catch(e => console.error('[atb] healthcheck:', e.message));
//    registerHealthcheckRoutes(app, pool, adminRequired);
//  No /consulta:
//    import { getLatestHealthcheck, renderHealthCard } from './atb-healthcheck.js';
//    const hc = await getLatestHealthcheck(pool).catch(() => null);
//    res.send(paginaConsulta(rows, renderHealthCard(hc)));
// ════════════════════════════════════════════════════════════════════════════
import { getFormSchema } from './atb-form-schema.js';
import { validarObrigatoriosServidor } from './atb-regras-form-routes.js';
import { parseFormPayload } from './atb-parser.js';
import { envTenant } from './atb-tenant.js';

// ── helpers de geração (espelham o harness do navegador) ─────────────────────
function fieldMap(schema) {
  const m = {};
  (schema.secoes || []).forEach(sec => (sec.campos || []).forEach(c => { if (c.key) m[c.key] = c; }));
  return m;
}
function opt(c) { return ((c && c.options) || []).filter(o => o && String(o).trim()); }
function simLike(c) { const o = opt(c); for (const x of o) if (/^sim/i.test(x)) return x; return o[0]; }
function fill(c) {
  if (!c) return 'preenchido';
  const t = c.type, o = opt(c);
  if (t === 'select' || t === 'radio') return o[0] || 'X';
  if (t === 'checkbox') return o.length ? [o[0]] : [];
  if (t === 'date') return '2026-06-01';
  if (t === 'number') return '1';
  if (t === 'crm') return '999999';
  if (t === 'matrix') {
    const row = {};
    (c.colunas || []).forEach(col => {
      const co = (col.options || []).filter(Boolean);
      row[col.key] = col.type === 'select' ? (co[0] || 'X')
                   : col.type === 'date' ? '2026-06-01'
                   : col.type === 'check' ? true : 'X';
    });
    return [row];
  }
  let base = (c.validate === 'nome_completo') ? 'Teste Da Silva' : 'Preenchimento automatico de teste';
  while (c.minChars && base.length < c.minChars) base += ' xxxxx';
  return base;
}
function coletarRegras(schema) {
  const r = [];
  (schema.secoes || []).forEach(sec => {
    if (sec.cond) r.push({ tipo: 'seção visível', alvo: (sec.titulo || sec.id || '?'), cond: sec.cond });
    (sec.campos || []).forEach(c => {
      if (c.cond)         r.push({ tipo: 'campo visível',       alvo: (c.label || c.key), cond: c.cond });
      if (c.requiredCond) r.push({ tipo: 'obrigatório condic.', alvo: (c.label || c.key), cond: c.requiredCond });
    });
  });
  return r;
}
function condResumo(cond) {
  if (!cond) return '(sem condição)';
  if (cond.all) return 'TODAS(' + cond.all.map(condResumo).join(' & ') + ')';
  if (cond.any) return 'QUALQUER(' + cond.any.map(condResumo).join(' | ') + ')';
  const sem = (cond.op === 'filled' || cond.op === 'not_filled');
  const val = Array.isArray(cond.valor) ? ('[' + cond.valor.join(',') + ']') : cond.valor;
  return cond.campo + ' ' + cond.op + (sem ? '' : (' ' + val));
}
function satisfazer(cond, map) {
  if (!cond) return {};
  if (cond.all) return cond.all.reduce((a, c) => Object.assign(a, satisfazer(c, map)), {});
  if (cond.any) return cond.any.length ? satisfazer(cond.any[0], map) : {};
  const campo = cond.campo, valor = cond.valor, o = {};
  switch (cond.op) {
    case 'eq':                o[campo] = valor; break;
    case 'in':                o[campo] = Array.isArray(valor) ? valor[0] : valor; break;
    case 'contains':          o[campo] = [valor]; break;
    case 'contains_any':      o[campo] = Array.isArray(valor) ? [valor[0]] : [valor]; break;
    case 'text_contains_any': o[campo] = Array.isArray(valor) ? String(valor[0]) : String(valor); break;
    case 'filled':            o[campo] = map[campo] ? fill(map[campo]) : 'preenchido'; break;
    case 'neq':               if (valor === '') o[campo] = 'preenchido'; break;
    case 'not_filled':        break;
    default: break;
  }
  return o;
}

// resolve um caso: itera preenchendo as faltas do validador, até passar (dry-run puro)
function resolverServer(schema, map, seed) {
  const d = Object.assign({ pac_nome: 'ZZ_TESTE', prontuario: '9999999', crm: '999999', prescritor_nome: 'Teste Da Silva' }, seed);
  const preenchidos = [];
  for (let step = 1; step <= 12; step++) {
    if (!d.pac_nome || !d.prontuario || !d.crm)
      return { ok: false, iters: step, erro: 'pac_nome/prontuario/crm em falta', preenchidos };
    let faltas;
    try { faltas = validarObrigatoriosServidor(schema, d); }
    catch (e) { return { ok: false, iters: step, erro: 'validador: ' + e.message, preenchidos }; }
    if (!faltas.length) {
      try { parseFormPayload(d); }
      catch (e) { return { ok: false, iters: step, erro: 'parse: ' + e.message, preenchidos }; }
      return { ok: true, iters: step, preenchidos };
    }
    if (step >= 12)
      return { ok: false, iters: step, erro: 'faltas persistentes', faltas: faltas.map(f => f.key), preenchidos };
    faltas.forEach(f => { d[f.key] = fill(map[f.key]); if (preenchidos.indexOf(f.key) < 0) preenchidos.push(f.key); });
  }
  return { ok: false, iters: 12, erro: 'loop', preenchidos };
}

// ── execução + persistência ──────────────────────────────────────────────────
export async function runHealthcheck(pool, inst = 'HUSF') {
  const schema = await getFormSchema(pool, inst);
  if (!schema) return null;            // instituição sem schema — nada a checar
  const map = fieldMap(schema);
  const regras = coletarRegras(schema);

  const casos = [];
  casos.push({ nome: 'Mínimo (sem triggers)', sub: '', seed: {} });
  const maxSeed = {};
  Object.keys(map).forEach(k => {
    const c = map[k];
    if (c.type === 'radio' || c.type === 'select') maxSeed[k] = simLike(c);
    else if (c.type === 'checkbox') { const o = opt(c); if (o.length) maxSeed[k] = [o[0]]; }
  });
  casos.push({ nome: 'Máximo (todas as opções)', sub: '', seed: maxSeed });
  regras.forEach(rg => casos.push({ nome: rg.tipo + ': ' + rg.alvo, sub: condResumo(rg.cond), seed: satisfazer(rg.cond, map) }));

  const detalhe = [];
  let passed = 0, failed = 0;
  for (const caso of casos) {
    const rr = resolverServer(schema, map, Object.assign({}, caso.seed));
    if (rr.ok) passed++; else failed++;
    detalhe.push({ caso: caso.nome, cond: caso.sub, ok: rr.ok, iters: rr.iters,
                   erro: rr.erro || null, faltas: rr.faltas || null });
  }
  const total = casos.length, ok = failed === 0;
  const { rows: [row] } = await pool.query(
    `INSERT INTO atb_healthcheck (instituicao, ok, total, passed, failed, detalhe)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, ran_at, ok, total, passed, failed`,
    [inst, ok, total, passed, failed, JSON.stringify(detalhe)]);
  return Object.assign(row, { detalhe, instituicao: inst });
}

export async function ensureHealthcheckTable(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atb_healthcheck (
      id      SERIAL PRIMARY KEY,
      ran_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
      ok      BOOLEAN     NOT NULL,
      total   INTEGER     NOT NULL,
      passed  INTEGER     NOT NULL,
      failed  INTEGER     NOT NULL,
      detalhe JSONB
    )`);
  // Escopo por instituição. Resultados existentes → HUSF (preserva o atual).
  await pool.query(`ALTER TABLE atb_healthcheck ADD COLUMN IF NOT EXISTS instituicao TEXT`);
  await pool.query(`UPDATE atb_healthcheck SET instituicao='HUSF' WHERE instituicao IS NULL`);
}

export async function getLatestHealthcheck(pool, inst = 'HUSF') {
  const { rows: [row] } = await pool.query(
    `SELECT id, ran_at, ok, total, passed, failed, detalhe FROM atb_healthcheck
      WHERE instituicao = $1 ORDER BY ran_at DESC LIMIT 1`, [inst]);
  return row || null;
}

export function startHealthcheckSchedule(pool) {
  // Mesmo padrão do regras-check: por-env (ATB_TENANT) checa só esse tenant; sem env
  // (subdomínio/legado) checa CADA instituição ativa, com resultado tagueado.
  const run = async () => {
    try {
      const fixo = envTenant();
      const alvos = fixo
        ? [fixo]
        : (await pool.query('SELECT sigla FROM atb_instituicoes WHERE ativo=true ORDER BY id')).rows.map(r => r.sigla);
      for (const sigla of alvos) {
        await runHealthcheck(pool, sigla)
          .then(r => r && console.log('[healthcheck]', sigla, r.ok ? 'NORMAL' : 'SUSPENSO', r.passed + '/' + r.total))
          .catch(e => console.error('[healthcheck]', sigla, 'erro:', e.message));
      }
    } catch (e) { console.error('[healthcheck] schedule:', e.message); }
  };
  setTimeout(run, 30 * 1000);             // ~30s após o boot
  setInterval(run, 8 * 60 * 60 * 1000);  // a cada 8 horas
}

export function registerHealthcheckRoutes(app, pool, adminRequired) {
  // dispara manualmente (sem esperar 24h) e mostra o resumo
  app.get('/atb/admin/healthcheck/run', adminRequired, async (req, res) => {
    try {
      const r = await runHealthcheck(pool, req.atbTenant || 'HUSF');
      if (!r) return res.json({ vazio: true });
      res.json({ ok: r.ok, total: r.total, passed: r.passed, failed: r.failed,
                 falhas: (r.detalhe || []).filter(d => !d.ok) });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });
  // último resultado (JSON)
  app.get('/atb/admin/healthcheck', adminRequired, async (req, res) => {
    try { res.json((await getLatestHealthcheck(pool, req.atbTenant || 'HUSF')) || { vazio: true }); }
    catch (e) { res.status(500).json({ error: e.message }); }
  });
  // painel HTML: card de status + falhas + botao "rodar agora" (?run=1)
  app.get('/atb/admin/healthcheck/painel', adminRequired, async (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    try {
      const inst = req.atbTenant || 'HUSF';
      const hc = req.query.run === '1' ? await runHealthcheck(pool, inst) : await getLatestHealthcheck(pool, inst);
      const esc = (v) => String(v == null ? '' : v).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
      const falhas = ((hc && hc.detalhe) || []).filter(d => !d.ok);
      const linhas = falhas.map(d =>
        `<tr><td style="padding:6px 10px;border-top:1px solid #eee">${esc(d.caso)}</td>` +
        `<td style="padding:6px 10px;border-top:1px solid #eee;color:#5f6368">${esc(d.cond || '\u2014')}</td>` +
        `<td style="padding:6px 10px;border-top:1px solid #eee">${esc(d.erro || (d.faltas ? 'faltam: ' + (Array.isArray(d.faltas) ? d.faltas.join(', ') : d.faltas) : '\u2014'))}</td></tr>`
      ).join('');
      const tabela = falhas.length
        ? `<table style="border-collapse:collapse;width:100%;font-size:13px;margin-top:8px">` +
          `<thead><tr style="text-align:left;color:#80868b">` +
          `<th style="padding:6px 10px">Caso</th><th style="padding:6px 10px">Condicao</th><th style="padding:6px 10px">Problema</th>` +
          `</tr></thead><tbody>${linhas}</tbody></table>`
        : `<p style="color:#1a8a52;font-size:13px;margin-top:8px">Todos os testes passaram.</p>`;
      res.send(`<!doctype html><html lang="pt-br"><head><meta charset="utf-8">` +
        `<meta name="viewport" content="width=device-width,initial-scale=1"><title>Saude do sistema</title></head>` +
        `<body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:860px;margin:24px auto;padding:0 16px;color:#202124">` +
        `<div style="display:flex;align-items:center;justify-content:space-between;gap:12px">` +
        `<h1 style="font-size:18px;margin:0">Saude do sistema</h1>` +
        `<a href="/atb/admin/healthcheck/painel?run=1" style="font-size:13px;padding:7px 12px;border:1px solid #d0d3d9;border-radius:8px;text-decoration:none;color:#1a73e8;background:#f8fafe">&#8635; Rodar verificacao agora</a>` +
        `</div>${renderHealthCard(hc)}${tabela}` +
        `<p style="margin-top:18px"><a href="/scih" style="font-size:13px;color:#5f6368">&#8592; Voltar ao Portal do SCIH</a></p>` +
        `</body></html>`);
    } catch (e) { res.status(500).send('Erro: ' + e.message); }
  });
}

// ── card de status (estilos inline; não depende do CSS da página) ────────────
export function renderHealthCard(hc) {
  const wrap = (bg, br, fg, titulo, sub) =>
    `<div style="display:flex;align-items:center;gap:12px;margin:14px 0;padding:12px 16px;border:1px solid ${br};background:${bg};border-radius:10px;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif">
       <span style="width:11px;height:11px;border-radius:50%;background:${fg};flex:0 0 auto"></span>
       <div><div style="font-weight:700;color:${fg};font-size:14px">${titulo}</div>
       <div style="color:#5f6368;font-size:12px;margin-top:1px">${sub}</div></div>
     </div>`;
  if (!hc) return wrap('#f4f6f9', '#e0e2e6', '#80868b', 'Sistema: status ainda não verificado', 'A primeira verificação roda em instantes.');
  const quando = hc.ran_at
    ? new Date(hc.ran_at).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })
    : '—';
  if (hc.ok)
    return wrap('#f1faf4', '#bfe6cf', '#1a8a52', 'Sistema NORMAL',
      `Envio de fichas verificado: ${hc.passed}/${hc.total} testes OK · ${quando}`);
  return wrap('#fdf2f2', '#f3c2c2', '#c0392b', 'Sistema SUSPENSO',
    `${hc.failed} de ${hc.total} testes falharam · verificado ${quando}`);
}
