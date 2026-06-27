// ════════════════════════════════════════════════════════════════════════════
//  atb-regras-check.js — verificação de LÓGICA (público: SCIH)
//  Separado do atb-healthcheck.js (que cobre só o ENVIO da ficha, p/ o banner do
//  /consulta). Aqui testamos se as regras estão FAZENDO o que deveriam:
//    • runRegrasCheck (AUTOMÁTICO, agendado): regras de triagem disparam quando
//      deveriam + obrigatoriedade condicional do formulário é de fato exigida.
//    • runVisibilidadeCheck (OPT-IN, botão): auditoria das condições de
//      visibilidade (campo.cond / secao.cond) — referências válidas e
//      comportamento discriminante. Não é agendado.
//
//  Wire (em registerAtbRoutes, junto do healthcheck):
//    import { ensureRegrasCheckTable, startRegrasCheckSchedule, registerRegrasCheckRoutes } from './atb-regras-check.js';
//    ensureRegrasCheckTable(pool).then(()=>startRegrasCheckSchedule(pool)).catch(e=>console.error('[atb] regras-check:',e.message));
//    registerRegrasCheckRoutes(app, pool, adminRequired);
// ════════════════════════════════════════════════════════════════════════════
import { getFormSchema } from './atb-form-schema.js';
import { avaliaCondServer, validarObrigatoriosServidor, aplicarPreenchimentosServidor } from './atb-regras-form-routes.js';
import { contextoFicha, avaliaCond } from './atb-triagem-regras.js';
import { getLatestHealthcheck, renderHealthCard } from './atb-healthcheck.js';
import { envTenant } from './atb-tenant.js';

// ── helpers de schema/síntese (form) ─────────────────────────────────────────
function fieldMap(schema) {
  const m = {};
  (schema.secoes || []).forEach(sec => (sec.campos || []).forEach(c => { if (c.key) m[c.key] = c; }));
  return m;
}
function opt(c) { return ((c && c.options) || []).filter(o => o && String(o).trim()); }
function fill(c) {
  if (!c) return 'preenchido';
  const t = c.type, o = opt(c);
  if (t === 'select' || t === 'radio') return o[0] || 'X';
  if (t === 'checkbox') return o.length ? [o[0]] : [];
  if (t === 'date') return '2026-06-01';
  if (t === 'number') return '1';
  if (t === 'crm') return '999999';
  let base = (c.validate === 'nome_completo') ? 'Teste Da Silva' : 'Preenchimento automatico de teste';
  while (c.minChars && base.length < c.minChars) base += ' xxxxx';
  return base;
}
// satisfaz uma cond DE FORMULÁRIO produzindo `dados` (espelha o harness)
function satisfazerForm(cond, map) {
  if (!cond) return {};
  if (cond.all) return cond.all.reduce((a, c) => Object.assign(a, satisfazerForm(c, map)), {});
  if (cond.any) return cond.any.length ? satisfazerForm(cond.any[0], map) : {};
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
    default:                  break;
  }
  return o;
}
function refsCond(cond, acc) {
  acc = acc || [];
  if (!cond) return acc;
  if (cond.all) { cond.all.forEach(c => refsCond(c, acc)); return acc; }
  if (cond.any) { cond.any.forEach(c => refsCond(c, acc)); return acc; }
  if (cond.campo) acc.push(cond.campo);
  return acc;
}
const ARRAY_OPS = new Set(['contains', 'contains_any']);
const SCALAR_OPS = new Set(['eq', 'neq', 'in', 'text_contains_any']);
function leafConds(cond, acc) {
  acc = acc || [];
  if (!cond) return acc;
  if (cond.all) { cond.all.forEach(c => leafConds(c, acc)); return acc; }
  if (cond.any) { cond.any.forEach(c => leafConds(c, acc)); return acc; }
  if (cond.campo) acc.push(cond);
  return acc;
}
// operador incompatível com o tipo do campo (ex.: contains_any em texto/número → nunca casa)
function incompatibilidadeOpTipo(cond, map) {
  const probl = [];
  for (const c of leafConds(cond)) {
    const f = map[c.campo]; if (!f) continue;
    const ehArray = f.type === 'checkbox';
    if (ehArray && SCALAR_OPS.has(c.op)) probl.push(`"${c.campo}" é multi-seleção (lista); operador "${c.op}" nunca casa — use "contém"/"contém algum de"`);
    if (!ehArray && ARRAY_OPS.has(c.op)) probl.push(`"${c.campo}" é de valor único; operador "${c.op}" não se aplica — use "texto contém algum de" (texto), "está entre"/"é igual a"`);
  }
  return probl;
}
function condResumo(cond) {
  if (!cond) return '(sem condição)';
  if (cond.all) return 'TODAS(' + cond.all.map(condResumo).join(' & ') + ')';
  if (cond.any) return 'QUALQUER(' + cond.any.map(condResumo).join(' | ') + ')';
  const sem = (cond.op === 'filled' || cond.op === 'not_filled');
  const val = Array.isArray(cond.valor) ? ('[' + cond.valor.join(',') + ']') : cond.valor;
  return cond.campo + ' ' + cond.op + (sem ? '' : (' ' + val));
}

// ── síntese de ficha p/ regras de TRIAGEM (datas como Date, como o pg) ────────
function _startOfDay(d){ const x = new Date(d); x.setHours(0,0,0,0); return x; }
function _dateMinusDays(ref, k){ const x = _startOfDay(ref); x.setDate(x.getDate() - k); return x; }
const CALC_DATE = { idade_dias: 'paciente_dn', dias_internacao: 'data_internacao', dias_uti: 'data_admissao_uti' }; // dias_uti lê a coluna real data_admissao_uti (não 'data_uti')
const NAO_SINT = new Set(['idade_meses', 'idade_anos', 'dias_desde_submissao', 'fichas_72h_mesmo_setor']); // não sintetizáveis com segurança (cross-ficha/relativos a hoje)
function _alvoDias(op, v){
  v = Number(v); if (!Number.isFinite(v)) return null;
  if (op === 'lt')  return Math.max(0, Math.floor(v) - 1);
  if (op === 'lte') return Math.max(0, Math.floor(v));
  if (op === 'gt')  return Math.floor(v) + 1;
  if (op === 'gte') return Math.max(0, Math.ceil(v));
  if (op === 'eq')  return v >= 0 ? Math.floor(v) : null;
  return null;
}
function sintetizarTriagem(cond, ficha, ref, info){
  if (!cond) return;
  if (cond.all) { cond.all.forEach(c => sintetizarTriagem(c, ficha, ref, info)); return; }
  if (cond.any) { if (cond.any.length) sintetizarTriagem(cond.any[0], ficha, ref, info); return; }
  const campo = cond.campo, op = cond.op, valor = cond.valor;
  if (CALC_DATE[campo]) {
    const k = _alvoDias(op, valor);
    if (k == null) { info.sint = false; return; }
    ficha[CALC_DATE[campo]] = _dateMinusDays(ref, k);
    return;
  }
  if (NAO_SINT.has(campo)) { info.sint = false; return; }
  const numOp = (op === 'lt' || op === 'lte' || op === 'gt' || op === 'gte');
  if (numOp) {
    const n = Number(valor);
    if (!Number.isFinite(n)) { info.sint = false; return; }
    ficha[campo] = op === 'lt' ? n - 1 : op === 'gt' ? n + 1 : n;
    return;
  }
  switch (op) {
    case 'eq':                ficha[campo] = valor; break;
    case 'neq':               ficha[campo] = (valor === '' ? 'preenchido' : (typeof valor === 'number' ? valor + 1 : String(valor) + '_x')); break;
    case 'in':                ficha[campo] = Array.isArray(valor) ? valor[0] : valor; break;
    case 'contains':          ficha[campo] = [valor]; break;
    case 'contains_any':      ficha[campo] = Array.isArray(valor) ? [valor[0]] : [valor]; break;
    case 'text_contains_any': ficha[campo] = Array.isArray(valor) ? String(valor[0]) : String(valor); break;
    case 'filled':            ficha[campo] = 'preenchido'; break;
    case 'not_filled':        ficha[campo] = ''; break;
    default:                  info.sint = false; break;
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  CHECK 2 (automático): triagem + obrigatoriedade condicional
// ════════════════════════════════════════════════════════════════════════════
export async function runRegrasCheck(pool, inst = 'HUSF') {
  const schema = await getFormSchema(pool, inst);
  const map = fieldMap(schema);
  const detalhe = [];
  let passed = 0, failed = 0;

  // 1) Regras de triagem: sintetiza ficha que satisfaz → exige disparo
  const regras = (await pool.query(
    'SELECT id, nome, condicoes FROM atb_triagem_regras WHERE ativo=true AND instituicao=$1 ORDER BY prioridade ASC, id ASC',
    [inst]
  )).rows;
  for (const rg of regras) {
    const caso = 'Triagem: ' + (rg.nome || ('#' + rg.id));
    const ref = new Date();
    const ficha = { created_at: ref };
    const info = { sint: true };
    sintetizarTriagem(rg.condicoes, ficha, ref, info);
    if (!info.sint) { detalhe.push({ grupo: 'triagem', caso, cond: condResumo(rg.condicoes), ok: true, skip: true }); passed++; continue; }
    const ctx = contextoFicha(ficha);
    const disparou = avaliaCond(rg.condicoes, ctx);
    if (disparou) passed++; else failed++;
    detalhe.push({ grupo: 'triagem', caso, cond: condResumo(rg.condicoes), ok: disparou,
      erro: disparou ? null : 'regra NAO disparou na ficha sintetizada que satisfaz suas condicoes',
      ctx: disparou ? null : { idade_dias: ctx.idade_dias, dias_internacao: ctx.dias_internacao } });
  }

  // 2) Obrigatoriedade condicional: condição satisfeita + campo vazio → tem que acusar
  for (const sec of (schema.secoes || [])) {
    for (const c of (sec.campos || [])) {
      if (!c.key || !c.requiredCond) continue;
      const caso = 'Obrigatório condic.: ' + (c.label || c.key);
      const dados = Object.assign({}, c.cond ? satisfazerForm(c.cond, map) : {}, satisfazerForm(c.requiredCond, map));
      delete dados[c.key]; // garante o campo-alvo vazio
      const condOk = (!c.cond || avaliaCondServer(c.cond, dados)) && avaliaCondServer(c.requiredCond, dados);
      if (!condOk) { detalhe.push({ grupo: 'requiredCond', caso, cond: condResumo(c.requiredCond), ok: true, skip: true }); passed++; continue; }
      let faltas; try { faltas = validarObrigatoriosServidor(schema, dados); }
      catch (e) { detalhe.push({ grupo: 'requiredCond', caso, cond: condResumo(c.requiredCond), ok: false, erro: 'validador: ' + e.message }); failed++; continue; }
      const acusou = faltas.some(f => f.key === c.key);
      if (acusou) passed++; else failed++;
      detalhe.push({ grupo: 'requiredCond', caso, cond: condResumo(c.requiredCond), ok: acusou,
        erro: acusou ? null : 'campo NAO foi exigido mesmo com a condicao satisfeita' });
    }
  }

  // 3) Preenchimento condicional: referências válidas + valor é opção do alvo + dispara
  for (const [i, r] of (schema.preenchimentos || []).entries()) {
    const alvoF = map[r.campo];
    const caso = 'Preenchimento: ' + (alvoF ? (alvoF.label || r.campo) : (r.campo || ('#' + i)));
    const cond = condResumo(r.quando);
    // (a) referências do "quando" + campo-alvo existem
    const refs = refsCond(r.quando); if (r.campo) refs.push(r.campo);
    const faltando = refs.filter(k => !map[k]);
    if (faltando.length) { detalhe.push({ grupo: 'preenchimento', caso, cond, ok: false, erro: 'referência inexistente: ' + faltando.join(', ') }); failed++; continue; }
    const incompP = incompatibilidadeOpTipo(r.quando, map);
    if (incompP.length) { detalhe.push({ grupo: 'preenchimento', caso, cond, ok: false, erro: 'operador×tipo: ' + incompP.join('; ') }); failed++; continue; }
    // (b) valor é uma opção do campo-alvo (quando o campo tem opções)
    const ops = opt(alvoF);
    if (ops.length && !ops.includes(r.valor)) {
      detalhe.push({ grupo: 'preenchimento', caso, cond, ok: false, erro: `valor "${r.valor}" não é opção de ${r.campo} (${ops.join(' | ')})` }); failed++; continue;
    }
    // (c) sintetiza ficha que satisfaz o "quando", alvo vazio → aplicar tem que setar
    const dados = satisfazerForm(r.quando, map); delete dados[r.campo];
    let setou;
    try { aplicarPreenchimentosServidor({ preenchimentos: [r] }, dados); setou = dados[r.campo] === r.valor; }
    catch (e) { detalhe.push({ grupo: 'preenchimento', caso, cond, ok: false, erro: 'aplicador: ' + e.message }); failed++; continue; }
    if (setou) passed++; else failed++;
    detalhe.push({ grupo: 'preenchimento', caso, cond, ok: setou,
      erro: setou ? null : 'não preencheu o campo na ficha sintetizada que satisfaz a condição' });
  }

  // 4) Operador × tipo de campo em TODAS as condições do formulário (visibilidade + obrigatoriedade)
  const auditarOpTipo = (cond, caso) => {
    if (!cond) return;
    const incomp = incompatibilidadeOpTipo(cond, map);
    if (incomp.length) { detalhe.push({ grupo: 'op_tipo', caso, cond: condResumo(cond), ok: false, erro: 'operador×tipo: ' + incomp.join('; ') }); failed++; }
    else { detalhe.push({ grupo: 'op_tipo', caso, cond: condResumo(cond), ok: true, skip: true }); passed++; }
  };
  for (const sec of (schema.secoes || [])) {
    auditarOpTipo(sec.cond, 'Visibilidade · Seção: ' + (sec.titulo || sec.id || '(seção)'));
    for (const c of (sec.campos || [])) {
      if (!c.key) continue;
      auditarOpTipo(c.cond, 'Visibilidade · ' + (c.label || c.key));
      auditarOpTipo(c.requiredCond, 'Obrigatoriedade · ' + (c.label || c.key));
    }
  }

  const total = detalhe.length, ok = failed === 0;
  const { rows: [row] } = await pool.query(
    `INSERT INTO atb_regras_check (ok, total, passed, failed, detalhe, instituicao)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, ran_at, ok, total, passed, failed`,
    [ok, total, passed, failed, JSON.stringify(detalhe), inst]);
  return Object.assign(row, { detalhe });
}

// ════════════════════════════════════════════════════════════════════════════
//  VISIBILIDADE (opt-in): auditoria das condições de visibilidade
// ════════════════════════════════════════════════════════════════════════════
export async function runVisibilidadeCheck(pool, inst = 'HUSF') {
  const schema = await getFormSchema(pool, inst);
  const map = fieldMap(schema);
  const keys = new Set(Object.keys(map));
  const detalhe = [];
  let passed = 0, failed = 0;

  const checar = (cond, tipo, alvo) => {
    const referidos = refsCond(cond);
    const faltando = referidos.filter(k => !keys.has(k));
    const dados = satisfazerForm(cond, map);
    const mostraQuandoSat = avaliaCondServer(cond, dados); // satisfeito → deveria mostrar
    const escondeVazio    = !avaliaCondServer(cond, {});   // form vazio → deveria esconder
    const ok = faltando.length === 0 && mostraQuandoSat;   // refs válidas + a cond é satisfazível
    if (ok) passed++; else failed++;
    detalhe.push({ tipo, alvo, cond: condResumo(cond), ok,
      erro: !ok ? (faltando.length ? ('cond referencia campo(s) inexistente(s): ' + faltando.join(', '))
                                   : 'cond nunca é satisfeita → campo/seção nunca aparece') : null,
      sempreVisivel: !escondeVazio });                     // info: aparece mesmo com form vazio
  };

  for (const sec of (schema.secoes || [])) {
    if (sec.cond) checar(sec.cond, 'seção', sec.titulo || sec.id || '?');
    for (const c of (sec.campos || [])) if (c.cond) checar(c.cond, 'campo', c.label || c.key);
  }
  return { ok: failed === 0, total: detalhe.length, passed, failed, detalhe };
}

// ── persistência + agendamento (só o check automático) ───────────────────────
export async function ensureRegrasCheckTable(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atb_regras_check (
      id      SERIAL PRIMARY KEY,
      ran_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
      ok      BOOLEAN     NOT NULL,
      total   INTEGER     NOT NULL,
      passed  INTEGER     NOT NULL,
      failed  INTEGER     NOT NULL,
      detalhe JSONB
    )`);
  // Tenant (2c): resultados por instituição. Linhas existentes = HUSF.
  await pool.query(`ALTER TABLE atb_regras_check ADD COLUMN IF NOT EXISTS instituicao TEXT`);
  await pool.query(`UPDATE atb_regras_check SET instituicao='HUSF' WHERE instituicao IS NULL`);
}
export async function getLatestRegrasCheck(pool, inst = 'HUSF') {
  const { rows: [row] } = await pool.query(
    'SELECT id, ran_at, ok, total, passed, failed, detalhe FROM atb_regras_check WHERE instituicao=$1 ORDER BY ran_at DESC LIMIT 1',
    [inst]);
  return row || null;
}
export function startRegrasCheckSchedule(pool) {
  // Job de fundo. Modelos suportados:
  //  • por-env (ATB_TENANT setado): checa só esse tenant.
  //  • por-subdomínio / legado (sem env): checa CADA instituição ativa, cada uma
  //    com seu resultado tagueado (getLatest é escopado, cada painel vê só o seu).
  //    No HUSF de hoje isso inclui HUSF; o check do HUSF continua igual ao atual.
  const run = async () => {
    try {
      const fixo = envTenant();
      const alvos = fixo
        ? [fixo]
        : (await pool.query('SELECT sigla FROM atb_instituicoes WHERE ativo=true ORDER BY id')).rows.map(r => r.sigla);
      for (const sigla of alvos) {
        await runRegrasCheck(pool, sigla)
          .catch(e => console.error('[atb] regras-check run', sigla, '-', e.message));
      }
    } catch (e) {
      console.error('[atb] regras-check schedule:', e.message);
    }
  };
  setTimeout(run, 45 * 1000);             // ~45s após o boot
  setInterval(run, 8 * 60 * 60 * 1000);   // a cada 8 horas
}

// ── card (estilos inline; não depende do CSS da página) ──────────────────────
export function renderRegrasCard(rc) {
  const wrap = (bg, br, fg, titulo, sub) =>
    `<div style="display:flex;align-items:center;gap:12px;margin:14px 0;padding:12px 16px;border:1px solid ${br};background:${bg};border-radius:10px;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif">
       <span style="width:11px;height:11px;border-radius:50%;background:${fg};flex:0 0 auto"></span>
       <div><div style="font-weight:700;color:${fg};font-size:14px">${titulo}</div>
       <div style="color:#5f6368;font-size:12px;margin-top:1px">${sub}</div></div></div>`;
  if (!rc) return wrap('#f4f6f9', '#e0e2e6', '#80868b', 'Regras: ainda não verificadas', 'A primeira verificação roda em instantes.');
  const quando = rc.ran_at
    ? new Date(rc.ran_at).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })
    : '—';
  if (rc.ok) return wrap('#f1faf4', '#bfe6cf', '#1a8a52', 'Regras OK',
    `Triagem, obrigatoriedade, preenchimento e operador×tipo: ${rc.passed}/${rc.total} testes OK · ${quando}`);
  return wrap('#fdf2f2', '#f3c2c2', '#c0392b', 'Regras com FALHA',
    `${rc.failed} de ${rc.total} testes falharam · verificado ${quando}`);
}

function _esc(v){ return String(v == null ? '' : v).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function _tabelaFalhas(detalhe){
  const f = (detalhe || []).filter(d => !d.ok);
  if (!f.length) return '<p style="color:#1a8a52;font-size:13px;margin-top:8px">Todos os testes passaram.</p>';
  const linhas = f.map(d =>
    `<tr><td style="padding:6px 10px;border-top:1px solid #eee">${_esc(d.caso || d.alvo)}</td>` +
    `<td style="padding:6px 10px;border-top:1px solid #eee;color:#5f6368">${_esc(d.cond || '')}</td>` +
    `<td style="padding:6px 10px;border-top:1px solid #eee">${_esc(d.erro || '')}</td></tr>`).join('');
  return `<table style="border-collapse:collapse;width:100%;font-size:13px;margin-top:8px">
    <thead><tr style="text-align:left;color:#80868b"><th style="padding:6px 10px">Item</th><th style="padding:6px 10px">Condição</th><th style="padding:6px 10px">Problema</th></tr></thead>
    <tbody>${linhas}</tbody></table>`;
}

// ── rotas: painel combinado (Envio + Lógica) + run + visibilidade (opt-in) ───
export function registerRegrasCheckRoutes(app, pool, adminRequired) {
  // Instituição por requisição: tenant-lock > ?inst= > HUSF (legado idêntico).
  const instReq = (req) =>
    req.atbTenant ||
    String((req.query && req.query.inst) || 'HUSF').replace(/[^A-Za-z0-9_]/g, '') ||
    'HUSF';

  // painel combinado para o /scih
  app.get('/atb/admin/regras-check/painel', adminRequired, async (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    const inst = instReq(req);
    try {
      const rc = req.query.run === '1' ? await runRegrasCheck(pool, inst) : await getLatestRegrasCheck(pool, inst);
      const hc = await getLatestHealthcheck(pool).catch(() => null);
      res.send(`<!doctype html><html lang="pt-br"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1"><title>Saúde do sistema</title></head>
        <body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:880px;margin:24px auto;padding:0 16px;color:#202124">
        <h1 style="font-size:18px;margin:0 0 4px">Saúde do sistema</h1>

        <h2 style="font-size:15px;margin:22px 0 0">Envio de fichas</h2>
        <p style="font-size:12px;color:#5f6368;margin:2px 0">É o que o banner do /consulta mostra: se prescritor/farmácia conseguem enviar ficha.</p>
        ${renderHealthCard(hc)}

        <h2 style="font-size:15px;margin:26px 0 0">Regras de triagem &amp; condicionais</h2>
        <p style="font-size:12px;color:#5f6368;margin:2px 0">Se as regras de triagem disparam quando deveriam e se a obrigatoriedade condicional é exigida.</p>
        <div style="margin:8px 0"><a href="/atb/admin/regras-check/painel?run=1" style="font-size:13px;padding:7px 12px;border:1px solid #d0d3d9;border-radius:8px;text-decoration:none;color:#1a73e8;background:#f8fafe">&#8635; Rodar verificação de regras agora</a></div>
        ${renderRegrasCard(rc)}
        ${_tabelaFalhas(rc && rc.detalhe)}

        <h2 style="font-size:15px;margin:26px 0 0">Visibilidade (opcional)</h2>
        <p style="font-size:12px;color:#5f6368;margin:2px 0">Auditoria das condições de visibilidade de campos/seções. Sob demanda — não roda sozinho.</p>
        <div style="margin:8px 0"><a href="/atb/admin/regras-check/visibilidade" style="font-size:13px;padding:7px 12px;border:1px solid #d0d3d9;border-radius:8px;text-decoration:none;color:#1a73e8;background:#f8fafe">Rodar auditoria de visibilidade</a></div>

        <p style="margin-top:22px"><a href="/scih" style="font-size:13px;color:#5f6368">&#8592; Voltar ao Portal do SCIH</a></p>
        </body></html>`);
    } catch (e) { res.status(500).send('Erro: ' + e.message); }
  });

  // visibilidade opt-in (sob demanda; não grava)
  app.get('/atb/admin/regras-check/visibilidade', adminRequired, async (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    try {
      const vc = await runVisibilidadeCheck(pool, instReq(req));
      const card = vc.ok
        ? `<div style="margin:12px 0;padding:12px 16px;border:1px solid #bfe6cf;background:#f1faf4;border-radius:10px;color:#1a8a52;font-weight:700">Visibilidade OK — ${vc.passed}/${vc.total} condições válidas</div>`
        : `<div style="margin:12px 0;padding:12px 16px;border:1px solid #f3c2c2;background:#fdf2f2;border-radius:10px;color:#c0392b;font-weight:700">${vc.failed} de ${vc.total} condições com problema</div>`;
      const sempre = (vc.detalhe || []).filter(d => d.sempreVisivel && d.ok);
      const nota = sempre.length
        ? `<p style="font-size:12px;color:#5f6368">Aviso (não é erro): ${sempre.length} condição(ões) ficam visíveis mesmo com o formulário vazio.</p>` : '';
      res.send(`<!doctype html><html lang="pt-br"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1"><title>Auditoria de visibilidade</title></head>
        <body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:880px;margin:24px auto;padding:0 16px;color:#202124">
        <h1 style="font-size:18px;margin:0">Auditoria de visibilidade</h1>
        <p style="font-size:12px;color:#5f6368">Server-side: confere referências e se cada condição é satisfazível. Não testa renderização no navegador (isso exige o harness de formulário).</p>
        ${card}${nota}${_tabelaFalhas(vc.detalhe)}
        <p style="margin-top:18px"><a href="/atb/admin/regras-check/painel" style="font-size:13px;color:#5f6368">&#8592; Voltar</a></p>
        </body></html>`);
    } catch (e) { res.status(500).send('Erro: ' + e.message); }
  });
}
