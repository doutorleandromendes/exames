// atb-lab-scmi.js — Resultados de laboratório · SCMI (portal Banco de Resultados)
// ──────────────────────────────────────────────────────────────────────────────
// Porte para Node do busca_resultados.py: login por unidade no portal de
// resultados da SCMI (HTTP puro — form login + API JSON), busca por nome do
// paciente em todas as unidades em paralelo, e proxy autenticado dos laudos.
//
// Rotas (todas protegidas pela auth passada em registerLabScmiRoutes):
//   GET /atb/scmi/lab?ficha=ID[&nome=...&dias=30]  → página de resultados
//   GET /atb/scmi/lab/laudo?u=UNIDADE&id=ID_DOC    → proxy do laudo (sessão do servidor)
//   GET /atb/scmi/lab/diag[?u=UNIDADE]             → teste de login (geo/credencial)
//
// Config:
//   SCMI_LAB_SENHA (env, obrigatória) — senha compartilhada das unidades.
//   BASE_URL e UNIDADES ficam no código (decisão do Dr. Leandro, 2026-07-08).
//
// Sessões: cache em memória por unidade (cookie jar próprio, TTL 20 min),
// relogin automático em caso de sessão expirada (retry único por busca).
// Sucesso de login = presença do cookie `listarestricao` (mesmo critério do
// script Python).

const BASE_URL = 'https://www.resultados.com.br';

const UNIDADES = [
  'enfermaria',
  'emergencia',
  'apartamento',
  'executivo',
  'pediatria',
  'prontosocorro',
  'Uti1',
  'Uti2',
  'Utineo',
  'Maternidade',
];

const UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15';

const SESSAO_TTL_MS = 20 * 60 * 1000; // 20 min
const TIMEOUT_MS    = 20000;
const MAX_PAGINAS   = 50;             // trava de segurança na paginação

const senhaEnv = () => process.env.SCMI_LAB_SENHA || '';

// ── Cookie jar mínimo + fetch com redirects manuais ─────────────────────────
// fetch nativo não preserva cookies entre hops de redirect; o portal seta o
// cookie de sessão justamente durante o redirect pós-login, então seguimos os
// redirects manualmente absorvendo Set-Cookie a cada hop.

function novoJar() { return new Map(); }

function absorverCookies(jar, res) {
  let sets = [];
  if (typeof res.headers.getSetCookie === 'function') {
    sets = res.headers.getSetCookie();
  } else {
    const s = res.headers.get('set-cookie');
    if (s) sets = s.split(/,(?=[^;=]+=)/); // fallback (split conservador)
  }
  for (const sc of sets) {
    const [par] = String(sc).split(';');
    const eq = par.indexOf('=');
    if (eq > 0) jar.set(par.slice(0, eq).trim(), par.slice(eq + 1).trim());
  }
}

function cookieHeader(jar) {
  return [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
}

async function fetchJar(jar, url, opts = {}, maxRedirs = 6) {
  let metodo  = opts.method || 'GET';
  let body    = opts.body;
  let headers = { ...(opts.headers || {}) };
  let alvo    = url;

  for (let i = 0; i <= maxRedirs; i++) {
    const h = { 'User-Agent': UA, ...headers };
    const ck = cookieHeader(jar);
    if (ck) h.Cookie = ck;

    const res = await fetch(alvo, {
      method: metodo, headers: h, body,
      redirect: 'manual',
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    absorverCookies(jar, res);

    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const loc = res.headers.get('location');
      if (!loc) { res.urlFinal = alvo; return res; }
      try { await res.arrayBuffer(); } catch {} // libera o socket
      alvo = new URL(loc, alvo).toString();
      if (res.status !== 307 && res.status !== 308) {
        metodo = 'GET'; body = undefined;
        delete headers['Content-Type'];
      }
      continue;
    }
    res.urlFinal = alvo;
    return res;
  }
  throw new Error('Redirecionamentos em excesso');
}

// ── Login (porte fiel do fazer_login do Python) ──────────────────────────────

function extrairFormLogin(html) {
  const m = html.match(/<form\b[^>]*>[\s\S]*?<\/form>/i);
  if (!m) throw new Error('Formulário de login não encontrado');
  const formHtml = m[0];
  const action = (formHtml.match(/<form\b[^>]*\baction\s*=\s*["']?([^"'\s>]*)/i) || [])[1] || '/';
  const inputs = [];
  const rx = /<input\b[^>]*>/gi;
  let im;
  while ((im = rx.exec(formHtml))) {
    const tag  = im[0];
    const name = (tag.match(/\bname\s*=\s*["']?([^"'\s>]+)/i) || [])[1];
    if (!name) continue;
    const value = (tag.match(/\bvalue\s*=\s*["']([^"']*)["']/i) || [])[1] || '';
    const type  = ((tag.match(/\btype\s*=\s*["']?([^"'\s>]+)/i) || [])[1] || 'text').toLowerCase();
    inputs.push({ name, value, type });
  }
  return { action, inputs };
}

async function fazerLogin(chave) {
  const senha = senhaEnv();
  if (!senha) throw new Error('SCMI_LAB_SENHA não configurada');

  const jar = novoJar();
  const r1 = await fetchJar(jar, BASE_URL + '/');
  if (!r1.ok) throw new Error(`Página de login: HTTP ${r1.status}`);
  const html = await r1.text();

  const { action, inputs } = extrairFormLogin(html);
  const alvo = action.startsWith('http')
    ? action
    : BASE_URL + (action.startsWith('/') ? action : '/' + action);

  const dados = new URLSearchParams();
  let temChave = false, temSenha = false;
  for (const inp of inputs) {
    const fl = inp.name.toLowerCase();
    if (!temChave && /(chave|identif|usuario|login|user)/.test(fl)) {
      dados.set(inp.name, chave); temChave = true;
    } else if (!temSenha && /(senha|password|pass|pwd)/.test(fl)) {
      dados.set(inp.name, senha); temSenha = true;
    } else {
      dados.set(inp.name, inp.value);
    }
  }
  if (!temChave || !temSenha) {
    const texto = inputs.filter(i => ['text', 'email', ''].includes(i.type));
    const pwd   = inputs.filter(i => i.type === 'password');
    if (!temChave && texto[0]) dados.set(texto[0].name, chave);
    if (!temSenha && pwd[0])   dados.set(pwd[0].name, senha);
  }

  const r2 = await fetchJar(jar, alvo, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: dados.toString(),
  });

  if (!jar.has('listarestricao')) {
    throw new Error(`Login falhou (${chave}) — URL final: ${r2.urlFinal || '?'}`);
  }
  if (!String(r2.urlFinal || '').includes('/Lista')) {
    try { const rl = await fetchJar(jar, BASE_URL + '/Lista'); await rl.arrayBuffer(); } catch {}
  }
  return jar;
}

// ── Cache de sessões por unidade ─────────────────────────────────────────────

const _sessoes = new Map(); // unidade → { jar, ts }

async function obterSessao(unidade, forcarNova = false) {
  const s = _sessoes.get(unidade);
  if (!forcarNova && s && (Date.now() - s.ts) < SESSAO_TTL_MS) return s.jar;
  const jar = await fazerLogin(unidade);
  _sessoes.set(unidade, { jar, ts: Date.now() });
  return jar;
}

// ── Busca ────────────────────────────────────────────────────────────────────

function parseDataMs(v) {
  const m = String(v || '').match(/\d+/);
  if (!m) return null;
  const d = new Date(Number(m[0]));
  return Number.isNaN(d.getTime()) ? null : d;
}

function parseExames(ds) {
  if (!ds) return [];
  try {
    let raw = JSON.parse(ds)?.SL_EXAMES?.EXAME ?? [];
    if (!Array.isArray(raw)) raw = [raw];
    return raw.map(e => (e && typeof e === 'object' ? e.NOME : null)).filter(Boolean);
  } catch { return []; }
}

async function pesquisar(jar, nome, dataIni, dataFim, pagina = 1) {
  const res = await fetchJar(jar, `${BASE_URL}/Lista/PesquisarResultados/`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      'Origin': BASE_URL,
      'Referer': `${BASE_URL}/Lista`,
    },
    body: JSON.stringify({
      tipo: 'di', titulo: nome,
      data_ini: dataIni, data_fim: dataFim,
      pasta: 1, pagina,
    }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const ct = res.headers.get('content-type') || '';
  if (!ct.includes('json')) throw new Error('Resposta não-JSON (sessão expirada?)');
  const data = await res.json();
  if (Array.isArray(data)) return data;
  if (data && typeof data === 'object') {
    for (const v of Object.values(data)) if (Array.isArray(v)) return v;
  }
  return [];
}

async function buscarUnidade(unidade, nome, dataIni, dataFim) {
  const rodar = async (jar) => {
    const out = [];
    let pagina = 1;
    for (;;) {
      const items = await pesquisar(jar, nome, dataIni, dataFim, pagina);
      if (!items.length) break;
      for (const item of items) {
        out.push({
          unidade,
          id_doc:        item.id_doc,
          titulo:        item.nm_doc_titulo || '',
          dt_coleta:     parseDataMs(item.dt_doc_real),
          dt_disponivel: parseDataMs(item.dt_doc_incl),
          exames:        parseExames(item.ds_doc_exames || ''),
          critico:       item.id_doc_crit === 'S',
        });
      }
      if (items.length < 20 || pagina >= MAX_PAGINAS) break;
      pagina++;
    }
    return out;
  };

  try {
    return await rodar(await obterSessao(unidade));
  } catch (_e) {
    // sessão pode ter expirado — relogin e retry único
    return await rodar(await obterSessao(unidade, true));
  }
}

function semAcentos(s) {
  return String(s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

async function buscarTodas(nome, dias) {
  const hoje    = new Date();
  const ini     = new Date(hoje.getTime() - dias * 86400000);
  const fmt     = (d) => d.toISOString().slice(0, 10);
  const dataIni = fmt(ini);
  const dataFim = fmt(hoje);

  const rodada = async (n) => {
    const settled = await Promise.allSettled(
      UNIDADES.map(u => buscarUnidade(u, n, dataIni, dataFim))
    );
    const resultados = [];
    const erros = [];
    settled.forEach((r, idx) => {
      if (r.status === 'fulfilled') resultados.push(...r.value);
      else erros.push({ unidade: UNIDADES[idx], erro: String(r.reason?.message || r.reason) });
    });
    return { resultados, erros };
  };

  let { resultados, erros } = await rodada(nome);

  // Fallback: nome com acentos e zero resultados → tenta sem acentos
  const plano = semAcentos(nome);
  if (!resultados.length && plano !== nome) {
    const seg = await rodada(plano);
    if (seg.resultados.length) ({ resultados, erros } = seg);
  }

  resultados.sort((a, b) => (b.dt_coleta?.getTime() || 0) - (a.dt_coleta?.getTime() || 0));
  return { resultados, erros, dataIni, dataFim };
}

// ── Página HTML ──────────────────────────────────────────────────────────────

function esc(v) {
  return String(v == null ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const fmtDataHora = (d) => d
  ? d.toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo', day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })
  : '—';

function paginaResultados({ nome, dias, fichaId, resultados, erros, dataIni, dataFim, aviso }) {
  const qsBase = (d) => {
    const p = new URLSearchParams();
    if (fichaId) p.set('ficha', fichaId);
    else p.set('nome', nome);
    p.set('dias', String(d));
    return `/atb/scmi/lab?${p}`;
  };
  const periodos = [7, 15, 30, 90, 180, 365].map(d =>
    `<a class="per${d === dias ? ' ativo' : ''}" href="${qsBase(d)}">${d}d</a>`).join('');

  const linhas = resultados.map(r => `
      <tr${r.critico ? ' class="crit"' : ''}>
        <td>${fmtDataHora(r.dt_coleta)}</td>
        <td><strong>${esc(String(r.unidade).toUpperCase())}</strong></td>
        <td class="tit">${esc(r.titulo)}${r.critico ? ' ⚠' : ''}</td>
        <td class="exs">${esc(r.exames.join(', ') || '—')}</td>
        <td><a target="_blank" rel="noopener" href="/atb/scmi/lab/laudo?u=${encodeURIComponent(r.unidade)}&id=${encodeURIComponent(r.id_doc)}">Abrir →</a></td>
      </tr>`).join('');

  const errosHtml = erros.length
    ? `<div class="erros">Unidades com erro: ${erros.map(e => `<b>${esc(e.unidade)}</b> (${esc(e.erro)})`).join(' · ')}</div>`
    : '';

  const voltar = fichaId
    ? `<a class="voltar" href="/atb/admin/ficha/${esc(fichaId)}">← ficha</a>` : '';

  return `<!DOCTYPE html>
<html lang="pt-BR"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lab SCMI · ${esc(nome)}</title>
<style>
  body  { font-family: system-ui, -apple-system, sans-serif; max-width: 1200px;
          margin: 1.6em auto; padding: 0 1em; color: #222; background:#fafbfc; }
  h1    { font-size: 1.15em; color: #1a4f7a; margin: 0 0 .15em; }
  .sub  { color: #666; font-size: .87em; margin: 0 0 1em; }
  .voltar { font-size:.85em; color:#1a4f7a; text-decoration:none; margin-right:10px; }
  form.busca { display:flex; gap:8px; align-items:center; margin: 0 0 1em; flex-wrap:wrap; }
  form.busca input[name=nome] { padding:6px 10px; border:1px solid #cfd6dd; border-radius:6px;
          font-size:.95em; min-width:280px; }
  form.busca button { padding:6px 14px; border:0; border-radius:6px; background:#1a4f7a;
          color:#fff; font-size:.9em; cursor:pointer; }
  .pers { display:inline-flex; gap:4px; margin-left:6px; }
  a.per { padding:4px 9px; border-radius:14px; font-size:.8em; text-decoration:none;
          background:#eef0f2; color:#5f6368; }
  a.per.ativo { background:#1a4f7a; color:#fff; font-weight:600; }
  table { width:100%; border-collapse:collapse; font-size:.9em; background:#fff;
          border:1px solid #e4e8ec; border-radius:8px; overflow:hidden; }
  th    { background:#1a4f7a; color:#fff; padding:.55em 1em; text-align:left; font-weight:500; }
  td    { padding:.5em 1em; border-bottom:1px solid #eceff2; vertical-align:top; }
  tr:hover td { background:#f0f6ff; }
  tr.crit td  { background:#fff6dd; }
  td.tit { font-size:.93em; }
  td.exs { font-size:.84em; color:#555; }
  a     { color:#1a4f7a; }
  .erros { background:#fdecea; border-left:4px solid #d93025; padding:.55em .9em;
           font-size:.85em; margin: 0 0 1em; border-radius:0 6px 6px 0; }
  .aviso { background:#e8f4fd; border-left:4px solid #1a4f7a; padding:.55em .9em;
           font-size:.85em; margin: 0 0 1em; border-radius:0 6px 6px 0; }
  .vazio { color:#888; padding: 1.5em 0; text-align:center; font-size:.95em; }
</style></head>
<body>
  <h1>${voltar}🔬 Resultados de laboratório — SCMI</h1>
  <p class="sub">${esc(nome)} · ${resultados.length} coleta(s) · ${esc(dataIni)} → ${esc(dataFim)}</p>
  <form class="busca" method="GET" action="/atb/scmi/lab">
    ${fichaId ? `<input type="hidden" name="ficha" value="${esc(fichaId)}">` : ''}
    <input name="nome" value="${esc(nome)}" placeholder="Nome do paciente (mín. 3 letras)">
    <input type="hidden" name="dias" value="${dias}">
    <button type="submit">Buscar</button>
    <span class="pers">${periodos}</span>
  </form>
  ${aviso ? `<div class="aviso">${esc(aviso)}</div>` : ''}
  ${errosHtml}
  ${resultados.length ? `<table>
    <thead><tr><th>Data coleta</th><th>Unidade</th><th>Título</th><th>Exames</th><th>Laudo</th></tr></thead>
    <tbody>${linhas}</tbody>
  </table>` : `<div class="vazio">Nenhum resultado no período — tente ampliar o intervalo ou encurtar o nome.</div>`}
</body></html>`;
}

function paginaErro(titulo, msg) {
  return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(titulo)}</title>
<style>body{font-family:system-ui,sans-serif;max-width:680px;margin:3em auto;padding:0 1em;color:#222}
h1{font-size:1.1em;color:#1a4f7a}.box{background:#fdecea;border-left:4px solid #d93025;
padding:.8em 1em;font-size:.92em;border-radius:0 6px 6px 0}</style></head>
<body><h1>${esc(titulo)}</h1><div class="box">${esc(msg)}</div></body></html>`;
}

// ── Rotas ────────────────────────────────────────────────────────────────────

export function registerLabScmiRoutes(app, pool, adminRequired) {

  // Página de resultados
  app.get('/atb/scmi/lab', adminRequired, async (req, res) => {
    try {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      if (!senhaEnv()) {
        return res.status(500).send(paginaErro('Lab SCMI — configuração pendente',
          'A variável de ambiente SCMI_LAB_SENHA não está configurada no Render.'));
      }

      const fichaId = String(req.query.ficha || '').replace(/\D/g, '') || null;
      let nome = String(req.query.nome || '').trim();

      if (!nome && fichaId) {
        const { rows: [f] } = await pool.query(
          `SELECT COALESCE(NULLIF(paciente_nome,''), paciente_nome_raw) AS nome
             FROM atb_fichas WHERE id = $1`, [fichaId]);
        if (!f) return res.status(404).send(paginaErro('Lab SCMI', 'Ficha não encontrada.'));
        nome = String(f.nome || '').trim();
      }
      if (nome.length < 3) {
        return res.status(400).send(paginaErro('Lab SCMI',
          'Informe um nome com pelo menos 3 letras (?nome=... ou ?ficha=ID).'));
      }

      let dias = parseInt(String(req.query.dias || '30'), 10);
      if (!Number.isFinite(dias) || dias < 1) dias = 30;
      if (dias > 730) dias = 730;

      const { resultados, erros, dataIni, dataFim } = await buscarTodas(nome, dias);
      res.send(paginaResultados({ nome, dias, fichaId, resultados, erros, dataIni, dataFim }));
    } catch (e) {
      console.error('LAB SCMI ERRO', e);
      res.status(502).send(paginaErro('Lab SCMI — erro',
        `Falha ao consultar o portal: ${String(e.message || e)}`));
    }
  });

  // Proxy autenticado do laudo (equivalente ao proxy local do script Python)
  app.get('/atb/scmi/lab/laudo', adminRequired, async (req, res) => {
    try {
      const unidade = String(req.query.u || '');
      const id      = String(req.query.id || '').replace(/[^\w-]/g, '');
      if (!UNIDADES.includes(unidade) || !id) {
        return res.status(400).send('Parâmetros inválidos');
      }

      const abrir = async (forcar) => fetchJar(
        await obterSessao(unidade, forcar), `${BASE_URL}/Laudo/Index/${id}`);

      let r = await abrir(false);
      if (!r.ok) r = await abrir(true);
      // Se caiu de volta na tela de login (HTML sem sessão), relogin único
      let ct = r.headers.get('content-type') || 'text/html';
      let corpoHtml = null;
      if (ct.includes('text/html')) {
        corpoHtml = await r.text();
        if (/type\s*=\s*["']?password/i.test(corpoHtml)) {
          r = await abrir(true);
          ct = r.headers.get('content-type') || 'text/html';
          corpoHtml = ct.includes('text/html') ? await r.text() : null;
        }
      }

      res.status(r.status);
      res.setHeader('Content-Type', ct);
      // sem CSP — deixamos o laudo carregar CSS/JS do portal

      if (corpoHtml != null) {
        // Reescreve caminhos relativos → absolutos do portal (href/src/action
        // que começam com "/" mas não "//")
        const html = corpoHtml.replace(
          /(href|src|action)=(["'])\/(?!\/)/gi,
          (_m, a, q) => `${a}=${q}${BASE_URL}/`
        );
        res.send(html);
      } else {
        res.send(Buffer.from(await r.arrayBuffer()));
      }
    } catch (e) {
      console.error('LAB SCMI LAUDO ERRO', e);
      res.status(502).send(`Falha ao abrir o laudo: ${String(e.message || e)}`);
    }
  });

  // Diagnóstico: login de teste (responde se o Render alcança o portal)
  app.get('/atb/scmi/lab/diag', adminRequired, async (req, res) => {
    const t0 = Date.now();
    if (!senhaEnv()) return res.json({ ok: false, erro: 'SCMI_LAB_SENHA não configurada' });
    const unidade = UNIDADES.includes(String(req.query.u)) ? String(req.query.u) : UNIDADES[0];
    try {
      const jar = await fazerLogin(unidade); // login sempre fresco — é um teste
      res.json({ ok: true, unidade, cookies: [...jar.keys()], ms: Date.now() - t0 });
    } catch (e) {
      res.json({ ok: false, unidade, erro: String(e.message || e), ms: Date.now() - t0 });
    }
  });
}
