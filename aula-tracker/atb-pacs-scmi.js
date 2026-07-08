// atb-pacs-scmi.js — Exames de imagem · SCMI (PACS Medilab)
// ──────────────────────────────────────────────────────────────────────────────
// Integração server-side com o portal Medilab da SCMI. Contrato capturado por
// inspeção (2026-07-08):
//   • Login:  POST /auth   campos loginUsuario / loginSenha  → cookie de sessão
//             (o g-recaptcha-response é vestigial: sem script/sitekey no portal)
//   • Busca:  POST /lista_laudos  (form-urlencoded — NÃO json)
//               { order, limit, offset, data_inicio, data_final, estado:"todos",
//                 tipo_filtro:"NOMEPACIENTE", filtro:<NOME>, filtroFiliais:"NONE" }
//             → { result:"ok", total, rows:[ {nome, patientID, dataNasc, data,
//                 modalidade, tipoExame, numero, imagem:"T|F", laudo:"T|F",
//                 tokenReq, ...} ] }
//   • Viewer: /viewer?os_exame=<tokenReq>   (os_exame === tokenReq — confirmado)
//             É um viewer DICOM completo (cornerstone/WADO) que renderiza no
//             cliente. Por isso NÃO proxiamos: o servidor só faz a busca (leve,
//             texto) e cada estudo vira um link direto que abre no navegador do
//             usuário, onde ele já tem sessão Medilab. Nenhum pixel DICOM passa
//             pelo Render.
//
// Rotas (protegidas pela auth passada em registerPacsScmiRoutes):
//   GET /atb/scmi/pacs?ficha=ID[&nome=...&dias=180]  → página de estudos
//   GET /atb/scmi/pacs/diag                           → teste de login (geo/cred)
//
// Config: SCMI_MEDILAB_SENHA (env, obrigatória). Usuário, base URL e contrato
// ficam no código (decisão do Dr. Leandro, 2026-07-08).

const BASE_URL   = 'https://medilab.santacasadeitatiba.org.br';
const USUARIO    = 'medico';              // usuário compartilhado do acesso SCMI
const VIEWER_URL = (token) => `${BASE_URL}/viewer?os_exame=${encodeURIComponent(token)}`;

const UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15';

const SESSAO_TTL_MS = 20 * 60 * 1000; // 20 min
const TIMEOUT_MS    = 20000;
const DIAS_PADRAO   = 180;            // PACS: janela mais larga que o lab
const MAX_LINHAS    = 200;

const senhaEnv = () => process.env.SCMI_MEDILAB_SENHA || '';

// ── Cookie jar + fetch com redirects manuais (idêntico em espírito ao lab) ──

function novoJar() { return new Map(); }

function absorverCookies(jar, res) {
  let sets = [];
  if (typeof res.headers.getSetCookie === 'function') sets = res.headers.getSetCookie();
  else { const s = res.headers.get('set-cookie'); if (s) sets = s.split(/,(?=[^;=]+=)/); }
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
      try { await res.arrayBuffer(); } catch {}
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

// ── Login ────────────────────────────────────────────────────────────────────
// Contrato do login (confirmado por inspeção 2026-07-08):
// O portal trata /auth em modo AJAX quando recebe X-Requested-With: XMLHttpRequest
// — responde HTTP 200 com JSON `[{"status":"1"}]` no sucesso (sem campo `falha`),
// ou `[{"falha":"T","status":"0","msg":"..."}]` no erro. É NESSE POST que a sessão
// é estabelecida (não há redirect no modo AJAX). Sem o header, o servidor
// responde com 302 (fluxo de form nativo) — evitamos esse caminho.
async function fazerLogin() {
  const senha = senhaEnv();
  if (!senha) throw new Error('SCMI_MEDILAB_SENHA não configurada');

  const jar = novoJar();
  // GET inicial para semear cookie de sessão
  const r0 = await fetchJar(jar, BASE_URL + '/login');
  try { await r0.arrayBuffer(); } catch {}

  const dados = new URLSearchParams();
  dados.set('g-recaptcha-response', '');
  dados.set('action', 'homepage');
  dados.set('loginUsuario', USUARIO);
  dados.set('loginSenha', senha);

  const r = await fetchJar(jar, BASE_URL + '/auth', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-Requested-With': 'XMLHttpRequest',   // ativa o modo AJAX → JSON de status
      'Origin': BASE_URL,
      'Referer': BASE_URL + '/login',
    },
    body: dados.toString(),
  });

  // Resposta esperada: JSON [{status:"1"}] (ok) ou [{falha:"T",status:"0",msg}] (erro)
  let obj = null;
  try {
    const txt = await r.text();
    const j = JSON.parse(txt);
    obj = Array.isArray(j) ? j[0] : j;
  } catch {
    throw new Error(`Login: resposta inesperada de /auth (HTTP ${r.status})`);
  }

  const ok = obj && (String(obj.status) === '1') && (obj.falha == null || obj.falha === 'F');
  if (!ok) {
    const msg = (obj && obj.msg) ? String(obj.msg) : 'credencial recusada';
    throw new Error(`Login recusado pelo Medilab: ${msg}`);
  }
  return jar;
}

// ── Cache de sessão ──────────────────────────────────────────────────────────

let _sessao = null; // { jar, ts }

async function obterSessao(forcarNova = false) {
  if (!forcarNova && _sessao && (Date.now() - _sessao.ts) < SESSAO_TTL_MS) return _sessao.jar;
  const jar = await fazerLogin();
  _sessao = { jar, ts: Date.now() };
  return jar;
}

// ── Busca de estudos ─────────────────────────────────────────────────────────

function semAcentos(s) {
  return String(s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

async function listaLaudos(jar, nome, dataIni, dataFim) {
  // IMPORTANTE: o /lista_laudos só aplica o filtro por nome quando o corpo vem
  // FORM-URLENCODED. Com application/json o servidor ignora o filtro e responde
  // total geral com rows:[] (confirmado por inspeção 2026-07-08).
  const params = new URLSearchParams();
  params.set('order', 'DESC');
  params.set('limit', String(MAX_LINHAS));
  params.set('offset', '0');
  params.set('data_inicio', dataIni);
  params.set('data_final', dataFim);
  params.set('estado', 'todos');
  params.set('tipo_filtro', 'NOMEPACIENTE');
  params.set('filtro', nome);
  params.set('filtroFiliais', 'NONE');

  const res = await fetchJar(jar, `${BASE_URL}/lista_laudos`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
      'X-Requested-With': 'XMLHttpRequest',
      'Origin': BASE_URL,
      'Referer': `${BASE_URL}/exames`,
    },
    body: params.toString(),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const ct = res.headers.get('content-type') || '';
  if (!ct.includes('json')) throw new Error('Resposta não-JSON (sessão expirada?)');
  const data = await res.json();
  const rows = Array.isArray(data?.rows) ? data.rows : (Array.isArray(data) ? data : []);
  return rows;
}

async function buscarEstudos(nome, dias) {
  const hoje    = new Date();
  const ini     = new Date(hoje.getTime() - dias * 86400000);
  const fmt     = (d) => d.toISOString().slice(0, 10);
  const dataIni = fmt(ini);
  const dataFim = fmt(hoje);

  const rodar = async (n) => {
    try {
      return await listaLaudos(await obterSessao(), n, dataIni, dataFim);
    } catch (_e) {
      return await listaLaudos(await obterSessao(true), n, dataIni, dataFim); // relogin único
    }
  };

  let rows = await rodar(nome);
  const plano = semAcentos(nome);
  if (!rows.length && plano !== nome) {
    const seg = await rodar(plano);
    if (seg.length) rows = seg;
  }

  const norm = rows.map(r => ({
    nome:       r.nome || '',
    patientID:  r.patientID || '',
    dataNasc:   r.dataNasc || '',
    data:       r.data || '',
    modalidade: r.modalidade || '',
    tipoExame:  r.tipoExame || '',
    numero:     r.numero || '',
    temImagem:  r.imagem === 'T',
    temLaudo:   r.laudo === 'T',
    token:      r.tokenReq || '',
  })).filter(e => e.token);

  norm.sort((a, b) => String(b.data).localeCompare(String(a.data)));
  return { estudos: norm, dataIni, dataFim };
}

// ── HTML ─────────────────────────────────────────────────────────────────────

function esc(v) {
  return String(v == null ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const fmtData = (s) => {
  const m = String(s || '').match(/^(\d{4})-(\d{2})-(\d{2})/);
  return m ? `${m[3]}/${m[2]}/${m[1]}` : (s || '—');
};

function paginaEstudos({ nome, dias, fichaId, estudos, dataIni, dataFim }) {
  const qsBase = (d) => {
    const p = new URLSearchParams();
    if (fichaId) p.set('ficha', fichaId); else p.set('nome', nome);
    p.set('dias', String(d));
    return `/atb/scmi/pacs?${p}`;
  };
  const periodos = [30, 90, 180, 365, 730].map(d =>
    `<a class="per${d === dias ? ' ativo' : ''}" href="${qsBase(d)}">${d}d</a>`).join('');

  const linhas = estudos.map(e => {
    const badges =
      (e.temImagem ? '<span class="bg img">imagem</span>' : '') +
      (e.temLaudo  ? '<span class="bg lau">laudo</span>'  : '');
    return `
      <tr>
        <td>${esc(fmtData(e.data))}</td>
        <td><span class="mod">${esc(e.modalidade || '—')}</span></td>
        <td class="tit">${esc(e.tipoExame || '—')}</td>
        <td class="pac">${esc(e.nome)}${e.dataNasc ? ` · ${esc(fmtData(e.dataNasc))}` : ''}</td>
        <td>${badges || '—'}</td>
        <td><a class="abrir" target="_blank" rel="noopener" href="${esc(VIEWER_URL(e.token))}">Abrir →</a></td>
      </tr>`;
  }).join('');

  const voltar = fichaId
    ? `<a class="voltar" href="/atb/admin/ficha/${esc(fichaId)}">← ficha</a>` : '';

  return `<!DOCTYPE html>
<html lang="pt-BR"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Imagens SCMI · ${esc(nome)}</title>
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
  td    { padding:.5em 1em; border-bottom:1px solid #eceff2; vertical-align:middle; }
  tr:hover td { background:#f0f6ff; }
  .mod  { display:inline-block; min-width:34px; text-align:center; font-weight:600;
          font-size:.82em; color:#1a4f7a; background:#e8f1fb; border-radius:4px; padding:1px 6px; }
  td.tit { font-size:.93em; }
  td.pac { font-size:.84em; color:#555; }
  .bg   { display:inline-block; font-size:.74em; border-radius:10px; padding:1px 8px; margin-right:4px; }
  .bg.img { background:#e3f0e4; color:#2e7d32; }
  .bg.lau { background:#fdecdd; color:#b3541e; }
  a.abrir { color:#1a4f7a; font-weight:500; text-decoration:none; }
  a.abrir:hover { text-decoration:underline; }
  .aviso { background:#e8f4fd; border-left:4px solid #1a4f7a; padding:.55em .9em;
           font-size:.83em; margin: 0 0 1em; border-radius:0 6px 6px 0; color:#33475b; }
  .vazio { color:#888; padding: 1.5em 0; text-align:center; font-size:.95em; }
</style></head>
<body>
  <h1>${voltar}🔗 Exames de imagem — SCMI (Medilab)</h1>
  <p class="sub">${esc(nome)} · ${estudos.length} estudo(s) · ${esc(fmtData(dataIni))} → ${esc(fmtData(dataFim))}</p>
  <form class="busca" method="GET" action="/atb/scmi/pacs">
    ${fichaId ? `<input type="hidden" name="ficha" value="${esc(fichaId)}">` : ''}
    <input name="nome" value="${esc(nome)}" placeholder="Nome do paciente (mín. 3 letras)">
    <input type="hidden" name="dias" value="${dias}">
    <button type="submit">Buscar</button>
    <span class="pers">${periodos}</span>
  </form>
  <div class="aviso">Os estudos abrem no visualizador do Medilab, em nova aba — use a sessão do seu navegador.</div>
  ${estudos.length ? `<table>
    <thead><tr><th>Data</th><th>Mod.</th><th>Exame</th><th>Paciente</th><th></th><th>Abrir</th></tr></thead>
    <tbody>${linhas}</tbody>
  </table>` : `<div class="vazio">Nenhum estudo no período — amplie o intervalo ou encurte o nome.</div>`}
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

export function registerPacsScmiRoutes(app, pool, adminRequired) {

  app.get('/atb/scmi/pacs', adminRequired, async (req, res) => {
    try {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      if (!senhaEnv()) {
        return res.status(500).send(paginaErro('PACS SCMI — configuração pendente',
          'A variável de ambiente SCMI_MEDILAB_SENHA não está configurada no Render.'));
      }

      const fichaId = String(req.query.ficha || '').replace(/\D/g, '') || null;
      let nome = String(req.query.nome || '').trim();

      if (!nome && fichaId) {
        const { rows: [f] } = await pool.query(
          `SELECT COALESCE(NULLIF(paciente_nome,''), paciente_nome_raw) AS nome
             FROM atb_fichas WHERE id = $1`, [fichaId]);
        if (!f) return res.status(404).send(paginaErro('PACS SCMI', 'Ficha não encontrada.'));
        nome = String(f.nome || '').trim();
      }
      if (nome.length < 3) {
        return res.status(400).send(paginaErro('PACS SCMI',
          'Informe um nome com pelo menos 3 letras (?nome=... ou ?ficha=ID).'));
      }

      let dias = parseInt(String(req.query.dias || DIAS_PADRAO), 10);
      if (!Number.isFinite(dias) || dias < 1) dias = DIAS_PADRAO;
      if (dias > 1825) dias = 1825;

      const { estudos, dataIni, dataFim } = await buscarEstudos(nome, dias);
      res.send(paginaEstudos({ nome, dias, fichaId, estudos, dataIni, dataFim }));
    } catch (e) {
      console.error('PACS SCMI ERRO', e);
      res.status(502).send(paginaErro('PACS SCMI — erro',
        `Falha ao consultar o Medilab: ${String(e.message || e)}`));
    }
  });

  // Diagnóstico: login de teste (responde se o Render alcança o Medilab)
  app.get('/atb/scmi/pacs/diag', adminRequired, async (req, res) => {
    const t0 = Date.now();
    if (!senhaEnv()) return res.json({ ok: false, erro: 'SCMI_MEDILAB_SENHA não configurada' });
    try {
      const jar = await fazerLogin(); // login sempre fresco — é um teste
      res.json({ ok: true, cookies: [...jar.keys()], ms: Date.now() - t0 });
    } catch (e) {
      res.json({ ok: false, erro: String(e.message || e), ms: Date.now() - t0 });
    }
  });
}
