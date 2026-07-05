// atb-pacs-nome-routes.js
// ─────────────────────────────────────────────────────────────────────────
// DIAGNÓSTICO (fase de verificação) — correção de nome via PACS HUSF.
//
// O PACS autentica por Spring Security com:
//   j_username = p<prontuário>     j_password = <DDMMYYYY da DN>
// (é o MESMO login que o autologin.html faz no navegador — nenhuma credencial
// nova; a "senha" é a própria DN que a ficha já guarda).
//
// Este endpoint testa, A PARTIR DO SERVIDOR (Render), se dá pra:
//   1) alcançar o PACS,  2) autenticar,  3) receber uma página onde o nome
//   (puxado do Tasy) apareça — pra então escrevermos o parser.
//
// É READ-ONLY, adminRequired, NÃO armazena nada. O trecho retornado pode conter
// PHI (o nome do paciente) e vai só pro navegador do admin que chamou.
//
// Wiring (atb-routes.js):
//   import { registerPacsNomeRoutes } from './atb-pacs-nome-routes.js';
//   registerPacsNomeRoutes(app, pool, adminRequired);

import express from 'express';

const PACS_BASE = 'https://pacs.husf.com.br';
const SIGLA = 'HUSF';
const TIMEOUT_MS = 8000;

// Deriva as credenciais do PACS a partir de prontuário + DN (mesma fórmula do link).
export function credenciaisPacs(prontuario, dn) {
  const d = String(dn || '').replace(/[^0-9]/g, ''); // YYYYMMDD (de 'AAAA-MM-DD')
  const pass = d.length >= 8 ? d.slice(6, 8) + d.slice(4, 6) + d.slice(0, 4) : ''; // DDMMYYYY
  return { user: 'p' + String(prontuario || '').trim(), pass };
}

async function instHUSF(pool) {
  const { rows } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla=$1`, [SIGLA]);
  return rows[0] ? rows[0].id : null;
}

// normalização p/ comparar com o nome da ficha (ignora acento/caixa/espaço)
function normPacsNome(s) {
  return String(s == null ? '' : s).normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .toUpperCase().replace(/\s+/g, ' ').trim();
}

export async function ensurePacsNomeSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atb_nome_pacs (
      instituicao_id  INTEGER REFERENCES atb_instituicoes(id),
      prontuario      TEXT NOT NULL,
      nome_pacs       TEXT,
      nome_pacs_norm  TEXT,
      visto_em        TIMESTAMPTZ DEFAULT now(),
      PRIMARY KEY (instituicao_id, prontuario)
    )`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atb_nome_pacs_log (
      id               BIGSERIAL PRIMARY KEY,
      ficha_id         BIGINT,
      prontuario       TEXT,
      nome_antigo      TEXT,
      nome_raw_antigo  TEXT,
      nome_novo        TEXT,
      aplicado_em      TIMESTAMPTZ DEFAULT now()
    )`);
}

// Nome do PACS para um prontuário (HUSF). Retorna {nome_pacs, nome_pacs_norm} ou null.
export async function buscarNomePacs(pool, instituicaoId, prontuario) {
  if (!prontuario) return null;
  const { rows } = await pool.query(
    `SELECT nome_pacs, nome_pacs_norm FROM atb_nome_pacs
      WHERE instituicao_id IS NOT DISTINCT FROM $1 AND prontuario = $2`,
    [instituicaoId, String(prontuario).trim()]);
  return rows[0] || null;
}

// true se o nome da ficha diverge do nome do PACS (comparação normalizada).
export function nomeDivergePacs(nomeFicha, nomePacsNorm) {
  if (!nomePacsNorm) return false;
  return normPacsNome(nomeFicha) !== nomePacsNorm;
}

async function comTimeout(fn, ms) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try { return await fn(ctrl.signal); } finally { clearTimeout(t); }
}

function pegarJsessionid(resp) {
  const arr = resp.headers.getSetCookie ? resp.headers.getSetCookie()
            : [resp.headers.get('set-cookie')].filter(Boolean);
  const m = arr.join('; ').match(/JSESSIONID=[^;]+/);
  return m ? m[0] : '';
}

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36';

// acumula cookies (Set-Cookie da resposta) sobre um jar existente
function acumulaCookies(resp, jarStr) {
  const arr = resp.headers.getSetCookie ? resp.headers.getSetCookie()
            : [resp.headers.get('set-cookie')].filter(Boolean);
  const jar = new Map();
  (jarStr || '').split('; ').filter(Boolean).forEach((kv) => { const i = kv.indexOf('='); if (i > 0) jar.set(kv.slice(0, i), kv.slice(i + 1)); });
  arr.forEach((sc) => { const f = sc.split(';')[0]; const i = f.indexOf('='); if (i > 0) jar.set(f.slice(0, i), f.slice(i + 1)); });
  return [...jar.entries()].map(([k, v]) => k + '=' + v).join('; ');
}

// procura token CSRF (hidden input _csrf, ou meta _csrf) e o form de login
function inspecionarLogin(html) {
  const info = { csrfName: '', csrfValue: '', formAction: '', temSenha: false };
  let m = html.match(/<input[^>]+name=["'](_csrf|csrf[_-]?token)["'][^>]+value=["']([^"']+)["']/i)
       || html.match(/<meta[^>]+name=["']_csrf["'][^>]+content=["']([^"']+)["']/i);
  if (m) { info.csrfName = (m[2] !== undefined ? m[1] : '_csrf'); info.csrfValue = (m[2] !== undefined ? m[2] : m[1]); }
  const fm = html.match(/<form[^>]*action=["']([^"']*(?:security_check|login|j_spring)[^"']*)["'][^>]*>/i);
  if (fm) info.formAction = fm[1];
  info.temSenha = /name=["']j_password["']|type=["']password["']/i.test(html);
  return info;
}

export function registerPacsNomeRoutes(app, pool, adminRequired) {
  app.get('/atb/admin/pacs-nome/teste', adminRequired, async (req, res) => {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    try {
      // Aceita ?ficha=ID (mais cômodo) ou ?prontuario=X&dn=AAAA-MM-DD
      let prontuario = req.query.prontuario, dn = req.query.dn;
      if (req.query.ficha) {
        const { rows: [f] } = await pool.query(
          `SELECT prontuario, to_char(paciente_dn,'YYYY-MM-DD') AS dn FROM atb_fichas WHERE id=$1`,
          [parseInt(req.query.ficha, 10)]);
        if (!f) return res.status(404).send('Ficha não encontrada.');
        prontuario = f.prontuario; dn = f.dn;
      }
      if (!prontuario || !dn) return res.status(400).send('Use ?ficha=ID  (ou ?prontuario=NNN&dn=AAAA-MM-DD)');

      const { user, pass } = credenciaisPacs(prontuario, dn);
      const log = [];
      log.push('Prontuário=' + prontuario + ' · DN=' + dn);
      log.push('user=' + user + ' · pass=' + (pass ? pass.replace(/\d/g, '•') + ' (mascarado, ' + pass.length + ' díg.)' : '(vazio!)'));
      log.push('');

      // 0) GET inicial p/ cookie de sessão + CSRF + inspeção do form de login
      const g = await comTimeout((signal) => fetch(PACS_BASE + '/', {
        headers: { 'User-Agent': UA }, redirect: 'follow', signal }), TIMEOUT_MS);
      let jar = acumulaCookies(g, '');
      const htmlLogin = await g.text();
      const insp = inspecionarLogin(htmlLogin);
      log.push('GET / → status=' + g.status + ' · url=' + g.url + ' · cookie=' + (jar ? 'SIM' : 'não'));
      log.push('  form login: action=' + (insp.formAction || '(não achei)') + ' · campo senha=' + (insp.temSenha ? 'sim' : 'não') + ' · CSRF=' + (insp.csrfValue ? insp.csrfName : 'não'));

      // 1) LOGIN (com UA + cookie inicial + CSRF, se houver)
      const action = insp.formAction && /^https?:/i.test(insp.formAction) ? insp.formAction
                   : PACS_BASE + (insp.formAction || '/j_spring_security_check');
      const body = { j_username: user, j_password: pass };
      if (insp.csrfValue) body[insp.csrfName] = insp.csrfValue;
      const loginResp = await comTimeout((signal) => fetch(action, {
        method: 'POST', redirect: 'manual', signal,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': UA, 'Cookie': jar, 'Referer': PACS_BASE + '/' },
        body: new URLSearchParams(body),
      }), TIMEOUT_MS);
      jar = acumulaCookies(loginResp, jar);
      const loc = loginResp.headers.get('location') || '';
      const temSessao = /JSESSIONID=/.test(jar);
      log.push('LOGIN → POST ' + action);
      log.push('  status=' + loginResp.status + ' · location=' + (loc || '(nenhum)') + ' · sessão=' + (temSessao ? 'SIM' : 'não'));
      if (/login.?error|error|falha|denied/i.test(loc)) log.push('  ⚠ redirect parece de ERRO de login.');
      if (loginResp.status === 401 || loginResp.status === 403) log.push('  ⚠ ' + loginResp.status + ' — o PACS recusou mesmo com UA/cookie/CSRF.');
      if (!temSessao && !(loginResp.status >= 300 && loginResp.status < 400)) {
        log.push('');
        log.push('Login server-side não vingou. Se persistir, o caminho é o USERSCRIPT (ler o nome no seu navegador já logado).');
        return res.send(log.join('\n'));
      }

      // 2) PÁGINA PÓS-LOGIN
      const alvo = /^https?:/i.test(loc) ? loc : (PACS_BASE + (loc || '/'));
      const pag = await comTimeout((signal) => fetch(alvo, { headers: { 'Cookie': jar, 'User-Agent': UA }, redirect: 'follow', signal }), TIMEOUT_MS);
      const html = await pag.text();
      log.push('PÁGINA → status=' + pag.status + ' · url=' + alvo + ' · ' + html.length + ' chars');
      log.push('');
      log.push('=== TRECHO (procure o nome do paciente; me diga a tag/atributo, sem colar o nome) ===');
      log.push(html.slice(0, 4000));
      return res.send(log.join('\n'));
    } catch (e) {
      const msg = e && e.name === 'AbortError'
        ? 'timeout — o PACS não respondeu no tempo. Provável: inalcançável a partir do Render (rede/firewall).'
        : (e && e.message) || String(e);
      return res.status(200).send('ERRO: ' + msg);
    }
  });

  // Ingestão do NOME vindo do PACS (userscript Tampermonkey). Auth por token
  // compartilhado (X-Pacs-Token == env PACS_NOME_TOKEN). Sem sessão de admin.
  app.post('/atb/api/pacs-nome', express.json({ limit: '64kb' }), async (req, res) => {
    const tok = process.env.PACS_NOME_TOKEN;
    if (!tok || req.get('X-Pacs-Token') !== tok) return res.status(401).json({ ok: false, error: 'token' });
    const prontuario = String((req.body && req.body.prontuario) || '').trim();
    const nome = String((req.body && req.body.nome) || '').trim();
    if (!prontuario || !nome) return res.status(400).json({ ok: false, error: 'faltam prontuario/nome' });
    try {
      const inst = await instHUSF(pool);
      await pool.query(`
        INSERT INTO atb_nome_pacs (instituicao_id, prontuario, nome_pacs, nome_pacs_norm, visto_em)
        VALUES ($1,$2,$3,$4, now())
        ON CONFLICT (instituicao_id, prontuario) DO UPDATE SET
          nome_pacs=EXCLUDED.nome_pacs, nome_pacs_norm=EXCLUDED.nome_pacs_norm, visto_em=now()`,
        [inst, prontuario, nome, normPacsNome(nome)]);
      res.json({ ok: true });
    } catch (e) {
      console.error('[atb] pacs-nome ingest:', e.message);
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // Aplica o nome do PACS numa ficha (grava em paciente_nome E paciente_nome_raw),
  // registrando o nome anterior em atb_nome_pacs_log (auditável/reversível).
  app.post('/atb/admin/ficha/:id/atualizar-nome-pacs', adminRequired, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const { rows: [f] } = await pool.query(
        `SELECT id, prontuario, instituicao_id, paciente_nome, paciente_nome_raw FROM atb_fichas WHERE id=$1`, [id]);
      if (!f) return res.status(404).json({ ok: false, error: 'ficha não encontrada' });
      const np = await buscarNomePacs(pool, f.instituicao_id, f.prontuario);
      if (!np || !np.nome_pacs) return res.status(400).json({ ok: false, error: 'sem nome do PACS para este prontuário' });
      await pool.query(
        `INSERT INTO atb_nome_pacs_log (ficha_id, prontuario, nome_antigo, nome_raw_antigo, nome_novo, aplicado_em)
         VALUES ($1,$2,$3,$4,$5, now())`,
        [f.id, f.prontuario, f.paciente_nome, f.paciente_nome_raw, np.nome_pacs]);
      await pool.query(`UPDATE atb_fichas SET paciente_nome=$1, paciente_nome_raw=$1 WHERE id=$2`, [np.nome_pacs, f.id]);
      res.json({ ok: true, nome: np.nome_pacs });
    } catch (e) {
      console.error('[atb] atualizar-nome-pacs:', e.message);
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // DIAGNÓSTICO Puppeteer: abre um Chromium headless, faz o autologin de UM
  // paciente e reporta se logou + achou o nome. Testa se o navegador real passa
  // pela proteção que barrou o fetch cru (401). adminRequired, não grava nada.
  app.get('/atb/admin/pacs-nome/teste-puppeteer', adminRequired, async (req, res) => {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    try {
      let prontuario = req.query.prontuario, dn = req.query.dn;
      if (req.query.ficha) {
        const { rows: [f] } = await pool.query(
          `SELECT prontuario, to_char(paciente_dn,'YYYY-MM-DD') AS dn FROM atb_fichas WHERE id=$1`,
          [parseInt(req.query.ficha, 10)]);
        if (!f) return res.status(404).send('Ficha não encontrada.');
        prontuario = f.prontuario; dn = f.dn;
      }
      if (!prontuario || !dn) return res.status(400).send('Use ?ficha=ID  (ou ?prontuario=NNN&dn=AAAA-MM-DD)');
      const t0 = Date.now();
      const d = await capturarNomePacs(prontuario, dn);
      const seg = ((Date.now() - t0) / 1000).toFixed(1);
      const log = [];
      log.push('Prontuário=' + prontuario + ' · DN=' + (d._dn || '(vazia!)') + ' · senha=' + (d._passLen ? d._passLen + ' díg.' : 'VAZIA') + ' · levou ' + seg + 's');
      log.push('URL final=' + d.url + ' · título=' + d.title);
      log.push('Login detectado=' + (d.login || '(nenhum)'));
      log.push('Nome encontrado=' + (d.nome || '(não)'));
      if (d.login && d.nome) log.push('\n✅ FUNCIONOU — Puppeteer logou e leu o nome. Dá pra fazer a captura prospectiva server-side.');
      else if (d.title && /negado|denied/i.test(d.title)) log.push('\n⚠ ACESSO NEGADO — login recusado (sessão/CSRF ou detecção de automação).');
      else if (d.url && /\/login/i.test(d.url)) log.push('\n⚠ Parou na tela de login.');
      else log.push('\n⚠ Logou mas não peguei o nome (seletor?).');
      if (!d.nome) log.push('\n--- TRECHO DA PÁGINA (pra diagnóstico) ---\n' + (d._body || '(vazio)'));
      res.send(log.join('\n'));
    } catch (e) {
      res.send('ERRO: ' + ((e && e.message) || e) + '\n\n(Se for erro de launch/OOM do Chromium, o plano do Render pode não ter RAM pro Puppeteer no web service.)');
    }
  });
}

// Captura o nome do paciente no PACS via Puppeteer (Chromium real → passa onde o
// fetch cru é barrado). Usa o autologin (mesmo fluxo do navegador do médico).
// Import dinâmico do puppeteer p/ não pesar o boot do app.
export async function capturarNomePacs(prontuario, dn) {
  const { user, pass } = credenciaisPacs(prontuario, dn);
  const puppeteer = (await import('puppeteer')).default;
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
  });
  try {
    const page = await browser.newPage();
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36');
    page.setDefaultNavigationTimeout(30000);
    // 1) GET inicial no PACS (MESMA origem) — estabelece a sessão/cookie JSESSIONID
    await page.goto('https://pacs.husf.com.br/', { waitUntil: 'networkidle2' }).catch(() => {});
    // 2) LOGIN SAME-ORIGIN: monta o form no próprio pacs.husf.com.br e submete p/
    //    j_spring_security_check. Assim o cookie de sessão VIAJA (o autologin via
    //    github.io é cross-site e o cookie SameSite não ia junto → POST "frio").
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 30000 }).catch(() => {}),
      page.evaluate((u, p) => {
        const f = document.createElement('form');
        f.method = 'POST'; f.action = '/j_spring_security_check';
        const a = document.createElement('input'); a.type = 'hidden'; a.name = 'j_username'; a.value = u; f.appendChild(a);
        const b = document.createElement('input'); b.type = 'hidden'; b.name = 'j_password'; b.value = p; f.appendChild(b);
        document.body.appendChild(f); f.submit();
      }, user, pass),
    ]);
    await page.waitForSelector('th', { timeout: 15000 }).catch(() => {});
    const dados = await page.evaluate(() => {
      const login = (document.body.innerText.match(/Login:\s*p(\d+)/i) || [])[1] || null;
      const ths = [].slice.call(document.querySelectorAll('th'));
      let th = null;
      for (let i = 0; i < ths.length; i++) { if (/nome do paciente/i.test(ths[i].innerText || '')) { th = ths[i]; break; } }
      let nome = null;
      if (th) {
        const col = (th.className || '').match(/yui-dt-col-[\w-]+/);
        if (col) { const cell = document.querySelector('td.' + col[0] + ' .yui-dt-liner'); if (cell) nome = (cell.innerText || '').trim(); }
        if (!nome && th.cellIndex >= 0) { const r = document.querySelector('table tbody tr'); if (r && r.children[th.cellIndex]) nome = (r.children[th.cellIndex].innerText || '').trim(); }
      }
      return { url: location.href, title: document.title, login, nome, _body: (document.body.innerText || '').replace(/\s+/g, ' ').slice(0, 400) };
    });
    return { ...dados, _user: user, _dn: dn, _passLen: pass.length };
  } finally {
    await browser.close().catch(() => {});
  }
}
