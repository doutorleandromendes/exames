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

const PACS_BASE = 'https://pacs.husf.com.br';
const TIMEOUT_MS = 8000;

// Deriva as credenciais do PACS a partir de prontuário + DN (mesma fórmula do link).
export function credenciaisPacs(prontuario, dn) {
  const d = String(dn || '').replace(/[^0-9]/g, ''); // YYYYMMDD (de 'AAAA-MM-DD')
  const pass = d.length >= 8 ? d.slice(6, 8) + d.slice(4, 6) + d.slice(0, 4) : ''; // DDMMYYYY
  return { user: 'p' + String(prontuario || '').trim(), pass };
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
}
