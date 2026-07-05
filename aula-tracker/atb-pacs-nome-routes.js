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

      // 1) LOGIN
      const loginResp = await comTimeout((signal) => fetch(PACS_BASE + '/j_spring_security_check', {
        method: 'POST', redirect: 'manual', signal,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ j_username: user, j_password: pass }),
      }), TIMEOUT_MS);
      const cookie = pegarJsessionid(loginResp);
      const loc = loginResp.headers.get('location') || '';
      log.push('LOGIN → status=' + loginResp.status + ' · location=' + (loc || '(nenhum)') + ' · sessão=' + (cookie ? 'SIM' : 'não'));
      if (/login.?error|error|falha/i.test(loc)) log.push('⚠ redirect parece de ERRO de login (credenciais recusadas?).');
      if (!cookie) {
        log.push('');
        log.push('Sem cookie de sessão → não dá pra abrir a página do paciente. Possíveis causas: credenciais recusadas, ou o PACS não aceita login server-side.');
        return res.send(log.join('\n'));
      }

      // 2) PÁGINA PÓS-LOGIN (segue o redirect com o cookie)
      const alvo = /^https?:/i.test(loc) ? loc : (PACS_BASE + (loc || '/'));
      const pag = await comTimeout((signal) => fetch(alvo, { headers: { Cookie: cookie }, signal, redirect: 'follow' }), TIMEOUT_MS);
      const html = await pag.text();
      log.push('PÁGINA → status=' + pag.status + ' · url=' + alvo + ' · ' + html.length + ' chars');
      log.push('');
      log.push('=== TRECHO DA PÁGINA (procure o nome do paciente; me diga em que tag/atributo ele está) ===');
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
