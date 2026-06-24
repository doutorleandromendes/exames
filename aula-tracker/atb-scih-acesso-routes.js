// atb-scih-acesso-routes.js
// Gestão de acesso da equipe do SCIH, reaproveitando a tabela access_requests.
// Fluxo: enfermeira pede acesso em /scih/solicitar -> super admin aprova em
// /atb/admin/scih -> sistema gera um link de ativação (token de uso único) ->
// a pessoa define a PRÓPRIA senha em /definir-senha?token=...
//
// Registrar em atb-routes.js (o 3º arg já é o scihRequired vindo do app.js):
//   import { registerScihAcessoRoutes, ensureScihAcessoSchema } from './atb-scih-acesso-routes.js';
//   ensureScihAcessoSchema(pool).catch(e => console.error('[atb] ensureScihAcessoSchema:', e.message));
//   registerScihAcessoRoutes(app, pool, adminRequired);   // adminRequired aqui = scihRequired

import bcrypt from 'bcrypt';
import crypto from 'crypto';

const TOKEN_TTL_DIAS = 7;

const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

// Página leve, fiel à paleta do app (claro, azul institucional #0c447c)
function page(title, body) {
  return `<!doctype html><html lang="pt-br"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${esc(title)}</title>
<style>
  :root{--bg:#f4f6f9;--card:#fff;--txt:#1b2330;--mut:#5b6472;--pri:#0c447c;--bd:#e0e2e6}
  *{box-sizing:border-box} body{margin:0;font-family:system-ui,Segoe UI,Arial;background:var(--bg);color:var(--txt)}
  .wrap{max-width:880px;margin:40px auto;padding:0 16px}
  .card{background:var(--card);border:1px solid var(--bd);border-radius:16px;padding:24px;box-shadow:0 1px 3px rgba(16,24,40,.06),0 6px 18px rgba(16,24,40,.05);margin-bottom:16px}
  h1{font-size:22px;margin:0 0 4px} h2{font-size:16px;margin:0 0 12px}
  label{display:block;margin:10px 0 4px;font-size:14px}
  input{width:100%;padding:12px;border-radius:10px;border:1px solid #cdd3db;background:#fff;color:var(--txt);font-size:14px}
  input:focus{outline:none;border-color:var(--pri);box-shadow:0 0 0 3px rgba(12,68,124,.12)}
  button{background:var(--pri);color:#fff;border:0;border-radius:12px;padding:11px 16px;cursor:pointer;font-weight:600;font-size:14px}
  button.ghost{background:#fff;color:var(--pri);border:1px solid var(--bd)}
  button.danger{background:#fff;color:#8a1414;border:1px solid #f0c0c0}
  a{color:var(--pri)} .mut{color:var(--mut)} .mt{margin-top:14px}
  table{width:100%;border-collapse:collapse;font-size:14px} th,td{padding:9px 8px;border-bottom:1px solid var(--bd);text-align:left;vertical-align:middle}
  th{font-size:12px;text-transform:uppercase;letter-spacing:.03em;color:var(--mut)}
  .pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600}
  .pill.on{background:#e6f1fb;color:#0c447c} .pill.off{background:#f1efe8;color:#5f5e5a}
  form.inline{display:inline} .row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
  .linkbox{background:#f4f6f9;border:1px dashed #b5c6dc;border-radius:10px;padding:12px;word-break:break-all;font-size:13px}
  .hub{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:12px}
  .hubcard{display:flex;align-items:center;gap:10px;padding:16px;border:1px solid var(--bd);border-radius:12px;background:#fff;color:var(--pri);font-weight:600;font-size:14px;text-decoration:none}
  .hubcard:hover{background:#f4f6f9}
  .hubcard.soon{color:#8a93a3;cursor:default;border-style:dashed}
  .hubcard.soon:hover{background:#fff}
  .sec{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--mut);margin:18px 0 8px;font-weight:600}
  .tag{margin-left:auto;font-size:11px;background:#f1efe8;color:#5f5e5a;border-radius:999px;padding:2px 8px;font-weight:600}
  .ext{margin-left:auto;font-size:13px;color:#8a93a3}
</style></head><body><div class="wrap">${body}</div></body></html>`;
}

export async function ensureScihAcessoSchema(pool) {
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS pront BOOLEAN DEFAULT false`);
  await pool.query(`ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS kind TEXT DEFAULT 'curso'`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS set_pw_token TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS set_pw_expires TIMESTAMPTZ`);
  await pool.query(`CREATE INDEX IF NOT EXISTS users_set_pw_token_idx ON users(set_pw_token)`);
}

function novoToken() { return crypto.randomBytes(24).toString('hex'); }
function baseUrl(req) { return `${req.protocol}://${req.get('host')}`; }

export function registerScihAcessoRoutes(app, pool, scihRequired) {
  // gate: precisa estar logado como super_admin (ou break-glass via cookie adm)
  const ensureSuper = (req, res, next) => {
    const isSuper = (req.user && req.user.super_admin) || req.cookies?.adm === '1';
    if (!isSuper) return res.status(403).send(page('Sem acesso',
      `<div class="card"><h1>Acesso restrito</h1><p class="mut">Apenas o super admin gerencia os acessos do SCIH.</p><a href="/inicio">Início</a></div>`));
    next();
  };
  const adminSuper = [scihRequired, ensureSuper];

  // ───────────────────────── portal pessoal (super admin) ─────────────────
  // Relatórios de vigilância publicados no GitHub Pages (repo vigilancia_husf).
  // Para mudar a base é só editar VIG.
  const VIG = 'https://doutorleandromendes.github.io/vigilancia_husf';
  app.get('/scih', adminSuper, (req, res) => {
    const nome = (req.user && req.user.full_name) || 'Dr. Leandro';
    const card = (href, icon, label, ext) =>
      `<a class="hubcard" href="${href}"${ext ? ' target="_blank" rel="noopener"' : ''}>${icon} ${label}${ext ? ' <span class="ext">↗</span>' : ''}</a>`;
    res.send(page('Portal do SCIH', `
      <div class="card">
        <h1>Portal do SCIH — HUSF</h1>
        <p class="mut">Olá, ${esc(nome)}. Atalhos do sistema de ATB e dos relatórios de vigilância.</p>
      </div>
      <div class="card">
        <div class="sec" style="margin-top:0">Operação diária — ATB</div>
        <div class="hub">
          ${card('/grade', '📋', 'Grade de controle')}
          ${card('/atb/admin/ficha-retrospectiva', '➕', 'Nova ficha retrospectiva')}
          ${card('/consulta', '🔎', 'Consulta / Farmácia')}
          ${card('/ficha', '📝', 'Formulário do prescritor')}
        </div>

        <div class="sec">Indicadores &amp; consumo</div>
        <div class="hub">
          ${card('/atb/admin/adesao', '📈', 'Adesão aos pareceres')}
          ${card(VIG + '/atb_dots.html', '💊', 'Consumo de ATB (DOTs)', true)}
        </div>

        <div class="sec">Vigilância — relatórios HUSF</div>
        <div class="hub">
          ${card(VIG + '/', '🦠', 'Respiratória (SG/SRAG)', true)}
          ${card(VIG + '/indicadores.html', '📊', 'IrAS &amp; determinantes', true)}
          ${card(VIG + '/mdr_mensal.html', '🧫', 'MDR mensal', true)}
          ${card(VIG + '/isc_v4.html', '🩹', 'Infecção de sítio cirúrgico', true)}
          ${card(VIG + '/micro.html', '🔬', 'Microbiologia', true)}
          ${card(VIG + '/sciet.html', '🧭', 'Algoritmo empírico UTI', true)}
        </div>

        <div class="sec">Acessos &amp; configuração</div>
        <div class="hub">
          ${card('/atb/admin/scih', '👥', 'Aprovar acessos do SCIH')}
          ${card('/atb/admin/regras', '🧠', 'Regras de triagem')}
          ${card('/atb/admin/form', '🧩', 'Editar opções do formulário')}
          ${card('/atb/admin/regras-form', '🔀', 'Regras do formulário')}
          ${card('/atb/admin/parecer-frases', '💬', 'Frases do Parecer')}
          ${card('/scih/solicitar', '✉️', 'Página de solicitação')}
          ${card('/atb/admin/config', '⚙️', 'Configurar ATB')}
          ${card('/atb/admin/regras-check/painel', '🩺', 'Saúde do sistema')}
        </div>
      </div>`));
  });

  // ───────────────────────── público: solicitar acesso (SCIH) ─────────────
  app.get('/scih/solicitar', (req, res) => {
    res.send(page('Solicitar acesso — SCIH', `
      <div class="card">
        <h1>Solicitar acesso ao sistema de ATB</h1>
        <p class="mut">Para a equipe do SCIH. Seu pedido será revisado pela coordenação; ao ser aprovado, você receberá um link para definir sua senha.</p>
        <form method="POST" action="/scih/solicitar" class="mt">
          <label>Nome completo</label><input name="full_name" required>
          <label>E-mail</label><input name="email" type="email" required placeholder="voce@alsf.org.br">
          <button class="mt">Enviar solicitação</button>
        </form>
      </div>`));
  });

  app.post('/scih/solicitar', async (req, res) => {
    try {
      const full_name = String(req.body?.full_name || '').trim();
      const email = String(req.body?.email || '').trim().toLowerCase();
      if (!full_name || !email || !email.includes('@')) {
        return res.status(400).send(page('Dados inválidos',
          `<div class="card"><h1>Dados inválidos</h1><a href="/scih/solicitar">Voltar</a></div>`));
      }
      const dom = (process.env.ALLOWED_EMAIL_DOMAIN || '').toLowerCase();
      if (dom && !email.endsWith('@' + dom)) {
        return res.status(400).send(page('Domínio não permitido',
          `<div class="card"><h1>Domínio de e-mail não permitido</h1><p class="mut">Use um endereço @${esc(dom)}.</p><a href="/scih/solicitar">Voltar</a></div>`));
      }
      // evita pedido duplicado pendente
      const dup = await pool.query(
        `SELECT 1 FROM access_requests WHERE LOWER(email)=$1 AND status='pending' AND kind='scih' LIMIT 1`, [email]);
      if (!dup.rowCount) {
        await pool.query(
          `INSERT INTO access_requests(full_name,email,kind,justification,status)
           VALUES ($1,$2,'scih','Equipe SCIH','pending')`, [full_name, email]);
      }
      res.send(page('Solicitação enviada', `
        <div class="card">
          <h1>Solicitação enviada</h1>
          <p>Obrigado, <strong>${esc(full_name)}</strong>. Seu pedido foi registrado.</p>
          <p class="mut">Assim que a coordenação aprovar, você receberá um link para definir sua senha e acessar o sistema.</p>
        </div>`));
    } catch (err) {
      console.error('[scih] solicitar:', err);
      res.status(500).send(page('Erro', `<div class="card"><h1>Falha ao enviar solicitação</h1><p class="mut">${esc(err.message)}</p></div>`));
    }
  });

  // ───────────────────────── admin (super): gerenciar SCIH ────────────────
  app.get('/atb/admin/scih', adminSuper, async (req, res) => {
    try {
      const pend = (await pool.query(
        `SELECT id, full_name, email, created_at
           FROM access_requests
          WHERE status='pending' AND kind='scih'
          ORDER BY created_at ASC`)).rows;

      const usuarios = (await pool.query(
        `SELECT id, full_name, email, scih, super_admin, pront,
                (set_pw_token IS NOT NULL AND (set_pw_expires IS NULL OR set_pw_expires > now())) AS pendente_senha
           FROM users
          WHERE scih = true OR super_admin = true OR pront = true
          ORDER BY super_admin DESC, LOWER(email) ASC`)).rows;

      const linhasPend = pend.map(r => `
        <tr>
          <td>${esc(r.full_name)}</td>
          <td>${esc(r.email)}</td>
          <td class="mut">${new Date(r.created_at).toLocaleDateString('pt-BR')}</td>
          <td class="row">
            <form method="POST" action="/atb/admin/scih/aprovar/${r.id}" class="inline"><button>Aprovar</button></form>
            <form method="POST" action="/atb/admin/scih/rejeitar/${r.id}" class="inline" onsubmit="return confirm('Rejeitar este pedido?')"><button class="danger">Rejeitar</button></form>
          </td>
        </tr>`).join('') || `<tr><td colspan="4" class="mut">Nenhum pedido pendente.</td></tr>`;

      const linhasUsr = usuarios.map(u => `
        <tr>
          <td>${esc(u.full_name || '—')}</td>
          <td>${esc(u.email)}</td>
          <td>${u.super_admin ? '<span class="pill on">super admin</span>' : (u.scih ? '<span class="pill on">SCIH</span>' : '<span class="pill off">—</span>')}</td>
          <td>${u.super_admin ? '<span class="pill on">sempre</span>' : (u.pront ? '<span class="pill on">liberado</span>' : '<span class="pill off">—</span>')}</td>
          <td>${u.pendente_senha ? '<span class="pill off">aguardando definir senha</span>' : '<span class="mut">ativa</span>'}</td>
          <td class="row">
            ${u.super_admin ? '<span class="mut">protegido</span>' : `
              <form method="POST" action="/atb/admin/scih/toggle/${u.id}" class="inline"><button class="ghost">${u.scih ? 'Remover SCIH' : 'Tornar SCIH'}</button></form>
              <form method="POST" action="/atb/admin/scih/pront-toggle/${u.id}" class="inline"><button class="ghost">${u.pront ? 'Remover prontuário' : 'Liberar prontuário'}</button></form>
              <form method="POST" action="/atb/admin/scih/link/${u.id}" class="inline"><button class="ghost">Gerar link de senha</button></form>`}
          </td>
        </tr>`).join('');

      res.send(page('Acessos do SCIH', `
        <div class="card">
          <h1>Acessos do SCIH</h1>
          <p class="mut">Aprove os pedidos pendentes e gerencie quem tem acesso ao sistema de ATB.</p>
        </div>

        <div class="card">
          <h2>Pedidos pendentes</h2>
          <table>
            <thead><tr><th>Nome</th><th>E-mail</th><th>Data</th><th>Ações</th></tr></thead>
            <tbody>${linhasPend}</tbody>
          </table>
        </div>

        <div class="card">
          <h2>Usuários com acesso</h2>
          <table>
            <thead><tr><th>Nome</th><th>E-mail</th><th>Papel</th><th>Prontuário</th><th>Senha</th><th>Ações</th></tr></thead>
            <tbody>${linhasUsr}</tbody>
          </table>
          <div class="mt">
            <h2 style="margin-top:18px">Tornar um e-mail já cadastrado em SCIH</h2>
            <form method="POST" action="/atb/admin/scih/marcar" class="row">
              <input name="email" type="email" placeholder="email@dominio" required style="max-width:340px">
              <button class="ghost">Marcar como SCIH</button>
            </form>
            <h2 style="margin-top:18px">Liberar acesso ao prontuário por e-mail</h2>
            <form method="POST" action="/atb/admin/scih/pront-marcar" class="row">
              <input name="email" type="email" placeholder="email@dominio" required style="max-width:340px">
              <button class="ghost">Liberar prontuário</button>
            </form>
            <p class="mut" style="font-size:13px">Use isto só para contas que já existem. Para gente nova, cadastre primeiro em /admin/alunos.</p>
          </div>
        </div>`));
    } catch (err) {
      console.error('[scih] painel:', err);
      res.status(500).send(page('Erro', `<div class="card"><h1>Falha ao carregar</h1><p class="mut">${esc(err.message)}</p></div>`));
    }
  });

  // aprovar pedido: cria/atualiza usuário com scih=true e gera link de senha
  app.post('/atb/admin/scih/aprovar/:id', adminSuper, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const r = (await client.query(
        `SELECT id, full_name, email FROM access_requests
          WHERE id=$1 AND status='pending' AND kind='scih' FOR UPDATE`, [id])).rows[0];
      if (!r) { await client.query('ROLLBACK'); return res.status(404).send(page('Não encontrado', `<div class="card"><h1>Pedido não encontrado ou já processado</h1><a href="/atb/admin/scih">Voltar</a></div>`)); }

      const email = r.email.toLowerCase().trim();
      const token = novoToken();
      const expira = new Date(Date.now() + TOKEN_TTL_DIAS * 86400000);

      const existing = (await client.query('SELECT id FROM users WHERE email=$1', [email])).rows[0];
      let userId;
      if (existing) {
        userId = existing.id;
        await client.query(
          `UPDATE users SET full_name=COALESCE($1,full_name), scih=true, set_pw_token=$2, set_pw_expires=$3 WHERE id=$4`,
          [r.full_name || null, token, expira, userId]);
      } else {
        // sem password_hash ainda: a pessoa define no link. password_hash NULL = login impossível até definir.
        userId = (await client.query(
          `INSERT INTO users(full_name,email,scih,set_pw_token,set_pw_expires) VALUES($1,$2,true,$3,$4) RETURNING id`,
          [r.full_name, email, token, expira])).rows[0].id;
      }

      await client.query(`UPDATE access_requests SET status='approved', processed_at=now() WHERE id=$1`, [id]);
      await client.query('COMMIT');

      const link = `${baseUrl(req)}/definir-senha?token=${token}`;
      res.send(page('Pedido aprovado', `
        <div class="card">
          <h1>Acesso aprovado</h1>
          <p><strong>${esc(r.full_name)}</strong> (${esc(email)}) agora tem acesso ao SCIH.</p>
          <p class="mut">Envie este link para a pessoa definir a senha (expira em ${TOKEN_TTL_DIAS} dias e só funciona uma vez):</p>
          <div class="linkbox" id="lk">${esc(link)}</div>
          <div class="row mt">
            <button class="ghost" onclick="navigator.clipboard.writeText(document.getElementById('lk').innerText).then(()=>{this.innerText='Copiado!'})">Copiar link</button>
            <a href="/atb/admin/scih">Voltar ao painel</a>
          </div>
        </div>`));
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch {}
      console.error('[scih] aprovar:', err);
      res.status(500).send(page('Erro', `<div class="card"><h1>Falha ao aprovar</h1><p class="mut">${esc(err.message)}</p></div>`));
    } finally { client.release(); }
  });

  app.post('/atb/admin/scih/rejeitar/:id', adminSuper, async (req, res) => {
    try {
      await pool.query(`UPDATE access_requests SET status='rejected', processed_at=now() WHERE id=$1 AND status='pending'`, [parseInt(req.params.id, 10)]);
      res.redirect('/atb/admin/scih');
    } catch (err) { console.error('[scih] rejeitar:', err); res.status(500).send('Falha ao rejeitar'); }
  });

  // liga/desliga scih de um usuário (super_admin é protegido)
  app.post('/atb/admin/scih/toggle/:userId', adminSuper, async (req, res) => {
    try {
      const uid = parseInt(req.params.userId, 10);
      const u = (await pool.query('SELECT scih, super_admin FROM users WHERE id=$1', [uid])).rows[0];
      if (u && !u.super_admin) {
        await pool.query('UPDATE users SET scih=$1 WHERE id=$2', [!u.scih, uid]);
      }
      res.redirect('/atb/admin/scih');
    } catch (err) { console.error('[scih] toggle:', err); res.status(500).send('Falha ao alternar'); }
  });

  // marca um e-mail já existente como SCIH
  app.post('/atb/admin/scih/marcar', adminSuper, async (req, res) => {
    try {
      const email = String(req.body?.email || '').trim().toLowerCase();
      const r = await pool.query('UPDATE users SET scih=true WHERE email=$1 RETURNING id', [email]);
      if (!r.rowCount) {
        return res.status(404).send(page('Não encontrado', `<div class="card"><h1>E-mail não cadastrado</h1><p class="mut">${esc(email)} não existe em usuários. Peça para a pessoa solicitar acesso em /scih/solicitar.</p><a href="/atb/admin/scih">Voltar</a></div>`));
      }
      res.redirect('/atb/admin/scih');
    } catch (err) { console.error('[scih] marcar:', err); res.status(500).send('Falha ao marcar'); }
  });

  // liga/desliga o acesso ao prontuário de um usuário (super_admin é sempre liberado)
  app.post('/atb/admin/scih/pront-toggle/:userId', adminSuper, async (req, res) => {
    try {
      const uid = parseInt(req.params.userId, 10);
      const u = (await pool.query('SELECT pront, super_admin FROM users WHERE id=$1', [uid])).rows[0];
      if (u && !u.super_admin) {
        await pool.query('UPDATE users SET pront=$1 WHERE id=$2', [!u.pront, uid]);
      }
      res.redirect('/atb/admin/scih');
    } catch (err) { console.error('[scih] pront-toggle:', err); res.status(500).send('Falha ao alternar prontuário'); }
  });

  // libera acesso ao prontuário para um e-mail já existente
  app.post('/atb/admin/scih/pront-marcar', adminSuper, async (req, res) => {
    try {
      const email = String(req.body?.email || '').trim().toLowerCase();
      const r = await pool.query('UPDATE users SET pront=true WHERE email=$1 RETURNING id', [email]);
      if (!r.rowCount) {
        return res.status(404).send(page('Não encontrado', `<div class="card"><h1>E-mail não cadastrado</h1><p class="mut">${esc(email)} não existe em usuários. Cadastre primeiro em /admin/alunos.</p><a href="/atb/admin/scih">Voltar</a></div>`));
      }
      res.redirect('/atb/admin/scih');
    } catch (err) { console.error('[scih] pront-marcar:', err); res.status(500).send('Falha ao liberar prontuário'); }
  });

  // (re)gera link de definição de senha para um usuário existente
  app.post('/atb/admin/scih/link/:userId', adminSuper, async (req, res) => {
    try {
      const uid = parseInt(req.params.userId, 10);
      const u = (await pool.query('SELECT full_name, email FROM users WHERE id=$1', [uid])).rows[0];
      if (!u) return res.status(404).send('Usuário não encontrado');
      const token = novoToken();
      const expira = new Date(Date.now() + TOKEN_TTL_DIAS * 86400000);
      await pool.query('UPDATE users SET set_pw_token=$1, set_pw_expires=$2 WHERE id=$3', [token, expira, uid]);
      const link = `${baseUrl(req)}/definir-senha?token=${token}`;
      res.send(page('Link gerado', `
        <div class="card">
          <h1>Link de senha gerado</h1>
          <p>Para <strong>${esc(u.full_name || u.email)}</strong> (${esc(u.email)}):</p>
          <div class="linkbox" id="lk">${esc(link)}</div>
          <div class="row mt">
            <button class="ghost" onclick="navigator.clipboard.writeText(document.getElementById('lk').innerText).then(()=>{this.innerText='Copiado!'})">Copiar link</button>
            <a href="/atb/admin/scih">Voltar ao painel</a>
          </div>
        </div>`));
    } catch (err) { console.error('[scih] link:', err); res.status(500).send('Falha ao gerar link'); }
  });

  // ───────────────────────── público: definir senha via token ─────────────
  app.get('/definir-senha', async (req, res) => {
    const token = String(req.query.token || '');
    const u = token ? (await pool.query(
      'SELECT email, set_pw_expires FROM users WHERE set_pw_token=$1', [token])).rows[0] : null;
    if (!u || (u.set_pw_expires && new Date() > new Date(u.set_pw_expires))) {
      return res.status(400).send(page('Link inválido', `
        <div class="card"><h1>Link inválido ou expirado</h1>
        <p class="mut">Peça à coordenação um novo link de acesso.</p></div>`));
    }
    res.send(page('Definir senha', `
      <div class="card">
        <h1>Defina sua senha</h1>
        <p class="mut">Conta: <strong>${esc(u.email)}</strong></p>
        <form method="POST" action="/definir-senha" class="mt" onsubmit="return validar()">
          <input type="hidden" name="token" value="${esc(token)}">
          <label>Nova senha (mínimo 8 caracteres)</label>
          <input id="p1" name="password" type="password" minlength="8" required>
          <label>Confirme a senha</label>
          <input id="p2" name="password2" type="password" minlength="8" required>
          <p id="erro" class="mut" style="color:#8a1414"></p>
          <button class="mt">Salvar senha e ativar conta</button>
        </form>
      </div>
      <script>
        function validar(){
          var a=document.getElementById('p1').value, b=document.getElementById('p2').value;
          if(a.length<8){document.getElementById('erro').innerText='A senha precisa ter ao menos 8 caracteres.';return false;}
          if(a!==b){document.getElementById('erro').innerText='As senhas não conferem.';return false;}
          return true;
        }
      </script>`));
  });

  app.post('/definir-senha', async (req, res) => {
    try {
      const token = String(req.body?.token || '');
      const password = String(req.body?.password || '');
      const password2 = String(req.body?.password2 || '');
      if (password.length < 8 || password !== password2) {
        return res.status(400).send(page('Senha inválida', `<div class="card"><h1>Senha inválida</h1><p class="mut">Verifique o tamanho (mín. 8) e a confirmação.</p><a href="/definir-senha?token=${esc(token)}">Voltar</a></div>`));
      }
      const u = token ? (await pool.query(
        'SELECT id, set_pw_expires FROM users WHERE set_pw_token=$1', [token])).rows[0] : null;
      if (!u || (u.set_pw_expires && new Date() > new Date(u.set_pw_expires))) {
        return res.status(400).send(page('Link inválido', `<div class="card"><h1>Link inválido ou expirado</h1><p class="mut">Peça um novo link à coordenação.</p></div>`));
      }
      const hash = await bcrypt.hash(password, 10);
      await pool.query(
        `UPDATE users SET password_hash=$1, temp_password=NULL, set_pw_token=NULL, set_pw_expires=NULL WHERE id=$2`,
        [hash, u.id]);
      res.send(page('Senha definida', `
        <div class="card">
          <h1>Pronto! Senha definida</h1>
          <p>Sua conta está ativa. Você já pode entrar no sistema.</p>
          <a href="/"><button class="mt">Ir para o login</button></a>
        </div>`));
    } catch (err) {
      console.error('[scih] definir-senha:', err);
      res.status(500).send(page('Erro', `<div class="card"><h1>Falha ao salvar senha</h1><p class="mut">${esc(err.message)}</p></div>`));
    }
  });
}
