// ====== Admin: Gerenciamento de USUÁRIOS por papel ======
// Sistema paralelo ao /admin/alunos. Enquanto /admin/alunos é sobre o aluno na aula
// (progresso, matrículas, CSV), este é o gerenciador de PESSOAS por papel, sem herança
// de curso. Não substitui /admin/alunos — coexiste, no mesmo padrão do lab-emissor.
//
// Papéis editáveis pela UI: is_admin, scih, micro, pront, agenda, recepcao.
// super_admin é READ-ONLY na tela (só via SQL) — evita escalonamento acidental.

import bcrypt from 'bcrypt';
import { safe, renderShell } from './ui-shell.js';
import { fmt, normalizeDateStr } from './aulas-utils.js';

const ALLOWED_EMAIL_DOMAIN = process.env.ALLOWED_EMAIL_DOMAIN || null;

// Papéis que a tela pode ligar/desligar. Ordem = ordem de exibição.
const ROLES = [
  { key: 'is_admin', label: 'Admin',      desc: 'Acesso administrativo (rótulo)' },
  { key: 'scih',     label: 'SCIH',       desc: 'Controle ATB / pareceres' },
  { key: 'micro',    label: 'Microbiologia', desc: 'Grade de culturas' },
  { key: 'pront',    label: 'Prontuário', desc: 'Pacientes e documentos' },
  { key: 'agenda',   label: 'Agenda/Secretaria', desc: 'Consultas e orçamentos' },
  { key: 'recepcao', label: 'Recepção',   desc: 'Check-in na agenda' },
  { key: 'pav',      label: 'PAV (bundle)', desc: 'Coleta do bundle de PAV à beira-leito' },
  { key: 'treino',   label: 'Conta de treino', desc: 'Dados marcados p/ exclusão pós-trial' },
];
const ROLE_KEYS = ROLES.map(r => r.key);
// Campos PAV que NÃO são booleanos (não entram no loop de roles): valor/texto.
// categoria_pav decide os itens e o alcance de salão; conselho é o registro
// profissional (CREFITO/COREN) da fisio. Só relevantes se 'pav' estiver ligado.
const CATEGORIAS_PAV_OPTS = [['', '—'], ['fisio', 'Fisioterapia'], ['enf', 'Enfermagem']];
// super_admin entra nas queries só para exibição, nunca para escrita via form.
const SELECT_COLS = ['id','full_name','email','expires_at','created_at','temp_password','super_admin', ...ROLE_KEYS, 'categoria_pav', 'conselho'];

// colunas ordenáveis (whitelist — nunca interpolar entrada do usuário em ORDER BY)
const SORTABLE = new Set(['id','full_name','email','created_at','expires_at']);

export function registerAulasAdminUsuariosRoutes(app, pool, { adminRequired }) {

  // ---------- LISTA / BUSCA ----------
  // Não despeja a base inteira: só lista quando há filtro (q/role) ou ?all=1.
  app.get('/admin/usuarios', adminRequired, async (req, res) => {
    try {
      const q     = (req.query.q || '').trim();
      const role  = (req.query.role || '').trim();
      const all   = req.query.all === '1';
      let sort    = (req.query.sort || 'full_name').trim();
      let dir     = (req.query.dir || 'asc').trim().toLowerCase();
      if (!SORTABLE.has(sort)) sort = 'full_name';
      if (dir !== 'asc' && dir !== 'desc') dir = 'asc';

      const roleValid = role === 'super_admin' || ROLE_KEYS.includes(role);
      const shouldList = all || !!q || roleValid;

      const params = [];
      const where = [];
      if (q) {
        params.push(`%${q.toLowerCase()}%`);
        where.push(`(LOWER(full_name) LIKE $${params.length} OR LOWER(email) LIKE $${params.length})`);
      }
      if (roleValid) where.push(`${role} = true`); // role vem de whitelist, seguro
      const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
      const orderSql = `ORDER BY ${sort} ${dir.toUpperCase()} NULLS LAST`;

      let users = [];
      if (shouldList) {
        const r = await pool.query(
          `SELECT ${SELECT_COLS.join(',')} FROM users ${whereSql} ${orderSql}`, params);
        users = r.rows;
      }

      // helper de header ordenável: preserva q/role/all e inverte dir na coluna ativa
      const qs = extra => {
        const p = new URLSearchParams();
        if (q) p.set('q', q);
        if (roleValid) p.set('role', role);
        if (all) p.set('all', '1');
        for (const [k,v] of Object.entries(extra)) p.set(k, v);
        return '/admin/usuarios?' + p.toString();
      };
      const th = (col, label) => {
        if (!SORTABLE.has(col)) return `<th>${label}</th>`;
        const active = sort === col;
        const nextDir = active && dir === 'asc' ? 'desc' : 'asc';
        const arrow = active ? (dir === 'asc' ? ' ▲' : ' ▼') : '';
        return `<th><a href="${qs({ sort: col, dir: nextDir })}" style="text-decoration:none;color:inherit">${label}${arrow}</a></th>`;
      };

      const roleBadges = u => {
        const bs = [];
        if (u.super_admin) bs.push(`<span class="badge badge-sa">super_admin</span>`);
        for (const r of ROLES) if (u[r.key]) bs.push(`<span class="badge">${r.label}</span>`);
        return bs.join(' ') || '<span class="mut">—</span>';
      };

      const rows = users.map(u => `<tr>
        <td>${u.id}</td>
        <td>${safe(u.full_name) || '<span class="mut">—</span>'}</td>
        <td>${safe(u.email)}</td>
        <td>${roleBadges(u)}</td>
        <td>${fmt(u.expires_at) || '<span class="mut">—</span>'}</td>
        <td><a href="/admin/usuarios/${u.id}">editar</a></td>
      </tr>`).join('');

      const roleFilterOpts = ['<option value="">(qualquer papel)</option>']
        .concat([{ key:'super_admin', label:'super_admin' }, ...ROLES]
          .map(r => `<option value="${r.key}" ${role === r.key ? 'selected' : ''}>${r.label}</option>`))
        .join('');

      const listBlock = shouldList
        ? `<table class="mt2">
            <thead><tr>
              ${th('id','ID')}${th('full_name','Nome')}${th('email','Email')}
              <th>Papéis</th>${th('expires_at','Validade')}<th></th>
            </tr></thead>
            <tbody>${rows || '<tr><td colspan="6" class="mut">Nenhum usuário encontrado.</td></tr>'}</tbody>
          </table>
          <p class="mut mt">${users.length} usuário(s).</p>`
        : `<div class="mut mt2" style="padding:24px;text-align:center;border:1px dashed #cdd3db;border-radius:12px">
            Use a busca ou um filtro de papel acima para listar usuários.<br>
            <a href="${qs({ all: '1' })}">Ou listar todos</a>.
          </div>`;

      const createOpts = ROLES.map(r =>
        `<label class="chk"><input type="checkbox" name="roles" value="${r.key}"> ${r.label}
          <span class="mut">— ${r.desc}</span></label>`).join('');

      const body = `
        <div class="card">
          <div class="right" style="justify-content:space-between">
            <h1>Usuários</h1>
            <div><a href="/inicio">Início</a></div>
          </div>

          <form method="GET" action="/admin/usuarios" class="mt2">
            <div class="row">
              <div><label>Nome/Email</label><input name="q" value="${safe(q)}" placeholder="ex.: maria / @gmail.com"></div>
              <div><label>Papel</label><select name="role">${roleFilterOpts}</select></div>
            </div>
            <button class="mt">Buscar</button>
            <a href="/admin/usuarios" class="mt" style="margin-left:12px;display:inline-block">Limpar</a>
          </form>

          ${listBlock}
        </div>

        <div class="card">
          <h2>Adicionar usuário</h2>
          <p class="mut">Cria uma pessoa com os papéis marcados — sem vínculo a curso. Para matricular um aluno, use <a href="/admin/alunos">Alunos</a>.</p>
          <form method="POST" action="/admin/usuarios" class="mt2">
            <div class="row">
              <div>
                <label>Nome completo</label><input name="full_name" required>
                <label>Senha</label><input name="password" type="text" required placeholder="ex.: Abc123456">
              </div>
              <div>
                <label>Email</label><input name="email" type="email" required>
                <label>Validade do usuário (opcional)</label><input name="user_expires_at" type="datetime-local">
              </div>
            </div>
            <label class="mt2">Papéis</label>
            <div class="roles-grid">${createOpts}</div>
            <div class="pav-extra">
              <div><label>Categoria PAV <span class="mut">(se papel PAV)</span></label>
                <select name="categoria_pav">${CATEGORIAS_PAV_OPTS.map(([v,l]) => `<option value="${v}">${l}</option>`).join('')}</select></div>
              <div><label>Conselho <span class="mut">(CREFITO/COREN)</span></label>
                <input name="conselho" placeholder="ex.: CREFITO 3/xxxxx"></div>
            </div>
            <button class="mt2">Criar usuário</button>
          </form>
        </div>

        <style>
          .badge{display:inline-block;padding:2px 8px;border-radius:999px;background:#eef1f5;border:1px solid #e0e2e6;font-size:12px;margin:1px 0}
          .badge-sa{background:#fdeaea;border-color:#f3c9c9;color:#a3272c;font-weight:600}
          .chk{display:block;font-weight:400;margin:6px 0}
          .roles-grid{display:grid;grid-template-columns:1fr 1fr;gap:4px 20px;margin-top:6px}
          @media(max-width:720px){ .roles-grid{grid-template-columns:1fr} }
          .pav-extra{display:grid;grid-template-columns:1fr 1fr;gap:12px 20px;margin-top:12px;padding-top:12px;border-top:1px solid #eef1f5}
          @media(max-width:720px){ .pav-extra{grid-template-columns:1fr} }
        </style>`;
      res.send(renderShell('Usuários', body));
    } catch (err) {
      console.error('ADMIN USUARIOS LIST ERROR', err);
      res.status(500).send(renderShell('Erro', `<div class="card"><h1>Falha ao carregar</h1><p class="mut">${safe(err.message||err)}</p></div>`));
    }
  });

  // ---------- CRIAR (sem curso) ----------
  app.post('/admin/usuarios', adminRequired, async (req, res) => {
    try {
      let { full_name, email, password, user_expires_at } = req.body || {};
      if (!full_name || !email || !password) return res.status(400).send('Nome, email e senha são obrigatórios');
      email = String(email).trim().toLowerCase();
      if (ALLOWED_EMAIL_DOMAIN && !email.endsWith(`@${ALLOWED_EMAIL_DOMAIN.toLowerCase()}`)) {
        return res.status(400).send('Domínio de e-mail inválido');
      }

      // roles marcados (checkbox único vem string; múltiplos vêm array). super_admin ignorado.
      let picked = req.body.roles || [];
      if (!Array.isArray(picked)) picked = [picked];
      picked = picked.filter(r => ROLE_KEYS.includes(r));

      const exp = normalizeDateStr(user_expires_at) || null;
      const plain = String(password).trim();
      const hash = await bcrypt.hash(plain, 10);

      const cols = ['full_name','email','password_hash','expires_at','temp_password', ...picked];
      const vals = [full_name, email, hash, exp, plain, ...picked.map(() => true)];
      // Campos PAV com valor (só se informados): categoria_pav (fisio/enf), conselho.
      const catPav = ['fisio','enf'].includes(req.body.categoria_pav) ? req.body.categoria_pav : null;
      const conselho = String(req.body.conselho || '').trim().slice(0, 60) || null;
      if (catPav) { cols.push('categoria_pav'); vals.push(catPav); }
      if (conselho) { cols.push('conselho'); vals.push(conselho); }
      const ph = vals.map((_, i) => `$${i+1}`).join(',');
      await pool.query(
        `INSERT INTO users (${cols.join(',')}) VALUES (${ph})`, vals);

      res.redirect('/admin/usuarios?q=' + encodeURIComponent(email));
    } catch (err) {
      console.error('ADMIN USUARIOS CREATE ERROR', err);
      // erro provável: email duplicado (UNIQUE)
      const msg = /duplicate|unique/i.test(String(err.message)) ? 'Já existe um usuário com esse e-mail.' : (err.message || 'Falha ao criar');
      res.status(500).send(renderShell('Erro', `<div class="card"><h1>Falha ao criar usuário</h1><p class="mut">${safe(msg)}</p><p><a href="/admin/usuarios">Voltar</a></p></div>`));
    }
  });

  // ---------- EDITAR (papéis + dados básicos) ----------
  app.get('/admin/usuarios/:id', adminRequired, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id)) return res.status(400).send('ID inválido');
    try {
      const r = await pool.query(`SELECT ${SELECT_COLS.join(',')}, welcome_email_sent_at FROM users WHERE id=$1`, [id]);
      const u = r.rows[0];
      if (!u) return res.status(404).send(renderShell('Usuário', `<div class="card"><h1>Usuário não encontrado</h1><a href="/admin/usuarios">Voltar</a></div>`));

      const roleChecks = ROLES.map(role => `
        <label class="chk"><input type="checkbox" name="roles" value="${role.key}" ${u[role.key] ? 'checked' : ''}> ${role.label}
          <span class="mut">— ${role.desc}</span></label>`).join('');

      const saBlock = `
        <label class="chk" style="opacity:.7">
          <input type="checkbox" disabled ${u.super_admin ? 'checked' : ''}> super_admin
          <span class="mut">— protegido; alterável apenas via SQL</span>
        </label>`;

      // atalho: se este usuário tem matrículas, aponta pro /admin/alunos (não duplicamos aqui)
      const m = await pool.query(`SELECT COUNT(*)::int AS n FROM course_members WHERE user_id=$1`, [id]);
      const temMatriculas = m.rows[0].n > 0;

      const body = `
        <div class="card">
          <div class="right" style="justify-content:space-between">
            <h1>Usuário #${u.id}</h1>
            <div><a href="/admin/usuarios">Voltar</a></div>
          </div>

          <form method="POST" action="/admin/usuarios/${u.id}" class="mt2">
            <label>Nome</label><input name="full_name" value="${safe(u.full_name).replace(/"/g,'&quot;')}">
            <label>Email</label><input name="email" type="email" value="${safe(u.email)}">
            <label>Nova senha (opcional)</label><input name="password" type="text" placeholder="deixe em branco para não alterar">
            <label>Validade do usuário</label><input name="user_expires_at" type="datetime-local">

            <label class="mt2">Papéis</label>
            <div class="roles-grid">${roleChecks}</div>
            <div class="mt">${saBlock}</div>
            <div class="pav-extra">
              <div><label>Categoria PAV <span class="mut">(se papel PAV)</span></label>
                <select name="categoria_pav">${CATEGORIAS_PAV_OPTS.map(([v,l]) => `<option value="${v}" ${u.categoria_pav === v || (!u.categoria_pav && v==='') ? 'selected' : ''}>${l}</option>`).join('')}</select></div>
              <div><label>Conselho <span class="mut">(CREFITO/COREN)</span></label>
                <input name="conselho" value="${safe(u.conselho || '').replace(/"/g,'&quot;')}" placeholder="ex.: CREFITO 3/xxxxx"></div>
            </div>

            <button class="mt2">Salvar</button>
          </form>

          <p class="mut mt2">
            ${temMatriculas
              ? `Este usuário tem matrículas em cursos — gerencie-as em <a href="/admin/alunos/${u.id}/edit">Alunos</a>.`
              : `Sem matrículas em cursos.`}
            ${u.temp_password ? ` · Senha temporária: <code>${safe(u.temp_password)}</code>` : ''}
          </p>
        </div>

        <style>
          .chk{display:block;font-weight:400;margin:6px 0}
          .roles-grid{display:grid;grid-template-columns:1fr 1fr;gap:4px 20px;margin-top:6px}
          @media(max-width:720px){ .roles-grid{grid-template-columns:1fr} }
          .pav-extra{display:grid;grid-template-columns:1fr 1fr;gap:12px 20px;margin-top:12px;padding-top:12px;border-top:1px solid #eef1f5}
          @media(max-width:720px){ .pav-extra{grid-template-columns:1fr} }
        </style>`;
      res.send(renderShell(`Usuário #${u.id}`, body));
    } catch (err) {
      console.error('ADMIN USUARIOS EDIT GET ERROR', err);
      res.status(500).send(renderShell('Erro', `<div class="card"><h1>Falha ao carregar</h1><p class="mut">${safe(err.message||err)}</p></div>`));
    }
  });

  app.post('/admin/usuarios/:id', adminRequired, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id)) return res.status(400).send('ID inválido');
    try {
      let { full_name, email, password, user_expires_at } = req.body || {};
      if (!full_name || !email) return res.status(400).send('Nome e email obrigatórios');
      email = String(email).trim().toLowerCase();
      if (ALLOWED_EMAIL_DOMAIN && !email.endsWith(`@${ALLOWED_EMAIL_DOMAIN.toLowerCase()}`)) {
        return res.status(400).send('Domínio de e-mail inválido');
      }
      const exp = normalizeDateStr(user_expires_at) || null;

      let picked = req.body.roles || [];
      if (!Array.isArray(picked)) picked = [picked];
      const pickedSet = new Set(picked.filter(r => ROLE_KEYS.includes(r)));

      // monta SET: dados básicos + cada papel = true/false (super_admin NUNCA entra)
      const sets = ['full_name=$1', 'email=$2', 'expires_at=$3'];
      const vals = [full_name, email, exp];
      let i = vals.length;
      for (const key of ROLE_KEYS) { sets.push(`${key}=$${++i}`); vals.push(pickedSet.has(key)); }
      // Campos PAV com valor (não booleanos): categoria_pav (fisio/enf/—), conselho.
      const catPav = ['fisio','enf'].includes(req.body.categoria_pav) ? req.body.categoria_pav : null;
      const conselho = String(req.body.conselho || '').trim().slice(0, 60) || null;
      sets.push(`categoria_pav=$${++i}`); vals.push(catPav);
      sets.push(`conselho=$${++i}`); vals.push(conselho);
      if (password && password.trim()) {
        const hash = await bcrypt.hash(password.trim(), 10);
        sets.push(`password_hash=$${++i}`); vals.push(hash);
      }
      vals.push(id);
      await pool.query(`UPDATE users SET ${sets.join(', ')} WHERE id=$${vals.length}`, vals);

      res.redirect(`/admin/usuarios/${id}`);
    } catch (err) {
      console.error('ADMIN USUARIOS EDIT POST ERROR', err);
      const msg = /duplicate|unique/i.test(String(err.message)) ? 'Já existe um usuário com esse e-mail.' : (err.message || 'Falha ao salvar');
      res.status(500).send(renderShell('Erro', `<div class="card"><h1>Falha ao salvar</h1><p class="mut">${safe(msg)}</p><p><a href="/admin/usuarios/${id}">Voltar</a></p></div>`));
    }
  });
}
