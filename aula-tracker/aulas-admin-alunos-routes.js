// ====== Admin: Alunos, Matrículas, Pendentes e Importação ======
// Extraído do app.js — sem alterações de comportamento.

import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { sendWelcomeEmail } from './mailer.js';
import { safe, renderShell } from './ui-shell.js';
import { fmt, normalizeDateStr } from './aulas-utils.js';

const ALLOWED_EMAIL_DOMAIN = process.env.ALLOWED_EMAIL_DOMAIN || null;
const SEMESTER_END = process.env.SEMESTER_END || null;

export function registerAulasAdminAlunosRoutes(app, pool, { authRequired, adminRequired }) {

async function sendWelcomeAndMark({ userId, email, name, login, plain }) {
  // Segurança: só envia uma vez
  const chk = await pool.query(
    'SELECT welcome_email_sent_at FROM users WHERE id=$1',
    [userId]
  );
  if (chk.rows[0]?.welcome_email_sent_at) return;

  await sendWelcomeEmail({
    to: email,
    name: name || email,
    login: login || email,
    password: String(plain)
  });

  await pool.query(
    'UPDATE users SET welcome_email_sent_at = now() WHERE id=$1',
    [userId]
  );
}

  // ====== Admin: Solicitações de acesso ======
app.get('/admin/pendentes', authRequired, adminRequired, async (req, res) => {
  try {
    const { rows: pend } = await pool.query(`
      SELECT ar.id, ar.full_name, ar.email, ar.justification, ar.created_at,
             c.id AS course_id, c.name AS course_name, c.slug AS course_slug
      FROM access_requests ar
      LEFT JOIN courses c ON c.id = ar.course_id
      WHERE ar.status = 'pending'
      ORDER BY ar.created_at ASC
    `);

    const rows = pend.map(r => `
      <tr>
        <td><strong>${safe(r.full_name)}</strong><div class="mut">${safe(r.email)}</div></td>
        <td>[${safe(r.course_slug||'-')}] ${safe(r.course_name||'(curso removido)')}</td>
        <td>${safe(r.justification||'—')}</td>
        <td>${fmt(r.created_at)||'—'}</td>
        <td style="white-space:nowrap">
          <form method="POST" action="/admin/pendentes/${r.id}/aprovar" class="inline">
            <button>Aprovar</button>
          </form>
          <form method="POST" action="/admin/pendentes/${r.id}/rejeitar" class="inline" style="margin-left:8px" onsubmit="return confirm('Rejeitar esta solicitação?');">
            <button style="background:#444">Rejeitar</button>
          </form>
        </td>
      </tr>
    `).join('');

    const html = `
      <div class="card">
        <div class="right" style="justify-content:space-between">
          <h1>Solicitações de acesso</h1>
          <div><a href="/aulas">Voltar</a></div>
        </div>
        <table class="mt2">
          <thead><tr><th>Aluno</th><th>Curso</th><th>Justificativa</th><th>Enviado em</th><th>Ações</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="5" class="mut">Nenhuma solicitação pendente.</td></tr>'}</tbody>
        </table>
      </div>`;
    res.send(renderShell('Pendentes', html));
  } catch (err) {
    console.error('ACCESS LIST ERROR', err);
    res.status(500).send('Falha ao listar solicitações');
  }
});

app.post('/admin/pendentes/:id/rejeitar', authRequired, adminRequired, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  try {
    await pool.query(
      `UPDATE access_requests SET status='rejected', processed_at=now() WHERE id=$1 AND status='pending'`,
      [id]
    );
    res.redirect('/admin/pendentes');
  } catch (err) {
    console.error('ACCESS REJECT ERROR', err);
    res.status(500).send('Falha ao rejeitar');
  }
});

app.post('/admin/pendentes/:id/aprovar', authRequired, adminRequired, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows: rws } = await client.query(
      `SELECT ar.id, ar.full_name, ar.email, ar.course_id
         FROM access_requests ar
        WHERE ar.id=$1 AND ar.status='pending'
        FOR UPDATE`,
      [id]
    );
    const r = rws[0];
    if (!r) {
      await client.query('ROLLBACK');
      return res.status(404).send('Solicitação não encontrada ou já processada');
    }

    // upsert de usuário por e-mail
    const email = r.email.toLowerCase().trim();
    const existing = (await client.query('SELECT id FROM users WHERE email=$1', [email])).rows[0];
    let userId;
    let plain = crypto.randomBytes(4).toString('hex'); // 8 chars
    const hash = await bcrypt.hash(plain, 10);

    if (existing) {
      userId = existing.id;
      // só define senha nova se usuário ainda não tiver (ou se quiser forçar reset)
      await client.query(`UPDATE users SET full_name = COALESCE($1, full_name) WHERE id=$2`, [r.full_name || null, userId]);
      const hasPwd = (await client.query('SELECT password_hash FROM users WHERE id=$1', [userId])).rows[0]?.password_hash;
      if (!hasPwd) {
        await client.query(`UPDATE users SET password_hash=$1, temp_password=$2 WHERE id=$3`, [hash, plain, userId]);
      }
    } else {
      const ins = await client.query(
        `INSERT INTO users(full_name,email,password_hash,temp_password)
         VALUES ($1,$2,$3,$4) RETURNING id`,
        [r.full_name, email, hash, plain]
      );
      userId = ins.rows[0].id;
    }

    // matrícula (upsert) no curso solicitado
    if (r.course_id) {
      await client.query(
        `INSERT INTO course_members(user_id, course_id, role)
         VALUES ($1,$2,'student')
         ON CONFLICT (user_id, course_id) DO NOTHING`,
        [userId, r.course_id]
      );
    }

    // marcar request como aprovado
    await client.query(
      `UPDATE access_requests
          SET status='approved', processed_at=now()
        WHERE id=$1`,
      [id]
    );

    await client.query('COMMIT');

    // envia e-mail de boas-vindas (e marca welcome_email_sent_at)
    await sendWelcomeAndMark({
      userId,
      email,
      name: r.full_name,
      login: email,
      plain
    });

    res.redirect('/admin/pendentes');
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch {}
    console.error('ACCESS APPROVE ERROR', err);
    res.status(500).send('Falha ao aprovar');
  } finally {
    client.release();
  }
});

// ====== Admin: Alunos (listar, filtrar, seleção múltipla, criar, editar, matrículas) ======
app.get('/admin/alunos', adminRequired, async (req, res) => {
    try {
      const { q, course_id, role } = req.query || {};
  
      // Cursos (inclua arquivados se quiser no filtro; aqui pego todos)
      const { rows: courses } = await pool.query('SELECT id, name, slug FROM courses ORDER BY name ASC');
  
      // Monta filtro dinâmico
      const params = [];
      const where = [];
  
      if (q && q.trim()) {
        params.push(`%${q.trim().toLowerCase()}%`);
        where.push(`(LOWER(u.full_name) LIKE $${params.length} OR LOWER(u.email) LIKE $${params.length})`);
      }
      if (course_id) {
        params.push(course_id);
        // só lista usuários matriculados no curso escolhido
        where.push(`EXISTS (SELECT 1 FROM course_members cm WHERE cm.user_id = u.id AND cm.course_id = $${params.length})`);
      }
      if (role === 'admin')  where.push(`u.is_admin = true`);
      if (role === 'student') where.push(`u.is_admin = false`);
  
      const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
  
      // Usuários filtrados
      const { rows: users } = await pool.query(
        `SELECT u.id, u.full_name, u.email, u.expires_at, u.is_admin, u.temp_password
           FROM users u
           ${whereSql}
           ORDER BY u.full_name NULLS LAST, u.email`
      , params);
  
      // Busca matrículas apenas dos usuários listados (evita tabela enorme quando há filtros)
      let byUser = new Map();
      if (users.length) {
        const ids = users.map(u => u.id);
        const placeholders = ids.map((_, i) => `$${i + 1}`).join(',');
        const { rows: members } = await pool.query(
          `SELECT cm.user_id, cm.course_id, cm.expires_at, c.name, c.slug
             FROM course_members cm
             JOIN courses c ON c.id = cm.course_id
            WHERE cm.user_id IN (${placeholders})`,
          ids
        );
        for (const m of members) {
          if (!byUser.has(m.user_id)) byUser.set(m.user_id, []);
          byUser.get(m.user_id).push(m);
        }
      }
  
      // linhas da tabela
      const userRows = users.map(u => {
        const m = byUser.get(u.id) || [];
        const memberships = m
          .map(x => `[${safe(x.slug)}] ${safe(x.name)}${x.expires_at ? ` <span class="mut">(até ${fmt(x.expires_at)})</span>` : ''}`)
          .join('<br/>') || '<span class="mut">—</span>';
  
        return `<tr>
          <td><input type="checkbox" name="ids[]" value="${u.id}"></td>
          <td>${u.id}</td>
          <td>${safe(u.full_name) || '-'}</td>
          <td>${safe(u.email)}</td>
          <td>${fmt(u.expires_at) || '<span class="mut">—</span>'}</td>
          <td>${u.is_admin ? 'Admin' : 'Aluno'}</td>
          <td>${u.temp_password ? `<code>${safe(u.temp_password)}</code>` : '—'}</td>
          <td><a href="/admin/alunos/${u.id}/edit">editar</a></td>
        </tr>`;
      }).join('');
  
      // opções de curso no filtro e no form de criação
      const courseOptsFilter = ['<option value="">(Todos)</option>']
        .concat(courses.map(c => `<option value="${c.id}" ${String(c.id) === String(course_id) ? 'selected' : ''}>[${safe(c.slug)}] ${safe(c.name)}</option>`))
        .join('');
      const courseOptsCreate = courses.map(c => `<option value="${c.id}">[${safe(c.slug)}] ${safe(c.name)}</option>`).join('');
  
      const roleOpts = `
        <option value="">(Todos)</option>
        <option value="student" ${role === 'student' ? 'selected' : ''}>Alunos</option>
        <option value="admin" ${role === 'admin' ? 'selected' : ''}>Admins</option>
      `;
  
      const body = `
        <div class="card">
          <div class="right" style="justify-content:space-between">
            <h1>Alunos</h1>
            <div><a href="/aulas">Voltar</a></div>
          </div>
  
          <!-- Filtros -->
          <form method="GET" action="/admin/alunos" class="mt2">
            <div class="row">
              <div>
                <label>Nome/Email</label>
                <input name="q" value="${q ? safe(q) : ''}" placeholder="ex.: maria / @usf.edu.br">
              </div>
              <div>
                <label>Curso</label>
                <select name="course_id">${courseOptsFilter}</select>
              </div>
              <div>
                <label>Tipo</label>
                <select name="role">${roleOpts}</select>
              </div>
            </div>
            <button class="mt">Filtrar</button>
            <a href="/admin/alunos" class="mt" style="margin-left:12px;display:inline-block">Limpar</a>
          </form>
  
          <!-- Ações em lote -->
          <form method="POST" action="/admin/alunos/bulk" id="bulkForm">
            <div class="mt2" style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
              <label><input type="checkbox" id="selectAll"> Selecionar todos</label>
              <button type="submit" name="action" value="delete" onclick="return confirm('Apagar os alunos selecionados? Esta ação também remove matrículas, sessões e eventos.');">Apagar selecionados</button>
            </div>
  
            <table class="mt2">
              <thead>
                <tr>
                  <th></th>
                  <th>ID</th>
                  <th>Nome</th>
                  <th>Email</th>
                  <th>Validade usuário</th>
                  <th>Tipo</th>
                  <th>Senha temporária</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>${userRows || '<tr><td colspan="8" class="mut">Nenhum aluno.</td></tr>'}</tbody>
            </table>
          </form>
  
          <!-- Adicionar aluno manualmente (mantido) -->
          <h2 class="mt2">Adicionar aluno manualmente</h2>
          <form method="POST" action="/admin/alunos" class="mt2">
            <div class="row">
              <div>
                <label>Nome completo</label><input name="full_name" required>
                <label>Senha</label><input name="password" type="text" required placeholder="ex.: Abc123456">
                <label>Validade do usuário (opcional)</label><input name="user_expires_at" type="datetime-local">
              </div>
              <div>
                <label>Email</label><input name="email" type="email" required>
                <label>Matricular no curso</label><select name="course_id">${courseOptsCreate}</select>
                <label>Validade da matrícula (opcional)</label><input name="member_expires_at" type="datetime-local">
              </div>
            </div>
            <button class="mt">Criar aluno</button>
          </form>
        </div>
  
        <script>
          (function(){
            const selectAll = document.getElementById('selectAll');
            const form = document.getElementById('bulkForm');
            if(selectAll && form){
              selectAll.addEventListener('change', ()=>{
                form.querySelectorAll('input[type="checkbox"][name="ids[]"]').forEach(ch => ch.checked = selectAll.checked);
              });
            }
          })();
        </script>
      `;
      res.send(renderShell('Alunos', body));
    } catch (err) {
      console.error('ADMIN STUDENTS LIST ERROR', err);
      res.status(500).send(renderShell('Erro', `<div class="card"><h1>Falha ao carregar</h1><p class="mut">${err.message || err}</p></div>`));
    }
  });

  // ====== Admin: Ação em lote (ex.: apagar selecionados) ======
app.post('/admin/alunos/bulk', adminRequired, async (req, res) => {
    const { action } = req.body || {};
    let ids = req.body['ids[]'] || req.body.ids || [];
    if (!Array.isArray(ids)) ids = [ids];
    ids = ids.map(x => parseInt(x, 10)).filter(n => Number.isFinite(n));
  
    if (!ids.length) return res.redirect('/admin/alunos');
  
    // não permitir que o admin logado se apague
    const selfId = req.user?.id;
    ids = ids.filter(id => id !== selfId);
    if (!ids.length) return res.redirect('/admin/alunos');
  
    if (action === 'delete') {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
  
        const placeholders = ids.map((_, i) => `$${i + 1}`).join(',');
  
        // apaga em ordem segura (se não houver FKs com CASCADE)
        await client.query(
          `DELETE FROM events
             WHERE session_id IN (SELECT id FROM sessions WHERE user_id IN (${placeholders}))`,
          ids
        );
        await client.query(
          `DELETE FROM sessions WHERE user_id IN (${placeholders})`,
          ids
        );
        await client.query(
          `DELETE FROM course_members WHERE user_id IN (${placeholders})`,
          ids
        );
        await client.query(
          `DELETE FROM users WHERE id IN (${placeholders})`,
          ids
        );
  
        await client.query('COMMIT');
        return res.redirect('/admin/alunos');
      } catch (e) {
        try { await client.query('ROLLBACK'); } catch {}
        console.error('BULK DELETE USERS ERROR', e);
        return res
          .status(500)
          .send(renderShell('Erro',
            `<div class="card"><h1>Falha ao apagar</h1><p class="mut">${safe(e.message || e)}</p><p><a href="/admin/alunos">Voltar</a></p></div>`));
      } finally {
        client.release();
      }
    }
  
    // outras ações futuras (ex.: tornar admin, remover admin, remover de curso, etc.)
    return res.redirect('/admin/alunos');
  });
  
// Se for enviar e-mail já no cadastro manual, garanta este import no topo do arquivo:
// import { sendWelcomeEmail } from './mailer.js';

app.post('/admin/alunos', adminRequired, async (req, res) => {
  try {
    let { full_name, email, password, user_expires_at, course_id, member_expires_at } = req.body || {};
    if (!full_name || !email || !password) return res.status(400).send('Dados obrigatórios');

    email = String(email).trim().toLowerCase();
    if (ALLOWED_EMAIL_DOMAIN && !email.endsWith(`@${ALLOWED_EMAIL_DOMAIN.toLowerCase()}`)) {
      return res.status(400).send('Domínio inválido');
    }

    const userExp = normalizeDateStr(user_expires_at) || SEMESTER_END || null;
    const plain = String(password).trim();
    const hash = await bcrypt.hash(plain, 10);

    // salva temp_password
    const ins = await pool.query(
      `INSERT INTO users (full_name, email, password_hash, expires_at, temp_password)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id`,
      [full_name, email, hash, userExp, plain]
    );
    const userId = ins.rows[0].id;

    if (course_id) {
      await pool.query(
        `INSERT INTO course_members (user_id, course_id, role, expires_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_id, course_id) DO UPDATE SET expires_at = EXCLUDED.expires_at`,
        [userId, course_id, 'student', normalizeDateStr(member_expires_at) || null]
      );
    }

    // Envia boas-vindas e marca
    if (process.env.SEND_WELCOME_ON_CREATE === '1') {
      try {
        await sendWelcomeAndMark({
          userId, email, name: full_name, login: email, plain
        });
      } catch (e) {
        console.error('WELCOME EMAIL (manual) ERROR', e);
        // segue sem travar o cadastro
      }
    }

    res.redirect('/admin/alunos');
  } catch (err) {
    console.error('ADMIN STUDENTS CREATE ERROR', err);
    res.status(500).send('Falha ao criar aluno');
  }
});

  
// ====== Admin: editar aluno + progresso por aula (com opção de Reenviar credenciais) ======
app.get('/admin/alunos/:id/edit', adminRequired, async (req,res)=>{
    const id = parseInt(req.params.id,10);
    if(!Number.isFinite(id)) return res.status(400).send('ID inválido');
  
    try{
      // dados do aluno (agora inclui temp_password e welcome_email_sent_at)
      const ures = await pool.query(
        `SELECT id, full_name, email, expires_at, temp_password, welcome_email_sent_at, created_at
           FROM users
          WHERE id=$1`,
        [id]
      );
      const u = ures.rows[0];
      if(!u){
        return res.status(404).send(
          renderShell('Editar aluno', `<div class="card"><h1>Aluno não encontrado</h1><a href="/admin/alunos">Voltar</a></div>`)
        );
      }
  
      // matrículas do aluno
      const mres = await pool.query(`
        SELECT cm.course_id, cm.expires_at, c.name, c.slug
        FROM course_members cm
        JOIN courses c ON c.id=cm.course_id
        WHERE cm.user_id=$1
        ORDER BY c.name
      `,[id]);
      const memberships = mres.rows;
  
      // cursos para combo
      const cres = await pool.query('SELECT id, name, slug FROM courses ORDER BY name ASC');
      const courses = cres.rows;
      const courseOpts = courses.map(c=>`<option value="${c.id}">[${safe(c.slug)}] ${safe(c.name)}</option>`).join('');
  
      // ===== PROGRESSO CONSOLIDADO POR AULA (do aluno) =====
      const prog = (await pool.query(`
        WITH base AS (
          SELECT
            v.id                AS video_id,
            v.title             AS video_title,
            v.duration_seconds  AS duration_seconds,
            MAX(e.video_time)   AS max_time,
            MAX(e.client_ts)    AS last_ts,
            COUNT(*) FILTER (WHERE e.type='play')   AS plays,
            COUNT(*) FILTER (WHERE e.type='pause')  AS pauses,
            COUNT(*) FILTER (WHERE e.type='ended')  AS ends,
            COUNT(*)                                   AS events
          FROM sessions s
          JOIN events   e ON e.session_id = s.id
          JOIN videos   v ON v.id = s.video_id
          WHERE s.user_id = $1
          GROUP BY v.id, v.title, v.duration_seconds
        )
        SELECT *,
          CASE WHEN duration_seconds IS NULL OR duration_seconds <= 0 THEN NULL
               ELSE ROUND( LEAST(GREATEST(max_time,0), duration_seconds)::numeric * 100.0 / duration_seconds, 1)
          END AS pct
        FROM base
        ORDER BY video_title ASC
      `,[id])).rows;
  
      const membershipsHtml = memberships.length
        ? memberships.map(x=>`<tr>
              <td>[${safe(x.slug)}] ${safe(x.name)}</td>
              <td>${fmt(x.expires_at) || '<span class="mut">—</span>'}</td>
              <td>
                <form class="inline" method="POST" action="/admin/alunos/${u.id}/matricula/${x.course_id}/validade">
                  <input name="member_expires_at" type="datetime-local">
                  <button>Atualizar validade</button>
                </form>
                <form class="inline" method="POST" action="/admin/alunos/${u.id}/matricula/${x.course_id}/remover" onsubmit="return confirm('Remover matrícula deste curso?');">
                  <button class="linkbutton" type="submit">remover</button>
                </form>
              </td>
            </tr>`).join('')
        : '<tr><td colspan="3" class="mut">Sem matrículas.</td></tr>';
  
      const progRows = prog.map(r => `
        <tr>
          <td>${r.video_id}</td>
          <td><a href="/aula/${r.video_id}" target="_blank">${safe(r.video_title)}</a></td>
          <td>${r.duration_seconds ?? '—'}</td>
          <td>${r.max_time ?? 0}</td>
          <td>${r.pct == null ? '—' : (r.pct + '%')}</td>
          <td>${fmt(r.last_ts) || '—'}</td>
          <td>${r.plays||0}/${r.pauses||0}/${r.ends||0}</td>
          <td><a href="/admin/relatorios?video_id=${r.video_id}&q=${encodeURIComponent(u.email)}" target="_blank">ver detalhes</a></td>
        </tr>
      `).join('');
  
      // Bloco de credenciais (mostra botão de Reenviar só se houver temp_password)
      const credsBlock = `
        <h3 class="mt2">Credenciais</h3>
        ${
          u.temp_password
            ? `
              <div class="mut">Um <code>temp_password</code> está armazenado para este aluno.</div>
              <form method="POST" action="/admin/alunos/${u.id}/resend" class="mt2">
                <button type="submit">Reenviar credenciais</button>
              </form>
              ${u.welcome_email_sent_at ? `<div class="mut" style="margin-top:6px">Último envio: ${fmt(u.welcome_email_sent_at)}</div>` : ''}
            `
            : `
              <div class="mut">Sem <code>temp_password</code> armazenado. Para habilitar o reenvio, defina uma nova senha no formulário acima.</div>
            `
        }
      `;
  
      const body = `
        <div class="card">
          <div class="right" style="justify-content:space-between">
            <h1>Editar aluno #${u.id}</h1>
            <div><a href="/admin/alunos">Voltar</a></div>
          </div>
          <form method="POST" action="/admin/alunos/${u.id}/edit" class="mt2">
            <label>Nome</label><input name="full_name" value="${safe(u.full_name).replace(/"/g,'&quot;')}">
            <label>Email</label><input name="email" type="email" value="${safe(u.email)}">
            <label>Nova senha (opcional)</label><input name="password" type="text" placeholder="deixe em branco para não alterar">
            <label>Validade do usuário</label><input name="user_expires_at" type="datetime-local">
            <button class="mt">Salvar</button>
          </form>
  
          ${credsBlock}
        </div>
  
        <div class="card">
          <h2>Matrículas</h2>
          <table class="mt2">
            <thead><tr><th>Curso</th><th>Validade</th><th>Ações</th></tr></thead>
            <tbody>${membershipsHtml}</tbody>
          </table>
  
          <h3 class="mt2">Matricular em curso</h3>
          <form method="POST" action="/admin/alunos/${u.id}/matricular" class="mt2">
            <label>Curso</label><select name="course_id" required>${courseOpts}</select>
            <label>Validade (opcional)</label><input name="member_expires_at" type="datetime-local">
            <button class="mt">Matricular</button>
          </form>
        </div>
  
        <div class="card">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:12px">
            <h2>Progresso por aula</h2>
            <div>
              <a href="/admin/alunos/${u.id}/relatorio.csv" target="_blank">Exportar CSV</a>
            </div>
          </div>
          <table class="mt2">
            <thead>
              <tr>
                <th>ID</th>
                <th>Vídeo</th>
                <th>Duração (s)</th>
                <th>Max pos (s)</th>
                <th>% assistido</th>
                <th>Último evento</th>
                <th>plays/pauses/ends</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              ${progRows || '<tr><td colspan="8" class="mut">Sem eventos para este aluno.</td></tr>'}
            </tbody>
          </table>
        </div>
      `;
  
      res.send(renderShell('Editar aluno', body));
    }catch(err){
      console.error('ADMIN STUDENT EDIT ERROR', err);
      res.status(500).send(renderShell('Erro', `<div class="card"><h1>Falha ao carregar</h1><p class="mut">${safe(err.message||err)}</p></div>`));
    }
  });
  
  // ====== Admin: CSV consolidado por aluno (resumo por aula) ======
app.get('/admin/alunos/:id/relatorio.csv', adminRequired, async (req,res)=>{
    const id = parseInt(req.params.id,10);
    if(!Number.isFinite(id)) return res.status(400).send('ID inválido');
  
    try{
      const rows = (await pool.query(`
        WITH base AS (
          SELECT
            v.id                AS video_id,
            v.title             AS video_title,
            v.duration_seconds  AS duration_seconds,
            MAX(e.video_time)   AS max_time,
            MAX(e.client_ts)    AS last_ts,
            COUNT(*) FILTER (WHERE e.type='play')   AS plays,
            COUNT(*) FILTER (WHERE e.type='pause')  AS pauses,
            COUNT(*) FILTER (WHERE e.type='ended')  AS ends,
            COUNT(*)                                   AS events
          FROM sessions s
          JOIN events   e ON e.session_id = s.id
          JOIN videos   v ON v.id = s.video_id
          WHERE s.user_id = $1
          GROUP BY v.id, v.title, v.duration_seconds
        )
        SELECT *,
          CASE WHEN duration_seconds IS NULL OR duration_seconds <= 0 THEN NULL
               ELSE ROUND( LEAST(GREATEST(max_time,0), duration_seconds)::numeric * 100.0 / duration_seconds, 1)
          END AS pct
        FROM base
        ORDER BY video_title ASC
      `,[id])).rows;
  
      res.setHeader('Content-Type','text/csv; charset=utf-8');
      const header = 'video_id;video_title;duration_seconds;max_time;pct;last_ts;plays;pauses;ends;events\n';
      const body = rows.map(r =>
        [
          r.video_id,
          (r.video_title||'').replace(/;/g, ','),
          r.duration_seconds ?? '',
          r.max_time ?? '',
          r.pct ?? '',
          r.last_ts ?? '',
          r.plays ?? 0,
          r.pauses ?? 0,
          r.ends ?? 0,
          r.events ?? 0
        ].join(';')
      ).join('\n');
      res.send(header + body);
    }catch(err){
      console.error('ADMIN STUDENT CSV ERROR', err);
      res.status(500).send('Falha ao gerar CSV');
    }
  });
app.post('/admin/alunos/:id/edit', adminRequired, async (req,res)=>{
  try{
    const id = parseInt(req.params.id,10);
    let { full_name, email, password, user_expires_at } = req.body || {};
    if(!full_name || !email) return res.status(400).send('Nome e email obrigatórios');
    email = String(email).trim().toLowerCase();
    if (ALLOWED_EMAIL_DOMAIN && !email.endsWith(`@${ALLOWED_EMAIL_DOMAIN.toLowerCase()}`)) return res.status(400).send('Domínio inválido');
    const exp = normalizeDateStr(user_expires_at) || null;
    if(password){
      const hash = await bcrypt.hash(password, 10);
      await pool.query('UPDATE users SET full_name=$1, email=$2, password_hash=$3, expires_at=$4 WHERE id=$5', [full_name,email,hash,exp,id]);
    }else{
      await pool.query('UPDATE users SET full_name=$1, email=$2, expires_at=$3 WHERE id=$4', [full_name,email,exp,id]);
    }
    res.redirect(`/admin/alunos/${id}/edit`);
  }catch(err){
    console.error('ADMIN STUDENT EDIT POST ERROR', err);
    res.status(500).send('Falha ao salvar');
  }
});
app.post('/admin/alunos/:id/matricular', adminRequired, async (req,res)=>{
  try{
    const id = parseInt(req.params.id,10);
    const { course_id, member_expires_at } = req.body || {};
    if(!course_id) return res.status(400).send('Curso obrigatório');
    await pool.query('INSERT INTO course_members(user_id,course_id,role,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT (user_id,course_id) DO UPDATE SET expires_at=EXCLUDED.expires_at',
      [id, course_id, 'student', normalizeDateStr(member_expires_at)||null]);
    res.redirect(`/admin/alunos/${id}/edit`);
  }catch(err){
    console.error('ADMIN ENROLL ERROR', err);
    res.status(500).send('Falha ao matricular');
  }
});
app.post('/admin/alunos/:id/matricula/:courseId/validade', adminRequired, async (req,res)=>{
  try{
    const id = parseInt(req.params.id,10);
    const courseId = parseInt(req.params.courseId,10);
    const { member_expires_at } = req.body || {};
    await pool.query('UPDATE course_members SET expires_at=$1 WHERE user_id=$2 AND course_id=$3', [normalizeDateStr(member_expires_at)||null, id, courseId]);
    res.redirect(`/admin/alunos/${id}/edit`);
  }catch(err){
    console.error('ADMIN ENROLL UPDATE ERROR', err);
    res.status(500).send('Falha ao atualizar validade');
  }
});
app.post('/admin/alunos/:id/matricula/:courseId/remover', adminRequired, async (req,res)=>{
  try{
    const id = parseInt(req.params.id,10);
    const courseId = parseInt(req.params.courseId,10);
    await pool.query('DELETE FROM course_members WHERE user_id=$1 AND course_id=$2', [id, courseId]);
    res.redirect(`/admin/alunos/${id}/edit`);
  }catch(err){
    console.error('ADMIN ENROLL REMOVE ERROR', err);
    res.status(500).send('Falha ao remover matrícula');
  }
});

app.post('/admin/alunos/:id/resend', adminRequired, async (req, res) => {
  try {
    const u = (await pool.query(
      'SELECT id, full_name, email, temp_password FROM users WHERE id=$1',
      [req.params.id]
    )).rows[0];

    if (!u) return res.status(404).send('Aluno não encontrado');
    if (!u.temp_password) return res.status(400).send('Sem senha temporária para este aluno.');

    await sendWelcomeEmail({
      to: u.email,
      name: u.full_name || u.email,
      login: u.email,
      password: u.temp_password
    });

    await pool.query(
      'UPDATE users SET welcome_email_sent_at = now() WHERE id=$1',
      [u.id]
    );

    res.redirect('/admin/alunos');
  } catch (e) {
    console.error('ADMIN RESEND ERROR', e);
    res.status(500).send('Falha ao reenviar credenciais');
  }
});

// ====== Admin: Relatório WEB por aluno (resumo por aula, com filtro por curso) ======
app.get('/admin/alunos/:id/relatorio', adminRequired, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id)) return res.status(400).send('ID inválido');

    const course_id = req.query.course_id ? parseInt(req.query.course_id, 10) : null;

    const u = (await pool.query('SELECT id, full_name, email FROM users WHERE id=$1', [id])).rows[0];
    if (!u) {
      return res.status(404).send(renderShell('Relatório do aluno', `<div class="card"><h1>Aluno não encontrado</h1><p><a href="/admin/alunos">Voltar</a></p></div>`));
    }

    const courses = (await pool.query(`
      SELECT DISTINCT c.id, c.name, c.slug
        FROM courses c
        JOIN videos v   ON v.course_id = c.id
        JOIN sessions s ON s.video_id  = v.id
       WHERE s.user_id = $1
       ORDER BY c.name
    `, [id])).rows;

    const courseOpts = ['<option value="">(Todos os cursos)</option>']
      .concat(courses.map(c => `<option value="${c.id}" ${String(c.id)===String(course_id||'')?'selected':''}>${safe(c.name)} (${safe(c.slug)})</option>`))
      .join('');

      const where = ['s.user_id = $1'];
      const params = [id];
      if (course_id) {
        params.push(course_id);
        where.push(`v.course_id = $${params.length}`);
      }
      const whereSql = `WHERE ${where.join(' AND ')}`;
      
      const sql = `
        WITH base AS (
          SELECT
            v.id               AS video_id,
            v.title            AS video_title,
            v.duration_seconds AS duration_seconds,
            c.name             AS course_name,
            c.slug             AS course_slug,
            MAX(e.client_ts)   AS last_ts,
            COUNT(*) FILTER (WHERE e.type='play')  AS plays,
            COUNT(*) FILTER (WHERE e.type='pause') AS pauses,
            COUNT(*) FILTER (WHERE e.type='ended') AS ends,
            COUNT(*)                                  AS events,
            COALESCE(
              SUM(
                GREATEST(0, ws.end_sec - ws.start_sec)
              ), 0
            ) AS watched_seconds
          FROM sessions s
          JOIN videos   v ON v.id = s.video_id
          JOIN courses  c ON c.id = v.course_id
          LEFT JOIN events e ON e.session_id = s.id
          LEFT JOIN watch_segments ws ON ws.session_id = s.id
          ${whereSql}
          GROUP BY v.id, v.title, v.duration_seconds, c.name, c.slug
        )
        SELECT *,
          CASE
            WHEN duration_seconds IS NULL OR duration_seconds <= 0 THEN NULL
            ELSE ROUND(LEAST(watched_seconds, duration_seconds)::numeric * 100.0 / duration_seconds, 1)
          END AS pct
        FROM base
        ORDER BY course_name, video_title
      `;
      const rows = (await pool.query(sql, params)).rows;

    const batchList = rows.map(r =>
      `<label style="display:block"><input type="checkbox" name="video_ids[]" value="${r.video_id}"> ${safe(r.course_name)} — ${safe(r.video_title)} (ID ${r.video_id})</label>`
    ).join('');

    const table = rows.map(r => `
      <tr>
        <td>${safe(r.course_name)}</td>
        <td>${safe(r.video_title)}</td>
        <td>${r.duration_seconds ?? '—'}</td>
        <td>${r.max_time ?? 0}</td>
        <td>${r.pct == null ? '—' : (r.pct + '%')}</td>
        <td class="mut">${safe(r.plays)} / ${safe(r.pauses)} / ${safe(r.ends)} / ${safe(r.events)}</td>
      </tr>
    `).join('');

    const csvLink = `/admin/alunos/${id}/relatorio.csv` + (course_id ? `?course_id=${course_id}` : '');

    const html = `
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:12px">
          <h1>Relatório do aluno — ${safe(u.full_name) || '-'} <span class="mut">(${safe(u.email)})</span></h1>
          <div><a href="/admin/alunos/${u.id}/edit">Voltar ao aluno</a></div>
        </div>

        <form method="GET" action="/admin/alunos/${u.id}/relatorio" class="mt2">
          <label>Curso</label>
          <select name="course_id" onchange="this.form.submit()">${courseOpts}</select>
          <a class="mt" href="${csvLink}" style="margin-left:12px;display:inline-block">Exportar CSV</a>
        </form>

        <div class="card mt2" style="border:1px solid #ddd">
          <h2 class="mt0">Limpar relatórios do aluno (vídeos listados)</h2>
          <form method="POST" action="/admin/alunos/${u.id}/relatorio/clear-batch" id="batchClearForm">
            <div class="mt">
              <button type="button" class="linklike" id="selAll">Selecionar todos</button> ·
              <button type="button" class="linklike" id="selNone">Limpar seleção</button>
            </div>
            <div class="mt" style="columns:2;max-width:720px">
              ${batchList || '<span class="mut">Nenhum vídeo no resultado atual.</span>'}
            </div>
            <input type="hidden" name="redirect" value="/admin/alunos/${u.id}/relatorio${course_id ? `?course_id=${course_id}` : ''}">
            <div class="mt">
              <button ${rows.length ? '' : 'disabled'} onclick="return confirm('Remover TODOS os eventos e sessões deste aluno nos vídeos selecionados?');">Limpar selecionados</button>
            </div>
          </form>
        </div>

        <table class="mt2">
          <tr><th>Curso</th><th>Vídeo</th><th>Duração (s)</th><th>Max pos (s)</th><th>% assistido</th><th class="mut">plays/pauses/ends/events</th></tr>
          ${table || '<tr><td colspan="6" class="mut">Sem dados para este aluno.</td></tr>'}
        </table>
      </div>
      <style>.linklike{background:none;border:0;padding:0;color:#007bff;cursor:pointer}</style>
      <script>
        (function(){
          const root = document.getElementById('batchClearForm');
          if(!root) return;
          const selAll = document.getElementById('selAll');
          const selNone = document.getElementById('selNone');
          selAll && selAll.addEventListener('click', ()=>{ root.querySelectorAll('input[type=checkbox]').forEach(ch=>ch.checked=true); });
          selNone && selNone.addEventListener('click', ()=>{ root.querySelectorAll('input[type=checkbox]').forEach(ch=>ch.checked=false); });
        })();
      </script>
    `;
    res.send(renderShell('Relatório do aluno', html));
  } catch (err) {
    console.error('ADMIN STUDENT REPORT WEB ERROR', err);
    res.status(500).send(renderShell('Erro', `<div class="card"><h1>Falha ao gerar relatório</h1><p class="mut">${safe(err.message||err)}</p></div>`));
  }
});

// ====== Admin: Limpar relatórios do aluno (em lote por vídeos selecionados) ======
app.post('/admin/alunos/:id/relatorio/clear-batch', adminRequired, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id)) return res.status(400).send('ID inválido');
  
    const redirect = req.body?.redirect || `/admin/alunos/${id}/relatorio`;
    const selected = []
      .concat(req.body['video_ids[]'] || req.body.video_ids || [])
      .flat()
      .map(x => parseInt(x, 10))
      .filter(n => Number.isFinite(n));
  
    if (selected.length === 0) return res.redirect(redirect);
  
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
  
      await client.query(`
        DELETE FROM events
          WHERE session_id IN (
            SELECT id FROM sessions
             WHERE user_id = $1
               AND video_id = ANY($2::int[])
          )`, [id, selected]);
  
      try {
        await client.query(`
          DELETE FROM watch_segments
            WHERE session_id IN (
              SELECT id FROM sessions
               WHERE user_id = $1
                 AND video_id = ANY($2::int[])
            )`, [id, selected]);
      } catch {}
  
      await client.query(`
        DELETE FROM sessions
         WHERE user_id = $1
           AND video_id = ANY($2::int[])`, [id, selected]);
  
      await client.query('COMMIT');
      res.redirect(redirect);
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      console.error('ADMIN STUDENT CLEAR BATCH ERROR', e);
      res.status(500).send('Falha ao limpar');
    } finally {
      client.release();
    }
  });
// ====== Admin: Importação de alunos (CSV ou colar colunas) — atualização seletiva (nome/senha/validade/e-mail) ======
app.get('/admin/import', adminRequired, async (req,res)=>{
  const { rows:courses } = await pool.query('SELECT id,name,slug FROM courses ORDER BY name');
  const courseOpts = courses.map(c=>`<option value="${c.id}">[${safe(c.slug)}] ${safe(c.name)}</option>`).join('');

  const body = `
    <div class="card">
      <h1>Importar alunos</h1>
      <form method="POST" action="/admin/import">
        <label>Curso</label>
        <select name="course_id" required>${courseOpts}</select>

        <label>Dados (CSV ou colar colunas)</label>
        <textarea name="data" rows="14" placeholder="Exemplos:
Nome completo, email_atual, senha, validade, novo_email(opcional)
João Silva,joao@ex.com,Senha123,2025-12-31,joao.silva@ex.com
Maria Souza,maria@ex.com,123456,2025-12-30,

• Separador pode ser vírgula ou ponto-e-vírgula.
• Aspas ao redor de campos com vírgulas são aceitas.
• A primeira linha de cabeçalho (se presente) é ignorada."></textarea>

        <fieldset style="margin-top:12px;border:1px solid #ddd;padding:12px;border-radius:6px">
          <legend>Quando o aluno já existir:</legend>
          <label style="display:block;margin-top:6px">
            <input type="checkbox" name="overwrite_name" value="1" checked>
            Atualizar <b>nome</b> com o do CSV
          </label>
          <label style="display:block;margin-top:6px">
            <input type="checkbox" name="overwrite_password" value="1">
            Substituir <b>senha</b> pela do CSV (se vazia, gerar aleatória)
          </label>
          <label style="display:block;margin-top:6px">
            <input type="checkbox" name="overwrite_expires" value="1">
            Atualizar <b>validade</b> (expires_at) com a do CSV
          </label>
          <label style="display:block;margin-top:6px">
            <input type="checkbox" name="overwrite_email" value="1">
            Atualizar <b>e-mail</b> para o <i>novo_email</i> (5ª coluna) se informado e não houver conflito
          </label>
        </fieldset>

        <button class="mt">Importar</button>
      </form>

      <p class="mut mt">Dica: reimporte sem medo — só atualiza o que você marcar acima.</p>
      <div class="mt"><a href="/aulas">Voltar</a></div>
    </div>`;
  res.send(renderShell('Importar alunos', body));
});

app.post('/admin/import', adminRequired, async (req,res)=>{
  let client;
  try{
    let { data, course_id, overwrite_name, overwrite_password, overwrite_expires, overwrite_email } = req.body||{};
    if (!data || !course_id) {
      return res.status(400).send(renderShell('Importar alunos', `<div class="card"><h1>Erro</h1><p>Dados e curso são obrigatórios.</p><p><a href="/admin/import">Voltar</a></p></div>`));
    }

    const owName = String(overwrite_name||'') === '1';
    const owPass = String(overwrite_password||'') === '1';
    const owExpr = String(overwrite_expires||'') === '1';
    const owMail = String(overwrite_email||'') === '1';

    // Coleta de quem receberá e-mail após o COMMIT
    const toNotify = []; // { userId, email, name, login, plain }

    // Parser robusto (agora com 5 colunas): nome, email_atual, senha, validade, novo_email(opcional)
    const splitSmart = (line) => {
      const sep = line.includes(';') ? ';' : ',';
      const parts = [];
      let cur = '', inQ = false;
      for (let i=0;i<line.length;i++){
        const ch = line[i];
        if (ch === '"') {
          if (inQ && line[i+1] === '"') { cur += '"'; i++; }
          else inQ = !inQ;
        } else if (ch === sep && !inQ) {
          parts.push(cur.trim()); cur = '';
        } else {
          cur += ch;
        }
      }
      parts.push(cur.trim());
      while (parts.length < 5) parts.push('');
      return parts.slice(0,5); // [full_name, email_atual, password, expires, novo_email]
    };

    const lines = String(data).split(/\r?\n/).map(l=>l.trim()).filter(Boolean);
    if (!lines.length) {
      return res.status(400).send(renderShell('Importar alunos', `<div class="card"><h1>Erro</h1><p>Nenhuma linha encontrada.</p><p><a href="/admin/import">Voltar</a></p></div>`));
    }

    // detectar cabeçalho
    const maybeHeader = splitSmart(lines[0]).map(s => s.toLowerCase());
    const isHeader =
      maybeHeader.some(s => ['nome','full_name'].includes(s)) ||
      maybeHeader.includes('email') ||
      maybeHeader.some(s => ['senha','password'].includes(s)) ||
      maybeHeader.some(s => ['validade','expires_at','expira','vencimento'].includes(s)) ||
      maybeHeader.includes('novo_email');
    const workLines = isHeader ? lines.slice(1) : lines;

    client = await pool.connect();
    await client.query('BEGIN');

    const results = []; // {lineNo, email, action, ok, message}

    for (let idx=0; idx<workLines.length; idx++){
      const line = workLines[idx];
      const lineNo = isHeader ? idx+2 : idx+1;

      try{
        const [full_name_raw, email_raw, password_raw, userExp_raw, newEmail_raw] = splitSmart(line);
        const full_name = (full_name_raw || '').trim();
        const emailCsv  = (email_raw  || '').trim().toLowerCase(); // e-mail ATUAL (chave de busca)
        const expiresAt = normalizeDateStr(userExp_raw) || null;
        const newMail   = (newEmail_raw || '').trim().toLowerCase(); // novo e-mail (opcional)

        if (!emailCsv) {
          results.push({ lineNo, email:'', action:'skip', ok:false, message:'Linha sem e-mail' });
          continue;
        }

        const existing = await client.query('SELECT id, email FROM users WHERE email=$1',[emailCsv]);
        let userId;
        let action = 'create';

        if (existing.rows[0]) {
          // ---- atualização ----
          userId = existing.rows[0].id;
          action = 'update';

          // nome
          if (owName && full_name) {
            await client.query('UPDATE users SET full_name=$1 WHERE id=$2',[full_name, userId]);
          }

          // validade
          if (owExpr) {
            await client.query('UPDATE users SET expires_at=$1 WHERE id=$2',[expiresAt, userId]);
          }

          // senha (só se marcado overwrite_password)
          if (owPass) {
            const plain = (password_raw && String(password_raw).trim().length)
              ? String(password_raw).trim()
              : crypto.randomBytes(5).toString('base64url');
            const hash = await bcrypt.hash(plain,10);
            await client.query(
              'UPDATE users SET password_hash=$1, temp_password=$2 WHERE id=$3',
              [hash, plain, userId]
            );
            // agenda envio por ter trocado a senha
            toNotify.push({ userId, email: emailCsv, name: full_name || emailCsv, login: emailCsv, plain });
          }

          // e-mail (se permitido e se houver novo_email DIFERENTE)
          if (owMail && newMail && newMail !== existing.rows[0].email) {
            // checa conflito
            const conflict = await client.query('SELECT 1 FROM users WHERE email=$1 AND id<>$2',[newMail, userId]);
            if (conflict.rows[0]) throw new Error(`E-mail ${newMail} já usado por outro usuário`);
            await client.query('UPDATE users SET email=$1 WHERE id=$2',[newMail, userId]);
          }

        } else {
          // ---- novo usuário ----
          const plain = (password_raw && String(password_raw).trim().length)
            ? String(password_raw).trim()
            : crypto.randomBytes(5).toString('base64url');
          const hash = await bcrypt.hash(plain,10);

          const ins = await client.query(
            'INSERT INTO users(full_name,email,password_hash,expires_at,temp_password) VALUES($1,$2,$3,$4,$5) RETURNING id',
            [full_name || emailCsv, emailCsv, hash, expiresAt, plain]
          );
          userId = ins.rows[0].id;

          // agenda envio por ser novo usuário
          toNotify.push({ userId, email: emailCsv, name: full_name || emailCsv, login: emailCsv, plain });
        }

        // matrícula (ignora se já existir)
        await client.query(
          'INSERT INTO course_members(user_id,course_id,role) VALUES($1,$2,$3) ON CONFLICT (user_id,course_id) DO NOTHING',
          [userId, course_id, 'student']
        );

        results.push({ lineNo, email: emailCsv, action, ok:true, message:'OK' });

      } catch (lineErr) {
        results.push({ lineNo, email:'', action:'', ok:false, message: lineErr.message || String(lineErr) });
      }
    }

    await client.query('COMMIT');

    // === Envia e-mails fora da transação ===
    if (process.env.SEND_WELCOME_ON_CREATE === '1') {
      for (const m of toNotify) {
        try {
          await sendWelcomeAndMark(m);
        } catch (e) {
          console.error('WELCOME EMAIL (import) ERROR', m.email, e);
        }
      }
    }

    // Renderiza relatório
    const okRows  = results.filter(r=>r.ok);
    const badRows = results.filter(r=>!r.ok);
    const tableOk = okRows.map(r=>`<tr><td>${r.lineNo}</td><td>${safe(r.email)}</td><td>${r.action}</td><td>OK</td></tr>`).join('');
    const tableBad= badRows.map(r=>`<tr><td>${r.lineNo}</td><td>${safe(r.email)}</td><td>${r.action||'-'}</td><td style="color:#b00">${safe(r.message)}</td></tr>`).join('');

    const html = `
      <div class="card">
        <h1>Resultado da importação</h1>
        <p>${okRows.length} linha(s) OK, ${badRows.length} com erro.</p>
        ${tableBad ? `<h3>Com erro</h3><table><tr><th>Linha</th><th>Email</th><th>Ação</th><th>Erro</th></tr>${tableBad}</table>` : ''}
        ${tableOk ? `<h3>Sucesso</h3><table><tr><th>Linha</th><th>Email</th><th>Ação</th><th>Status</th></tr>${tableOk}</table>` : ''}
        <div class="mt"><a href="/admin/alunos">Voltar para Alunos</a> · <a href="/admin/import">Nova importação</a></div>
      </div>
    `;
    return res.send(renderShell('Importação', html));

  }catch(err){
    if (client) try{ await client.query('ROLLBACK'); }catch{}
    console.error('ADMIN IMPORT ERROR', err);
    return res.status(500).send(renderShell('Importar alunos', `<div class="card"><h1>Falha ao importar</h1><p class="mut">${safe(err.message||String(err))}</p><p><a href="/admin/import">Voltar</a></p></div>`));
  } finally {
    if (client) client.release();
  }
});

}
