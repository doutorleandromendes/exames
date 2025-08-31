// Aula Tracker — Postgres + Cloudflare R2 (SigV4)
// Admin: gerencia cursos, aulas, alunos/matrículas; vê/edita tudo; relatórios web + CSV ordenados por nome
// Player: URL assinada SigV4 (R2), sem download, watermark e tracking de progresso
// Ajustes nesta versão:
// - Disponibilidade: courses.start_date e videos.available_from
// - Tela admin para editar disponibilidade das aulas (/admin/videos/availability)
// - Filtro em /aulas (aluno) respeitando as datas

import express from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { Pool } from 'pg';

const app = express();
app.set('trust proxy', 1);
app.use(bodyParser.json({ limit: '2mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '4mb' }));
app.use(cookieParser());

const PORT = process.env.PORT || 3000;

// ====== ENV ======
const DATABASE_URL = process.env.DATABASE_URL;
const PGSSLMODE = process.env.PGSSLMODE || 'require';
const ADMIN_SECRET = process.env.ADMIN_SECRET || null;
const ALLOWED_EMAIL_DOMAIN = process.env.ALLOWED_EMAIL_DOMAIN || null;
const SEMESTER_END = process.env.SEMESTER_END || null;

// R2 (SigV4)
const R2_BUCKET = process.env.R2_BUCKET;
const R2_ENDPOINT = process.env.R2_ENDPOINT; // https://<ACCOUNT>.r2.cloudflarestorage.com
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY;

// ====== PG Pool ======
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: PGSSLMODE === 'require' ? { rejectUnauthorized: false } : false
});

// ====== HTML helpers ======
function renderShell(title, body) {
  return `<!doctype html>
  <html lang="pt-br">
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <title>${title}</title>
    <style>
      :root{--bg:#0b0c10;--card:#15171c;--txt:#e7e9ee;--mut:#a7adbb;--pri:#4f8cff}
      *{box-sizing:border-box} body{margin:0;font-family:system-ui,Segoe UI,Arial;background:var(--bg);color:var(--txt)}
      .wrap{max-width:1100px;margin:40px auto;padding:0 16px}
      .card{background:var(--card);border:1px solid #20242b;border-radius:16px;padding:24px;box-shadow:0 8px 24px rgba(0,0,0,.2)}
      label{display:block;margin:8px 0 4px}
      input,select,textarea{width:100%;padding:12px;border-radius:10px;border:1px solid #2a2f39;background:#0f1116;color:var(--txt)}
      button{background:var(--pri);color:#fff;border:0;border-radius:12px;padding:12px 16px;cursor:pointer;font-weight:600}
      .row{display:grid;gap:16px;grid-template-columns:1fr 1fr}
      .mt{margin-top:16px}.mt2{margin-top:24px}.mut{color:var(--mut)} a{color:#8fb6ff}
      table{width:100%;border-collapse:collapse} th,td{padding:8px;border-bottom:1px solid #2a2f39;text-align:left;vertical-align:top}
      .video{position:relative;aspect-ratio:16/9;background:#000;border-radius:16px;overflow:hidden}
      .wm{position:absolute;right:12px;bottom:12px;opacity:.65;background:rgba(0,0,0,.35);padding:6px 10px;border-radius:10px;font-size:12px}
      code{background:#0f1116;border:1px solid #2a2f39;border-radius:8px;padding:0 6px}
      .right{display:flex;gap:12px;align-items:center}
      form.inline{display:inline}
    </style>
  </head>
  <body><div class="wrap">${body}</div></body>
  </html>`;
}
const parseISO = s => (s ? new Date(s) : null);
const safe = s => (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const fmt = d => d ? new Date(d).toLocaleString('pt-BR') : '';
const fmtDTLocal = d => d ? new Date(d).toISOString().replace('T',' ').slice(0,16) : '';

// ====== Auth helpers ======
const isAdmin = req => req.cookies?.adm === '1';
const adminRequired = (req,res,next)=>{ if(!ADMIN_SECRET) return res.status(500).send('ADMIN_SECRET não configurado'); if(!isAdmin(req)) return res.redirect('/admin'); next(); };
const authRequired = async (req,res,next)=>{
  const uid = req.cookies?.uid;
  if(!uid) return res.redirect('/');
  try{
    const { rows } = await pool.query('SELECT id,email,full_name,expires_at FROM users WHERE id=$1',[uid]);
    const user = rows[0];
    if(!user) return res.redirect('/');
    const exp = parseISO(user.expires_at);
    if (exp && new Date() > exp) return res.send(renderShell('Acesso expirado', `<div class="card"><h1>Acesso expirado</h1><a href="/">Voltar</a></div>`));
    req.user = user;
    next();
  }catch{
    return res.redirect('/');
  }
};

// ====== MIGRAÇÕES ======
async function migrate(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users(
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE,
      password_hash TEXT,
      full_name TEXT,
      created_at TIMESTAMPTZ DEFAULT now(),
      expires_at TIMESTAMPTZ
    );`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS courses(
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      enroll_code TEXT,
      expires_at TIMESTAMPTZ
    );`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS course_members(
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
      role TEXT DEFAULT 'student',
      expires_at TIMESTAMPTZ,
      PRIMARY KEY (user_id, course_id)
    );`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS videos(
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      r2_key TEXT NOT NULL,
      course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
      duration_seconds INTEGER
    );`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessions(
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
      started_at TIMESTAMPTZ DEFAULT now()
    );`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS events(
      id SERIAL PRIMARY KEY,
      session_id INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
      type TEXT,
      video_time INTEGER,
      client_ts TIMESTAMPTZ
    );`);

  // Novas colunas de disponibilidade (idempotentes)
  await pool.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS start_date TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE videos  ADD COLUMN IF NOT EXISTS available_from TIMESTAMPTZ`);
}
migrate().catch(e=>console.error('migration error', e));

// ====== Clonar curso (copia as aulas do curso origem para um novo curso/semestre) ======
app.get('/admin/cursos/:id/clone', authRequired, adminRequired, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!Number.isFinite(id)) {
        return res.status(400).send(renderShell('Clonar curso', '<div class="card">ID inválido</div>'));
      }
  
      const { rows } = await pool.query('SELECT id, name, slug, start_date FROM courses WHERE id=$1', [id]);
      const c = rows[0];
      if (!c) {
        return res.send(renderShell('Erro', '<div class="card">Curso não encontrado</div>'));
      }
  
      const html = `
        <div class="card">
          <div style="display:flex;justify-content:space-between;gap:12px;align-items:center">
            <h1>Clonar Curso: ${safe(c.name)}</h1>
            <div><a href="/admin/cursos">Voltar</a></div>
          </div>
  
          <form method="POST" action="/admin/cursos/${c.id}/clone">
            <label>Novo nome</label>
            <input name="name" required value="${safe(c.name)}">
  
            <label>Novo slug</label>
            <input name="slug" required value="${safe(c.slug)}-novo">
  
            <label>Data de início do novo curso (YYYY-MM-DD ou YYYY-MM-DDTHH:mm-03:00)</label>
            <input name="start_date" placeholder="2025-02-10">
  
            <button class="mt">Clonar curso e aulas</button>
          </form>
  
          <p class="mut mt">
            As aulas serão clonadas com os mesmos títulos e R2 keys. O campo <code>available_from</code>
            nos vídeos clonados ficará vazio (você define depois). Relatórios e matrículas não são clonados.
          </p>
        </div>
      `;
      res.send(renderShell('Clonar curso', html));
    } catch (err) {
      console.error('ADMIN CLONE GET ERROR', err);
      res.status(500).send(renderShell('Erro', `<div class="card"><h1>Falha ao carregar</h1><p class="mut">${safe(err.message||err)}</p></div>`));
    }
  });

app.post('/admin/cursos/:id/clone', authRequired, adminRequired, async (req, res) => {
  const { id } = req.params;
  const { name, slug, start_date } = req.body || {};

  // cria novo curso
  const q1 = await pool.query(
    'INSERT INTO courses(name,slug,start_date) VALUES($1,$2,$3) RETURNING id',
    [name, slug, normalizeDateStr(start_date)]
  );
  const newCourseId = q1.rows[0].id;

  // copia aulas do curso origem para o novo
  await pool.query(`
    INSERT INTO videos (title, r2_key, course_id, duration_seconds, available_from)
    SELECT title, r2_key, $1, duration_seconds, NULL
    FROM videos WHERE course_id = $2
  `, [newCourseId, id]);

  res.redirect('/admin/cursos');
});


// ====== SigV4 (R2) ======
function hmac(key, msg) { return crypto.createHmac('sha256', key).update(msg).digest(); }
function sha256Hex(msg) { return crypto.createHash('sha256').update(msg).digest('hex'); }
function getV4SigningKey(secretKey, dateStamp, region, service) {
  const kDate = hmac('AWS4'+secretKey, dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  const kSigning = hmac(kService, 'aws4_request');
  return kSigning;
}
function generateSignedUrlForKey(key) {
  if (!R2_BUCKET || !R2_ENDPOINT || !R2_ACCESS_KEY_ID || !R2_SECRET_ACCESS_KEY) return null;
  const method='GET', service='s3', region='auto';
  const host = R2_ENDPOINT.replace(/^https?:\/\//,'').replace(/\/$/,'');
  const canonicalUri = `/${encodeURIComponent(R2_BUCKET)}/${key.split('/').map(encodeURIComponent).join('/')}`;

  const now = new Date();
  const amzdate = now.toISOString().replace(/[:-]|\.\d{3}/g,''); // YYYYMMDDTHHMMSSZ
  const datestamp = amzdate.substring(0,8);
  const credentialScope = `${datestamp}/${region}/${service}/aws4_request`;
  const expires = 86400; // 24h

  const qp = [
    ['X-Amz-Algorithm','AWS4-HMAC-SHA256'],
    ['X-Amz-Credential', `${R2_ACCESS_KEY_ID}/${credentialScope}`],
    ['X-Amz-Date', amzdate],
    ['X-Amz-Expires', String(expires)],
    ['X-Amz-SignedHeaders','host'],
    ['response-content-type','video/mp4']
  ];
  const canonicalQuerystring = qp.map(([k,v])=>`${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
  const canonicalHeaders = `host:${host}\n`;
  const signedHeaders = 'host';
  const payloadHash = 'UNSIGNED-PAYLOAD';

  const canonicalRequest = [method, canonicalUri, canonicalQuerystring, canonicalHeaders, signedHeaders, payloadHash].join('\n');
  const stringToSign = ['AWS4-HMAC-SHA256', amzdate, credentialScope, sha256Hex(canonicalRequest)].join('\n');
  const signingKey = getV4SigningKey(R2_SECRET_ACCESS_KEY, datestamp, region, service);
  const signature = crypto.createHmac('sha256', signingKey).update(stringToSign).digest('hex');

  return `${R2_ENDPOINT}${canonicalUri}?${canonicalQuerystring}&X-Amz-Signature=${signature}`;
}

// ====== Utils ======
function normalizeDateStr(s) {
  if (!s) return null;
  s = String(s).trim();
  if (!s) return null;
  if (/[zZ]|[+\-]\d{2}:\d{2}$/.test(s)) return s;
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return `${s}T23:59:59-03:00`;
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(s)) return `${s}:00-03:00`;
  const d = new Date(s);
  return isFinite(d) ? d.toISOString() : null;
}
const fmtDT = (d)=> d ? new Date(d).toISOString().replace('T',' ').slice(0,16) : '';

// ====== Health ======
app.get('/healthz', (req,res)=> res.status(200).send('ok'));

// ====== Público ======
app.get('/', (req,res)=>{
  const right = `<div class="card"><h2>Acesso</h2><p class="mut">Use o login/senha fornecidos pela coordenação.</p><p class="mut mt"><a href="/admin">Sou admin</a></p></div>`;
  const html = `
    <div class="row">
      <div class="card">
        <h1>Entrar</h1>
        <form id="loginForm" class="mt2">
          <label>E-mail</label><input name="email" type="email" required>
          <label>Senha</label><input name="password" type="password" required>
          <button class="mt">Entrar</button>
        </form>
      </div>
      ${right}
    </div>
    <script>
      async function postJSON(url, data){
        const r = await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
        const t = await r.text(); let j; try{ j=JSON.parse(t) }catch{ j={} }
        if(!r.ok) throw new Error(j.error||t||'Erro');
        return j;
      }
      document.getElementById('loginForm').addEventListener('submit', async (e)=>{
        e.preventDefault(); const f = new FormData(e.target);
        try{
          await postJSON('/api/login',{ email:f.get('email'), password:f.get('password') });
          location.href='/aulas';
        }catch(err){ alert(err.message); }
      });
    </script>`;
  res.send(renderShell('Acesso', html));
});
app.get('/logout', (req,res)=>{ res.clearCookie('uid'); res.clearCookie('adm'); res.redirect('/'); });

// ====== Admin (ativação por ADMIN_SECRET em cookie) ======
app.get('/admin', authRequired, (req,res)=>{
  if(!ADMIN_SECRET) return res.send(renderShell('Admin', `<div class="card"><h1>Admin</h1><p class="mut">Defina ADMIN_SECRET.</p></div>`));
  const html = `<div class="card"><h1>Admin</h1>
    <form method="POST" action="/admin">
      <label>ADMIN_SECRET</label><input name="secret" type="password" required>
      <button>Entrar no modo admin</button>
    </form>
    <p class="mut">Após entrar, verá cursos, cadastro de aulas, alunos, importação e disponibilidade.</p>
  </div>`;
  res.send(renderShell('Admin', html));
});
app.post('/admin', authRequired, (req,res)=>{
  const { secret } = req.body || {};
  if(!ADMIN_SECRET) return res.status(500).send('ADMIN_SECRET não configurado');
  if(secret !== ADMIN_SECRET) return res.status(403).send('ADMIN_SECRET inválido');
  res.cookie('adm','1',{ httpOnly:true, sameSite:'lax', secure:true, maxAge: 1000*60*60*24 });
  res.redirect('/aulas');
});
app.get('/admin/logout', authRequired, (req,res)=>{ res.clearCookie('adm'); res.redirect('/aulas'); });

// ====== /aulas — Admin vê tudo; aluno só o que está matriculado e liberado pelas datas ======
app.get('/aulas', authRequired, async (req,res)=>{
    try{
      const admin = isAdmin(req);
      const slug = (req.query.curso || '').trim();      // filtro por curso (slug)
      const q    = (req.query.q || '').trim();          // filtro por título (busca simples)
  
      // Carrega lista de cursos (para o dropdown) e identifica o curso atual (para link "Clonar")
      let courseForActions = null;
      let courseOptionsHtml = '';
      try {
        const { rows: courseRows } = await pool.query(
          'SELECT id, slug, name FROM courses WHERE archived = false ORDER BY name'
        );
        courseOptionsHtml = ['<option value="">(Todos os cursos)</option>']
          .concat(courseRows.map(c => 
            `<option value="${safe(c.slug)}" ${c.slug===slug?'selected':''}>${safe(c.name)} (${safe(c.slug)})</option>`
          ))
          .join('');
        if (admin && slug) {
          courseForActions = courseRows.find(c => c.slug === slug) || null;
        }
      } catch {}
  
      // Busca as aulas conforme papel (admin/aluno) + filtros (slug, q)
      let rows = [];
      if (admin) {
        // Admin: pode filtrar por curso (slug) e por título (q)
        const cond = [];
        const params = [];
        let idx = 1;
  
        cond.push('1=1'); // base
  
        if (slug) {
          cond.push(`c.slug = $${idx++}`);
          params.push(slug);
        }
        if (q) {
          cond.push(`LOWER(v.title) LIKE $${idx++}`);
          params.push(`%${q.toLowerCase()}%`);
        }
  
        const sqlAdmin = `
          SELECT v.id, v.title, v.course_id, v.r2_key, v.available_from,
                 c.name AS course_name, c.slug, c.start_date
          FROM videos v
          JOIN courses c ON c.id = v.course_id
          WHERE ${cond.join(' AND ')}
          ORDER BY v.id DESC`;
        ({ rows } = await pool.query(sqlAdmin, params));
      } else {
        // Aluno: apenas aulas matriculadas e liberadas; aceita também filtro de título (q)
        const condCore = [
          `(c.expires_at IS NULL OR c.expires_at > now())`,
          `(cm.expires_at IS NULL OR cm.expires_at > now())`,
          `(c.start_date IS NULL OR c.start_date <= now())`,
          `(v.available_from IS NULL OR v.available_from <= now())`,
          `c.archived = false`
        ];
        const paramsAluno = [req.user.id];
  
        if (slug) {
          condCore.unshift(`c.slug = $${paramsAluno.length + 1}`);
          paramsAluno.push(slug);
        }
        if (q) {
          condCore.push(`LOWER(v.title) LIKE $${paramsAluno.length + 1}`);
          paramsAluno.push(`%${q.toLowerCase()}%`);
        }
  
        const sqlAluno = `
          SELECT v.id, v.title, v.course_id, v.available_from,
                 c.name AS course_name, c.slug, c.start_date
          FROM videos v
          JOIN courses c ON c.id = v.course_id
          JOIN course_members cm ON cm.course_id = v.course_id AND cm.user_id = $1
          WHERE ${condCore.join(' AND ')}
          ORDER BY v.id DESC`;
        ({ rows } = await pool.query(sqlAluno, paramsAluno));
      }
  
      // Lista de itens (links)
      const items = rows.map(v=>{
        const tag = (!admin)
          ? ''
          : ` <span class="mut">[curso desde: ${fmt(v.start_date)||'—'} · aula desde: ${fmt(v.available_from)||'—'}]</span>`;
        const base = `<li><strong>[${safe(v.course_name)}]</strong> <a href="/aula/${v.id}">${safe(v.title)}</a>${tag} — <span class="mut">/aula/${v.id}</span>`;
        const extra = admin
          ? ` — <a href="/admin/relatorio/${v.id}">relatório (web)</a> · <a href="/admin/relatorio/${v.id}.csv">CSV</a> · <a href="/admin/videos/${v.id}/edit">editar</a>`
          : '';
        return `${base}${extra}</li>`;
      }).join('');
  
      // Barra de ações (inclui "Clonar curso" quando filtrado por um curso válido)
      const actions = admin
        ? [
            `<a href="/admin/cursos">Cursos</a>`,
            `<a href="/admin/videos">Cadastrar aula</a>`,
            `<a href="/admin/videos/availability">Disponibilidade de Aulas</a>`,
            `<a href="/admin/alunos">Alunos</a>`,
            `<a href="/admin/relatorios">Relatórios</a>`,
            `<a href="/admin/import">Importar alunos</a>`,
            (courseForActions ? `<a href="/admin/cursos/${courseForActions.id}/clone">Clonar curso "${safe(courseForActions.name)}"</a>` : null),
            `<a href="/admin/logout">Sair admin</a>`,
            `<a href="/logout">Sair</a>`
          ].filter(Boolean).join(' · ')
        : `<a href="/logout">Sair</a>`;
  
      // UI com filtros (dropdown de curso + busca por título)
      const body = `
        <div class="card">
          <div class="right" style="justify-content:space-between;align-items:center;gap:12px">
            <h1>Aulas</h1>
            <div>${actions}</div>
          </div>
  
          <form method="GET" action="/aulas" class="mt2" style="display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end">
            <div>
              <label style="display:block;margin-bottom:4px">Curso</label>
              <select name="curso" onchange="this.form.submit()" style="min-width:240px">${courseOptionsHtml}</select>
            </div>
            <div>
              <label style="display:block;margin-bottom:4px">Título contém</label>
              <input name="q" value="${safe(q)}" placeholder="ex.: hepatites, antibióticos" style="min-width:260px">
            </div>
            <div>
              <button type="submit">Aplicar</button>
              ${(slug || q) ? `<a href="/aulas" style="margin-left:8px">Limpar</a>` : ''}
            </div>
          </form>
  
          <p class="mut" style="margin-top:8px">
            ${slug ? `Curso: <strong>${safe(slug)}</strong>` : 'Curso: (todos)'}
            ${q ? ` · Título contém: <strong>${safe(q)}</strong>` : ''}
          </p>
  
          <ul style="margin-top:12px">${items || '<li class="mut">Nenhuma aula disponível.</li>'}</ul>
        </div>`;
      res.send(renderShell('Aulas', body));
    }catch(err){
      console.error('AULAS ERROR', err);
      res.status(500).send(renderShell('Erro', `<div class="card"><h1>Falha ao listar aulas</h1><p class="mut">${safe(err.message||err)}</p></div>`));
    }
  });

// ====== Relatórios (painel com filtros) ======
app.get('/admin/relatorios', authRequired, adminRequired, async (req, res) => {
  const { course_id, video_id, q, dt_from, dt_to } = req.query;

  // combos
  const courses = (await pool.query('SELECT id,name,slug FROM courses ORDER BY name')).rows;
  const videos = course_id
    ? (await pool.query('SELECT id,title FROM videos WHERE course_id=$1 ORDER BY title',[course_id])).rows
    : [];

  // filtros dinâmicos
  const where = [];
  const params = [];
  if (course_id) { params.push(course_id); where.push(`v.course_id = $${params.length}`); }
  if (video_id)  { params.push(video_id);  where.push(`v.id = $${params.length}`); }
  if (q)         { params.push(`%${String(q).toLowerCase()}%`); where.push(`(lower(u.full_name) LIKE $${params.length} OR lower(u.email) LIKE $${params.length})`); }
  if (dt_from)   { params.push(dt_from);   where.push(`e.client_ts >= $${params.length}`); }
  if (dt_to)     { params.push(dt_to);     where.push(`e.client_ts <= $${params.length}`); }
  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

  // agregação aluno × vídeo (% assistido via max(video_time) / duration_seconds)
  const sql = `
    WITH base AS (
      SELECT u.id AS user_id, u.full_name, u.email,
             v.id AS video_id, v.title, v.duration_seconds,
             MAX(e.video_time) AS max_time
      FROM sessions s
      JOIN events e ON e.session_id = s.id
      JOIN users u  ON u.id = s.user_id
      JOIN videos v ON v.id = s.video_id
      ${whereSql}
      GROUP BY u.id,u.full_name,u.email,v.id,v.title,v.duration_seconds
    )
    SELECT *, 
      CASE
        WHEN duration_seconds IS NULL OR duration_seconds <= 0 THEN NULL
        ELSE ROUND( LEAST(GREATEST(max_time,0), duration_seconds)::numeric * 100.0 / duration_seconds, 1)
      END AS pct
    FROM base
    ORDER BY full_name, title
  `;
  const rows = (await pool.query(sql, params)).rows;

  // combos HTML
  const courseOpts = ['<option value="">(Todos)</option>']
    .concat(courses.map(c=>`<option value="${c.id}" ${String(c.id)===String(course_id)?'selected':''}>${c.name}</option>`))
    .join('');
  const videoOpts = ['<option value="">(Todos)</option>']
    .concat(videos.map(v=>`<option value="${v.id}" ${String(v.id)===String(video_id)?'selected':''}>${v.title}</option>`))
    .join('');

  // tabela
  const table = rows.map(r=>`
    <tr>
      <td>${r.full_name}</td>
      <td>${r.email}</td>
      <td>${r.title}</td>
      <td>${r.duration_seconds ?? '—'}</td>
      <td>${r.max_time ?? 0}</td>
      <td>${r.pct == null ? '—' : r.pct + '%'}</td>
    </tr>
  `).join('');

  const csvLink = `/admin/relatorios.csv?` + new URLSearchParams({
    course_id: course_id || '',
    video_id: video_id || '',
    q: q || '',
    dt_from: dt_from || '',
    dt_to: dt_to || ''
  }).toString();

  const html = `
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px">
        <h1>Relatórios (agregado)</h1>
        <div><a href="/aulas">Voltar</a></div>
      </div>

      <form method="GET" action="/admin/relatorios" class="mt2">
        <div class="row">
          <div>
            <label>Curso</label>
            <select name="course_id" onchange="this.form.submit()">${courseOpts}</select>
          </div>
          <div>
            <label>Aula (vídeo)</label>
            <select name="video_id">${videoOpts}</select>
          </div>
        </div>
        <div class="row">
          <div>
            <label>Aluno (nome/email)</label>
            <input name="q" value="${q||''}" placeholder="ex.: maria@ / João">
          </div>
          <div>
            <label>De</label>
            <input name="dt_from" value="${dt_from||''}" placeholder="2025-08-01T00:00:00-03:00">
          </div>
          <div>
            <label>Até</label>
            <input name="dt_to" value="${dt_to||''}" placeholder="2025-08-31T23:59:59-03:00">
          </div>
        </div>
        <button class="mt">Aplicar filtros</button>
        <a class="mt" href="${csvLink}" style="margin-left:12px;display:inline-block">Exportar CSV</a>
        <a class="mt" href="/admin/relatorio/raw" style="margin-left:12px;display:inline-block">Ver eventos brutos</a>
      </form>

      <table>
        <tr><th>Nome</th><th>Email</th><th>Vídeo</th><th>Duração (s)</th><th>Max pos (s)</th><th>% assistido</th></tr>
        ${table || '<tr><td colspan="6" class="mut">Sem dados para os filtros.</td></tr>'}
      </table>
    </div>
  `;
  res.send(renderShell('Relatórios', html));
});

// ====== CSV com os mesmos filtros (separador ;) ======
app.get('/admin/relatorios.csv', authRequired, adminRequired, async (req, res) => {
  const { course_id, video_id, q, dt_from, dt_to } = req.query;
  const where = [];
  const params = [];
  if (course_id) { params.push(course_id); where.push(`v.course_id = $${params.length}`); }
  if (video_id)  { params.push(video_id);  where.push(`v.id = $${params.length}`); }
  if (q)         { params.push(`%${String(q).toLowerCase()}%`); where.push(`(lower(u.full_name) LIKE $${params.length} OR lower(u.email) LIKE $${params.length})`); }
  if (dt_from)   { params.push(dt_from);   where.push(`e.client_ts >= $${params.length}`); }
  if (dt_to)     { params.push(dt_to);     where.push(`e.client_ts <= $${params.length}`); }
  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

  const sql = `
    WITH base AS (
      SELECT u.id AS user_id, u.full_name, u.email,
             v.id AS video_id, v.title, v.duration_seconds,
             MAX(e.video_time) AS max_time
      FROM sessions s
      JOIN events e ON e.session_id = s.id
      JOIN users u  ON u.id = s.user_id
      JOIN videos v ON v.id = s.video_id
      ${whereSql}
      GROUP BY u.id,u.full_name,u.email,v.id,v.title,v.duration_seconds
    )
    SELECT full_name, email, title AS video_title, duration_seconds, max_time,
      CASE
        WHEN duration_seconds IS NULL OR duration_seconds <= 0 THEN NULL
        ELSE ROUND( LEAST(GREATEST(max_time,0), duration_seconds)::numeric * 100.0 / duration_seconds, 1)
      END AS pct
    FROM base
    ORDER BY full_name, video_title
  `;
  const rows = (await pool.query(sql, params)).rows;

  res.setHeader('Content-Type','text/csv; charset=utf-8');
  const header = 'full_name;email;video_title;duration_seconds;max_time;pct\n';
  const body = rows.map(r =>
    `${(r.full_name||'').replace(/;/g,' ')};${r.email};${(r.video_title||'').replace(/;/g,' ')};${r.duration_seconds??''};${r.max_time??0};${r.pct??''}`
  ).join('\n');
  res.send(header + body);
});


// ====== Debug URL assinada ======
app.get('/debug/signed/:id', authRequired, async (req,res)=>{
  const id = parseInt(req.params.id,10);
  const { rows } = await pool.query('SELECT r2_key FROM videos WHERE id=$1',[id]);
  if (!rows[0]) return res.status(404).send('Aula não encontrada');
  const url = generateSignedUrlForKey(rows[0].r2_key);
  res.type('text/plain').send(url || 'ERRO: R2_* ausente');
});

// ====== Admin: Cursos (listar/criar/editar) ======
// Página de gerenciamento do curso: lista vídeos, permite editar várias datas e ordem de uma vez
app.get('/admin/cursos/:id', adminRequired, async (req, res) => {
    const courseId = parseInt(req.params.id, 10);
    try {
      const { rows: cRows } = await pool.query(
        'SELECT id, name, slug, archived FROM courses WHERE id=$1',
        [courseId]
      );
      if (!cRows[0]) {
        return res.send(renderShell('Curso', `<div class="card"><h1>Curso não encontrado</h1><p><a href="/admin/cursos">Voltar</a></p></div>`));
      }
      const curso = cRows[0];
  
      const { rows: videos } = await pool.query(
        `SELECT id, title, r2_key, duration_seconds, available_from, sort_index
           FROM videos
          WHERE course_id = $1
          ORDER BY sort_index NULLS LAST, id ASC`,
        [courseId]
      );
  
      // Converte timestamptz -> formato aceito por <input type="datetime-local"> (YYYY-MM-DDTHH:mm, sem TZ)
      const tsToLocalInput = (ts) => {
        if (!ts) return '';
        const d = new Date(ts);              // interpreta o que veio do banco
        if (isNaN(d)) return '';
        const pad = (n) => String(n).padStart(2,'0');
        const yyyy = d.getFullYear();
        const mm   = pad(d.getMonth()+1);
        const dd   = pad(d.getDate());
        const HH   = pad(d.getHours());
        const MM   = pad(d.getMinutes());
        return `${yyyy}-${mm}-${dd}T${HH}:${MM}`;
      };
  
      const rowsHtml = videos.map((v, idx) => `
        <tr data-row-index="${idx}">
          <td style="white-space:nowrap">
            <button type="button" class="btn-up"   style="background:none;border:0;color:#007bff;cursor:pointer;padding:0">↑</button>
            <button type="button" class="btn-down" style="background:none;border:0;color:#007bff;cursor:pointer;padding:0">↓</button>
          </td>
          <td>${v.id}<input type="hidden" name="video_id[]" value="${v.id}"></td>
          <td>${safe(v.title)}</td>
          <td><code>${safe(v.r2_key)}</code></td>
          <td>${v.duration_seconds ?? '—'}</td>
          <td><input type="datetime-local" name="available_from[]" value="${tsToLocalInput(v.available_from)}"></td>
          <td><input type="number" name="sort_index[]" value="${v.sort_index ?? ''}" min="0" step="1" style="width:90px"></td>
        </tr>
      `).join('');
  
      const html = `
        <div class="card">
          <h1>Gerenciar Curso: ${safe(curso.name)} ${curso.archived ? '<span class="mut">(arquivado)</span>' : ''}</h1>
          <p class="mut">Slug: <code>${safe(curso.slug)}</code></p>
          <p><a href="/admin/cursos">Voltar</a></p>
  
          <form method="POST" action="/admin/cursos/${curso.id}/bulk" id="bulkForm">
            <div class="row">
              <div>
                <label>Intervalo sugerido</label>
                <select id="intervalSelect" name="__interval">
                  <option value="P7D">+7 dias</option>
                  <option value="P15D">+15 dias</option>
                  <option value="P30D">+30 dias</option>
                  <option value="custom">Personalizado…</option>
                </select>
              </div>
              <div id="customDaysWrap" style="display:none">
                <label>Dias (personalizado)</label>
                <input type="number" id="customDays" min="1" step="1" placeholder="ex.: 10">
              </div>
            </div>
  
            <div class="mt2">
              <button type="button" id="btnAutofill">Autopreencher datas a partir da primeira</button>
              <button type="button" id="btnNormalizeOrder">Reindexar ordem 10,20,30…</button>
            </div>
  
            <table class="mt2" id="videosTable">
              <thead>
                <tr>
                  <th>Ordem</th>
                  <th>ID</th>
                  <th>Título</th>
                  <th>R2 key</th>
                  <th>Duração (s)</th>
                  <th>Disponível a partir</th>
                  <th>sort_index</th>
                </tr>
              </thead>
              <tbody>
                ${rowsHtml || '<tr><td colspan="7" class="mut">Nenhum vídeo neste curso.</td></tr>'}
              </tbody>
            </table>
  
            <div class="mt2">
              <button type="submit">Salvar alterações</button>
            </div>
          </form>
        </div>
  
        <script>
          (function(){
            const table = document.getElementById('videosTable').querySelector('tbody');
            const intervalSelect = document.getElementById('intervalSelect');
            const customWrap = document.getElementById('customDaysWrap');
            const customDays = document.getElementById('customDays');
  
            intervalSelect.addEventListener('change', ()=>{
              customWrap.style.display = intervalSelect.value === 'custom' ? '' : 'none';
            });
  
            function swapRows(i, j){
              const rows = Array.from(table.querySelectorAll('tr'));
              if (i < 0 || j < 0 || i >= rows.length || j >= rows.length) return;
              if (i === j) return;
              if (j > i) {
                table.insertBefore(rows[j], rows[i]);
              } else {
                table.insertBefore(rows[i], rows[j]);
              }
            }
  
            table.addEventListener('click', (ev)=>{
              const tr = ev.target.closest('tr');
              if (!tr) return;
              const rows = Array.from(table.querySelectorAll('tr'));
              const idx = rows.indexOf(tr);
  
              if (ev.target.classList.contains('btn-up'))   swapRows(idx, idx-1);
              if (ev.target.classList.contains('btn-down')) swapRows(idx+1, idx);
            });
  
            document.getElementById('btnNormalizeOrder').addEventListener('click', ()=>{
              const rows = Array.from(table.querySelectorAll('tr'));
              let v = 10;
              rows.forEach(tr=>{
                const si = tr.querySelector('input[name="sort_index[]"]');
                if (si) { si.value = v; v += 10; }
              });
            });
  
            document.getElementById('btnAutofill').addEventListener('click', ()=>{
              const rows = Array.from(table.querySelectorAll('tr'));
              if (rows.length === 0) return;
  
              const firstInput = rows[0].querySelector('input[name="available_from[]"]');
              if (!firstInput || !firstInput.value) {
                alert('Preencha a data do primeiro vídeo antes de autopreencher.');
                return;
              }
              let base = new Date(firstInput.value);
              if (isNaN(base.getTime())) { alert('Data inicial inválida.'); return; }
  
              let days = 7;
              const val = intervalSelect.value;
              if (val === 'P7D') days = 7;
              else if (val === 'P15D') days = 15;
              else if (val === 'P30D') days = 30;
              else if (val === 'custom') {
                const n = parseInt(customDays.value,10);
                if (!n || n < 1) { alert('Informe um número de dias válido.'); return; }
                days = n;
              }
  
              let current = new Date(base.getTime());
              for (let i=1;i<rows.length;i++){
                current = new Date(current.getTime());
                current.setDate(current.getDate() + days);
                const inp = rows[i].querySelector('input[name="available_from[]"]');
                if (inp) {
                  const yyyy = current.getFullYear().toString().padStart(4,'0');
                  const mm = (current.getMonth()+1).toString().padStart(2,'0');
                  const dd = current.getDate().toString().padStart(2,'0');
                  const hh = current.getHours().toString().padStart(2,'0');
                  const mi = current.getMinutes().toString().padStart(2,'0');
                  inp.value = \`\${yyyy}-\${mm}-\${dd}T\${hh}:\${mi}\`;
                }
              }
            });
          })();
        </script>
      `;
      res.send(renderShell('Gerenciar Curso', html));
    } catch (err) {
      console.error('ADMIN COURSE MANAGE ERROR', err);
      res.status(500).send(renderShell('Erro', `<div class="card"><h1>Falha ao carregar</h1><p class="mut">${err.message||err}</p></div>`));
    }
  });

 // Salva em lote as datas/ordem do curso
app.post('/admin/cursos/:id/bulk', adminRequired, async (req, res) => {
  const courseId = parseInt(req.params.id, 10);
  try {
    const vids = Array.isArray(req.body['video_id[]']) ? req.body['video_id[]'] :
                 Array.isArray(req.body.video_id)      ? req.body.video_id      : [req.body.video_id];
    const avs  = Array.isArray(req.body['available_from[]']) ? req.body['available_from[]'] :
                 Array.isArray(req.body.available_from)      ? req.body.available_from      : [req.body.available_from];
    const sis  = Array.isArray(req.body['sort_index[]']) ? req.body['sort_index[]'] :
                 Array.isArray(req.body.sort_index)      ? req.body.sort_index      : [req.body.sort_index];

    // normaliza tamanho
    const n = Math.max(vids.length, avs.length, sis.length);

    for (let i = 0; i < n; i++) {
      const vid = parseInt(vids[i], 10);
      if (!vid) continue;

      // trata datetime-local sem TZ -> adiciona -03:00
      const raw = (avs[i] && String(avs[i]).trim()) || null;
      let avail = null;
      if (raw) {
        avail = /Z|[+-]\d{2}:\d{2}$/.test(raw) ? raw : `${raw}-03:00`;
      }

      // sort_index
      const siRaw = (sis[i] !== undefined && sis[i] !== null) ? String(sis[i]).trim() : '';
      const si = siRaw === '' ? null : parseInt(siRaw, 10);

      await pool.query(
        `UPDATE videos
            SET available_from = $1::timestamptz,
                sort_index     = $2
          WHERE id = $3 AND course_id = $4`,
        [avail, isNaN(si) ? null : si, vid, courseId]
      );
    }

    res.redirect(`/admin/cursos/${courseId}`);
  } catch (err) {
    console.error('ADMIN COURSE BULK SAVE ERROR', err);
    res.status(500).send(renderShell('Erro', `<div class="card"><h1>Falha ao salvar</h1><p class="mut">${err.message||err}</p></div>`));
  }
});
  
  
app.get('/admin/cursos', adminRequired, async (req,res)=>{
  try{
    const show = req.query.show || 'active'; // 'active' | 'all' | 'archived'
    let whereSql = '';
    if (show === 'active')      whereSql = 'WHERE archived=false';
    else if (show === 'archived') whereSql = 'WHERE archived=true';
    // 'all' não filtra

    const { rows } = await pool.query(
      `SELECT id,name,slug,enroll_code,start_date,expires_at,archived
         FROM courses
         ${whereSql}
         ORDER BY name ASC`
    );

    const list = rows.map(c => {
      const tag = c.archived ? ' <span class="mut">[ARQUIVADO]</span>' : '';
      const actions = `
  <a href="/admin/cursos/${c.id}/edit">editar</a> · 
  <a href="/admin/cursos/${c.id}">Gerenciar</a> ·
  ${c.archived
    ? `<form style="display:inline" method="POST" action="/admin/cursos/${c.id}/unarchive">
         <button style="background:none;border:0;color:#007bff;cursor:pointer;padding:0;text-decoration:underline">desarquivar</button>
       </form>`
    : `<form style="display:inline" method="POST" action="/admin/cursos/${c.id}/archive">
         <button style="background:none;border:0;color:#007bff;cursor:pointer;padding:0;text-decoration:underline">arquivar</button>
       </form>`
  }
  · <form style="display:inline" method="POST" action="/admin/cursos/${c.id}/delete" onsubmit="return confirm('Apagar curso? Só permitido se não tiver aulas/matrículas.');">
      <button style="background:none;border:0;color:#007bff;cursor:pointer;padding:0;text-decoration:underline">apagar</button>
    </form>
`;

      return `
        <tr>
          <td>${c.id}</td>
          <td>${safe(c.name)}${tag}</td>
          <td><code>${safe(c.slug)}</code></td>
          <td>${safe(c.enroll_code)||'<span class="mut">—</span>'}</td>
          <td>${fmt(c.start_date)||'<span class="mut">—</span>'}</td>
          <td>${fmt(c.expires_at)||'<span class="mut">—</span>'}</td>
          <td>${actions}</td>
        </tr>`;
    }).join('');

    const tabs = `
      <div class="mut" style="margin:8px 0">
        Filtro:
        <a href="/admin/cursos?show=active"${(show==='active')?' style="font-weight:700"':''}>Ativos</a> ·
        <a href="/admin/cursos?show=archived"${(show==='archived')?' style="font-weight:700"':''}>Arquivados</a> ·
        <a href="/admin/cursos?show=all"${(show==='all')?' style="font-weight:700"':''}>Todos</a>
      </div>`;

    const form = `
      <div class="card">
        <h1>Cursos</h1>
        ${tabs}
        <table class="mt2">
          <thead><tr><th>ID</th><th>Nome</th><th>Slug</th><th>Código</th><th>Disponível desde</th><th>Validade</th><th></th></tr></thead>
          <tbody>${list || '<tr><td colspan="7" class="mut">Nenhum curso.</td></tr>'}</tbody>
        </table>

        <h2 class="mt2">Novo curso</h2>
        <form method="POST" action="/admin/cursos" class="mt2">
          <label>Nome</label><input name="name" required>
          <label>Slug</label><input name="slug" required>
          <label>Código (opcional)</label><input name="enroll_code">
          <label>Disponível desde (opcional)</label><input name="start_date" type="datetime-local">
          <label>Validade (opcional)</label><input name="expires_at" type="datetime-local">
          <button class="mt">Criar</button>
        </form>
      </div>`;
    res.send(renderShell('Cursos', form));
  }catch(err){
    console.error('ADMIN COURSES ERROR', err);
    res.status(500).send(renderShell('Erro', `<div class="card"><h1>Falha ao carregar</h1><p class="mut">${err.message||err}</p></div>`));
  }
});

// Arquivar
app.post('/admin/cursos/:id/archive', adminRequired, async (req,res)=>{
  const id = parseInt(req.params.id,10);
  try{
    await pool.query('UPDATE courses SET archived=true WHERE id=$1',[id]);
    res.redirect('/admin/cursos?show=active');
  }catch(err){
    console.error('COURSE ARCHIVE ERROR', err);
    res.status(500).send('Falha ao arquivar');
  }
});

// Desarquivar
app.post('/admin/cursos/:id/unarchive', adminRequired, async (req,res)=>{
  const id = parseInt(req.params.id,10);
  try{
    await pool.query('UPDATE courses SET archived=false WHERE id=$1',[id]);
    res.redirect('/admin/cursos?show=archived');
  }catch(err){
    console.error('COURSE UNARCHIVE ERROR', err);
    res.status(500).send('Falha ao desarquivar');
  }
});

// Apagar (somente se não tiver vídeos nem matrículas)
app.post('/admin/cursos/:id/delete', adminRequired, async (req,res)=>{
  const id = parseInt(req.params.id,10);
  try{
    const { rows:hasV } = await pool.query('SELECT 1 FROM videos WHERE course_id=$1 LIMIT 1',[id]);
    const { rows:hasE } = await pool.query('SELECT 1 FROM enrollments WHERE course_id=$1 LIMIT 1',[id]);
    if (hasV.length || hasE.length){
      return res.status(400).send(renderShell('Não permitido',
        `<div class="card"><h1>Não é possível apagar</h1>
          <p class="mut">O curso ainda possui aulas e/ou matrículas. Remova-as antes.</p>
          <p><a href="/admin/cursos">Voltar</a></p>
        </div>`));
    }
    await pool.query('DELETE FROM courses WHERE id=$1',[id]);
    res.redirect('/admin/cursos?show=all');
  }catch(err){
    console.error('COURSE DELETE ERROR', err);
    res.status(500).send('Falha ao apagar');
  }
});

app.post('/admin/cursos', adminRequired, async (req,res)=>{
  try{
    let { name, slug, enroll_code, start_date, expires_at } = req.body || {};
    if(!name || !slug) return res.status(400).send('Dados obrigatórios');
    if (expires_at && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(expires_at)) expires_at = `${expires_at}:00Z`;
    if (start_date && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(start_date)) start_date = `${start_date}:00Z`;
    await pool.query('INSERT INTO courses(name,slug,enroll_code,start_date,expires_at) VALUES($1,$2,$3,$4,$5)', [name, slug, enroll_code||null, start_date||null, expires_at||null]);
    res.redirect('/admin/cursos');
  }catch(err){
    console.error('ADMIN COURSES CREATE ERROR', err);
    res.status(500).send('Falha ao salvar');
  }
});
app.get('/admin/cursos/:id/edit', adminRequired, async (req,res)=>{
  try{
    const id = parseInt(req.params.id,10);
    const { rows } = await pool.query('SELECT id,name,slug,enroll_code,start_date,expires_at FROM courses WHERE id=$1',[id]);
    const c = rows[0];
    if(!c) return res.status(404).send(renderShell('Editar Curso', `<div class="card"><h1>Curso não encontrado</h1><a href="/admin/cursos">Voltar</a></div>`));
    const body = `
      <div class="card">
        <h1>Editar curso #${c.id}</h1>
        <form method="POST" action="/admin/cursos/${c.id}/edit" class="mt2">
          <label>Nome</label><input name="name" value="${safe(c.name).replace(/"/g,'&quot;')}" required>
          <label>Slug</label><input name="slug" value="${safe(c.slug)}" required>
          <label>Código (opcional)</label><input name="enroll_code" value="${safe(c.enroll_code||'')}">
          <label>Disponível desde (opcional)</label><input name="start_date" type="datetime-local" value="${fmtDTLocal(c.start_date)||''}">
          <label>Validade (opcional)</label><input name="expires_at" type="datetime-local" value="${fmtDTLocal(c.expires_at)||''}">
          <button class="mt">Salvar</button>
          <a href="/admin/cursos" style="margin-left:12px">Cancelar</a>
        </form>
      </div>`;
    res.send(renderShell('Editar Curso', body));
  }catch(err){
    console.error('ADMIN COURSE EDIT GET ERROR', err);
    res.status(500).send('Falha ao carregar');
  }
});
app.post('/admin/cursos/:id/edit', adminRequired, async (req,res)=>{
  try{
    const id = parseInt(req.params.id,10);
    let { name, slug, enroll_code, start_date, expires_at } = req.body || {};
    if(!name || !slug) return res.status(400).send('Dados obrigatórios');
    await pool.query('UPDATE courses SET name=$1, slug=$2, enroll_code=$3, start_date=$4, expires_at=$5 WHERE id=$6',
      [name, slug, enroll_code||null, normalizeDateStr(start_date)||null, normalizeDateStr(expires_at)||null, id]);
    res.redirect('/admin/cursos');
  }catch(err){
    console.error('ADMIN COURSE EDIT POST ERROR', err);
    res.status(500).send('Falha ao salvar');
  }
});

// ====== Admin: Vídeos (listar/criar/editar/apagar) ======
app.get('/admin/videos', adminRequired, async (req,res)=>{
  try{
    const { rows:courses } = await pool.query('SELECT id,name,slug FROM courses WHERE archived=false ORDER BY name ASC');
    const options = courses.map(c=>`<option value="${c.id}">[${safe(c.slug)}] ${safe(c.name)}</option>`).join('');

    const { rows:videos } = await pool.query(`
      SELECT v.id, v.title, v.r2_key, v.duration_seconds, v.available_from,
             c.name AS course_name, c.slug, c.archived
      FROM videos v
      JOIN courses c ON c.id = v.course_id
      ORDER BY v.id DESC`);
    const list = videos.map(v => `
      <tr>
        <td>${v.id}</td>
        <td>${safe(v.title)}</td>
        <td><code>${safe(v.r2_key)}</code></td>
        <td>${v.duration_seconds ?? '-'}</td>
        <td>[${safe(v.slug)}] ${safe(v.course_name)} ${v.archived ? '<span class="mut">(arquivado)</span>' : ''}</td>
        <td>${fmt(v.available_from) || '<span class="mut">—</span>'}</td>
        <td>
          <a href="/aula/${v.id}" target="_blank">ver</a> ·
          <a href="/admin/relatorio/${v.id}">relatório (web)</a> ·
          <a href="/admin/relatorio/${v.id}.csv">CSV</a> ·
          <form method="POST" action="/admin/relatorio/${v.id}/clear" style="display:inline" onsubmit="return confirm('Remover TODOS os eventos e sessões deste vídeo?');">
  <button style="background:none;border:0;padding:0;color:#007bff;cursor:pointer">limpar relatório</button>
</form> ·
          <a href="/admin/videos/${v.id}/edit">editar</a>
        </td>
      </tr>`).join('');

    const body = `
      <div class="card">
        <div class="right" style="justify-content:space-between"><h1>Gerenciar Aulas</h1>
          <div><a href="/aulas">Voltar</a></div>
        </div>
        <h2 class="mt2">Aulas cadastradas</h2>
        <table>
          <thead><tr><th>ID</th><th>Título</th><th>R2 key</th><th>Duração (s)</th><th>Curso</th><th>Disponível a partir</th><th>Ações</th></tr></thead>
          <tbody>${list || '<tr><td colspan="7" class="mut">Nenhuma aula.</td></tr>'}</tbody>
        </table>

        <h2 class="mt2">Cadastrar nova aula</h2>
        <form method="POST" action="/admin/videos" class="mt2">
          <label>Curso</label><select name="course_id" required>${options}</select>
          <label>Título</label><input name="title" required>
          <label>R2 Key</label><input name="r2_key" required placeholder="pasta/arquivo.mp4">
          <label>Duração (segundos) — opcional</label><input name="duration_seconds" type="number" min="1" placeholder="ex.: 4840">
          <label>Disponível a partir de (opcional)</label><input name="available_from" type="datetime-local">
          <button class="mt">Salvar</button>
        </form>
      </div>`;
    res.send(renderShell('Gerenciar Aulas', body));
  }catch(err){
    console.error('ADMIN VIDEOS LIST ERROR', err);
    res.status(500).send(renderShell('Erro', `<div class="card"><h1>Falha ao carregar</h1><p class="mut">${err.message||err}</p></div>`));
  }
});
app.post('/admin/videos', adminRequired, async (req,res)=>{
  try{
    const { title, r2_key, course_id, duration_seconds, available_from } = req.body || {};
    if(!title || !r2_key || !course_id) return res.status(400).send('Dados obrigatórios');
    const dur = duration_seconds ? Math.max(0, parseInt(duration_seconds, 10)) : null;
    await pool.query(
      'INSERT INTO videos(title,r2_key,course_id,duration_seconds,available_from) VALUES($1,$2,$3,$4,$5)',
      [title, r2_key, course_id, dur, normalizeDateStr(available_from)||null]
    );
    res.redirect('/admin/videos');
  }catch(err){
    console.error('ADMIN VIDEOS CREATE ERROR', err);
    res.status(500).send('Falha ao salvar');
  }
});
app.get('/admin/videos/:id/edit', adminRequired, async (req,res)=>{
  try{
    const id = parseInt(req.params.id,10);
    const { rows:vrows } = await pool.query(`
      SELECT v.id, v.title, v.r2_key, v.course_id, v.duration_seconds, v.available_from, c.slug AS course_slug
      FROM videos v JOIN courses c ON c.id = v.course_id
      WHERE v.id=$1`, [id]);
    const v = vrows[0];
    if(!v) return res.status(404).send(renderShell('Editar Aula', `<div class="card"><h1>Aula não encontrada</h1><a href="/admin/videos">Voltar</a></div>`));

    const { rows:courses } = await pool.query('SELECT id,name,slug FROM courses ORDER BY name ASC');
    const options = courses.map(c=>`<option value="${c.id}" ${c.id===v.course_id?'selected':''}>[${safe(c.slug)}] ${safe(c.name)}</option>`).join('');

    const body = `
      <div class="card">
        <h1>Editar Aula #${v.id}</h1>
        <form method="POST" action="/admin/videos/${v.id}/edit" class="mt2">
          <label>Curso</label><select name="course_id" required>${options}</select>
          <label>Título</label><input name="title" value="${safe(v.title).replace(/"/g,'&quot;')}" required>
          <label>R2 Key</label><input name="r2_key" value="${safe(v.r2_key).replace(/"/g,'&quot;')}" required>
          <label>Duração (segundos) — opcional</label>
          <input name="duration_seconds" type="number" min="1" value="${v.duration_seconds ?? ''}">
          <label>Disponível a partir de (opcional)</label>
          <input name="available_from" type="datetime-local" value="${fmtDTLocal(v.available_from)||''}">
          <div class="mt">
            <button>Salvar alterações</button>
            <a href="/admin/videos" style="margin-left:12px">Cancelar</a>
          </div>
        </form>
        <hr class="mt">
        <form method="POST" action="/admin/videos/${v.id}/delete" onsubmit="return confirm('Tem certeza que deseja apagar esta aula? Essa ação não pode ser desfeita.');">
          <button style="background:#b32d2e">Apagar aula</button>
        </form>
      </div>`;
    res.send(renderShell('Editar Aula', body));
  }catch(err){
    console.error('ADMIN VIDEO EDIT GET ERROR', err);
    res.status(500).send(renderShell('Erro', `<div class="card"><h1>Falha ao carregar</h1><p class="mut">${err.message||err}</p></div>`));
  }
});
app.post('/admin/videos/:id/edit', adminRequired, async (req,res)=>{
  try{
    const id = parseInt(req.params.id,10);
    const { title, r2_key, course_id, duration_seconds, available_from } = req.body || {};
    if(!title || !r2_key || !course_id) return res.status(400).send('Dados obrigatórios');
    const dur = duration_seconds ? Math.max(0, parseInt(duration_seconds, 10)) : null;
    await pool.query(
      'UPDATE videos SET title=$1, r2_key=$2, course_id=$3, duration_seconds=$4, available_from=$5 WHERE id=$6',
      [title, r2_key, course_id, dur, normalizeDateStr(available_from)||null, id]
    );
    res.redirect('/admin/videos');
  }catch(err){
    console.error('ADMIN VIDEO EDIT POST ERROR', err);
    res.status(500).send('Falha ao salvar alterações');
  }
});
app.post('/admin/videos/:id/delete', adminRequired, async (req,res)=>{
  try{
    const id = parseInt(req.params.id,10);
    await pool.query('DELETE FROM videos WHERE id=$1', [id]);
    res.redirect('/admin/videos');
  }catch(err){
    console.error('ADMIN VIDEO DELETE ERROR', err);
    res.status(500).send('Falha ao deletar');
  }
});

// ====== Admin: Disponibilidade de Aulas (edição em massa) ======
app.get('/admin/videos/availability', authRequired, adminRequired, async (req,res)=>{
  try{
    const { rows } = await pool.query(`
      SELECT v.id, v.title, v.available_from, c.name AS course_name, c.slug
      FROM videos v LEFT JOIN courses c ON c.id = v.course_id
      ORDER BY c.name, v.title
    `);
    const lines = rows.map(v=>{
      const val = v.available_from ? fmtDTLocal(v.available_from) : '';
      return `<tr>
        <td>${v.id}</td>
        <td>[${safe(v.slug||'–')}] ${safe(v.course_name||'Sem curso')}</td>
        <td>${safe(v.title)}</td>
        <td><input type="datetime-local" name="avail_${v.id}" value="${val}"></td>
      </tr>`;
    }).join('');
    const html = `
      <div class="card">
        <div class="right" style="justify-content:space-between;align-items:center">
          <h1>Disponibilidade de Aulas</h1>
          <div><a href="/aulas">Voltar</a></div>
        </div>
        <form method="POST" action="/admin/videos/availability">
          <table>
            <thead><tr><th>ID</th><th>Curso</th><th>Título</th><th>Disponível a partir de</th></tr></thead>
            <tbody>${lines || '<tr><td colspan="4" class="mut">Nenhuma aula.</td></tr>'}</tbody>
          </table>
          <button class="mt">Salvar alterações</button>
        </form>
        <p class="mut mt">Deixe em branco para liberar imediatamente.</p>
      </div>`;
    res.send(renderShell('Disponibilidade de Aulas', html));
  }catch(err){
    console.error('AVAILABILITY GET ERROR', err);
    res.status(500).send(renderShell('Erro', `<div class="card"><h1>Falha ao carregar</h1><p class="mut">${err.message||err}</p></div>`));
  }
});

app.post('/admin/videos/availability', authRequired, adminRequired, async (req,res)=>{
  try{
    const entries = Object.entries(req.body||{}).filter(([k])=>k.startsWith('avail_'));
    for (const [key, val] of entries){
      const id = parseInt(key.slice('avail_'.length),10);
      if (!id) continue;
      const iso = normalizeDateStr(val);
      await pool.query('UPDATE videos SET available_from=$1 WHERE id=$2', [iso || null, id]);
    }
    res.redirect('/admin/videos/availability');
  }catch(err){
    console.error('AVAILABILITY SAVE ERROR', err);
    res.status(500).send(renderShell('Erro', `<div class="card"><h1>Falha ao salvar</h1><p class="mut">${err.message||err}</p></div>`));
  }
});

// ====== Admin: limpar relatórios (por vídeo) — POST ======
app.post('/admin/relatorio/:videoId/clear', adminRequired, async (req, res) => {
    const videoId = parseInt(req.params.videoId, 10);
    if (!Number.isFinite(videoId)) return res.status(400).send('VideoId inválido');
  
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
  
      // apaga events das sessões do vídeo
      await client.query(
        `DELETE FROM events
           WHERE session_id IN (SELECT id FROM sessions WHERE video_id = $1)`,
        [videoId]
      );
      // apaga as próprias sessões do vídeo
      await client.query(`DELETE FROM sessions WHERE video_id = $1`, [videoId]);
  
      await client.query('COMMIT');
  
      // volta para o relatório web desse vídeo (ou para /admin/videos se preferir)
      res.redirect(`/admin/relatorio/${videoId}`);
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      console.error('ADMIN CLEAR VIDEO ERROR', e);
      res.status(500).send('Falha ao limpar');
    } finally {
      client.release();
    }
  });
  
  // ====== Admin: limpar relatórios (por curso) — POST ======
  app.post('/admin/relatorio/curso/:courseId/clear', adminRequired, async (req, res) => {
    const courseId = parseInt(req.params.courseId, 10);
    if (!Number.isFinite(courseId)) return res.status(400).send('CourseId inválido');
  
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
  
      // apaga events de todas as sessões de todos os vídeos do curso
      await client.query(
        `DELETE FROM events
           WHERE session_id IN (
             SELECT s.id
               FROM sessions s
               JOIN videos v ON v.id = s.video_id
              WHERE v.course_id = $1
           )`,
        [courseId]
      );
      // apaga sessões dos vídeos do curso
      await client.query(
        `DELETE FROM sessions
           WHERE video_id IN (SELECT id FROM videos WHERE course_id = $1)`,
        [courseId]
      );
  
      await client.query('COMMIT');
  
      // redireciona para a listagem de vídeos (ou para /admin/cursos/:id se preferir)
      res.redirect('/admin/videos');
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      console.error('ADMIN CLEAR COURSE ERROR', e);
      res.status(500).send('Falha ao limpar');
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
  
app.post('/admin/alunos', adminRequired, async (req,res)=>{
  try{
    let { full_name, email, password, user_expires_at, course_id, member_expires_at } = req.body || {};
    if(!full_name || !email || !password) return res.status(400).send('Dados obrigatórios');
    email = String(email).trim().toLowerCase();
    if (ALLOWED_EMAIL_DOMAIN && !email.endsWith(`@${ALLOWED_EMAIL_DOMAIN.toLowerCase()}`)) return res.status(400).send('Domínio inválido');
    const userExp = normalizeDateStr(user_expires_at) || SEMESTER_END || null;
    const hash = await bcrypt.hash(password, 10);
    const ins = await pool.query('INSERT INTO users(full_name,email,password_hash,expires_at) VALUES($1,$2,$3,$4) RETURNING id', [full_name,email,hash,userExp]);
    const userId = ins.rows[0].id;
    if (course_id) {
      await pool.query('INSERT INTO course_members(user_id,course_id,role,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT (user_id,course_id) DO UPDATE SET expires_at=EXCLUDED.expires_at',
        [userId, course_id, 'student', normalizeDateStr(member_expires_at) || null]);
    }
    res.redirect('/admin/alunos');
  }catch(err){
    console.error('ADMIN STUDENTS CREATE ERROR', err);
    res.status(500).send('Falha ao criar aluno');
  }
});
// ====== Admin: editar aluno + progresso por aula (compatível com schema atual) ======
app.get('/admin/alunos/:id/edit', adminRequired, async (req,res)=>{
    const id = parseInt(req.params.id,10);
    if(!Number.isFinite(id)) return res.status(400).send('ID inválido');
  
    try{
      // dados do aluno (mantém colunas que você já usa hoje)
      const ures = await pool.query(
        'SELECT id, full_name, email, expires_at FROM users WHERE id=$1',
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
  Nome completo, email, senha, validade
  João Silva,joao@ex.com,Senha123,2025-12-31
  Maria Souza,maria@ex.com,123456,2025-12-30
  
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
              Atualizar <b>e-mail</b> com o do CSV (se mudar; falha caso entre em conflito com outro usuário)
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
  
      // Parser robusto: separa por ; se existir ; na linha, senão por ,; remove aspas externas
      const splitSmart = (line) => {
        // suporta campos entre aspas com vírgula dentro
        const sep = line.includes(';') ? ';' : ',';
        const parts = [];
        let cur = '';
        let inQ = false;
  
        for (let i=0;i<line.length;i++){
          const ch = line[i];
          if (ch === '"') {
            // toggle aspas (dupla aspa "" vira aspas literal)
            if (inQ && line[i+1] === '"') { cur += '"'; i++; }
            else inQ = !inQ;
          } else if (ch === sep && !inQ) {
            parts.push(cur.trim());
            cur = '';
          } else {
            cur += ch;
          }
        }
        parts.push(cur.trim());
  
        while (parts.length < 4) parts.push('');
        return parts.slice(0,4); // [full_name, email, password, expires]
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
        maybeHeader.some(s => ['validade','expires_at','expira','vencimento'].includes(s));
      const workLines = isHeader ? lines.slice(1) : lines;
  
      client = await pool.connect();
      await client.query('BEGIN');
  
      const results = []; // {lineNo, email, action, ok, message}
  
      for (let idx=0; idx<workLines.length; idx++){
        const line = workLines[idx];
        const lineNo = isHeader ? idx+2 : idx+1;
  
        try{
          const [full_name_raw, email_raw, password_raw, userExp_raw] = splitSmart(line);
          const full_name = (full_name_raw || '').trim();
          const emailCsv  = (email_raw  || '').trim().toLowerCase();
          const expiresAt = normalizeDateStr(userExp_raw) || null;
  
          if (!emailCsv) {
            results.push({ lineNo, email:'', action:'skip', ok:false, message:'Linha sem e-mail' });
            continue;
          }
  
          const existing = await client.query('SELECT id, email FROM users WHERE email=$1',[emailCsv]);
          let userId;
          let action = 'create';
  
          if (existing.rows[0]) {
            // ---- já existe: atualização seletiva ----
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
  
            // senha
            if (owPass) {
              const plain = (password_raw && String(password_raw).trim().length)
                ? String(password_raw).trim()
                : crypto.randomBytes(5).toString('base64url');
              const hash = await bcrypt.hash(plain,10);
              await client.query(
                'UPDATE users SET password_hash=$1, temp_password=$2 WHERE id=$3',
                [hash, plain, userId]
              );
            }
  
            // e-mail (se permitido e diferente)
            if (owMail) {
              const newMail = emailCsv; // aqui usamos o mesmo valor do CSV; se quiser permitir “mudar de A para B”, troque a origem
              // Se quiser permitir que a 1ª coluna contenha um novo email, troque para:
              // const newMail = (email_novo_raw || email_raw).toLowerCase();
              if (newMail && newMail !== existing.rows[0].email) {
                // checa conflito
                const conflict = await client.query('SELECT 1 FROM users WHERE email=$1 AND id<>$2',[newMail, userId]);
                if (conflict.rows[0]) throw new Error(`E-mail ${newMail} já usado por outro usuário`);
                await client.query('UPDATE users SET email=$1 WHERE id=$2',[newMail, userId]);
              }
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
  
      // Renderiza relatório da importação
      const okRows  = results.filter(r=>r.ok);
      const badRows = results.filter(r=>!r.ok);
  
      const tableOk = okRows.map(r=>`<tr><td>${r.lineNo}</td><td>${safe(r.email)}</td><td>${r.action}</td><td>OK</td></tr>`).join('');
      const tableBad= badRows.map(r=>`<tr><td>${r.lineNo}</td><td>${safe(r.email)}</td><td>${r.action||'-'}</td><td style="color:#b00">${safe(r.message)}</td></tr>`).join('');
  
      const html = `
        <div class="card">
          <h1>Resultado da importação</h1>
          <p>${okRows.length} linha(s) OK, ${badRows.length} com erro.</p>
  
          ${tableBad ? `
            <h3>Com erro</h3>
            <table><tr><th>Linha</th><th>Email</th><th>Ação</th><th>Erro</th></tr>${tableBad}</table>
          ` : ''}
  
          ${tableOk ? `
            <h3>Sucesso</h3>
            <table><tr><th>Linha</th><th>Email</th><th>Ação</th><th>Status</th></tr>${tableOk}</table>
          ` : ''}
  
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
// ====== Player (admin bypass de matrícula) ======
app.get('/aula/:id', authRequired, async (req,res)=>{
  try{
    const videoId = parseInt(req.params.id,10);
    const { rows:vr } = await pool.query(
      `SELECT v.id, v.title, v.r2_key, v.course_id, v.duration_seconds, v.available_from,
              c.name AS course_name, c.expires_at, c.start_date
       FROM videos v JOIN courses c ON c.id = v.course_id WHERE v.id=$1`, [videoId]
    );
    const v = vr[0];
    if(!v) return res.status(404).send(renderShell('Aula', `<div class="card"><h1>Aula não encontrada</h1><a href="/aulas">Voltar</a></div>`));

    const admin = isAdmin(req);
    if (!admin) {
      if (v.expires_at && new Date(v.expires_at) <= new Date()){
        return res.status(403).send(renderShell('Curso expirado', `<div class="card"><h1>Curso expirado</h1><p class="mut">${safe(v.course_name)} expirou.</p><a href="/aulas">Voltar</a></div>`));
      }
      if (v.start_date && new Date(v.start_date) > new Date()){
        return res.status(403).send(renderShell('Indisponível', `<div class="card"><h1>Aula ainda não liberada</h1><p class="mut">Disponível a partir de ${fmt(v.start_date)}.</p></div>`));
      }
      if (v.available_from && new Date(v.available_from) > new Date()){
        return res.status(403).send(renderShell('Indisponível', `<div class="card"><h1>Aula ainda não liberada</h1><p class="mut">Disponível a partir de ${fmt(v.available_from)}.</p></div>`));
      }
      const { rows:m } = await pool.query('SELECT expires_at FROM course_members WHERE user_id=$1 AND course_id=$2',[req.user.id, v.course_id]);
      const mem = m[0];
      if(!mem) return res.status(403).send(renderShell('Sem matrícula', `<div class="card"><h1>Você não está matriculado em "${safe(v.course_name)}"</h1></div>`));
      if (mem.expires_at && new Date(mem.expires_at) <= new Date()){
        return res.status(403).send(renderShell('Matrícula expirada', `<div class="card"><h1>Matrícula expirada</h1></div>`));
      }
    }

    const signedUrl = generateSignedUrlForKey(v.r2_key);
    const uidForSession = req.user.id; // registra sessão do admin ou aluno
    const ins = await pool.query('INSERT INTO sessions(user_id,video_id) VALUES($1,$2) RETURNING id', [uidForSession, videoId]);
    const sessionId = ins.rows[0].id;
    const wm = (req.user.full_name || req.user.email || '').replace(/</g,'&lt;').replace(/>/g,'&gt;');

    const body = `
      <div class="card">
        <div class="right" style="justify-content:space-between;gap:12px">
          <h1 style="margin:0">${safe(v.title)}</h1>
          <div><a href="/logout">Sair</a></div>
        </div>
        <p class="mut">Curso: ${safe(v.course_name)} ${admin? '· <strong>(ADMIN)</strong>' : ''}</p>
        <div class="video">
          <video id="player" controls playsinline preload="metadata" controlsList="nodownload" oncontextmenu="return false" style="width:100%;height:100%">
            ${signedUrl ? `<source src="${signedUrl}" type="video/mp4" />` : ''}
          </video>
          <div class="wm">${wm}</div>
        </div>
      </div>
      <script>
        (function(){
          const video = document.getElementById('player');
          const sessionId = ${sessionId};
          function send(type){
            fetch('/track',{method:'POST',headers:{'Content-Type':'application/json'},
              body: JSON.stringify({sessionId,type,videoTime:Math.floor(video.currentTime||0),clientTs:new Date().toISOString()})});
          }
          if(!${JSON.stringify(!!signedUrl)}) alert('Vídeo não configurado (R2).');
          video.addEventListener('play',  ()=>send('play'));
          video.addEventListener('pause', ()=>send('pause'));
          video.addEventListener('ended', ()=>send('ended'));
          setInterval(()=>send('progress'), 5000);
          video.addEventListener('loadedmetadata', ()=>{
            const dur = Math.floor(video.duration || 0);
            if (dur > 0) {
              fetch('/api/video-duration', {method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({ videoId: ${videoId}, durationSeconds: dur })}).catch(()=>{});
            }
          });
          video.addEventListener('error', ()=>console.error('HTMLMediaError', video.error));
        })();
      </script>`;
    res.send(renderShell(v.title, body));
  }catch(err){
    console.error('PLAYER ERROR', err);
    res.status(500).send(renderShell('Erro', `<div class="card"><h1>Falha ao abrir player</h1><p class="mut">${err.message||err}</p></div>`));
  }
});

// ====== API: grava duração do vídeo se ainda não houver ======
app.post('/api/video-duration', async (req,res)=>{
  try{
    const { videoId, durationSeconds } = req.body || {};
    const id = parseInt(videoId, 10);
    const dur = Math.max(0, parseInt(durationSeconds || 0, 10));
    if (!id || !dur) return res.status(400).json({error:'parâmetros inválidos'});
    await pool.query(
      'UPDATE videos SET duration_seconds = COALESCE(duration_seconds, $2) WHERE id = $1',
      [id, dur]
    );
    res.json({ok:true});
  }catch(err){
    console.error('VIDEO DURATION ERROR', err);
    res.status(500).json({error:'falha ao gravar duração'});
  }
});

// ====== Relatório CSV (ordenado por nome) ======
app.get('/admin/relatorio/:videoId.csv', adminRequired, async (req,res)=>{
  try{
    const videoId = parseInt(req.params.videoId,10);
    const { rows } = await pool.query(`
      SELECT u.full_name, u.email, s.id as session, e.type, e.video_time, e.client_ts
      FROM events e
      JOIN sessions s ON s.id = e.session_id
      JOIN users u ON u.id = s.user_id
      WHERE s.video_id = $1
      ORDER BY u.full_name NULLS LAST, u.email, e.client_ts`, [videoId]);
    res.setHeader('Content-Type','text/csv; charset=utf-8');
    const header = 'full_name,email,session,type,video_time,client_ts\n';
    const body = rows.map(r=>`${(r.full_name||'').replace(/,/g,' ')},${r.email},${r.session},${r.type},${r.video_time},${r.client_ts?.toISOString?.()||r.client_ts}`).join('\n');
    res.send(header+body);
  }catch(err){
    console.error('REPORT CSV ERROR', err);
    res.status(500).send('Falha ao gerar CSV');
  }
});

// ====== Relatório WEB (% assistido, ordenado por nome) ======
app.get('/admin/relatorio/:videoId', adminRequired, async (req,res)=>{
  try{
    const videoId = parseInt(req.params.videoId,10);
    const page = Math.max(1, parseInt(req.query.page||'1',10));
    const pageSize = 500;
    const offset = (page-1)*pageSize;

    const { rows:vt } = await pool.query(`
      SELECT v.title, v.duration_seconds, c.name AS course_name
      FROM videos v LEFT JOIN courses c ON c.id=v.course_id
      WHERE v.id = $1`, [videoId]);
    if (!vt[0]) return res.status(404).send(renderShell('Relatório', `<div class="card"><h1>Aula não encontrada</h1><p><a href="/aulas">Voltar</a></p></div>`));
    const videoTitle = vt[0].title;
    const courseName = vt[0].course_name || '-';
    const durationSec = vt[0].duration_seconds || null;

    const { rows:summary } = await pool.query(`
      SELECT
        u.full_name,
        u.email,
        COUNT(DISTINCT s.id) AS sessions,
        MIN(s.started_at) AS first_access,
        MAX(e.client_ts) AS last_event,
        MAX(e.video_time) AS max_time_seen,
        SUM(CASE WHEN e.type = 'ended' THEN 1 ELSE 0 END) AS finishes
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      LEFT JOIN events e ON e.session_id = s.id
      WHERE s.video_id = $1
      GROUP BY u.full_name, u.email
      ORDER BY u.full_name NULLS LAST, u.email
    `, [videoId]);

    const { rows:events } = await pool.query(`
      SELECT u.full_name, u.email, s.id AS session, e.type, e.video_time, e.client_ts
      FROM events e
      JOIN sessions s ON s.id = e.session_id
      JOIN users u ON u.id = s.user_id
      WHERE s.video_id = $1
      ORDER BY u.full_name NULLS LAST, u.email, e.client_ts
      LIMIT $2 OFFSET $3
    `, [videoId, pageSize, offset]);

    const { rows:cnt } = await pool.query(`
      SELECT COUNT(*)::int AS n
      FROM events e
      JOIN sessions s ON s.id = e.session_id
      WHERE s.video_id = $1
    `, [videoId]);
    const total = cnt[0]?.n || 0;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));

    const rowsSummary = summary.map(r => {
      let pct = '—';
      if (durationSec && durationSec > 0) {
        const ended = Number(r.finishes||0) > 0;
        const maxSeen = Number(r.max_time_seen||0);
        const calc = ended ? 100 : Math.min(100, Math.round((maxSeen / durationSec) * 100));
        pct = isFinite(calc) ? (calc + '%') : '—';
      }
      return `
        <tr>
          <td>${safe(r.full_name)||'-'}</td>
          <td>${safe(r.email)}</td>
          <td>${r.sessions}</td>
          <td>${fmt(r.first_access)}</td>
          <td>${fmt(r.last_event)}</td>
          <td>${r.max_time_seen ?? 0}s</td>
          <td>${r.finishes}</td>
          <td><strong>${pct}</strong></td>
        </tr>`;
    }).join('');

    const rowsEvents = events.map(r => `
      <tr>
        <td>${safe(r.full_name)||'-'}</td>
        <td>${safe(r.email)}</td>
        <td>${r.session}</td>
        <td>${safe(r.type)}</td>
        <td>${r.video_time ?? 0}</td>
        <td>${fmt(r.client_ts)}</td>
      </tr>`).join('');

    const pager = `
      <div class="mt">
        <span class="mut">Página ${page} de ${totalPages} (${total} eventos)</span><br/>
        ${page>1 ? `<a href="/admin/relatorio/${videoId}?page=${page-1}">« Anterior</a>` : `<span class="mut">« Anterior</span>`}
        &nbsp;|&nbsp;
        ${page<totalPages ? `<a href="/admin/relatorio/${videoId}?page=${page+1}">Próxima »</a>` : `<span class="mut">Próxima »</span>`}
      </div>`;

    const body = `
      <div class="card">
        <div class="right" style="justify-content:space-between;gap:12px">
          <h1 style="margin:0">Relatório — ${safe(videoTitle)}</h1>
          <div>
            <a href="/admin/relatorio/${videoId}.csv">Exportar CSV</a> ·
            <a href="/aulas">Voltar</a>
          </div>
        </div>
        <p class="mut">Curso: ${safe(courseName)} ${durationSec ? `· Duração do vídeo: <code>${durationSec}s</code>` : ''}</p>

        <h2 class="mt2">Resumo por aluno</h2>
        <table>
          <thead>
            <tr>
              <th>Nome</th><th>Email</th><th>Sessões</th>
              <th>1º acesso</th><th>Último evento</th><th>Pico (s)</th><th>Concluiu (vezes)</th>
              <th>% assistido</th>
            </tr>
          </thead>
          <tbody>${rowsSummary || `<tr><td colspan="8" class="mut">Sem dados.</td></tr>`}</tbody>
        </table>

        <h2 class="mt2">Eventos (bruto)</h2>
        <table>
          <thead>
            <tr><th>Nome</th><th>Email</th><th>Sessão</th><th>Tipo</th><th>Tempo (s)</th><th>Carimbo</th></tr>
          </thead>
          <tbody>${rowsEvents || `<tr><td colspan="6" class="mut">Sem eventos nesta página.</td></tr>`}</tbody>
        </table>
        ${pager}
      </div>`;
    res.send(renderShell('Relatório', body));
  }catch(err){
    console.error('ADMIN REPORT WEB ERROR', err);
    res.status(500).send(renderShell('Erro', `<div class="card"><h1>Falha ao gerar relatório</h1><p class="mut">${err.message||err}</p></div>`));
  }
});

// ====== Relatórios com filtros ======
// UI de filtros + tabela com % assistido
app.get('/admin/relatorios', authRequired, adminRequired, async (req, res) => {
  const { course_id, video_id, q, dt_from, dt_to } = req.query;

  // combos de curso e aula
  const courses = (await pool.query(
    'SELECT id, name, slug FROM courses ORDER BY name'
  )).rows;

  let videos = [];
  if (course_id) {
    videos = (await pool.query(
      'SELECT id, title FROM videos WHERE course_id=$1 ORDER BY title', [course_id]
    )).rows;
  }

  // monta SQL dinamicamente (filtra por curso, por vídeo, por aluno e por faixa de datas)
  const params = [];
  const where = [];

  if (course_id) { params.push(course_id); where.push(`v.course_id = $${params.length}`); }
  if (video_id)  { params.push(video_id);  where.push(`v.id = $${params.length}`); }
  if (q) {
    params.push(`%${q.toLowerCase()}%`);
    where.push(`(lower(u.full_name) LIKE $${params.length} OR lower(u.email) LIKE $${params.length})`);
  }
  if (dt_from) { params.push(dt_from); where.push(`e.client_ts >= $${params.length}`); }
  if (dt_to)   { params.push(dt_to);   where.push(`e.client_ts <= $${params.length}`); }

  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

  // agregação por aluno x vídeo, calculando max(video_time) e % assistido
  const sql = `
    WITH base AS (
      SELECT u.id AS user_id, u.full_name, u.email, v.id AS video_id, v.title, v.duration_seconds,
             MAX(e.video_time) AS max_time
      FROM sessions s
      JOIN events e   ON e.session_id = s.id
      JOIN users u    ON u.id = s.user_id
      JOIN videos v   ON v.id = s.video_id
      ${whereSql}
      GROUP BY u.id, u.full_name, u.email, v.id, v.title, v.duration_seconds
    )
    SELECT *,
      CASE
        WHEN duration_seconds IS NULL OR duration_seconds <= 0 THEN NULL
        ELSE ROUND( LEAST(GREATEST(max_time,0), duration_seconds)::numeric * 100.0 / duration_seconds, 1)
      END AS pct
    FROM base
    ORDER BY full_name, title
  `;
  const rows = (await pool.query(sql, params)).rows;

  // HTML da página
  const courseOptions = ['<option value="">(Todos)</option>']
    .concat(courses.map(c => `<option value="${c.id}" ${String(c.id)===String(course_id)?'selected':''}>${c.name}</option>`))
    .join('');
  const videoOptions = ['<option value="">(Todos)</option>']
    .concat(videos.map(v => `<option value="${v.id}" ${String(v.id)===String(video_id)?'selected':''}>${v.title}</option>`))
    .join('');

  const table = rows.map(r => `
    <tr>
      <td>${r.full_name}</td>
      <td>${r.email}</td>
      <td>${r.title}</td>
      <td>${r.duration_seconds ?? '—'}</td>
      <td>${r.max_time ?? 0}</td>
      <td>${r.pct == null ? '—' : (r.pct + '%')}</td>
    </tr>
  `).join('');

  const csvLink = `/admin/relatorios.csv?` + new URLSearchParams({
    course_id: course_id || '',
    video_id: video_id || '',
    q: q || '',
    dt_from: dt_from || '',
    dt_to: dt_to || ''
  }).toString();

  const html = `
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px">
        <h1>Relatórios</h1>
        <div><a href="/aulas">Voltar</a></div>
      </div>

      <form method="GET" action="/admin/relatorios" class="mt2">
        <div class="row">
          <div>
            <label>Curso</label>
            <select name="course_id" onchange="this.form.submit()">${courseOptions}</select>
          </div>
          <div>
            <label>Aula (vídeo)</label>
            <select name="video_id">${videoOptions}</select>
          </div>
        </div>
        <div class="row">
          <div>
            <label>Aluno (nome ou email)</label>
            <input name="q" value="${q||''}" placeholder="ex.: maria@ / João">
          </div>
          <div>
            <label>De (client_ts)</label>
            <input name="dt_from" value="${dt_from||''}" placeholder="2025-08-01T00:00:00-03:00">
          </div>
          <div>
            <label>Até (client_ts)</label>
            <input name="dt_to" value="${dt_to||''}" placeholder="2025-08-31T23:59:59-03:00">
          </div>
        </div>
        <button class="mt">Aplicar filtros</button>
        <a class="mt" href="${csvLink}" style="margin-left:12px;display:inline-block">Exportar CSV</a>
      </form>

      <table>
        <tr>
          <th>Nome</th><th>Email</th><th>Vídeo</th><th>Duração (s)</th><th>Max pos (s)</th><th>% assistido</th>
        </tr>
        ${table || '<tr><td colspan="6" class="mut">Sem dados para os filtros selecionados.</td></tr>'}
      </table>
    </div>
  `;
  res.send(renderShell('Relatórios', html));
});

// CSV com os mesmos filtros (separador ; para Excel BR)
app.get('/admin/relatorios.csv', authRequired, adminRequired, async (req, res) => {
  const { course_id, video_id, q, dt_from, dt_to } = req.query;
  const params = [];
  const where = [];

  if (course_id) { params.push(course_id); where.push(`v.course_id = $${params.length}`); }
  if (video_id)  { params.push(video_id);  where.push(`v.id = $${params.length}`); }
  if (q)         { params.push(`%${String(q).toLowerCase()}%`); where.push(`(lower(u.full_name) LIKE $${params.length} OR lower(u.email) LIKE $${params.length})`); }
  if (dt_from)   { params.push(dt_from); where.push(`e.client_ts >= $${params.length}`); }
  if (dt_to)     { params.push(dt_to);   where.push(`e.client_ts <= $${params.length}`); }

  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

  const sql = `
    WITH base AS (
      SELECT u.id AS user_id, u.full_name, u.email, v.id AS video_id, v.title, v.duration_seconds,
             MAX(e.video_time) AS max_time
      FROM sessions s
      JOIN events e   ON e.session_id = s.id
      JOIN users u    ON u.id = s.user_id
      JOIN videos v   ON v.id = s.video_id
      ${whereSql}
      GROUP BY u.id, u.full_name, u.email, v.id, v.title, v.duration_seconds
    )
    SELECT full_name, email, title AS video_title, duration_seconds, max_time,
      CASE
        WHEN duration_seconds IS NULL OR duration_seconds <= 0 THEN NULL
        ELSE ROUND( LEAST(GREATEST(max_time,0), duration_seconds)::numeric * 100.0 / duration_seconds, 1)
      END AS pct
    FROM base
    ORDER BY full_name, video_title
  `;
  const rows = (await pool.query(sql, params)).rows;

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  const header = 'full_name;email;video_title;duration_seconds;max_time;pct\n';
  const body = rows.map(r =>
    `${(r.full_name||'').replace(/;/g,' ')};${r.email};${(r.video_title||'').replace(/;/g,' ')};${r.duration_seconds??''};${r.max_time??0};${r.pct??''}`
  ).join('\n');
  res.send(header + body);
});


// ====== APIs ======
app.post('/api/login', async (req,res)=>{
  try{
    let { email, password } = req.body || {};
    if(!email || !password) return res.status(400).json({error:'Dados obrigatórios'});

    const e = String(email).trim().toLowerCase();
    if (ALLOWED_EMAIL_DOMAIN && !e.endsWith(`@${ALLOWED_EMAIL_DOMAIN.toLowerCase()}`)) {
      return res.status(400).json({error:`Use seu e-mail institucional (@${ALLOWED_EMAIL_DOMAIN}).`});
    }

    const { rows } = await pool.query('SELECT id,password_hash FROM users WHERE email=$1',[e]);
    const row = rows[0];
    if(!row) return res.status(401).json({error:'Credenciais inválidas'});

    const ok = await bcrypt.compare(password, row.password_hash).catch(()=>false);
    if(!ok) return res.status(401).json({error:'Credenciais inválidas'});

    res.clearCookie('adm'); // reset admin a cada login
    res.cookie('uid', row.id, { httpOnly:true, sameSite:'lax', secure:true, maxAge: 1000*60*60*24*30 });
    res.json({ok:true});
  }catch(err){
    console.error('LOGIN ERROR', err);
    res.status(500).json({error:'Falha ao autenticar'});
  }
});

app.post('/track', async (req,res)=>{
  try{
    const { sessionId, type, videoTime, clientTs } = req.body||{};
    if(!sessionId||!type) return res.status(400).end();
    await pool.query('INSERT INTO events(session_id,type,video_time,client_ts) VALUES($1,$2,$3,$4)',
      [sessionId, type, Math.max(0,parseInt(videoTime||0,10)), clientTs || new Date().toISOString()]);
    res.status(204).end();
  }catch(err){
    console.error('TRACK ERROR', err);
    res.status(500).end();
  }
});

// ====== start ======
process.on('unhandledRejection', (reason) => console.error('UNHANDLED REJECTION', reason));
process.on('uncaughtException',  (err)    => console.error('UNCAUGHT EXCEPTION', err));
app.listen(PORT, ()=> console.log(`Aula Tracker (Postgres) rodando na porta ${PORT}`));
