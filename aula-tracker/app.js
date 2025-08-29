// Aula Tracker — Multi-cursos com validade por usuário e por matrícula.
// Express + SQLite; Admin cria cursos, cadastra vídeos por curso e importa alunos por CSV.
// Aluno faz login -> vê só aulas dos cursos onde está matriculado e dentro da validade.
// Vídeo servido por URL assinada (Cloudflare R2, SigV4) com controles para dificultar download.
// Relatório CSV por vídeo (nome completo, email, sessão, eventos, tempo, timestamp).

import express from 'express';
import sqlite3 from 'sqlite3';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const db = new sqlite3.Database('db.sqlite');
const PORT = process.env.PORT || 3000;

// ====== CONFIG ======
const SEMESTER_END = process.env.SEMESTER_END || null;                 // ex: 2025-12-20T23:59:59-03:00
const ALLOWED_EMAIL_DOMAIN = process.env.ALLOWED_EMAIL_DOMAIN || null; // ex: universidade.br (opcional)
const ADMIN_SECRET = process.env.ADMIN_SECRET || null;                  // obrigatório

// Cloudflare R2 (S3 compat — SigV4)
const R2_BUCKET = process.env.R2_BUCKET; // ex: aulas-videos
const R2_ENDPOINT = process.env.R2_ENDPOINT; // ex: https://<account>.r2.cloudflarestorage.com
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY;

app.use(bodyParser.json({ limit: '2mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '4mb' }));
app.use(cookieParser());

// ====== DB bootstrap & auto-migrations ======
db.serialize(() => {
  // Base tables
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password_hash TEXT,
    full_name TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    enroll_code TEXT
    -- expires_at adicionado por migração
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS course_members (
    user_id INTEGER NOT NULL,
    course_id INTEGER NOT NULL,
    role TEXT DEFAULT 'student',
    PRIMARY KEY (user_id, course_id)
    -- expires_at adicionado por migração
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS videos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    r2_key TEXT NOT NULL
    -- course_id adicionado por migração
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    video_id INTEGER,
    started_at TEXT DEFAULT (datetime('now'))
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    type TEXT,
    video_time INTEGER,
    client_ts TEXT
  )`);

  // --- auto-migrations: adiciona colunas se faltarem ---
  db.all(`PRAGMA table_info(videos)`, (err, cols) => {
    if (err) return;
    const hasCourseId = (cols || []).some(c => c.name === 'course_id');
    if (!hasCourseId) db.run(`ALTER TABLE videos ADD COLUMN course_id INTEGER`);
  });

  db.all(`PRAGMA table_info(courses)`, (err, cols) => {
    if (err) return;
    const hasExp = (cols || []).some(c => c.name === 'expires_at');
    if (!hasExp) db.run(`ALTER TABLE courses ADD COLUMN expires_at TEXT`);
  });

  db.all(`PRAGMA table_info(course_members)`, (err, cols) => {
    if (err) return;
    const hasExp = (cols || []).some(c => c.name === 'expires_at');
    if (!hasExp) db.run(`ALTER TABLE course_members ADD COLUMN expires_at TEXT`);
  });
});

// ====== Helpers comuns ======
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
      .wrap{max-width:960px;margin:40px auto;padding:0 16px}
      .card{background:var(--card);border:1px solid #20242b;border-radius:16px;padding:24px;box-shadow:0 8px 24px rgba(0,0,0,.2)}
      label{display:block;margin:8px 0 4px}
      input,select,textarea{width:100%;padding:12px;border-radius:10px;border:1px solid #2a2f39;background:#0f1116;color:var(--txt)}
      button{background:var(--pri);color:#fff;border:0;border-radius:12px;padding:12px 16px;cursor:pointer;font-weight:600}
      .row{display:grid;gap:16px;grid-template-columns:1fr 1fr}
      .mt{margin-top:16px}.mt2{margin-top:24px}.mut{color:var(--mut)} a{color:#8fb6ff}
      table{width:100%;border-collapse:collapse} th,td{padding:8px;border-bottom:1px solid #2a2f39;text-align:left}
      .video{position:relative;aspect-ratio:16/9;background:#000;border-radius:16px;overflow:hidden}
      .wm{position:absolute;right:12px;bottom:12px;opacity:.65;background:rgba(0,0,0,.35);padding:6px 10px;border-radius:10px;font-size:12px}
      code,pre{background:#0f1116;border:1px solid #2a2f39;border-radius:8px;padding:2px 6px}
    </style>
  </head>
  <body><div class="wrap">${body}</div></body>
  </html>`;
}
function parseISO(s){ if(!s) return null; const d = new Date(s); return isFinite(d) ? d : null; }
function isAdmin(req){ return req.cookies?.adm === '1'; }
function adminRequired(req,res,next){ if(!ADMIN_SECRET) return res.status(500).send('ADMIN_SECRET não configurado'); if(!isAdmin(req)) return res.redirect('/admin'); next(); }
function authRequired(req,res,next){
  const uid = req.cookies?.uid;
  if(!uid) return res.redirect('/');
  db.get('SELECT id,email,full_name,expires_at FROM users WHERE id=?',[uid], (err,user)=>{
    if(err||!user) return res.redirect('/');
    const exp = parseISO(user.expires_at);
    if(exp && new Date()>exp) return res.send(renderShell('Acesso expirado', `<div class="card"><h1>Acesso expirado</h1><p class="mut">Contate a coordenação.</p><a href="/">Voltar</a></div>`));
    req.user = user; next();
  });
}

// ====== Helpers de curso/matrícula ======
function getCourseBySlug(slug, cb){ db.get('SELECT * FROM courses WHERE slug=?',[slug], cb); }
function listCourses(cb){ db.all('SELECT id,name,slug FROM courses ORDER BY id DESC', cb); }
function ensureMembership(userId, courseId, cb){
  db.run('INSERT OR IGNORE INTO course_members(user_id,course_id,role) VALUES (?,?,?)',
    [userId, courseId, 'student'], cb);
}

// ====== R2 Signed URL (SigV4) ======
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
  const method = 'GET', service='s3', region='auto';
  const host = R2_ENDPOINT.replace(/^https?:\/\//,'').replace(/\/$/,'');
  const canonicalUri = `/${encodeURIComponent(R2_BUCKET)}/${key.split('/').map(encodeURIComponent).join('/')}`;

  const now = new Date();
  const amzdate = now.toISOString().replace(/[:-]|\.\d{3}/g,''); // YYYYMMDDTHHMMSSZ
  const datestamp = amzdate.substring(0,8);
  const credentialScope = `${datestamp}/${region}/${service}/aws4_request`;
  const expires = 600; // 10 min

  const queryParams = [
    ['X-Amz-Algorithm','AWS4-HMAC-SHA256'],
    ['X-Amz-Credential', `${R2_ACCESS_KEY_ID}/${credentialScope}`],
    ['X-Amz-Date', amzdate],
    ['X-Amz-Expires', String(expires)],
    ['X-Amz-SignedHeaders','host']
  ];
  const canonicalQuerystring = queryParams.map(([k,v])=>`${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
  const canonicalHeaders = `host:${host}\n`;
  const signedHeaders = 'host';
  const payloadHash = 'UNSIGNED-PAYLOAD';

  const canonicalRequest = [method, canonicalUri, canonicalQuerystring, canonicalHeaders, signedHeaders, payloadHash].join('\n');
  const stringToSign = ['AWS4-HMAC-SHA256', amzdate, credentialScope, sha256Hex(canonicalRequest)].join('\n');
  const signingKey = getV4SigningKey(R2_SECRET_ACCESS_KEY, datestamp, region, service);
  const signature = crypto.createHmac('sha256', signingKey).update(stringToSign).digest('hex');

  return `${R2_ENDPOINT}${canonicalUri}?${canonicalQuerystring}&X-Amz-Signature=${signature}`;
}

// ====== Normalização de datas do CSV ======
// Aceita: YYYY-MM-DD  -> YYYY-MM-DDT23:59:59-03:00
//         YYYY-MM-DDTHH:MM -> YYYY-MM-DDTHH:MM:00-03:00
//         ISO com Z/offset -> mantém
function normalizeDateStr(s) {
  if (!s) return null;
  s = String(s).trim();
  if (!s) return null;
  if (/[zZ]|[+\-]\d{2}:\d{2}$/.test(s)) return s; // já com timezone
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return `${s}T23:59:59-03:00`;
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(s)) return `${s}:00-03:00`;
  const d = new Date(s);
  return isFinite(d) ? d.toISOString() : null;
}

// ====== Páginas ======
// Home: só login (sem auto-registro)
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

// Admin: entrar/sair modo admin
app.get('/admin', authRequired, (req,res)=>{
  if(!ADMIN_SECRET) return res.send(renderShell('Admin', `<div class="card"><h1>Admin</h1><p class="mut">Defina ADMIN_SECRET no Render.</p></div>`));
  const html = `<div class="card"><h1>Admin</h1>
    <form method="POST" action="/admin">
      <label>ADMIN_SECRET</label><input name="secret" type="password" required>
      <button>Entrar no modo admin</button>
    </form>
    <p class="mut">Após entrar, verá cursos, cadastro de aulas e importação.</p>
  </div>`;
  res.send(renderShell('Admin', html));
});
app.post('/admin', authRequired, (req,res)=>{
  const { secret } = req.body || {};
  if(!ADMIN_SECRET) return res.status(500).send('ADMIN_SECRET não configurado');
  if(secret !== ADMIN_SECRET) return res.status(403).send('ADMIN_SECRET inválido');
  res.cookie('adm','1',{ httpOnly:true, sameSite:'lax' });
  res.redirect('/aulas');
});
app.get('/admin/logout', authRequired, (req,res)=>{ res.clearCookie('adm'); res.redirect('/aulas'); });

// Lista de aulas (apenas cursos onde o aluno é membro e dentro da validade)
app.get('/aulas', authRequired, (req,res)=>{
  const admin = isAdmin(req);
  const slug = (req.query.curso || '').trim();

  const sql = `
    SELECT v.id, v.title, v.course_id, c.name as course_name, c.slug, c.expires_at, cm.expires_at as mem_expires_at
    FROM videos v
    JOIN courses c ON c.id = v.course_id
    JOIN course_members cm ON cm.course_id = v.course_id AND cm.user_id = ?
    WHERE ${slug ? 'c.slug = ? AND ' : ''} 
          (c.expires_at IS NULL OR datetime(c.expires_at) > datetime('now'))
      AND (cm.expires_at IS NULL OR datetime(cm.expires_at) > datetime('now'))
    ORDER BY v.id DESC`;

  const params = slug ? [req.user.id, slug] : [req.user.id];

  db.all(sql, params, (err,rows)=>{
    if(err) return res.status(500).send('erro');

    const items = rows.map(v=>{
      const base = `<li><strong>[${v.course_name}]</strong> <a href="/aula/${v.id}">${v.title}</a> — <span class="mut">/aula/${v.id}</span>`;
      const extra = admin ? ` — <a href="/admin/relatorio/${v.id}.csv">relatório</a>` : '';
      return `${base}${extra}</li>`;
    }).join('');

    const actions = admin
      ? `<a href="/admin/cursos">Cursos</a> · <a href="/admin/videos">Cadastrar aula</a> · <a href="/admin/import">Importar alunos</a> · <a href="/admin/logout">Sair admin</a> · <a href="/logout">Sair</a>`
      : `<a href="/logout">Sair</a>`;

    const body = `
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <h1>Aulas</h1>
          <div>${actions}</div>
        </div>
        <p class="mut">Filtro: ${
          slug ? `<strong>${slug}</strong> · <a href="/aulas">limpar</a>`
               : '(use ?curso=slug, ex: /aulas?curso=infecto-2025-1)'
        }</p>
        <ul>${items || '<li class="mut">Nenhuma aula disponível (pode ter expirado).</li>'}</ul>
      </div>`;
    res.send(renderShell('Aulas', body));
  });
});

// Debug: mostrar URL assinada (teste)
app.get('/debug/signed/:id', authRequired, (req,res)=>{
  const id = parseInt(req.params.id,10);
  db.get('SELECT r2_key FROM videos WHERE id=?',[id],(err,row)=>{
    if(err||!row) return res.status(404).send('Aula não encontrada');
    const url = generateSignedUrlForKey(row.r2_key);
    res.type('text/plain').send(url || 'ERRO: R2_* env vars ausentes');
  });
});

// ====== Admin: cursos ======
app.get('/admin/cursos', adminRequired, (req,res)=>{
  db.all('SELECT id,name,slug,enroll_code,expires_at FROM courses ORDER BY id DESC', (e,rows)=>{
    const list = (rows||[]).map(c => `
      <li>
        <strong>${c.name}</strong>
        — slug: <code>${c.slug}</code>
        ${c.enroll_code?` — código: <code>${c.enroll_code}</code>`:''}
        ${c.expires_at?` — expira: <code>${c.expires_at}</code>`:' — <em>sem validade</em>'}
      </li>`).join('');

    const form = `
      <div class="card">
        <h1>Cursos</h1>
        <ul>${list || '<li class="mut">Nenhum curso.</li>'}</ul>

        <h2 class="mt2">Novo curso</h2>
        <form method="POST" action="/admin/cursos" class="mt2">
          <label>Nome</label><input name="name" required>
          <label>Slug (único, sem espaços)</label><input name="slug" required>
          <label>Código (opcional)</label><input name="enroll_code">
          <label>Validade (opcional)</label><input name="expires_at" type="datetime-local">
          <button class="mt">Criar</button>
        </form>

        <h2 class="mt2">Atualizar validade</h2>
        <form method="POST" action="/admin/cursos/validade" class="mt2">
          <label>Slug do curso</label><input name="slug" required>
          <label>Nova validade</label><input name="expires_at" type="datetime-local">
          <button class="mt">Salvar validade</button>
        </form>
      </div>`;
    res.send(renderShell('Cursos', form));
  });
});
app.post('/admin/cursos', adminRequired, (req,res)=>{
  let { name, slug, enroll_code, expires_at } = req.body || {};
  if(!name || !slug) return res.status(400).send('Dados obrigatórios');
  if (expires_at && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(expires_at)) expires_at = `${expires_at}:00Z`;
  if (!expires_at) expires_at = null;

  db.run('INSERT INTO courses(name,slug,enroll_code,expires_at) VALUES(?,?,?,?)',
    [name, slug, enroll_code||null, expires_at],
    (err)=>{ if(err) return res.status(500).send('Falha ao criar curso (slug único?)'); res.redirect('/admin/cursos'); }
  );
});
app.post('/admin/cursos/validade', adminRequired, (req,res)=>{
  let { slug, expires_at } = req.body || {};
  if(!slug) return res.status(400).send('Slug é obrigatório');
  if (expires_at && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(expires_at)) expires_at = `${expires_at}:00Z`;
  if (!expires_at) expires_at = null;

  db.run('UPDATE courses SET expires_at=? WHERE slug=?', [expires_at, slug], (err)=>{
    if(err) return res.status(500).send('Falha ao atualizar'); res.redirect('/admin/cursos');
  });
});

// ====== Admin: cadastrar vídeo por curso ======
app.get('/admin/videos', adminRequired, (req,res)=>{
  listCourses((e, courses)=>{
    const options = (courses||[]).map(c=>`<option value="${c.id}">[${c.slug}] ${c.name}</option>`).join('');
    const form = `
      <div class="card">
        <h1>Cadastrar Aula</h1>
        <form method="POST" action="/admin/videos" class="mt2">
          <label>Curso</label><select name="course_id" required>${options}</select>
          <label>Título</label><input name="title" required>
          <label>R2 Key (ex.: pasta/arquivo.mp4)</label><input name="r2_key" required>
          <button class="mt">Salvar</button>
        </form>
        <p class="mut mt">A "R2 key" é o caminho do objeto no bucket (sem domínio).</p>
      </div>`;
    res.send(renderShell('Cadastrar Aula', form));
  });
});
app.post('/admin/videos', adminRequired, (req,res)=>{
  const { title, r2_key, course_id } = req.body || {};
  if(!title || !r2_key || !course_id) return res.status(400).send('Dados obrigatórios');
  db.run('INSERT INTO videos(title,r2_key,course_id) VALUES(?,?,?)',[title,r2_key,course_id], (err)=>{
    if(err) return res.status(500).send('Falha ao salvar'); res.redirect('/aulas');
  });
});

// ====== Admin: importador de alunos (CSV) ======
app.get('/admin/import', adminRequired, (req,res)=>{
  const body = `
    <div class="card">
      <h1>Importar alunos (CSV)</h1>
      <p class="mut">Formato: <code>full_name,email,password,course_slug,user_expires_at,member_expires_at</code>.
      <br>Os 2 últimos são opcionais. Datas aceitas:
      <code>YYYY-MM-DD</code> (assume 23:59:59 -03:00),
      <code>YYYY-MM-DDTHH:MM</code> (assume -03:00),
      ou ISO com timezone (ex.: <code>2025-12-20T23:59:59-03:00</code>).</p>
      <form method="POST" action="/admin/import" class="mt2">
        <label>CSV</label>
        <textarea name="csv" rows="12" style="width:100%;font-family:monospace"></textarea>
        <button class="mt">Importar</button>
      </form>
      <p class="mut mt">Senhas armazenadas com hash (bcrypt). O aluno é matriculado no curso indicado; datas de validade são aplicadas.</p>
    </div>`;
  res.send(renderShell('Importar', body));
});
app.post('/admin/import', adminRequired, async (req,res)=>{
  const csv = (req.body?.csv || '').trim();
  if(!csv) return res.status(400).send('CSV vazio');

  const lines = csv.split(/\r?\n/).filter(Boolean);
  const results = [];
  const defaultExpires = SEMESTER_END || null;

  for (const line of lines){
    // parse CSV simples com aspas
    const cols = []; let cur='', inQ=false;
    for(let i=0;i<line.length;i++){
      const ch=line[i];
      if(ch === '"'){ inQ=!inQ; continue; }
      if(ch === ',' && !inQ){ cols.push(cur.trim()); cur=''; continue; }
      cur += ch;
    }
    cols.push(cur.trim());

    let [
      full_name,           // 0
      email,               // 1
      password,            // 2 (pode vir vazio -> geramos)
      course_slug,         // 3
      user_expires_at,     // 4 (opcional) -> users.expires_at
      member_expires_at    // 5 (opcional) -> course_members.expires_at
    ] = cols;

    if(!full_name || !email || !course_slug){
      results.push({email, ok:false, msg:'faltam campos (full_name,email,course_slug)'}); continue;
    }
    if (ALLOWED_EMAIL_DOMAIN && !email.toLowerCase().endsWith(`@${ALLOWED_EMAIL_DOMAIN.toLowerCase()}`)) {
      results.push({email, ok:false, msg:`domínio inválido (exige @${ALLOWED_EMAIL_DOMAIN})`}); continue;
    }

    password = (password && password.length>=3) ? password : ((email.split('@')[0]||'aluno') + '123');
    const userExpISO   = normalizeDateStr(user_expires_at)   || defaultExpires;
    const memberExpISO = normalizeDateStr(member_expires_at) || null;

    // curso
    const course = await new Promise(resolve=>{
      db.get('SELECT * FROM courses WHERE slug=?',[course_slug], (e,c)=>resolve(c||null));
    });
    if(!course){ results.push({email, ok:false, msg:`curso não encontrado: ${course_slug}`}); continue; }

    const hash = await bcrypt.hash(password, 10);

    const existing = await new Promise(resolve=>{
      db.get('SELECT id FROM users WHERE email=?',[email], (e,row)=>resolve(row||null));
    });

    let userId;
    if(!existing){
      userId = await new Promise(resolve=>{
        db.run('INSERT INTO users(full_name,email,password_hash,expires_at) VALUES(?,?,?,?)',
          [full_name,email,hash,userExpISO],
          function(err){ resolve(err ? null : this.lastID); });
      });
      if(!userId){ results.push({email, ok:false, msg:'falha ao criar usuário'}); continue; }
    }else{
      userId = existing.id;
      await new Promise(resolve=>{
        db.run('UPDATE users SET full_name=?, password_hash=?, expires_at=? WHERE id=?',
          [full_name, hash, userExpISO, userId], ()=>resolve());
      });
    }

    await new Promise(resolve=>{
      db.run('INSERT OR IGNORE INTO course_members(user_id,course_id,role) VALUES (?,?,?)',
        [userId, course.id, 'student'], ()=>resolve());
    });
    if (memberExpISO){
      await new Promise(resolve=>{
        db.run('UPDATE course_members SET expires_at=? WHERE user_id=? AND course_id=?',
          [memberExpISO, userId, course.id], ()=>resolve());
      });
    }

    results.push({email, ok:true, msg:`ok (curso: ${course.slug}${memberExpISO?`, matrícula expira ${memberExpISO}`:''}; user exp: ${userExpISO||'—'})`});
  }

  const htmlRows = results.map(r=>`<tr><td>${r.email||'-'}</td><td>${r.ok?'✅':'❌'}</td><td>${r.msg}</td></tr>`).join('');
  const body = `
    <div class="card">
      <h1>Importação concluída</h1>
      <table>
        <thead><tr><th>E-mail</th><th>Status</th><th>Mensagem</th></tr></thead>
        <tbody>${htmlRows}</tbody>
      </table>
      <p class="mt"><a href="/admin/import">Voltar</a> · <a href="/aulas">Aulas</a></p>
    </div>`;
  res.send(renderShell('Importado', body));
});

// ====== Player (checa validade do curso e da matrícula) ======
app.get('/aula/:id', authRequired, (req,res)=>{
  const videoId = parseInt(req.params.id,10);
  db.get(`SELECT v.id, v.title, v.r2_key, v.course_id, c.name as course_name, c.expires_at
          FROM videos v JOIN courses c ON c.id = v.course_id
          WHERE v.id=?`, [videoId], (err, v)=>{
    if(err||!v) {
      return res.status(404).send(renderShell('Aula', `<div class="card"><h1>Aula não encontrada</h1><a href="/aulas">Voltar</a></div>`));
    }
    // validade do curso
    if (v.expires_at && new Date(v.expires_at) <= new Date()){
      return res.status(403).send(
        renderShell('Curso expirado', `<div class="card"><h1>Curso expirado</h1><p class="mut">"${v.course_name}" expirou em <code>${v.expires_at}</code>.</p><a href="/aulas">Voltar</a></div>`)
      );
    }
    // matrícula + validade da matrícula
    db.get('SELECT expires_at FROM course_members WHERE user_id=? AND course_id=?',[req.user.id, v.course_id], (e,m)=>{
      if(e || !m){
        return res.status(403).send(renderShell('Acesso negado', `<div class="card"><h1>Você não está matriculado em "${v.course_name}"</h1></div>`));
      }
      if (m.expires_at && new Date(m.expires_at) <= new Date()){
        return res.status(403).send(renderShell('Matrícula expirada', `<div class="card"><h1>Matrícula expirada</h1><p class="mut">Seu acesso a "${v.course_name}" expirou em <code>${m.expires_at}</code>.</p><a href="/aulas">Voltar</a></div>`));
      }

      const signedUrl = generateSignedUrlForKey(v.r2_key);
      db.run('INSERT INTO sessions(user_id, video_id) VALUES(?,?)',[req.user.id, videoId], function(){
        const sessionId = this.lastID;
        const wm = (req.user.full_name || req.user.email || '').replace(/</g,'&lt;').replace(/>/g,'&gt;');

        const body = `
          <div class="card">
            <div style="display:flex;justify-content:space-between;align-items:center;gap:12px">
              <h1 style="margin:0">${v.title}</h1>
              <div><a href="/logout">Sair</a></div>
            </div>
            <p class="mut">Curso: ${v.course_name} — seu progresso é registrado automaticamente.</p>
            <div class="video">
              <video id="player" controls playsinline preload="metadata" controlsList="nodownload"
                     oncontextmenu="return false" style="width:100%;height:100%">
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
              video.addEventListener('error', ()=>alert('Erro no player (veja Console/Network).'));
            })();
          </script>`;
        res.send(renderShell(v.title, body));
      });
    });
  });
});

// ====== Relatório CSV por vídeo (admin) — vírgulas no nome tratadas ======
app.get('/admin/relatorio/:videoId.csv', adminRequired, (req,res)=>{
  const { videoId } = req.params;
  const sql = `
    SELECT u.full_name, u.email, s.id as session, e.type, e.video_time, e.client_ts
    FROM events e
    JOIN sessions s ON s.id = e.session_id
    JOIN users u ON u.id = s.user_id
    WHERE s.video_id = ?
    ORDER BY u.full_name, u.email, e.client_ts`;
  db.all(sql, [videoId], (err, rows)=>{
    if(err) return res.status(500).send('erro');
    res.setHeader('Content-Type','text/csv; charset=utf-8');
    const header = 'full_name,email,session,type,video_time,client_ts\n';
    // substitui vírgulas do nome por espaço para não quebrar CSV
    const body = rows.map(r=>`${(r.full_name||'').replace(/,/g,' ')},${r.email},${r.session},${r.type},${r.video_time},${r.client_ts}`).join('\n');
    res.send(header+body);
  });
});

// ====== APIs ======
app.post('/api/login', (req,res)=>{
  const { email, password } = req.body || {};
  if(!email || !password) return res.status(400).json({error:'Dados obrigatórios'});

  if (ALLOWED_EMAIL_DOMAIN && !email.toLowerCase().endsWith(`@${ALLOWED_EMAIL_DOMAIN.toLowerCase()}`)) {
    return res.status(400).json({error:`Use seu e-mail institucional (@${ALLOWED_EMAIL_DOMAIN}).`});
  }

  db.get('SELECT id,password_hash FROM users WHERE email=?',[email], async (err,row)=>{
    if(!row) return res.status(401).json({error:'Credenciais inválidas'});
    const ok = await bcrypt.compare(password, row.password_hash);
    if(!ok) return res.status(401).json({error:'Credenciais inválidas'});

    // Sempre entra como aluno por padrão
    res.clearCookie('adm');
    res.cookie('uid', row.id, { httpOnly:true, sameSite:'lax' });
    res.json({ok:true});
  });
});

// rastreamento (play/pause/progress/ended)
app.post('/track',(req,res)=>{
  const { sessionId, type, videoTime, clientTs } = req.body||{};
  if(!sessionId||!type) return res.status(400).end();
  db.run('INSERT INTO events(session_id,type,video_time,client_ts) VALUES(?,?,?,?)',
    [sessionId,type,Math.max(0,parseInt(videoTime||0,10)),clientTs||new Date().toISOString()],
    ()=>res.status(204).end());
});

app.listen(PORT, ()=> console.log(`Aula Tracker rodando na porta ${PORT}`));
