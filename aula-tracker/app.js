// Aula Tracker — Postgres edition (Render PG)
// Features: multi-cursos + validade por matrícula, import CSV, login com cookie, admin via ADMIN_SECRET,
// player com R2 SigV4 (24h), relatório CSV, migrações automáticas de schema.

import express from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { Pool } from 'pg';

const app = express();
app.set('trust proxy', 1); // necessário no Render p/ cookies secure
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

// ====== HTML ======
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
    </style>
  </head>
  <body><div class="wrap">${body}</div></body>
  </html>`;
}
const parseISO = s => (s ? new Date(s) : null);
const isAdmin = req => req.cookies?.adm === '1';
const adminRequired = (req,res,next)=>{ if(!ADMIN_SECRET) return res.status(500).send('ADMIN_SECRET não configurado'); if(!isAdmin(req)) return res.redirect('/admin'); next(); };
const authRequired = async (req,res,next)=>{
  const uid = req.cookies?.uid;
  if(!uid) return res.redirect('/');
  const { rows } = await pool.query('SELECT id,email,full_name,expires_at FROM users WHERE id=$1',[uid]);
  const user = rows[0];
  if(!user) return res.redirect('/');
  const exp = parseISO(user.expires_at);
  if (exp && new Date() > exp) return res.send(renderShell('Acesso expirado', `<div class="card"><h1>Acesso expirado</h1><a href="/">Voltar</a></div>`));
  req.user = user;
  next();
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
      course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL
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
}
migrate().catch(e=>console.error('migration error', e));

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

// ====== Rotas públicas ======
app.get('/', (req,res)=>{
  const right = `<div class="card"><h2>Acesso</h2><p class="mut">Use o login/senha fornecidos.</p><p class="mut mt"><a href="/admin">Sou admin</a></p></div>`;
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

// ====== Admin (ativação por ADMIN_SECRET) ======
app.get('/admin', authRequired, (req,res)=>{
  if(!ADMIN_SECRET) return res.send(renderShell('Admin', `<div class="card"><h1>Admin</h1><p class="mut">Defina ADMIN_SECRET.</p></div>`));
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
  res.cookie('adm','1',{ httpOnly:true, sameSite:'lax', secure:true, maxAge: 1000*60*60*24 });
  res.redirect('/aulas');
});
app.get('/admin/logout', authRequired, (req,res)=>{ res.clearCookie('adm'); res.redirect('/aulas'); });

// ====== Listagem de aulas (por matrícula válida) ======
app.get('/aulas', authRequired, async (req,res)=>{
  const admin = isAdmin(req);
  const slug = (req.query.curso || '').trim();

  const sql = `
  SELECT v.id, v.title, v.course_id, c.name AS course_name, c.slug
  FROM videos v
  JOIN courses c ON c.id = v.course_id
  JOIN course_members cm ON cm.course_id = v.course_id AND cm.user_id = $1
  WHERE ${slug ? 'c.slug = $2 AND ' : ''} 
        (c.expires_at IS NULL OR c.expires_at > now())
    AND (cm.expires_at IS NULL OR cm.expires_at > now())
  ORDER BY v.id DESC`;

  const params = slug ? [req.user.id, slug] : [req.user.id];
  const { rows } = await pool.query(sql, params);

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
      <p class="mut">Filtro: ${slug ? `<strong>${slug}</strong> · <a href="/aulas">limpar</a>` : '(use ?curso=slug)'}</p>
      <ul>${items || '<li class="mut">Nenhuma aula disponível.</li>'}</ul>
    </div>`;
  res.send(renderShell('Aulas', body));
});

// ====== Debug URL assinada ======
app.get('/debug/signed/:id', authRequired, async (req,res)=>{
  const id = parseInt(req.params.id,10);
  const { rows } = await pool.query('SELECT r2_key FROM videos WHERE id=$1',[id]);
  if (!rows[0]) return res.status(404).send('Aula não encontrada');
  const url = generateSignedUrlForKey(rows[0].r2_key);
  res.type('text/plain').send(url || 'ERRO: R2_* ausente');
});

// ====== Admin: cursos ======
app.get('/admin/cursos', adminRequired, async (req,res)=>{
  const { rows } = await pool.query('SELECT id,name,slug,enroll_code,expires_at FROM courses ORDER BY id DESC');
  const list = rows.map(c=>`
    <li><strong>${c.name}</strong> — slug: <code>${c.slug}</code> ${c.enroll_code?` — código: <code>${c.enroll_code}</code>`:''}
        ${c.expires_at?` — expira: <code>${c.expires_at.toISOString?c.expires_at.toISOString():c.expires_at}</code>`:' — <em>sem validade</em>'}
    </li>`).join('');
  const form = `
    <div class="card">
      <h1>Cursos</h1>
      <ul>${list || '<li class="mut">Nenhum curso.</li>'}</ul>
      <h2 class="mt2">Novo curso</h2>
      <form method="POST" action="/admin/cursos" class="mt2">
        <label>Nome</label><input name="name" required>
        <label>Slug</label><input name="slug" required>
        <label>Código (opcional)</label><input name="enroll_code">
        <label>Validade (opcional)</label><input name="expires_at" type="datetime-local">
        <button class="mt">Criar</button>
      </form>
      <h2 class="mt2">Atualizar validade</h2>
      <form method="POST" action="/admin/cursos/validade" class="mt2">
        <label>Slug</label><input name="slug" required>
        <label>Nova validade</label><input name="expires_at" type="datetime-local">
        <button class="mt">Salvar</button>
      </form>
    </div>`;
  res.send(renderShell('Cursos', form));
});
app.post('/admin/cursos', adminRequired, async (req,res)=>{
  let { name, slug, enroll_code, expires_at } = req.body || {};
  if(!name || !slug) return res.status(400).send('Dados obrigatórios');
  if (expires_at && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(expires_at)) expires_at = `${expires_at}:00Z`;
  await pool.query('INSERT INTO courses(name,slug,enroll_code,expires_at) VALUES($1,$2,$3,$4)', [name, slug, enroll_code||null, expires_at||null]);
  res.redirect('/admin/cursos');
});
app.post('/admin/cursos/validade', adminRequired, async (req,res)=>{
  let { slug, expires_at } = req.body || {};
  if(!slug) return res.status(400).send('Slug obrigatório');
  if (expires_at && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(expires_at)) expires_at = `${expires_at}:00Z`;
  await pool.query('UPDATE courses SET expires_at=$1 WHERE slug=$2', [expires_at||null, slug]);
  res.redirect('/admin/cursos');
});

// ====== Admin: cadastrar vídeo ======
app.get('/admin/videos', adminRequired, async (req,res)=>{
  const { rows:courses } = await pool.query('SELECT id,name,slug FROM courses ORDER BY id DESC');
  const options = courses.map(c=>`<option value="${c.id}">[${c.slug}] ${c.name}</option>`).join('');
  const form = `
    <div class="card">
      <h1>Cadastrar Aula</h1>
      <form method="POST" action="/admin/videos" class="mt2">
        <label>Curso</label><select name="course_id" required>${options}</select>
        <label>Título</label><input name="title" required>
        <label>R2 Key</label><input name="r2_key" required>
        <button class="mt">Salvar</button>
      </form>
    </div>`;
  res.send(renderShell('Cadastrar Aula', form));
});
app.post('/admin/videos', adminRequired, async (req,res)=>{
  const { title, r2_key, course_id } = req.body || {};
  if(!title || !r2_key || !course_id) return res.status(400).send('Dados obrigatórios');
  await pool.query('INSERT INTO videos(title,r2_key,course_id) VALUES($1,$2,$3)', [title, r2_key, course_id]);
  res.redirect('/aulas');
});

// ====== Admin: import CSV ======
app.get('/admin/import', adminRequired, (req,res)=>{
  const body = `
    <div class="card">
      <h1>Importar alunos (CSV)</h1>
      <p class="mut">Formato: <code>full_name,email,password,course_slug,user_expires_at,member_expires_at</code></p>
      <form method="POST" action="/admin/import" class="mt2">
        <label>CSV</label><textarea name="csv" rows="12" style="width:100%;font-family:monospace"></textarea>
        <button class="mt">Importar</button>
      </form>
    </div>`;
  res.send(renderShell('Importar', body));
});
app.post('/admin/import', adminRequired, async (req,res)=>{
  const csv = (req.body?.csv || '').trim();
  if(!csv) return res.status(400).send('CSV vazio');
  const lines = csv.split(/\r?\n/).filter(Boolean);
  const results = [];

  for (const line of lines){
    const cols=[]; let cur='', inQ=false;
    for(let i=0;i<line.length;i++){
      const ch=line[i];
      if(ch === '"'){ inQ=!inQ; continue; }
      if(ch === ',' && !inQ){ cols.push(cur.trim()); cur=''; continue; }
      cur += ch;
    }
    cols.push(cur.trim());

    let [full_name,email,password,course_slug,user_expires_at,member_expires_at] = cols;
    if(!full_name || !email || !course_slug){ results.push({email,ok:false,msg:'faltam campos'}); continue; }

    email = String(email).trim().toLowerCase();
    if(ALLOWED_EMAIL_DOMAIN && !email.endsWith(`@${ALLOWED_EMAIL_DOMAIN.toLowerCase()}`)){ results.push({email,ok:false,msg:'domínio inválido'}); continue; }
    password = (password && password.length>=3) ? password : ((email.split('@')[0]||'aluno') + '123');
    const userExpISO = normalizeDateStr(user_expires_at) || SEMESTER_END || null;
    const memExpISO  = normalizeDateStr(member_expires_at) || null;

    const c = await pool.query('SELECT id,slug FROM courses WHERE slug=$1',[course_slug]);
    if(!c.rows[0]){ results.push({email,ok:false,msg:`curso não encontrado: ${course_slug}`}); continue; }
    const courseId = c.rows[0].id;

    const hash = await bcrypt.hash(password, 10);

    const u = await pool.query('SELECT id FROM users WHERE email=$1',[email]);
    let userId;
    if(!u.rows[0]){
      const ins = await pool.query('INSERT INTO users(full_name,email,password_hash,expires_at) VALUES($1,$2,$3,$4) RETURNING id',
        [full_name,email,hash,userExpISO]);
      userId = ins.rows[0].id;
    }else{
      userId = u.rows[0].id;
      await pool.query('UPDATE users SET full_name=$1, password_hash=$2, expires_at=$3 WHERE id=$4',
        [full_name,hash,userExpISO,userId]);
    }

    await pool.query('INSERT INTO course_members(user_id,course_id,role) VALUES($1,$2,$3) ON CONFLICT (user_id,course_id) DO NOTHING',
      [userId, courseId, 'student']);
    if (memExpISO){
      await pool.query('UPDATE course_members SET expires_at=$1 WHERE user_id=$2 AND course_id=$3',
        [memExpISO, userId, courseId]);
    }

    results.push({email, ok:true, msg:`ok (curso:${course_slug})`});
  }

  const htmlRows = results.map(r=>`<tr><td>${r.email||'-'}</td><td>${r.ok?'✅':'❌'}</td><td>${r.msg}</td></tr>`).join('');
  res.send(renderShell('Importado', `<div class="card"><h1>Importação</h1><table><thead><tr><th>Email</th><th>OK</th><th>Mensagem</th></tr></thead><tbody>${htmlRows}</tbody></table><p class="mt"><a href="/aulas">Aulas</a></p></div>`));
});

// ====== Player ======
app.get('/aula/:id', authRequired, async (req,res)=>{
  const videoId = parseInt(req.params.id,10);
  const { rows:vr } = await pool.query(
    `SELECT v.id, v.title, v.r2_key, v.course_id, c.name AS course_name, c.expires_at
     FROM videos v JOIN courses c ON c.id = v.course_id WHERE v.id=$1`, [videoId]
  );
  const v = vr[0];
  if(!v) return res.status(404).send(renderShell('Aula', `<div class="card"><h1>Aula não encontrada</h1><a href="/aulas">Voltar</a></div>`));

  if (v.expires_at && new Date(v.expires_at) <= new Date()){
    return res.status(403).send(renderShell('Curso expirado', `<div class="card"><h1>Curso expirado</h1><p class="mut">${v.course_name} expirou.</p><a href="/aulas">Voltar</a></div>`));
  }
  const { rows:m } = await pool.query('SELECT expires_at FROM course_members WHERE user_id=$1 AND course_id=$2',[req.user.id, v.course_id]);
  const mem = m[0];
  if(!mem) return res.status(403).send(renderShell('Sem matrícula', `<div class="card"><h1>Você não está matriculado em "${v.course_name}"</h1></div>`));
  if (mem.expires_at && new Date(mem.expires_at) <= new Date()){
    return res.status(403).send(renderShell('Matrícula expirada', `<div class="card"><h1>Matrícula expirada</h1></div>`));
  }

  const signedUrl = generateSignedUrlForKey(v.r2_key);
  const ins = await pool.query('INSERT INTO sessions(user_id,video_id) VALUES($1,$2) RETURNING id', [req.user.id, videoId]);
  const sessionId = ins.rows[0].id;
  const wm = (req.user.full_name || req.user.email || '').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const body = `
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px">
        <h1 style="margin:0">${v.title}</h1>
        <div><a href="/logout">Sair</a></div>
      </div>
      <p class="mut">Curso: ${v.course_name}</p>
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
        video.addEventListener('error', ()=>console.error('HTMLMediaError', video.error));
      })();
    </script>`;
  res.send(renderShell(v.title, body));
});

// ====== Relatório CSV ======
app.get('/admin/relatorio/:videoId.csv', adminRequired, async (req,res)=>{
  const videoId = parseInt(req.params.videoId,10);
  const { rows } = await pool.query(`
    SELECT u.full_name, u.email, s.id as session, e.type, e.video_time, e.client_ts
    FROM events e
    JOIN sessions s ON s.id = e.session_id
    JOIN users u ON u.id = s.user_id
    WHERE s.video_id = $1
    ORDER BY u.full_name, u.email, e.client_ts`, [videoId]);
  res.setHeader('Content-Type','text/csv; charset=utf-8');
  const header = 'full_name,email,session,type,video_time,client_ts\n';
  const body = rows.map(r=>`${(r.full_name||'').replace(/,/g,' ')},${r.email},${r.session},${r.type},${r.video_time},${r.client_ts?.toISOString?.()||r.client_ts}`).join('\n');
  res.send(header+body);
});

// ====== APIs ======
app.post('/api/login', async (req,res)=>{
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
  res.clearCookie('adm');
  res.cookie('uid', row.id, { httpOnly:true, sameSite:'lax', secure:true, maxAge: 1000*60*60*24*30 });
  res.json({ok:true});
});

// track
app.post('/track', async (req,res)=>{
  const { sessionId, type, videoTime, clientTs } = req.body||{};
  if(!sessionId||!type) return res.status(400).end();
  await pool.query('INSERT INTO events(session_id,type,video_time,client_ts) VALUES($1,$2,$3,$4)',
    [sessionId, type, Math.max(0,parseInt(videoTime||0,10)), clientTs || new Date().toISOString()]);
  res.status(204).end();
});

// ====== BOOTSTRAP (temporário) ======
app.get('/bootstrap', (req,res)=>{
  if (!ADMIN_SECRET) return res.status(500).send('ADMIN_SECRET não configurado');
  const html = `
  <div style="font-family:system-ui;max-width:720px;margin:40px auto">
    <h1>Bootstrap</h1>
    <p class="mut">Use só para criar o primeiro usuário. Depois remova esta rota.</p>
    <h2>Criar usuário</h2>
    <form method="POST" action="/bootstrap/create" style="border:1px solid #2a2f39;padding:12px;border-radius:8px">
      <p><label>ADMIN_SECRET</label><br><input name="admin_secret" required></p>
      <p><label>Nome completo</label><br><input name="full_name" required></p>
      <p><label>Email</label><br><input name="email" type="email" required></p>
      <p><label>Senha</label><br><input name="password" type="password" required></p>
      <button>Criar usuário</button>
    </form>
    <h2 style="margin-top:24px">Entrar como admin</h2>
    <form method="POST" action="/bootstrap/login-admin" style="border:1px solid #2a2f39;padding:12px;border-radius:8px">
      <p><label>ADMIN_SECRET</label><br><input name="admin_secret" required></p>
      <p><label>Email do usuário</label><br><input name="email" type="email" required></p>
      <button>Logar e ativar admin</button>
    </form>
  </div>`;
  res.send(html);
});
app.post('/bootstrap/create', async (req,res)=>{
  const { admin_secret, full_name, email, password } = req.body || {};
  if (admin_secret !== ADMIN_SECRET) return res.status(403).send('ADMIN_SECRET inválido');
  const e = String(email||'').trim().toLowerCase();
  const hash = await bcrypt.hash(String(password||''), 10);
  try{
    await pool.query('INSERT INTO users(full_name,email,password_hash) VALUES($1,$2,$3)', [full_name||'', e, hash]);
    res.send('<p>Usuário criado. <a href="/bootstrap">Voltar</a> | <a href="/">Ir ao login</a></p>');
  }catch(err){ res.status(400).send('Falha ao criar: '+err.message); }
});
app.post('/bootstrap/login-admin', async (req,res)=>{
  const { admin_secret, email } = req.body || {};
  if (admin_secret !== ADMIN_SECRET) return res.status(403).send('ADMIN_SECRET inválido');
  const e = String(email||'').trim().toLowerCase();
  const { rows } = await pool.query('SELECT id FROM users WHERE email=$1',[e]);
  if(!rows[0]) return res.status(404).send('Usuário não encontrado');
  res.cookie('uid', rows[0].id, { httpOnly:true, sameSite:'lax', secure:true, maxAge: 1000*60*60*24*30 });
  res.cookie('adm', '1', { httpOnly:true, sameSite:'lax', secure:true, maxAge: 1000*60*60*24 });
  res.redirect('/aulas');
});

// ====== start ======
app.listen(PORT, ()=> console.log(`Aula Tracker (Postgres) rodando na porta ${PORT}`));
