// Aula Tracker — Multi-cursos (sem auto-registro), Express + SQLite
// Fluxo: admin cria cursos, importa alunos por CSV (nome,email,senha,slug do curso), cadastra vídeos por curso.
// Aluno faz login -> vê só as aulas dos cursos onde está matriculado -> assiste com URL R2 assinada (SigV4).
// Relatórios CSV por vídeo. Área admin protegida por ADMIN_SECRET (cookie 'adm').

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
const SEMESTER_END = process.env.SEMESTER_END || null; // ex: 2025-12-20T23:59:59-03:00
const ALLOWED_EMAIL_DOMAIN = process.env.ALLOWED_EMAIL_DOMAIN || null; // ex: universidade.br (opcional)
const ADMIN_SECRET = process.env.ADMIN_SECRET || null; // obrigatório
// Cloudflare R2 (S3 compat, SigV4)
const R2_BUCKET = process.env.R2_BUCKET;
const R2_ENDPOINT = process.env.R2_ENDPOINT; // ex: https://<account>.r2.cloudflarestorage.com
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY;

app.use(bodyParser.json({ limit: '2mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '4mb' }));
app.use(cookieParser());

// ====== DB bootstrap & migrations ======
db.serialize(() => {
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
    enroll_code TEXT,           -- opcional nesse app; importação já matricula
    expires_at TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS course_members (
    user_id INTEGER NOT NULL,
    course_id INTEGER NOT NULL,
    role TEXT DEFAULT 'student', -- 'student' | 'instructor'
    PRIMARY KEY (user_id, course_id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS videos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    r2_key TEXT NOT NULL
    -- course_id será adicionado por migração se ainda não existir
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

  // Migração leve: garantir coluna videos.course_id
  db.all(`PRAGMA table_info(videos)`, (err, cols) => {
    if (err) return;
    const hasCourseId = (cols || []).some(c => c.name === 'course_id');
    if (!hasCourseId) {
      db.run(`ALTER TABLE videos ADD COLUMN course_id INTEGER`, () => {});
    }
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

// ====== Helpers de curso ======
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

// Admin: entrar/ sair modo admin
app.get('/admin', authRequired, (req,res)=>{
  if(!ADMIN_SECRET) return res.send(renderShell('Admin', `<div class="card"><h1>Admin</h1><p class="mut">Defina ADMIN_SECRET no Render.</p></div>`));
  const html = `<div class="card"><h1>Admin</h1>
    <form method="POST" action="/admin">
      <label>ADMIN_SECRET</label><input name="secret" type="password" required>
      <button>Entrar no modo admin</button>
    </form>
    <p class="mut">Após entrar, verá botões de cursos, cadastro de vídeos e importação.</p>
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

// Lista de aulas do(s) curso(s) do aluno (+ filtro ?curso=slug)
app.get('/aulas', authRequired, (req,res)=>{
  const admin = isAdmin(req);
  const slug = (req.query.curso || '').trim();

  const sql = `
    SELECT v.id, v.title, v.course_id, c.name as course_name, c.slug
    FROM videos v
    JOIN courses c ON c.id = v.course_id
    WHERE v.course_id IN (SELECT course_id FROM course_members WHERE user_id=?)
      ${slug ? 'AND c.slug = ?' : ''}
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
        <ul>${items || '<li class="mut">Nenhuma aula disponível para seus cursos.</li>'}</ul>
      </div>`;
    res.send(renderShell('Aulas', body));
  });
});

// Debug: mostrar URL assinada para teste
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
  db.all('SELECT id,name,slug,enroll_code FROM courses ORDER BY id DESC', (e,rows)=>{
    const list = (rows||[]).map(c=>`<li><strong>${c.name}</strong> — slug: <code>${c.slug}</code>${c.enroll_code?` — código: <code>${c.enroll_code}</code>`:''}</li>`).join('');
    const form = `
      <div class="card">
        <h1>Cursos</h1>
        <ul>${list || '<li class="mut">Nenhum curso.</li>'}</ul>
        <h2 class="mt2">Novo curso</h2>
        <form method="POST" action="/admin/cursos" class="mt2">
          <label>Nome</label><input name="name" required>
          <label>Slug (único, sem espaços)</label><input name="slug" required>
          <label>Código (opcional, se for usar auto-matrícula)</label><input name="enroll_code">
          <button class="mt">Criar</button>
        </form>
      </div>`;
    res.send(renderShell('Cursos', form));
  });
});
app.post('/admin/cursos', adminRequired, (req,res)=>{
  const { name, slug, enroll_code } = req.body || {};
  if(!name || !slug) return res.status(400).send('Dados obrigatórios');
  db.run('INSERT INTO courses(name,slug,enroll_code) VALUES(?,?,?)',[name,slug,enroll_code||null], (err)=>{
    if(err) return res.status(500).send('Falha ao criar curso (slug único?)');
    res.redirect('/admin/cursos');
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
    if(err) return res.status(500).send('Falha ao salvar');
    res.redirect('/aulas');
  });
});

// ====== Admin: importador de alunos (CSV) ======
app.get('/admin/import', adminRequired, (req,res)=>{
  const body = `
    <div class="card">
      <h1>Importar alunos (CSV)</h1>
      <p class="mut">Formato: <code>full_name,email,password,course_slug</code> — uma linha por aluno.</p>
      <form method="POST" action="/admin/import" class="mt2">
        <label>CSV</label>
        <textarea name="csv" rows="12" style="width:100%;font-family:monospace"></textarea>
        <button class="mt">Importar</button>
      </form>
      <p class="mut mt">As senhas são armazenadas com hash (bcrypt). Alunos são automaticamente matriculados no curso.</p>
    </div>`;
  res.send(renderShell('Importar', body));
});
app.post('/admin/import', adminRequired, async (req,res)=>{
  const csv = (req.body?.csv || '').trim();
  if(!csv) return res.status(400).send('CSV vazio');

  const lines = csv.split(/\r?\n/).filter(Boolean);
  const results = [];
  const expiresAt = SEMESTER_END || null;

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
    let [full_name, email, password, course_slug] = cols;

    if(!full_name || !email || !course_slug){
      results.push({email, ok:false, msg:'faltam campos (full_name,email,course_slug)'}); continue;
    }
    if (ALLOWED_EMAIL_DOMAIN && !email.toLowerCase().endsWith(`@${ALLOWED_EMAIL_DOMAIN.toLowerCase()}`)) {
      results.push({email, ok:false, msg:`domínio inválido (exige @${ALLOWED_EMAIL_DOMAIN})`}); continue;
    }
    if(!password || password.length<3){
      password = (email.split('@')[0]||'aluno') + '123';
    }

    const course = await new Promise(resolve=>{
      getCourseBySlug(course_slug, (e,c)=>resolve(c||null));
    });
    if(!course){ results.push({email, ok:false, msg:`curso não encontrado: ${course_slug}`}); continue; }

    const hash = await bcrypt.hash(password, 10);

    const user = await new Promise(resolve=>{
      db.get('SELECT id FROM users WHERE email=?',[email], (e,row)=>resolve(row||null));
    });

    let userId;
    if(!user){
      userId = await new Promise(resolve=>{
        db.run('INSERT INTO users(full_name,email,password_hash,expires_at) VALUES(?,?,?,?)',
          [full_name,email,hash,expiresAt],
          function(err){ resolve(err ? null : this.lastID); });
      });
      if(!userId){ results.push({email, ok:false, msg:'falha ao criar usuário'}); continue; }
    }else{
      userId = user.id;
      await new Promise(resolve=>{
        db.run('UPDATE users SET full_name=?, password_hash=?, expires_at=? WHERE id=?',
          [full_name, hash, expiresAt, userId], ()=>resolve());
      });
    }

    await new Promise(resolve=>{ ensureMembership(userId, course.id, ()=>resolve()); });

    results.push({email, ok:true, msg:`ok (curso: ${course.slug})`});
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

// ====== Player (exige matrícula no curso do vídeo) ======
app.get('/aula/:id', authRequired, (req,res)=>{
  const videoId = parseInt(req.params.id,10);
  db.get(`SELECT v.id, v.title, v.r2_key, v.course_id, c.name as course_name
          FROM videos v JOIN courses c ON c.id = v.course_id
          WHERE v.id=?`, [videoId], (err, v)=>{
    if(err||!v) {
      return res.status(404).send(renderShell('Aula', `<div class="card"><h1>Aula não encontrada</h1><a href="/aulas">Voltar</a></div>`));
    }
    db.get('SELECT 1 FROM course_members WHERE user_id=? AND course_id=?',[req.user.id, v.course_id], (e,m)=>{
      if(e || !m){
        return res.status(403).send(renderShell('Acesso negado', `<div class="card"><h1>Você não está matriculado em "${v.course_name}"</h1><p class="mut">Peça a inclusão ou use outro curso.</p></div>`));
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

// ====== Relatório CSV por vídeo (admin) ======
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

// rastreamento
app.post('/track',(req,res)=>{
  const { sessionId, type, videoTime, clientTs } = req.body||{};
  if(!sessionId||!type) return res.status(400).end();
  db.run('INSERT INTO events(session_id,type,video_time,client_ts) VALUES(?,?,?,?)',
    [sessionId,type,Math.max(0,parseInt(videoTime||0,10)),clientTs||new Date().toISOString()],
    ()=>res.status(204).end());
});

app.listen(PORT, ()=> console.log(`Aula Tracker rodando na porta ${PORT}`));
