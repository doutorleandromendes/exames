// Aula Tracker — Express + SQLite (com UI)
// - Login/Registro (nome completo) + expiração opcional
// - /aulas (lista) e /admin/videos (cadastro via ADMIN_SECRET)
// - /aula/:id com URL ASSINADA (R2) + controlsList="nodownload" + bloqueio clique direito + watermark
// - Tracking play/pause/progress/ended
// - Relatório CSV (cabeçalho corrigido)

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
const SEMESTER_END = process.env.SEMESTER_END || null;
const ALLOWED_EMAIL_DOMAIN = process.env.ALLOWED_EMAIL_DOMAIN || null;
const CLASS_CODE = process.env.CLASS_CODE || null;
const ADMIN_SECRET = process.env.ADMIN_SECRET || null;

// R2
const R2_BUCKET = process.env.R2_BUCKET;
const R2_ENDPOINT = process.env.R2_ENDPOINT; // ex: https://xxxxx.r2.cloudflarestorage.com
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY;
const VIDEO_KEY = process.env.VIDEO_KEY || null; // opcional (seed inicial)

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// ====== DB ======
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password_hash TEXT,
    full_name TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS videos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    r2_key TEXT NOT NULL
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

  // Seed: cria "Aula 1" se não houver vídeos e existir VIDEO_KEY
  db.get('SELECT COUNT(*) as c FROM videos', (e,row)=>{
    if(row && row.c===0 && VIDEO_KEY){
      db.run('INSERT INTO videos(title,r2_key) VALUES(?,?)', ['Aula 1', VIDEO_KEY]);
    }
  });
});

// ====== UI helper ======
function renderShell(title, body) {
  return `<!doctype html>
  <html lang="pt-br">
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <title>${title}</title>
    <style>
      :root{--bg:#0b0c10;--card:#15171c;--txt:#e7e9ee;--mut:#a7adbb;--pri:#4f8cff;}
      *{box-sizing:border-box} body{margin:0;font-family:system-ui,Segoe UI,Arial;background:var(--bg);color:var(--txt)}
      .wrap{max-width:960px;margin:40px auto;padding:0 16px}
      .card{background:var(--card);border:1px solid #20242b;border-radius:16px;padding:24px;box-shadow:0 8px 24px rgba(0,0,0,.2)}
      label{display:block;margin:8px 0 4px}
      input{width:100%;padding:12px;border-radius:10px;border:1px solid #2a2f39;background:#0f1116;color:var(--txt)}
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

function parseISO(s){ if(!s) return null; const d = new Date(s); return isFinite(d) ? d : null; }

function authRequired(req, res, next) {
  const uid = req.cookies?.uid;
  if (!uid) return res.redirect('/');
  db.get('SELECT id,email,full_name,expires_at FROM users WHERE id = ?', [uid], (err, user) => {
    if (err || !user) return res.redirect('/');
    const exp = parseISO(user.expires_at);
    if (exp && new Date() > exp) {
      return res.send(renderShell('Acesso expirado',
        `<div class="card"><h1>Acesso expirado</h1><p class="mut">Seu acesso expirou em <b>${exp.toLocaleString('pt-BR')}</b>.</p><a href="/">Voltar</a></div>`));
    }
    req.user = user;
    next();
  });
}

// ====== Signed URL (R2) ======
function generateSignedUrlForKey(key) {
  if (!R2_BUCKET || !R2_ENDPOINT || !R2_ACCESS_KEY_ID || !R2_SECRET_ACCESS_KEY) return null;
  const expiresIn = 60 * 5; // 5 min
  const expiration = Math.floor(Date.now() / 1000) + expiresIn;
  const stringToSign = `GET\n\n\n${expiration}\n/${R2_BUCKET}/${key}`;
  const signature = crypto.createHmac('sha1', R2_SECRET_ACCESS_KEY).update(stringToSign).digest('base64');
  return `${R2_ENDPOINT}/${R2_BUCKET}/${key}?AWSAccessKeyId=${encodeURIComponent(R2_ACCESS_KEY_ID)}&Expires=${expiration}&Signature=${encodeURIComponent(signature)}`;
}

// ====== Páginas ======
app.get('/', (req, res) => {
  const showCode = !!CLASS_CODE;
  const domainMsg = ALLOWED_EMAIL_DOMAIN
    ? `Use seu e-mail institucional (@${ALLOWED_EMAIL_DOMAIN}).`
    : 'Use seu e-mail.';
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
      <div class="card">
        <h2>Registrar</h2>
        <form id="regForm" class="mt2">
          <label>Nome completo</label><input name="fullName" required>
          <label>E-mail</label><input name="email" type="email" required>
          <label>Senha</label><input name="password" type="password" required>
          ${showCode ? '<label>Código da turma</label><input name="classCode" required>' : ''}
          <button class="mt">Criar conta</button>
        </form>
        <p class="mut mt">${domainMsg}</p>
      </div>
    </div>
    <script>
      async function postJSON(url, data){
        const r = await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
        const t = await r.text(); let j; try{ j = JSON.parse(t) }catch{ j = {} }
        if(!r.ok) throw new Error(j.error || t || 'Erro');
        return j;
      }
      document.getElementById('regForm').addEventListener('submit', async (e)=>{
        e.preventDefault();
        const f = new FormData(e.target);
        try {
          await postJSON('/api/register',{
            fullName: f.get('fullName'),
            email: f.get('email'),
            password: f.get('password'),
            classCode: f.get('classCode') || null
          });
          alert('Conta criada. Agora faça login.');
        } catch(err){ alert(err.message); }
      });
      document.getElementById('loginForm').addEventListener('submit', async (e)=>{
        e.preventDefault();
        const f = new FormData(e.target);
        try {
          await postJSON('/api/login',{ email:f.get('email'), password:f.get('password') });
          location.href = '/aulas';
        } catch(err){ alert(err.message); }
      });
    </script>`;
  res.send(renderShell('Acesso', html));
});

app.get('/logout', (req,res)=>{ res.clearCookie('uid'); res.redirect('/'); });

// Lista de aulas
app.get('/aulas', authRequired, (req,res)=>{
  db.all('SELECT id,title FROM videos ORDER BY id DESC', (err,rows)=>{
    if(err) return res.status(500).send('erro');
    const items = rows.map(v=>`<li><a href="/aula/${v.id}">${v.title}</a> — <span class="mut">/aula/${v.id}</span> — <a href="/admin/relatorio/${v.id}.csv">relatório</a></li>`).join('');
    const body = `
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <h1>Aulas</h1>
          <div><a href="/admin/videos">Cadastrar nova</a> · <a href="/logout">Sair</a></div>
        </div>
        <ul>${items || '<li class="mut">Nenhuma aula cadastrada ainda.</li>'}</ul>
      </div>`;
    res.send(renderShell('Aulas', body));
  });
});

// Cadastro de aulas (admin)
app.get('/admin/videos', authRequired, (req,res)=>{
  if(!ADMIN_SECRET) {
    return res.send(renderShell('Cadastro', `<div class="card"><h1>Cadastro de Aulas</h1><p class="mut">Defina ADMIN_SECRET nas variáveis de ambiente do Render.</p></div>`));
  }
  const html = `
    <div class="card">
      <h1>Cadastro de Aulas</h1>
      <form method="POST" action="/admin/videos" class="mt2">
        <label>Título</label><input name="title" required>
        <label>R2 Key (ex.: pasta/arquivo.mp4)</label><input name="r2_key" required>
        <label>ADMIN_SECRET</label><input name="secret" type="password" required>
        <button class="mt">Salvar</button>
      </form>
      <p class="mut mt">A "R2 key" é o caminho do objeto dentro do bucket (não é a URL completa).</p>
    </div>`;
  res.send(renderShell('Cadastro', html));
});

app.post('/admin/videos', authRequired, (req,res)=>{
  const { title, r2_key, secret } = req.body || {};
  if(secret!==ADMIN_SECRET) return res.status(403).send('ADMIN_SECRET inválido');
  db.run('INSERT INTO videos(title,r2_key) VALUES(?,?)',[title,r2_key], (err)=>{
    if(err) return res.status(500).send('Falha ao salvar');
    res.redirect('/aulas');
  });
});

// Player por ID
app.get('/aula/:id', authRequired, (req,res)=>{
  const videoId = parseInt(req.params.id,10);
  db.get('SELECT id,title,r2_key FROM videos WHERE id=?',[videoId], (err, v)=>{
    if(err||!v) return res.status(404).send(renderShell('Aula', `<div class="card"><h1>Aula não encontrada</h1><a href="/aulas">Voltar</a></div>`));
    const signedUrl = generateSignedUrlForKey(v.r2_key);
    db.run('INSERT INTO sessions(user_id,video_id) VALUES(?,?)',[req.user.id, videoId], function(){
      const sessionId = this.lastID;
      const wm = (req.user.full_name || req.user.email || '').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      const body = `
        <div class="card">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:12px">
            <h1 style="margin:0">${v.title}</h1>
            <div><a href="/logout">Sair</a></div>
          </div>
          <p class="mut">Seu progresso é registrado automaticamente.</p>
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
                body:JSON.stringify({sessionId,type,videoTime:Math.floor(video.currentTime||0),clientTs:new Date().toISOString()})});
            }
            if(!${JSON.stringify(!!signedUrl)}){
              alert('Vídeo não configurado (R2_* ausente ou key inválida).');
            }
            video.addEventListener('play', ()=>send('play'));
            video.addEventListener('pause',()=>send('pause'));
            video.addEventListener('ended',()=>send('ended'));
            setInterval(()=>send('progress'),5000);
          })();
        </script>`;
      res.send(renderShell(v.title, body));
    });
  });
});

// ====== Relatório CSV (cabeçalho corrigido) ======
app.get('/admin/relatorio/:videoId.csv', authRequired, (req,res)=>{
  const { videoId } = req.params;
  const sql = `
    SELECT u.full_name, u.email, s.id as session, e.type, e.video_time, e.client_ts
    FROM events e
    JOIN sessions s ON s.id = e.session_id
    JOIN users u ON u.id = s.user_id
    WHERE s.video_id = ?
    ORDER BY u.full_name, u.email, e.client_ts
  `;
  db.all(sql, [videoId], (err, rows)=>{
    if(err) return res.status(500).send('erro');
    res.setHeader('Content-Type','text/csv; charset=utf-8');
    const header = ['full_name','email','session','type','video_time','client_ts'].join(',') + '\n';
    const body = rows.map(r =>
      `${(r.full_name||'').replace(/,/g,' ')},${r.email},${r.session},${r.type},${r.video_time},${r.client_ts}`
    ).join('\n');
    res.send(header+body);
  });
});

// ====== APIs ======
app.post('/api/register', async (req,res)=>{
  try{
    const { fullName, email, password, classCode } = req.body || {};
    if (!fullName || !email || !password) return res.status(400).json({error:'Dados obrigatórios'});
    if (ALLOWED_EMAIL_DOMAIN && !email.toLowerCase().endsWith(`@${ALLOWED_EMAIL_DOMAIN.toLowerCase()}`)) {
      return res.status(400).json({error:`Use seu e-mail institucional (@${ALLOWED_EMAIL_DOMAIN}).`});
    }
    if (CLASS_CODE && classCode !== CLASS_CODE) {
      return res.status(400).json({error:'Código da turma inválido.'});
    }
    const hash = await bcrypt.hash(password, 10);
    const expiresAt = SEMESTER_END || null;
    db.run('INSERT INTO users(full_name,email,password_hash,expires_at) VALUES(?,?,?,?)',[fullName,email,hash,expiresAt], function(err){
      if(err) return res.status(400).json({error:'E-mail já cadastrado'});
      res.json({ok:true});
    });
  }catch{
    res.status(500).json({error:'Falha ao registrar'});
  }
});

app.post('/api/login', (req,res)=>{
  const { email, password } = req.body || {};
  if(!email || !password) return res.status(400).json({error:'Dados obrigatórios'});
  db.get('SELECT id, password_hash FROM users WHERE email=?',[email], async (err,row)=>{
    if(!row) return res.status(401).json({error:'Credenciais inválidas'});
    const ok = await bcrypt.compare(password, row.password_hash);
    if(!ok) return res.status(401).json({error:'Credenciais inválidas'});
    res.cookie('uid', row.id, { httpOnly:true, sameSite:'lax' });
    res.json({ok:true});
  });
});

app.post('/track',(req,res)=>{
  const { sessionId, type, videoTime, clientTs } = req.body||{};
  if(!sessionId||!type) return res.status(400).end();
  db.run('INSERT INTO events(session_id,type,video_time,client_ts) VALUES(?,?,?,?)',
    [sessionId,type,Math.max(0,parseInt(videoTime||0,10)),clientTs||new Date().toISOString()],
    ()=>res.status(204).end());
});

app.listen(PORT, ()=> console.log(`Aula Tracker rodando na porta ${PORT}`));
