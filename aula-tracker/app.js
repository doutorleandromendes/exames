// Aula Tracker — versão completa com Express + SQLite
// Inclui Login/Registro, Player por aula (/aula/:id), Relatório CSV corrigido, Admin para cadastrar aulas
// Gera Signed URLs do R2 para proteger os vídeos (sem botão de download)

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

// R2 configs
const R2_BUCKET = process.env.R2_BUCKET;
const R2_ENDPOINT = process.env.R2_ENDPOINT; // ex: https://xxxx.r2.cloudflarestorage.com
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY;
const VIDEO_KEY = process.env.VIDEO_KEY || null; // opcional (usado no seed inicial)

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

  db.run(`CREATE TABLE IF NOT EXISTS videos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    r2_key TEXT NOT NULL
  )`);

  // Seed inicial se não houver vídeo cadastrado
  db.get('SELECT COUNT(*) as c FROM videos', (e,row)=>{
    if(row && row.c===0 && VIDEO_KEY){
      db.run('INSERT INTO videos(title,r2_key) VALUES(?,?)', ['Aula 1', VIDEO_KEY]);
    }
  });
});

function renderPage(title, body) {
  return `<!doctype html><html lang="pt-br"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width,initial-scale=1" /><title>${title}</title></head><body>${body}</body></html>`;
}

function parseISO(s){ if(!s) return null; const d = new Date(s); return isFinite(d) ? d : null; }

function authRequired(req, res, next) {
  const uid = req.cookies?.uid;
  if (!uid) return res.redirect('/');
  db.get('SELECT expires_at FROM users WHERE id = ?', [uid], (err, user) => {
    if (err || !user) return res.redirect('/');
    const exp = parseISO(user.expires_at);
    if (exp && new Date() > exp) return res.send(renderPage('Expirado','<h1>Acesso expirado</h1>'));
    req.userId = parseInt(uid, 10);
    next();
  });
}

// ====== Signed URL Generator ======
function generateSignedUrlForKey(key) {
  const expiresIn = 60 * 5; // 5 min
  const expiration = Math.floor(Date.now() / 1000) + expiresIn;
  const stringToSign = `GET\n\n\n${expiration}\n/${R2_BUCKET}/${key}`;
  const signature = crypto.createHmac('sha1', R2_SECRET_ACCESS_KEY).update(stringToSign).digest('base64');
  return `${R2_ENDPOINT}/${R2_BUCKET}/${key}?AWSAccessKeyId=${R2_ACCESS_KEY_ID}&Expires=${expiration}&Signature=${encodeURIComponent(signature)}`;
}

// ====== Pages ======
app.get('/', (req, res) => {
  const body = `<h1>Login</h1><form method="POST" action="/api/login"><input name="email"><input type="password" name="password"><button>Entrar</button></form>`;
  res.send(renderPage('Login', body));
});

// Lista de aulas
app.get('/aulas', authRequired, (req,res)=>{
  db.all('SELECT id,title FROM videos ORDER BY id DESC', (err,rows)=>{
    if(err) return res.status(500).send('erro');
    const items = rows.map(v=>`<li><a href="/aula/${v.id}">${v.title}</a> — link: /aula/${v.id} — <a href="/admin/relatorio/${v.id}">relatório</a></li>`).join('');
    res.send(renderPage('Aulas', `<h1>Aulas</h1><ul>${items || '<li>Nenhuma aula.</li>'}</ul><p><a href="/admin/videos">Cadastrar nova</a></p>`));
  });
});

// Player por ID
app.get('/aula/:id', authRequired, (req,res)=>{
  const videoId = parseInt(req.params.id,10);
  db.get('SELECT title, r2_key FROM videos WHERE id=?',[videoId], (err, v)=>{
    if(err||!v) return res.status(404).send('Aula não encontrada');
    const signedUrl = generateSignedUrlForKey(v.r2_key);
    db.run('INSERT INTO sessions(user_id,video_id) VALUES(?,?)',[req.userId, videoId], function(){
      const sessionId = this.lastID;
      const body = `
        <h1>${v.title}</h1>
        <video id="player" controls playsinline preload="metadata" style="width:100%" controlsList="nodownload" oncontextmenu="return false">
          <source src="${signedUrl}" type="video/mp4" />
        </video>
        <script>
          const video=document.getElementById('player');
          const sessionId=${sessionId};
          function send(type){fetch('/track',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sessionId,type,videoTime:Math.floor(video.currentTime),clientTs:new Date().toISOString()})});}
          video.addEventListener('play',()=>send('play'));
          video.addEventListener('pause',()=>send('pause'));
          video.addEventListener('ended',()=>send('ended'));
          setInterval(()=>send('progress'),5000);
        </script>`;
      res.send(renderPage(v.title, body));
    });
  });
});

// Cadastro de aulas (admin)
app.get('/admin/videos', authRequired, (req,res)=>{
  if(!ADMIN_SECRET) return res.status(500).send('ADMIN_SECRET não configurado');
  const html = `
    <h1>Cadastro de Aulas</h1>
    <form method="POST" action="/admin/videos">
      <label>Título</label><input name="title" required>
      <label>R2 Key (ex.: pasta/arquivo.mp4)</label><input name="r2_key" required>
      <label>ADMIN_SECRET</label><input name="secret" type="password" required>
      <button>Salvar</button>
    </form>
    <p><a href="/aulas">Ver lista de aulas</a></p>`;
  res.send(renderPage('Cadastro', html));
});

app.post('/admin/videos', authRequired, (req,res)=>{
  const { title, r2_key, secret } = req.body || {};
  if(secret!==ADMIN_SECRET) return res.status(403).send('ADMIN_SECRET inválido');
  db.run('INSERT INTO videos(title,r2_key) VALUES(?,?)',[title,r2_key], (err)=>{
    if(err) return res.status(500).send('Falha ao salvar');
    res.redirect('/aulas');
  });
});

// ====== Relatório CSV corrigido ======
app.get('/admin/relatorio/:videoId.csv', authRequired, (req,res)=>{
  const { videoId } = req.params;
  const sql = `SELECT u.full_name, u.email, s.id as session, e.type, e.video_time, e.client_ts FROM events e JOIN sessions s ON s.id=e.session_id JOIN users u ON u.id=s.user_id WHERE s.video_id=? ORDER BY u.full_name, u.email, e.client_ts`;
  db.all(sql, [videoId], (err, rows)=>{
    if(err) return res.status(500).send('erro');
    res.setHeader('Content-Type','text/csv; charset=utf-8');
    const header = 'full_name,email,session,type,video_time,client_ts\n';
    const body = rows.map(r=>`${(r.full_name||'').replace(/,/g,' ')},${r.email},${r.session},${r.type},${r.video_time},${r.client_ts}`).join('\n');
    res.send(header+body);
  });
});

// ====== APIs ======
app.post('/api/register', async (req,res)=>{
  const { fullName, email, password } = req.body || {};
  const hash = await bcrypt.hash(password, 10);
  const expiresAt = SEMESTER_END || null;
  db.run('INSERT INTO users(full_name,email,password_hash,expires_at) VALUES(?,?,?,?)',[fullName,email,hash,expiresAt], function(err){
    if(err) return res.status(400).json({error:'E-mail já cadastrado'});
    res.json({ok:true});
  });
});

app.post('/api/login', (req,res)=>{
  const { email, password } = req.body || {};
  db.get('SELECT id,password_hash FROM users WHERE email=?',[email], async (err,row)=>{
    if(!row) return res.status(401).json({error:'Credenciais inválidas'});
    const ok = await bcrypt.compare(password,row.password_hash);
    if(!ok) return res.status(401).json({error:'Credenciais inválidas'});
    res.cookie('uid', row.id, { httpOnly:true });
    res.json({ok:true});
  });
});

app.post('/track',(req,res)=>{
  const { sessionId, type, videoTime, clientTs } = req.body||{};
  if(!sessionId||!type) return res.status(400).end();
  db.run('INSERT INTO events(session_id,type,video_time,client_ts) VALUES(?,?,?,?)',[sessionId,type,videoTime||0,clientTs||null],()=>res.status(204).end());
});

app.listen(PORT, ()=> console.log(`Aula Tracker rodando na porta ${PORT}`));
