// Aula Tracker — app único (Express + SQLite) com páginas de Login/Registro, Player, Relatório
// Agora com: expiração por semestre, filtro de e-mail institucional, código de turma, e NOME COMPLETO no relatório.
// Variáveis necessárias no Render: VIDEO_URL, SEMESTER_END, (opcionais) ALLOWED_EMAIL_DOMAIN, CLASS_CODE, ADMIN_SECRET

import express from 'express';
import sqlite3 from 'sqlite3';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const db = new sqlite3.Database('db.sqlite');
const PORT = process.env.PORT || 3000;

// ====== CONFIG ======
const VIDEO_URL = process.env.VIDEO_URL || 'https://example.com/aula-123.mp4'; // link público do MP4/HLS
const SEMESTER_END = process.env.SEMESTER_END || null; // Ex: "2025-12-20T23:59:59-03:00"
const ALLOWED_EMAIL_DOMAIN = process.env.ALLOWED_EMAIL_DOMAIN || null; // Ex: "suauniversidade.br"
const CLASS_CODE = process.env.CLASS_CODE || null; // Ex: "INFECTO2025"
const ADMIN_SECRET = process.env.ADMIN_SECRET || null; // para rotas admin opcionais

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// ====== DB: tabelas ======
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
    title TEXT,
    duration INTEGER
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

  // Migrações leves
  db.all(`PRAGMA table_info(users)`, (err, cols) => {
    if (cols && !cols.some(c => c.name === 'expires_at')) {
      db.run(`ALTER TABLE users ADD COLUMN expires_at TEXT`, () => console.log('users.expires_at adicionada'));
    }
    if (cols && !cols.some(c => c.name === 'full_name')) {
      db.run(`ALTER TABLE users ADD COLUMN full_name TEXT`, () => console.log('users.full_name adicionada'));
    }
  });

  // Semente de um vídeo (id=1)
  db.get('SELECT COUNT(*) as c FROM videos', (err, row) => {
    if (!row || row.c === 0) {
      db.run('INSERT INTO videos(title, duration) VALUES(?,?)', ['Aula de Exemplo', null]);
    }
  });
});

// ====== Helpers ======
function renderPage(title, body) {
  const domainMsg = ALLOWED_EMAIL_DOMAIN ? `Use seu e-mail institucional (@${ALLOWED_EMAIL_DOMAIN}).` : 'Use seu e-mail.';
  const codeMsg = CLASS_CODE ? `Informe também o código da turma: <strong>${CLASS_CODE}</strong>.` : '';
  return `<!doctype html>
  <html lang="pt-br"><head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>${title}</title>
    <style>
      :root{--bg:#0b0c10;--card:#15171c;--txt:#e7e9ee;--mut:#a7adbb;--pri:#4f8cff;}
      *{box-sizing:border-box} body{margin:0;font-family:system-ui,Segoe UI,Arial;background:var(--bg);color:var(--txt)}
      .wrap{max-width:940px;margin:40px auto;padding:0 16px}
      .card{background:var(--card);border:1px solid #20242b;border-radius:16px;padding:24px;box-shadow:0 8px 24px rgba(0,0,0,.2)}
      h1,h2{margin:0 0 12px} p{color:var(--mut)} label{display:block;margin:8px 0 4px}
      input{width:100%;padding:12px;border-radius:10px;border:1px solid #2a2f39;background:#0f1116;color:var(--txt)}
      button{background:var(--pri);color:#fff;border:0;border-radius:12px;padding:12px 16px;cursor:pointer;font-weight:600}
      .row{display:grid;gap:16px;grid-template-columns:1fr 1fr}
      .mt{margin-top:16px} .mt2{margin-top:24px} .mut{color:var(--mut)} a{color:#8fb6ff}
      table{width:100%;border-collapse:collapse;margin-top:16px} th,td{padding:8px;border-bottom:1px solid #2a2f39;text-align:left}
      .video{aspect-ratio:16/9;background:#000;border-radius:16px;overflow:hidden}
    </style>
  </head><body><div class="wrap">${body}
    <p class="mut" style="margin-top:16px">${domainMsg} ${codeMsg}</p>
  </div></body></html>`;
}

function parseISO(s){ if(!s) return null; const d = new Date(s); return isFinite(d) ? d : null; }

function authRequired(req, res, next) {
  const uid = req.cookies?.uid;
  if (!uid) return res.redirect('/?next=' + encodeURIComponent(req.originalUrl));
  db.get('SELECT expires_at FROM users WHERE id = ?', [uid], (err, user) => {
    if (err || !user) return res.redirect('/');
    const exp = parseISO(user.expires_at);
    if (exp && new Date() > exp) {
      const html = `
        <div class="card">
          <h1>Acesso expirado</h1>
          <p class="mut">O acesso a esta disciplina expirou em <strong>${exp.toLocaleString('pt-BR')}</strong>.</p>
          <a href="/" style="display:inline-block;margin-top:12px">Voltar</a>
        </div>`;
      return res.send(renderPage('Acesso expirado', html));
    }
    req.userId = parseInt(uid, 10);
    next();
  });
}

// ====== Páginas ======
app.get('/', (req, res) => {
  const nextUrl = req.query.next || '/aula/1';
  const showCodeField = !!CLASS_CODE;
  const body = `
  <div class="row">
    <div class="card">
      <h1>Entrar</h1>
      <p class="mut">Após entrar, você terá acesso à aula e seu progresso será registrado.</p>
      <form id="loginForm" class="mt2">
        <input type="hidden" name="next" value="${nextUrl}">
        <label>E-mail</label>
        <input name="email" type="email" required>
        <label>Senha</label>
        <input name="password" type="password" required>
        <button class="mt">Entrar</button>
      </form>
    </div>
    <div class="card">
      <h2>Registrar</h2>
      <form id="regForm" class="mt2">
        <label>Nome completo</label>
        <input name="fullName" type="text" required>
        <label>E-mail</label>
        <input name="email" type="email" required>
        <label>Senha</label>
        <input name="password" type="password" required>
        ${showCodeField ? '<label>Código da turma</label><input name="classCode" type="text" required>' : ''}
        <button class="mt">Criar conta</button>
      </form>
    </div>
  </div>
  <script>
    async function postJSON(url, data){
      const r = await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
      const text = await r.text(); let j; try{ j = JSON.parse(text); }catch{ j = {}; }
      if(!r.ok){ throw new Error(j.error || text || 'Erro'); }
      return j;
    }
    document.getElementById('regForm').addEventListener('submit', async (e)=>{
      e.preventDefault();
      const f = new FormData(e.target);
      try {
        await postJSON('/api/register',{ fullName:f.get('fullName'), email:f.get('email'), password:f.get('password'), classCode:f.get('classCode')||null });
        alert('Conta criada. Agora faça login.');
      } catch(err){ alert(err.message); }
    });
    document.getElementById('loginForm').addEventListener('submit', async (e)=>{
      e.preventDefault();
      const f = new FormData(e.target);
      try {
        await postJSON('/api/login',{ email:f.get('email'), password:f.get('password') });
        const next = f.get('next')||'/aula/1';
        location.href = next;
      } catch(err){ alert(err.message); }
    });
  </script>`;
  res.send(renderPage('Acesso à Aula', body));
});

app.get('/logout', (req,res)=>{ res.clearCookie('uid'); res.redirect('/'); });

app.get('/aula/:videoId', authRequired, (req,res)=>{
  const { videoId } = req.params;
  db.run('INSERT INTO sessions(user_id, video_id) VALUES(?,?)',[req.userId, videoId], function(){
    const sessionId = this.lastID;
    const body = `
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px">
        <h1 style="margin:0">Aula</h1>
        <div><a href="/logout">Sair</a></div>
      </div>
      <p class="mut">Seu progresso é registrado automaticamente.</p>
      <div class="video">
        <video id="player" controls playsinline preload="metadata" style="width:100%;height:100%">
          <source src="${VIDEO_URL}" type="video/mp4" />
        </video>
      </div>
    </div>
    <script>
      (function(){
        const video = document.getElementById('player');
        const sessionId = ${sessionId};
        function now(){ return new Date().toISOString(); }
        let last = 0;
        function send(payload){
          const b = new Blob([JSON.stringify(payload)],{type:'application/json'});
          if(!(navigator.sendBeacon && navigator.sendBeacon('/track', b))){
            fetch('/track',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
          }
        }
        function ping(type){
          const t = Math.floor(video.currentTime||0);
          const ms = Date.now();
          if(type==='progress' && (ms-last)<5000) return; // a cada 5s
          last = ms;
          send({ sessionId, type, videoTime:t, clientTs: now() });
        }
        video.addEventListener('play', ()=> ping('play'));
        video.addEventListener('pause', ()=> ping('pause'));
        video.addEventListener('ended', ()=> ping('ended'));
        video.addEventListener('timeupdate', ()=> ping('progress'));
        window.addEventListener('beforeunload', ()=> ping('progress'));
      })();
    </script>`;
    res.send(renderPage('Aula', body));
  });
});

// ====== Relatório (CSV) ======
app.get('/admin/relatorio/:videoId.csv', authRequired, (req, res) => {
  const { videoId } = req.params;
  const sql = `
    SELECT u.full_name, u.email, s.id as session, e.type, e.video_time, e.client_ts
    FROM events e
    JOIN sessions s ON s.id = e.session_id
    JOIN users u ON u.id = s.user_id
    WHERE s.video_id = ?
    ORDER BY u.full_name, u.email, e.client_ts
  `;
  db.all(sql, [videoId], (err, rows) => {
    if (err) return res.status(500).send('erro');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');

    // Evita aspas “curvas” e quebras de linha acidentais
    const header = ['full_name','email','session','type','video_time','client_ts'].join(',') + '\n';
    const body = rows.map(r =>
      `${(r.full_name||'').replace(/,/g,' ')},${r.email},${r.session},${r.type},${r.video_time},${r.client_ts}`
    ).join('\n');

    res.send(header + body);
  });
});

// ====== Relatório (HTML) ======
app.get('/admin/relatorio/:videoId', authRequired, (req, res) => {
  const { videoId } = req.params;
  const sql = `
    SELECT u.full_name, u.email, s.id as session, e.type, e.video_time, e.client_ts
    FROM events e
    JOIN sessions s ON s.id = e.session_id
    JOIN users u ON u.id = s.user_id
    WHERE s.video_id = ?
    ORDER BY u.full_name, u.email, e.client_ts
  `;
  db.all(sql, [videoId], (err, rows) => {
    if (err) return res.status(500).send('erro');
    const byUser = new Map();
    for (const r of rows){
      const key = r.email; if(!byUser.has(key)) byUser.set(key, []);
      byUser.get(key).push(r);
    }
    const lines = [];
    byUser.forEach((events,email)=>{
      const watched = new Set();
      for (const ev of events){ if(ev.type==='progress' || ev.type==='ended') watched.add(ev.video_time); }
      const maxSec = Math.max(...Array.from(watched), 0) + 1;
      const percent = '≈ ' + Math.min(100, Math.round((watched.size / (maxSec || 1)) * 100)) + '%';
      const name = events[0]?.full_name || '';
      lines.push(`<tr><td>${(name||email)}</td><td>${events[0]?.client_ts||''}</td><td>${events[events.length-1]?.client_ts||''}</td><td>${percent}</td></tr>`);
    });
    const body = `
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <h1>Relatório da Aula #${videoId}</h1>
          <a href="/admin/relatorio/${videoId}.csv">Baixar CSV</a>
        </div>
        <table>
          <thead><tr><th>Aluno</th><th>Primeiro acesso</th><th>Último evento</th><th>Percentual (aprox.)</th></tr></thead>
          <tbody>${lines.join('')}</tbody>
        </table>
        <p class="mut">Dica: o CSV tem todos os eventos. Para % precisa, consolide intervalos no backend.</p>
      </div>`;
    res.send(renderPage('Relatório', body));
  });
});

// ====== APIs ======
app.post('/api/register', async (req,res)=>{
  try{
    const { fullName, email, password, classCode } = req.body || {};
    if(!fullName || !email || !password) return res.status(400).json({error:'Dados obrigatórios'});

    if (ALLOWED_EMAIL_DOMAIN && !email.toLowerCase().endsWith(`@${ALLOWED_EMAIL_DOMAIN.toLowerCase()}`)) {
      return res.status(400).json({error:`Use seu e-mail institucional (@${ALLOWED_EMAIL_DOMAIN}).`});
    }
    if (CLASS_CODE && classCode !== CLASS_CODE) {
      return res.status(400).json({error:'Código da turma inválido.'});
    }

    const hash = await bcrypt.hash(password, 10);
    const expiresAt = SEMESTER_END || null;
    db.run('INSERT INTO users(full_name,email,password_hash,expires_at) VALUES(?,?,?,?)',[fullName, email, hash, expiresAt], function(err){
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
  db.get('SELECT id, password_hash, expires_at FROM users WHERE email=?',[email], async (err,row)=>{
    if(!row) return res.status(401).json({error:'Credenciais inválidas'});
    const exp = parseISO(row.expires_at);
    if (exp && new Date() > exp) return res.status(403).json({error:'Acesso expirado para este usuário.'});
    const ok = await bcrypt.compare(password, row.password_hash);
    if(!ok) return res.status(401).json({error:'Credenciais inválidas'});
    res.cookie('uid', row.id, { httpOnly:true, sameSite:'lax' });
    res.json({ok:true});
  });
});

app.post('/track', (req,res)=>{
  const { sessionId, type, videoTime, clientTs } = req.body || {};
  if(!sessionId || !type) return res.status(400).end();
  db.run('INSERT INTO events(session_id,type,video_time,client_ts) VALUES(?,?,?,?)',[sessionId,type,videoTime??0,clientTs??null],()=>res.status(204).end());
});

// ====== Admin opcional: definir expiração em lote ======
app.post('/admin/set-expiration', (req,res)=>{
  if(!ADMIN_SECRET) return res.status(403).json({error:'ADMIN_SECRET não configurado'});
  const { secret, expiresAt, domain } = req.body || {};
  if (secret !== ADMIN_SECRET) return res.status(403).end();
  const sql = domain
    ? `UPDATE users SET expires_at = ? WHERE email LIKE ?`
    : `UPDATE users SET expires_at = ?`;
  const params = domain ? [expiresAt, `%@${domain}`] : [expiresAt];
  db.run(sql, params, function(err){
    if (err) return res.status(500).json({error:'Falha ao atualizar'});
    res.json({ok:true, updated:this.changes});
  });
});

app.listen(PORT, ()=> console.log(`Aula Tracker rodando na porta ${PORT}`));

/*
==================== package.json (crie este arquivo no repositório) ====================
{
  "name": "aula-tracker",
  "version": "1.0.2",
  "type": "module",
  "main": "app.js",
  "scripts": { "start": "node app.js" },
  "dependencies": {
    "bcrypt": "^5.1.1",
    "body-parser": "^1.20.2",
    "cookie-parser": "^1.4.6",
    "express": "^4.19.2",
    "sqlite3": "^5.1.6"
  }
}
========================================================================================
INSTRUÇÕES (Render):
- Environment vars: VIDEO_URL, SEMESTER_END, (opcionais) ALLOWED_EMAIL_DOMAIN, CLASS_CODE, ADMIN_SECRET
- Manual Deploy → Clear build cache & deploy
- Teste: registrar (com nome), login, /aula/1, relatório em /admin/relatorio/1 e CSV em /admin/relatorio/1.csv
*/
