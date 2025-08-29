// Aula Tracker — Express + Postgres — Cursos, Aulas e Alunos (admin CRUD), Limpar relatórios
// - Login (aluno/admin). Admin = criado no primeiro start via env ADMIN_EMAIL/ADMIN_PASSWORD
// - Cursos (slug), Aulas por curso (release_at), Player com R2 SigV4 (sem download), Watermark
// - Admin: gerencia cursos/aulas, RELATÓRIOS (CSV/HTML) ordenados por nome, e ALUNOS (CRUD + vínculo ao curso + expiração)
// - Admin: limpar relatórios (por curso, por vídeo, ou tudo)

import express from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { Pool } from 'pg';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

// ====== ENV ======
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('DATABASE_URL ausente');
  process.exit(1);
}
const SEMESTER_END = process.env.SEMESTER_END || null;
const ALLOWED_EMAIL_DOMAIN = process.env.ALLOWED_EMAIL_DOMAIN || null;
const CLASS_CODE = process.env.CLASS_CODE || null;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || null;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || null;

// R2 SigV4
const R2_ACCOUNT_ID = process.env.R2_ACCOUNT_ID;
const R2_BUCKET = process.env.R2_BUCKET;
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY;

const pool = new Pool({ connectionString: DATABASE_URL });

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// ====== HTML Shell ======
function shell(title, inner) {
  return `<!doctype html>
<html lang="pt-br">
<head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${title}</title>
<style>
:root{--bg:#0b0c10;--card:#15171c;--txt:#e7e9ee;--mut:#a7adbb;--pri:#4f8cff}
*{box-sizing:border-box} body{margin:0;font-family:system-ui,Segoe UI,Arial;background:var(--bg);color:var(--txt)}
.wrap{max-width:1000px;margin:40px auto;padding:0 16px}
.card{background:var(--card);border:1px solid #20242b;border-radius:16px;padding:24px;box-shadow:0 8px 24px rgba(0,0,0,.2)}
a{color:#8fb6ff} .mut{color:var(--mut)} label{display:block;margin:8px 0 4px}
input,select{width:100%;padding:10px;border-radius:10px;border:1px solid #2a2f39;background:#0f1116;color:var(--txt)}
button{background:var(--pri);color:#fff;border:0;border-radius:12px;padding:10px 14px;cursor:pointer;font-weight:600}
.row{display:grid;gap:16px;grid-template-columns:1fr 1fr}
table{width:100%;border-collapse:collapse} th,td{padding:8px;border-bottom:1px solid #2a2f39;text-align:left}
.video{position:relative;aspect-ratio:16/9;background:#000;border-radius:16px;overflow:hidden}
.wm{position:absolute;right:12px;bottom:12px;opacity:.65;background:rgba(0,0,0,.35);padding:6px 10px;border-radius:10px;font-size:12px}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;background:#22314a;color:#cfe1ff;font-size:12px;margin-left:8px}
.actions{display:flex;gap:8px;flex-wrap:wrap}
</style>
</head>
<body><div class="wrap">${inner}</div></body></html>`;
}

// ====== Helpers ======
const now = () => new Date();
const parseISO = (s)=> (s ? new Date(s) : null);
function isPast(d){ return d && new Date(d) < new Date(); }

async function migrate(){
  // users, courses, course_members, videos, sessions, events
  await pool.query(`
  CREATE TABLE IF NOT EXISTS users(
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT now()
  )`);

  await pool.query(`
  CREATE TABLE IF NOT EXISTS courses(
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ
  )`);

  await pool.query(`
  CREATE TABLE IF NOT EXISTS course_members(
    id SERIAL PRIMARY KEY,
    course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ,
    UNIQUE(course_id,user_id)
  )`);

  await pool.query(`
  CREATE TABLE IF NOT EXISTS videos(
    id SERIAL PRIMARY KEY,
    course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    r2_key TEXT NOT NULL,
    duration_seconds INTEGER,
    release_at TIMESTAMPTZ
  )`);

  await pool.query(`
  CREATE TABLE IF NOT EXISTS sessions(
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
    started_at TIMESTAMPTZ DEFAULT now()
  )`);

  await pool.query(`
  CREATE TABLE IF NOT EXISTS events(
    id SERIAL PRIMARY KEY,
    session_id INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    video_time INTEGER DEFAULT 0,
    client_ts TIMESTAMPTZ DEFAULT now()
  )`);

  // colunas novas idempotentes
  await pool.query(`ALTER TABLE videos ADD COLUMN IF NOT EXISTS release_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE videos ADD COLUMN IF NOT EXISTS duration_seconds INTEGER`);
  await pool.query(`ALTER TABLE users  ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE`);
  await pool.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE course_members ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ`);

  // cria admin se não existir
  if (ADMIN_EMAIL && ADMIN_PASSWORD) {
    const { rowCount } = await pool.query('SELECT 1 FROM users WHERE email=$1',[ADMIN_EMAIL]);
    if (!rowCount){
      const hash = await bcrypt.hash(ADMIN_PASSWORD, 10);
      await pool.query(
        'INSERT INTO users(full_name,email,password_hash,is_admin) VALUES($1,$2,$3,TRUE)',
        ['Administrador', ADMIN_EMAIL, hash]
      );
      console.log('Admin criado:', ADMIN_EMAIL);
    }
  }
}
await migrate();

// auth
async function getUserById(id){
  const { rows } = await pool.query('SELECT id,email,full_name,is_admin FROM users WHERE id=$1',[id]);
  return rows[0] || null;
}
function mustAuth(req,res,next){
  const uid = req.cookies?.uid;
  if (!uid) return res.redirect('/');
  getUserById(uid).then(u=>{
    if(!u) return res.redirect('/');
    req.user = u;
    next();
  }).catch(()=>res.redirect('/'));
}
function isAdmin(req){ return !!req.user?.is_admin; }
function mustAdmin(req,res,next){ if(!isAdmin(req)) return res.redirect('/'); next(); }

// R2 SigV4 (GET)
function r2PresignGET(key, expiresSeconds=600){
  // https://{ACCOUNT_ID}.r2.cloudflarestorage.com/{bucket}/{key}
  if(!R2_ACCOUNT_ID||!R2_BUCKET||!R2_ACCESS_KEY_ID||!R2_SECRET_ACCESS_KEY) return null;
  const host = `${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
  const region = 'auto';
  const service = 's3';
  const method = 'GET';
  const amzdate = new Date().toISOString().replace(/[-:]/g,'').replace(/\.\d{3}Z$/,'Z'); // YYYYMMDDTHHMMSSZ
  const datestamp = amzdate.slice(0,8);
  const canonicalUri = `/${R2_BUCKET}/${encodeURI(key)}`;
  const query = new URLSearchParams({
    'X-Amz-Algorithm':'AWS4-HMAC-SHA256',
    'X-Amz-Credential':`${R2_ACCESS_KEY_ID}/${datestamp}/${region}/${service}/aws4_request`,
    'X-Amz-Date':amzdate,
    'X-Amz-Expires':String(expiresSeconds),
    'X-Amz-SignedHeaders':'host',
    'response-content-type':'video/mp4'
  });
  const canonicalQueryString = query.toString();
  const canonicalHeaders = `host:${host}\n`;
  const signedHeaders = 'host';
  const payloadHash = 'UNSIGNED-PAYLOAD';
  const canonicalRequest = [
    method, canonicalUri, canonicalQueryString, canonicalHeaders, signedHeaders, payloadHash
  ].join('\n');

  const hash = (str)=>crypto.createHash('sha256').update(str,'utf8').digest('hex');
  const kDate = crypto.createHmac('sha256', 'AWS4' + R2_SECRET_ACCESS_KEY).update(datestamp).digest();
  const kRegion = crypto.createHmac('sha256', kDate).update(region).digest();
  const kService = crypto.createHmac('sha256', kRegion).update(service).digest();
  const kSigning = crypto.createHmac('sha256', kService).update('aws4_request').digest();
  const stringToSign = [
    'AWS4-HMAC-SHA256', amzdate,
    `${datestamp}/${region}/${service}/aws4_request`,
    hash(canonicalRequest)
  ].join('\n');
  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex');

  return `https://${host}${canonicalUri}?${canonicalQueryString}&X-Amz-Signature=${signature}`;
}

// ====== Páginas ======
app.get('/', (req,res)=>{
  const domainMsg = ALLOWED_EMAIL_DOMAIN ? `Use seu e-mail institucional (@${ALLOWED_EMAIL_DOMAIN}).` : 'Use seu e-mail.';
  const showCode = !!CLASS_CODE;
  const html = `
  <div class="row">
    <div class="card">
      <h1>Entrar</h1>
      <form id="loginForm">
        <label>E-mail</label><input name="email" type="email" required>
        <label>Senha</label><input name="password" type="password" required>
        <button class="mt">Entrar</button>
      </form>
    </div>
    <div class="card">
      <h2>Registrar</h2>
      <form id="regForm">
        <label>Nome completo</label><input name="fullName" required>
        <label>E-mail</label><input name="email" type="email" required>
        <label>Senha</label><input name="password" type="password" required>
        ${showCode ? '<label>Código da turma</label><input name="classCode" required>' : ''}
        <button class="mt">Criar conta</button>
      </form>
      <p class="mut">${domainMsg}</p>
    </div>
  </div>
  <script>
    async function post(url,data){
      const r = await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
      const t = await r.text(); let j; try{j=JSON.parse(t)}catch{j={}}
      if(!r.ok) throw new Error(j.error||t||'Erro');
      return j;
    }
    document.getElementById('loginForm').addEventListener('submit', async (e)=>{
      e.preventDefault();
      const f=new FormData(e.target);
      try{ await post('/api/login',{email:f.get('email'),password:f.get('password')}); location.href='/aulas'; }
      catch(err){ alert(err.message); }
    });
    document.getElementById('regForm').addEventListener('submit', async (e)=>{
      e.preventDefault();
      const f=new FormData(e.target);
      try{ await post('/api/register',{fullName:f.get('fullName'),email:f.get('email'),password:f.get('password'),classCode:f.get('classCode')||null}); alert('Conta criada. Faça login.'); }
      catch(err){ alert(err.message); }
    });
  </script>`;
  res.send(shell('Acesso', html));
});

app.get('/logout',(req,res)=>{ res.clearCookie('uid'); res.redirect('/'); });

// ====== Aulas (lista por curso) ======
app.get('/aulas', mustAuth, async (req,res)=>{
  try{
    if(isAdmin(req)){
      // Admin vê TUDO
      const { rows:courses } = await pool.query('SELECT id,name,slug FROM courses ORDER BY name');
      const { rows:videos }  = await pool.query(`SELECT v.id,v.title,v.r2_key,v.release_at,c.name as course
                                                 FROM videos v JOIN courses c ON c.id=v.course_id
                                                 ORDER BY c.name, v.id DESC`);
      const list = videos.map(v=>`<tr><td>${v.course}</td><td><a href="/aula/${v.id}">${v.title}</a></td><td class="mut">${v.r2_key}</td><td>${v.release_at? new Date(v.release_at).toLocaleString('pt-BR') : '-'}</td><td>
        <div class="actions">
          <a href="/admin/videos/${v.id}/edit">Editar</a>
          <a href="/admin/relatorio/${v.id}">Relatório</a>
          <a href="/admin/relatorio/${v.id}.csv">CSV</a>
        </div>
      </td></tr>`).join('');
      const html = `
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <h1>Aulas (Admin)</h1>
          <div class="actions">
            <a href="/admin/videos">Nova aula</a>
            <a href="/admin/cursos">Cursos</a>
            <a href="/admin/alunos">Alunos</a>
            <a href="/admin/relatorios/limpar">Limpar relatórios</a>
            <a href="/logout">Sair</a>
          </div>
        </div>
        <table>
          <thead><tr><th>Curso</th><th>Título</th><th>R2 key</th><th>Release</th><th>Ações</th></tr></thead>
          <tbody>${list || '<tr><td colspan="5" class="mut">Sem aulas</td></tr>'}</tbody>
        </table>
      </div>`;
      return res.send(shell('Aulas', html));
    }

    // Aluno: vê apenas aulas liberadas dos cursos onde é membro e não expirou
    const { rows:videos } = await pool.query(`
      SELECT v.id,v.title,c.name as course
      FROM videos v
      JOIN courses c ON c.id=v.course_id
      JOIN course_members cm ON cm.course_id=v.course_id AND cm.user_id=$1
      WHERE (c.expires_at IS NULL OR c.expires_at > now())
        AND (cm.expires_at IS NULL OR cm.expires_at > now())
        AND (v.release_at IS NULL OR v.release_at <= now())
      ORDER BY c.name, v.id DESC`, [req.user.id]);
    const list = videos.map(v=>`<li><a href="/aula/${v.id}">${v.title}</a> <span class="badge">${v.course}</span></li>`).join('');
    const html = `
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <h1>Aulas</h1>
        <div class="actions"><a href="/logout">Sair</a></div>
      </div>
      <ul>${list || '<li class="mut">Nenhuma aula disponível ainda.</li>'}</ul>
    </div>`;
    res.send(shell('Aulas', html));
  }catch(err){
    console.error(err); res.status(500).send('erro');
  }
});

// ====== Player ======
app.get('/aula/:id', mustAuth, async (req,res)=>{
  try{
    const id = parseInt(req.params.id,10);
    const { rows } = await pool.query(`
      SELECT v.*, c.name as course_name
      FROM videos v JOIN courses c ON c.id=v.course_id
      WHERE v.id=$1`, [id]);
    const v = rows[0];
    if(!v) return res.status(404).send(shell('Aula', `<div class="card"><h1>Aula não encontrada</h1><a href="/aulas">Voltar</a></div>`));

    if(!isAdmin(req)){
      // checa vínculo e release
      const { rowCount:member } = await pool.query(`
        SELECT 1 FROM course_members WHERE course_id=$1 AND user_id=$2
          AND (expires_at IS NULL OR expires_at > now())`, [v.course_id, req.user.id]);
      if(!member) return res.status(403).send(shell('Sem acesso', `<div class="card"><h1>Sem acesso a este curso</h1><a href="/aulas">Voltar</a></div>`));
      if(v.release_at && new Date(v.release_at) > new Date()){
        return res.status(403).send(shell('Indisponível', `<div class="card"><h1>Aula ainda não disponível</h1><p class="mut">Liberação: ${new Date(v.release_at).toLocaleString('pt-BR')}</p><a href="/aulas">Voltar</a></div>`));
      }
    }

    const url = r2PresignGET(v.r2_key, 600);
    if(!url) return res.status(500).send(shell('Erro', `<div class="card"><h1>Vídeo não configurado</h1><p class="mut">Verifique variáveis R2_*</p></div>`));

    const ins = await pool.query('INSERT INTO sessions(user_id,video_id) VALUES($1,$2) RETURNING id',[req.user.id, v.id]);
    const sessionId = ins.rows[0].id;
    const wm = (req.user.full_name || req.user.email || '').replace(/</g,'&lt;').replace(/>/g,'&gt;');

    const html = `
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px">
        <h1 style="margin:0">${v.title} <span class="badge">${v.course_name}</span></h1>
        <div class="actions"><a href="/aulas">Aulas</a><a href="/logout">Sair</a></div>
      </div>
      <p class="mut">Seu progresso é registrado automaticamente.</p>
      <div class="video">
        <video id="player" controls playsinline preload="metadata" controlsList="nodownload" oncontextmenu="return false" style="width:100%;height:100%">
          <source src="${url}" type="video/mp4"/>
        </video>
        <div class="wm">${wm}</div>
      </div>
    </div>
    <script>
      (function(){
        const video=document.getElementById('player');
        const sessionId=${sessionId};
        function send(type){
          fetch('/track',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sessionId,type,videoTime:Math.floor(video.currentTime||0),clientTs:new Date().toISOString()})});
        }
        video.addEventListener('play',()=>send('play'));
        video.addEventListener('pause',()=>send('pause'));
        video.addEventListener('ended',()=>send('ended'));
        setInterval(()=>send('progress'),5000);
        video.addEventListener('error',()=>{const e=video.error; alert('Erro no player (Console/Network). code='+(e&&e.code));});
      })();
    </script>`;
    res.send(shell(v.title, html));
  }catch(err){
    console.error(err); res.status(500).send('erro');
  }
});

// ====== Relatórios (HTML + CSV) — ordenado por nome ======
app.get('/admin/relatorio/:videoId', mustAuth, mustAdmin, async (req,res)=>{
  try{
    const videoId = parseInt(req.params.videoId,10);
    const { rows } = await pool.query(`
      SELECT u.full_name, u.email, s.id as session, e.type, e.video_time, e.client_ts
      FROM events e
      JOIN sessions s ON s.id=e.session_id
      JOIN users u ON u.id=s.user_id
      WHERE s.video_id=$1
      ORDER BY u.full_name ASC, u.email ASC, e.client_ts ASC`, [videoId]);
    const trs = rows.map(r=>`<tr><td>${r.full_name}</td><td>${r.email}</td><td>${r.session}</td><td>${r.type}</td><td>${r.video_time}</td><td>${new Date(r.client_ts).toLocaleString('pt-BR')}</td></tr>`).join('');
    const html = `
    <div class="card">
      <h1>Relatório do Vídeo #${videoId}</h1>
      <div class="actions"><a href="/admin/relatorio/${videoId}.csv">Exportar CSV</a> <a href="/aulas">Voltar</a></div>
      <table><thead><tr><th>Nome</th><th>E-mail</th><th>Sessão</th><th>Tipo</th><th>Tempo (s)</th><th>Quando</th></tr></thead>
      <tbody>${trs || '<tr><td colspan="6" class="mut">Sem eventos</td></tr>'}</tbody></table>
    </div>`;
    res.send(shell('Relatório', html));
  }catch(err){
    console.error(err); res.status(500).send('erro');
  }
});

app.get('/admin/relatorio/:videoId.csv', mustAuth, mustAdmin, async (req,res)=>{
  try{
    const videoId = parseInt(req.params.videoId,10);
    const { rows } = await pool.query(`
      SELECT u.full_name, u.email, s.id as session, e.type, e.video_time, e.client_ts
      FROM events e
      JOIN sessions s ON s.id=e.session_id
      JOIN users u ON u.id=s.user_id
      WHERE s.video_id=$1
      ORDER BY u.full_name ASC, u.email ASC, e.client_ts ASC`, [videoId]);
    res.setHeader('Content-Type','text/csv; charset=utf-8');
    const header = 'full_name;email;session;type;video_time;client_ts\n';
    const body = rows.map(r =>
      `${(r.full_name||'').replace(/;/g,' ') };${r.email};${r.session};${r.type};${r.video_time};${r.client_ts.toISOString()}`
    ).join('\n');
    res.send(header+body);
  }catch(err){
    console.error(err); res.status(500).send('erro');
  }
});

// ====== Limpar relatórios (fim de semestre) ======
app.get('/admin/relatorios/limpar', mustAuth, mustAdmin, async (req,res)=>{
  const { rows: courses } = await pool.query('SELECT id,name FROM courses ORDER BY name');
  const { rows: videos }  = await pool.query('SELECT id,title FROM videos ORDER BY title');
  const optionsCourse = courses.map(c=>`<option value="${c.id}">${c.name}</option>`).join('');
  const optionsVideo  = videos.map(v=>`<option value="${v.id}">${v.title}</option>`).join('');
  const html = `
  <div class="card">
    <h1>Limpar relatórios</h1>
    <form method="POST" action="/admin/relatorios/limpar" class="mt2">
      <label>Escopo</label>
      <select name="scope" required>
        <option value="all">Tudo (todos os vídeos)</option>
        <option value="course">Por curso</option>
        <option value="video">Por vídeo</option>
      </select>
      <div id="courseBox" style="display:none" class="mt2">
        <label>Curso</label>
        <select name="course_id">${optionsCourse}</select>
      </div>
      <div id="videoBox" style="display:none" class="mt2">
        <label>Vídeo</label>
        <select name="video_id">${optionsVideo}</select>
      </div>
      <button class="mt2" onclick="return confirm('Tem certeza? Isso apaga eventos e sessões no escopo escolhido.')">Limpar</button>
    </form>
  </div>
  <script>
    const scopeSel=document.querySelector('select[name=scope]');
    const courseBox=document.getElementById('courseBox');
    const videoBox=document.getElementById('videoBox');
    function togg(){
      courseBox.style.display = scopeSel.value==='course' ? '' : 'none';
      videoBox.style.display  = scopeSel.value==='video' ? '' : 'none';
    }
    scopeSel.addEventListener('change', togg); togg();
  </script>`;
  res.send(shell('Limpar relatórios', html));
});

app.post('/admin/relatorios/limpar', mustAuth, mustAdmin, async (req,res)=>{
  try{
    const { scope, course_id, video_id } = req.body || {};
    if (scope==='all'){
      await pool.query('DELETE FROM events');
      await pool.query('DELETE FROM sessions');
    } else if (scope==='course' && course_id){
      await pool.query(`
        DELETE FROM events WHERE session_id IN (
          SELECT s.id FROM sessions s
          JOIN videos v ON v.id=s.video_id
          WHERE v.course_id=$1
        )`, [course_id]);
      await pool.query(`
        DELETE FROM sessions WHERE id IN (
          SELECT s.id FROM sessions s
          JOIN videos v ON v.id=s.video_id
          WHERE v.course_id=$1
        )`, [course_id]);
    } else if (scope==='video' && video_id){
      await pool.query('DELETE FROM events WHERE session_id IN (SELECT id FROM sessions WHERE video_id=$1)', [video_id]);
      await pool.query('DELETE FROM sessions WHERE video_id=$1', [video_id]);
    }
    res.redirect('/aulas');
  }catch(err){
    console.error(err); res.status(500).send('Falha ao limpar');
  }
});

// ====== Admin: Cursos ======
app.get('/admin/cursos', mustAuth, mustAdmin, async (req,res)=>{
  const { rows } = await pool.query('SELECT id,name,slug,expires_at FROM courses ORDER BY name');
  const trs = rows.map(c=>`<tr><td>${c.name}</td><td>${c.slug}</td><td>${c.expires_at? new Date(c.expires_at).toLocaleDateString('pt-BR'):'-'}</td><td class="actions">
    <a href="/admin/cursos/${c.id}/edit">Editar</a>
  </td></tr>`).join('');
  const html = `
  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <h1>Cursos</h1>
      <div class="actions">
        <a href="/admin/cursos/new">Novo curso</a>
        <a href="/aulas">Aulas</a>
        <a href="/admin/alunos">Alunos</a>
      </div>
    </div>
    <table><thead><tr><th>Nome</th><th>Slug</th><th>Expira</th><th>Ações</th></tr></thead><tbody>${trs||'<tr><td colspan="4" class="mut">Sem cursos</td></tr>'}</tbody></table>
  </div>`;
  res.send(shell('Cursos', html));
});

app.get('/admin/cursos/new', mustAuth, mustAdmin, (req,res)=>{
  const html = `
  <div class="card"><h1>Novo curso</h1>
    <form method="POST" action="/admin/cursos/new">
      <label>Nome</label><input name="name" required>
      <label>Slug</label><input name="slug" required>
      <label>Expira em (opcional)</label><input name="expires_at" type="datetime-local">
      <button>Criar</button>
    </form>
  </div>`;
  res.send(shell('Novo curso', html));
});

app.post('/admin/cursos/new', mustAuth, mustAdmin, async (req,res)=>{
  const { name, slug, expires_at } = req.body || {};
  const exp = (expires_at && /^\d{4}-\d{2}-\d{2}T/.test(expires_at)) ? new Date(expires_at).toISOString() : null;
  await pool.query('INSERT INTO courses(name,slug,expires_at) VALUES($1,$2,$3)', [name, slug, exp]);
  res.redirect('/admin/cursos');
});

app.get('/admin/cursos/:id/edit', mustAuth, mustAdmin, async (req,res)=>{
  const id = parseInt(req.params.id,10);
  const { rows } = await pool.query('SELECT id,name,slug,expires_at FROM courses WHERE id=$1',[id]);
  const c = rows[0]; if(!c) return res.redirect('/admin/cursos');
  const html = `
  <div class="card"><h1>Editar curso</h1>
    <form method="POST" action="/admin/cursos/${id}/edit">
      <label>Nome</label><input name="name" value="${c.name}" required>
      <label>Slug</label><input name="slug" value="${c.slug}" required>
      <label>Expira em</label><input name="expires_at" type="datetime-local" value="${c.expires_at? new Date(c.expires_at).toISOString().slice(0,16):''}">
      <button>Salvar</button>
    </form>
  </div>`;
  res.send(shell('Editar curso', html));
});

app.post('/admin/cursos/:id/edit', mustAuth, mustAdmin, async (req,res)=>{
  const id = parseInt(req.params.id,10);
  const { name, slug, expires_at } = req.body || {};
  const exp = (expires_at && /^\d{4}-\d{2}-\d{2}T/.test(expires_at)) ? new Date(expires_at).toISOString() : null;
  await pool.query('UPDATE courses SET name=$1, slug=$2, expires_at=$3 WHERE id=$4', [name, slug, exp, id]);
  res.redirect('/admin/cursos');
});

// ====== Admin: Aulas ======
app.get('/admin/videos', mustAuth, mustAdmin, async (req,res)=>{
  const { rows:courses } = await pool.query('SELECT id,name FROM courses ORDER BY name');
  const options = courses.map(c=>`<option value="${c.id}">${c.name}</option>`).join('');
  const html = `
  <div class="card"><h1>Nova aula</h1>
    <form method="POST" action="/admin/videos">
      <label>Curso</label><select name="course_id" required>${options}</select>
      <label>Título</label><input name="title" required>
      <label>R2 key</label><input name="r2_key" required>
      <label>Duração (seg) (opcional)</label><input name="duration_seconds" type="number" min="0">
      <label>Disponível a partir de (opcional)</label><input name="release_at" type="datetime-local">
      <button>Salvar</button>
    </form>
  </div>`;
  res.send(shell('Nova aula', html));
});

app.post('/admin/videos', mustAuth, mustAdmin, async (req,res)=>{
  const { course_id, title, r2_key, duration_seconds, release_at } = req.body || {};
  const dur = duration_seconds ? Math.max(0, parseInt(duration_seconds,10)) : null;
  const rel = (release_at && /^\d{4}-\d{2}-\d{2}T/.test(release_at)) ? new Date(release_at).toISOString() : null;
  await pool.query('INSERT INTO videos(course_id,title,r2_key,duration_seconds,release_at) VALUES($1,$2,$3,$4,$5)',
    [course_id, title, r2_key, dur, rel]);
  res.redirect('/aulas');
});

app.get('/admin/videos/:id/edit', mustAuth, mustAdmin, async (req,res)=>{
  const id = parseInt(req.params.id,10);
  const { rows:vrows } = await pool.query('SELECT * FROM videos WHERE id=$1',[id]);
  const v = vrows[0]; if(!v) return res.redirect('/aulas');
  const { rows:courses } = await pool.query('SELECT id,name FROM courses ORDER BY name');
  const opts = courses.map(c=>`<option value="${c.id}" ${c.id===v.course_id?'selected':''}>${c.name}</option>`).join('');
  const html = `
  <div class="card"><h1>Editar aula</h1>
    <form method="POST" action="/admin/videos/${id}/edit">
      <label>Curso</label><select name="course_id">${opts}</select>
      <label>Título</label><input name="title" value="${v.title}">
      <label>R2 key</label><input name="r2_key" value="${v.r2_key}">
      <label>Duração (seg)</label><input name="duration_seconds" type="number" min="0" value="${v.duration_seconds??''}">
      <label>Disponível a partir de</label><input name="release_at" type="datetime-local" value="${v.release_at? new Date(v.release_at).toISOString().slice(0,16):''}">
      <div class="actions"><button>Salvar</button> <a href="/aulas">Cancelar</a></div>
    </form>
  </div>`;
  res.send(shell('Editar aula', html));
});

app.post('/admin/videos/:id/edit', mustAuth, mustAdmin, async (req,res)=>{
  const id = parseInt(req.params.id,10);
  const { course_id, title, r2_key, duration_seconds, release_at } = req.body || {};
  const dur = duration_seconds ? Math.max(0, parseInt(duration_seconds,10)) : null;
  const rel = (release_at && /^\d{4}-\d{2}-\d{2}T/.test(release_at)) ? new Date(release_at).toISOString() : null;
  await pool.query('UPDATE videos SET course_id=$1,title=$2,r2_key=$3,duration_seconds=$4,release_at=$5 WHERE id=$6',
    [course_id, title, r2_key, dur, rel, id]);
  res.redirect('/aulas');
});

// ====== Admin: Alunos (CRUD + vínculo a curso) ======
app.get('/admin/alunos', mustAuth, mustAdmin, async (req,res)=>{
  const { rows: courses } = await pool.query('SELECT id,name FROM courses ORDER BY name');
  const { rows: users } = await pool.query(`
    SELECT u.id,u.full_name,u.email,u.is_admin,
           STRING_AGG(c.name, ', ' ORDER BY c.name) AS cursos
    FROM users u
    LEFT JOIN course_members cm ON cm.user_id=u.id
    LEFT JOIN courses c ON c.id=cm.course_id
    GROUP BY u.id
    ORDER BY u.full_name ASC, u.email ASC`);
  const tr = users.map(u=>`<tr><td>${u.full_name}${u.is_admin? ' <span class="badge">admin</span>':''}</td><td>${u.email}</td><td>${u.cursos||'-'}</td>
  <td class="actions"><a href="/admin/alunos/${u.id}/edit">Editar</a></td></tr>`).join('');
  const courseOpts = courses.map(c=>`<option value="${c.id}">${c.name}</option>`).join('');
  const html = `
  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <h1>Alunos</h1>
      <div class="actions"><a href="/aulas">Aulas</a><a href="/admin/cursos">Cursos</a></div>
    </div>
    <h3>Criar aluno</h3>
    <form method="POST" action="/admin/alunos/new" class="mt2">
      <label>Nome completo</label><input name="full_name" required>
      <label>E-mail</label><input name="email" type="email" required>
      <label>Senha</label><input name="password" type="password" required>
      <label>Curso (opcional)</label><select name="course_id"><option value="">(nenhum)</option>${courseOpts}</select>
      <label>Vínculo expira em (opcional)</label><input name="member_expires_at" type="datetime-local">
      <button class="mt2">Criar</button>
    </form>
    <h3 class="mt2">Lista</h3>
    <table><thead><tr><th>Nome</th><th>E-mail</th><th>Cursos</th><th>Ações</th></tr></thead>
    <tbody>${tr || '<tr><td colspan="4" class="mut">Sem alunos</td></tr>'}</tbody></table>
  </div>`;
  res.send(shell('Alunos', html));
});

app.post('/admin/alunos/new', mustAuth, mustAdmin, async (req,res)=>{
  try{
    const { full_name, email, password, course_id, member_expires_at } = req.body || {};
    if(!full_name||!email||!password) return res.status(400).send('Dados obrigatórios');
    const hash = await bcrypt.hash(password,10);
    const { rows:urows } = await pool.query(
      'INSERT INTO users(full_name,email,password_hash,is_admin) VALUES($1,$2,$3,FALSE) RETURNING id',
      [full_name,email,hash]
    );
    if (course_id){
      const exp = (member_expires_at && /^\d{4}-\d{2}-\d{2}T/.test(member_expires_at)) ? new Date(member_expires_at).toISOString() : null;
      await pool.query('INSERT INTO course_members(course_id,user_id,expires_at) VALUES($1,$2,$3) ON CONFLICT (course_id,user_id) DO UPDATE SET expires_at=EXCLUDED.expires_at',
        [course_id, urows[0].id, exp]);
    }
    res.redirect('/admin/alunos');
  }catch(err){
    console.error(err); res.status(500).send('Falha ao criar aluno');
  }
});

app.get('/admin/alunos/:id/edit', mustAuth, mustAdmin, async (req,res)=>{
  const id = parseInt(req.params.id,10);
  const { rows: urows } = await pool.query('SELECT id,full_name,email,is_admin FROM users WHERE id=$1',[id]);
  const u = urows[0]; if(!u) return res.redirect('/admin/alunos');
  const { rows: courses } = await pool.query('SELECT id,name FROM courses ORDER BY name');
  const { rows: mems } = await pool.query(`
    SELECT cm.course_id,c.name,cm.expires_at
    FROM course_members cm JOIN courses c ON c.id=cm.course_id
    WHERE cm.user_id=$1 ORDER BY c.name`,[id]);

  const courseOpts = courses.map(c=>`<option value="${c.id}">${c.name}</option>`).join('');
  const memRows = mems.map(m=>`<tr><td>${m.name}</td><td>${m.expires_at? new Date(m.expires_at).toISOString().slice(0,16):''}</td>
    <td class="actions">
      <form method="POST" action="/admin/alunos/${id}/member/${m.course_id}/remove" onsubmit="return confirm('Remover vínculo?')"><button>Remover</button></form>
    </td></tr>`).join('');

  const html = `
  <div class="card"><h1>Editar aluno</h1>
    <form method="POST" action="/admin/alunos/${id}/edit">
      <label>Nome</label><input name="full_name" value="${u.full_name}">
      <label>E-mail</label><input name="email" type="email" value="${u.email}">
      <label>Nova senha (opcional)</label><input name="new_password" type="password">
      <label>É admin?</label>
      <select name="is_admin"><option value="false" ${!u.is_admin?'selected':''}>Não</option><option value="true" ${u.is_admin?'selected':''}>Sim</option></select>
      <div class="actions" style="margin-top:12px"><button>Salvar</button> <a href="/admin/alunos">Voltar</a></div>
    </form>
    <h3 class="mt2">Vínculos a cursos</h3>
    <form method="POST" action="/admin/alunos/${id}/member/add">
      <div class="row">
        <div>
          <label>Curso</label><select name="course_id">${courseOpts}</select>
        </div>
        <div>
          <label>Expira em (opcional)</label><input name="expires_at" type="datetime-local">
        </div>
      </div>
      <button class="mt2">Adicionar/Atualizar vínculo</button>
    </form>
    <table class="mt2"><thead><tr><th>Curso</th><th>Expira em</th><th>Ações</th></tr></thead>
    <tbody>${memRows || '<tr><td colspan="3" class="mut">Sem vínculos</td></tr>'}</tbody></table>

    <h3 class="mt2">Remover aluno</h3>
    <form method="POST" action="/admin/alunos/${id}/delete" onsubmit="return confirm('Remover este aluno? Isso remove vínculos e sessões/eventos dele.')">
      <button style="background:#b84040">Remover aluno</button>
    </form>
  </div>`;
  res.send(shell('Editar aluno', html));
});

app.post('/admin/alunos/:id/edit', mustAuth, mustAdmin, async (req,res)=>{
  try{
    const id = parseInt(req.params.id,10);
    const { full_name, email, new_password, is_admin } = req.body || {};
    if(new_password){
      const hash = await bcrypt.hash(new_password,10);
      await pool.query('UPDATE users SET full_name=$1,email=$2,password_hash=$3,is_admin=$4 WHERE id=$5',
        [full_name, email, hash, String(is_admin)==='true', id]);
    } else {
      await pool.query('UPDATE users SET full_name=$1,email=$2,is_admin=$3 WHERE id=$4',
        [full_name, email, String(is_admin)==='true', id]);
    }
    res.redirect('/admin/alunos');
  }catch(err){
    console.error(err); res.status(500).send('Falha ao salvar aluno');
  }
});

app.post('/admin/alunos/:id/member/add', mustAuth, mustAdmin, async (req,res)=>{
  try{
    const id = parseInt(req.params.id,10);
    const { course_id, expires_at } = req.body || {};
    const exp = (expires_at && /^\d{4}-\d{2}-\d{2}T/.test(expires_at)) ? new Date(expires_at).toISOString() : null;
    await pool.query(
      'INSERT INTO course_members(course_id,user_id,expires_at) VALUES($1,$2,$3) ON CONFLICT (course_id,user_id) DO UPDATE SET expires_at=EXCLUDED.expires_at',
      [course_id, id, exp]
    );
    res.redirect(`/admin/alunos/${id}/edit`);
  }catch(err){
    console.error(err); res.status(500).send('Falha ao vincular curso');
  }
});

app.post('/admin/alunos/:id/member/:course_id/remove', mustAuth, mustAdmin, async (req,res)=>{
  const id = parseInt(req.params.id,10);
  const course_id = parseInt(req.params.course_id,10);
  await pool.query('DELETE FROM course_members WHERE course_id=$1 AND user_id=$2',[course_id, id]);
  res.redirect(`/admin/alunos/${id}/edit`);
});

app.post('/admin/alunos/:id/delete', mustAuth, mustAdmin, async (req,res)=>{
  const id = parseInt(req.params.id,10);
  await pool.query('DELETE FROM users WHERE id=$1',[id]);
  res.redirect('/admin/alunos');
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
    await pool.query('INSERT INTO users(full_name,email,password_hash,is_admin) VALUES($1,$2,$3,FALSE)', [fullName,email,hash]);
    res.json({ok:true});
  }catch(err){
    console.error(err); res.status(400).json({error:'E-mail já cadastrado'});
  }
});

app.post('/api/login', async (req,res)=>{
  try{
    const { email, password } = req.body || {};
    if(!email || !password) return res.status(400).json({error:'Dados obrigatórios'});
    const { rows } = await pool.query('SELECT id,password_hash FROM users WHERE email=$1',[email]);
    const row = rows[0]; if(!row) return res.status(401).json({error:'Credenciais inválidas'});
    const ok = await bcrypt.compare(password, row.password_hash);
    if(!ok) return res.status(401).json({error:'Credenciais inválidas'});
    res.cookie('uid', row.id, { httpOnly:true, sameSite:'lax' });
    res.json({ok:true});
  }catch{
    res.status(500).json({error:'Falha no login'});
  }
});

app.post('/track', async (req,res)=>{
  try{
    const { sessionId, type, videoTime, clientTs } = req.body||{};
    if(!sessionId||!type) return res.status(400).end();
    const vt = Math.max(0, parseInt(videoTime||0,10));
    const ts = clientTs && /^\d{4}-/.test(clientTs) ? clientTs : new Date().toISOString();
    await pool.query('INSERT INTO events(session_id,type,video_time,client_ts) VALUES($1,$2,$3,$4)', [sessionId,type,vt,ts]);
    res.status(204).end();
  }catch{ res.status(204).end(); }
});

app.listen(PORT, ()=> console.log(`Aula Tracker rodando na porta ${PORT}`));
