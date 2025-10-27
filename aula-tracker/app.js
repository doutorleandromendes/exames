// Aula Tracker — Postgres + Cloudflare R2 (SigV4)
// Admin: gerencia cursos, aulas, alunos/matrículas; vê/edita tudo; relatórios web + CSV ordenados por nome
// Player: URL assinada SigV4 (R2), sem download, watermark e tracking de progresso
// Ajustes nesta versão:
// - Disponibilidade: courses.start_date e videos.available_from
// - Tela admin para editar disponibilidade das aulas (/admin/videos/availability)
// - Filtro em /aulas (aluno) respeitando as datas

import express from 'express';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { Pool } from 'pg';
import { sendWelcomeEmail } from './mailer.js';

// ---- SSL config helper (minimal, surgical) ----
const __pgSslMode = (process.env.PGSSLMODE || '').toLowerCase();
const __sslConfig = (__pgSslMode === 'disable')
  ? false
  : { rejectUnauthorized: (__pgSslMode === 'no-verify') ? false : true };
// -----------------------------------------------

const app = express();
app.set('trust proxy', 1);

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '4mb' }));
app.use(cookieParser());
app.use(express.static('public'))

const PORT = process.env.PORT || 3000;

// ====== ENV ======
const DATABASE_URL = process.env.DATABASE_URL;
const DATABASE_URL_UNPOOLED = process.env.DATABASE_URL_UNPOOLED || null;
const PGSSLMODE = process.env.PGSSLMODE || 'require';
const SUPABASE_POOLER_URL = process.env.SUPABASE_POOLER_URL || null;
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
  connectionString: SUPABASE_POOLER_URL || DATABASE_URL,
  // Usa o Transaction Pooler (porta 6543) quando SUPABASE_POOLER_URL estiver definido; SSL com verificação de certificado
  ssl: __sslConfig
});
// Pool dedicado para migrações (usa conexão direta quando disponível)
const migratorPool = new Pool({
  connectionString: DATABASE_URL_UNPOOLED || DATABASE_URL,
  ssl: __sslConfig
});
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

// ====== HTML helpers ======

function safe(s){
  return String(s ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}

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
      .admin-back-top{margin-bottom:16px}
    </style>
  </head>
  <body>
    <div class="wrap">
      <div id="admin-back" class="admin-back-top" style="display:none">
        <a href="/aulas">← Voltar para aulas</a>
      </div>
      ${body}
    </div>
    <script>
      if (location.pathname.startsWith('/admin')) {
        document.getElementById('admin-back').style.display = 'block';
      }
    </script>
  </body>
  </html>`;
}

const parseISO = s => (s ? new Date(s) : null);
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
  await migratorPool.query(`
    CREATE TABLE IF NOT EXISTS users(
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE,
      password_hash TEXT,
      full_name TEXT,
      created_at TIMESTAMPTZ DEFAULT now(),
      expires_at TIMESTAMPTZ
    );`);

  await migratorPool.query(`
    CREATE TABLE IF NOT EXISTS courses(
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      enroll_code TEXT,
      expires_at TIMESTAMPTZ
    );`);

  await migratorPool.query(`
    CREATE TABLE IF NOT EXISTS course_members(
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
      role TEXT DEFAULT 'student',
      expires_at TIMESTAMPTZ,
      PRIMARY KEY (user_id, course_id)
    );`);

  await migratorPool.query(`
    CREATE TABLE IF NOT EXISTS videos(
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      r2_key TEXT NOT NULL,
      course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
      duration_seconds INTEGER
    );`);

  await migratorPool.query(`
    CREATE TABLE IF NOT EXISTS video_files (
      id SERIAL PRIMARY KEY,
      video_id INTEGER NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
      label TEXT NOT NULL,
      r2_key TEXT NOT NULL,
      sort_index INTEGER
    );
  `);

  await migratorPool.query(`
    CREATE TABLE IF NOT EXISTS sessions(
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
      started_at TIMESTAMPTZ DEFAULT now()
    );`);

  await migratorPool.query(`
    CREATE TABLE IF NOT EXISTS events(
      id SERIAL PRIMARY KEY,
      session_id INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
      type TEXT,
      video_time INTEGER,
      client_ts TIMESTAMPTZ
    );`);

  // ---- colunas novas/idempotentes (antes dos índices) ----
  await migratorPool.query(`ALTER TABLE users   ADD COLUMN IF NOT EXISTS temp_password TEXT`);
  await migratorPool.query(`ALTER TABLE users   ADD COLUMN IF NOT EXISTS welcome_email_sent_at TIMESTAMPTZ`);
  await migratorPool.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS archived boolean DEFAULT false`);
  await migratorPool.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS start_date TIMESTAMPTZ`);
  await migratorPool.query(`ALTER TABLE videos  ADD COLUMN IF NOT EXISTS available_from TIMESTAMPTZ`);
  await migratorPool.query(`ALTER TABLE videos  ADD COLUMN IF NOT EXISTS sort_index INTEGER`);

  // ---- watch_segments ----
  await migratorPool.query(`
    CREATE TABLE IF NOT EXISTS watch_segments (
      id SERIAL PRIMARY KEY,
      session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
      start_sec INTEGER NOT NULL,
      end_sec   INTEGER NOT NULL,
      CHECK (end_sec >= start_sec)
    );
  `);
  await migratorPool.query(`
    CREATE INDEX IF NOT EXISTS watch_segments_session_idx
      ON watch_segments(session_id, start_sec, end_sec);
  `);

  // Pedidos de acesso (pendentes/aprovados/rejeitados)
await migratorPool.query(`
  CREATE TABLE IF NOT EXISTS access_requests (
    id SERIAL PRIMARY KEY,
    full_name TEXT NOT NULL,
    email     TEXT NOT NULL,
    course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
    justification TEXT,
    status    TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected
    created_at TIMESTAMPTZ DEFAULT now(),
    processed_at TIMESTAMPTZ,
    processed_by INTEGER REFERENCES users(id) ON DELETE SET NULL
  );
`);
await migratorPool.query(`CREATE INDEX IF NOT EXISTS access_requests_status_idx ON access_requests(status, created_at DESC)`);
await migratorPool.query(`CREATE INDEX IF NOT EXISTS access_requests_email_idx  ON access_requests(LOWER(email))`);


  // ---- índices (depois das colunas existirem) ----
  await migratorPool.query(`CREATE INDEX IF NOT EXISTS video_files_video_idx
                      ON video_files(video_id, sort_index NULLS LAST, id)`);

  await migratorPool.query(`CREATE INDEX IF NOT EXISTS videos_course_order_idx
                      ON videos(course_id, sort_index NULLS LAST, id)`);

  // Unicidade por (course_id, r2_key) — e remove possíveis índices antigos em r2_key
  await migratorPool.query(`
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname='public' AND indexname='videos_r2_key_key') THEN
        EXECUTE 'DROP INDEX videos_r2_key_key';
      END IF;
      IF EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname='public' AND indexname='videos_r2_key_idx') THEN
        EXECUTE 'DROP INDEX videos_r2_key_idx';
      END IF;
    END $$;`);
  await migratorPool.query(`CREATE UNIQUE INDEX IF NOT EXISTS videos_course_r2_key_unique ON videos(course_id, r2_key)`);
}
migrate().catch(e=>console.error('migration error', e));


// ====== Clonar curso (formulário com lista de aulas + ferramentas por linha) ======
app.get('/admin/cursos/:id/clone', authRequired, adminRequired, async (req, res) => {
    const srcId = parseInt(req.params.id, 10);
  
    // curso origem
    const { rows: crs } = await pool.query('SELECT id,name,slug FROM courses WHERE id=$1', [srcId]);
    const c = crs[0];
    if (!c) return res.send(renderShell('Erro', '<div class="card">Curso não encontrado</div>'));
  
    // vídeos do curso origem (ordem por sort_index, depois id)
    const { rows: vids } = await pool.query(`
      SELECT id, title, r2_key, duration_seconds, sort_index
      FROM videos
      WHERE course_id=$1
      ORDER BY sort_index NULLS LAST, id ASC
    `, [srcId]);
  
    // linhas da tabela (cada vídeo com input de data e botões de ajuda)
    const rowsHtml = vids.map((v, i) => `
      <tr data-idx="${i}">
        <td style="white-space:nowrap">
          <strong>${safe(v.title)}</strong>
          <div class="mut"><code>${safe(v.r2_key)}</code></div>
        </td>
        <td style="width:240px">
          <input type="datetime-local" name="available_from[]" placeholder="(opcional)">
        </td>
        <td style="width:120px">
          <input type="number" name="sort_index[]" value="${v.sort_index ?? ''}" min="0" step="1" placeholder="ordem">
        </td>
        <td style="white-space:nowrap;vertical-align:top">
          <button type="button" class="btn-copy-prev" style="background:none;border:0;color:#007bff;cursor:pointer;padding:0">Copiar de cima</button>
          &nbsp;·&nbsp;
          <select class="dd-offset" style="min-width:90px">
            <option value="">+dias…</option>
            <option value="7">+7</option>
            <option value="14">+14</option>
            <option value="21">+21</option>
          </select>
          <button type="button" class="btn-apply" style="background:none;border:0;color:#007bff;cursor:pointer;padding:0">Aplicar</button>
          <input type="hidden" name="src_video_id[]" value="${v.id}">
        </td>
        
      </tr>
    `).join('');
  
    const html = `
      <div class="card">
        <div style="display:flex;justify-content:space-between;gap:12px;align-items:center">
          <h1>Clonar Curso: ${safe(c.name)} <span class="mut">(${safe(c.slug)})</span></h1>
          <div><a href="/admin/cursos">Voltar</a></div>
        </div>
  
        <form method="POST" action="/admin/cursos/${c.id}/clone" id="cloneForm">
          <div class="row">
            <div>
              <label>Novo nome</label>
              <input name="name" value="${safe(c.name)} 2" required>
            </div>
            <div>
              <label>Novo slug</label>
              <input name="slug" value="${safe(c.slug)}-novo" required>
            </div>
          </div>
          <div class="row">
            <div>
              <label>Data de início do novo curso (opcional)</label>
              <input name="start_date" placeholder="YYYY-MM-DD ou YYYY-MM-DDTHH:mm-03:00">
            </div>
            <div class="mut">
              As aulas serão clonadas com os mesmos títulos e R2 keys.
              Você pode definir aqui a <em>data de liberação</em> e a <em>ordem (sort_index)</em> de cada uma.
            </div>
          </div>
  
          <h3 class="mt2">Aulas do curso origem</h3>
          <table>
            <thead>
              <tr>
                <th>Título</th>
                <th>Disponível a partir</th>
                <th>Ordem (sort_index)</th>
                <th>Atalhos</th>
              </tr>
            </thead>
            <tbody id="vidTbody">
              ${rowsHtml || '<tr><td colspan="4" class="mut">Nenhuma aula neste curso.</td></tr>'}
            </tbody>
          </table>
  
          <div class="mt2">
            <button type="button" id="btnAutofillAll">Autopreencher em cascata (+7d)</button>
            <span class="mut">— a partir da 1ª linha</span>
          </div>
  
          <div class="mt2">
            <button type="submit">Clonar curso e aulas</button>
          </div>
        </form>
      </div>
  
      <script>
        (function(){
          const tbody = document.getElementById('vidTbody');
          function fmt(dt){
            const yyyy = dt.getFullYear().toString().padStart(4,'0');
            const mm   = (dt.getMonth()+1).toString().padStart(2,'0');
            const dd   = dt.getDate().toString().padStart(2,'0');
            const hh   = dt.getHours().toString().padStart(2,'0');
            const mi   = dt.getMinutes().toString().padStart(2,'0');
            return \`\${yyyy}-\${mm}-\${dd}T\${hh}:\${mi}\`;
          }
          function parseInput(val){
            if(!val) return null;
            const d = new Date(val);
            return isNaN(d.getTime()) ? null : d;
          }
  
          // Copiar data da linha anterior
          tbody.addEventListener('click', (ev)=>{
            if(!ev.target.classList.contains('btn-copy-prev')) return;
            const tr = ev.target.closest('tr');
            const idx = Number(tr.dataset.idx);
            if(idx <= 0) { alert('Não há linha anterior.'); return; }
            const prev = tbody.querySelector('tr[data-idx="'+(idx-1)+'"] input[name="available_from[]"]');
            const cur  = tr.querySelector('input[name="available_from[]"]');
            if(prev && cur){
              cur.value = prev.value || '';
            }
          });
  
          // Aplicar +dias baseado na linha anterior
          tbody.addEventListener('click', (ev)=>{
            if(!ev.target.classList.contains('btn-apply')) return;
            const tr = ev.target.closest('tr');
            const idx = Number(tr.dataset.idx);
            if(idx <= 0) { alert('Defina a data da linha anterior primeiro.'); return; }
            const prevVal = tbody.querySelector('tr[data-idx="'+(idx-1)+'"] input[name="available_from[]"]').value;
            const sel = tr.querySelector('select.dd-offset');
            const addDays = parseInt(sel.value,10);
            if(!addDays){ alert('Escolha +7, +14 ou +21d.'); return; }
            const base = parseInput(prevVal);
            if(!base){ alert('Linha anterior sem data válida.'); return; }
            const d = new Date(base.getTime());
            d.setDate(d.getDate() + addDays);
            tr.querySelector('input[name="available_from[]"]').value = fmt(d);
          });
  
          // Autopreencher tudo a partir da 1ª linha (+7d)
          document.getElementById('btnAutofillAll').addEventListener('click', ()=>{
            const rows = Array.from(tbody.querySelectorAll('tr'));
            if(rows.length < 2) return;
            const first = rows[0].querySelector('input[name="available_from[]"]').value;
            const base = parseInput(first);
            if(!base){ alert('Preencha a data da 1ª aula antes.'); return; }
            let cur = new Date(base.getTime());
            for(let i=1;i<rows.length;i++){
              cur = new Date(cur.getTime());
              cur.setDate(cur.getDate() + 7);
              rows[i].querySelector('input[name="available_from[]"]').value = fmt(cur);
            }
          });
        })();
      </script>
    `;
  
    res.send(renderShell('Clonar curso', html));
  });

// ====== Clonar curso (salvar curso + aulas + PDFs) ======
app.post('/admin/cursos/:id/clone', authRequired, adminRequired, async (req, res) => {
  const srcCourseId = parseInt(req.params.id, 10);
  let { name, slug, start_date } = req.body || {};

  // helpers
  const asArr = (v) => (v == null ? [] : Array.isArray(v) ? v : [v]);
  const trim  = (s) => (s == null ? '' : String(s).trim());
  // aceita tanto name="campo[]" quanto name="campo"
  const getArr = (base) => {
  const v = (req.body?.[`${base}[]`] ?? req.body?.[base] ?? []);
  return Array.isArray(v) ? v : (v != null ? [v] : []);
};


  name = trim(name);
  slug = trim(slug);
  if (!name || !slug) return res.status(400).send('Nome e slug são obrigatórios');

  // normaliza arrays vindos do form (quando há 1 item, vêm como string)
  const srcIds     = getArr('src_video_id').map(x => parseInt(x, 10)).filter(Number.isFinite);
let availInputs  = getArr('available_from').map(trim);
let sortInputs   = getArr('sort_index').map(trim);


  // alinha comprimentos para evitar desalinhamento por campos faltando
  if (availInputs.length < srcIds.length) availInputs = availInputs.concat(Array(srcIds.length - availInputs.length).fill(''));
  if (sortInputs.length  < srcIds.length) sortInputs  = sortInputs.concat(Array(srcIds.length  - sortInputs.length ).fill(''));

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // evitar 23505 em slug duplicado
    const slugExists = await client.query(`SELECT 1 FROM courses WHERE slug=$1 LIMIT 1`, [slug]);
    if (slugExists.rows[0]) {
      await client.query('ROLLBACK');
      return res.status(400).send('Slug já existe. Escolha outro.');
    }

    // 1) cria o novo curso e obtém newCourseId
    const startDateNorm = trim(start_date) ? (normalizeDateStr(trim(start_date)) || null) : null;
    const { rows: courseRows } = await client.query(
      `INSERT INTO courses(name, slug, start_date)
       VALUES ($1, $2, $3) RETURNING id`,
      [name, slug, startDateNorm]
    );
    const newCourseId = courseRows[0].id;

    // 2) busca os vídeos de origem selecionados
    if (srcIds.length) {
      const { rows: srcVids } = await client.query(
        `SELECT id, title, r2_key, duration_seconds, sort_index, available_from
           FROM videos
          WHERE course_id = $1
            AND id = ANY($2::int[])
          ORDER BY array_position($2::int[], id)`,
        [srcCourseId, srcIds]
      );
      const byId = new Map(srcVids.map(v => [v.id, v]));

      // 3) insere um-a-um na ORDEM do formulário e clona PDFs
      for (let i = 0; i < srcIds.length; i++) {
        const srcId = srcIds[i];
        const src = byId.get(srcId);
        if (!src) continue;

        const rawAvail = availInputs[i];
        const rawSort  = sortInputs[i];

        const available_from = rawAvail ? (normalizeDateStr(rawAvail) || null) : null;
        const sort_index = Number.isFinite(parseInt(rawSort, 10))
          ? parseInt(rawSort, 10)
          : (src.sort_index ?? null);

        // 3.1 cria o novo vídeo (RETURNING id)
        let newVideoId = null;
        try {
          const ins = await client.query(
            `INSERT INTO videos (title, r2_key, course_id, duration_seconds, available_from, sort_index)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id`,
            [src.title, src.r2_key, newCourseId, src.duration_seconds, available_from, sort_index]
          );
          newVideoId = ins.rows[0].id;
        } catch (e) {
          // fallback para o caso de ainda existir UNIQUE global em r2_key no ambiente atual
          if (String(e.code) === '23505') {
            const altKey = `${src.r2_key}-c${newCourseId}`;
            const ins2 = await client.query(
              `INSERT INTO videos (title, r2_key, course_id, duration_seconds, available_from, sort_index)
               VALUES ($1, $2, $3, $4, $5, $6)
               RETURNING id`,
              [src.title, altKey, newCourseId, src.duration_seconds, available_from, sort_index]
            );
            newVideoId = ins2.rows[0].id;
          } else {
            throw e;
          }
        }

        // 3.2 clona os PDFs (video_files) do vídeo origem
        const { rows: files } = await client.query(
          `SELECT label, r2_key, sort_index
             FROM video_files
            WHERE video_id = $1
            ORDER BY sort_index NULLS LAST, id`,
          [srcId]
        );

        for (const f of files) {
          await client.query(
            `INSERT INTO video_files (video_id, label, r2_key, sort_index)
             VALUES ($1, $2, $3, $4)`,
            [newVideoId, f.label, f.r2_key, f.sort_index]
          );
        }
      }
    }

    await client.query('COMMIT');
    res.redirect(`/admin/cursos/${newCourseId}`);
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch {}
    console.error('ADMIN CLONE POST ERROR', e);
    res.status(500).send('Falha ao clonar curso');
  } finally {
    client.release();
  }
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

function generateSignedUrlForKey(key, opts = {}) {
  const { contentType = 'video/mp4', disposition } = opts;
  if (!R2_BUCKET || !R2_ENDPOINT || !R2_ACCESS_KEY_ID || !R2_SECRET_ACCESS_KEY) return null;

  const urlObj = new URL(R2_ENDPOINT.replace(/\/+$/,''));
  const host = urlObj.host;

  const method = 'GET';
  const service = 's3';
  const region = 'auto';

  const encodedKey = String(key).split('/').map(encodeURIComponent).join('/');
  const canonicalUri = `/${encodeURIComponent(R2_BUCKET)}/${encodedKey}`;

  const now = new Date();
  const amzdate = now.toISOString().replace(/[:-]|\.\d{3}/g,''); // YYYYMMDDTHHMMSSZ
  const datestamp = amzdate.slice(0,8);
  const credentialScope = `${datestamp}/${region}/${service}/aws4_request`;

  const encodeRFC3986 = s => encodeURIComponent(s).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());

  const qp = [
    ['X-Amz-Algorithm','AWS4-HMAC-SHA256'],
    ['X-Amz-Credential', `${R2_ACCESS_KEY_ID}/${credentialScope}`],
    ['X-Amz-Date', amzdate],
    ['X-Amz-Expires', '86400'],
    ['X-Amz-SignedHeaders','host'],
  ];
  if (contentType) qp.push(['response-content-type', contentType]);
  if (disposition) qp.push(['response-content-disposition', disposition]);

  qp.sort((a,b)=> a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
  const canonicalQuerystring = qp.map(([k,v]) => `${encodeRFC3986(k)}=${encodeRFC3986(v)}`).join('&');

  const canonicalHeaders = `host:${host}\n`;
  const signedHeaders = 'host';
  const payloadHash = 'UNSIGNED-PAYLOAD';

  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQuerystring,
    canonicalHeaders,
    signedHeaders,
    payloadHash
  ].join('\n');

  // use top-level ESM import: crypto
  const algorithm = 'AWS4-HMAC-SHA256';
  const stringToSign = [
    algorithm,
    amzdate,
    credentialScope,
    crypto.createHash('sha256').update(canonicalRequest).digest('hex')
  ].join('\n');

  const kDate = crypto.createHmac('sha256', 'AWS4' + R2_SECRET_ACCESS_KEY).update(datestamp).digest();
  const kRegion = crypto.createHmac('sha256', kDate).update(region).digest();
  const kService = crypto.createHmac('sha256', kRegion).update(service).digest();
  const kSigning = crypto.createHmac('sha256', kService).update('aws4_request').digest();

  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex');

  return `${R2_ENDPOINT.replace(/\/+$/,'')}/${encodeURIComponent(R2_BUCKET)}/${encodedKey}?${canonicalQuerystring}&X-Amz-Signature=${signature}`;
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
  const right = `<div class="card">
  <h2>Acesso</h2>
  <p class="mut">Use o login/senha fornecidos pela coordenação.</p>
  <p class="mut mt"><a href="/solicitar-acesso">Não tenho acesso — quero solicitar</a></p>
  <p class="mut mt"><a href="/admin">Sou admin</a></p>
</div>`;

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

// ====== Solicitar acesso (público) ======
app.get('/solicitar-acesso', async (req, res) => {
  const { rows: courses } = await pool.query(`SELECT id, name, slug FROM courses WHERE archived=false ORDER BY name`);
  const options = ['<option value="">(Selecione o curso)</option>']
    .concat(courses.map(c => `<option value="${c.id}">${safe(c.name)} (${safe(c.slug)})</option>`))
    .join('');
  const html = `
    <div class="card">
      <h1>Solicitar acesso</h1>
      <form method="POST" action="/solicitar-acesso" class="mt2">
        <label>Nome completo</label><input name="full_name" required>
        <label>E-mail</label><input name="email" type="email" required>
        <label>Curso</label><select name="course_id" required>${options}</select>
        <label>Justificativa (opcional)</label><textarea name="justification" rows="4" placeholder="Conte brevemente por que precisa do acesso."></textarea>
        <button class="mt">Enviar solicitação</button>
      </form>
      <p class="mut mt">Nós vamos revisar seu pedido e, se aprovado, você receberá um e-mail com sua senha inicial.</p>
    </div>`;
  res.send(renderShell('Solicitar acesso', html));
});

app.post('/solicitar-acesso', async (req, res) => {
  try {
    let { full_name, email, course_id, justification } = req.body || {};
    full_name = (full_name||'').trim();
    email = (email||'').trim().toLowerCase();
    const cid = parseInt(course_id, 10);

    if (!full_name || !email || !Number.isFinite(cid)) {
      return res.status(400).send(renderShell('Solicitar acesso', `<div class="card"><h1>Dados inválidos</h1><p><a href="/solicitar-acesso">Voltar</a></p></div>`));
    }

    // (Opcional) restringir domínio se já usa ALLOWED_EMAIL_DOMAIN
    if (ALLOWED_EMAIL_DOMAIN && !email.endsWith(`@${ALLOWED_EMAIL_DOMAIN.toLowerCase()}`)) {
      return res.status(400).send(renderShell('Solicitar acesso', `<div class="card"><h1>Domínio de e-mail não permitido</h1><p class="mut">Use um endereço @${safe(ALLOWED_EMAIL_DOMAIN)}</p></div>`));
    }

    await pool.query(
      `INSERT INTO access_requests(full_name,email,course_id,justification)
       VALUES ($1,$2,$3,$4)`,
      [full_name, email, cid, (justification||'').trim() || null]
    );

    res.send(renderShell('Solicitação enviada', `
      <div class="card">
        <h1>Pedido recebido</h1>
        <p>Obrigado, <strong>${safe(full_name)}</strong>. Sua solicitação será analisada.</p>
        <p class="mut">Se aprovada, você receberá um e-mail com instruções de acesso.</p>
        <p><a href="/">Voltar à página inicial</a></p>
      </div>
    `));
  } catch (err) {
    console.error('ACCESS REQUEST ERROR', err);
    res.status(500).send(renderShell('Erro', `<div class="card"><h1>Falha ao enviar solicitação</h1><p class="mut">${safe(err.message||err)}</p></div>`));
  }
});


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
            `<a href="/admin/pendentes">Solicitações de acesso</a>`,
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

// ====== Relatórios (filtros + limpeza em lote + totais + negativos corrigido) ======
app.get('/admin/relatorios', authRequired, adminRequired, async (req, res) => {
  try {
    const { course_id, video_id, q, dt_from, dt_to, show_missing } = req.query;
    const activeOnly  = (req.query.active_only  ?? '1') === '1'; // default ligado
    const wantMissing = (show_missing ?? '0') === '1';

    // pct_min (ignorado no negativo)
    const rawPctMin = req.query.pct_min;
    const pctMin = Number.isFinite(parseFloat(rawPctMin))
      ? Math.max(0, Math.min(100, parseFloat(rawPctMin)))
      : null;

    // === combos ===
    const courses = (await pool.query(
      activeOnly
        ? 'SELECT id,name,slug FROM courses WHERE archived = false ORDER BY name'
        : 'SELECT id,name,slug FROM courses ORDER BY name'
    )).rows;

    const videos = course_id
      ? (await pool.query('SELECT id,title FROM videos WHERE course_id=$1 ORDER BY title', [course_id])).rows
      : [];

    const hasAnyFilter = Boolean(course_id || video_id || q || dt_from || dt_to || pctMin != null || activeOnly || wantMissing);

    let rows = [];
    let infoMsg = '';

    if (hasAnyFilter) {
      if (wantMissing) {
        // ================= RELATÓRIO NEGATIVO (matriculados sem atividade) =================
        if (!course_id) {
          infoMsg = 'Para relatório negativo, selecione um curso.';
          rows = [];
        } else {
          const params = [];
          const condEnroll = ['cm.course_id = $1'];
          params.push(course_id);

          if (activeOnly) condEnroll.push('c.archived = false');
          if (q) {
            params.push(`%${String(q).toLowerCase()}%`);
            condEnroll.push(`(LOWER(u.full_name) LIKE $${params.length} OR LOWER(u.email) LIKE $${params.length})`);
          }

          // Filtros de tempo (eventos e sessões)
          let evTime = '', sessTime = '';
          if (dt_from) { params.push(dt_from); evTime   += ` AND ev.client_ts >= $${params.length}`; }
          if (dt_to)   { params.push(dt_to);   evTime   += ` AND ev.client_ts <= $${params.length}`; }
          if (dt_from) { params.push(dt_from); sessTime += ` AND s.started_at >= $${params.length}`; }
          if (dt_to)   { params.push(dt_to);   sessTime += ` AND s.started_at <= $${params.length}`; }

          // CTE vids com numeração correta
          let vidsSql;
          if (video_id) {
            const vidIdx = params.length + 1;
            vidsSql = `SELECT id, title, duration_seconds FROM videos WHERE id = $${vidIdx}`;
            params.push(video_id);
          } else {
            vidsSql = `SELECT id, title, duration_seconds FROM videos WHERE course_id = $1`;
          }

          const sqlNeg = `
            WITH enrolled AS (
              SELECT u.id, u.full_name, u.email
              FROM course_members cm
              JOIN users   u ON u.id = cm.user_id
              JOIN courses c ON c.id = cm.course_id
              WHERE ${condEnroll.join(' AND ')}
            ),
            vids AS (${vidsSql}),
            activity_events AS (
              SELECT DISTINCT s.user_id, s.video_id
              FROM sessions s
              JOIN vids vv ON vv.id = s.video_id
              JOIN events ev ON ev.session_id = s.id
              WHERE 1=1 ${evTime}
            ),
            activity_ws AS (
              SELECT DISTINCT s.user_id, s.video_id
              FROM sessions s
              JOIN vids vv ON vv.id = s.video_id
              JOIN watch_segments ws ON ws.session_id = s.id
              WHERE 1=1 ${sessTime}
            ),
            activity AS (
              SELECT * FROM activity_events
              UNION
              SELECT * FROM activity_ws
            )
            ${video_id ? `
              SELECT e.id AS user_id, e.full_name, e.email,
                     v.id AS video_id, v.title, v.duration_seconds,
                     0::int AS max_time, 0::numeric AS pct
              FROM enrolled e
              CROSS JOIN vids v
              LEFT JOIN activity a ON a.user_id = e.id AND a.video_id = v.id
              WHERE a.user_id IS NULL
              ORDER BY e.full_name, v.title
              LIMIT 5000
            ` : `
              ,activity_any AS (SELECT DISTINCT user_id FROM activity)
              SELECT e.id AS user_id, e.full_name, e.email,
                     NULL::int AS video_id,
                     '(nenhuma aula do curso no período)'::text AS title,
                     NULL::int AS duration_seconds,
                     0::int AS max_time, 0::numeric AS pct
              FROM enrolled e
              LEFT JOIN activity_any a ON a.user_id = e.id
              WHERE a.user_id IS NULL
              ORDER BY e.full_name
              LIMIT 5000
            `}
          `;

          rows = (await pool.query(sqlNeg, params)).rows;
        }

      } else {
        // ================= RELATÓRIO POSITIVO (assistiram; com segmentos) =================
        const whereBase = [];
        const whereTime = [];
        const params = [];

        if (course_id) { params.push(course_id); whereBase.push(`v.course_id = $${params.length}`); }
        if (video_id)  { params.push(video_id);  whereBase.push(`v.id = $${params.length}`); }
        if (q) {
          params.push(`%${String(q).toLowerCase()}%`);
          whereBase.push(`(LOWER(u.full_name) LIKE $${params.length} OR LOWER(u.email) LIKE $${params.length} OR LOWER(v.title) LIKE $${params.length})`);
        }
        if (activeOnly) { whereBase.push(`c.archived = false`); }

        if (dt_from)   { params.push(dt_from); whereTime.push(`e.client_ts >= $${params.length}`); }
        if (dt_to)     { params.push(dt_to);   whereTime.push(`e.client_ts <= $${params.length}`); }

        const baseSql = whereBase.length ? `WHERE ${whereBase.join(' AND ')}` : '';
        const timeSql =
          whereTime.length
            ? `AND EXISTS (SELECT 1 FROM events e WHERE e.session_id = s.id AND ${whereTime.join(' AND ')})`
            : '';

        const sql = `
          WITH base AS (
            SELECT u.id AS user_id, u.full_name, u.email,
                   v.id AS video_id, v.title, v.duration_seconds
            FROM sessions s
            JOIN users   u ON u.id = s.user_id
            JOIN videos  v ON v.id = s.video_id
            JOIN courses c ON c.id = v.course_id
            ${baseSql}
            ${timeSql}
            GROUP BY u.id, u.full_name, u.email, v.id, v.title, v.duration_seconds
          ),
          segs AS (
            SELECT s.user_id, s.video_id, v.duration_seconds,
                   GREATEST(0, LEAST(ws.start_sec, v.duration_seconds)) AS s,
                   GREATEST(0, LEAST(ws.end_sec,   v.duration_seconds)) AS e
            FROM sessions s
            JOIN videos v          ON v.id = s.video_id
            JOIN courses c         ON c.id = v.course_id
            JOIN watch_segments ws ON ws.session_id = s.id
            ${baseSql}
            ${timeSql}
          ),
          ordered AS (
            SELECT *, LAG(e) OVER (PARTITION BY user_id, video_id ORDER BY s, e) AS prev_e
            FROM segs
          ),
          grp AS (
            SELECT *, SUM(CASE WHEN prev_e IS NULL OR s > prev_e THEN 1 ELSE 0 END)
              OVER (PARTITION BY user_id, video_id ORDER BY s, e) AS g
            FROM ordered
          ),
          merged AS (
            SELECT user_id, video_id, duration_seconds, MIN(s) AS s, MAX(e) AS e
            FROM grp
            GROUP BY user_id, video_id, duration_seconds, g
          ),
          watched AS (
            SELECT user_id, video_id, duration_seconds,
                   SUM(GREATEST(e - s, 0)) AS watched_sec,
                   MAX(e) AS max_end
            FROM merged
            GROUP BY user_id, video_id, duration_seconds
          ),
          ev AS (
            SELECT s.user_id, s.video_id, MAX(e.video_time) AS max_time
            FROM sessions s
            JOIN events e ON e.session_id = s.id
            JOIN videos v ON v.id = s.video_id
            JOIN courses c ON c.id = v.course_id
            ${baseSql}
            ${whereTime.length ? `AND ${whereTime.join(' AND ')}` : ''}
            GROUP BY s.user_id, s.video_id
          ),
          enriched AS (
            SELECT b.user_id, b.full_name, b.email,
                   b.video_id, b.title, b.duration_seconds,
                   COALESCE(w.max_end, ev.max_time, 0) AS max_pos,
                   CASE
                     WHEN b.duration_seconds IS NULL OR b.duration_seconds <= 0 THEN NULL
                     WHEN w.watched_sec IS NOT NULL THEN LEAST(w.watched_sec, b.duration_seconds) * 100.0 / b.duration_seconds
                     WHEN ev.max_time    IS NOT NULL THEN LEAST(GREATEST(ev.max_time,0), b.duration_seconds) * 100.0 / b.duration_seconds
                     ELSE 0
                   END AS pct
            FROM base b
            LEFT JOIN watched w ON w.user_id = b.user_id AND w.video_id = b.video_id
            LEFT JOIN ev      ev ON ev.user_id = b.user_id AND ev.video_id = b.video_id
          )
          SELECT user_id, full_name, email, video_id, title, duration_seconds,
                 max_pos AS max_time,
                 CASE WHEN pct IS NULL THEN NULL ELSE ROUND(pct::numeric, 1) END AS pct
          FROM enriched
          ${pctMin != null ? `WHERE pct IS NOT NULL AND pct >= $${params.length + 1}` : ``}
          ORDER BY full_name, title
          LIMIT 5000
        `;
        if (pctMin != null) params.push(pctMin);
        rows = (await pool.query(sql, params)).rows;
      }
    }

    // vídeos distintos (para limpeza) só no positivo
    const distinctVideos = [];
    if (hasAnyFilter && rows.length && !wantMissing) {
      const seen = new Set();
      for (const r of rows) if (r.video_id && !seen.has(r.video_id)) {
        seen.add(r.video_id);
        distinctVideos.push({ id: r.video_id, title: r.title });
      }
    }

    // === Totais ===
    const totalRegistros   = rows.length;
    const alunosDistintos  = new Set(rows.map(r => r.user_id)).size;
    const pctVals = (!wantMissing)
      ? rows.map(r => (typeof r.pct === 'number' ? r.pct : null)).filter(v => v != null)
      : [];
    const mediaPct = (pctVals.length ? (pctVals.reduce((a,b)=>a+b,0) / pctVals.length).toFixed(1) : null);

    const totalsHtml = totalRegistros ? `
      <tfoot>
        <tr style="font-weight:bold;background:#20242b">
          <td colspan="3">Totais</td>
          <td colspan="2">${totalRegistros} registro(s) · ${alunosDistintos} aluno(s)</td>
          <td>${(!wantMissing && mediaPct != null) ? `Média: ${mediaPct}%` : '—'}</td>
        </tr>
      </tfoot>` : '';

    // combos HTML
    const courseOpts = ['<option value="">(Todos)</option>']
      .concat(courses.map(c =>
        `<option value="${c.id}" ${String(c.id) === String(course_id) ? 'selected' : ''}>${safe(c.name)}</option>`
      )).join('');
    const videoOpts = ['<option value="">(Todos)</option>']
      .concat(videos.map(v =>
        `<option value="${v.id}" ${String(v.id) === String(video_id) ? 'selected' : ''}>${safe(v.title)}</option>`
      )).join('');

    const tableBody = hasAnyFilter
      ? (rows.map(r => `
           <tr>
             <td>${safe(r.full_name || '-')}</td>
             <td>${safe(r.email)}</td>
             <td>${safe(r.title || (wantMissing ? '(sem vídeo específico)' : '—'))}</td>
             <td>${r.duration_seconds ?? '—'}</td>
             <td>${r.max_time ?? 0}</td>
             <td>${r.pct == null ? '—' : r.pct + '%'}</td>
           </tr>
         `).join('') || '<tr><td colspan="6" class="mut">Sem dados para os filtros.</td></tr>')
      : '<tr><td colspan="6" class="mut">Aplique algum filtro e clique em “Aplicar filtros”.</td></tr>';

    // CSV (só no positivo)
    const csvLink = `/admin/relatorios.csv?` + new URLSearchParams({
      course_id: course_id || '',
      video_id:  video_id  || '',
      q:         q || '',
      dt_from:   dt_from || '',
      dt_to:     dt_to || '',
      pct_min:   pctMin ?? '',
      active_only: activeOnly ? '1' : '0'
    }).toString();
    const csvHtml = wantMissing
      ? '<span class="mt mut" style="margin-left:12px;display:inline-block">CSV indisponível para relatório negativo</span>'
      : `<a class="mt" href="${csvLink}" style="margin-left:12px;display:inline-block">Exportar CSV</a>`;

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
              <select name="video_id"${wantMissing ? '' : ''}>${videoOpts}</select>
            </div>
            <div style="display:flex;align-items:center;gap:10px;margin-top:22px;flex-wrap:wrap">
              <label style="display:flex;align-items:center;gap:6px;margin:0">
                <input type="checkbox" id="active_only" name="active_only" value="1" ${activeOnly ? 'checked' : ''}>
                <span>Apenas cursos ativos</span>
              </label>
              <label style="display:flex;align-items:center;gap:6px;margin:0">
                <input type="checkbox" id="show_missing" name="show_missing" value="1" ${wantMissing ? 'checked' : ''}>
                <span>Mostrar negativos (não assistiram)</span>
              </label>
            </div>
          </div>
          <div class="row">
            <div>
              <label>Aluno (nome/email)</label>
              <input name="q" value="${safe(q||'')}" placeholder="ex.: maria@ / João">
            </div>
            <div>
              <label>De</label>
              <input name="dt_from" value="${safe(dt_from||'')}" placeholder="2025-08-01T00:00:00-03:00">
            </div>
            <div>
              <label>Até</label>
              <input name="dt_to" value="${safe(dt_to||'')}" placeholder="2025-08-31T23:59:59-03:00">
            </div>
            <div>
              <label>Mínimo % assistido (≥) ${wantMissing ? '<span class="mut">(ignorado no negativo)</span>' : ''}</label>
              <input name="pct_min" type="number" min="0" max="100" step="0.1" value="${wantMissing ? '' : (pctMin ?? '')}" ${wantMissing ? 'disabled' : ''}>
            </div>
          </div>
          <button class="mt">Aplicar filtros</button>
          ${csvHtml}
          <a class="mt" href="/admin/relatorio/raw" style="margin-left:12px;display:inline-block">Ver eventos brutos</a>
          ${infoMsg ? `<div class="mut mt">${safe(infoMsg)}</div>` : ''}
        </form>

        ${(!wantMissing && hasAnyFilter) ? `
          <div class="card mt2" style="border:1px solid #ddd">
            <h2 style="margin-top:0">Limpeza em lote (vídeos no resultado atual)</h2>
            <form method="POST" action="/admin/relatorios/clear-batch" id="batchClearForm">
              <div class="mt">
                <button type="button" class="linklike" id="selAll">Selecionar todos</button> ·
                <button type="button" class="linklike" id="selNone">Limpar seleção</button>
              </div>
              <div class="mt" style="columns:2;max-width:720px">
                ${distinctVideos.length ? distinctVideos.map(v =>
                  `<label style="display:block"><input type="checkbox" name="video_ids[]" value="${v.id}"> ${safe(v.title)} (ID ${v.id})</label>`
                ).join('') : '<span class="mut">Nenhum vídeo no resultado atual.</span>'}
              </div>
              <input type="hidden" name="redirect" value="${safe(req.url)}">
              <div class="mt">
                <button ${distinctVideos.length ? '' : 'disabled'} onclick="return confirm('Remover TODOS os eventos e sessões dos vídeos selecionados?');">Limpar relatórios selecionados</button>
              </div>
            </form>
          </div>` : ''
        }

        <table class="mt2">
          <thead>
            <tr><th>Nome</th><th>Email</th><th>Vídeo</th><th>Duração (s)</th><th>Max pos (s)</th><th>% assistido</th></tr>
          </thead>
          <tbody>${tableBody}</tbody>
          ${totalsHtml}
        </table>
      </div>

      <style>.linklike{background:none;border:0;padding:0;color:#8fb6ff;cursor:pointer}</style>
      <script>
        (function(){
          const root = document.getElementById('batchClearForm');
          if(!root) return;
          const selAll  = document.getElementById('selAll');
          const selNone = document.getElementById('selNone');
          selAll  && selAll.addEventListener('click', ()=>{ root.querySelectorAll('input[type=checkbox]').forEach(ch=>ch.checked=true); });
          selNone && selNone.addEventListener('click', ()=>{ root.querySelectorAll('input[type=checkbox]').forEach(ch=>ch.checked=false); });
        })();
      </script>
    `;

    res.send(renderShell('Relatórios', html));
  } catch (err) {
    console.error('RELATORIOS ERROR', err);
    res.status(500).send(renderShell('Erro', `<div class="card"><h1>Falha ao abrir relatórios</h1><p class="mut">${safe(err.message||err)}</p></div>`));
  }
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

    const addVideoFormHtml = `
      <div class="card">
        <h2>Adicionar nova aula ao curso</h2>
        <form method="POST" action="/admin/cursos/${curso.id}/videos/add" class="mt2">
          <div class="row">
            <div>
              <label>Título</label>
              <input name="title" required placeholder="Ex.: Aula 05 — Antibioticoterapia">
            </div>
            <div>
              <label>Duração (segundos)</label>
              <input name="duration_seconds" type="number" min="0" placeholder="Ex.: 1800">
            </div>
          </div>
          <div class="row">
            <div>
              <label>R2 Key (vídeo)</label>
              <input name="r2_key" required placeholder="Ex.: videos/2025/aula05.mp4">
              <p class="mut">A URL assinada é gerada em tempo de execução; aqui vai apenas a <b>R2 key</b>.</p>
            </div>
            <div>
              <label>Disponível a partir de</label>
              <input name="available_from" type="datetime-local" placeholder="opcional">
            </div>
          </div>
          <div class="row">
            <div>
              <label>Ordem (sort_index)</label>
              <input name="sort_index" type="number" placeholder="opcional">
            </div>
          </div>
          <button class="mt">Adicionar aula</button>
        </form>
      </div>
    `;

    // --- lista alunos matriculados neste curso ---
    const { rows: members } = await pool.query(
      `SELECT u.id AS user_id, u.full_name, u.email,
              cm.expires_at AS member_expires_at
         FROM course_members cm
         JOIN users u ON u.id = cm.user_id
        WHERE cm.course_id = $1
        ORDER BY u.full_name NULLS LAST, u.email`,
      [courseId]
    );

    const membersRows = members.map(m => `
      <tr>
        <td>${safe(m.full_name) || '-'}</td>
        <td>${safe(m.email)}</td>
        <td>${fmt(m.member_expires_at) || '<span class="mut">—</span>'}</td>
        <td style="white-space:nowrap">
          <form class="inline" method="POST" action="/admin/cursos/${courseId}/matriculas/${m.user_id}/validade" style="display:inline-block;margin-right:8px">
            <input type="datetime-local" name="member_expires_at" style="max-width:220px">
            <button>Atualizar validade</button>
          </form>
          · <a href="/admin/alunos/${m.user_id}/relatorio?course_id=${courseId}">relatório do aluno</a>
        </td>
      </tr>
    `).join('');

    // Converte timestamptz -> <input type="datetime-local">
    const tsToLocalInput = (ts) => {
      if (!ts) return '';
      const d = new Date(ts);
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
        <td style="white-space:nowrap">
          <form method="POST"
                action="/admin/cursos/${curso.id}/videos/${v.id}/delete"
                class="inline"
                onsubmit="return confirm('Excluir a aula &quot;${safe(v.title)}&quot;? Isso removerá relatórios desse vídeo.');">
            <button class="linkbutton" type="submit">Excluir</button>
          </form>
        </td>
      </tr>
    `).join('');

    const html = `
      <div class="card">
        <div class="right" style="justify-content:space-between">
          <h1>Gerenciar Curso: ${safe(curso.name)} ${curso.archived ? '<span class="mut">(arquivado)</span>' : ''}</h1>
          <div><a href="/admin/cursos">Voltar</a></div>
        </div>
        <p class="mut">Slug: <code>${safe(curso.slug)}</code></p>

        ${addVideoFormHtml}

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
                <th>Ações</th>
              </tr>
            </thead>
            <tbody>
              ${rowsHtml || '<tr><td colspan="8" class="mut">Nenhum vídeo neste curso.</td></tr>'}
            </tbody>
          </table>

          <div class="mt2">
            <button type="submit">Salvar alterações</button>
          </div>
        </form>
      </div>

      <div class="card">
        <h2 class="mt0">Alunos matriculados neste curso</h2>
        <table>
          <thead>
            <tr><th>Nome</th><th>Email</th><th>Validade da matrícula</th><th>Ações</th></tr>
          </thead>
          <tbody>
            ${membersRows || '<tr><td colspan="4" class="mut">Nenhum aluno matriculado.</td></tr>'}
          </tbody>
        </table>

        <h3 class="mt2">Adicionar aluno manualmente a este curso</h3>
        <form method="POST" action="/admin/cursos/${curso.id}/alunos/add">
          <div class="row">
            <div>
              <label>Nome completo</label>
              <input name="full_name" required>
              <label>Senha inicial</label>
              <input name="password" type="text" placeholder="ex.: Abc123456" required>
              <label>Validade (usuário, opcional)</label>
              <input name="user_expires_at" type="datetime-local">
            </div>
            <div>
              <label>Email</label>
              <input name="email" type="email" required>
              <label>Validade (matrícula no curso, opcional)</label>
              <input name="member_expires_at" type="datetime-local">
              <div class="mut" style="margin-top:8px">Se o e-mail já existir, o aluno é reaproveitado e apenas a matrícula é criada/atualizada.</div>
            </div>
          </div>
          <button class="mt">Adicionar aluno ao curso</button>
        </form>
      </div>

      <style>.linkbutton{background:none;border:0;color:#8fb6ff;cursor:pointer;padding:0}</style>
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
    res.status(500).send(renderShell('Erro', `<div class="card"><h1>Falha ao carregar</h1><p class="mut">${safe(err.message||err)}</p></div>`));
  }
});

// ====== Admin: adicionar aula manualmente a um curso ======
app.post('/admin/cursos/:id/videos/add', authRequired, adminRequired, async (req, res) => {
  const courseId = parseInt(req.params.id, 10);
  try {
    let { title, r2_key, duration_seconds, available_from, sort_index } = req.body || {};
    if (!courseId || !r2_key || !title) {
      return res.status(400).send('Título e R2 key são obrigatórios');
    }

    // Normalizações
    title = String(title).trim();
    r2_key = String(r2_key).trim();
    duration_seconds = duration_seconds ? parseInt(duration_seconds, 10) : null;
    sort_index = (sort_index !== '' && sort_index != null) ? parseInt(sort_index, 10) : null;

    // available_from com helper
    const avail = normalizeDateStr ? (normalizeDateStr(available_from) || null) : (available_from || null);

    await pool.query(
      `INSERT INTO videos (title, r2_key, course_id, duration_seconds, available_from, sort_index)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [title, r2_key, courseId, duration_seconds, avail, sort_index]
    );

    res.redirect(`/admin/cursos/${courseId}`);
  } catch (err) {
    console.error('ADMIN ADD VIDEO ERROR', err);
    res.status(500).send(renderShell('Erro', `
      <div class="card">
        <h1>Falha ao adicionar aula</h1>
        <p class="mut">${safe(err.message || String(err))}</p>
        <div class="mt"><a href="/admin/cursos/${req.params.id}">Voltar</a></div>
      </div>
    `));
  }
});

// ====== Admin: deletar aula de um curso ======
app.post('/admin/cursos/:id/videos/:vid/delete', authRequired, adminRequired, async (req, res) => {
  const courseId = parseInt(req.params.id, 10);
  const videoId  = parseInt(req.params.vid, 10);
  try {
    if (!courseId || !videoId) return res.status(400).send('IDs inválidos');

    // ON DELETE CASCADE já limpa sessions/events/video_files ligados a esse vídeo
    await pool.query('DELETE FROM videos WHERE id=$1 AND course_id=$2', [videoId, courseId]);

    res.redirect(`/admin/cursos/${courseId}`);
  } catch (err) {
    console.error('ADMIN DELETE VIDEO ERROR', err);
    res.status(500).send(renderShell('Erro', `
      <div class="card">
        <h1>Falha ao remover aula</h1>
        <p class="mut">${safe(err.message || String(err))}</p>
        <div class="mt"><a href="/admin/cursos/${req.params.id}">Voltar</a></div>
      </div>
    `));
  }
});
  // ====== Admin: atualizar validade da matrícula de um aluno neste curso ======
app.post('/admin/cursos/:courseId/matriculas/:userId/validade', adminRequired, async (req, res) => {
    try {
      const courseId = parseInt(req.params.courseId, 10);
      const userId   = parseInt(req.params.userId, 10);
      if (!Number.isFinite(courseId) || !Number.isFinite(userId)) {
        return res.status(400).send('Parâmetros inválidos');
      }
  
      const memberExp = normalizeDateStr(req.body?.member_expires_at) || null;
  
      // Garante que o curso existe
      const c = (await pool.query('SELECT id FROM courses WHERE id=$1', [courseId])).rows[0];
      if (!c) return res.status(404).send('Curso não encontrado');
  
      // Se a matrícula não existir, cria; se existir, atualiza validade
      await pool.query(
        `INSERT INTO course_members(user_id, course_id, role, expires_at)
         VALUES ($1,$2,'student',$3)
         ON CONFLICT (user_id, course_id)
         DO UPDATE SET expires_at = EXCLUDED.expires_at`,
        [userId, courseId, memberExp]
      );
  
      res.redirect(`/admin/cursos/${courseId}`);
    } catch (err) {
      console.error('ADMIN UPDATE MEMBER VALIDITY ERROR', err);
      res.status(500).send('Falha ao atualizar validade da matrícula');
    }
  });

  // ====== Admin: adicionar aluno manualmente e matricular no curso ======
app.post('/admin/cursos/:courseId/alunos/add', adminRequired, async (req, res) => {
    try {
      const courseId = parseInt(req.params.courseId, 10);
      if (!Number.isFinite(courseId)) return res.status(400).send('courseId inválido');
  
      let { full_name, email, password, user_expires_at, member_expires_at } = req.body || {};
      if (!full_name || !email || !password) return res.status(400).send('Dados obrigatórios');
  
      email = String(email).trim().toLowerCase();
  
      // (opcional) Respeita domínio institucional, se você já usa essa env:
      if (typeof ALLOWED_EMAIL_DOMAIN !== 'undefined' && ALLOWED_EMAIL_DOMAIN) {
        if (!email.endsWith(`@${ALLOWED_EMAIL_DOMAIN.toLowerCase()}`)) {
          return res.status(400).send('Domínio de email inválido');
        }
      }
  
      const userExp   = normalizeDateStr(user_expires_at)   || null;
      const memberExp = normalizeDateStr(member_expires_at) || null;
  
      // Cria ou reaproveita usuário por email
      const u = (await pool.query('SELECT id FROM users WHERE email=$1', [email])).rows[0];
      let userId;
  
      if (u) {
        userId = u.id;
        // Atualiza nome e (se desejar) a validade do usuário
        await pool.query(
          'UPDATE users SET full_name = COALESCE($1, full_name), expires_at = COALESCE($2, expires_at) WHERE id=$3',
          [full_name || null, userExp, userId]
        );
        // Atualiza senha se enviada (conforme seu fluxo atual)
        if (password && String(password).trim()) {
          const hash = await bcrypt.hash(password, 10);
          await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2', [hash, userId]);
        }
      } else {
        const hash = await bcrypt.hash(password, 10);
        const ins = await pool.query(
          'INSERT INTO users(full_name,email,password_hash,expires_at) VALUES($1,$2,$3,$4) RETURNING id',
          [full_name, email, hash, userExp]
        );
        userId = ins.rows[0].id;
      }
  
      // Matricula (upsert) no curso alvo
      await pool.query(
        `INSERT INTO course_members(user_id,course_id,role,expires_at)
         VALUES ($1,$2,'student',$3)
         ON CONFLICT (user_id,course_id)
         DO UPDATE SET expires_at = EXCLUDED.expires_at`,
        [userId, courseId, memberExp]
      );
  
      res.redirect(`/admin/cursos/${courseId}`);
    } catch (err) {
      console.error('ADMIN ADD STUDENT TO COURSE ERROR', err);
      res.status(500).send('Falha ao adicionar aluno ao curso');
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
  <a href="/admin/cursos/${c.id}/clone">clonar</a> ·
  ${c.archived
    ? `<form style="display:inline" method="POST" action="/admin/cursos/${c.id}/unarchive">
         <button style="background:none;border:0;padding:0;color:#007bff;cursor:pointer">desarquivar</button>
       </form>`
    : `<form style="display:inline" method="POST" action="/admin/cursos/${c.id}/archive">
         <button style="background:none;border:0;padding:0;color:#007bff;cursor:pointer">arquivar</button>
       </form>`
  }
  · <form style="display:inline" method="POST" action="/admin/cursos/${c.id}/delete" onsubmit="return confirm('Apagar curso? Só permitido se não tiver aulas/matrículas.');">
      <button style="background:none;border:0;padding:0;color:#007bff;cursor:pointer">apagar</button>
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

    const { rows: files } = await pool.query(
      `SELECT id, label, r2_key, sort_index FROM video_files WHERE video_id=$1 ORDER BY sort_index NULLS LAST, id ASC`,
      [id]
    );
    const filesRows = files.map(f => `
      <tr>
        <td>${safe(f.label)}</td>
        <td><code>${safe(f.r2_key)}</code></td>
        <td>${f.sort_index ?? ''}</td>
        <td>
          <form method="POST" action="/admin/videos/${id}/pdfs/${f.id}/delete" onsubmit="return confirm('Remover este PDF?')">
            <button type="submit">remover</button>
          </form>
        </td>
      </tr>`).join('');
    const filesHtml = `
      <h3 class="mt">Materiais (PDFs)</h3>
      <table>
        <thead><tr><th>Título</th><th>R2 key</th><th>ordem</th><th></th></tr></thead>
        <tbody>${filesRows || '<tr><td colspan="4" class="mut">Nenhum PDF</td></tr>'}</tbody>
      </table>
      <h4 class="mt">Adicionar PDF</h4>
      <form method="POST" action="/admin/videos/${id}/pdfs">
        <div>Título<br><input name="label" required></div>
        <div>R2 key (no mesmo bucket do vídeo)<br><input name="r2_key" required></div>
        <div>Ordem (opcional)<br><input name="sort_index" type="number"></div>
        <p><button type="submit">Adicionar</button></p>
      </form>`;

    
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
        ${filesHtml}
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

app.post('/admin/videos/:id/pdfs', adminRequired, async (req, res) => {
  try{
    const videoId = parseInt(req.params.id, 10);
    let { label, r2_key, sort_index } = req.body || {};
    if (!label || !r2_key) return res.status(400).send('Título e R2 key são obrigatórios');
    const si = (sort_index === '' || sort_index == null) ? null : parseInt(sort_index, 10);
    await pool.query(
      `INSERT INTO video_files (video_id, label, r2_key, sort_index) VALUES ($1, $2, $3, $4)`,
      [videoId, label, r2_key, Number.isFinite(si) ? si : null]
    );
    res.redirect(`/admin/videos/${videoId}/edit`);
  }catch(err){
    console.error('ADMIN ADD PDF ERROR', err);
    res.status(500).send('Falha ao adicionar PDF');
  }
});
app.post('/admin/videos/:videoId/pdfs/:pdfId/delete', adminRequired, async (req, res) => {
  try{
    const videoId = parseInt(req.params.videoId, 10);
    const pdfId   = parseInt(req.params.pdfId, 10);
    await pool.query('DELETE FROM video_files WHERE id=$1 AND video_id=$2', [pdfId, videoId]);
    res.redirect(`/admin/videos/${videoId}/edit`);
  }catch(err){
    console.error('ADMIN DEL PDF ERROR', err);
    res.status(500).send('Falha ao remover PDF');
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

  // opcional: a UI pode mandar para onde voltar após limpar
  const redirect = req.body?.redirect || `/admin/relatorio/${videoId}`;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1) apaga eventos ligados às sessões do vídeo
    await client.query(
      `DELETE FROM events
         WHERE session_id IN (SELECT id FROM sessions WHERE video_id = $1)`,
      [videoId]
    );

    // 2) (se você usa watch_segments) apaga também os segmentos assistidos
    //    - só terá efeito se a sua tabela existir
    try {
      await client.query(
        `DELETE FROM watch_segments
           WHERE session_id IN (SELECT id FROM sessions WHERE video_id = $1)`,
        [videoId]
      );
    } catch (e) {
      // tabela pode não existir; segue o jogo
    }

    // 3) por último, remove as próprias sessões
    await client.query(`DELETE FROM sessions WHERE video_id = $1`, [videoId]);

    await client.query('COMMIT');

    res.redirect(redirect);
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

// Cadastro manual de aluno + envio de credenciais
app.post('/admin/alunos', adminRequired, async (req, res) => {
    try {
      let { full_name, email, password, user_expires_at, course_id, member_expires_at } = req.body || {};
      if (!full_name || !email || !password) return res.status(400).send('Dados obrigatórios');
  
      email = String(email).trim().toLowerCase();
      if (ALLOWED_EMAIL_DOMAIN && !email.endsWith(`@${ALLOWED_EMAIL_DOMAIN.toLowerCase()}`)) {
        return res.status(400).send('Domínio inválido');
      }
  
      const userExp = normalizeDateStr(user_expires_at) || SEMESTER_END || null;
  
      const plain = String(password).trim();         // senha em claro
      const hash  = await bcrypt.hash(plain, 10);    // hash para login
  
      // grava temp_password para poder enviar por e-mail
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
  
      // dispara o e-mail (controlado por env)
      if (process.env.SEND_WELCOME_ON_CREATE === '1') {
        try {
          await sendWelcomeAndMark({
            userId,
            email,
            name: full_name,
            login: email,
            plain
          });
        } catch (e) {
          console.error('WELCOME EMAIL (manual) ERROR', e);
          // segue o fluxo mesmo que falhe o envio
        }
      }
  
      res.redirect('/admin/alunos');
    } catch (err) {
      console.error('ADMIN STUDENTS CREATE ERROR', err);
      res.status(500).send('Falha ao criar aluno');
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
  
      const signedUrl = generateSignedUrlForKey(v.r2_key, { contentType: 'video/mp4' });
      const uidForSession = req.user.id; // registra sessão do admin ou aluno
      const ins = await pool.query('INSERT INTO sessions(user_id,video_id) VALUES($1,$2) RETURNING id', [uidForSession, videoId]);
      const sessionId = ins.rows[0].id;
      const wm = (req.user.full_name || req.user.email || '').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  
      
// Materiais (PDFs)
const { rows: pdfFiles } = await pool.query(
  'SELECT id, label, r2_key FROM video_files WHERE video_id=$1 ORDER BY sort_index NULLS LAST, id ASC',
  [videoId]
);

// monta a lista apenas com PDFs (pelo label conter “pdf” ou a key terminar com .pdf)
const pdfList = (pdfFiles || [])
  .filter(f => {
    const lbl = String(f.label || '').toLowerCase();
    const key = String(f.r2_key || '').toLowerCase();
    return lbl.includes('pdf') || key.endsWith('.pdf');
  })
  .map(f => {
    // nome amigável/seguro para o filename
    const raw = String(f.label || 'material').replace(/["<>\r\n]+/g, ' ').trim() || 'material';
    const base = raw.replace(/\.pdf$/i, '');
    const href = generateSignedUrlForKey(f.r2_key, {
      contentType: 'application/pdf',
      disposition: `attachment; filename="${encodeURIComponent(base)}.pdf"`
    });
    return `<li><a href="${href}">Baixar ${safe(f.label || f.r2_key)} (PDF)</a></li>`;
  })
  .join('');

const pdfBlock = pdfList ? `<h3 class="mt2">Materiais (PDFs)</h3><ul>${pdfList}</ul>` : '';

// ===== body inteiro dentro de um único template string =====
const body = `
  <div class="card">
    <div class="right" style="justify-content:space-between;gap:12px">
      <h1 style="margin:0">${safe(v.title)}</h1>
      <div><a href="/logout">Sair</a></div>
    </div>
    <p class="mut">Curso: ${safe(v.course_name)} ${admin ? '· <strong>(ADMIN)</strong>' : ''}</p>

    <div class="video">
      <video id="player" controls playsinline preload="metadata" controlsList="nodownload" oncontextmenu="return false" style="width:100%;height:100%">
        ${signedUrl ? `<source src="${signedUrl}" type="video/mp4" />` : ''}
      </video>
      <div class="wm">${wm}</div>
    </div>

    ${pdfBlock}
  </div>

  <script>
  (function(){
    const video = document.getElementById('player');
    const sessionId = ${sessionId};

    // ————— Segmentos efetivamente assistidos —————
    let playing = false;
    let segStart = null;   // início do trecho realmente tocado
    let lastT = 0;
    let lastSentAt = 0;

    function now(){ return Date.now(); }

    function sendSegment(start, end){
      if (start == null) return;
      const a = Math.floor(Math.max(0, start));
      const b = Math.floor(Math.max(0, end));
      if (b > a) {
        fetch('/track/segment', {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ sessionId, startSec:a, endSec:b })
        }).catch(()=>{});
      }
    }

    // começou a tocar → abre segmento
    video.addEventListener('play', ()=>{
      playing = true;
      segStart = Math.floor(video.currentTime || 0);
      lastT = segStart;
    });

    // tocando: fecha bloco se houver pulo, e envia parciais a cada ~10s
    video.addEventListener('timeupdate', ()=>{
      if (!playing) return;
      const t = Math.floor(video.currentTime || 0);

      // salto p/ trás ou p/ frente > 5s → fecha segmento anterior
      if (segStart != null && (t < lastT || t - lastT > 5)) {
        sendSegment(segStart, lastT);
        segStart = t; // reabre a partir do novo ponto
      }
      lastT = t;

      // envia a cada 10s para não acumular demais
      if (now() - lastSentAt > 10000 && segStart != null && lastT > segStart) {
        sendSegment(segStart, lastT);
        segStart = lastT; // novo bloco começa aqui
        lastSentAt = now();
      }
    });

    // pausou → fecha segmento
    video.addEventListener('pause', ()=>{
      playing = false;
      const t = Math.floor(video.currentTime || 0);
      if (segStart != null) sendSegment(segStart, t);
      segStart = null;
    });

    // terminou → fecha segmento
    video.addEventListener('ended', ()=>{
      const t = Math.floor(video.currentTime || 0);
      if (segStart != null) sendSegment(segStart, t);
      segStart = null;
      playing = false;
    });

    // antes do seek → fecha segmento corrente
    video.addEventListener('seeking', ()=>{
      if (segStart != null) {
        const t = Math.floor(video.currentTime || 0);
        sendSegment(segStart, t);
        segStart = null;
      }
    });

    // após seek: se continuar tocando, reabre
    video.addEventListener('seeked', ()=>{
      if (!video.paused && !video.ended) {
        segStart = Math.floor(video.currentTime || 0);
        lastT = segStart;
        playing = true;
      }
    });

    // ————— Eventos simples (compatibilidade/telemetria) —————
    function send(type){
      fetch('/track', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({
          sessionId,
          type,
          videoTime: Math.floor(video.currentTime||0),
          clientTs: new Date().toISOString()
        })
      }).catch(()=>{});
    }
    if(!${JSON.stringify(!!signedUrl)}) alert('Vídeo não configurado (R2).');
    video.addEventListener('play',  ()=>send('play'));
    video.addEventListener('pause', ()=>send('pause'));
    video.addEventListener('ended', ()=>send('ended'));
    setInterval(()=>send('progress'), 5000);

    // ao carregar metadata → reporta duração (se ainda não estiver no banco)
    video.addEventListener('loadedmetadata', ()=>{
      const dur = Math.floor(video.duration || 0);
      if (dur > 0) {
        fetch('/api/video-duration', {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ videoId: ${videoId}, durationSeconds: dur })
        }).catch(()=>{});
      }
    });

    // debug de erros de mídia
    video.addEventListener('error', ()=>{
      const err = video.error;
      console.error('HTMLMediaError', err);
      alert('Erro no player. Verifique Console/Network. Code: ' + (err && err.code));
    });
  })();
  </script>
`;

res.send(renderShell(v.title, body));
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

// ====== Tracking de trechos assistidos (segmentos) ======
app.post('/track/segment', async (req, res) => {
    try {
      const { sessionId, startSec, endSec } = req.body || {};
      const sid = parseInt(sessionId, 10);
      const a = Math.max(0, parseInt(startSec, 10));
      const b = Math.max(0, parseInt(endSec, 10));
  
      if (!Number.isFinite(sid) || !Number.isFinite(a) || !Number.isFinite(b) || b <= a) {
        return res.status(400).send('segmento inválido');
      }
  
      // Sanitize: limite de tamanho de segmento (evita “um salto” virar tudo)
      if (b - a > 600) { // 10 minutos num pacote só? corta.
        return res.status(400).send('segmento muito longo');
      }
  
      await pool.query(
        'INSERT INTO watch_segments(session_id, start_sec, end_sec) VALUES($1,$2,$3)',
        [sid, a, b]
      );
  
      res.status(204).end();
    } catch (e) {
      console.error('TRACK SEGMENT ERROR', e);
      res.status(500).send('erro');
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

// ====== Relatório WEB (% assistido com base em watch_segments, ordenado por nome) ======
app.get('/admin/relatorio/:videoId', adminRequired, async (req,res)=>{
  try{
    const videoId = parseInt(req.params.videoId,10);
    const page = Math.max(1, parseInt(req.query.page||'1',10));
    const pageSize = 500;
    const offset = (page-1)*pageSize;

    // Metadados do vídeo
    const { rows:vt } = await pool.query(`
      SELECT v.title, v.duration_seconds, c.name AS course_name
      FROM videos v LEFT JOIN courses c ON c.id=v.course_id
      WHERE v.id = $1`, [videoId]);
    if (!vt[0]) {
      return res.status(404).send(
        renderShell('Relatório', `<div class="card"><h1>Aula não encontrada</h1><p><a href="/aulas">Voltar</a></p></div>`)
      );
    }
    const videoTitle = vt[0].title;
    const courseName = vt[0].course_name || '-';
    const durationSec = vt[0].duration_seconds || null;

    // ===== Resumo por aluno (usa união de segmentos assistidos + fallback) =====
    const { rows:summary } = await pool.query(`
      WITH base AS (  -- um registro por usuário que abriu esse vídeo
        SELECT
          u.id          AS user_id,
          u.full_name,
          u.email,
          v.duration_seconds
        FROM sessions s
        JOIN users  u ON u.id = s.user_id
        JOIN videos v ON v.id = s.video_id
        WHERE s.video_id = $1
        GROUP BY u.id, u.full_name, u.email, v.duration_seconds
      ),
      sess AS (       -- contagem de sessões e primeiro acesso
        SELECT
          s.user_id,
          COUNT(DISTINCT s.id)          AS sessions,
          MIN(s.started_at)             AS first_access
        FROM sessions s
        WHERE s.video_id = $1
        GROUP BY s.user_id
      ),
      ev AS (         -- métricas de eventos (inclui max_time e último evento)
        SELECT
          s.user_id,
          MAX(e.video_time)                                 AS max_time_seen,
          MAX(e.client_ts)                                  AS last_event,
          COUNT(*) FILTER (WHERE e.type='ended')            AS finishes
        FROM sessions s
        LEFT JOIN events e ON e.session_id = s.id
        WHERE s.video_id = $1
        GROUP BY s.user_id
      ),
      segs_raw AS (   -- segmentos assistidos (limitados à duração do vídeo)
        SELECT
          s.user_id,
          v.duration_seconds,
          GREATEST(0, LEAST(ws.start_sec, v.duration_seconds)) AS s,
          GREATEST(0, LEAST(ws.end_sec,   v.duration_seconds)) AS e
        FROM sessions s
        JOIN videos v          ON v.id = s.video_id
        JOIN watch_segments ws ON ws.session_id = s.id
        WHERE s.video_id = $1
      ),
      ordered AS (    -- ordena segmentos por usuário e marca quebras
        SELECT *,
               LAG(e) OVER (PARTITION BY user_id ORDER BY s, e) AS prev_e
        FROM segs_raw
      ),
      grp AS (        -- agrupa segmentos contíguos/sobrepostos
        SELECT *,
               SUM(CASE WHEN prev_e IS NULL OR s > prev_e THEN 1 ELSE 0 END)
               OVER (PARTITION BY user_id ORDER BY s, e) AS g
        FROM ordered
      ),
      merged AS (     -- une os segmentos por grupo
        SELECT user_id, duration_seconds, MIN(s) AS s, MAX(e) AS e
        FROM grp
        GROUP BY user_id, duration_seconds, g
      ),
      watched AS (    -- total efetivamente assistido por usuário + pico real
        SELECT
          user_id,
          duration_seconds,
          SUM(GREATEST(e - s, 0)) AS watched_sec,
          MAX(e)                  AS max_end
        FROM merged
        GROUP BY user_id, duration_seconds
      )
      SELECT
        b.full_name,
        b.email,
        COALESCE(se.sessions, 0)              AS sessions,
        se.first_access,
        ev.last_event,
        -- "Pico (s)" prioriza fim de segmento; senão usa max_time_seen
        COALESCE(w.max_end, ev.max_time_seen, 0) AS max_time_seen,
        COALESCE(ev.finishes, 0)              AS finishes,
        CASE
          WHEN b.duration_seconds IS NULL OR b.duration_seconds <= 0 THEN NULL
          WHEN w.watched_sec IS NOT NULL THEN
            ROUND(LEAST(w.watched_sec, b.duration_seconds)::numeric * 100.0 / b.duration_seconds, 1)
          WHEN COALESCE(ev.finishes,0) > 0 THEN
            100.0
          WHEN ev.max_time_seen IS NOT NULL THEN
            ROUND(LEAST(GREATEST(ev.max_time_seen,0), b.duration_seconds)::numeric * 100.0 / b.duration_seconds, 1)
          ELSE 0
        END AS pct
      FROM base b
      LEFT JOIN sess    se ON se.user_id = b.user_id
      LEFT JOIN ev      ev ON ev.user_id = b.user_id
      LEFT JOIN watched w  ON w.user_id  = b.user_id
      ORDER BY b.full_name NULLS LAST, b.email
    `, [videoId]);

    // ===== Eventos brutos paginados (inalterado) =====
    const { rows:events } = await pool.query(`
      SELECT u.full_name, u.email, s.id AS session, e.type, e.video_time, e.client_ts
      FROM events e
      JOIN sessions s ON s.id = e.session_id
      JOIN users u    ON u.id = s.user_id
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

    // ===== Render =====
    const rowsSummary = summary.map(r => {
      const pctNum = Number(r.pct ?? 0);
      const pctStr = (durationSec && durationSec > 0 && isFinite(pctNum)) ? (pctNum + '%') : '—';
      return `
        <tr>
          <td>${safe(r.full_name)||'-'}</td>
          <td>${safe(r.email)}</td>
          <td>${r.sessions}</td>
          <td>${fmt(r.first_access)}</td>
          <td>${fmt(r.last_event)}</td>
          <td>${r.max_time_seen ?? 0}s</td>
          <td>${r.finishes}</td>
          <td><strong>${pctStr}</strong></td>
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

    const clearForm = `
<form method="POST" action="/admin/relatorio/${videoId}/clear"
      style="display:inline"
      onsubmit="return confirm('Remover TODOS os eventos e sessões deste vídeo?');">
  <input type="hidden" name="redirect" value="/admin/relatorio/${videoId}">
  <button style="background:none;border:0;color:#007bff;cursor:pointer;padding:0">Limpar relatório</button>
</form>`;

    const body = `
      <div class="card">
        <div class="right" style="justify-content:space-between;gap:12px">
          <h1 style="margin:0">Relatório — ${safe(videoTitle)}</h1>
          <div>
            <a href="/admin/relatorio/${videoId}.csv">Exportar CSV</a> ·
            ${clearForm}
            · <a href="/aulas">Voltar</a>
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
    res.status(500).send(renderShell('Erro', `<div class="card"><h1>Falha ao gerar relatório</h1><p class="mut">${safe(err.message||err)}</p></div>`));
  }
});
// ====== Relatórios com filtros (rápidos) ======
// UI de filtros + tabela com % assistido (usa MAX(video_time) / duration_seconds)
app.get('/admin/relatorios', authRequired, adminRequired, async (req, res) => {
    try {
      const { course_id, video_id, q, dt_from, dt_to } = req.query;
  
      // flags adicionais usados no HTML/CSV
      const activeOnly = (req.query.active_only ?? '1') === '1'; // default ligado
      const rawPctMin = req.query.pct_min;
      const pctMin = Number.isFinite(parseFloat(rawPctMin))
        ? Math.max(0, Math.min(100, parseFloat(rawPctMin)))
        : null;
  
      // combos de curso e, se houver curso, de vídeo
      const courses = (await pool.query(
        'SELECT id, name, slug FROM courses ORDER BY name'
      )).rows;
  
      let videos = [];
      if (course_id) {
        videos = (await pool.query(
          'SELECT id, title FROM videos WHERE course_id=$1 ORDER BY title', [course_id]
        )).rows;
      }
  
      // Se nenhum filtro foi definido, NÃO executa a query pesada; mostra só a UI
      const hasAnyFilter = Boolean(course_id || video_id || (q && q.trim()) || dt_from || dt_to || pctMin != null || activeOnly);
  
      let rows = [];
      if (hasAnyFilter) {
        // monta SQL dinamicamente (filtra por curso, por vídeo, por aluno e por faixa de datas)
        const params = [];
        const where = [];
  
        if (course_id) { params.push(course_id); where.push(`v.course_id = $${params.length}`); }
        if (video_id)  { params.push(video_id);  where.push(`v.id = $${params.length}`); }
        if (q && q.trim()) {
          params.push(`%${q.toLowerCase()}%`);
          where.push(`(LOWER(u.full_name) LIKE $${params.length} OR LOWER(u.email) LIKE $${params.length} OR LOWER(v.title) LIKE $${params.length})`);
        }
        if (dt_from) { params.push(dt_from); where.push(`e.client_ts >= $${params.length}`); }
        if (dt_to)   { params.push(dt_to);   where.push(`e.client_ts <= $${params.length}`); }
        if (activeOnly) { where.push(`c.archived = false`); }
  
        const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
  
        const sql = `
          WITH base AS (
            SELECT
              u.id AS user_id,
              u.full_name,
              u.email,
              v.id AS video_id,
              v.title,
              v.duration_seconds,
              MAX(e.video_time) AS max_time
            FROM sessions s
            JOIN events e   ON e.session_id = s.id
            JOIN users u    ON u.id = s.user_id
            JOIN videos v   ON v.id = s.video_id
            JOIN courses c  ON c.id = v.course_id
            ${whereSql}
            GROUP BY u.id, u.full_name, u.email, v.id, v.title, v.duration_seconds
          ),
          enriched AS (
            SELECT *,
              CASE
                WHEN duration_seconds IS NULL OR duration_seconds <= 0 THEN NULL
                ELSE LEAST(GREATEST(max_time,0), duration_seconds) * 100.0 / duration_seconds
              END AS pct
            FROM base
          )
          SELECT
            user_id, full_name, email, video_id, title, duration_seconds, max_time,
            CASE WHEN pct IS NULL THEN NULL ELSE ROUND(pct::numeric, 1) END AS pct
          FROM enriched
          ${pctMin != null ? `WHERE pct IS NOT NULL AND pct >= $${params.length + 1}` : ``}
          ORDER BY full_name, title
        `;
        if (pctMin != null) params.push(pctMin);
  
        rows = (await pool.query(sql, params)).rows;
      }
  
      // HTML da página
      const courseOptions = ['<option value="">(Todos)</option>']
        .concat(courses.map(c => `<option value="${c.id}" ${String(c.id)===String(course_id)?'selected':''}>${safe(c.name)}</option>`))
        .join('');
      const videoOptions = ['<option value="">(Todos)</option>']
        .concat(videos.map(v => `<option value="${v.id}" ${String(v.id)===String(video_id)?'selected':''}>${safe(v.title)}</option>`))
        .join('');
  
      const table = !hasAnyFilter
        ? '<tr><td colspan="6" class="mut">Escolha pelo menos um filtro e clique em “Aplicar filtros”.</td></tr>'
        : (rows.map(r => `
            <tr>
              <td>${safe(r.full_name)}</td>
              <td>${safe(r.email)}</td>
              <td>${safe(r.title)}</td>
              <td>${r.duration_seconds ?? '—'}</td>
              <td>${r.max_time ?? 0}</td>
              <td>${r.pct == null ? '—' : (r.pct + '%')}</td>
            </tr>
          `).join('') || '<tr><td colspan="6" class="mut">Sem dados para os filtros selecionados.</td></tr>');
  
      const csvLink = `/admin/relatorios.csv?` + new URLSearchParams({
        course_id: course_id || '',
        video_id: video_id || '',
        q: (q || '').trim(),
        dt_from: dt_from || '',
        dt_to: dt_to || '',
        pct_min: pctMin ?? '',
        active_only: activeOnly ? '1' : '0'
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
              <div style="display:flex;align-items:center;gap:6px;margin-top:22px">
                <input type="checkbox" id="active_only" name="active_only" value="1" ${activeOnly ? 'checked' : ''}>
                <label for="active_only" style="margin:0">Apenas cursos ativos</label>
              </div>
            </div>
  
            <div class="row">
              <div>
                <label>Aluno (nome ou email)</label>
                <input name="q" value="${safe(q||'')}" placeholder="ex.: maria@ / João">
              </div>
              <div>
                <label>De (client_ts)</label>
                <input name="dt_from" value="${safe(dt_from||'')}" placeholder="2025-08-01T00:00:00-03:00">
              </div>
              <div>
                <label>Até (client_ts)</label>
                <input name="dt_to" value="${safe(dt_to||'')}" placeholder="2025-08-31T23:59:59-03:00">
              </div>
              <div>
                <label>Mínimo % assistido (≥)</label>
                <input name="pct_min" type="number" min="0" max="100" step="0.1" value="${pctMin ?? ''}">
              </div>
            </div>
  
            <button class="mt">Aplicar filtros</button>
            <a class="mt" href="${csvLink}" style="margin-left:12px;display:inline-block">Exportar CSV</a>
          </form>
  
          <table>
            <tr>
              <th>Nome</th><th>Email</th><th>Vídeo</th><th>Duração (s)</th><th>Max pos (s)</th><th>% assistido</th>
            </tr>
            ${table}
          </table>
        </div>
      `;
  
      res.send(renderShell('Relatórios', html));
    } catch (err) {
      console.error('ADMIN/RELATORIOS ERROR', err);
      res.status(500).send(renderShell('Erro', `
        <div class="card">
          <h1>Falha ao carregar relatórios</h1>
          <p class="mut">${safe(err.message || err)}</p>
          <p><a href="/aulas">Voltar</a></p>
        </div>`));
    }
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

// ====== KEEPALIVE SUPABASE ======
setInterval(async () => {
  try {
    await pool.query('SELECT 1');
    console.log('Keepalive Supabase OK', new Date().toISOString());
  } catch (err) {
    console.error('Erro no keepalive Supabase', err.message);
  }
}, 5 * 60 * 1000); // a cada 5 minutos
