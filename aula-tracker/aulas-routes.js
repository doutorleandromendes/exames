// ====== Rotas públicas / aluno / player / tracking ======
// Extraído do app.js — sem alterações de comportamento.

import bcrypt from 'bcrypt';
import { safe, renderShell } from './ui-shell.js';
import { fmt } from './aulas-utils.js';
import { generateSignedUrlForKey } from './aulas-storage.js';

const ADMIN_SECRET = process.env.ADMIN_SECRET || null;
const ALLOWED_EMAIL_DOMAIN = process.env.ALLOWED_EMAIL_DOMAIN || null;

export function registerAulasRoutes(app, pool, { authRequired, isAdmin }) {

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
          <label style="display:flex;align-items:center;gap:8px;font-weight:400;margin-top:10px">
            <input type="checkbox" name="remember" style="width:auto"> Manter-me conectado neste dispositivo
          </label>
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
          await postJSON('/api/login',{ email:f.get('email'), password:f.get('password'), remember:f.get('remember')==='on' });
          location.href='/inicio';
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
app.get('/admin', (req,res)=>{
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
app.post('/admin', (req,res)=>{
  const { secret } = req.body || {};
  if(!ADMIN_SECRET) return res.status(500).send('ADMIN_SECRET não configurado');
  if(secret !== ADMIN_SECRET) return res.status(403).send('ADMIN_SECRET inválido');
  res.cookie('adm','1',{ httpOnly:true, sameSite:'lax', secure:true, maxAge: 1000*60*60*24 });
  res.redirect('/inicio');
});
app.get('/admin/logout', (req,res)=>{ res.clearCookie('adm'); res.redirect('/'); });

// ====== Início — hub genérico: lista os módulos que o usuário realmente acessa ======
app.get('/inicio', async (req,res)=>{
  const adm = isAdmin(req);
  const uid = req.cookies?.uid;
  let user = null;
  if(uid){
    try{
      const { rows } = await pool.query(
        'SELECT id,full_name,scih,super_admin,micro,pront,agenda,recepcao FROM users WHERE id=$1',[uid]);
      user = rows[0]||null;
    }catch{}
  }
  if(!user && !adm) return res.redirect('/');

  const f = k => !!(user && user[k]);
  const sa = adm || f('super_admin');            // super admin / break-glass: vê tudo
  const ehAtb = sa || f('scih') || f('micro');

  // micro "puro" (sem outros papéis) mantém o atalho histórico direto ao grid
  if (user && f('micro') && !sa && !f('scih') && !f('agenda') && !f('recepcao') && !f('pront'))
    return res.redirect('/atb/admin/grid');

  // o usuário tem alguma matrícula ativa em aulas?
  let temAulas = sa;
  if (user && !temAulas){
    try{
      const { rows } = await pool.query(
        `SELECT 1 FROM course_members cm
           JOIN courses c ON c.id = cm.course_id
          WHERE cm.user_id=$1 AND c.archived=false
            AND (c.expires_at IS NULL OR c.expires_at > now())
            AND (cm.expires_at IS NULL OR cm.expires_at > now())
          LIMIT 1`, [user.id]);
      temAulas = rows.length > 0;
    }catch{}
  }

  // catálogo de módulos: { visível?, destino, card }
  const mods = [];
  const add = (cond, href, ic, titulo, desc) => { if (cond) mods.push({ href, ic, titulo, desc }); };
  add(ehAtb, '/atb/admin/grid', '📋', 'Controle ATB', 'Grid de pareceres e monitoramento');
  add(sa || f('agenda') || f('recepcao'), '/agenda', '🗓️', 'Agenda', 'Consultas do consultório');
  add(sa || f('pront'), '/pront', '🩺', 'Prontuário', 'Pacientes, consultas e documentos');
  add(sa || f('agenda'), '/secretaria', '🧾', 'Secretaria', 'Orçamentos e documentos');
  add(sa || f('agenda'), '/estoque', '📦', 'Estoque', 'Testes rápidos');
  add(temAulas, '/aulas', '🎓', 'Aulas', 'InfectoAulas');

  // atalhos secundários (mesmos do hub antigo, preservados para SCIH/admin)
  const extras = [];
  if (ehAtb) {
    extras.push(`<a class="hubcard" href="/atb/admin/adesao">📈 Adesão aos pareceres</a>`);
    extras.push(`<a class="hubcard" href="/atb/admin/ficha-retrospectiva">➕ Ficha retrospectiva</a>`);
    extras.push(`<a class="hubcard" href="/consulta">🔎 Consulta (Farmácia)</a>`);
    extras.push(`<a class="hubcard" href="/atb/admin/config">⚙️ Configurar ATB</a>`);
  }
  if (sa) extras.push(`<a class="hubcard" href="/atb/admin/scih">👥 Acessos</a>`);

  // sem nenhum módulo → aulas (aluno recém-cadastrado vê a mensagem de lá)
  if (!mods.length) return res.redirect('/aulas');
  // um único destino e nada mais → vai direto, sem hub de um card só
  if (mods.length === 1 && !extras.length) return res.redirect(mods[0].href);

  const nome = user?.full_name || 'Admin (break-glass)';
  const html = `<div class="card"><h1>Início</h1><p class="mut">Olá, ${nome}.</p>
    <div class="hub">
      ${mods.map(m => `<a class="hubcard" href="${m.href}">
        <span class="hc-ic">${m.ic}</span>
        <span class="hc-t">${m.titulo}</span>
        <span class="hc-d">${m.desc}</span></a>`).join('')}
    </div>
    ${extras.length ? `<h2 style="font-size:15px;margin:20px 0 8px;color:#5b6472">Mais</h2>
      <div class="hub hub-sm">${extras.join('')}</div>` : ''}
  </div>
  <style>
  .hub{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;margin-top:14px}
  .hubcard{display:block;padding:16px;border:1px solid #e0e2e6;border-radius:12px;text-decoration:none;color:#0c447c;font-weight:600;background:#fff}
  .hubcard:hover{background:#f4f6f9}
  .hc-ic{display:block;font-size:26px;line-height:1.2}
  .hc-t{display:block;font-size:16px;margin-top:6px}
  .hc-d{display:block;font-size:12px;font-weight:400;color:#5b6472;margin-top:2px}
  .hub-sm{grid-template-columns:repeat(auto-fill,minmax(190px,1fr))}
  .hub-sm .hubcard{padding:12px 14px;font-size:14px}
  @media (max-width:720px){ .hub{grid-template-columns:1fr 1fr;gap:10px} .hub-sm{grid-template-columns:1fr} }
  </style>`;
  res.send(renderShell('Início', html));
});

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

// ====== Debug URL assinada ======
app.get('/debug/signed/:id', authRequired, async (req,res)=>{
  const id = parseInt(req.params.id,10);
  const { rows } = await pool.query('SELECT r2_key FROM videos WHERE id=$1',[id]);
  if (!rows[0]) return res.status(404).send('Aula não encontrada');
  const url = generateSignedUrlForKey(rows[0].r2_key);
  res.type('text/plain').send(url || 'ERRO: R2_* ausente');
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

// ====== APIs ======
app.post('/api/login', async (req,res)=>{
  try{
    let { email, password, remember } = req.body || {};
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
    const maxAge = remember ? 1000*60*60*24*365 : 1000*60*60*24*30; // 365d se "manter conectado", senão 30d
    res.cookie('uid', row.id, { httpOnly:true, sameSite:'lax', secure:true, maxAge });
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

}
