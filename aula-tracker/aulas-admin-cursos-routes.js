// ====== Admin: Cursos, Vídeos, Clone e Disponibilidade ======
// Extraído do app.js — sem alterações de comportamento.

import bcrypt from 'bcrypt';
import { safe, renderShell } from './ui-shell.js';
import { fmt, fmtDTLocal, normalizeDateStr } from './aulas-utils.js';

const ALLOWED_EMAIL_DOMAIN = process.env.ALLOWED_EMAIL_DOMAIN || null;

export function registerAulasAdminCursosRoutes(app, pool, { authRequired, adminRequired }) {

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

}
