// ====== Admin: Relatórios de aulas (web/CSV, por vídeo, limpeza) ======
// Extraído do app.js — sem alterações de comportamento.

import { safe, renderShell } from './ui-shell.js';
import { fmt } from './aulas-utils.js';

export function registerAulasAdminRelatoriosRoutes(app, pool, { authRequired, adminRequired }) {

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

}
