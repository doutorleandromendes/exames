// lab-lfa-routes.js
// Rota do LFA Strip Analyzer no Portal Lab.
//
// Registrar no app.js:
//   import { registerLfaRoutes } from './lab-lfa-routes.js';
//   registerLfaRoutes(app, pool, adminRequired);
//
// E adicionar '/lab-lfa-analyzer.js' à whitelist STATIC_PUBLIC em app.js.
//
// Dependências: reaproveita uploadToR2 de ./lab-storage.js e a tabela
// lab_result_images (já existente) para anexar o laudo a um exame.

import { uploadToR2 } from './lab-storage.js';

export function registerLfaRoutes(app, pool, adminRequired) {

  // ── Página da ferramenta ────────────────────────────────────────────────
  // Host mínimo: carrega o motor estático, que se auto-renderiza em #lfa-root.
  // Não usa renderShell porque o analyzer tem layout próprio full-height; mas
  // herda auth adminRequired.
  app.get('/lab/admin/lfa', adminRequired, (req, res) => {
    const resultId = (req.query.resultado || '').toString().replace(/[^0-9]/g, '');
    const attachInit = resultId
      ? `window.LFA=window.LFA||{};window.LFA.attachResultId=${JSON.stringify(resultId)};`
      : '';
    res.type('text/html').send(`<!doctype html>
<html lang="pt-br">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>LFA Strip Analyzer · Lab</title>
</head>
<body style="margin:0">
  <div id="lfa-root"></div>
  <script>${attachInit}</script>
  <script>
    // Integração opcional: se veio ?resultado=ID, anexa o laudo ao exame no R2.
    window.LFA = window.LFA || {};
    if (window.LFA.attachResultId) {
      window.LFA.onExport = async function(blob, meta){
        try {
          const fd = new FormData();
          fd.append('image', blob, 'lfa_laudo.png');
          fd.append('caption', 'LFA · ' + (meta.testName||'') + ' · ' +
            (meta.results||[]).filter(r=>r.result==='POSITIVO').map(r=>r.name).join(', '));
          const r = await fetch('/lab/admin/lfa/anexar/' + window.LFA.attachResultId, {
            method:'POST', body: fd
          });
          const j = await r.json();
          if (j.ok) {
            const el = document.createElement('div');
            el.textContent = '✓ Laudo anexado ao exame #' + window.LFA.attachResultId;
            el.style.cssText='position:fixed;bottom:16px;left:50%;transform:translateX(-50%);background:#0c447c;color:#fff;padding:10px 18px;border-radius:8px;font:13px/1.4 system-ui;z-index:9999;box-shadow:0 4px 16px rgba(0,0,0,.25)';
            document.body.appendChild(el);
            setTimeout(()=>el.remove(), 4000);
          } else {
            alert('Falha ao anexar: ' + (j.error||'erro desconhecido'));
          }
        } catch(e){ alert('Erro ao anexar laudo: ' + e.message); }
      };
    }
  </script>
  <script src="/lab-lfa-analyzer.js"></script>
</body>
</html>`);
  });

  // ── Anexar laudo PNG a um exame (opcional) ──────────────────────────────
  // POST multipart: campo 'image' (PNG do laudo) + 'caption'.
  // Grava no R2 e vincula via lab_result_images (mesmo padrão do upload de
  // imagens de resultado já existente).
  app.post('/lab/admin/lfa/anexar/:resultId', adminRequired, async (req, res) => {
    // Este endpoint usa multipart; o parser global de JSON pula rotas de upload
    // grande, mas aqui recebemos FormData. Fazemos parse manual do buffer.
    try {
      const resultId = parseInt(req.params.resultId, 10);
      if (!Number.isInteger(resultId)) {
        return res.status(400).json({ error: 'resultId inválido' });
      }

      // Confirma que o exame existe
      const { rows: exist } = await pool.query(
        'SELECT id FROM lab_results WHERE id=$1', [resultId]
      );
      if (!exist.length) {
        return res.status(404).json({ error: 'Exame não encontrado' });
      }

      // Lê o corpo multipart manualmente (evita adicionar multer como dep).
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const raw = Buffer.concat(chunks);

      const parsed = parseMultipartImage(raw, req.headers['content-type'] || '');
      if (!parsed || !parsed.buffer || !parsed.buffer.length) {
        return res.status(400).json({ error: 'Imagem ausente no upload' });
      }

      const stamp = Date.now();
      const r2Key = `lab/lfa/${resultId}/laudo_${stamp}.png`;
      await uploadToR2(r2Key, parsed.buffer, 'image/png');

      const { rows: [{ max_sort }] } = await pool.query(
        'SELECT COALESCE(MAX(sort_index), 0) AS max_sort FROM lab_result_images WHERE result_id=$1',
        [resultId]
      );
      const { rows: [img] } = await pool.query(
        `INSERT INTO lab_result_images (result_id, r2_key, caption, sort_index)
         VALUES ($1,$2,$3,$4) RETURNING id`,
        [resultId, r2Key, (parsed.caption || 'LFA laudo').slice(0, 300),
         parseInt(max_sort, 10) + 10]
      );

      res.json({ ok: true, image_id: img.id, r2_key: r2Key });
    } catch (err) {
      console.error('LFA ANEXAR ERROR', err);
      res.status(500).json({ error: err.message });
    }
  });

} // fim registerLfaRoutes

// ── Parser multipart mínimo (1 campo de imagem + caption) ─────────────────
// Suficiente para o FormData de 2 campos enviado pela página. Evita multer.
function parseMultipartImage(raw, contentType) {
  const m = /boundary=(.+)$/.exec(contentType);
  if (!m) return null;
  const boundary = '--' + m[1];
  const parts = splitBuffer(raw, Buffer.from(boundary));
  let buffer = null, caption = '';
  for (const part of parts) {
    const headerEnd = part.indexOf('\r\n\r\n');
    if (headerEnd < 0) continue;
    const header = part.slice(0, headerEnd).toString('utf8');
    let body = part.slice(headerEnd + 4);
    // remove trailing CRLF
    if (body.length >= 2 && body[body.length - 2] === 0x0d && body[body.length - 1] === 0x0a) {
      body = body.slice(0, body.length - 2);
    }
    if (/name="image"/.test(header)) {
      buffer = body;
    } else if (/name="caption"/.test(header)) {
      caption = body.toString('utf8');
    }
  }
  return { buffer, caption };
}

function splitBuffer(buf, sep) {
  const out = [];
  let start = 0, idx;
  while ((idx = buf.indexOf(sep, start)) !== -1) {
    if (idx > start) out.push(buf.slice(start, idx));
    start = idx + sep.length;
  }
  return out;
}
