// ====== UI Shell (HTML helpers) ======
// Extraído do app.js — sem alterações de comportamento.

export function safe(s){
  return String(s ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}

export function renderShell(title, body, favicon) {
  return `<!doctype html>
  <html lang="pt-br">
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <title>${title}</title>
    ${favicon ? `<link rel="icon" href="${favicon}"/>` : ''}
    <style>
      :root{--bg:#f4f6f9;--card:#ffffff;--txt:#1b2330;--mut:#5b6472;--pri:#0c447c;--bd:#e0e2e6}
      *{box-sizing:border-box} body{margin:0;font-family:system-ui,Segoe UI,Arial;background:var(--bg);color:var(--txt)}
      .wrap{max-width:1100px;margin:40px auto;padding:0 16px}
      .card{background:var(--card);border:1px solid var(--bd);border-radius:16px;padding:24px;box-shadow:0 1px 3px rgba(16,24,40,.06),0 6px 18px rgba(16,24,40,.05)}
      label{display:block;margin:8px 0 4px}
      input,select,textarea{width:100%;padding:12px;border-radius:10px;border:1px solid #cdd3db;background:#fff;color:var(--txt)}
      input:focus,select:focus,textarea:focus{outline:none;border-color:var(--pri);box-shadow:0 0 0 3px rgba(12,68,124,.12)}
      button{background:var(--pri);color:#fff;border:0;border-radius:12px;padding:12px 16px;cursor:pointer;font-weight:600}
      button:hover{filter:brightness(1.08)}
      .row{display:grid;gap:16px;grid-template-columns:1fr 1fr}
      .mt{margin-top:16px}.mt2{margin-top:24px}.mut{color:var(--mut)} a{color:var(--pri)}
      table{width:100%;border-collapse:collapse} th,td{padding:8px;border-bottom:1px solid var(--bd);text-align:left;vertical-align:top}
      .video{position:relative;aspect-ratio:16/9;background:#000;border-radius:16px;overflow:hidden}
      .wm{position:absolute;right:12px;bottom:12px;opacity:.65;background:rgba(0,0,0,.35);padding:6px 10px;border-radius:10px;font-size:12px;color:#fff}
      code{background:#eef1f5;border:1px solid var(--bd);border-radius:8px;padding:0 6px}
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
