// estoque-routes.js
// Controle de estoque dos testes rápidos do consultório.
// PWA responsivo (celular + desktop) em /estoque, API JSON em /estoque/api/*.
// Escrita atômica no Postgres — múltiplas pessoas contam simultaneamente sem conflito.
//
// Uso em app.js:
//   registerEstoqueRoutes(app, pool, secretariaRequired, renderShell);

function safe(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Nome de quem está mexendo, para o log de auditoria.
function quemDe(req) {
  return req.user?.full_name || req.user?.email || 'admin';
}

export function registerEstoqueRoutes(app, pool, secretariaRequired, renderShell) {

  // ================= API =================

  // Lista todos os itens ativos com status calculado.
  app.get('/estoque/api/itens', secretariaRequired, async (req, res) => {
    try {
      const { rows } = await pool.query(`
        SELECT id, nome, qtd_uso, qtd_estoque, alerta_uso, alerta_estoque, ordem
          FROM estoque_itens
         WHERE ativo = TRUE
         ORDER BY ordem NULLS LAST, nome
      `);
      res.json({ ok: true, itens: rows });
    } catch (e) {
      console.error('[estoque] api/itens', e);
      res.status(500).json({ ok: false, error: 'Erro ao carregar itens' });
    }
  });

  // Ajuste incremental (+N / -N) num campo. Atômico. Nunca deixa negativo.
  app.post('/estoque/api/itens/:id/ajuste', secretariaRequired, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const campo = String(req.body?.campo || '');
    const delta = parseInt(req.body?.delta, 10);
    if (!id || !['uso', 'estoque'].includes(campo) || !Number.isInteger(delta)) {
      return res.status(400).json({ ok: false, error: 'Parâmetros inválidos' });
    }
    const col = campo === 'uso' ? 'qtd_uso' : 'qtd_estoque';
    try {
      const { rows } = await pool.query(
        `UPDATE estoque_itens
            SET ${col} = GREATEST(0, ${col} + $1),
                updated_at = now(), updated_by = $2
          WHERE id = $3 AND ativo = TRUE
          RETURNING id, nome, qtd_uso, qtd_estoque, alerta_uso, alerta_estoque`,
        [delta, quemDe(req), id]
      );
      if (!rows[0]) return res.status(404).json({ ok: false, error: 'Item não encontrado' });
      const item = rows[0];
      const valorNovo = campo === 'uso' ? item.qtd_uso : item.qtd_estoque;
      await pool.query(
        `INSERT INTO estoque_mov (item_id, campo, delta, valor_novo, quem)
         VALUES ($1,$2,$3,$4,$5)`,
        [id, campo, delta, valorNovo, quemDe(req)]
      );
      res.json({ ok: true, item });
    } catch (e) {
      console.error('[estoque] ajuste', e);
      res.status(500).json({ ok: false, error: 'Erro ao ajustar' });
    }
  });

  // Set absoluto (contagem/levantamento). Atômico.
  app.post('/estoque/api/itens/:id/set', secretariaRequired, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const campo = String(req.body?.campo || '');
    const valor = parseInt(req.body?.valor, 10);
    if (!id || !['uso', 'estoque'].includes(campo) || !Number.isInteger(valor) || valor < 0) {
      return res.status(400).json({ ok: false, error: 'Parâmetros inválidos' });
    }
    const col = campo === 'uso' ? 'qtd_uso' : 'qtd_estoque';
    try {
      const { rows } = await pool.query(
        `UPDATE estoque_itens
            SET ${col} = $1, updated_at = now(), updated_by = $2
          WHERE id = $3 AND ativo = TRUE
          RETURNING id, nome, qtd_uso, qtd_estoque, alerta_uso, alerta_estoque`,
        [valor, quemDe(req), id]
      );
      if (!rows[0]) return res.status(404).json({ ok: false, error: 'Item não encontrado' });
      await pool.query(
        `INSERT INTO estoque_mov (item_id, campo, delta, valor_novo, quem)
         VALUES ($1,$2,NULL,$3,$4)`,
        [id, campo, valor, quemDe(req)]
      );
      res.json({ ok: true, item: rows[0] });
    } catch (e) {
      console.error('[estoque] set', e);
      res.status(500).json({ ok: false, error: 'Erro ao salvar' });
    }
  });

  // Cadastrar novo teste.
  app.post('/estoque/api/itens', secretariaRequired, async (req, res) => {
    const nome = String(req.body?.nome || '').trim();
    const alertaUso = parseInt(req.body?.alerta_uso, 10);
    const alertaEstoque = parseInt(req.body?.alerta_estoque, 10);
    if (!nome) return res.status(400).json({ ok: false, error: 'Nome obrigatório' });
    try {
      const { rows: maxRows } = await pool.query('SELECT COALESCE(MAX(ordem),0)+10 AS proxima FROM estoque_itens');
      const { rows } = await pool.query(
        `INSERT INTO estoque_itens (nome, alerta_uso, alerta_estoque, ordem, updated_by)
         VALUES ($1,$2,$3,$4,$5)
         RETURNING id, nome, qtd_uso, qtd_estoque, alerta_uso, alerta_estoque, ordem`,
        [nome,
         Number.isInteger(alertaUso) ? alertaUso : 5,
         Number.isInteger(alertaEstoque) ? alertaEstoque : 5,
         maxRows[0].proxima, quemDe(req)]
      );
      res.json({ ok: true, item: rows[0] });
    } catch (e) {
      if (e.code === '23505') return res.status(409).json({ ok: false, error: 'Já existe um teste com esse nome' });
      console.error('[estoque] criar', e);
      res.status(500).json({ ok: false, error: 'Erro ao cadastrar' });
    }
  });

  // Editar nome / thresholds.
  app.post('/estoque/api/itens/:id/editar', secretariaRequired, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const nome = String(req.body?.nome || '').trim();
    const alertaUso = parseInt(req.body?.alerta_uso, 10);
    const alertaEstoque = parseInt(req.body?.alerta_estoque, 10);
    if (!id || !nome) return res.status(400).json({ ok: false, error: 'Parâmetros inválidos' });
    try {
      const { rows } = await pool.query(
        `UPDATE estoque_itens
            SET nome = $1, alerta_uso = $2, alerta_estoque = $3,
                updated_at = now(), updated_by = $4
          WHERE id = $5
          RETURNING id, nome, qtd_uso, qtd_estoque, alerta_uso, alerta_estoque, ordem`,
        [nome,
         Number.isInteger(alertaUso) ? alertaUso : 5,
         Number.isInteger(alertaEstoque) ? alertaEstoque : 5,
         quemDe(req), id]
      );
      if (!rows[0]) return res.status(404).json({ ok: false, error: 'Item não encontrado' });
      res.json({ ok: true, item: rows[0] });
    } catch (e) {
      if (e.code === '23505') return res.status(409).json({ ok: false, error: 'Já existe um teste com esse nome' });
      console.error('[estoque] editar', e);
      res.status(500).json({ ok: false, error: 'Erro ao editar' });
    }
  });

  // Desativar (soft delete — preserva histórico de movimentações).
  app.post('/estoque/api/itens/:id/desativar', secretariaRequired, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!id) return res.status(400).json({ ok: false, error: 'ID inválido' });
    try {
      await pool.query(
        'UPDATE estoque_itens SET ativo = FALSE, updated_at = now(), updated_by = $1 WHERE id = $2',
        [quemDe(req), id]
      );
      res.json({ ok: true });
    } catch (e) {
      console.error('[estoque] desativar', e);
      res.status(500).json({ ok: false, error: 'Erro ao remover' });
    }
  });

  // Ordenação personalizada — grava a ordem da bancada (global, compartilhada).
  // Recebe { ids: [id1, id2, ...] } na sequência desejada; grava ordem = índice*10.
  app.post('/estoque/api/ordem', secretariaRequired, async (req, res) => {
    const ids = Array.isArray(req.body?.ids) ? req.body.ids.map(n => parseInt(n, 10)).filter(Number.isInteger) : null;
    if (!ids || !ids.length) return res.status(400).json({ ok: false, error: 'Lista de ids inválida' });
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (let i = 0; i < ids.length; i++) {
        await client.query('UPDATE estoque_itens SET ordem = $1 WHERE id = $2', [(i + 1) * 10, ids[i]]);
      }
      await client.query('COMMIT');
      res.json({ ok: true });
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      console.error('[estoque] ordem', e);
      res.status(500).json({ ok: false, error: 'Erro ao salvar ordem' });
    } finally {
      client.release();
    }
  });

  // ================= PWA =================

  app.get('/estoque', secretariaRequired, (req, res) => {
    res.send(renderPage());
  });

  // Manifest e service worker do PWA (rotas próprias, escopo /estoque).
  app.get('/estoque/manifest.webmanifest', (req, res) => {
    res.type('application/manifest+json').send(JSON.stringify({
      name: 'Estoque · Clínica Kadri',
      short_name: 'Estoque',
      start_url: '/estoque',
      scope: '/estoque',
      display: 'standalone',
      theme_color: '#0c447c',
      background_color: '#f4f6f9',
      icons: [
        { src: '/icon-192.png', sizes: '192x192', type: 'image/png' },
        { src: '/icon-512.png', sizes: '512x512', type: 'image/png' }
      ]
    }));
  });

  app.get('/estoque/sw.js', (req, res) => {
    res.type('application/javascript').send(`
const CACHE='estoque-v1';
self.addEventListener('install',e=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
// Network-first: dados sempre frescos; sem cache de API para não servir contagem velha.
self.addEventListener('fetch',e=>{
  const u=new URL(e.request.url);
  if(u.pathname.startsWith('/estoque/api/')) return; // nunca cacheia API
  e.respondWith(fetch(e.request).catch(()=>caches.match(e.request)));
});
`);
  });
}

// ---------- Página (HTML + JS embutido) ----------
function renderPage() {
  return `<!doctype html>
<html lang="pt-br">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"/>
<meta name="theme-color" content="#0c447c"/>
<link rel="manifest" href="/estoque/manifest.webmanifest"/>
<title>Estoque · Clínica Kadri</title>
<style>
  :root{
    --bg:#f4f6f9;--card:#fff;--txt:#1b2330;--mut:#5b6472;--pri:#0c447c;
    --bd:#e0e2e6;--ok:#1a7a4a;--danger:#b03030;--dangerbg:#fdf0f0;
  }
  *{box-sizing:border-box;-webkit-tap-highlight-color:transparent;margin:0;padding:0}
  body{font-family:system-ui,-apple-system,Segoe UI,Arial;background:var(--bg);color:var(--txt);padding-bottom:90px}
  header{position:sticky;top:0;z-index:20;background:var(--pri);color:#fff;padding:12px 14px;box-shadow:0 1px 6px rgba(0,0,0,.14)}
  .htop{display:flex;justify-content:space-between;align-items:center;gap:10px}
  header h1{font-size:16px;font-weight:600}
  .modebtn{background:rgba(255,255,255,.15);color:#fff;border:0;border-radius:10px;padding:8px 12px;font-size:13px;font-weight:600;cursor:pointer;display:flex;align-items:center;gap:6px;white-space:nowrap}
  .modebtn:active{background:rgba(255,255,255,.28)}
  .sub{font-size:12px;opacity:.88;margin-top:3px}
  .progbar{height:3px;background:rgba(255,255,255,.25);border-radius:3px;margin-top:6px;overflow:hidden;display:none}
  .progbar.show{display:block}
  .progbar>i{display:block;height:100%;background:#fff;width:0;transition:width .3s}
  .wrap{max-width:760px;margin:0 auto;padding:10px}
  .seg{display:flex;background:#e7ebf1;border-radius:12px;padding:3px;gap:2px;margin-bottom:8px}
  .seg button{flex:1;border:0;background:transparent;color:var(--mut);font-weight:600;padding:11px;border-radius:9px;font-size:13px;cursor:pointer}
  .seg button.on{background:#fff;color:var(--pri);box-shadow:0 1px 3px rgba(0,0,0,.1)}
  .subtools{display:flex;gap:8px;align-items:center;margin-bottom:10px}
  .search{flex:1}
  .search input{width:100%;padding:11px 13px;border-radius:11px;border:1px solid #cdd3db;font-size:16px;background:#fff}
  .search input:focus{outline:none;border-color:var(--pri);box-shadow:0 0 0 3px rgba(12,68,124,.12)}
  .rbtn{border:1px solid var(--bd);background:#fff;color:var(--pri);border-radius:11px;padding:11px 13px;font-weight:600;font-size:14px;cursor:pointer;white-space:nowrap}
  .rbtn.on{background:var(--pri);color:#fff;border-color:var(--pri)}
  .alertbar{display:none;background:var(--dangerbg);border:1px solid #f0caca;color:var(--danger);border-radius:12px;padding:10px 13px;margin-bottom:10px;font-size:14px;font-weight:600}
  .alertbar.show{display:block}

  /* ---- modo CONSULTA (dois campos) ---- */
  .item{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:14px;margin-bottom:10px}
  .item.low{border-color:#f0caca;background:linear-gradient(#fff,var(--dangerbg))}
  .item-top{display:flex;justify-content:space-between;align-items:flex-start;gap:8px}
  .nome{font-weight:600;font-size:15px;line-height:1.3}
  .edit-link{color:var(--mut);font-size:12px;background:none;border:0;cursor:pointer;padding:4px;flex:0 0 auto}
  .fields{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px}
  .field{background:#f7f9fc;border:1px solid var(--bd);border-radius:12px;padding:10px}
  .field .lbl{font-size:11px;text-transform:uppercase;letter-spacing:.4px;color:var(--mut);font-weight:700;display:flex;justify-content:space-between}
  .field .lbl .thr{font-weight:500;text-transform:none;letter-spacing:0}
  .field.low .lbl{color:var(--danger)}
  .field.low .qty{color:var(--danger)}

  /* ---- modo CONTAGEM (linha compacta) ---- */
  .row{display:flex;align-items:center;gap:10px;background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:8px 10px;margin-bottom:7px;min-height:58px}
  .row.low{border-color:#f0caca;background:linear-gradient(90deg,var(--dangerbg),#fff 60%)}
  .row.counted{border-color:#bfe3d1}
  .grip{color:#c2c8d0;font-size:22px;cursor:grab;flex:0 0 auto;display:none;touch-action:none;padding:4px}
  .reordering .grip{display:block}
  .reordering .stepper{display:none}
  .row .nome{flex:1;min-width:0;font-size:14px}
  .row .nome .tick{color:var(--ok);font-size:13px;margin-left:5px;opacity:0}
  .row.counted .nome .tick{opacity:1}
  .sortable-ghost{opacity:.4}
  .sortable-chosen{box-shadow:0 6px 20px rgba(12,68,124,.25);border-color:var(--pri)}

  /* ---- steppers (compartilhado) ---- */
  .stepper{display:flex;align-items:center;gap:8px;margin-top:8px}
  .row .stepper{margin-top:0;flex:0 0 auto}
  .stepper button{width:44px;height:44px;border-radius:11px;border:1px solid var(--bd);background:#fff;font-size:23px;font-weight:700;color:var(--pri);cursor:pointer;flex:0 0 auto;display:flex;align-items:center;justify-content:center}
  .stepper button:active{background:#eef2f7;transform:scale(.94)}
  .qtywrap{flex:1;text-align:center}
  .row .qtywrap{flex:0 0 auto;width:60px}
  .qty{width:100%;text-align:center;font-size:24px;font-weight:700;border:1px solid transparent;border-radius:8px;padding:2px;background:transparent;color:var(--txt)}
  .qty:focus{outline:none;border-color:var(--pri);background:#fff}
  .thr-inline{font-size:10px;color:var(--mut);text-align:center;margin-top:-2px}
  .row.low .thr-inline{color:var(--danger)}

  .empty{text-align:center;color:var(--mut);padding:40px 20px}
  .hint{font-size:12px;color:var(--mut);text-align:center;padding:6px 0 12px}

  dialog{border:0;border-radius:16px;padding:0;max-width:440px;width:92%;box-shadow:0 10px 40px rgba(0,0,0,.25)}
  dialog::backdrop{background:rgba(16,24,40,.45)}
  .dlg{padding:20px}
  .dlg h2{margin:0 0 4px;font-size:18px}
  .dlg label{display:block;font-size:13px;color:var(--mut);font-weight:600;margin:12px 0 4px}
  .dlg input{width:100%;padding:11px;border-radius:10px;border:1px solid #cdd3db;font-size:16px}
  .dlg input:focus{outline:none;border-color:var(--pri);box-shadow:0 0 0 3px rgba(12,68,124,.12)}
  .dlg-row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
  .dlg-actions{display:flex;gap:8px;margin-top:18px}
  .dlg-actions .btn{flex:1}
  .btn{border:0;border-radius:11px;padding:11px 14px;font-weight:600;cursor:pointer;font-size:14px}
  .btn-pri{background:var(--pri);color:#fff}
  .btn-ghost{background:#fff;color:var(--pri);border:1px solid var(--bd)}
  .btn-danger{background:var(--dangerbg);color:var(--danger);border:1px solid #f0caca}
  .toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%);background:#1b2330;color:#fff;padding:9px 18px;border-radius:12px;font-size:14px;opacity:0;transition:opacity .2s;z-index:100;pointer-events:none}
  .toast.show{opacity:.95}
  .fab{position:fixed;right:16px;bottom:18px;width:56px;height:56px;border-radius:50%;background:var(--pri);color:#fff;border:0;font-size:30px;box-shadow:0 4px 14px rgba(12,68,124,.4);cursor:pointer;z-index:30}
  @media(max-width:480px){ .fields{grid-template-columns:1fr} }
</style>
</head>
<body>
<header>
  <div class="htop">
    <h1>Controle de estoque</h1>
    <button class="modebtn" id="modeBtn"></button>
  </div>
  <div class="sub" id="sub">Testes rápidos · Clínica Kadri</div>
  <div class="progbar" id="progbar"><i id="progfill"></i></div>
</header>

<div class="wrap">
  <div class="seg" id="seg"></div>
  <div class="subtools">
    <div class="search"><input id="q" type="search" placeholder="Buscar teste…" autocomplete="off"/></div>
    <button class="rbtn" id="reorderBtn" style="display:none">Reordenar</button>
  </div>
  <div class="alertbar" id="alertbar"></div>
  <div id="list"><div class="empty">Carregando…</div></div>
  <div class="hint" id="hint"></div>
</div>

<button class="fab" id="fabNovo" title="Cadastrar teste">+</button>

<dialog id="dlgItem">
  <div class="dlg">
    <h2 id="dlgTitle">Novo teste</h2>
    <label>Nome do teste</label>
    <input id="fNome" type="text" placeholder="Ex.: Dengue (IgG/IgM)"/>
    <div class="dlg-row">
      <div><label>Alerta gaveta</label><input id="fAlertaUso" type="text" inputmode="numeric" pattern="[0-9]*" value="5"/></div>
      <div><label>Alerta storage</label><input id="fAlertaEstoque" type="text" inputmode="numeric" pattern="[0-9]*" value="5"/></div>
    </div>
    <div class="dlg-actions">
      <button class="btn btn-ghost" id="dlgCancel">Cancelar</button>
      <button class="btn btn-pri" id="dlgSave">Salvar</button>
    </div>
    <div class="dlg-actions" id="dlgDeleteRow" style="display:none;margin-top:8px">
      <button class="btn btn-danger" id="dlgDelete">Remover do estoque</button>
    </div>
  </div>
</dialog>

<div class="toast" id="toast"></div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/Sortable/1.15.2/Sortable.min.js"></script>
<script>
(function(){
  const $=s=>document.querySelector(s);
  const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const toast=m=>{const t=$('#toast');t.textContent=m;t.classList.add('show');clearTimeout(t._t);t._t=setTimeout(()=>t.classList.remove('show'),1500);};

  let itens=[], editId=null, sortable=null;
  // modo persiste por aparelho; campo/contagem só em memória
  let view=localStorage.getItem('estoque_view')||'consulta';   // 'consulta' | 'contagem'
  let consultaField='ambos';   // ambos | uso | estoque
  let contagemField='uso';     // uso | estoque
  let reordering=false;
  const counted=new Set();

  async function api(url,opts){
    const r=await fetch(url,Object.assign({headers:{'Content-Type':'application/json'}},opts||{}));
    const d=await r.json().catch(()=>({ok:false,error:'Resposta inválida'}));
    if(!r.ok||!d.ok) throw new Error(d.error||'Erro');
    return d;
  }
  async function load(){
    try{ const d=await api('/estoque/api/itens'); itens=d.itens; buildChrome(); render(); }
    catch(e){ $('#list').innerHTML='<div class="empty">Erro ao carregar: '+esc(e.message)+'</div>'; }
  }
  const lowUso=it=>it.qtd_uso<=it.alerta_uso;
  const lowEstoque=it=>it.qtd_estoque<=it.alerta_estoque;

  // ---- header / segmented control conforme o modo ----
  function buildChrome(){
    $('#modeBtn').innerHTML = view==='consulta' ? 'Contagem →' : '← Consulta';
    if(view==='contagem'){
      $('#seg').innerHTML='<button data-f="uso">Gaveta</button><button data-f="estoque">Storage</button>';
      $('#seg').querySelectorAll('button').forEach(b=>{ b.classList.toggle('on',b.dataset.f===contagemField); b.onclick=()=>{ contagemField=b.dataset.f; buildChrome(); render(); }; });
      $('#reorderBtn').style.display='';
      $('#progbar').classList.add('show');
    }else{
      $('#seg').innerHTML='<button data-f="ambos">Ambos</button><button data-f="uso">Gaveta</button><button data-f="estoque">Storage</button>';
      $('#seg').querySelectorAll('button').forEach(b=>{ b.classList.toggle('on',b.dataset.f===consultaField); b.onclick=()=>{ consultaField=b.dataset.f; buildChrome(); render(); }; });
      $('#reorderBtn').style.display='none';
      if(reordering) toggleReorder(false);
      $('#progbar').classList.remove('show');
    }
  }

  function render(){ view==='contagem'?renderContagem():renderConsulta(); }

  function renderConsulta(){
    const q=$('#q').value.trim().toLowerCase();
    const list=itens.filter(it=>!q||it.nome.toLowerCase().includes(q));
    const lows=itens.filter(it=>lowUso(it)||lowEstoque(it));
    const ab=$('#alertbar');
    if(lows.length){ ab.classList.add('show'); ab.textContent='⚠ '+lows.length+' '+(lows.length===1?'teste':'testes')+' abaixo do alerta'; } else ab.classList.remove('show');
    $('#hint').textContent='';
    if(!list.length){ $('#list').innerHTML='<div class="empty">Nenhum teste encontrado.</div>'; return; }
    const mode=consultaField;
    $('#list').innerHTML=list.map(it=>{
      const lu=lowUso(it), le=lowEstoque(it);
      const isLow=(mode==='uso'&&lu)||(mode==='estoque'&&le)||(mode==='ambos'&&(lu||le));
      const fUso=\`<div class="field \${lu?'low':''}"><div class="lbl">Gaveta <span class="thr">alerta \${it.alerta_uso}</span></div>
        <div class="stepper"><button data-act="dec" data-id="\${it.id}" data-campo="uso">−</button>
        <div class="qtywrap"><input class="qty" type="text" inputmode="numeric" pattern="[0-9]*" enterkeyhint="done" value="\${it.qtd_uso}" data-set="\${it.id}" data-campo="uso"/></div>
        <button data-act="inc" data-id="\${it.id}" data-campo="uso">+</button></div></div>\`;
      const fEst=\`<div class="field \${le?'low':''}"><div class="lbl">Storage <span class="thr">alerta \${it.alerta_estoque}</span></div>
        <div class="stepper"><button data-act="dec" data-id="\${it.id}" data-campo="estoque">−</button>
        <div class="qtywrap"><input class="qty" type="text" inputmode="numeric" pattern="[0-9]*" enterkeyhint="done" value="\${it.qtd_estoque}" data-set="\${it.id}" data-campo="estoque"/></div>
        <button data-act="inc" data-id="\${it.id}" data-campo="estoque">+</button></div></div>\`;
      const fields = mode==='ambos'?fUso+fEst : mode==='uso'?fUso : fEst;
      return \`<div class="item \${isLow?'low':''}"><div class="item-top"><div class="nome">\${esc(it.nome)}</div>
        <button class="edit-link" data-edit="\${it.id}">✎ editar</button></div>
        <div class="fields" style="\${mode==='ambos'?'':'grid-template-columns:1fr'}">\${fields}</div></div>\`;
    }).join('');
  }

  function renderContagem(){
    const q=$('#q').value.trim().toLowerCase();
    const list=itens.filter(it=>!q||it.nome.toLowerCase().includes(q));
    const col=contagemField==='uso'?'qtd_uso':'qtd_estoque';
    const acol=contagemField==='uso'?'alerta_uso':'alerta_estoque';
    const lows=itens.filter(it=>it[col]<=it[acol]);
    const ab=$('#alertbar');
    if(lows.length){ ab.classList.add('show'); ab.textContent='⚠ '+lows.length+' abaixo do alerta ('+(contagemField==='uso'?'gaveta':'storage')+')'; } else ab.classList.remove('show');
    if(!list.length){ $('#list').innerHTML='<div class="empty">Nenhum teste encontrado.</div>'; updateProgress(); return; }
    $('#list').innerHTML=list.map(it=>{
      const v=it[col], lo=it[col]<=it[acol], done=counted.has(contagemField+':'+it.id);
      return \`<div class="row \${lo?'low':''} \${done?'counted':''}" data-id="\${it.id}">
        <span class="grip">≡</span>
        <div class="nome">\${esc(it.nome)}<span class="tick">✓</span></div>
        <div class="stepper"><button data-act="dec" data-id="\${it.id}" data-campo="\${contagemField}">−</button>
        <div class="qtywrap"><input class="qty" type="text" inputmode="numeric" pattern="[0-9]*" enterkeyhint="done" value="\${v}" data-set="\${it.id}" data-campo="\${contagemField}"/>
        <div class="thr-inline">alerta \${it[acol]}</div></div>
        <button data-act="inc" data-id="\${it.id}" data-campo="\${contagemField}">+</button></div></div>\`;
    }).join('');
    $('#list').classList.toggle('reordering',reordering);
    updateProgress();
  }

  function updateProgress(){
    if(view!=='contagem'){ return; }
    const total=itens.length, done=itens.filter(it=>counted.has(contagemField+':'+it.id)).length;
    $('#progfill').style.width=(total?Math.round(done/total*100):0)+'%';
    $('#sub').textContent=reordering?'Arraste pela alça para reordenar':('Contando '+(contagemField==='uso'?'a gaveta':'o storage')+' · '+done+' / '+total);
    $('#hint').textContent=reordering?'A ordem vale para as duas telas e fica salva para todos.':'Toque no número para digitar direto.';
  }

  // ---- ações compartilhadas ----
  async function ajuste(id,campo,delta){
    try{ const d=await api('/estoque/api/itens/'+id+'/ajuste',{method:'POST',body:JSON.stringify({campo,delta})}); merge(d.item); counted.add(campo+':'+id); refreshCounts(); }
    catch(e){ toast('Erro: '+e.message); }
  }
  async function setVal(id,campo,valor){
    try{ const d=await api('/estoque/api/itens/'+id+'/set',{method:'POST',body:JSON.stringify({campo,valor})}); merge(d.item); counted.add(campo+':'+id); toast('Salvo'); refreshCounts(); }
    catch(e){ toast('Erro: '+e.message); load(); }
  }
  function merge(item){ const i=itens.findIndex(x=>x.id===item.id); if(i>=0) itens[i]=Object.assign(itens[i],item); render(); }
  // atualiza só contadores/alertas sem re-render pesado durante digitação rápida
  function refreshCounts(){ if(view==='contagem') updateProgress(); }

  $('#list').addEventListener('click',e=>{
    const b=e.target.closest('button'); if(!b) return;
    if(b.dataset.act){ if(reordering) return; ajuste(+b.dataset.id,b.dataset.campo,b.dataset.act==='inc'?1:-1); }
    else if(b.dataset.edit){ openEdit(+b.dataset.edit); }
  });
  $('#list').addEventListener('change',e=>{
    const inp=e.target.closest('input[data-set]'); if(!inp) return;
    const v=parseInt(inp.value,10);
    if(!Number.isInteger(v)||v<0){ load(); return; }
    setVal(+inp.dataset.set,inp.dataset.campo,v);
  });
  // campo é type=text (teclado numérico iOS) — descarta não-dígitos
  $('#list').addEventListener('input',e=>{
    const inp=e.target.closest('input[data-set]'); if(!inp) return;
    const limpo=inp.value.replace(/[^0-9]/g,''); if(limpo!==inp.value) inp.value=limpo;
  });
  $('#list').addEventListener('keydown',e=>{ if(e.key==='Enter'&&e.target.matches('input[data-set]')) e.target.blur(); });

  $('#q').addEventListener('input',render);

  // ---- alternar modo ----
  $('#modeBtn').addEventListener('click',()=>{
    view = view==='consulta'?'contagem':'consulta';
    localStorage.setItem('estoque_view',view);
    if(view==='consulta'){ $('#sub').textContent='Testes rápidos · Clínica Kadri'; }
    buildChrome(); render();
  });

  // ---- reordenar (só no modo contagem) ----
  function toggleReorder(on){
    reordering = on!==undefined?on:!reordering;
    $('#reorderBtn').classList.toggle('on',reordering);
    $('#reorderBtn').textContent=reordering?'Concluir':'Reordenar';
    document.body.classList.toggle('reordering',reordering);
    $('#list').classList.toggle('reordering',reordering);
    if(reordering && !sortable && window.Sortable){
      sortable=Sortable.create($('#list'),{handle:'.grip',animation:150,ghostClass:'sortable-ghost',chosenClass:'sortable-chosen',
        onEnd:async()=>{
          const ids=[...$('#list').querySelectorAll('.row')].map(r=>+r.dataset.id);
          // reflete a nova ordem no array local
          itens.sort((a,b)=>ids.indexOf(a.id)-ids.indexOf(b.id));
          try{ await api('/estoque/api/ordem',{method:'POST',body:JSON.stringify({ids})}); toast('Ordem salva'); }
          catch(e){ toast('Erro ao salvar ordem'); }
        }});
    }
    updateProgress();
  }
  $('#reorderBtn').addEventListener('click',()=>toggleReorder());

  // ---- dialog cadastro/edição ----
  const dlg=$('#dlgItem');
  const cleanNum=el=>{ el.addEventListener('input',()=>{ const c=el.value.replace(/[^0-9]/g,''); if(c!==el.value) el.value=c; }); };
  cleanNum($('#fAlertaUso')); cleanNum($('#fAlertaEstoque'));
  function openNew(){ editId=null; $('#dlgTitle').textContent='Novo teste'; $('#fNome').value=''; $('#fAlertaUso').value=5; $('#fAlertaEstoque').value=5; $('#dlgDeleteRow').style.display='none'; dlg.showModal(); $('#fNome').focus(); }
  function openEdit(id){ const it=itens.find(x=>x.id===id); if(!it) return; editId=id; $('#dlgTitle').textContent='Editar teste'; $('#fNome').value=it.nome; $('#fAlertaUso').value=it.alerta_uso; $('#fAlertaEstoque').value=it.alerta_estoque; $('#dlgDeleteRow').style.display='flex'; dlg.showModal(); }
  $('#fabNovo').addEventListener('click',openNew);
  $('#dlgCancel').addEventListener('click',()=>dlg.close());
  $('#dlgSave').addEventListener('click',async()=>{
    const nome=$('#fNome').value.trim();
    const alerta_uso=parseInt($('#fAlertaUso').value,10), alerta_estoque=parseInt($('#fAlertaEstoque').value,10);
    if(!nome){ toast('Informe o nome'); return; }
    try{
      if(editId){ const d=await api('/estoque/api/itens/'+editId+'/editar',{method:'POST',body:JSON.stringify({nome,alerta_uso,alerta_estoque})}); merge(d.item); }
      else{ const d=await api('/estoque/api/itens',{method:'POST',body:JSON.stringify({nome,alerta_uso,alerta_estoque})}); itens.push(d.item); itens.sort((a,b)=>(a.ordem||0)-(b.ordem||0)); render(); }
      dlg.close(); toast('Salvo');
    }catch(e){ toast('Erro: '+e.message); }
  });
  $('#dlgDelete').addEventListener('click',async()=>{
    if(!editId) return;
    if(!confirm('Remover este teste do controle de estoque? O histórico é preservado.')) return;
    try{ await api('/estoque/api/itens/'+editId+'/desativar',{method:'POST',body:'{}'}); itens=itens.filter(x=>x.id!==editId); render(); dlg.close(); toast('Removido'); }
    catch(e){ toast('Erro: '+e.message); }
  });
  dlg.addEventListener('click',e=>{ if(e.target===dlg) dlg.close(); });

  if('serviceWorker' in navigator){ navigator.serviceWorker.register('/estoque/sw.js').catch(()=>{}); }
  load();
})();
</script>
</body>
</html>`;
}
