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
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1"/>
<meta name="theme-color" content="#0c447c"/>
<link rel="manifest" href="/estoque/manifest.webmanifest"/>
<title>Estoque · Clínica Kadri</title>
<style>
  :root{
    --bg:#f4f6f9;--card:#fff;--txt:#1b2330;--mut:#5b6472;--pri:#0c447c;
    --bd:#e0e2e6;--ok:#1a7a4a;--warn:#c07a10;--danger:#b03030;--warnbg:#fff8ec;--dangerbg:#fdf0f0;
  }
  *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
  body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Arial;background:var(--bg);color:var(--txt);padding-bottom:80px}
  header{position:sticky;top:0;z-index:20;background:var(--pri);color:#fff;padding:14px 16px;box-shadow:0 1px 6px rgba(0,0,0,.12)}
  header h1{margin:0;font-size:17px;font-weight:700}
  .sub{font-size:12px;opacity:.85;margin-top:2px}
  .wrap{max-width:900px;margin:0 auto;padding:12px 12px}
  .tools{display:flex;gap:8px;align-items:center;margin:12px 0;flex-wrap:wrap}
  .search{flex:1;min-width:180px;position:relative}
  .search input{width:100%;padding:12px 14px;border-radius:12px;border:1px solid #cdd3db;font-size:16px;background:#fff}
  .search input:focus{outline:none;border-color:var(--pri);box-shadow:0 0 0 3px rgba(12,68,124,.12)}
  .seg{display:flex;background:#e7ebf1;border-radius:12px;padding:3px;gap:2px}
  .seg button{flex:1;border:0;background:transparent;color:var(--mut);font-weight:600;padding:9px 12px;border-radius:9px;font-size:13px;cursor:pointer}
  .seg button.on{background:#fff;color:var(--pri);box-shadow:0 1px 3px rgba(0,0,0,.1)}
  .btn{border:0;border-radius:11px;padding:11px 14px;font-weight:600;cursor:pointer;font-size:14px}
  .btn-pri{background:var(--pri);color:#fff}
  .btn-ghost{background:#fff;color:var(--pri);border:1px solid var(--bd)}
  .alertbar{display:none;background:var(--dangerbg);border:1px solid #f0caca;color:var(--danger);border-radius:12px;padding:10px 14px;margin:10px 0;font-size:14px;font-weight:600}
  .alertbar.show{display:block}
  .item{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:14px;margin-bottom:10px;box-shadow:0 1px 2px rgba(16,24,40,.04)}
  .item.low{border-color:#f0caca;background:linear-gradient(#fff,var(--dangerbg))}
  .item-top{display:flex;justify-content:space-between;align-items:flex-start;gap:8px}
  .nome{font-weight:600;font-size:15px;line-height:1.3}
  .edit-link{color:var(--mut);font-size:12px;background:none;border:0;cursor:pointer;padding:4px;flex:0 0 auto}
  .fields{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px}
  .field{background:#f7f9fc;border:1px solid var(--bd);border-radius:12px;padding:10px}
  .field .lbl{font-size:11px;text-transform:uppercase;letter-spacing:.4px;color:var(--mut);font-weight:700;display:flex;justify-content:space-between}
  .field .lbl .thr{font-weight:500;text-transform:none;letter-spacing:0}
  .stepper{display:flex;align-items:center;gap:8px;margin-top:8px}
  .stepper button{width:38px;height:38px;border-radius:10px;border:1px solid var(--bd);background:#fff;font-size:20px;font-weight:700;color:var(--pri);cursor:pointer;flex:0 0 auto}
  .stepper button:active{background:#eef2f7}
  .qty{flex:1;text-align:center;font-size:22px;font-weight:700;border:1px solid transparent;border-radius:8px;padding:4px;min-width:0;background:transparent;color:var(--txt);-moz-appearance:textfield}
  .qty::-webkit-outer-spin-button,.qty::-webkit-inner-spin-button{-webkit-appearance:none;margin:0}
  .qty:focus{outline:none;border-color:var(--pri);background:#fff}
  .field.low .qty{color:var(--danger)}
  .field.low .lbl{color:var(--danger)}
  .empty{text-align:center;color:var(--mut);padding:40px 20px}
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
  .btn-danger{background:var(--dangerbg);color:var(--danger);border:1px solid #f0caca}
  .toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#1b2330;color:#fff;padding:10px 18px;border-radius:12px;font-size:14px;opacity:0;transition:opacity .2s;z-index:100;pointer-events:none}
  .toast.show{opacity:.95}
  .fab{position:fixed;right:16px;bottom:16px;width:56px;height:56px;border-radius:50%;background:var(--pri);color:#fff;border:0;font-size:28px;box-shadow:0 4px 14px rgba(12,68,124,.4);cursor:pointer;z-index:30}
  @media(max-width:480px){ .fields{grid-template-columns:1fr} }
</style>
</head>
<body>
<header>
  <h1>Controle de Estoque</h1>
  <div class="sub">Testes rápidos · Clínica Kadri</div>
</header>

<div class="wrap">
  <div class="tools">
    <div class="search"><input id="q" type="search" placeholder="Buscar teste…" autocomplete="off"/></div>
    <div class="seg">
      <button data-mode="ambos" class="on">Ambos</button>
      <button data-mode="uso">Gaveta</button>
      <button data-mode="estoque">Storage</button>
    </div>
  </div>
  <div class="alertbar" id="alertbar"></div>
  <div id="list"><div class="empty">Carregando…</div></div>
</div>

<button class="fab" id="fabNovo" title="Cadastrar teste">+</button>

<dialog id="dlgItem">
  <div class="dlg">
    <h2 id="dlgTitle">Novo teste</h2>
    <label>Nome do teste</label>
    <input id="fNome" type="text" placeholder="Ex.: Dengue (IgG/IgM)"/>
    <div class="dlg-row">
      <div><label>Alerta gaveta</label><input id="fAlertaUso" type="number" min="0" value="5"/></div>
      <div><label>Alerta storage</label><input id="fAlertaEstoque" type="number" min="0" value="5"/></div>
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

<script>
(function(){
  const $=s=>document.querySelector(s);
  let itens=[], mode='ambos', editId=null;

  const toast=(m)=>{const t=$('#toast');t.textContent=m;t.classList.add('show');clearTimeout(t._t);t._t=setTimeout(()=>t.classList.remove('show'),1600);};
  const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

  async function api(url,opts){
    const r=await fetch(url,Object.assign({headers:{'Content-Type':'application/json'}},opts||{}));
    const d=await r.json().catch(()=>({ok:false,error:'Resposta inválida'}));
    if(!r.ok||!d.ok) throw new Error(d.error||'Erro');
    return d;
  }

  async function load(){
    try{ const d=await api('/estoque/api/itens'); itens=d.itens; render(); }
    catch(e){ $('#list').innerHTML='<div class="empty">Erro ao carregar: '+esc(e.message)+'</div>'; }
  }

  function lowUso(it){ return it.qtd_uso <= it.alerta_uso; }
  function lowEstoque(it){ return it.qtd_estoque <= it.alerta_estoque; }

  function render(){
    const q=$('#q').value.trim().toLowerCase();
    let list=itens.filter(it=>!q||it.nome.toLowerCase().includes(q));

    // Barra de resumo de alertas (sempre sobre a lista completa, não filtrada)
    const lows=itens.filter(it=>lowUso(it)||lowEstoque(it));
    const ab=$('#alertbar');
    if(lows.length){ ab.classList.add('show'); ab.textContent='⚠ '+lows.length+' '+(lows.length===1?'teste':'testes')+' abaixo do alerta'; }
    else ab.classList.remove('show');

    if(!list.length){ $('#list').innerHTML='<div class="empty">Nenhum teste encontrado.</div>'; return; }

    $('#list').innerHTML=list.map(it=>{
      const lu=lowUso(it), le=lowEstoque(it);
      const isLow=(mode==='uso'&&lu)||(mode==='estoque'&&le)||(mode==='ambos'&&(lu||le));
      const fUso=\`
        <div class="field \${lu?'low':''}">
          <div class="lbl">Gaveta <span class="thr">alerta \${it.alerta_uso}</span></div>
          <div class="stepper">
            <button data-act="dec" data-id="\${it.id}" data-campo="uso">−</button>
            <input class="qty" type="number" inputmode="numeric" value="\${it.qtd_uso}" data-set="\${it.id}" data-campo="uso"/>
            <button data-act="inc" data-id="\${it.id}" data-campo="uso">+</button>
          </div>
        </div>\`;
      const fEst=\`
        <div class="field \${le?'low':''}">
          <div class="lbl">Storage <span class="thr">alerta \${it.alerta_estoque}</span></div>
          <div class="stepper">
            <button data-act="dec" data-id="\${it.id}" data-campo="estoque">−</button>
            <input class="qty" type="number" inputmode="numeric" value="\${it.qtd_estoque}" data-set="\${it.id}" data-campo="estoque"/>
            <button data-act="inc" data-id="\${it.id}" data-campo="estoque">+</button>
          </div>
        </div>\`;
      let fields='';
      if(mode==='ambos') fields=fUso+fEst;
      else if(mode==='uso') fields=fUso;
      else fields=fEst;
      return \`<div class="item \${isLow?'low':''}">
        <div class="item-top">
          <div class="nome">\${esc(it.nome)}</div>
          <button class="edit-link" data-edit="\${it.id}">✎ editar</button>
        </div>
        <div class="fields" style="\${mode==='ambos'?'':'grid-template-columns:1fr'}">\${fields}</div>
      </div>\`;
    }).join('');
  }

  // Ajuste +/-
  async function ajuste(id,campo,delta){
    try{
      const d=await api('/estoque/api/itens/'+id+'/ajuste',{method:'POST',body:JSON.stringify({campo,delta})});
      merge(d.item);
    }catch(e){ toast('Erro: '+e.message); }
  }
  // Set absoluto (edição direta do número)
  async function setVal(id,campo,valor){
    try{
      const d=await api('/estoque/api/itens/'+id+'/set',{method:'POST',body:JSON.stringify({campo,valor})});
      merge(d.item); toast('Salvo');
    }catch(e){ toast('Erro: '+e.message); load(); }
  }
  function merge(item){
    const i=itens.findIndex(x=>x.id===item.id);
    if(i>=0) itens[i]=Object.assign(itens[i],item);
    render();
  }

  // Delegação de eventos na lista
  $('#list').addEventListener('click',e=>{
    const b=e.target.closest('button'); if(!b) return;
    if(b.dataset.act){
      const delta=b.dataset.act==='inc'?1:-1;
      ajuste(+b.dataset.id,b.dataset.campo,delta);
    }else if(b.dataset.edit){
      openEdit(+b.dataset.edit);
    }
  });
  // Set absoluto ao sair do campo numérico
  $('#list').addEventListener('change',e=>{
    const inp=e.target.closest('input[data-set]'); if(!inp) return;
    const v=parseInt(inp.value,10);
    if(!Number.isInteger(v)||v<0){ load(); return; }
    setVal(+inp.dataset.set,inp.dataset.campo,v);
  });
  // Enter confirma (blur dispara change)
  $('#list').addEventListener('keydown',e=>{
    if(e.key==='Enter'&&e.target.matches('input[data-set]')) e.target.blur();
  });

  $('#q').addEventListener('input',render);
  document.querySelectorAll('.seg button').forEach(b=>b.addEventListener('click',()=>{
    document.querySelectorAll('.seg button').forEach(x=>x.classList.remove('on'));
    b.classList.add('on'); mode=b.dataset.mode; render();
  }));

  // ===== Dialog cadastro/edição =====
  const dlg=$('#dlgItem');
  function openNew(){
    editId=null;
    $('#dlgTitle').textContent='Novo teste';
    $('#fNome').value=''; $('#fAlertaUso').value=5; $('#fAlertaEstoque').value=5;
    $('#dlgDeleteRow').style.display='none';
    dlg.showModal(); $('#fNome').focus();
  }
  function openEdit(id){
    const it=itens.find(x=>x.id===id); if(!it) return;
    editId=id;
    $('#dlgTitle').textContent='Editar teste';
    $('#fNome').value=it.nome; $('#fAlertaUso').value=it.alerta_uso; $('#fAlertaEstoque').value=it.alerta_estoque;
    $('#dlgDeleteRow').style.display='flex';
    dlg.showModal();
  }
  $('#fabNovo').addEventListener('click',openNew);
  $('#dlgCancel').addEventListener('click',()=>dlg.close());
  $('#dlgSave').addEventListener('click',async()=>{
    const nome=$('#fNome').value.trim();
    const alerta_uso=parseInt($('#fAlertaUso').value,10);
    const alerta_estoque=parseInt($('#fAlertaEstoque').value,10);
    if(!nome){ toast('Informe o nome'); return; }
    try{
      if(editId){
        const d=await api('/estoque/api/itens/'+editId+'/editar',{method:'POST',body:JSON.stringify({nome,alerta_uso,alerta_estoque})});
        merge(d.item);
      }else{
        const d=await api('/estoque/api/itens',{method:'POST',body:JSON.stringify({nome,alerta_uso,alerta_estoque})});
        itens.push(d.item); itens.sort((a,b)=>(a.ordem||0)-(b.ordem||0)); render();
      }
      dlg.close(); toast('Salvo');
    }catch(e){ toast('Erro: '+e.message); }
  });
  $('#dlgDelete').addEventListener('click',async()=>{
    if(!editId) return;
    if(!confirm('Remover este teste do controle de estoque? O histórico é preservado.')) return;
    try{
      await api('/estoque/api/itens/'+editId+'/desativar',{method:'POST',body:'{}'});
      itens=itens.filter(x=>x.id!==editId); render(); dlg.close(); toast('Removido');
    }catch(e){ toast('Erro: '+e.message); }
  });
  dlg.addEventListener('click',e=>{ if(e.target===dlg) dlg.close(); });

  if('serviceWorker' in navigator){ navigator.serviceWorker.register('/estoque/sw.js').catch(()=>{}); }
  load();
})();
</script>
</body>
</html>`;
}
