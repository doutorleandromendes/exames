// pav-scan-routes.js
// ──────────────────────────────────────────────────────────────────────────
// PWA de leitura point-of-care do instrumento PAV em papel.
//
//   /pav/scan            → página da câmera (instalável, offline-first)
//   /pav/scan/reader.js  → o leitor OMR (JS puro, cacheável)
//   /pav/scan/template.json → a geometria (fonte única, gerada por gen_omr.py)
//   /pav/scan/sw.js      → service worker (cache dos assets p/ uso offline)
//
// Fluxo: a fisio/enf tira a foto da folha na beira do leito → o aparelho lê as
// bolhas localmente → confirma paciente + digita os campos numéricos (recorte
// mostrado) → entra numa fila IndexedDB → sobe para /pav/api/import quando houver
// rede. Reler a mesma folha é seguro (idempotência no servidor).
//
//    registerPavScanRoutes(app, pool, pavRequired, TEMPLATE_JSON, READER_SRC);
// ──────────────────────────────────────────────────────────────────────────
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export function registerPavScanRoutes(app, pool, pavRequired) {
  // assets do leitor e template (lidos do disco; em produção podem ser embutidos)
  let READER = '', TEMPLATE = '{}';
  try { READER = fs.readFileSync(path.join(__dirname, 'pav-omr-reader.mjs'), 'utf8'); } catch {}
  try { TEMPLATE = fs.readFileSync(path.join(__dirname, 'pav-omr-template.json'), 'utf8'); } catch {}

  let MODEL = '{}';
  try { MODEL = fs.readFileSync(path.join(__dirname, 'pav-digit-model.json'), 'utf8'); } catch {}

  app.get('/pav/scan/reader.js', pavRequired, (_req, res) => {
    res.type('application/javascript').send(READER);
  });
  app.get('/pav/scan/template.json', pavRequired, (_req, res) => {
    res.type('application/json').send(TEMPLATE);
  });
  app.get('/pav/scan/model.json', pavRequired, (_req, res) => {
    res.type('application/json').send(MODEL);
  });

  // service worker: cache dos assets para funcionar offline na UTI
  app.get('/pav/scan/sw.js', (_req, res) => {
    res.type('application/javascript').send(`
const C = 'pav-scan-v1';
const ASSETS = ['/pav/scan', '/pav/scan/reader.js', '/pav/scan/template.json', '/pav/scan/model.json'];
self.addEventListener('install', e => e.waitUntil(caches.open(C).then(c => c.addAll(ASSETS))));
self.addEventListener('activate', e => e.waitUntil(
  caches.keys().then(ks => Promise.all(ks.filter(k => k !== C).map(k => caches.delete(k))))));
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (ASSETS.some(a => u.pathname === a))
    e.respondWith(caches.match(e.request).then(r => r || fetch(e.request)));
});`);
  });

  app.get('/pav/scan', pavRequired, (_req, res) => {
    res.type('html').send(SCAN_HTML);
  });
}

const SCAN_HTML = `<!doctype html><html lang="pt-BR"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>PAV · Leitura de folha</title>
<style>
  :root{--pri:#0e6b52;--nc:#c0392b;--ok:#1e874b;--line:#d8e0dd;--mut:#607068}
  *{box-sizing:border-box}
  body{margin:0;font:15px/1.5 system-ui,-apple-system,sans-serif;background:#0b0d0c;color:#eaf2ee}
  header{padding:12px 14px;background:#0e6b52;color:#fff;display:flex;align-items:center;gap:10px}
  header b{font-size:15px}
  #net{margin-left:auto;font-size:12px;padding:2px 8px;border-radius:10px;background:rgba(255,255,255,.18)}
  #net.off{background:#c0392b}
  main{padding:14px;max-width:640px;margin:0 auto}
  video,canvas{width:100%;border-radius:12px;background:#000;display:block}
  .guide{position:relative}
  .guide .frame{position:absolute;inset:6% 4%;border:2px dashed rgba(255,255,255,.6);border-radius:8px;pointer-events:none}
  .guide .corner{position:absolute;width:22px;height:22px;border:3px solid #7ee0b0}
  button{font:inherit;font-weight:600;border:0;border-radius:10px;padding:12px 16px;background:var(--pri);color:#fff}
  button.sec{background:#243330;color:#cfe6dd}
  button:disabled{opacity:.4}
  .row{display:flex;gap:10px;margin:12px 0;flex-wrap:wrap}
  .card{background:#141917;border:1px solid #223029;border-radius:12px;padding:14px;margin:12px 0}
  .num{display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid #1e2825}
  .num img{height:26px;border:1px solid #2a3a34;border-radius:4px;background:#fff}
  .num input{width:70px;font:inherit;text-align:center;padding:6px;border-radius:8px;border:1px solid #2a3a34;background:#0e1412;color:#eaf2ee}
  .mk{display:inline-block;min-width:22px;text-align:center;font-weight:700;border-radius:6px;padding:1px 6px;font-size:13px}
  .mk.S{background:#123d2b;color:#7ee0b0}.mk.N{background:#3d1a16;color:#f0a89e}.mk.A{background:#7a5b13;color:#ffd98a}
  small{color:var(--mut)}
  .q{background:#141917;border:1px solid #223029;border-radius:10px;padding:10px 12px;margin:8px 0;display:flex;justify-content:space-between}
  .q b{color:#7ee0b0}
</style></head><body>
<header><b>PAV · Leitura de folha</b><span id="net">•••</span></header>
<main>
  <div id="step1">
    <p><small>Enquadre a folha inteira, com os quatro quadrados pretos dos cantos visíveis. Boa luz, sem sombra sobre o papel.</small></p>
    <div class="guide">
      <video id="v" playsinline autoplay muted></video>
      <div class="frame"></div>
    </div>
    <div class="row">
      <button id="shot">📷 Capturar e ler</button>
      <button class="sec" id="flip">↺ Câmera</button>
    </div>
  </div>

  <canvas id="cv" hidden></canvas>

  <div id="step2" hidden>
    <div class="card" id="fidbox"></div>
    <div class="card">
      <b>Paciente</b>
      <div id="fichas"><small>carregando fichas…</small></div>
    </div>
    <div class="card">
      <b>Bolhas lidas</b> <small id="marksum"></small>
      <div id="marks"></div>
    </div>
    <div class="card">
      <b>Valores numéricos</b> <small>digite o que você vê no recorte</small>
      <div id="nums"></div>
    </div>
    <div class="row">
      <button id="enq">✔ Adicionar à fila</button>
      <button class="sec" id="again">↺ Nova foto</button>
    </div>
  </div>

  <div class="card" id="fila">
    <b>Fila para envio</b> <small id="filesum">vazia</small>
    <div id="filalist"></div>
    <div class="row"><button class="sec" id="sync" hidden>⇧ Enviar agora</button></div>
  </div>
</main>

<script type="module">
import { readSheet, readNumber, loadDigitMLP } from '/pav/scan/reader.js';

const CONF_OK = 0.99;   // portão: acima disso pré-preenche; abaixo pede revisão
const $ = s => document.querySelector(s);
fetch('/pav/scan/model.json').then(r=>r.json()).then(m=>{ if(m && m.W0) loadDigitMLP(m); }).catch(()=>{});
const netEl = $('#net');
function setNet(){ const on = navigator.onLine; netEl.textContent = on?'online':'offline'; netEl.classList.toggle('off',!on); if(on) syncAll(); }
addEventListener('online',setNet); addEventListener('offline',setNet);

let template=null, stream=null, facing='environment', lastRead=null, fichas=[];
fetch('/pav/scan/template.json').then(r=>r.json()).then(t=>template=t);
fetch('/pav/api/fichas-ativas').then(r=>r.json()).then(d=>{fichas=d.fichas||[];}).catch(()=>{});

async function startCam(){
  if(stream) stream.getTracks().forEach(t=>t.stop());
  stream = await navigator.mediaDevices.getUserMedia({video:{facingMode:facing,width:{ideal:2560},height:{ideal:1440}}});
  $('#v').srcObject = stream;
}
startCam().catch(()=>{ $('#v').outerHTML='<p style="color:#f0a89e">Sem acesso à câmera. Habilite a permissão.</p>'; });
$('#flip').onclick=()=>{ facing = facing==='environment'?'user':'environment'; startCam(); };

// ── captura e leitura ──
$('#shot').onclick=()=>{
  const v=$('#v'), cv=$('#cv');
  cv.width=v.videoWidth; cv.height=v.videoHeight;
  const ctx=cv.getContext('2d'); ctx.drawImage(v,0,0);
  const img=ctx.getImageData(0,0,cv.width,cv.height);
  const gray=new Uint8Array(cv.width*cv.height);
  for(let i=0,j=0;i<img.data.length;i+=4,j++)
    gray[j]=(img.data[i]*0.299+img.data[i+1]*0.587+img.data[i+2]*0.114)|0;

  const res=readSheet(gray,cv.width,cv.height,template);
  if(!res.ok){ alert('Não consegui ler: '+res.erro+'. Reenquadre com os 4 cantos visíveis.'); return; }
  lastRead={res,gray,w:cv.width,h:cv.height};
  mostrar(res,cv);
};

function crop(gray,w,box){
  const [x,y,bw,bh]=box; const c=document.createElement('canvas');
  c.width=Math.max(1,bw); c.height=Math.max(1,bh); const cx=c.getContext('2d');
  const id=cx.createImageData(c.width,c.height);
  for(let yy=0;yy<c.height;yy++)for(let xx=0;xx<c.width;xx++){
    const sx=x+xx,sy=y+yy,g=(sy>=0&&sx>=0&&sy*w+sx<gray.length)?gray[sy*w+sx]:255,o=(yy*c.width+xx)*4;
    id.data[o]=id.data[o+1]=id.data[o+2]=g; id.data[o+3]=255;
  }
  cx.putImageData(id,0,0); return c.toDataURL();
}

function mostrar(res,cv){
  $('#step1').hidden=true; $('#step2').hidden=false;
  $('#fidbox').innerHTML='<b>✔ Folha reconhecida</b> <small>4 cantos localizados · perspectiva corrigida</small>';

  // fichas
  $('#fichas').innerHTML = fichas.length
    ? fichas.map(f=>'<label style="display:block;padding:6px 0"><input type=radio name=ficha value="'+f.id+'"> '+
        (f.paciente||'—')+' <small>· leito '+(f.leito||'?')+' · '+(f.salao||'').trim()+'</small></label>').join('')
    : '<small>Sem fichas ativas carregadas (offline?). Você poderá associar ao enviar.</small>';

  // bolhas
  let nS=0,nN=0,nA=0,nV=0;
  const linhas = res.marks.map(row=>{
    const cels = row.dias.map((per,d)=> per.map((c,p)=>{
      const v=c.valor; if(v==='S')nS++; else if(v==='N')nN++; else if(v==='AMBAS')nA++; else nV++;
      const cls=v==='S'?'S':v==='N'?'N':v==='AMBAS'?'A':'';
      return v?'<span class="mk '+cls+'">'+(v==='AMBAS'?'!':v)+'</span>':'<span class="mk">·</span>';
    }).join(' ')).join(' | ');
    return '<div style="padding:5px 0;border-bottom:1px solid #1e2825"><small>'+row.label+'</small><br>'+cels+'</div>';
  }).join('');
  $('#marks').innerHTML=linhas;
  $('#marksum').textContent = nS+' sim · '+nN+' não · '+nA+' dupla(!) · '+nV+' vazias';

  // numéricos: OCR com portão de confiança + recorte para revisão/auditoria
  const nums=[]; window._ocr = [];   // guarda amostras p/ log
  let baixaConf=0;
  for(const nb of res.numeric_boxes){
    nb.dias.forEach((perList,d)=> perList.forEach((caixas,p)=>{
      if(!caixas.length) return;
      const xs=caixas.map(b=>b[0]), ys=caixas.map(b=>b[1]);
      const x=Math.min(...xs), y=Math.min(...ys);
      const bw=Math.max(...caixas.map(b=>b[0]+b[2]))-x, bh=Math.max(...caixas.map(b=>b[1]+b[3]))-y;
      const img=crop(lastRead.gray,lastRead.w,[x,y,bw,bh]);

      // ── OCR do campo ──
      const rn = readNumber(lastRead.gray, lastRead.w, lastRead.h, caixas);
      const per = nb.por_dia? '' : (p===0?'Dia':'Noite');
      const id='n_'+nb.key+'_'+d+'_'+p;
      const val = rn.vazio ? '' : (rn.valor ?? '');
      const revisar = !rn.vazio && rn.conf_min < CONF_OK;
      if(revisar) baixaConf++;
      const cls = rn.vazio ? '' : (revisar ? 'style="border-color:#c0392b"' : 'style="border-color:#1e874b"');
      const tag = rn.vazio ? '' : (revisar
        ? '<span class="mk N" title="confirme">revisar '+Math.round(rn.conf_min*100)+'%</span>'
        : '<span class="mk S">'+Math.round(rn.conf_min*100)+'%</span>');

      window._ocr.push({ key:nb.key, d, p, turno:(p===0?'D':'N'), por_dia:nb.por_dia,
        png:img, valor_ocr:String(val), conf:rn.conf_min, revisar });

      nums.push('<div class="num"><img src="'+img+'"><small>'+nb.label+' · D'+(d+1)+' '+per+'</small>'+
        '<input id="'+id+'" data-key="'+nb.key+'" data-d="'+d+'" data-p="'+p+'" inputmode="numeric" '+
        'value="'+val+'" '+cls+'> '+tag+'</div>');
    }));
  }
  $('#nums').innerHTML = nums.length
    ? (baixaConf? '<div style="color:#f0a89e;margin-bottom:6px">⚠ '+baixaConf+' campo(s) em vermelho: confira o recorte e corrija se preciso.</div>':'')
      + nums.join('')
    : '<small>Nenhum campo numérico marcado.</small>';
}

$('#again').onclick=()=>{ $('#step2').hidden=true; $('#step1').hidden=false; };

// ── montar payload e enfileirar ──
$('#enq').onclick=async ()=>{
  const fichaSel=document.querySelector('input[name=ficha]:checked');
  const fichaId = fichaSel? Number(fichaSel.value): null;
  if(!fichaId){ alert('Escolha o paciente.'); return; }

  // monta células a partir das marcas (bolhas) + numéricos digitados
  const map={}; // "data|turno|categoria" -> itens  (data aqui é placeholder: sem data lida, usa hoje por período)
  // NOTA v1: a data de cada dia vem das caixas de data (digitação futura); por ora
  // marcamos o índice do dia e o servidor/―conferência resolve a data real.
  const cells=[];
  for(const row of lastRead.res.marks){
    const cat = row.enf ? 'enf' : 'fisio';
    row.dias.forEach((per,d)=> per.forEach((c,p)=>{
      if(!c.valor || c.valor==='AMBAS') return; // dupla marca → deixa p/ conferência
      const turno = p===0?'D':'N';
      const chave = d+'|'+turno+'|'+cat;
      map[chave] = map[chave]||{};
      map[chave][row.key] = {resp: c.valor==='S'?'sim':'nao'};
    }));
  }
  const ocrAmostras=[];
  document.querySelectorAll('#nums input').forEach(inp=>{
    const val=inp.value.trim();
    const d=inp.dataset.d, p=inp.dataset.p, key=inp.dataset.key;
    const turno=p==='0'?'D':'N';
    // amostra de OCR p/ auditoria+treino (mesmo se vazio: registra o que foi lido)
    const src=(window._ocr||[]).find(o=>o.key===key&&String(o.d)===d&&String(o.p)===p);
    if(src){
      ocrAmostras.push({ key, turno, png:src.png, valor_ocr:src.valor_ocr,
        conf:src.conf, valor_final:val, revisado: src.revisar || (val!==src.valor_ocr) });
    }
    if(!val) return;
    const chave=d+'|'+turno+'|fisio';
    map[chave]=map[chave]||{}; map[chave][key]={valor:Number(val)};
  });
  for(const [chave,itens] of Object.entries(map)){
    const [d,turno,cat]=chave.split('|');
    cells.push({dia_idx:Number(d),turno,categoria:cat,itens});
  }

  const job={ ficha_id:fichaId, criado_em:Date.now(), celulas:cells, ocr_amostras:ocrAmostras };
  await enfileirar(job);
  $('#step2').hidden=true; $('#step1').hidden=false;
  renderFila(); setNet();
};

// ── fila offline (IndexedDB) ──
function idb(){ return new Promise((ok,err)=>{ const r=indexedDB.open('pav-scan',1);
  r.onupgradeneeded=()=>r.result.createObjectStore('fila',{keyPath:'id',autoIncrement:true});
  r.onsuccess=()=>ok(r.result); r.onerror=()=>err(r.error); }); }
async function enfileirar(job){ const db=await idb(); return new Promise((ok,err)=>{
  const tx=db.transaction('fila','readwrite'); tx.objectStore('fila').add(job); tx.oncomplete=ok; tx.onerror=()=>err(tx.error); }); }
async function listarFila(){ const db=await idb(); return new Promise((ok)=>{
  const out=[]; const c=db.transaction('fila').objectStore('fila').openCursor();
  c.onsuccess=e=>{ const cur=e.target.result; if(cur){out.push({...cur.value,id:cur.key});cur.continue();}else ok(out); }; }); }
async function removerFila(id){ const db=await idb(); return new Promise((ok)=>{
  const tx=db.transaction('fila','readwrite'); tx.objectStore('fila').delete(id); tx.oncomplete=ok; }); }

async function renderFila(){
  const itens=await listarFila();
  $('#filesum').textContent = itens.length? itens.length+' folha(s) aguardando': 'vazia';
  $('#sync').hidden = itens.length===0;
  $('#filalist').innerHTML = itens.map(j=>'<div class="q"><span>Ficha '+j.ficha_id+' · '+j.celulas.length+' células</span><b>'+
    (navigator.onLine?'pronto':'offline')+'</b></div>').join('');
}
$('#sync').onclick=syncAll;
async function syncAll(){
  if(!navigator.onLine) return;
  const itens=await listarFila();
  for(const j of itens){
    try{
      const r=await fetch('/pav/api/import',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({ficha_id:j.ficha_id, ocr_amostras:j.ocr_amostras||[], celulas:j.celulas.map(c=>({
          // v1: sem data lida, o servidor usa a semana informada na conferência;
          // aqui enviamos dia_idx e o backend de conferência resolve a data.
          data:c.data||new Date().toISOString().slice(0,10), turno:c.turno, categoria:c.categoria, itens:c.itens, hora:c.hora }))})});
      if(r.ok) await removerFila(j.id);
    }catch(e){ /* mantém na fila */ }
  }
  renderFila();
}

if('serviceWorker' in navigator) navigator.serviceWorker.register('/pav/scan/sw.js').catch(()=>{});
setNet(); renderFila();
</script></body></html>`;
