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
import crypto from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export function registerPavScanRoutes(app, pool, pavRequired) {
  // assets do leitor e template (lidos do disco; em produção podem ser embutidos)
  // Impressão digital do conteúdo: muda a cada deploy e invalida cache antigo.
  let VER = 'dev';
  let READER = '', TEMPLATE = '{}';
  try { READER = fs.readFileSync(path.join(__dirname, 'pav-omr-reader.mjs'), 'utf8'); } catch {}
  try { TEMPLATE = fs.readFileSync(path.join(__dirname, 'pav-omr-template.json'), 'utf8'); } catch {}

  let MODEL = '{}';
  try { MODEL = fs.readFileSync(path.join(__dirname, 'pav-digit-model.json'), 'utf8'); } catch {}
  try {
    VER = crypto.createHash('sha1')
      .update(READER).update(TEMPLATE).update(String(MODEL.length)).update(SCAN_HTML)
      .digest('hex').slice(0, 10);
  } catch {}

  app.get('/pav/scan/reader.js', pavRequired, (_req, res) => {
    res.set('Cache-Control', 'no-cache');
    res.type('application/javascript').send(READER);
  });
  app.get('/pav/scan/template.json', pavRequired, (_req, res) => {
    res.type('application/json').send(TEMPLATE);
  });
  app.get('/pav/scan/model.json', pavRequired, (_req, res) => {
    res.type('application/json').send(MODEL);
  });

  // service worker: cache dos assets para funcionar offline na UTI
  // SERVICE WORKER — reescrito depois de um incidente grave: a versão anterior
  // usava cache-first com nome FIXO ('pav-scan-v1'). Resultado: o primeiro
  // acesso congelava o app naquela versão e TODO deploy seguinte era ignorado
  // pelo aparelho. Agora: nome versionado pelo conteúdo, NETWORK-FIRST (o cache
  // é só rede-caiu), e o SW novo assume imediatamente (skipWaiting/claim).
  app.get('/pav/scan/sw.js', (_req, res) => {
    res.set('Cache-Control', 'no-store');
    res.type('application/javascript').send(`
const VER = '${VER}';
const C   = 'pav-scan-' + VER;
const ASSETS = ['/pav/scan', '/pav/scan/reader.js', '/pav/scan/template.json', '/pav/scan/model.json'];

self.addEventListener('install', e => { self.skipWaiting(); });

self.addEventListener('activate', e => e.waitUntil((async () => {
  // apaga TODOS os caches antigos desta app (não só os de nome diferente)
  const ks = await caches.keys();
  await Promise.all(ks.filter(k => k.startsWith('pav-scan-') && k !== C).map(k => caches.delete(k)));
  await self.clients.claim();
})()));

self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  const u = new URL(e.request.url);
  if (u.origin !== self.location.origin) return;
  const base = u.pathname;
  if (!ASSETS.includes(base)) return;
  // NETWORK-FIRST: a rede manda; o cache só entra se a rede falhar (UTI offline)
  e.respondWith((async () => {
    try {
      const r = await fetch(e.request);
      if (r && r.ok) { const c = await caches.open(C); c.put(e.request, r.clone()); }
      return r;
    } catch (err) {
      const hit = await caches.match(e.request, { ignoreSearch: true });
      if (hit) return hit;
      throw err;
    }
  })());
});`);
  });

  app.get('/pav/scan', pavRequired, (_req, res) => {
    res.set('Cache-Control', 'no-store');     // o HTML nunca vem de cache
    res.type('html').send(SCAN_HTML.replace(/__VER__/g, VER));
  });
}

const SCAN_HTML = `<!doctype html><html lang="pt-BR"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">
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
  canvas{width:100%;border-radius:12px;background:#000;display:block}
  /* CAPTURA EM TELA CHEIA, SEMPRE. Sem opt-in por toque (a versão anterior
     exigia tocar p/ ampliar e ninguém tocava) e sem recorte: o vídeo aparece
     inteiro (object-fit:contain) e é capturado inteiro — o que se vê é
     exatamente o que é lido, com o campo de visão máximo da câmera. */
  #step1{position:fixed;inset:0;background:#000;z-index:20;display:flex;
         align-items:center;justify-content:center}
  #step1 video{width:100%;height:100%;object-fit:contain;background:#000}
  #alvo{position:absolute;border:2px dashed rgba(255,255,255,.5);border-radius:4px;
        pointer-events:none;transition:border-color .18s}
  #alvo.ok{border-color:#7ee0b0;border-style:solid}
  .corner{position:absolute;width:26px;height:26px;border:3px solid rgba(255,255,255,.35);
          pointer-events:none;transition:border-color .15s,transform .15s}
  .corner.on{border-color:#7ee0b0;transform:scale(1.12)}
  .hint{position:absolute;left:0;right:0;top:calc(10px + env(safe-area-inset-top));
        text-align:center;font-size:13px;font-weight:600;color:#fff;
        text-shadow:0 1px 5px #000;pointer-events:none;padding:0 12px}
  .hint.ok{color:#7ee0b0}
  #camdiag{position:absolute;left:0;right:0;bottom:calc(74px + env(safe-area-inset-bottom));
           text-align:center;font-size:11px;color:#9fb3ab;text-shadow:0 1px 4px #000;pointer-events:none}
  #ctrls{position:absolute;left:0;right:0;bottom:calc(12px + env(safe-area-inset-bottom));
         display:flex;gap:8px;justify-content:center;padding:0 10px;margin:0}
  #ctrls button{box-shadow:0 3px 14px rgba(0,0,0,.6)}
  #erro{position:absolute;inset:auto 16px auto 16px;top:40%;color:#f0a89e;text-align:center;font-size:14px}
  .rot{background:#3d2a10;color:#ffd98a;border:1px solid #6b4a18;border-radius:10px;padding:10px 12px;margin:10px 0;font-size:13px}
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
    <video id="v" playsinline autoplay muted></video>
    <div id="alvo"></div>
    <div class="corner" id="ctl"></div><div class="corner" id="ctr"></div>
    <div class="corner" id="cbl"></div><div class="corner" id="cbr"></div>
    <div class="hint" id="hint">procurando os cantos…</div>
    <div id="camdiag"></div>
    <div id="erro" hidden></div>
    <div id="ctrls">
      <button id="shot">📷 Capturar</button>
      <button class="sec" id="auto">⏸ Auto</button>
      <button class="sec" id="flip">↺</button>
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
import { readSheet, readNumber, loadDigitMLP, findFiducials } from '/pav/scan/reader.js?v=__VER__';

const CONF_OK = 0.99;   // portão: acima disso pré-preenche; abaixo pede revisão
const $ = s => document.querySelector(s);
fetch('/pav/scan/model.json?v=__VER__').then(r=>r.json()).then(m=>{ if(m && m.W0) loadDigitMLP(m); }).catch(()=>{});
const netEl = $('#net');
function setNet(){ const on = navigator.onLine; netEl.textContent = on?'online':'offline'; netEl.classList.toggle('off',!on); if(on) syncAll(); }
addEventListener('online',setNet); addEventListener('offline',setNet);

let template=null, stream=null, facing='environment', lastRead=null, fichas=[];
let autoOn=true, detTimer=null, estaveis=0, lendo=false;
const ESTAVEIS_P_DISPARO = 4;      // frames consecutivos com os 4 cantos → dispara
const DET_MS = 160;                // intervalo do loop de detecção (~6 fps)

fetch('/pav/scan/template.json?v=__VER__').then(r=>r.json()).then(t=>template=t);
fetch('/pav/api/fichas-ativas').then(r=>r.json()).then(d=>{fichas=d.fichas||[];}).catch(()=>{});

// log visível na própria tela: sem isso, depurar câmera em celular é adivinhação
function log(msg){
  const el=$('#camdiag'); if(!el) return;
  el.textContent = msg;
}

async function startCam(){
  if(stream) stream.getTracks().forEach(t=>t.stop());
  $('#erro').hidden=true;
  // CADEIA DE FALLBACK. A versão anterior pedia 4032×3024 — resolução de FOTO;
  // streams de VÍDEO no iPhone vão até ~1920×1440 (4:3) e o pedido devolvia um
  // stream que não reproduzia (tela preta). Aqui tentamos do melhor ao básico e
  // paramos no primeiro que funciona.
  const tentativas = [
    {facingMode:{ideal:facing}, width:{ideal:1920}, height:{ideal:1440}},  // 4:3 nítido
    {facingMode:{ideal:facing}},                                           // simples
    true,                                                                  // qualquer câmera
  ];
  let err=null;
  for(const c of tentativas){
    try{
      log('pedindo câmera…');
      stream = await navigator.mediaDevices.getUserMedia({video:c, audio:false});
      log('stream obtido');
      break;
    }catch(e){ err=e; stream=null; log('falhou: '+(e.name||e)); }
  }
  if(!stream){
    $('#erro').hidden=false;
    $('#erro').textContent='Não consegui abrir a câmera'+(err?(' ('+(err.name||err)+')'):'')
      +'. Verifique a permissão de câmera do navegador e se a página está em HTTPS.';
    return;
  }
  const v=$('#v');
  v.srcObject = stream;
  v.setAttribute('playsinline','');    // iOS: sem isso o vídeo abre em tela cheia nativa
  try{ await v.play(); }catch(e){}
  // espera as dimensões chegarem (iOS demora alguns frames)
  for(let i=0;i<40 && !v.videoWidth;i++) await new Promise(r=>setTimeout(r,50));
  const t=stream.getVideoTracks()[0], st=t?t.getSettings():{};
  $('#camdiag').textContent = v.videoWidth
    ? ('câmera '+v.videoWidth+'×'+v.videoHeight+(st.facingMode?' · '+st.facingMode:''))
    : 'câmera sem sinal de vídeo';
  posicionarAlvo();
  iniciarDeteccao();
}

// ── INICIALIZAÇÃO DA CÂMERA ───────────────────────────────────────────────
// (a ausência desta chamada foi o bug que deixou o app não-funcional: startCam
//  existia mas só era invocada pelo botão de trocar câmera)
let camIniciada=false;
async function ligarCamera(){
  if(camIniciada) return; camIniciada=true;
  try{ await startCam(); }
  catch(e){
    camIniciada=false;
    $('#erro').hidden=false;
    $('#erro').innerHTML='Falha ao iniciar a câmera: '+(e && (e.name||e.message||e))
      +'<br><br><button id="retry" style="margin-top:8px">Tentar de novo</button>';
    const r=$('#retry'); if(r) r.onclick=()=>{ $('#erro').hidden=true; ligarCamera(); };
  }
}
ligarCamera();
// iOS às vezes exige gesto do usuário: qualquer toque na tela tenta de novo
$('#step1').addEventListener('click', ()=>{ if(!stream) ligarCamera(); }, {passive:true});

$('#flip').onclick=(e)=>{ e.stopPropagation(); facing = facing==='environment'?'user':'environment'; camIniciada=false; ligarCamera(); };
// entra em tela cheia ao tocar no guia; sai no ✕ (a leitura também sai)
$('#auto').onclick=()=>{ autoOn=!autoOn; $('#auto').textContent = autoOn?'⏸ Pausar automático':'▶ Retomar automático';
  if(autoOn) iniciarDeteccao(); else pararDeteccao(); setHint(autoOn?'procurando os cantos…':'automático pausado','') };

// avisa se o telefone está em pé (a ficha é deitada)
function checaOrientacao(){
  const retrato = window.innerHeight > window.innerWidth;
  const h=$('#hint');
  if(retrato && !h.dataset.lock) h.dataset.dica='deite o celular p/ enquadrar maior';
}
addEventListener('resize', checaOrientacao); checaOrientacao();

// ── SEM RECORTE: o frame inteiro é exibido (contain) e capturado ───────────
// Toda a classe de bugs anterior (foto diferente do preview, campo de visão
// perdido, fiduciais fora do quadro) vinha de recortar o frame. Sem recorte:
// o que se vê é o frame, e o frame é o que se lê. A defesa contra cantos
// escuros do ambiente é a validação de plausibilidade, no leitor.
function grabFrame(v, maxW){
  const VW=v.videoWidth, VH=v.videoHeight;
  const w = maxW ? Math.min(maxW, VW) : VW;
  const h = Math.round(VH*w/VW);
  const c = grabFrame._c || (grabFrame._c = document.createElement('canvas'));
  c.width=w; c.height=h;
  const cx=c.getContext('2d',{willReadFrequently:true});
  cx.drawImage(v, 0,0,VW,VH, 0,0,w,h);
  const im=cx.getImageData(0,0,w,h);
  const g=new Uint8Array(w*h);
  for(let i=0,j=0;i<im.data.length;i+=4,j++)
    g[j]=(im.data[i]*0.299+im.data[i+1]*0.587+im.data[i+2]*0.114)|0;
  return {gray:g, w, h};
}

// desenha o retângulo-guia (297:210) sobre a ÁREA REALMENTE EXIBIDA do vídeo
// (object-fit:contain deixa tarjas pretas — o guia não pode invadi-las)
function posicionarAlvo(){
  const v=$('#v'), al=$('#alvo');
  if(!v.videoWidth){ al.style.display='none'; return; }
  al.style.display='block';
  const CW=v.clientWidth, CH=v.clientHeight;
  const esc=Math.min(CW/v.videoWidth, CH/v.videoHeight);   // contain
  const dw=v.videoWidth*esc, dh=v.videoHeight*esc;         // área exibida
  const dx=(CW-dw)/2, dy=(CH-dh)/2;
  const A=297/210;
  let tw,th;
  if(dw/dh > A){ th=dh*0.92; tw=th*A; } else { tw=dw*0.92; th=tw/A; }
  const tx=dx+(dw-tw)/2, ty=dy+(dh-th)/2;
  const r=v.getBoundingClientRect(), p=$('#step1').getBoundingClientRect();
  const ox=r.left-p.left, oy=r.top-p.top;
  Object.assign(al.style,{left:(ox+tx)+'px',top:(oy+ty)+'px',width:tw+'px',height:th+'px'});
  const C=13;
  const pos=[[tx,ty],[tx+tw-C*2,ty],[tx,ty+th-C*2],[tx+tw-C*2,ty+th-C*2]];
  ['#ctl','#ctr','#cbl','#cbr'].forEach((id,i)=>{
    Object.assign($(id).style,{left:(ox+pos[i][0])+'px',top:(oy+pos[i][1])+'px'});
  });
}
addEventListener('resize', posicionarAlvo);
addEventListener('orientationchange', ()=>setTimeout(posicionarAlvo,300));

// ── loop de detecção em baixa resolução (1–8ms por frame; barato) ──────────
function pararDeteccao(){ if(detTimer){ clearInterval(detTimer); detTimer=null; } }
function iniciarDeteccao(){
  pararDeteccao();
  if(!autoOn) return;
  detTimer = setInterval(()=>{
    if(lendo || !template) return;
    const v=$('#v');
    if(!v.videoWidth) return;
    const {gray:g, w:gw, h:gh} = grabFrame(v, 480);   // MESMO recorte do preview
    const f = findFiducials(g, gw, gh);
    marcarCantos(f);
    if(f){
      estaveis++;
      setRing(estaveis/ESTAVEIS_P_DISPARO);
      setHint(estaveis>=ESTAVEIS_P_DISPARO?'capturando…':'4 cantos ✓ segure firme','ok');
      if(estaveis>=ESTAVEIS_P_DISPARO){ estaveis=0; setRing(0); capturar(true); }
    } else {
      estaveis=0; setRing(0);
      setHint('procurando os cantos… aproxime e enquadre a folha toda','');
    }
  }, DET_MS);
}
function marcarCantos(f){
  ['#ctl','#ctr','#cbl','#cbr'].forEach((id,i)=> $(id).classList.toggle('on', !!(f && f[i])));
  $('#alvo').classList.toggle('ok', !!f);
}
function setRing(frac){
  // progresso da captura automática mostrado no próprio texto do topo
  const el=$('#ringfill'); if(el) el.style.clipPath='inset('+Math.max(0,(1-Math.min(1,frac))*100)+'% 0 0 0)';
}
function setHint(txt,cls){ const h=$('#hint'); h.textContent=txt; h.className='hint'+(cls?' '+cls:''); }

// ── captura (automática ou manual) ────────────────────────────────────────
function capturar(automatico){
  if(lendo) return;
  lendo=true;
  try{
    const v=$('#v');
    if(!v.videoWidth){ lendo=false; return; }
    // frame INTEIRO em resolução máxima — exatamente o que está no visor
    const {gray, w:cw, h:ch} = grabFrame(v);
    // PISO DE RESOLUÇÃO: abaixo de ~900px de largura a bolha tem <11px e a
    // leitura degrada. Avisa (não bloqueia: melhor ler com aviso que travar).
    if (cw < 900) {
      setHint('resolução baixa ('+cw+'px) — aproxime o celular', '');
      if (!automatico && !confirm('A câmera está entregando só '+cw+'px de largura.\n'
        + 'A leitura pode falhar. Aproximar o celular da folha melhora muito.\n\nLer assim mesmo?')) {
        lendo=false; return;
      }
    }
    const res=readSheet(gray,cw,ch,template);
    if(!res.ok){
      if(!automatico) alert('Não consegui ler: '+res.erro+'. Reenquadre com os 4 cantos visíveis.');
      setHint('não deu — reenquadre','');       // no automático, só avisa e segue tentando
      lendo=false; return;
    }
    if(navigator.vibrate) navigator.vibrate(60);           // confirmação tátil
    pararDeteccao();
    lastRead={res,gray,w:cw,h:ch};
    mostrar(res);
  } finally { lendo=false; }
}
$('#shot').onclick=()=>capturar(false);

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

function thumbCapturada(gray,w,h,fid){
  const tw=Math.min(420,w), th=Math.round(h*tw/w);
  const c=document.createElement('canvas'); c.width=tw; c.height=th;
  const cx=c.getContext('2d'); const id=cx.createImageData(tw,th);
  for(let y=0;y<th;y++)for(let x=0;x<tw;x++){
    const g=gray[((y*h/th)|0)*w+((x*w/tw)|0)], o=(y*tw+x)*4;
    id.data[o]=id.data[o+1]=id.data[o+2]=g; id.data[o+3]=255;
  }
  cx.putImageData(id,0,0);
  cx.fillStyle='#19c37d';
  for(const [fx,fy] of fid){ cx.beginPath(); cx.arc(fx*tw/w, fy*th/h, 6, 0, 7); cx.fill(); }
  return c.toDataURL();
}
function mostrar(res){
  $('#step1').hidden=true; $('#step2').hidden=false;
  $('#fidbox').innerHTML='<b>✔ Folha reconhecida</b> <small>'+lastRead.w+'×'+lastRead.h+'px'
    + (res.refino? ' · ajuste '+res.refino.off.dx+','+res.refino.off.dy+'mm':'')+'</small>'
    + '<div style="margin-top:8px"><img style="width:100%;border-radius:8px" src="'+thumbCapturada(lastRead.gray,lastRead.w,lastRead.h,res.fiducials)+'"></div>';

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

$('#again').onclick=()=>{ $('#step2').hidden=true; $('#step1').hidden=false; estaveis=0; setRing(0); posicionarAlvo(); iniciarDeteccao(); };

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
  $('#step2').hidden=true; $('#step1').hidden=false; estaveis=0; setRing(0); posicionarAlvo(); iniciarDeteccao();
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

if('serviceWorker' in navigator){
  navigator.serviceWorker.register('/pav/scan/sw.js').then(reg=>{
    reg.update();                                  // checa versão nova a cada carga
    // se um SW novo assumir, recarrega uma única vez p/ pegar o código atual
    let recarregou=false;
    navigator.serviceWorker.addEventListener('controllerchange',()=>{
      if(recarregou) return; recarregou=true; location.reload();
    });
  }).catch(()=>{});
}
// escotilha de emergência: /pav/scan#reset limpa cache e SW e recarrega
if(location.hash==='#reset'){
  (async()=>{
    try{
      const ks=await caches.keys(); await Promise.all(ks.map(k=>caches.delete(k)));
      const rs=await navigator.serviceWorker.getRegistrations(); await Promise.all(rs.map(r=>r.unregister()));
    }catch(e){}
    location.replace('/pav/scan');
  })();
}
setNet(); renderFila();
</script></body></html>`;
