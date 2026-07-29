// harness-pav-scan-boot.mjs
//   uso:  node harness-pav-scan-boot.mjs [caminho/pav-scan-routes.js]
//
// Executa o JS da página /pav/scan num DOM SIMULADO e verifica que ela faz o
// que promete ao carregar. Existe por causa de um bug real: numa reescrita, a
// chamada que LIGA A CÂMERA foi apagada — o app subiu sintaticamente perfeito
// e completamente não-funcional (tela preta, sem erro). Checagem de sintaxe não
// pega isso; só executar pega.
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const alvo = process.argv[2] || path.join(__dirname, 'pav-scan-routes.js');
const src = fs.readFileSync(alvo, 'utf8');
const i = src.indexOf('const SCAN_HTML = `');
const html = src.slice(i + 19, src.lastIndexOf('`;'));
const js = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1];

// ── DOM mínimo ────────────────────────────────────────────────────────────
const ids = [...html.matchAll(/id="([a-zA-Z0-9_-]+)"/g)].map(m => m[1]);
const chamadas = { getUserMedia: 0, play: 0, addEventListener: 0 };
const feitos = new Map();

function novoEl(id) {
  const el = {
    id, style: {}, dataset: {}, classList: { add(){}, remove(){}, toggle(){}, contains(){return false} },
    children: [], hidden: false, textContent: '', innerHTML: '', value: '',
    videoWidth: 0, videoHeight: 0, clientWidth: 800, clientHeight: 600,
    setAttribute(){}, getAttribute(){return null}, removeAttribute(){},
    appendChild(){}, remove(){}, focus(){}, click(){},
    addEventListener(){ chamadas.addEventListener++; },
    getBoundingClientRect(){ return {left:0,top:0,width:800,height:600,right:800,bottom:600}; },
    getContext(){ return { drawImage(){}, getImageData(){ return {data:new Uint8ClampedArray(4)} },
      createImageData(){ return {data:new Uint8ClampedArray(4)} }, putImageData(){}, fillRect(){},
      beginPath(){}, arc(){}, fill(){}, ellipse(){} }; },
    toDataURL(){ return 'data:,'; },
    play(){ chamadas.play++; return Promise.resolve(); },
    set srcObject(v){ this._src = v; }, get srcObject(){ return this._src; },
    querySelector(){ return null; }, querySelectorAll(){ return []; },
    closest(){ return null; },
  };
  return el;
}
for (const id of ids) feitos.set(id, novoEl(id));

const document = {
  querySelector(sel){
    const id = sel.startsWith('#') ? sel.slice(1) : null;
    if (id && feitos.has(id)) return feitos.get(id);
    if (id) { const e = novoEl(id); feitos.set(id, e); return e; }
    return novoEl('x');
  },
  querySelectorAll(){ return []; },
  createElement(t){ return novoEl('novo-' + t); },
  addEventListener(){ chamadas.addEventListener++; },
  body: novoEl('body'),
};

const navigator = {
  onLine: true,
  vibrate(){},
  mediaDevices: {
    getUserMedia(c){
      chamadas.getUserMedia++;
      chamadas.ultimaConstraint = JSON.stringify(c);
      return Promise.resolve({
        getTracks(){ return [{ stop(){} }]; },
        getVideoTracks(){ return [{ getSettings(){ return {width:1920,height:1440,facingMode:'environment'}; }, stop(){} }]; },
      });
    },
  },
  serviceWorker: { register(){ return Promise.resolve(); } },
};

const location = { href:'https://app.exemplo/pav/scan', hash:'', pathname:'/pav/scan',
                   reload(){ chamadas.reload=(chamadas.reload||0)+1; }, replace(){} };
const globals = {
  document, navigator, location, window: { innerWidth: 800, innerHeight: 600, location },
  addEventListener(){ chamadas.addEventListener++; },
  setTimeout, clearTimeout, setInterval: () => 1, clearInterval,
  fetch: () => Promise.resolve({ json: () => Promise.resolve({}), ok: true }),
  indexedDB: { open(){
    const store={ add(){},delete(){},openCursor(){ const c={}; setTimeout(()=>c.onsuccess&&c.onsuccess({target:{result:null}}),0); return c; } };
    const db={ transaction(){ const tx={ objectStore(){ return store; } }; setTimeout(()=>tx.oncomplete&&tx.oncomplete(),0); return tx; },
               createObjectStore(){ return store; } };
    const r={ result: db };
    setTimeout(()=>{ r.onsuccess && r.onsuccess({target:{result:db}}); },0);
    return r; } },
  console, alert(){}, confirm(){ return true; },
  Uint8Array, Float32Array, Math, JSON, Number, String, Object, Array, Promise, Error, Date,
};

// stubs dos imports do módulo (o leitor é testado à parte)
const preludio = `
const readSheet=()=>({ok:false,erro:'stub'}), readNumber=()=>({valor:null,conf_min:1,vazio:true,digitos:[]}),
      loadDigitMLP=()=>{}, findFiducials=()=>null;
`;
const corpo = js.replace(/^\s*import[^\n]*\n/gm, '');

let erroExec = null;
try {
  const fn = new Function(...Object.keys(globals), preludio + corpo);
  fn(...Object.values(globals));
} catch (e) { erroExec = e; }

await new Promise(r => setTimeout(r, 120));   // deixa as promises resolverem

// ── verificações ──────────────────────────────────────────────────────────
let falhas = 0;
const t = (nome, ok, extra='') => { console.log((ok?'  ✓ ':'  ✗ ')+nome+(extra?' — '+extra:'')); if(!ok) falhas++; };

console.log('BOOT DA PWA /pav/scan em DOM simulado:\n');
t('o script executa sem exceção', !erroExec, erroExec ? String(erroExec).slice(0,120) : '');
t('PEDE A CÂMERA ao carregar', chamadas.getUserMedia > 0,
  chamadas.getUserMedia ? 'constraint: '+chamadas.ultimaConstraint.slice(0,70) : 'getUserMedia NUNCA foi chamado');
t('dá play no vídeo', chamadas.play > 0);
t('registra listeners', chamadas.addEventListener > 0);

console.log(`\n${falhas ? falhas+' FALHA(S)' : 'boot OK'}`);
process.exit(falhas ? 1 : 0);
