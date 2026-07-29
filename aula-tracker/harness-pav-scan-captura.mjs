// harness-pav-scan-captura.mjs
//   uso:  node harness-pav-scan-captura.mjs
//
// Exercita o caminho CAPTURA → LEITURA → TELA DE REVISÃO com um DOM simulado.
//
// Existe por causa de um travamento real: capturar() chama pararDeteccao()
// ANTES de mostrar(). Se mostrar() lançar qualquer exceção, o loop de detecção
// já está morto, a tela de revisão nunca aparece e o app congela para sempre
// exibindo "capturando…" — sem erro visível para o usuário.

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const src = fs.readFileSync(path.join(__dirname, 'pav-scan-routes.js'), 'utf8');
const i = src.indexOf('const SCAN_HTML = `');
const html = src.slice(i + 19, src.lastIndexOf('`;'));
const js = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1];

// ── resultado realista de readSheet (o que o leitor devolve de verdade) ────
function resultadoFalso() {
  const marks = [];
  for (const key of ['higiene_oral', 'cabeceira', 'aspiracao']) {
    const dias = [];
    for (let d = 0; d < 7; d++) dias.push([
      { valor: d === 0 ? 'S' : null, fracS: 0.3, fracN: 0 },
      { valor: d === 0 ? 'N' : null, fracS: 0, fracN: 0.3 },
    ]);
    marks.push({ key, enf: key === 'higiene_oral', label: key, dias });
  }
  const numeric_boxes = [];
  for (const [key, nd, porDia] of [['vm_dias', 2, true], ['cuff', 2, false], ['fio2', 3, false]]) {
    const dias = [];
    for (let d = 0; d < 7; d++) {
      const pers = [];
      for (let p = 0; p < (porDia ? 1 : 2); p++) {
        const caixas = [];
        for (let k = 0; k < nd; k++) caixas.push([100 + k * 20, 200 + d * 30, 18, 24]);
        pers.push(caixas);
      }
      dias.push(pers);
    }
    numeric_boxes.push({ key, label: key, por_dia: porDia, dias });
  }
  return {
    ok: true,
    fiducials: [[10, 10], [500, 12], [12, 400], [498, 402]],
    H: [1, 0, 0, 0, 1, 0, 0, 0, 1],
    marks, numeric_boxes,
    meta_boxes: { prontuario: [[10, 10, 20, 24]], datas: [[[10, 10, 20, 24]]], horas: [[[[10, 10, 20, 24]]]] },
    refino: { off: { dx: 0, dy: 0, pico: 3.1 }, darkRef: 30, fiducials_refinados: [[10, 10], [500, 12], [12, 400], [498, 402]] },
  };
}

// ── DOM simulado ──────────────────────────────────────────────────────────
const ids = [...html.matchAll(/id="([a-zA-Z0-9_-]+)"/g)].map(m => m[1]);
const feitos = new Map();
const estado = { hint: '', step1Hidden: null, step2Hidden: null, deteccaoParada: false };

function novoEl(id) {
  const el = {
    id, style: {}, dataset: {},
    classList: { add(){}, remove(){}, toggle(){}, contains(){ return false; } },
    hidden: false, _text: '', _html: '',
    get textContent(){ return this._text; },
    set textContent(v){ this._text = v; if (this.id === 'hint') estado.hint = v; },
    get innerHTML(){ return this._html; },
    set innerHTML(v){ this._html = v; },
    value: '', videoWidth: 1920, videoHeight: 1440, clientWidth: 800, clientHeight: 600,
    width: 0, height: 0,
    setAttribute(){}, getAttribute(){ return null; }, appendChild(){}, remove(){},
    addEventListener(){}, click(){}, focus(){},
    getBoundingClientRect(){ return { left:0, top:0, width:800, height:600, right:800, bottom:600 }; },
    getContext(){ return {
      drawImage(){}, fillRect(){}, beginPath(){}, arc(){}, fill(){}, ellipse(){},
      getImageData(w2,h2,w3,h3){ const n=Math.max(1,(w3||1)*(h3||1))*4; return { data:new Uint8ClampedArray(n) }; },
      createImageData(w2,h2){ const n=Math.max(1,(w2||1)*(h2||1))*4; return { data:new Uint8ClampedArray(n) }; },
      putImageData(){},
    }; },
    toDataURL(){ estado.pngs=(estado.pngs||0)+1; return 'data:image/png;base64,AAAA'; },
    play(){ return Promise.resolve(); },
    set srcObject(v){ this._s = v; }, get srcObject(){ return this._s; },
    querySelector(){ return null; }, querySelectorAll(){ return []; }, closest(){ return null; },
  };
  Object.defineProperty(el, 'hidden', {
    get(){ return this._hidden || false; },
    set(v){ this._hidden = v; if (this.id === 'step1') estado.step1Hidden = v; if (this.id === 'step2') estado.step2Hidden = v; },
  });
  return el;
}
for (const id of ids) feitos.set(id, novoEl(id));

const document = {
  querySelector(sel){
    const id = sel.startsWith('#') ? sel.slice(1) : null;
    if (id) { if (!feitos.has(id)) feitos.set(id, novoEl(id)); return feitos.get(id); }
    return novoEl('x');
  },
  querySelectorAll(sel){
    // #nums input: devolve alguns inputs, como na tela de revisão real
    if (sel.includes('input')) return [
      { value:'28', dataset:{ key:'cuff', d:'0', p:'0' } },
      { value:'',   dataset:{ key:'fio2', d:'0', p:'1' } },
    ];
    return [];
  },
  createElement(t){ return novoEl('novo-' + t); },
  addEventListener(){},
  body: novoEl('body'),
};

const location = { href:'https://x/pav/scan', hash:'', pathname:'/pav/scan', reload(){}, replace(){} };
const navigator = {
  onLine:true, vibrate(){},
  mediaDevices:{ getUserMedia(){ return Promise.resolve({
    getTracks(){ return [{stop(){}}]; },
    getVideoTracks(){ return [{ getSettings(){ return {width:1920,height:1440}; }, stop(){} }]; } }); } },
  serviceWorker:{ register(){ return Promise.resolve({ update(){}, }); },
                  addEventListener(){}, getRegistrations(){ return Promise.resolve([]); } },
};

const globals = {
  document, navigator, location, window:{ innerWidth:800, innerHeight:600, location },
  addEventListener(){}, setTimeout, clearTimeout,
  setInterval(fn){ globals.__loop = fn; return 7; },
  clearInterval(){ estado.deteccaoParada = true; },
  fetch:()=>Promise.resolve({ json:()=>Promise.resolve({}), ok:true }),
  indexedDB:{ open(){ const store={add(){},delete(){},openCursor(){ const c={}; setTimeout(()=>c.onsuccess&&c.onsuccess({target:{result:null}}),0); return c; }};
    const db={ transaction(){ const tx={objectStore(){return store;}}; setTimeout(()=>tx.oncomplete&&tx.oncomplete(),0); return tx; }, createObjectStore(){return store;} };
    const r={result:db}; setTimeout(()=>r.onsuccess&&r.onsuccess({target:{result:db}}),0); return r; } },
  caches:{ keys(){ return Promise.resolve([]); }, delete(){ return Promise.resolve(true); } },
  console, alert(){}, confirm(){ return true; },
  Uint8Array, Uint8ClampedArray, Float32Array, Math, JSON, Number, String, Object, Array, Promise, Error, Date, isNaN, parseInt, parseFloat,
};

// stubs: readSheet devolve resultado VÁLIDO (é o caminho que trava)
const preludio = `
const readSheet = () => globalThis.__resFalso();
const readNumber = () => ({ valor: 28, conf_min: 0.995, vazio: false, digitos: [] });
const loadDigitMLP = () => {};
const findFiducials = () => [[10,10],[500,12],[12,400],[498,402]];
`;
globalThis.__resFalso = resultadoFalso;

const corpo = js.replace(/^\s*import[^\n]*\n/gm, '');

let falhas = 0;
const t = (n, ok, ex='') => { console.log((ok?'  ✓ ':'  ✗ ')+n+(ex?' — '+ex:'')); if(!ok) falhas++; };

console.log('CAPTURA → REVISÃO (o caminho que travava em "capturando…"):\n');

let erroBoot = null, api = null;
try {
  const fn = new Function(...Object.keys(globals), preludio + corpo + '\n;return { capturar: typeof capturar!=="undefined"?capturar:null, mostrar: typeof mostrar!=="undefined"?mostrar:null };');
  api = fn(...Object.values(globals));
} catch (e) { erroBoot = e; }
await new Promise(r => setTimeout(r, 80));

t('o módulo carrega', !erroBoot, erroBoot ? String(erroBoot).slice(0,110) : '');
t('capturar() existe', !!(api && api.capturar));

if (api && api.capturar) {
  let erroCap = null;
  const t0 = Date.now();
  try { api.capturar(true); } catch (e) { erroCap = e; }
  const msSincrono = Date.now() - t0;
  const pngsNaAbertura = estado.pngs || 0;
  t('capturar() NÃO lança exceção', !erroCap,
    erroCap ? (erroCap.message || String(erroCap)).slice(0,140) : '');
  t('a tela de revisão aparece (step2 visível)', estado.step2Hidden === false,
    estado.step2Hidden === null ? 'mostrar() nunca rodou' : '');
  t('não ficou preso em "capturando…"', estado.hint !== 'capturando…',
    'hint = "' + estado.hint + '"');
  // A revisão tem que ABRIR antes do trabalho pesado (63 PNGs + 154 inferências).
  // Se todos os PNGs forem gerados sincronamente, a interface congela e o app
  // parece travado — foi exatamente o sintoma relatado no aparelho.
  t('a revisão abre SEM gerar todos os recortes de uma vez', pngsNaAbertura <= 8,
    pngsNaAbertura + ' PNG(s) na abertura');
  await new Promise(r => setTimeout(r, 400));    // deixa os lotes rodarem
  t('os campos numéricos são processados depois (em lotes)', (estado.pngs||0) > pngsNaAbertura,
    'total ' + (estado.pngs||0) + ' PNGs');
}

console.log(`\n${falhas ? falhas + ' FALHA(S)' : 'captura → revisão OK'}`);
process.exit(falhas ? 1 : 0);
