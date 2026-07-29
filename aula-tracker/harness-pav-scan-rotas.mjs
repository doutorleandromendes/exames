// harness-pav-scan-rotas.mjs
//   uso:  node harness-pav-scan-rotas.mjs
//
// Exercita as rotas de /pav/scan com um app Express simulado. Verifica o que
// realmente chega ao navegador: o reader.js tem os exports que a página
// importa? o service worker é network-first e versionado? a página injeta a
// versão? Um asset ausente aqui derruba a PWA inteira em silêncio — este
// harness transforma isso em falha de teste.
import { registerPavScanRoutes } from './pav-scan-routes.js';

const rotas = new Map();
const app = { get(p, ...h){ rotas.set(p, h[h.length-1]); } };
const passa = (_q,_s,n)=>n&&n();
registerPavScanRoutes(app, null, passa);

function chamar(p){
  return new Promise(res=>{
    let st=200, tipo='', corpo='', headers={};
    const r={ set(k,v){headers[k]=v; return r;}, type(t){tipo=t; return r;},
              status(s){st=s; return r;}, send(b){corpo=b; res({st,tipo,corpo,headers});} };
    const h=rotas.get(p); if(!h) return res({st:404,tipo:'',corpo:'',headers:{}});
    h({},r);
  });
}

let f=0; const t=(n,ok,ex='')=>{console.log((ok?'  ✓ ':'  ✗ ')+n+(ex?' — '+ex:'')); if(!ok)f++;};
console.log('ROTAS de /pav/scan:\n');
console.log('  registradas: '+[...rotas.keys()].join(', ')+'\n');

const reader = await chamar('/pav/scan/reader.js');
t('reader.js responde 200', reader.st===200, 'HTTP '+reader.st);
t('reader.js tem conteúdo real', reader.corpo.length>5000, reader.corpo.length+' bytes');
t('reader.js exporta o que a página importa',
  ['readSheet','readNumber','loadDigitMLP','findFiducials'].every(x=>reader.corpo.includes('export function '+x)));

const tpl = await chamar('/pav/scan/template.json');
t('template.json tem geometria', tpl.corpo.includes('fiducials_mm'), tpl.corpo.length+' bytes');

const mod = await chamar('/pav/scan/model.json');
t('model.json tem os pesos', mod.corpo.includes('W0'), mod.corpo.length+' bytes');

const sw = await chamar('/pav/scan/sw.js');
t('sw.js é network-first', sw.corpo.includes('await fetch(e.request)') && !sw.corpo.includes("r || fetch"));
t('sw.js tem cache versionado', /const VER = '[0-9a-f]{6,}'/.test(sw.corpo),
  (sw.corpo.match(/const VER = '([^']*)'/)||[])[1]);
t('sw.js não é cacheado', sw.headers['Cache-Control']==='no-store');

const diag = await chamar('/pav/scan/diag');
t('/diag responde e é autocontido', diag.corpo.includes('diagnóstico') && !diag.corpo.includes('type="module"'));

const pag = await chamar('/pav/scan');
t('página injeta a versão (sem __VER__ sobrando)', !pag.corpo.includes('__VER__'));
t('página tem captura de erro de boot', pag.corpo.includes('__bootErro'));
t('página é no-store', pag.headers['Cache-Control']==='no-store');

console.log(`\n${f? f+' FALHA(S)':'rotas OK'}`);
process.exit(f?1:0);
