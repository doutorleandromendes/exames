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

import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

let f=0; const t=(n,ok,ex='')=>{console.log((ok?'  ✓ ':'  ✗ ')+n+(ex?' — '+ex:'')); if(!ok)f++;};

// Valida a SINTAXE do JavaScript que realmente chega ao navegador.
// Existe por causa de um bug que custou dias: '\n' escrito dentro do template
// literal do servidor é interpretado pelo Node e vira quebra de linha REAL no
// HTML enviado — quebrando as strings do script. O servidor compila, o HTML
// chega, e o script morre inteiro no navegador com SyntaxError. A página fica
// visualmente montada e completamente inerte, sem nenhum erro do lado do Node.
// Verifica se o atributo `hidden` realmente esconde os elementos que o código
// alterna. Regras por ID com `display:` têm especificidade maior que a folha do
// navegador ([hidden]{display:none}) e a anulam em silêncio: o elemento "some"
// no JS e continua na tela. Foi assim que a captura ficou presa em "capturando…"
// — a tela de revisão abria ATRÁS da câmera, que nunca era escondida.
function checarHidden(nome, html){
  const css=(html.match(/<style>([\s\S]*?)<\/style>/)||[])[1]||'';
  const js=(html.match(/<script(?:\s+type="module")?>([\s\S]*?)<\/script>/g)||[]).join('\n');
  // ids cujo `hidden` o código manipula
  const alvos=[...new Set([...js.matchAll(/\$\('#([a-zA-Z0-9_-]+)'\)\.hidden\s*=/g)].map(m=>m[1]))];
  if(!alvos.length) return;
  const temReset=/\[hidden\]\s*{[^}]*display\s*:\s*none\s*!important/.test(css);
  const perigosos=alvos.filter(id=>new RegExp('#'+id+'\\s*{[^}]*display\\s*:','m').test(css));
  t(nome+': `hidden` funciona nos elementos alternados', temReset || perigosos.length===0,
    perigosos.length && !temReset
      ? 'regra #'+perigosos.join(', #')+' com display: anula o hidden (falta [hidden]{display:none!important})'
      : 'ids: '+alvos.join(', '));
}

function checarScripts(nome, html){
  const scripts=[...html.matchAll(/<script(?:\s+type="module")?>([\s\S]*?)<\/script>/g)];
  t(nome+': tem script embutido', scripts.length>0, scripts.length+' bloco(s)');
  scripts.forEach((m,i)=>{
    const tmp=path.join(os.tmpdir(), `chk-${nome}-${i}-${Date.now()}.mjs`);
    fs.writeFileSync(tmp, m[1]);
    let ok=true, msg='';
    try { execFileSync(process.execPath, ['--check', tmp], {stdio:'pipe'}); }
    catch(e){ ok=false; msg=String(e.stderr||e).split('\n').slice(1,3).join(' ').trim().slice(0,90); }
    fs.unlinkSync(tmp);
    t(`${nome}: script #${i} tem sintaxe válida`, ok, msg);
  });
  // nenhuma string pode ficar aberta por quebra de linha crua
  const abertas=html.split('\n').filter(l=>(l.match(/(?<!\\)'/g)||[]).length%2===1);
  t(nome+': nenhuma string aberta por quebra de linha', abertas.length===0,
    abertas.length? abertas.length+' linha(s), ex.: '+abertas[0].trim().slice(0,50) : '');
}
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
checarScripts('diag', diag.corpo);

const pag = await chamar('/pav/scan');
t('página injeta a versão (sem __VER__ sobrando)', !pag.corpo.includes('__VER__'));
t('página tem captura de erro de boot', pag.corpo.includes('__bootErro'));
t('página é no-store', pag.headers['Cache-Control']==='no-store');
checarScripts('scan', pag.corpo);
checarHidden('scan', pag.corpo);

console.log(`\n${f? f+' FALHA(S)':'rotas OK'}`);
process.exit(f?1:0);
