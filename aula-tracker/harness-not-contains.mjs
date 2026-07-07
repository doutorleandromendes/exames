// harness-not-contains.mjs
// Prova o operador not_contains / not_contains_any nos DOIS avaliadores
// (engine cliente + validador servidor) e na regra real de "Uso prévio de VM".
// Extrai avaliaCond do engine (função de browser) e importa avaliaCondServer.
// Uso: node harness-not-contains.mjs

import { readFileSync } from 'fs';
import { avaliaCondServer } from './atb-regras-form-routes.js';

// ── extrai a função avaliaCond do engine (arquivo de browser, sem export) ────
const src = readFileSync('./atb-form-engine.js', 'utf8');
const ini = src.indexOf('function avaliaCond(');
const corpo = src.slice(ini);
// pega até o fechamento da função (contagem simples de chaves)
let depth = 0, fim = -1, started = false;
for (let i = corpo.indexOf('{'); i < corpo.length; i++) {
  if (corpo[i] === '{') { depth++; started = true; }
  else if (corpo[i] === '}') { depth--; if (started && depth === 0) { fim = i + 1; break; } }
}
const fnTxt = corpo.slice(0, fim);
const _filled = v => v !== undefined && v !== null && v !== '' && !(Array.isArray(v) && v.length === 0);
const _textContainsAny = () => false; // não usado neste teste
// eslint-disable-next-line no-new-func
const avaliaCond = new Function('_filled', '_textContainsAny', fnTxt + '; return avaliaCond;')(_filled, _textContainsAny);

// ── regra real: VM obrigatório quando UTI/UTI C E dispositivos SEM IOT ────────
const REGRA_VM = { all: [
  { campo: 'setor', op: 'in', valor: ['UTI', 'UTI C'] },
  { campo: 'dispositivos_invasivos', op: 'not_contains', valor: 'IOT' },
]};

const casos = [
  { nome: 'UTI, sem dispositivos → exige VM',        d: { setor: 'UTI', dispositivos_invasivos: [] },              esperado: true },
  { nome: 'UTI, só AVP → exige VM',                  d: { setor: 'UTI', dispositivos_invasivos: ['AVP'] },         esperado: true },
  { nome: 'UTI COM IOT → NÃO exige VM',              d: { setor: 'UTI', dispositivos_invasivos: ['IOT'] },         esperado: false },
  { nome: 'UTI COM IOT+AVP → NÃO exige VM',          d: { setor: 'UTI', dispositivos_invasivos: ['AVP','IOT'] },   esperado: false },
  { nome: 'UTI C, sem IOT → exige VM',               d: { setor: 'UTI C', dispositivos_invasivos: ['SVD'] },       esperado: true },
  { nome: 'Enfermaria (fora UTI), sem IOT → não',    d: { setor: 'Semi', dispositivos_invasivos: [] },             esperado: false },
  { nome: 'UTI, dispositivos ausente → exige VM',    d: { setor: 'UTI' },                                          esperado: true },
];

// ── not_contains_any: nenhum de uma lista ────────────────────────────────────
const REGRA_NENHUM = { campo: 'dispositivos_invasivos', op: 'not_contains_any', valor: ['IOT', 'CDL (Shilley)'] };
const casosLista = [
  { nome: 'sem IOT nem CDL → true',   d: { dispositivos_invasivos: ['AVP', 'CVC'] },      esperado: true },
  { nome: 'tem IOT → false',          d: { dispositivos_invasivos: ['AVP', 'IOT'] },      esperado: false },
  { nome: 'tem CDL → false',          d: { dispositivos_invasivos: ['CDL (Shilley)'] },   esperado: false },
];

let passed = 0, failed = 0;
function roda(titulo, regra, lista) {
  console.log('── ' + titulo);
  for (const c of lista) {
    const cli = avaliaCond(regra, c.d);
    const srv = avaliaCondServer(regra, c.d);
    const concordam = cli === srv;
    const certo = cli === c.esperado;
    const OK = concordam && certo;
    console.log((OK ? '✅' : '❌'), c.nome.padEnd(42), 'cliente=' + cli, 'servidor=' + srv,
      concordam ? '' : '⚠ DIVERGEM', certo ? '' : '⚠ esperado ' + c.esperado);
    OK ? passed++ : failed++;
  }
}

roda('not_contains (regra VM real)', REGRA_VM, casos);
roda('not_contains_any', REGRA_NENHUM, casosLista);

console.log(`\n${passed} passaram, ${failed} falharam`);
if (failed) process.exit(1);
