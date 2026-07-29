// harness-pav-scan-sw.mjs
//   uso:  node harness-pav-scan-sw.mjs [caminho/pav-scan-routes.js]
//
// Simula o Service Worker do /pav/scan e prova a propriedade que faltava e que
// nos custou várias rodadas de depuração às cegas: DEPOIS DE UM DEPLOY, O
// APARELHO RECEBE O CÓDIGO NOVO.
//
// A versão antiga usava cache-first com nome de cache fixo. O primeiro acesso
// congelava o app naquela versão e todo deploy seguinte era silenciosamente
// ignorado — a tela continuava idêntica, sem erro, dando a impressão de que as
// correções não funcionavam (quando na verdade nem chegavam a rodar).

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const alvo = process.argv[2] || path.join(__dirname, 'pav-scan-routes.js');
const src = fs.readFileSync(alvo, 'utf8');

// extrai o corpo do SW servido pela rota
const m = src.match(/app\.get\('\/pav\/scan\/sw\.js'[\s\S]*?res\.type\('application\/javascript'\)\.send\(`([\s\S]*?)`\);/);
if (!m) { console.log('✗ não encontrei o service worker no arquivo'); process.exit(1); }
const swFonte = m[1];

// ── ambiente mínimo de Service Worker ─────────────────────────────────────
function novoAmbiente(versao, servidor) {
  const caches_ = new Map();          // nome -> Map(url -> corpo)
  const handlers = {};
  const caches = {
    async open(nome) {
      if (!caches_.has(nome)) caches_.set(nome, new Map());
      const store = caches_.get(nome);
      return {
        async put(req, resp) { store.set(typeof req === 'string' ? req : req.url, await resp.text()); },
        async addAll(urls) {
          // normaliza p/ URL absoluta — é assim que o navegador chaveia o cache
          for (const u of urls) { const abs = new URL(u, 'https://app.exemplo').href; store.set(abs, servidor(abs)); }
        },
        async match(req) { const u = typeof req === 'string' ? req : req.url; return store.has(u) ? resposta(store.get(u)) : undefined; },
      };
    },
    async keys() { return [...caches_.keys()]; },
    async delete(nome) { return caches_.delete(nome); },
    async match(req) {
      const u = typeof req === 'string' ? req : req.url;
      for (const store of caches_.values()) if (store.has(u)) return resposta(store.get(u));
      return undefined;
    },
  };
  const resposta = (corpo, ok = true) => ({
    ok, _corpo: corpo, async text() { return corpo; }, clone() { return resposta(corpo, ok); },
  });

  let rede = true;
  const self_ = {
    location: { origin: 'https://app.exemplo' },
    addEventListener(ev, fn) { handlers[ev] = fn; },
    skipWaiting() { self_._skip = true; },
    clients: { async claim() { self_._claim = true; } },
  };
  const fetch_ = async (req) => {
    if (!rede) throw new Error('offline');
    const u = typeof req === 'string' ? req : req.url;
    return resposta(servidor(u));
  };

  const fn = new Function('self', 'caches', 'fetch', 'URL', 'Promise', 'console', swFonte
    .replace(/\$\{VER\}/g, versao));
  fn(self_, caches, fetch_, URL, Promise, console);

  return {
    handlers, caches_, self_,
    setRede(v) { rede = v; },
    async install() { const e = { waitUntil: p => p }; await handlers.install?.(e); },
    async activate() { let p; await handlers.activate?.({ waitUntil: x => { p = x; return x; } }); await p; },
    async buscar(url) {
      let out = null;
      const e = { request: { url, method: 'GET' }, respondWith(p) { out = p; } };
      try { handlers.fetch?.(e); } catch (err) { return '<<ERRO:' + err.message + '>>'; }
      if (!out) {                                   // não interceptou → rede direta
        try { return servidor(url); } catch (err) { return '<<ERRO:offline>>'; }
      }
      try {
        const r = await out;
        return r?._corpo ?? (r?.text ? await r.text() : '<<VAZIO>>');
      } catch (err) { return '<<ERRO:' + err.message + '>>'; }
    },
  };
}

// ── cenário: deploy v1 → usuário acessa → deploy v2 → usuário volta ───────
let falhas = 0;
const t = (n, ok, extra = '') => { console.log((ok ? '  ✓ ' : '  ✗ ') + n + (extra ? ' — ' + extra : '')); if (!ok) falhas++; };

console.log('SERVICE WORKER — o deploy novo chega ao aparelho?\n');

// servidor "v1"
let versaoServida = 'CODIGO-V1';
const servidor = (u) => versaoServida + ' @ ' + u;

const a1 = novoAmbiente('hash-v1', servidor);
await a1.install();
await a1.activate();
const r1 = await a1.buscar('https://app.exemplo/pav/scan/reader.js');
t('1ª visita recebe o código v1', String(r1).includes('CODIGO-V1'), String(r1).slice(0, 24));

// ── DEPLOY: o servidor passa a entregar v2 ──
versaoServida = 'CODIGO-V2';

// mesmo SW ainda instalado (o navegador só troca quando o sw.js muda)
const r2 = await a1.buscar('https://app.exemplo/pav/scan/reader.js');
t('após deploy, o MESMO SW já entrega v2 (network-first)', String(r2).includes('CODIGO-V2'),
  String(r2).includes('CODIGO-V1') ? 'PRESO NO CACHE ANTIGO' : '');

// SW novo (hash mudou porque o conteúdo mudou)
const a2 = novoAmbiente('hash-v2', servidor);
// herda os caches antigos do aparelho
for (const [k, v] of a1.caches_) a2.caches_.set(k, v);
await a2.install();
t('SW novo chama skipWaiting (assume sem esperar)', a2.self_._skip === true);
await a2.activate();
t('SW novo chama clients.claim (controla as abas abertas)', a2.self_._claim === true);
t('caches antigos foram apagados', ![...a2.caches_.keys()].some(k => k.includes('hash-v1')),
  [...a2.caches_.keys()].join(','));
const r3 = await a2.buscar('https://app.exemplo/pav/scan/reader.js');
t('SW novo entrega v2', String(r3).includes('CODIGO-V2'));

// ── offline: o cache tem que salvar (UTI sem sinal) ──
await a2.buscar('https://app.exemplo/pav/scan/reader.js');   // garante cache quente
a2.setRede(false);
const r4 = await a2.buscar('https://app.exemplo/pav/scan/reader.js');
t('offline: serve do cache (uso na UTI)', String(r4).includes('CODIGO-V2'),
  r4 ? '' : 'nada devolvido');

console.log(`\n${falhas ? falhas + ' FALHA(S)' : 'service worker OK — deploys chegam e offline funciona'}`);
process.exit(falhas ? 1 : 0);
