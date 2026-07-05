// pacs-nome-worker.mjs
// ─────────────────────────────────────────────────────────────────────────
// WORKER de captura de nome do PACS — roda numa VPS NO BRASIL.
//
// Por quê no Brasil: o PACS (Animati) tem bloqueio geográfico e só aceita
// acesso de dentro do país. O app fica no Render (EUA), então é barrado. Este
// worker roda no Brasil, faz o login legítimo (prontuário + DN, o mesmo do
// navegador do médico) e devolve SÓ o nome (grafia) ao app — nenhum outro dado
// do PACS é lido. O PACS é apenas um checkpoint da grafia de um nome que o app
// já possui.
//
// Fluxo:
//   1) GET  {APP_BASE}/atb/api/pacs-nome/pendentes  → lista {prontuario, dn}
//   2) p/ cada: login no PACS via Puppeteer (contexto isolado) → lê o nome
//   3) POST {APP_BASE}/atb/api/pacs-nome  → grava o nome
//
// Instalar na VPS (Node 18+):
//   npm init -y && npm i puppeteer && npx puppeteer browsers install chrome
//   APP_BASE=https://app.lcmendes.med.br PACS_NOME_TOKEN=xxxx node pacs-nome-worker.mjs
// Agendar via cron (de hora em hora), ex.:
//   0 * * * * cd /caminho && APP_BASE=... PACS_NOME_TOKEN=... /usr/bin/node pacs-nome-worker.mjs >> worker.log 2>&1
//
// ⚠ NUNCA versione o token — ele vem por variável de ambiente.

import puppeteer from 'puppeteer';

const APP_BASE  = process.env.APP_BASE || 'https://app.lcmendes.med.br';
const TOKEN     = process.env.PACS_NOME_TOKEN;
const LIMIT     = parseInt(process.env.LIMIT || '25', 10);
const DELAY_MS  = parseInt(process.env.DELAY_MS || '4000', 10); // pausa entre pacientes (gentil c/ o PACS)
const PACS_BASE = 'https://pacs.husf.com.br';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36';

if (!TOKEN) { console.error('Falta a env var PACS_NOME_TOKEN'); process.exit(1); }

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// login = "p"+prontuário ; senha = DN em DDMMAAAA (a DN chega como AAAA-MM-DD)
function credenciais(prontuario, dn) {
  const d = String(dn || '').replace(/[^0-9]/g, '');
  return { user: 'p' + String(prontuario || '').trim(), pass: d.length >= 8 ? d.slice(6, 8) + d.slice(4, 6) + d.slice(0, 4) : '' };
}

async function pendentes() {
  const r = await fetch(`${APP_BASE}/atb/api/pacs-nome/pendentes?limit=${LIMIT}`, { headers: { 'X-Pacs-Token': TOKEN } });
  if (!r.ok) throw new Error('pendentes HTTP ' + r.status);
  const j = await r.json();
  return (j && j.pendentes) || [];
}

async function enviar(prontuario, nome) {
  const r = await fetch(`${APP_BASE}/atb/api/pacs-nome`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Pacs-Token': TOKEN },
    body: JSON.stringify({ prontuario, nome }),
  });
  if (!r.ok) throw new Error('ingest HTTP ' + r.status);
}

// Login same-origin no PACS + leitura do nome. Contexto isolado por paciente
// (cookies não vazam entre logins).
async function capturar(browser, prontuario, dn) {
  const { user, pass } = credenciais(prontuario, dn);
  if (!pass) return null;
  const context = await browser.createBrowserContext(); // Puppeteer v22+ (isola sessão)
  const page = await context.newPage();
  try {
    await page.setUserAgent(UA);
    page.setDefaultNavigationTimeout(30000);
    // 1) GET inicial (mesma origem) — estabelece a sessão/cookie
    await page.goto(PACS_BASE + '/', { waitUntil: 'networkidle2' }).catch(() => {});
    // 2) LOGIN same-origin: form no próprio PACS → j_spring_security_check (cookie viaja)
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 30000 }).catch(() => {}),
      page.evaluate((u, p) => {
        const f = document.createElement('form');
        f.method = 'POST'; f.action = '/j_spring_security_check';
        const a = document.createElement('input'); a.type = 'hidden'; a.name = 'j_username'; a.value = u; f.appendChild(a);
        const b = document.createElement('input'); b.type = 'hidden'; b.name = 'j_password'; b.value = p; f.appendChild(b);
        document.body.appendChild(f); f.submit();
      }, user, pass),
    ]);
    await page.waitForSelector('th', { timeout: 15000 }).catch(() => {});
    // 3) lê o nome (coluna "Nome do paciente" da YUI DataTable)
    return await page.evaluate(() => {
      const ths = [].slice.call(document.querySelectorAll('th'));
      let th = null;
      for (let i = 0; i < ths.length; i++) { if (/nome do paciente/i.test(ths[i].innerText || '')) { th = ths[i]; break; } }
      if (!th) return null;
      let nome = null;
      const col = (th.className || '').match(/yui-dt-col-[\w-]+/);
      if (col) { const c = document.querySelector('td.' + col[0] + ' .yui-dt-liner'); if (c) nome = (c.innerText || '').trim(); }
      if (!nome && th.cellIndex >= 0) { const r = document.querySelector('table tbody tr'); if (r && r.children[th.cellIndex]) nome = (r.children[th.cellIndex].innerText || '').trim(); }
      return nome || null;
    });
  } finally {
    await context.close().catch(() => {});
  }
}

(async () => {
  let lista;
  try { lista = await pendentes(); }
  catch (e) { console.error('[worker] falha ao buscar pendentes:', e.message); process.exit(1); }
  console.log(`[worker] ${lista.length} ficha(s) pendente(s)`);
  if (!lista.length) return;

  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
  });
  let ok = 0;
  try {
    for (const f of lista) {
      try {
        const nome = await capturar(browser, f.prontuario, f.dn);
        if (nome) { await enviar(f.prontuario, nome); ok++; console.log(`[worker] ${f.prontuario} → ${nome}`); }
        else console.log(`[worker] ${f.prontuario} → sem nome (login falhou ou paciente sem estudos)`);
      } catch (e) { console.log(`[worker] ${f.prontuario} → erro: ${e.message}`); }
      await sleep(DELAY_MS);
    }
  } finally {
    await browser.close().catch(() => {});
  }
  console.log(`[worker] concluído: ${ok}/${lista.length} capturados`);
})();
