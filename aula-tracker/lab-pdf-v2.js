// ============================================================
//  lab-pdf-v2.js — Template REDESENHADO do laudo (paralelo)
//  Mesma linguagem visual do diagnostico/ (Fraunces + IBM Plex,
//  acento safranin). Mesmo contrato de dados do lab-pdf.js:
//    buildPdfHtmlV2({ patient, collection, results, sign })
//    generateLabPdfV2(data)  → Buffer
//  Preserva: identificação, blocos por exame (Amostra·Método·VR),
//  resultado color-coded, seção T/C (split ||TC||), observação,
//  grade de imagens (r.images[].dataUri) e assinatura ICP-Brasil.
//  Mecânica idêntica: header/footer repetidos por página,
//  page-break-inside:avoid, A4.
// ============================================================
import puppeteer from 'puppeteer';
import { readFileSync } from 'node:fs';

// Logo (mesmo arquivo do template atual)
let LOGO_SVG = '';
try {
  LOGO_SVG = readFileSync(new URL('./logo-lm.svg', import.meta.url), 'utf8');
} catch {
  LOGO_SVG = '';
}

let _browserV2 = null;

// ── helpers (espelham o lab-pdf.js) ─────────────────────────────
function safe(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function toBR(dateStr) {
  if (!dateStr) return '—';
  const s = String(dateStr);
  if (/^\d{2}\/\d{2}\/\d{4}$/.test(s)) return s;
  const d = new Date(s.length === 10 ? s + 'T12:00:00' : s);
  if (isNaN(d)) return s;
  return d.toLocaleDateString('pt-BR');
}
// Semântica clínica preservada, em tons da marca:
//   positivo/reagente → safranin (atenção) · negativo → verde quente · neutro → atenuado
function resultColorV2(value, storedColor) {
  if (storedColor === 'positivo') return '#6e2c3c';
  if (storedColor === 'negativo') return '#3f6b4c';
  if (storedColor === 'neutro')   return '#8a807c';
  const v = (value || '').toUpperCase();
  if (/EM\s+ANDAMENTO/.test(v))                                  return '#8a807c';
  if (/NÃO\s+REAGENTE|NAO\s+REAGENTE|NEGATIVO|AUSENTE/.test(v)) return '#3f6b4c';
  if (/REAGENTE|POSITIVO|PRESENTE|CRESCIMENTO|DETECTADO/.test(v) &&
      !/NÃO\s+DETECTADO|NAO\s+DETECTADO/.test(v))                return '#6e2c3c';
  return '#211c1d';
}
function formatResultText(value) {
  return safe((value || '').trim())
    .replace(/\*(.+?)\*/gs, '<strong>$1</strong>')
    .replace(/_(.+?)_/gs,   '<em>$1</em>')
    .replace(/^EM ANDAMENTO$/im, '<em style="color:#8a807c">Em andamento</em>')
    .replace(/SENSÍVEL A:/gi,   '<span style="color:#3f6b4c;font-weight:700">SENSÍVEL A:</span>')
    .replace(/RESISTENTE A:/gi, '<span style="color:#6e2c3c;font-weight:700">RESISTENTE A:</span>')
    .replace(/\r\n|\r|\n/g, '<br>');   // quebras de linha por último (após âncoras ^/$)
}

// ── Template HTML ───────────────────────────────────────────────
export function buildPdfHtmlV2({ patient, collection, results, sign }) {
  const todayBR     = new Date().toLocaleDateString('pt-BR');
  const collectedBR = toBR(collection.collected_at);
  const birthBR     = toBR(patient.birth_date);
  const lauNo       = `${new Date().getFullYear()}-${String(collection.id || '').padStart(4, '0')}`;

  const logoHtml = LOGO_SVG
    ? `<div class="logo-wrap">${LOGO_SVG}</div>`
    : `<div class="logo-wrap seal"><span>LM</span></div>`;

  const resultsHtml = results.map((r, i) => {
    const tcMatch   = r.result_value ? r.result_value.match(/^([\s\S]*?)\|\|TC\|\|(.+)$/) : null;
    const mainValue = tcMatch ? tcMatch[1].trim() : r.result_value;
    const tcDisplay = tcMatch ? tcMatch[2].trim() : null;

    const tcHtml = tcDisplay
      ? `<div class="tcsec"><span class="tl">Relação T/C</span><span class="tv">${safe(tcDisplay)}</span></div>`
      : '';
    const obs = r.observation
      ? `<div class="obs">${safe(r.observation)}</div>`
      : '';
    const imagesHtml = (r.images && r.images.length)
      ? `<div class="imgs"><div class="il">Imagens</div><div class="grid">
           ${r.images.map(img => {
             const w = Math.max(10, Math.min(100, img.display_width || 50));
             return `<div class="im" style="width:calc(${w}% - 8px)">
               <img src="${img.dataUri}" alt="${safe(img.caption || '')}">
               ${img.caption ? `<div class="cap">${safe(img.caption)}</div>` : ''}
             </div>`;
           }).join('')}
         </div></div>`
      : '';

    return `
      <div class="exam">
        <div class="en">${safe(r.exam_name)}</div>
        <div class="meta">
          <span><b>Amostra:</b> ${safe(r.sample_type)}</span>
          <span><b>Método:</b> ${safe(r.method)}</span>
          <span><b>VR:</b> ${safe(r.reference_value || '—')}</span>
        </div>
        <div class="resblock">
          <span class="rl">Resultado</span>
          <span class="rv" style="color:${resultColorV2(mainValue, r.result_color)}">${formatResultText(mainValue)}</span>
        </div>
        ${tcHtml}
        ${obs}
        ${imagesHtml}
      </div>`;
  }).join('');

  const signHtml = sign
    ? `<div class="sign">
         <div class="stamp"><div><div class="s1">ICP-BRASIL</div><div class="s2">assinado</div></div></div>
         <div class="txt">Assinado digitalmente com certificado <b>ICP-Brasil</b> por Leandro César Mendes — CRM 134.985/SP.
           <div class="vf">verifique em <b>${safe(sign.verifUrl)}</b> · código <span class="code">${safe(sign.verifCode)}</span></div>
         </div>
       </div>`
    : '';

  return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,340;9..144,420;9..144,540;9..144,600&family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root{--ink:#211c1d;--ink-soft:#3a2f31;--paper:#fdfcf9;--slide:#efeae1;
    --safranin:#6e2c3c;--muted:#6b615e;--muted-2:#8a807c;--hair:#e0d8cd;--hair-soft:#efe8dc;
    --serif:"Fraunces",Georgia,serif;--sans:"IBM Plex Sans",system-ui,sans-serif;--mono:"IBM Plex Mono",ui-monospace,monospace;}
  *{box-sizing:border-box}
  html,body{margin:0;padding:0}
  body{font-family:var(--sans);color:var(--ink);background:var(--paper);font-size:12px;line-height:1.5;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .page{padding:6mm 20mm 4mm;position:relative}
  /* header decorativo (pág. 1) */
  .head{display:flex;justify-content:space-between;align-items:flex-start}
  .clinic .nm{font-family:var(--serif);font-size:15px;font-weight:540;line-height:1.1}
  .clinic .sp{font-family:var(--mono);font-size:8px;letter-spacing:.14em;text-transform:uppercase;color:var(--safranin);margin-top:2px}
  .clinic .reg{font-family:var(--mono);font-size:7.5px;color:var(--muted);margin-top:3px}
  .doc{text-align:right;display:flex;gap:12px;align-items:flex-start}
  .doc .dt{font-family:var(--serif);font-size:17px;font-weight:420}
  .doc .nl{font-family:var(--mono);font-size:8px;color:var(--muted);margin-top:3px}
  .logo-wrap{width:40px;height:40px;flex:0 0 auto}
  .logo-wrap svg{width:40px;height:40px}
  .logo-wrap.seal{border:1.5px solid var(--safranin);border-radius:50%;display:grid;place-items:center;color:var(--safranin)}
  .logo-wrap.seal span{font-family:var(--serif);font-weight:540;font-size:18px}
  .rule{height:2px;background:var(--safranin);border-radius:2px;margin:10px 0 0}
  /* identificação */
  .ident{display:grid;grid-template-columns:1fr 1fr;gap:2px 20px;margin:12px 0 14px}
  .ident .row{display:flex;gap:8px;font-size:11px;padding:2px 0;border-bottom:1px solid var(--hair-soft)}
  .ident .k{font-family:var(--mono);font-size:8px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);min-width:88px;padding-top:1px}
  .ident .v{font-weight:500}
  /* exames */
  .exam{padding:11px 0;border-top:1px solid var(--hair);page-break-inside:avoid}
  .exam:first-of-type{border-top:none}
  .en{font-family:var(--serif);font-size:13.5px;font-weight:540;line-height:1.15}
  .meta{display:flex;gap:16px;flex-wrap:wrap;margin-top:4px;font-family:var(--mono);font-size:8px;color:var(--muted)}
  .meta b{color:var(--ink-soft);font-weight:600}
  .resblock{margin-top:7px;display:flex;align-items:baseline;gap:10px}
  .resblock .rl{font-family:var(--mono);font-size:7.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
  .resblock .rv{font-size:13px;font-weight:600}
  .tcsec{margin-top:5px;display:flex;gap:8px;align-items:baseline}
  .tcsec .tl{font-family:var(--mono);font-size:7.5px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
  .tcsec .tv{font-family:var(--mono);font-size:10px;color:var(--ink-soft);font-weight:500}
  .obs{margin-top:5px;font-size:10.5px;color:var(--muted);font-style:italic}
  .imgs{margin-top:7px}
  .imgs .il{font-family:var(--mono);font-size:7.5px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-bottom:4px}
  .imgs .grid{display:flex;gap:8px;flex-wrap:wrap;align-items:flex-start}
  .imgs .im{flex:0 0 auto;min-width:60px}
  .imgs .im img{width:100%;height:auto;max-height:80mm;object-fit:contain;border-radius:4px;border:1px solid var(--hair);display:block}
  .imgs .cap{font-family:var(--mono);font-size:7px;color:var(--muted);margin-top:2px;text-align:center}
  /* assinatura */
  .sign{margin-top:16px;padding:12px 14px;background:var(--slide);border-radius:10px;display:flex;gap:12px;align-items:center;page-break-inside:avoid}
  .sign .stamp{width:50px;height:50px;flex:0 0 auto;border-radius:50%;border:1.5px solid var(--safranin);display:grid;place-items:center;text-align:center;color:var(--safranin)}
  .sign .stamp .s1{font-family:var(--mono);font-size:6px;letter-spacing:.08em}
  .sign .stamp .s2{font-family:var(--serif);font-size:9px;font-weight:600}
  .sign .txt{font-size:10px;line-height:1.5;color:var(--ink-soft)}
  .sign .txt b{color:var(--ink)}
  .sign .vf{font-family:var(--mono);font-size:9px;color:var(--muted);margin-top:2px}
  .sign .vf .code{color:var(--safranin);font-weight:600}
</style></head>
<body>
  <div class="page">
    <div class="head">
      <div class="clinic">
        <div class="nm">Consultório Dr. Leandro Mendes</div>
        <div class="sp">Infectologia · Diagnóstico</div>
        <div class="reg">CRM 134.985/SP · RQE 61.808</div>
      </div>
      <div class="doc">
        <div>
          <div class="dt">Resultado de Exame</div>
          <div class="nl">laudo nº ${safe(lauNo)} · emitido ${todayBR}</div>
        </div>
        ${logoHtml}
      </div>
    </div>
    <div class="rule"></div>

    <div class="ident">
      <div class="row"><span class="k">Paciente</span><span class="v">${safe(patient.full_name)}</span></div>
      <div class="row"><span class="k">Nascimento</span><span class="v">${birthBR}</span></div>
      <div class="row"><span class="k">Data do teste</span><span class="v">${collectedBR}</span></div>
      <div class="row"><span class="k">Emitido em</span><span class="v">${todayBR}</span></div>
    </div>

    ${resultsHtml}
    ${signHtml}
  </div>
</body></html>`;
}

// ── Puppeteer (mesma mecânica do lab-pdf.js) ────────────────────
async function getBrowserV2() {
  if (!_browserV2 || !_browserV2.connected) {
    _browserV2 = await puppeteer.launch({
      headless: true,
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || puppeteer.executablePath(),
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
    });
  }
  return _browserV2;
}

export async function generateLabPdfV2(data) {
  const { patient, collection } = data;
  const esc = s => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  const headerTemplate = `<div style="width:100%;padding:4px 20mm 3px;box-sizing:border-box;
      font-size:7px;font-family:'IBM Plex Mono',ui-monospace,monospace;
      border-bottom:0.5px solid #e0d8cd;display:flex;justify-content:space-between;align-items:center;color:#8a807c;letter-spacing:.02em">
    <span style="font-weight:600;color:#6e2c3c">Dr. Leandro Mendes<span style="font-weight:400;color:#8a807c"> · Infectologia · CRM 134.985/SP</span></span>
    <span><strong style="color:#3a2f31">${esc(patient.full_name)}</strong><span style="color:#8a807c">&nbsp;·&nbsp;DN ${toBR(patient.birth_date)}&nbsp;·&nbsp;Coleta ${toBR(collection.collected_at)}</span></span>
  </div>`;

  const footerTemplate = `<div style="width:100%;padding:2px 20mm 0;box-sizing:border-box;
      font-size:6.5px;font-family:'IBM Plex Mono',ui-monospace,monospace;
      border-top:0.5px solid #e0d8cd;display:flex;justify-content:space-between;align-items:center;color:#8a807c">
    <span>Clínica Kadri · Euroville Tower Corporate · Praça Maastrich, 200, sala 64, Bragança Paulista-SP · lcmendes@gmail.com · (11) 99611-2338</span>
    <span style="white-space:nowrap;margin-left:8px">p.&nbsp;<span class="pageNumber"></span>/<span class="totalPages"></span></span>
  </div>`;

  const browser = await getBrowserV2();
  const page = await browser.newPage();
  try {
    await page.setContent(buildPdfHtmlV2(data), { waitUntil: 'networkidle0' });
    return await page.pdf({
      format: 'A4',
      printBackground: true,
      displayHeaderFooter: true,
      headerTemplate,
      footerTemplate,
      margin: { top: '20mm', bottom: '16mm', left: '0', right: '0' },
    });
  } finally {
    await page.close();
  }
}
