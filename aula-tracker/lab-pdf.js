// lab-pdf.js
// Geração de PDF dos laudos via Puppeteer
// O logo é lido uma vez na inicialização de logo-lm.svg

import puppeteer from 'puppeteer';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { fetchR2ImageAsDataURI } from './lab-storage.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Carrega o SVG do logo uma vez ao iniciar o servidor
let LOGO_SVG = '';
try {
  LOGO_SVG = readFileSync(join(__dirname, 'logo-lm.svg'), 'utf-8');
} catch {
  console.warn('[lab-pdf] logo-lm.svg não encontrado — usando círculo vazio');
}

// ====== Helpers ======

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

function resultColor(value, storedColor) {
  if (storedColor === 'positivo') return '#b03030';
  if (storedColor === 'negativo') return '#1a7a4a';
  if (storedColor === 'neutro')   return '#888888';
  const v = (value || '').toUpperCase();
  if (/EM\s+ANDAMENTO/.test(v))                                   return '#888888';
  if (/NÃO\s+REAGENTE|NAO\s+REAGENTE|NEGATIVO|AUSENTE/.test(v)) return '#1a7a4a';
  if (/REAGENTE|POSITIVO|PRESENTE|CRESCIMENTO/.test(v))          return '#b03030';
  return '#1a1a1a';
}

function formatResultText(value) {
  return safe((value || '').trim())
    .replace(/\*(.+?)\*/gs,  '<strong>$1</strong>')
    .replace(/_(.+?)_/gs,    '<em>$1</em>')
    .replace(/^EM ANDAMENTO$/im,
      '<em style="color:#888">Em andamento</em>')
    .replace(/SENSÍVEL A:/gi,
      '<span style="color:#1a7a4a;font-weight:700">SENSÍVEL A:</span>')
    .replace(/RESISTENTE A:/gi,
      '<span style="color:#b03030;font-weight:700">RESISTENTE A:</span>');
}

// ====== Template HTML do laudo ======

export function buildPdfHtml({ patient, collection, results }) {
  const todayBR     = new Date().toLocaleDateString('pt-BR');
  const collectedBR = toBR(collection.collected_at);
  const birthBR     = toBR(patient.birth_date);

  const logoHtml = LOGO_SVG
    ? `<div class="logo-wrap">${LOGO_SVG}</div>`
    : `<div class="logo-wrap"></div>`;

  const resultsHtml = results.map((r, i) => {
    const obs = r.observation
      ? `<div class="res-obs">${safe(r.observation)}</div>`
      : '';
    const divider = i < results.length - 1
      ? '<div class="ex-divider"></div>'
      : '';

    const tcMatch   = r.result_value ? r.result_value.match(/^([\s\S]*?)\|\|TC\|\|(.+)$/) : null;
    const mainValue = tcMatch ? tcMatch[1].trim() : r.result_value;
    const tcDisplay = tcMatch ? tcMatch[2].trim() : null;

    const tcHtml = tcDisplay
      ? `<div class="tc-section">
           <div class="tc-label">Relação T/C</div>
           <div class="tc-value">${safe(tcDisplay)}</div>
         </div>`
      : '';

    const imagesHtml = (r.images && r.images.length)
      ? `<div class="img-block">
           <div class="img-block-label">Imagens</div>
           <div class="img-grid">
             ${r.images.map(img => `
               <div class="img-item">
                 <img src="${img.dataUri}" alt="${safe(img.caption || '')}">
                 ${img.caption ? `<div class="img-caption">${safe(img.caption)}</div>` : ''}
               </div>
             `).join('')}
           </div>
         </div>`
      : '';

    return `
      <div class="exam-block">
        <div class="ex-box">${safe(r.exam_name)}</div>
        <div class="ex-meta-row">
          <span class="ex-meta">
            <strong>Amostra:</strong> ${safe(r.sample_type)}
            &nbsp;·&nbsp;
            <strong>Método:</strong> ${safe(r.method)}
          </span>
          <span class="ex-meta"><strong>VR:</strong> ${safe(r.reference_value || '—')}</span>
        </div>
        <div class="res-block">
          <div class="res-label">Resultado</div>
          <div class="res-text" style="color:${resultColor(mainValue, r.result_color)}">${formatResultText(mainValue)}</div>
          ${tcHtml}
          ${obs}
        </div>
        ${imagesHtml}
      </div>
      ${divider}
    `;
  }).join('');

  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8"/>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html, body {
      width: 210mm;
      background: #fff;
      font-family: 'Segoe UI', system-ui, Arial, sans-serif;
      color: #111;
      font-size: 11px;
      line-height: 1.55;
    }
    .page {
      width: 210mm;
      min-height: 297mm;
      display: flex;
      flex-direction: column;
    }

    /* ── Cabeçalho decorativo (visível em preview E no PDF) ── */
    .report-header-body {
      display: flex;
      align-items: flex-end;
      justify-content: flex-end;
      gap: 14px;
      padding: 10px 22mm 8px;
    }
    .pdf-head-meta { text-align: right; }
    .pdf-clinic {
      font-size: 8px;
      color: #666;
      letter-spacing: .06em;
      text-transform: uppercase;
      margin-bottom: 3px;
    }
    .pdf-title {
      font-size: 15px;
      font-weight: 700;
      color: #111;
      letter-spacing: .05em;
      text-transform: uppercase;
    }
    .logo-wrap {
      width: 40px;
      height: 40px;
      border-radius: 50%;
      background: #111;
      flex-shrink: 0;
      overflow: hidden;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .logo-wrap svg {
      width: 40px !important;
      height: 40px !important;
    }

    /* Régua */
    .pdf-rule { height: 1.5px; background: #111; opacity: .18; margin: 0 22mm; }

    /* Identificação do paciente */
    .pdf-ident {
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      padding: 8px 22mm 7px;
      border-bottom: 0.5px solid #e5e5e5;
    }
    .pdf-ident p { font-size: 10px; color: #333; }
    .pdf-ident strong { font-weight: 600; color: #111; }

    /* Corpo dos exames */
    .pdf-body { padding: 0 22mm 16px; flex: 1; }

    /* Sem quebra de página dentro de um bloco de exame */
    .exam-block {
      break-inside: avoid;
      page-break-inside: avoid;
    }

    /* Nome do exame */
    .ex-box {
      font-weight: 600;
      font-style: italic;
      background: #f0f0f0;
      padding: 5px 9px;
      margin: 10px 0 5px;
      border-radius: 3px;
      font-size: 11px;
      border-left: 2.5px solid #222;
    }

    /* Metadados */
    .ex-meta-row {
      display: flex;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 4px;
      margin: 2px 0;
    }
    .ex-meta { font-size: 8.5px; color: #777; }
    .ex-meta strong { font-weight: 600; }

    /* Separador entre exames */
    .ex-divider { height: 0.5px; background: #e5e5e5; margin: 8px 0 0; }

    /* Bloco de resultado */
    .res-block {
      background: #f5f5f5;
      border: 0.5px solid #e2e2e2;
      border-radius: 3px;
      padding: 5px 10px 6px;
      margin: 5px 0 3px;
      display: block;
      width: 100%;
      box-sizing: border-box;
    }
    .res-label {
      font-size: 7px;
      text-transform: uppercase;
      letter-spacing: .12em;
      color: #aaa;
      margin-bottom: 2px;
      display: block;
    }
    .res-text {
      font-size: 11px;
      font-weight: 700;
      line-height: 1.4;
      white-space: pre-wrap;
      word-break: break-word;
      text-align: left;
      display: block;
    }
    .tc-section {
      margin-top: 6px;
      padding-top: 5px;
      padding-left: 14px;
      border-top: 0.5px dashed #ddd;
    }
    .tc-label {
      font-size: 7px;
      text-transform: uppercase;
      letter-spacing: .12em;
      color: #aaa;
      margin-bottom: 2px;
      display: block;
    }
    .tc-value {
      font-size: 10px;
      font-weight: 600;
      color: #444;
      display: block;
    }
    .res-obs {
      font-style: italic;
      color: #555;
      font-size: 8px;
      margin-top: 6px;
      line-height: 1.5;
      border-top: 0.5px dashed #ddd;
      padding-top: 5px;
      font-weight: 400;
    }

    /* Bloco de imagens */
    .img-block {
      margin: 6px 0 3px;
      background: #f5f5f5;
      border: 0.5px solid #e2e2e2;
      border-radius: 3px;
      padding: 6px 10px 8px;
    }
    .img-block-label {
      font-size: 7px;
      text-transform: uppercase;
      letter-spacing: .12em;
      color: #aaa;
      margin-bottom: 6px;
      display: block;
    }
    .img-grid { display: flex; flex-wrap: wrap; gap: 6px; }
    .img-item {
      flex: 0 0 calc(50% - 3px);
      max-width: calc(50% - 3px);
    }
    .img-item img {
      width: 100%;
      height: auto;
      max-height: 80mm;
      object-fit: contain;
      border-radius: 2px;
      display: block;
    }
    .img-caption {
      font-size: 7.5px;
      color: #777;
      text-align: center;
      margin-top: 3px;
      font-style: italic;
    }

    /* Assinatura */
    .pdf-sign {
      font-size: 8.5px;
      font-weight: 600;
      text-align: center;
      padding: 10px 22mm 6px;
      color: #333;
      border-top: 0.5px solid #e5e5e5;
      margin-top: 8px;
    }

    /* Rodapé do body — visível no preview, oculto no PDF (footerTemplate substitui) */
    .report-footer-body {
      background: #111;
      color: #f5f5f5;
      padding: 7px 16px;
      font-size: 7.5px;
      text-align: center;
      line-height: 1.5;
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }

    /* Na impressão: oculta apenas o rodapé do body (footerTemplate repete em todas as págs).
       O cabeçalho decorativo (.report-header-body) permanece visível — aparece na pág. 1. */
    @media print {
      .report-footer-body { display: none !important; }
    }

    a { color: #f5f5f5; text-decoration: none; }
    a[href]:after { content: "" !important; }
  </style>
</head>
<body>
<div class="page">

  <!-- Cabeçalho decorativo: logo + título. Visível no preview e na pág. 1 do PDF. -->
  <div class="report-header-body">
    <div class="pdf-head-meta">
      <div class="pdf-clinic">Consultório · Dr. Leandro Mendes</div>
      <div class="pdf-title">RESULTADO DE EXAME</div>
    </div>
    ${logoHtml}
  </div>

  <div class="pdf-rule"></div>

  <div class="pdf-ident">
    <p><strong>Nome:</strong> ${safe(patient.full_name)}</p>
    <p><strong>Data de Nascimento:</strong> ${birthBR}</p>
    <p><strong>Data do Teste:</strong> ${collectedBR}</p>
    <p><strong>Emitido em:</strong> ${todayBR}</p>
  </div>

  <div class="pdf-body">
    ${resultsHtml}
  </div>

  <div class="pdf-sign">
    Assinado Digitalmente por: Leandro César Mendes — CRM 134.985SP
  </div>

  <!-- Rodapé: visível no preview. Na impressão, footerTemplate assume. -->
  <div class="report-footer-body">
    Consultório Dr. Leandro Mendes – Euroville Tower Corporate<br>
    Praça Maastrich, 200, sala 603, Bragança Paulista-SP<br>
    doutorleandromendes@gmail.com | (11) 99611-2338
  </div>

</div>
</body>
</html>`;
}

// ====== Puppeteer: instância reutilizada ======

let _browser = null;

async function getBrowser() {
  if (!_browser || !_browser.connected) {
    _browser = await puppeteer.launch({
      headless: true,
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || puppeteer.executablePath(),
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
      ],
    });
  }
  return _browser;
}

// Gera o PDF e retorna um Buffer
export async function generateLabPdf(data) {
  const { patient, collection } = data;

  const esc = s => String(s || '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  // Cabeçalho compacto repetido em todas as páginas (inclusive pág. 1, acima do header decorativo)
  const headerTemplate = `<div style="width:100%;padding:4px 22mm 3px;box-sizing:border-box;
      font-size:7.5px;font-family:system-ui,-apple-system,Arial,sans-serif;
      border-bottom:0.5px solid #ddd;display:flex;
      justify-content:space-between;align-items:center;color:#555">
    <span style="font-weight:600;color:#333">Dr. Leandro Mendes
      <span style="font-weight:400;color:#999"> · Infectologia · CRM 134.985-SP</span>
    </span>
    <span>
      <strong style="color:#333">${esc(patient.full_name)}</strong>
      <span style="color:#999">&nbsp;·&nbsp;DN:&nbsp;${toBR(patient.birth_date)}&nbsp;·&nbsp;Coleta:&nbsp;${toBR(collection.collected_at)}</span>
    </span>
  </div>`;

  // Rodapé compacto repetido em todas as páginas
  const footerTemplate = `<div style="width:100%;padding:2px 22mm 0;box-sizing:border-box;
      font-size:6.5px;font-family:system-ui,-apple-system,Arial,sans-serif;
      border-top:0.5px solid #ddd;display:flex;
      justify-content:space-between;align-items:center;color:#aaa">
    <span>Consultório Dr. Leandro Mendes · Euroville Tower Corporate · Praça Maastrich, 200, sala 603, Bragança Paulista-SP</span>
    <span style="white-space:nowrap;margin-left:8px;color:#888">
      p.&nbsp;<span class="pageNumber"></span>/<span class="totalPages"></span>
    </span>
  </div>`;

  const browser = await getBrowser();
  const page    = await browser.newPage();
  try {
    await page.setContent(buildPdfHtml(data), { waitUntil: 'networkidle0' });
    return await page.pdf({
      format:              'A4',
      printBackground:     true,
      displayHeaderFooter: true,
      headerTemplate,
      footerTemplate,
      margin: { top: '20mm', bottom: '18mm', left: '0', right: '0' },
    });
  } finally {
    await page.close();
  }
}
