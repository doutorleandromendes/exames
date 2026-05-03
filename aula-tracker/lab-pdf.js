// lab-pdf.js
// Geração de PDF dos laudos via Puppeteer
// O logo é lido uma vez na inicialização de public/logo-lm.svg

import puppeteer from 'puppeteer';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Carrega o SVG do logo uma vez ao iniciar o servidor
let LOGO_SVG = '';
try {
  LOGO_SVG = readFileSync(join(__dirname, 'logo-lm.svg'), 'utf-8');
} catch {
  console.warn('[lab-pdf] public/logo-lm.svg não encontrado — usando círculo vazio');
}

// ====== Helpers ======

function safe(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Converte YYYY-MM-DD (ou Date) para DD/MM/AAAA sem problemas de fuso
function toBR(dateStr) {
  if (!dateStr) return '—';
  const s = String(dateStr);
  // Se já é DD/MM/AAAA, retorna como está
  if (/^\d{2}\/\d{2}\/\d{4}$/.test(s)) return s;
  // Adiciona T12:00:00 para evitar virar o dia por fuso
  const d = new Date(s.length === 10 ? s + 'T12:00:00' : s);
  if (isNaN(d)) return s;
  return d.toLocaleDateString('pt-BR');
}

// Determina a cor do resultado com base no valor
function resultColor(value) {
  const v = (value || '').toUpperCase();
  if (/NÃO\s+REAGENTE|NAO\s+REAGENTE|NEGATIVO|AUSENTE|NORMAL/.test(v)) return '#1a7a4a';
  if (/REAGENTE|POSITIVO|PRESENTE|CRESCIMENTO/.test(v))                  return '#b03030';
  return '#111111';
}

// Colore marcadores SENSÍVEL A / RESISTENTE A dentro do texto de resultado
function formatResultText(value) {
  return safe(value)
    .replace(/SENSÍVEL A:/gi,   '<span style="color:#1a7a4a;font-weight:700">SENSÍVEL A:</span>')
    .replace(/RESISTENTE A:/gi, '<span style="color:#b03030;font-weight:700">RESISTENTE A:</span>');
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
          <div class="res-text" style="color:${resultColor(r.result_value)}">
            ${formatResultText(r.result_value)}
          </div>
          ${obs}
        </div>
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

    /* Cabeçalho */
    .pdf-head {
      display: flex;
      align-items: flex-end;
      justify-content: flex-end;
      gap: 14px;
      padding: 14px 22mm 10px;
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

    /* Cabeçalho do exame (nome) */
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

    /* Metadados (amostra, método, VR) */
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
      padding: 8px 12px;
      margin: 6px 0 3px;
    }
    .res-label {
      font-size: 7.5px;
      text-transform: uppercase;
      letter-spacing: .12em;
      color: #999;
      margin-bottom: 4px;
    }
    .res-text {
      font-size: 11.5px;
      font-weight: 700;
      line-height: 1.55;
      white-space: pre-wrap;
      word-break: break-word;
      text-align: left;
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

    /* Assinatura e rodapé */
    .pdf-sign {
      font-size: 8.5px;
      font-weight: 600;
      text-align: center;
      padding: 10px 22mm 6px;
      color: #333;
      border-top: 0.5px solid #e5e5e5;
      margin-top: 8px;
    }
    .pdf-footer {
      background: #111;
      color: #f5f5f5;
      padding: 7px 16px;
      font-size: 7.5px;
      text-align: center;
      line-height: 1.5;
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }
    a { color: #f5f5f5; text-decoration: none; }
    a[href]:after { content: "" !important; }
  </style>
</head>
<body>
<div class="page">

  <div class="pdf-head">
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

  <div class="pdf-footer">
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
  const browser = await getBrowser();
  const page = await browser.newPage();
  try {
    await page.setContent(buildPdfHtml(data), { waitUntil: 'networkidle0' });
    return await page.pdf({
      format: 'A4',
      printBackground: true,
      margin: { top: 0, right: 0, bottom: 0, left: 0 },
    });
  } finally {
    await page.close();
  }
}
