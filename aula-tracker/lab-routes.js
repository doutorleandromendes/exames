// lab-routes.js
// Todas as rotas do portal de resultados laboratoriais
// Prefixo /lab/admin/* para o médico, /lab/* para o paciente
//
// Uso em app.js:
//   registerLabRoutes(app, pool, adminRequired, renderShell);

import { buildPdfHtml, generateLabPdf } from './lab-pdf.js';
import { uploadToR2, deleteFromR2 } from './lab-storage.js';

// ====== Helpers locais ======

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
function renderText(value) {
  return safe(value)
    .replace(/\*(.+?)\*/g,   '<strong>$1</strong>')
    .replace(/_(.+?)_/g,     '<em>$1</em>')
    .replace(/SENSÍVEL A:/gi,   '<span style="color:#1a7a4a;font-weight:700">SENSÍVEL A:</span>')
    .replace(/RESISTENTE A:/gi, '<span style="color:#b03030;font-weight:700">RESISTENTE A:</span>')
    .replace(/\n/g, '<br>');
}
// Gera chave no formato LM-XXXX-XXXX (sem chars ambíguos 0/O/I/1)
function generateKey() {
  const abc = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const part = (n) =>
    Array.from({ length: n }, () => abc[Math.floor(Math.random() * abc.length)]).join('');
  return `LM-${part(4)}-${part(4)}`;
}

// Data de expiração: hoje + 90 dias
function keyExpiresAt() {
  const d = new Date();
  d.setDate(d.getDate() + 90);
  return d.toISOString();
}

// ====== Shell do portal do paciente (tema claro/branco) ======

function renderPatientShell(title, body, patient = null) {
  return `<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>${safe(title)} · Dr. Leandro Mendes</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: system-ui, -apple-system, 'Segoe UI', Arial, sans-serif;
      background: #f5f5f5;
      color: #111;
      font-size: 14px;
      line-height: 1.6;
    }
    .wrap { max-width: 800px; margin: 0 auto; padding: 32px 16px 80px; }
    .card {
      background: #fff;
      border: 0.5px solid #e5e5e5;
      border-radius: 12px;
      padding: 28px;
      margin-bottom: 14px;
    }
    label {
      display: block;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: .07em;
      color: #666;
      margin-bottom: 6px;
      margin-top: 14px;
    }
    label:first-child { margin-top: 0; }
    input[type="text"] {
      width: 100%;
      padding: 11px 14px;
      border: 0.5px solid #ccc;
      border-radius: 8px;
      font-size: 16px;
      background: #fafafa;
      color: #111;
      font-family: monospace;
      letter-spacing: .1em;
      text-transform: uppercase;
    }
    .btn-primary {
      width: 100%;
      padding: 13px;
      background: #111;
      color: #fff;
      border: 0;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      margin-top: 12px;
    }
    .btn-download {
      padding: 9px 20px;
      background: #111;
      color: #fff;
      border: 0;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .muted { color: #888; font-size: 12px; }
    .error-msg { color: #b03030; font-size: 13px; margin-top: 12px; text-align: center; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th {
      text-align: left;
      padding: 8px 12px;
      font-size: 10px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: .07em;
      color: #888;
      border-bottom: 0.5px solid #e5e5e5;
      background: #fafafa;
    }
    td { padding: 10px 12px; border-bottom: 0.5px solid #f0f0f0; vertical-align: middle; }
    tr:last-child td { border-bottom: none; }
    .tag-pos { color: #b03030; font-weight: 600; }
    .tag-neg { color: #1a7a4a; font-weight: 600; }
    .chk { accent-color: #111; width: 15px; height: 15px; cursor: pointer; }
    .coleta-card {
      background: #fff;
      border: 0.5px solid #e5e5e5;
      border-radius: 10px;
      margin-bottom: 12px;
      overflow: hidden;
    }
    .coleta-top {
      padding: 14px 18px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .coleta-date { font-size: 15px; font-weight: 600; color: #111; }
    .coleta-body { border-top: 0.5px solid #f0f0f0; }
    .dl-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 18px;
      background: #fafafa;
      border-top: 0.5px solid #f0f0f0;
    }
    .badge {
      display: inline-block;
      font-size: 10px;
      padding: 2px 9px;
      border-radius: 10px;
      background: #f0f0f0;
      color: #666;
    }
  </style>
</head>
<body>
  <!-- Barra de navegação superior -->
  <div style="background:#111;padding:12px 24px;display:flex;align-items:center;justify-content:space-between">
    <div style="display:flex;align-items:center;gap:10px">
      <div style="width:28px;height:28px;border-radius:50%;background:#fff;display:flex;align-items:center;justify-content:center;flex-shrink:0">
        <svg viewBox="0 0 32 32" fill="none" style="width:16px;height:16px">
          <path d="M8 22L8 10L14 18L20 10L20 22" stroke="#111" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
          <path d="M22 10 Q28 14 28 18 Q28 23 22 22" stroke="#111" stroke-width="2" stroke-linecap="round" fill="none"/>
        </svg>
      </div>
      <span style="color:#fff;font-size:13px;font-weight:500">
        Dr. Leandro Mendes
        <span style="opacity:.6;font-weight:400"> · Portal de Resultados</span>
      </span>
    </div>
    ${patient
      ? `<a href="/lab/logout" style="color:#fff;font-size:12px;opacity:.7;text-decoration:none">Sair</a>`
      : ''}
  </div>

  <div class="wrap">
    ${body}
  </div>

  <!-- Rodapé fixo -->
  <div style="background:#111;color:#f5f5f5;padding:10px 24px;font-size:10px;text-align:center;line-height:1.6;position:fixed;bottom:0;left:0;right:0;z-index:10">
    Consultório Dr. Leandro Mendes · Euroville Tower Corporate · Praça Maastrich, 200, sala 603, Bragança Paulista-SP
  </div>
</body>
</html>`;
}
async function getCollectionData(pool, collectionId, patientIdCheck = null, resultIds = null) {
  const q = patientIdCheck
    ? `SELECT lc.*, lp.full_name, lp.birth_date
       FROM lab_collections lc
       JOIN lab_patients lp ON lp.id = lc.patient_id
       WHERE lc.id = $1 AND lc.patient_id = $2`
    : `SELECT lc.*, lp.full_name, lp.birth_date
       FROM lab_collections lc
       JOIN lab_patients lp ON lp.id = lc.patient_id
       WHERE lc.id = $1`;

  const params = patientIdCheck ? [collectionId, patientIdCheck] : [collectionId];
  const { rows: [collection] } = await pool.query(q, params);
  if (!collection) return null;

  let resultsQ, resultsParams;
  if (resultIds && resultIds.length) {
    resultsQ = `SELECT lr.*,
      (SELECT COUNT(*) FROM lab_result_images WHERE result_id = lr.id) AS _img_count
      FROM lab_results lr
      WHERE lr.collection_id=$1 AND lr.id = ANY($2::int[])
      ORDER BY lr.sort_index NULLS LAST, lr.id ASC`;
    resultsParams = [collectionId, resultIds];
  } else {
    resultsQ = `SELECT lr.*,
      (SELECT COUNT(*) FROM lab_result_images WHERE result_id = lr.id) AS _img_count
      FROM lab_results lr
      WHERE lr.collection_id=$1
      ORDER BY lr.sort_index NULLS LAST, lr.id ASC`;
    resultsParams = [collectionId];
  }
  const { rows: results } = await pool.query(resultsQ, resultsParams);

  const resultIds2 = results.map(r => r.id);
  let imagesByResult = {};
  if (resultIds2.length) {
    const { rows: imgs } = await pool.query(
      `SELECT * FROM lab_result_images WHERE result_id = ANY($1::int[])
       ORDER BY result_id, sort_index NULLS LAST, id`,
      [resultIds2]
    );
    for (const img of imgs) {
      if (!imagesByResult[img.result_id]) imagesByResult[img.result_id] = [];
      imagesByResult[img.result_id].push(img);
    }
  }

  const { fetchR2ImageAsDataURI } = await import('./lab-storage.js');
  for (const r of results) {
    const imgs = imagesByResult[r.id] || [];
    r.images = await Promise.all(imgs.map(async img => {
      try {
        const dataUri = await fetchR2ImageAsDataURI(img.r2_key);
        return { ...img, dataUri };
      } catch (e) {
        console.warn('[lab] imagem não carregada:', img.r2_key, e.message);
        return null;
      }
    }));
    r.images = r.images.filter(Boolean);
  }

  return {
    patient:    { full_name: collection.full_name, birth_date: collection.birth_date },
    collection: { collected_at: collection.collected_at },
    results,
  };
}

async function getCollectionDataLite(pool, collectionId, patientIdCheck = null, resultIds = null) {
  const q = patientIdCheck
    ? `SELECT lc.*, lp.full_name, lp.birth_date
       FROM lab_collections lc JOIN lab_patients lp ON lp.id = lc.patient_id
       WHERE lc.id = $1 AND lc.patient_id = $2`
    : `SELECT lc.*, lp.full_name, lp.birth_date
       FROM lab_collections lc JOIN lab_patients lp ON lp.id = lc.patient_id
       WHERE lc.id = $1`;
  const params = patientIdCheck ? [collectionId, patientIdCheck] : [collectionId];
  const { rows: [collection] } = await pool.query(q, params);
  if (!collection) return null;

  let resultsQ, resultsParams;
  if (resultIds && resultIds.length) {
    resultsQ      = `SELECT * FROM lab_results WHERE collection_id=$1 AND id = ANY($2::int[]) ORDER BY sort_index NULLS LAST, id ASC`;
    resultsParams = [collectionId, resultIds];
  } else {
    resultsQ      = `SELECT * FROM lab_results WHERE collection_id=$1 ORDER BY sort_index NULLS LAST, id ASC`;
    resultsParams = [collectionId];
  }
  const { rows: results } = await pool.query(resultsQ, resultsParams);

  for (const r of results) r.images = [];

  return {
    patient:    { full_name: collection.full_name, birth_date: collection.birth_date },
    collection: { collected_at: collection.collected_at },
    results,
  };
}

// ====== Registro de rotas ======

export function registerLabRoutes(app, pool, adminRequired, renderShell) {

  // Rota de diagnóstico temporária — remover após resolver
  app.get('/lab/admin/debug-chrome', adminRequired, async (req, res) => {
    const { execSync } = await import('child_process');
    const lines = [];
    try { lines.push('which chromium: ' + execSync('which chromium').toString().trim()); } catch { lines.push('which chromium: não encontrado'); }
    try { lines.push('which chromium-browser: ' + execSync('which chromium-browser').toString().trim()); } catch { lines.push('which chromium-browser: não encontrado'); }
    try { lines.push('which google-chrome: ' + execSync('which google-chrome').toString().trim()); } catch { lines.push('which google-chrome: não encontrado'); }
    try { lines.push('find puppeteer cache: ' + execSync('find /opt/render/.cache/puppeteer -name "chrome" -type f 2>/dev/null | head -5').toString().trim()); } catch { lines.push('find puppeteer cache: erro'); }
    try { lines.push('puppeteer.executablePath(): ' + (await import('puppeteer')).default.executablePath()); } catch (e) { lines.push('puppeteer.executablePath(): ' + e.message); }
    res.type('text/plain').send(lines.join('\n'));
  });
// GET /lab/admin/api/pacientes-sheet — proxy do CSV do Google Sheets → JSON
  app.get('/lab/admin/api/pacientes-sheet', adminRequired, async (req, res) => {
    try {
      const SHEET_URL = 'https://docs.google.com/spreadsheets/d/e/2PACX-1vRAamiMm4NPvlRTIi5sxzkCWEJhQ6GOWPhMcDaueuzmBgZmEjJjIy9eYpW-iruMdkD23pOPAun3x9Ci/pub?output=csv';
      const resp = await fetch(SHEET_URL + '&_ts=' + Date.now());
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const csv = await resp.text();

      // Parser CSV robusto (lida com campos entre aspas)
      function parseCSVLine(line) {
        const cols = [];
        let cur = '', inQ = false;
        for (let i = 0; i < line.length; i++) {
          const ch = line[i];
          if (ch === '"') {
            if (inQ && line[i+1] === '"') { cur += '"'; i++; }
            else inQ = !inQ;
          } else if (ch === ',' && !inQ) {
            cols.push(cur.trim()); cur = '';
          } else {
            cur += ch;
          }
        }
        cols.push(cur.trim());
        return cols;
      }

      function toISO(s) {
        if (!s) return '';
        s = String(s).trim();
        // DD-MM-AAAA (formato da planilha: 04-11-1958)
        if (/^\d{1,2}-\d{1,2}-\d{4}$/.test(s)) {
          const [d, m, y] = s.split('-');
          return `${y}-${m.padStart(2,'0')}-${d.padStart(2,'0')}`;
        }
        // DD/MM/AAAA
        if (/^\d{1,2}\/\d{1,2}\/\d{4}$/.test(s)) {
          const [d, m, y] = s.split('/');
          return `${y}-${m.padStart(2,'0')}-${d.padStart(2,'0')}`;
        }
        // YYYY-MM-DD
        if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
        // Fallback
        const dt = new Date(s);
        if (!isNaN(dt)) {
          return `${dt.getFullYear()}-${String(dt.getMonth()+1).padStart(2,'0')}-${String(dt.getDate()).padStart(2,'0')}`;
        }
        return '';
      }

      const lines = csv.split(/\r?\n/).filter(Boolean);
      const pacientes = [];
      for (let i = 1; i < lines.length; i++) {
        const cols = parseCSVLine(lines[i]);
        const nome = `${(cols[0]||'').trim()} ${(cols[1]||'').trim()}`.trim();
        const rawDN = (cols[2]||'').trim();
        const dn   = toISO(rawDN);
        if (nome) pacientes.push({ nome, dn });
      }
      pacientes.sort((a, b) => a.nome.localeCompare(b.nome, 'pt-BR', { sensitivity: 'base' }));

      res.json(pacientes);
    } catch (err) {
      console.error('LAB SHEET PROXY ERROR', err);
      res.status(500).json([]);
    }
  });

  // GET /lab/admin/api/exames
  const rawUrl = 'https://raw.githubusercontent.com/doutorleandromendes/exames/main/products.csv';

      const resp = await fetch(rawUrl + '?_ts=' + Date.now(), {
        headers: { 'User-Agent': 'lab-portal-lm' },
      });
      // sem Authorization — repo público não precisa

      const resp = await fetch(apiUrl, { headers });

      // Loga status para debug nos logs do Render
      const bodyText = await resp.text();
      console.log('[lab/exames] status:', resp.status);
      console.log('[lab/exames] primeiros 300 chars:', bodyText.slice(0, 300));

      if (!resp.ok) throw new Error('GitHub HTTP ' + resp.status + ' — ' + bodyText.slice(0, 200));

      // Tenta ; primeiro, depois ,
      function parseExames(text, sep) {
        const lines = text.split(/\r?\n/).filter(Boolean);
        if (lines.length < 2) return [];
        const exames = [];
        for (let i = 1; i < lines.length; i++) {
          const nome = (lines[i].split(sep)[0] || '').replace(/^"|"$/g, '').trim();
          if (nome) exames.push(nome);
        }
        return [...new Set(exames)];
      }

      let exames = parseExames(bodyText, ';');
      if (!exames.length) exames = parseExames(bodyText, ',');

      console.log('[lab/exames] total parseados:', exames.length);

      if (!exames.length) throw new Error('Nenhum exame encontrado no CSV');

      exames.sort((a, b) => a.localeCompare(b, 'pt-BR', { sensitivity: 'base' }));
      res.json(exames);
    } catch (err) {
      console.error('LAB EXAMES PROXY ERROR:', err.message);
      res.status(500).json([]);
    }
  });
  // ============================================================
  // ADMIN ROUTES  (/lab/admin/*)
  // Usam renderShell (tema escuro, igual ao resto do admin)
  // ============================================================

  // GET /lab/admin — visão geral
  app.get('/lab/admin', adminRequired, async (req, res) => {
    try {
      const { rows: [s] } = await pool.query(`
        SELECT
          (SELECT COUNT(*) FROM lab_patients)                             AS patients,
          (SELECT COUNT(*) FROM lab_collections)                         AS collections,
          (SELECT COUNT(*) FROM lab_results)                             AS results,
          (SELECT COUNT(*) FROM lab_access_keys WHERE expires_at > now()) AS active_keys
      `);

      const { rows: recent } = await pool.query(`
        SELECT lc.id, lc.collected_at, lp.full_name, lp.id AS patient_id,
               COUNT(lr.id)  AS exam_count,
               lak.key_code
        FROM lab_collections lc
        JOIN lab_patients lp    ON lp.id  = lc.patient_id
        LEFT JOIN lab_results lr ON lr.collection_id = lc.id
        LEFT JOIN lab_access_keys lak ON lak.patient_id = lp.id
        GROUP BY lc.id, lc.collected_at, lp.full_name, lp.id, lak.key_code
        ORDER BY lc.created_at DESC
        LIMIT 10
      `);

      const recentRows = recent.map(r => `
        <tr>
          <td><strong>${safe(r.full_name)}</strong></td>
          <td>${toBR(r.collected_at)}</td>
          <td><span style="font-size:11px;background:#20242b;padding:2px 8px;border-radius:8px;color:#a7adbb">${r.exam_count} exame(s)</span></td>
          <td style="font-family:monospace;font-size:12px;color:#a7adbb">${safe(r.key_code || '—')}</td>
          <td>
            <a href="/lab/admin/coletas/${r.id}">abrir</a> ·
            <a href="/lab/admin/coletas/${r.id}/preview" target="_blank">preview PDF</a>
          </td>
        </tr>
      `).join('');

      const stats = [
        ['Pacientes',         s.patients],
        ['Coletas',           s.collections],
        ['Exames emitidos',   s.results],
        ['Chaves ativas',     s.active_keys],
      ].map(([lbl, val]) => `
        <div style="background:var(--card);border:1px solid #20242b;border-radius:10px;padding:14px 16px">
          <div style="font-size:22px;font-weight:600;color:#e7e9ee">${val}</div>
          <div style="font-size:11px;color:#a7adbb;text-transform:uppercase;letter-spacing:.06em;margin-top:2px">${lbl}</div>
        </div>
      `).join('');

      const html = `
        <div class="card" style="margin-bottom:16px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
            <h1>Portal de Resultados</h1>
            <div>
              <a href="/lab/admin/pacientes" style="margin-right:12px">Pacientes</a>
              <a href="/lab/admin/pacientes/novo">+ Novo paciente</a>
            </div>
          </div>
          <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px">${stats}</div>
        </div>
        <div class="card">
          <h2 style="margin-bottom:14px">Últimas coletas</h2>
          <table>
            <thead><tr>
              <th>Paciente</th><th>Data da coleta</th><th>Exames</th><th>Chave</th><th></th>
            </tr></thead>
            <tbody>${recentRows || '<tr><td colspan="5" class="mut">Nenhuma coleta ainda.</td></tr>'}</tbody>
          </table>
        </div>
      `;
      res.send(renderShell('Lab · Visão geral', html));
    } catch (err) {
      console.error('LAB ADMIN OVERVIEW ERROR', err);
      res.status(500).send(renderShell('Erro', `<div class="card"><h1>Falha</h1><p class="mut">${safe(err.message)}</p></div>`));
    }
  });

  // GET /lab/admin/pacientes — lista de pacientes
  app.get('/lab/admin/pacientes', adminRequired, async (req, res) => {
    try {
      const { rows } = await pool.query(`
        SELECT lp.id, lp.full_name, lp.birth_date,
               lak.key_code, lak.expires_at,
               COUNT(DISTINCT lc.id) AS collection_count,
               MAX(lc.collected_at)  AS last_collection
        FROM lab_patients lp
        LEFT JOIN lab_access_keys lak ON lak.patient_id = lp.id
        LEFT JOIN lab_collections lc  ON lc.patient_id  = lp.id
        GROUP BY lp.id, lp.full_name, lp.birth_date, lak.key_code, lak.expires_at
        ORDER BY lp.full_name
      `);

      const tableRows = rows.map(r => {
        const expired = r.expires_at && new Date(r.expires_at) < new Date();
        const statusColor = expired ? '#b03030' : '#3fb950';
        const statusText  = expired ? 'Expirada' : 'Ativa';
        return `
          <tr>
            <td><strong>${safe(r.full_name)}</strong></td>
            <td>${toBR(r.birth_date)}</td>
            <td style="font-family:monospace;font-size:12px">${safe(r.key_code || '—')}</td>
            <td style="color:${statusColor}">${r.expires_at ? `${statusText} (${toBR(r.expires_at)})` : '—'}</td>
            <td>${r.collection_count}</td>
            <td>${toBR(r.last_collection)}</td>
            <td><a href="/lab/admin/pacientes/${r.id}">abrir</a></td>
          </tr>
        `;
      }).join('');

      const html = `
        <div class="card">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
            <h1>Pacientes</h1>
            <a href="/lab/admin/pacientes/novo">+ Novo paciente</a>
          </div>
          <table>
            <thead><tr>
              <th>Nome</th><th>Nascimento</th><th>Chave</th><th>Status</th>
              <th>Coletas</th><th>Última coleta</th><th></th>
            </tr></thead>
            <tbody>${tableRows || '<tr><td colspan="7" class="mut">Nenhum paciente cadastrado.</td></tr>'}</tbody>
          </table>
        </div>
      `;
      res.send(renderShell('Lab · Pacientes', html));
    } catch (err) {
      console.error('LAB PATIENTS LIST ERROR', err);
      res.status(500).send(renderShell('Erro', `<div class="card"><p class="mut">${safe(err.message)}</p></div>`));
    }
  });

  // GET /lab/admin/pacientes/novo — formulário de novo paciente
  app.get('/lab/admin/pacientes/novo', adminRequired, (req, res) => {
    // URL da planilha de pacientes (mesma do gerador de laudos HTML)
    const SHEET_URL = 'https://docs.google.com/spreadsheets/d/e/2PACX-1vRAamiMm4NPvlRTIi5sxzkCWEJhQ6GOWPhMcDaueuzmBgZmEjJjIy9eYpW-iruMdkD23pOPAun3x9Ci/pub?output=csv';

    // Script injetado como string normal para evitar conflito com template literals do Node
    const clientScript = [
      '(function(){',
      '  fetch("/pront/api/pacientes")',
      '    .then(function(r){ return r.json(); })',
      '    .then(function(pacs){',
      '      var sel = document.getElementById("pacSelect");',
      '      pacs.forEach(function(p){',
      '        var opt = document.createElement("option");',
      '        opt.value = p.id+"|"+p.nome+"|"+(p.dn||"");',
      '        opt.textContent = p.nome;',
      '        sel.appendChild(opt);',
      '      });',
      '      document.getElementById("statusPac").textContent = pacs.length+" pacientes do prontuário";',
      '    })',
      '    .catch(function(){',
      '      document.getElementById("statusPac").textContent = "Não foi possível carregar o cadastro — preencha manualmente";',
      '    });',
      '  document.getElementById("pacSelect").addEventListener("change", function(){',
      '    var parts = this.value.split("|");',
      '    document.getElementById("fProntId").value = parts[0]||"";',
      '    document.getElementById("fNome").value     = parts[1]||"";',
      '    document.getElementById("fDN").value       = parts[2]||"";',
      '  });',
      '})();',
    ].join('\n');

    const html = `
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
          <h1>Novo paciente</h1>
          <a href="/lab/admin/pacientes">← Voltar</a>
        </div>

        <div id="statusPac" class="mut" style="margin-bottom:10px">Carregando pacientes…</div>

        <label>Selecionar do prontuário</label>
        <select id="pacSelect"
          style="width:100%;padding:10px;border-radius:8px;border:1px solid #2a2f39;background:#0f1116;color:#e7e9ee;font-size:14px;margin-bottom:16px">
          <option value="">— escolha um paciente ou preencha manualmente —</option>
        </select>

        <form method="POST" action="/lab/admin/pacientes">
          <input type="hidden" id="fProntId" name="pront_id">
          <label>Nome completo</label>
          <input id="fNome" name="full_name" required placeholder="Nome completo do paciente">
          <label>Data de nascimento</label>
          <input id="fDN" name="birth_date" type="date" required>
          <label>Observações internas (opcional)</label>
          <textarea name="notes" rows="2"
            placeholder="Uso interno — não aparece no portal do paciente"
            style="width:100%;padding:10px;border-radius:8px;border:1px solid #2a2f39;background:#0f1116;color:#e7e9ee;font-size:14px;resize:vertical;margin-top:4px"></textarea>
          <button class="mt">Cadastrar e gerar chave de acesso</button>
        </form>
        <p class="mut mt">A chave de acesso com validade de 90 dias é gerada automaticamente.</p>
      </div>
      <script>${clientScript}</script>
    `;
    res.send(renderShell('Lab · Novo paciente', html));
  });

  // POST /lab/admin/pacientes — cria paciente + gera chave
  app.post('/lab/admin/pacientes', adminRequired, async (req, res) => {
    const client = await pool.connect();
    try {
      const full_name  = (req.body?.full_name  || '').trim();
      const birth_date = (req.body?.birth_date || '').trim();
      const notes      = (req.body?.notes      || '').trim() || null;
      const pront_id   = parseInt(req.body?.pront_id, 10) || null;

      if (!full_name || !birth_date) {
        return res.status(400).send(renderShell('Erro', `
          <div class="card"><h1>Nome e data de nascimento são obrigatórios</h1>
          <p><a href="/lab/admin/pacientes/novo">Voltar</a></p></div>
        `));
      }

      await client.query('BEGIN');

      // Se este paciente do prontuário já tem um lab_patient, reaproveita (não duplica)
      if (pront_id) {
        const { rows: jaLigado } = await client.query(
          'SELECT id FROM lab_patients WHERE pront_id=$1 LIMIT 1', [pront_id]);
        if (jaLigado.length) {
          await client.query('COMMIT');
          return res.redirect(`/lab/admin/pacientes/${jaLigado[0].id}`);
        }
      }

      const { rows: [patient] } = await client.query(
        'INSERT INTO lab_patients (full_name, birth_date, notes, pront_id) VALUES ($1, $2, $3, $4) RETURNING id',
        [full_name, birth_date, notes, pront_id]
      );

      // Gera chave única (tenta até 10 vezes para evitar colisão)
      let keyCode;
      for (let i = 0; i < 10; i++) {
        keyCode = generateKey();
        const { rows: exists } = await client.query(
          'SELECT 1 FROM lab_access_keys WHERE key_code=$1', [keyCode]
        );
        if (!exists.length) break;
      }

      await client.query(
        'INSERT INTO lab_access_keys (patient_id, key_code, expires_at) VALUES ($1, $2, $3)',
        [patient.id, keyCode, keyExpiresAt()]
      );

      await client.query('COMMIT');
      res.redirect(`/lab/admin/pacientes/${patient.id}`);
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('LAB CREATE PATIENT ERROR', err);
      res.status(500).send(renderShell('Erro', `<div class="card"><p class="mut">${safe(err.message)}</p></div>`));
    } finally {
      client.release();
    }
  });

  // GET /lab/admin/pacientes/:id — detalhe do paciente
  app.get('/lab/admin/pacientes/:id', adminRequired, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);

      const { rows: [patient] } = await pool.query(
        'SELECT * FROM lab_patients WHERE id=$1', [id]
      );
      if (!patient) return res.status(404).send(renderShell('Erro', `<div class="card"><h1>Paciente não encontrado</h1></div>`));

      const { rows: keys } = await pool.query(
        'SELECT * FROM lab_access_keys WHERE patient_id=$1 ORDER BY created_at DESC', [id]
      );
      const { rows: collections } = await pool.query(`
        SELECT lc.id, lc.collected_at, COUNT(lr.id) AS exam_count
        FROM lab_collections lc
        LEFT JOIN lab_results lr ON lr.collection_id = lc.id
        WHERE lc.patient_id = $1
        GROUP BY lc.id, lc.collected_at
        ORDER BY lc.collected_at DESC
      `, [id]);

      const keyRows = keys.map(k => {
        const expired = new Date(k.expires_at) < new Date();
        return `
          <tr>
            <td style="font-family:monospace;font-size:15px;letter-spacing:.06em"><strong>${safe(k.key_code)}</strong></td>
            <td>${toBR(k.created_at)}</td>
            <td>${toBR(k.expires_at)}</td>
            <td style="color:${expired ? '#b03030' : '#3fb950'}">${expired ? 'Expirada' : 'Ativa'}</td>
            <td>
              <form method="POST" action="/lab/admin/pacientes/${id}/renovar-chave" style="display:inline">
                <button style="background:none;border:0;color:#8fb6ff;cursor:pointer;padding:0;font-size:13px">Renovar +90 dias</button>
              </form>
            </td>
          </tr>
        `;
      }).join('');

      const collectionRows = collections.map(c => `
        <tr>
          <td><strong>${toBR(c.collected_at)}</strong></td>
          <td>${c.exam_count} exame(s)</td>
          <td>
            <a href="/lab/admin/coletas/${c.id}">editar</a> ·
            <a href="/lab/admin/coletas/${c.id}/preview" target="_blank">preview PDF</a> ·
            <a href="/lab/admin/coletas/${c.id}/pdf">baixar PDF</a>
          </td>
        </tr>
      `).join('');

      const html = `
        <div class="card" style="margin-bottom:16px">
          <div style="display:flex;justify-content:space-between;align-items:flex-start">
            <div>
              <h1>${safe(patient.full_name)}</h1>
              <p class="mut">Nascido(a) em ${toBR(patient.birth_date)}</p>
              ${patient.notes ? `<p class="mut" style="margin-top:4px">${safe(patient.notes)}</p>` : ''}
            </div>
            <a href="/lab/admin/pacientes">← Pacientes</a>
          </div>
        </div>

        <div class="card" style="margin-bottom:16px">
          <h2 style="margin-bottom:12px">Chave de acesso</h2>
          <table>
            <thead><tr><th>Chave</th><th>Emitida em</th><th>Expira em</th><th>Status</th><th></th></tr></thead>
            <tbody>${keyRows || '<tr><td colspan="5" class="mut">Nenhuma chave gerada.</td></tr>'}</tbody>
          </table>
        </div>

        <div class="card">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
            <h2>Coletas</h2>
            <a href="/lab/admin/coletas/nova?patient_id=${id}">+ Nova coleta</a>
          </div>
          <table>
            <thead><tr><th>Data da coleta</th><th>Exames</th><th>Ações</th></tr></thead>
            <tbody>${collectionRows || '<tr><td colspan="3" class="mut">Nenhuma coleta ainda.</td></tr>'}</tbody>
          </table>
        </div>
      `;
      res.send(renderShell(`Lab · ${patient.full_name}`, html));
    } catch (err) {
      console.error('LAB PATIENT DETAIL ERROR', err);
      res.status(500).send(renderShell('Erro', `<div class="card"><p class="mut">${safe(err.message)}</p></div>`));
    }
  });
// GET /lab/admin/resultados/:id/json — dados do resultado para edição inline
  app.get('/lab/admin/resultados/:id/json', adminRequired, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const { rows: [r] } = await pool.query('SELECT * FROM lab_results WHERE id=$1', [id]);
      if (!r) return res.status(404).json({ error: 'Não encontrado' });
      res.json(r);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
  
  // POST /lab/admin/pacientes/:id/renovar-chave
  app.post('/lab/admin/pacientes/:id/renovar-chave', adminRequired, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    try {
      await pool.query(
        'UPDATE lab_access_keys SET expires_at=$1 WHERE patient_id=$2',
        [keyExpiresAt(), id]
      );
      res.redirect(`/lab/admin/pacientes/${id}`);
    } catch (err) {
      console.error('LAB RENEW KEY ERROR', err);
      res.status(500).send('Falha ao renovar chave');
    }
  });

  // GET /lab/admin/coletas/nova — formulário de nova coleta
  app.get('/lab/admin/coletas/nova', adminRequired, async (req, res) => {
    try {
      const patient_id = parseInt(req.query.patient_id, 10);
      const { rows: [patient] } = await pool.query(
        'SELECT id, full_name FROM lab_patients WHERE id=$1', [patient_id]
      );
      if (!patient) return res.status(400).send(renderShell('Erro', `<div class="card"><h1>Paciente não encontrado</h1></div>`));

      const today = new Date().toISOString().split('T')[0];
      const html = `
        <div class="card">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
            <h1>Nova coleta — ${safe(patient.full_name)}</h1>
            <a href="/lab/admin/pacientes/${patient.id}">← Paciente</a>
          </div>
          <form method="POST" action="/lab/admin/coletas" class="mt2">
            <input type="hidden" name="patient_id" value="${patient.id}">
            <label>Data da coleta</label>
            <input name="collected_at" type="date" value="${today}" required>
            <button class="mt">Criar coleta e adicionar exames</button>
          </form>
          <p class="mut mt">Após criar a coleta você adiciona os exames um a um.</p>
        </div>
      `;
      res.send(renderShell('Lab · Nova coleta', html));
    } catch (err) {
      res.status(500).send(renderShell('Erro', `<div class="card"><p class="mut">${safe(err.message)}</p></div>`));
    }
  });

  // POST /lab/admin/coletas — cria coleta
  app.post('/lab/admin/coletas', adminRequired, async (req, res) => {
    try {
      const { patient_id, collected_at } = req.body || {};
      if (!patient_id || !collected_at) return res.status(400).send('Dados obrigatórios');
      const { rows: [c] } = await pool.query(
        'INSERT INTO lab_collections (patient_id, collected_at) VALUES ($1, $2) RETURNING id',
        [parseInt(patient_id, 10), collected_at]
      );
      res.redirect(`/lab/admin/coletas/${c.id}`);
    } catch (err) {
      console.error('LAB CREATE COLLECTION ERROR', err);
      res.status(500).send('Falha ao criar coleta');
    }
  });

  // GET /lab/admin/coletas/:id — detalhe da coleta + formulário de exame
  app.get('/lab/admin/coletas/:id', adminRequired, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);

      const { rows: [collection] } = await pool.query(`
        SELECT lc.*, lp.full_name, lp.birth_date, lp.id AS patient_id
        FROM lab_collections lc
        JOIN lab_patients lp ON lp.id = lc.patient_id
        WHERE lc.id = $1
      `, [id]);
      if (!collection) return res.status(404).send(renderShell('Erro', `<div class="card"><h1>Coleta não encontrada</h1></div>`));

      const { rows: results } = await pool.query(
        `SELECT lr.*,
          (SELECT COUNT(*) FROM lab_result_images WHERE result_id = lr.id) AS _img_count
         FROM lab_results lr
         WHERE lr.collection_id=$1 ORDER BY lr.sort_index NULLS LAST, lr.id ASC`,
        [id]
      );
      
      const resultRows = results.map(r => {
        const imgCount = r._img_count || 0;
        return `
        <tr>
          <td><strong>${safe(r.exam_name)}</strong></td>
          <td style="color:#a7adbb">${safe(r.sample_type)}</td>
          <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
            ${safe((r.result_value || '').split('\n')[0])}
          </td>
          <td style="white-space:nowrap">
            <a href="#exam-form" onclick="loadExamForEdit(${r.id})"
               style="color:#8fb6ff;font-size:12px;margin-right:8px">editar</a>
            <a href="#exam-form" onclick="duplicateExam(${r.id})"
               style="color:#8fb6ff;font-size:12px;margin-right:8px">duplicar</a>
            <a href="#imgs-${r.id}"
               onclick="toggleImgs(${r.id})"
               style="color:#8fb6ff;font-size:12px;margin-right:8px"
               id="imgs-toggle-${r.id}">📷 imagens</a>
            <form method="POST" action="/lab/admin/resultados/${r.id}/delete" style="display:inline"
                  onsubmit="return confirm('Remover o exame &quot;${safe(r.exam_name)}&quot;?')">
              <button style="background:none;border:0;color:#8fb6ff;cursor:pointer;padding:0;font-size:12px">remover</button>
            </form>
          </td>
        </tr>
        <tr id="imgs-${r.id}" style="display:none">
          <td colspan="4" style="padding:0 0 8px 14px">
            <div id="imgs-list-${r.id}" style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:8px"></div>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              <input type="file" id="img-file-${r.id}" accept="image/*" multiple
                style="font-size:12px;color:#a7adbb">
              <input type="text" id="img-caption-${r.id}" placeholder="Legenda (opcional)"
                style="padding:5px 8px;border-radius:6px;border:1px solid #2a2f39;background:#0f1116;color:#e7e9ee;font-size:12px;width:180px">
              <button type="button" onclick="uploadImgs(${r.id})"
                style="padding:5px 14px;background:#4f8cff;color:#fff;border:0;border-radius:6px;font-size:12px;cursor:pointer">
                Upload
              </button>
              <span id="img-status-${r.id}" style="font-size:11px;color:#a7adbb"></span>
            </div>
          </td>
        </tr>
      `}).join('');

      const sampleOptions = ['Soro','Sangue Total','Plasma','Urina','Secreção','Swab','Linfa','Fezes','Líquor','Líquido Sinovial','Outro']
        .map(s => `<option>${s}</option>`).join('');

      const pdfActionsHtml = results.length ? `
        <div class="card" style="margin-top:12px">
          <p style="font-size:13px;color:#a7adbb;margin-bottom:10px">
            Revise os exames e abra o preview antes de enviar ao paciente.
          </p>
          <a href="/lab/admin/coletas/${id}/preview" target="_blank"
             style="display:block;width:100%;text-align:center;padding:11px;background:#4f8cff;color:#fff;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px;margin-bottom:8px">
            Abrir preview do PDF
          </a>
          <a href="/lab/admin/coletas/${id}/pdf"
             style="display:block;width:100%;text-align:center;padding:11px;background:#1a7a4a;color:#fff;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px">
            Baixar PDF final
          </a>
        </div>
      ` : '';

      const html = `
        <div class="card" style="margin-bottom:16px">
          <div style="display:flex;justify-content:space-between;align-items:flex-start">
            <div>
              <h1>${safe(collection.full_name)}</h1>
              <p class="mut">Coleta de ${toBR(collection.collected_at)} · Nasc. ${toBR(collection.birth_date)}</p>
            </div>
            <div style="display:flex;gap:12px;align-items:center">
              <form method="POST" action="/lab/admin/coletas/${id}/delete"
                    onsubmit="return confirm('Deletar esta coleta e todos os exames? Esta ação não pode ser desfeita.')">
                <button style="background:#b03030;color:#fff;border:0;border-radius:6px;padding:6px 14px;font-size:13px;cursor:pointer">
                  Deletar coleta
                </button>
              </form>
              <a href="/lab/admin/pacientes/${collection.patient_id}">← Paciente</a>
            </div>
          </div>
        </div>

        <div style="display:grid;grid-template-columns:1fr 360px;gap:16px;align-items:start">
          <!-- Formulário de novo exame -->
          <div class="card">
            <h2 style="margin-bottom:14px">Adicionar exame</h2>
           <form method="POST" action="/lab/admin/coletas/${id}/resultados" id="exam-form"
      data-original-action="/lab/admin/coletas/${id}/resultados">

              <label>Nome do exame</label>
              <select id="examSelect"
                style="width:100%;padding:10px;border-radius:8px;border:1px solid #2a2f39;background:#0f1116;color:#e7e9ee;font-size:14px">
                <option value="">Carregando…</option>
              </select>
              <label style="display:flex;align-items:center;gap:6px;margin-top:6px;font-size:12px;text-transform:none;letter-spacing:0">
                <input type="checkbox" id="examManualToggle">
                Digitar manualmente
              </label>
              <input id="examManualInput" name="exam_name"
                placeholder="Ex.: Sífilis — VDRL"
                style="display:none;margin-top:6px">
              <input id="examSelectHidden" name="exam_name" type="hidden">

              <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
                <div>
                <label>Amostra</label>
                <select id="sampleSelect" name="sample_type"
                  style="width:100%;padding:10px;border-radius:8px;border:1px solid #2a2f39;background:#0f1116;color:#e7e9ee;font-size:14px">
                  ${sampleOptions}
                </select>
                <label style="display:flex;align-items:center;gap:6px;margin-top:6px;font-size:12px;text-transform:none;letter-spacing:0;cursor:pointer">
                  <input type="checkbox" id="sampleManualToggle">
                  Digitar manualmente
                </label>
                <input id="sampleManualInput" name="sample_type_manual"
                  placeholder="Ex.: Líquor, Líquido pleural, LCR..."
                  style="display:none;margin-top:6px;width:100%;padding:10px;border-radius:8px;border:1px solid #2a2f39;background:#0f1116;color:#e7e9ee;font-size:14px">
              </div>
                <div>
                  <label>Valor de referência</label>
                  <input name="reference_value" placeholder="Ex.: NÃO REAGENTE">
                </div>
              </div>

              <label>Método</label>
              <input name="method" required placeholder="Ex.: Imunocromatografia de Fluxo Lateral">

              <label>Resultado</label>
              <div id="result-container"></div>
              <div style="margin-top:8px">
                <label style="margin-bottom:6px">Cor semântica</label>
                <div style="display:flex;gap:6px">
                  <button type="button" id="color-btn-auto"     onclick="setResultColor('auto')"
                    style="padding:4px 12px;border-radius:20px;border:1px solid #2a2f39;background:#20242b;color:#a7adbb;font-size:12px;cursor:pointer;opacity:1">
                    Auto
                  </button>
                  <button type="button" id="color-btn-negativo" onclick="setResultColor('negativo')"
                    style="padding:4px 12px;border-radius:20px;border:1px solid #1a7a4a;background:#20242b;color:#3fb950;font-size:12px;cursor:pointer;opacity:0.4">
                    ● Negativo
                  </button>
                  <button type="button" id="color-btn-neutro"   onclick="setResultColor('neutro')"
                    style="padding:4px 12px;border-radius:20px;border:1px solid #555;background:#20242b;color:#888;font-size:12px;cursor:pointer;opacity:0.4">
                    ● Neutro
                  </button>
                  <button type="button" id="color-btn-positivo" onclick="setResultColor('positivo')"
                    style="padding:4px 12px;border-radius:20px;border:1px solid #b03030;background:#20242b;color:#f47067;font-size:12px;cursor:pointer;opacity:0.4">
                    ● Positivo
                  </button>
                </div>
                <input type="hidden" name="result_color" id="result_color_input" value="auto">
              </div>
              
              <label>Observação (opcional)</label>
              <input name="observation" placeholder="Ex.: Teste realizado com baixo volume de soro">

              <label>Imagens (opcional)</label>
              <input type="file" id="img-inline-input" accept="image/*" multiple
                style="font-size:13px;color:#a7adbb;width:100%">
              <input type="text" id="img-inline-caption"
                placeholder="Legenda para todas as imagens (opcional)"
                style="margin-top:6px;width:100%;padding:10px;border-radius:8px;border:1px solid #2a2f39;background:#0f1116;color:#e7e9ee;font-size:13px">

              <button class="mt" style="width:100%;padding:11px;font-size:14px">+ Adicionar exame</button>
            </form>
          </div>

          <!-- Painel lateral: exames adicionados + ações de PDF -->
          <div>
            <div class="card">
              <h2 style="margin-bottom:12px">
                Exames nesta coleta
                <span class="mut" style="font-weight:400">(${results.length})</span>
              </h2>
              ${results.length ? `
                <table>
                  <thead><tr><th>Exame</th><th>Amostra</th><th>Resultado</th><th></th></tr></thead>
                  <tbody>${resultRows}</tbody>
                </table>
              ` : '<p class="mut">Nenhum exame adicionado ainda.</p>'}
            </div>
            ${pdfActionsHtml}
          </div>
<script>
      function toggleImgs(resultId) {
        var row = document.getElementById('imgs-' + resultId);
        if (!row) return;
        var visible = row.style.display !== 'none';
        row.style.display = visible ? 'none' : '';
        if (!visible) loadImgList(resultId);
      }

      function deleteImg(imgId) {
        if (confirm('Remover esta imagem?')) {
          document.getElementById('img-del-' + imgId).submit();
        }
      }

      function setResultColor(color) {
        var input = document.getElementById('result_color_input');
        if (input) input.value = color;
        var ids = ['auto', 'negativo', 'neutro', 'positivo'];
        ids.forEach(function(c) {
          var btn = document.getElementById('color-btn-' + c);
          if (btn) btn.style.opacity = c === color ? '1' : '0.4';
        });
      }

      async function loadImgList(resultId) {
        var container = document.getElementById('imgs-list-' + resultId);
        if (!container) return;
        try {
          var resp = await fetch('/lab/admin/resultados/' + resultId + '/images-list');
          var imgs = await resp.json();
          if (!imgs.length) {
            container.innerHTML = '<span style="font-size:12px;color:#666">Nenhuma imagem ainda.</span>';
            return;
          }
          container.innerHTML = imgs.map(function(img) {
            var html = '<div style="position:relative;display:inline-block">';
            html += '<img src="' + img.thumb_url + '" alt="' + (img.caption || '') + '" style="width:80px;height:80px;object-fit:cover;border-radius:6px;border:0.5px solid #2a2f39">';
            if (img.caption) {
              html += '<div style="font-size:10px;color:#a7adbb;text-align:center;max-width:80px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + img.caption + '</div>';
            }
            html += '<form method="POST" action="/lab/admin/images/' + img.id + '/delete" id="img-del-' + img.id + '" style="display:none"></form>';
            html += '<button type="button" onclick="deleteImg(' + img.id + ')" style="position:absolute;top:-6px;right:-6px;width:18px;height:18px;border-radius:50%;background:#b03030;color:#fff;border:0;cursor:pointer;font-size:11px;line-height:1;padding:0">\u00d7</button>';
            html += '</div>';
            return html;
          }).join('');
        } catch(e) {
          container.innerHTML = '<span style="font-size:12px;color:#b03030">Erro ao carregar imagens.</span>';
        }
      }
      async function loadExamForEdit(resultId) {
        try {
          var resp = await fetch('/lab/admin/resultados/' + resultId + '/json');
          var data = await resp.json();
          if (typeof window.prefillExamForm === 'function') {
            window.prefillExamForm(data, resultId);
          }
        } catch(e) {
          alert('Erro ao carregar exame para edição.');
          console.error(e);
        }
      }
      async function duplicateExam(resultId) {
        try {
          var resp = await fetch('/lab/admin/resultados/' + resultId + '/json');
          var data = await resp.json();
          if (typeof window.prefillForDuplicate === 'function') {
            window.prefillForDuplicate(data);
          }
        } catch(e) {
          alert('Erro ao duplicar exame.');
          console.error(e);
        }
      }
      async function uploadImgs(resultId) {
        var fileInput    = document.getElementById('img-file-' + resultId);
        var captionInput = document.getElementById('img-caption-' + resultId);
        var status       = document.getElementById('img-status-' + resultId);
        var files        = fileInput && fileInput.files;
        if (!files || !files.length) { alert('Selecione pelo menos uma imagem.'); return; }
        status.textContent = 'Enviando\u2026';
        var ok = 0, fail = 0;
        for (var i = 0; i < files.length; i++) {
          var file = files[i];
          if (file.size > 8 * 1024 * 1024) { alert(file.name + ' \u00e9 maior que 8MB.'); fail++; continue; }
          try {
            var base64 = await new Promise(function(resolve, reject) {
              var reader = new FileReader();
              reader.onload  = function(e) { resolve(e.target.result.split(',')[1]); };
              reader.onerror = reject;
              reader.readAsDataURL(file);
            });
            var uploadResp = await fetch('/lab/admin/resultados/' + resultId + '/images', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ data: base64, contentType: file.type, caption: captionInput.value }),
            });
            if (!uploadResp.ok) {
              var errJson = await uploadResp.json();
              throw new Error(errJson.error || 'Erro');
            }
            ok++;
          } catch(e) { console.error(e); fail++; }
        }
        status.textContent = ok + ' enviada(s)' + (fail ? ', ' + fail + ' falha(s)' : '');
        fileInput.value = '';
        captionInput.value = '';
        loadImgList(resultId);
      }
      </script>
      
         <script src="/lab-admin-coleta.js"></script>
        </div>
      `;
      res.send(renderShell(`Lab · Coleta ${toBR(collection.collected_at)}`, html));
    } catch (err) {
      console.error('LAB COLLECTION DETAIL ERROR', err);
      res.status(500).send(renderShell('Erro', `<div class="card"><p class="mut">${safe(err.message)}</p></div>`));
    }
  });

  // POST /lab/admin/coletas/:id/resultados — adiciona exame à coleta
  app.post('/lab/admin/coletas/:id/resultados', adminRequired, async (req, res) => {
    try {
      const collection_id = parseInt(req.params.id, 10);
      const examRaw         = req.body?.exam_name;
      const exam_name       = (Array.isArray(examRaw)
        ? examRaw.filter(Boolean).pop()
        : examRaw || '').trim();
      const sampleRaw       = req.body?.sample_type;
      const sample_type     = (Array.isArray(sampleRaw)
        ? sampleRaw.filter(Boolean).pop()
        : sampleRaw || 'Soro').trim();
      const method          = String(req.body?.method          || '').trim();
      const result_value    = String(req.body?.result_value    || '').trim();
      const reference_value = String(req.body?.reference_value || '').trim() || null;
      const observation     = String(req.body?.observation     || '').trim() || null;
      const result_color = String(req.body?.result_color || 'auto').trim();

      if (!exam_name || !method || !result_value) {
        return res.status(400).json({ error: 'Nome do exame, método e resultado são obrigatórios' });
      }

      const { rows: [{ max_sort }] } = await pool.query(
        'SELECT COALESCE(MAX(sort_index), 0) AS max_sort FROM lab_results WHERE collection_id=$1',
        [collection_id]
      );
      const { rows: [newResult] } = await pool.query(
        `INSERT INTO lab_results
           (collection_id, exam_name, sample_type, method, result_value, reference_value, observation, sort_index, result_color)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
        [collection_id, exam_name, sample_type, method, result_value,
         reference_value, observation, parseInt(max_sort, 10) + 10, result_color]
      );

      // Suporta tanto AJAX (retorna JSON) quanto submit nativo (redireciona)
      const isAjax = req.headers['x-requested-with'] === 'XMLHttpRequest';
      if (isAjax) {
        return res.json({ ok: true, result_id: newResult.id, collection_id });
      }
      res.redirect(`/lab/admin/coletas/${collection_id}`);
    } catch (err) {
      console.error('LAB ADD RESULT ERROR', err);
      const isAjax = req.headers['x-requested-with'] === 'XMLHttpRequest';
      if (isAjax) return res.status(500).json({ error: err.message });
      res.status(500).send('Falha ao adicionar exame');
    }
  });

  // POST /lab/admin/resultados/:id/delete — remove exame
  app.post('/lab/admin/resultados/:id/delete', adminRequired, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const { rows: [r] } = await pool.query(
        'SELECT collection_id FROM lab_results WHERE id=$1', [id]
      );
      if (!r) return res.status(404).send('Exame não encontrado');
      await pool.query('DELETE FROM lab_results WHERE id=$1', [id]);
      res.redirect(`/lab/admin/coletas/${r.collection_id}`);
    } catch (err) {
      console.error('LAB DELETE RESULT ERROR', err);
      res.status(500).send('Falha ao remover exame');
    }
  });

  // POST /lab/admin/resultados/:id/images — upload de imagem (base64 JSON)
  app.post('/lab/admin/resultados/:id/images', adminRequired, async (req, res) => {
    try {
      const result_id = parseInt(req.params.id, 10);
      const { data, contentType, caption } = req.body || {};

      if (!data || !contentType) return res.status(400).json({ error: 'Dados obrigatórios' });
      if (!contentType.startsWith('image/')) return res.status(400).json({ error: 'Tipo inválido' });

      // Limita a 8MB (base64 ~33% maior que binário)
      if (data.length > 11_000_000) return res.status(400).json({ error: 'Imagem muito grande (máx 8MB)' });

      const buffer  = Buffer.from(data, 'base64');
      const ext     = contentType.split('/')[1]?.replace('jpeg', 'jpg') || 'jpg';
      const r2Key   = `lab-images/${result_id}/${Date.now()}.${ext}`;

      await uploadToR2(r2Key, buffer, contentType);

      const { rows: [{ max_sort }] } = await pool.query(
        'SELECT COALESCE(MAX(sort_index), 0) AS max_sort FROM lab_result_images WHERE result_id=$1',
        [result_id]
      );
      const { rows: [img] } = await pool.query(
        `INSERT INTO lab_result_images (result_id, r2_key, caption, sort_index)
         VALUES ($1,$2,$3,$4) RETURNING id`,
        [result_id, r2Key, (caption || '').trim() || null, parseInt(max_sort, 10) + 10]
      );

      res.json({ ok: true, image_id: img.id, r2_key: r2Key });
    } catch (err) {
      console.error('LAB IMAGE UPLOAD ERROR', err);
      res.status(500).json({ error: err.message });
    }
  });
// GET /lab/admin/resultados/:id/images-list — JSON com lista de imagens
  app.get('/lab/admin/resultados/:id/images-list', adminRequired, async (req, res) => {
    try {
      const result_id = parseInt(req.params.id, 10);
      const { rows } = await pool.query(
        'SELECT id, r2_key, caption FROM lab_result_images WHERE result_id=$1 ORDER BY sort_index NULLS LAST, id',
        [result_id]
      );
      // Gera URLs assinadas para thumbnails (60s de validade, só para preview admin)
      const { fetchR2ImageAsDataURI } = await import('./lab-storage.js');
      const imgs = await Promise.all(rows.map(async img => ({
        id:       img.id,
        caption:  img.caption,
        thumb_url: await fetchR2ImageAsDataURI(img.r2_key).then(uri => uri).catch(() => ''),
      })));
      res.json(imgs);
    } catch (err) {
      console.error('LAB IMAGES LIST ERROR', err);
      res.status(500).json([]);
    }
  });
  // POST /lab/admin/images/:id/delete — remove imagem do DB e R2
  app.post('/lab/admin/images/:id/delete', adminRequired, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const { rows: [img] } = await pool.query(
        'SELECT result_id, r2_key FROM lab_result_images WHERE id=$1', [id]
      );
      if (!img) return res.status(404).send('Imagem não encontrada');

      await pool.query('DELETE FROM lab_result_images WHERE id=$1', [id]);
      await deleteFromR2(img.r2_key);

      // Redireciona de volta para a coleta (via referrer ou busca collection_id)
      const { rows: [r] } = await pool.query(
        'SELECT collection_id FROM lab_results WHERE id=$1', [img.result_id]
      );
      const target = r ? `/lab/admin/coletas/${r.collection_id}` : '/lab/admin';
      res.redirect(target);
    } catch (err) {
      console.error('LAB IMAGE DELETE ERROR', err);
      res.status(500).send('Falha ao remover imagem');
    }
  });

  // GET /lab/admin/resultados/:id/edit — formulário de edição de exame
  app.get('/lab/admin/resultados/:id/edit', adminRequired, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const { rows: [r] } = await pool.query(
        `SELECT lr.*, lc.id AS collection_id, lc.collected_at, lp.full_name
         FROM lab_results lr
         JOIN lab_collections lc ON lc.id = lr.collection_id
         JOIN lab_patients lp    ON lp.id = lc.patient_id
         WHERE lr.id = $1`, [id]
      );
      if (!r) return res.status(404).send(renderShell('Erro', `<div class="card"><h1>Exame não encontrado</h1></div>`));

      const sampleOptions = ['Soro','Sangue Total','Plasma','Urina','Secreção','Swab','Linfa','Fezes','Líquor','Líquido Sinovial','Outro']
        .map(s => `<option ${s === r.sample_type ? 'selected' : ''}>${s}</option>`).join('');

      const html = `
        <div class="card">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
            <div>
              <h1>Editar exame</h1>
              <p class="mut">${safe(r.full_name)} · Coleta de ${toBR(r.collected_at)}</p>
            </div>
            <a href="/lab/admin/coletas/${r.collection_id}">← Voltar à coleta</a>
          </div>
          <form method="POST" action="/lab/admin/resultados/${r.id}/edit">
            <label>Nome do exame</label>
            <input name="exam_name" required value="${safe(r.exam_name)}">

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
              <div>
                <label>Amostra</label>
                <select name="sample_type"
                  style="width:100%;padding:10px;border-radius:8px;border:1px solid #2a2f39;background:#0f1116;color:#e7e9ee;font-size:14px">
                  ${sampleOptions}
                </select>
              </div>
              <div>
                <label>Valor de referência</label>
                <input name="reference_value" value="${safe(r.reference_value || '')}">
              </div>
            </div>

            <label>Método</label>
            <input name="method" required value="${safe(r.method)}">

            <label>Resultado</label>
            <textarea name="result_value" rows="5" required
              style="width:100%;padding:10px;border-radius:8px;border:1px solid #2a2f39;background:#0f1116;color:#e7e9ee;font-size:14px;resize:vertical;font-family:inherit"
            >${safe(r.result_value)}</textarea>

            <label>Observação (opcional)</label>
            <input name="observation" value="${safe(r.observation || '')}">

            <div style="display:flex;gap:10px;margin-top:16px">
              <button style="padding:11px 24px;background:#4f8cff;color:#fff;border:0;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer">
                Salvar alterações
              </button>
              <a href="/lab/admin/coletas/${r.collection_id}"
                 style="padding:11px 24px;background:#20242b;color:#e7e9ee;border-radius:8px;font-size:14px;text-decoration:none;display:inline-block">
                Cancelar
              </a>
            </div>
          </form>
        </div>
      `;
      res.send(renderShell('Lab · Editar exame', html));
    } catch (err) {
      console.error('LAB EDIT RESULT GET ERROR', err);
      res.status(500).send(renderShell('Erro', `<div class="card"><p class="mut">${safe(err.message)}</p></div>`));
    }
  });

  // POST /lab/admin/resultados/:id/edit — salva edição
  app.post('/lab/admin/resultados/:id/edit', adminRequired, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const exam_name       = String(req.body?.exam_name       || '').trim();
      const sample_type     = String(req.body?.sample_type     || 'Soro').trim();
      const method          = String(req.body?.method          || '').trim();
      const result_value    = String(req.body?.result_value    || '').trim();
      const reference_value = String(req.body?.reference_value || '').trim() || null;
      const observation     = String(req.body?.observation     || '').trim() || null;
      const result_color = String(req.body?.result_color || 'auto').trim();

      if (!exam_name || !method || !result_value) {
        return res.status(400).send('Campos obrigatórios em falta');
      }

      await pool.query(
        `UPDATE lab_results
         SET exam_name=$1, sample_type=$2, method=$3, result_value=$4,
             reference_value=$5, observation=$6, result_color=$7
         WHERE id=$8`,
        [exam_name, sample_type, method, result_value, reference_value, observation, result_color, id]
      );

     const { rows: [r] } = await pool.query(
        'SELECT collection_id FROM lab_results WHERE id=$1', [id]
      );
      const isAjax = req.headers['x-requested-with'] === 'XMLHttpRequest';
      if (isAjax) return res.json({ ok: true, collection_id: r.collection_id });
      res.redirect(`/lab/admin/coletas/${r.collection_id}`);
    } catch (err) {
      console.error('LAB EDIT RESULT POST ERROR', err);
      res.status(500).send('Falha ao salvar alterações');
    }
  });

  // POST /lab/admin/coletas/:id/delete — deleta coleta inteira
  app.post('/lab/admin/coletas/:id/delete', adminRequired, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const { rows: [c] } = await pool.query(
        'SELECT patient_id FROM lab_collections WHERE id=$1', [id]
      );
      if (!c) return res.status(404).send('Coleta não encontrada');
      // ON DELETE CASCADE remove os lab_results automaticamente
      await pool.query('DELETE FROM lab_collections WHERE id=$1', [id]);
      res.redirect(`/lab/admin/pacientes/${c.patient_id}`);
    } catch (err) {
      console.error('LAB DELETE COLLECTION ERROR', err);
      res.status(500).send('Falha ao deletar coleta');
    }
  });

  // GET /lab/admin/coletas/:id/preview — preview do PDF como HTML (abre em nova aba)
  app.get('/lab/admin/coletas/:id/preview', adminRequired, async (req, res) => {
    try {
      const data = await getCollectionData(pool, parseInt(req.params.id, 10));
      if (!data) return res.status(404).send('Coleta não encontrada');
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(buildPdfHtml(data));
    } catch (err) {
      console.error('LAB PREVIEW ERROR', err);
      res.status(500).send(`Falha ao gerar preview: ${safe(err.message)}`);
    }
  });

  // GET /lab/admin/coletas/:id/pdf — gera e baixa o PDF final
  app.get('/lab/admin/coletas/:id/pdf', adminRequired, async (req, res) => {
    try {
      const data = await getCollectionData(pool, parseInt(req.params.id, 10));
      if (!data) return res.status(404).send('Coleta não encontrada');
      const pdf = await generateLabPdf(data);
      const fname = `Laudo_${data.patient.full_name.replace(/\s+/g, '_')}_${data.collection.collected_at}.pdf`;
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(fname)}"`);
      res.send(pdf);
    } catch (err) {
      console.error('LAB PDF ADMIN ERROR', err);
      res.status(500).send(`Falha ao gerar PDF: ${safe(err.message)}`);
    }
  });

  // ============================================================
  // ROTAS DO PORTAL DO PACIENTE  (/lab/*)
  // Usam renderPatientShell (tema claro/branco)
  // ============================================================

  // Middleware de autenticação do paciente (verifica cookie lab_key)
  const labAuth = async (req, res, next) => {
    const keyCode = req.cookies?.lab_key;
    if (!keyCode) return res.redirect('/lab');
    try {
      const { rows: [row] } = await pool.query(`
        SELECT lp.id, lp.full_name, lp.birth_date
        FROM lab_patients lp
        JOIN lab_access_keys lak ON lak.patient_id = lp.id
        WHERE lak.key_code = $1 AND lak.expires_at > now()
      `, [keyCode]);
      if (!row) { res.clearCookie('lab_key'); return res.redirect('/lab?erro=chave'); }
      req.labPatient = row;
      next();
    } catch (err) {
      console.error('LAB AUTH ERROR', err);
      res.redirect('/lab');
    }
  };

  // GET /lab — página de login do paciente
  app.get('/lab', (req, res) => {
    const erroMsg = req.query.erro === 'chave'
      ? 'Chave inválida ou expirada. Solicite uma nova ao consultório.'
      : '';

    const html = `
      <div style="max-width:400px;margin:48px auto">
        <div style="text-align:center;margin-bottom:28px">
          <div style="width:52px;height:52px;border-radius:50%;background:#111;margin:0 auto 14px;display:flex;align-items:center;justify-content:center">
            <svg viewBox="0 0 32 32" fill="none" style="width:28px;height:28px">
              <path d="M8 22L8 10L14 18L20 10L20 22" stroke="white" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
              <path d="M22 10 Q28 14 28 18 Q28 23 22 22" stroke="white" stroke-width="1.8" stroke-linecap="round" fill="none"/>
            </svg>
          </div>
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:#888;margin-bottom:4px">Consultório · Infectologia</div>
          <div style="font-size:20px;font-weight:600;color:#111">Dr. Leandro Mendes</div>
          <div style="font-size:12px;color:#888;margin-top:2px">Portal de Resultados</div>
        </div>

        <div class="card">
          <form method="POST" action="/lab/auth">
            <label>Chave de acesso</label>
            <input type="text" name="key_code" placeholder="LM-XXXX-XXXX"
              required autofocus autocomplete="off" spellcheck="false">
            <button class="btn-primary">Acessar meus resultados</button>
          </form>
          ${erroMsg ? `<p class="error-msg">${erroMsg}</p>` : ''}
          <p class="muted" style="text-align:center;margin-top:16px;line-height:1.6">
            A chave de acesso foi entregue pelo consultório.<br>
            Dúvidas: (11) 99611-2338
          </p>
        </div>

        <p style="text-align:center;font-size:11px;color:#bbb;margin-top:16px">
          🔒 Acesso criptografado · Seus dados são confidenciais
        </p>
      </div>
    `;
    res.send(renderPatientShell('Acesso', html));
  });

  // POST /lab/auth — valida chave e define cookie
  app.post('/lab/auth', async (req, res) => {
    try {
      const keyCode = ((req.body?.key_code) || '').trim().toUpperCase();
      if (!keyCode) return res.redirect('/lab?erro=chave');

      const { rows: [row] } = await pool.query(`
        SELECT lp.id FROM lab_patients lp
        JOIN lab_access_keys lak ON lak.patient_id = lp.id
        WHERE lak.key_code = $1 AND lak.expires_at > now()
      `, [keyCode]);

      if (!row) return res.redirect('/lab?erro=chave');

      res.cookie('lab_key', keyCode, {
        httpOnly: true,
        sameSite: 'lax',
        secure: true,
        maxAge: 1000 * 60 * 60 * 24 * 90, // 90 dias
      });
      res.redirect('/lab/resultados');
    } catch (err) {
      console.error('LAB AUTH POST ERROR', err);
      res.redirect('/lab?erro=chave');
    }
  });

  // GET /lab/logout
  app.get('/lab/logout', (req, res) => {
    res.clearCookie('lab_key');
    res.redirect('/lab');
  });

  // GET /lab/resultados — dashboard do paciente
  app.get('/lab/resultados', labAuth, async (req, res) => {
    try {
      const patient = req.labPatient;

      const { rows: collections } = await pool.query(`
        SELECT lc.id, lc.collected_at,
               COALESCE(
                 json_agg(
json_build_object(
  'id',           lr.id,
  'exam_name',    lr.exam_name,
  'result_value', lr.result_value,
  'result_color', lr.result_color,
  'sample_type',  lr.sample_type
) ORDER BY lr.sort_index NULLS LAST, lr.id
                 ) FILTER (WHERE lr.id IS NOT NULL),
                 '[]'
               ) AS results
        FROM lab_collections lc
        LEFT JOIN lab_results lr ON lr.collection_id = lc.id
        WHERE lc.patient_id = $1
        GROUP BY lc.id, lc.collected_at
        ORDER BY lc.collected_at DESC
      `, [patient.id]);

      function resultClass(val, storedColor) {
        if (storedColor === 'positivo') return 'tag-pos';
        if (storedColor === 'negativo') return 'tag-neg';
        if (storedColor === 'neutro')   return '';
        const v = (val || '').toUpperCase();
        if (/NÃO\s+REAGENTE|NAO\s+REAGENTE|NEGATIVO|AUSENTE/.test(v)) return 'tag-neg';
        if (/REAGENTE|POSITIVO|PRESENTE|CRESCIMENTO/.test(v))          return 'tag-pos';
        return '';
      }

      const monthNames = ['janeiro','fevereiro','março','abril','maio','junho','julho','agosto','setembro','outubro','novembro','dezembro'];

      const collectionsHtml = collections.map(c => {
        const results  = c.results || [];
        const raw = c.collected_at instanceof Date
          ? c.collected_at.toISOString().split('T')[0]
          : String(c.collected_at).split('T')[0];
        const d = new Date(raw + 'T12:00:00');
        const dateLabel = `${d.getDate()} de ${monthNames[d.getMonth()]} de ${d.getFullYear()}`;

        const resRows = results.map(r => `
          <tr>
            <td style="padding:10px 18px;width:40px">
              <input type="checkbox" class="chk" name="result_ids" value="${r.id}"
                     form="form-${c.id}" checked>
            </td>
            <td style="padding:10px 12px">${safe(r.exam_name)}</td>
            <td style="padding:10px 12px;font-size:11px;color:#888">${safe(r.sample_type)}</td>
            <td style="padding:10px 12px">
              <span class="${resultClass(r.result_value, r.result_color)}" style="font-size:13px">
                ${renderText((r.result_value || '').split('\n')[0])}
              </span>
            </td>
          </tr>
        `).join('');

        return `
          <div class="coleta-card">
            <div class="coleta-top">
              <span class="coleta-date">${dateLabel}</span>
              <span class="badge">${results.length} exame(s)</span>
            </div>
            <div class="coleta-body">
              <form id="form-${c.id}" action="/lab/coleta/${c.id}/pdf" method="GET" target="_blank">
                <table style="width:100%">
                  <thead><tr>
                    <th style="padding:8px 18px;width:40px"></th>
                    <th>Exame</th><th>Amostra</th><th>Resultado</th>
                  </tr></thead>
                  <tbody>${resRows}</tbody>
                </table>
                <div class="dl-bar">
                  <span class="muted">Selecione os exames a incluir</span>
                  <div style="display:flex;gap:8px">
                    <button type="submit" formaction="/lab/coleta/${c.id}/view"
                            class="btn-download" style="background:#333">
                      <svg width="13" height="13" viewBox="0 0 16 16" fill="currentColor">
                        <path d="M8 3C4 3 1 8 1 8s3 5 7 5 7-5 7-5-3-5-7-5zm0 8a3 3 0 110-6 3 3 0 010 6z"/>
                        <circle cx="8" cy="8" r="1.5"/>
                      </svg>
                      Visualizar
                    </button>
                    <button type="submit" class="btn-download">
                      <svg width="13" height="13" viewBox="0 0 16 16" fill="currentColor">
                        <path d="M8 12l-4-4h2.5V3h3v5H12L8 12z"/>
                        <path d="M2 14h12v-1.5H2V14z"/>
                      </svg>
                      Baixar PDF
                    </button>
                  </div>
                </div>
        `;
      }).join('');

      const html = `
        <div style="margin-bottom:24px">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#888;margin-bottom:4px">
            Bem-vindo(a)
          </div>
          <h1 style="font-size:22px;font-weight:600;color:#111">${safe(patient.full_name)}</h1>
          <p class="muted" style="margin-top:3px">Data de nascimento: ${toBR(patient.birth_date)}</p>
        </div>
        ${collectionsHtml || '<div class="card"><p class="muted">Nenhum resultado disponível ainda.</p></div>'}
      `;
      res.send(renderPatientShell('Meus resultados', html, patient));
    } catch (err) {
      console.error('LAB RESULTS PAGE ERROR', err);
      res.status(500).send(renderPatientShell('Erro', '<p>Falha ao carregar resultados. Tente novamente.</p>'));
    }
  });

  // GET /lab/coleta/:id/view — visualização HTML para o paciente
  app.get('/lab/coleta/:id/view', labAuth, async (req, res) => {
    try {
      const collectionId = parseInt(req.params.id, 10);
      const patient      = req.labPatient;
      let ids = req.query.result_ids || req.query['result_ids[]'];
      if (ids && !Array.isArray(ids)) ids = [ids];
      const parsedIds = (ids || []).map(id => parseInt(id, 10)).filter(Number.isFinite);
      const data = await getCollectionDataLite(
        pool, collectionId, patient.id, parsedIds.length ? parsedIds : null
      );
      if (!data) return res.status(404).send('Coleta não encontrada');
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(buildPdfHtml(data));
    } catch (err) {
      console.error('LAB PATIENT VIEW ERROR', err);
      res.status(500).send('Falha ao carregar visualização.');
    }
  });

  // GET /lab/coleta/:id/pdf — gera PDF para os exames selecionados pelo paciente
  app.get('/lab/coleta/:id/pdf', labAuth, async (req, res) => {
    try {
      const collectionId = parseInt(req.params.id, 10);
      const patient      = req.labPatient;

      // Coleta os IDs selecionados (query string: result_ids=1&result_ids=2)
      let ids = req.query.result_ids || req.query['result_ids[]'];
      if (ids && !Array.isArray(ids)) ids = [ids];
      const parsedIds = (ids || []).map(id => parseInt(id, 10)).filter(Number.isFinite);

      // Se nenhum selecionado, usa todos (fallback)
      const data = await getCollectionData(
        pool, collectionId, patient.id, parsedIds.length ? parsedIds : null
      );
      if (!data) return res.status(404).send('Coleta não encontrada');

      const pdf   = await generateLabPdf(data);
      const fname = `Laudo_${patient.full_name.replace(/\s+/g, '_')}_${data.collection.collected_at}.pdf`;
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(fname)}"`);
      res.send(pdf);
    } catch (err) {
      console.error('LAB PATIENT PDF ERROR', err);
      res.status(500).send('Falha ao gerar PDF. Tente novamente ou entre em contato com o consultório.');
    }
  });

} // fim de registerLabRoutes
