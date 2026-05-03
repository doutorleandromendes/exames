// lab-routes.js
// Todas as rotas do portal de resultados laboratoriais
// Prefixo /lab/admin/* para o médico, /lab/* para o paciente
//
// Uso em app.js:
//   registerLabRoutes(app, pool, adminRequired, renderShell);

import { buildPdfHtml, generateLabPdf } from './lab-pdf.js';

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

// ====== Loader de dados compartilhado ======

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
    resultsQ      = `SELECT * FROM lab_results WHERE collection_id=$1 AND id = ANY($2::int[]) ORDER BY sort_index NULLS LAST, id ASC`;
    resultsParams = [collectionId, resultIds];
  } else {
    resultsQ      = `SELECT * FROM lab_results WHERE collection_id=$1 ORDER BY sort_index NULLS LAST, id ASC`;
    resultsParams = [collectionId];
  }
  const { rows: results } = await pool.query(resultsQ, resultsParams);

  return {
    patient:    { full_name: collection.full_name, birth_date: collection.birth_date },
    collection: { collected_at: collection.collected_at },
    results,
  };
}

// ====== Registro de rotas ======

export function registerLabRoutes(app, pool, adminRequired, renderShell) {
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

      // Converte qualquer formato de data para YYYY-MM-DD
      function toISO(s) {
        if (!s) return '';
        s = String(s).trim();
        // DD/MM/AAAA
        if (/^\d{1,2}\/\d{1,2}\/\d{4}$/.test(s)) {
          const [d, m, y] = s.split('/');
          return `${y}-${m.padStart(2,'0')}-${d.padStart(2,'0')}`;
        }
        // YYYY-MM-DD
        if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
        // MM/DD/YYYY (formato US que o Sheets às vezes exporta)
        if (/^\d{1,2}\/\d{1,2}\/\d{4}$/.test(s)) {
          const [m, d, y] = s.split('/');
          return `${y}-${m.padStart(2,'0')}-${d.padStart(2,'0')}`;
        }
        // Tenta Date() como fallback
        const dt = new Date(s);
        if (!isNaN(dt)) {
          const y = dt.getFullYear();
          const m = String(dt.getMonth()+1).padStart(2,'0');
          const d = String(dt.getDate()).padStart(2,'0');
          return `${y}-${m}-${d}`;
        }
        return '';
      }

      const lines = csv.split(/\r?\n/).filter(Boolean);
      const pacientes = [];
      for (let i = 1; i < lines.length; i++) {
        const cols = parseCSVLine(lines[i]);
        const nome = `${(cols[0]||'').trim()} ${(cols[1]||'').trim()}`.trim();
        const dn   = toISO((cols[2]||'').trim());
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
  app.get('/lab/admin/api/exames', adminRequired, async (req, res) => {
    try {
      const apiUrl = 'https://api.github.com/repos/doutorleandromendes/exames/contents/products.csv?ref=main';

      const headers = {
        'Accept':              'application/vnd.github.raw',
        'X-GitHub-Api-Version':'2022-11-28',
        'User-Agent':          'lab-portal-lm',
      };
      if (process.env.GITHUB_TOKEN) {
        headers['Authorization'] = 'Bearer ' + process.env.GITHUB_TOKEN;
      }

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
      '  fetch("/lab/admin/api/pacientes-sheet")',
      '    .then(function(r){ return r.json(); })',
      '    .then(function(pacs){',
      '      var sel = document.getElementById("pacSelect");',
      '      pacs.forEach(function(p){',
      '        var opt = document.createElement("option");',
      '        opt.value = p.nome+"|"+p.dn;',
      '        opt.textContent = p.nome;',
      '        sel.appendChild(opt);',
      '      });',
      '      document.getElementById("statusPac").textContent = pacs.length+" pacientes carregados da planilha";',
      '    })',
      '    .catch(function(){',
      '      document.getElementById("statusPac").textContent = "Não foi possível carregar a planilha — preencha manualmente";',
      '    });',
      '  document.getElementById("pacSelect").addEventListener("change", function(){',
      '    if(!this.value) return;',
      '    var parts = this.value.split("|");',
      '    document.getElementById("fNome").value = parts[0]||"";',
      '    document.getElementById("fDN").value   = parts[1]||"";',
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

        <label>Selecionar da planilha</label>
        <select id="pacSelect"
          style="width:100%;padding:10px;border-radius:8px;border:1px solid #2a2f39;background:#0f1116;color:#e7e9ee;font-size:14px;margin-bottom:16px">
          <option value="">— escolha um paciente ou preencha manualmente —</option>
        </select>

        <form method="POST" action="/lab/admin/pacientes">
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

      if (!full_name || !birth_date) {
        return res.status(400).send(renderShell('Erro', `
          <div class="card"><h1>Nome e data de nascimento são obrigatórios</h1>
          <p><a href="/lab/admin/pacientes/novo">Voltar</a></p></div>
        `));
      }

      await client.query('BEGIN');

      const { rows: [patient] } = await client.query(
        'INSERT INTO lab_patients (full_name, birth_date, notes) VALUES ($1, $2, $3) RETURNING id',
        [full_name, birth_date, notes]
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
        'SELECT * FROM lab_results WHERE collection_id=$1 ORDER BY sort_index NULLS LAST, id ASC',
        [id]
      );

      const resultRows = results.map(r => `
        <tr>
          <td><strong>${safe(r.exam_name)}</strong></td>
          <td style="color:#a7adbb">${safe(r.sample_type)}</td>
          <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
            ${safe((r.result_value || '').split('\n')[0])}
          </td>
          <td>
            <form method="POST" action="/lab/admin/resultados/${r.id}/delete" style="display:inline"
                  onsubmit="return confirm('Remover o exame &quot;${safe(r.exam_name)}&quot;?')">
              <button style="background:none;border:0;color:#8fb6ff;cursor:pointer;padding:0;font-size:12px">remover</button>
            </form>
          </td>
        </tr>
      `).join('');

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
            <a href="/lab/admin/pacientes/${collection.patient_id}">← Paciente</a>
          </div>
        </div>

        <div style="display:grid;grid-template-columns:1fr 360px;gap:16px;align-items:start">
          <!-- Formulário de novo exame -->
          <div class="card">
            <h2 style="margin-bottom:14px">Adicionar exame</h2>
            <form method="POST" action="/lab/admin/coletas/${id}/resultados">

              <label>Nome do exame</label>
              <select id="examSelect"
                style="width:100%;padding:10px;border-radius:8px;border:1px solid #2a2f39;background:#0f1116;color:#e7e9ee;font-size:14px">
                <option value="">Carregando…</option>
              </select>
              <label style="display:flex;align-items:center;gap:6px;margin-top:6px;font-size:12px;text-transform:none;letter-spacing:0">
                <input type="checkbox" id="examManualToggle">
                Digitar manualmente
              </label>
              <input id="examManualInput" name="exam_name" required
                placeholder="Ex.: Sífilis — VDRL"
                style="display:none;margin-top:6px">
              <input id="examSelectHidden" name="exam_name" type="hidden">

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
                  <input name="reference_value" placeholder="Ex.: NÃO REAGENTE">
                </div>
              </div>

              <label>Método</label>
              <input name="method" required placeholder="Ex.: Imunocromatografia de Fluxo Lateral">

              <label>Resultado</label>
              <textarea name="result_value" rows="4" required
                placeholder="Ex.: NÃO REAGENTE&#10;&#10;Para culturas, use linhas separadas:&#10;SENSÍVEL A: Meropenem...&#10;RESISTENTE A: Ciprofloxacina..."
                style="width:100%;padding:10px;border-radius:8px;border:1px solid #2a2f39;background:#0f1116;color:#e7e9ee;font-size:14px;resize:vertical;font-family:inherit"></textarea>

              <label>Observação (opcional)</label>
              <input name="observation" placeholder="Ex.: Teste realizado com baixo volume de soro">

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
        (function(){
          var sel   = document.getElementById('examSelect');
          var hidden = document.getElementById('examSelectHidden');
          var manual = document.getElementById('examManualInput');
          var toggle = document.getElementById('examManualToggle');

          fetch('/lab/admin/api/exames')
            .then(function(r){ return r.json(); })
            .then(function(exames){
              sel.innerHTML = '<option value="">— selecione o exame —</option>';
              exames.forEach(function(nome){
                var opt = document.createElement('option');
                opt.value = nome; opt.textContent = nome;
                sel.appendChild(opt);
              });
            })
            .catch(function(){
              sel.innerHTML = '<option value="">Falha ao carregar — use digitação manual</option>';
              toggle.checked = true;
              toggle.dispatchEvent(new Event('change'));
            });

          sel.addEventListener('change', function(){
            hidden.value = this.value;
          });

          toggle.addEventListener('change', function(){
            var isManual = this.checked;
            sel.style.display    = isManual ? 'none' : '';
            hidden.disabled      = isManual;
            manual.style.display = isManual ? '' : 'none';
            manual.required      = isManual;
            if(!isManual) hidden.value = sel.value;
          });
        })();
      </script>
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
      const exam_name       = (req.body?.exam_name       || '').trim();
      const sample_type     = (req.body?.sample_type     || 'Soro').trim();
      const method          = (req.body?.method          || '').trim();
      const result_value    = (req.body?.result_value    || '').trim();
      const reference_value = (req.body?.reference_value || '').trim() || null;
      const observation     = (req.body?.observation     || '').trim() || null;

      if (!exam_name || !method || !result_value) {
        return res.status(400).send('Nome do exame, método e resultado são obrigatórios');
      }

      // sort_index = max atual + 10
      const { rows: [{ max_sort }] } = await pool.query(
        'SELECT COALESCE(MAX(sort_index), 0) AS max_sort FROM lab_results WHERE collection_id=$1',
        [collection_id]
      );

      await pool.query(
        `INSERT INTO lab_results
           (collection_id, exam_name, sample_type, method, result_value, reference_value, observation, sort_index)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [collection_id, exam_name, sample_type, method, result_value,
         reference_value, observation, parseInt(max_sort, 10) + 10]
      );

      res.redirect(`/lab/admin/coletas/${collection_id}`);
    } catch (err) {
      console.error('LAB ADD RESULT ERROR', err);
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

      function resultClass(val) {
        const v = (val || '').toUpperCase();
        if (/NÃO\s+REAGENTE|NAO\s+REAGENTE|NEGATIVO|AUSENTE/.test(v)) return 'tag-neg';
        if (/REAGENTE|POSITIVO|PRESENTE|CRESCIMENTO/.test(v))          return 'tag-pos';
        return '';
      }

      const monthNames = ['janeiro','fevereiro','março','abril','maio','junho','julho','agosto','setembro','outubro','novembro','dezembro'];

      const collectionsHtml = collections.map(c => {
        const results  = c.results || [];
        const d        = new Date(String(c.collected_at) + 'T12:00:00');
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
              <span class="${resultClass(r.result_value)}" style="font-size:13px">
                ${safe((r.result_value || '').split('\n')[0])}
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
                  <span class="muted">Selecione os exames a incluir no PDF</span>
                  <button type="submit" class="btn-download">
                    <svg width="13" height="13" viewBox="0 0 16 16" fill="currentColor">
                      <path d="M8 12l-4-4h2.5V3h3v5H12L8 12z"/>
                      <path d="M2 14h12v-1.5H2V14z"/>
                    </svg>
                    Baixar PDF
                  </button>
                </div>
              </form>
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
