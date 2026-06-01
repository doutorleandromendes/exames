// atb-routes.js

import { handleWebhook, iniciarPolling, rodarTriagemIA } from './atb-sync.js';
import { parseFormPayload } from './atb-parser.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function safe(s) {
  return String(s ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

export function registerAtbRoutes(app, pool, adminRequired, renderShell) {

  // ── Webhook (sem auth) ────────────────────────────────────────────────
  app.post('/atb/webhook', handleWebhook(pool));

  // ── Polling no startup ────────────────────────────────────────────────
  iniciarPolling(pool).catch(e => console.error('[atb] falha ao iniciar polling:', e.message));

  // ── Formulário do prescritor (público) ────────────────────────────────
  app.get('/atb/form', (req, res) => {
    const inst = (req.query.inst || 'HUSF').replace(/'/g, '');
    let html = fs.readFileSync(path.join(__dirname, 'atb-form.html'), 'utf8');
    html = html.replace("window.ATB_INSTITUICAO || 'HUSF'", `'${inst}'`);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  });

  // ── API: valida CRM ───────────────────────────────────────────────────
  app.get('/atb/api/validar-crm', async (req, res) => {
    const { crm, instituicao } = req.query;
    if (!crm) return res.status(400).json({ erro: 'CRM obrigatório' });
    try {
      const { rows } = await pool.query(`
        SELECT m.nome, m.especialidade
        FROM atb_medicos m
        JOIN atb_instituicoes i ON i.id = m.instituicao_id
        WHERE m.crm = $1
          AND ($2::text IS NULL OR i.sigla = $2)
          AND m.ativo = true
        LIMIT 1
      `, [crm.trim(), instituicao || null]);
      if (rows[0]) {
        res.json({ encontrado: true, nome: rows[0].nome, especialidade: rows[0].especialidade });
      } else {
        res.json({ encontrado: false });
      }
    } catch (e) {
      res.status(500).json({ erro: e.message });
    }
  });

  // ── API: recebe submissão do formulário próprio ────────────────────────
  app.post('/atb/api/fichas', async (req, res) => {
    try {
      const d = req.body;
      if (!d.pac_nome || !d.prontuario || !d.crm) {
        return res.status(400).json({ error: 'Campos obrigatórios em falta' });
      }
      const parsed = parseFormPayload(d);
      const inst   = d.instituicao || 'HUSF';
      const { rows: [instRow] } = await pool.query(
        'SELECT id FROM atb_instituicoes WHERE sigla = $1', [inst]
      );
      const submissionId = `form_${Date.now()}_${Math.random().toString(36).slice(2,8)}`;

      const { rows: [ficha] } = await pool.query(`
        INSERT INTO atb_fichas (
          instituicao_id, jotform_submission_id, jotform_created_at,
          paciente_nome, paciente_nome_raw, paciente_dn, paciente_idade,
          prontuario, atendimento, setor, leito, equipe_responsavel,
          data_internacao, data_admissao_uti, tipo_terapia, historia_clinica,
          cirurgia, foco_infeccao, sepse, gestante, lactante, comorbidades,
          uso_atb_7d, atb_previos, culturas_colhidas, culturas_previas,
          dispositivos_invasivos, dialise, acesso_dialise, data_insercao_cateter,
          sitio_cvc, sitio_cdl, sitio_pai, peso_nascimento, acesso_vascular_neo,
          insuficiencia_renal, clcr, peso, altura, faz_quimio, cateter_quimio,
          acesso_quimio, classificacao_fratura, atb_solicitado, posologia,
          tempo_previsto, oxacilina_associacao, crm, prescritor_nome,
          sofa, sofa_renal, payload_raw, status
        ) VALUES (
          $1,$2,now(),$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
          $16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,
          $30,$31,$32,$33,$34,$35,$36,$37,$38,$39,$40,$41,$42,$43,
          $44,$45,$46,$47,$48,$49,$50,$51,'pendente'
        ) RETURNING id
      `, [
        instRow?.id, submissionId,
        parsed.paciente_nome, parsed.paciente_nome_raw, parsed.paciente_dn,
        parsed.paciente_idade, parsed.prontuario, parsed.atendimento,
        parsed.setor, parsed.leito, parsed.equipe_responsavel,
        parsed.data_internacao, parsed.data_admissao_uti, parsed.tipo_terapia,
        parsed.historia_clinica, parsed.cirurgia, parsed.foco_infeccao,
        parsed.sepse, parsed.gestante, parsed.lactante,
        JSON.stringify(parsed.comorbidades), parsed.uso_atb_7d,
        JSON.stringify(parsed.atb_previos), JSON.stringify(parsed.culturas_colhidas),
        JSON.stringify(parsed.culturas_previas), JSON.stringify(parsed.dispositivos_invasivos),
        parsed.dialise, parsed.acesso_dialise, parsed.data_insercao_cateter,
        JSON.stringify(parsed.sitio_cvc), JSON.stringify(parsed.sitio_cdl),
        JSON.stringify(parsed.sitio_pai), parsed.peso_nascimento,
        JSON.stringify(parsed.acesso_vascular_neo), JSON.stringify(parsed.insuficiencia_renal),
        parsed.clcr, parsed.peso, parsed.altura, parsed.faz_quimio,
        parsed.cateter_quimio, parsed.acesso_quimio, parsed.classificacao_fratura,
        JSON.stringify(parsed.atb_solicitado), JSON.stringify(parsed.posologia),
        parsed.tempo_previsto, parsed.oxacilina_associacao,
        parsed.crm, parsed.prescritor_nome, parsed.sofa, parsed.sofa_renal,
        JSON.stringify(d),
      ]);

      // Triagem IA assíncrona
      rodarTriagemIA(parsed).then(async triagem => {
        if (!triagem) return;
        await pool.query(`
          INSERT INTO atb_avaliacoes (ficha_id, triagem_ia, triagem_ia_at)
          VALUES ($1,$2,now())
          ON CONFLICT (ficha_id) DO UPDATE SET triagem_ia=$2, triagem_ia_at=now()
        `, [ficha.id, JSON.stringify(triagem)]);
      }).catch(() => {});

      res.json({ ok: true, id: ficha.id });
    } catch (e) {
      console.error('[atb] POST /fichas error:', e);
      res.status(500).json({ error: e.message });
    }
  });

  // ── Dashboard ─────────────────────────────────────────────────────────
  app.get('/atb/admin', adminRequired, async (req, res) => {
    try {
      const { rows: [totais] } = await pool.query(`
        SELECT
          COUNT(*)                                               AS total,
          COUNT(*) FILTER (WHERE status = 'pendente')           AS pendentes,
          COUNT(*) FILTER (WHERE status = 'avaliado')           AS avaliados,
          COUNT(*) FILTER (WHERE date_trunc('day', created_at)
                                 = CURRENT_DATE)               AS hoje
        FROM atb_fichas
      `);

      const { rows: recentes } = await pool.query(`
        SELECT f.id, f.paciente_nome, f.prontuario, f.setor, f.atb_solicitado,
               f.status, f.sofa, f.created_at, f.recomendacao_scih,
               i.sigla AS instituicao, a.triagem_ia
        FROM atb_fichas f
        LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
        LEFT JOIN atb_avaliacoes   a ON a.ficha_id = f.id
        ORDER BY f.created_at DESC
        LIMIT 20
      `);

      const statusBadge = s => {
        const c = { pendente:'#ba8c00', em_avaliacao:'#4f8cff', avaliado:'#1a7a4a', arquivado:'#555' };
        return `<span style="font-size:10px;padding:2px 8px;border-radius:8px;background:${c[s]||'#333'};color:#fff">${s}</span>`;
      };
      const riscoBadge = triagem => {
        if (!triagem) return '<span style="color:#555;font-size:11px">—</span>';
        const c = { alto:'#b03030', medio:'#ba8c00', baixo:'#1a7a4a', inconclusivo:'#555' };
        const r = triagem.risco_iras || 'inconclusivo';
        return `<span style="font-size:10px;padding:2px 8px;border-radius:8px;background:${c[r]||'#555'};color:#fff">${r}</span>`;
      };

      const tableRows = recentes.map(f => {
        const atbs = Array.isArray(f.atb_solicitado) ? f.atb_solicitado.join(', ') : '—';
        return `<tr>
          <td><strong>${safe(f.paciente_nome||'—')}</strong>
            <div class="mut" style="font-size:11px">${safe(f.prontuario||'')}</div></td>
          <td><span class="mut">${safe(f.instituicao||'')}</span> ${safe(f.setor||'')}</td>
          <td style="font-size:12px">${safe(atbs)}</td>
          <td>${f.sofa!=null?f.sofa:'—'}</td>
          <td>${riscoBadge(f.triagem_ia)}</td>
          <td>${statusBadge(f.status)}</td>
          <td><a href="/atb/admin/fichas/${f.id}">abrir</a></td>
        </tr>`;
      }).join('');

      const stats = [
        ['Total', totais.total], ['Hoje', totais.hoje],
        ['Pendentes', totais.pendentes], ['Avaliados', totais.avaliados],
      ].map(([lbl,val]) => `
        <div style="background:var(--card);border:1px solid #20242b;border-radius:10px;padding:14px 16px">
          <div style="font-size:22px;font-weight:600;color:#e7e9ee">${val}</div>
          <div style="font-size:11px;color:#a7adbb;text-transform:uppercase;letter-spacing:.06em;margin-top:2px">${lbl}</div>
        </div>`).join('');

      const html = `
        <div class="card" style="margin-bottom:16px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
            <h1>Controle ATB</h1>
            <div>
              <a href="/atb/admin/fichas" style="margin-right:12px">Ver todas</a>
              <a href="/atb/admin/config">Configurar</a>
            </div>
          </div>
          <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px">${stats}</div>
        </div>
        <div class="card">
          <h2 style="margin-bottom:14px">Fichas recentes</h2>
          <table>
            <thead><tr>
              <th>Paciente</th><th>Local</th><th>ATB</th>
              <th>SOFA</th><th>Risco IA</th><th>Status</th><th></th>
            </tr></thead>
            <tbody>${tableRows||'<tr><td colspan="7" class="mut">Nenhuma ficha ainda.</td></tr>'}</tbody>
          </table>
        </div>`;
      res.send(renderShell('ATB · Dashboard', html));
    } catch (e) {
      console.error('[atb] dashboard error:', e);
      res.status(500).send(renderShell('Erro', `<div class="card"><p class="mut">${safe(e.message)}</p></div>`));
    }
  });

  // ── Listagem de fichas ────────────────────────────────────────────────
  app.get('/atb/admin/fichas', adminRequired, async (req, res) => {
    try {
      const { q='', status='', inst='', page='1', per='40' } = req.query;
      const pageNum  = Math.max(1, parseInt(page, 10));
      const pageSize = Math.min(100, Math.max(10, parseInt(per, 10)));
      const offset   = (pageNum - 1) * pageSize;

      const where = ['1=1'], params = [];
      if (q.trim()) {
        params.push(`%${q.toLowerCase()}%`);
        where.push(`(LOWER(f.paciente_nome) LIKE $${params.length}
                 OR LOWER(f.paciente_nome_raw) LIKE $${params.length}
                 OR f.prontuario LIKE $${params.length}
                 OR f.atendimento LIKE $${params.length}
                 OR LOWER(f.prescritor_nome) LIKE $${params.length})`);
      }
      if (status) { params.push(status); where.push(`f.status = $${params.length}`); }
      if (inst)   { params.push(inst);   where.push(`i.sigla  = $${params.length}`); }
      const whereSql = where.join(' AND ');

      const { rows: [{ total }] } = await pool.query(`
        SELECT COUNT(*) AS total
        FROM atb_fichas f
        LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
        WHERE ${whereSql}
      `, params);

      const { rows } = await pool.query(`
        SELECT f.id, f.paciente_nome, f.prontuario, f.atendimento,
               f.setor, f.tipo_terapia, f.atb_solicitado, f.sepse,
               f.sofa, f.status, f.prescritor_nome, f.recomendacao_scih,
               f.jotform_created_at, f.created_at, f.obito,
               i.sigla AS instituicao,
               a.iras, a.triagem_ia
        FROM atb_fichas f
        LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
        LEFT JOIN atb_avaliacoes   a ON a.ficha_id = f.id
        WHERE ${whereSql}
        ORDER BY f.created_at DESC
        LIMIT $${params.length+1} OFFSET $${params.length+2}
      `, [...params, pageSize, offset]);

      const totalPages = Math.max(1, Math.ceil(parseInt(total,10) / pageSize));

      const { rows: sc } = await pool.query(
        `SELECT status, COUNT(*) AS n FROM atb_fichas GROUP BY status`
      );
      const counts = Object.fromEntries(sc.map(r => [r.status, r.n]));

      const stStyle = {
        pendente:     'background:#b84c1e22;color:#b84c1e',
        em_avaliacao: 'background:#2563eb22;color:#2563eb',
        avaliado:     'background:#1a6b3a22;color:#1a6b3a',
        arquivado:    'background:#70706822;color:#706e68',
        historico:    'background:#70706811;color:#a0a09a',
      };
      const riscoCor = { alto:'#b84c1e', medio:'#8a6500', baixo:'#1a6b3a', inconclusivo:'#706e68' };
      const badge = (label, style) =>
        `<span style="font-size:10px;padding:2px 8px;border-radius:10px;font-weight:600;${style}">${safe(label)}</span>`;

      const recMap = {
        'Sim':'✓ Sim', 'Não':'✗ Não',
        'Com ajustes (especificados abaixo)':'⚠ Ajustes',
        'Suspenso':'⊘ Suspenso', 'Ficha Repetida':'↩ Repetida',
      };

      const tableRows = rows.map(f => {
        const atbs   = Array.isArray(f.atb_solicitado) ? f.atb_solicitado.join(', ') : '—';
        const risco  = f.triagem_ia?.risco_iras;
        const dt     = f.jotform_created_at || f.created_at;
        const dtFmt  = dt ? new Date(dt).toLocaleDateString('pt-BR') : '—';
        const rec    = Array.isArray(f.recomendacao_scih) ? f.recomendacao_scih[0]||'' : '';
        const recStyle = rec==='Sim'
          ? 'background:#1a6b3a22;color:#1a6b3a'
          : rec==='Não'
          ? 'background:#b84c1e22;color:#b84c1e'
          : 'background:#8a650022;color:#8a6500';
        return `<tr style="cursor:pointer" onclick="location.href='/atb/admin/fichas/${f.id}'">
          <td style="white-space:nowrap">
            <div style="font-size:12px;font-weight:600;font-family:monospace">${dtFmt}</div>
            <div class="mut" style="font-size:10px">${safe(f.instituicao||'')} · ${safe(f.setor||'')}</div>
          </td>
          <td>
            <div style="font-weight:600;font-size:13px">${safe(f.paciente_nome||f.prontuario||'—')}</div>
            <div class="mut" style="font-size:11px">Pront. ${safe(f.prontuario||'—')}${f.obito?' · <span style="color:#b84c1e">✝ Óbito</span>':''}</div>
          </td>
          <td style="font-size:12px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${safe(atbs)}</td>
          <td>${f.sofa!=null?`<span style="font-family:monospace;font-size:13px;font-weight:600">${f.sofa}</span>`:'<span class="mut">—</span>'}</td>
          <td>${risco?`<span style="font-size:10px;padding:2px 8px;border-radius:10px;font-weight:600;background:${riscoCor[risco]}22;color:${riscoCor[risco]}">${risco}</span>`:'<span class="mut" style="font-size:11px">—</span>'}</td>
          <td>${rec?badge(recMap[rec]||rec,recStyle):''}</td>
          <td>${badge(f.status, stStyle[f.status]||'')}</td>
          <td style="text-align:right"><a href="/atb/admin/fichas/${f.id}" onclick="event.stopPropagation()" style="font-size:12px;color:#4f8cff;text-decoration:none">Abrir →</a></td>
        </tr>`;
      }).join('');

      const mkUrl = p => `/atb/admin/fichas?${new URLSearchParams({...req.query,page:p})}`;
      const pager = totalPages > 1 ? `
        <div style="display:flex;align-items:center;gap:8px;margin-top:16px;font-size:12px">
          ${pageNum>1?`<a href="${mkUrl(pageNum-1)}" style="color:#8fb6ff">← Anterior</a>`:'<span class="mut">← Anterior</span>'}
          <span class="mut">Página ${pageNum} de ${totalPages} · ${total} fichas</span>
          ${pageNum<totalPages?`<a href="${mkUrl(pageNum+1)}" style="color:#8fb6ff">Próxima →</a>`:'<span class="mut">Próxima →</span>'}
        </div>` : `<div class="mut" style="margin-top:12px;font-size:12px">${total} fichas</div>`;

      const statusTabs = [
        ['','Todas',total],
        ['pendente','Pendentes',counts.pendente||0],
        ['em_avaliacao','Em avaliação',counts.em_avaliacao||0],
        ['avaliado','Avaliadas',counts.avaliado||0],
        ['historico','Histórico',counts.historico||0],
      ].map(([val,label,count]) => {
        const active = status===val;
        const url = new URLSearchParams({...req.query,status:val,page:'1'});
        return `<a href="/atb/admin/fichas?${url}"
          style="display:inline-flex;align-items:center;gap:6px;padding:6px 14px;
                 border-radius:20px;font-size:12px;text-decoration:none;
                 font-weight:${active?600:400};
                 background:${active?'#4f8cff':'#20242b'};
                 color:${active?'#fff':'#a7adbb'}">
          ${label} <span style="font-size:10px;opacity:.7">${count}</span>
        </a>`;
      }).join('');

      const html = `
        <div class="card">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
            <h1>Fichas ATB</h1>
            <a href="/atb/admin">← Dashboard</a>
          </div>

          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px">${statusTabs}</div>

          <form method="GET" action="/atb/admin/fichas"
                style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px;align-items:flex-end">
            <input type="hidden" name="status" value="${safe(status)}"/>
            <div>
              <label style="display:block;font-size:10px;text-transform:uppercase;
                            letter-spacing:.06em;color:#a7adbb;margin-bottom:4px">Buscar</label>
              <input name="q" value="${safe(q)}" placeholder="Paciente, prontuário, prescritor..."
                style="padding:9px 12px;border-radius:8px;border:1px solid #2a2f39;
                       background:#0f1116;color:#e7e9ee;font-size:13px;width:260px"/>
            </div>
            <div>
              <label style="display:block;font-size:10px;text-transform:uppercase;
                            letter-spacing:.06em;color:#a7adbb;margin-bottom:4px">Hospital</label>
              <select name="inst"
                style="padding:9px 12px;border-radius:8px;border:1px solid #2a2f39;
                       background:#0f1116;color:#e7e9ee;font-size:13px">
                <option value="">Todos</option>
                <option value="HUSF" ${inst==='HUSF'?'selected':''}>HUSF</option>
                <option value="H2"   ${inst==='H2'  ?'selected':''}>H2</option>
              </select>
            </div>
            <button style="padding:9px 18px;background:#4f8cff;color:#fff;border:0;
                           border-radius:8px;font-size:13px;cursor:pointer;font-weight:600">
              Filtrar
            </button>
            ${(q||inst)?`<a href="/atb/admin/fichas?status=${safe(status)}" style="padding:9px;color:#a7adbb;font-size:12px">Limpar</a>`:''}
          </form>

          <table style="width:100%;border-collapse:collapse">
            <thead>
              <tr style="border-bottom:1px solid #20242b">
                ${['Data / Local','Paciente','ATB','SOFA','Risco IA','Parecer','Status',''].map(h=>
                  `<th style="padding:8px 6px;text-align:left;font-size:10px;text-transform:uppercase;
                              letter-spacing:.06em;color:#a7adbb;font-weight:600">${h}</th>`
                ).join('')}
              </tr>
            </thead>
            <tbody style="font-size:13px">
              ${tableRows||'<tr><td colspan="8" class="mut" style="padding:24px;text-align:center">Nenhuma ficha encontrada.</td></tr>'}
            </tbody>
          </table>
          ${pager}
        </div>
        <style>
          tbody tr:hover { background:#1a1e25; }
          tbody tr td { padding:10px 6px;border-bottom:1px solid #1a1e25;vertical-align:middle; }
          tbody tr:last-child td { border-bottom:none; }
        </style>`;
      res.send(renderShell('ATB · Fichas', html));
    } catch (e) {
      console.error('[atb] fichas list error:', e);
      res.status(500).send(renderShell('Erro', `<div class="card"><p class="mut">${safe(e.message)}</p></div>`));
    }
  });

  // ── Detalhe de ficha ──────────────────────────────────────────────────
  app.get('/atb/admin/fichas/:id', adminRequired, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const { rows: [f] } = await pool.query(`
        SELECT f.*, i.sigla AS instituicao, i.nome AS instituicao_nome,
               a.iras, a.etiol_iras, a.micro, a.desfecho_iras, a.desfecho_data,
               a.saps3, a.tempo_saps, a.triagem_ia
        FROM atb_fichas f
        LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
        LEFT JOIN atb_avaliacoes   a ON a.ficha_id = f.id
        WHERE f.id = $1
      `, [id]);
      if (!f) return res.status(404).send(renderShell('Erro','<div class="card"><h1>Ficha não encontrada</h1></div>'));

      const triagem = f.triagem_ia;
      const triagemHtml = triagem ? `
        <div style="background:#181c22;border:1px solid #2a2f39;border-radius:8px;padding:14px;margin-top:12px">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#a7adbb;margin-bottom:8px">Triagem IA (Claude)</div>
          <div>Risco IrAS: <strong style="color:${triagem.risco_iras==='alto'?'#e06c6c':triagem.risco_iras==='medio'?'#e0b86c':'#6ce0a0'}">${triagem.risco_iras}</strong></div>
          ${triagem.potenciais_iras?.length?`<div>Potenciais: ${triagem.potenciais_iras.map(s=>`<code style="font-size:11px;background:#20242b;padding:1px 6px;border-radius:4px">${safe(s)}</code>`).join(' ')}</div>`:''}
          <div style="margin-top:6px;color:#a7adbb;font-size:13px">${safe(triagem.justificativa_iras||'')}</div>
          ${triagem.alertas?.length?`<div style="margin-top:8px;color:#e0b86c;font-size:12px">⚠ ${triagem.alertas.join(' · ')}</div>`:''}
          <div style="margin-top:8px">Adequação ATB: <strong>${safe(triagem.adequacao_atb||'')}</strong></div>
          ${triagem.sugestao_de_escalacao?`<div style="color:#a7adbb;font-size:12px;margin-top:4px">${safe(triagem.sugestao_de_escalacao)}</div>`:''}
        </div>` : '<p class="mut">Triagem IA não disponível.</p>';

      const atbs = Array.isArray(f.atb_solicitado) ? f.atb_solicitado.join(', ') : '—';
      const disp = Array.isArray(f.dispositivos_invasivos) ? f.dispositivos_invasivos.join(', ') : '—';

      const html = `
        <div class="card" style="margin-bottom:12px">
          <div style="display:flex;justify-content:space-between;align-items:flex-start">
            <div>
              <h1>${safe(f.paciente_nome||f.paciente_nome_raw||'—')}</h1>
              <p class="mut">
                ${safe(f.instituicao||'')} · ${safe(f.setor||'')}
                ${f.leito?`· Leito ${safe(f.leito)}`:''}
                · Prontuário ${safe(f.prontuario||'—')}
                · Atend. ${safe(f.atendimento||'—')}
              </p>
              ${f.link_exames?`<a href="${f.link_exames}" target="_blank" style="font-size:12px">🔗 Exames</a>`:''}
              ${f.link_labs?` · <a href="${f.link_labs}" target="_blank" style="font-size:12px">🔬 LIS</a>`:''}
            </div>
            <a href="/atb/admin/fichas">← Fichas</a>
          </div>
        </div>

        <div style="display:grid;grid-template-columns:1fr 360px;gap:14px">
          <div>
            <div class="card" style="margin-bottom:12px">
              <h2>Clínica</h2>
              <table>
                <tr><td class="mut">Tipo terapia</td><td>${safe(f.tipo_terapia||'—')}</td></tr>
                <tr><td class="mut">Foco</td><td>${safe(f.foco_infeccao||'—')}</td></tr>
                <tr><td class="mut">Sepse</td><td>${f.sepse===true?'Sim':f.sepse===false?'Não':'—'}</td></tr>
                <tr><td class="mut">ATB solicitado</td><td>${safe(atbs)}</td></tr>
                <tr><td class="mut">Tempo previsto</td><td>${f.tempo_previsto!=null?f.tempo_previsto+' dias':'—'}</td></tr>
                <tr><td class="mut">SOFA</td><td>${f.sofa!=null?f.sofa:'—'}</td></tr>
                <tr><td class="mut">Dispositivos</td><td>${safe(disp)}</td></tr>
              </table>
              <div style="margin-top:12px">
                <div class="mut" style="font-size:11px;margin-bottom:4px">História clínica</div>
                <div style="font-size:13px;white-space:pre-wrap;color:#c8ccd4">${safe(f.historia_clinica||'—')}</div>
              </div>
            </div>

            <div class="card">
              <h2>Avaliação SCIH</h2>
              <form method="POST" action="/atb/admin/fichas/${id}/avaliar" class="mt2">
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
                  <div>
                    <label>IrAS</label>
                    <select name="iras" style="width:100%;padding:10px;border-radius:8px;border:1px solid #2a2f39;background:#0f1116;color:#e7e9ee">
                      <option value="">—</option>
                      ${['Sim','Não','Suspeita'].map(v=>`<option ${f.iras===v?'selected':''}>${v}</option>`).join('')}
                    </select>
                  </div>
                  <div>
                    <label>Etiologia IrAS</label>
                    <input name="etiol_iras" value="${safe(f.etiol_iras||'')}">
                  </div>
                  <div>
                    <label>Microrganismo</label>
                    <input name="micro" value="${safe(f.micro||'')}">
                  </div>
                  <div>
                    <label>Desfecho IrAS</label>
                    <input name="desfecho_iras" value="${safe(f.desfecho_iras||'')}">
                  </div>
                  <div>
                    <label>Data desfecho</label>
                    <input name="desfecho_data" type="date" value="${f.desfecho_data?String(f.desfecho_data).slice(0,10):''}">
                  </div>
                  <div>
                    <label>SAPS3</label>
                    <input name="saps3" type="number" value="${f.saps3!=null?f.saps3:''}">
                  </div>
                </div>
                <div style="display:flex;gap:10px;margin-top:14px">
                  <select name="status" style="padding:10px;border-radius:8px;border:1px solid #2a2f39;background:#0f1116;color:#e7e9ee">
                    ${['pendente','em_avaliacao','avaliado','arquivado'].map(s=>`<option ${f.status===s?'selected':''}>${s}</option>`).join('')}
                  </select>
                  <button style="flex:1;padding:10px;background:#4f8cff;color:#fff;border:0;border-radius:8px;font-weight:600;cursor:pointer">Salvar avaliação</button>
                </div>
              </form>
            </div>
          </div>

          <div>
            <div class="card" style="margin-bottom:12px">
              <h2>Triagem IA</h2>
              ${triagemHtml}
              <form method="POST" action="/atb/admin/fichas/${id}/retriagem" style="margin-top:10px">
                <button style="width:100%;padding:8px;background:#20242b;color:#a7adbb;border:0;border-radius:8px;font-size:12px;cursor:pointer">
                  Rodar triagem novamente
                </button>
              </form>
            </div>

            <div class="card">
              <h2>Prescritor & Recomendação</h2>
              <p style="font-size:13px">${safe(f.prescritor_nome||'—')} <span class="mut">CRM ${safe(f.crm||'—')}</span></p>
              ${Array.isArray(f.recomendacao_scih)&&f.recomendacao_scih.length
                ?`<div style="margin-top:8px">${f.recomendacao_scih.map(r=>`<span style="display:inline-block;font-size:11px;margin:2px;padding:2px 8px;border-radius:8px;background:#20242b;color:#a7adbb">${safe(r)}</span>`).join('')}</div>`:''}
              ${f.recomendacoes_especificacao?`<p style="font-size:12px;color:#a7adbb;margin-top:6px">${safe(f.recomendacoes_especificacao)}</p>`:''}
            </div>
          </div>
        </div>`;
      res.send(renderShell(`ATB · ${f.paciente_nome||'Ficha'}`, html));
    } catch (e) {
      console.error('[atb] ficha detail error:', e);
      res.status(500).send(renderShell('Erro',`<div class="card"><p class="mut">${safe(e.message)}</p></div>`));
    }
  });

  // ── Salva avaliação ───────────────────────────────────────────────────
  app.post('/atb/admin/fichas/:id/avaliar', adminRequired, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const { iras, etiol_iras, micro, desfecho_iras, desfecho_data, saps3, status } = req.body||{};
    try {
      await pool.query(`
        INSERT INTO atb_avaliacoes
          (ficha_id,iras,etiol_iras,micro,desfecho_iras,desfecho_data,saps3,avaliado_por,updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())
        ON CONFLICT (ficha_id) DO UPDATE SET
          iras=$2,etiol_iras=$3,micro=$4,desfecho_iras=$5,
          desfecho_data=$6,saps3=$7,avaliado_por=$8,updated_at=now()
      `, [id,iras||null,etiol_iras||null,micro||null,desfecho_iras||null,
          desfecho_data||null,saps3||null,req.user?.id]);
      await pool.query('UPDATE atb_fichas SET status=$1,updated_at=now() WHERE id=$2',
        [status||'pendente',id]);
      res.redirect(`/atb/admin/fichas/${id}`);
    } catch (e) {
      console.error('[atb] avaliar error:', e);
      res.status(500).send('Falha ao salvar avaliação');
    }
  });

  // ── Re-rodar triagem ──────────────────────────────────────────────────
  app.post('/atb/admin/fichas/:id/retriagem', adminRequired, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    try {
      const { rows: [f] } = await pool.query('SELECT * FROM atb_fichas WHERE id=$1',[id]);
      if (f) {
        const triagem = await rodarTriagemIA(f);
        if (triagem) {
          await pool.query(`
            INSERT INTO atb_avaliacoes (ficha_id,triagem_ia,triagem_ia_at)
            VALUES ($1,$2,now())
            ON CONFLICT (ficha_id) DO UPDATE SET triagem_ia=$2,triagem_ia_at=now()
          `,[id,JSON.stringify(triagem)]);
        }
      }
      res.redirect(`/atb/admin/fichas/${id}`);
    } catch (e) {
      console.error('[atb] retriagem error:', e);
      res.redirect(`/atb/admin/fichas/${id}`);
    }
  });

  // ── Configuração ──────────────────────────────────────────────────────
  app.get('/atb/admin/config', adminRequired, async (req, res) => {
    const { rows: insts } = await pool.query('SELECT * FROM atb_instituicoes ORDER BY id');
    const rows = insts.map(i => `
      <tr>
        <td>${safe(i.nome)}</td>
        <td><code>${safe(i.sigla)}</code></td>
        <td>
          <form method="POST" action="/atb/admin/config/${i.id}"
                style="display:flex;gap:8px;align-items:center">
            <input name="jotform_form_id" value="${safe(i.jotform_form_id||'')}"
              placeholder="ex.: 242856789"
              style="width:160px;padding:8px;border-radius:6px;border:1px solid #2a2f39;background:#0f1116;color:#e7e9ee">
            <button style="padding:8px 14px;background:#4f8cff;color:#fff;border:0;border-radius:6px;cursor:pointer">Salvar</button>
          </form>
        </td>
      </tr>`).join('');

    const webhookUrl = `${req.protocol}://${req.get('host')}/atb/webhook`;
    const html = `
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
          <h1>Configuração ATB</h1>
          <a href="/atb/admin">← Dashboard</a>
        </div>
        <h2>Webhook JotForm</h2>
        <p class="mut">Configure este URL em cada formulário JotForm:</p>
        <code style="display:block;background:#0f1116;padding:12px;border-radius:8px;margin:8px 0;font-size:13px">${webhookUrl}</code>
        <p class="mut" style="font-size:12px">
          JotForm → Settings → Integrations → WebHooks → Add WebHook → cole o URL acima.
        </p>
        <h2 class="mt2">Form IDs por instituição</h2>
        <table>
          <thead><tr><th>Hospital</th><th>Sigla</th><th>JotForm Form ID</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
        <h2 class="mt2">Variáveis de ambiente (Render)</h2>
        <table>
          <tr><td><code>JOTFORM_API_KEY</code></td><td class="mut">Sua API key do JotForm</td></tr>
          <tr><td><code>ANTHROPIC_API_KEY</code></td><td class="mut">Já existe no infectoaulas ✓</td></tr>
        </table>
      </div>`;
    res.send(renderShell('ATB · Configuração', html));
  });

  app.post('/atb/admin/config/:id', adminRequired, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const { jotform_form_id } = req.body||{};
    await pool.query('UPDATE atb_instituicoes SET jotform_form_id=$1 WHERE id=$2',
      [jotform_form_id?.trim()||null, id]);
    res.redirect('/atb/admin/config');
  });

}
