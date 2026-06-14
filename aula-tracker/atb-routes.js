// atb-routes.js

import { handleWebhook, iniciarPolling, rodarTriagemIA } from './atb-sync.js';
import { parseFormPayload } from './atb-parser.js';
import { fetchR2Stream, fetchR2ImageAsDataURI } from './lab-storage.js';
import { ensureFormSchemaTable, getFormSchema, saveFormSchema } from './atb-form-schema.js';
import { carregarPrescritores, validarFormatoCRM, buscarCRM, statusCache } from './atb-prescritores.js';
import { registerParecerApiRoutes } from './atb-parecer-routes.js';
import { ensureComplementoSchema, registerComplementoRoutes } from './atb-complemento-routes.js';
import { ensureParecerSchema, registerParecerEditRoutes, renderParecerCell, parecerGridAssets } from './atb-parecer-edit-routes.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { registerFichaCardRoutes, fichaCardAssets } from './atb-ficha-card-routes.js';
import { registerFichaViewRoutes } from './atb-ficha-view-routes.js';
import { ensureAnexosSchema, registerAnexosRoutes } from './atb-anexos-routes.js';

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

  // ── Schema do formulário: cria tabela + semeia HUSF/H2 no boot ─────────
  ensureFormSchemaTable(pool).catch(e => console.error('[atb] falha ao preparar schema:', e.message));

  // ── Prescritores: carrega o CSV vivo no boot (cache em memória, recarrega a cada 15min) ──
  carregarPrescritores().catch(e => console.error('[atb] falha ao carregar prescritores:', e.message));

  // ── Complementação: cria a coluna de rastreabilidade no boot ──────────
  ensureParecerSchema(pool).catch(e => console.error('[atb] falha ao preparar parecer:', e.message));
  ensureComplementoSchema(pool).catch(e => console.error('[atb] falha ao preparar complemento:', e.message));
  ensureAnexosSchema(pool).catch(e => console.error('[atb] falha ao preparar anexos:', e.message));
  
  registerParecerEditRoutes(app, pool, adminRequired);
  // ── Rotas de parecer (alimentam o Apps Script) + complementação ───────
  registerParecerApiRoutes(app, pool);
  registerComplementoRoutes(app, pool, adminRequired);
  registerFichaCardRoutes(app, pool, adminRequired);
  registerFichaViewRoutes(app, pool, adminRequired);
  registerAnexosRoutes(app, pool, adminRequired);

  // Logo institucional (data URI) lido uma vez do disco
  let ATB_LOGO = '';
  try { ATB_LOGO = fs.readFileSync(path.join(__dirname, 'atb-logo.b64'), 'utf8').trim(); }
  catch (e) { console.warn('[atb] logo não encontrado:', e.message); }

  // ── Formulário do prescritor (público, motor schema-driven) ────────────
  app.get('/atb/form', (req, res) => {
    const inst = (req.query.inst || 'HUSF').replace(/[^A-Za-z0-9_]/g, '');
    let html = fs.readFileSync(path.join(__dirname, 'atb-form.html'), 'utf8');
    // injeta instituição + logo antes do bootstrap do motor
    const inject = `<script>window.ATB_INSTITUICAO=${JSON.stringify(inst)};window.ATB_LOGO=${JSON.stringify(ATB_LOGO)};</script>`;
    html = html.replace(
      `<script>window.ATB_INSTITUICAO = window.ATB_INSTITUICAO || 'HUSF';</script>`,
      inject
    );
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  });

  // ── Serve o motor de renderização (JS) ─────────────────────────────────
  app.get('/atb/form-engine.js', (req, res) => {
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    res.sendFile(path.join(__dirname, 'atb-form-engine.js'));
  });

  // ── API: definição do formulário (público — o motor consome) ───────────
  app.get('/atb/api/form-schema', async (req, res) => {
    const inst = (req.query.inst || 'HUSF').replace(/[^A-Za-z0-9_]/g, '');
    try {
      const def = await getFormSchema(pool, inst);
      if (!def) return res.status(404).json({ erro: 'schema não encontrado' });
      res.json(def);
    } catch (e) {
      res.status(500).json({ erro: e.message });
    }
  });

  // ── API: valida CRM (CSV vivo + salvaguardas anti-fraude) ──────────────
  app.get('/atb/api/validar-crm', async (req, res) => {
    const { crm } = req.query;
    if (!crm) return res.status(400).json({ erro: 'CRM obrigatório' });
    try {
      // Salvaguarda 1: formato (4-7 dígitos, sem zeros/letras — derivado dos dados reais)
      const fmt = validarFormatoCRM(crm);
      if (!fmt.ok) {
        return res.json({ valido: false, cadastrado: false, nome: null, motivo: fmt.motivo });
      }
      // Lookup no cache do CSV (8.345 prescritores; CRM+UF único, 1º match)
      const hit = buscarCRM(crm);
      if (hit.cadastrado) {
        return res.json({ valido: true, cadastrado: true, nome: hit.nome, uf: hit.uf });
      }
      // Salvaguarda 2: formato ok mas fora do cadastro → permite com declaração (no front)
      return res.json({ valido: true, cadastrado: false, nome: null });
    } catch (e) {
      res.status(500).json({ erro: e.message });
    }
  });

  // ── Admin: status + recarga manual do cache de prescritores ────────────
  app.get('/atb/admin/api/prescritores-status', adminRequired, (req, res) => {
    res.json(statusCache());
  });
  app.post('/atb/admin/api/recarregar-prescritores', adminRequired, async (req, res) => {
    try {
      const r = await carregarPrescritores(true);
      res.json({ ok: true, ...statusCache(), recarregados: r });
    } catch (e) {
      res.status(500).json({ ok: false, erro: e.message });
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
              <a href="/atb/admin/grid" style="margin-right:12px">Grade de fichas</a>
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

      // anexos da ficha
      const { rows: anexos } = await pool.query(
        `SELECT id, tipo, nome_original FROM atb_ficha_imagens WHERE ficha_id=$1 ORDER BY tipo, id`, [id]
      );
      const pdfs = anexos.filter(a => a.tipo === 'pdf');
      const imgs = anexos.filter(a => a.tipo !== 'pdf');
      const anexosHtml = (pdfs.length || imgs.length) ? `
        <div class="card" style="margin-bottom:12px">
          <h2>Anexos</h2>
          ${pdfs.length ? `<div style="margin-top:8px">
            ${pdfs.map(a=>`<a href="/atb/admin/ficha/${id}/anexo/${a.id}" target="_blank"
              style="display:inline-flex;align-items:center;gap:6px;padding:6px 12px;margin:3px;border-radius:8px;background:#20242b;color:#8fb6ff;text-decoration:none;font-size:13px">
              📄 ${safe(a.nome_original||('PDF '+a.id))}</a>`).join('')}
          </div>` : ''}
          ${imgs.length ? `<div style="margin-top:10px;display:flex;flex-wrap:wrap;gap:8px">
            ${imgs.map(a=>`<a href="/atb/admin/ficha/${id}/anexo/${a.id}" target="_blank" title="${safe(a.nome_original||'')}"
              style="display:block">
              <img src="/atb/admin/ficha/${id}/anexo/${a.id}" loading="lazy"
                style="width:90px;height:90px;object-fit:cover;border-radius:6px;border:1px solid #2a2f39"></a>`).join('')}
          </div>` : ''}
        </div>` : '';

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
      const IRAS_OPC = ['','PAV','PAV/EVA','IPCSLab','IPCSClin','ITU','ISC','(HD)ILAV','(HD)ICS','(HD)Bact','HD_Bact_FAV','HD_Bact_CDL','HD_Bact_PC','HD_ILAV_FAV','HD_ILAV_CDL','HD_ILAV_PC','CDI','Onco_Bact','Sem dados','Descartado','Repetida'];
      const DESF_OPC = ['','Sobrev_int','Sobrev_alta','Obito_R','Obito_NR','Alta'];

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
              ${f.link_exames?`<a href="${safe(f.link_exames)}" target="_blank" style="font-size:12px">🔗 Exames</a>`:''}
              ${f.link_labs?` · <a href="${safe(f.link_labs)}" target="_blank" style="font-size:12px">🔬 LIS</a>`:''}
            </div>
            <a href="/atb/admin/complementar/${id}" style="background:#00469e;color:#fff;padding:6px 14px;border-radius:8px;text-decoration:none;font-size:13px;font-weight:600;margin-right:12px">+ Complementar dados</a>
            <a href="/atb/admin/grid">← Grade</a>
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
                      ${IRAS_OPC.map(v=>`<option value="${v}" ${(f.iras||'')===v?'selected':''}>${v||'—'}</option>`).join('')}
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
                    <select name="desfecho_iras" style="width:100%;padding:10px;border-radius:8px;border:1px solid #2a2f39;background:#0f1116;color:#e7e9ee">
                      ${DESF_OPC.map(v=>`<option value="${v}" ${(f.desfecho_iras||'')===v?'selected':''}>${v||'—'}</option>`).join('')}
                    </select>
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
            ${anexosHtml}
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
              <a href="/atb/admin/parecer/${id}" style="display:inline-block;margin-top:10px;padding:8px 14px;background:#00469e;color:#fff;border-radius:8px;text-decoration:none;font-size:13px">✎ Emitir / editar parecer</a>
            </div>
          </div>
        </div>`;
      res.send(renderShell(`ATB · ${f.paciente_nome||'Ficha'}`, html));
    } catch (e) {
      console.error('[atb] ficha detail error:', e);
      res.status(500).send(renderShell('Erro',`<div class="card"><p class="mut">${safe(e.message)}</p></div>`));
    }
  });

  // ── Salva avaliação (form do detalhe) ──────────────────────────────────
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

  // ════════════════════════════════════════════════════════════════════════
  // GRADE DE FICHAS (estilo Tables) + anexos
  // ════════════════════════════════════════════════════════════════════════

  const _C = {
    laranjaClaro:'#fcd9b6', pessego:'#fcdcd2', rosa:'#f8d7e8', roxoClaro:'#e3d4f5',
    tealClaro:'#c3efe0', azulClaro:'#cfe9f7', azulClaro2:'#b8e0ed', verdeClaro:'#d4f0c4',
    amareloClaro:'#f0ead0', cinzaAzul:'#c5cce0', lilas:'#ecd6f7',
    verdeMedio:'#74c47d', cinzaMedio:'#a9b0c7', laranjaMedio:'#d98a3d',
    azulMedio:'#5a9bf0', vermelho:'#e85d5d', amareloMedio:'#f0b840',
  };
  const _FG = '#3a3a3a', _FGW = '#ffffff';
  const IRAS_CORES = {
    'PAV':{bg:_C.laranjaClaro,fg:_FG},'PAV/EVA':{bg:_C.azulMedio,fg:_FGW},
    'IPCSLab':{bg:_C.vermelho,fg:_FGW},'IPCSClin':{bg:_C.roxoClaro,fg:_FG},
    'ITU':{bg:_C.amareloMedio,fg:_FG},'ISC':{bg:_C.azulClaro,fg:_FG},
    '(HD)ILAV':{bg:_C.verdeClaro,fg:_FG},'(HD)ICS':{bg:_C.amareloClaro,fg:_FG},
    '(HD)Bact':{bg:_C.laranjaClaro,fg:_FG},'Sem dados':{bg:_C.laranjaClaro,fg:_FG},
    'Descartado':{bg:_C.verdeMedio,fg:_FGW},'Repetida':{bg:_C.cinzaMedio,fg:_FGW},
    'CDI':{bg:_C.laranjaMedio,fg:_FGW},'HD_Bact_FAV':{bg:_C.laranjaClaro,fg:_FG},
    'HD_Bact_CDL':{bg:_C.pessego,fg:_FG},'HD_Bact_PC':{bg:_C.rosa,fg:_FG},
    'HD_ILAV_FAV':{bg:_C.roxoClaro,fg:_FG},'HD_ILAV_CDL':{bg:_C.tealClaro,fg:_FG},
    'HD_ILAV_PC':{bg:_C.azulClaro,fg:_FG},'Onco_Bact':{bg:_C.cinzaMedio,fg:_FGW},
  };
  const SETOR_CORES = {
    'PS':{bg:_C.laranjaClaro,fg:_FG},'EPM':{bg:_C.pessego,fg:_FG},
    'Cuidados Intermediários':{bg:_C.rosa,fg:_FG},'Psiquiatria':{bg:_C.roxoClaro,fg:_FG},
    'Apartamento':{bg:_C.tealClaro,fg:_FG},'Oncologia':{bg:_C.azulClaro,fg:_FG},
    'Clínica Cirúrgica':{bg:_C.verdeClaro,fg:_FG},'Semi':{bg:_C.amareloClaro,fg:_FG},
    'Hemodiálise':{bg:_C.laranjaClaro,fg:_FG},'Pediatria':{bg:_C.cinzaAzul,fg:_FG},
    'UTI':{bg:_C.azulClaro2,fg:_FG},'UTI Neo / Infantil':{bg:_C.pessego,fg:_FG},
    'UTI C':{bg:_C.lilas,fg:_FG},'UTI Respiratória':{bg:_C.azulClaro,fg:_FG},
    'Ginecologia/Obstetrícia':{bg:_C.cinzaAzul,fg:_FG},'Clínica Médica':{bg:_C.amareloClaro,fg:_FG},
  };
  const ATB_CORES = {
    'Cefepime':{bg:_C.laranjaClaro,fg:_FG},'Ceftriaxone':{bg:_C.pessego,fg:_FG},
    'Fosfomicina':{bg:_C.rosa,fg:_FG},'Anfotericina B':{bg:_C.roxoClaro,fg:_FG},
    'Daptomicina':{bg:_C.tealClaro,fg:_FG},'Tigeciclina':{bg:_C.azulClaro,fg:_FG},
    'Micafungina':{bg:_C.verdeClaro,fg:_FG},'Meropenem':{bg:_C.amareloClaro,fg:_FG},
    'Piperacilina/Tazobactam':{bg:_C.laranjaClaro,fg:_FG},'Vancomicina':{bg:_C.cinzaAzul,fg:_FG},
    'Teicoplanina':{bg:_C.azulClaro2,fg:_FG},'Polimixina B':{bg:_C.pessego,fg:_FG},
    'Polimixina E (colestimetato)':{bg:_C.lilas,fg:_FG},'Amicacina':{bg:_C.roxoClaro,fg:_FG},
    'Gentamicina':{bg:_C.amareloClaro,fg:_FG},'LINEZOLIDA':{bg:_C.cinzaAzul,fg:_FG},
  };
  const REC_CORES = {
    'Sim':{bg:_C.laranjaClaro,fg:_FG},'Não':{bg:_C.pessego,fg:_FG},
    'Com ajustes (especificados abaixo)':{bg:_C.rosa,fg:_FG},'Ficha Repetida':{bg:_C.roxoClaro,fg:_FG},
    'ATB não controlado':{bg:_C.tealClaro,fg:_FG},'Suspenso':{bg:_C.azulClaro,fg:_FG},
    'Audit_post':{bg:_C.verdeClaro,fg:_FG},
  };
  const _pill = (mapa, val) => {
    const c = mapa[val] || { bg:'#eceff3', fg:_FG };
    return `<span style="display:inline-block;padding:3px 9px;border-radius:5px;font-size:12px;line-height:1.3;white-space:nowrap;background:${c.bg};color:${c.fg}">${safe(val)}</span>`;
  };
  const _pillsIras = (val) => !val ? '' :
    String(val).split(/\n+/).map(v => _pill(IRAS_CORES, v.trim())).join(' ');
  const _pillsMulti = (mapa, arr) => {
    const items = Array.isArray(arr) ? arr : (arr ? [arr] : []);
    return items.map(v => _pill(mapa, v)).join(' ');
  };
  const IRAS_OPCOES = ['','PAV','PAV/EVA','IPCSLab','IPCSClin','ITU','ISC','(HD)ILAV','(HD)ICS','(HD)Bact','HD_Bact_FAV','HD_Bact_CDL','HD_Bact_PC','HD_ILAV_FAV','HD_ILAV_CDL','HD_ILAV_PC','CDI','Onco_Bact','Sem dados','Descartado','Repetida'];
  const DESFECHO_OPCOES = ['','Sobrev_int','Sobrev_alta','Obito_R','Obito_NR','Alta'];

  // ── A GRADE: /atb/admin/grid ───────────────────────────────────────────
  app.get('/atb/admin/grid', adminRequired, async (req, res) => {
    try {
      const { q='', inst='', setor='', mes='', iras='', page='1' } = req.query;
      const pageNum = Math.max(1, parseInt(page,10));
      const pageSize = 80;
      const offset = (pageNum-1)*pageSize;

      const where = ['1=1'], params = [];
      if (q.trim()) {
        params.push(`%${q.toLowerCase()}%`);
        where.push(`(LOWER(f.paciente_nome) LIKE $${params.length} OR LOWER(f.paciente_nome_raw) LIKE $${params.length} OR f.prontuario LIKE $${params.length})`);
      }
      if (inst)  { params.push(inst);  where.push(`i.sigla = $${params.length}`); }
      if (setor) { params.push(setor); where.push(`f.setor = $${params.length}`); }
      if (mes)   { params.push(mes);   where.push(`EXTRACT(MONTH FROM COALESCE(f.data_referencia, f.jotform_created_at, f.created_at)) = $${params.length}`); }
      if (iras === 'pendente')        where.push(`(a.iras IS NULL OR a.iras = '')`);
      else if (iras === 'confirmada') where.push(`a.iras NOT IN ('Descartado','Repetida','Sem dados') AND a.iras IS NOT NULL AND a.iras <> ''`);
      else if (iras === 'descartado') where.push(`a.iras = 'Descartado'`);
      const whereSql = where.join(' AND ');

      const { rows:[{total}] } = await pool.query(`
        SELECT COUNT(*) AS total FROM atb_fichas f
        LEFT JOIN atb_instituicoes i ON i.id=f.instituicao_id
        LEFT JOIN atb_avaliacoes a ON a.ficha_id=f.id WHERE ${whereSql}`, params);

      const { rows:[vig] } = await pool.query(`
        SELECT
          COUNT(*) FILTER (WHERE a.iras NOT IN ('Descartado','Repetida','Sem dados') AND a.iras IS NOT NULL AND a.iras<>'') AS confirmadas,
          COUNT(*) FILTER (WHERE a.iras = 'Descartado') AS descartadas,
          COUNT(*) FILTER (WHERE a.iras IS NULL OR a.iras = '') AS pendentes,
          COUNT(*) FILTER (WHERE a.desfecho_iras IN ('Obito_R','Obito_NR')) AS obitos
        FROM atb_fichas f
        LEFT JOIN atb_instituicoes i ON i.id=f.instituicao_id
        LEFT JOIN atb_avaliacoes a ON a.ficha_id=f.id WHERE ${whereSql}`, params);

      const { rows } = await pool.query(`
        SELECT f.id, f.paciente_nome, f.paciente_nome_raw, f.prontuario, f.setor,
               f.atb_solicitado, f.recomendacao_scih, f.sofa, f.obito,
               f.link_exames, f.link_labs, f.data_referencia, f.jotform_created_at, f.created_at,
               i.sigla AS instituicao,
               a.iras, a.etiol_iras, a.micro, a.saps3, a.desfecho_iras, a.desfecho_data,
               (SELECT COUNT(*) FROM atb_ficha_imagens WHERE ficha_id=f.id AND tipo='pdf')    AS n_pdf,
               (SELECT COUNT(*) FROM atb_ficha_imagens WHERE ficha_id=f.id AND tipo='imagem') AS n_img
        FROM atb_fichas f
        LEFT JOIN atb_instituicoes i ON i.id=f.instituicao_id
        LEFT JOIN atb_avaliacoes a ON a.ficha_id=f.id
        WHERE ${whereSql}
        ORDER BY COALESCE(f.data_referencia, f.jotform_created_at, f.created_at) DESC
        LIMIT $${params.length+1} OFFSET $${params.length+2}`, [...params, pageSize, offset]);

      const totalPages = Math.max(1, Math.ceil(parseInt(total,10)/pageSize));
      const dtFmt = d => d ? new Date(d).toLocaleDateString('pt-BR',{day:'2-digit',month:'2-digit',year:'2-digit'}) : '—';

      const linhas = rows.map((f,i) => {
        const nome = f.paciente_nome || f.paciente_nome_raw || '—';
        const dd = f.desfecho_data ? String(f.desfecho_data).slice(0,10) : '';
        const irasVal = (f.iras||'').split(/\n+/)[0];
        const anexos = (f.n_pdf>0?`<a href="/atb/admin/fichas/${f.id}" title="${f.n_pdf} PDF" style="text-decoration:none">📄${f.n_pdf}</a>`:'') +
                       (f.n_img>0?` <span title="${f.n_img} imagem" style="color:#9aa0a6">📷${f.n_img}</span>`:'');
        return `<tr data-ficha="${f.id}">
          <td class="rownum">${offset+i+1}</td>
          <td class="sticky-col" title="${safe(nome)}">
            <a href="/atb/admin/fichas/${f.id}" class="pac-link">${safe(nome)}</a>
            <div class="sub">${dtFmt(f.data_referencia||f.jotform_created_at)} · ${safe(f.instituicao||'')}${f.obito?' · <span style="color:#c0392b">✝</span>':''} ${anexos}</div>
          </td>
          <td class="sub">${safe(f.prontuario||'—')}</td>
          <td>${f.setor?_pill(SETOR_CORES,f.setor):'—'}</td>
          <td>${_pillsMulti(ATB_CORES, f.atb_solicitado)||'—'}</td>
          <td style="text-align:center;font-family:monospace">${f.sofa!=null?f.sofa:'—'}</td>
          ${renderParecerCell(f, safe)}
          <td class="iras-cell">${_pillsIras(f.iras)}
            <select data-field="iras" class="iras-select">
              ${IRAS_OPCOES.map(o=>`<option value="${o}" ${irasVal===o?'selected':''}>${o||'— classificar —'}</option>`).join('')}
            </select></td>
          <td class="edit"><input data-field="etiol_iras" value="${safe(f.etiol_iras||'')}" placeholder="—" style="width:90px"></td>
          <td class="edit"><input data-field="micro" value="${safe(f.micro||'')}" placeholder="—" style="width:150px"></td>
          <td class="edit"><input data-field="saps3" type="number" value="${f.saps3!=null?f.saps3:''}" placeholder="—" style="width:52px;text-align:center"></td>
          <td class="edit"><select data-field="desfecho_iras" style="width:108px">
              ${DESFECHO_OPCOES.map(o=>`<option value="${o}" ${f.desfecho_iras===o?'selected':''}>${o||'—'}</option>`).join('')}
            </select></td>
          <td class="edit"><input data-field="desfecho_data" type="date" value="${dd}" style="width:120px"></td>
          <td style="text-align:center;white-space:nowrap">
            ${f.link_exames?`<a href="${safe(f.link_exames)}" target="_blank" title="Exames">🔗</a>`:''}
            ${f.link_labs?`<a href="${safe(f.link_labs)}" target="_blank" title="LIS" style="margin-left:3px">🔬</a>`:''}
          </td>
          <td><span class="saved">✓</span></td>
        </tr>`;
      }).join('');

      const vigTabs = [
        ['','Todas',total],['pendente','A classificar',vig.pendentes],
        ['confirmada','IrAS confirmadas',vig.confirmadas],['descartado','Descartadas',vig.descartadas],
      ].map(([val,label,count])=>{
        const active = iras===val;
        const u = new URLSearchParams({...req.query,iras:val,page:'1'});
        const cor = val==='confirmada'?'#e85d5d':val==='pendente'?'#5a9bf0':val==='descartado'?'#74c47d':'#888';
        return `<a href="/atb/admin/grid?${u}" style="display:inline-flex;align-items:center;gap:6px;padding:6px 14px;border-radius:18px;font-size:13px;text-decoration:none;font-weight:${active?600:400};background:${active?cor:'#eef0f2'};color:${active?'#fff':'#5f6368'}">${label} <span style="font-size:11px;opacity:.85">${count}</span></a>`;
      }).join('');

      const meses=['','Jan','Fev','Mar','Abr','Mai','Jun','Jul','Ago','Set','Out','Nov','Dez'];
      const mesOpts = meses.map((m,idx)=> idx===0?`<option value="">Todos os meses</option>`:`<option value="${idx}" ${String(idx)===mes?'selected':''}>${m}</option>`).join('');
      const mkUrl = p => `/atb/admin/grid?${new URLSearchParams({...req.query,page:p})}`;
      const pager = totalPages>1?`<div style="display:flex;align-items:center;gap:10px;font-size:13px">
          ${pageNum>1?`<a href="${mkUrl(pageNum-1)}">←</a>`:'<span style="color:#ccc">←</span>'}
          <span style="color:#80868b">Pág. ${pageNum}/${totalPages} · ${total} fichas</span>
          ${pageNum<totalPages?`<a href="${mkUrl(pageNum+1)}">→</a>`:'<span style="color:#ccc">→</span>'}
        </div>`:`<span style="color:#80868b;font-size:13px">${total} fichas</span>`;

      const html = `
        <div class="atb-light">
        <div style="display:flex;justify-content:space-between;align-items:baseline;flex-wrap:wrap;gap:10px;margin-bottom:14px">
          <div style="display:flex;align-items:baseline;gap:14px">
            <h1 style="margin:0;color:#202124">Controle ATB</h1>
            <span style="color:#80868b;font-size:13px">Vigilância · avaliação · stewardship</span>
          </div>
          <div style="display:flex;gap:14px"><a href="/atb/admin">Resumo</a><a href="/atb/admin/config">Configurar</a></div>
        </div>
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px">
          <div class="metric" style="border-left-color:#e85d5d"><div class="mv" style="color:#c0392b">${vig.confirmadas}</div><div class="ml">IrAS confirmadas</div></div>
          <div class="metric" style="border-left-color:#5a9bf0"><div class="mv" style="color:#2c6fb5">${vig.pendentes}</div><div class="ml">A classificar</div></div>
          <div class="metric" style="border-left-color:#74c47d"><div class="mv" style="color:#3a8a4a">${vig.descartadas}</div><div class="ml">Descartadas</div></div>
          <div class="metric" style="border-left-color:#a9b0c7"><div class="mv" style="color:#5f6368">${vig.obitos}</div><div class="ml">Óbitos no recorte</div></div>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">${vigTabs}</div>
        <form method="GET" action="/atb/admin/grid" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center">
          <input type="hidden" name="iras" value="${safe(iras)}">
          <input name="q" value="${safe(q)}" placeholder="Paciente, prontuário..." class="fil" style="width:210px">
          <select name="inst" class="fil"><option value="">Todos hospitais</option><option value="HUSF" ${inst==='HUSF'?'selected':''}>HUSF</option><option value="H2" ${inst==='H2'?'selected':''}>H2</option></select>
          <select name="mes" class="fil">${mesOpts}</select>
          <input name="setor" value="${safe(setor)}" placeholder="Setor" class="fil" style="width:120px">
          <button class="btn-fil">Filtrar</button>
          ${(q||inst||mes||setor)?`<a href="/atb/admin/grid?iras=${safe(iras)}" style="color:#80868b;font-size:13px">Limpar</a>`:''}
          <div style="margin-left:auto">${pager}</div>
        </form>
        <div class="grid-wrap">
          <table class="atb-grid">
            <thead><tr>
              <th class="rownum">#</th><th class="sticky-col">Paciente</th>
              <th>Pront.</th><th>Setor</th><th>ATB</th>
              <th style="text-align:center">SOFA</th><th>Parecer</th>
              <th class="grp">IrAS</th><th class="grp">Etiol</th><th class="grp">Microrganismo</th>
              <th class="grp">SAPS3</th><th class="grp">Desfecho</th><th class="grp">Dt. desf.</th>
              <th style="text-align:center">Links</th><th></th>
            </tr></thead>
            <tbody>${linhas || '<tr><td colspan="15" style="padding:30px;text-align:center;color:#80868b">Nenhuma ficha no recorte.</td></tr>'}</tbody>
          </table>
        </div>
        </div>
        <style>
          /* escapa do .wrap (max-width:1100px) do renderShell: estica para quase toda a largura e pinta fundo claro */
          .atb-light{position:relative;left:50%;right:50%;margin-left:-49vw;margin-right:-49vw;width:98vw;background:#f5f6f8;min-height:100vh;margin-top:-40px;padding:28px 24px 60px;border-radius:0}
          .atb-light h1{font-weight:600}
          .atb-light a{color:#3b6fd4;text-decoration:none}
          .atb-light .metric{background:#fff;border:1px solid #e8eaed;border-left:3px solid;border-radius:8px;padding:10px 14px}
          .atb-light .metric .mv{font-size:20px;font-weight:600}
          .atb-light .metric .ml{font-size:10px;color:#80868b;text-transform:uppercase;letter-spacing:.05em;margin-top:1px}
          .atb-light .fil{padding:7px 11px;border-radius:7px;border:1px solid #dadce0;background:#fff;color:#202124;font-size:13px}
          .atb-light .btn-fil{padding:7px 16px;background:#2bb673;color:#fff;border:0;border-radius:7px;font-size:13px;cursor:pointer;font-weight:600}
          .atb-light .grid-wrap{overflow-x:auto;border:1px solid #e8eaed;border-radius:10px;background:#fff}
          table.atb-grid{border-collapse:separate;border-spacing:0;width:max-content;min-width:100%;font-size:13px}
          table.atb-grid th{position:sticky;top:0;z-index:5;background:#fff;color:#5f6368;text-align:left;font-size:11px;font-weight:600;padding:11px 12px;border-bottom:1px solid #e0e2e6;border-right:1px solid #f0f1f3;white-space:nowrap}
          table.atb-grid th.grp{background:#f3faf6;color:#1a8a5a}
          table.atb-grid td{padding:8px 12px;border-bottom:1px solid #f0f1f3;border-right:1px solid #f6f7f8;white-space:nowrap;vertical-align:middle;color:#202124}
          table.atb-grid tbody tr:hover td{background:#fafbfc}
          table.atb-grid tbody tr:hover td.sticky-col{background:#f5f7f9}
          .atb-light .rownum{color:#bdc1c6;font-size:12px;text-align:center;width:34px}
          .atb-light .sticky-col{position:sticky;left:0;z-index:4;background:#fff;box-shadow:1px 0 0 #e8eaed;min-width:175px;max-width:175px}
          table.atb-grid th.sticky-col{z-index:6}
          .atb-light .pac-link{font-weight:600;font-size:13px;color:#202124!important;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
          .atb-light .sub{font-size:11px;color:#9aa0a6}
          .atb-light .edit input,.atb-light .edit select,.atb-light .iras-select{border:1px solid #dadce0;border-radius:5px;color:#202124;font-size:12px;padding:4px 7px;font-family:inherit;background:#fff}
          .atb-light .edit input:focus,.atb-light .edit select:focus,.atb-light .iras-select:focus{outline:none;border-color:#2bb673;box-shadow:0 0 0 2px rgba(43,182,115,.2)}
          .atb-light .edit input::placeholder{color:#bdc1c6}
          .atb-light .iras-cell .iras-select{margin-top:3px;width:140px;display:block}
          .atb-light .saved{opacity:0;color:#2bb673;font-size:13px;transition:opacity .3s}
        </style>
        <script>
        (function(){
          var timers={};
          function salvar(id,field,value,row){
            fetch('/atb/admin/api/avaliacao/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({field:field,value:value})})
            .then(function(r){return r.json()}).then(function(j){
              if(j.ok){var s=row.querySelector('.saved');if(s){s.style.opacity='1';setTimeout(function(){s.style.opacity='0'},1100);}}
            }).catch(function(){});
          }
          document.querySelectorAll('tr[data-ficha]').forEach(function(row){
            var id=row.getAttribute('data-ficha');
            row.querySelectorAll('[data-field]').forEach(function(el){
              var ev=(el.tagName==='SELECT'||el.type==='date')?'change':'input';
              el.addEventListener(ev,function(){
                var field=el.getAttribute('data-field');
                clearTimeout(timers[id+field]);
                timers[id+field]=setTimeout(function(){salvar(id,field,el.value,row)},ev==='input'?700:0);
              });
            });
          });
        })();
       </script>
        ${parecerGridAssets()}
        ${fichaCardAssets()}`;
      res.send(renderShell('ATB · Controle', html));
    } catch (e) {
      console.error('[atb] grid error:', e);
      res.status(500).send(renderShell('Erro', `<div class="card"><p class="mut">${safe(e.message)}</p></div>`));
    }
  });

  // ── Endpoint: grava célula de avaliação inline ─────────────────────────
  app.post('/atb/admin/api/avaliacao/:id', adminRequired, async (req, res) => {
    const id = parseInt(req.params.id,10);
    const { field, value } = req.body || {};
    const OK = ['iras','etiol_iras','micro','saps3','tempo_saps','desfecho_iras','desfecho_data'];
    if (!OK.includes(field)) return res.status(400).json({ ok:false, error:'campo inválido' });
    try {
      let v = value === '' ? null : value;
      if ((field==='saps3'||field==='tempo_saps') && v!=null) v = parseFloat(v);
      await pool.query(`
        INSERT INTO atb_avaliacoes (ficha_id, ${field}, avaliado_por, updated_at)
        VALUES ($1,$2,$3,now())
        ON CONFLICT (ficha_id) DO UPDATE SET ${field}=EXCLUDED.${field}, avaliado_por=$3, updated_at=now()
      `, [id, v, req.user?.id]);
      res.json({ ok:true });
    } catch (e) {
      console.error('[atb] inline save error:', e.message);
      res.status(500).json({ ok:false, error:e.message });
    }
  });

  // ── Serve anexo (PDF/imagem via stream do R2) ──────────────────────────
  app.get('/atb/admin/ficha/:fid/anexo/:aid', adminRequired, async (req, res) => {
    try {
      const fid = parseInt(req.params.fid,10);
      const aid = parseInt(req.params.aid,10);
      const { rows:[a] } = await pool.query(
        'SELECT r2_key, nome_original, tipo FROM atb_ficha_imagens WHERE id=$1 AND ficha_id=$2',
        [aid, fid]
      );
      if (!a) return res.status(404).send('Anexo não encontrado');

      const r2resp = await fetchR2Stream(a.r2_key);
      const ct = r2resp.headers.get('content-type') ||
                 (a.tipo==='pdf' ? 'application/pdf' : 'application/octet-stream');
      res.setHeader('Content-Type', ct);
      const len = r2resp.headers.get('content-length');
      if (len) res.setHeader('Content-Length', len);
      const nome = (a.nome_original || `anexo-${aid}`).replace(/"/g,'');
      res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(nome)}"`);

      const reader = r2resp.body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        res.write(Buffer.from(value));
      }
      res.end();
    } catch (e) {
      console.error('[atb] anexo error:', e.message);
      res.status(500).send('Falha ao carregar anexo');
    }
  });

  // ════════════════════════════════════════════════════════════════════════
  // EDITOR DO FORMULÁRIO (Capacidade A: editar opções) — /atb/admin/form
  // ════════════════════════════════════════════════════════════════════════
  app.get('/atb/admin/form', adminRequired, async (req, res) => {
    const inst = (req.query.inst || 'HUSF').replace(/[^A-Za-z0-9_]/g, '');
    let def;
    try { def = await getFormSchema(pool, inst); }
    catch (e) { return res.send(renderShell('ATB · Editor', `<div class="card"><p>Erro: ${safe(e.message)}</p></div>`)); }
    if (!def) return res.send(renderShell('ATB · Editor', `<div class="card"><p>Schema não encontrado para ${safe(inst)}.</p></div>`));

    // Lista apenas campos com opções editáveis (select/radio/checkbox)
    const blocos = [];
    def.secoes.forEach(sec => {
      sec.campos.forEach(c => {
        if ((c.type === 'select' || c.type === 'radio' || c.type === 'checkbox') && Array.isArray(c.options)) {
          blocos.push(`
            <div class="card" style="margin-bottom:14px">
              <div style="display:flex;justify-content:space-between;align-items:baseline">
                <h2 style="margin:0">${safe(c.label)}</h2>
                <code style="font-size:11px;color:#888">${safe(c.key)} · ${c.type}</code>
              </div>
              <p class="mut" style="font-size:12px;margin:4px 0 10px">Seção: ${safe(sec.titulo)} · uma opção por linha</p>
              <textarea name="opt__${safe(c.key)}" rows="${Math.max(3, c.options.length)}"
                style="width:100%;box-sizing:border-box;padding:10px;border-radius:8px;border:1px solid #2a2d36;background:#0f1116;color:#e6e6e6;font-family:monospace;font-size:13px;line-height:1.6"
              >${safe(c.options.join('\n'))}</textarea>
            </div>`);
        }
      });
    });

    const html = `
      <form method="POST" action="/atb/admin/form?inst=${encodeURIComponent(inst)}">
        <div class="card" style="margin-bottom:14px">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <div>
              <h1 style="margin:0">Editor do formulário</h1>
              <p class="mut" style="margin:4px 0 0">${safe(def.titulo || '')} · ${safe(inst)} · versão ${def.versao || 1}</p>
            </div>
            <a href="/atb/admin">← Dashboard</a>
          </div>
          <p class="mut" style="font-size:13px;margin-top:12px">
            Edite as opções dos campos de seleção. Ao salvar, uma nova versão é criada
            e o formulário passa a usá-la imediatamente — sem deploy.
            <a href="/atb/form?inst=${encodeURIComponent(inst)}" target="_blank">Abrir formulário ↗</a>
          </p>
          <div style="margin-top:10px">
            <label class="mut" style="font-size:12px">Instituição: </label>
            <a href="/atb/admin/form?inst=HUSF" style="margin-right:10px;${inst==='HUSF'?'font-weight:700':''}">HUSF</a>
            <a href="/atb/admin/form?inst=H2" style="${inst==='H2'?'font-weight:700':''}">H2</a>
          </div>
        </div>
        ${blocos.join('')}
        <div class="card">
          <button type="submit" style="background:#00469e;color:#fff;border:none;border-radius:8px;padding:12px 28px;font-size:14px;font-weight:600;cursor:pointer">
            Salvar nova versão
          </button>
        </div>
      </form>`;
    res.send(renderShell('ATB · Editor do formulário', html));
  });

  app.post('/atb/admin/form', adminRequired, async (req, res) => {
    const inst = (req.query.inst || 'HUSF').replace(/[^A-Za-z0-9_]/g, '');
    try {
      const def = await getFormSchema(pool, inst);
      if (!def) throw new Error('schema não encontrado');
      // aplica as opções editadas (campos opt__<key>)
      const body = req.body || {};
      Object.keys(body).forEach(k => {
        if (!k.startsWith('opt__')) return;
        const key = k.slice(5);
        const opcoes = String(body[k] || '').split('\n').map(s => s.trim()).filter(Boolean);
        def.secoes.forEach(sec => sec.campos.forEach(c => {
          if (c.key === key && Array.isArray(c.options)) c.options = opcoes;
        }));
      });
      const adminId = req.cookies && req.cookies.uid ? parseInt(req.cookies.uid, 10) : null;
      const v = await saveFormSchema(pool, inst, def, adminId);
      console.log(`[atb] schema ${inst} salvo como v${v}`);
      res.redirect('/atb/admin/form?inst=' + encodeURIComponent(inst));
    } catch (e) {
      res.send(renderShell('ATB · Editor', `<div class="card"><p>Erro ao salvar: ${safe(e.message)}</p></div>`));
    }
  });

}
