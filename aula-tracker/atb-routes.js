// atb-routes.js  (início — webhook + polling + rotas base)
// O dashboard completo virá na próxima iteração

import { handleWebhook, iniciarPolling } from './atb-sync.js';

function safe(s) {
  return String(s ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

export function registerAtbRoutes(app, pool, adminRequired, renderShell) {

  // ── Webhook (sem auth — chamado pelo JotForm) ─────────────────────────
  app.post('/atb/webhook', handleWebhook(pool));

  // ── Inicia polling no startup ─────────────────────────────────────────
  iniciarPolling(pool).catch(e => console.error('[atb] falha ao iniciar polling:', e.message));

  // ── Dashboard admin ───────────────────────────────────────────────────
  app.get('/atb/admin', adminRequired, async (req, res) => {
    try {
      const { rows: [totais] } = await pool.query(`
        SELECT
          COUNT(*)                                          AS total,
          COUNT(*) FILTER (WHERE status = 'pendente')      AS pendentes,
          COUNT(*) FILTER (WHERE status = 'avaliado')      AS avaliados,
          COUNT(*) FILTER (WHERE date_trunc('day', created_at) = CURRENT_DATE) AS hoje
        FROM atb_fichas
      `);

      const { rows: recentes } = await pool.query(`
        SELECT f.id, f.paciente_nome, f.prontuario, f.setor, f.atb_solicitado,
               f.status, f.sofa, f.created_at, f.recomendacao_scih,
               i.sigla AS instituicao,
               a.triagem_ia
        FROM atb_fichas f
        LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
        LEFT JOIN atb_avaliacoes a  ON a.ficha_id = f.id
        ORDER BY f.created_at DESC
        LIMIT 20
      `);

      const statusBadge = (s) => {
        const cores = { pendente:'#ba8c00', em_avaliacao:'#4f8cff', avaliado:'#1a7a4a', arquivado:'#555' };
        return `<span style="font-size:10px;padding:2px 8px;border-radius:8px;background:${cores[s]||'#333'};color:#fff">${s}</span>`;
      };

      const riscoBadge = (triagem) => {
        if (!triagem) return '<span style="color:#555;font-size:11px">—</span>';
        const cores = { alto:'#b03030', medio:'#ba8c00', baixo:'#1a7a4a', inconclusivo:'#555' };
        const r = triagem.risco_iras || 'inconclusivo';
        return `<span style="font-size:10px;padding:2px 8px;border-radius:8px;background:${cores[r]||'#555'};color:#fff">${r}</span>`;
      };

      const rows = recentes.map(f => {
        const atbs = Array.isArray(f.atb_solicitado) ? f.atb_solicitado.join(', ') : '—';
        const triagem = f.triagem_ia;
        return `
          <tr>
            <td><strong>${safe(f.paciente_nome || '—')}</strong>
              <div class="mut" style="font-size:11px">${safe(f.prontuario||'')}</div></td>
            <td><span class="mut">${safe(f.instituicao||'')}</span> ${safe(f.setor||'')}</td>
            <td style="font-size:12px">${safe(atbs)}</td>
            <td>${f.sofa != null ? f.sofa : '—'}</td>
            <td>${riscoBadge(triagem)}</td>
            <td>${statusBadge(f.status)}</td>
            <td><a href="/atb/admin/fichas/${f.id}">abrir</a></td>
          </tr>`;
      }).join('');

      const stats = [
        ['Total',     totais.total],
        ['Hoje',      totais.hoje],
        ['Pendentes', totais.pendentes],
        ['Avaliados', totais.avaliados],
      ].map(([lbl, val]) => `
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
              <th>Paciente</th><th>Local</th><th>ATB</th><th>SOFA</th>
              <th>Risco IA</th><th>Status</th><th></th>
            </tr></thead>
            <tbody>${rows || '<tr><td colspan="7" class="mut">Nenhuma ficha ainda.</td></tr>'}</tbody>
          </table>
        </div>`;
      res.send(renderShell('ATB · Dashboard', html));
    } catch (e) {
      console.error('[atb] dashboard error:', e);
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
        LEFT JOIN atb_avaliacoes a  ON a.ficha_id = f.id
        WHERE f.id = $1
      `, [id]);
      if (!f) return res.status(404).send(renderShell('Erro', '<div class="card"><h1>Ficha não encontrada</h1></div>'));

      const triagem = f.triagem_ia;
      const triagemHtml = triagem ? `
        <div style="background:#181c22;border:1px solid #2a2f39;border-radius:8px;padding:14px;margin-top:12px">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#a7adbb;margin-bottom:8px">Triagem IA (Claude)</div>
          <div>Risco IrAS: <strong style="color:${triagem.risco_iras==='alto'?'#e06c6c':triagem.risco_iras==='medio'?'#e0b86c':'#6ce0a0'}">${triagem.risco_iras}</strong></div>
          ${triagem.potenciais_iras?.length ? `<div>Potenciais: ${triagem.potenciais_iras.map(s=>`<code style="font-size:11px;background:#20242b;padding:1px 6px;border-radius:4px">${safe(s)}</code>`).join(' ')}</div>` : ''}
          <div style="margin-top:6px;color:#a7adbb;font-size:13px">${safe(triagem.justificativa_iras||'')}</div>
          ${triagem.alertas?.length ? `<div style="margin-top:8px;color:#e0b86c;font-size:12px">⚠ ${triagem.alertas.join(' · ')}</div>` : ''}
          <div style="margin-top:8px">Adequação ATB: <strong>${safe(triagem.adequacao_atb||'')}</strong></div>
          ${triagem.sugestao_de_escalacao ? `<div style="color:#a7adbb;font-size:12px;margin-top:4px">${safe(triagem.sugestao_de_escalacao)}</div>` : ''}
        </div>` : '<p class="mut">Triagem IA não disponível.</p>';

      const atbs = Array.isArray(f.atb_solicitado) ? f.atb_solicitado.join(', ') : '—';
      const disp = Array.isArray(f.dispositivos_invasivos) ? f.dispositivos_invasivos.join(', ') : '—';

      const html = `
        <div class="card" style="margin-bottom:12px">
          <div style="display:flex;justify-content:space-between;align-items:flex-start">
            <div>
              <h1>${safe(f.paciente_nome || f.paciente_nome_raw || '—')}</h1>
              <p class="mut">
                ${safe(f.instituicao||'')} · ${safe(f.setor||'')} ${f.leito?`· Leito ${safe(f.leito)}`:''}
                · Prontuário ${safe(f.prontuario||'—')} · Atend. ${safe(f.atendimento||'—')}
              </p>
              ${f.link_exames ? `<a href="${f.link_exames}" target="_blank" style="font-size:12px">🔗 Exames</a>` : ''}
              ${f.link_labs   ? ` · <a href="${f.link_labs}"   target="_blank" style="font-size:12px">🔬 LIS</a>` : ''}
            </div>
            <a href="/atb/admin">← Dashboard</a>
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
              <h2>Prescritor & Recomendação JotForm</h2>
              <p style="font-size:13px">${safe(f.prescritor_nome||'—')} <span class="mut">CRM ${safe(f.crm||'—')}</span></p>
              ${Array.isArray(f.recomendacao_scih) && f.recomendacao_scih.length
                ? `<div style="margin-top:8px">${f.recomendacao_scih.map(r=>`<span style="display:inline-block;font-size:11px;margin:2px;padding:2px 8px;border-radius:8px;background:#20242b;color:#a7adbb">${safe(r)}</span>`).join('')}</div>`
                : ''}
              ${f.recomendacoes_especificacao ? `<p style="font-size:12px;color:#a7adbb;margin-top:6px">${safe(f.recomendacoes_especificacao)}</p>` : ''}
            </div>
          </div>
        </div>`;

      res.send(renderShell(`ATB · ${f.paciente_nome || 'Ficha'}`, html));
    } catch (e) {
      console.error('[atb] ficha detail error:', e);
      res.status(500).send(renderShell('Erro', `<div class="card"><p class="mut">${safe(e.message)}</p></div>`));
    }
  });

  // POST — salva avaliação
  app.post('/atb/admin/fichas/:id/avaliar', adminRequired, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const { iras, etiol_iras, micro, desfecho_iras, desfecho_data, saps3, status } = req.body || {};
    try {
      await pool.query(
        `INSERT INTO atb_avaliacoes (ficha_id, iras, etiol_iras, micro, desfecho_iras, desfecho_data, saps3, avaliado_por, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())
         ON CONFLICT (ficha_id) DO UPDATE SET
           iras=$2, etiol_iras=$3, micro=$4, desfecho_iras=$5,
           desfecho_data=$6, saps3=$7, avaliado_por=$8, updated_at=now()`,
        [id, iras||null, etiol_iras||null, micro||null, desfecho_iras||null,
         desfecho_data||null, saps3||null, req.user?.id]
      );
      await pool.query('UPDATE atb_fichas SET status=$1, updated_at=now() WHERE id=$2', [status||'pendente', id]);
      res.redirect(`/atb/admin/fichas/${id}`);
    } catch (e) {
      console.error('[atb] avaliar error:', e);
      res.status(500).send('Falha ao salvar avaliação');
    }
  });

  // POST — re-rodar triagem IA
  app.post('/atb/admin/fichas/:id/retriagem', adminRequired, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    try {
      const { rows: [f] } = await pool.query('SELECT * FROM atb_fichas WHERE id=$1', [id]);
      if (f) {
        const { rodarTriagemIA } = await import('./atb-sync.js');
        const triagem = await rodarTriagemIA(f);
        if (triagem) {
          await pool.query(`
            INSERT INTO atb_avaliacoes (ficha_id, triagem_ia, triagem_ia_at)
            VALUES ($1,$2,now())
            ON CONFLICT (ficha_id) DO UPDATE SET triagem_ia=$2, triagem_ia_at=now()
          `, [id, JSON.stringify(triagem)]);
        }
      }
      res.redirect(`/atb/admin/fichas/${id}`);
    } catch (e) {
      console.error('[atb] retriagem error:', e);
      res.redirect(`/atb/admin/fichas/${id}`);
    }
  });

  // ── Configuração: vincula form_id às instituições ─────────────────────
  app.get('/atb/admin/config', adminRequired, async (req, res) => {
    const { rows: insts } = await pool.query('SELECT * FROM atb_instituicoes ORDER BY id');
    const rows = insts.map(i => `
      <tr>
        <td>${safe(i.nome)}</td>
        <td><code>${safe(i.sigla)}</code></td>
        <td>
          <form method="POST" action="/atb/admin/config/${i.id}" style="display:flex;gap:8px;align-items:center">
            <input name="jotform_form_id" value="${safe(i.jotform_form_id||'')}"
              placeholder="ex.: 242856789" style="width:160px;padding:8px;border-radius:6px;border:1px solid #2a2f39;background:#0f1116;color:#e7e9ee">
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
          No JotForm: Settings → Integrations → WebHooks → Add WebHook → cole o URL acima.
          Faça isso para cada formulário (HUSF e Hospital 2).
        </p>

        <h2 class="mt2">Form IDs por instituição</h2>
        <p class="mut" style="margin-bottom:8px">O Form ID aparece na URL do formulário no JotForm.</p>
        <table>
          <thead><tr><th>Hospital</th><th>Sigla</th><th>JotForm Form ID</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>

        <h2 class="mt2">Variáveis de ambiente necessárias (Render)</h2>
        <table>
          <tr><td><code>JOTFORM_API_KEY</code></td><td class="mut">Sua API key do JotForm</td></tr>
          <tr><td><code>ANTHROPIC_API_KEY</code></td><td class="mut">Já existe no infectoaulas ✓</td></tr>
        </table>
      </div>`;
    res.send(renderShell('ATB · Configuração', html));
  });

  app.post('/atb/admin/config/:id', adminRequired, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const { jotform_form_id } = req.body || {};
    await pool.query('UPDATE atb_instituicoes SET jotform_form_id=$1 WHERE id=$2',
      [jotform_form_id?.trim() || null, id]);
    res.redirect('/atb/admin/config');
  });

}
