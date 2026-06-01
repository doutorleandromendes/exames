// atb-sync.js
// Motor de sincronização: webhook handler + polling + normalização via Claude

import { parseAnswers, parseWebhookRaw } from './atb-parser.js';

const JOTFORM_API   = 'https://api.jotform.com';
const ANTHROPIC_API = 'https://api.anthropic.com/v1/messages';

// ── Normalização de nome via Claude ───────────────────────────────────────

async function normalizarNome(nomeRaw) {
  if (!nomeRaw?.trim()) return nomeRaw || null;
  try {
    const res = await fetch(ANTHROPIC_API, {
      method: 'POST',
      headers: {
        'Content-Type':    'application/json',
        'x-api-key':       process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 60,
        messages: [{
          role: 'user',
          content:
            `Corrija este nome de paciente hospitalar: remova sobrenomes duplicados, ` +
            `abreviações incorretas e espaços extras. Retorne APENAS o nome corrigido ` +
            `em letras maiúsculas, sem pontuação extra.\n\nNome: "${nomeRaw.trim()}"`,
        }],
      }),
    });
    const data = await res.json();
    const normalizado = data?.content?.[0]?.text?.trim();
    return normalizado || nomeRaw;
  } catch (e) {
    console.warn('[atb] normalização de nome falhou:', e.message);
    return nomeRaw;
  }
}

// ── Triagem automática via Claude ─────────────────────────────────────────

export async function rodarTriagemIA(ficha) {
  try {
    const contexto = JSON.stringify({
      setor:                  ficha.setor,
      data_internacao:        ficha.data_internacao,
      data_admissao_uti:      ficha.data_admissao_uti,
      tipo_terapia:           ficha.tipo_terapia,
      historia_clinica:       ficha.historia_clinica,
      foco_infeccao:          ficha.foco_infeccao,
      sepse:                  ficha.sepse,
      dispositivos_invasivos: ficha.dispositivos_invasivos,
      data_insercao_cateter:  ficha.data_insercao_cateter,
      culturas_colhidas:      ficha.culturas_colhidas,
      culturas_previas:       ficha.culturas_previas,
      atb_solicitado:         ficha.atb_solicitado,
      posologia:              ficha.posologia,
      tempo_previsto:         ficha.tempo_previsto,
      sofa:                   ficha.sofa,
      insuficiencia_renal:    ficha.insuficiencia_renal,
      clcr:                   ficha.clcr,
      peso:                   ficha.peso,
      comorbidades:           ficha.comorbidades,
    }, null, 2);

    const res = await fetch(ANTHROPIC_API, {
      method: 'POST',
      headers: {
        'Content-Type':    'application/json',
        'x-api-key':       process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 600,
        messages: [{
          role: 'user',
          content:
            `Você é um especialista em controle de infecção hospitalar. Analise esta ficha de solicitação ` +
            `de antimicrobiano e responda APENAS em JSON com a estrutura abaixo, sem markdown:\n\n` +
            `{\n` +
            `  "risco_iras": "alto" | "medio" | "baixo" | "inconclusivo",\n` +
            `  "potenciais_iras": ["IRAS-CVC", "PAV", "ITU-SVD", ...] ou [],\n` +
            `  "justificativa_iras": "string curta",\n` +
            `  "adequacao_atb": "adequado" | "rever_espectro" | "rever_dose" | "rever_indicacao" | "inconclusivo",\n` +
            `  "alertas": ["string", ...] ou [],\n` +
            `  "sugestao_de_escalacao": "string ou null"\n` +
            `}\n\nDados da ficha:\n${contexto}`,
        }],
      }),
    });

    const data  = await res.json();
    const text  = data?.content?.[0]?.text?.trim();
    const clean = text?.replace(/```json|```/g, '').trim();
    return JSON.parse(clean);
  } catch (e) {
    console.warn('[atb] triagem IA falhou:', e.message);
    return null;
  }
}

// ── Inserção/atualização de ficha no banco ────────────────────────────────

async function upsertFicha(pool, submissionId, parsed, instituicaoId, payloadRaw, criadaEm) {
  const nomeFinal = await normalizarNome(parsed.paciente_nome_raw);
  const p = parsed;

  const result = await pool.query(`
    INSERT INTO atb_fichas (
      instituicao_id, jotform_submission_id, jotform_created_at,
      paciente_nome, paciente_nome_raw, paciente_dn, paciente_idade,
      prontuario, atendimento,
      setor, leito, equipe_responsavel, data_internacao, data_admissao_uti,
      tipo_terapia, historia_clinica, cirurgia, foco_infeccao,
      sepse, gestante, lactante,
      comorbidades, uso_atb_7d, atb_previos, culturas_colhidas, culturas_previas,
      dispositivos_invasivos, dialise, acesso_dialise, data_insercao_cateter,
      sitio_cvc, sitio_cdl, sitio_pai, peso_nascimento, acesso_vascular_neo,
      insuficiencia_renal, clcr, peso, altura,
      faz_quimio, cateter_quimio, acesso_quimio, classificacao_fratura,
      atb_solicitado, posologia, tempo_previsto, oxacilina_associacao,
      crm, prescritor_nome, sofa, sofa_renal,
      recomendacao_scih, recomendacoes_especificacao, recomendacoes_adicionais,
      ha_esquema_sugerido, avaliador, complemento_scih, parecer_evolutivo,
      obito, data_obito, link_exames, link_labs, payload_raw, synced_at
    ) VALUES (
      $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
      $21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,
      $39,$40,$41,$42,$43,$44,$45,$46,$47,$48,$49,$50,$51,$52,$53,$54,$55,$56,
      $57,$58,$59,$60,$61,$62,$63,now()
    )
    ON CONFLICT (jotform_submission_id) DO UPDATE SET
      paciente_nome               = EXCLUDED.paciente_nome,
      paciente_nome_raw           = EXCLUDED.paciente_nome_raw,
      recomendacao_scih           = EXCLUDED.recomendacao_scih,
      recomendacoes_especificacao = EXCLUDED.recomendacoes_especificacao,
      recomendacoes_adicionais    = EXCLUDED.recomendacoes_adicionais,
      ha_esquema_sugerido         = EXCLUDED.ha_esquema_sugerido,
      avaliador                   = EXCLUDED.avaliador,
      complemento_scih            = EXCLUDED.complemento_scih,
      parecer_evolutivo           = EXCLUDED.parecer_evolutivo,
      obito                       = EXCLUDED.obito,
      data_obito                  = EXCLUDED.data_obito,
      payload_raw                 = EXCLUDED.payload_raw,
      synced_at                   = now(),
      updated_at                  = now()
    RETURNING id, (xmax = 0) AS inserted
  `, [
    instituicaoId,
    submissionId,
    criadaEm,
    nomeFinal,
    p.paciente_nome_raw,
    p.paciente_dn,
    p.paciente_idade,
    p.prontuario,
    p.atendimento,
    p.setor,
    p.leito,
    p.equipe_responsavel,
    p.data_internacao,
    p.data_admissao_uti,
    p.tipo_terapia,
    p.historia_clinica,
    p.cirurgia,
    p.foco_infeccao,
    p.sepse,
    p.gestante,
    p.lactante,
    JSON.stringify(p.comorbidades       || []),
    p.uso_atb_7d,
    JSON.stringify(p.atb_previos        || []),
    JSON.stringify(p.culturas_colhidas  || {}),
    JSON.stringify(p.culturas_previas   || []),
    JSON.stringify(p.dispositivos_invasivos || []),
    p.dialise,
    p.acesso_dialise,
    p.data_insercao_cateter,
    JSON.stringify(p.sitio_cvc          || []),
    JSON.stringify(p.sitio_cdl          || []),
    JSON.stringify(p.sitio_pai          || []),
    p.peso_nascimento,
    JSON.stringify(p.acesso_vascular_neo || []),
    JSON.stringify(p.insuficiencia_renal || []),
    p.clcr,
    p.peso,
    p.altura,
    p.faz_quimio,
    p.cateter_quimio,
    p.acesso_quimio,
    p.classificacao_fratura,
    JSON.stringify(p.atb_solicitado     || []),
    JSON.stringify(p.posologia          || []),
    p.tempo_previsto,
    p.oxacilina_associacao,
    p.crm,
    p.prescritor_nome,
    p.sofa,
    p.sofa_renal,
    JSON.stringify(p.recomendacao_scih  || []),
    p.recomendacoes_especificacao,
    p.recomendacoes_adicionais,
    p.ha_esquema_sugerido,
    p.avaliador,
    p.complemento_scih,
    JSON.stringify(p.parecer_evolutivo  || []),
    p.obito || false,
    p.data_obito,
    p.link_exames,
    p.link_labs,
    JSON.stringify(payloadRaw),
  ]);

  return result.rows[0] || null;
}

// ── Webhook handler ───────────────────────────────────────────────────────

export function handleWebhook(pool) {
  return async (req, res) => {
    res.status(200).end();

    try {
      const body        = req.body || {};
      const submissionId = body.submissionID || body.submission_id;
      const formId       = body.formID       || body.form_id;
      if (!submissionId || !formId) return;

      const { rows: [inst] } = await pool.query(
        'SELECT id FROM atb_instituicoes WHERE jotform_form_id = $1', [String(formId)]
      );
      const instituicaoId = inst?.id || null;

      const raw     = body.rawRequest || body;
      const answers = parseWebhookRaw(raw);
      if (!answers) return;

      const parsed   = parseAnswers(answers, formId);
      const criadaEm = body.created_at ? new Date(body.created_at) : new Date();
      const fichaRow = await upsertFicha(pool, submissionId, parsed, instituicaoId, raw, criadaEm);

      if (fichaRow?.inserted) {
        rodarTriagemIA(parsed).then(async (triagem) => {
          if (!triagem) return;
          await pool.query(`
            INSERT INTO atb_avaliacoes (ficha_id, triagem_ia, triagem_ia_at)
            VALUES ($1,$2,now())
            ON CONFLICT (ficha_id) DO UPDATE
              SET triagem_ia=$2, triagem_ia_at=now()
          `, [fichaRow.id, JSON.stringify(triagem)]);
        }).catch(e => console.error('[atb] triagem webhook error:', e.message));
      }

      await pool.query(
        `INSERT INTO atb_sync_log (instituicao_id, tipo, submission_id, status, detalhes)
         VALUES ($1,'webhook',$2,'ok',$3)`,
        [instituicaoId, submissionId, JSON.stringify({ formId, inserted: fichaRow?.inserted })]
      );
    } catch (e) {
      console.error('[atb] webhook error:', e.message);
      pool.query(
        `INSERT INTO atb_sync_log (tipo, submission_id, status, detalhes)
         VALUES ('webhook',null,'erro',$1)`,
        [JSON.stringify({ error: e.message })]
      ).catch(() => {});
    }
  };
}

// ── Polling ───────────────────────────────────────────────────────────────

async function pollInstituicao(pool, inst) {
  const apiKey = process.env.JOTFORM_API_KEY;
  if (!apiKey || !inst.jotform_form_id) return;

  const since = new Date(Date.now() - 24 * 60 * 60 * 1000)
    .toISOString().slice(0,19).replace('T',' ');

  const url = `${JOTFORM_API}/form/${inst.jotform_form_id}/submissions` +
    `?apiKey=${apiKey}&limit=100&orderby=created_at&direction=DESC` +
    `&filter=${encodeURIComponent(JSON.stringify({ 'created_at:gt': since }))}`;

  const res  = await fetch(url);
  const data = await res.json();

  if (data.responseCode !== 200 || !Array.isArray(data.content)) {
    console.warn('[atb] poll API error:', data.responseCode, data.message);
    return;
  }

  let novas = 0;
  for (const sub of data.content) {
    try {
      const parsed   = parseAnswers(sub.answers || {}, inst.jotform_form_id);
      const criadaEm = sub.created_at ? new Date(sub.created_at) : new Date();
      const fichaRow = await upsertFicha(pool, sub.id, parsed, inst.id, sub, criadaEm);

      if (fichaRow?.inserted) {
        novas++;
        rodarTriagemIA(parsed).then(async (triagem) => {
          if (!triagem) return;
          await pool.query(`
            INSERT INTO atb_avaliacoes (ficha_id, triagem_ia, triagem_ia_at)
            VALUES ($1,$2,now())
            ON CONFLICT (ficha_id) DO UPDATE
              SET triagem_ia=$2, triagem_ia_at=now()
          `, [fichaRow.id, JSON.stringify(triagem)]);
        }).catch(e => console.error('[atb] triagem poll error:', e.message));
      }
    } catch (e) {
      console.error(`[atb] poll sub ${sub.id} error:`, e.message, e.stack);
    }
  }

  if (novas > 0 || data.content.length > 0) {
    console.log(`[atb] poll ${inst.sigla}: ${data.content.length} encontradas, ${novas} novas`);
  }
}

export async function iniciarPolling(pool) {
  const INTERVALO_MS = 10 * 60 * 1000;

  const poll = async () => {
    try {
      const { rows: insts } = await pool.query(
        'SELECT id, sigla, jotform_form_id FROM atb_instituicoes WHERE ativo=true AND jotform_form_id IS NOT NULL'
      );
      await Promise.all(insts.map(inst => pollInstituicao(pool, inst)));
    } catch (e) {
      console.error('[atb] polling error:', e.message);
    }
  };

  await poll();
  setInterval(poll, INTERVALO_MS);
  console.log(`[atb] polling ativo (intervalo: ${INTERVALO_MS / 60000} min)`);
}
