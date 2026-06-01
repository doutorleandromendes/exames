// atb-parser.js
// Converte o payload da API JotForm → objeto estruturado para o banco
// Funciona tanto para respostas de polling (answers por qid)
// quanto para webhooks (rawRequest JSON)

// ── Helpers de tipo ──────────────────────────────────────────────────────

const toBool = (v) => {
  if (!v) return null;
  if (typeof v === 'boolean') return v;
  const s = String(v).trim().toLowerCase();
  if (['sim', 'yes', '1', 'true'].includes(s)) return true;
  if (['não', 'nao', 'no', '0', 'false'].includes(s)) return false;
  return null;
};

const toDate = (v) => {
  if (!v) return null;
  const s = String(v).trim();
  if (!s || s === '{}') return null;

  // dd/mm/yyyy ou dd-mm-yyyy
  const dmy = s.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})$/);
  if (dmy) return `${dmy[3]}-${dmy[2].padStart(2,'0')}-${dmy[1].padStart(2,'0')}`;

  // dd-mm-yyyy hh:mm (litemode JotForm)
  const dmyt = s.match(/^(\d{1,2})-(\d{1,2})-(\d{4})/);
  if (dmyt) return `${dmyt[3]}-${dmyt[2].padStart(2,'0')}-${dmyt[1].padStart(2,'0')}`;

  // yyyy-mm-dd
  if (/^\d{4}-\d{2}-\d{2}/.test(s)) return s.slice(0,10);

  return null;
};

const toInt = (v) => {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : null;
};

const toNum = (v) => {
  const n = parseFloat(String(v).replace(',','.'));
  return Number.isFinite(n) ? n : null;
};

const toArray = (v) => {
  if (!v) return [];
  if (Array.isArray(v)) return v.filter(Boolean);
  if (typeof v === 'string') {
    if (v.startsWith('[')) try { return JSON.parse(v); } catch {}
    return v.split(',').map(s => s.trim()).filter(Boolean);
  }
  return [];
};

// Matriz JotForm → array de objetos
// JotForm envia matrizes como { "ATB1": { "Qual?": "Meropenem", ... }, ... }
const toMatrix = (v) => {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return [];
  return Object.entries(v)
    .map(([row, cols]) => ({ row, ...cols }))
    .filter(r => Object.values(r).some(c => c && c !== row));
};

// ── Parser principal ──────────────────────────────────────────────────────

/**
 * Recebe o objeto `answers` de uma submissão JotForm (polling API)
 * e retorna o objeto estruturado para inserção no banco.
 *
 * answers = { "3": { answer: {...}, type: "...", name: "..." }, ... }
 */
export function parseAnswers(answers, formId) {
  const get = (qid) => answers[String(qid)]?.answer ?? null;
  const str = (qid) => {
    const v = get(qid);
    if (!v) return null;
    if (typeof v === 'string') return v.trim() || null;
    return null;
  };

  // qid 3 — nome do paciente (control_fullname)
  const nameObj = get(3);
  const rawFirst = (nameObj?.first || '').trim();
  const rawLast  = (nameObj?.last  || '').trim();
  const paciente_nome_raw = [rawFirst, rawLast].filter(Boolean).join(' ');

  // qid 44 — ATB solicitado (checkbox → pode vir como string ou array)
  const atbRaw = get(44);
  const atb_solicitado = toArray(atbRaw);

  // qid 30 — Recomendação SCIH (checkbox)
  const rec_scih_raw = get(30);
  const recomendacao_scih = toArray(rec_scih_raw);

  // qid 37 — Comorbidades (checkbox, hidden)
  const comorbRaw = get(37);
  const comorbidades = toArray(comorbRaw);

  // qid 43 — Dispositivos invasivos (checkbox)
  const dispRaw = get(43);
  const dispositivos_invasivos = toArray(dispRaw);

  // qid 47 — Insuficiência renal (checkbox)
  const irRaw = get(47);
  const insuficiencia_renal = toArray(irRaw);

  // qid 55 — Acesso vascular Neo (checkbox)
  const avn = toArray(get(55));

  // qid 39 — ATB nos últimos 7 dias (matrix)
  const atb_previos = toMatrix(get(39));

  // qid 42 — Culturas colhidas (matrix)
  const culturas_colhidas_raw = get(42);
  const culturas_colhidas = culturas_colhidas_raw && typeof culturas_colhidas_raw === 'object'
    ? culturas_colhidas_raw : {};

  // qid 58 — Culturas prévias (matrix)
  const culturas_previas = toMatrix(get(58));

  // qid 45 — Posologia (matrix)
  const posologia = toMatrix(get(45));

  // qid 61 — Parecer evolutivo (matrix)
  const parecer_evolutivo = toMatrix(get(61));

  // Gerar links automáticos
  // link_exames: autologin usando prontuário e DN
  const pron = str(107);
  const dn   = toDate(get(14));
  const link_exames = (pron && dn)
    ? `https://doutorleandromendes.github.io/exames/autologin.html?user=p${pron}&pass=${dn.replace(/-/g,'').slice(6,8)+dn.replace(/-/g,'').slice(4,6)+dn.replace(/-/g,'').slice(0,4)}`
    : null;

  // link_labs: API local (ainda local, pode migrar depois)
  const nomePac = paciente_nome_raw;
  const link_labs = nomePac
    ? `http://localhost:3000/api/buscar?nome=${encodeURIComponent(nomePac)}`
    : null;

  return {
    paciente_nome_raw,
    paciente_nome: null, // será preenchido pela normalização via Claude
    paciente_dn: dn,
    paciente_idade: str(95),
    prontuario: pron,
    atendimento: str(63),

    setor: str(17),
    leito: str(36),
    equipe_responsavel: str(75),
    data_internacao: toDate(get(11)),
    data_admissao_uti: toDate(get(113)),

    tipo_terapia: str(60),
    historia_clinica: str(10),
    cirurgia: str(76),
    foco_infeccao: str(40),
    sepse: toBool(str(41)),
    gestante: toBool(str(97)),
    lactante: toBool(str(98)),

    comorbidades,
    uso_atb_7d: toBool(str(38)),
    atb_previos,
    culturas_colhidas,
    culturas_previas,

    dispositivos_invasivos,
    dialise: toBool(str(59)),
    acesso_dialise: str(52),
    data_insercao_cateter: toDate(get(87)),
    sitio_cvc: toArray(get(116)),
    sitio_cdl: toArray(get(117)),
    sitio_pai: toArray(get(118)),

    peso_nascimento: toNum(str(54)),
    acesso_vascular_neo: avn,

    insuficiencia_renal,
    clcr: toNum(str(66)),
    peso: toNum(str(67)),
    altura: toNum(str(65)),

    faz_quimio: toBool(str(82)),
    cateter_quimio: toBool(str(84)),
    acesso_quimio: str(83),

    classificacao_fratura: str(111),

    atb_solicitado,
    posologia,
    tempo_previsto: toInt(str(62)),
    oxacilina_associacao: toBool(str(152)),

    crm: str(34) || str(151),
    prescritor_nome: str(32),

    sofa: toInt(str(142)),
    sofa_renal: toInt(str(141)),

    recomendacao_scih,
    recomendacoes_especificacao: str(88),
    recomendacoes_adicionais: str(35),
    ha_esquema_sugerido: str(164),
    avaliador: str(50),
    complemento_scih: str(99),
    parecer_evolutivo,

    obito: toBool(str(90)) || false,
    data_obito: toDate(get(91)),

    link_exames,
    link_labs,
  };
}

/**
 * Para webhooks: o JotForm envia rawRequest como JSON com chaves
 * no formato q{id}_{name} ou {name}. Converte para o formato de answers.
 */
export function parseWebhookRaw(rawRequest) {
  let data = {};
  if (typeof rawRequest === 'string') {
    try { data = JSON.parse(rawRequest); } catch { return null; }
  } else if (typeof rawRequest === 'object') {
    data = rawRequest;
  }

  // Mapeia chaves de volta para qid
  const qidMap = {
    3:  data['q3_nome']                   || { first: data['nome[first]'] || '', last: data['nome[last]'] || '' },
    10: data['q10_historiaClinica']        || data['historiaClinica'],
    11: data['q11_dataDe11']              || data['dataDe11'],
    14: data['q14_dataDe14']              || data['dataDe14'],
    17: data['q17_setorDe']              || data['setorDe'],
    30: data['q30_recomendacaoScih30']   || data['recomendacaoScih30'],
    32: data['q32_nomeCompleto']          || data['nomeCompleto'],
    34: data['q34_responsavelPelo34']     || data['responsavelPelo34'],
    35: data['q35_recomendacoesDo']       || data['recomendacoesDo'],
    36: data['q36_leito']                || data['leito'],
    37: data['q37_comorbidadesantecedentes'] || data['comorbidadesantecedentes'],
    38: data['q38_usoDe']                || data['usoDe'],
    39: data['q39_atbNos']               || data['atbNos'],
    40: data['q40_focoDe']               || data['focoDe'],
    41: data['q41_sepse']                || data['sepse'],
    42: data['q42_culturasColhidas']     || data['culturasColhidas'],
    43: data['q43_dispositivosInvasivos'] || data['dispositivosInvasivos'],
    44: data['q44_atbSolicitado']        || data['atbSolicitado'],
    45: data['q45_posologia']            || data['posologia'],
    47: data['q47_insuficienciaRenal']   || data['insuficienciaRenal'],
    50: data['q50_avaliador']            || data['avaliador'],
    52: data['q52_acessoPra']            || data['acessoPra'],
    54: data['q54_pesoAo54']             || data['pesoAo54'],
    55: data['q55_acessoVascular']       || data['acessoVascular'],
    58: data['q58_culturasPrevias']      || data['culturasPrevias'],
    59: data['q59_dialise']              || data['dialise'],
    60: data['q60_tipoDe']              || data['tipoDe'],
    61: data['q61_parecerEvolutivo']     || data['parecerEvolutivo'],
    62: data['q62_tempoPrevisto']        || data['tempoPrevisto'],
    63: data['q63_atendimento']          || data['atendimento'],
    65: data['q65_alturaem']             || data['alturaem'],
    66: data['q66_clearenceDe']          || data['clearenceDe'],
    67: data['q67_pesoem']               || data['pesoem'],
    75: data['q75_equipeResponsavel']    || data['equipeResponsavel'],
    76: data['q76_cirurgiaA']            || data['cirurgiaA'],
    82: data['q82_pacienteFaz']          || data['pacienteFaz'],
    83: data['q83_acessoPra83']          || data['acessoPra83'],
    84: data['q84_possuiCateter']        || data['possuiCateter'],
    87: data['q87_dataDe']              || data['dataDe'],
    88: data['q88_recomendacoesScih']   || data['recomendacoesScih'],
    90: data['q90_obito']               || data['obito'],
    91: data['q91_dataDo']              || data['dataDo'],
    95: data['q95_idade']               || data['idade'],
    97: data['q97_gestante']            || data['gestante'],
    98: data['q98_lactante']            || data['lactante'],
    99: data['q99_complementoScih']     || data['complementoScih'],
    107: data['q107_prontuario']         || data['prontuario'],
    111: data['q111_classificacaoDe']    || data['classificacaoDe'],
    113: data['q113_dataDe113']          || data['dataDe113'],
    116: data['q116_sitioDe']           || data['sitioDe'],
    117: data['q117_sitioDe117']         || data['sitioDe117'],
    118: data['q118_sitioDe118']         || data['sitioDe118'],
    141: data['q141_sofa_renal2']        || data['sofa_renal2'],
    142: data['q142_sofa']              || data['sofa'],
    151: data['q151_insiraUma151']       || data['insiraUma151'],
    152: data['q152_seraPrescrita']      || data['seraPrescrita'],
    164: data['q164_haEsquema']          || data['haEsquema'],
  };

  // Converte para formato de answers esperado pelo parseAnswers
  const answers = {};
  for (const [qid, answer] of Object.entries(qidMap)) {
    if (answer !== undefined && answer !== null) {
      answers[qid] = { answer };
    }
  }
  return answers;
}
// ── Adicionar em atb-routes.js, dentro de registerAtbRoutes ──────────────

// Serve o formulário do prescritor (sem auth — CRM é a "autenticação")
app.get('/atb/form', (req, res) => {
  const inst = req.query.inst || 'HUSF';
  // Lê o HTML e injeta a instituição
  import('fs').then(fs => {
    import('path').then(path => {
      const filePath = path.join(process.cwd(), 'atb-form.html');
      let html = fs.readFileSync(filePath, 'utf8');
      html = html.replace(
        "window.ATB_INSTITUICAO || 'HUSF'",
        `'${inst.replace(/'/g,'')}'`
      );
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(html);
    });
  });
});

// API: valida CRM contra atb_medicos
app.get('/atb/api/validar-crm', async (req, res) => {
  const { crm, instituicao } = req.query;
  if (!crm) return res.status(400).json({ erro: 'CRM obrigatório' });
  try {
    const { rows } = await pool.query(`
      SELECT m.nome, m.especialidade
      FROM atb_medicos m
      JOIN atb_instituicoes i ON i.id = m.instituicao_id
      WHERE m.crm = $1
        AND (i.sigla = $2 OR $2 IS NULL)
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

// API: recebe submissão do formulário próprio
app.post('/atb/api/fichas', async (req, res) => {
  try {
    const d = req.body;
    if (!d.pac_nome || !d.prontuario || !d.crm) {
      return res.status(400).json({ error: 'Campos obrigatórios em falta' });
    }

    // Converte o payload do React para o formato do nosso banco
    const { parseFormPayload } = await import('./atb-parser.js');
    const parsed = parseFormPayload(d);

    // Normaliza nome via Claude (assíncrono, não bloqueia a resposta)
    const { rodarTriagemIA } = await import('./atb-sync.js');

    // Busca instituição
    const inst = d.instituicao || 'HUSF';
    const { rows: [instRow] } = await pool.query(
      'SELECT id FROM atb_instituicoes WHERE sigla = $1', [inst]
    );

    // Gera um ID único para submissões do formulário próprio
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
        VALUES ($1, $2, now())
        ON CONFLICT (ficha_id) DO UPDATE SET triagem_ia=$2, triagem_ia_at=now()
      `, [ficha.id, JSON.stringify(triagem)]);
    }).catch(() => {});

    res.json({ ok: true, id: ficha.id });
  } catch (e) {
    console.error('[atb] POST /fichas error:', e);
    res.status(500).json({ error: e.message });
  }
});
