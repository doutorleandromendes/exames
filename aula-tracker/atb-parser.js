// atb-parser.js
// Converte o payload da API JotForm → objeto estruturado para o banco

// ── Helpers de tipo ──────────────────────────────────────────────────────

const toBool = (v) => {
  if (!v) return null;
  if (typeof v === 'boolean') return v;
  const s = String(v).trim().toLowerCase();
  if (['sim', 'yes', '1', 'true'].includes(s)) return true;
  if (['não', 'nao', 'no', '0', 'false'].includes(s)) return false;
  return null;
};

// toDate — adicionar tratamento do objeto litemode do JotForm
const toDate = (v) => {
  if (!v) return null;
  // JotForm liteMode datetime retorna objeto {litemode: "dd-mm-yyyy"}
  if (typeof v === 'object' && !Array.isArray(v)) {
    return toDate(v.litemode || v.day && `${v.day}-${v.month}-${v.year}` || null);
  }
  const s = String(v).trim();
  if (!s || s === '{}' || s === '[object Object]') return null;
  const dmy = s.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})$/);
  if (dmy) return `${dmy[3]}-${dmy[2].padStart(2,'0')}-${dmy[1].padStart(2,'0')}`;
  const dmyt = s.match(/^(\d{1,2})-(\d{1,2})-(\d{4})/);
  if (dmyt) return `${dmyt[3]}-${dmyt[2].padStart(2,'0')}-${dmyt[1].padStart(2,'0')}`;
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

const toMatrix = (v) => {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return [];
  return Object.entries(v)
    .map(([rowKey, cols]) => ({ row: rowKey, ...cols }))
    .filter(r => Object.values(r).some(c => c && c !== r.row));
};

// ── Parser JotForm (polling / webhook) ───────────────────────────────────

export function montarLinkExames(pron, dn) {
  const p = String(pron == null ? '' : pron).replace(/\D/g, '');
  const d = String(dn == null ? '' : dn).replace(/\D/g, '');
  if (!p || d.length < 8) return null;
  return `https://doutorleandromendes.github.io/exames/autologin.html?user=p${p}&pass=${d.slice(6,8)+d.slice(4,6)+d.slice(0,4)}`;
}

export function parseAnswers(answers, formId) {
  const get = (qid) => answers[String(qid)]?.answer ?? null;
  const str = (qid) => {
    const v = get(qid);
    if (!v) return null;
    if (typeof v === 'string') return v.trim() || null;
    return null;
  };

  const nameObj = get(3);
  const rawFirst = (nameObj?.first || '').trim();
  const rawLast  = (nameObj?.last  || '').trim();
  const paciente_nome_raw = [rawFirst, rawLast].filter(Boolean).join(' ');

  const atb_solicitado     = toArray(get(44));
  const recomendacao_scih  = toArray(get(30));
  const comorbidades       = toArray(get(37));
  const dispositivos_invasivos = toArray(get(43));
  const insuficiencia_renal    = toArray(get(47));
  const avn                = toArray(get(55));
  const atb_previos        = toMatrix(get(39));
  const culturas_colhidas_raw  = get(42);
  const culturas_colhidas  = culturas_colhidas_raw && typeof culturas_colhidas_raw === 'object'
    ? culturas_colhidas_raw : {};
  const culturas_previas   = toMatrix(get(58));
  const posologia          = toMatrix(get(45));
  const parecer_evolutivo  = toMatrix(get(61));

  const pron = String(str(107) || '').replace(/\D/g, '') || null; // prontuário: só dígitos
  const dn   = toDate(get(14));
  const link_exames = montarLinkExames(pron, dn);
  const nomePac  = paciente_nome_raw;
  const link_labs = nomePac
    ? `http://localhost:3000/api/buscar?nome=${String(nomePac).trim().replace(/\s+/g,"+")}`
    : null;

  return {
    paciente_nome_raw,
    paciente_nome: null,
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
    sinais_dialise: str(53),
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

export function parseWebhookRaw(rawRequest) {
  let data = {};
  if (typeof rawRequest === 'string') {
    try { data = JSON.parse(rawRequest); } catch { return null; }
  } else if (typeof rawRequest === 'object') {
    data = rawRequest;
  }

  const qidMap = {
    3:   data['q3_nome'] || { first: data['nome[first]']||'', last: data['nome[last]']||'' },
    10:  data['q10_historiaClinica']        || data['historiaClinica'],
    11:  data['q11_dataDe11']               || data['dataDe11'],
    14:  data['q14_dataDe14']               || data['dataDe14'],
    17:  data['q17_setorDe']                || data['setorDe'],
    30:  data['q30_recomendacaoScih30']      || data['recomendacaoScih30'],
    32:  data['q32_nomeCompleto']            || data['nomeCompleto'],
    34:  data['q34_responsavelPelo34']       || data['responsavelPelo34'],
    35:  data['q35_recomendacoesDo']         || data['recomendacoesDo'],
    36:  data['q36_leito']                   || data['leito'],
    37:  data['q37_comorbidadesantecedentes']|| data['comorbidadesantecedentes'],
    38:  data['q38_usoDe']                   || data['usoDe'],
    39:  data['q39_atbNos']                  || data['atbNos'],
    40:  data['q40_focoDe']                  || data['focoDe'],
    41:  data['q41_sepse']                   || data['sepse'],
    42:  data['q42_culturasColhidas']        || data['culturasColhidas'],
    43:  data['q43_dispositivosInvasivos']   || data['dispositivosInvasivos'],
    44:  data['q44_atbSolicitado']           || data['atbSolicitado'],
    45:  data['q45_posologia']               || data['posologia'],
    47:  data['q47_insuficienciaRenal']      || data['insuficienciaRenal'],
    50:  data['q50_avaliador']               || data['avaliador'],
    52:  data['q52_acessoPra']               || data['acessoPra'],
    53:  data['q53_sinaisDe']                || data['sinaisDe'],
    54:  data['q54_pesoAo54']                || data['pesoAo54'],
    55:  data['q55_acessoVascular']          || data['acessoVascular'],
    58:  data['q58_culturasPrevias']         || data['culturasPrevias'],
    59:  data['q59_dialise']                 || data['dialise'],
    60:  data['q60_tipoDe']                  || data['tipoDe'],
    61:  data['q61_parecerEvolutivo']        || data['parecerEvolutivo'],
    62:  data['q62_tempoPrevisto']           || data['tempoPrevisto'],
    63:  data['q63_atendimento']             || data['atendimento'],
    65:  data['q65_alturaem']                || data['alturaem'],
    66:  data['q66_clearenceDe']             || data['clearenceDe'],
    67:  data['q67_pesoem']                  || data['pesoem'],
    75:  data['q75_equipeResponsavel']       || data['equipeResponsavel'],
    76:  data['q76_cirurgiaA']               || data['cirurgiaA'],
    82:  data['q82_pacienteFaz']             || data['pacienteFaz'],
    83:  data['q83_acessoPra83']             || data['acessoPra83'],
    84:  data['q84_possuiCateter']           || data['possuiCateter'],
    87:  data['q87_dataDe']                  || data['dataDe'],
    88:  data['q88_recomendacoesScih']       || data['recomendacoesScih'],
    90:  data['q90_obito']                   || data['obito'],
    91:  data['q91_dataDo']                  || data['dataDo'],
    95:  data['q95_idade']                   || data['idade'],
    97:  data['q97_gestante']                || data['gestante'],
    98:  data['q98_lactante']                || data['lactante'],
    99:  data['q99_complementoScih']         || data['complementoScih'],
    107: data['q107_prontuario']             || data['prontuario'],
    111: data['q111_classificacaoDe']        || data['classificacaoDe'],
    113: data['q113_dataDe113']              || data['dataDe113'],
    116: data['q116_sitioDe']               || data['sitioDe'],
    117: data['q117_sitioDe117']             || data['sitioDe117'],
    118: data['q118_sitioDe118']             || data['sitioDe118'],
    141: data['q141_sofa_renal2']            || data['sofa_renal2'],
    142: data['q142_sofa']                   || data['sofa'],
    151: data['q151_insiraUma151']           || data['insiraUma151'],
    152: data['q152_seraPrescrita']          || data['seraPrescrita'],
    164: data['q164_haEsquema']              || data['haEsquema'],
  };

  const answers = {};
  for (const [qid, answer] of Object.entries(qidMap)) {
    if (answer !== undefined && answer !== null) {
      answers[qid] = { answer };
    }
  }
  return answers;
}

// ── Parser do formulário React próprio ───────────────────────────────────

export function parseFormPayload(d, inst = null) {
  const toB = v => v === 'Sim' ? true : v === 'Não' ? false : null;
  const toD = v => v || null;
  const toN = v => v !== '' && v != null ? parseFloat(v) : null;

  const GLASGOW  = ['15','13-14','10-12','6-9','< 6','Não avaliado'];
  const PAM_OPTS = [
    'PAM > 70 (sem DVA)','PAM < 70 (sem DVA)',
    'Em uso de Dopamina ≤ 5 µg/kg/min ou qualquer dose de Dobutamina',
    'Em uso de Dopamina > 5 ou Noradrenalina ≤ 0,1 µg/kg/min',
    'Em uso de Dopamina > 15 ou Noradrenalina > 0,1 µg/kg/min',
  ];
  const PLAQ    = ['≥ 150 mil','100–149 mil','50–99 mil','20–49 mil','< 20 mil','Não disponível'];
  const BILI    = ['< 1,2','1,2–1,9','2,0–5,9','6,0–11,9','≥ 12,0','Não disponível'];
  const CREAT   = ['< 1,2','1,2–1,9','2,0–3,4','3,5–4,9','≥ 5,0','Não disponível'];
  const DIURESE = ['> 500ml','< 500ml','< 200ml','Não mensurada'];
  const SPO2_AA = ['≥ 97%','95–96%','92–94%','< 92%'];
  const SPO2_O2 = ['≥ 95%','92–94%','< 92%'];
  const PF      = ['≥ 400','300–399','200–299','100–199','< 100'];

  const gl_sc  = [0,1,2,3,4,0][GLASGOW.indexOf(d.sofa_glasgow)]  ?? 0;
  const pam_sc = [0,1,2,3,4][PAM_OPTS.indexOf(d.sofa_pam)]       ?? 0;
  const plq_sc = [0,1,2,3,4,0][PLAQ.indexOf(d.sofa_plaq)]        ?? 0;
  const bil_sc = [0,1,2,3,4,0][BILI.indexOf(d.sofa_bili)]        ?? 0;
  const cre_sc = [0,1,2,3,4,0][CREAT.indexOf(d.sofa_creat)]      ?? 0;
  const dur_sc = [0,1,2,0][DIURESE.indexOf(d.sofa_diurese)]      ?? 0;
  let resp_sc  = 0;
  if (d.sofa_suporte === 'Ar ambiente')
    resp_sc = [0,1,2,3][SPO2_AA.indexOf(d.sofa_spo2_aa)] ?? 0;
  else if (d.sofa_suporte === 'Oxigênio suplementar (cateter/máscara)')
    resp_sc = [1,2,3][SPO2_O2.indexOf(d.sofa_spo2_o2)] ?? 0;
  else if (d.sofa_suporte === 'VNI ou Ventilação Mecânica (VM)')
    resp_sc = [0,1,2,3,4][PF.indexOf(d.sofa_pf)] ?? 0;

  const sofa_renal = Math.max(cre_sc, dur_sc);
  const sofa       = gl_sc + resp_sc + pam_sc + plq_sc + bil_sc + sofa_renal;

  const paciente_nome_raw = [d.pac_nome, d.pac_sobrenome].filter(Boolean).join(' ');
  const paciente_idade    = d.pac_dn
    ? String(Math.floor((new Date() - new Date(d.pac_dn)) / 31557600000))
    : null;

  const pron = String(d.prontuario || '').replace(/\D/g, '') || null; // prontuário: só dígitos
  const dn   = toD(d.pac_dn);
  const link_exames = montarLinkExames(pron, dn);
  // link_labs (localhost:3000) é o buscador LIS do HUSF — não gravar em fichas
  // SCMI, cujo botão de labs é renderizado dinamicamente (atb-lab-scmi.js).
  // Sem tenant informado (healthcheck, chamadas legadas) mantém o comportamento antigo.
  const link_labs = (paciente_nome_raw && (!inst || inst === 'HUSF'))
    ? `http://localhost:3000/api/buscar?nome=${String(paciente_nome_raw).trim().replace(/\s+/g,"+")}`
    : null;

  return {
    paciente_nome:          paciente_nome_raw,
    paciente_nome_raw,
    paciente_dn:            dn,
    paciente_idade,
    prontuario:             pron,
    atendimento:            d.atendimento   || null,
    setor:                  d.setor         || null,
    leito:                  d.leito         || null,
    equipe_responsavel:     d.equipe        || null,
    data_internacao:        toD(d.data_internacao),
    data_admissao_uti:      toD(d.data_uti),
    tipo_terapia:           d.tipo_terapia  || null,
    historia_clinica:       d.historia_clinica      || null,
    cirurgia:               d.cirurgia      || null,
    foco_infeccao:          d.foco_infeccao         || null,
    sepse:                  toB(d.sepse),
    gestante:               toB(d.gestante),
    lactante:               toB(d.lactante),
    comorbidades:           d.comorbidades  || [],
    uso_atb_7d:             toB(d.uso_atb_7d),
    atb_previos:            d.atb_previos   || [],
    culturas_colhidas:      d.culturas_colhidas || {},
    culturas_previas:       d.culturas_previas  || [],
    dispositivos_invasivos: d.dispositivos_invasivos || [],
    dialise:                toB(d.dialise),
    acesso_dialise:         d.acesso_dialise || null,
    sinais_dialise:         d.sinais_dialise || null,
    data_insercao_cateter:  toD(d.data_insercao_cateter),
    sitio_cvc:              d.sitio_cvc     || [],
    sitio_cdl:              d.sitio_cdl     || [],
    sitio_pai:              d.sitio_pai     || [],
    peso_nascimento:        toN(d.peso_nascimento),
    acesso_vascular_neo:    d.acesso_vascular_neo   || [],
    insuficiencia_renal:    d.insuficiencia_renal   || [],
    clcr:                   toN(d.clcr),
    peso:                   toN(d.peso),
    altura:                 toN(d.altura),
    faz_quimio:             toB(d.faz_quimio),
    cateter_quimio:         toB(d.cateter_quimio),
    acesso_quimio:          d.acesso_quimio || null,
    classificacao_fratura:  d.classificacao_fratura || null,
    atb_solicitado:         d.atb_solicitado || [],
    posologia:              d.posologia     || [],
    tempo_previsto:         toN(d.tempo_previsto),
    oxacilina_associacao:   toB(d.oxacilina_associacao),
    crm:                    d.crm           || null,
    prescritor_nome:        d.prescritor_nome || null,
    sofa:                   sofa            || null,
    sofa_renal:             sofa_renal      || null,
    link_exames,
    link_labs,
  };
}
