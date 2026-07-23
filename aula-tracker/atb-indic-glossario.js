// atb-indic-glossario.js
// ════════════════════════════════════════════════════════════════════════════
// Glossário dos INDICADORES do SCIH (dashboards públicos scih.lcmendes.med.br).
//
// Papel: traduzir pergunta em português → LOCALIZADOR estruturado
//        { setor, indicador, periodo }
// O modelo NÃO calcula nada e NÃO interpreta números crus: ele só localiza.
// O resolvedor (determinístico) extrai o valor real + a âncora estatística.
//
// ANCORAGEM (o ponto crítico anti-delírio) — o que existe por família:
//   • Taxas de IRAS (pav/itu/ipcs/taxaIH/tot…): NÃO há teste de significância.
//     Âncoras disponíveis: `limiares` (limiar de endemicidade) e `status`
//     (classificação endêmica já calculada). Tendência só pode ser descrita
//     como comparação com o limiar/série — NUNCA como "aumento significativo".
//   • MDR (esbl/kpc/acin): há Mann-Kendall, joinpoint, CUSUM e IC-Poisson.
//   • DOT (consumo de ATB): há Mann-Kendall e joinpoint.
// ════════════════════════════════════════════════════════════════════════════

// ── Setores ─────────────────────────────────────────────────────────────────
// chave no JSON → { rotulo, sinonimos }
export const SETORES = {
  global:            { rotulo: 'Institucional (global)', sin: ['global', 'institucional', 'hospital', 'geral', 'husf'] },
  clinicaMedica:     { rotulo: 'Clínica Médica',         sin: ['clinica medica', 'cm', 'médica'] },
  clinicaCirurgica:  { rotulo: 'Clínica Cirúrgica',      sin: ['clinica cirurgica', 'cc', 'cirúrgica'] },
  epm:               { rotulo: 'EPM',                    sin: ['epm', 'pediatria', 'materno'] },
  hd:                { rotulo: 'Hemodiálise',            sin: ['hd', 'hemodialise', 'dialise', 'nefrologia'] },
  utiAB:             { rotulo: 'UTI A/B (adulto)',       sin: ['uti ab', 'utiab', 'uti a', 'uti b', 'uti adulto'] },
  utic:              { rotulo: 'UTI C (adulto)',         sin: ['uti c', 'utic'] },
  utiNeo:            { rotulo: 'UTI Neonatal',           sin: ['uti neo', 'utineo', 'neonatal', 'neo', 'utin'] },
  isc:               { rotulo: 'ISC (cirúrgicas)',       sin: ['isc', 'sitio cirurgico', 'ferida operatoria'] },
};

// "UTI adulto" sem especificar = as duas unidades adultas.
export const GRUPOS_SETOR = {
  utiAdulto: ['utiAB', 'utic'],
  uti:       ['utiAB', 'utic', 'utiNeo'],
  clinicas:  ['clinicaMedica', 'clinicaCirurgica'],
};

// ── Indicadores por setor ───────────────────────────────────────────────────
// chave → { rotulo, unidade, setores, familia }
// familia decide QUAL âncora estatística existe (ver ANCORAS).
export const INDICADORES = {
  // -------- taxas de IRAS (família 'iras': sem teste de significância) ------
  pav:     { rotulo: 'PAV (pneumonia associada à VM)', unidade: '/1000 VM-dia',
             setores: ['utiAB', 'utic'], familia: 'iras', limiar: 'pavMax',
             sin: ['pav', 'pneumonia', 'pneumonia associada', 'pneumonia ventilador', 'vap'] },
  itu:     { rotulo: 'ITU relacionada a SVD', unidade: '/1000 SVD-dia',
             setores: ['utiAB', 'utic'], familia: 'iras', limiar: 'ituMax',
             sin: ['itu', 'infeccao urinaria', 'urinaria', 'trato urinario', 'svd'] },
  ipcs:    { rotulo: 'IPCS (infecção primária de corrente sanguínea)', unidade: '/1000 CVC-dia',
             setores: ['utiAB', 'utic', 'utiNeo'], familia: 'iras', limiar: 'ipcsMax',
             sin: ['ipcs', 'corrente sanguinea', 'bacteremia', 'infeccao de cateter', 'icsl', 'primaria'] },
  tot:     { rotulo: 'Taxa global de IRAS do setor', unidade: '/1000 pacientes-dia',
             setores: ['utiAB', 'utic'], familia: 'iras', limiar: 'totMax',
             sin: ['total', 'taxa total', 'iras total', 'infeccao total', 'global do setor'] },
  taxaIH:  { rotulo: 'Taxa de infecção hospitalar', unidade: '%',
             setores: ['global', 'clinicaMedica', 'clinicaCirurgica', 'epm'], familia: 'iras',
             sin: ['taxa ih', 'taxa de infeccao', 'infeccao hospitalar', 'taxa de ih'] },
  // -------- uso de dispositivos (família 'iras') ---------------------------
  svd:     { rotulo: 'Utilização de SVD', unidade: '%', setores: ['utiAB', 'utic'],
             familia: 'iras', limiar: 'svdMax', sin: ['svd', 'sonda vesical', 'uso de sonda'] },
  cvc:     { rotulo: 'Utilização de CVC', unidade: '%', setores: ['utiAB', 'utic'],
             familia: 'iras', limiar: 'cvcMax', sin: ['cvc', 'cateter central', 'uso de cateter'] },
  hm:      { rotulo: 'Adesão à higiene das mãos', unidade: '%',
             setores: ['utiAB', 'utic', 'clinicaMedica', 'clinicaCirurgica', 'epm'], familia: 'iras',
             sin: ['higiene das maos', 'hm', 'lavagem de maos', 'adesao higiene'] },
  // -------- séries mensais das clínicas (infSeries) ------------------------
  infSeries: { rotulo: 'Infecções por mês (por topografia)', unidade: 'casos',
             setores: ['clinicaMedica', 'clinicaCirurgica', 'epm'], familia: 'iras',
             sin: ['infeccoes por mes', 'casos por mes', 'serie mensal'] },
  // -------- MDR (família 'mdr': TEM Mann-Kendall/CUSUM/IC-Poisson) ---------
  mdr:     { rotulo: 'Microrganismos multirresistentes', unidade: '/1000 pacientes-dia',
             setores: ['utiAB', 'utic'], familia: 'mdr',
             sin: ['mdr', 'multirresistente', 'multirresistencia', 'kpc', 'esbl', 'acinetobacter', 'resistencia'] },
  // -------- DOT (família 'dot': TEM Mann-Kendall/joinpoint) ----------------
  dddPip:   { rotulo: 'Consumo de piperacilina-tazobactam', unidade: 'DDD/1000 pac-dia',
              setores: ['utiAB', 'utic'], familia: 'dot', chaveStats: 'pip', limiar: 'pipMax',
              sin: ['pipe', 'piperacilina', 'tazo', 'tazocin'] },
  dddCarba: { rotulo: 'Consumo de carbapenêmicos', unidade: 'DDD/1000 pac-dia',
              setores: ['utiAB', 'utic'], familia: 'dot', chaveStats: 'cbp', limiar: 'carbaMax',
              sin: ['carbapenemico', 'carbapenem', 'meropenem', 'meropenem'] },
  dddGlico: { rotulo: 'Consumo de glicopeptídeos', unidade: 'DDD/1000 pac-dia',
              setores: ['utiAB', 'utic'], familia: 'dot', chaveStats: 'gpp', limiar: 'glicoMax',
              sin: ['glicopeptideo', 'vancomicina', 'vanco', 'teico'] },
  dddPoli:  { rotulo: 'Consumo de polimixinas', unidade: 'DDD/1000 pac-dia',
              setores: ['utiAB', 'utic'], familia: 'dot', chaveStats: 'pb', limiar: 'poliMax',
              sin: ['polimixina', 'poli', 'colistina'] },
};

// ── Âncoras estatísticas disponíveis por família ────────────────────────────
// É o mapa que impede o modelo de afirmar tendência onde não há teste.
export const ANCORAS = {
  iras: {
    testeSignificancia: false,
    disponivel: ['limiar de endemicidade (limiares)', 'classificação endêmica (status)', 'série histórica'],
    regra: 'NÃO existe teste de significância para taxas de IRAS. Descreva o valor, compare com o limiar de endemicidade e cite o status. NUNCA afirme "aumento/queda significativa" nem "tendência estatística".',
  },
  mdr: {
    testeSignificancia: true,
    disponivel: ['Mann-Kendall (mdr_mensal)', 'joinpoint', 'CUSUM', 'IC-Poisson 2026'],
    regra: 'Use o veredito do Mann-Kendall (tendencia + sig + p). Se sig=false, diga explicitamente que a tendência NÃO é estatisticamente significativa.',
  },
  dot: {
    testeSignificancia: true,
    disponivel: ['Mann-Kendall (dot_mensal_por_par / dot_institucional)', 'joinpoint'],
    regra: 'Use o veredito do Mann-Kendall (tendencia + sig + p). Se sig=false, diga explicitamente que a tendência NÃO é estatisticamente significativa.',
  },
};

// ── Prompt do passo 1 (localizar) ───────────────────────────────────────────
export function promptLocalizador() {
  const setores = Object.entries(SETORES)
    .map(([k, v]) => `  ${k} = ${v.rotulo} (sinônimos: ${v.sin.join(', ')})`).join('\n');
  const indics = Object.entries(INDICADORES)
    .map(([k, v]) => `  ${k} = ${v.rotulo} [${v.unidade}] · setores: ${v.setores.join('|')} · sinônimos: ${v.sin.join(', ')}`).join('\n');
  return `Você converte uma pergunta em português sobre indicadores de controle de infecção (SCIH/HUSF) em um LOCALIZADOR JSON. Você NÃO responde a pergunta, NÃO calcula nada, NÃO interpreta números.

SETORES (use a chave exata):
${setores}

Grupos: "UTI adulto" (sem especificar) = ["utiAB","utic"]; "UTI" genérico = ["utiAB","utic","utiNeo"].

INDICADORES (use a chave exata):
${indics}

PERÍODOS: a série tem pontos ANUAIS ("2020".."2025") e MENSAIS ("jan/26","fev/26",...,"dez/26").
  - "em 2025" → {"tipo":"ponto","valor":"2025"}
  - "em junho de 2026"/"jun/26" → {"tipo":"ponto","valor":"jun/26"}
  - "primeiro semestre de 2026" → {"tipo":"intervalo","de":"jan/26","ate":"jun/26"}
  - "atual"/"agora"/"último"/sem período → {"tipo":"ultimo"}
  - "nos últimos tempos"/"recentemente"/"tendência" → {"tipo":"serie"} (série toda, p/ tendência)

RESPONDA APENAS com JSON válido, sem markdown, no formato:
{"setores":["utiAB"],"indicadores":["pav"],"periodo":{"tipo":"ultimo"},"intencao":"valor"}

"intencao": "valor" (quer um número) | "tendencia" (quer saber se subiu/caiu) | "comparacao" (comparar setores/períodos).

REGRA INVIOLÁVEL: se a pergunta mencionar algo que não está nas listas acima, devolva
{"erro":"não reconheci: <termo>"} — NUNCA invente chave de setor ou indicador.`;
}

// ── Prompt do passo 3 (verbalizar) — o anti-delírio ─────────────────────────
export function promptVerbalizador() {
  return `Você é um assistente de vigilância epidemiológica do SCIH. Você recebe DADOS JÁ RESOLVIDOS (valores reais extraídos dos indicadores) e responde à pergunta do usuário em português, de forma conversacional e concisa.

REGRAS INVIOLÁVEIS (violá-las é erro grave):
1. Use APENAS os números que estão nos DADOS. Nunca invente, estime ou recalcule valores.
2. Sobre TENDÊNCIA (aumento/queda/estável):
   - Se os DADOS trazem um teste estatístico (mann_kendall/cusum/ic_poisson), use o veredito dele.
     Se sig=false, diga EXPLICITAMENTE que a variação NÃO é estatisticamente significativa.
   - Se os DADOS dizem "sem teste de significância disponível", você NÃO pode afirmar que houve
     aumento ou queda real. Descreva os valores observados, compare com o limiar de endemicidade
     e com o status, e diga com franqueza que não há teste estatístico para essa série.
3. Nunca dê conselho clínico nem recomende conduta. Você descreve indicadores.
4. Se os DADOS estiverem vazios ou incompletos, diga o que falta — não preencha lacunas.
5. Cite sempre a unidade e o período dos números que usar.
6. Seja direto: 2 a 5 frases. Sem listas longas, sem preâmbulo.`;
}
