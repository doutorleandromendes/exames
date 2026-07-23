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
             setores: ['utiAB', 'utic'], familia: 'iras', limiar: 'totMax', limiarMin: 'totMin',
             sin: ['total', 'taxa total', 'iras total', 'infeccao total', 'global do setor'] },
  taxaIH:  { rotulo: 'Taxa de infecção hospitalar', unidade: '%',
             setores: ['global', 'clinicaMedica', 'clinicaCirurgica', 'epm'], familia: 'iras',
             sin: ['taxa ih', 'taxa de infeccao', 'infeccao hospitalar', 'taxa de ih'] },
  // -------- uso de dispositivos (família 'iras') ---------------------------
  svd:     { rotulo: 'Utilização de SVD', unidade: '%', setores: ['utiAB', 'utic'],
             familia: 'iras', limiar: 'svdMax', limiarMin: 'svdMin', sin: ['svd', 'sonda vesical', 'uso de sonda'] },
  cvc:     { rotulo: 'Utilização de CVC', unidade: '%', setores: ['utiAB', 'utic'],
             familia: 'iras', limiar: 'cvcMax', limiarMin: 'cvcMin', sin: ['cvc', 'cateter central', 'uso de cateter'] },
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
              setores: ['utiAB', 'utic'], familia: 'dot', chaveStats: 'pip', limiar: 'pipMax', limiarMin: 'pipMin',
              sin: ['pipe', 'piperacilina', 'tazo', 'tazocin'] },
  dddCarba: { rotulo: 'Consumo de carbapenêmicos', unidade: 'DDD/1000 pac-dia',
              setores: ['utiAB', 'utic'], familia: 'dot', chaveStats: 'cbp', limiar: 'carbaMax', limiarMin: 'carbaMin',
              sin: ['carbapenemico', 'carbapenem', 'meropenem', 'meropenem'] },
  dddGlico: { rotulo: 'Consumo de glicopeptídeos', unidade: 'DDD/1000 pac-dia',
              setores: ['utiAB', 'utic'], familia: 'dot', chaveStats: 'gpp', limiar: 'glicoMax', limiarMin: 'glicoMin',
              sin: ['glicopeptideo', 'vancomicina', 'vanco', 'teico'] },
  dddPoli:  { rotulo: 'Consumo de polimixinas', unidade: 'DDD/1000 pac-dia',
              setores: ['utiAB', 'utic'], familia: 'dot', chaveStats: 'pb', limiar: 'poliMax', limiarMin: 'poliMin',
              sin: ['polimixina', 'poli', 'colistina'] },
};

// ── Âncoras estatísticas disponíveis por família ────────────────────────────
// Metodologia conforme as NOTAS METODOLÓGICAS do próprio painel do SCIH.
// (Correção importante: as taxas de IRAS TÊM modelo estatístico — os limiares
// são o intervalo de predição de 95% de uma regressão, não um corte arbitrário.)
export const ANCORAS = {
  iras: {
    testeSignificancia: true,
    metodo: 'Regressão multivariada binomial negativa ou de Poisson (conforme a frequência de desfechos). Os limiares mínimo e máximo são o INTERVALO DE PREDIÇÃO DE 95% do modelo ajustado sobre a série histórica. Endemicidade global e HD: teste binomial exato de Clopper-Pearson, com limiar pelo IC95% sobre biênio de referência.',
    classificacao: 'Endêmico = dentro dos limiares previstos pelo modelo. Alerta supraendêmico = acima do limiar máximo. Atividade excepcional = aumento sustentado por ≥3 competências consecutivas acima do limiar.',
    regra: 'A leitura correta é POSICIONAL, contra o modelo: compare o valor com o limiar previsto (IP95%) e use a classificação de status. Valor dentro dos limiares = variação compatível com o previsto (NÃO é aumento real). Acima do limiar máximo = alerta supraendêmico. Não use Mann-Kendall aqui: a tendência destas séries é avaliada pelo modelo de predição, não por teste de tendência monotônica.',
  },
  mdr: {
    testeSignificancia: true,
    metodo: 'Regressão multivariada de Poisson com teste de tendência de Cochran-Armitage; limiar de endemicidade por Clopper-Pearson sobre biênio base. Complementarmente: Mann-Kendall mensal, CUSUM e IC-Poisson.',
    regra: 'Use o veredito do Mann-Kendall (tendencia + sig + p) quando presente e, se houver, o IC-Poisson. Se sig=false, diga explicitamente que a tendência NÃO é estatisticamente significativa.',
  },
  dot: {
    testeSignificancia: true,
    metodo: 'Mann-Kendall e joinpoint sobre a série mensal de consumo; limiares por intervalo de predição de 95% do modelo de regressão.',
    regra: 'Use o veredito do Mann-Kendall (tendencia + sig + p). Se sig=false, diga explicitamente que a tendência NÃO é estatisticamente significativa. Compare também o valor com o limiar previsto.',
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
  return `Você é o assistente de vigilância epidemiológica do SCIH conversando com um profissional da equipe. Você recebe DADOS JÁ RESOLVIDOS (valores reais dos indicadores) e responde à pergunta de forma direta e conversacional — como um colega competente responderia, não como um relatório.

TOM — escreva como um colega experiente responde de viva-voz, não como um relatório:
- Primeira frase = a resposta. "Não." / "Sim, e vale olhar." / "Não dá pra afirmar."
- Frases CURTAS e diretas. Uma ideia por frase.
- Cite o número que sustenta a conclusão, incluindo o LIMIAR quando existir — a comparação "valor contra teto" é a informação, não um detalhe. Diga "13,05 contra um teto de 24,93", não "dentro do previsto".
- NÃO repita o enunciado da pergunta na resposta.
- Máximo 3 frases. Sem listas.

PROIBIDO (soa a relatório): "considerando que", "além disso", "o que reforça a ideia de que",
"o que é compatível com", "vale ressaltar", "cabe destacar", "em suma", "de modo geral".

EXEMPLO RUIM (não faça):
"Não, não há sinal de aumento nas infecções de cateter na UTI AB em 2026, considerando que os
valores estão dentro do previsto pelo modelo, com a última leitura em junho sendo de 13,05 por
1000 CVC-dia, o que é compatível com o esperado. Além disso, não há meses consecutivos acima
do limiar máximo, o que reforça a ideia de que a situação está dentro do controle esperado."

EXEMPLO BOM (faça assim):
"Não. A IPCS ficou dentro da faixa prevista o ano todo — junho fechou em 13,05/1000 CVC-dia,
bem abaixo do teto de 24,93. Nenhum mês de 2026 estourou o limiar."

COMO LER A ESTATÍSTICA (inviolável — a resposta tem que ser fiel ao método):
- Os limiares (limiarMax/limiarMin) NÃO são cortes arbitrários: são o intervalo de predição de 95% de um modelo de regressão (binomial negativa ou Poisson) ajustado sobre a série histórica. Estar dentro deles significa "compatível com o previsto".
- Use o campo "avaliacaoLimiar" já calculado: posicao ("dentro"/"acima"/"abaixo") e mesesAcimaConsecutivos.
  · dentro → a variação é compatível com o previsto pelo modelo. NÃO chame isso de aumento real.
  · acima do limiar máximo → alerta supraendêmico.
  · ≥3 competências consecutivas acima → atividade excepcional.
- Quando houver "veredito" de Mann-Kendall (MDR/consumo), use-o: se sig=false, diga explicitamente que a tendência não é estatisticamente significativa.
- Nunca calcule estatística por conta própria, nunca invente número, nunca contrarie a classificação de status.

OUTRAS REGRAS:
- Use APENAS os números dos DADOS. Cite a unidade quando o número for o ponto da frase.
- Nunca dê conselho clínico nem recomende conduta.
- Se faltar dado, diga o que falta em vez de preencher a lacuna.`;
}
