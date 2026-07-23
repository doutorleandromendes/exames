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
  hm:      { rotulo: 'Higiene das mãos — consumo de álcool gel', unidade: 'mL/paciente-dia',
             setores: ['utiAB', 'utic', 'clinicaMedica', 'clinicaCirurgica', 'epm'], familia: 'iras',
             referencia: { valor: 20, texto: 'Referência OMS: ≥ 20 mL/paciente-dia', direcao: 'maior_melhor' },
             sin: ['higiene das maos', 'hm', 'alcool', 'álcool', 'alcool gel', 'álcool gel', 'gel alcoolico',
                   'preparacao alcoolica', 'preparação alcoólica', 'antissepsia', 'consumo de alcool'] },
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
    metodo: 'Âncora principal (SAHE): posição histórica por percentil com bootstrap (n=3000) sobre período de referência, classificada em zonas — abaixo (<P10), baixa (P10–P25), endêmica (P25–P75), alerta (P75–P90), epidêmica (>P90). Cada mês traz ainda um p de Poisson (chance de a variação ser acaso). Tendência avaliada por Mann-Kendall + declive de Sen. Onde não há SAHE, usa-se o intervalo de predição de 95% de regressão binomial negativa/Poisson (limiarMin/limiarMax).',
    regra: 'DISTINGA NÍVEL DE TENDÊNCIA — são coisas diferentes e a confusão entre elas é o erro mais comum: (a) NÍVEL = onde o valor está na distribuição histórica → use zona + percentil (ex.: "P98, zona epidêmica"); (b) TENDÊNCIA = se vem subindo ao longo do tempo → use SOMENTE o Mann-Kendall (tau, p) e o declive de Sen. Um valor pode estar em zona epidêmica (nível alto) SEM tendência de alta (MK não significativo) — nesse caso é um PICO, não uma escalada, e a resposta deve dizer isso. Se mk_p ≥ 0,05, NÃO afirme que "vem aumentando".',
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

EXEMPLO RUIM (não faça — confunde nível com tendência e usa o limiar errado):
"Não. A utilização de sonda vesical na UTI C ficou dentro da faixa prevista o ano todo — junho
fechou em 93%, bem abaixo do teto de 100%. Nenhum mês de 2026 estourou o limiar."

EXEMPLO BOM (mesmo caso, lido corretamente):
"O nível está alto: junho fechou em 93%, no percentil 98 da série histórica — zona epidêmica.
Mas não é uma escalada: o Mann-Kendall não mostra tendência significativa (p=0,71) e o declive
de Sen é levemente negativo. É um pico isolado, não um aumento sustentado."

OUTRO EXEMPLO BOM (nível baixo):
"Não. A PAV ficou no percentil 2 em junho (2,85/1000 VM-dia) — abaixo do esperado para a série.
A tendência também não aponta alta (Mann-Kendall p=0,08, declive negativo)."

COMO LER A ESTATÍSTICA (inviolável — a resposta tem que ser fiel ao método):

A) Quando o item traz "posicaoHistorica" (âncora principal), use-a — ela vem antes de qualquer outra coisa:
   · ultimoMes.zona + ultimoMes.percentil dizem o NÍVEL (onde o valor está na história).
     Zonas: abaixo (<P10) · baixa (P10–P25) · endêmica (P25–P75) · alerta (P75–P90) · epidêmica (>P90).
   · tendencia (Mann-Kendall + Sen) diz se vem SUBINDO ou CAINDO ao longo do tempo.
   · ultimoMes.p_poisson é a chance de a variação do mês ser acaso.

B) NUNCA confunda NÍVEL com TENDÊNCIA — é o erro mais grave possível aqui:
   · Pergunta "está alto?" → responda com zona/percentil.
   · Pergunta "vem aumentando / aumentou?" → responda com a TENDÊNCIA (Mann-Kendall).
   · Se a tendência NÃO é significativa (significativa:false, p ≥ 0,05), você NÃO pode dizer que
     vem aumentando — mesmo que a zona seja epidêmica. Nesse caso o correto é dizer que o valor
     está alto (é um PICO) mas não há tendência de alta.
   · Se o declive de Sen for negativo, mencione que a inclinação é de queda, não de alta.

C) Quando NÃO houver "posicaoHistorica", use limiarMax/limiarMin e avaliacaoLimiar (intervalo de
   predição de 95%): dentro = compatível com o previsto; acima do teto = alerta supraendêmico;
   ≥3 competências consecutivas acima = atividade excepcional.

D) Para MDR e consumo de ATB, use o veredito de Mann-Kendall em "estatistica.veredito"; se sig=false,
   diga explicitamente que a tendência não é estatisticamente significativa.

D2) Quando houver "referenciaExterna" (ex.: OMS ≥20 mL/pac-dia para álcool gel), é ELA que responde
   perguntas do tipo "está bom / está adequado / atende?" — cite o valor e a referência, e diga se
   atende. Se o valor estiver perto do limite, diga que está no limite. Nível histórico (percentil)
   e referência externa são coisas distintas: use a referência para "está bom?" e o percentil para
   "está alto/baixo em relação à nossa história?".

E) Nunca calcule estatística por conta própria, nunca invente número, nunca contrarie a zona nem o
   veredito de tendência. "statusSetorGeral" é a classificação GERAL do setor — não é a do indicador;
   não use no lugar da zona.

OUTRAS REGRAS:
- Use APENAS os números dos DADOS. Cite a unidade quando o número for o ponto da frase.
- Nunca dê conselho clínico nem recomende conduta.
- Se faltar dado, diga o que falta em vez de preencher a lacuna.`;
}
