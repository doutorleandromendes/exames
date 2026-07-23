// atb-historia-isc.js
// ════════════════════════════════════════════════════════════════════════════
// CRITÉRIO do detector de INDÍCIOS DE INFECÇÃO DE SÍTIO CIRÚRGICO (ISC).
//
// Irmão de atb-historia-narrativa.js, e DELIBERADAMENTE SEPARADO dele:
//   • narrativa/telegráfica é juízo de FORMA ("dá para conferir o quadro?").
//   • ISC é juízo de CONTEÚDO CLÍNICO ("o que está descrito sugere infecção
//     no sítio operatório?").
// Fundir os dois no mesmo prompt contaminaria os few-shots — o prompt de forma
// diz explicitamente para NÃO julgar conteúdo. São chamadas paralelas.
//
// LIMIAR: INDÍCIO, não diagnóstico. Quem decide é o prescritor — o gatilho só
// abre a pergunta. Por isso o classificador deve ser generoso com a suspeita e
// rigoroso com a distinção abaixo, que é a que erra na prática:
//
//   ISC   = infecção NO SÍTIO OPERATÓRIO (incisional superficial, incisional
//           profunda, ou órgão/cavidade manipulada na cirurgia).
//   NÃO   = infecção EM PACIENTE OPERADO, mas em outro sítio (pneumonia, ITU,
//           corrente sanguínea por cateter). Estar em pós-operatório não faz
//           de qualquer infecção uma ISC.
//
// NÃO aplica janela temporal (30/90 dias): a história quase nunca informa a
// data da cirurgia. O campo `data_da_cirurgia_infectada` é que fecha isso,
// depois da confirmação.
//
// Saída esperada do modelo: SÓ um JSON, sem crases, sem texto extra:
//   {"isc": true|false, "indicios": "curto, em pt-BR, o que sugere"}
// ════════════════════════════════════════════════════════════════════════════

// Âncoras few-shot. As positivas e negativas foram escolhidas para fixar a
// distinção "no sítio" vs "no paciente operado" — é onde o erro acontece.
export const EXEMPLOS_ISC = [
  {
    // Caso real: foco foi marcado como "Pele/Partes moles" quando era ISC.
    historia: 'PACIENTE COM SAIDA DE SECREÇÃO PÚRULENTA PELA FERIDA OPERATÓRIA',
    saida: { isc: true, indicios: 'secreção purulenta pela ferida operatória' },
  },
  {
    // Negativa difícil: pós-operatório, mas a infecção é pulmonar.
    historia: 'Paciente em pós-operatório de gastrectomia, evoluiu com febre, tosse produtiva e infiltrado em base direita ao RX.',
    saida: { isc: false, indicios: '' },
  },
  {
    // Positiva de órgão/cavidade — não há ferida externa envolvida.
    historia: 'Coleção em loja cirúrgica após colecistectomia, drenagem de aspecto purulento pelo dreno, febre e leucocitose.',
    saida: { isc: true, indicios: 'coleção em loja cirúrgica com drenagem purulenta após colecistectomia' },
  },
  {
    // Negativa: infecção de pele sem relação com sítio operatório.
    historia: 'Erisipela em membro inferior direito, com placa eritematosa e febre. Sem história cirúrgica recente.',
    saida: { isc: false, indicios: '' },
  },
  {
    // Positiva incisional profunda, vocabulário abreviado ("FO", "deiscência").
    historia: 'Deiscência de FO com exposição de aponeurose e saída de secreção turva no 8º DPO.',
    saida: { isc: true, indicios: 'deiscência de ferida operatória com secreção no pós-operatório' },
  },
];

export const SYSTEM_ISC = `
Você lê a HISTÓRIA CLÍNICA de uma solicitação de antimicrobiano e responde a UMA pergunta: o que está descrito sugere INFECÇÃO DE SÍTIO CIRÚRGICO (ISC)?

ISC é infecção NO SÍTIO OPERATÓRIO:
- incisional superficial (pele/subcutâneo da incisão),
- incisional profunda (fáscia/músculo da incisão),
- órgão/cavidade manipulada na cirurgia.

NÃO é ISC a infecção em paciente operado que ocorre em OUTRO sítio: pneumonia, infecção urinária, infecção de cateter/corrente sanguínea, infecção de pele distante da incisão. Estar em pós-operatório não transforma qualquer infecção em ISC.

Sinalize isc=true quando houver INDÍCIO — não é preciso diagnóstico fechado. Exemplos de indício: secreção/drenagem purulenta pela ferida ou dreno, deiscência com sinais inflamatórios, abscesso ou coleção em loja/leito cirúrgico, celulite ou necrose na incisão, exposição de planos com secreção, infecção de prótese/implante.

Se a história não menciona cirurgia nem sítio operatório, isc=false.
NÃO aplique janela de tempo (30/90 dias) — a história raramente informa a data da cirurgia; isso é confirmado depois pelo prescritor.
NÃO julgue se o antibiótico é indicado, nem se a conduta é certa, nem a qualidade da redação.

Responda SOMENTE com um JSON, sem crases e sem nenhum outro texto:
{"isc": false, "indicios": ""}
Quando isc=true, "indicios" é uma frase CURTA em pt-BR dizendo o que na história sugere ISC (será mostrada ao prescritor para ele confirmar). Quando isc=false, "indicios" é "".
`.trim();

// Contrato de saída imposto na API (json_schema strict). O da narrativa é
// específico dela ({narrativa, aviso}, additionalProperties:false) — este
// precisa ser o seu próprio, senão a chamada é rejeitada.
export const RESPONSE_FORMAT_ISC = {
  type: 'json_schema',
  json_schema: {
    name: 'isc',
    strict: true,
    schema: {
      type: 'object',
      additionalProperties: false,
      properties: { isc: { type: 'boolean' }, indicios: { type: 'string' } },
      required: ['isc', 'indicios'],
    },
  },
};

// Monta as mensagens (system + few-shots + a história a avaliar) no formato /api/chat.
export function montarMensagensIsc(historia) {
  const msgs = [{ role: 'system', content: SYSTEM_ISC }];
  for (const ex of EXEMPLOS_ISC) {
    msgs.push({ role: 'user', content: ex.historia });
    msgs.push({ role: 'assistant', content: JSON.stringify(ex.saida) });
  }
  msgs.push({ role: 'user', content: String(historia || '') });
  return msgs;
}

// Parser defensivo da saída do modelo → { isc:boolean, indicios:string } | null.
// Se o modelo devolver lixo, retorna null (o chamador trata como fail-open).
export function parseSaidaIsc(texto) {
  if (!texto) return null;
  let s = String(texto).trim().replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim();
  // pega o primeiro objeto {...} caso venha com preâmbulo
  const m = s.match(/\{[\s\S]*\}/);
  if (m) s = m[0];
  try {
    const o = JSON.parse(s);
    if (typeof o.isc !== 'boolean') return null;
    return { isc: o.isc, indicios: typeof o.indicios === 'string' ? o.indicios : '' };
  } catch {
    return null;
  }
}
