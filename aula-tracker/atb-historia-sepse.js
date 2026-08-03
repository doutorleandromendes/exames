// atb-historia-sepse.js
// ════════════════════════════════════════════════════════════════════════════
// CRITÉRIO do detector de INDÍCIOS DE SEPSE na história clínica.
//
// Irmão de atb-historia-narrativa.js e atb-historia-isc.js, e deliberadamente
// separado dos dois:
//   • narrativa  = juízo de FORMA ("dá para conferir o quadro?").
//   • ISC        = juízo de CONTEÚDO sobre o SÍTIO da infecção.
//   • sepse      = juízo de CONTEÚDO sobre a GRAVIDADE (há disfunção orgânica?).
// Cada um tem seus few-shots; fundir contaminaria os três.
//
// PARA QUE SERVE
// O prescritor marca "Sepse: Não" e descreve um quadro que sugere sepse. Isso
// tem consequência: o marcador de sepse governa regras de triagem e entra em
// indicador. O gatilho abre a pergunta no envio; quem decide é o prescritor.
//
// A DISTINÇÃO QUE ERRA NA PRÁTICA — e que os few-shots fixam:
//   SEPSE   = infecção COM disfunção orgânica (Sepsis-3). O que conta é a
//             disfunção: hipotensão/vasopressor, lactato alto, rebaixamento,
//             oligúria/elevação de creatinina, insuficiência respiratória,
//             plaquetopenia, necessidade de UTI pelo quadro infeccioso.
//   NÃO     = infecção SEM disfunção orgânica. Febre isolada, leucocitose
//             isolada, PCR alta, dor e eritema local — sinais de infecção e de
//             resposta inflamatória, não de sepse. Paciente grave por outro
//             motivo (pós-operatório, doença de base) também não é sepse.
//
// LIMIAR: INDÍCIO, não diagnóstico. Ser generoso com a suspeita e rigoroso com
// a distinção acima — o custo de perguntar é baixo, o de perder um caso é alto.
//
// Saída esperada do modelo: SÓ um JSON, sem crases, sem texto extra:
//   {"sepse": true|false, "indicios": "curto, em pt-BR, o que sugere"}
// ════════════════════════════════════════════════════════════════════════════

// Âncoras few-shot. Positivas e negativas escolhidas para fixar
// "infecção COM disfunção" vs "infecção SEM disfunção" — onde o erro acontece.
export const EXEMPLOS_SEPSE = [
  {
    // Disfunção hemodinâmica explícita: o caso mais claro.
    historia: 'PNEUMONIA ASPIRATIVA, EVOLUIU COM HIPOTENSÃO E NECESSIDADE DE NORADRENALINA EM UTI',
    saida: { sepse: true, indicios: 'hipotensão com necessidade de vasopressor' },
  },
  {
    // Disfunções múltiplas sem a palavra "sepse" escrita.
    historia: 'Paciente com ITU alta, evoluiu com rebaixamento do nível de consciência, oligúria e lactato de 4,2.',
    saida: { sepse: true, indicios: 'rebaixamento, oligúria e lactato elevado' },
  },
  {
    // NEGATIVA DIFÍCIL: infecção com febre e leucocitose, sem disfunção.
    historia: 'Pneumonia comunitária, febre 38,5°C, tosse produtiva, leucocitose de 18.000. Hemodinamicamente estável, em enfermaria.',
    saida: { sepse: false, indicios: '' },
  },
  {
    // NEGATIVA DIFÍCIL: infecção local exuberante, sem repercussão sistêmica.
    historia: 'CELULITE EXTENSA EM MEMBRO INFERIOR DIREITO COM DOR E ERITEMA IMPORTANTES, AFEBRIL, ESTAVEL',
    saida: { sepse: false, indicios: '' },
  },
  {
    // NEGATIVA DIFÍCIL: paciente grave, mas a gravidade não vem da infecção.
    historia: 'Politraumatizado em ventilação mecânica por TCE grave, em uso de droga vasoativa desde a admissão. Iniciado ATB por suspeita de infecção de trato urinário.',
    saida: { sepse: false, indicios: '' },
  },
  {
    // POSITIVA: disfunção respiratória atribuída ao quadro infeccioso.
    historia: 'Foco abdominal com peritonite, taquipneico, saturando mal, PA 80/50, transferido para UTI.',
    saida: { sepse: true, indicios: 'hipotensão e insuficiência respiratória no contexto de peritonite' },
  },
];

export const SYSTEM_SEPSE = `
Você lê a HISTÓRIA CLÍNICA de uma solicitação de antimicrobiano e responde a UMA pergunta: o que está descrito sugere SEPSE?

SEPSE (Sepsis-3) é infecção COM disfunção orgânica. O que caracteriza é a DISFUNÇÃO, não a infecção:
- hipotensão, choque, uso de vasopressor (noradrenalina, dopamina),
- lactato elevado,
- rebaixamento do nível de consciência, confusão aguda,
- oligúria, elevação aguda de creatinina, necessidade de diálise aguda,
- insuficiência respiratória, hipoxemia, necessidade de ventilação por causa do quadro infeccioso,
- plaquetopenia ou coagulopatia agudas,
- necessidade de UTI motivada pelo quadro infeccioso.

NÃO É SEPSE:
- infecção SEM disfunção orgânica, por mais exuberante que seja o quadro local;
- febre isolada, calafrios isolados, leucocitose isolada, PCR ou procalcitonina altas — são resposta inflamatória, não disfunção;
- paciente grave por OUTRO motivo (trauma, pós-operatório, doença de base) que recebe antibiótico — a gravidade precisa vir da infecção;
- profilaxia cirúrgica.

Sinalize sepse=true quando houver INDÍCIO de disfunção orgânica ligada à infecção — não é preciso diagnóstico fechado nem escore calculado. Na dúvida entre "infecção grave sem disfunção descrita" e "sepse", responda false: quem confirma é o prescritor.

NÃO julgue se o antibiótico é indicado, nem se a conduta é certa, nem a qualidade da redação.

Responda SOMENTE com um JSON, sem crases e sem nenhum outro texto:
{"sepse": false, "indicios": ""}
Quando sepse=true, "indicios" é uma frase CURTA em pt-BR dizendo o que na história sugere sepse (será mostrada ao prescritor para ele confirmar). Quando sepse=false, "indicios" é "".
`.trim();

// Contrato de saída imposto na API (json_schema strict). Cada classificador tem
// o seu — reaproveitar o do ISC faria a chamada ser rejeitada.
export const RESPONSE_FORMAT_SEPSE = {
  type: 'json_schema',
  json_schema: {
    name: 'sepse',
    strict: true,
    schema: {
      type: 'object',
      additionalProperties: false,
      properties: { sepse: { type: 'boolean' }, indicios: { type: 'string' } },
      required: ['sepse', 'indicios'],
    },
  },
};

// Monta as mensagens (system + few-shots + a história a avaliar) no formato /api/chat.
export function montarMensagensSepse(historia) {
  const msgs = [{ role: 'system', content: SYSTEM_SEPSE }];
  for (const ex of EXEMPLOS_SEPSE) {
    msgs.push({ role: 'user', content: ex.historia });
    msgs.push({ role: 'assistant', content: JSON.stringify(ex.saida) });
  }
  msgs.push({ role: 'user', content: String(historia || '') });
  return msgs;
}

// Parser defensivo da saída do modelo → { sepse:boolean, indicios:string } | null.
// Se o modelo devolver lixo, retorna null (o chamador trata como fail-open: sem
// gatilho, o formulário segue como se a IA não existisse).
export function parseSaidaSepse(texto) {
  if (!texto) return null;
  let s = String(texto).trim().replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim();
  const m = s.match(/\{[\s\S]*\}/);
  if (m) s = m[0];
  try {
    const o = JSON.parse(s);
    if (typeof o.sepse !== 'boolean') return null;
    return { sepse: o.sepse, indicios: typeof o.indicios === 'string' ? o.indicios : '' };
  } catch {
    return null;
  }
}
