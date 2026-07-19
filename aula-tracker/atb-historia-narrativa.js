// atb-historia-narrativa.js
// ════════════════════════════════════════════════════════════════════════════
// CRITÉRIO (moat) do detector de história TELEGRÁFICA vs NARRATIVA.
//
// ESCOPO (fase 1): SÓ forma, não mérito. A pergunta é única —
//   "a história descreve achados observáveis, de modo que dê pra ENTENDER e
//    CONFERIR o quadro? Ou é só um rótulo/diagnóstico sem descrição?"
// NÃO avalia se a indicação de ATB é boa. Documentar bem ≠ indicar bem.
//
// O eixo é SEMÂNTICO, não métrico — os exemplos reais provam:
//   "BRONCOASPIRAÇÃO" (15 chars, passa qualquer minChars) → telegráfica.
//   "aumento de secreção traqueal… sem febre ou imagem em RX" (~18 palavras)
//      → narrativa, mesmo curta.
// Por isso o juiz é o LLM; contagem de palavras/caracteres não serve.
//
// Saída esperada do modelo: SÓ um JSON, sem crases, sem texto extra:
//   {"narrativa": true|false, "aviso": "curto, acionável, em pt-BR"}
// ════════════════════════════════════════════════════════════════════════════

// Âncoras few-shot no vocabulário real (fichas do próprio banco).
export const EXEMPLOS_NARRATIVA = [
  {
    historia: 'BRONCOASPIRAÇÃO',
    saida: { narrativa: false, aviso: 'A história está telegráfica — é só um diagnóstico. Descreva o quadro em texto corrido (o que foi observado, evolução, exames).' },
  },
  {
    historia: 'AUMENTO DE SECREÇÃO TRAQUEAL, QUE ATRAPALHA MECANICA, SEM NOVAS DISFUNÇÕES, FEBRE, OU IMAGEM EM RX',
    saida: { narrativa: true, aviso: '' },
  },
];

export const SYSTEM_NARRATIVA = `
Você classifica a HISTÓRIA CLÍNICA de uma solicitação de antimicrobiano quanto à FORMA (não ao mérito clínico).

Pergunta única: a história descreve ACHADOS OBSERVÁVEIS (sinais, sintomas, evolução, exames — presentes ou pertinentemente ausentes), de modo que outra pessoa consiga ENTENDER e CONFERIR o quadro? Ou é apenas um RÓTULO/diagnóstico, ou taquigrafia, sem descrição que o sustente?

- Apenas um rótulo/diagnóstico, ou fragmento telegráfico → narrativa=false.
- Tem descrição de achados, ainda que CURTA → narrativa=true.

NÃO julgue se o antibiótico é indicado, se a conduta é certa, ou se faltam dados clínicos específicos. Só forma: prosa informativa vs bilhete. Comprimento NÃO é critério — uma história curta pode ser narrativa; uma palavra longa pode ser só rótulo.

Responda SOMENTE com um JSON, sem crases e sem nenhum outro texto:
{"narrativa": true, "aviso": ""}
Quando narrativa=false, "aviso" é uma frase curta, gentil e acionável em pt-BR pedindo para descrever o quadro em texto corrido. Quando narrativa=true, "aviso" é "".
`.trim();

// Monta as mensagens (system + few-shots + a história a avaliar) no formato /api/chat.
export function montarMensagensNarrativa(historia) {
  const msgs = [{ role: 'system', content: SYSTEM_NARRATIVA }];
  for (const ex of EXEMPLOS_NARRATIVA) {
    msgs.push({ role: 'user', content: ex.historia });
    msgs.push({ role: 'assistant', content: JSON.stringify(ex.saida) });
  }
  msgs.push({ role: 'user', content: String(historia || '') });
  return msgs;
}

// Parser defensivo da saída do modelo → { narrativa:boolean, aviso:string } | null.
// Se o modelo devolver lixo, retorna null (o chamador trata como fail-open).
export function parseSaidaNarrativa(texto) {
  if (!texto) return null;
  let s = String(texto).trim().replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim();
  // pega o primeiro objeto {...} caso venha com preâmbulo
  const m = s.match(/\{[\s\S]*\}/);
  if (m) s = m[0];
  try {
    const o = JSON.parse(s);
    if (typeof o.narrativa !== 'boolean') return null;
    return { narrativa: o.narrativa, aviso: typeof o.aviso === 'string' ? o.aviso : '' };
  } catch {
    return null;
  }
}
