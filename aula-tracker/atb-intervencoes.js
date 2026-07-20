// atb-intervencoes.js
// ════════════════════════════════════════════════════════════════════════════
// MOTOR DE INTERVENÇÕES — a peça central do pipeline de teste do formulário.
//
// Uma "intervenção" é uma mudança NOMEADA no código, expressa como um conjunto
// de transformações por ÂNCORA SEMÂNTICA (achar um trecho único, trocar por
// outro) — o mesmo mecanismo de um str_replace com âncora, mas registrado,
// reversível e verificável.
//
// Por que âncora e não diff de linha: o diff de linha quebra quando o arquivo
// muda perto (ex.: a Fase C desloca tudo). A âncora casa pelo CONTEÚDO. Se o
// trecho não existe mais (produção mudou aquele pedaço), o motor FALHA
// BARULHENTO em vez de aplicar errado — e essa falha é o sinal de "re-ancore".
//
// Invariante de segurança inegociável: toda âncora deve casar EXATAMENTE UMA
// vez. Zero = produção mudou. Duas+ = ambígua. Nos dois casos: recusa e explica.
//
// Este módulo NÃO toca em nenhum arquivo de produção. Ele transforma STRINGS e
// devolve STRINGS. Quem decide o que fazer com o resultado (servir como engine
// de teste, gerar artefato pra commit) é o transportador — outra peça.
// ════════════════════════════════════════════════════════════════════════════

// Erro tipado para o transportador distinguir "re-ancore" de "bug real".
export class IntervencaoErro extends Error {
  constructor(mensagem, detalhe) {
    super(mensagem);
    this.name = 'IntervencaoErro';
    this.detalhe = detalhe || {};
  }
}

// ── Validação do formato de uma intervenção ──────────────────────────────────
// Uma intervenção é: { nome, alvo, descricao?, transformacoes: [{ ancora, vira, nota? }] }
// tambemToca? é documentação (outros arquivos afetados); o motor só age no alvo.
export function validarIntervencao(interv) {
  const erros = [];
  if (!interv || typeof interv !== 'object') return ['intervenção não é um objeto'];
  if (!interv.nome || typeof interv.nome !== 'string') erros.push('falta "nome" (string)');
  if (!interv.alvo || typeof interv.alvo !== 'string') erros.push('falta "alvo" (arquivo)');
  if (!Array.isArray(interv.transformacoes) || interv.transformacoes.length === 0)
    erros.push('falta "transformacoes" (lista não-vazia)');
  else interv.transformacoes.forEach((t, i) => {
    if (!t || typeof t !== 'object') { erros.push(`transformação #${i}: não é objeto`); return; }
    if (typeof t.ancora !== 'string' || t.ancora === '') erros.push(`transformação #${i}: "ancora" vazia`);
    if (typeof t.vira !== 'string') erros.push(`transformação #${i}: "vira" ausente`);
    if (t.ancora === t.vira) erros.push(`transformação #${i}: "ancora" e "vira" idênticas (no-op)`);
  });
  return erros;
}

// ── Checagem de uma única transformação contra um conteúdo ───────────────────
// Retorna { ok, ocorrencias, motivo }. NÃO altera nada.
export function checarTransformacao(conteudo, ancora) {
  // contagem de ocorrências sem regex (âncora é texto literal, pode ter chars especiais)
  let n = 0, idx = 0;
  while ((idx = conteudo.indexOf(ancora, idx)) !== -1) { n++; idx += ancora.length; }
  if (n === 1) return { ok: true, ocorrencias: 1 };
  if (n === 0) return { ok: false, ocorrencias: 0, motivo: 'âncora não encontrada (o alvo mudou?)' };
  return { ok: false, ocorrencias: n, motivo: `âncora ambígua: casa ${n} vezes (precisa de mais contexto)` };
}

// ── Aplicar uma intervenção a um conteúdo ────────────────────────────────────
// Modo "dry": só valida todas as âncoras, sem produzir saída (pré-checagem).
// Aplicação é ATÔMICA: se QUALQUER âncora falhar, nada é aplicado.
// As transformações são checadas contra o conteúdo ORIGINAL (ordem não importa),
// e aplicadas em sequência — cada "vira" não pode reintroduzir/ocultar a âncora
// de outra (verificado: cada âncora tem de casar 1x no original).
export function aplicarIntervencao(conteudo, interv, opts = {}) {
  const problemas = validarIntervencao(interv);
  if (problemas.length) throw new IntervencaoErro(`intervenção "${interv && interv.nome || '?'}" inválida`, { problemas });

  // 1) pré-checa TODAS as âncoras contra o original (atomicidade)
  const relatorio = interv.transformacoes.map((t, i) => {
    const c = checarTransformacao(conteudo, t.ancora);
    return { i, nota: t.nota || null, ...c };
  });
  const falhas = relatorio.filter((r) => !r.ok);
  if (falhas.length) {
    throw new IntervencaoErro(
      `intervenção "${interv.nome}": ${falhas.length} âncora(s) não aplicável(is) em ${interv.alvo}`,
      { alvo: interv.alvo, falhas, relatorio });
  }
  if (opts.dry) return { ok: true, dry: true, alvo: interv.alvo, transformacoes: relatorio.length };

  // 2) aplica em sequência (cada âncora já garantida única no original)
  let out = conteudo;
  for (const t of interv.transformacoes) {
    // re-checa contra o estado corrente: uma "vira" anterior não pode ter criado
    // uma 2ª cópia da âncora seguinte (paranoia barata que pega intervenção mal-escrita)
    const c = checarTransformacao(out, t.ancora);
    if (!c.ok) throw new IntervencaoErro(
      `intervenção "${interv.nome}": âncora deixou de ser única após transformação anterior`,
      { alvo: interv.alvo, motivo: c.motivo });
    out = out.replace(t.ancora, t.vira);   // replace literal: 1ª (e única) ocorrência
  }
  return { ok: true, alvo: interv.alvo, conteudo: out, transformacoes: interv.transformacoes.length };
}

// ── Reverter: aplica a intervenção "ao contrário" (vira ⇄ ancora) ────────────
// Só funciona se cada "vira" for único no conteúdo transformado — mesma garantia.
export function reverterIntervencao(conteudo, interv, opts = {}) {
  const inversa = {
    nome: interv.nome + ' (reversão)',
    alvo: interv.alvo,
    transformacoes: interv.transformacoes.map((t) => ({ ancora: t.vira, vira: t.ancora, nota: t.nota })),
  };
  return aplicarIntervencao(conteudo, inversa, opts);
}

// ── Aplicar uma PILHA de intervenções, na ordem ──────────────────────────────
// Cada uma sobre o resultado da anterior. Falha barulhento na primeira que não
// aplica, dizendo qual — para o transportador saber onde parou.
export function aplicarPilha(conteudo, intervencoes, opts = {}) {
  let out = conteudo;
  const aplicadas = [];
  for (const interv of intervencoes) {
    try {
      const r = aplicarIntervencao(out, interv, opts);
      if (!opts.dry) out = r.conteudo;
      aplicadas.push({ nome: interv.nome, ok: true, transformacoes: r.transformacoes });
    } catch (e) {
      throw new IntervencaoErro(
        `pilha parou em "${interv.nome}": ${e.message}`,
        { aplicadasAntes: aplicadas.map((a) => a.nome), erro: e.detalhe });
    }
  }
  return { ok: true, dry: !!opts.dry, conteudo: opts.dry ? undefined : out, aplicadas };
}

// ── Diff legível de uma intervenção (para a tela do transportador) ───────────
// Não é diff de linha; é "por transformação, o antes → depois" — que é o que o
// revisor precisa aprovar. Trecho grande é truncado no meio.
export function descreverIntervencao(interv) {
  const corta = (s, n = 240) => (s.length <= n ? s : s.slice(0, n / 2) + `\n… (${s.length - n} chars) …\n` + s.slice(-n / 2));
  return {
    nome: interv.nome,
    alvo: interv.alvo,
    descricao: interv.descricao || '',
    tambemToca: interv.tambemToca || [],
    transformacoes: interv.transformacoes.map((t, i) => ({
      i, nota: t.nota || null, de: corta(t.ancora), para: corta(t.vira),
    })),
  };
}
