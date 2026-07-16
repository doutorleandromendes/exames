// isc-triagem.js
// ──────────────────────────────────────────────────────────────────────────
// Decide QUAIS cirurgias do mapa entram na vigilância pós-alta — e em que
// equipe. Puro: sem banco, sem HTTP.
//
// POR QUE PRECISA EXISTIR
// O "Relação das Cirurgias" traz tudo que passa pelo centro cirúrgico: ~500
// procedimentos/mês, incluindo Bera (exame de audiologia), parto normal,
// broncoscopia, bloqueio de nervo e infiltração de coluna — que não são
// cirurgia para ISC. Importar tudo afogaria a agenda da colaboradora e
// estragaria o denominador. A implantação é escalonada: fase 1 = neuro, cardio
// e cesarianas; depois, o rol do CVE.
//
// POR QUE LIMITE DE PALAVRA (E NÃO "CONTÉM")
// Um teste com `/raque/` marcou TRAQUEOSTOMIA como neurocirurgia
// ("T-RAQUE-OSTOMIA"). Em texto livre de prontuário, substring casa errado o
// tempo todo. Aqui todo termo casa com \b...\b, ignorando acento e caixa.
//
// ORDEM IMPORTA: a primeira regra que casa vence. Regras de EXCLUSÃO
// (vigiar=false) vêm primeiro, para "Coluna Vertebral: Infiltração" ser
// descartada antes da regra de neuro pegá-la pelo "coluna".
//
// Nenhuma regra casou → a cirurgia fica FORA DO RECORTE: aparece na prévia,
// não vira ficha. Ampliar a vigilância = adicionar regra, não mexer em código.
// ──────────────────────────────────────────────────────────────────────────

const semAcento = s => String(s ?? '')
  .normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();

// Casa `termo` como palavra inteira dentro de `texto`. Aceita termo com espaço
// ("operacao cesariana"). Escapa metacaracteres: o termo vem do banco, digitado
// por gente — nunca é tratado como regex.
export function casaTermo(texto, termo) {
  const t = semAcento(texto);
  const p = semAcento(termo).trim();
  if (!p) return false;
  const esc = p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(^|[^a-z0-9])${esc}([^a-z0-9]|$)`, 'i').test(t);
}

// Lista "a|b|c" → casa se QUALQUER termo casar.
export function casaLista(texto, lista) {
  if (!lista) return false;
  const termos = String(lista).split('|').map(s => s.trim()).filter(Boolean);
  return termos.some(t => casaTermo(texto, t));
}

// Uma regra casa quando TODAS as condições preenchidas casam (AND entre os
// campos, OR dentro de cada lista). Campo vazio = não restringe.
export function regraCasa(regra, { procedimento, cirurgiao, tipo_anestesia }) {
  if (!regra || regra.ativo === false) return false;
  if (regra.nao_match_proc && casaLista(procedimento, regra.nao_match_proc)) return false;
  const temFiltro = !!(regra.match_proc || regra.match_cirurgiao || regra.match_tipo);
  if (!temFiltro) return false;                       // regra vazia nunca casa (evita pegar tudo)
  if (regra.match_proc && !casaLista(procedimento, regra.match_proc)) return false;
  if (regra.match_cirurgiao && !casaLista(cirurgiao, regra.match_cirurgiao)) return false;
  if (regra.match_tipo && !casaLista(tipo_anestesia, regra.match_tipo)) return false;
  return true;
}

// Aplica o conjunto na ordem. Devolve { regra, vigiar, equipe_id, codigo_cve,
// implante } ou null quando nada casou.
export function triar(ctx, regras) {
  const lista = (regras || []).filter(r => r.ativo !== false)
    .slice().sort((a, b) => (a.ordem ?? 100) - (b.ordem ?? 100) || (a.id ?? 0) - (b.id ?? 0));
  for (const r of lista) {
    if (regraCasa(r, ctx)) {
      return {
        regra: r,
        vigiar: r.vigiar !== false,
        equipe_id: r.equipe_id ?? null,
        codigo_cve: r.codigo_cve ?? null,
        implante: r.implante ?? null,
        motivo: r.nome,
      };
    }
  }
  return null;
}

// ── Regras semente (fase 1: neuro · cardio · cesariana) ───────────────────
// Só por PROCEDIMENTO: nome de cirurgião não entra em repositório público, e
// muda com o corpo clínico. Regra por cirurgião se cadastra pela tela.
//
// ordem < 50 = exclusões (rodam antes). Ampliar para o rol do CVE = inserir
// linhas com ordem ≥ 100.
export const REGRAS_SEED = [
  // ── Exclusões: passam pelo centro cirúrgico, não são ISC ────────────────
  { nome: 'Excluir: exame diagnóstico', ordem: 10, vigiar: false,
    match_proc: 'bera|potenciais auditivos|broncoscopia|broncofibroscopia|endoscopia digestiva|colonoscopia|laringoscopia' },
  { nome: 'Excluir: bloqueio / infiltração (dor)', ordem: 12, vigiar: false,
    match_proc: 'bloqueio|infiltracao|infiltração' },
  { nome: 'Excluir: parto normal', ordem: 14, vigiar: false,
    match_proc: 'parto normal' },
  { nome: 'Excluir: curetagem', ordem: 16, vigiar: false,
    match_proc: 'curetagem' },

  // ── Fase 1 ──────────────────────────────────────────────────────────────
  // Cesariana: o texto do procedimento é confiável (os obstetras variam, o
  // termo não). Cobre "OPERAÇÃO CESARIANA" e "... COM LAQUEADURA TUBARIA".
  { nome: 'Cesariana', ordem: 100, vigiar: true, equipe: 'Obstetrícia',
    codigo_cve: 'CESARIANA', implante: false,
    match_proc: 'cesariana|cesarea|cesárea' },

  // Neuro: crânio e coluna. O "nao_match" é redundante com as exclusões acima
  // (ordem menor), mas fica como cinto e suspensório — se alguém desativar a
  // exclusão, infiltração de coluna não vira neurocirurgia.
  { nome: 'Neurocirurgia', ordem: 110, vigiar: true, equipe: 'Neurocirurgia',
    codigo_cve: 'CNEURO', implante: true,
    match_proc: 'craniotomia|craniectomia|cranioplastia|intracraniano|intracraniana|microcirurgia para tumor|derivacao ventricular|derivacao raque|derivacao raque-peritoneal|ventriculo-peritoneal|dvp|dve|artrodese|laminectomia|discectomia|coluna|neurocirurgia',
    nao_match_proc: 'infiltracao|bloqueio' },

  // Cardio: cirurgia cardíaca aberta.
  { nome: 'Cirurgia Cardíaca', ordem: 120, vigiar: true, equipe: 'Cirurgia Cardíaca',
    codigo_cve: 'CCARD', implante: true,
    match_proc: 'revascularizacao miocardica|revascularização miocárdica|plastica valvar|troca valvar|valvoplastia|extracorporea|extracórporea|coronaria|coronária|cardiaca|cardíaca|marcapasso|marca-passo' },
];
