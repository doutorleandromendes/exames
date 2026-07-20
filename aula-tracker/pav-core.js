// pav-core.js
// ──────────────────────────────────────────────────────────────────────────
// Núcleo do módulo PAV (bundle de prevenção de pneumonia associada à VM) —
// SEM dependência de banco, de Express ou de HTML. Tudo função pura: dá para
// testar com harness (padrão do projeto — ver harness-pav-core.mjs).
//
// ╔═ PARADIGMA: DUAS CAMADAS SEPARADAS ═════════════════════════════════════╗
// ║                                                                          ║
// ║  REGISTRO (o que a fisio/enf preenche)  →  FATO. "fiz o quê neste turno" ║
// ║     Linguagem de quem executa: "decúbito elevado? sim". "cuff? 28".      ║
// ║     NÃO existe "conforme/não conforme" aqui. NÃO existe all-or-none.     ║
// ║     O instrumento registra o trabalho, não o julga.                      ║
// ║                                                                          ║
// ║  LEITURA (o que o dashboard/SCIH calcula)  →  INTERPRETAÇÃO.             ║
// ║     Aplica regras (cuff 25–30, etc.) sobre o registro e DERIVA           ║
// ║     conformidade, adesão all-or-none, estatística. Vive só aqui.         ║
// ║     Muda sem tocar no formulário nem no dado já coletado — dá até para   ║
// ║     recalcular a adesão do passado com uma regra nova, porque o fato     ║
// ║     bruto ("22°") está guardado, não o veredito ("NC").                  ║
// ║                                                                          ║
// ╚══════════════════════════════════════════════════════════════════════════╝
//
// Mesma disciplina do ISC: o contato registra o que o paciente respondeu, e
// contatoTemAlerta() DERIVA o alerta depois. Fato e interpretação separados.
//
// O que este módulo FAZ: registro factual do bundle, VM-dia por construção,
// série ventilatória prospectiva p/ o ATB, escopo de acesso (turno × salão),
// e — na camada de leitura — conformidade e adesão.
// O que este módulo NÃO faz: classificar PAV. Classificação de IRAS é
// inteiramente do módulo ATB. Aqui não há critério diagnóstico, de propósito.
// ──────────────────────────────────────────────────────────────────────────

// ══════════════════════════════════════════════════════════════════════════
//  GRADE DE TURNOS  (cobre 24h sem buraco e sem sobreposição)
// ══════════════════════════════════════════════════════════════════════════
// A CATEGORIA é derivada do horário: quem loga às 03:00 só pode estar no turno
// da enfermagem; às 15:00, no T da fisio. Por isso turnoVigente() não recebe
// categoria — o relógio a determina. Anotação é UMA vez por turno; bordas não
// vazam. Fisio: M 07–13, T 13–19, N 19–01 (cruza meia-noite). Enf: E 01–07.
//
// ⚠️ O N (fisio, 19:00–01:00) é o ÚNICO turno que cruza a meia-noite. Um check
// às 00:30 pertence ao N do dia em que o turno COMEÇOU (regra em diaDoTurno).
export const TURNOS = [
  { turno: 'M', categoria: 'fisio', ini: 7,  fim: 13, label: 'Manhã'     },
  { turno: 'T', categoria: 'fisio', ini: 13, fim: 19, label: 'Tarde'     },
  { turno: 'N', categoria: 'fisio', ini: 19, fim: 25, label: 'Noite'     },  // 25h = 01:00 do dia seguinte
  { turno: 'E', categoria: 'enf',   ini: 1,  fim: 7,  label: 'Madrugada' },
];

export const CATEGORIAS_PAV = [
  ['fisio', 'Fisioterapia'],
  ['enf',   'Enfermagem'],
];

// Salões da UTI. Fixos hoje (dois). Se surgir um terceiro, é migração de 1 linha.
export const SALOES = [
  ['UTIAB', 'UTI adulto B'],
  ['UTIC',  'UTI coronariana'],
];

// Alcance de salão por categoria de papel:
//   fisio  → atravessa os dois salões (mesma pessoa cobre ambos no turno)
//   enf    → o salão vem da SESSÃO (login único, seleção por sessão), não da conta
export const SALOES_FISIO = SALOES.map(s => s[0]);

// ── Estados do episódio (encerramento em dois níveis) ─────────────────────
// 'ativo'              → em VM, na lista
// 'extubacao_pendente' → enf registrou extubação (preencheu tudo); AINDA na
//                        lista, aguarda confirmação de fisio/SCIH no período seguinte
// 'encerrado'          → fisio/SCIH confirmaram; fora da lista, VM-dia fechado
export const ESTADOS_EPISODIO = ['ativo', 'extubacao_pendente', 'encerrado'];
export const ESTADO_NA_LISTA = new Set(['ativo', 'extubacao_pendente']); // população ativa

export const DESFECHOS = [
  ['extubacao_programada',  'Extubação programada'],
  ['extubacao_acidental',   'Extubação acidental / autoextubação'],
  ['obito',                 'Óbito'],
  ['tqt',                   'Traqueostomia'],
  ['transferencia_externa', 'Transferência externa'],
  ['reintubacao',           'Reintubação (novo episódio)'],
];

// Decide o efeito de um pedido de encerramento, conforme QUEM pede.
// A enfermagem só PROPÕE (vira 'extubacao_pendente', preenchendo tudo); fisio,
// SCIH e super-admin ENCERRAM direto ('encerrado'). Confirmar uma pendência é
// sempre encerramento (ato de fisio/SCIH). Função pura → testável.
//   ctx: { categoria_pav, super_admin, scih }
//   acao: 'registrar' (marcar extubação) | 'confirmar' (revisar pendência)
// Devolve { estado_novo, encerra, motivo }.
export function efeitoEncerramento(ctx, acao = 'registrar') {
  const revisor = !!(ctx?.super_admin || ctx?.scih || ctx?.categoria_pav === 'fisio');

  if (acao === 'confirmar') {
    if (!revisor) return { estado_novo: null, encerra: false, motivo: 'confirmação é ato de fisio/SCIH' };
    return { estado_novo: 'encerrado', encerra: true, motivo: null };
  }
  // acao === 'registrar' (marcar extubação)
  if (revisor) return { estado_novo: 'encerrado', encerra: true, motivo: null };
  if (ctx?.categoria_pav === 'enf') return { estado_novo: 'extubacao_pendente', encerra: false, motivo: null };
  return { estado_novo: null, encerra: false, motivo: 'sem permissão para encerrar' };
}


// ══════════════════════════════════════════════════════════════════════════
//  CATÁLOGO DE REGISTRO  (o que o formulário coleta — FATO, nunca julgamento)
// ══════════════════════════════════════════════════════════════════════════
// tipo:
//   'sim_nao'   → foi feito? (registro de execução; não é conforme/não-conforme)
//   'valor'     → número aferido (cuff, FiO2, PEEP, PaO2)
// categoria: quem VÊ o item ('fisio' | 'enf' | 'ambos')
// periodicidade: 'turno' | 'dia'
// justifica_se_nao: exige texto quando a resposta é 'nao' (o motivo é FATO,
//                   não contraindicação-julgada)
// via: item tem qualificador de COMO foi feito (subglótica: às cegas × porta)
//
// Ordem = ordem de exibição no formulário.
export const REGISTRO = [
  // — Itens de execução do bundle (sim/não) —
  { key: 'cabeceira',   label: 'Decúbito elevado (30–45°)',        cat: 'ambos', per: 'turno', tipo: 'sim_nao' },
  { key: 'higiene_oral',label: 'Higiene oral',                     cat: 'enf',   per: 'turno', tipo: 'sim_nao' },
  { key: 'aspiracao',   label: 'Aspiração de vias aéreas',         cat: 'ambos', per: 'turno', tipo: 'sim_nao' },
  { key: 'subglotica',  label: 'Aspiração subglótica',             cat: 'fisio', per: 'turno', tipo: 'sim_nao', via: true },
  { key: 'despertar',   label: 'Despertar diário / TRE',           cat: 'fisio', per: 'dia',   tipo: 'sim_nao', justifica_se_nao: true },
  { key: 'extubacao',   label: 'Avaliação de prontidão p/ extubação', cat: 'fisio', per: 'dia', tipo: 'sim_nao' },
  // — Eventos de troca (sim/não; hoje só sinaliza, alarme fica p/ o futuro) —
  { key: 'circuito',    label: 'Troca de circuito',                cat: 'fisio', per: 'turno', tipo: 'sim_nao' },
  { key: 'hmef',        label: 'Troca de HMEF',                    cat: 'fisio', per: 'turno', tipo: 'sim_nao' },
  { key: 'sistema',     label: 'Troca de sistema fechado',         cat: 'fisio', per: 'turno', tipo: 'sim_nao' },
  // — Valores aferidos —
  { key: 'cuff',        label: 'Pressão do cuff (cmH₂O)',          cat: 'fisio', per: 'turno', tipo: 'valor', unidade: 'cmH2O' },
];

export const REGISTRO_KEYS = new Set(REGISTRO.map(c => c.key));

// Vocabulário do qualificador "via" (aspiração subglótica). Default às_cegas:
// hoje o HUSF a faz às cegas (pericânula); porta_dedicada entra quando houver
// TOT com porta. Só faz sentido quando o item foi 'sim'.
export const SUBGLOTICA_VIA = [
  ['as_cegas',       'Às cegas (pericânula)'],
  ['porta_dedicada', 'Porta dedicada'],
];
export const SUBGLOTICA_VIA_DEFAULT = 'as_cegas';

// ── Parâmetros ventilatórios e secreção (FATO, p/ o ATB) ──────────────────
export const SECRECAO_QUANTIDADE = [
  ['ausente', 'Ausente'], ['pequena', 'Pequena'], ['media', 'Média'], ['grande', 'Grande'],
];
export const SECRECAO_ASPECTO = [
  ['mucoide', 'Mucoide'], ['seromucoide', 'Seromucoide'], ['purulenta', 'Purulenta'], ['hematica', 'Hemática'],
];

// ══════════════════════════════════════════════════════════════════════════
//  EXTRAÇÃO DO REGISTRO  (POST → fato limpo; campo solto é descartado)
// ══════════════════════════════════════════════════════════════════════════
// Devolve { itens:{[key]:{resp|valor, via?, justificativa?}}, vent, secrecao }.
// NÃO avalia conformidade — isso é da camada de leitura. Só limpa e valida FATO.
// motivos[] acumula rejeições factuais (ex.: 'nao' sem justificativa obrigatória).
export function extraiRegistro(body) {
  const b = body || {};
  const itens = {};
  const motivos = [];

  for (const campo of REGISTRO) {
    if (campo.tipo === 'valor') {
      const v = numOrNull(b[`v_${campo.key}`]);
      if (v != null) itens[campo.key] = { valor: v };
      continue;
    }
    // sim_nao
    const raw = String(b[`r_${campo.key}`] ?? '').toLowerCase();
    if (raw !== 'sim' && raw !== 'nao') continue;   // não respondido → ausente
    const item = { resp: raw };

    if (campo.justifica_se_nao && raw === 'nao') {
      const just = String(b[`j_${campo.key}`] ?? '').trim();
      if (!just) { motivos.push(`${campo.key}: justificativa obrigatória quando "não"`); }
      else item.justificativa = just.slice(0, 2000);
    }
    if (campo.via && raw === 'sim') {
      item.via = enumDe(b[`via_${campo.key}`], SUBGLOTICA_VIA, SUBGLOTICA_VIA_DEFAULT);
    }
    itens[campo.key] = item;
  }

  const vent = {
    fio2: numOrNull(b.fio2),   // em %
    peep: numOrNull(b.peep),
    pao2: numOrNull(b.pao2),   // opcional (só se houve gaso)
  };
  vent.pf = relacaoPF(vent.pao2, vent.fio2);

  const secrecao = {
    quantidade: enumDe(b.sec_quantidade, SECRECAO_QUANTIDADE),
    aspecto:    enumDe(b.sec_aspecto, SECRECAO_ASPECTO),
  };

  return { itens, vent, secrecao: (secrecao.aspecto ? secrecao : null), motivos };
}

// ══════════════════════════════════════════════════════════════════════════
//  ESCOPO DE ACESSO  (turno vigente × salão) — quem pode escrever o quê, onde
// ══════════════════════════════════════════════════════════════════════════
// Turno vigente a partir do relógio DO SERVIDOR (nunca do cliente — senão a
// trava é teatro). Devolve { turno, categoria, data } | null.
export function turnoVigente(agora = new Date()) {
  const h = agora.getHours() + agora.getMinutes() / 60;
  for (const def of TURNOS) {
    const hNorm = (def.fim > 24 && h < (def.fim - 24)) ? h + 24 : h;
    if (hNorm >= def.ini && hNorm < def.fim) {
      return { turno: def.turno, categoria: def.categoria, data: diaDoTurno(def.turno, agora) };
    }
  }
  return null;
}

// O DIA a que um turno pertence. Só o N (fisio) pode pertencer ao dia anterior
// quando o relógio já passou da meia-noite: check às 00:30 do dia 18 é o N que
// começou no dia 17.
export function diaDoTurno(turno, agora = new Date()) {
  const d = new Date(agora);
  if (turno === 'N' && agora.getHours() < 2) d.setDate(d.getDate() - 1);
  return d.toISOString().slice(0, 10);
}

// Alcance de salão do CONTEXTO de trabalho:
//   fisio            → os dois salões (atributo do papel)
//   enf              → o salão da SESSÃO (login único, seleção por sessão)
//   super_admin      → todos
// ctx: { super_admin, categoria_pav, salao_sessao }
export function saloesDoContexto(ctx) {
  if (ctx?.super_admin) return [...SALOES_FISIO];
  if (ctx?.categoria_pav === 'fisio') return [...SALOES_FISIO];
  if (ctx?.categoria_pav === 'enf') return ctx?.salao_sessao ? [ctx.salao_sessao] : [];
  return [];
}

// A trava de escrita. Precisa de TRÊS coisas alinhadas:
//   (1) turno vigente da categoria do usuário   (2) data/turno do alvo == vigente
//   (3) o salão do alvo ∈ alcance do contexto
// super_admin escreve em qualquer (data,turno,salão), mas sai marcado retroativo.
// alvo: { data, turno, salao }.  ctx: { super_admin, categoria_pav, salao_sessao }.
// Devolve { permitido, retroativo, motivo }.
export function podeEscrever(alvo, ctx, agora = new Date()) {
  const su = !!(ctx?.super_admin);
  const vig = turnoVigente(agora);

  if (su) {
    const noVigente = vig && alvo?.data === vig.data && alvo?.turno === vig.turno;
    return { permitido: true, retroativo: !noVigente, motivo: null };
  }

  if (!vig) return { permitido: false, retroativo: false, motivo: 'fora de qualquer turno' };
  if (ctx?.categoria_pav && ctx.categoria_pav !== vig.categoria)
    return { permitido: false, retroativo: false, motivo: `turno vigente é da ${vig.categoria}` };
  if (alvo?.data !== vig.data || alvo?.turno !== vig.turno)
    return { permitido: false, retroativo: false, motivo: 'só o turno cronológico vigente' };

  const saloes = saloesDoContexto(ctx);
  if (!saloes.includes(alvo?.salao))
    return { permitido: false, retroativo: false, motivo: 'salão fora do seu alcance' };

  return { permitido: true, retroativo: false, motivo: null };
}

// Quais fichas (episódios ativos) o contexto VÊ. Interseção de salão apenas —
// a categoria já filtra os ITENS na tela, mas os leitos visíveis são todos os
// do(s) salão(ões) alcançado(s).
// fichas: [{ id, leito, salao, ... }]. Devolve as visíveis.
export function leitosVisiveis(ctx, fichas) {
  const saloes = new Set(saloesDoContexto(ctx));
  return (Array.isArray(fichas) ? fichas : []).filter(f => saloes.has(f?.salao));
}

// Itens do REGISTRO que uma categoria preenche (fisio não vê higiene oral; enf
// vê só o que lhe compete). 'ambos' aparece para as duas.
export function itensDaCategoria(categoria) {
  return REGISTRO.filter(c => c.cat === 'ambos' || c.cat === categoria);
}

// Trava de TRANSFERÊNCIA entre salões. Irmã de podeEscrever, com uma diferença:
// a transferência tem DOIS salões (origem e destino), e AMBOS precisam estar no
// alcance de quem registra. Isso exclui a enf naturalmente — ela alcança um só
// salão, logo nunca alcança os dois extremos de uma transferência.
//   fisio         → alcança UTIAB e UTIC → transfere entre eles, no turno vigente
//   super_admin   → transfere qualquer coisa, inclusive backfill (retroativo)
//   enf           → bloqueada (não alcança ambos os salões)
// mov: { data, turno, salao_de, salao_para }.  ctx: idem podeEscrever.
export function podeTransferir(mov, ctx, agora = new Date()) {
  if (mov?.salao_de === mov?.salao_para)
    return { permitido: false, retroativo: false, motivo: 'origem e destino iguais' };

  const su = !!(ctx?.super_admin);
  const vig = turnoVigente(agora);
  const saloes = saloesDoContexto(ctx);
  const alcancaAmbos = saloes.includes(mov?.salao_de) && saloes.includes(mov?.salao_para);

  if (su) {
    if (!alcancaAmbos) return { permitido: false, retroativo: false, motivo: 'salão fora do alcance' };
    const noVigente = vig && mov?.data === vig.data && mov?.turno === vig.turno;
    return { permitido: true, retroativo: !noVigente, motivo: null };
  }

  if (!alcancaAmbos)
    return { permitido: false, retroativo: false, motivo: 'transferência exige alcançar os dois salões' };
  if (!vig) return { permitido: false, retroativo: false, motivo: 'fora de qualquer turno' };
  if (ctx?.categoria_pav && ctx.categoria_pav !== vig.categoria)
    return { permitido: false, retroativo: false, motivo: `turno vigente é da ${vig.categoria}` };
  if (mov?.data !== vig.data || mov?.turno !== vig.turno)
    return { permitido: false, retroativo: false, motivo: 'só o turno cronológico vigente' };

  return { permitido: true, retroativo: false, motivo: null };
}

// ══════════════════════════════════════════════════════════════════════════
//  PARÂMETROS  →  ATB
// ══════════════════════════════════════════════════════════════════════════
// P/F SEMPRE calculado, nunca digitado (evita erro de conta e nº não
// reprodutível). PaO2 opcional — só existe se houve gasometria. FiO2 em %.
export function relacaoPF(pao2, fio2Pct) {
  if (pao2 == null || pao2 === '' || fio2Pct == null || fio2Pct === '') return null;
  const p = Number(pao2), f = Number(fio2Pct);
  if (!Number.isFinite(p) || !Number.isFinite(f) || f <= 0) return null;
  return Math.round(p / (f / 100));
}

// "Pior do dia" — concilia os até 4 turnos (E/M/T/N) num valor por campo.
// "Pior" tem sentido próprio: FiO2 maior; PEEP maior; P/F menor. Secreção:
// purulenta SEMPRE trumpa; a quantidade que sobe é a DA AMOSTRA PURULENTA.
// Só sobe ao ATB: purulenta + quantidade. Sem purulenta mas com registro →
// "sem secreção purulenta". Dia sem registro → null (— na série).
const RANK_QTD = { ausente: 0, pequena: 1, media: 2, grande: 3 };

export function piorDoDia(checksDoDia) {
  const cs = Array.isArray(checksDoDia) ? checksDoDia : [];
  let fio2 = null, peep = null, pf = null, temVent = false;
  let purulenta = null, algumaSecrecao = false;

  for (const c of cs) {
    const v = c?.vent || {};
    if (v.fio2 != null && Number.isFinite(Number(v.fio2))) { temVent = true; fio2 = fio2 == null ? Number(v.fio2) : Math.max(fio2, Number(v.fio2)); }
    if (v.peep != null && Number.isFinite(Number(v.peep))) { temVent = true; peep = peep == null ? Number(v.peep) : Math.max(peep, Number(v.peep)); }
    const pfc = (v.pf != null) ? Number(v.pf) : relacaoPF(v.pao2, v.fio2);
    if (Number.isFinite(pfc)) { temVent = true; pf = pf == null ? pfc : Math.min(pf, pfc); }

    const s = c?.secrecao;
    if (s && s.aspecto) {
      algumaSecrecao = true;
      if (s.aspecto === 'purulenta') {
        const q = s.quantidade || 'pequena';
        if (!purulenta || (RANK_QTD[q] ?? 0) > (RANK_QTD[purulenta.quantidade] ?? 0)) purulenta = { quantidade: q };
      }
    }
  }
  return {
    fio2, peep, pf, tem_registro_vent: temVent,
    secrecao_para_atb: purulenta
      ? { purulenta: true, quantidade: purulenta.quantidade }
      : (algumaSecrecao ? { purulenta: false, quantidade: null } : null),
  };
}

// Série D-3..D+3 p/ pré-preencher a tela de complementação do ATB. O ATB é o
// ÚNICO ESCRITOR de atb_evolutivos; isto só PRÉ-PREENCHE. Formato casado com
// GRUPOS.ventilatorio do ATB: { PEEP, FiO2, Rel, ST, Data }. `retroativo` marca
// dias que contêm algum check retroativo (distinguir "ao vivo" de "reconstruído").
export const DIAS_SERIE = ['D-3', 'D-2', 'D-1', 'D0', 'D+1', 'D+2', 'D+3'];

export function serieVentilatoria(agregadosPorDia, d0ISO) {
  const out = {};
  const base = toISODate(d0ISO);
  for (let off = -3; off <= 3; off++) {
    const dia = addDays(base, off);
    const rot = DIAS_SERIE[off + 3];
    const ag = agregadosPorDia?.[dia] || null;
    if (!ag) { out[rot] = { PEEP: '', FiO2: '', Rel: '', ST: '', Data: dia, retroativo: false }; continue; }
    let st = '';
    if (ag.secrecao_para_atb) {
      st = ag.secrecao_para_atb.purulenta ? `purulenta, ${ag.secrecao_para_atb.quantidade}` : 'sem secreção purulenta';
    }
    out[rot] = {
      PEEP: ag.peep != null ? String(ag.peep) : '',
      FiO2: ag.fio2 != null ? String(ag.fio2) : '',
      Rel:  ag.pf   != null ? String(ag.pf)   : '',
      ST:   st, Data: dia, retroativo: !!ag.retroativo,
    };
  }
  return out;
}

// ══════════════════════════════════════════════════════════════════════════
//  VM-DIA  (denominador, por construção)
// ══════════════════════════════════════════════════════════════════════════
// Dias de calendário de VM de UM episódio dentro de um mês. Conta o dia da
// intubação; o dia da extubação NÃO conta (alinha "dia anterior à remoção" da
// NT 03/2025). Aberto no fechamento → conta até o último dia do mês.
// Transferência de salão NÃO interrompe o episódio (mesmo episódio, VM-dia
// contínuo) — por isso VM-dia não conhece salão.
export function vmDiaEpisodio(dataIntubISO, dataExtubISO, mesISO) {
  const intub = toISODate(dataIntubISO);
  if (!intub) return 0;
  const [ano, mes] = mesISO.split('-').map(Number);
  const primeiro = `${mesISO}-01`;
  const ultimo = new Date(Date.UTC(ano, mes, 0)).toISOString().slice(0, 10);
  const ini = intub > primeiro ? intub : primeiro;
  const extub = toISODate(dataExtubISO);
  const fimExtub = extub ? addDays(extub, -1) : null;
  const fim = (fimExtub && fimExtub < ultimo) ? fimExtub : ultimo;
  if (fim < ini) return 0;
  return diffDias(ini, fim) + 1;
}

// ══════════════════════════════════════════════════════════════════════════
//  CAMADA DE LEITURA  (INTERPRETAÇÃO — vive só aqui, o formulário não a conhece)
// ══════════════════════════════════════════════════════════════════════════
// Regras de conformidade DEFAULT. A CCIRAS ajusta sem tocar no form nem no dado
// já coletado — e dá para recalcular o passado, porque o registro guarda o FATO.
export const REGRAS_DEFAULT = {
  cuff: { faixa: [25, 30] },   // cmH2O
  // Itens sim_nao: 'sim' é conforme. Exceções de contexto (ex.: despertar 'não'
  // com justificativa contar ou não) ficam em flags abaixo — decisão da leitura.
  despertar_nao_justificado_conta_conforme: true,   // 'não' + justificativa → NA (conforme)
  // Eventos de troca NÃO entram no bundle (são registro, não medida auditada):
  fora_do_bundle: new Set(['circuito', 'hmef', 'sistema']),
};

// Interpreta UM item do registro sob as regras. Devolve 'C' | 'NC' | 'NA' | null.
export function conformidadeItem(campo, item, regras = REGRAS_DEFAULT) {
  if (regras.fora_do_bundle?.has(campo.key)) return null;   // fora do bundle
  if (item == null) return null;                            // não registrado

  if (campo.tipo === 'valor') {
    const faixa = regras[campo.key]?.faixa;
    if (!faixa || item.valor == null) return null;
    const v = Number(item.valor);
    if (!Number.isFinite(v)) return null;
    return (v >= faixa[0] && v <= faixa[1]) ? 'C' : 'NC';
  }
  // sim_nao
  if (item.resp === 'sim') return 'C';
  if (item.resp === 'nao') {
    if (campo.justifica_se_nao && item.justificativa && regras.despertar_nao_justificado_conta_conforme)
      return 'NA';   // não feito por motivo registrado → não penaliza
    return 'NC';
  }
  return null;
}

// Adesão all-or-none — CÁLCULO sobre o registro, não campo do formulário.
// 1 se todos os itens do bundle são C (ou C+NA); 0 se algum é NC; null se
// incompleto. NA não penaliza nem infla (sai do numerador e do denominador de
// "aplicáveis conformes", mas conta como cumprido no all-or-none).
export function adesaoBundle(registroItens, regras = REGRAS_DEFAULT) {
  const itens = registroItens || {};
  const nc = [], faltando = [];
  let aplicaveis = 0, conformes = 0;

  for (const campo of REGISTRO) {
    if (regras.fora_do_bundle?.has(campo.key)) continue;   // eventos de troca fora
    const estado = conformidadeItem(campo, itens[campo.key], regras);
    if (estado == null) { faltando.push(campo.key); continue; }
    if (estado === 'NA') { continue; }                     // cumprido, fora da contagem
    aplicaveis++;
    if (estado === 'C') conformes++;
    else nc.push(campo.key);
  }
  const completo = faltando.length === 0;
  const adesao = !completo ? null : (nc.length === 0 ? 1 : 0);
  return { completo, adesao, aplicaveis, conformes, nc, faltando };
}

// ── Datas (mesmas do ISC — reusadas para casar comportamento) ─────────────
export function toISODate(d) {
  if (!d) return null;
  const dt = (d instanceof Date) ? d : new Date(d);
  if (Number.isNaN(dt.getTime())) return null;
  return dt.toISOString().slice(0, 10);
}
export function addDays(isoDate, dias) {
  const base = toISODate(isoDate);
  if (!base) return null;
  const dt = new Date(base + 'T12:00:00Z');
  dt.setUTCDate(dt.getUTCDate() + Number(dias || 0));
  return dt.toISOString().slice(0, 10);
}
export function diffDias(isoA, isoB) {
  const a = toISODate(isoA), b = toISODate(isoB);
  if (!a || !b) return null;
  return Math.round((new Date(b + 'T12:00:00Z') - new Date(a + 'T12:00:00Z')) / 86400000);
}
export function hojeISO() { return new Date().toISOString().slice(0, 10); }

// ── Sanitização ───────────────────────────────────────────────────────────
export function enumDe(v, permitidos, fallback = null) {
  const s = String(v ?? '').trim();
  const chaves = permitidos.map(p => Array.isArray(p) ? p[0] : p);
  return chaves.includes(s) ? s : fallback;
}
function numOrNull(v) {
  if (v == null || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}
