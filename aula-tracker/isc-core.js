// isc-core.js
// ──────────────────────────────────────────────────────────────────────────
// Núcleo do módulo ISC — SEM dependência de banco, de Express ou de HTML.
// Tudo aqui é função pura: dá para testar com harness (padrão do projeto).
//
// FONTE ÚNICA DE VERDADE do checklist. O JotForm duplicava literalmente o mesmo
// bloco de perguntas para 7d (qids 14–25) e 30d (qids 26–34) — dois conjuntos
// que precisavam ser mantidos em sincronia na mão. Aqui o checklist é UM só e
// as janelas apenas o reusam. Adicionar uma pergunta = 1 linha, não 3 lugares.
// ──────────────────────────────────────────────────────────────────────────

// ── Checklist canônico ────────────────────────────────────────────────────
// tipo: 'sim_nao' | 'multi' | 'texto'
// alerta: valores que, se marcados, acendem o sinal de suspeita na ficha.
// Passo 0: confirmação de identidade. Não é janela clínica (não vira contato de
// busca ativa) — é o portão que libera as demais. janela = -1 no template/fila.
export const JANELA_IDENTIDADE = -1;

export const CHECKLIST = [
  { key: 'alta',             label: 'Já teve alta?',                                              tipo: 'sim_nao' },
  { key: 'dreno',            label: 'Usou ou está usando dreno?',                                 tipo: 'sim_nao' },
  { key: 'ferida',           label: 'Como está a ferida?',                                        tipo: 'multi',
    opcoes: ['SEM SINAIS DE INFECÇÃO', 'Deiscência', 'Secreção purulenta', 'Secreção serosa',
             'Hiperemia local', 'Calor / edema local', 'Dor à palpação', 'Não tirou os pontos'],
    alerta: ['Deiscência', 'Secreção purulenta', 'Hiperemia local', 'Calor / edema local'] },
  { key: 'dor_bifasica',     label: 'Dor que melhorou e voltou a piorar?',                        tipo: 'sim_nao', alerta: ['Sim'] },
  { key: 'febre',            label: 'Teve febre?',                                                tipo: 'sim_nao', alerta: ['Sim'] },
  { key: 'atb_pos',          label: 'Usou ou está usando antibióticos depois da cirurgia?',       tipo: 'sim_nao', alerta: ['Sim'] },
  { key: 'dx_infeccao',      label: 'Teve algum diagnóstico de infecção da ferida operatória?',   tipo: 'sim_nao', alerta: ['Sim'] },
  { key: 'reabordagem',      label: 'Precisou de novas cirurgias na mesma topografia?',           tipo: 'sim_nao', alerta: ['Sim'] },
  { key: 'readmissao',       label: 'Precisou voltar ao hospital / internar de novo?',            tipo: 'sim_nao', alerta: ['Sim'] },
  { key: 'contato_medico',   label: 'Precisou entrar em contato com a equipe médica?',            tipo: 'sim_nao' },
  { key: 'retorno_equipe',   label: 'Já teve retorno com a equipe cirúrgica? Tudo correndo bem?', tipo: 'sim_nao' },
];

export const CHECKLIST_KEYS = new Set(CHECKLIST.map(c => c.key));

export const RECOMENDACOES = [
  'Sem recomendações / Paz e Bem',
  'Manter cuidados com a ferida',
  'Entrar em contato com equipe médica',
  'Procurar UBS / PS',
  'Retorno ao hospital (PS)',
  'Agendar retorno ambulatorial',
];

export const MOTIVOS_INSUCESSO = [
  ['nao_atende',      'Não atende'],
  ['numero_invalido', 'Número inválido / inexistente'],
  ['caixa_postal',    'Caixa postal'],
  ['recusou',         'Recusou responder'],
  ['sem_resposta_wpp','Mensagem entregue, sem resposta'],
  ['outro',           'Outro'],
];

export const CANAIS = [
  ['whatsapp',   'WhatsApp'],
  ['telefone',   'Telefone'],
  ['presencial', 'Presencial'],
  ['prontuario', 'Prontuário / registro'],
  ['outro',      'Outro'],
];

export const ISC_TIPOS = [
  ['incisional_superficial', 'Incisional superficial'],
  ['incisional_profunda',    'Incisional profunda'],
  ['orgao_cavidade',         'Órgão / cavidade'],
];

export const ISC_CLASSIFICACOES = [
  ['nao_avaliada',  'Não avaliada'],
  ['investigando',  'Em investigação'],
  ['confirmada',    'ISC confirmada'],
  ['descartada',    'Descartada'],
];

export const POTENCIAL_CONTAMINACAO = [
  ['limpa',                    'Limpa'],
  ['potencialmente_contaminada','Potencialmente contaminada'],
  ['contaminada',              'Contaminada'],
  ['infectada',                'Infectada'],
];

export const STATUS_VIGILANCIA = [
  ['em_vigilancia',    'Em vigilância'],
  ['concluida',        'Concluída'],
  ['perda_seguimento', 'Perda de seguimento'],
  ['obito',            'Óbito'],
  ['excluida',         'Excluída'],
];

// Critérios diagnósticos (NHSN/ANVISA) — marcação múltipla na classificação.
export const ISC_CRITERIOS = [
  'Drenagem purulenta da incisão',
  'Cultura positiva de material da incisão/órgão',
  'Deiscência espontânea ou abertura deliberada com sinais/sintomas',
  'Abscesso ou evidência de infecção ao exame direto / reoperação',
  'Evidência de infecção em imagem (TC/RM/US)',
  'Diagnóstico de ISC pelo cirurgião ou médico assistente',
];

// ── Datas ─────────────────────────────────────────────────────────────────
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

// ── Rotina de importação do mapa cirúrgico ────────────────────────────────
// O mapa é importado toda segunda e quinta de manhã. Se passou do meio-dia e
// não veio, a vigilância começa a perder paciente — por isso o grid avisa.
//
// ⚠️ Aqui NÃO se usa hojeISO(): ele deriva de toISOString(), que é UTC, e
// depois das 21h BRT devolve o dia seguinte (TZ=America/Sao_Paulo não afeta
// toISOString). Dia da semana e hora-limite só fecham com métodos LOCais.
export const DIAS_IMPORTACAO = [1, 4];          // 1=segunda, 4=quinta (getDay)
export const HORA_LIMITE_IMPORTACAO = 12;

export function dataLocalISO(d = new Date()) {
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

// Último dia de importação já VENCIDO (passou do meio-dia). Olhar para trás —
// e não só para hoje — é o que impede a segunda esquecida de sumir do radar na
// terça: o alerta permanece até a importação acontecer.
export function diaEsperadoImportacao(agora = new Date(), dias = DIAS_IMPORTACAO, hora = HORA_LIMITE_IMPORTACAO) {
  const d = new Date(agora.getTime());
  for (let i = 0; i < 8; i++) {
    if (dias.includes(d.getDay()) && (i > 0 || agora.getHours() >= hora)) return dataLocalISO(d);
    d.setDate(d.getDate() - 1);
  }
  return null;
}

// { atrasada, esperado, ultima, diasAtraso } — comparação por DIA.
export function statusImportacao(ultimaImportacao, agora = new Date(), opts = {}) {
  const esperado = diaEsperadoImportacao(agora, opts.dias, opts.hora);
  if (!esperado) return { atrasada: false, esperado: null, ultima: toISODate(ultimaImportacao) || null };
  const ultima = ultimaImportacao ? dataLocalISO(new Date(ultimaImportacao)) : null;
  const atrasada = !ultima || ultima < esperado;
  const diasAtraso = atrasada
    ? Math.round((new Date(`${dataLocalISO(agora)}T00:00:00`) - new Date(`${esperado}T00:00:00`)) / 86400000)
    : 0;
  return { atrasada, esperado, ultima, diasAtraso };
}

// ── Exibição de data ──────────────────────────────────────────────────────
// DD-MM-AAAA: é como o SCIH lê data. Só para TELA.
//
// ⚠️ NUNCA usar no value de <input type="date">: o HTML exige AAAA-MM-DD e o
// campo fica VAZIO em silêncio se receber outro formato — o usuário abre o
// form de edição e acha que a data sumiu. Ali continua toISODate().
// Idem para <input type="month"> (AAAA-MM) e para valor que vai para o banco.
export function dataBR(d) {
  const iso = toISODate(d);
  if (!iso) return '';
  const [y, m, dd] = iso.split('-');
  return `${dd}-${m}-${y}`;
}

// ── Telefone ──────────────────────────────────────────────────────────────
// Normaliza para E.164 brasileiro (55 + DDD + número). Devolve null se não der.
// Guardamos o cru também (telefone_raw): nunca perder o que a pessoa digitou.
export function normalizaTelefone(raw) {
  let d = String(raw ?? '').replace(/\D/g, '');
  if (!d) return null;
  if (d.startsWith('00')) d = d.slice(2);
  if (d.length >= 12 && d.startsWith('55')) d = d.slice(2);   // já vinha com país
  if (d.length === 11 || d.length === 10) return '55' + d;    // DDD + 9/8 dígitos
  if (d.length === 8 || d.length === 9) return null;          // sem DDD → inútil p/ wa.me
  if (d.length >= 12 && d.length <= 15) return d;             // internacional
  return null;
}

export function formataTelefone(e164) {
  const d = String(e164 ?? '').replace(/\D/g, '');
  if (d.length === 13 && d.startsWith('55')) return `(${d.slice(2, 4)}) ${d.slice(4, 9)}-${d.slice(9)}`;
  if (d.length === 12 && d.startsWith('55')) return `(${d.slice(2, 4)}) ${d.slice(4, 8)}-${d.slice(8)}`;
  return e164 || '';
}

export function linkWhatsApp(e164, texto) {
  const d = String(e164 ?? '').replace(/\D/g, '');
  if (!d) return null;
  return `https://wa.me/${d}?text=${encodeURIComponent(String(texto ?? ''))}`;
}

// ── Janelas ───────────────────────────────────────────────────────────────
export function janelasDe(ficha, equipe) {
  const j = ficha?.janelas;
  if (Array.isArray(j) && j.length) return [...j].map(Number).filter(Boolean).sort((a, b) => a - b);
  const fonte = ficha?.implante ? equipe?.janelas_implante : equipe?.janelas_default;
  if (Array.isArray(fonte) && fonte.length) return [...fonte].map(Number).filter(Boolean).sort((a, b) => a - b);
  return ficha?.implante ? [7, 30, 90] : [7, 30];
}

// Tolerância: a janela de 7d aceita contato entre D+5 e D+14; 30d entre D+25 e
// D+44; 90d entre D+80 e D+120. Fora disso o contato ainda conta, mas o cálculo
// de "atrasado" usa a data prevista.
export const TOLERANCIA_ATRASO_DIAS = 7;

// ── Alertas ───────────────────────────────────────────────────────────────
// Um contato "acende alerta" quando as respostas do paciente sugerem possível
// ISC. Há duas fontes, e as duas convivem:
//
//   1. EMBUTIDAS (CHECKLIST[].alerta): o baseline clínico, versionado em código.
//      Nunca somem — mesmo que o banco de regras esteja vazio, febre acende.
//   2. CONFIGURÁVEIS (isc_alerta_regras): o médico cria/edita/desliga pela tela.
//      Permitem combinação (E dentro do grupo, OU entre grupos) e escopo por
//      equipe. É a resposta ao pedido de "regras de flag conforme as respostas".
//
// O resultado é o OR de tudo que está LIGADO. Desligar uma regra configurável
// não desliga o baseline embutido — para silenciar o baseline, a regra teria de
// ser reescrita em código (decisão consciente, não um clique).

// Uma CONDIÇÃO casa quando a resposta do campo contém algum dos valores.
function condCasa(respostas, cond) {
  const v = (respostas || {})[cond.campo];
  if (v == null) return false;
  const vals = (Array.isArray(v) ? v : [v]).map(String);
  const alvos = (Array.isArray(cond.valores) ? cond.valores : [cond.valores]).map(String);
  return vals.some(x => alvos.includes(x));
}

// Uma REGRA configurável casa quando ALGUM grupo casa (OU entre grupos), e um
// grupo casa quando TODAS as suas condições casam (E dentro do grupo).
// Formato: regra.grupos = [ [ {campo,valores}, ... ], ... ]
export function regraAlertaCasa(regra, respostas) {
  if (!regra || regra.ativo === false) return false;
  const grupos = Array.isArray(regra.grupos) ? regra.grupos : [];
  if (!grupos.length) return false;
  return grupos.some(grupo =>
    Array.isArray(grupo) && grupo.length > 0 && grupo.every(cond => condCasa(respostas, cond)));
}

// Sementes de alerta: as regras clínicas mínimas, entregues como regras NORMAIS
// e editáveis. O banco importa isto no primeiro boot (uma vez); a partir daí o
// médico ajusta ou apaga como quiser. Não há regra "embutida" aplicada em tempo
// de execução — o motor lê só o banco.
const NOME_SEED = {
  ferida: 'Sinais locais na ferida', dor_bifasica: 'Dor bifásica (melhorou e piorou)',
  febre: 'Febre', atb_pos: 'Antibiótico após a cirurgia',
  dx_infeccao: 'Diagnóstico de infecção da ferida', reabordagem: 'Reabordagem na mesma topografia',
  readmissao: 'Readmissão hospitalar',
};
export const REGRAS_ALERTA_SEED = CHECKLIST
  .filter(c => c.alerta && c.alerta.length)
  .map((c, i) => ({
    nome: NOME_SEED[c.key] || c.label, ordem: (i + 1) * 10,
    grupos: [[{ campo: c.key, valores: c.alerta }]],
  }));

// respostas + regras → acende? TODAS as regras são configuráveis (vêm do banco);
// não há mais piso embutido. `suspeita === true` (médico marcou) sempre acende.
export function contatoTemAlerta(respostas, suspeita, regras = []) {
  if (suspeita === true) return true;
  return (Array.isArray(regras) ? regras : []).some(r => regraAlertaCasa(r, respostas));
}

// Quais regras acenderam — para explicar na ficha "por que está sinalizado".
export function alertasDe(respostas, regras = []) {
  return (Array.isArray(regras) ? regras : []).filter(r => regraAlertaCasa(r, respostas)).map(r => r.nome);
}

// ── Motor de estado ───────────────────────────────────────────────────────
// Recalcula janelas_estado + derivados a partir da ficha e dos contatos.
// PURA: recebe dados, devolve o patch. Quem grava é a rota. Mesma disciplina
// do monitoring engine do ATB — o derivado nunca é a fonte da verdade.
//
// status por janela:
//   'concluida'  → houve contato com sucesso naquela janela
//   'pendente'   → data prevista ainda não chegou
//   'aberta'     → já venceu, dentro da tolerância, sem contato com sucesso
//   'atrasada'   → passou a tolerância, sem contato com sucesso
//   'sem_contato'→ tentativas registradas, todas sem sucesso, e já venceu tudo
export function recomputarEstado(ficha, contatos, equipe, hoje = hojeISO(), regrasAlerta = []) {
  const janelas = janelasDe(ficha, equipe);
  const dtCir = toISODate(ficha?.data_cirurgia);
  const lista = Array.isArray(contatos) ? contatos : [];

  const estado = {};
  let proximaJanela = null, proximoEm = null;
  let contatosOk = 0, tentativasFalhas = 0, temAlerta = false;

  for (const c of lista) {
    if (c?.sucesso === false) tentativasFalhas++;
    if (c?.sucesso !== false && contatoTemAlerta(c?.respostas, c?.suspeita_isc, regrasAlerta)) temAlerta = true;
  }

  for (const dias of janelas) {
    const prevista = dtCir ? addDays(dtCir, dias) : null;
    const daJanela = lista.filter(c => Number(c?.janela) === Number(dias));
    const ok = daJanela.find(c => c?.sucesso !== false) || null;
    const tentativas = daJanela.length;

    let status;
    if (ok) {
      status = 'concluida';
      contatosOk++;
    } else if (!prevista || prevista > hoje) {
      status = 'pendente';
    } else {
      const atraso = diffDias(prevista, hoje);
      if (atraso > TOLERANCIA_ATRASO_DIAS) status = tentativas > 0 ? 'sem_contato' : 'atrasada';
      else status = 'aberta';
    }

    estado[String(dias)] = {
      status,
      data_prevista: prevista,
      data_contato: ok ? toISODate(ok.data_contato) : null,
      contato_id: ok ? ok.id : null,
      tentativas,
      alerta: ok ? contatoTemAlerta(ok.respostas, ok.suspeita_isc, regrasAlerta) : false,
    };

    if (!ok && proximaJanela === null && (status === 'pendente' || status === 'aberta' || status === 'atrasada')) {
      proximaJanela = dias;
      proximoEm = prevista;
    }
  }

  const ultimo = lista
    .map(c => c?.data_contato)
    .filter(Boolean)
    .sort()
    .pop() || null;

  // Fecha a vigilância sozinha quando todas as janelas foram cumpridas.
  // Não mexe em status terminal decidido por pessoa (óbito/perda/excluída).
  let status_vigilancia = ficha?.status_vigilancia || 'em_vigilancia';
  const terminais = new Set(['obito', 'perda_seguimento', 'excluida']);
  if (!terminais.has(status_vigilancia)) {
    const todasOk = janelas.length > 0 && janelas.every(d => estado[String(d)]?.status === 'concluida');
    status_vigilancia = todasOk ? 'concluida' : 'em_vigilancia';
  }

  return {
    janelas,
    janelas_estado: estado,
    proxima_janela: proximaJanela,
    proximo_contato_em: proximoEm,
    contatos_ok: contatosOk,
    tentativas_falhas: tentativasFalhas,
    tem_alerta: temAlerta,
    ultimo_contato_em: ultimo,
    status_vigilancia,
  };
}

// ── Templates de mensagem ─────────────────────────────────────────────────
export function primeiroNome(nome) {
  const n = String(nome ?? '').trim();
  if (!n) return 'tudo bem';
  return n.split(/\s+/)[0].replace(/^(.)(.*)$/, (_, a, b) => a.toUpperCase() + b.toLowerCase());
}

// Exibição em prosa, para a MENSAGEM DO PACIENTE: "sua cirurgia (01/07/2026)".
// Barra é a forma natural em texto corrido — a tela usa hífen (dataBR).
function dataBarra(iso) {
  const d = toISODate(iso);
  if (!d) return '';
  const [y, m, dd] = d.split('-');
  return `${dd}/${m}/${y}`;
}

// Substitui {{chave}}. Placeholder desconhecido vira string vazia (nunca deixa
// "{{x}}" vazar para o paciente).
export function renderTemplate(corpo, ctx) {
  const vars = {
    paciente:       ctx?.paciente_nome || ctx?.paciente_iniciais || '',
    primeiro_nome:  primeiroNome(ctx?.paciente_nome || ''),
    iniciais:       ctx?.paciente_iniciais || '',
    procedimento:   ctx?.procedimento || 'sua cirurgia',
    data_cirurgia:  dataBarra(ctx?.data_cirurgia),
    dias_pos_op:    ctx?.dias_pos_op != null ? String(ctx.dias_pos_op) : '',
    equipe:         ctx?.equipe || ctx?.especialidade || 'equipe cirúrgica',
    hospital:       ctx?.hospital || '',
    cirurgiao:      ctx?.cirurgiao || '',
  };
  return String(corpo ?? '').replace(/\{\{\s*([a-z_]+)\s*\}\}/gi, (_, k) => {
    const v = vars[String(k).toLowerCase()];
    return v == null ? '' : String(v);
  });
}

export const PLACEHOLDERS = [
  '{{primeiro_nome}}', '{{paciente}}', '{{iniciais}}', '{{procedimento}}',
  '{{data_cirurgia}}', '{{dias_pos_op}}', '{{equipe}}', '{{cirurgiao}}', '{{hospital}}',
];

// ── Sanitização ───────────────────────────────────────────────────────────
export function boolDe(v) {
  const s = String(v ?? '').trim().toLowerCase();
  if (['1', 'true', 'on', 'sim', 's', 'yes'].includes(s)) return true;
  if (['0', 'false', 'off', 'nao', 'não', 'n', 'no'].includes(s)) return false;
  return null;
}

export function enumDe(v, permitidos, fallback = null) {
  const s = String(v ?? '').trim();
  return permitidos.includes(s) ? s : fallback;
}

// Extrai só as chaves do checklist do corpo do POST; o resto é descartado.
// (Evita que campo solto do form vire chave arbitrária no JSONB.)
export function extraiRespostas(body) {
  const out = {};
  for (const campo of CHECKLIST) {
    const raw = body?.[`r_${campo.key}`];
    if (raw == null || raw === '') continue;
    if (campo.tipo === 'multi') {
      const arr = Array.isArray(raw) ? raw : [raw];
      const val = arr.map(String).filter(x => campo.opcoes.includes(x));
      if (val.length) out[campo.key] = val;
    } else if (campo.tipo === 'sim_nao') {
      const s = String(raw);
      if (s === 'Sim' || s === 'Não' || s === 'Não sabe') out[campo.key] = s;
    } else {
      out[campo.key] = String(raw).slice(0, 2000);
    }
  }
  return out;
}
