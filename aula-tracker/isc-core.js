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
// Um contato "acende alerta" se qualquer resposta bater com CHECKLIST[].alerta.
export function contatoTemAlerta(respostas, suspeita) {
  if (suspeita === true) return true;
  const r = respostas || {};
  for (const campo of CHECKLIST) {
    if (!campo.alerta) continue;
    const v = r[campo.key];
    if (v == null) continue;
    const vals = Array.isArray(v) ? v : [v];
    if (vals.some(x => campo.alerta.includes(String(x)))) return true;
  }
  return false;
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
export function recomputarEstado(ficha, contatos, equipe, hoje = hojeISO()) {
  const janelas = janelasDe(ficha, equipe);
  const dtCir = toISODate(ficha?.data_cirurgia);
  const lista = Array.isArray(contatos) ? contatos : [];

  const estado = {};
  let proximaJanela = null, proximoEm = null;
  let contatosOk = 0, tentativasFalhas = 0, temAlerta = false;

  for (const c of lista) {
    if (c?.sucesso === false) tentativasFalhas++;
    if (c?.sucesso !== false && contatoTemAlerta(c?.respostas, c?.suspeita_isc)) temAlerta = true;
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
      alerta: ok ? contatoTemAlerta(ok.respostas, ok.suspeita_isc) : false,
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
