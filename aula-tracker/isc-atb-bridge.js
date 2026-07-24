// isc-atb-bridge.js
// ════════════════════════════════════════════════════════════════════════════
// PONTE ISC → ATB
//
// Quando o médico do SCIH classifica uma ficha de vigilância como ISC
// CONFIRMADA, cria automaticamente a ficha retrospectiva correspondente no
// portal de ATB, já classificada como IrAS = ISC.
//
// Por que existe: a ISC confirmada na busca ativa é, por definição, uma IrAS —
// e hoje ela precisa ser redigitada à mão no ATB para entrar no numerador do
// CVE. Redigitação é onde o dado se perde.
//
// ── PRINCÍPIO: NÃO INVENTAR VALOR DE DROPDOWN ─────────────────────────────
// Todo valor que cai num campo de opções fixas é validado, EM RUNTIME, contra
// a fonte canônica daquele campo — não contra uma cópia feita aqui:
//   • foco_infeccao  → options do campo no schema VIVO (atb_form_schema)
//   • recomendacao_scih (parecer) → PARECER_VEREDITOS (atb-parecer-edit-routes)
//   • iras           → IRAS_VALORES (atb-regras-routes)
// Se algum valor deixar de existir na origem, a ponte FALHA ALTO (lança), em vez
// de gravar lixo silencioso numa ficha que alimenta indicador oficial.
//
// ── DESCOBERTAS DO SCHEMA QUE MOLDARAM ESTE MÓDULO ────────────────────────
//  1. `iras` NÃO está em atb_fichas: vive em atb_avaliacoes (ficha_id UNIQUE).
//     São dois INSERTs, não um.
//  2. `data_referencia` e `data_da_cirurgia_infectada` NÃO estão no CREATE TABLE
//     base: são campos PROMOVIDOS de payload_raw (atb-form-editor-routes). Podem
//     ou não existir. Por isso as colunas opcionais são checadas no
//     information_schema em runtime — mesmo padrão do atb-grid-filters, que já
//     faz `colsReais.has('data_da_cirurgia_infectada')`. Quando a coluna não
//     existe, o valor vai para payload_raw (modelo híbrido do projeto), sem
//     perder o dado.
//  3. Nada em atb_fichas é NOT NULL além do id — o que exige disciplina nossa,
//     não do banco.
// ════════════════════════════════════════════════════════════════════════════

import { getFormSchema } from './atb-form-schema.js';
import { PARECER_VEREDITOS } from './atb-parecer-edit-routes.js';
import { IRAS_VALORES } from './atb-regras-routes.js';
import { toISODate, dataBR, contatoTemAlerta } from './isc-core.js';

// ── Valores pretendidos (o QUE queremos gravar) ────────────────────────────
// Ficam aqui só como intenção declarada; a validação abaixo é que decide se
// podem ser usados.
export const ALVO = {
  foco_infeccao: 'Infecção do sítio cirúrgico',
  parecer:       'Audit_post',
  iras:          'ISC',
  // Setor de internação. A ficha nasce da vigilância pós-alta, então não há
  // setor "de verdade" — mas a coluna alimenta filtro e recorte da grade do ATB,
  // e deixá-la nula bagunçaria o agrupamento. 'PS' é o valor combinado como
  // neutro. Também é validado contra o schema: se sumir da lista, a ponte para.
  setor:         'PS',
};

const PREFIXO_HISTORIA = 'Imput do Sistema de ISC';

// ── Validação contra as fontes canônicas ──────────────────────────────────
// Devolve { ok, erros[], opcoes:{...} }. Não grava nada — serve tanto para a
// gravação quanto para um "pré-voo" que a tela pode mostrar antes de acionar.
export async function validarValores(pool, sigla = 'HUSF') {
  const erros = [];
  const opcoes = {};

  // 1. foco_infeccao — do schema VIVO do formulário
  let schema = null;
  try { schema = await getFormSchema(pool, sigla); } catch (e) { erros.push(`schema do formulário ilegível: ${e.message}`); }
  const campos = schema ? (schema.secoes || schema.blocos || []).flatMap(s => s.campos || []) : [];
  for (const [chave, alvo] of [['foco_infeccao', ALVO.foco_infeccao], ['setor', ALVO.setor]]) {
    const campo = campos.find(c => c.key === chave);
    if (!campo) { erros.push(`campo '${chave}' não encontrado no schema ativo de ${sigla}`); continue; }
    opcoes[chave] = campo.options || [];
    if (!opcoes[chave].includes(alvo)) {
      erros.push(`'${alvo}' não está nas opções de ${chave}: ${JSON.stringify(opcoes[chave])}`);
    }
  }

  // 2. parecer (veredito) — fonte única do módulo de parecer
  opcoes.parecer = PARECER_VEREDITOS;
  if (!PARECER_VEREDITOS.includes(ALVO.parecer)) {
    erros.push(`'${ALVO.parecer}' não está em PARECER_VEREDITOS`);
  }

  // 3. iras — lista canônica exportada
  opcoes.iras = IRAS_VALORES;
  if (!IRAS_VALORES.includes(ALVO.iras)) {
    erros.push(`'${ALVO.iras}' não está em IRAS_VALORES`);
  }

  return { ok: erros.length === 0, erros, opcoes };
}

// ── Colunas opcionais (promovidas) ────────────────────────────────────────
// Mesmo padrão do atb-grid-filters: perguntar ao banco, não presumir.
export async function colunasReais(pool, tabela = 'atb_fichas') {
  const { rows } = await pool.query(
    `SELECT column_name FROM information_schema.columns WHERE table_name = $1`, [tabela]);
  return new Set(rows.map(r => r.column_name));
}

// ── História clínica ──────────────────────────────────────────────────────
// "Imput do Sistema de ISC - [nome da cirurgia] [data da cirurgia]"
// Texto livre, então não há dropdown a validar — mas há o cuidado de não
// produzir "undefined" nem sobra de hífen quando falta procedimento ou data.
export function montarHistoriaClinica(ficha) {
  const proc = String(ficha?.procedimento ?? '').trim();
  const dt = dataBR(ficha?.data_cirurgia);
  const partes = [proc, dt].filter(Boolean).join(' ');
  return partes ? `${PREFIXO_HISTORIA} - ${partes}` : PREFIXO_HISTORIA;
}

// ── Data de referência ────────────────────────────────────────────────────
// "data do contato que gerou o alerta confirmado": o contato mais recente que
// ACENDEU alerta. `isc_contatos` não guarda um booleano "alertou" — o alerta é
// derivado das respostas pelas regras vigentes (mesma disciplina do resto do
// módulo: derivado nunca é fonte da verdade). Por isso recebe `regras`.
//
// Cascata quando nenhum contato acendeu (ex.: o médico confirmou a ISC por
// outra via, sem que a resposta batesse regra): data do diagnóstico → último
// contato → data da cirurgia. Nunca fica nula em silêncio.
export function dataDoContatoQueAlertou(contatos, ficha, regras = []) {
  const comAlerta = (contatos || [])
    .filter(c => c && c.sucesso !== false && contatoTemAlerta(c.respostas, c.suspeita_isc, regras))
    .sort((a, b) => String(toISODate(b.data_contato) || '').localeCompare(String(toISODate(a.data_contato) || '')));
  return toISODate(comAlerta[0]?.data_contato)
      || toISODate(ficha?.isc_data_diagnostico)
      || toISODate(ficha?.ultimo_contato_em)
      || toISODate(ficha?.data_cirurgia)
      || null;
}

// ── Criação da ficha no ATB ───────────────────────────────────────────────
// Idempotente por construção: se a ficha ISC já aponta para uma ficha ATB viva,
// não cria outra. Ficha ATB duplicada inflaria o numerador de IrAS do CVE — é o
// erro mais caro que esta ponte poderia cometer, então é o primeiro a ser
// barrado. Também respeita re-salvamentos da classificação, que são normais.
//
// Devolve { criada:boolean, atbFichaId, motivo }.
export async function criarFichaAtbDeIsc(pool, iscFichaId, opts = {}) {
  const { userId = null, sigla = 'HUSF' } = opts;

  const { rows: [f] } = await pool.query(
    `SELECT f.*, e.nome AS equipe_nome, i.sigla AS inst_sigla
       FROM isc_fichas f
       LEFT JOIN isc_equipes e ON e.id = f.equipe_id
       LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
      WHERE f.id = $1`, [iscFichaId]);
  if (!f) return { criada: false, motivo: 'ficha ISC não encontrada' };

  if (f.isc_classificacao !== 'confirmada') {
    return { criada: false, motivo: `classificação é '${f.isc_classificacao}', não 'confirmada'` };
  }

  // Idempotência: já existe ficha ATB ligada a esta?
  //
  // ⚠️ ESTA GUARDA FALHA FECHADA, de propósito. A primeira versão usava
  // `.catch(() => ({ rows: [] }))` para tolerar a ausência da coluna opcional
  // `deletado_em` — e o efeito foi o oposto do pretendido: quando a consulta
  // falhava, a guarda concluía "não existe" e criava uma SEGUNDA ficha de IrAS.
  // Um teste de reclassificação pegou isso. Guarda que não consegue verificar
  // tem de bloquear, nunca liberar: ficha de IrAS duplicada infla o numerador
  // do CVE e é muito mais cara que uma criação a menos.
  if (f.atb_ficha_id) {
    const colsF = await colunasReais(pool, 'atb_fichas');
    const filtroVivo = colsF.has('deletado_em') ? ' AND deletado_em IS NULL' : '';
    let ja = null;
    try {
      const { rows } = await pool.query(
        `SELECT id FROM atb_fichas WHERE id = $1${filtroVivo}`, [f.atb_ficha_id]);
      ja = rows[0] || null;
    } catch (e) {
      // Não deu para verificar → não cria.
      return { criada: false, atbFichaId: f.atb_ficha_id,
               motivo: `não foi possível verificar a ficha ATB existente (${e.message}) — criação bloqueada por segurança` };
    }
    if (ja) return { criada: false, atbFichaId: f.atb_ficha_id, motivo: 'já existe ficha ATB para esta ISC' };
  }

  // Só cria com os valores validados na origem. Falha alto: uma ficha que
  // alimenta indicador oficial não pode nascer com campo inventado.
  const val = await validarValores(pool, f.inst_sigla || sigla);
  if (!val.ok) {
    throw new Error(`ponte ISC→ATB abortada, valores inválidos na origem: ${val.erros.join(' · ')}`);
  }

  const { rows: contatos } = await pool.query(
    `SELECT * FROM isc_contatos WHERE ficha_id = $1 ORDER BY data_contato DESC`, [iscFichaId]);
  // Regras de alerta vigentes para a equipe da ficha (mesmo escopo do grid).
  const { rows: regrasTodas } = await pool.query(
    `SELECT * FROM isc_alerta_regras
      WHERE ativo = true AND ($1::int IS NULL OR instituicao_id = $1) ORDER BY ordem, id`,
    [f.instituicao_id]);
  const regras = regrasTodas.filter(r => {
    const eqs = Array.isArray(r.equipe_ids) ? r.equipe_ids : [];
    return eqs.length === 0 || (f.equipe_id != null && eqs.map(Number).includes(Number(f.equipe_id)));
  });
  const dataRef = dataDoContatoQueAlertou(contatos, f, regras);
  const historia = montarHistoriaClinica(f);
  const dataCirurgia = toISODate(f.data_cirurgia);

  const cols = await colunasReais(pool, 'atb_fichas');

  // Colunas fixas (existem no CREATE TABLE base).
  const campos = {
    instituicao_id: f.instituicao_id,
    paciente_nome: f.paciente_nome || null,
    paciente_nome_raw: f.paciente_nome || null,
    prontuario: f.prontuario || null,
    setor: ALVO.setor,
    atendimento: f.atendimento || null,
    historia_clinica: historia,
    foco_infeccao: ALVO.foco_infeccao,
    cirurgia: f.procedimento || null,
    equipe_responsavel: f.equipe_nome || null,
    // ATB = null: a coluna é JSONB de lista. Lista vazia é "nenhum ATB
    // solicitado"; NULL seria "não sabemos". Aqui sabemos: é vazia.
    atb_solicitado: JSON.stringify([]),
    recomendacao_scih: JSON.stringify([ALVO.parecer]),
    retrospectiva: true,
    status: 'pendente',
  };

  // Colunas promovidas: só entram se existirem de fato. O que não existir vai
  // para payload_raw, que é onde o modelo híbrido guarda campo não promovido.
  const extras = {};
  const opcional = (col, valor) => {
    if (valor == null) return;
    if (cols.has(col)) campos[col] = valor; else extras[col] = valor;
  };
  opcional('data_referencia', dataRef);
  opcional('data_da_cirurgia_infectada', dataCirurgia);

  // Rastreabilidade da origem, sempre em payload_raw (não depende de coluna).
  extras.origem_isc = {
    isc_ficha_id: f.id,
    isc_tipo: f.isc_tipo || null,
    isc_data_diagnostico: toISODate(f.isc_data_diagnostico),
    isc_patogeno: f.isc_patogeno || null,
    data_cirurgia: dataCirurgia,
    procedimento: f.procedimento || null,
    equipe: f.equipe_nome || null,
    criado_em: new Date().toISOString(),
  };
  campos.payload_raw = JSON.stringify(extras);
  if (cols.has('criada_por')) campos.criada_por = userId;

  const nomes = Object.keys(campos);
  const marcadores = nomes.map((n, i) =>
    (n === 'atb_solicitado' || n === 'recomendacao_scih' || n === 'payload_raw') ? `$${i + 1}::jsonb`
    : (n === 'data_referencia' || n === 'data_da_cirurgia_infectada') ? `$${i + 1}::date`
    : `$${i + 1}`);
  const valores = nomes.map(n => campos[n]);

  const { rows: [nova] } = await pool.query(
    `INSERT INTO atb_fichas (${nomes.join(', ')}, created_at, updated_at)
     VALUES (${marcadores.join(', ')}, now(), now()) RETURNING id`, valores);

  // IrAS vive em atb_avaliacoes (ficha_id UNIQUE) — INSERT separado.
  await pool.query(
    `INSERT INTO atb_avaliacoes (ficha_id, iras, avaliado_por, created_at, updated_at)
     VALUES ($1, $2, $3, now(), now())
     ON CONFLICT (ficha_id) DO UPDATE SET iras = EXCLUDED.iras, updated_at = now()`,
    [nova.id, ALVO.iras, userId]);

  await pool.query(`UPDATE isc_fichas SET atb_ficha_id = $2, updated_at = now() WHERE id = $1`,
    [iscFichaId, nova.id]);

  return { criada: true, atbFichaId: nova.id, dataReferencia: dataRef, historia };
}
