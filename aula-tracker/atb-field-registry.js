// atb-field-registry.js
// ════════════════════════════════════════════════════════════════════════════
// REGISTRO DE CAMPOS — fonte única de verdade sobre os campos da ficha.
//
// Hoje o mesmo conjunto de campos vive replicado à mão em ~8 lugares (parser,
// 3 INSERTs, registries de edição, COLS da grade, telas de detalhe). É por isso
// que o INSERT "perde coluna" a cada refactor: são listas paralelas mantidas de
// cabeça, não derivadas umas das outras.
//
// Este módulo deriva TUDO do schema vivo (atb_form_schema) + um punhado de
// metadados que o schema não carrega (renomeações de coluna e as colunas
// computadas/sistema que não correspondem a um campo do formulário).
//
// Garantia de projeto: este registro REPRODUZ o INSERT hard-coded atual de
// atb-routes.js (POST /atb/api/fichas):
//   11 colunas de sistema/computadas + 45 derivadas do schema = 56 (idêntico),
//   54 parâmetros ($N) — now() e 'pendente' inline, como hoje.
// A serialização (scalar vs JSON) é DERIVADA do tipo do campo no schema:
//   checkbox|matrix → JSON.stringify ; todo o resto → scalar — casando 1:1
//   com o JSON.stringify(...) espalhado no INSERT atual.
//
// Campos do schema SEM coluna real em atb_fichas (ainda não promovidos) ficam
// de fora do INSERT e viajam em payload_raw — é o estado "extras" do modelo
// híbrido. "Promover" = ALTER TABLE + backfill do payload_raw; na próxima
// leitura de colunas reais o campo entra no INSERT sozinho.
//
// Exporta:
//   COLUNA_DE                — chave do schema → coluna real (quando diferem)
//   camposDoSchema(schema)   — campos do schema que geram coluna de dados
//   registroFicha(schema)    — plano ordenado de colunas da ficha
//   colunasReaisFichas(pool) — Set de colunas de atb_fichas (information_schema)
//   gerarInsertFichas(opts)  — { text, values, mapa, extras } (INSERT param.)
//   serializa(serial, valor) — coerção de serialização (scalar|json)
// ════════════════════════════════════════════════════════════════════════════

// ── Renomeações: chave no schema/form → coluna física em atb_fichas ───────────
// (mesmo mapa que o parser aplica ao montar `parsed`, e que as regras usam.)
export const COLUNA_DE = {
  pac_nome: 'paciente_nome',
  pac_dn:   'paciente_dn',
  equipe:   'equipe_responsavel',
  data_uti: 'data_admissao_uti',
};

// Tipos de campo cujo valor é array/objeto e grava como JSONB.
const TIPOS_JSON = new Set(['checkbox', 'matrix']);

// Tipos de campo que NÃO geram coluna de dados (widgets / blocos compostos):
//   sofa       — _sofa_bloco produz sofa/sofa_renal via parser (colunas de sistema)
//   dose_vanco — widget de apoio à decisão; escreve na matriz posologia
export const TIPOS_SEM_COLUNA = new Set(['sofa', 'dose_vanco']);

// ── Colunas de SISTEMA / COMPUTADAS ───────────────────────────────────────────
// Não correspondem a um campo do formulário (são contexto, derivadas ou fixas).
// `from` diz de onde o gerador tira o valor:
//   ['ctx', k]    → ctx[k]
//   ['parsed', k] → parsed[k]  (computado pelo parser: idade, sofa, links, raw)
//   ['sql', expr] → expressão SQL inline sem placeholder (ex.: now())
//   ['lit', v]    → literal SQL inline com aspas (ex.: status 'pendente')
// `serial`: 'json' aplica JSON.stringify; 'scalar' (default) passa direto.
export const COLUNAS_SISTEMA = [
  { col: 'instituicao_id',        from: ['ctx', 'instituicao_id'] },
  { col: 'jotform_submission_id', from: ['ctx', 'submission_id'] },
  { col: 'jotform_created_at',    from: ['sql', 'now()'] },
  { col: 'paciente_nome_raw',     from: ['parsed', 'paciente_nome_raw'] },
  { col: 'paciente_idade',        from: ['parsed', 'paciente_idade'] },
  { col: 'sofa',                  from: ['parsed', 'sofa'] },
  { col: 'sofa_renal',            from: ['parsed', 'sofa_renal'] },
  { col: 'payload_raw',           from: ['ctx', 'payload_raw'], serial: 'json' },
  { col: 'historia_narrativa',    from: ['ctx', 'historia_narrativa'] },
  { col: 'status',                from: ['lit', 'pendente'] },
  { col: 'link_exames',           from: ['parsed', 'link_exames'] },
  { col: 'link_labs',             from: ['parsed', 'link_labs'] },
];

// ── Campos derivados do SCHEMA ────────────────────────────────────────────────
// Percorre secoes→campos e devolve, para cada campo que vira coluna de dados,
// um descritor { key (schema), col (banco), serial, tipoForm, secao }.
// Sub-colunas de matrix (colunas:[{key:...}]) NÃO são campos — não são visitadas
// porque a caminhada é só no nível campos[].
export function camposDoSchema(schema) {
  const out = [], vistos = new Set();
  for (const sec of (schema?.secoes || [])) {
    for (const c of (sec.campos || [])) {
      if (!c || !c.key || c.key.charAt(0) === '_') continue;   // _sofa_bloco etc.
      if (TIPOS_SEM_COLUNA.has(c.type)) continue;               // widgets
      const col = COLUNA_DE[c.key] || c.key;
      if (vistos.has(col)) continue; vistos.add(col);
      out.push({
        key: c.key,
        col,
        serial: TIPOS_JSON.has(c.type) ? 'json' : 'scalar',
        tipoForm: c.type,
        secao: sec.id || sec.titulo || null,
      });
    }
  }
  return out;
}

// ── Registro completo da ficha (sistema + schema), ordenado ───────────────────
// Cada item: { col, serial, origem:'sistema'|'coluna', from, key?, tipoForm?, secao? }
export function registroFicha(schema) {
  const sistema = COLUNAS_SISTEMA.map(s => ({
    col: s.col, serial: s.serial || 'scalar', origem: 'sistema', from: s.from,
  }));
  const doSchema = camposDoSchema(schema).map(c => ({
    col: c.col, serial: c.serial, origem: 'coluna',
    key: c.key, tipoForm: c.tipoForm, secao: c.secao,
    from: ['parsed', c.col],        // o parser expõe pelos nomes de COLUNA
  }));
  return [...sistema, ...doSchema];
}

// ── Colunas reais de atb_fichas (para decidir coluna vs extras) ───────────────
export async function colunasReaisFichas(pool) {
  const { rows } = await pool.query(`
    SELECT column_name FROM information_schema.columns
    WHERE table_name = 'atb_fichas'
  `);
  return new Set(rows.map(r => r.column_name));
}

// ── Serialização (espelha o JSON.stringify(...) do INSERT atual) ──────────────
export function serializa(serial, valor) {
  if (serial === 'json') return JSON.stringify(valor);
  return valor;
}

// ── Gerador do INSERT da ficha ────────────────────────────────────────────────
// opts:
//   schema        — definição viva do formulário (de getFormSchema)
//   parsed        — saída de parseFormPayload(d)
//   ctx           — { instituicao_id, submission_id, payload_raw }
//   colunasReais  — Set de colunas existentes em atb_fichas.
//                   Campos do schema sem coluna real ficam FORA do INSERT —
//                   o valor já viaja em payload_raw (estado 'extras').
// Retorna { text, values, mapa, extras }:
//   text/values — INSERT parametrizado pronto para pool.query
//   mapa        — { coluna: valor } (para harness de paridade / auditoria)
//   extras      — [keys do schema sem coluna real] (não promovidos)
export function gerarInsertFichas({ schema, parsed, ctx, colunasReais }) {
  const plano = registroFicha(schema);
  const cols = [], placeholders = [], values = [], mapa = {}, extras = [];
  let i = 1;

  for (const item of plano) {
    if (item.origem === 'coluna' && colunasReais && !colunasReais.has(item.col)) {
      extras.push(item.key || item.col);
      continue;
    }
    const [tipo, ref] = item.from;
    if (tipo === 'sql') {
      cols.push(item.col); placeholders.push(ref); mapa[item.col] = `SQL:${ref}`;
      continue;
    }
    if (tipo === 'lit') {
      cols.push(item.col); placeholders.push(`'${String(ref).replace(/'/g, "''")}'`);
      mapa[item.col] = ref;
      continue;
    }
    let valor;
    if (tipo === 'ctx')         valor = ctx ? ctx[ref] : null;
    else if (tipo === 'parsed') valor = parsed ? parsed[ref] : null;
    else valor = null;

    valor = serializa(item.serial, valor);
    cols.push(item.col);
    placeholders.push('$' + i++);
    values.push(valor);
    mapa[item.col] = valor;
  }

  const text =
    `INSERT INTO atb_fichas (\n  ${cols.join(', ')}\n) VALUES (\n  ${placeholders.join(', ')}\n) RETURNING id`;

  return { text, values, mapa, extras };
}
