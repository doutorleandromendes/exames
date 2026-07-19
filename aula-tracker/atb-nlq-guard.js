// atb-nlq-guard.js
// ════════════════════════════════════════════════════════════════════════════
// GUARD read-only para o SQL gerado pelo LLM (NL→SQL).
//
// DEFESA EM PROFUNDIDADE. Este guard é a SEGUNDA linha de defesa. A PRIMEIRA e
// mais importante é rodar o SQL numa conexão com um ROLE read-only do Postgres
// (default_transaction_read_only = on) + statement_timeout curto. NUNCA rode SQL
// vindo do modelo numa conexão com privilégio de escrita, mesmo com este guard.
//
// O guard filtra o óbvio (DDL/DML, múltiplos statements, funções perigosas) e
// força um LIMIT. Ele NÃO substitui o role read-only — é cinto + suspensório.
// ════════════════════════════════════════════════════════════════════════════

// Palavras-chave de escrita/DDL/administração. Word-boundary evita falso-positivo
// em identificadores como updated_at, created_at, deletado_em, 'avaliado', etc.
const PALAVRAS_PROIBIDAS = /\b(insert|update|delete|drop|alter|create|truncate|grant|revoke|copy|call|do|merge|vacuum|analyze|reindex|cluster|comment|lock|into|refresh|prepare|execute|reset)\b/i;

// Funções que leem arquivos, dormem, ou mexem em backends/config — bloquear.
const FUNCOES_PERIGOSAS = /\b(pg_sleep|pg_read_file|pg_read_binary_file|pg_ls_dir|lo_import|lo_export|dblink|pg_terminate_backend|pg_cancel_backend|set_config|pg_reload_conf)\s*\(/i;

/**
 * Valida que o SQL é somente-leitura e um único statement.
 * @param {string} sqlBruto - SQL cru vindo do modelo.
 * @returns {{ ok: boolean, erros: string[], sql: string }}
 */
export function validarSQLLeitura(sqlBruto) {
  const erros = [];
  if (!sqlBruto || typeof sqlBruto !== 'string') {
    return { ok: false, erros: ['SQL vazio ou inválido.'], sql: '' };
  }

  // Remove cercas de markdown (```sql ... ```) que o modelo às vezes emite.
  let sql = sqlBruto.trim()
    .replace(/^```(?:sql)?\s*/i, '')
    .replace(/\s*```$/i, '')
    .trim();

  // Remove um ";" final único; qualquer ";" restante = múltiplos statements.
  sql = sql.replace(/;\s*$/, '');
  if (sql.includes(';')) erros.push('Múltiplos statements não são permitidos (";" no meio).');

  // Analisa uma versão sem comentários (pra não esconderem payload).
  const semComentarios = sql
    .replace(/--.*$/gm, '')
    .replace(/\/\*[\s\S]*?\*\//g, '');

  if (!/^\s*(select|with)\b/i.test(semComentarios)) {
    erros.push('Apenas SELECT ou WITH é permitido.');
  }
  if (PALAVRAS_PROIBIDAS.test(semComentarios)) {
    erros.push('Palavra-chave de escrita/DDL detectada.');
  }
  if (FUNCOES_PERIGOSAS.test(semComentarios)) {
    erros.push('Função perigosa detectada (I/O de arquivo, sleep, admin de backend).');
  }

  return { ok: erros.length === 0, erros, sql };
}

/**
 * Garante um LIMIT no fim de queries que retornam linhas, para não puxar a base
 * inteira. Não mexe em queries que já têm LIMIT. Agregados (sem LIMIT) também
 * ganham um teto — inofensivo, e barato como rede de segurança.
 * @param {string} sql
 * @param {number} [limite=500]
 * @returns {string}
 */
export function forcarLimite(sql, limite = 500) {
  if (/\blimit\s+\d+/i.test(sql)) return sql;
  return `${sql.trimEnd()}\nLIMIT ${limite}`;
}

/**
 * Conveniência: valida e (se ok) aplica o limite. Retorna o objeto de validação
 * com o SQL já limitado quando ok===true.
 */
export function prepararSQL(sqlBruto, limite = 500) {
  const v = validarSQLLeitura(sqlBruto);
  if (!v.ok) return v;
  return { ...v, sql: forcarLimite(v.sql, limite) };
}
