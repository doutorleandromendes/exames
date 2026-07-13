// atb-triagem-regras.js
// ─────────────────────────────────────────────────────────────────────────
// MOTOR DE TRIAGEM POR REGRAS (Fase 1 — o "cérebro").
//
// Regras vivem no banco (atb_triagem_regras) e são avaliadas na CRIAÇÃO da
// ficha. A primeira regra (por prioridade) cujas condições casam aplica suas
// ações: preenche Parecer (veredito/especificação) e/ou IrAS — SEMPRE de forma
// auditável, marcada e SÓ em campo vazio (nunca sobrescreve trabalho humano,
// nem toca fichas já classificadas).
//
// A linguagem de condição é a MESMA do formulário (avaliaCond), portada aqui
// para o servidor, + operadores numéricos (lt/lte/gt/gte) p/ idade_dias etc.
//
// Fase 2 (próxima): painel /atb/admin/regras p/ povoar/editar sem SQL.
// ─────────────────────────────────────────────────────────────────────────

// ── Schema + seed ──────────────────────────────────────────────────────────
import { buscarCulturasDaFicha } from './atb-culturas-routes.js';
import { buscarHemoDaFicha, hemoTemAlerta } from './atb-hemocultura-routes.js';
import { buscarMdrDaFicha, mdrTemAlerta, mdrResistencias } from './atb-mdr-routes.js';

export async function ensureTriagemRegrasSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atb_triagem_regras (
      id          SERIAL PRIMARY KEY,
      nome        TEXT UNIQUE NOT NULL,
      descricao   TEXT,
      prioridade  INTEGER NOT NULL DEFAULT 100,   -- menor avalia primeiro
      ativo       BOOLEAN NOT NULL DEFAULT true,
      condicoes   JSONB   NOT NULL DEFAULT '{}',   -- { all:[...] } | { any:[...] }
      acoes       JSONB   NOT NULL DEFAULT '{}',   -- { veredito, especificacao, iras, etiol_iras, ... }
      modo        TEXT    NOT NULL DEFAULT 'auto', -- 'auto' (reservado p/ futuro)
      created_by  INTEGER REFERENCES users(id),
      created_at  TIMESTAMPTZ DEFAULT now(),
      updated_at  TIMESTAMPTZ DEFAULT now()
    )
  `);
  await pool.query(`ALTER TABLE atb_avaliacoes ADD COLUMN IF NOT EXISTS triagem_regra_id INTEGER`);
  await pool.query(`ALTER TABLE atb_avaliacoes ADD COLUMN IF NOT EXISTS triagem_regra_at TIMESTAMPTZ`);

  // ── Tenant (2b): instituição por regra ────────────────────────────────────
  // Coluna de escopo (sigla). Linhas existentes viram HUSF → triagem do HUSF
  // continua idêntica. A unicidade do nome passa a ser POR instituição, para que
  // HUSF e H2 possam ter regras de mesmo nome. Tudo idempotente.
  await pool.query(`ALTER TABLE atb_triagem_regras ADD COLUMN IF NOT EXISTS instituicao TEXT`);
  await pool.query(`UPDATE atb_triagem_regras SET instituicao='HUSF' WHERE instituicao IS NULL`);
  // Remove qualquer UNIQUE antigo que seja SOMENTE sobre (nome), descobrindo o nome
  // real do constraint via catálogo — não assume o nome padrão. O composto
  // (instituicao, nome) tem 2 colunas e nunca é encontrado por esta busca.
  try {
    const antigos = (await pool.query(`
      SELECT con.conname
        FROM pg_constraint con
        JOIN pg_class rel ON rel.oid = con.conrelid
       WHERE rel.relname = 'atb_triagem_regras'
         AND con.contype = 'u'
         AND con.conkey = ARRAY[(SELECT attnum FROM pg_attribute
                                   WHERE attrelid = rel.oid AND attname = 'nome' AND NOT attisdropped)]::smallint[]
    `)).rows;
    for (const { conname } of antigos) {
      await pool.query(`ALTER TABLE atb_triagem_regras DROP CONSTRAINT IF EXISTS "${conname}"`);
    }
  } catch (e) {
    console.warn('[triagem] aviso ao remover unique antigo de nome:', e.message);
  }
  // Unicidade do nome agora é POR instituição (idempotente).
  try {
    await pool.query(`ALTER TABLE atb_triagem_regras
      ADD CONSTRAINT atb_triagem_regras_inst_nome_key UNIQUE (instituicao, nome)`);
  } catch (e) {
    if (!/already exists|duplicate|exists/i.test(e.message || '')) throw e; // idempotente
  }

  // Seed: a regra do exemplo (idempotente por instituição+nome). É clínica do HUSF.
  await pool.query(`
    INSERT INTO atb_triagem_regras (instituicao, nome, descricao, prioridade, ativo, condicoes, acoes, modo)
    VALUES ('HUSF',$1,$2,$3,true,$4::jsonb,$5::jsonb,'auto')
    ON CONFLICT (instituicao, nome) DO NOTHING
  `, [
    'RN <2d UTI Neo + Gentamicina',
    'Recém-nascido com menos de 2 dias de vida em UTI Neo, em gentamicina: esquema empírico de sepse neonatal precoce — Parecer "Sim", IrAS "Descartado".',
    10,
    JSON.stringify({ all: [
      { campo: 'setor',          op: 'eq',       valor: 'UTI Neo / Infantil' },
      { campo: 'idade_dias',     op: 'lt',       valor: 2 },
      { campo: 'atb_solicitado', op: 'contains', valor: 'Gentamicina' },
    ]}),
    JSON.stringify({
      veredito: 'Sim',
      especificacao: 'Esquema empírico adequado para sepse neonatal precoce.',
      iras: 'Descartado',
    }),
  ]);
}

// ── Avaliador de condição (idêntico ao form + numéricos) ───────────────────
function _normTxt(s) {
  return String(s == null ? '' : s).toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}
function _filled(v) {
  if (v == null) return false;
  if (Array.isArray(v)) return v.length > 0;
  return String(v).trim() !== '';
}
function _textContainsAny(v, tokens) {
  const hay = _normTxt(v);
  if (!hay || !Array.isArray(tokens)) return false;
  return tokens.some((t) => {
    const nt = _normTxt(t);
    if (!nt) return false;
    if (nt.length <= 3) {
      const esc = nt.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      return new RegExp('(^|[^a-z0-9])' + esc + '([^a-z0-9]|$)').test(hay);
    }
    return hay.indexOf(nt) !== -1;
  });
}
function _num(v) {
  if (v == null || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

export function avaliaCond(cond, valores) {
  if (!cond) return true;
  if (cond.all) return Array.isArray(cond.all) && cond.all.every((c) => avaliaCond(c, valores));
  if (cond.any) return Array.isArray(cond.any) && cond.any.some((c) => avaliaCond(c, valores));
  const v = valores[cond.campo];
  switch (cond.op) {
    case 'eq':  return v === cond.valor;
    case 'neq': return v !== cond.valor;
    case 'in':  return Array.isArray(cond.valor) && cond.valor.indexOf(v) !== -1;
    case 'filled':     return _filled(v);
    case 'not_filled': return !_filled(v);
    case 'contains':     return Array.isArray(v) && v.indexOf(cond.valor) !== -1;
    case 'contains_any': return Array.isArray(v) && Array.isArray(cond.valor) &&
                                cond.valor.some((x) => v.indexOf(x) !== -1);
    case 'text_contains_any': return _textContainsAny(v, cond.valor);
    case 'lt':  { const n = _num(v); return n != null && n <  Number(cond.valor); }
    case 'lte': { const n = _num(v); return n != null && n <= Number(cond.valor); }
    case 'gt':  { const n = _num(v); return n != null && n >  Number(cond.valor); }
    case 'gte': { const n = _num(v); return n != null && n >= Number(cond.valor); }
    default: return false; // op desconhecido NÃO faz a regra casar (seguro)
  }
}

// ── Contexto da ficha (colunas + calculados) ───────────────────────────────
function _toDate(x) {
  if (!x) return null;
  // Colunas DATE/TIMESTAMPTZ chegam como objeto Date do pg — usar direto.
  if (x instanceof Date) return isNaN(x.getTime()) ? null : x;
  const d = new Date(String(x).slice(0, 10) + 'T00:00:00');
  return isNaN(d) ? null : d;
}
function calcIdade(dn, ref) {
  const d = _toDate(dn); if (!d) return {};
  const r = _toDate(ref) || new Date();
  const dias = Math.floor((r - d) / 86400000);
  if (dias < 0) return {};
  let anos = r.getFullYear() - d.getFullYear();
  let m = r.getMonth() - d.getMonth();
  if (m < 0 || (m === 0 && r.getDate() < d.getDate())) anos--;
  const meses = anos * 12 + (m < 0 ? m + 12 : m) - ((r.getDate() < d.getDate()) ? 1 : 0);
  return { idade_dias: dias, idade_meses: Math.max(0, meses), idade_anos: Math.max(0, anos) };
}

// Monta o objeto que as condições enxergam: TODAS as colunas da ficha + idades.
// (data de referência da idade: data clínica da ficha → internação → criação.)
// Dias inteiros entre uma data (YYYY-MM-DD) e a referência (= submissão da ficha).
// Negativo/ausente -> null (não casa em comparações numéricas).
function _diasDesde(data, ref) {
  const d = _toDate(data); if (!d) return null;
  const r = _toDate(ref) || new Date();
  const dias = Math.floor((r - d) / 86400000);
  return dias >= 0 ? dias : null;
}

export function contextoFicha(f) {
  const ref = f.data_referencia || f.jotform_created_at || f.created_at || null;
  return {
    ...f,
    ...calcIdade(f.paciente_dn, ref),
    // Campos calculados por OPERAÇÃO (data/derivados). Para uma nova regra baseada
    // em operação: calcule aqui e registre em EXTRAS (atb-regras-routes.js).
    dias_internacao: _diasDesde(f.data_internacao, ref),
    // Dias desde a admissão na UTI. A COLUNA do banco é data_admissao_uti
    // (data_uti é a chave do FORMULÁRIO; o parser mapeia uma na outra). Usar a
    // coluna errada deixava dias_uti sempre null.
    dias_uti: _diasDesde(f.data_admissao_uti, ref),
    // Dias desde a SUBMISSÃO da ficha (referência = hoje, não a própria submissão):
    // hoje - COALESCE(jotform_created_at, created_at). Útil sobretudo em backfill.
    dias_desde_submissao: _diasDesde(f.jotform_created_at || f.created_at, null),
  };
}

// ── Aplicação ──────────────────────────────────────────────────────────────
function vereditoVazio(recomendacao_scih) {
  if (recomendacao_scih == null) return true;
  if (Array.isArray(recomendacao_scih)) return recomendacao_scih.length === 0;
  try { const a = JSON.parse(recomendacao_scih); return !Array.isArray(a) || a.length === 0; }
  catch { return String(recomendacao_scih).trim() === '' || recomendacao_scih === '[]'; }
}

// Avalia as regras ativas (1ª que casa) e aplica as ações em campos VAZIOS.
// Retorna { regra_id, nome } aplicada, ou null. Auto-tratada (nunca lança).
// Constrói o contexto de avaliação de uma ficha: campos base + gatilhos derivados
// (fichas_72h_*, culturas/hemo). Fonte ÚNICA compartilhada pela triagem
// (aplicarRegras) e pelo executor de monitoramento — sem duplicar gatilhos.
export async function montarContexto(pool, fichaId) {
    const f = (await pool.query(
      `SELECT f.*, i.sigla AS _inst_sigla
         FROM atb_fichas f
         LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
        WHERE f.id = $1`, [fichaId])).rows[0];
    if (!f) return null;
    const _sigla = f._inst_sigla || 'HUSF';

    const ctx = contextoFicha(f);

    // Campo derivado por CONSULTA (cross-ficha): nº de OUTRAS fichas não-deletadas do
    // MESMA INSTITUIÇÃO (tenant) + MESMO prontuário + MESMO setor, nas 72h ANTERIORES a esta (exclui a própria).
    // Permite uma regra "IrAS Repetida" (condição: fichas_72h_mesmo_setor >= 1).
    ctx.fichas_72h_mesmo_setor = 0;
    if (f.prontuario && f.setor) {
      const refData = f.data_referencia || f.jotform_created_at || f.created_at || null;
      if (refData) {
        const rc = await pool.query(
          `SELECT COUNT(*)::int AS n
             FROM atb_fichas o
            WHERE o.id <> $1
              AND o.deletado_em IS NULL
              AND o.instituicao_id IS NOT DISTINCT FROM $5   -- mesmo tenant (prontuário é por-hospital)
              AND o.prontuario = $2
              AND o.setor = $3
              AND COALESCE(o.data_referencia, o.jotform_created_at, o.created_at) >= ($4::timestamptz - interval '72 hours')
              AND COALESCE(o.data_referencia, o.jotform_created_at, o.created_at) <  $4::timestamptz`,
          [fichaId, f.prontuario, f.setor, refData, f.instituicao_id]
        );
        ctx.fichas_72h_mesmo_setor = rc.rows[0] ? rc.rows[0].n : 0;
      }
    }

    // Fichas REPETIDAS: nº de OUTRAS fichas do MESMO tenant + MESMO prontuário com
    // ATB sobreposto (mesmo antimicrobiano solicitado), nas 72h ANTERIORES a esta.
    // Permite uma regra "Solicitação repetida" (condição: fichas_72h_mesmo_atb >= 1).
    ctx.fichas_72h_mesmo_atb = 0;
    if (f.prontuario && Array.isArray(f.atb_solicitado) && f.atb_solicitado.length) {
      const refData = f.data_referencia || f.jotform_created_at || f.created_at || null;
      if (refData) {
        const rc = await pool.query(
          `SELECT COUNT(*)::int AS n
             FROM atb_fichas o
            WHERE o.id <> $1
              AND o.deletado_em IS NULL
              AND o.instituicao_id IS NOT DISTINCT FROM $5
              AND o.prontuario = $2
              AND jsonb_typeof(o.atb_solicitado) = 'array'
              AND o.atb_solicitado ?| $3::text[]
              AND COALESCE(o.data_referencia, o.jotform_created_at, o.created_at) >= ($4::timestamptz - interval '72 hours')
              AND COALESCE(o.data_referencia, o.jotform_created_at, o.created_at) <  $4::timestamptz`,
          [fichaId, f.prontuario, f.atb_solicitado, refData, f.instituicao_id]
        );
        ctx.fichas_72h_mesmo_atb = rc.rows[0] ? rc.rows[0].n : 0;
      }
    }

    // Campos derivados de MICROBIOLOGIA (culturas casadas na janela −30d/+5d).
    // mr = LISTA (dropdown de mecanismos, match exato); organismos/materiais = TEXTO
    // concatenado (usar text_contains_any, que ignora acento/cedilha/caixa).
    ctx.cultura_positiva = false; ctx.cultura_mr = []; ctx.cultura_organismos = ''; ctx.cultura_materiais = ''; ctx.cultura_hemocultura = false; ctx.hemocultura_5d5d = false;
    try {
      const cults = await buscarCulturasDaFicha(pool, f);
      const mdr = await buscarMdrDaFicha(pool, f);   // 2ª fonte de positiva/MR: alerta de MDR por e-mail
      ctx.cultura_positiva   = cults.length > 0 || mdrTemAlerta(mdr);
      ctx.cultura_mr         = [...new Set([...cults.map((c) => c.resistencia).filter(Boolean), ...mdrResistencias(mdr)])];
      ctx.cultura_organismos = [...new Set(cults.map((c) => c.microorganismo).filter(Boolean))].join(' | ');
      ctx.cultura_materiais  = [...new Set(cults.map((c) => c.material).filter(Boolean))].join(' | ');
      ctx.cultura_hemocultura = cults.some((c) => _normTxt(c.material).indexOf('hemocultura') !== -1)
        || hemoTemAlerta(await buscarHemoDaFicha(pool, f));   // 2ª fonte: alerta de e-mail (−30d/+5d)
    } catch (e) { console.error('[atb] culturas na triagem:', e.message); }

    // Hemocultura positiva na janela APERTADA −5d/+5d (específica p/ monitoramento,
    // distinta do cultura_hemocultura de −30d/+5d). Reusa o mesmo match/janela do SQL.
    try {
      const cults55 = await buscarCulturasDaFicha(pool, f, 5, 5);
      ctx.hemocultura_5d5d = cults55.some((c) => _normTxt(c.material).indexOf('hemocultura') !== -1)
        || hemoTemAlerta(await buscarHemoDaFicha(pool, f, 5, 5));   // 2ª fonte: alerta de e-mail (−5d/+5d)
    } catch (e) { console.error('[atb] hemo 5d5d:', e.message); }

    return { f, ctx, sigla: _sigla };
}

export async function aplicarRegras(pool, fichaId) {
  try {
    const _built = await montarContexto(pool, fichaId);
    if (!_built) return null;
    const { f, ctx, sigla: _sigla } = _built;

    const regras = (await pool.query(
      'SELECT id, nome, condicoes, acoes FROM atb_triagem_regras WHERE ativo=true AND instituicao=$1 ORDER BY prioridade ASC, id ASC',
      [_sigla]
    )).rows;
    if (!regras.length) return null;

    const regra = regras.find((r) => avaliaCond(r.condicoes, ctx));
    if (!regra) return null;

    const acoes = regra.acoes || {};

    // estado atual de IrAS (só preenche se vazio)
    const av = (await pool.query('SELECT iras FROM atb_avaliacoes WHERE ficha_id=$1', [fichaId])).rows[0];
    const irasVazio = !av || av.iras == null || String(av.iras).trim() === '';

    // ── Parecer (só se ainda não há veredito) ──
    if (acoes.veredito && vereditoVazio(f.recomendacao_scih)) {
      await pool.query(
        `UPDATE atb_fichas
            SET recomendacao_scih = $2::jsonb,
                recomendacoes_especificacao = COALESCE(recomendacoes_especificacao, $3),
                parecer_emitido_at = now(),
                updated_at = now()
          WHERE id = $1`,
        [fichaId, JSON.stringify([acoes.veredito]), acoes.especificacao || null]
      );
    }

    // ── IrAS + auditoria da regra (upsert na avaliação) ──
    await pool.query(
      `INSERT INTO atb_avaliacoes (ficha_id, iras, etiol_iras, triagem_regra_id, triagem_regra_at, updated_at)
       VALUES ($1, $2, $3, $4, now(), now())
       ON CONFLICT (ficha_id) DO UPDATE SET
         iras = CASE WHEN ($5 AND $2 IS NOT NULL) THEN $2 ELSE atb_avaliacoes.iras END,
         etiol_iras = COALESCE(atb_avaliacoes.etiol_iras, $3),
         triagem_regra_id = $4,
         triagem_regra_at = now(),
         updated_at = now()`,
      [fichaId, (acoes.iras || null), (acoes.etiol_iras || null), regra.id, irasVazio]
    );

    console.log('[triagem] ficha', fichaId, '→ regra', regra.id, `(${regra.nome})`);
    return { regra_id: regra.id, nome: regra.nome };
  } catch (e) {
    console.error('[triagem] aplicarRegras', fichaId, '-', e.message);
    return null;
  }
}
