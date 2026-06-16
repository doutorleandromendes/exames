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

  // Seed: a regra do exemplo (idempotente por nome).
  await pool.query(`
    INSERT INTO atb_triagem_regras (nome, descricao, prioridade, ativo, condicoes, acoes, modo)
    VALUES ($1,$2,$3,true,$4::jsonb,$5::jsonb,'auto')
    ON CONFLICT (nome) DO NOTHING
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
export function contextoFicha(f) {
  const ref = f.data_referencia || f.jotform_created_at || f.created_at || null;
  return { ...f, ...calcIdade(f.paciente_dn, ref) };
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
export async function aplicarRegras(pool, fichaId) {
  try {
    const f = (await pool.query('SELECT * FROM atb_fichas WHERE id=$1', [fichaId])).rows[0];
    if (!f) return null;

    const regras = (await pool.query(
      'SELECT id, nome, condicoes, acoes FROM atb_triagem_regras WHERE ativo=true ORDER BY prioridade ASC, id ASC'
    )).rows;
    if (!regras.length) return null;

    const ctx = contextoFicha(f);
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
