// normaliza-prontuario.mjs
// ─────────────────────────────────────────────────────────────────────────
// Limpa prontuários com caracteres não-numéricos (espaço, ponto, hífen, letra).
// O prontuário é sempre só dígitos; qualquer sujeira quebra silenciosamente os
// matches ficha↔PACS↔cultura↔nome (todos casam por prontuário). Este script
// conserta o que JÁ está no banco. A normalização das fichas NOVAS está no
// parser (atb-parser.js).
//
// Uso (no Shell do Render):
//   node normaliza-prontuario.mjs            → DRY-RUN (só mostra o que faria)
//   node normaliza-prontuario.mjs --apply    → efetiva as mudanças
//
// Requer DATABASE_URL no ambiente (mesmo do app).

import pg from 'pg';
const { Pool } = pg;

const APLICAR = process.argv.includes('--apply');
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: true }, max: 4 });

// HUSF-only: a normalização retroativa NÃO toca na SCMI (histórico pode ter
// peculiaridades que não queremos alterar sem certeza).
const { rows: [husf] } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla='HUSF'`);
if (!husf) { console.error('ERRO: instituição HUSF não encontrada.'); process.exit(1); }
const HUSF = husf.id;

try {
  const { rows: [f] }  = await pool.query(`SELECT COUNT(*)::int AS n FROM atb_fichas    WHERE prontuario ~ '[^0-9]' AND instituicao_id = $1`, [HUSF]);
  const { rows: [np] } = await pool.query(`SELECT COUNT(*)::int AS n FROM atb_nome_pacs WHERE prontuario ~ '[^0-9]' AND instituicao_id = $1`, [HUSF]);
  console.log(`atb_fichas (HUSF) com prontuário sujo:    ${f.n}`);
  console.log(`atb_nome_pacs (HUSF) com prontuário sujo: ${np.n}`);

  if (!APLICAR) {
    const { rows } = await pool.query(
      `SELECT id, prontuario FROM atb_fichas WHERE prontuario ~ '[^0-9]' AND instituicao_id = $1 ORDER BY id LIMIT 15`, [HUSF]);
    if (rows.length) {
      console.log('\nAmostra (id · "sujo" → "limpo"):');
      for (const r of rows) console.log(`  ${r.id} · "${r.prontuario}" → "${r.prontuario.replace(/[^0-9]/g, '')}"`);
    }
    console.log('\n(dry-run) Nada foi alterado. Rode com  --apply  para efetivar.');
  } else {
    const r1 = await pool.query(
      `UPDATE atb_fichas SET prontuario = regexp_replace(prontuario, '[^0-9]', '', 'g') WHERE prontuario ~ '[^0-9]' AND instituicao_id = $1`, [HUSF]);
    console.log(`✓ atb_fichas normalizados: ${r1.rowCount}`);
    // atb_nome_pacs é derivado (o worker repopula com o prontuário limpo); apaga os sujos.
    const r2 = await pool.query(`DELETE FROM atb_nome_pacs WHERE prontuario ~ '[^0-9]' AND instituicao_id = $1`, [HUSF]);
    console.log(`✓ atb_nome_pacs sujos removidos (serão recapturados pelo worker): ${r2.rowCount}`);
    console.log('\nPronto.');
  }
} catch (e) {
  console.error('ERRO:', e.message);
  process.exitCode = 1;
} finally {
  await pool.end().catch(() => {});
}
