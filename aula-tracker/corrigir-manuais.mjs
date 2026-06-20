// corrigir-manuais.mjs — fecha os 4 casos pulados pela normalização.
// Dry-run por padrão; --execute aplica. Mesmo backup (atb_nomes_backup) + recompute de link_labs.
//
// >>> REVISE estas formas antes de --execute (são nomes de paciente) <<<
const CORRECOES = {
  18615: 'JARLENE CAMILO DA SILVA MAFRA',
  18627: 'JOAO BATISTA ALVES OLIVEIRA FILHO',
  18395: 'ELISA NICOLE DE ALMEIDA MORAES',
};
const SOFT_DELETE = [1];   // registro de teste «textbox_sample…»

import pg from 'pg';
const EXECUTE = process.argv.includes('--execute');
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL || process.env.SUPABASE_POOLER_URL,
  ssl: { rejectUnauthorized: false },
});
const buildLabs = (nome) => nome ? `http://localhost:3000/api/buscar?nome=${String(nome).trim().replace(/\s+/g, '+')}` : null;

await pool.query(`
  CREATE TABLE IF NOT EXISTS atb_nomes_backup (
    ficha_id INTEGER PRIMARY KEY, nome_old TEXT, nome_raw_old TEXT,
    link_labs_old TEXT, normalizado_at TIMESTAMPTZ DEFAULT now())`);

console.log(EXECUTE ? '>>> MODO EXECUTE <<<\n' : '>>> DRY-RUN — use --execute para aplicar <<<\n');

// ── correções de nome ──
for (const [id, nome] of Object.entries(CORRECOES)) {
  const f = (await pool.query('SELECT id, paciente_nome, paciente_nome_raw, link_labs, deletado_em FROM atb_fichas WHERE id=$1', [id])).rows[0];
  if (!f) { console.log(`  #${id}: NÃO ENCONTRADA`); continue; }
  if (f.deletado_em) { console.log(`  #${id}: deletada — pulando`); continue; }
  const labs = buildLabs(nome);
  console.log(`  #${id}: «${f.paciente_nome_raw}»  →  «${nome}»`);
  if (EXECUTE) {
    await pool.query('INSERT INTO atb_nomes_backup (ficha_id, nome_old, nome_raw_old, link_labs_old) VALUES ($1,$2,$3,$4) ON CONFLICT (ficha_id) DO NOTHING',
      [f.id, f.paciente_nome, f.paciente_nome_raw, f.link_labs]);
    await pool.query('UPDATE atb_fichas SET paciente_nome=$2, paciente_nome_raw=$2, link_labs=$3, updated_at=now() WHERE id=$1',
      [f.id, nome, labs]);
  }
}

// ── soft-delete do registro de teste ──
for (const id of SOFT_DELETE) {
  const f = (await pool.query('SELECT id, paciente_nome_raw, deletado_em FROM atb_fichas WHERE id=$1', [id])).rows[0];
  if (!f) { console.log(`  soft-delete #${id}: NÃO ENCONTRADA`); continue; }
  if (f.deletado_em) { console.log(`  soft-delete #${id}: já deletada`); continue; }
  console.log(`  soft-delete #${id}: «${f.paciente_nome_raw}»`);
  if (EXECUTE) await pool.query('UPDATE atb_fichas SET deletado_em=now(), updated_at=now() WHERE id=$1', [f.id]);
}

console.log(EXECUTE ? '\n✔ Aplicado (nomes em atb_nomes_backup; soft-delete reversível via deletado_em=NULL).'
                    : '\n(dry-run — rode com --execute para aplicar)');
await pool.end();
