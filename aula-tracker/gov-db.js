// gov-db.js
// ──────────────────────────────────────────────────────────────────────────
// Migrações do módulo GOVERNANÇA — painel do Comitê de Gestão Estratégica.
// Padrão idêntico ao pav-db.js / isc-db.js: idempotente, CREATE ... IF NOT
// EXISTS, ADD COLUMN IF NOT EXISTS.
//
// MODELO (uma diferença importante em relação ao ATB/ISC/PAV):
//   este módulo NÃO coleta dado. O pipeline em Python apura fora daqui e
//   ENTREGA a competência pronta. O banco guarda o resultado, não a matéria-prima.
//
//   gov_competencia → 1 linha por competência publicada. payload = o
//                     data_governanca.json integral, somente agregados.
//                     Guardar o histórico permite reabrir exatamente o que o
//                     comitê viu numa reunião de meses atrás — num painel de
//                     conselho isso é requisito, não conveniência.
//   gov_acesso_log  → quem abriu, qual competência, quando. Documento de
//                     conselho tem rastro de leitura.
//
// USERS: acrescenta o papel `gestao`. Deliberadamente SEPARADO de `scih`:
// são comitês diferentes, com escopos diferentes. Quem faz controle de
// infecção não passa a ver mortalidade institucional por tabela.
//
// TENANCY: o vínculo de instituição segue o mesmo desenho do scihRequired,
// via req.atbTenant, para quando o SCMI tiver painel próprio.
// ──────────────────────────────────────────────────────────────────────────

export async function runGovMigrations(pool) {

  // ── Papel de governança nos usuários ──────────────────────────────────────
  // gestao : flag de acesso ao painel. super_admin e o break-glass (cookie adm)
  //          cruzam, como em todo o resto do app.
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS gestao BOOLEAN DEFAULT false`);

  // ── Competências publicadas ───────────────────────────────────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS gov_competencia (
      competencia   TEXT PRIMARY KEY CHECK (competencia ~ '^\\d{4}-\\d{2}$'),
      gerado_em     TIMESTAMPTZ NOT NULL DEFAULT now(),
      publicado_por TEXT,
      origem        TEXT,
      instituicao   TEXT NOT NULL DEFAULT 'HUSF',
      payload       JSONB NOT NULL,
      CONSTRAINT gov_payload_tem_meses
        CHECK (jsonb_typeof(payload -> 'meses') = 'array')
    )`);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS gov_competencia_inst_idx
      ON gov_competencia (instituicao, competencia DESC)`);

  // ── Log de acesso ─────────────────────────────────────────────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS gov_acesso_log (
      id          BIGSERIAL PRIMARY KEY,
      usuario_id  INTEGER,
      competencia TEXT,
      rota        TEXT,
      ip          TEXT,
      em          TIMESTAMPTZ NOT NULL DEFAULT now()
    )`);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS gov_acesso_log_em_idx
      ON gov_acesso_log (em DESC)`);

  console.log('gov migrations ok');
}
