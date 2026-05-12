// lab-db.js
// Migrations para o portal de resultados laboratoriais
// Não modifica nenhuma tabela existente — apenas cria tabelas novas com prefixo lab_

export async function runLabMigrations(pool) {
  // Pacientes do laboratório
  await pool.query(`
    CREATE TABLE IF NOT EXISTS lab_patients (
      id         SERIAL PRIMARY KEY,
      full_name  TEXT NOT NULL,
      birth_date DATE NOT NULL,
      notes      TEXT,
      created_at TIMESTAMPTZ DEFAULT now()
    )
  `);

  // Chaves de acesso (uma por paciente, formato LM-XXXX-XXXX)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS lab_access_keys (
      id         SERIAL PRIMARY KEY,
      patient_id INTEGER NOT NULL REFERENCES lab_patients(id) ON DELETE CASCADE,
      key_code   TEXT UNIQUE NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ DEFAULT now()
    )
  `);

  // Coletas (uma coleta = conjunto de exames de uma mesma data)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS lab_collections (
      id           SERIAL PRIMARY KEY,
      patient_id   INTEGER NOT NULL REFERENCES lab_patients(id) ON DELETE CASCADE,
      collected_at DATE NOT NULL,
      created_at   TIMESTAMPTZ DEFAULT now()
    )
  `);

  // Resultados individuais (um por exame dentro de uma coleta)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS lab_results (
      id              SERIAL PRIMARY KEY,
      collection_id   INTEGER NOT NULL REFERENCES lab_collections(id) ON DELETE CASCADE,
      exam_name       TEXT NOT NULL,
      sample_type     TEXT NOT NULL DEFAULT 'Soro',
      method          TEXT NOT NULL,
      result_value    TEXT NOT NULL,
      reference_value TEXT,
      observation     TEXT,
      sort_index      INTEGER,
      created_at      TIMESTAMPTZ DEFAULT now()
    )
  `);

  // Índices
  await pool.query(`
    CREATE INDEX IF NOT EXISTS lab_access_keys_code_idx
      ON lab_access_keys(key_code)
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS lab_collections_patient_idx
      ON lab_collections(patient_id, collected_at DESC)
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS lab_results_collection_idx
      ON lab_results(collection_id, sort_index NULLS LAST, id)
  `);

  // Imagens vinculadas a resultados individuais
  await pool.query(`
    CREATE TABLE IF NOT EXISTS lab_result_images (
      id         SERIAL PRIMARY KEY,
      result_id  INTEGER NOT NULL REFERENCES lab_results(id) ON DELETE CASCADE,
      r2_key     TEXT NOT NULL,
      caption    TEXT,
      sort_index INTEGER,
      created_at TIMESTAMPTZ DEFAULT now()
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS lab_result_images_result_idx
      ON lab_result_images(result_id, sort_index NULLS LAST, id)
  `);

  console.log('[lab-db] migrations OK');
}
