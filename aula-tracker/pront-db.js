// pront-db.js — esquema do prontuário (módulo pront_*).
// Padrão igual a runLabMigrations: idempotente (CREATE ... IF NOT EXISTS).
//   Uso em app.js:  await runProntMigrations(pool);

export async function runProntMigrations(pool) {
  const sql = `
  CREATE TABLE IF NOT EXISTS pront_pacientes (
    id            BIGSERIAL PRIMARY KEY,
    nome          TEXT NOT NULL,
    dn            DATE,
    cpf           TEXT,
    sexo          TEXT,
    telefone      TEXT,
    obs           TEXT,
    criado_por    TEXT,
    criado_em     TIMESTAMPTZ DEFAULT now(),
    atualizado_em TIMESTAMPTZ DEFAULT now()
  );
  CREATE INDEX IF NOT EXISTS idx_pront_pac_nome ON pront_pacientes (lower(nome));
  CREATE INDEX IF NOT EXISTS idx_pront_pac_cpf  ON pront_pacientes (cpf);

  CREATE TABLE IF NOT EXISTS pront_coletas (
    id           BIGSERIAL PRIMARY KEY,
    paciente_id  BIGINT NOT NULL REFERENCES pront_pacientes(id) ON DELETE CASCADE,
    data_coleta  DATE NOT NULL,
    laboratorio  TEXT,
    fonte        TEXT,            -- foto | pdf_texto | xlsx | manual
    documento_id BIGINT,          -- origem (pront_documentos), se houver
    tarv         TEXT,            -- esquema antirretroviral, quando aplicável
    criado_por   TEXT,
    criado_em    TIMESTAMPTZ DEFAULT now(),
    UNIQUE (paciente_id, data_coleta, laboratorio)
  );
  CREATE INDEX IF NOT EXISTS idx_pront_col_pac ON pront_coletas (paciente_id, data_coleta);

  CREATE TABLE IF NOT EXISTS pront_resultados (
    id            BIGSERIAL PRIMARY KEY,
    coleta_id     BIGINT NOT NULL REFERENCES pront_coletas(id) ON DELETE CASCADE,
    canonico      TEXT,                 -- NULL = "outros" (guardado, sem tendência)
    rotulo        TEXT,
    nome_original TEXT,
    tipo_valor    TEXT,                 -- numerico | censurado | qualitativo | texto
    valor_num     DOUBLE PRECISION,     -- para gráfico/tendência
    operador      TEXT,                 -- < > <= >=  (censurado)
    unidade       TEXT,
    resultado_txt TEXT,                 -- qualitativo / texto literal
    status_flag   TEXT                  -- alto | baixo | normal | NULL
  );
  CREATE INDEX IF NOT EXISTS idx_pront_res_col   ON pront_resultados (coleta_id);
  CREATE INDEX IF NOT EXISTS idx_pront_res_canon ON pront_resultados (canonico);

  -- fila de documentos para extração (foto/pdf/xlsx). O worker consome 'pendente'.
  CREATE TABLE IF NOT EXISTS pront_documentos (
    id                    BIGSERIAL PRIMARY KEY,
    paciente_id           BIGINT REFERENCES pront_pacientes(id) ON DELETE SET NULL,
    tipo                  TEXT,          -- foto | pdf | xlsx | audio
    nome_arquivo          TEXT,
    mime                  TEXT,
    r2_key                TEXT NOT NULL,
    tamanho               INTEGER,
    status                TEXT DEFAULT 'pendente',  -- pendente|processando|extraido|erro|confirmado|descartado
    provedor              TEXT,          -- ollama | claude | parser_texto
    extraido_json         JSONB,         -- {paciente,data_coleta,analitos[],avisos[]} para conferência
    erro                  TEXT,
    data_coleta_sugerida  DATE,
    tentativas            INT DEFAULT 0,
    criado_por            TEXT,
    criado_em             TIMESTAMPTZ DEFAULT now(),
    processado_em         TIMESTAMPTZ
  );
  CREATE INDEX IF NOT EXISTS idx_pront_doc_status ON pront_documentos (status, criado_em);
  CREATE INDEX IF NOT EXISTS idx_pront_doc_pac    ON pront_documentos (paciente_id);

  -- colunas para áudio de consulta (idempotente)
  ALTER TABLE pront_documentos ADD COLUMN IF NOT EXISTS modo        TEXT;            -- (audio) resumo | consulta
  ALTER TABLE pront_documentos ADD COLUMN IF NOT EXISTS diarizar    BOOLEAN DEFAULT false;
  ALTER TABLE pront_documentos ADD COLUMN IF NOT EXISTS transcricao TEXT;            -- transcript bruto do Whisper

  -- consultas / evoluções em texto (base para próximas etapas)
  CREATE TABLE IF NOT EXISTS pront_consultas (
    id          BIGSERIAL PRIMARY KEY,
    paciente_id BIGINT NOT NULL REFERENCES pront_pacientes(id) ON DELETE CASCADE,
    data        DATE NOT NULL DEFAULT current_date,
    texto       TEXT,
    criado_por  TEXT,
    criado_em   TIMESTAMPTZ DEFAULT now()
  );
  CREATE INDEX IF NOT EXISTS idx_pront_cons_pac ON pront_consultas (paciente_id, data);

  -- documentos emitidos pelo gerador (receita/pedido/relatório/atestado), guardados na ficha
  CREATE TABLE IF NOT EXISTS pront_docs_emitidos (
    id          BIGSERIAL PRIMARY KEY,
    paciente_id BIGINT NOT NULL REFERENCES pront_pacientes(id) ON DELETE CASCADE,
    tipo        TEXT,            -- receituario | pedido | relatorio | atestado
    paper       TEXT,            -- A4 | A5
    r2_key      TEXT NOT NULL,
    criado_por  TEXT,
    criado_em   TIMESTAMPTZ DEFAULT now()
  );
  CREATE INDEX IF NOT EXISTS idx_pront_docs_emit_pac ON pront_docs_emitidos (paciente_id, criado_em DESC);

  -- ponte com o módulo de laboratório: lab_patients aponta para o cadastro mestre (pront_pacientes).
  -- Guardado: só roda se lab_patients já existir (as migrações rodam concorrentes no boot).
  DO $$
  BEGIN
    IF to_regclass('public.lab_patients') IS NOT NULL THEN
      ALTER TABLE lab_patients ADD COLUMN IF NOT EXISTS pront_id BIGINT REFERENCES pront_pacientes(id) ON DELETE SET NULL;
      CREATE INDEX IF NOT EXISTS idx_lab_patients_pront ON lab_patients (pront_id);
    END IF;
  END $$;
  `;
  await pool.query(sql);
  console.log("[pront] migrations OK");
}
