// atb-db.js
// Migrações do módulo ATB — Controle de Antimicrobianos
// Padrão idêntico ao lab-db.js

export async function runAtbMigrations(pool) {

  // ── Instituições ─────────────────────────────────────────────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atb_instituicoes (
      id                SERIAL PRIMARY KEY,
      nome              TEXT NOT NULL,
      sigla             TEXT UNIQUE NOT NULL,
      jotform_form_id   TEXT UNIQUE,
      ativo             BOOLEAN DEFAULT true,
      created_at        TIMESTAMPTZ DEFAULT now()
    )
  `);

  // Renomeia o placeholder H2 → SCMI (Santa Casa de Itatiba). Roda ANTES do seed,
  // para o INSERT seguinte ver SCMI já existindo e não criar linha duplicada.
  // Preserva o id da linha (e portanto as FKs de fichas). Idempotente.
  await pool.query(`
    UPDATE atb_instituicoes
       SET sigla='SCMI', nome='Irmandade da Santa Casa de Misericórdia de Itatiba'
     WHERE sigla='H2'
       AND NOT EXISTS (SELECT 1 FROM atb_instituicoes WHERE sigla='SCMI')
  `);

  // Seed inicial (idempotente)
  await pool.query(`
    INSERT INTO atb_instituicoes (nome, sigla) VALUES
      ('Hospital União São Francisco', 'HUSF'),
      ('Irmandade da Santa Casa de Misericórdia de Itatiba', 'SCMI')
    ON CONFLICT (sigla) DO NOTHING
  `);

  // ── Fichas ───────────────────────────────────────────────────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atb_fichas (
      id                      SERIAL PRIMARY KEY,
      instituicao_id          INTEGER REFERENCES atb_instituicoes(id),
      jotform_submission_id   TEXT UNIQUE,
      jotform_created_at      TIMESTAMPTZ,

      -- Paciente
      paciente_nome           TEXT,
      paciente_nome_raw       TEXT,
      paciente_dn             DATE,
      paciente_idade          TEXT,
      prontuario              TEXT,
      atendimento             TEXT,

      -- Internação
      setor                   TEXT,
      leito                   TEXT,
      equipe_responsavel      TEXT,
      data_internacao         DATE,
      data_admissao_uti       DATE,

      -- Contexto clínico
      tipo_terapia            TEXT,
      historia_clinica        TEXT,
      cirurgia                TEXT,
      foco_infeccao           TEXT,
      sepse                   BOOLEAN,
      gestante                BOOLEAN,
      lactante                BOOLEAN,

      -- Comorbidades / antecedentes
      comorbidades            JSONB    DEFAULT '[]',

      -- ATB prévios (últimos 7 dias)
      uso_atb_7d              BOOLEAN,
      atb_previos             JSONB    DEFAULT '[]',

      -- Culturas
      culturas_colhidas       JSONB    DEFAULT '{}',
      culturas_previas        JSONB    DEFAULT '[]',

      -- Dispositivos invasivos
      dispositivos_invasivos  JSONB    DEFAULT '[]',
      dialise                 BOOLEAN,
      acesso_dialise          TEXT,
      data_insercao_cateter   DATE,
      sitio_cvc               JSONB    DEFAULT '[]',
      sitio_cdl               JSONB    DEFAULT '[]',
      sitio_pai               JSONB    DEFAULT '[]',

      -- Neonatal
      peso_nascimento         NUMERIC,
      acesso_vascular_neo     JSONB    DEFAULT '[]',

      -- Função renal
      insuficiencia_renal     JSONB    DEFAULT '[]',
      clcr                    NUMERIC,
      peso                    NUMERIC,
      altura                  NUMERIC,

      -- Quimioterapia
      faz_quimio              BOOLEAN,
      cateter_quimio          BOOLEAN,
      acesso_quimio           TEXT,

      -- Fratura exposta
      classificacao_fratura   TEXT,

      -- ATB solicitado
      atb_solicitado          JSONB    DEFAULT '[]',
      posologia               JSONB    DEFAULT '[]',
      tempo_previsto          INTEGER,
      oxacilina_associacao    BOOLEAN,

      -- Prescritor
      crm                     TEXT,
      prescritor_nome         TEXT,

      -- Scores calculados pelo JotForm
      sofa                    INTEGER,
      sofa_renal              INTEGER,

      -- Campos SCIH preenchidos no JotForm (Leandro)
      recomendacao_scih       JSONB    DEFAULT '[]',
      recomendacoes_especificacao TEXT,
      recomendacoes_adicionais    TEXT,
      ha_esquema_sugerido     TEXT,
      avaliador               TEXT,
      complemento_scih        TEXT,
      parecer_evolutivo       JSONB    DEFAULT '[]',

      -- Óbito
      obito                   BOOLEAN  DEFAULT false,
      data_obito              DATE,

      -- Links gerados automaticamente
      link_exames             TEXT,
      link_labs               TEXT,

      -- Payload completo (auditoria e campos futuros)
      payload_raw             JSONB,

      -- Status do workflow no nosso sistema
      -- pendente | em_avaliacao | avaliado | arquivado
      status                  TEXT     DEFAULT 'pendente',

      synced_at               TIMESTAMPTZ DEFAULT now(),
      created_at              TIMESTAMPTZ DEFAULT now(),
      updated_at              TIMESTAMPTZ DEFAULT now()
    )
  `);

  // ── Avaliação SCIH (substitui colunas manuais do Tables) ─────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atb_avaliacoes (
      id              SERIAL PRIMARY KEY,
      ficha_id        INTEGER UNIQUE REFERENCES atb_fichas(id) ON DELETE CASCADE,

      -- Classificação IrAS
      iras            TEXT,
      etiol_iras      TEXT,
      micro           TEXT,
      desfecho_iras   TEXT,
      desfecho_data   DATE,

      -- Scores adicionais
      saps3           NUMERIC,
      tempo_saps      NUMERIC,

      -- Saída do Claude (triagem automática)
      triagem_ia      JSONB,
      triagem_ia_at   TIMESTAMPTZ,

      avaliado_por    INTEGER REFERENCES users(id),
      created_at      TIMESTAMPTZ DEFAULT now(),
      updated_at      TIMESTAMPTZ DEFAULT now()
    )
  `);

  // Data de inserção do campo `micro` (a micro preenche no grid). Coluna própria porque
  // updated_at é da linha inteira — muda quando qualquer outro campo é editado.
  await pool.query(`ALTER TABLE atb_avaliacoes ADD COLUMN IF NOT EXISTS micro_at TIMESTAMPTZ`);
  // Backfill único p/ registros anteriores à coluna: usa updated_at como melhor aproximação.
  await pool.query(`
    UPDATE atb_avaliacoes
       SET micro_at = updated_at
     WHERE micro IS NOT NULL AND micro <> '' AND micro_at IS NULL
  `);

  // ── Dados evolutivos (preenchidos pelas colaboradoras) ───────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atb_evolutivos (
      id                          SERIAL PRIMARY KEY,
      ficha_id                    INTEGER UNIQUE REFERENCES atb_fichas(id) ON DELETE CASCADE,

      labs                        JSONB DEFAULT '{}',
      hemodinamica                JSONB DEFAULT '{}',
      ventilatorio                JSONB DEFAULT '{}',
      acesso_vascular_neo_evol    JSONB DEFAULT '{}',

      preenchido_por              INTEGER REFERENCES users(id),
      created_at                  TIMESTAMPTZ DEFAULT now(),
      updated_at                  TIMESTAMPTZ DEFAULT now()
    )
  `);

  // ── Log de sincronização ─────────────────────────────────────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atb_sync_log (
      id              SERIAL PRIMARY KEY,
      instituicao_id  INTEGER REFERENCES atb_instituicoes(id),
      tipo            TEXT,     -- 'webhook' | 'polling'
      submission_id   TEXT,
      status          TEXT,     -- 'ok' | 'erro' | 'duplicada'
      detalhes        JSONB,
      created_at      TIMESTAMPTZ DEFAULT now()
    )
  `);

  // ── Índices ──────────────────────────────────────────────────────────────
  await pool.query(`CREATE INDEX IF NOT EXISTS atb_fichas_inst_data_idx
    ON atb_fichas(instituicao_id, created_at DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS atb_fichas_status_idx
    ON atb_fichas(status, created_at DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS atb_fichas_prontuario_idx
    ON atb_fichas(prontuario)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS atb_fichas_jotform_idx
    ON atb_fichas(jotform_submission_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS atb_sync_log_inst_idx
    ON atb_sync_log(instituicao_id, created_at DESC)`);

  // Tag do gatilho de IA de história narrativa (Fase C):
  //   true  = história verificada como narrativa
  //   false = telegráfica (só grava assim se a regra NÃO bloquear o envio)
  //   null  = não verificada (regra não se aplica, ou fail-open de infra)
  await pool.query(`ALTER TABLE atb_fichas ADD COLUMN IF NOT EXISTS historia_narrativa BOOLEAN`);
  // Confirmação do prescritor no gatilho de ISC: true=confirmou, false=negou,
  // null=não foi perguntado. É o rótulo de ouro do classificador.
  await pool.query(`ALTER TABLE atb_fichas ADD COLUMN IF NOT EXISTS isc_confirmada BOOLEAN`);

  console.log('[atb] migrations ok');
}
