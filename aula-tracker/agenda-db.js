// agenda-db.js — esquema do módulo de agenda (agenda_*).
// Padrão igual a runProntMigrations: idempotente (CREATE/ALTER ... IF NOT EXISTS).
//   Uso em app.js:  runAgendaMigrations(migratorPool).catch(...)

export async function runAgendaMigrations(pool) {
  const sql = `
  -- Papéis: agenda (secretária: agenda/edita/cancela/fatura), recepcao (recepcionista: vê o dia + check-in)
  ALTER TABLE users ADD COLUMN IF NOT EXISTS agenda   BOOLEAN DEFAULT false;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS recepcao BOOLEAN DEFAULT false;

  CREATE TABLE IF NOT EXISTS agenda_eventos (
    id                 BIGSERIAL PRIMARY KEY,
    paciente_id        BIGINT REFERENCES pront_pacientes(id) ON DELETE SET NULL,
    paciente_nome      TEXT NOT NULL,        -- desnormalizado: caso novo pode não ter prontuário ainda
    paciente_telefone  TEXT,
    paciente_email     TEXT,                 -- usado pelos lembretes
    data               DATE NOT NULL,
    hora_inicio        TIME NOT NULL,
    duracao_min        INTEGER NOT NULL DEFAULT 30,
    tipo               TEXT NOT NULL DEFAULT 'caso_novo',   -- caso_novo | retorno | reavaliacao | social
    modalidade         TEXT NOT NULL DEFAULT 'presencial',  -- presencial | teleconsulta
    local              TEXT,                                -- braganca | campinas | NULL (tele)
    link_video         TEXT,                                -- link do Meet (manual ou gerado via Calendar API)
    google_event_id    TEXT,                                -- id do evento no Google Calendar (teleconsulta), p/ update/delete
    obs                TEXT,
    status             TEXT NOT NULL DEFAULT 'agendado',    -- agendado|confirmado|chegou|em_atendimento|finalizado|faltou|cancelado
    chegou_em          TIMESTAMPTZ,          -- log da recepção
    chegou_por         TEXT,
    cancelado_em       TIMESTAMPTZ,
    cancelado_por      TEXT,
    cancelamento_motivo TEXT,
    -- faturamento do evento (itens adicionais em agenda_fatura_itens)
    valor_consulta     NUMERIC(10,2) NOT NULL DEFAULT 0,
    pagamento_status   TEXT NOT NULL DEFAULT 'pendente',    -- pendente | pago | isento
    pagamento_meio     TEXT,                                -- pix|cartao_credito|cartao_debito|dinheiro|transferencia|convenio|outro
    pago_em            TIMESTAMPTZ,
    pagamento_por      TEXT,
    criado_por         TEXT,
    criado_em          TIMESTAMPTZ DEFAULT now(),
    atualizado_por     TEXT,
    atualizado_em      TIMESTAMPTZ DEFAULT now()
  );
  CREATE INDEX IF NOT EXISTS idx_agenda_ev_data ON agenda_eventos (data, hora_inicio);
  CREATE INDEX IF NOT EXISTS idx_agenda_ev_pac  ON agenda_eventos (paciente_id);
  CREATE INDEX IF NOT EXISTS idx_agenda_ev_pag  ON agenda_eventos (pagamento_status);
  ALTER TABLE agenda_eventos ADD COLUMN IF NOT EXISTS google_event_id TEXT;   -- retrocompatível: tabela criada no Lote 1

  -- Itens adicionais de faturamento (exames, procedimentos) — total = valor_consulta + soma(itens)
  CREATE TABLE IF NOT EXISTS agenda_fatura_itens (
    id         BIGSERIAL PRIMARY KEY,
    evento_id  BIGINT NOT NULL REFERENCES agenda_eventos(id) ON DELETE CASCADE,
    descricao  TEXT NOT NULL,
    valor      NUMERIC(10,2) NOT NULL DEFAULT 0,
    criado_por TEXT,
    criado_em  TIMESTAMPTZ DEFAULT now()
  );
  CREATE INDEX IF NOT EXISTS idx_agenda_fi_ev ON agenda_fatura_itens (evento_id);

  -- Feriados: nacionais via BrasilAPI (sync), estaduais/municipais por seed fixo + manual
  CREATE TABLE IF NOT EXISTS agenda_feriados (
    id          BIGSERIAL PRIMARY KEY,
    data        DATE NOT NULL,
    nome        TEXT NOT NULL,
    escopo      TEXT NOT NULL DEFAULT 'nacional',  -- nacional | estadual_sp | municipal_braganca | municipal_campinas
    facultativo BOOLEAN NOT NULL DEFAULT false,    -- ponto facultativo (ex.: aniversário de Bragança 15/12)
    origem      TEXT NOT NULL DEFAULT 'manual',    -- api | seed | manual
    criado_em   TIMESTAMPTZ DEFAULT now(),
    UNIQUE (data, escopo, nome)
  );
  CREATE INDEX IF NOT EXISTS idx_agenda_fer_data ON agenda_feriados (data);

  -- Fila de lembretes (worker consome 'pendente'; envio D-1)
  CREATE TABLE IF NOT EXISTS agenda_lembretes (
    id         BIGSERIAL PRIMARY KEY,
    evento_id  BIGINT NOT NULL REFERENCES agenda_eventos(id) ON DELETE CASCADE,
    canal      TEXT NOT NULL DEFAULT 'email',     -- email | whatsapp
    status     TEXT NOT NULL DEFAULT 'pendente',  -- pendente | enviado | erro | cancelado
    enviar_em  TIMESTAMPTZ,                       -- quando deve ser disparado (véspera)
    enviado_em TIMESTAMPTZ,
    erro       TEXT,
    UNIQUE (evento_id, canal)
  );
  CREATE INDEX IF NOT EXISTS idx_agenda_lem_status ON agenda_lembretes (status, enviar_em);
  `;
  await pool.query(sql);
  console.log('[agenda-db] migrações ok');
}
