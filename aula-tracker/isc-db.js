// isc-db.js
// ──────────────────────────────────────────────────────────────────────────
// Migrações do módulo ISC — Vigilância pós-alta de Infecção de Sítio Cirúrgico.
// Padrão idêntico ao atb-db.js / lab-db.js: idempotente, CREATE ... IF NOT EXISTS,
// ADD COLUMN IF NOT EXISTS, seeds com ON CONFLICT DO NOTHING.
//
// MODELO (a virada em relação ao JotForm):
//   O JotForm tratava CADA CONTATO como uma submissão independente — o mesmo
//   paciente virava 2 linhas soltas (7d e 30d). Aqui:
//
//     isc_fichas   → 1 linha por PACIENTE-CIRURGIA (a linha do grid).
//     isc_contatos → N linhas: cada tentativa/ponto de contato (log longitudinal).
//
//   O estado por janela é MATERIALIZADO em isc_fichas (janelas_estado JSONB +
//   colunas derivadas) para o grid ser rápido/filtrável sem join, e é recalculado
//   a partir de isc_contatos a cada escrita (mesma disciplina do monitoring engine
//   do ATB: uma fonte de verdade, derivados sempre recomputados).
//
// TENANCY: mesma base compartilhada, separada por instituicao_id (FK para
// atb_instituicoes — reaproveitada de propósito: é a MESMA lista de hospitais,
// não faz sentido um segundo cadastro divergindo).
// ──────────────────────────────────────────────────────────────────────────

export async function runIscMigrations(pool) {

  // ── Equipes sob vigilância ────────────────────────────────────────────────
  // Hoje: Neuro e Cardio (HUSF). O desenho já suporta ampliar para as equipes
  // que entrarem em auditoria depois, sem DDL novo — basta INSERT.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS isc_equipes (
      id               SERIAL PRIMARY KEY,
      instituicao_id   INTEGER REFERENCES atb_instituicoes(id),
      nome             TEXT NOT NULL,
      sigla            TEXT,
      -- Janelas de vigilância padrão desta equipe (dias pós-op).
      janelas_default  JSONB   DEFAULT '[7,30]',
      -- Janelas quando a cirurgia envolve implante/prótese (NHSN pós-2016: 90d).
      janelas_implante JSONB   DEFAULT '[7,30,90]',
      -- Equipes cujo procedimento é quase sempre com implante já marcam por default.
      implante_default BOOLEAN DEFAULT false,
      ativo            BOOLEAN DEFAULT true,
      ordem            INTEGER DEFAULT 100,
      created_at       TIMESTAMPTZ DEFAULT now(),
      UNIQUE (instituicao_id, nome)
    )
  `);

  // Seed das equipes iniciais do HUSF (idempotente).
  await pool.query(`
    INSERT INTO isc_equipes (instituicao_id, nome, sigla, janelas_default, janelas_implante, implante_default, ordem)
    SELECT i.id, v.nome, v.sigla, v.jd::jsonb, v.ji::jsonb, v.impl, v.ordem
      FROM atb_instituicoes i
      CROSS JOIN (VALUES
        ('Neurocirurgia',      'NEURO',  '[7,30]',    '[7,30,90]', true,  10),
        ('Cirurgia Cardíaca',  'CARDIO', '[7,30]',    '[7,30,90]', true,  20),
        ('Cirurgia Geral',     'CGERAL', '[7,30]',    '[7,30,90]', false, 30),
        ('Ortopedia',          'ORTO',   '[7,30]',    '[7,30,90]', true,  40),
        ('Ginecologia',        'GO',     '[7,30]',    '[7,30,90]', false, 50),
        ('Urologia',           'URO',    '[7,30]',    '[7,30,90]', false, 60),
        ('Vascular',           'VASC',   '[7,30]',    '[7,30,90]', true,  70),
        ('Obstetrícia',        'GO-OBST','[7,30]',    '[7,30,90]', false, 15)
      ) AS v(nome, sigla, jd, ji, impl, ordem)
     WHERE i.sigla = 'HUSF'
    ON CONFLICT (instituicao_id, nome) DO NOTHING
  `);

  // ── Fichas ────────────────────────────────────────────────────────────────
  // 1 linha = 1 paciente-cirurgia = 1 linha do grid.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS isc_fichas (
      id                    SERIAL PRIMARY KEY,
      instituicao_id        INTEGER REFERENCES atb_instituicoes(id),

      -- Identificação
      paciente_nome         TEXT,
      paciente_iniciais     TEXT,
      paciente_dn           DATE,
      prontuario            TEXT,
      atendimento           TEXT,
      telefone              TEXT,          -- E.164 normalizado (55DDD9XXXXXXXX)
      telefone_raw          TEXT,          -- como foi digitado
      contato_alternativo   TEXT,

      -- Cirurgia (dados estáveis — não mudam entre contatos)
      equipe_id             INTEGER REFERENCES isc_equipes(id),
      especialidade         TEXT,          -- texto livre / fallback histórico
      procedimento          TEXT,
      cirurgiao             TEXT,
      data_cirurgia         DATE NOT NULL,
      data_alta             DATE,
      implante              BOOLEAN DEFAULT false,
      potencial_contaminacao TEXT,         -- limpa | potencialmente_contaminada | contaminada | infectada
      duracao_min           INTEGER,
      asa                   TEXT,
      antibioticoprofilaxia TEXT,

      -- Plano de vigilância
      janelas               JSONB   DEFAULT '[7,30]',   -- dias pós-op a contatar
      status_vigilancia     TEXT    DEFAULT 'em_vigilancia',
        -- em_vigilancia | concluida | perda_seguimento | obito | excluida

      -- Estado materializado (derivado de isc_contatos; recomputado a cada escrita)
      janelas_estado        JSONB   DEFAULT '{}',
        -- { "7": {status,data_prevista,data_contato,contato_id,alerta}, "30": {...} }
      proxima_janela        INTEGER,
      proximo_contato_em    DATE,
      contatos_ok           INTEGER DEFAULT 0,
      tentativas_falhas     INTEGER DEFAULT 0,
      tem_alerta            BOOLEAN DEFAULT false,
      ultimo_contato_em     TIMESTAMPTZ,

      -- Sinal vindo da colaboradora (triagem)
      suspeita_isc          BOOLEAN DEFAULT false,

      -- Classificação SCIH (do médico — nunca sobrescrita por contato)
      isc_classificacao     TEXT    DEFAULT 'nao_avaliada',
        -- nao_avaliada | investigando | confirmada | descartada
      isc_tipo              TEXT,   -- incisional_superficial | incisional_profunda | orgao_cavidade
      isc_data_diagnostico  DATE,
      isc_criterios         JSONB   DEFAULT '[]',
      isc_patogeno          TEXT,
      isc_readmissao        BOOLEAN DEFAULT false,
      isc_reabordagem       BOOLEAN DEFAULT false,
      isc_obito_relacionado BOOLEAN DEFAULT false,
      isc_observacao        TEXT,
      classificado_por      TEXT,
      classificado_em       TIMESTAMPTZ,

      -- Desfecho
      obito                 BOOLEAN DEFAULT false,
      obito_data            DATE,
      obito_causa           TEXT,   -- outras_causas | relacionado_procedimento

      observacao            TEXT,
      payload_raw           JSONB   DEFAULT '{}',   -- extras não promovidos (padrão ATB)
      origem                TEXT    DEFAULT 'app',  -- app | jotform | import
      jotform_submission_id TEXT UNIQUE,

      created_at            TIMESTAMPTZ DEFAULT now(),
      updated_at            TIMESTAMPTZ DEFAULT now()
    )
  `);

  // Colunas adicionadas depois entram aqui (idempotente).
  const colsExtras = [
    ['telefone_raw', 'TEXT'],
    ['contato_alternativo', 'TEXT'],
    ['antibioticoprofilaxia', 'TEXT'],
    ['isc_criterios', `JSONB DEFAULT '[]'`],
    // DDD deduzido da cidade no import — a agenda pede confirmação antes do envio.
    ['telefone_presumido', 'BOOLEAN DEFAULT false'],
    // Nº da cirurgia no Tasy (col A do Relação das Cirurgias). Único e estável
    // por cirurgia — melhor chave de deduplicação que atendimento+data, que
    // quebra quando a cirurgia é remarcada.
    ['cirurgia_id', 'TEXT'],
  ];
  for (const [col, tipo] of colsExtras) {
    await pool.query(`ALTER TABLE isc_fichas ADD COLUMN IF NOT EXISTS ${col} ${tipo}`);
  }

  await pool.query(`CREATE INDEX IF NOT EXISTS isc_fichas_inst_idx        ON isc_fichas (instituicao_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS isc_fichas_dtcir_idx       ON isc_fichas (data_cirurgia DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS isc_fichas_proximo_idx     ON isc_fichas (proximo_contato_em) WHERE status_vigilancia = 'em_vigilancia'`);
  await pool.query(`CREATE INDEX IF NOT EXISTS isc_fichas_classif_idx     ON isc_fichas (isc_classificacao)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS isc_fichas_equipe_idx      ON isc_fichas (equipe_id)`);
  // NOTA: NÃO indexar to_char(data_cirurgia,'YYYY-MM') — to_char(date,text) é
  // STABLE, não IMMUTABLE, e o Postgres recusa o índice de expressão. O filtro
  // "mês da cirurgia" do grid é resolvido por RANGE (>= 1º do mês, < 1º do mês
  // seguinte), que é sargável e usa o btree de data_cirurgia acima.
  // Anti-duplicata (fallback): mesmo atendimento + mesma data = mesma ficha.
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS isc_fichas_unica_idx
      ON isc_fichas (instituicao_id, atendimento, data_cirurgia)
     WHERE atendimento IS NOT NULL AND atendimento <> ''
  `);
  // Anti-duplicata (preferencial): o nº da cirurgia do Tasy.
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS isc_fichas_cirurgia_idx
      ON isc_fichas (instituicao_id, cirurgia_id)
     WHERE cirurgia_id IS NOT NULL AND cirurgia_id <> ''
  `);

  // ── Contatos ──────────────────────────────────────────────────────────────
  // O log longitudinal e auditável. NADA aqui é sobrescrito: cada tentativa,
  // com ou sem sucesso, vira uma linha. As respostas do checklist ficam em
  // JSONB (respostas) — o checklist é versionado em código (isc-checklist.js),
  // não replicado em DDL, para não repetir o erro dos 8 registries paralelos.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS isc_contatos (
      id               SERIAL PRIMARY KEY,
      ficha_id         INTEGER NOT NULL REFERENCES isc_fichas(id) ON DELETE CASCADE,
      janela           INTEGER,          -- 7 | 30 | 90 ... NULL = contato avulso
      data_contato     TIMESTAMPTZ DEFAULT now(),
      canal            TEXT DEFAULT 'whatsapp',  -- whatsapp | telefone | presencial | prontuario | outro
      sucesso          BOOLEAN DEFAULT true,
      motivo_insucesso TEXT,             -- nao_atende | numero_invalido | recusou | caixa_postal | outro
      informante       TEXT,             -- "Nome / grau de parentesco"
      respostas        JSONB DEFAULT '{}',
      suspeita_isc     BOOLEAN DEFAULT false,
      recomendacoes    JSONB DEFAULT '[]',
      responsavel      TEXT,             -- quem fez o contato
      observacao       TEXT,
      created_at       TIMESTAMPTZ DEFAULT now()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS isc_contatos_ficha_idx ON isc_contatos (ficha_id, janela, data_contato DESC)`);

  // ── Templates de mensagem ─────────────────────────────────────────────────
  // Corpo com placeholders {{paciente}}, {{primeiro_nome}}, {{procedimento}},
  // {{dias_pos_op}}, {{data_cirurgia}}, {{equipe}}, {{hospital}}.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS isc_msg_templates (
      id             SERIAL PRIMARY KEY,
      instituicao_id INTEGER REFERENCES atb_instituicoes(id),
      janela         INTEGER,      -- NULL = template genérico / avulso
      nome           TEXT NOT NULL,
      corpo          TEXT NOT NULL,
      ativo          BOOLEAN DEFAULT true,
      ordem          INTEGER DEFAULT 100,
      created_at     TIMESTAMPTZ DEFAULT now(),
      updated_at     TIMESTAMPTZ DEFAULT now()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS isc_msg_templates_idx ON isc_msg_templates (instituicao_id, janela, ativo)`);

  // Seed dos templates padrão do HUSF (idempotente por nome+instituição).
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS isc_msg_templates_nome_idx
      ON isc_msg_templates (instituicao_id, nome)
  `);
  await pool.query(`
    INSERT INTO isc_msg_templates (instituicao_id, janela, nome, corpo, ordem)
    SELECT i.id, v.janela, v.nome, v.corpo, v.ordem
      FROM atb_instituicoes i
      CROSS JOIN (VALUES
        (NULL::int, 'Apresentação (1º contato)',
         E'Olá, {{primeiro_nome}}! Aqui é da Comissão de Controle de Infecção do {{hospital}}.\\n\\nEstamos acompanhando a recuperação de quem passou por cirurgia aqui conosco. São só algumas perguntas rápidas sobre como está a sua recuperação — leva menos de 2 minutos e ajuda muito no seu cuidado.\\n\\nPodemos conversar agora?',
         10),
        (7, 'Busca ativa · 7 dias',
         E'Olá, {{primeiro_nome}}! Aqui é da Comissão de Controle de Infecção do {{hospital}}.\\n\\nFaz {{dias_pos_op}} dias da sua cirurgia ({{procedimento}}, em {{data_cirurgia}}). Queremos saber como está a sua recuperação:\\n\\n1) Como está o corte da cirurgia? Está com vermelhidão, inchaço, saindo secreção ou pus?\\n2) Teve febre?\\n3) A dor melhorou e depois voltou a piorar?\\n4) Está tomando algum antibiótico?\\n5) Precisou voltar ao hospital ou procurar o médico?\\n\\nPode responder por aqui mesmo. Obrigado!',
         20),
        (30, 'Busca ativa · 30 dias',
         E'Olá, {{primeiro_nome}}! Aqui é da Comissão de Controle de Infecção do {{hospital}}.\\n\\nJá se passaram {{dias_pos_op}} dias da sua cirurgia ({{procedimento}}). Só um retorno rápido:\\n\\n1) Como está a ferida operatória? Cicatrizou bem?\\n2) Teve febre, secreção ou abertura do corte nesse período?\\n3) Precisou usar antibiótico?\\n4) Precisou de nova cirurgia no mesmo local?\\n5) Já teve o retorno com a equipe cirúrgica? Correu tudo bem?\\n\\nObrigado por ajudar!',
         30),
        (90, 'Busca ativa · 90 dias (implante)',
         E'Olá, {{primeiro_nome}}! Aqui é da Comissão de Controle de Infecção do {{hospital}}.\\n\\nEstamos completando o acompanhamento de {{dias_pos_op}} dias da sua cirurgia ({{procedimento}}). É o último contato:\\n\\n1) Houve algum problema com a cicatriz desde a última vez que conversamos?\\n2) Precisou de antibiótico, nova cirurgia ou internação por causa do local operado?\\n3) Está tudo bem no acompanhamento com a equipe?\\n\\nObrigado pela colaboração!',
         40),
        (NULL::int, 'Sem resposta (reforço)',
         E'Olá, {{primeiro_nome}}! Aqui é da Comissão de Controle de Infecção do {{hospital}}.\\n\\nTentamos contato sobre a sua recuperação pós-cirúrgica e não conseguimos falar com você. Quando puder, é só responder por aqui — são só algumas perguntas rápidas.\\n\\nSe estiver tudo bem, pode responder apenas "tudo bem". Obrigado!',
         50),
        (NULL::int, 'Orientação de retorno',
         E'{{primeiro_nome}}, pelo que você nos contou, o ideal é que você seja avaliad@ presencialmente.\\n\\nOrientamos procurar o Pronto-Socorro do {{hospital}} / a equipe da {{equipe}} para uma avaliação da ferida operatória.\\n\\nQualquer piora (febre, saída de pus, abertura do corte, dor forte), procure atendimento imediatamente. Paz e Bem!',
         60)
      ) AS v(janela, nome, corpo, ordem)
     WHERE i.sigla = 'HUSF'
    ON CONFLICT (instituicao_id, nome) DO NOTHING
  `);

  // ── Config de mensageria ──────────────────────────────────────────────────
  // O número institucional do WhatsApp Business. Serve para (a) lembrar a
  // colaboradora, no momento do envio, de qual número a mensagem DEVE sair, e
  // (b) o autoteste de remetente. Fica no banco, não no código: número de
  // hospital muda e não vai virar deploy.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS isc_config (
      instituicao_id    INTEGER PRIMARY KEY REFERENCES atb_instituicoes(id),
      whatsapp_business TEXT,     -- E.164 (ex.: 551124901268)
      updated_at        TIMESTAMPTZ DEFAULT now()
    )
  `);

  // ── Fila de envios ────────────────────────────────────────────────────────
  // PROVISÃO PARA ENVIO AUTOMÁTICO. Fase 1: o sistema agenda + renderiza a
  // mensagem e a colaboradora dispara pelo WhatsApp Business (link wa.me) e
  // marca como enviada → status 'manual'. Fase 2: um worker drena status
  // 'pendente' pela Cloud API. A tabela já contempla os dois — a troca é de
  // driver, não de modelo.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS isc_envios (
      id                  SERIAL PRIMARY KEY,
      ficha_id            INTEGER NOT NULL REFERENCES isc_fichas(id) ON DELETE CASCADE,
      janela              INTEGER,
      template_id         INTEGER REFERENCES isc_msg_templates(id) ON DELETE SET NULL,
      telefone            TEXT,
      corpo               TEXT,            -- já renderizado (snapshot do que foi enviado)
      status              TEXT DEFAULT 'pendente',
        -- pendente | enviado | manual | erro | cancelado
      agendado_para       DATE,
      enviado_em          TIMESTAMPTZ,
      enviado_por         TEXT,
      provider            TEXT,            -- 'manual' | 'whatsapp_cloud' | ...
      provider_message_id TEXT,
      tentativas          INTEGER DEFAULT 0,
      erro                TEXT,
      created_at          TIMESTAMPTZ DEFAULT now(),
      updated_at          TIMESTAMPTZ DEFAULT now()
    )
  `);
  // Idempotência do agendador: 1 envio por ficha+janela.
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS isc_envios_ficha_janela_idx
      ON isc_envios (ficha_id, janela) WHERE janela IS NOT NULL
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS isc_envios_fila_idx ON isc_envios (status, agendado_para)`);

  // ── Importação de mapa cirúrgico ──────────────────────────────────────────
  // PERFIS: o mapeamento coluna→campo salvo. Sem isso, alguém reconfigura 18
  // selects toda semana e para de usar o importador na terceira vez.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS isc_import_perfis (
      id             SERIAL PRIMARY KEY,
      instituicao_id INTEGER REFERENCES atb_instituicoes(id),
      nome           TEXT NOT NULL,
      mapeamento     JSONB NOT NULL DEFAULT '{}',   -- { "0": "paciente_nome", ... }
      delim          TEXT,
      created_at     TIMESTAMPTZ DEFAULT now(),
      updated_at     TIMESTAMPTZ DEFAULT now(),
      UNIQUE (instituicao_id, nome)
    )
  `);

  // LOTES: toda importação é rastreável e REVERSÍVEL. Import de mapa errado
  // acontece — sem lote, desfazer vira caça manual no grid.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS isc_import_lotes (
      id             SERIAL PRIMARY KEY,
      instituicao_id INTEGER REFERENCES atb_instituicoes(id),
      criado_por     TEXT,
      arquivo_nome   TEXT,
      mapeamento     JSONB DEFAULT '{}',
      total_linhas   INTEGER DEFAULT 0,
      criadas        INTEGER DEFAULT 0,
      ignoradas      INTEGER DEFAULT 0,
      desfeito_em    TIMESTAMPTZ,
      created_at     TIMESTAMPTZ DEFAULT now()
    )
  `);

  // Código da especialidade no CVE (ex.: CNEURO). Fica na equipe para o
  // relatório de numeradores casar com a planilha sem tradução no meio.
  await pool.query(`ALTER TABLE isc_equipes ADD COLUMN IF NOT EXISTS codigo_cve TEXT`);

  // ── Regras de triagem ─────────────────────────────────────────────────────
  // Definem o que do mapa cirúrgico entra na vigilância. A implantação é
  // escalonada: fase 1 = neuro/cardio/cesariana; depois, o rol do CVE. Ampliar
  // = INSERT, nunca DDL nem deploy.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS isc_triagem_regras (
      id              SERIAL PRIMARY KEY,
      instituicao_id  INTEGER REFERENCES atb_instituicoes(id),
      nome            TEXT NOT NULL,
      ordem           INTEGER DEFAULT 100,
      ativo           BOOLEAN DEFAULT true,
      -- Termos separados por | . Casam como PALAVRA INTEIRA, sem acento.
      match_proc      TEXT,
      nao_match_proc  TEXT,
      match_cirurgiao TEXT,
      match_tipo      TEXT,
      -- Resultado
      vigiar          BOOLEAN DEFAULT true,
      equipe_id       INTEGER REFERENCES isc_equipes(id) ON DELETE SET NULL,
      codigo_cve      TEXT,
      implante        BOOLEAN,
      created_at      TIMESTAMPTZ DEFAULT now(),
      updated_at      TIMESTAMPTZ DEFAULT now(),
      UNIQUE (instituicao_id, nome)
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS isc_triagem_idx ON isc_triagem_regras (instituicao_id, ativo, ordem)`);

  // Seed das regras da fase 1 (idempotente). As de exclusão têm ordem menor,
  // para "Coluna Vertebral: Infiltração" cair fora antes da regra de neuro.
  const { REGRAS_SEED } = await import('./isc-triagem.js');
  for (const r of REGRAS_SEED) {
    await pool.query(
      `INSERT INTO isc_triagem_regras
         (instituicao_id, nome, ordem, vigiar, match_proc, nao_match_proc, codigo_cve, implante, equipe_id)
       SELECT i.id, $2, $3, $4, $5, $6, $7, $8,
              (SELECT e.id FROM isc_equipes e WHERE e.instituicao_id = i.id AND e.nome = $9)
         FROM atb_instituicoes i WHERE i.sigla = $1
       ON CONFLICT (instituicao_id, nome) DO NOTHING`,
      ['HUSF', r.nome, r.ordem, r.vigiar, r.match_proc || null, r.nao_match_proc || null,
       r.codigo_cve || null, r.implante ?? null, r.equipe || null]);
  }
  // Propaga o código CVE para a equipe (o relatório lê de lá).
  await pool.query(`
    UPDATE isc_equipes e SET codigo_cve = r.codigo_cve
      FROM isc_triagem_regras r
     WHERE r.equipe_id = e.id AND r.codigo_cve IS NOT NULL AND e.codigo_cve IS NULL`);

  // Perfil semeado do Tasy_Rel (mapeamento conferido coluna a coluna pelo SCIH).
  // Os índices são da PLANILHA, não do rótulo: no layout de impressão o título
  // fica na coluna errada — "Data Inicio" está na K, a data na I.
  //   A=0 nº cirurgia · D=3 atend · F=5 procedimento · G=6 endereço+fone
  //   I=8 data · N=13 duração · O=14 paciente · X=23 cirurgião · AA=26 anestesia
  await pool.query(`
    INSERT INTO isc_import_perfis (instituicao_id, nome, mapeamento, delim)
    SELECT i.id, 'Tasy_Rel — Relação das Cirurgias', $1::jsonb, E'\t'
      FROM atb_instituicoes i WHERE i.sigla = 'HUSF'
    ON CONFLICT (instituicao_id, nome) DO NOTHING
  `, [JSON.stringify({
    0: 'cirurgia_id', 3: 'atendimento', 5: 'procedimento', 6: 'contato_blob',
    8: 'data_cirurgia', 13: 'duracao_min', 14: 'paciente_nome',
    23: 'cirurgiao', 26: 'tipo_anestesia',
  })]);

  await pool.query(`ALTER TABLE isc_fichas ADD COLUMN IF NOT EXISTS import_lote_id INTEGER REFERENCES isc_import_lotes(id) ON DELETE SET NULL`);
  await pool.query(`CREATE INDEX IF NOT EXISTS isc_fichas_lote_idx ON isc_fichas (import_lote_id)`);

  console.log('[isc-db] migrações ISC concluídas');
}
