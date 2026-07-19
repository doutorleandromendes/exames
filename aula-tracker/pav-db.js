// pav-db.js
// ──────────────────────────────────────────────────────────────────────────
// Migrações do módulo PAV — bundle de prevenção de pneumonia associada à VM.
// Padrão idêntico ao atb-db.js / isc-db.js: idempotente, CREATE ... IF NOT
// EXISTS, ADD COLUMN IF NOT EXISTS, seeds com ON CONFLICT DO NOTHING.
//
// MODELO (o paradigma de duas camadas — ver pav-core.js):
//   pav_fichas        → 1 linha por EPISÓDIO de VM (a linha do grid / população
//                       ativa). Reintubação abre episódio NOVO. Transferência de
//                       salão NÃO abre — muda o salão (cache), preserva o episódio.
//   pav_checks        → 1 linha por VERIFICAÇÃO (ficha × data × turno × categoria).
//                       Guarda FATO: respostas sim/não, valores, parâmetros. NUNCA
//                       "conforme" — conformidade é DERIVADA na camada de leitura.
//   pav_transferencias→ log datado de mudança de salão (fonte da verdade do salão;
//                       pav_fichas.salao é cache do destino da última transferência).
//
// O estado materializado (adesão do dia, cobertura de turnos, salão atual) fica
// em pav_fichas para o grid ser rápido, e é recomputado a cada escrita — mesma
// disciplina do ISC/ATB: uma fonte de verdade, derivados sempre recomputados.
//
// TENANCY: instituicao_id → atb_instituicoes (a MESMA lista de hospitais).
//
// USERS: acrescenta o papel PAV. Diferente do ISC (que só lê), o PAV tem perfis
// que GERAM dado à beira-leito — por isso os campos de categoria/conselho.
// ──────────────────────────────────────────────────────────────────────────

import { REGISTRO, SALOES } from './pav-core.js';

export async function runPavMigrations(pool) {

  // ── Papel PAV nos usuários ────────────────────────────────────────────────
  // pav            : flag de acesso ao módulo (fisio individual OU login enf).
  // categoria_pav  : 'fisio' | 'enf' — decide os ITENS que a pessoa vê e o
  //                  alcance de salão (fisio: dois; enf: o da sessão).
  // conselho       : registro profissional (CREFITO da fisio). Autoria confiável
  //                  — cada check nasce assinado. Enf compartilhada preenche a
  //                  identificação por check (ver pav_checks.identificacao_manual).
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS pav           BOOLEAN DEFAULT false`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS categoria_pav TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS conselho      TEXT`);

  // ── Fichas: 1 por episódio de VM ──────────────────────────────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pav_fichas (
      id                  SERIAL PRIMARY KEY,
      instituicao_id      INTEGER REFERENCES atb_instituicoes(id),

      -- Paciente (chave de casamento com o ATB: instituicao_id + prontuario).
      paciente_nome       TEXT,
      paciente_nome_raw   TEXT,
      prontuario          TEXT,
      atendimento         TEXT,

      -- Localização. salao = CACHE do destino da última transferência (a fonte
      -- da verdade é pav_transferencias + salao inicial). leito é livre.
      salao               TEXT,           -- 'UTIAB' | 'UTIC'
      leito               TEXT,

      -- Episódio de VM.
      data_intubacao      DATE,
      data_extubacao      DATE,           -- NULL enquanto ventilado
      numero_tubo         TEXT,
      rima_labial         TEXT,
      -- Provisionado p/ o futuro (TOT com porta subglótica dedicada). Hoje NULL:
      -- a aspiração subglótica é feita às cegas (pericânula). Ver pav-core REGISTRO.
      tot_subglotica      BOOLEAN,

      -- População ativa: ativo=true enquanto em VM; vira false na extubação.
      -- (mesmo recorte diário do ISC: entra ao intubar, inativa ao extubar.)
      ativo               BOOLEAN DEFAULT true,

      -- Desfecho do episódio (motivo da saída de VM). Registro factual, NÃO é
      -- classificação de PAV — isso é do ATB.
      desfecho            TEXT,           -- 'extubacao_programada'|'extubacao_acidental'|'obito'|'tqt'|'transferencia_externa'|...

      -- Estado materializado (recomputado a cada escrita; grid sem join).
      estado_dia          JSONB   DEFAULT '{}',   -- {data: {cobertura, turnos_preenchidos, adesao, nc:[]}}
      ultimo_check_em     TIMESTAMPTZ,

      created_at          TIMESTAMPTZ DEFAULT now(),
      updated_at          TIMESTAMPTZ DEFAULT now()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS pav_fichas_ativo_idx  ON pav_fichas (instituicao_id, ativo, salao)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS pav_fichas_pront_idx  ON pav_fichas (instituicao_id, prontuario)`);

  // ── Checks: 1 por (ficha × data × turno × categoria) ──────────────────────
  // Chave única garante a anotação UMA vez por turno. A categoria entra na chave
  // porque, na sobreposição teórica de bordas, fisio e enf poderiam tocar o mesmo
  // dia — mas como as janelas não vazam (M/T/N fisio, E enf), na prática cada
  // (data,turno) tem uma categoria só. A chave protege contra corrida mesmo assim.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pav_checks (
      id                  SERIAL PRIMARY KEY,
      ficha_id            INTEGER REFERENCES pav_fichas(id) ON DELETE CASCADE,
      instituicao_id      INTEGER REFERENCES atb_instituicoes(id),

      -- Coordenada temporal do turno (data = diaDoTurno, ver pav-core).
      data                DATE    NOT NULL,
      turno               TEXT    NOT NULL,   -- 'M'|'T'|'N'|'E'
      categoria           TEXT    NOT NULL,   -- 'fisio'|'enf'

      -- Salão de onde a pessoa AFIRMOU ter trabalhado (auditoria + trava da enf,
      -- cujo salão vem da sessão). Para a fisio, é o salão do leito.
      salao               TEXT,

      -- REGISTRO (fato). itens: {[key]: {resp:'sim'|'nao', valor?, via?, justificativa?}}.
      -- vent: {fio2, peep, pao2, pf}. secrecao: {quantidade, aspecto} | null.
      -- NUNCA guarda "conforme" — isso é derivado na leitura.
      itens               JSONB   DEFAULT '{}',
      vent                JSONB   DEFAULT '{}',
      secrecao            JSONB,

      -- Autoria. preenchido_por = conta logada (sempre, p/ auditoria técnica).
      -- identificacao_manual = nome+COREN digitados (enf compartilhada); NULL p/ fisio.
      preenchido_por      INTEGER REFERENCES users(id),
      preenchido_por_nome TEXT,
      identificacao_manual TEXT,

      -- retroativo = escrito fora do turno vigente (só super-admin). Marca a série
      -- do ATB para distinguir "colhido ao vivo" de "reconstruído".
      retroativo          BOOLEAN DEFAULT false,

      -- Versões (correção dentro do turno vigente acumula histórico, como atb_evolutivos).
      historico           JSONB   DEFAULT '[]',

      created_at          TIMESTAMPTZ DEFAULT now(),
      updated_at          TIMESTAMPTZ DEFAULT now(),

      UNIQUE (ficha_id, data, turno, categoria)
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS pav_checks_ficha_idx ON pav_checks (ficha_id, data)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS pav_checks_dia_idx   ON pav_checks (instituicao_id, data, salao)`);

  // ── Transferências: log datado de mudança de salão ────────────────────────
  // Fonte da verdade do salão do paciente ao longo do tempo. pav_fichas.salao é
  // só o cache do destino da última. em = quando ACONTECEU (fisio: turno atual;
  // super-admin backfill: data real). registrado_em = quando foi LANÇADO.
  // A análise futura por salão fatia VM-dia usando `em`, não `registrado_em`.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pav_transferencias (
      id                  SERIAL PRIMARY KEY,
      ficha_id            INTEGER REFERENCES pav_fichas(id) ON DELETE CASCADE,
      instituicao_id      INTEGER REFERENCES atb_instituicoes(id),
      salao_de            TEXT    NOT NULL,
      salao_para          TEXT    NOT NULL,
      em                  TIMESTAMPTZ NOT NULL,   -- quando aconteceu
      registrado_em       TIMESTAMPTZ DEFAULT now(),
      por                 INTEGER REFERENCES users(id),
      por_nome            TEXT,
      retroativo          BOOLEAN DEFAULT false,
      created_at          TIMESTAMPTZ DEFAULT now()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS pav_transf_ficha_idx ON pav_transferencias (ficha_id, em)`);

  // ── Regras de conformidade (camada de leitura, editável pela CCIRAS) ──────
  // O REGISTRO (o que a fisio preenche) é versionado em código (pav-core.js), NÃO
  // em DDL — mesma lição do ISC (não repetir o erro dos registries paralelos).
  // Mas as REGRAS de conformidade mudam por decisão institucional e sem deploy:
  // ficam em tabela para a CCIRAS ajustar (cuff 25–30 → 20–30, etc.) e para o
  // dashboard recalcular inclusive o passado, já que o fato bruto está guardado.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pav_regras (
      id                  SERIAL PRIMARY KEY,
      instituicao_id      INTEGER REFERENCES atb_instituicoes(id),
      chave               TEXT NOT NULL,     -- 'cuff.faixa', 'despertar.na_conta_conforme', ...
      valor               JSONB NOT NULL,
      vigente_desde       DATE  DEFAULT CURRENT_DATE,
      atualizado_por      INTEGER REFERENCES users(id),
      updated_at          TIMESTAMPTZ DEFAULT now(),
      UNIQUE (instituicao_id, chave)
    )
  `);

  // Seed das regras default (idempotente). Espelha REGRAS_DEFAULT do pav-core.
  await pool.query(`
    INSERT INTO pav_regras (instituicao_id, chave, valor)
    SELECT i.id, v.chave, v.valor::jsonb
      FROM atb_instituicoes i
      CROSS JOIN (VALUES
        ('cuff.faixa',                     '[25,30]'),
        ('despertar.na_conta_conforme',    'true')
      ) AS v(chave, valor)
    ON CONFLICT (instituicao_id, chave) DO NOTHING
  `);

  console.log('[pav] migrations ok — registro:', REGISTRO.length, 'itens · salões:', SALOES.map(s => s[0]).join(','));
}
