// estoque-db.js
// Migrations e seed do controle de estoque dos testes rápidos do consultório.
// Não modifica nenhuma tabela existente — apenas cria tabelas novas com prefixo estoque_.
// Todas as migrations usam IF NOT EXISTS. O seed é idempotente: só popula se a tabela
// estiver vazia, nunca sobrescreve contagens reais depois do primeiro deploy.

export async function runEstoqueMigrations(pool) {
  // Itens do estoque — um registro por teste/cassete físico.
  // qtd_uso     = cassetes na gaveta do laboratório (lacrados, prontos p/ uso)
  // qtd_estoque = cassetes no storage (lacrados, reposição)
  // alerta_uso / alerta_estoque = thresholds independentes de estoque baixo
  await pool.query(`
    CREATE TABLE IF NOT EXISTS estoque_itens (
      id            SERIAL PRIMARY KEY,
      nome          TEXT NOT NULL UNIQUE,
      qtd_uso       INTEGER NOT NULL DEFAULT 0,
      qtd_estoque   INTEGER NOT NULL DEFAULT 0,
      alerta_uso    INTEGER NOT NULL DEFAULT 5,
      alerta_estoque INTEGER NOT NULL DEFAULT 5,
      ativo         BOOLEAN NOT NULL DEFAULT TRUE,
      ordem         INTEGER,
      updated_at    TIMESTAMPTZ DEFAULT now(),
      updated_by    TEXT
    )
  `);

  // Log de movimentações — quem contou/alterou o quê, para auditoria.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS estoque_mov (
      id         SERIAL PRIMARY KEY,
      item_id    INTEGER NOT NULL REFERENCES estoque_itens(id) ON DELETE CASCADE,
      campo      TEXT NOT NULL,          -- 'uso' | 'estoque'
      delta      INTEGER,               -- +N / -N quando incremento; NULL em set absoluto
      valor_novo INTEGER NOT NULL,
      quem       TEXT,
      created_at TIMESTAMPTZ DEFAULT now()
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS estoque_itens_ordem_idx
      ON estoque_itens(ativo, ordem NULLS LAST, nome)
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS estoque_mov_item_idx
      ON estoque_mov(item_id, created_at DESC)
  `);

  // ===== Seed idempotente =====
  // Só insere se a tabela estiver completamente vazia (primeiro deploy).
  // Depois disso, o catálogo é gerenciado pela própria UI (cadastro/edição).
  const { rows } = await pool.query('SELECT COUNT(*)::int AS n FROM estoque_itens');
  if (rows[0].n === 0) {
    await pool.query(`
      INSERT INTO estoque_itens (nome, ordem) VALUES
    ('Adenovírus - Antígeno', 10),
    ('Anaplasma/Ehrlichia/Babesia/Lyme (Combo)', 20),
    ('CMV (IgG/IgM)', 30),
    ('Calprotectina Fecal – Qualitativo', 40),
    ('Candida/Trichomonas (Combo)', 50),
    ('Chikungunya (IgG/IgM)', 60),
    ('Cistatina C – Dosagem sérica', 70),
    ('Clamídia - Antígeno', 80),
    ('Clostridioides difficile - GDH', 90),
    ('Clostridioides difficile - GDH + Toxinas A/B (Combo)', 100),
    ('Clostridioides difficile - Toxinas A/B', 110),
    ('Covid + FluAB - Antígenos', 120),
    ('Cryptococcus - Antígeno', 130),
    ('Cryptosporidium - Antígeno', 140),
    ('Dengue (Combo) - Antígeno + Anticorpos', 150),
    ('Dengue (IgG/IgM)', 160),
    ('Dengue - Antígeno NS1', 170),
    ('Doença de Chagas (Trypanossoma cruzi) - Anticorpos Totais', 180),
    ('Dosagem sérica de Procalcitonina', 190),
    ('Dímero D – Dosagem', 200),
    ('Epstein-Barr (VCA/EBNA/Heterófilos)', 210),
    ('Febre Amarela (IgG/IgM)', 220),
    ('Giardia - Antígeno', 230),
    ('Gonorreia - Antígeno', 240),
    ('HIV - 3a geração', 250),
    ('HIV - 4a geração', 260),
    ('HSV1 (IgG/IgM)', 270),
    ('HSV2 (IgG/IgM)', 280),
    ('Hanseníase (Lepra) - Antígeno', 290),
    ('Helicobacter pylori - Antígeno', 300),
    ('Hemoglobina Glicada – Dosagem', 310),
    ('Hepatite A (IgG/IgM)', 320),
    ('Hepatite B - Anticorpo AntiHBc', 330),
    ('Hepatite B - Anticorpo AntiHBs', 340),
    ('Hepatite B - Antígeno Hbe', 350),
    ('Hepatite B - Antígeno de Superfície', 360),
    ('Hepatite C - Anticorpos Totais', 370),
    ('Hepatite E (IgG/IgM)', 380),
    ('Influenza A/B (FluAB) - Antígeno', 390),
    ('Legionella - Antígeno', 400),
    ('Leishmania donovani - Antigeno', 410),
    ('Leptospirose (IgG/IgM)', 420),
    ('Lyme (IgG/IgM)', 430),
    ('MPOX (IgG/IgM)', 440),
    ('MPOX - Antígeno', 450),
    ('Malária - Antígeno (Pf/Pan)', 460),
    ('Malária - Antígeno (Pf/Pv)', 470),
    ('Mycoplasma - Antígeno', 480),
    ('Painel Respiratório (Covid+FluAB+VSR) - Antígenos', 490),
    ('Proteína C Reativa – Dosagem sérica', 500),
    ('Rubéola (IgG/IgM)', 510),
    ('SARS-CoV2 (Covid) - Antígeno', 520),
    ('Sarampo (IgG/IgM)', 530),
    ('Streptococcus pneumoniae - Antígeno', 540),
    ('Streptococcus pyogenes - Antígeno', 550),
    ('Sífilis - Anticorpos Totais', 560),
    ('Sífilis - VDRL', 570),
    ('Toxoplasmose (IgG/IgM)', 580),
    ('Trichomonas - Antígeno', 590),
    ('Vírus Metapneumovírus - Antígeno', 600),
    ('Vírus Parainfluenza - Antígeno', 610),
    ('Vírus Sincicial Respiratório - Antígeno', 620),
    ('West Nile (IgG/IgM)', 630),
    ('Zika (IgG/IgM)', 640)
      ON CONFLICT (nome) DO NOTHING
    `);
    console.log('[estoque] seed inicial aplicado (64 itens)');
  }
}
