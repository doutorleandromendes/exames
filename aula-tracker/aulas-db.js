// ====== Migrações do domínio Aulas ======
// Extraído do app.js (função migrate) — sem alterações de comportamento.

export async function runAulasMigrations(migratorPool){
  await migratorPool.query(`
    CREATE TABLE IF NOT EXISTS users(
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE,
      password_hash TEXT,
      full_name TEXT,
      created_at TIMESTAMPTZ DEFAULT now(),
      expires_at TIMESTAMPTZ
    );`);
  await migratorPool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS scih BOOLEAN DEFAULT false`);
  await migratorPool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS super_admin BOOLEAN DEFAULT false`);
  await migratorPool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS micro BOOLEAN DEFAULT false`);
  await migratorPool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS pront BOOLEAN DEFAULT false`);

  await migratorPool.query(`
    CREATE TABLE IF NOT EXISTS courses(
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      enroll_code TEXT,
      expires_at TIMESTAMPTZ
    );`);

  await migratorPool.query(`
    CREATE TABLE IF NOT EXISTS course_members(
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
      role TEXT DEFAULT 'student',
      expires_at TIMESTAMPTZ,
      PRIMARY KEY (user_id, course_id)
    );`);

  await migratorPool.query(`
    CREATE TABLE IF NOT EXISTS videos(
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      r2_key TEXT NOT NULL,
      course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
      duration_seconds INTEGER
    );`);

  await migratorPool.query(`
    CREATE TABLE IF NOT EXISTS video_files (
      id SERIAL PRIMARY KEY,
      video_id INTEGER NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
      label TEXT NOT NULL,
      r2_key TEXT NOT NULL,
      sort_index INTEGER
    );
  `);

  await migratorPool.query(`
    CREATE TABLE IF NOT EXISTS sessions(
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
      started_at TIMESTAMPTZ DEFAULT now()
    );`);

  await migratorPool.query(`
    CREATE TABLE IF NOT EXISTS events(
      id SERIAL PRIMARY KEY,
      session_id INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
      type TEXT,
      video_time INTEGER,
      client_ts TIMESTAMPTZ
    );`);

  // ---- colunas novas/idempotentes (antes dos índices) ----
  await migratorPool.query(`ALTER TABLE users   ADD COLUMN IF NOT EXISTS temp_password TEXT`);
  await migratorPool.query(`ALTER TABLE users   ADD COLUMN IF NOT EXISTS welcome_email_sent_at TIMESTAMPTZ`);
  await migratorPool.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS archived boolean DEFAULT false`);
  await migratorPool.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS start_date TIMESTAMPTZ`);
  await migratorPool.query(`ALTER TABLE videos  ADD COLUMN IF NOT EXISTS available_from TIMESTAMPTZ`);
  await migratorPool.query(`ALTER TABLE videos  ADD COLUMN IF NOT EXISTS sort_index INTEGER`);

  // ---- watch_segments ----
  await migratorPool.query(`
    CREATE TABLE IF NOT EXISTS watch_segments (
      id SERIAL PRIMARY KEY,
      session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
      start_sec INTEGER NOT NULL,
      end_sec   INTEGER NOT NULL,
      CHECK (end_sec >= start_sec)
    );
  `);
  await migratorPool.query(`
    CREATE INDEX IF NOT EXISTS watch_segments_session_idx
      ON watch_segments(session_id, start_sec, end_sec);
  `);

  // Pedidos de acesso (pendentes/aprovados/rejeitados)
await migratorPool.query(`
  CREATE TABLE IF NOT EXISTS access_requests (
    id SERIAL PRIMARY KEY,
    full_name TEXT NOT NULL,
    email     TEXT NOT NULL,
    course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
    justification TEXT,
    status    TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected
    created_at TIMESTAMPTZ DEFAULT now(),
    processed_at TIMESTAMPTZ,
    processed_by INTEGER REFERENCES users(id) ON DELETE SET NULL
  );
`);
await migratorPool.query(`CREATE INDEX IF NOT EXISTS access_requests_status_idx ON access_requests(status, created_at DESC)`);
await migratorPool.query(`CREATE INDEX IF NOT EXISTS access_requests_email_idx  ON access_requests(LOWER(email))`);


  // ---- índices (depois das colunas existirem) ----
  await migratorPool.query(`CREATE INDEX IF NOT EXISTS video_files_video_idx
                      ON video_files(video_id, sort_index NULLS LAST, id)`);

  await migratorPool.query(`CREATE INDEX IF NOT EXISTS videos_course_order_idx
                      ON videos(course_id, sort_index NULLS LAST, id)`);

  // Unicidade por (course_id, r2_key) — e remove possíveis índices antigos em r2_key
  await migratorPool.query(`
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname='public' AND indexname='videos_r2_key_key') THEN
        EXECUTE 'DROP INDEX videos_r2_key_key';
      END IF;
      IF EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname='public' AND indexname='videos_r2_key_idx') THEN
        EXECUTE 'DROP INDEX videos_r2_key_idx';
      END IF;
    END $$;`);
  await migratorPool.query(`CREATE UNIQUE INDEX IF NOT EXISTS videos_course_r2_key_unique ON videos(course_id, r2_key)`);
}
