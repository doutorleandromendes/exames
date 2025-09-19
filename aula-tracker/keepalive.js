// keepalive.js
import pg from 'pg';
const { Pool } = pg;

// Use a URL do **Transaction Pooler (porta 6543)** do Supabase.
// Você pode reaproveitar a mesma DATABASE_URL da produção ou criar uma var dedicada.
const DB_URL = process.env.SUPABASE_POOLER_URL || process.env.DATABASE_URL;

const pool = new Pool({
  connectionString: DB_URL,
  // O pooler do Supabase apresenta certificado válido; se der erro de CA na sua stack,
// troque para { rejectUnauthorized: false } só para destravar.
  ssl: { rejectUnauthorized: true }
});

(async () => {
  const t0 = Date.now();
  const r = await pool.query('select now() as ts');
  console.log('[keepalive]', r.rows[0].ts, 'latency=', Date.now() - t0, 'ms');
  await pool.end();
  process.exit(0);
})().catch(err => {
  console.error('[keepalive] error:', err);
  process.exit(1);
});
