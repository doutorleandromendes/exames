// keepalive.js
import pg from 'pg';
const { Pool } = pg;

// ---- SSL config helper (igual ao app) ----
const __pgSslMode = (process.env.PGSSLMODE || '').toLowerCase();
const __sslConfig = (__pgSslMode === 'disable')
  ? false
  : { rejectUnauthorized: (__pgSslMode === 'no-verify') ? false : true };
// ------------------------------------------

// Use a URL do **Transaction Pooler (porta 6543)** do Supabase.
// Você pode reaproveitar a mesma DATABASE_URL da produção ou criar uma var dedicada.
const DB_URL = process.env.SUPABASE_POOLER_URL || process.env.DATABASE_URL;

const pool = new Pool({
  connectionString: DB_URL,
  ssl: __sslConfig
});

(async () => {
  try {
    const t0 = Date.now();
    const r = await pool.query('select now() as ts');
    console.log('[keepalive]', r.rows[0].ts, 'latency =', Date.now() - t0, 'ms');
  } catch (err) {
    console.error('[keepalive] error:', err);
  } finally {
    await pool.end();
    process.exit(0);
  }
})();
