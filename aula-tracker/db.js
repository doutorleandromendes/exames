// db.js
import pg from "pg";
const { Pool } = pg;

function makePool() {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL, // <- pooled
    max: 5,
    keepAlive: true,
    idleTimeoutMillis: 10000,
    connectionTimeoutMillis: 5000,
    ssl: { rejectUnauthorized: true },
    statement_timeout: 15000,
    query_timeout: 15000,
  });

  pool.on("error", (err) => {
    console.warn("[DB] pool error", err.code || err.message);
  });

  return pool;
}

let pool = makePool();

export async function q(sql, params = [], tries = 3) {
  for (let i = 0; i < tries; i++) {
    try {
      return await pool.query(sql, params);
    } catch (err) {
      const transient =
        err.code === "ECONNRESET" ||
        err.code === "ECONNREFUSED" ||
        err.message?.includes("Connection terminated unexpectedly") ||
        err.message?.includes("read ECONNREFUSED") ||
        err.code === "57P01"; // admin_shutdown
      if (transient && i < tries - 1) {
        console.warn(`[DB] retry ${i + 1}/${tries} por`, err.code || err.message);
        if (i === 0) {
          try { await pool.end().catch(() => {}); } catch {}
          pool = makePool();
        }
        await new Promise(r => setTimeout(r, 1000 * Math.pow(2, i))); // 1s,2s
        continue;
      }
      throw err;
    }
  }
}
