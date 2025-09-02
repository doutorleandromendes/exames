// send-initial-welcome.js
import pg from 'pg';
import 'dotenv/config.js';
import { sendWelcomeEmail } from './mailer.js';

const { Pool } = pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // ssl: { rejectUnauthorized: false } // habilite se seu provedor exigir
});

// -------- Filtros por ambiente --------
const ONLY_EMAILS = (process.env.ONLY_EMAILS || '')
  .split(',')
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);

// Ex.: "%@mail.usf.edu.br" ou "%@gmail.com" ou "%joao%"
const EMAIL_FILTER = (process.env.EMAIL_FILTER || '').trim().toLowerCase();

// -------- Ajustes gerais --------
const DRY_RUN = process.env.DRY_RUN === '1';                 // 1 = só loga
const LIMIT = parseInt(process.env.BATCH_LIMIT || '500', 10);
const THROTTLE_MS = parseInt(process.env.THROTTLE_MS || '800', 10);

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function main() {
  console.log(`[init] DRY_RUN=${DRY_RUN} LIMIT=${LIMIT} THROTTLE_MS=${THROTTLE_MS}`);
  console.log(`[init] ONLY_EMAILS=${ONLY_EMAILS.length ? ONLY_EMAILS.join(',') : '(none)'} EMAIL_FILTER=${EMAIL_FILTER || '(none)'}`);

  // 1) garante coluna de controle
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS welcome_email_sent_at TIMESTAMPTZ
  `);

  // 2) monta a query com filtros
  let sql = `
    SELECT id, full_name, email, temp_password
      FROM users
     WHERE welcome_email_sent_at IS NULL
  `;
  const params = [];

  if (ONLY_EMAILS.length > 0) {
    params.push(ONLY_EMAILS);
    sql += ` AND lower(email) = ANY($${params.length})`;
  }

  if (EMAIL_FILTER) {
    params.push(EMAIL_FILTER);
    sql += ` AND lower(email) LIKE $${params.length}`;
  }

  params.push(LIMIT);
  sql += ` ORDER BY id LIMIT $${params.length}`;

  const { rows: users } = await pool.query(sql, params);
  console.log(`[query] ${users.length} usuário(s) elegível(eis)`);

  for (const u of users) {
    // sem temp_password não sabemos a senha em texto
    if (!u.temp_password) {
      console.warn(`[skip] ${u.email} sem temp_password — pulando`);
      continue;
    }

    const payload = {
      to: u.email,
      name: u.full_name || u.email,
      login: u.email,            // login = e-mail
      password: u.temp_password, // senha exatamente como cadastrada (numérica ou não)
    };

    if (DRY_RUN) {
      console.log(`[dry-run] Enviaria para: ${payload.to} | login=${payload.login}`);
      continue;
    }

    try {
      await sendWelcomeEmail(payload);
      await pool.query(
        'UPDATE users SET welcome_email_sent_at = now() WHERE id = $1',
        [u.id]
      );
      console.log(`[ok] ${u.email}`);
      await sleep(THROTTLE_MS);
    } catch (err) {
      console.error(`[erro] ${u.email}`, err);
    }
  }

  await pool.end();
  console.log('[done]');
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
