// send-initial-welcome.js
import pg from 'pg';
import 'dotenv/config.js';            // se você usa .env (opcional)
import { sendWelcomeEmail } from './mailer.js';

const { Pool } = pg;

// Ajuste se necessário: DATABASE_URL deve estar configurada
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // ssl: { rejectUnauthorized: false } // descomente se seu provedor exigir
});

// Configurações úteis
const DRY_RUN = process.env.DRY_RUN === '1';   // 1 = não envia, só loga
const LIMIT = parseInt(process.env.BATCH_LIMIT || '500', 10); // segurança
const THROTTLE_MS = parseInt(process.env.THROTTLE_MS || '800', 10); // Gmail ~1s

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function main() {
  console.log(`[init] DRY_RUN=${DRY_RUN} LIMIT=${LIMIT} THROTTLE_MS=${THROTTLE_MS}`);

  // 1) garanta que a coluna welcome_email_sent_at exista
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS welcome_email_sent_at TIMESTAMPTZ
  `);

  // 2) busque usuários ainda não notificados
  //    Obs.: só podemos incluir SENHA se existir temp_password. Se não existir, não sabemos a senha (só o hash).
  const { rows: users } = await pool.query(
    `SELECT id, full_name, email, temp_password
       FROM users
      WHERE welcome_email_sent_at IS NULL
      ORDER BY id
      LIMIT $1`, [LIMIT]
  );

  console.log(`[query] ${users.length} usuário(s) elegível(eis)`);

  for (const u of users) {
    // Se não temos a senha em claro, não dá pra incluir a senha no e-mail.
    if (!u.temp_password) {
      console.warn(`[skip] ${u.email} sem temp_password — pulando (não sabemos a senha em texto)`);
      continue;
    }

    const payload = {
      to: u.email,
      name: u.full_name || u.email,
      login: u.email,            // seu login é o e-mail
      password: u.temp_password, // senha exatamente como cadastrada
    };

    if (DRY_RUN) {
      console.log(`[dry-run] Enviaria para: ${payload.to} | login=${payload.login}`);
    } else {
      try {
        await sendWelcomeEmail(payload);
        await pool.query(
          'UPDATE users SET welcome_email_sent_at = now() WHERE id = $1',
          [u.id]
        );
        console.log(`[ok] ${u.email}`);
        await sleep(THROTTLE_MS); // respeita limite do Gmail
      } catch (err) {
        console.error(`[erro] ${u.email}`, err);
      }
    }
  }

  await pool.end();
  console.log('[done]');
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
