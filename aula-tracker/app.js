// Aula Tracker — Postgres + Cloudflare R2 (SigV4)
// Admin: gerencia cursos, aulas, alunos/matrículas; vê/edita tudo; relatórios web + CSV ordenados por nome
// Player: URL assinada SigV4 (R2), sem download, watermark e tracking de progresso
// Ajustes nesta versão:
// - Disponibilidade: courses.start_date e videos.available_from
// - Tela admin para editar disponibilidade das aulas (/admin/videos/availability)
// - Filtro em /aulas (aluno) respeitando as datas

import express from 'express';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import { Pool } from 'pg';
import { runLabMigrations } from './lab-db.js';       // ← ADICIONAR
import { registerLabRoutes } from './lab-routes.js';  // ← ADICIONAR
import { dirname } from 'path';
import { fileURLToPath } from 'url';
import { runAtbMigrations } from './atb-db.js';        // ← ADICIONAR
import { registerAtbRoutes } from './atb-routes.js';   // ← ADICIONAR
import { runProntMigrations } from './pront-db.js';
import { registerProntRoutes } from './pront-routes.js';
import { runAgendaMigrations } from './agenda-db.js';
import { registerAgendaRoutes } from './agenda-routes.js';
import { registerSecretariaRoutes } from './secretaria-routes.js';
import { startAgendaLembretes } from './agenda-lembretes.js';
import { renderShell } from './ui-shell.js';
import { createAuthMiddlewares } from './auth-middlewares.js';
import { runAulasMigrations } from './aulas-db.js';
import { registerAulasRoutes } from './aulas-routes.js';
import { registerAulasAdminCursosRoutes } from './aulas-admin-cursos-routes.js';
import { registerAulasAdminAlunosRoutes } from './aulas-admin-alunos-routes.js';
import { registerAulasAdminRelatoriosRoutes } from './aulas-admin-relatorios-routes.js';

const __dirname = dirname(fileURLToPath(import.meta.url));


// ---- SSL config helper (minimal, surgical) ----
const __pgSslMode = (process.env.PGSSLMODE || '').toLowerCase();
const __sslConfig = (__pgSslMode === 'disable')
  ? false
  : { rejectUnauthorized: (__pgSslMode === 'no-verify') ? false : true };
// -----------------------------------------------

const app = express();
app.set('trust proxy', 1);

// JSON pequeno (2mb) por padrão; as rotas de upload grande (áudio, exames, conferência)
// têm o próprio parser de 25mb (jsonGrande), então o global PULA essas rotas pra não barrá-las antes.
const jsonPequeno = express.json({ limit: '2mb' });
const ROTAS_UPLOAD_GRANDE = /\/(consulta\/audio|upload|exames\/importar\/(previa|gravar)|exames\/resultado\/editar|conferencia\/[^/]+\/confirmar(-consulta)?)$/;
app.use((req, res, next) => {
  if (req.method === 'POST' && ROTAS_UPLOAD_GRANDE.test(req.path)) return next();
  return jsonPequeno(req, res, next);
});
app.use(express.urlencoded({ extended: true, limit: '4mb' }));
app.use(cookieParser());
app.use(express.static(__dirname));

const PORT = process.env.PORT || 3000;

// ====== ENV ======
const DATABASE_URL = process.env.DATABASE_URL;
const DATABASE_URL_UNPOOLED = process.env.DATABASE_URL_UNPOOLED || null;
const PGSSLMODE = process.env.PGSSLMODE || 'require';
const SUPABASE_POOLER_URL = process.env.SUPABASE_POOLER_URL || null;
const ADMIN_SECRET = process.env.ADMIN_SECRET || null;
const ALLOWED_EMAIL_DOMAIN = process.env.ALLOWED_EMAIL_DOMAIN || null;
const SEMESTER_END = process.env.SEMESTER_END || null;

// R2 (SigV4)
const R2_BUCKET = process.env.R2_BUCKET;
const R2_ENDPOINT = process.env.R2_ENDPOINT; // https://<ACCOUNT>.r2.cloudflarestorage.com
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY;

// ====== PG Pool ======
const pool = new Pool({
  connectionString: SUPABASE_POOLER_URL || DATABASE_URL,
  // Usa o Transaction Pooler (porta 6543) quando SUPABASE_POOLER_URL estiver definido; SSL com verificação de certificado
  ssl: __sslConfig
});
// Pool dedicado para migrações (usa conexão direta quando disponível)
const migratorPool = new Pool({
  connectionString: DATABASE_URL_UNPOOLED || DATABASE_URL,
  ssl: __sslConfig
});
// ====== HTML helpers / Auth / Utils (extraídos) ======
// safe/renderShell -> ui-shell.js | middlewares -> auth-middlewares.js
// normalizeDateStr/fmtDTLocal -> aulas-utils.js | R2 -> aulas-storage.js
const {
  isAdmin,
  adminRequired,
  authRequired,
  scihRequired,
  gridRequired,
  prontRequired,
  medicoRequired,
  agendaRequired,
  secretariaRequired,
} = createAuthMiddlewares({ pool, ADMIN_SECRET, renderShell });

// ====== Migrações do domínio Aulas (aulas-db.js) ======
runAulasMigrations(migratorPool).catch(e=>console.error('migration error', e));

runLabMigrations(migratorPool).catch(e => console.error('lab migration error', e)); // ← ADICIONAR
runAtbMigrations(migratorPool).catch(e => console.error('atb migration error', e));   // ← ADICIONAR
runProntMigrations(migratorPool)
  .then(() => runAgendaMigrations(migratorPool))   // agenda depende de pront_pacientes
  .catch(e => console.error('pront/agenda migration error', e));



// ====== Health ======
app.get('/healthz', (req,res)=> res.status(200).send('ok'));

// ====== start ======
process.on('unhandledRejection', (reason) => console.error('UNHANDLED REJECTION', reason));
process.on('uncaughtException',  (err)    => console.error('UNCAUGHT EXCEPTION', err));
try { registerAulasRoutes(app, pool, { authRequired, isAdmin }); }
catch (e) { console.error('ERRO registerAulasRoutes', e); }
try { registerAulasAdminCursosRoutes(app, pool, { authRequired, adminRequired }); }
catch (e) { console.error('ERRO registerAulasAdminCursosRoutes', e); }
try { registerAulasAdminAlunosRoutes(app, pool, { authRequired, adminRequired }); }
catch (e) { console.error('ERRO registerAulasAdminAlunosRoutes', e); }
try { registerAulasAdminRelatoriosRoutes(app, pool, { authRequired, adminRequired }); }
catch (e) { console.error('ERRO registerAulasAdminRelatoriosRoutes', e); }
try { registerLabRoutes(app, pool, adminRequired, renderShell); }
catch (e) { console.error('ERRO registerLabRoutes', e); }
try { registerAtbRoutes(app, pool, scihRequired, renderShell, gridRequired); }
catch (e) { console.error('ERRO registerAtbRoutes', e); }
try { registerProntRoutes(app, pool, prontRequired, adminRequired, renderShell, medicoRequired); }
catch (e) { console.error('ERRO registerProntRoutes', e); }
try { registerAgendaRoutes(app, pool, agendaRequired, renderShell); }
catch (e) { console.error('ERRO registerAgendaRoutes', e); }
try { registerSecretariaRoutes(app, pool, secretariaRequired, renderShell); }
catch (e) { console.error('ERRO registerSecretariaRoutes', e); }
try { startAgendaLembretes(pool); }
catch (e) { console.error('ERRO startAgendaLembretes', e); }
app.listen(PORT, ()=> console.log(`Aula Tracker (Postgres) rodando na porta ${PORT}`));

// ====== KEEPALIVE SUPABASE ======
setInterval(async () => {
  try {
    await pool.query('SELECT 1');
    console.log('Keepalive Supabase OK', new Date().toISOString());
  } catch (err) {
    console.error('Erro no keepalive Supabase', err.message);
  }
}, 5 * 60 * 1000); // a cada 5 minutos
