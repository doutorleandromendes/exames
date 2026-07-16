// harness-isc-scih.mjs — bloco ISC no portal /scih.
// Cobre o que dá para quebrar em produção: contador ao vivo, portal não cair
// quando o ISC ainda não migrou, e o gate de super_admin.
import express from 'express';
import cookieParser from 'cookie-parser';
import { Pool } from 'pg';
import { registerScihAcessoRoutes } from './atb-scih-acesso-routes.js';
import { runIscMigrations } from './isc-db.js';
import { addDays, hojeISO } from './isc-core.js';

const DB = process.env.ISC_TEST_DB || 'postgresql://postgres:x@localhost:5432/iscteste';
const pool = new Pool({ connectionString: DB });
let ok = 0, fail = 0;
const t = (n, c, x = '') => { if (c) { ok++; console.log('  ✓', n); } else { fail++; console.log('  ✗ FALHOU:', n, x); } };

await runIscMigrations(pool);
await pool.query('TRUNCATE isc_envios, isc_contatos, isc_fichas RESTART IDENTITY CASCADE');
const { rows: [husf] } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla='HUSF'`);

// 2 vencidos + 1 com alerta a classificar + 1 tranquilo
const D = addDays(hojeISO(), -35);
await pool.query(
  `INSERT INTO isc_fichas (instituicao_id, paciente_nome, data_cirurgia, atendimento,
     status_vigilancia, proximo_contato_em, tem_alerta, isc_classificacao)
   VALUES ($1,'VENCIDO 1',$2,'V1','em_vigilancia',$3,false,'nao_avaliada'),
          ($1,'VENCIDO 2',$2,'V2','em_vigilancia',$3,true,'nao_avaliada'),
          ($1,'FUTURO',$2,'F1','em_vigilancia',$4,false,'nao_avaliada'),
          ($1,'JA CLASSIFICADO',$2,'C1','concluida',NULL,true,'confirmada')`,
  [husf.id, D, addDays(hojeISO(), -5), addDays(hojeISO(), 20)]);

function subir(usuario) {
  const app = express();
  app.use(cookieParser());
  app.use((req, res, next) => { req.user = usuario; next(); });
  // scihRequired falso: o gate real testado aqui é o ensureSuper de dentro.
  registerScihAcessoRoutes(app, pool, (q, s, n) => n());
  return app.listen(0);
}
const pega = async (srv, cookie) => {
  const r = await fetch(`http://127.0.0.1:${srv.address().port}/scih`, {
    headers: cookie ? { cookie } : {}, redirect: 'manual',
  });
  return { status: r.status, html: await r.text() };
};

console.log('\n── Gate: só super_admin ──');
let srv = subir({ full_name: 'Colaboradora', scih: true, super_admin: false });
let r = await pega(srv);
t('usuário scih comum → 403 no portal', r.status === 403, `status=${r.status}`);
t('e não vaza os links do ISC', !r.html.includes('/isc/admin/agenda'));
srv.close();

srv = subir({ full_name: 'Dr. Leandro', scih: true, super_admin: true });
r = await pega(srv);
t('super_admin → 200', r.status === 200, `status=${r.status}`);

console.log('\n── Bloco ISC presente ──');
t('seção de vigilância pós-alta', r.html.includes('Vigilância pós-alta — ISC'));
t('agenda', r.html.includes('/isc/admin/agenda'));
t('grid', r.html.includes('/isc/admin/grid'));
t('nova ficha manual', r.html.includes('/isc/admin/nova'));
t('importar mapa', r.html.includes('/isc/admin/importar'));
t('regras de triagem', r.html.includes('/isc/admin/triagem'));
t('mensagens', r.html.includes('/isc/admin/templates'));
t('export csv', r.html.includes('/isc/admin/export.csv'));

console.log('\n── Contadores ao vivo ──');
t('agenda mostra 2 vencidos', /Agenda de contatos.*?>2</s.test(r.html), 'badge não encontrado');
t('grid mostra 1 a classificar', /Grid de vigilância.*?>1</s.test(r.html));
t('não conta ficha futura como vencida', !/Agenda de contatos.*?>3</s.test(r.html));
t('não conta ficha já classificada na triagem', !/Grid de vigilância.*?>2</s.test(r.html));
t('sem aviso de erro quando o banco responde', !r.html.includes('Não consegui ler os contadores'));

console.log('\n── ATB intacto (não quebrei o portal) ──');
t('grade de controle', r.html.includes('/grade'));
t('adesão', r.html.includes('/atb/admin/adesao'));
t('aprovar acessos', r.html.includes('/atb/admin/scih'));
t('relatório antigo rotulado como histórico', r.html.includes('ISC — histórico (JotForm)'));
srv.close();

console.log('\n── Zero pendências: sem badge, não "0" ──');
await pool.query(`UPDATE isc_fichas SET status_vigilancia='concluida', tem_alerta=false`);
srv = subir({ full_name: 'X', super_admin: true });
r = await pega(srv);
t('seção continua visível', r.html.includes('Vigilância pós-alta — ISC'));
t('sem badge zerado poluindo', !/Agenda de contatos.*?>0</s.test(r.html));
srv.close();

console.log('\n── Portal NÃO cai se o ISC ainda não migrou ──');
// É o boot real: o /scih pode ser aberto antes das migrações do ISC terminarem.
const poolSemIsc = new Pool({ connectionString: DB });
const appX = express();
appX.use(cookieParser());
appX.use((req, res, next) => { req.user = { full_name: 'X', super_admin: true }; next(); });
registerScihAcessoRoutes(appX, {
  query: async (sql, p) => {
    if (/isc_fichas/.test(sql)) throw new Error('relation "isc_fichas" does not exist');
    return poolSemIsc.query(sql, p);
  },
}, (q, s, n) => n());
const srvX = appX.listen(0);
r = await pega(srvX);
t('portal responde 200 mesmo assim', r.status === 200, `status=${r.status}`);
t('ATB continua lá', r.html.includes('/grade'));
t('cards do ISC continuam lá', r.html.includes('/isc/admin/agenda'));
t('e avisa que não leu os contadores', r.html.includes('Não consegui ler os contadores'));
srvX.close(); await poolSemIsc.end();

await pool.end();
console.log(`\n${'═'.repeat(52)}\n${ok} passaram · ${fail} falharam\n`);
process.exit(fail ? 1 : 0);
