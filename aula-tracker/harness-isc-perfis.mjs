// harness-isc-perfis.mjs — separação colaboradora × médico do SCIH.
//
// O que importa aqui NÃO é a tela: é o servidor. Esconder um botão não protege
// nada — o teste bate direto no endpoint com a sessão da colaboradora e exige
// 403 + dado intacto no banco.
import express from 'express';
import cookieParser from 'cookie-parser';
import { Pool } from 'pg';
import { registerIscRoutes } from './isc-routes.js';
import { registerIscImportRoutes } from './isc-import-routes.js';
import { runIscMigrations } from './isc-db.js';
import { renderShell } from './ui-shell.js';
import { addDays, hojeISO } from './isc-core.js';

const DB = process.env.ISC_TEST_DB || 'postgresql://postgres:x@localhost:5432/iscteste';
const pool = new Pool({ connectionString: DB });
let ok = 0, fail = 0;
const t = (n, c, x = '') => { if (c) { ok++; console.log('  ✓', n); } else { fail++; console.log('  ✗ FALHOU:', n, x); } };

await runIscMigrations(pool);
await pool.query('TRUNCATE isc_envios, isc_contatos, isc_fichas, isc_import_lotes RESTART IDENTITY CASCADE');
const { rows: [husf] } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla='HUSF'`);
const D = addDays(hojeISO(), -10);
const { rows: [lote] } = await pool.query(
  `INSERT INTO isc_import_lotes (instituicao_id, arquivo_nome, criadas) VALUES ($1,'x.xls',1) RETURNING id`, [husf.id]);
const { rows: [f] } = await pool.query(
  `INSERT INTO isc_fichas (instituicao_id, paciente_nome, data_cirurgia, atendimento, import_lote_id, tem_alerta)
   VALUES ($1,'MARIA TESTE',$2,'A1',$3,true) RETURNING id`, [husf.id, D, lote.id]);

// Dois perfis reais: a colaboradora (scih) e o médico (super_admin).
const COLAB = { id: 1, full_name: 'Colaboradora', scih: true, super_admin: false };
const MEDICO = { id: 2, full_name: 'Dr. Leandro', scih: true, super_admin: true };

function subir(usuario, cookies = {}) {
  const app = express();
  app.use(cookieParser());
  app.use(express.urlencoded({ extended: true }));
  app.use((req, res, next) => {
    req.user = usuario;                       // o que o scihRequired real deixa
    req.cookies = { ...req.cookies, ...cookies };
    next();
  });
  // Espelha o scihRequired real: sem usuário, o break-glass (cookie adm) passa
  // com req.user = null — foi assim que o 302 do redirect me enganou de "sucesso".
  const scihFake = (req, res, next) =>
    (usuario || cookies.adm === '1') ? next() : res.redirect('/');
  registerIscRoutes(app, pool, scihFake, renderShell);
  registerIscImportRoutes(app, pool, scihFake, renderShell);
  return app.listen(0);
}
const get = (s, u) => fetch(`http://127.0.0.1:${s.address().port}${u}`, { redirect: 'manual' });
const post = (s, u, b) => fetch(`http://127.0.0.1:${s.address().port}${u}`, {
  method: 'POST', redirect: 'manual',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams(b || {}),
});

console.log('\n── COLABORADORA: opera a vigilância ──');
let s = subir(COLAB);
t('abre o grid', (await get(s, '/isc/admin/grid?inst=HUSF')).status === 200);
t('abre a agenda', (await get(s, '/isc/admin/agenda?inst=HUSF')).status === 200);
t('abre a ficha', (await get(s, `/isc/admin/ficha/${f.id}?inst=HUSF`)).status === 200);
t('cadastra ficha manual', (await get(s, '/isc/admin/nova?inst=HUSF')).status === 200);
t('abre o importador', (await get(s, '/isc/admin/importar?inst=HUSF')).status === 200);
t('edita mensagens', (await get(s, '/isc/admin/templates?inst=HUSF')).status === 200);
let r = await post(s, `/isc/admin/ficha/${f.id}/contato?inst=HUSF`, { janela: '7', r_febre: 'Sim', responsavel: 'Ana' });
t('REGISTRA CONTATO (o trabalho dela)', r.status === 302, `status=${r.status}`);
t('o contato foi gravado', (await pool.query('SELECT count(*)::int n FROM isc_contatos WHERE ficha_id=$1', [f.id])).rows[0].n === 1);

console.log('\n── COLABORADORA: barrada nos atos médicos (no SERVIDOR) ──');
r = await post(s, `/isc/admin/ficha/${f.id}/classificar?inst=HUSF`, {
  isc_classificacao: 'confirmada', isc_tipo: 'incisional_profunda', classificado_por: 'Ana',
});
t('classificar → 403', r.status === 403, `status=${r.status}`);
let { rows: [chk] } = await pool.query('SELECT * FROM isc_fichas WHERE id=$1', [f.id]);
t('e a ficha NÃO foi classificada', chk.isc_classificacao === 'nao_avaliada', chk.isc_classificacao);
t('nem carimbou autoria', !chk.classificado_em);

t('ver regras de triagem → 403', (await get(s, '/isc/admin/triagem?inst=HUSF')).status === 403);
r = await post(s, '/isc/admin/triagem?inst=HUSF', { nome: 'Regra da Ana', ordem: '1', match_proc: 'x', vigiar: '1', ativo: '1' });
t('criar regra de triagem → 403', r.status === 403, `status=${r.status}`);
t('e nenhuma regra foi criada', (await pool.query(`SELECT count(*)::int n FROM isc_triagem_regras WHERE nome='Regra da Ana'`)).rows[0].n === 0);

r = await post(s, `/isc/admin/importar/lote/${lote.id}/desfazer?inst=HUSF`, {});
t('desfazer lote → 403', r.status === 403, `status=${r.status}`);
t('e a ficha continua viva', (await pool.query('SELECT count(*)::int n FROM isc_fichas WHERE id=$1', [f.id])).rows[0].n === 1);

console.log('\n── COLABORADORA: a tela não promete o que o servidor nega ──');
let html = await (await get(s, `/isc/admin/ficha/${f.id}?inst=HUSF`)).text();
t('não renderiza o formulário de classificação', !html.includes(`/isc/admin/ficha/${f.id}/classificar`));
t('mas MOSTRA a classificação em leitura', html.includes('Classificação SCIH'));
t('e explica que está na fila do médico', html.includes('fila de classificação do médico'));
html = await (await get(s, '/isc/admin/grid?inst=HUSF')).text();
t('nav sem link de triagem', !html.includes('/isc/admin/triagem'));
html = await (await get(s, '/isc/admin/importar?inst=HUSF')).text();
t('importador sem botão desfazer', !html.includes('/desfazer'));
t('importador sem link de triagem', !html.includes('/isc/admin/triagem'));
s.close();

console.log('\n── MÉDICO: faz tudo ──');
s = subir(MEDICO);
r = await post(s, `/isc/admin/ficha/${f.id}/classificar?inst=HUSF`, {
  isc_classificacao: 'confirmada', isc_tipo: 'incisional_profunda',
  isc_patogeno: 'S. aureus', classificado_por: 'Dr. Leandro',
});
t('classifica', r.status === 302, `status=${r.status}`);
({ rows: [chk] } = await pool.query('SELECT * FROM isc_fichas WHERE id=$1', [f.id]));
t('classificação gravada', chk.isc_classificacao === 'confirmada');
t('autoria carimbada', chk.classificado_por === 'Dr. Leandro' && !!chk.classificado_em);
t('vê as regras de triagem', (await get(s, '/isc/admin/triagem?inst=HUSF')).status === 200);
r = await post(s, '/isc/admin/triagem?inst=HUSF', { nome: 'Regra do médico', ordem: '130', match_proc: 'teste', vigiar: '1', ativo: '1' });
t('cria regra', r.status === 302);
t('regra criada', (await pool.query(`SELECT count(*)::int n FROM isc_triagem_regras WHERE nome='Regra do médico'`)).rows[0].n === 1);
html = await (await get(s, `/isc/admin/ficha/${f.id}?inst=HUSF`)).text();
t('vê o formulário de classificação', html.includes(`/isc/admin/ficha/${f.id}/classificar`));
html = await (await get(s, '/isc/admin/grid?inst=HUSF')).text();
t('nav com link de triagem', html.includes('/isc/admin/triagem'));
s.close();

console.log('\n── Break-glass (cookie adm) continua valendo ──');
// Mesmo escape do ensureSuper do atb-scih-acesso-routes: sem ele, um problema
// de sessão tranca o próprio médico para fora.
s = subir(null, { adm: '1' });
r = await post(s, `/isc/admin/ficha/${f.id}/classificar?inst=HUSF`, { isc_classificacao: 'descartada' });
t('adm=1 sem usuário classifica', r.status === 302, `status=${r.status}`);
t('surtiu efeito', (await pool.query('SELECT isc_classificacao FROM isc_fichas WHERE id=$1', [f.id])).rows[0].isc_classificacao === 'descartada');
s.close();

console.log('\n── Ficha da colaboradora sobreviveu a tudo ──');
t('contato dela intacto', (await pool.query('SELECT count(*)::int n FROM isc_contatos WHERE ficha_id=$1', [f.id])).rows[0].n === 1);

await pool.end();
console.log(`\n${'═'.repeat(52)}\n${ok} passaram · ${fail} falharam\n`);
process.exit(fail ? 1 : 0);
