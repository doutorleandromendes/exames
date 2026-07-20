// harness-isc-mapa-perfil.mjs — mapeamento de importação travado para não-admin.
//
// A colaboradora importa, mas NÃO edita o mapeamento — usa o perfil que o admin
// configurou. O teste que importa é o ATAQUE: um POST forjado com mapa_json não
// pode furar o bloqueio. Esconder na tela é só metade; a guarda é no servidor.
import express from 'express';
import cookieParser from 'cookie-parser';
import { Pool } from 'pg';
import { registerIscImportRoutes } from './isc-import-routes.js';
import { runIscMigrations } from './isc-db.js';
import { renderShell } from './ui-shell.js';
import { hojeISO, addDays } from './isc-core.js';

const DB = process.env.ISC_TEST_DB || 'postgresql://postgres:x@localhost:5432/iscteste';
const pool = new Pool({ connectionString: DB });
let ok = 0, fail = 0;
const t = (n, c, x = '') => { if (c) { ok++; console.log('  ✓', n); } else { fail++; console.log('  ✗ FALHOU:', n, x); } };
const eq = (n, a, b) => t(`${n} → ${JSON.stringify(a)}`, JSON.stringify(a) === JSON.stringify(b), `esperado ${JSON.stringify(b)}`);

await runIscMigrations(pool);
await pool.query('TRUNCATE isc_envios, isc_contatos, isc_fichas, isc_import_lotes, isc_import_perfis RESTART IDENTITY CASCADE');
const { rows: [inst] } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla='HUSF'`);

// O admin configura UM perfil. col0=nome, col1=atendimento, col2=data.
const { rows: [pf] } = await pool.query(
  `INSERT INTO isc_import_perfis (instituicao_id, nome, mapeamento, delim)
   VALUES ($1,'Tasy HUSF',$2,';') RETURNING id`,
  [inst.id, JSON.stringify({ 0: 'paciente_nome', 1: 'atendimento', 2: 'data_cirurgia', 3: 'procedimento' })]);

const D = addDays(hojeISO(), -5), Dbr = D.split('-').reverse().join('/');
// Procedimento DENTRO do recorte (cesariana), senão a triagem barra e o teste
// mede a coisa errada.
const CSV = `Paciente;Atendimento;Data;Procedimento\nMARIA SILVA;A1;${Dbr};OPERAÇÃO CESARIANA`;

function subir(usuario) {
  const app = express();
  app.use(cookieParser());
  app.use(express.urlencoded({ extended: true }));
  app.use((req, res, next) => { req.user = usuario; next(); });
  registerIscImportRoutes(app, pool, (q, s, n) => n(), renderShell);
  return app.listen(0);
}
const post = (s, u, b) => fetch(`http://127.0.0.1:${s.address().port}${u}`, {
  method: 'POST', redirect: 'manual',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(b),
});
const get = (s, u) => fetch(`http://127.0.0.1:${s.address().port}${u}`).then(r => r.text());

const COLAB = { full_name: 'Ana', scih: true, super_admin: false };
const ADMIN = { full_name: 'Dr. Leandro', scih: true, super_admin: true };

console.log('\n── Colaboradora: a tela de importar ──');
let s = subir(COLAB);
let h = await get(s, '/isc/admin/importar?inst=HUSF');
t('vê o seletor de perfil', h.includes('name="perfil_id"'));
t('perfil é obrigatório', /name="perfil_id"[^>]*required/.test(h));
t('perfil único já vem selecionado', /value="1"[^>]*selected/.test(h));
t('não vê "Adivinhar pelas colunas"', !h.includes('Adivinhar pelas colunas'));
t('vê o aviso de que o admin configurou', h.includes('administrador configurou'));
s.close();

console.log('\n── Colaboradora: a prévia é read-only no mapeamento ──');
s = subir(COLAB);
h = await (await post(s, '/isc/admin/importar/previa', { inst: 'HUSF', texto: CSV, perfil_id: String(pf.id) })).text();
t('mapeamento aplicado (mostra os campos)', h.includes('Nome do paciente') && h.includes('Atendimento'));
t('NÃO tem <select class="mp"> editável', !h.includes('class="mp"'));
t('NÃO tem botão Recalcular', !h.includes('Recalcular'));
t('NÃO tem Salvar perfil', !h.includes('Salvar perfil'));
t('NÃO tem seletor de layout', !h.includes('name="modo"') || !h.includes('Layout: detectar'));
t('diz que foi o admin quem definiu', h.includes('Definido pelo administrador'));
t('menciona o perfil usado', h.includes('Tasy HUSF'));
t('tem o botão de criar fichas', h.includes('Criar 1 ficha'));
t('tem Cancelar', h.includes('Cancelar'));
t('form de gravar manda perfil_id, não mapa_json', h.includes('name="perfil_id"') && !h.includes('name="mapa_json"'));
s.close();

console.log('\n── ⚠ ATAQUE: colaboradora forja mapa_json na prévia ──');
s = subir(COLAB);
// Tenta mapear a coluna 0 (nome) como se fosse procedimento — bagunçar tudo.
h = await (await post(s, '/isc/admin/importar/previa', {
  inst: 'HUSF', texto: CSV, perfil_id: String(pf.id),
  mapa_json: JSON.stringify({ 0: 'procedimento', 1: 'procedimento', 2: 'observacao', 3: 'observacao' }),
})).text();
t('mapa_json forjado é IGNORADO — nome continua mapeado certo', h.includes('MARIA SILVA'));
t('e a prévia não tem erro (o perfil válido prevaleceu)', !h.includes('é obrigatório'));
s.close();

console.log('\n── ⚠ ATAQUE: colaboradora forja mapa_json no GRAVAR ──');
s = subir(COLAB);
let r = await post(s, '/isc/admin/importar/gravar', {
  inst: 'HUSF', texto: CSV, perfil_id: String(pf.id),
  mapa_json: JSON.stringify({ 0: 'procedimento' }),   // tenta gravar nome como procedimento
});
t('grava mesmo assim (não quebra o fluxo dela)', r.status === 302);
const { rows: [f] } = await pool.query('SELECT * FROM isc_fichas ORDER BY id DESC LIMIT 1');
eq('o NOME foi para paciente_nome (perfil venceu)', f.paciente_nome, 'MARIA SILVA');
t('e NÃO virou procedimento', f.procedimento !== 'MARIA SILVA', `procedimento=${f.procedimento}`);
eq('atendimento certo', f.atendimento, 'A1');
s.close();
await pool.query('TRUNCATE isc_fichas RESTART IDENTITY CASCADE');

console.log('\n── ⚠ ATAQUE: colaboradora tenta salvar um perfil novo ──');
s = subir(COLAB);
await post(s, '/isc/admin/importar/previa', {
  inst: 'HUSF', texto: CSV, perfil_id: String(pf.id),
  salvar_perfil: '1', perfil_nome: 'Perfil da Ana',
});
eq('nenhum perfil novo criado', (await pool.query(`SELECT count(*)::int n FROM isc_import_perfis WHERE nome='Perfil da Ana'`)).rows[0].n, 0);
s.close();

console.log('\n── Admin: continua com o editor completo ──');
s = subir(ADMIN);
h = await (await post(s, '/isc/admin/importar/previa', { inst: 'HUSF', texto: CSV, perfil_id: String(pf.id) })).text();
t('tem os selects de mapeamento', h.includes('class="mp"'));
t('tem Recalcular', h.includes('Recalcular'));
t('tem Salvar perfil', h.includes('Salvar perfil'));
t('tem seletor de layout', h.includes('Layout: detectar'));
t('form de gravar usa mapa_json', h.includes('name="mapa_json"'));

// Admin PODE remapear pela tela.
h = await (await post(s, '/isc/admin/importar/previa', {
  inst: 'HUSF', texto: CSV,
  mapa_json: JSON.stringify({ 0: 'paciente_nome', 1: 'prontuario', 2: 'data_cirurgia', 3: 'procedimento' }),
})).text();
t('admin remapeia col1 para prontuário', h.includes('Prontuário'));

// Admin salva perfil.
await post(s, '/isc/admin/importar/previa', {
  inst: 'HUSF', texto: CSV, salvar_perfil: '1', perfil_nome: 'Perfil do Admin',
  mapa_json: JSON.stringify({ 0: 'paciente_nome', 1: 'atendimento', 2: 'data_cirurgia', 3: 'procedimento' }),
});
eq('admin cria perfil normalmente', (await pool.query(`SELECT count(*)::int n FROM isc_import_perfis WHERE nome='Perfil do Admin'`)).rows[0].n, 1);
s.close();

console.log('\n── Break-glass (cookie adm) conta como admin ──');
const app = express();
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => { req.user = null; req.cookies = { adm: '1' }; next(); });
registerIscImportRoutes(app, pool, (q, s2, n) => n(), renderShell);
const srv = app.listen(0);
h = await (await fetch(`http://127.0.0.1:${srv.address().port}/isc/admin/importar/previa`, {
  method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ inst: 'HUSF', texto: CSV, perfil_id: String(pf.id) }),
})).text();
t('adm=1 vê o editor', h.includes('class="mp"'));
srv.close();

await pool.end();
console.log(`\n${'═'.repeat(52)}\n${ok} passaram · ${fail} falharam\n`);
process.exit(fail ? 1 : 0);
