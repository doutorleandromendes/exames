// harness-isc-data.mjs — exibição DD-MM-AAAA sem quebrar os formulários.
//
// O risco real deste tweak não é cosmético: <input type="date"> exige ISO por
// spec. Se o value vier "13-07-2026", o navegador esvazia o campo EM SILÊNCIO —
// a colaboradora abre a edição, a data sumiu, ela salva e apaga o dado.
// Por isso metade deste harness testa os inputs, não a exibição.
import express from 'express';
import { Pool } from 'pg';
import { registerIscRoutes } from './isc-routes.js';
import { registerIscImportRoutes } from './isc-import-routes.js';
import { runIscMigrations } from './isc-db.js';
import { renderShell } from './ui-shell.js';
import { dataBR, toISODate, renderTemplate, addDays, hojeISO } from './isc-core.js';

const DB = process.env.ISC_TEST_DB || 'postgresql://postgres:x@localhost:5432/iscteste';
const pool = new Pool({ connectionString: DB });
let ok = 0, fail = 0;
const t = (n, c, x = '') => { if (c) { ok++; console.log('  ✓', n); } else { fail++; console.log('  ✗ FALHOU:', n, x); } };
const eq = (n, a, b) => t(`${n} → ${JSON.stringify(a)}`, JSON.stringify(a) === JSON.stringify(b), `esperado ${JSON.stringify(b)}`);

console.log('\n── dataBR ──');
eq('ISO → BR', dataBR('2026-07-13'), '13-07-2026');
eq('Date → BR', dataBR(new Date('2026-07-13T12:00:00Z')), '13-07-2026');
eq('timestamptz → BR', dataBR('2026-07-13T02:00:00.000Z'), '13-07-2026');
eq('zero à esquerda preservado', dataBR('2026-01-05'), '05-01-2026');
eq('null → vazio (não "NaN")', dataBR(null), '');
eq('undefined → vazio', dataBR(undefined), '');
eq('lixo → vazio', dataBR('abacaxi'), '');
eq('vazio → vazio', dataBR(''), '');

console.log('\n── toISODate segue intacto (é o que vai pro banco e pro input) ──');
eq('não mexeram nele', toISODate('2026-07-13T02:00:00Z'), '2026-07-13');

console.log('\n── Mensagem do paciente continua em prosa (dd/mm/aaaa) ──');
// Tela usa hífen; texto corrido para o paciente usa barra — é o que se lê natural.
t('template com barra', renderTemplate('cirurgia em {{data_cirurgia}}', { data_cirurgia: '2026-07-13' }) === 'cirurgia em 13/07/2026');

await runIscMigrations(pool);
await pool.query('TRUNCATE isc_envios, isc_contatos, isc_fichas, isc_import_lotes RESTART IDENTITY CASCADE');
const { rows: [i] } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla='HUSF'`);
const { rows: [eqp] } = await pool.query(`SELECT id FROM isc_equipes WHERE instituicao_id=$1 AND nome='Neurocirurgia'`, [i.id]);
const CIR = addDays(hojeISO(), -10), ALTA = addDays(hojeISO(), -7), DX = addDays(hojeISO(), -2);
const { rows: [f] } = await pool.query(
  `INSERT INTO isc_fichas (instituicao_id, paciente_nome, atendimento, data_cirurgia, data_alta, equipe_id,
     procedimento, telefone, status_vigilancia, proximo_contato_em, proxima_janela, janelas, janelas_estado,
     isc_classificacao, isc_tipo, isc_data_diagnostico, classificado_por, classificado_em)
   VALUES ($1,'MARIA TESTE','A1',$2,$3,$4,'CRANIOTOMIA','5511999999999','em_vigilancia',$5,7,'[7,30]',$6,
           'confirmada','incisional_profunda',$7,'Dr. Leandro',now()) RETURNING id`,
  [i.id, CIR, ALTA, eqp.id, addDays(CIR, 7), JSON.stringify({ 7: { status: 'concluida', data_prevista: addDays(CIR, 7), data_contato: addDays(CIR, 8) }, 30: { status: 'pendente', data_prevista: addDays(CIR, 30) } }), DX]);
await pool.query(
  `INSERT INTO isc_contatos (ficha_id, janela, data_contato, canal, sucesso, respostas)
   VALUES ($1, 7, $2, 'whatsapp', true, '{"febre":"Não"}')`, [f.id, addDays(CIR, 8)]);

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use((q, s, n) => { q.user = { super_admin: true }; n(); });
registerIscRoutes(app, pool, (q, s, n) => n(), renderShell);
registerIscImportRoutes(app, pool, (q, s, n) => n(), renderShell);
const srv = app.listen(0);
const B = `http://127.0.0.1:${srv.address().port}`;
const pega = u => fetch(B + u).then(r => r.text());

const brCir = dataBR(CIR), brAlta = dataBR(ALTA), brDx = dataBR(DX);

console.log('\n── Grid mostra DD-MM-AAAA ──');
let h = await pega('/isc/admin/grid?inst=HUSF');
t(`data da cirurgia (${brCir})`, h.includes(brCir), 'não achei');
t(`data do diagnóstico (${brDx})`, h.includes(brDx));
t('próximo contato em BR', h.includes(dataBR(addDays(CIR, 7))));
t('tooltip da janela em BR', h.includes('previsto ' + dataBR(addDays(CIR, 7))));
t('NÃO sobrou ISO na tela', !h.includes(CIR), `vazou ${CIR}`);

console.log('\n── Agenda e ficha ──');
h = await pega('/isc/admin/agenda?inst=HUSF&dias=30');
t('cirurgia em BR', h.includes(brCir));
t('sem ISO', !h.includes(CIR));

h = await pega(`/isc/admin/ficha/${f.id}?inst=HUSF`);
t('cabeçalho em BR', h.includes(brCir));
t('data de alta em BR', h.includes(brAlta));
t('timeline do contato em BR', h.includes(dataBR(addDays(CIR, 8))));
t('badge da janela em BR', h.includes(dataBR(addDays(CIR, 30))));

console.log('\n── ⚠ O QUE NÃO PODE QUEBRAR: <input type="date"> ──');
// Se o value não for ISO, o navegador esvazia o campo sem avisar.
t('data da cirurgia no form = ISO',
  new RegExp(`name="data_cirurgia"\\s+value="${CIR}"`).test(h), 'value não é ISO!');
t('data da alta no form = ISO',
  new RegExp(`name="data_alta"\\s+value="${ALTA}"`).test(h));
t('data do diagnóstico no form = ISO',
  new RegExp(`name="isc_data_diagnostico"\\s+value="${DX}"`).test(h));
t('data do contato (hoje) = ISO',
  new RegExp(`name="data_contato"\\s+value="${hojeISO()}"`).test(h));
t('nenhum input date recebeu BR', !/type="date"[^>]*value="\d{2}-\d{2}-\d{4}"/.test(h), 'algum input está em BR!');

h = await pega('/isc/admin/nova?inst=HUSF');
t('nova ficha: data da cirurgia = ISO (hoje)', h.includes(`name="data_cirurgia" required value="${hojeISO()}"`));
t('nova ficha: nenhum input em BR', !/type="date"[^>]*value="\d{2}-\d{2}-\d{4}"/.test(h));

console.log('\n── Round-trip: editar não perde a data ──');
// O teste que prova que o form não esvaziou: salvar sem tocar na data.
let r = await fetch(`${B}/isc/admin/ficha/${f.id}/editar?inst=HUSF`, {
  method: 'POST', redirect: 'manual',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ paciente_nome: 'MARIA TESTE', data_cirurgia: CIR, data_alta: ALTA, status_vigilancia: 'em_vigilancia' }),
});
t('salva', r.status === 302);
const { rows: [dep] } = await pool.query('SELECT data_cirurgia, data_alta FROM isc_fichas WHERE id=$1', [f.id]);
eq('data da cirurgia intacta no banco', toISODate(dep.data_cirurgia), CIR);
eq('data da alta intacta no banco', toISODate(dep.data_alta), ALTA);

console.log('\n── Filtro por mês continua AAAA-MM (input type=month) ──');
h = await pega(`/isc/admin/grid?inst=HUSF&mes=${CIR.slice(0, 7)}`);
t('filtro de mês funciona', h.includes('MARIA TESTE'));
t('e o input month guarda AAAA-MM', h.includes(`name="mes" value="${CIR.slice(0, 7)}"`));

console.log('\n── CSV segue ISO (análise, não tela) ──');
const csv = await pega('/isc/admin/export.csv?inst=HUSF');
t('CSV em ISO — ordena certo e não é ambíguo', csv.includes(CIR));
t('CSV não vira BR', !csv.includes(brCir));

console.log('\n── Prévia do importador em BR ──');
r = await fetch(`${B}/isc/admin/importar/previa?inst=HUSF`, {
  method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    inst: 'HUSF', sem_triagem: '1',
    texto: `Paciente;Atendimento;Data da Cirurgia\nJOAO;Z9;${dataBR(CIR).replace(/-/g, '/')}`,
  }),
});
h = await r.text();
t('prévia mostra a data em BR', h.includes(brCir), 'não achei');
// A chave de dedup (diagnóstico, em <code>) carrega a data ISO de propósito:
// é a chave literal usada na comparação. O que não pode é a CÉLULA de data
// da tabela sair em ISO.
const semChaves = h.replace(/<code>[^<]*<\/code>/g, '');
t('a célula de data não sai em ISO', !semChaves.includes(CIR));

srv.close(); await pool.end();
console.log(`\n${'═'.repeat(52)}\n${ok} passaram · ${fail} falharam\n`);
process.exit(fail ? 1 : 0);
