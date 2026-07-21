// harness-isc-identidade.mjs — passo 0: confirmação de identidade.
//
// Regra clínica: NENHUMA mensagem sobre a cirurgia sai antes de confirmar que o
// número é do paciente. A primeira mensagem clínica já revela que a pessoa foi
// operada; para um número errado (e vários têm DDD presumido) isso é vazamento.
// Este harness prova que o portão segura a mensagem clínica e libera após o OK.
import express from 'express';
import { Pool } from 'pg';
import { registerIscRoutes } from './isc-routes.js';
import { runIscMigrations } from './isc-db.js';
import { renderShell } from './ui-shell.js';
import { addDays, hojeISO, renderTemplate, JANELA_IDENTIDADE } from './isc-core.js';

const DB = process.env.ISC_TEST_DB || 'postgresql://postgres:x@localhost:5432/iscteste';
const pool = new Pool({ connectionString: DB });
let ok = 0, fail = 0;
const t = (n, c, x = '') => { if (c) { ok++; console.log('  ✓', n); } else { fail++; console.log('  ✗ FALHOU:', n, x); } };
const eq = (n, a, b) => t(`${n} → ${JSON.stringify(a)}`, JSON.stringify(a) === JSON.stringify(b), `esperado ${JSON.stringify(b)}`);

console.log('\n── Núcleo ──');
eq('JANELA_IDENTIDADE é -1', JANELA_IDENTIDADE, -1);
// A mensagem do passo 0 usa primeiro_nome, nunca o nome completo: senão qualquer
// um confirmaria "sim" ao ouvir o nome inteiro.
t('primeiro_nome derivado do nome completo',
  renderTemplate('É de {{primeiro_nome}}?', { paciente_nome: 'Maria Silva Souza' }) === 'É de Maria?');

await runIscMigrations(pool);
await pool.query('TRUNCATE isc_envios, isc_contatos, isc_fichas RESTART IDENTITY CASCADE');
const { rows: [inst] } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla='HUSF'`);
const { rows: [eqp] } = await pool.query(`SELECT id FROM isc_equipes WHERE instituicao_id=$1 AND nome='Obstetrícia'`, [inst.id]);

console.log('\n── Template do passo 0 foi semeado ──');
const { rows: [tpl0] } = await pool.query(`SELECT * FROM isc_msg_templates WHERE instituicao_id=$1 AND janela=-1`, [inst.id]);
t('existe template janela -1', !!tpl0);
t('menciona o HUSF', /São Francisco|HUSF/.test(tpl0.corpo));
t('pede confirmação de identidade', /confirmar/i.test(tpl0.corpo));
t('usa {{primeiro_nome}}, não nome completo', tpl0.corpo.includes('{{primeiro_nome}}'));

const D = addDays(hojeISO(), -8);
const { rows: [f] } = await pool.query(
  `INSERT INTO isc_fichas (instituicao_id, paciente_nome, atendimento, data_cirurgia, equipe_id, procedimento,
     telefone, telefone_presumido, status_vigilancia, proximo_contato_em, proxima_janela, janelas, janelas_estado)
   VALUES ($1,'MARIA SILVA SOUZA','A1',$2,$3,'OPERAÇÃO CESARIANA','5511911111111',true,'em_vigilancia',$4,7,'[7,30]','{}')
   RETURNING id, identidade_status`, [inst.id, D, eqp.id, addDays(D, 7)]);
eq('ficha nasce com identidade pendente', f.identidade_status, 'pendente');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use((q, s, n) => { q.user = { full_name: 'Ana Colaboradora', scih: true }; n(); });
registerIscRoutes(app, pool, (q, s, n) => n(), renderShell);
const srv = app.listen(0);
const B = `http://127.0.0.1:${srv.address().port}`;
const pega = u => fetch(B + u).then(r => r.text());
const post = (u, b) => fetch(B + u, {
  method: 'POST', redirect: 'manual',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(b),
});
const AG = '/isc/admin/agenda?inst=HUSF&dias=0';

console.log('\n── Identidade pendente: a agenda fala em CONFIRMAR, não em busca ativa ──');
let h = await pega(AG);
t('badge "confirmar identidade primeiro"', h.includes('confirmar identidade primeiro'));
t('botão do WhatsApp é o do passo 0', h.includes('confirmar identidade'));
t('mensagem do wa.me é a de identidade (tem "confirmar essa informação")',
  h.includes('confirmar%20essa%20informa') || /Este%20%C3%A9%20um%20n%C3%BAmero/.test(h));
t('a mensagem do wa NÃO é a clínica de 7 dias', !h.includes('Faz%207%20dias') && !/como%20est%C3%A1%20a%20sua%20recupera/i.test(h));
t('tem botão "Confirmou identidade"', h.includes('Confirmou identidade'));
t('tem botão "Não é o paciente"', h.includes('Não é o paciente'));
t('NÃO oferece "Já enviei" da clínica ainda', !h.includes('>Já enviei<'));

console.log('\n── Portão: não dá para marcar a mensagem CLÍNICA como enviada ──');
let r = await post('/isc/admin/envio/marcar', { inst: 'HUSF', ficha_id: f.id, janela: '7' });
t('marcar janela 7 com identidade pendente → 409', r.status === 409, `status=${r.status}`);
eq('nada entrou na fila', (await pool.query('SELECT count(*)::int n FROM isc_envios')).rows[0].n, 0);

console.log('\n── Confirmar identidade ──');
r = await post(`/isc/admin/ficha/${f.id}/identidade`, { inst: 'HUSF', status: 'confirmada' });
t('redireciona', r.status === 302);
let { rows: [f2] } = await pool.query('SELECT * FROM isc_fichas WHERE id=$1', [f.id]);
eq('status confirmada', f2.identidade_status, 'confirmada');
t('carimba quem', f2.identidade_por === 'Ana Colaboradora');
t('carimba quando', !!f2.identidade_em);

console.log('\n── Agora a busca ativa é liberada ──');
h = await pega(AG);
t('badge vira "identidade confirmada"', h.includes('identidade confirmada'));
t('some o "confirmar primeiro"', !h.includes('confirmar identidade primeiro'));
t('botão do WhatsApp volta a ser o normal', h.includes('>Abrir WhatsApp<'));
t('agora a mensagem do wa é a CLÍNICA (7 dias)', /Faz%207%20dias|dias%20da%20sua%20cirurgia/i.test(h));
t('reaparece "Já enviei"', h.includes('Já enviei'));
r = await post('/isc/admin/envio/marcar', { inst: 'HUSF', ficha_id: f.id, janela: '7' });
t('marcar clínica agora funciona', r.status === 302);
eq('entrou na fila', (await pool.query('SELECT count(*)::int n FROM isc_envios')).rows[0].n, 1);

console.log('\n── Identidade vale por PACIENTE: janela 30 não pede de novo ──');
// Fecha a janela 7 e avança para a 30.
await post(`/isc/admin/ficha/${f.id}/contato?inst=HUSF`, { janela: '7', r_febre: 'Não', responsavel: 'Ana' });
r = await post('/isc/admin/envio/marcar', { inst: 'HUSF', ficha_id: f.id, janela: '30' });
t('janela 30 não é barrada (identidade já confirmada)', r.status === 302, `status=${r.status}`);

console.log('\n── "Não é o paciente": registra, decisão fica com a colaboradora ──');
const { rows: [g] } = await pool.query(
  `INSERT INTO isc_fichas (instituicao_id, paciente_nome, atendimento, data_cirurgia, equipe_id, procedimento,
     telefone, status_vigilancia, proximo_contato_em, proxima_janela, janelas, janelas_estado)
   VALUES ($1,'JOAO OUTRO','A2',$2,$3,'CRANIOTOMIA','5511922222222','em_vigilancia',$4,7,'[7,30]','{}') RETURNING id`,
  [inst.id, D, eqp.id, addDays(D, 7)]);
r = await post(`/isc/admin/ficha/${g.id}/identidade`, { inst: 'HUSF', status: 'negada' });
t('redireciona', r.status === 302);
const { rows: [g2] } = await pool.query('SELECT * FROM isc_fichas WHERE id=$1', [g.id]);
eq('status negada', g2.identidade_status, 'negada');
eq('vigilância NÃO foi encerrada automaticamente', g2.status_vigilancia, 'em_vigilancia');
h = await pega(AG);
t('agenda mostra "identidade negada"', h.includes('identidade negada'));
r = await post('/isc/admin/envio/marcar', { inst: 'HUSF', ficha_id: g.id, janela: '7' });
t('e a clínica continua barrada (negada ≠ confirmada)', r.status === 409, `status=${r.status}`);

console.log('\n── Corrigir engano: pode voltar a pendente ──');
r = await post(`/isc/admin/ficha/${g.id}/identidade`, { inst: 'HUSF', status: 'pendente' });
t('volta a pendente', r.status === 302);
const { rows: [g3] } = await pool.query('SELECT identidade_status, identidade_em FROM isc_fichas WHERE id=$1', [g.id]);
eq('status pendente', g3.identidade_status, 'pendente');
t('limpa o carimbo', !g3.identidade_em);

console.log('\n── Guardas ──');
r = await post(`/isc/admin/ficha/999999/identidade`, { inst: 'HUSF', status: 'confirmada' });
t('ficha inexistente → 404', r.status === 404);
r = await post(`/isc/admin/ficha/${f.id}/identidade`, { inst: 'HUSF', status: 'invalido' });
t('status inválido → 400', r.status === 400);
const { rows: [scmi] } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla='SCMI'`);
const { rows: [fscmi] } = await pool.query(
  `INSERT INTO isc_fichas (instituicao_id, paciente_nome, atendimento, data_cirurgia)
   VALUES ($1,'SCMI',' S9',$2) RETURNING id`, [scmi.id, D]);
r = await post(`/isc/admin/ficha/${fscmi.id}/identidade`, { inst: 'HUSF', status: 'confirmada' });
t('cross-tenant → 404', r.status === 404);
eq('e não confirmou a ficha do SCMI', (await pool.query('SELECT identidade_status FROM isc_fichas WHERE id=$1', [fscmi.id])).rows[0].identidade_status, 'pendente');

srv.close(); await pool.end();
console.log(`\n${'═'.repeat(52)}\n${ok} passaram · ${fail} falharam\n`);
process.exit(fail ? 1 : 0);
