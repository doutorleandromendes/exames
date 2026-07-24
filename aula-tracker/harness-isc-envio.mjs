// harness-isc-envio.mjs — fluxo de envio da colaboradora.
//
// O sistema NÃO envia: ela dispara no WhatsApp e volta para dizer que enviou.
// O que se testa aqui é o LAÇO se fechar — sem ele a agenda mostra os mesmos
// pacientes o dia inteiro e o paciente recebe a mesma mensagem duas vezes.
import express from 'express';
import { Pool } from 'pg';
import { registerIscRoutes } from './isc-routes.js';
import { runIscMigrations } from './isc-db.js';
import { renderShell } from './ui-shell.js';
import { addDays, hojeISO, dataBR } from './isc-core.js';

const DB = process.env.ISC_TEST_DB || 'postgresql://postgres:x@localhost:5432/iscteste';
const pool = new Pool({ connectionString: DB });
let ok = 0, fail = 0;
const t = (n, c, x = '') => { if (c) { ok++; console.log('  ✓', n); } else { fail++; console.log('  ✗ FALHOU:', n, x); } };
const eq = (n, a, b) => t(`${n} → ${JSON.stringify(a)}`, JSON.stringify(a) === JSON.stringify(b), `esperado ${JSON.stringify(b)}`);

await runIscMigrations(pool);
await pool.query('TRUNCATE isc_envios, isc_contatos, isc_fichas RESTART IDENTITY CASCADE');
await pool.query(`INSERT INTO isc_config (instituicao_id, whatsapp_business)
                  SELECT id, '551124901268' FROM atb_instituicoes WHERE sigla='HUSF'
                  ON CONFLICT (instituicao_id) DO UPDATE SET whatsapp_business=EXCLUDED.whatsapp_business`);
const { rows: [inst] } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla='HUSF'`);
const { rows: [eqp] } = await pool.query(`SELECT id FROM isc_equipes WHERE instituicao_id=$1 AND nome='Obstetrícia'`, [inst.id]);

const D = addDays(hojeISO(), -10);
const mk = (nome, at, tel) => pool.query(
  `INSERT INTO isc_fichas (instituicao_id, paciente_nome, atendimento, data_cirurgia, equipe_id, procedimento,
     telefone, status_vigilancia, proximo_contato_em, proxima_janela, janelas, janelas_estado)
   VALUES ($1,$2,$3,$4,$5,'OPERAÇÃO CESARIANA',$6,'em_vigilancia',$7,7,'[7,30]','{}') RETURNING id`,
  [inst.id, nome, at, D, eqp.id, tel, addDays(D, 7)]).then(r => r.rows[0].id);
const f1 = await mk('MARIA SILVA', 'A1', '5511911111111');
const f2 = await mk('JOANA SOUZA', 'A2', '5511922222222');
const f3 = await mk('SEM FONE', 'A3', null);
// Este harness testa o fluxo de ENVIO clínico, que é o passo DEPOIS da
// identidade. Confirma o passo 0 no seed — a confirmação em si tem harness
// próprio (harness-isc-identidade).
await pool.query(`UPDATE isc_fichas SET identidade_status='confirmada', identidade_em=now(), identidade_por='seed'
                   WHERE id = ANY($1)`, [[f1, f2, f3]]);

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

console.log('\n── Estado inicial: 3 a enviar ──');
let h = await pega(AG);
t('contador "a enviar"', h.includes('>3 a enviar<'), 'contador errado');
t('contador "aguardando" zerado', h.includes('>0 aguardando resposta<'));
t('mensagem pronta com o nome', h.includes('Olá, Maria!'));
t('link wa.me do paciente', h.includes('https://wa.me/5511911111111'));
t('botão "Já enviei"', h.includes('Já enviei'));
t('banner do número institucional', h.includes('(11) 2490-1268'));
t('quem não tem telefone não ganha "Já enviei"',
  (h.match(/Já enviei/g) || []).length === 2, `achei ${(h.match(/Já enviei/g) || []).length}`);

console.log('\n── Abrir o WhatsApp NÃO marca como enviada ──');
// Abrir a conversa não é enviar. Marcar no clique registraria envio que não
// aconteceu — some da fila e ninguém contata o paciente.
await fetch(`https://wa.me/5511911111111`).catch(() => {});
eq('nada na fila ainda', (await pool.query('SELECT count(*)::int n FROM isc_envios')).rows[0].n, 0);

console.log('\n── "Já enviei" fecha o laço ──');
let r = await post('/isc/admin/envio/marcar', { inst: 'HUSF', ficha_id: f1, janela: '7' });
t('redireciona de volta p/ agenda', r.status === 302 && /\/isc\/admin\/agenda/.test(r.headers.get('location') || ''));
const { rows: [ev] } = await pool.query('SELECT * FROM isc_envios WHERE ficha_id=$1', [f1]);
eq('status manual', ev.status, 'manual');
t('carimba quando', !!ev.enviado_em);
eq('carimba quem', ev.enviado_por, 'Ana Colaboradora');
eq('janela certa', ev.janela, 7);
t('snapshot do texto enviado', /Olá, Maria!/.test(ev.corpo || ''), 'sem corpo');
eq('telefone do envio', ev.telefone, '5511911111111');

console.log('\n── A agenda passa a distinguir ──');
h = await pega(AG);
t('contador vira 2 a enviar', h.includes('>2 a enviar<'));
t('e 1 aguardando resposta', h.includes('>1 aguardando resposta<'));
t('card mostra "enviada ... aguardando resposta"', h.includes('aguardando resposta</span>'));
t('mostra a data do envio', h.includes(dataBR(hojeISO())));
t('e quem enviou', h.includes('por Ana Colaboradora'));
t('botão vira "Reabrir conversa"', h.includes('Reabrir conversa'));
t('e aparece "Desmarcar"', h.includes('Desmarcar'));

console.log('\n── Filtro "só as que faltam enviar" ──');
h = await pega(AG + '&pendentes=1');
t('esconde a já enviada', !h.includes('MARIA SILVA'));
t('mostra as pendentes', h.includes('JOANA SOUZA') && h.includes('SEM FONE'));
t('contadores continuam completos', h.includes('>2 a enviar<') && h.includes('>1 aguardando resposta<'));

console.log('\n── Desmarcar devolve para a fila ──');
r = await post('/isc/admin/envio/desmarcar', { inst: 'HUSF', ficha_id: f1, janela: '7' });
t('redireciona', r.status === 302);
const { rows: [ev2] } = await pool.query('SELECT * FROM isc_envios WHERE ficha_id=$1', [f1]);
eq('volta a pendente', ev2.status, 'pendente');
t('limpa o carimbo', !ev2.enviado_em && !ev2.enviado_por);
t('mas preserva o snapshot do texto', /Olá, Maria!/.test(ev2.corpo || ''));
h = await pega(AG);
t('volta a contar 3 a enviar', h.includes('>3 a enviar<'));

console.log('\n── Marcar duas vezes não duplica ──');
await post('/isc/admin/envio/marcar', { inst: 'HUSF', ficha_id: f1, janela: '7' });
await post('/isc/admin/envio/marcar', { inst: 'HUSF', ficha_id: f1, janela: '7' });
eq('1 linha só na fila', (await pool.query('SELECT count(*)::int n FROM isc_envios WHERE ficha_id=$1', [f1])).rows[0].n, 1);

console.log('\n── Registrar a resposta tira da agenda ──');
r = await post(`/isc/admin/ficha/${f1}/contato?inst=HUSF`, { janela: '7', prontuario: 'P-TESTE', r_febre: 'Não', responsavel: 'Ana' });
t('registra', r.status === 302);
h = await pega(AG);
t('MARIA sai da agenda (janela 7 fechada)', !h.includes('MARIA SILVA'));
t('sobram as 2 sem contato', h.includes('>2 a enviar<'));

console.log('\n── Nova janela = novo envio (o antigo não some) ──');
const { rows: envs } = await pool.query('SELECT janela, status FROM isc_envios WHERE ficha_id=$1 ORDER BY janela', [f1]);
eq('envio da janela 7 preservado', envs.map(e => [e.janela, e.status]), [[7, 'manual']]);
await post('/isc/admin/envio/marcar', { inst: 'HUSF', ficha_id: f1, janela: '30' });
eq('janela 30 vira linha nova', (await pool.query('SELECT count(*)::int n FROM isc_envios WHERE ficha_id=$1', [f1])).rows[0].n, 2);

console.log('\n── Guardas ──');
r = await post('/isc/admin/envio/marcar', { inst: 'HUSF', ficha_id: '999999', janela: '7' });
t('ficha inexistente → 404', r.status === 404, `status=${r.status}`);
r = await post('/isc/admin/envio/marcar', { inst: 'HUSF', ficha_id: f2, janela: '' });
t('sem janela → 400', r.status === 400, `status=${r.status}`);

const { rows: [scmi] } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla='SCMI'`);
const { rows: [fs] } = await pool.query(
  `INSERT INTO isc_fichas (instituicao_id, paciente_nome, atendimento, data_cirurgia, status_vigilancia, proximo_contato_em, proxima_janela)
   VALUES ($1,'PACIENTE SCMI','S1',$2,'em_vigilancia',$3,7) RETURNING id`, [scmi.id, D, addDays(D, 7)]);
r = await post('/isc/admin/envio/marcar', { inst: 'HUSF', ficha_id: fs.id, janela: '7' });
t('marcar envio de ficha de outro tenant → 404', r.status === 404, `status=${r.status}`);
eq('e nada foi gravado', (await pool.query('SELECT count(*)::int n FROM isc_envios WHERE ficha_id=$1', [fs.id])).rows[0].n, 0);

console.log('\n── Ficha SEM telefone não sai da fila ──');
await post('/isc/admin/envio/marcar', { inst: 'HUSF', ficha_id: f2, janela: '7' });
h = await pega(AG + '&pendentes=1');
// Sem número não há o que enviar: continua pendente até alguém achar o telefone.
// Sumir daqui seria perder o paciente da vigilância em silêncio.
t('SEM FONE continua pendente', h.includes('SEM FONE'));
t('e a agenda diz que falta telefone', h.includes('sem telefone'));
eq('só ela na fila de envio', (await pega(AG)).match(/>1 a enviar</) ? 1 : 0, 1);

// Com telefone e tudo marcado, aí sim a fila esvazia.
await pool.query('UPDATE isc_fichas SET telefone=$2 WHERE id=$1', [f3, '5511933333333']);
await post('/isc/admin/envio/marcar', { inst: 'HUSF', ficha_id: f3, janela: '7' });
h = await pega(AG + '&pendentes=1');
t('agora sim: "Tudo enviado — aguardando as respostas"', h.includes('Tudo enviado — aguardando as respostas'));

srv.close(); await pool.end();
console.log(`\n${'═'.repeat(52)}\n${ok} passaram · ${fail} falharam\n`);
process.exit(fail ? 1 : 0);
