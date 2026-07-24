// harness-isc-rotina.mjs — três ajustes de rotina operacional.
//
//  1. Banner de importação atrasada (segunda e quinta, meio-dia)
//  2. Correção da confirmação de identidade (inclusive desfazer "não é")
//  3. Prontuário obrigatório no primeiro contato — e daí para a ficha do ATB
import express from 'express';
import { Pool } from 'pg';
import { registerIscRoutes } from './isc-routes.js';
import { registerIscImportRoutes } from './isc-import-routes.js';
import { runIscMigrations } from './isc-db.js';
import { renderShell } from './ui-shell.js';
import {
  statusImportacao, diaEsperadoImportacao, dataLocalISO, addDays, hojeISO, dataBR,
} from './isc-core.js';

const DB = process.env.ISC_TEST_DB || 'postgresql://postgres:x@localhost:5432/iscteste';
const pool = new Pool({ connectionString: DB });
let ok = 0, fail = 0;
const t = (n, c, x = '') => { if (c) { ok++; console.log('  ✓', n); } else { fail++; console.log('  ✗ FALHOU:', n, x); } };
const eq = (n, a, b) => t(`${n} → ${JSON.stringify(a)}`, JSON.stringify(a) === JSON.stringify(b), `esperado ${JSON.stringify(b)}`);

// Datas construídas em hora LOCAL (new Date(ano, mês, dia, hora)) — assim o
// teste vale em qualquer TZ, que é o ponto: a regra é "meio-dia local".
// 2026: 20/07 = segunda · 23/07 = quinta · 16/07 = quinta anterior.
const L = (dia, hora = 0, mes = 6) => new Date(2026, mes, dia, hora, 0, 0);

console.log('\n── 1. Rotina de importação: segunda e quinta, até meio-dia ──');
// dataLocalISO NÃO pode usar toISOString: às 23h BRT o UTC já virou o dia.
eq('data local às 23h30 continua sendo o mesmo dia', dataLocalISO(L(20, 23)), '2026-07-20');
// A razão de dataLocalISO existir: às 23h de qualquer TZ a oeste de Greenwich,
// toISOString() já virou o dia — e hojeISO() do projeto usa exatamente isso.
const meiaNoiteMenosUm = L(20, 23);
t('toISOString() pode adiantar o dia (por isso não é usado aqui)',
  meiaNoiteMenosUm.getTimezoneOffset() <= 0 || meiaNoiteMenosUm.toISOString().slice(0, 10) === '2026-07-21');

eq('segunda 11h → o vencido ainda é a quinta anterior', diaEsperadoImportacao(L(20, 11)), '2026-07-16');
eq('segunda 12h01 → vence a própria segunda', diaEsperadoImportacao(L(20, 12)), '2026-07-20');
eq('quinta 14h → vence a própria quinta', diaEsperadoImportacao(L(23, 14)), '2026-07-23');
eq('sábado → o último vencido é a quinta', diaEsperadoImportacao(L(25, 10)), '2026-07-23');

t('segunda 12h01 sem importar → ATRASADA', statusImportacao(null, L(20, 12)).atrasada === true);
t('segunda 12h01 tendo importado de manhã → em dia',
  statusImportacao(L(20, 9), L(20, 12)).atrasada === false);
t('segunda 11h (antes do prazo) não cobra a segunda',
  diaEsperadoImportacao(L(20, 11)) !== '2026-07-20');
// O ponto que importa: a segunda esquecida não some do radar na terça.
const terca = statusImportacao(L(16, 9), L(21, 10));
t('TERÇA com a segunda esquecida → continua atrasada', terca.atrasada === true);
eq('e diz de qual dia está devendo', terca.esperado, '2026-07-20');
eq('com o atraso em dias', terca.diasAtraso, 1);
t('importou na terça (atrasado) → volta a ficar em dia',
  statusImportacao(L(21, 14), L(21, 15)).atrasada === false);
t('domingo não cobra nada de novo',
  statusImportacao(L(23, 9), L(26, 10)).atrasada === false);

// ── Banco ────────────────────────────────────────────────────────────────
await runIscMigrations(pool);
await pool.query('TRUNCATE isc_envios, isc_contatos, isc_fichas, isc_import_lotes RESTART IDENTITY CASCADE');
const { rows: [inst] } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla='HUSF'`);
const { rows: [eqp] } = await pool.query(
  `SELECT id FROM isc_equipes WHERE instituicao_id=$1 AND nome='Obstetrícia'`, [inst.id]);

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use((q, s, n) => { q.user = { id: 1, full_name: 'Ana Colaboradora', scih: true, super_admin: true }; n(); });
registerIscRoutes(app, pool, (q, s, n) => n(), renderShell);
registerIscImportRoutes(app, pool, (q, s, n) => n(), renderShell);
const srv = app.listen(0);
const B = `http://127.0.0.1:${srv.address().port}`;
const pega = u => fetch(B + u).then(r => r.text());
const post = (u, b) => fetch(B + u, {
  method: 'POST', redirect: 'manual',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(b),
});

console.log('\n── Banner no grid ──');
let h = await pega('/isc/admin/grid?inst=HUSF');
// Sem nenhuma importação registrada, o banner deve estar lá (salvo se hoje for
// domingo antes de qualquer dia vencido — o que não ocorre: sempre há um passado).
t('sem importação nenhuma → banner aparece', h.includes('Importação do mapa cirúrgico atrasada'));
t('explica a rotina', h.includes('toda segunda e quinta'));
t('diz que nunca houve importação', h.includes('Nenhuma importação registrada'));
t('oferece o atalho de importar', h.includes('/isc/admin/importar'));
t('explica a consequência clínica', h.includes('não é vigiada'));

// Com uma importação de hoje, o banner some.
await pool.query(`INSERT INTO isc_import_lotes (instituicao_id, arquivo_nome, criadas, created_at)
                  VALUES ($1,'mapa.xls',10, now())`, [inst.id]);
h = await pega('/isc/admin/grid?inst=HUSF');
t('com importação de hoje → banner some', !h.includes('Importação do mapa cirúrgico atrasada'));

// Importação antiga volta a acender.
await pool.query(`UPDATE isc_import_lotes SET created_at = now() - interval '20 days'`);
h = await pega('/isc/admin/grid?inst=HUSF');
t('importação de 20 dias atrás → banner volta', h.includes('Importação do mapa cirúrgico atrasada'));
t('e mostra a data da última', h.includes(dataBR(addDays(hojeISO(), -20))));

console.log('\n── 2. Correção da confirmação de identidade ──');
const DC = addDays(hojeISO(), -8);
const { rows: [f] } = await pool.query(
  `INSERT INTO isc_fichas (instituicao_id, paciente_nome, atendimento, data_cirurgia, equipe_id,
     procedimento, telefone, status_vigilancia, proximo_contato_em, proxima_janela, janelas, janelas_estado)
   VALUES ($1,'MARIA SILVA','A1',$2,$3,'OPERAÇÃO CESARIANA','5511911111111','em_vigilancia',$4,7,'[7,30]','{}')
   RETURNING id`, [inst.id, DC, eqp.id, addDays(DC, 7)]);
const AG = '/isc/admin/agenda?inst=HUSF&dias=0';

// Marca "não é o paciente" — era daqui que não se saía.
await post(`/isc/admin/ficha/${f.id}/identidade`, { inst: 'HUSF', status: 'negada' });
eq('ficou negada', (await pool.query('SELECT identidade_status FROM isc_fichas WHERE id=$1', [f.id])).rows[0].identidade_status, 'negada');

h = await pega(AG);
t('agenda mostra o estado negado', h.includes('identidade negada'));
t('e agora OFERECE a correção', h.includes('Na verdade é o paciente'));
t('e permite voltar a perguntar', h.includes('Perguntar de novo'));

let r = await post(`/isc/admin/ficha/${f.id}/identidade`, { inst: 'HUSF', status: 'confirmada' });
t('corrigir para confirmada funciona', r.status === 302);
const { rows: [f2] } = await pool.query('SELECT * FROM isc_fichas WHERE id=$1', [f.id]);
eq('agora confirmada', f2.identidade_status, 'confirmada');
t('carimbo de autoria atualizado', f2.identidade_por === 'Ana Colaboradora' && !!f2.identidade_em);
r = await post('/isc/admin/envio/marcar', { inst: 'HUSF', ficha_id: f.id, janela: '7' });
t('e a busca ativa foi DESBLOQUEADA', r.status === 302, `status=${r.status}`);

console.log('\n── Correção também pela ficha, nos dois sentidos ──');
h = await pega(`/isc/admin/ficha/${f.id}?inst=HUSF`);
t('ficha tem o bloco de identidade', h.includes('Confirmação de identidade (passo 0)'));
t('mostra o estado atual', h.includes('Confirmada'));
t('avisa que dá para corrigir', h.includes('corrigida a qualquer momento'));
t('oferece marcar como não sendo o paciente', h.includes('Não é o paciente'));
t('e voltar a pendente', h.includes('Voltar a pendente'));
t('não oferece o estado em que já está', !/value="confirmada"/.test(h.split('Classificação SCIH')[0]));

await post(`/isc/admin/ficha/${f.id}/identidade`, { inst: 'HUSF', status: 'pendente' });
const { rows: [f3] } = await pool.query('SELECT identidade_status, identidade_em FROM isc_fichas WHERE id=$1', [f.id]);
eq('voltou a pendente', f3.identidade_status, 'pendente');
t('e o carimbo foi limpo', !f3.identidade_em);
await post(`/isc/admin/ficha/${f.id}/identidade`, { inst: 'HUSF', status: 'confirmada' });

console.log('\n── 3. Prontuário obrigatório no primeiro contato ──');
h = await pega(`/isc/admin/ficha/${f.id}?inst=HUSF`);
t('formulário de contato tem o campo', h.includes('name="prontuario"'));
t('marcado como obrigatório', h.includes('Obrigatório no 1º contato'));
t('explica por quê', h.includes('não traz prontuário'));

// Primeira janela sem prontuário → barrado NO SERVIDOR.
r = await post(`/isc/admin/ficha/${f.id}/contato?inst=HUSF`, {
  janela: '7', r_febre: 'Não', responsavel: 'Ana',
});
t('1º contato sem prontuário → 400', r.status === 400, `status=${r.status}`);
eq('e o contato NÃO foi gravado', (await pool.query('SELECT count(*)::int n FROM isc_contatos WHERE ficha_id=$1', [f.id])).rows[0].n, 0);
t('a mensagem explica o motivo', /prontuário/i.test(await r.text()));

// Tentativa SEM SUCESSO não exige — ela não teria como obter o dado.
r = await post(`/isc/admin/ficha/${f.id}/contato?inst=HUSF`, {
  janela: '7', sem_sucesso: '1', motivo_insucesso: 'nao_atende', responsavel: 'Ana',
});
t('tentativa sem sucesso NÃO exige prontuário', r.status === 302, `status=${r.status}`);
eq('e foi registrada', (await pool.query('SELECT count(*)::int n FROM isc_contatos WHERE ficha_id=$1', [f.id])).rows[0].n, 1);

// Com prontuário → grava e sobe para a ficha.
r = await post(`/isc/admin/ficha/${f.id}/contato?inst=HUSF`, {
  janela: '7', prontuario: 'P98765', r_febre: 'Sim', responsavel: 'Ana',
});
t('com prontuário → grava', r.status === 302);
eq('prontuário subiu para a ficha', (await pool.query('SELECT prontuario FROM isc_fichas WHERE id=$1', [f.id])).rows[0].prontuario, 'P98765');

// Janelas seguintes não voltam a exigir (já está na ficha).
r = await post(`/isc/admin/ficha/${f.id}/contato?inst=HUSF`, {
  janela: '30', r_febre: 'Não', responsavel: 'Ana',
});
t('janela 30 não re-exige', r.status === 302);

// E dá para corrigir um prontuário errado num contato posterior.
r = await post(`/isc/admin/ficha/${f.id}/contato?inst=HUSF`, {
  janela: '30', prontuario: 'P11111', r_febre: 'Não', responsavel: 'Ana',
});
eq('prontuário corrigido', (await pool.query('SELECT prontuario FROM isc_fichas WHERE id=$1', [f.id])).rows[0].prontuario, 'P11111');

// Ficha que JÁ tinha prontuário não é barrada no 1º contato.
const { rows: [g] } = await pool.query(
  `INSERT INTO isc_fichas (instituicao_id, paciente_nome, atendimento, prontuario, data_cirurgia, equipe_id,
     procedimento, status_vigilancia, identidade_status, janelas, janelas_estado)
   VALUES ($1,'JOAO','A2','P555',$2,$3,'OPERAÇÃO CESARIANA','em_vigilancia','confirmada','[7,30]','{}')
   RETURNING id`, [inst.id, DC, eqp.id]);
r = await post(`/isc/admin/ficha/${g.id}/contato?inst=HUSF`, { janela: '7', r_febre: 'Não', responsavel: 'Ana' });
t('ficha que já tem prontuário passa direto', r.status === 302, `status=${r.status}`);
h = await pega(`/isc/admin/ficha/${g.id}?inst=HUSF`);
t('e o campo vem preenchido', h.includes('value="P555"'));
t('sem o asterisco de obrigatório', h.includes('Já registrado'));

srv.close(); await pool.end();
console.log(`\n${'═'.repeat(52)}\n${ok} passaram · ${fail} falharam\n`);
process.exit(fail ? 1 : 0);
