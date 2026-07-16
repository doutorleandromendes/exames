// harness-isc-sort.mjs — ordenação do grid de ISC.
// Mesmo contrato do grid do ATB: ?sort=&dir=, ciclo asc → desc → reset.
// Testa a ORDEM REAL das linhas, não só se o link aparece.
import express from 'express';
import { Pool } from 'pg';
import { registerIscRoutes } from './isc-routes.js';
import { runIscMigrations } from './isc-db.js';
import { renderShell } from './ui-shell.js';
import { addDays, hojeISO } from './isc-core.js';

const DB = process.env.ISC_TEST_DB || 'postgresql://postgres:x@localhost:5432/iscteste';
const pool = new Pool({ connectionString: DB });
let ok = 0, fail = 0;
const t = (n, c, x = '') => { if (c) { ok++; console.log('  ✓', n); } else { fail++; console.log('  ✗ FALHOU:', n, x); } };
const eq = (n, a, b) => t(`${n} → ${JSON.stringify(a)}`, JSON.stringify(a) === JSON.stringify(b), `esperado ${JSON.stringify(b)}`);

await runIscMigrations(pool);
await pool.query('TRUNCATE isc_envios, isc_contatos, isc_fichas RESTART IDENTITY CASCADE');
const { rows: [i] } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla='HUSF'`);
const { rows: eqs } = await pool.query(`SELECT id, nome FROM isc_equipes WHERE instituicao_id=$1 ORDER BY nome`, [i.id]);
const NEURO = eqs.find(e => e.nome === 'Neurocirurgia').id;
const OBST = eqs.find(e => e.nome === 'Obstetrícia').id;

// Dados escolhidos para que cada ordenação dê uma ordem DIFERENTE — senão o
// teste passa sem provar nada.
//  nome    cirurgia    equipe   próx.contato   classificação   patógeno
const D = d => addDays(hojeISO(), d);
await pool.query(
  `INSERT INTO isc_fichas (instituicao_id, paciente_nome, atendimento, data_cirurgia, equipe_id,
     status_vigilancia, proximo_contato_em, tem_alerta, isc_classificacao, isc_patogeno, contatos_ok)
   VALUES
     ($1,'CARLOS','A1',$2,$5,'em_vigilancia',$7,false,'nao_avaliada',NULL,0),
     ($1,'ANA','A2',$3,$6,'em_vigilancia',$8,true,'confirmada','S. aureus',2),
     ($1,'BRUNO','A3',$4,$5,'em_vigilancia',$9,false,'descartada','E. coli',1)`,
  [i.id, D(-5), D(-30), D(-15), NEURO, OBST, D(2), D(-3), D(10)]);
// Uma sem próximo contato: NULLS LAST tem que valer nos dois sentidos.
await pool.query(
  `INSERT INTO isc_fichas (instituicao_id, paciente_nome, atendimento, data_cirurgia, equipe_id,
     status_vigilancia, proximo_contato_em, isc_classificacao)
   VALUES ($1,'ZULMIRA','A4',$2,$3,'concluida',NULL,'nao_avaliada')`, [i.id, D(-60), NEURO]);

const app = express();
app.use((req, res, next) => { req.user = { super_admin: true }; next(); });
registerIscRoutes(app, pool, (q, s, n) => n(), renderShell);
const srv = app.listen(0);
const base = `http://127.0.0.1:${srv.address().port}`;

// Lê os nomes na ordem em que o grid renderizou.
async function ordem(qs) {
  const html = await (await fetch(`${base}/isc/admin/grid?inst=HUSF&${qs}`)).text();
  return [...html.matchAll(/class="pac"[^>]*>([^<]+)</g)].map(m => m[1].trim());
}
const pega = qs => fetch(`${base}/isc/admin/grid?inst=HUSF&${qs}`).then(r => r.text());

console.log('\n── Padrão: cirurgia mais recente primeiro ──');
eq('sem sort', await ordem(''), ['CARLOS', 'BRUNO', 'ANA', 'ZULMIRA']);

console.log('\n── Ciclo de 3 cliques (paciente) ──');
eq('1º clique: asc', await ordem('sort=paciente&dir=asc'), ['ANA', 'BRUNO', 'CARLOS', 'ZULMIRA']);
eq('2º clique: desc', await ordem('sort=paciente&dir=desc'), ['ZULMIRA', 'CARLOS', 'BRUNO', 'ANA']);
eq('3º clique: reset = padrão', await ordem(''), ['CARLOS', 'BRUNO', 'ANA', 'ZULMIRA']);

console.log('\n── O link do cabeçalho implementa o ciclo ──');
let html = await pega('');
t('sem ordenação → link pede asc', html.includes('sort=paciente&dir=asc'));
t('e sem seta', !/Paciente<span class="arr"/.test(html));
html = await pega('sort=paciente&dir=asc');
t('em asc → mostra ▲', /Paciente<span class="arr"> ▲/.test(html));
t('e o link pede desc', html.includes('sort=paciente&dir=desc'));
t('marca a coluna ativa', /class="th-sort on"[^>]*>Paciente/.test(html));
html = await pega('sort=paciente&dir=desc');
t('em desc → mostra ▼', /Paciente<span class="arr"> ▼/.test(html));
t('e o link REMOVE a ordenação (reset)', !/href="\/isc\/admin\/grid\?[^"]*sort=paciente[^"]*"[^>]*>Paciente/.test(html));
t('tooltip explica o 3º clique', html.includes('Remover ordenação'));

console.log('\n── Todas as colunas ordenam ──');
eq('cirurgia asc (mais antiga primeiro)', await ordem('sort=cirurgia&dir=asc'), ['ZULMIRA', 'ANA', 'BRUNO', 'CARLOS']);
eq('equipe asc (Neuro < Obst)', (await ordem('sort=equipe&dir=asc')).slice(-1), ['ANA']);
eq('classificação asc', await ordem('sort=classif&dir=asc'), ['ANA', 'BRUNO', 'CARLOS', 'ZULMIRA']);
eq('janelas (contatos_ok) desc', (await ordem('sort=janelas&dir=desc'))[0], 'ANA');
eq('sinal desc (com alerta primeiro)', (await ordem('sort=sinal&dir=desc'))[0], 'ANA');
t('patógeno asc: nulos por último', (await ordem('sort=patogeno&dir=asc')).slice(0, 2).join() === 'BRUNO,ANA');

console.log('\n── NULLS LAST nos dois sentidos ──');
// ZULMIRA não tem próximo contato. Não pode encabeçar nenhuma das direções.
eq('prox asc: nulo por último', (await ordem('sort=prox&dir=asc')).slice(-1), ['ZULMIRA']);
eq('prox desc: nulo por último também', (await ordem('sort=prox&dir=desc')).slice(-1), ['ZULMIRA']);
eq('prox asc: mais atrasado primeiro', (await ordem('sort=prox&dir=asc'))[0], 'ANA');

console.log('\n── Ordenação sobrevive ao filtro e à paginação ──');
html = await pega('sort=paciente&dir=desc');
t('form de filtro carrega sort/dir escondidos', /name="sort" value="paciente"/.test(html) && /name="dir" value="desc"/.test(html));
t('sem sort, não polui o form', !/name="sort"/.test(await pega('')));
eq('filtro + sort juntos', await ordem('sort=paciente&dir=asc&equipe=' + NEURO), ['BRUNO', 'CARLOS', 'ZULMIRA']);

console.log('\n── Whitelist: sort é chave, nunca SQL ──');
const ANTES = ['CARLOS', 'BRUNO', 'ANA', 'ZULMIRA'];
eq('coluna inexistente → cai no padrão', await ordem('sort=nao_existe&dir=asc'), ANTES);
eq('injeção no sort não derruba', await ordem('sort=' + encodeURIComponent('f.id; DROP TABLE isc_fichas;--')), ANTES);
eq('injeção no dir não derruba', await ordem('sort=paciente&dir=' + encodeURIComponent("asc; DROP TABLE isc_fichas;--")), ['ANA', 'BRUNO', 'CARLOS', 'ZULMIRA']);
t('tabela intacta', (await pool.query('SELECT count(*)::int n FROM isc_fichas')).rows[0].n === 4);
eq('dir inválido vira asc', await ordem('sort=paciente&dir=xyz'), ['ANA', 'BRUNO', 'CARLOS', 'ZULMIRA']);

console.log('\n── Ordenar não vaza outro tenant ──');
const { rows: [scmi] } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla='SCMI'`);
await pool.query(`INSERT INTO isc_fichas (instituicao_id, paciente_nome, atendimento, data_cirurgia)
                  VALUES ($1,'AAAA SCMI','S1',$2)`, [scmi.id, D(-1)]);
t('AAAA (1º em asc) não aparece no HUSF', !(await ordem('sort=paciente&dir=asc')).includes('AAAA SCMI'));

srv.close(); await pool.end();
console.log(`\n${'═'.repeat(52)}\n${ok} passaram · ${fail} falharam\n`);
process.exit(fail ? 1 : 0);
