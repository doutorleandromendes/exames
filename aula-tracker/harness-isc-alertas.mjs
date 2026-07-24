// harness-isc-alertas.mjs — regras configuráveis de flag de possível ISC.
//
// Combinação E/OU, liga/desliga, escopo por equipe. O que importa provar:
//  1. as regras EMBUTIDAS nunca somem (baseline clínico sempre vale);
//  2. "febre E secreção" acende só com as DUAS (não é OR disfarçado);
//  3. escopo por equipe restringe de verdade;
//  4. o alerta persiste no banco via recomputarEstado, não só na memória.
import express from 'express';
import { Pool } from 'pg';
import { registerIscImportRoutes } from './isc-import-routes.js';
import { registerIscRoutes } from './isc-routes.js';
import { runIscMigrations } from './isc-db.js';
import { renderShell } from './ui-shell.js';
import {
  contatoTemAlerta, regraAlertaCasa, alertasDe, recomputarEstado,
  REGRAS_ALERTA_SEED, addDays, hojeISO,
} from './isc-core.js';

const DB = process.env.ISC_TEST_DB || 'postgresql://postgres:x@localhost:5432/iscteste';
const pool = new Pool({ connectionString: DB });
let ok = 0, fail = 0;
const t = (n, c, x = '') => { if (c) { ok++; console.log('  ✓', n); } else { fail++; console.log('  ✗ FALHOU:', n, x); } };
const eq = (n, a, b) => t(`${n} → ${JSON.stringify(a)}`, JSON.stringify(a) === JSON.stringify(b), `esperado ${JSON.stringify(b)}`);

console.log('\n── Motor puro: E dentro do grupo, OU entre grupos ──');
const febreEsec = { id: 1, ativo: true, nome: 'Febre + secreção', grupos: [[{ campo: 'febre', valores: ['Sim'] }, { campo: 'ferida', valores: ['Secreção purulenta'] }]] };
t('acende com AMBAS', regraAlertaCasa(febreEsec, { febre: 'Sim', ferida: ['Secreção purulenta'] }));
t('NÃO acende só com febre', !regraAlertaCasa(febreEsec, { febre: 'Sim' }));
t('NÃO acende só com secreção', !regraAlertaCasa(febreEsec, { ferida: ['Secreção purulenta'] }));
t('NÃO acende com febre + secreção SEROSA (valor diferente)', !regraAlertaCasa(febreEsec, { febre: 'Sim', ferida: ['Secreção serosa'] }));

const ou = { id: 2, ativo: true, nome: 'x', grupos: [[{ campo: 'readmissao', valores: ['Sim'] }], [{ campo: 'febre', valores: ['Sim'] }, { campo: 'dor_bifasica', valores: ['Sim'] }]] };
t('OU: só readmissão acende', regraAlertaCasa(ou, { readmissao: 'Sim' }));
t('OU: febre+dor acende', regraAlertaCasa(ou, { febre: 'Sim', dor_bifasica: 'Sim' }));
t('OU: só febre não acende', !regraAlertaCasa(ou, { febre: 'Sim' }));

t('regra desligada nunca acende', !regraAlertaCasa({ ...ou, ativo: false }, { readmissao: 'Sim' }));
t('regra sem grupos nunca acende', !regraAlertaCasa({ ativo: true, grupos: [] }, { febre: 'Sim' }));
t('grupo vazio não acende (evita pegar tudo)', !regraAlertaCasa({ ativo: true, grupos: [[]] }, { febre: 'Sim' }));

console.log('\n── Sem piso embutido: o motor lê SÓ o que recebe ──');
t('há sementes para o banco importar', REGRAS_ALERTA_SEED.length >= 5);
t('sementes têm nome descritivo, não "Como está a ferida?"', REGRAS_ALERTA_SEED.every(r => !/\?$/.test(r.nome)));
t('SEM regras → nada acende (nem febre)', !contatoTemAlerta({ febre: 'Sim' }, false, []));
t('COM a semente de febre → acende', contatoTemAlerta({ febre: 'Sim' }, false,
  REGRAS_ALERTA_SEED.filter(r => /febre/i.test(r.nome)).map(r => ({ ...r, ativo: true }))));
t('suspeita marcada na mão sempre acende, mesmo sem regras', contatoTemAlerta({}, true, []));

console.log('\n── alertasDe explica o que acendeu ──');
const regrasComFebre = [...REGRAS_ALERTA_SEED.filter(r => /febre/i.test(r.nome)).map(r => ({ ...r, ativo: true })), febreEsec];
const explica = alertasDe({ febre: 'Sim', ferida: ['Secreção purulenta'] }, regrasComFebre);
t('lista a regra de febre', explica.some(x => /febre/i.test(x)));
t('lista a regra combinada', explica.includes('Febre + secreção'));

await runIscMigrations(pool);
// Banco limpo COMO EM PRODUÇÃO no 1º boot: zera regras E o marcador de seed, e
// re-roda a migração para o seed plantar do zero (o marcador é o que impede
// re-seed em bancos já semeados; aqui queremos justamente exercitar o seed).
await pool.query('TRUNCATE isc_alerta_regras, isc_envios, isc_contatos, isc_fichas RESTART IDENTITY CASCADE');
await pool.query(`UPDATE isc_config SET alerta_seed_em = NULL`);
await runIscMigrations(pool);
const { rows: [inst] } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla='HUSF'`);
const { rows: eqs } = await pool.query(`SELECT id, nome FROM isc_equipes WHERE instituicao_id=$1`, [inst.id]);
const OBST = eqs.find(e => e.nome === 'Obstetrícia').id;
const NEURO = eqs.find(e => e.nome === 'Neurocirurgia').id;

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use((q, s, n) => { q.user = { full_name: 'Dr. Leandro', super_admin: true }; n(); });
registerIscRoutes(app, pool, (q, s, n) => n(), renderShell);
registerIscImportRoutes(app, pool, (q, s, n) => n(), renderShell);
const srv = app.listen(0);
const B = `http://127.0.0.1:${srv.address().port}`;
const pega = u => fetch(B + u).then(r => r.text());
const post = (u, b) => fetch(B + u, {
  method: 'POST', redirect: 'manual',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(b),
});

console.log('\n── Seed: regras clínicas plantadas no banco ──');
const { rows: [{ n: nSeed }] } = await pool.query(`SELECT count(*)::int n FROM isc_alerta_regras WHERE instituicao_id=$1`, [inst.id]);
t('as sementes foram plantadas como regras normais', nSeed === REGRAS_ALERTA_SEED.length, `tinha ${nSeed}`);
t('regra "Febre" existe e é editável', (await pool.query(`SELECT count(*)::int n FROM isc_alerta_regras WHERE instituicao_id=$1 AND nome='Febre'`, [inst.id])).rows[0].n === 1);
t('marcador anti-re-seed gravado', !!(await pool.query('SELECT alerta_seed_em FROM isc_config WHERE instituicao_id=$1', [inst.id])).rows[0]?.alerta_seed_em);

// Re-rodar migração NÃO deve duplicar nem ressuscitar o que foi apagado.
await pool.query(`DELETE FROM isc_alerta_regras WHERE instituicao_id=$1 AND nome='Febre'`, [inst.id]);
await runIscMigrations(pool);
t('apagar "Febre" e migrar de novo NÃO a ressuscita',
  (await pool.query(`SELECT count(*)::int n FROM isc_alerta_regras WHERE instituicao_id=$1 AND nome='Febre'`, [inst.id])).rows[0].n === 0);

console.log('\n── Tela: CRUD ──');
let h = await pega('/isc/admin/alertas?inst=HUSF');
t('tela abre', h.includes('Regras de alerta') || h.includes('Como funciona'));
t('não fala mais em "embutida"', !h.includes('embutida'));
t('tem editor de grupos', h.includes('Grupo (OU)'));

let r = await post('/isc/admin/alertas', {
  inst: 'HUSF', nome: 'Febre + secreção purulenta',
  grupos: JSON.stringify([[{ campo: 'febre', valores: ['Sim'] }, { campo: 'ferida', valores: ['Secreção purulenta'] }]]),
  equipe_ids: JSON.stringify([]),
});
t('cria regra (todas as equipes)', r.status === 302);
const { rows: [regra] } = await pool.query(`SELECT * FROM isc_alerta_regras WHERE nome = 'Febre + secreção purulenta'`);
t('gravou os grupos', Array.isArray(regra.grupos) && regra.grupos[0].length === 2);
eq('escopo vazio = todas', regra.equipe_ids, []);

r = await post('/isc/admin/alertas', {
  inst: 'HUSF', nome: 'Só neuro: dreno',
  grupos: JSON.stringify([[{ campo: 'dreno', valores: ['Sim'] }]]),
  equipe_ids: JSON.stringify([NEURO]),
});
t('cria regra com escopo de equipe', r.status === 302);

console.log('\n── Saneamento: campo forjado é descartado ──');
r = await post('/isc/admin/alertas', {
  inst: 'HUSF', nome: 'Forjada',
  grupos: JSON.stringify([[{ campo: 'campo_que_nao_existe', valores: ['x'] }]]),
  equipe_ids: '[]',
});
t('regra só com campo inválido → 400 (sem condição válida)', r.status === 400, `status=${r.status}`);
eq('nada gravado', (await pool.query(`SELECT count(*)::int n FROM isc_alerta_regras WHERE nome='Forjada'`)).rows[0].n, 0);

console.log('\n── Efeito real: alerta persiste via recomputarEstado ──');
const D = addDays(hojeISO(), -8);
const mkFicha = (nome, eqId) => pool.query(
  `INSERT INTO isc_fichas (instituicao_id, paciente_nome, atendimento, data_cirurgia, equipe_id, status_vigilancia, proximo_contato_em, proxima_janela, janelas, janelas_estado, identidade_status)
   VALUES ($1,$2,$3,$4,$5,'em_vigilancia',$6,7,'[7,30]','{}','confirmada') RETURNING id`,
  [inst.id, nome, nome, D, eqId, addDays(D, 7)]).then(r => r.rows[0].id);
const fObst = await mkFicha('MARIA OBST', OBST);
const fNeuro = await mkFicha('JOAO NEURO', NEURO);

// Recriar a regra de Febre (apagada acima) para testar o efeito.
await post('/isc/admin/alertas', { inst: 'HUSF', nome: 'Febre',
  grupos: JSON.stringify([[{ campo: 'febre', valores: ['Sim'] }]]), equipe_ids: '[]' });
await post(`/isc/admin/ficha/${fObst}/contato?inst=HUSF`, { janela: '7', prontuario: 'P-TESTE', r_febre: 'Sim', responsavel: 'Ana' });
t('febre acende (regra do banco)', (await pool.query('SELECT tem_alerta FROM isc_fichas WHERE id=$1', [fObst])).rows[0].tem_alerta === true);

// Escopo: a regra de dreno é só de NEURO. Em Obstetrícia não pode acender.
const fObst2 = await mkFicha('ANA OBST', OBST);
await post(`/isc/admin/ficha/${fObst2}/contato?inst=HUSF`, { janela: '7', prontuario: 'P-TESTE', r_dreno: 'Sim', responsavel: 'Ana' });
t('dreno em OBSTETRÍCIA não acende (regra é só de neuro)',
  (await pool.query('SELECT tem_alerta FROM isc_fichas WHERE id=$1', [fObst2])).rows[0].tem_alerta === false);

await post(`/isc/admin/ficha/${fNeuro}/contato?inst=HUSF`, { janela: '7', prontuario: 'P-TESTE', r_dreno: 'Sim', responsavel: 'Ana' });
t('dreno em NEURO acende (dentro do escopo)',
  (await pool.query('SELECT tem_alerta FROM isc_fichas WHERE id=$1', [fNeuro])).rows[0].tem_alerta === true);

console.log('\n── Toggle e exclusão ──');
r = await post(`/isc/admin/alertas/${regra.id}/toggle`, { inst: 'HUSF' });
t('desliga', r.status === 302);
t('ficou inativa', (await pool.query('SELECT ativo FROM isc_alerta_regras WHERE id=$1', [regra.id])).rows[0].ativo === false);
r = await post(`/isc/admin/alertas/${regra.id}/toggle`, { inst: 'HUSF' });
t('religa', (await pool.query('SELECT ativo FROM isc_alerta_regras WHERE id=$1', [regra.id])).rows[0].ativo === true);
r = await post(`/isc/admin/alertas/${regra.id}/excluir`, { inst: 'HUSF' });
t('exclui', r.status === 302);
eq('sumiu', (await pool.query('SELECT count(*)::int n FROM isc_alerta_regras WHERE id=$1', [regra.id])).rows[0].n, 0);

console.log('\n── Guardas ──');
h = await pega('/isc/admin/alertas?inst=HUSF');
t('nav tem link de Alertas', h.includes('/isc/admin/alertas'));
const { rows: [scmi] } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla='SCMI'`);
await pool.query(`INSERT INTO isc_alerta_regras (instituicao_id, nome, grupos) VALUES ($1,'DO SCMI','[[{"campo":"febre","valores":["Sim"]}]]')`, [scmi.id]);
h = await pega('/isc/admin/alertas?inst=HUSF');
t('regra do SCMI não aparece no HUSF', !h.includes('DO SCMI'));

srv.close(); await pool.end();
console.log(`\n${'═'.repeat(52)}\n${ok} passaram · ${fail} falharam\n`);
process.exit(fail ? 1 : 0);
