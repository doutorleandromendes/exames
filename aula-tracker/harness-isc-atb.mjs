// harness-isc-atb.mjs — ponte ISC → ATB.
//
// Roda contra os schemas REAIS das duas metades (runAtbMigrations +
// runIscMigrations no mesmo banco), porque o risco aqui é justamente escrever
// numa coluna que não existe ou num dropdown com valor inventado.
//
// O que este harness insiste em provar:
//   1. todo valor de dropdown existe na FONTE CANÔNICA (não numa cópia local);
//   2. a ponte é idempotente — reclassificar não duplica ficha de IrAS;
//   3. `iras` vai para atb_avaliacoes, não para atb_fichas;
//   4. coluna promovida ausente não quebra nada nem perde dado (vai p/ payload_raw);
//   5. classificação diferente de 'confirmada' não cria nada.
import express from 'express';
import { Pool } from 'pg';
import { runAtbMigrations } from './atb-db.js';
import { runIscMigrations } from './isc-db.js';
import { ensureRetroSchema } from './atb-ficha-retro-routes.js';
import { ensureFormSchemaTable, saveFormSchema, SEMENTE_HUSF } from './atb-form-schema.js';
import { registerIscRoutes } from './isc-routes.js';
import { renderShell } from './ui-shell.js';
import {
  criarFichaAtbDeIsc, validarValores, montarHistoriaClinica,
  dataDoContatoQueAlertou, colunasReais, ALVO,
} from './isc-atb-bridge.js';
import { PARECER_VEREDITOS } from './atb-parecer-edit-routes.js';
import { IRAS_VALORES } from './atb-regras-routes.js';
import { addDays, hojeISO, dataBR } from './isc-core.js';

const DB = process.env.ATB_ISC_TEST_DB || 'postgresql://postgres:x@localhost:5432/pontesteste';
const pool = new Pool({ connectionString: DB });
let ok = 0, fail = 0;
const t = (n, c, x = '') => { if (c) { ok++; console.log('  ✓', n); } else { fail++; console.log('  ✗ FALHOU:', n, x); } };
const eq = (n, a, b) => t(`${n} → ${JSON.stringify(a)}`, JSON.stringify(a) === JSON.stringify(b), `esperado ${JSON.stringify(b)}`);

// ── Banco com as duas metades ────────────────────────────────────────────
await pool.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, email TEXT, full_name TEXT,
                  scih BOOLEAN DEFAULT false, super_admin BOOLEAN DEFAULT false)`);
await runAtbMigrations(pool);
await ensureRetroSchema(pool);
await ensureFormSchemaTable(pool);
await saveFormSchema(pool, 'HUSF', SEMENTE_HUSF);
await runIscMigrations(pool);
await pool.query(`TRUNCATE atb_avaliacoes, atb_fichas RESTART IDENTITY CASCADE`);
await pool.query(`TRUNCATE isc_envios, isc_contatos, isc_fichas RESTART IDENTITY CASCADE`);
const { rows: [inst] } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla='HUSF'`);
const { rows: [eqp] } = await pool.query(
  `SELECT id, nome FROM isc_equipes WHERE instituicao_id=$1 AND nome='Neurocirurgia'`, [inst.id]);
const { rows: [u] } = await pool.query(
  `INSERT INTO users (full_name, super_admin) VALUES ('Dr. Leandro', true) RETURNING id`);

console.log('\n── Valores validados contra a FONTE CANÔNICA ──');
const val = await validarValores(pool, 'HUSF');
t('validação passa', val.ok, JSON.stringify(val.erros));
t("foco veio do schema VIVO (atb_form_schema)", val.opcoes.foco_infeccao.length >= 5);
t(`'${ALVO.foco_infeccao}' existe nas opções de foco_infeccao`, val.opcoes.foco_infeccao.includes(ALVO.foco_infeccao));
t(`'${ALVO.parecer}' existe em PARECER_VEREDITOS`, PARECER_VEREDITOS.includes(ALVO.parecer));
t(`'${ALVO.iras}' existe em IRAS_VALORES`, IRAS_VALORES.includes(ALVO.iras));
// A prova de que a validação não é decorativa: um alvo inexistente reprova.
const original = ALVO.foco_infeccao;
ALVO.foco_infeccao = 'Foco Que Não Existe';
const ruim = await validarValores(pool, 'HUSF');
t('valor inventado é REPROVADO pela validação', !ruim.ok && /não está nas opções/.test(ruim.erros.join()));
ALVO.foco_infeccao = original;

console.log('\n── História clínica ──');
eq('formato pedido', montarHistoriaClinica({ procedimento: 'CRANIOTOMIA', data_cirurgia: '2026-07-13' }),
  'Imput do Sistema de ISC - CRANIOTOMIA 13-07-2026');
t('sem procedimento não vira "undefined"', !/undefined/.test(montarHistoriaClinica({ data_cirurgia: '2026-07-13' })));
t('sem nada, não sobra hífen solto', montarHistoriaClinica({}) === 'Imput do Sistema de ISC');

console.log('\n── Data de referência = contato que acendeu o alerta ──');
const regraFebre = { ativo: true, nome: 'Febre', grupos: [[{ campo: 'febre', valores: ['Sim'] }]] };
const contatos = [
  { data_contato: '2026-07-20', sucesso: true, respostas: { febre: 'Não' } },
  { data_contato: '2026-07-25', sucesso: true, respostas: { febre: 'Sim' } },   // acendeu
  { data_contato: '2026-07-28', sucesso: true, respostas: { febre: 'Não' } },
];
eq('pega o contato que alertou, não o mais recente',
  dataDoContatoQueAlertou(contatos, {}, [regraFebre]), '2026-07-25');
eq('sem contato com alerta, cai p/ data do diagnóstico',
  dataDoContatoQueAlertou([], { isc_data_diagnostico: '2026-08-01' }, [regraFebre]), '2026-08-01');
eq('sem nada, cai p/ data da cirurgia',
  dataDoContatoQueAlertou([], { data_cirurgia: '2026-07-01' }, []), '2026-07-01');

// ── Ficha ISC completa ───────────────────────────────────────────────────
const DC = addDays(hojeISO(), -20);
const { rows: [f] } = await pool.query(
  `INSERT INTO isc_fichas (instituicao_id, paciente_nome, prontuario, atendimento, data_cirurgia,
     equipe_id, procedimento, status_vigilancia, identidade_status, janelas, janelas_estado)
   VALUES ($1,'MARIA SILVA SOUZA','P12345','A999',$2,$3,'CRANIOTOMIA DESCOMPRESSIVA',
           'em_vigilancia','confirmada','[7,30]','{}') RETURNING id`,
  [inst.id, DC, eqp.id]);
const DCONT = addDays(DC, 8);
await pool.query(
  `INSERT INTO isc_contatos (ficha_id, janela, data_contato, canal, sucesso, respostas)
   VALUES ($1, 7, $2, 'whatsapp', true, '{"febre":"Sim"}')`, [f.id, DCONT]);

console.log('\n── Sem confirmação, nada acontece ──');
let r = await criarFichaAtbDeIsc(pool, f.id, { userId: u.id });
t('classificação nao_avaliada → não cria', r.criada === false, JSON.stringify(r));
eq('nenhuma ficha ATB', (await pool.query('SELECT count(*)::int n FROM atb_fichas')).rows[0].n, 0);

await pool.query(`UPDATE isc_fichas SET isc_classificacao='descartada' WHERE id=$1`, [f.id]);
r = await criarFichaAtbDeIsc(pool, f.id, { userId: u.id });
t('descartada → não cria', r.criada === false);

console.log('\n── ISC confirmada → ficha ATB criada ──');
await pool.query(
  `UPDATE isc_fichas SET isc_classificacao='confirmada', isc_tipo='orgao_cavidade',
     isc_data_diagnostico=$2, isc_patogeno='S. aureus' WHERE id=$1`, [f.id, addDays(DC, 10)]);
r = await criarFichaAtbDeIsc(pool, f.id, { userId: u.id });
t('criou', r.criada === true, JSON.stringify(r));
const { rows: [a] } = await pool.query(`SELECT * FROM atb_fichas WHERE id=$1`, [r.atbFichaId]);

eq('nome do paciente', a.paciente_nome, 'MARIA SILVA SOUZA');
eq('nome_raw preenchido junto', a.paciente_nome_raw, 'MARIA SILVA SOUZA');
eq('prontuário', a.prontuario, 'P12345');
eq('história clínica no formato pedido', a.historia_clinica,
  `Imput do Sistema de ISC - CRANIOTOMIA DESCOMPRESSIVA ${dataBR(DC)}`);
eq('foco de infecção', a.foco_infeccao, 'Infecção do sítio cirúrgico');
eq('ATB = lista vazia (nenhum ATB solicitado)', a.atb_solicitado, []);
eq('parecer = Audit_post (formato do módulo de parecer: array)', a.recomendacao_scih, ['Audit_post']);
t('marcada como retrospectiva', a.retrospectiva === true);
eq('status nasce pendente (entra em "A classificar")', a.status, 'pendente');
eq('instituição herdada da ISC', a.instituicao_id, inst.id);
eq('cirurgia registrada', a.cirurgia, 'CRANIOTOMIA DESCOMPRESSIVA');
eq('equipe herdada', a.equipe_responsavel, 'Neurocirurgia');
eq('setor = PS (neutro, para não bagunçar o recorte da grade)', a.setor, 'PS');
t("'PS' foi validado contra as opções do schema, não hardcoded",
  val.opcoes.setor && val.opcoes.setor.includes('PS'), JSON.stringify(val.opcoes.setor));

console.log('\n── IrAS vai para atb_avaliacoes, não atb_fichas ──');
const colsF = await colunasReais(pool, 'atb_fichas');
t('atb_fichas NÃO tem coluna iras (por isso o INSERT separado)', !colsF.has('iras'));
const { rows: [av] } = await pool.query(`SELECT * FROM atb_avaliacoes WHERE ficha_id=$1`, [r.atbFichaId]);
t('linha de avaliação criada', !!av);
eq('iras = ISC', av.iras, 'ISC');
eq('autoria registrada', av.avaliado_por, u.id);

console.log('\n── Datas ──');
eq('data de referência = contato que alertou', r.dataReferencia, DCONT);
const cols = await colunasReais(pool, 'atb_fichas');
if (cols.has('data_referencia')) {
  eq('gravou na coluna data_referencia', String(a.data_referencia).slice(0, 10), DCONT);
} else {
  eq('coluna ausente → foi para payload_raw', a.payload_raw.data_referencia, DCONT);
}
if (cols.has('data_da_cirurgia_infectada')) {
  eq('gravou na coluna data_da_cirurgia_infectada', String(a.data_da_cirurgia_infectada).slice(0, 10), DC);
} else {
  eq('coluna promovida ausente → payload_raw, sem perder o dado', a.payload_raw.data_da_cirurgia_infectada, DC);
}

console.log('\n── Rastreabilidade da origem ──');
eq('payload_raw aponta para a ficha ISC', a.payload_raw.origem_isc.isc_ficha_id, f.id);
eq('guarda o tipo de ISC', a.payload_raw.origem_isc.isc_tipo, 'orgao_cavidade');
eq('guarda o patógeno', a.payload_raw.origem_isc.isc_patogeno, 'S. aureus');
eq('ISC aponta de volta para a ficha ATB',
  (await pool.query('SELECT atb_ficha_id FROM isc_fichas WHERE id=$1', [f.id])).rows[0].atb_ficha_id, r.atbFichaId);

console.log('\n── ⚠ Idempotência: reclassificar NÃO duplica ──');
// Duplicar aqui inflaria o numerador de IrAS do CVE. É o erro mais caro.
const r2 = await criarFichaAtbDeIsc(pool, f.id, { userId: u.id });
t('2ª chamada não cria', r2.criada === false, JSON.stringify(r2));
eq('e devolve a ficha existente', r2.atbFichaId, r.atbFichaId);
eq('continua com 1 ficha ATB', (await pool.query('SELECT count(*)::int n FROM atb_fichas')).rows[0].n, 1);
eq('continua com 1 avaliação', (await pool.query('SELECT count(*)::int n FROM atb_avaliacoes')).rows[0].n, 1);

console.log('\n── Pela ROTA (o caminho real do médico) ──');
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use((q, s, n) => { q.user = { id: u.id, full_name: 'Dr. Leandro', super_admin: true }; n(); });
registerIscRoutes(app, pool, (q, s, n) => n(), renderShell);
const srv = app.listen(0);
const B = `http://127.0.0.1:${srv.address().port}`;
const post = (u2, b) => fetch(B + u2, {
  method: 'POST', redirect: 'manual',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(b),
});

const { rows: [g] } = await pool.query(
  `INSERT INTO isc_fichas (instituicao_id, paciente_nome, prontuario, data_cirurgia, equipe_id,
     procedimento, status_vigilancia, identidade_status, janelas, janelas_estado)
   VALUES ($1,'JOAO PEREIRA','P777',$2,$3,'OPERAÇÃO CESARIANA','em_vigilancia','confirmada','[7,30]','{}')
   RETURNING id`, [inst.id, DC, eqp.id]);

let res = await post(`/isc/admin/ficha/${g.id}/classificar?inst=HUSF`, {
  isc_classificacao: 'confirmada', isc_tipo: 'incisional_superficial', classificado_por: 'Dr. Leandro',
});
t('classificar redireciona', res.status === 302);
t('redirect avisa que criou a ficha ATB', /[?&]atb=\d+/.test(res.headers.get('location') || ''),
  res.headers.get('location'));
const { rows: [g2] } = await pool.query('SELECT atb_ficha_id FROM isc_fichas WHERE id=$1', [g.id]);
t('ficha ATB ligada', !!g2.atb_ficha_id);
eq('agora 2 fichas ATB', (await pool.query('SELECT count(*)::int n FROM atb_fichas')).rows[0].n, 2);
eq('iras da 2ª também é ISC',
  (await pool.query('SELECT iras FROM atb_avaliacoes WHERE ficha_id=$1', [g2.atb_ficha_id])).rows[0].iras, 'ISC');

// Re-salvar a classificação (o médico corrige o tipo) não pode duplicar.
res = await post(`/isc/admin/ficha/${g.id}/classificar?inst=HUSF`, {
  isc_classificacao: 'confirmada', isc_tipo: 'incisional_profunda', classificado_por: 'Dr. Leandro',
});
eq('re-salvar classificação NÃO cria 3ª ficha',
  (await pool.query('SELECT count(*)::int n FROM atb_fichas')).rows[0].n, 2);

console.log('\n── Ficha sem prontuário (o mapa do Tasy não traz) ──');
const { rows: [h] } = await pool.query(
  `INSERT INTO isc_fichas (instituicao_id, paciente_nome, data_cirurgia, equipe_id, procedimento,
     isc_classificacao, status_vigilancia, janelas, janelas_estado)
   VALUES ($1,'SEM PRONTUARIO',$2,$3,'LAQUEADURA TUBARIA','confirmada','em_vigilancia','[7,30]','{}')
   RETURNING id`, [inst.id, DC, eqp.id]);
const rh = await criarFichaAtbDeIsc(pool, h.id, { userId: u.id });
t('cria mesmo sem prontuário (não bloqueia o registro)', rh.criada === true);
const { rows: [ah] } = await pool.query('SELECT prontuario, paciente_nome FROM atb_fichas WHERE id=$1', [rh.atbFichaId]);
t('prontuário fica nulo, explicitamente', ah.prontuario === null);
eq('mas o nome vai', ah.paciente_nome, 'SEM PRONTUARIO');

console.log('\n── Elo completo: prontuário do 1º contato → ficha do ATB ──');
// É por isso que o prontuário virou obrigatório no primeiro contato: o mapa
// cirúrgico não traz esse dado, e sem ele a ficha do ATB nasce sem identificação.
const { rows: [p1] } = await pool.query(
  `INSERT INTO isc_fichas (instituicao_id, paciente_nome, data_cirurgia, equipe_id, procedimento,
     status_vigilancia, identidade_status, janelas, janelas_estado)
   VALUES ($1,'CARLOS ANDRADE',$2,$3,'OPERAÇÃO CESARIANA','em_vigilancia','confirmada','[7,30]','{}')
   RETURNING id, prontuario`, [inst.id, DC, eqp.id]);
t('ficha nasce SEM prontuário (mapa do Tasy não traz)', !p1.prontuario);

res = await post(`/isc/admin/ficha/${p1.id}/contato?inst=HUSF`, {
  janela: '7', r_febre: 'Sim', responsavel: 'Ana', prontuario: 'PRT-4242',
});
t('1º contato grava o prontuário', res.status === 302, `status=${res.status}`);
eq('prontuário na ficha ISC',
  (await pool.query('SELECT prontuario FROM isc_fichas WHERE id=$1', [p1.id])).rows[0].prontuario, 'PRT-4242');

res = await post(`/isc/admin/ficha/${p1.id}/classificar?inst=HUSF`, {
  isc_classificacao: 'confirmada', isc_tipo: 'incisional_superficial', classificado_por: 'Dr. Leandro',
});
const { rows: [p2] } = await pool.query('SELECT atb_ficha_id FROM isc_fichas WHERE id=$1', [p1.id]);
const { rows: [ap] } = await pool.query('SELECT prontuario, setor, paciente_nome FROM atb_fichas WHERE id=$1', [p2.atb_ficha_id]);
eq('prontuário chegou na ficha do ATB', ap.prontuario, 'PRT-4242');
eq('com o nome', ap.paciente_nome, 'CARLOS ANDRADE');
eq('e o setor neutro combinado', ap.setor, 'PS');

console.log('\n── Falha alto se a origem mudar ──');
ALVO.setor = 'Setor Inexistente';
const vs = await validarValores(pool, 'HUSF');
t('setor fora das opções também reprova', !vs.ok && /não está nas opções de setor/.test(vs.erros.join()));
ALVO.setor = 'PS';
ALVO.iras = 'IRAS_INEXISTENTE';
const { rows: [z] } = await pool.query(
  `INSERT INTO isc_fichas (instituicao_id, paciente_nome, data_cirurgia, isc_classificacao, janelas, janelas_estado)
   VALUES ($1,'TESTE FALHA',$2,'confirmada','[7,30]','{}') RETURNING id`, [inst.id, DC]);
let lancou = false;
try { await criarFichaAtbDeIsc(pool, z.id, { userId: u.id }); } catch (e) { lancou = /valores inválidos/.test(e.message); }
t('valor fora da lista canônica ABORTA (não grava lixo)', lancou);
eq('e nenhuma ficha nasceu do erro',
  (await pool.query(`SELECT count(*)::int n FROM atb_fichas WHERE paciente_nome='TESTE FALHA'`)).rows[0].n, 0);
ALVO.iras = 'ISC';

srv.close(); await pool.end();
console.log(`\n${'═'.repeat(52)}\n${ok} passaram · ${fail} falharam\n`);
process.exit(fail ? 1 : 0);
