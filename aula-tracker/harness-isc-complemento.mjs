// harness-isc-complemento.mjs — reimportação e complementação de dados.
//
// CENÁRIO REAL: importa-se o mapa SEM contato e, depois, o MESMO recorte COM a
// coluna endereço+fone. Antes disto, a 2ª importação dava "66 duplicadas, nada
// a fazer" e 61 telefones se perdiam calados.
//
// A regra é PREENCHER LACUNA, NUNCA SOBRESCREVER: metade deste harness testa o
// que NÃO pode acontecer — a correção manual da colaboradora sobreviver ao
// reimport, e a classificação nunca ser tocada.
import fs from 'fs';
import express from 'express';
import * as XLSX from 'xlsx';
import { Pool } from 'pg';
import { registerIscImportRoutes } from './isc-import-routes.js';
import { registerIscRoutes } from './isc-routes.js';
import { runIscMigrations } from './isc-db.js';
import { renderShell } from './ui-shell.js';
import { camposComplementaveis, montarPrevia, CAMPOS_COMPLEMENTAVEIS } from './isc-import.js';
import { normalizaAoA } from './isc-import-relatorio.js';
import { addDays, hojeISO } from './isc-core.js';

const DB = process.env.ISC_TEST_DB || 'postgresql://postgres:x@localhost:5432/iscteste';
const pool = new Pool({ connectionString: DB });
let ok = 0, fail = 0;
const t = (n, c, x = '') => { if (c) { ok++; console.log('  ✓', n); } else { fail++; console.log('  ✗ FALHOU:', n, x); } };
const eq = (n, a, b) => t(`${n} → ${JSON.stringify(a)}`, JSON.stringify(a) === JSON.stringify(b), `esperado ${JSON.stringify(b)}`);

console.log('\n── camposComplementaveis: preenche lacuna, não sobrescreve ──');
eq('campo vazio é preenchido', camposComplementaveis({ cirurgiao: null }, { cirurgiao: 'Dr X' }), { cirurgiao: 'Dr X' });
eq('string vazia conta como lacuna', camposComplementaveis({ cirurgiao: '  ' }, { cirurgiao: 'Dr X' }), { cirurgiao: 'Dr X' });
eq('campo PREENCHIDO é intocado', camposComplementaveis({ cirurgiao: 'Dr Y' }, { cirurgiao: 'Dr X' }), {});
eq('import sem o dado não apaga o que existe', camposComplementaveis({ cirurgiao: 'Dr Y' }, { cirurgiao: null }), {});
eq('nada a fazer', camposComplementaveis({ cirurgiao: 'Dr Y' }, {}), {});
t('classificação NUNCA é complementável', !CAMPOS_COMPLEMENTAVEIS.includes('isc_classificacao'));
t('tipo de ISC também não', !CAMPOS_COMPLEMENTAVEIS.includes('isc_tipo'));
t('patógeno também não', !CAMPOS_COMPLEMENTAVEIS.includes('isc_patogeno'));
t('data_cirurgia não (é chave de janela)', !CAMPOS_COMPLEMENTAVEIS.includes('data_cirurgia'));
t('janelas não (vêm da triagem)', !CAMPOS_COMPLEMENTAVEIS.includes('janelas'));

console.log('\n── Acoplamento do telefone ──');
eq('telefone entra com raw e presumido',
  camposComplementaveis({ telefone: null }, { telefone: '5511911111111', telefone_raw: '(11) 91111-1111', telefone_presumido: true }),
  { telefone: '5511911111111', telefone_raw: '(11) 91111-1111', telefone_presumido: true });
eq('telefone protegido → raw NÃO entra sozinho (mentiria)',
  camposComplementaveis({ telefone: '5511900000000', telefone_raw: null }, { telefone: '5511911111111', telefone_raw: '(11) 91111-1111', telefone_presumido: true }),
  {});
t('presumido=false também acompanha',
  camposComplementaveis({ telefone: null }, { telefone: '5511911111111' }).telefone_presumido === false);

await runIscMigrations(pool);
await pool.query('TRUNCATE isc_envios, isc_contatos, isc_fichas, isc_import_lotes RESTART IDENTITY CASCADE');
const { rows: [inst] } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla='HUSF'`);

const app = express();
app.use(express.urlencoded({ extended: true, limit: '4mb' }));
app.use((q, s, n) => { q.user = { super_admin: true }; n(); });
registerIscRoutes(app, pool, (q, s, n) => n(), renderShell);
registerIscImportRoutes(app, pool, (q, s, n) => n(), renderShell);
const srv = app.listen(0);
const B = `http://127.0.0.1:${srv.address().port}`;
const post = (u, b) => fetch(B + u, {
  method: 'POST', redirect: 'manual',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(b),
});
const n1 = async q => (await pool.query(q)).rows[0].n;

// ── Cenário sintético controlado ─────────────────────────────────────────
const D = addDays(hojeISO(), -10), Dbr = D.split('-').reverse().join('/');
// Procedimentos DENTRO do recorte da fase 1 (senão a triagem barra, e o teste
// não estaria medindo complementação).
const SEM_FONE = `Cirurgia;Atend;Paciente;Procedimento;Data
900001;A1;MARIA SILVA;OPERAÇÃO CESARIANA;${Dbr}
900002;A2;JOAO SOUZA;CRANIOTOMIA;${Dbr}`;
const COM_FONE = `Cirurgia;Atend;Paciente;Procedimento;Data;Contato;Cirurgiao
900001;A1;MARIA SILVA;OPERAÇÃO CESARIANA;${Dbr};Rua A Itatiba SP 13250000 Fone:  Celular: 968650910;Dr Alfa
900002;A2;JOAO SOUZA;CRANIOTOMIA;${Dbr};Rua B Itatiba SP 13250000 Fone:  Celular: 997651317;Dr Beta
900003;A3;ANA COSTA;OPERAÇÃO CESARIANA;${Dbr};Rua C Itatiba SP 13250000 Fone:  Celular: 964154403;Dr Gama`;
const M1 = JSON.stringify({ 0: 'cirurgia_id', 1: 'atendimento', 2: 'paciente_nome', 3: 'procedimento', 4: 'data_cirurgia' });
const M2 = JSON.stringify({ 0: 'cirurgia_id', 1: 'atendimento', 2: 'paciente_nome', 3: 'procedimento', 4: 'data_cirurgia', 5: 'contato_blob', 6: 'cirurgiao' });

console.log('\n── 1ª importação: mapa SEM contato ──');
let r = await post('/isc/admin/importar/gravar', { inst: 'HUSF', texto: SEM_FONE, mapa_json: M1, arquivo_nome: 'sem_fone.xls' });
t('grava', r.status === 302);
eq('2 fichas', await n1('SELECT count(*)::int n FROM isc_fichas'), 2);
eq('nenhuma com telefone', await n1('SELECT count(*)::int n FROM isc_fichas WHERE telefone IS NOT NULL'), 0);

console.log('\n── A colaboradora corrige um telefone na mão ──');
await pool.query(`UPDATE isc_fichas SET telefone='5511900000000', telefone_presumido=false WHERE cirurgia_id='900001'`);
// e o médico classifica essa mesma ficha
await pool.query(`UPDATE isc_fichas SET isc_classificacao='confirmada', isc_tipo='incisional_profunda',
                  isc_patogeno='S. aureus', classificado_por='Dr. Leandro', classificado_em=now() WHERE cirurgia_id='900001'`);

console.log('\n── 2ª importação: mesmo recorte, COM contato ──');
let html = await (await post('/isc/admin/importar/previa', { inst: 'HUSF', texto: COM_FONE, mapa_json: M2 })).text();
t('prévia anuncia complementação', html.includes('Serão complementadas'));
t('mostra QUAIS campos vai preencher', html.includes('Vai preencher:'));
t('e avisa que não sobrescreve', html.includes('preenche campo vazio'));
t('botão soma criar + complementar', /Criar 1 ficha\(s\) · complementar 2/.test(html), 'botão errado');

r = await post('/isc/admin/importar/gravar', { inst: 'HUSF', texto: COM_FONE, mapa_json: M2, arquivo_nome: 'com_fone.xls' });
t('grava', r.status === 302);
eq('agora 3 fichas (1 nova)', await n1('SELECT count(*)::int n FROM isc_fichas'), 3);
eq('todas com telefone', await n1('SELECT count(*)::int n FROM isc_fichas WHERE telefone IS NOT NULL'), 3);
eq('cirurgião complementado', await n1(`SELECT count(*)::int n FROM isc_fichas WHERE cirurgiao IS NOT NULL`), 3);

console.log('\n── ⚠ O QUE NÃO PODE ACONTECER ──');
let { rows: [f1] } = await pool.query(`SELECT * FROM isc_fichas WHERE cirurgia_id='900001'`);
eq('telefone corrigido À MÃO sobreviveu', f1.telefone, '5511900000000');
t('e não virou "presumido"', f1.telefone_presumido === false);
t('telefone_raw NÃO entrou sozinho', !f1.telefone_raw, `raw=${f1.telefone_raw}`);
eq('classificação intacta', f1.isc_classificacao, 'confirmada');
eq('tipo intacto', f1.isc_tipo, 'incisional_profunda');
eq('patógeno intacto', f1.isc_patogeno, 'S. aureus');
eq('autoria intacta', f1.classificado_por, 'Dr. Leandro');
t('mas o cirurgião (que faltava) foi complementado', f1.cirurgiao === 'Dr Alfa', f1.cirurgiao);

const { rows: [f2] } = await pool.query(`SELECT * FROM isc_fichas WHERE cirurgia_id='900002'`);
t('ficha não tocada recebeu o telefone do mapa', /^55\d{11}$/.test(f2.telefone || ''), f2.telefone);
t('e ficou marcada como DDD presumido', f2.telefone_presumido === true);
t('com o telefone_raw junto', !!f2.telefone_raw);

console.log('\n── 3ª importação: idempotente ──');
r = await post('/isc/admin/importar/gravar', { inst: 'HUSF', texto: COM_FONE, mapa_json: M2 });
eq('continua com 3 fichas', await n1('SELECT count(*)::int n FROM isc_fichas'), 3);
const { rows: [l3] } = await pool.query(`SELECT * FROM isc_import_lotes ORDER BY id DESC LIMIT 1`);
eq('lote 3: nada criado', l3.criadas, 0);
eq('lote 3: nada complementado (não sobrou lacuna)', l3.complementadas, 0);
eq('lote 3: tudo ignorado', l3.ignoradas, 3);
html = await (await post('/isc/admin/importar/previa', { inst: 'HUSF', texto: COM_FONE, mapa_json: M2 })).text();
t('prévia agora diz "já existe"', html.includes('já existe'));

console.log('\n── Contadores do lote ──');
const { rows: lotes } = await pool.query(`SELECT * FROM isc_import_lotes ORDER BY id`);
eq('lote 1: 2 criadas', [lotes[0].criadas, lotes[0].complementadas], [2, 0]);
eq('lote 2: 1 criada, 2 complementadas', [lotes[1].criadas, lotes[1].complementadas], [1, 2]);
html = await (await fetch(B + '/isc/admin/importar?inst=HUSF')).text();
t('histórico mostra as complementações', html.includes('2 complementadas'));
t('e avisa que desfazer não reverte complemento', html.includes('NÃO voltam atrás'));

console.log('\n── Desfazer só apaga o que o lote CRIOU ──');
r = await post('/isc/admin/importar/lote/2/desfazer', { inst: 'HUSF' });
t('desfaz', r.status === 302);
eq('sobraram as 2 do lote 1', await n1('SELECT count(*)::int n FROM isc_fichas'), 2);
t('complemento do lote 2 permanece (não há snapshot)',
  !!(await pool.query(`SELECT telefone FROM isc_fichas WHERE cirurgia_id='900002'`)).rows[0].telefone);

console.log('\n── Isolamento de tenant na complementação ──');
const { rows: [scmi] } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla='SCMI'`);
await pool.query(`INSERT INTO isc_fichas (instituicao_id, cirurgia_id, atendimento, paciente_nome, data_cirurgia)
                  VALUES ($1,'900002','A2','SCMI HOMONIMO',$2)`, [scmi.id, D]);
r = await post('/isc/admin/importar/gravar', { inst: 'HUSF', texto: COM_FONE, mapa_json: M2 });
const { rows: [sc] } = await pool.query(`SELECT * FROM isc_fichas WHERE paciente_nome='SCMI HOMONIMO'`);
t('ficha do SCMI com mesmo nº de cirurgia NÃO foi complementada pelo HUSF', !sc.telefone && !sc.cirurgiao);

// ── Os arquivos reais ────────────────────────────────────────────────────
const F1 = '/mnt/user-data/uploads/mapa_teste.XLS', F2 = '/mnt/user-data/uploads/mapa_fone.XLS';
if (fs.existsSync(F1) && fs.existsSync(F2)) {
  console.log('\n── ARQUIVOS REAIS: sem contato → com contato ──');
  await pool.query('TRUNCATE isc_envios, isc_contatos, isc_fichas, isc_import_lotes RESTART IDENTITY CASCADE');
  const ler = f => {
    const wb = XLSX.read(fs.readFileSync(f), { type: 'buffer', codepage: 1252 });
    return normalizaAoA(XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]], { header: 1, raw: true, defval: '', blankrows: true }), 'auto');
  };
  const A = ler(F1), Bx = ler(F2);
  const mA = { 0: 'cirurgia_id', 3: 'atendimento', 5: 'procedimento', 7: 'data_cirurgia', 12: 'duracao_min', 13: 'paciente_nome', 22: 'cirurgiao' };
  const mB = { 0: 'cirurgia_id', 3: 'atendimento', 5: 'procedimento', 6: 'contato_blob', 8: 'data_cirurgia', 13: 'duracao_min', 14: 'paciente_nome', 23: 'cirurgiao', 26: 'tipo_anestesia' };

  const p1 = montarPrevia(A.linhas, mA, [], new Map(), null);
  for (const it of p1.itens.filter(x => x.status === 'nova')) {
    const f = it.ficha;
    await pool.query(
      `INSERT INTO isc_fichas (instituicao_id, cirurgia_id, atendimento, paciente_nome, procedimento,
         data_cirurgia, cirurgiao, duracao_min, origem) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'import')`,
      [inst.id, f.cirurgia_id, f.atendimento, f.paciente_nome, f.procedimento, f.data_cirurgia, f.cirurgiao, f.duracao_min || null]);
  }
  eq('1ª: 66 fichas, 0 telefones', [await n1('SELECT count(*)::int n FROM isc_fichas'), await n1('SELECT count(*)::int n FROM isc_fichas WHERE telefone IS NOT NULL')], [66, 0]);

  const cols = ['id', 'cirurgia_id', 'atendimento', 'data_cirurgia', ...CAMPOS_COMPLEMENTAVEIS].filter((c, i, a) => a.indexOf(c) === i).join(',');
  const { rows } = await pool.query(`SELECT ${cols} FROM isc_fichas`);
  const mapaEx = new Map(rows.map(r => [`cir:${r.cirurgia_id}`, r]));
  const p2 = montarPrevia(Bx.linhas, mB, [], mapaEx, null);
  eq('2ª: 1 nova, 66 complementa, 0 duplicada', [p2.resumo.novas, p2.resumo.complementa, p2.resumo.duplicadas], [1, 66, 0]);
  const comTel = p2.itens.filter(i => i.complemento && 'telefone' in i.complemento.campos).length;
  t(`${comTel} telefones que antes se perdiam agora entram`, comTel >= 60, `só ${comTel}`);
  t('todo complemento tem id de ficha', p2.itens.filter(i => i.status === 'complementa').every(i => i.complemento.id > 0));
} else {
  console.log('\n(arquivos reais ausentes — só o cenário sintético rodou)');
}

srv.close(); await pool.end();
console.log(`\n${'═'.repeat(52)}\n${ok} passaram · ${fail} falharam\n`);
process.exit(fail ? 1 : 0);
