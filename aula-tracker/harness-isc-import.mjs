// harness-isc-import.mjs — importador de mapa cirúrgico, E2E + núcleo puro.
// Mapa cirúrgico é dado sujo: cabeçalho repetido no meio, data em 4 formatos,
// nome vazio, linha remarcada duplicada, vírgula dentro do nome. O teste usa
// exatamente isso.
import express from 'express';
import { Pool } from 'pg';
import * as XLSX from 'xlsx';
import { registerIscRoutes } from './isc-routes.js';
import { registerIscImportRoutes, xlsxParaTexto } from './isc-import-routes.js';
import { runIscMigrations } from './isc-db.js';
import { renderShell } from './ui-shell.js';
import {
  detectaDelimitador, partirLinha, parseTabular, parseDataFlexivel,
  parseBoolFlexivel, parsePotencial, parseAsa, adivinhaMapeamento, montarPrevia,
  chaveDedup,
} from './isc-import.js';
import { addDays, hojeISO } from './isc-core.js';

const DB = process.env.ISC_TEST_DB || 'postgresql://postgres:x@localhost:5432/iscteste';
const pool = new Pool({ connectionString: DB });
let ok = 0, fail = 0;
const t = (n, c, x = '') => { if (c) { ok++; console.log('  ✓', n); } else { fail++; console.log('  ✗ FALHOU:', n, x); } };
const eq = (n, a, b) => t(`${n} (${JSON.stringify(a)})`, JSON.stringify(a) === JSON.stringify(b), `esperado ${JSON.stringify(b)}`);

console.log('\n── Datas (mapa cirúrgico vem em tudo quanto é formato) ──');
eq('dd/mm/yyyy', parseDataFlexivel('05/03/2026'), '2026-03-05');
eq('dd/mm/yyyy com hora', parseDataFlexivel('05/03/2026 14:30'), '2026-03-05');
eq('ISO', parseDataFlexivel('2026-03-05'), '2026-03-05');
eq('ISO com hora', parseDataFlexivel('2026-03-05T14:30:00'), '2026-03-05');
eq('dd-mm-yyyy', parseDataFlexivel('05-03-2026'), '2026-03-05');
eq('dd.mm.yyyy', parseDataFlexivel('05.03.2026'), '2026-03-05');
eq('dd/mm/yy', parseDataFlexivel('05/03/26'), '2026-03-05');
// Serial computado, não chutado: dias desde 1899-12-30.
const serial = String(Date.UTC(2026, 2, 5) / 86400000 + 25569);
eq('serial do Excel', parseDataFlexivel(serial), '2026-03-05');
eq('serial fora da faixa fica texto', parseDataFlexivel('12345'), null);
eq('31/02 não existe → null', parseDataFlexivel('31/02/2026'), null);
eq('mês 13 → null', parseDataFlexivel('05/13/2026'), null);
eq('lixo → null', parseDataFlexivel('A COMBINAR'), null);
eq('vazio → null', parseDataFlexivel(''), null);

console.log('\n── Outros parsers ──');
eq('SIM', parseBoolFlexivel('Sim'), true);
eq('X marca implante', parseBoolFlexivel('X'), true);
eq('vazio = não', parseBoolFlexivel(''), false);
eq('lixo → null (vira aviso)', parseBoolFlexivel('talvez'), null);
eq('potencial: limpa', parsePotencial('Limpa'), 'limpa');
eq('potencial: pot. contaminada', parsePotencial('Potencialmente Contaminada'), 'potencialmente_contaminada');
eq('potencial: ordem importa', parsePotencial('CONTAMINADA'), 'contaminada');
eq('potencial: infectada', parsePotencial('Infectada'), 'infectada');
eq('ASA numérico → romano', parseAsa('2'), 'II');
eq('ASA romano', parseAsa('III'), 'III');
eq('ASA "ASA II"', parseAsa('ASA II'), 'II');

console.log('\n── Delimitador e aspas ──');
eq('TAB detectado', detectaDelimitador('a\tb\tc\n1\t2\t3'), '\t');
eq('ponto-e-vírgula detectado', detectaDelimitador('a;b;c\n1;2;3'), ';');
eq('vírgula detectada', detectaDelimitador('a,b,c\n1,2,3'), ',');
eq('aspas protegem a vírgula', partirLinha('1,"SILVA, MARIA",3', ','), ['1', 'SILVA, MARIA', '3']);
eq('aspas duplas escapadas', partirLinha('a,"diz ""oi""",c', ','), ['a', 'diz "oi"', 'c']);

console.log('\n── Palpite de mapeamento ──');
let m = adivinhaMapeamento(['Paciente', 'Nº Cirurgia', 'Data da Cirurgia', 'Procedimento', 'Especialidade', 'Cirurgião']);
eq('nome', m[0], 'paciente_nome');
eq('cirurgia_id', m[1], 'cirurgia_id');
eq('data', m[2], 'data_cirurgia');
eq('procedimento', m[3], 'procedimento');
eq('equipe via "Especialidade"', m[4], 'equipe');
eq('cirurgião (com acento)', m[5], 'cirurgiao');
m = adivinhaMapeamento(['NOME DO PACIENTE', 'PRONTUARIO', 'DT CIRURGIA', 'FONE']);
eq('variantes maiúsculas/abreviadas', [m[0], m[1], m[2], m[3]], ['paciente_nome', 'prontuario', 'data_cirurgia', 'telefone']);
t('coluna desconhecida fica sem mapa', adivinhaMapeamento(['XPTO_9'])[0] === undefined);

console.log('\n── XLSX → texto ──');
const wb = XLSX.utils.book_new();
XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet([
  ['Paciente', 'Atendimento', 'Data da Cirurgia'],
  ['ANA LIMA', 'X1', '05/03/2026'],
]), 'Mapa');
const b64 = XLSX.write(wb, { type: 'base64', bookType: 'xlsx' });
const txt = xlsxParaTexto(b64);
t('xlsx vira TSV', txt.split('\n')[0] === 'Paciente\tAtendimento\tData da Cirurgia', JSON.stringify(txt.slice(0, 60)));
t('xlsx preserva linha de dados', txt.includes('ANA LIMA'));

console.log('\n── Prévia com mapa SUJO ──');
await runIscMigrations(pool);
await pool.query('TRUNCATE isc_envios, isc_contatos, isc_fichas, isc_import_lotes, isc_import_perfis RESTART IDENTITY CASCADE');
const { rows: insts } = await pool.query(`SELECT id, sigla FROM atb_instituicoes`);
const HUSF = insts.find(i => i.sigla === 'HUSF').id;
const { rows: equipes } = await pool.query(`SELECT id,nome,sigla,implante_default,janelas_default,janelas_implante FROM isc_equipes WHERE instituicao_id=$1`, [HUSF]);

const D = addDays(hojeISO(), -3);
const [yy, mm, dd] = D.split('-');
const MAPA_SUJO = [
  'Paciente;Nº Cirurgia;Data da Cirurgia;Procedimento;Especialidade;Telefone;Implante;Potencial;ASA',
  `"SILVA, MARIA DAS DORES";A100;${dd}/${mm}/${yy};Craniotomia;Neurocirurgia;(11) 91234-5678;Sim;Limpa;2`,
  `JOAO PEREIRA;A101;${dd}/${mm}/${yy};Revascularização;Cirurgia Cardíaca;11987654321;;Limpa;III`,
  '',                                                                  // linha vazia
  'Paciente;Nº Cirurgia;Data da Cirurgia;Procedimento;Especialidade;Telefone;Implante;Potencial;ASA',  // cabeçalho repetido
  `;A102;${dd}/${mm}/${yy};Colecistectomia;Cirurgia Geral;;;Contaminada;`,   // SEM NOME → erro
  `CARLOS SOUZA;A103;A COMBINAR;Hernioplastia;Cirurgia Geral;;;Limpa;`,      // data inválida → erro
  `"SILVA, MARIA DAS DORES";A100;${dd}/${mm}/${yy};Craniotomia;Neurocirurgia;;;Limpa;`,  // remarcada → dup interna
  `ANA COSTA;A104;${dd}/${mm}/${yy};Artroplastia;Ortopedia;;;Limpa;`,
  `PEDRO ALVES;A105;${dd}/${mm}/${yy};Facectomia;Oftalmologia;;;Limpa;`,     // equipe não cadastrada → aviso
].join('\n');

const { header, linhas } = parseTabular(MAPA_SUJO);
eq('linha vazia some; cabeçalho repetido NÃO (vira erro)', linhas.length, 8);
const mapa = adivinhaMapeamento(header);
const prev = montarPrevia(linhas, mapa, equipes, new Set());
// erros = cabeçalho repetido + linha sem nome + data "A COMBINAR"
// avisos = linha remarcada (dup interna) + equipe não cadastrada
eq('resumo da prévia', [prev.resumo.total, prev.resumo.novas, prev.resumo.duplicadas, prev.resumo.erros], [8, 4, 1, 3]);

const porNome = n => prev.itens.find(i => (i.ficha.paciente_nome || '').includes(n));
t('nome com vírgula preservado', porNome('SILVA')?.ficha.paciente_nome === 'SILVA, MARIA DAS DORES');
t('telefone normalizado', porNome('SILVA')?.ficha.telefone === '5511912345678');
t('equipe resolvida p/ id', porNome('SILVA')?.ficha.equipe_id === equipes.find(e => e.nome === 'Neurocirurgia').id);
t('implante do mapa respeitado', porNome('SILVA')?.ficha.implante === true);
t('ASA 2 → II', porNome('SILVA')?.ficha.asa === 'II');
t('implante_default da equipe quando mapa cala', porNome('JOAO')?.ficha.implante === true);
t('sem nome → erro', prev.itens.find(i => i.bruto.cirurgia_id === 'A102')?.status === 'erro');
t('data inválida → erro', porNome('CARLOS')?.status === 'erro');
t('erro cita o campo', porNome('CARLOS')?.erros.some(e => /Data da cirurgia/i.test(e)), JSON.stringify(porNome('CARLOS')?.erros));
t('cabeçalho repetido no meio vira erro (não ficha)', prev.itens.some(i => i.status === 'erro' && /data/i.test(i.erros.join())));
t('linha remarcada → duplicada interna', prev.itens.filter(i => i.status === 'duplicada').length === 1);
t('equipe desconhecida → aviso, não erro', porNome('PEDRO')?.status === 'nova');
t('equipe desconhecida preserva texto', porNome('PEDRO')?.ficha.especialidade === 'Oftalmologia');
t('equipe desconhecida avisa', porNome('PEDRO')?.avisos.some(a => /não cadastrada/.test(a)));

console.log('\n── Dedup contra o banco ──');
// A chave agora é prefixada (`at:` vs `cir:`) — usa chaveDedup em vez de montar à mão.
const prev2 = montarPrevia(linhas, mapa, equipes, new Set([chaveDedup({ cirurgia_id: 'A100', data_cirurgia: D })]));
eq('ficha já existente vira duplicada', prev2.resumo.novas, 3);
eq('duplicadas sobem p/ 2', prev2.resumo.duplicadas, 2);

// Daqui em diante, sem_triagem=1: este harness cobre parsing, dedup, lote e
// isolamento — o recorte clínico tem harness próprio (harness-isc-triagem).
console.log('\n── chaveDedup: ordem de confiabilidade ──');
eq('nº da cirurgia manda', chaveDedup({ cirurgia_id: '286711', prontuario: 'P1', data_cirurgia: '2026-07-13' }), 'cir:286711');
eq('sem nº → prontuário+data', chaveDedup({ prontuario: 'P1', data_cirurgia: '2026-07-13' }), 'pront:P1|2026-07-13');
eq('sem nada disso → nome+data', chaveDedup({ paciente_nome: 'Ana Silva', data_cirurgia: '2026-07-13' }), 'nome:ANA SILVA|2026-07-13');
// Cirurgia remarcada muda a data, mas não o nº → não vira ficha nova.
eq('remarcada mantém a mesma chave', chaveDedup({ cirurgia_id: '286711', data_cirurgia: '2026-07-20' }), 'cir:286711');
t('sem nome e sem data → sem chave', chaveDedup({ procedimento: 'X' }) === null);

console.log('\n── Palpite: as armadilhas de substring ──');
// "contaMINacao" contém "min" — a versão frouxa mapeava Min → potencial_contaminacao.
t('"Min" NÃO vira potencial_contaminacao', adivinhaMapeamento(['Min'])[0] !== 'potencial_contaminacao');
// No Tasy_Rel, "Cirurgia" é o nº da cirurgia — não a descrição do procedimento.
t('"Cirurgia" NÃO vira procedimento', adivinhaMapeamento(['Cirurgia'])[0] !== 'procedimento');
t('"CID" não vira nada', adivinhaMapeamento(['CID'])[0] === undefined);
// O que tem de continuar funcionando:
// "Atend" não vira mais nada: o campo atendimento foi aposentado justamente
// porque colunas parecidas ("Unid atend") caíam nele.
t('"Atend" não vira nada', adivinhaMapeamento(['Atend'])[0] === undefined);
t('"Unid atend" também não', adivinhaMapeamento(['Unid atend'])[0] === undefined);
eq('"Cirurgia" vira nº da cirurgia', adivinhaMapeamento(['Cirurgia'])[0], 'cirurgia_id');
eq('"Pront." vira prontuário', adivinhaMapeamento(['Pront.'])[0], 'prontuario');
eq('"Procedimento Principal" ainda casa', adivinhaMapeamento(['Procedimento Principal'])[0], 'procedimento');
eq('"Data da Cirurgia" ainda casa', adivinhaMapeamento(['Data da Cirurgia'])[0], 'data_cirurgia');
eq('"Paciente" ainda casa', adivinhaMapeamento(['Paciente'])[0], 'paciente_nome');

console.log('\n── Refino por valor: o rótulo mente, o dado não ──');
// Rótulo errado de propósito: no Tasy_Rel o rótulo mais próximo da data é "CID".
const linhasV = [
  ['286711', '13/07/2026 02:00', 'Rua A Itatiba SP 13250000 Fone: 1146039995 Celular: 968650910', 'Leonardo Soares de Pugas'],
  ['286715', '13/07/2026 07:55', 'Rua B Itatiba SP 13250000 Fone:  Celular: 997651317', 'Anthony Moreira Lima'],
  ['286721', '13/07/2026 08:00', 'Rua C Itatiba SP 13250000 Fone:  Celular: 964154403', 'Amanda Dorneles Barros'],
];
const mv = adivinhaMapeamento(['Cirurgia', 'CID', 'CID', 'Paciente'], linhasV);
eq('acha a data pela CARA do dado, apesar do rótulo "CID"', mv[1], 'data_cirurgia');
eq('acha o bloco de contato por "Fone:/Celular:"', mv[2], 'contato_blob');
eq('paciente pelo rótulo', mv[3], 'paciente_nome');
t('sem as linhas, a data não é achada (só o rótulo mente)', adivinhaMapeamento(['Cirurgia', 'CID', 'CID', 'Paciente'])[1] === undefined);

console.log('\n── E2E: gravar / desfazer ──');
const app = express();
app.use(express.urlencoded({ extended: true, limit: '4mb' }));
app.use(express.json());
// Sessão de médico: cobre importar + desfazer lote (ato médico). O corte de
// permissão tem harness próprio (harness-isc-perfis).
app.use((req, res, next) => { req.user = { id: 1, full_name: 'Dr. Leandro', scih: true, super_admin: true }; next(); });
registerIscRoutes(app, pool, (q, s, n) => n(), renderShell);
registerIscImportRoutes(app, pool, (q, s, n) => n(), renderShell);
const srv = app.listen(0);
const base = `http://127.0.0.1:${srv.address().port}`;
const post = (u, b) => fetch(base + u, { method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(b) });
const get = u => fetch(base + u, { redirect: 'manual' });

let r = await post('/isc/admin/importar/previa', { inst: 'HUSF', texto: MAPA_SUJO, sem_triagem: '1' });
let html = await r.text();
t('prévia renderiza', r.status === 200);
t('prévia mostra "serão criadas"', html.includes('Serão criadas'));
t('prévia mostra erro da linha ruim', html.includes('A COMBINAR') || html.includes('data não reconhecida'));
t('prévia NÃO gravou nada ainda', (await pool.query('SELECT count(*)::int n FROM isc_fichas')).rows[0].n === 0);

r = await post('/isc/admin/importar/gravar', { inst: 'HUSF', texto: MAPA_SUJO, mapa_json: JSON.stringify(mapa), sem_triagem: '1' });
t('gravar redireciona p/ grid', r.status === 302, `status=${r.status}`);
t('redirect filtra pelo lote', /lote=\d+/.test(r.headers.get('location') || ''), r.headers.get('location'));
let { rows: fs } = await pool.query('SELECT * FROM isc_fichas ORDER BY id');
eq('gravou só as 4 novas', fs.length, 4);
t('origem = import', fs.every(f => f.origem === 'import'));
t('lote carimbado', fs.every(f => f.import_lote_id === 1));
t('estado materializado no import', fs.every(f => f.proxima_janela === 7 && f.proximo_contato_em), JSON.stringify(fs.map(f => f.proxima_janela)));
const maria = fs.find(f => f.paciente_nome.includes('SILVA'));
t('implante → janelas 90d', JSON.stringify(maria.janelas) === '[7,30,90]', JSON.stringify(maria.janelas));

console.log('\n── Reimportar o mesmo mapa não duplica ──');
r = await post('/isc/admin/importar/gravar', { inst: 'HUSF', texto: MAPA_SUJO, mapa_json: JSON.stringify(mapa), sem_triagem: '1' });
eq('continua com 4 fichas', (await pool.query('SELECT count(*)::int n FROM isc_fichas')).rows[0].n, 4);
eq('lote 2 criou 0', (await pool.query('SELECT criadas FROM isc_import_lotes WHERE id=2')).rows[0].criadas, 0);

console.log('\n── Servidor não confia no browser ──');
// O browser pode mentir na classificação; o servidor recalcula a prévia.
r = await post('/isc/admin/importar/gravar', {
  inst: 'HUSF', mapa_json: JSON.stringify(mapa),
  texto: 'Paciente;Nº Cirurgia;Data da Cirurgia\n;A999;lixo',   // erro puro
  sem_triagem: '1',
});
eq('linha com erro não entra mesmo forçando', (await pool.query('SELECT count(*)::int n FROM isc_fichas')).rows[0].n, 4);

console.log('\n── Isolamento de tenant no import ──');
r = await post('/isc/admin/importar/gravar', {
  inst: 'SCMI', mapa_json: JSON.stringify(mapa),
  texto: `Paciente;Nº Cirurgia;Data da Cirurgia\nPACIENTE SCMI;S1;${dd}/${mm}/${yy}`,
  sem_triagem: '1',
});
const { rows: [sc] } = await pool.query(`SELECT * FROM isc_fichas WHERE paciente_nome='PACIENTE SCMI'`);
t('ficha vai pro tenant certo', sc.instituicao_id === insts.find(i => i.sigla === 'SCMI').id);
html = await (await get('/isc/admin/grid?inst=HUSF')).text();
t('grid HUSF não vê import do SCMI', !html.includes('PACIENTE SCMI'));

console.log('\n── Perfis de mapeamento ──');
r = await post('/isc/admin/importar/previa', { inst: 'HUSF', texto: MAPA_SUJO, salvar_perfil: '1', perfil_nome: 'Mapa HUSF', mapa_json: JSON.stringify(mapa), sem_triagem: '1' });
t('perfil salvo', (await pool.query(`SELECT count(*)::int n FROM isc_import_perfis WHERE nome='Mapa HUSF'`)).rows[0].n === 1);
r = await post('/isc/admin/importar/previa', { inst: 'HUSF', texto: MAPA_SUJO, salvar_perfil: '1', perfil_nome: 'Mapa HUSF', mapa_json: JSON.stringify(mapa), sem_triagem: '1' });
t('salvar 2x faz upsert, não duplica', (await pool.query(`SELECT count(*)::int n FROM isc_import_perfis WHERE nome='Mapa HUSF'`)).rows[0].n === 1);
const { rows: [pf] } = await pool.query(`SELECT id FROM isc_import_perfis WHERE nome='Mapa HUSF'`);
html = await (await post('/isc/admin/importar/previa', { inst: 'HUSF', texto: MAPA_SUJO, perfil_id: String(pf.id), sem_triagem: '1' })).text();
t('perfil salvo é reaplicado', html.includes('Serão criadas'));

console.log('\n── Desfazer lote ──');
// Trabalha 1 ficha: contato registrado → não pode ser apagada.
await post(`/isc/admin/ficha/${maria.id}/contato?inst=HUSF`, { janela: '7', prontuario: 'P-TESTE', r_febre: 'Não', responsavel: 'Ana' });
r = await post('/isc/admin/importar/lote/1/desfazer', { inst: 'HUSF' });
t('desfazer redireciona', r.status === 302);
({ rows: fs } = await pool.query('SELECT * FROM isc_fichas WHERE import_lote_id=1'));
eq('só a ficha com contato sobrevive', fs.length, 1);
t('a sobrevivente é a que tem contato', fs[0].id === maria.id);
t('lote marcado como desfeito', !!(await pool.query('SELECT desfeito_em FROM isc_import_lotes WHERE id=1')).rows[0].desfeito_em);

console.log('\n── Triagem LIGADA por padrão nas rotas ──');
// Sem sem_triagem=1, o recorte da fase 1 tem que valer: artroplastia fica fora.
const nAntes = (await pool.query('SELECT count(*)::int n FROM isc_fichas')).rows[0].n;
await post('/isc/admin/importar/gravar', {
  inst: 'HUSF', mapa_json: JSON.stringify({ 0: 'paciente_nome', 1: 'cirurgia_id', 2: 'data_cirurgia', 3: 'procedimento' }),
  texto: `a;b;c;d\nFORA RECORTE;T1;${dd}/${mm}/${yy};Artroplastia de joelho`,
});
eq('procedimento fora do recorte não vira ficha', (await pool.query('SELECT count(*)::int n FROM isc_fichas')).rows[0].n, nAntes);
await post('/isc/admin/importar/gravar', {
  inst: 'HUSF', mapa_json: JSON.stringify({ 0: 'paciente_nome', 1: 'cirurgia_id', 2: 'data_cirurgia', 3: 'procedimento' }),
  texto: `a;b;c;d\nDENTRO RECORTE;T2;${dd}/${mm}/${yy};OPERAÇÃO CESARIANA`,
});
eq('cesariana entra e ganha a equipe da regra', (await pool.query(
  `SELECT e.nome FROM isc_fichas f JOIN isc_equipes e ON e.id=f.equipe_id WHERE f.cirurgia_id='T2'`)).rows[0]?.nome, 'Obstetrícia');

console.log('\n── XSS via mapa cirúrgico ──');
await post('/isc/admin/importar/gravar', {
  inst: 'HUSF', mapa_json: JSON.stringify({ 0: 'paciente_nome', 1: 'cirurgia_id', 2: 'data_cirurgia' }),
  texto: `a;b;c\n<script>alert(1)</script>;XSS1;${dd}/${mm}/${yy}`,
  sem_triagem: '1',
});
html = await (await get('/isc/admin/grid?inst=HUSF')).text();
t('nome malicioso escapado no grid', !html.includes('<script>alert(1)</script>') && html.includes('&lt;script&gt;'));
html = await (await post('/isc/admin/importar/previa', { inst: 'HUSF', texto: `a;b;c\n<script>alert(2)</script>;X;${dd}/${mm}/${yy}`, sem_triagem: '1' })).text();
t('nome malicioso escapado na prévia', !html.includes('<script>alert(2)</script>'));

srv.close(); await pool.end();
console.log(`\n${'═'.repeat(52)}\n${ok} passaram · ${fail} falharam\n`);
process.exit(fail ? 1 : 0);
