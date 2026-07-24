// harness-isc-pront.mjs — layout do Tasy_Rel muda de colunas.
//
// O relatório tem LARGURA FIXA: cada coluna pedida entra no lugar de outra. Já
// circularam três combinações:
//   v1  A=nº cirurgia   D=atendimento
//   v2  A=prontuário    D=atendimento
//   v3  A=nº cirurgia   D=prontuário     ← atual
//
// O que precisa continuar valendo em qualquer transição:
//   1. o perfil semeado migra — SEM atropelar customização do operador;
//   2. reimportar o mesmo período em OUTRO layout não duplica ficha;
//   3. o campo que faltava é COMPLEMENTADO na ficha já existente.
// Duplicar aqui significaria o paciente recebendo toda a busca ativa de novo.
import fs from 'fs';
import * as XLSX from 'xlsx';
import { Pool } from 'pg';
import { runIscMigrations } from './isc-db.js';
import { normalizaAoA } from './isc-import-relatorio.js';
import {
  montarPrevia, chaveDedup, chavesDedup, adivinhaMapeamento,
  CAMPOS_COMPLEMENTAVEIS, CAMPOS_IMPORTAVEIS,
} from './isc-import.js';
import { toISODate } from './isc-core.js';

const DB = process.env.ISC_TEST_DB || 'postgresql://postgres:x@localhost:5432/iscteste';
const pool = new Pool({ connectionString: DB });
let ok = 0, fail = 0;
const t = (n, c, x = '') => { if (c) { ok++; console.log('  ✓', n); } else { fail++; console.log('  ✗ FALHOU:', n, x); } };
const eq = (n, a, b) => t(`${n} → ${JSON.stringify(a)}`, JSON.stringify(a) === JSON.stringify(b), `esperado ${JSON.stringify(b)}`);

const BASE = {
  5: 'procedimento', 6: 'contato_blob', 8: 'data_cirurgia',
  13: 'duracao_min', 14: 'paciente_nome', 23: 'cirurgiao', 26: 'tipo_anestesia',
};
const MAPA_V1 = { ...BASE, 0: 'cirurgia_id', 3: 'atendimento' };
const MAPA_V2 = { ...BASE, 0: 'prontuario', 3: 'atendimento' };
const MAPA_V3 = { ...BASE, 0: 'cirurgia_id', 3: 'prontuario' };   // atual

await runIscMigrations(pool);
const { rows: [inst] } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla='HUSF'`);

console.log('\n── Perfil semeado migrou para prontuário ──');
const { rows: [pf] } = await pool.query(
  `SELECT * FROM isc_import_perfis WHERE nome='Tasy_Rel — Relação das Cirurgias' AND instituicao_id=$1`, [inst.id]);
t('perfil existe', !!pf);
eq('coluna A = nº da cirurgia', pf.mapeamento['0'], 'cirurgia_id');
eq('coluna D = prontuário', pf.mapeamento['3'], 'prontuario');
eq('demais colunas intactas', [pf.mapeamento['8'], pf.mapeamento['14'], pf.mapeamento['6']],
  ['data_cirurgia', 'paciente_nome', 'contato_blob']);

console.log('\n── Migração NÃO atropela customização do operador ──');
// Perfil ajustado à mão: a migração tem de deixar em paz.
const custom = { ...MAPA_V1, 13: 'observacao' };
await pool.query(
  `INSERT INTO isc_import_perfis (instituicao_id, nome, mapeamento, delim)
   VALUES ($1,'Perfil do operador',$2::jsonb, E'\\t')
   ON CONFLICT (instituicao_id, nome) DO UPDATE SET mapeamento=EXCLUDED.mapeamento`,
  [inst.id, JSON.stringify(custom)]);
// Também devolve o perfil semeado ao layout antigo, para exercitar a migração.
await pool.query(
  `UPDATE isc_import_perfis SET mapeamento=$2::jsonb
    WHERE instituicao_id=$1 AND nome='Tasy_Rel — Relação das Cirurgias'`,
  [inst.id, JSON.stringify(MAPA_V1)]);
await runIscMigrations(pool);
const { rows: [pf2] } = await pool.query(
  `SELECT mapeamento FROM isc_import_perfis WHERE instituicao_id=$1 AND nome='Tasy_Rel — Relação das Cirurgias'`, [inst.id]);
eq('perfil semeado v1 migra sozinho', pf2.mapeamento['0'], 'cirurgia_id');
eq('e ganha o prontuário na D', pf2.mapeamento['3'], 'prontuario');
const { rows: [pc] } = await pool.query(
  `SELECT mapeamento FROM isc_import_perfis WHERE instituicao_id=$1 AND nome='Perfil do operador'`, [inst.id]);
eq('perfil CUSTOMIZADO fica como estava', pc.mapeamento['0'], 'cirurgia_id');
eq('inclusive o ajuste manual', pc.mapeamento['13'], 'observacao');

console.log('\n── Chaves de dedup por layout ──');
eq('v1 gera nº de cirurgia + atendimento',
  chavesDedup({ cirurgia_id: '287094', atendimento: '4929063', data_cirurgia: '2026-07-23' }),
  ['cir:287094', 'at:4929063|2026-07-23']);
eq('v2 gera atendimento + prontuário',
  chavesDedup({ prontuario: '954386', atendimento: '4929063', data_cirurgia: '2026-07-23' }),
  ['at:4929063|2026-07-23', 'pront:954386|2026-07-23']);
eq('v3 gera nº de cirurgia + prontuário',
  chavesDedup({ cirurgia_id: '287094', prontuario: '954386', data_cirurgia: '2026-07-23' }),
  ['cir:287094', 'pront:954386|2026-07-23']);
eq('a principal continua sendo a mais confiável',
  chaveDedup({ cirurgia_id: '287094', prontuario: '954386', data_cirurgia: '2026-07-23' }), 'cir:287094');
t('prontuário sem data não vira chave (mesmo paciente opera mais de uma vez)',
  chavesDedup({ prontuario: '954386' }).length === 0);
t('linha sem nada identificável não tem chave', chaveDedup({ paciente_nome: 'X' }) === null);

console.log('\n── Transições entre layouts NÃO duplicam ──');
const LINHA = { cirurgia_id: '287094', prontuario: '954386', atendimento: '4929063',
                data_cirurgia: '2026-07-23', paciente_nome: 'Margareth Farias' };
async function reimporta(fichaAntiga, mapaLinha) {
  await pool.query('TRUNCATE isc_envios, isc_contatos, isc_fichas, isc_import_lotes RESTART IDENTITY CASCADE');
  await pool.query(
    `INSERT INTO isc_fichas (instituicao_id, cirurgia_id, atendimento, prontuario, paciente_nome, data_cirurgia, procedimento)
     VALUES ($1,$2,$3,$4,'MARGARETH FARIAS','2026-07-23','MARCAPASSO')`,
    [inst.id, fichaAntiga.cirurgia_id || null, fichaAntiga.atendimento || null, fichaAntiga.prontuario || null]);
  const cols = ['id', 'cirurgia_id', 'atendimento', 'prontuario', 'data_cirurgia', ...CAMPOS_COMPLEMENTAVEIS]
    .filter((c, i, a) => a.indexOf(c) === i).join(',');
  const { rows } = await pool.query(`SELECT ${cols} FROM isc_fichas`);
  const ex = new Map();
  for (const r of rows) for (const k of chavesDedup(r)) if (!ex.has(k)) ex.set(k, r);
  const campos = Object.values(mapaLinha);
  const linha = campos.map(c => c === 'data_cirurgia' ? '23/07/2026' : (LINHA[c] ?? ''));
  const mapa = Object.fromEntries(campos.map((c, i) => [i, c]));
  return montarPrevia([linha], mapa, [], ex, null);
}
const M3 = { 0: 'cirurgia_id', 1: 'prontuario', 2: 'data_cirurgia', 3: 'paciente_nome' };
const M2 = { 0: 'prontuario', 1: 'atendimento', 2: 'data_cirurgia', 3: 'paciente_nome' };
const M1 = { 0: 'cirurgia_id', 1: 'atendimento', 2: 'data_cirurgia', 3: 'paciente_nome' };  // 'atendimento' já não existe: será ignorado

let p1 = await reimporta({ cirurgia_id: '287094', atendimento: '4929063' }, M3);
eq('ficha v1 + linha v3 → complementa (casa pelo nº da cirurgia)', [p1.resumo.novas, p1.resumo.complementa], [0, 1]);
eq('e ganha o prontuário que faltava', Object.keys(p1.complemento || p1.itens[0].complemento.campos), ['prontuario']);

// O caso que exigiu a lista de chaves: v2 não tem nº de cirurgia, v3 não tem
// atendimento — só o prontuário+data liga as duas.
let p2 = await reimporta({ prontuario: '954386', atendimento: '4929063' }, M3);
eq('ficha v2 + linha v3 → complementa (casa pelo prontuário+data)', [p2.resumo.novas, p2.resumo.complementa], [0, 1]);
eq('e ganha o nº da cirurgia', Object.keys(p2.itens[0].complemento.campos), ['cirurgia_id']);

// Layout v1 lido HOJE: casa pelo nº da cirurgia, mas nada a somar — a coluna de
// atendimento é simplesmente ignorada, porque o campo foi aposentado.
let p3 = await reimporta({ cirurgia_id: '287094', prontuario: '954386' }, M1);
eq('ficha v3 + linha v1 → reconhecida, nada a somar', [p3.resumo.novas, p3.resumo.duplicadas], [0, 1]);
t('e o atendimento do arquivo antigo é ignorado', !p3.itens[0].ficha.atendimento);

let p4 = await reimporta({ cirurgia_id: '287094', prontuario: '954386' }, M3);
eq('mesmo layout duas vezes → nada a fazer', [p4.resumo.novas, p4.resumo.duplicadas], [0, 1]);

// Cirurgia diferente do mesmo paciente noutro dia continua sendo ficha nova.
await pool.query('TRUNCATE isc_envios, isc_contatos, isc_fichas RESTART IDENTITY CASCADE');
await pool.query(
  `INSERT INTO isc_fichas (instituicao_id, cirurgia_id, prontuario, paciente_nome, data_cirurgia)
   VALUES ($1,'287094','954386','MARGARETH','2026-07-23')`, [inst.id]);
const { rows: r2 } = await pool.query(
  `SELECT id, cirurgia_id, atendimento, prontuario, data_cirurgia FROM isc_fichas`);
const ex2 = new Map();
for (const r of r2) for (const k of chavesDedup(r)) ex2.set(k, r);
const outra = montarPrevia([['999999', '954386', '30/07/2026', 'MARGARETH']], M3, [], ex2, null);
eq('mesma paciente, outra cirurgia/dia → ficha NOVA', outra.resumo.novas, 1);

console.log('\n── Diagnóstico da dedup (o que explica "N fichas novas") ──');
await pool.query('TRUNCATE isc_envios, isc_contatos, isc_fichas RESTART IDENTITY CASCADE');
await pool.query(
  `INSERT INTO isc_fichas (instituicao_id, cirurgia_id, atendimento, paciente_nome, data_cirurgia)
   VALUES ($1,'286711','4923414','ANTIGA','2026-07-13')`, [inst.id]);
const { rows: rd } = await pool.query(`SELECT id, cirurgia_id, atendimento, prontuario, paciente_nome, data_cirurgia FROM isc_fichas`);
const exD = new Map();
for (const r of rd) for (const k of chavesDedup(r)) exD.set(k, r);

// Linha de OUTRO período: não casa — e isso é o comportamento CORRETO.
const outroPeriodo = montarPrevia([['287094', '954386', '23/07/2026', 'NOVA']],
  { 0: 'cirurgia_id', 1: 'prontuario', 2: 'data_cirurgia', 3: 'paciente_nome' }, [], exD, null);
eq('período diferente → ficha nova (correto)', outroPeriodo.resumo.novas, 1);
eq('diagnóstico conta as fichas existentes', outroPeriodo.dedup.fichasNoSistema, 1);
eq('e mostra os tipos de chave dos dois lados',
  [Object.keys(outroPeriodo.dedup.porTipoNoSistema).sort(), Object.keys(outroPeriodo.dedup.porTipoNoArquivo).sort()],
  [['at', 'cir', 'nome'], ['cir', 'nome', 'pront']]);
eq('nenhuma casou', outroPeriodo.dedup.casaram, 0);
t('a linha expõe sua chave, para conferência', outroPeriodo.itens[0].chaves.includes('cir:287094'));

// Mesma cirurgia → casa, e o diagnóstico registra.
const mesmo = montarPrevia([['286711', '954386', '13/07/2026', 'ANTIGA']],
  { 0: 'cirurgia_id', 1: 'prontuario', 2: 'data_cirurgia', 3: 'paciente_nome' }, [], exD, null);
eq('mesma cirurgia → complementa', [mesmo.resumo.novas, mesmo.resumo.complementa], [0, 1]);
eq('diagnóstico registra que casou', mesmo.dedup.casaram, 1);

// Sem nº de cirurgia e sem prontuário, nome+data ainda identifica a ficha —
// é o último recurso, e o aviso na linha diz isso.
const soNome = montarPrevia([['', '', '13/07/2026', 'SO NOME']],
  { 0: 'cirurgia_id', 1: 'prontuario', 2: 'data_cirurgia', 3: 'paciente_nome' }, [], exD, null);
eq('vira ficha', soNome.resumo.novas, 1);
eq('e ainda tem chave (nome+data)', soNome.itens[0].chaves, ['nome:SO NOME|2026-07-13']);
t('mas avisa que a identificação é fraca',
  soNome.itens[0].avisos.some(a => /nome \+ data/.test(a)), JSON.stringify(soNome.itens[0].avisos));
eq('não conta como sem chave', soNome.dedup.semChave, 0);

// Regressão: linha FORA DO RECORTE também calcula chaves. Sem isso, um mapa
// mensal com 425 procedimentos fora do recorte disparava um alarme vermelho
// de "425 linhas sem chave de deduplicação" que não queria dizer nada.
const regrasReais = (await pool.query('SELECT * FROM isc_triagem_regras WHERE ativo ORDER BY ordem, id')).rows;
const comTriagem = montarPrevia(
  [['286355', '823269', '01/07/2026', 'FULANO', 'PARTO NORMAL'],
   ['286356', '823270', '01/07/2026', 'CICLANA', 'OPERAÇÃO CESARIANA']],
  { 0: 'cirurgia_id', 1: 'prontuario', 2: 'data_cirurgia', 3: 'paciente_nome', 4: 'procedimento' },
  [], new Map(), regrasReais);
eq('1 entra, 1 fica fora', [comTriagem.resumo.novas, comTriagem.resumo.fora_recorte], [1, 1]);
eq('linha fora do recorte NÃO conta como sem chave', comTriagem.dedup.semChave, 0);
t('e ela tem chaves calculadas',
  comTriagem.itens.find(i => i.status === 'fora_recorte').chaves.length === 3);

console.log('\n── Atendimento aposentado da importação ──');
// Foi o campo `atendimento` mapeável que permitiu o erro: a coluna "Unid atend"
// (unidade + leito, "10 01") virou atendimento, e a chave virou `at:10 01|data`.
t('atendimento NÃO é mais campo importável',
  !CAMPOS_IMPORTAVEIS.some(c => c.key === 'atendimento'));
const rot = [];
[[0, 'Cirurgia'], [3, 'Pront.'], [5, 'Procedimento Principal'], [6, 'Procedimento Principal'],
 [8, 'CID'], [13, 'Min'], [14, 'Paciente'], [17, 'Unid atend'], [19, 'Idade'], [20, 'Convênio'],
 [23, 'Cirurgião'], [24, 'Anestesista'], [26, 'Tipo']].forEach(([i, r]) => { rot[i] = r; });
const palpite = adivinhaMapeamento(rot);
eq('"Cirurgia" → nº da cirurgia', palpite[0], 'cirurgia_id');
eq('"Pront." → prontuário', palpite[3], 'prontuario');
eq('"Min" → duração', palpite[13], 'duracao_min');
t('"Unid atend" NÃO vira atendimento (nem nada)', !palpite[17], palpite[17]);
t('nenhuma coluna vira atendimento', !Object.values(palpite).includes('atendimento'));

console.log('\n── Ficha legada (só atendimento) é reconhecida e migrada ──');
await pool.query('TRUNCATE isc_envios, isc_contatos, isc_fichas RESTART IDENTITY CASCADE');
await pool.query(
  `INSERT INTO isc_fichas (instituicao_id, paciente_nome, atendimento, data_cirurgia, procedimento)
   VALUES ($1,'Sueli Cristina de Oliveira','4923427','2026-07-13','OPERAÇÃO CESARIANA COM LAQUEADURA TUBARIA')`,
  [inst.id]);
const { rows: rl } = await pool.query(
  `SELECT id, cirurgia_id, atendimento, prontuario, paciente_nome, data_cirurgia FROM isc_fichas`);
const exL = new Map();
for (const r of rl) for (const k of chavesDedup(r)) exL.set(k, r);
t('a ficha legada só tem chaves at: e nome:',
  [...exL.keys()].every(k => /^(at|nome):/.test(k)), JSON.stringify([...exL.keys()]));

const linhaNova = montarPrevia([['286798', '922514', '13/07/2026', 'Sueli Cristina de Oliveira']],
  { 0: 'cirurgia_id', 1: 'prontuario', 2: 'data_cirurgia', 3: 'paciente_nome' }, [], exL, null);
eq('reconhecida, não duplicada', [linhaNova.resumo.novas, linhaNova.resumo.complementa], [0, 1]);
eq('casou pela ponte nome+data', linhaNova.itens[0].casouPor, 'nome:SUELI CRISTINA DE OLIVEIRA|2026-07-13');
eq('e recebe os dois identificadores novos',
  Object.keys(linhaNova.itens[0].complemento.campos).sort(), ['cirurgia_id', 'prontuario']);

console.log('\n── TRAVA: mesmo paciente, mesmo dia, cirurgias diferentes ──');
// No mapa de julho há 3 casos reais assim (ex.: cirurgias 286355 e 286333 na
// mesma paciente, no mesmo dia). Sem a trava, a segunda seria engolida pela
// primeira via prontuário+data ou nome+data.
await pool.query('TRUNCATE isc_fichas RESTART IDENTITY CASCADE');
await pool.query(
  `INSERT INTO isc_fichas (instituicao_id, cirurgia_id, prontuario, paciente_nome, data_cirurgia)
   VALUES ($1,'286355','823269','ALINE APARECIDA BUENO DE ALMEIDA','2026-07-01')`, [inst.id]);
const { rows: rt } = await pool.query(
  `SELECT id, cirurgia_id, atendimento, prontuario, paciente_nome, data_cirurgia FROM isc_fichas`);
const exT = new Map();
for (const r of rt) for (const k of chavesDedup(r)) exT.set(k, r);
const outraCirurgia = montarPrevia([['286333', '823269', '01/07/2026', 'Aline Aparecida Bueno de Almeida']],
  { 0: 'cirurgia_id', 1: 'prontuario', 2: 'data_cirurgia', 3: 'paciente_nome' }, [], exT, null);
eq('cirurgia diferente NÃO é engolida', outraCirurgia.resumo.novas, 1);
t('mesmo compartilhando prontuário e nome no mesmo dia',
  exT.has('pront:823269|2026-07-01') && exT.has('nome:ALINE APARECIDA BUENO DE ALMEIDA|2026-07-01'));
// E o inverso continua valendo: MESMO nº de cirurgia casa.
const mesmaCirurgia = montarPrevia([['286355', '823269', '01/07/2026', 'ALINE APARECIDA BUENO DE ALMEIDA']],
  { 0: 'cirurgia_id', 1: 'prontuario', 2: 'data_cirurgia', 3: 'paciente_nome' }, [], exT, null);
eq('mesmo nº de cirurgia casa', mesmaCirurgia.resumo.novas, 0);

console.log('\n── Uma ficha só pode ser reivindicada por UMA linha ──');
// No mapa de julho há 3 pacientes operados DUAS vezes no mesmo dia. Se a ficha
// antiga (que só tem atendimento) casa por nome+data, as duas linhas apontariam
// para ela — e a segunda cirurgia sumiria, sem virar ficha e sem aviso.
await pool.query('TRUNCATE isc_fichas RESTART IDENTITY CASCADE');
await pool.query(
  `INSERT INTO isc_fichas (instituicao_id, atendimento, paciente_nome, data_cirurgia)
   VALUES ($1,'4923400','AMANDA DORNELES BARROS','2026-07-13')`, [inst.id]);
const { rows: rr } = await pool.query(
  `SELECT id, cirurgia_id, atendimento, prontuario, paciente_nome, data_cirurgia FROM isc_fichas`);
const exR = new Map();
for (const r of rr) for (const k of chavesDedup(r)) exR.set(k, r);
const duas = montarPrevia(
  [['286728', '915188', '13/07/2026', 'Amanda Dorneles Barros'],
   ['286721', '915188', '13/07/2026', 'Amanda Dorneles Barros']],
  { 0: 'cirurgia_id', 1: 'prontuario', 2: 'data_cirurgia', 3: 'paciente_nome' }, [], exR, null);
eq('1 complementa + 1 nova (nenhuma cirurgia some)', [duas.resumo.complementa, duas.resumo.novas], [1, 1]);
eq('só a 1ª reivindica a ficha antiga', duas.itens[0].complemento.id, rr[0].id);
t('a 2ª vira ficha própria', duas.itens[1].status === 'nova' && !duas.itens[1].complemento);
t('e as duas mantêm nº de cirurgia distinto',
  duas.itens[0].ficha.cirurgia_id !== duas.itens[1].ficha.cirurgia_id);

// ── Arquivo real ─────────────────────────────────────────────────────────
const REAL = '/mnt/user-data/uploads/mapa_pront_teste2.XLS';
if (fs.existsSync(REAL)) {
  console.log('\n── ARQUIVO REAL (Tasy_Rel com prontuário) ──');
  const wb = XLSX.read(fs.readFileSync(REAL), { type: 'buffer', codepage: 1252 });
  const aoa = XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]], { header: 1, raw: true, defval: '', blankrows: true });
  const o = normalizaAoA(aoa, 'auto');
  eq('layout de impressão detectado', o.diagnostico.modo, 'relatorio');
  eq('11 registros', o.diagnostico.registros, 11);
  t('coluna do contato (G) capturada', o.colunasUteis.includes(6));

  const p = montarPrevia(o.linhas, MAPA_V3, [], new Map(), null);
  eq('11 fichas, 0 erro', [p.resumo.novas, p.resumo.erros], [11, 0]);
  eq('11 prontuários preenchidos', p.itens.filter(i => i.ficha.prontuario).length, 11);
  eq('11 prontuários distintos', new Set(p.itens.map(i => i.ficha.prontuario)).size, 11);
  eq('11 nº de cirurgia preenchidos', p.itens.filter(i => i.ficha.cirurgia_id).length, 11);
  eq('11 nº de cirurgia distintos', new Set(p.itens.map(i => i.ficha.cirurgia_id)).size, 11);
  eq('11 telefones resolvidos', p.itens.filter(i => i.ficha.telefone).length, 11);
  t('todo prontuário tem 6 dígitos', p.itens.every(i => /^\d{6}$/.test(i.ficha.prontuario)));
  t('nenhuma ficha traz atendimento (a coluna saiu do relatório)',
    p.itens.every(i => !i.ficha.atendimento));
  t('toda ficha tem chave de dedup pelo nº da cirurgia',
    p.itens.every(i => /^cir:/.test(chaveDedup(i.ficha))));

  // A prova de qual coluna é qual, sem confiar no rótulo: DISPERSÃO. Nº de
  // cirurgia é sequência emitida no período (gap pequeno); prontuário é cadastro
  // acumulado de anos (gap enorme). Os dois no mesmo arquivo tornam o teste direto.
  const gapMedio = arr => {
    const n = arr.map(Number).sort((a, b) => a - b);
    return n.slice(1).reduce((s, v, i) => s + (v - n[i]), 0) / (n.length - 1);
  };
  const gCir = gapMedio(p.itens.map(i => i.ficha.cirurgia_id));
  const gPro = gapMedio(p.itens.map(i => i.ficha.prontuario));
  t(`col A é sequencial (gap ${Math.round(gCir)}) → nº de cirurgia`, gCir < 100);
  t(`col D é dispersa (gap ${Math.round(gPro)}) → prontuário`, gPro > 1000);
  t('e a diferença é de ordens de grandeza', gPro / gCir > 100);

  eq('1º paciente', p.itens[0].ficha.paciente_nome, 'Margareth Farias');
  eq('1º prontuário', p.itens[0].ficha.prontuario, '954386');
  eq('todas na mesma data', new Set(p.itens.map(i => i.ficha.data_cirurgia)).size, 1);

  console.log('\n── Triagem no arquivo real ──');
  const { rows: regras } = await pool.query('SELECT * FROM isc_triagem_regras WHERE ativo ORDER BY ordem, id');
  const { rows: eqs } = await pool.query(
    'SELECT id,nome,sigla,implante_default,janelas_default,janelas_implante FROM isc_equipes WHERE instituicao_id=$1', [inst.id]);
  const pt = montarPrevia(o.linhas, MAPA_V3, eqs, new Map(), regras);
  eq('3 entram, 8 fora', [pt.resumo.novas, pt.resumo.fora_recorte], [3, 8]);
  const nome = id => (eqs.find(e => e.id === id) || {}).nome;
  const dentro = pt.itens.filter(i => i.status === 'nova').map(i => nome(i.ficha.equipe_id)).sort();
  eq('2 cesarianas + 1 cardíaca', dentro, ['Cirurgia Cardíaca', 'Obstetrícia', 'Obstetrícia']);
  t('"Cesariana" (forma curta) também casa',
    pt.itens.some(i => i.status === 'nova' && /^Cesariana$/i.test(i.ficha.procedimento)));
  t('marcapasso entra como implante (90 dias)',
    pt.itens.some(i => /MARCAPASSO/i.test(i.ficha.procedimento) && i.ficha.implante === true));
} else {
  console.log('\n(arquivo real ausente — só o cenário sintético rodou)');
}

await pool.end();
console.log(`\n${'═'.repeat(52)}\n${ok} passaram · ${fail} falharam\n`);
process.exit(fail ? 1 : 0);
