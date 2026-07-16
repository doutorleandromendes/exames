// harness-isc-relatorio.mjs — normalizador de layout de impressão (Tasy_Rel).
//
// A fixture sintética replica EXATAMENTE as manhas do "Relação das Cirurgias":
//   • linhas 0-1 = título/período (não cabeçalho)
//   • linha 2 = cabeçalho, com rótulos FORA da coluna do dado
//   • texto longo quebrado em linhas de continuação
//   • rodapé "Total minutos:" em colunas que nenhum registro usa
// Assim o teste roda em qualquer máquina, sem depender do arquivo do hospital.
// Se mapa_teste.XLS estiver presente, valida contra o arquivo REAL também.
import fs from 'fs';
import * as XLSX from 'xlsx';
import {
  normalizaAoA, normalizaRelatorio, normalizaPlano, detectaAncora, detectaLayout,
} from './isc-import-relatorio.js';
import { adivinhaMapeamento, montarPrevia, parseContato, resolveTelefone, chaveDedup } from './isc-import.js';

let ok = 0, fail = 0;
const t = (n, c, x = '') => { if (c) { ok++; console.log('  ✓', n); } else { fail++; console.log('  ✗ FALHOU:', n, x); } };
const eq = (n, a, b) => t(`${n} → ${JSON.stringify(a)}`, JSON.stringify(a) === JSON.stringify(b), `esperado ${JSON.stringify(b)}`);

// ── Fixture: Tasy_Rel sintético ───────────────────────────────────────────
// Colunas do dado:  0=Cirurgia 3=Atend 5=Procedimento 7=DataInicio 12=Min
//                  13=Paciente 16=Unid 18=Idade 19=Convênio 22=Cirurgião 25=Tipo
// Colunas do RÓTULO: deslocadas de propósito, como no arquivo real.
const L = (o) => { const l = new Array(27).fill(''); for (const [k, v] of Object.entries(o)) l[k] = v; return l; };
const TASY = [
  L({ 14: 'Relação das Cirurgias' }),
  L({ 14: '13/07/2026 Até 16/07/2026' }),
  L({ 1: 'Cirurgia', 4: 'Atend', 5: 'Procedimento Principal', 6: 'CID', 10: 'Data Inicio', 11: 'Min',
      13: 'Paciente', 15: 'Unid atend', 17: 'Idade', 18: 'Convênio', 21: 'Cirurgião', 26: 'Tipo' }),
  // registro 1 — procedimento e nome quebram em 3 e 2 linhas
  L({ 0: 286711, 3: 4923414, 5: 'TRATAMENTO ', 7: '13/07/2026 02:00', 12: 125,
      13: 'Leonardo Soares de ', 16: 'C5 21', 18: 25, 19: 'SUS', 22: 'Fernando Amaral', 25: 'Geral' }),
  L({ 5: 'CIRÚRGICO DE ', 13: 'Pugas' }),
  L({ 5: 'FRATURA DO FÊMUR' }),
  // registro 2 — sem quebra
  L({ 0: 286715, 3: 4923428, 5: 'Apendicectomia', 7: '13/07/2026 07:55', 12: 40,
      13: 'Anthony Lima', 16: 'AP-E 02', 18: 5, 19: 'UNIMED', 22: 'Gisele Oliveira', 25: 'Sedação' }),
  // registro 3 — última, seguida do rodapé
  L({ 0: 286721, 3: 4923433, 5: 'Fistulectomia Anal em Um ', 7: '13/07/2026 08:00', 12: 45,
      13: 'Erico Verissimo de ', 16: '10 01', 18: 30, 19: 'SUS', 22: 'Isabella Tavelin', 25: 'Local' }),
  L({ 5: 'Tempo', 13: 'Carvalho' }),
  L({ 8: 'Total minutos:', 9: 8889, 24: 'Total Geral', 27: 3 }),   // rodapé
];

// Variante "com fone": bloco endereço+telefone numa linha SEPARADA (col 6),
// que NUNCA aparece na linha de início do registro. Foi isto que expôs o bug
// da regra "coluna útil = tem dado no início".
// Montado explicitamente (splice deslocava os índices e jogava o contato no
// registro errado). TASY: 0-2 título/cabeçalho · 3-5 reg1 · 6 reg2 · 7-8 reg3 · 9 rodapé
const C = t => L({ 6: t });
const TASY_FONE = [
  TASY[0], TASY[1], TASY[2],
  TASY[3], TASY[4], TASY[5], C('Rua A,1 Centro Itatiba SP 13250000 Fone: 1146039995 Celular: 968650910'),
  TASY[6],                   C('Rua B,2 Centro Morungaba SP 13260000 Fone:  Celular: 997651317'),
  TASY[7], TASY[8],          C('Rua C,3 Centro Bilbo SP 99999999 Fone:  Celular: 964154403'),
  TASY[9],
];

console.log('\n── Detecção ──');
eq('âncora = coluna 0', detectaAncora(TASY), 0);
t('layout de relatório detectado', detectaLayout(TASY).relatorio === true, JSON.stringify(detectaLayout(TASY)));
const PLANO = [['Paciente', 'Atendimento', 'Data'], ['ANA', 'A1', '01/02/2026'], ['BIA', 'A2', '02/02/2026'], ['CIA', 'A3', '03/02/2026']];
t('tabela plana NÃO vira relatório', detectaLayout(PLANO).relatorio === false, JSON.stringify(detectaLayout(PLANO)));

console.log('\n── Reconstrução dos registros ──');
const n = normalizaRelatorio(TASY);
eq('3 registros de 10 linhas', n.diagnostico.registros, 3);
eq('cabeçalho achado na linha 3 (1-based)', n.diagnostico.linhaCabecalho, 3);
eq('11 colunas úteis', n.colunasUteis.length, 11);
eq('colunas úteis certas', n.colunasUteis, [0, 3, 5, 7, 12, 13, 16, 18, 19, 22, 25]);
t('coluna do rodapé descartada (8)', !n.colunasUteis.includes(8));
t('coluna do rodapé descartada (24)', !n.colunasUteis.includes(24));
t('coluna CID vazia descartada (6)', !n.colunasUteis.includes(6));

console.log('\n── Concatenação das continuações ──');
eq('procedimento remontado', n.linhas[0][5], 'TRATAMENTO CIRÚRGICO DE FRATURA DO FÊMUR');
eq('nome remontado', n.linhas[0][13], 'Leonardo Soares de Pugas');
eq('registro sem quebra intacto', n.linhas[1][5], 'Apendicectomia');
eq('índice ORIGINAL preservado (perfil salvo continua válido)', n.linhas[0][7], '13/07/2026 02:00');

console.log('\n── Rodapé não contamina o último registro ──');
eq('último procedimento limpo', n.linhas[2][5], 'Fistulectomia Anal em Um Tempo');
eq('último nome limpo', n.linhas[2][13], 'Erico Verissimo de Carvalho');
t('"Total minutos" não vazou p/ nenhum campo', !JSON.stringify(n.linhas).includes('Total'));
t('8889 não vazou', !JSON.stringify(n.linhas).includes('8889'));

console.log('\n── Rótulos são DICA reposicionada ──');
eq('col 0 → "Cirurgia" (rótulo estava na 1)', n.rotulos[0], 'Cirurgia');
eq('col 3 → "Atend" (rótulo estava na 4)', n.rotulos[3], 'Atend');
eq('col 13 → "Paciente" (coincide)', n.rotulos[13], 'Paciente');
t('col 7: dica erra (pega "CID"), por isso o operador confirma', n.rotulos[7] === 'CID');

console.log('\n── Fim a fim: normalizar → mapear → prévia ──');
const mapa = { 13: 'paciente_nome', 3: 'atendimento', 7: 'data_cirurgia', 5: 'procedimento', 12: 'duracao_min', 22: 'cirurgiao' };
const prev = montarPrevia(n.linhas, mapa, [], new Set());
eq('3 fichas válidas, 0 erro', prev.resumo, { total: 3, novas: 3, duplicadas: 0, erros: 0, fora_recorte: 0, avisos: 0 });
eq('data com hora → ISO', prev.itens[0].ficha.data_cirurgia, '2026-07-13');
eq('nome completo na ficha', prev.itens[0].ficha.paciente_nome, 'Leonardo Soares de Pugas');
eq('duração', prev.itens[0].ficha.duracao_min, 125);

console.log('\n── Variante COM CONTATO (coluna só em continuação) ──');
const nf = normalizaRelatorio(TASY_FONE);
eq('ainda 3 registros', nf.diagnostico.registros, 3);
t('col 6 (contato) NÃO é descartada', nf.colunasUteis.includes(6), JSON.stringify(nf.colunasUteis));
t('rodapé continua descartado (col 8)', !nf.colunasUteis.includes(8));
t('rodapé continua descartado (col 24)', !nf.colunasUteis.includes(24));
eq('bloco de contato remontado', nf.linhas[0][6], 'Rua A,1 Centro Itatiba SP 13250000 Fone: 1146039995 Celular: 968650910');
t('"Total minutos" segue fora', !JSON.stringify(nf.linhas).includes('Total'));

console.log('\n── parseContato ──');
const pc = parseContato('Rua A,1 Centro Itatiba SP 13250000 Fone: 1146039995 Celular: 968650910');
eq('fone', pc.fone, '1146039995');
eq('celular', pc.celular, '968650910');
eq('cidade', pc.cidade, 'Itatiba');
eq('uf', pc.uf, 'SP');
t('endereço sem os telefones', pc.endereco === 'Rua A,1 Centro Itatiba SP 13250000');

console.log('\n── resolveTelefone: WhatsApp manda na prioridade ──');
eq('celular s/DDD vence fixo c/DDD', resolveTelefone({ fone: '1173301074', celular: '968650910', cidade: 'Itatiba' }).e164, '5511968650910');
t('e marca como presumido', resolveTelefone({ fone: '', celular: '968650910', cidade: 'Itatiba' }).presumido === true);
eq('DDD 19 p/ Morungaba', resolveTelefone({ celular: '997651317', cidade: 'Morungaba' }).e164, '5519997651317');
eq('DDD 35 p/ Extrema/MG', resolveTelefone({ celular: '997651317', cidade: 'Extrema' }).e164, '5535997651317');
eq('cidade fora da tabela → SEM telefone', resolveTelefone({ celular: '997651317', cidade: 'Bilbo' }).e164, null);
eq('8 dígitos ambíguo → SEM telefone', resolveTelefone({ celular: '95994731', cidade: 'Itatiba' }).e164, null);
eq('móvel já c/ DDD não é presumido', resolveTelefone({ celular: '11968650910', cidade: 'Itatiba' }).presumido, false);
eq('só fixo → usa, mas avisa', resolveTelefone({ fone: '1146039995', celular: '', cidade: 'Itatiba' }).e164, '551146039995');
t('fixo avisa que WhatsApp não chega', /fixo/i.test(resolveTelefone({ fone: '1146039995', cidade: 'Itatiba' }).aviso || ''));
eq('sem nada', resolveTelefone({ fone: '1', celular: '', cidade: 'Itatiba' }).e164, null);
t('NUNCA inventa DDD sem cidade', resolveTelefone({ celular: '968650910', cidade: null }).e164 === null);

console.log('\n── Fim a fim com contato ──');
const mapaF = { 13: 'paciente_nome', 3: 'atendimento', 7: 'data_cirurgia', 5: 'procedimento', 6: 'contato_blob' };
const pf = montarPrevia(nf.linhas, mapaF, [], new Set());
eq('3 fichas, 0 erro', [pf.resumo.novas, pf.resumo.erros], [3, 0]);
eq('ficha 1 com celular + DDD da cidade', pf.itens[0].ficha.telefone, '5511968650910');
t('ficha 1 marcada presumido', pf.itens[0].ficha.telefone_presumido === true);
eq('ficha 3 (cidade desconhecida) SEM telefone', pf.itens[2].ficha.telefone, undefined);
t('ficha 3 avisa o motivo', pf.itens[2].avisos.some(a => /fora da tabela/.test(a)));
t('número cru preservado no contato alternativo', /964154403/.test(pf.itens[2].ficha.contato_alternativo || ''));
t('endereço preservado na observação', /Bilbo/.test(pf.itens[2].ficha.observacao || ''));

console.log('\n── Não regride na tabela plana ──');
const p = normalizaAoA(PLANO, 'auto');
eq('modo plano', p.diagnostico.modo, 'plano');
eq('3 registros', p.linhas.length, 3);
eq('cabeçalho preservado', p.rotulos, ['Paciente', 'Atendimento', 'Data']);
const mp = adivinhaMapeamento(p.rotulos);
eq('adivinha mapeia plano', [mp[0], mp[1], mp[2]], ['paciente_nome', 'atendimento', 'data_cirurgia']);
eq('prévia do plano', montarPrevia(p.linhas, mp, [], new Set()).resumo.novas, 3);

console.log('\n── Override manual do modo ──');
eq('forçar relatório numa plana trata o cabeçalho como registro (4)', normalizaAoA(PLANO, 'relatorio').linhas.length, 4);
eq('forçar plano num relatório não quebra', normalizaAoA(TASY, 'plano').diagnostico.modo, 'plano');

console.log('\n── Casos degenerados ──');
eq('vazio', normalizaAoA([], 'auto').linhas.length, 0);
eq('só cabeçalho', normalizaAoA([['a', 'b']], 'auto').linhas.length, 0);
t('sem âncora não explode', !!normalizaRelatorio([[''], ['']]).diagnostico.erro);

// ── Arquivo real do HUSF, se presente ────────────────────────────────────
const REAL = '/mnt/user-data/uploads/mapa_teste.XLS';
if (fs.existsSync(REAL)) {
  console.log('\n── ARQUIVO REAL (Tasy_Rel HUSF) ──');
  const wb = XLSX.read(fs.readFileSync(REAL), { type: 'buffer', codepage: 1252 });
  const aoa = XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]],
    { header: 1, raw: true, defval: '', blankrows: true });
  const r = normalizaAoA(aoa, 'auto');
  eq('layout detectado', r.diagnostico.modo, 'relatorio');
  eq('66 registros (bate com "Total Geral: 66" do rodapé)', r.diagnostico.registros, 66);
  eq('185 linhas lidas', r.diagnostico.linhasLidas, 185);
  eq('12 colunas úteis de 29', r.diagnostico.colunasUteis, 12);
  eq('1º procedimento remontado', r.linhas[0][5], 'TRATAMENTO CIRÚRGICO DE FRATURA DA DIÁFISE DO FÊMUR');
  eq('1º paciente remontado', r.linhas[0][13], 'Leonardo Soares de Pugas');
  eq('último paciente remontado', r.linhas[65][13], 'Erico Verissimo de Carvalho');
  t('rodapé não contaminou', !JSON.stringify(r.linhas).includes('Total minutos'));
  const mr = { 13: 'paciente_nome', 3: 'atendimento', 7: 'data_cirurgia', 5: 'procedimento', 12: 'duracao_min', 22: 'cirurgiao' };
  const pr = montarPrevia(r.linhas, mr, [], new Set());
  eq('66 fichas, 0 erro', [pr.resumo.novas, pr.resumo.erros], [66, 0]);
  t('todas com data válida', pr.itens.every(i => /^\d{4}-\d{2}-\d{2}$/.test(i.ficha.data_cirurgia)));
  t('todas com atendimento', pr.itens.every(i => i.ficha.atendimento));
}

const REAL_FONE = '/mnt/user-data/uploads/mapa_fone.XLS';
if (fs.existsSync(REAL_FONE)) {
  console.log('\n── ARQUIVO REAL COM CONTATO (Tasy_Rel HUSF) ──');
  const wb2 = XLSX.read(fs.readFileSync(REAL_FONE), { type: 'buffer', codepage: 1252 });
  const aoa2 = XLSX.utils.sheet_to_json(wb2.Sheets[wb2.SheetNames[0]], { header: 1, raw: true, defval: '', blankrows: true });
  const r2 = normalizaAoA(aoa2, 'auto');
  eq('67 registros', r2.diagnostico.registros, 67);
  t('col 6 (contato) capturada', r2.colunasUteis.includes(6));
  t('rodapé não vazou', !JSON.stringify(r2.linhas).includes('Total minutos'));
  const m2 = { 14: 'paciente_nome', 3: 'atendimento', 8: 'data_cirurgia', 5: 'procedimento', 13: 'duracao_min', 23: 'cirurgiao', 6: 'contato_blob' };
  const p2 = montarPrevia(r2.linhas, m2, [], new Set());
  eq('67 fichas, 0 erro', [p2.resumo.novas, p2.resumo.erros], [67, 0]);
  // Mapeamento CONFERIDO pelo SCIH, coluna a coluna (é o perfil semeado).
  console.log('  — perfil Tasy_Rel (mapeamento conferido) —');
  const PERFIL = { 0: 'cirurgia_id', 3: 'atendimento', 5: 'procedimento', 6: 'contato_blob',
                   8: 'data_cirurgia', 13: 'duracao_min', 14: 'paciente_nome',
                   23: 'cirurgiao', 26: 'tipo_anestesia' };
  const pp = montarPrevia(r2.linhas, PERFIL, [], new Set());
  eq('67 fichas, 0 erro com o perfil', [pp.resumo.novas, pp.resumo.erros], [67, 0]);
  t('nº da cirurgia capturado', pp.itens[0].ficha.cirurgia_id === '286711', pp.itens[0].ficha.cirurgia_id);
  t('67 nº de cirurgia distintos', new Set(pp.itens.map(i => i.ficha.cirurgia_id)).size === 67);
  t('duração capturada', pp.itens[0].ficha.duracao_min === 125, String(pp.itens[0].ficha.duracao_min));
  t('dedup usa o nº da cirurgia', pp.itens.every(i => /^cir:/.test(chaveDedup(i.ficha) || '')));

  const comTel = p2.itens.filter(i => i.ficha.telefone).length;
  t(`${comTel}/67 com telefone resolvido`, comTel >= 60, `só ${comTel}`);
  t('todo telefone presumido está MARCADO', p2.itens.every(i => !i.ficha.telefone_presumido || !!i.ficha.telefone));
  t('todo telefone presumido tem aviso', p2.itens.filter(i => i.ficha.telefone_presumido).every(i => i.avisos.some(a => /presumido/.test(a))));
  t('quem ficou sem telefone tem o motivo', p2.itens.filter(i => !i.ficha.telefone).every(i => i.avisos.length > 0));
  t('nenhum telefone com menos de 12 dígitos', p2.itens.filter(i => i.ficha.telefone).every(i => i.ficha.telefone.length >= 12));
} else {
  console.log('\n(arquivos reais ausentes — só a fixture sintética rodou)');
}

console.log(`\n${'═'.repeat(52)}\n${ok} passaram · ${fail} falharam\n`);
process.exit(fail ? 1 : 0);
