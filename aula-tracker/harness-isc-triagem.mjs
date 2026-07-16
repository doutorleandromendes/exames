// harness-isc-triagem.mjs — o que entra na vigilância pós-alta.
// Puro + fim a fim contra o mapa real, se presente.
import fs from 'fs';
import * as XLSX from 'xlsx';
import { casaTermo, casaLista, regraCasa, triar, REGRAS_SEED } from './isc-triagem.js';
import { montarPrevia } from './isc-import.js';
import { normalizaAoA } from './isc-import-relatorio.js';

let ok = 0, fail = 0;
const t = (n, c, x = '') => { if (c) { ok++; console.log('  ✓', n); } else { fail++; console.log('  ✗ FALHOU:', n, x); } };
const eq = (n, a, b) => t(`${n} → ${JSON.stringify(a)}`, JSON.stringify(a) === JSON.stringify(b), `esperado ${JSON.stringify(b)}`);

console.log('\n── casaTermo: palavra inteira, sem acento ──');
t('casa palavra exata', casaTermo('OPERAÇÃO CESARIANA', 'cesariana'));
t('ignora acento nos dois lados', casaTermo('REVASCULARIZAÇÃO MIOCÁRDICA', 'revascularizacao miocardica'));
t('ignora caixa', casaTermo('craniotomia frontal', 'CRANIOTOMIA'));
t('casa no fim da string', casaTermo('CIRURGIA DE COLUNA', 'coluna'));
t('casa com hífen como limite', casaTermo('DERIVAÇÃO RAQUE- PERITONEAL', 'derivacao raque'));
t('casa com parêntese como limite', casaTermo('Cerebral (Bera)', 'bera'));
// A armadilha que um teste real pegou: /raque/ marcava TRAQUEOSTOMIA como neuro.
t('NÃO casa substring: raque ⊄ TRAQUEOSTOMIA', !casaTermo('TRAQUEOSTOMIA', 'raque'));
t('NÃO casa substring: coluna ⊄ COLUNAVERTEBRAL', !casaTermo('COLUNAVERTEBRAL', 'coluna'));
t('NÃO casa parcial: cesar ⊄ CESARIANA', !casaTermo('OPERAÇÃO CESARIANA', 'cesar'));
t('termo vazio não casa', !casaTermo('qualquer coisa', ''));
t('metacaractere de regex é escapado, não interpretado', !casaTermo('abc', '.*'));
t('lista casa qualquer um', casaLista('PLÁSTICA VALVAR', 'coronaria|valvar|marcapasso'));
t('lista sem match', !casaLista('APENDICECTOMIA', 'coronaria|valvar'));

console.log('\n── regraCasa ──');
const rNeuro = { nome: 'Neuro', match_proc: 'craniotomia|coluna', nao_match_proc: 'infiltracao', vigiar: true };
t('casa pelo procedimento', regraCasa(rNeuro, { procedimento: 'CRANIOTOMIA DESCOMPRESSIVA' }));
t('nao_match vence o match', !regraCasa(rNeuro, { procedimento: 'Coluna Vertebral: Infiltração Foraminal' }));
t('regra inativa nunca casa', !regraCasa({ ...rNeuro, ativo: false }, { procedimento: 'CRANIOTOMIA' }));
t('regra sem nenhum filtro nunca casa (não pega tudo)', !regraCasa({ nome: 'vazia', vigiar: true }, { procedimento: 'X' }));
t('AND entre campos: proc casa mas cirurgião não', !regraCasa({ match_proc: 'coluna', match_cirurgiao: 'Sekine' }, { procedimento: 'CIRURGIA DE COLUNA', cirurgiao: 'Outro Medico' }));
t('AND entre campos: ambos casam', regraCasa({ match_proc: 'coluna', match_cirurgiao: 'Sekine' }, { procedimento: 'CIRURGIA DE COLUNA', cirurgiao: 'Marcos Kendi Sekine' }));
t('filtro por tipo de anestesia', regraCasa({ match_tipo: 'geral' }, { procedimento: 'X', tipo_anestesia: 'Geral' }));

console.log('\n── triar: ordem e precedência ──');
const REGRAS = REGRAS_SEED.map((r, i) => ({ ...r, id: i + 1, equipe_id: { 'Obstetrícia': 1, 'Neurocirurgia': 2, 'Cirurgia Cardíaca': 3 }[r.equipe] || null }));
const T = proc => triar({ procedimento: proc, cirurgiao: '', tipo_anestesia: '' }, REGRAS);

eq('cesariana → vigiar', [T('OPERAÇÃO CESARIANA').vigiar, T('OPERAÇÃO CESARIANA').equipe_id], [true, 1]);
eq('cesariana c/ laqueadura → vigiar', T('OPERAÇÃO CESARIANA COM LAQUEADURA TUBARIA').equipe_id, 1);
eq('craniotomia → neuro', T('MICROCIRURGIA PARA TUMOR INTRACRANIANO').equipe_id, 2);
eq('derivação raque → neuro', T('DERIVAÇÃO RAQUE- PERITONEAL').equipe_id, 2);
eq('coluna endoscópica → neuro', T('Cirurgia de coluna por via endoscópica').equipe_id, 2);
eq('revascularização → cardio', T('REVASCULARIZAÇÃO MIOCÁRDICA C/ USO DE EXTRACÓRPOREA').equipe_id, 3);
eq('plástica valvar → cardio', T('PLÁSTICA VALVAR E/OU TROCA VALVAR MÚLTIPLA').equipe_id, 3);

t('neuro marca implante (90d)', T('CRANIOTOMIA').implante === true);
t('cardio marca implante (90d)', T('PLÁSTICA VALVAR').implante === true);
t('cesariana NÃO marca implante', T('OPERAÇÃO CESARIANA').implante === false);
eq('código CVE vem junto', T('MICROCIRURGIA PARA TUMOR INTRACRANIANO').codigo_cve, 'CNEURO');

console.log('\n── Exclusões rodam ANTES (ordem menor) ──');
t('Bera → excluída', T('Pesquisa de Potenciais Auditivos de Tronco Cerebral (Bera)').vigiar === false);
t('infiltração de coluna → excluída, não neuro', T('Coluna Vertebral: Infiltração Foraminal ou Facetária').vigiar === false);
eq('  e o motivo é a exclusão', T('Coluna Vertebral: Infiltração Foraminal').motivo, 'Excluir: bloqueio / infiltração (dor)');
t('parto normal → excluído', T('PARTO NORMAL').vigiar === false);
t('bloqueio de nervo → excluído', T('Bloqueio De Nervo Periferico').vigiar === false);
t('broncoscopia → excluída', T('BRONCOSCOPIA (BRONCOFIBROSCOPIA').vigiar === false);
t('curetagem → excluída', T('CURETAGEM SEMIOTICA C/ OU S/ DILATACAO DO COLO DO UTERO').vigiar === false);

console.log('\n── Fora do recorte (fase 1) ──');
t('TRAQUEOSTOMIA não casa nada', T('TRAQUEOSTOMIA') === null);
t('apendicectomia fora da fase 1', T('APENDICECTOMIA VIDEOLAPAROSCÓPICA') === null);
t('prótese de mama fora da fase 1', T('Prótese de Mama - (PARTICULAR)') === null);
t('sem regras → triar devolve null', triar({ procedimento: 'X' }, []) === null);

console.log('\n── montarPrevia com triagem ──');
const linhas = [
  ['OPERAÇÃO CESARIANA', 'A1', '13/07/2026 08:55', 'Maria'],
  ['Pesquisa de Potenciais Auditivos (Bera)', 'A2', '13/07/2026 07:55', 'Anthony'],
  ['APENDICECTOMIA', 'A3', '13/07/2026 10:00', 'Juan'],
  ['CRANIOTOMIA', 'A4', '13/07/2026 12:45', 'Silvio'],
];
const mapa = { 0: 'procedimento', 1: 'atendimento', 2: 'data_cirurgia', 3: 'paciente_nome' };
const equipes = [{ id: 1, nome: 'Obstetrícia' }, { id: 2, nome: 'Neurocirurgia' }, { id: 3, nome: 'Cirurgia Cardíaca' }];
const pv = montarPrevia(linhas, mapa, equipes, new Set(), REGRAS);
eq('2 entram, 2 fora', [pv.resumo.novas, pv.resumo.fora_recorte], [2, 2]);
eq('cesariana recebe equipe da regra', pv.itens[0].ficha.equipe_id, 1);
eq('Bera fora, com motivo', [pv.itens[1].status, pv.itens[1].motivo], ['fora_recorte', 'Excluir: exame diagnóstico']);
eq('apendicectomia fora', pv.itens[2].motivo, 'Nenhuma regra de vigilância casou');
t('craniotomia entra c/ implante', pv.itens[3].ficha.implante === true);
t('fora do recorte não gera erro de campo', pv.itens[1].erros.length === 0);

console.log('\n── Sem regras = comportamento antigo (CSV próprio) ──');
const semRegras = montarPrevia(linhas, mapa, equipes, new Set(), null);
eq('todas viram candidatas', semRegras.resumo.novas, 4);
eq('nenhuma fora do recorte', semRegras.resumo.fora_recorte, 0);

// ── Mapa real ────────────────────────────────────────────────────────────
const REAL = '/mnt/user-data/uploads/mapa_fone.XLS';
if (fs.existsSync(REAL)) {
  console.log('\n── MAPA REAL (67 cirurgias, 4 dias) ──');
  const wb = XLSX.read(fs.readFileSync(REAL), { type: 'buffer', codepage: 1252 });
  const aoa = XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]], { header: 1, raw: true, defval: '', blankrows: true });
  const o = normalizaAoA(aoa, 'auto');
  const mr = { 14: 'paciente_nome', 3: 'atendimento', 8: 'data_cirurgia', 5: 'procedimento', 13: 'duracao_min', 23: 'cirurgiao', 6: 'contato_blob', 26: 'tipo_anestesia' };
  const p = montarPrevia(o.linhas, mr, equipes, new Set(), REGRAS);
  eq('67 lidas · 13 entram · 54 fora · 0 erro', [p.resumo.total, p.resumo.novas, p.resumo.fora_recorte, p.resumo.erros], [67, 13, 54, 0]);
  const porEq = {};
  p.itens.filter(i => i.status === 'nova').forEach(i => { const n = (equipes.find(e => e.id === i.ficha.equipe_id) || {}).nome; porEq[n] = (porEq[n] || 0) + 1; });
  eq('8 cesarianas · 3 neuro · 2 cardio', porEq, { 'Cirurgia Cardíaca': 2, 'Obstetrícia': 8, 'Neurocirurgia': 3 });
  t('toda ficha que entra tem equipe', p.itens.filter(i => i.status === 'nova').every(i => i.ficha.equipe_id));
  t('toda ficha que entra tem data válida', p.itens.filter(i => i.status === 'nova').every(i => /^\d{4}-\d{2}-\d{2}$/.test(i.ficha.data_cirurgia)));
  const tq = p.itens.find(i => /TRAQUEOSTOMIA/i.test(i.ficha.procedimento || ''));
  t('TRAQUEOSTOMIA não virou neurocirurgia', tq.status === 'fora_recorte' && !tq.ficha.equipe_id);
  const inf = p.itens.find(i => /Infiltra/i.test(i.ficha.procedimento || ''));
  t('infiltração de coluna excluída (não neuro)', inf.status === 'fora_recorte' && /infiltra/i.test(inf.motivo));
  const neuros = p.itens.filter(i => i.status === 'nova' && i.ficha.equipe_id === 2);
  t('neuro tem janela de 90d (implante)', neuros.every(i => i.ficha.implante === true));
  const comTel = p.itens.filter(i => i.status === 'nova' && i.ficha.telefone).length;
  t(`${comTel}/13 das vigiadas com telefone`, comTel >= 11, `só ${comTel}`);
} else {
  console.log('\n(mapa real ausente — só os testes puros rodaram)');
}

console.log(`\n${'═'.repeat(52)}\n${ok} passaram · ${fail} falharam\n`);
process.exit(fail ? 1 : 0);
