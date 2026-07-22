// harness-pav-core.mjs — validação do núcleo PAV sem banco, sem Express.
// Rodar: node harness-pav-core.mjs
import {
  extraiRegistro, turnoVigente, diaDoTurno, saloesDoContexto, podeEscrever,
  leitosVisiveis, itensDaCategoria, podeTransferir, efeitoEncerramento, estadoTurnosDoDia, coberturaDoDia, relacaoPF, piorDoDia, serieVentilatoria,
  vmDiaEpisodio, conformidadeItem, adesaoBundle,
  REGISTRO, REGRAS_DEFAULT, SUBGLOTICA_VIA_DEFAULT,
} from './pav-core.js';

let ok = 0, fail = 0;
const t = (nome, cond) => { if (cond) { ok++; console.log('  ✓', nome); } else { fail++; console.log('  ✗ FALHOU:', nome); } };
const eq = (nome, a, b) => t(`${nome} (${JSON.stringify(a)} === ${JSON.stringify(b)})`, JSON.stringify(a) === JSON.stringify(b));
const at = (dia, h, min = 0) => new Date(2026, 6, dia, h, min, 0);
const campo = k => REGISTRO.find(c => c.key === k);

console.log('\n═══ CAMADA DE REGISTRO (fato) ═══');

console.log('\n── extraiRegistro: sim/não e valores ──');
const reg = extraiRegistro({
  r_cabeceira: 'sim', r_higiene_oral: 'nao', r_aspiracao: 'sim',
  r_subglotica: 'sim', r_despertar: 'nao', j_despertar: 'BNM cisatracúrio',
  r_extubacao: 'sim', r_circuito: 'nao', r_hmef: 'sim',
  v_cuff: '28', fio2: '45', peep: '10', pao2: '88',
  sec_quantidade: 'media', sec_aspecto: 'purulenta',
  campo_lixo: 'x', r_naoexiste: 'sim',
});
eq('cabeceira sim', reg.itens.cabeceira.resp, 'sim');
eq('higiene não', reg.itens.higiene_oral.resp, 'nao');
eq('cuff valor', reg.itens.cuff.valor, 28);
eq('despertar não + justificativa', reg.itens.despertar.justificativa, 'BNM cisatracúrio');
eq('subglótica via default (às cegas)', reg.itens.subglotica.via, SUBGLOTICA_VIA_DEFAULT);
eq('P/F calculado no registro', reg.vent.pf, 196);
eq('secreção capturada', reg.secrecao.aspecto, 'purulenta');
t('campo lixo descartado', reg.itens.campo_lixo === undefined);
t('chave inexistente descartada', reg.itens.naoexiste === undefined);
t('sem motivos pendentes', reg.motivos.length === 0);

console.log('\n── extraiRegistro: NÃO existe "conforme" no registro ──');
t('item só tem resp/valor, nunca estado', reg.itens.cabeceira.estado === undefined);

console.log('\n── extraiRegistro: justificativa obrigatória no "não" ──');
const regSemJust = extraiRegistro({ r_despertar: 'nao' });
t('despertar não sem justificativa → motivo', regSemJust.motivos.some(m => m.includes('despertar')));

console.log('\n── extraiRegistro: via só quando "sim" ──');
const regViaNao = extraiRegistro({ r_subglotica: 'nao' });
t('subglótica não → sem via', regViaNao.itens.subglotica.via === undefined);
const regViaPorta = extraiRegistro({ r_subglotica: 'sim', via_subglotica: 'porta_dedicada' });
eq('subglótica sim + porta dedicada', regViaPorta.itens.subglotica.via, 'porta_dedicada');

console.log('\n═══ ESCOPO DE ACESSO (turno × salão) ═══');

console.log('\n── turnoVigente ──');
eq('08:00 → M fisio', turnoVigente(at(17, 8)).turno, 'M');
eq('15:00 → T fisio', turnoVigente(at(17, 15)).categoria, 'fisio');
eq('20:00 → N', turnoVigente(at(17, 20)).turno, 'N');
eq('03:00 → E enf', turnoVigente(at(17, 3)).categoria, 'enf');
eq('01:00 exato → E', turnoVigente(at(17, 1)).turno, 'E');
eq('13:00 exato → T', turnoVigente(at(17, 13)).turno, 'T');

console.log('\n── diaDoTurno: N cruza meia-noite ──');
eq('N 00:30 dia 18 → dia 17', diaDoTurno('N', at(18, 0, 30)), '2026-07-17');
eq('E 03:00 dia 18 → dia 18', diaDoTurno('E', at(18, 3)), '2026-07-18');
eq('turno vigente 00:30 é N', turnoVigente(at(18, 0, 30)).turno, 'N');
eq('data do N às 00:30 = dia anterior', turnoVigente(at(18, 0, 30)).data, '2026-07-17');

console.log('\n── saloesDoContexto ──');
eq('fisio alcança os dois salões', saloesDoContexto({ categoria_pav: 'fisio' }), ['UTIAB', 'UTIC']);
eq('enf alcança só o salão da sessão', saloesDoContexto({ categoria_pav: 'enf', salao_sessao: 'UTIAB' }), ['UTIAB']);
eq('enf sem salão de sessão → vazio', saloesDoContexto({ categoria_pav: 'enf' }), []);
eq('super_admin alcança tudo', saloesDoContexto({ super_admin: true }), ['UTIAB', 'UTIC']);

console.log('\n── podeEscrever: turno × salão ──');
const fisio = { categoria_pav: 'fisio' };
const enfAB = { categoria_pav: 'enf', salao_sessao: 'UTIAB' };
const su = { super_admin: true };

t('fisio escreve UTIC no T vigente', podeEscrever({ data: '2026-07-17', turno: 'T', salao: 'UTIC' }, fisio, at(17, 15)).permitido);
t('fisio escreve UTIAB no T vigente', podeEscrever({ data: '2026-07-17', turno: 'T', salao: 'UTIAB' }, fisio, at(17, 15)).permitido);
t('fisio NÃO faz backfill', !podeEscrever({ data: '2026-07-17', turno: 'M', salao: 'UTIAB' }, fisio, at(17, 15)).permitido);
t('fisio NÃO escreve madrugada (é da enf)', !podeEscrever({ data: '2026-07-17', turno: 'E', salao: 'UTIAB' }, fisio, at(17, 3)).permitido);

t('enf UTIAB escreve UTIAB na madrugada', podeEscrever({ data: '2026-07-17', turno: 'E', salao: 'UTIAB' }, enfAB, at(17, 3)).permitido);
t('enf UTIAB BLOQUEADA em UTIC (fora do alcance)', !podeEscrever({ data: '2026-07-17', turno: 'E', salao: 'UTIC' }, enfAB, at(17, 3)).permitido);
eq('motivo do bloqueio de salão', podeEscrever({ data: '2026-07-17', turno: 'E', salao: 'UTIC' }, enfAB, at(17, 3)).motivo, 'salão fora do seu alcance');
t('enf NÃO escreve no turno da fisio', !podeEscrever({ data: '2026-07-17', turno: 'M', salao: 'UTIAB' }, enfAB, at(17, 8)).permitido);

t('super-admin backfill em qualquer salão', podeEscrever({ data: '2026-07-10', turno: 'M', salao: 'UTIC' }, su, at(17, 15)).permitido);
t('backfill do super-admin é retroativo', podeEscrever({ data: '2026-07-10', turno: 'M', salao: 'UTIC' }, su, at(17, 15)).retroativo);
t('super-admin no vigente NÃO é retroativo', !podeEscrever({ data: '2026-07-17', turno: 'T', salao: 'UTIC' }, su, at(17, 15)).retroativo);

console.log('\n── leitosVisiveis ──');
const fichas = [
  { id: 1, leito: '02', salao: 'UTIAB' },
  { id: 2, leito: '04', salao: 'UTIAB' },
  { id: 3, leito: 'C1', salao: 'UTIC' },
];
eq('fisio vê os 3 leitos (dois salões)', leitosVisiveis(fisio, fichas).map(f => f.id), [1, 2, 3]);
eq('enf UTIAB vê só os 2 de UTIAB', leitosVisiveis(enfAB, fichas).map(f => f.id), [1, 2]);

console.log('\n── itensDaCategoria ──');
t('fisio não vê higiene oral', !itensDaCategoria('fisio').some(c => c.key === 'higiene_oral'));
t('enf vê higiene oral', itensDaCategoria('enf').some(c => c.key === 'higiene_oral'));
t('ambos veem cabeceira', itensDaCategoria('fisio').some(c => c.key === 'cabeceira') && itensDaCategoria('enf').some(c => c.key === 'cabeceira'));
t('fisio vê subglótica, enf não', itensDaCategoria('fisio').some(c => c.key === 'subglotica') && !itensDaCategoria('enf').some(c => c.key === 'subglotica'));

console.log('\n── podeTransferir: exige alcançar os dois salões ──');
t('fisio transfere UTIAB→UTIC no turno',
  podeTransferir({ data: '2026-07-17', turno: 'T', salao_de: 'UTIAB', salao_para: 'UTIC' }, fisio, at(17, 15)).permitido);
t('fisio NÃO transfere fora do turno',
  !podeTransferir({ data: '2026-07-17', turno: 'M', salao_de: 'UTIAB', salao_para: 'UTIC' }, fisio, at(17, 15)).permitido);
t('enf NÃO transfere (alcança só um salão)',
  !podeTransferir({ data: '2026-07-17', turno: 'E', salao_de: 'UTIAB', salao_para: 'UTIC' }, enfAB, at(17, 3)).permitido);
eq('motivo do bloqueio da enf',
  podeTransferir({ data: '2026-07-17', turno: 'E', salao_de: 'UTIAB', salao_para: 'UTIC' }, enfAB, at(17, 3)).motivo,
  'transferência exige alcançar os dois salões');
t('origem == destino rejeitada',
  !podeTransferir({ data: '2026-07-17', turno: 'T', salao_de: 'UTIAB', salao_para: 'UTIAB' }, fisio, at(17, 15)).permitido);
t('super-admin faz transferência retroativa',
  podeTransferir({ data: '2026-07-10', turno: 'M', salao_de: 'UTIAB', salao_para: 'UTIC' }, su, at(17, 15)).retroativo);
t('super-admin transferência no vigente NÃO é retroativa',
  !podeTransferir({ data: '2026-07-17', turno: 'T', salao_de: 'UTIAB', salao_para: 'UTIC' }, su, at(17, 15)).retroativo);

console.log('\n── efeitoEncerramento: dois níveis ──');
eq('enf registra extubação → pendente', efeitoEncerramento({ categoria_pav: 'enf' }, 'registrar').estado_novo, 'extubacao_pendente');
eq('enf NÃO encerra direto', efeitoEncerramento({ categoria_pav: 'enf' }, 'registrar').encerra, false);
eq('fisio registra extubação → encerrado direto', efeitoEncerramento({ categoria_pav: 'fisio' }, 'registrar').estado_novo, 'encerrado');
eq('fisio encerra direto', efeitoEncerramento({ categoria_pav: 'fisio' }, 'registrar').encerra, true);
eq('SCIH encerra direto', efeitoEncerramento({ scih: true }, 'registrar').estado_novo, 'encerrado');
eq('super-admin encerra direto', efeitoEncerramento({ super_admin: true }, 'registrar').estado_novo, 'encerrado');
eq('fisio confirma pendência → encerrado', efeitoEncerramento({ categoria_pav: 'fisio' }, 'confirmar').estado_novo, 'encerrado');
eq('enf NÃO confirma pendência', efeitoEncerramento({ categoria_pav: 'enf' }, 'confirmar').estado_novo, null);
eq('motivo do bloqueio da enf ao confirmar', efeitoEncerramento({ categoria_pav: 'enf' }, 'confirmar').motivo, 'confirmação é ato de fisio/SCIH');

console.log('\n── estadoTurnosDoDia / coberturaDoDia: grid do SCIH ──');
// um dia com M conforme, T com NC (cabeceira não), N vazio, E vazio
const bundleOk = { cabeceira:{resp:'sim'}, aspiracao:{resp:'sim'}, higiene_oral:{resp:'sim'},
  subglotica:{resp:'sim'}, despertar:{resp:'sim'}, extubacao:{resp:'sim'}, cuff:{valor:28} };
const bundleNC = { ...bundleOk, cabeceira:{resp:'nao'} };
const checksDia = [ { turno:'M', itens: bundleOk }, { turno:'T', itens: bundleNC } ];
const est = estadoTurnosDoDia(checksDia);
eq('M conforme', est.M, 'conforme');
eq('T com NC', est.T, 'nc');
eq('N vazio (lacuna, não NC)', est.N, 'vazio');
eq('E vazio', est.E, 'vazio');
const cob = coberturaDoDia(checksDia);
eq('2 turnos preenchidos', cob.preenchidos, 2);
eq('1 turno conforme', cob.conformes, 1);
eq('total de turnos = 4', cob.total_turnos, 4);
// dia sem nenhum check → tudo vazio, 0 preenchidos
eq('dia vazio: 0 preenchidos', coberturaDoDia([]).preenchidos, 0);

console.log('\n═══ PARÂMETROS → ATB ═══');

console.log('\n── relacaoPF ──');
eq('88/45% → 196', relacaoPF(88, 45), 196);
eq('sem PaO2 → null', relacaoPF(null, 45), null);
eq('FiO2 zero → null', relacaoPF(88, 0), null);

console.log('\n── piorDoDia ──');
const dia = [
  { vent: { fio2: 40, peep: 8, pao2: 90 } },
  { vent: { fio2: 45, peep: 10, pao2: 88 } },
  { vent: { fio2: 35, peep: 12, pao2: 70 } },
];
const pd = piorDoDia(dia);
eq('pior FiO2 = maior', pd.fio2, 45);
eq('pior PEEP = maior', pd.peep, 12);
eq('pior P/F = menor', pd.pf, 196);

console.log('\n── piorDoDia: purulenta trumpa ──');
eq('purulenta pequena trumpa mucoide grande',
  piorDoDia([{ secrecao: { aspecto: 'purulenta', quantidade: 'pequena' } }, { secrecao: { aspecto: 'mucoide', quantidade: 'grande' } }]).secrecao_para_atb,
  { purulenta: true, quantidade: 'pequena' });
eq('entre purulentas, maior quantidade',
  piorDoDia([{ secrecao: { aspecto: 'purulenta', quantidade: 'pequena' } }, { secrecao: { aspecto: 'purulenta', quantidade: 'grande' } }]).secrecao_para_atb,
  { purulenta: true, quantidade: 'grande' });
eq('sem purulenta mas com registro',
  piorDoDia([{ secrecao: { aspecto: 'mucoide', quantidade: 'media' } }]).secrecao_para_atb,
  { purulenta: false, quantidade: null });
eq('sem registro de secreção → null', piorDoDia([{ vent: { fio2: 40 } }]).secrecao_para_atb, null);

console.log('\n── serieVentilatoria ──');
const agg = {
  '2026-07-16': { fio2: 50, peep: 12, pf: 180, secrecao_para_atb: { purulenta: true, quantidade: 'media' }, retroativo: false },
  '2026-07-17': { fio2: 45, peep: 10, pf: 196, secrecao_para_atb: { purulenta: false, quantidade: null }, retroativo: true },
};
const serie = serieVentilatoria(agg, '2026-07-17');
eq('D0 = 17/07', serie['D0'].Data, '2026-07-17');
eq('D-1 FiO2 em %', serie['D-1'].FiO2, '50');
eq('D-1 ST purulenta', serie['D-1'].ST, 'purulenta, media');
eq('D0 ST sem purulenta', serie['D0'].ST, 'sem secreção purulenta');
eq('D0 marca retroativo', serie['D0'].retroativo, true);
eq('D+1 sem dado → vazio', serie['D+1'].FiO2, '');

console.log('\n── vmDiaEpisodio (transferência de salão não interrompe) ──');
eq('ventilado todo mês desde dia 5', vmDiaEpisodio('2026-07-05', null, '2026-07'), 27);
eq('extubação não conta', vmDiaEpisodio('2026-07-05', '2026-07-10', '2026-07'), 5);
eq('intubado antes do mês → desde dia 1', vmDiaEpisodio('2026-06-28', null, '2026-07'), 31);
eq('intub e extub dia seguinte → 1', vmDiaEpisodio('2026-07-05', '2026-07-06', '2026-07'), 1);

console.log('\n═══ CAMADA DE LEITURA (interpretação) ═══');

console.log('\n── conformidadeItem: aplica regras sobre o fato ──');
eq('cuff 28 → C (dentro de 25–30)', conformidadeItem(campo('cuff'), { valor: 28 }), 'C');
eq('cuff 34 → NC', conformidadeItem(campo('cuff'), { valor: 34 }), 'NC');
eq('cabeceira sim → C', conformidadeItem(campo('cabeceira'), { resp: 'sim' }), 'C');
eq('cabeceira não → NC', conformidadeItem(campo('cabeceira'), { resp: 'nao' }), 'NC');
eq('despertar não + justificativa → NA', conformidadeItem(campo('despertar'), { resp: 'nao', justificativa: 'BNM' }), 'NA');
eq('despertar não SEM justificativa → NC', conformidadeItem(campo('despertar'), { resp: 'nao' }), 'NC');
eq('evento de troca (hmef) fora do bundle → null', conformidadeItem(campo('hmef'), { resp: 'sim' }), null);
eq('item não registrado → null', conformidadeItem(campo('cabeceira'), null), null);

console.log('\n── adesaoBundle: CÁLCULO, não campo do form ──');
const tudoSim = {
  cabeceira: { resp: 'sim' }, higiene_oral: { resp: 'sim' }, aspiracao: { resp: 'sim' },
  subglotica: { resp: 'sim' }, despertar: { resp: 'sim' }, extubacao: { resp: 'sim' },
  cuff: { valor: 28 },
  // eventos de troca presentes mas irrelevantes p/ adesão:
  circuito: { resp: 'nao' }, hmef: { resp: 'sim' }, sistema: { resp: 'nao' },
};
eq('tudo sim + cuff ok → adesão 1', adesaoBundle(tudoSim).adesao, 1);
t('eventos de troca não entram no bundle', !adesaoBundle(tudoSim).nc.includes('circuito'));

const umNC = { ...tudoSim, cabeceira: { resp: 'nao' } };
eq('cabeceira não → adesão 0', adesaoBundle(umNC).adesao, 0);
eq('lista o culpado', adesaoBundle(umNC).nc, ['cabeceira']);

const cuffFora = { ...tudoSim, cuff: { valor: 40 } };
eq('cuff 40 → adesão 0', adesaoBundle(cuffFora).adesao, 0);

const comNA = { ...tudoSim, despertar: { resp: 'nao', justificativa: 'BNM' } };
eq('despertar NA não penaliza → adesão 1', adesaoBundle(comNA).adesao, 1);

const incompleto = { cabeceira: { resp: 'sim' }, cuff: { valor: 28 } };
eq('incompleto → adesão null', adesaoBundle(incompleto).adesao, null);

console.log('\n── recálculo com regra nova (poder da separação) ──');
const regra2030 = { ...REGRAS_DEFAULT, cuff: { faixa: [20, 30] } };
eq('cuff 22 é NC na regra 25–30', conformidadeItem(campo('cuff'), { valor: 22 }, REGRAS_DEFAULT), 'NC');
eq('mesmo fato vira C na regra 20–30', conformidadeItem(campo('cuff'), { valor: 22 }, regra2030), 'C');

console.log(`\n${'═'.repeat(50)}\n${ok} passaram · ${fail} falharam\n`);
process.exit(fail ? 1 : 0);
