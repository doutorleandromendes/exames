// harness-isc-core.mjs — validação do núcleo ISC sem banco, sem Express.
// Rodar: node harness-isc-core.mjs
import {
  recomputarEstado, contatoTemAlerta, normalizaTelefone, renderTemplate,
  REGRAS_ALERTA_SEED,
  extraiRespostas, janelasDe, addDays, diffDias,
} from './isc-core.js';

let ok = 0, fail = 0;
const t = (nome, cond) => { if (cond) { ok++; console.log('  ✓', nome); } else { fail++; console.log('  ✗ FALHOU:', nome); } };
const eq = (nome, a, b) => t(`${nome} (${JSON.stringify(a)} === ${JSON.stringify(b)})`, JSON.stringify(a) === JSON.stringify(b));

console.log('\n── Telefone ──');
eq('celular com DDD', normalizaTelefone('(11) 91234-5678'), '5511912345678');
eq('já com 55', normalizaTelefone('+55 11 91234-5678'), '5511912345678');
eq('fixo 10 dígitos', normalizaTelefone('1132145678'), '551132145678');
eq('sem DDD → null', normalizaTelefone('91234-5678'), null);
eq('lixo → null', normalizaTelefone('abc'), null);

console.log('\n── Datas ──');
eq('D+7', addDays('2026-07-01', 7), '2026-07-08');
eq('D+90 cruza mês', addDays('2026-07-01', 90), '2026-09-29');
eq('diff', diffDias('2026-07-01', '2026-07-16'), 15);

console.log('\n── Janelas ──');
eq('implante → 90d da equipe', janelasDe({ implante: true }, { janelas_default: [7, 30], janelas_implante: [7, 30, 90] }), [7, 30, 90]);
eq('sem implante', janelasDe({ implante: false }, { janelas_default: [7, 30], janelas_implante: [7, 30, 90] }), [7, 30]);
eq('override da ficha vence', janelasDe({ janelas: [15] }, { janelas_default: [7, 30] }), [15]);
eq('sem equipe, implante', janelasDe({ implante: true }, null), [7, 30, 90]);

console.log('\n── Alertas ──');
// Modelo novo: não há piso embutido — as regras vêm sempre por parâmetro. Aqui
// usamos as sementes (o que o banco planta no 1º boot) como regras ativas.
const R = REGRAS_ALERTA_SEED.map(r => ({ ...r, ativo: true }));
t('febre Sim acende', contatoTemAlerta({ febre: 'Sim' }, false, R));
t('febre Não não acende', !contatoTemAlerta({ febre: 'Não' }, false, R));
t('ferida com secreção purulenta acende', contatoTemAlerta({ ferida: ['Secreção purulenta'] }, false, R));
t('ferida SEM SINAIS não acende', !contatoTemAlerta({ ferida: ['SEM SINAIS DE INFECÇÃO'] }, false, R));
t('ferida "Não tirou os pontos" não acende', !contatoTemAlerta({ ferida: ['Não tirou os pontos'] }, false, R));
t('suspeita manual acende sozinha, mesmo sem regras', contatoTemAlerta({}, true, []));
t('vazio não acende', !contatoTemAlerta({}, false, R));
t('SEM regras nada acende (não há piso embutido)', !contatoTemAlerta({ febre: 'Sim' }, false, []));

console.log('\n── Motor de estado ──');
const ficha = { data_cirurgia: '2026-07-01', implante: true, status_vigilancia: 'em_vigilancia' };
const eqp = { janelas_default: [7, 30], janelas_implante: [7, 30, 90] };

// (1) recém-operado, nada vencido
let e = recomputarEstado(ficha, [], eqp, '2026-07-02');
eq('nada vencido → 1ª janela pendente', e.janelas_estado['7'].status, 'pendente');
eq('próxima janela = 7', e.proxima_janela, 7);
eq('próximo contato = D+7', e.proximo_contato_em, '2026-07-08');
eq('segue em vigilância', e.status_vigilancia, 'em_vigilancia');

// (2) janela 7 venceu hoje, dentro da tolerância
e = recomputarEstado(ficha, [], eqp, '2026-07-10');
eq('venceu há 2d → aberta', e.janelas_estado['7'].status, 'aberta');

// (3) passou da tolerância, sem tentativa
e = recomputarEstado(ficha, [], eqp, '2026-07-25');
eq('passou tolerância sem tentativa → atrasada', e.janelas_estado['7'].status, 'atrasada');
eq('pula para 7 (não 30)', e.proxima_janela, 7);

// (4) tentativas sem sucesso, passou tolerância
const semSucesso = [
  { id: 1, janela: 7, sucesso: false, data_contato: '2026-07-09' },
  { id: 2, janela: 7, sucesso: false, data_contato: '2026-07-11' },
];
e = recomputarEstado(ficha, semSucesso, eqp, '2026-07-25');
eq('tentou e falhou → sem_contato', e.janelas_estado['7'].status, 'sem_contato');
eq('conta falhas', e.tentativas_falhas, 2);
eq('nenhum contato ok', e.contatos_ok, 0);

// (4b) falha DENTRO da tolerância: janela continua sendo o alvo da fila
e = recomputarEstado(ficha, [{ id: 9, janela: 7, sucesso: false, data_contato: '2026-07-09' }], eqp, '2026-07-10');
eq('falha dentro da tolerância → aberta', e.janelas_estado['7'].status, 'aberta');
eq('continua mirando a janela 7', e.proxima_janela, 7);

// (5) contato com sucesso fecha a janela
const comSucesso = [
  ...semSucesso,
  { id: 3, janela: 7, sucesso: true, data_contato: '2026-07-12', respostas: { febre: 'Não' } },
];
e = recomputarEstado(ficha, comSucesso, eqp, '2026-07-25');
eq('7d concluída', e.janelas_estado['7'].status, 'concluida');
eq('avança para 30', e.proxima_janela, 30);
eq('contato_id preservado', e.janelas_estado['7'].contato_id, 3);
eq('contatos_ok', e.contatos_ok, 1);
t('sem alerta (febre Não)', e.tem_alerta === false);

// (6) alerta propaga para a ficha
const comAlerta = [{ id: 4, janela: 7, sucesso: true, data_contato: '2026-07-08', respostas: { ferida: ['Deiscência'] } }];
e = recomputarEstado(ficha, comAlerta, eqp, '2026-07-09', R);
t('deiscência acende alerta na ficha', e.tem_alerta === true);
t('alerta marcado na janela', e.janelas_estado['7'].alerta === true);
// Sem regras, o mesmo contato não acende — prova que o piso saiu do código.
const semR = recomputarEstado(ficha, comAlerta, eqp, '2026-07-09', []);
t('sem regras, deiscência NÃO acende', semR.tem_alerta === false);

// (7) todas as janelas cumpridas → conclui sozinha
const todas = [7, 30, 90].map((j, i) => ({ id: i + 10, janela: j, sucesso: true, data_contato: addDays('2026-07-01', j), respostas: { febre: 'Não' } }));
e = recomputarEstado(ficha, todas, eqp, '2026-10-01');
eq('vigilância concluída', e.status_vigilancia, 'concluida');
eq('sem próxima janela', e.proxima_janela, null);
eq('3 contatos ok', e.contatos_ok, 3);

// (8) status terminal não é sobrescrito pelo motor
e = recomputarEstado({ ...ficha, status_vigilancia: 'obito' }, [], eqp, '2026-10-01');
eq('óbito não vira em_vigilancia', e.status_vigilancia, 'obito');
e = recomputarEstado({ ...ficha, status_vigilancia: 'perda_seguimento' }, todas, eqp, '2026-10-01');
eq('perda_seguimento não vira concluida', e.status_vigilancia, 'perda_seguimento');

// (9) contato avulso (janela null) não fecha janela nenhuma
e = recomputarEstado(ficha, [{ id: 99, janela: null, sucesso: true, data_contato: '2026-07-08', respostas: {} }], eqp, '2026-07-09');
eq('avulso não fecha 7d', e.janelas_estado['7'].status, 'aberta');

console.log('\n── Templates ──');
const ctx = { paciente_nome: 'MARIA DAS DORES SILVA', procedimento: 'Craniotomia', data_cirurgia: '2026-07-01', dias_pos_op: 7, hospital: 'HUSF', equipe: 'Neurocirurgia' };
const r = renderTemplate('Olá, {{primeiro_nome}}! {{procedimento}} em {{data_cirurgia}}, {{dias_pos_op}} dias. {{hospital}}/{{equipe}}.', ctx);
eq('render completo', r, 'Olá, Maria! Craniotomia em 01/07/2026, 7 dias. HUSF/Neurocirurgia.');
t('placeholder desconhecido vira vazio', renderTemplate('a{{xyz}}b', ctx) === 'ab');
t('nunca vaza chaves', !renderTemplate('{{primeiro_nome}} {{nada}}', ctx).includes('{{'));

console.log('\n── Sanitização de respostas ──');
const resp = extraiRespostas({
  r_febre: 'Sim', r_ferida: ['Deiscência', 'HACKEADO'], r_alta: 'lixo',
  campo_malicioso: 'x', 'r_naoexiste': 'y',
});
eq('sim_nao válido passa', resp.febre, 'Sim');
eq('multi filtra opção inexistente', resp.ferida, ['Deiscência']);
t('sim_nao inválido descartado', resp.alta === undefined);
t('campo fora do checklist descartado', resp.campo_malicioso === undefined);
t('chave inexistente descartada', resp.naoexiste === undefined);

console.log(`\n${'═'.repeat(50)}\n${ok} passaram · ${fail} falharam\n`);
process.exit(fail ? 1 : 0);
