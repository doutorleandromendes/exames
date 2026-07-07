// harness-editor-validacao.mjs
// Testa validarDefinicao + statusCampos do editor estrutural contra o schema real.
// Uso: node harness-editor-validacao.mjs

import { SEMENTE_HUSF, buildSCMI } from './atb-form-schema.js';
import { registroFicha } from './atb-field-registry.js';
import { validarDefinicao, statusCampos } from './atb-form-editor-routes.js';

const COLS = new Set(registroFicha(SEMENTE_HUSF).map(x => x.col));
const clone = o => JSON.parse(JSON.stringify(o));
const ctx = { schemaAtual: SEMENTE_HUSF, colunasReais: COLS };

let passed = 0, failed = 0;
function caso(nome, obtido, esperadoOk, erroContem) {
  const okOk = obtido.ok === esperadoOk;
  const okErro = !erroContem || obtido.erros.some(e => e.includes(erroContem));
  const OK = okOk && okErro;
  console.log((OK ? '✅' : '❌'), nome, OK ? '' : JSON.stringify(obtido.erros));
  OK ? passed++ : failed++;
}

// 1-2: schemas reais validam limpos
caso('HUSF (semente) valida limpo', validarDefinicao(SEMENTE_HUSF, ctx), true);
caso('SCMI (buildSCMI) valida limpo', validarDefinicao(buildSCMI(), { schemaAtual: buildSCMI(), colunasReais: COLS }), true);

// 3: campo novo criável → ok
let d = clone(SEMENTE_HUSF);
d.secoes[1].campos.push({ key: 'alergias', type: 'checkbox', label: 'Alergias', options: ['Penicilina'] });
caso('campo novo (checkbox) aceito', validarDefinicao(d, ctx), true);

// 4: campo novo tipo não-criável → erro
d = clone(SEMENTE_HUSF);
d.secoes[1].campos.push({ key: 'nova_matriz', type: 'matrix', label: 'X', colunas: [] });
caso('campo novo matrix recusado', validarDefinicao(d, ctx), false, 'não pode ser criado');

// 5: key duplicada
d = clone(SEMENTE_HUSF);
d.secoes[1].campos.push({ key: 'setor', type: 'text', label: 'Dup' });
caso('key duplicada recusada', validarDefinicao(d, ctx), false, 'duplicada');

// 6: key reservada
d = clone(SEMENTE_HUSF);
d.secoes[1].campos.push({ key: 'status', type: 'text', label: 'X' });
caso('key reservada recusada', validarDefinicao(d, ctx), false, 'reservada');

// 7: remover pac_nome
d = clone(SEMENTE_HUSF);
for (const s of d.secoes) s.campos = s.campos.filter(c => c.key !== 'pac_nome');
caso('remoção de pac_nome recusada', validarDefinicao(d, ctx), false, 'pac_nome');

// 8: remover _sofa_bloco
d = clone(SEMENTE_HUSF);
for (const s of d.secoes) s.campos = s.campos.filter(c => c.key !== '_sofa_bloco');
caso('remoção de _sofa_bloco recusada', validarDefinicao(d, ctx), false, '_sofa_bloco');

// 9: remover campo comum → permitido
d = clone(SEMENTE_HUSF);
for (const s of d.secoes) s.campos = s.campos.filter(c => c.key !== 'cirurgia');
caso('remoção de campo comum permitida', validarDefinicao(d, ctx), true);

// 10: mudar tipo de campo integrado
d = clone(SEMENTE_HUSF);
for (const s of d.secoes) for (const c of s.campos) if (c.key === 'setor') c.type = 'text';
caso('mudança de tipo em campo integrado recusada', validarDefinicao(d, ctx), false, 'travado');

// 11: select sem opções
d = clone(SEMENTE_HUSF);
d.secoes[1].campos.push({ key: 'vazio_sel', type: 'select', label: 'X', options: [] });
caso('select sem opções recusado', validarDefinicao(d, ctx), false, 'exige ao menos uma opção');

// 12: cond referenciando campo inexistente
d = clone(SEMENTE_HUSF);
d.secoes[1].campos.push({ key: 'c1', type: 'text', label: 'X', cond: { campo: 'nao_existe', op: 'eq', valor: 'a' } });
caso('cond com campo inexistente recusada', validarDefinicao(d, ctx), false, 'inexistente');

// 13: cond com op desconhecido
d = clone(SEMENTE_HUSF);
d.secoes[1].campos.push({ key: 'c2', type: 'text', label: 'X', cond: { campo: 'setor', op: 'zzz', valor: 'a' } });
caso('cond com op desconhecido recusada', validarDefinicao(d, ctx), false, 'desconhecido');

// 14: op de lista sem array
d = clone(SEMENTE_HUSF);
d.secoes[1].campos.push({ key: 'c3', type: 'text', label: 'X', cond: { campo: 'setor', op: 'in', valor: 'a' } });
caso('op "in" sem lista recusado', validarDefinicao(d, ctx), false, 'lista');

// 15: seção com id inválido
d = clone(SEMENTE_HUSF);
d.secoes.push({ id: '9x!', titulo: 'Ruim', campos: [] });
caso('seção com id inválido recusada', validarDefinicao(d, ctx), false, 'id inválido');

// 16: statusCampos — integrado vs extras
d = clone(SEMENTE_HUSF);
d.secoes[1].campos.push({ key: 'alergias', type: 'checkbox', label: 'Alergias', options: ['Penicilina'] });
const st = statusCampos(d, COLS);
const okSt = st.setor && st.setor.temColuna === true && st.setor.naGrade === true
  && st.alergias && st.alergias.temColuna === false && st.alergias.origem === 'extras'
  && st.pac_nome && st.pac_nome.col === 'paciente_nome'
  && !('_sofa_bloco' in st) && !('dose_vanco' in st);
console.log(okSt ? '✅' : '❌', 'statusCampos: setor integrado+grade, alergias extras, widgets fora');
okSt ? passed++ : failed++;

console.log(`\n${passed} passaram, ${failed} falharam`);
if (failed) process.exit(1);
