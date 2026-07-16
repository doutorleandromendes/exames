// harness-isc-rotas.mjs — E2E das rotas ISC contra Postgres real.
// Sobe um Express de verdade, monta registerIscRoutes e percorre o fluxo:
// criar ficha → tentativa falha → contato com alerta → classificar → grid →
// agenda → cron → CSV. Valida também o isolamento entre tenants.
//
// Uso: ISC_TEST_DB=postgresql://... node harness-isc-rotas.mjs
import express from 'express';
import { Pool } from 'pg';
import { registerIscRoutes } from './isc-routes.js';
import { runIscMigrations } from './isc-db.js';
import { renderShell } from './ui-shell.js';
import { addDays, hojeISO } from './isc-core.js';

const DB = process.env.ISC_TEST_DB || 'postgresql://postgres:x@localhost:5432/iscteste';
const pool = new Pool({ connectionString: DB });

let ok = 0, fail = 0;
const t = (nome, cond, extra = '') => {
  if (cond) { ok++; console.log('  ✓', nome); }
  else { fail++; console.log('  ✗ FALHOU:', nome, extra); }
};

await runIscMigrations(pool);
await pool.query('TRUNCATE isc_envios, isc_contatos, isc_fichas RESTART IDENTITY CASCADE');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
// Sessão de médico do SCIH: este harness exercita o módulo inteiro, inclusive a
// classificação (que é ato médico). A separação colaboradora × médico tem
// harness próprio (harness-isc-perfis).
app.use((req, res, next) => { req.user = { id: 1, full_name: 'Dr. Leandro', scih: true, super_admin: true }; next(); });
registerIscRoutes(app, pool, (req, res, next) => next(), renderShell);
const srv = app.listen(0);
const base = `http://127.0.0.1:${srv.address().port}`;

// Arrays precisam virar CHAVES REPETIDAS (checkbox HTML), não "a,b".
function formBody(obj) {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(obj)) {
    if (Array.isArray(v)) v.forEach(x => u.append(k, x));
    else u.append(k, v);
  }
  return u;
}
const post = (url, body) => fetch(base + url, {
  method: 'POST', redirect: 'manual',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: formBody(body),
});
const get = url => fetch(base + url, { redirect: 'manual' });

const { rows: insts } = await pool.query(`SELECT id, sigla FROM atb_instituicoes`);
const HUSF = insts.find(i => i.sigla === 'HUSF').id;
const SCMI = insts.find(i => i.sigla === 'SCMI').id;
const { rows: eqs } = await pool.query(`SELECT id, nome FROM isc_equipes WHERE instituicao_id=$1 ORDER BY ordem`, [HUSF]);
const NEURO = eqs[0].id;

const D0 = addDays(hojeISO(), -35);   // cirurgia há 35 dias: 7d e 30d vencidos

console.log('\n── Criação de ficha ──');
let r = await post('/isc/admin/fichas?inst=HUSF', {
  paciente_nome: 'MARIA DAS DORES SILVA', paciente_iniciais: 'M.D.S.',
  prontuario: '123456', atendimento: 'AT-9001', telefone: '(11) 91234-5678',
  equipe_id: NEURO, procedimento: 'Craniotomia para tumor', cirurgiao: 'Dr. X',
  data_cirurgia: D0, implante: '1', janelas: '',
});
t('POST /fichas redireciona', r.status === 302, `status=${r.status}`);
const fid = Number(r.headers.get('location').split('/').pop());
t('ficha criada com id', Number.isInteger(fid) && fid > 0);

let { rows: [f] } = await pool.query('SELECT * FROM isc_fichas WHERE id=$1', [fid]);
t('telefone normalizado E.164', f.telefone === '5511912345678', f.telefone);
t('telefone_raw preservado', f.telefone_raw === '(11) 91234-5678');
t('implante → janelas [7,30,90] da equipe', JSON.stringify(f.janelas) === '[7,30,90]', JSON.stringify(f.janelas));
t('tenant gravado', f.instituicao_id === HUSF);
t('estado sincronizado na criação', f.proxima_janela === 7, `proxima=${f.proxima_janela}`);
t('próximo contato = D+7', f.proximo_contato_em.toISOString().slice(0, 10) === addDays(D0, 7));

console.log('\n── Anti-duplicata ──');
r = await post('/isc/admin/fichas?inst=HUSF', {
  paciente_nome: 'OUTRA PESSOA', atendimento: 'AT-9001', data_cirurgia: D0, equipe_id: NEURO, procedimento: 'x',
});
t('mesmo atendimento+data → 409', r.status === 409, `status=${r.status}`);

console.log('\n── Tentativa sem sucesso ──');
r = await post(`/isc/admin/ficha/${fid}/contato?inst=HUSF`, {
  janela: '7', canal: 'whatsapp', sem_sucesso: '1', motivo_insucesso: 'nao_atende', responsavel: 'Ana',
});
t('registra tentativa falha', r.status === 302);
({ rows: [f] } = await pool.query('SELECT * FROM isc_fichas WHERE id=$1', [fid]));
t('conta tentativa falha', f.tentativas_falhas === 1, `=${f.tentativas_falhas}`);
t('falha NÃO marca janela como concluída', f.janelas_estado['7'].status === 'sem_contato', JSON.stringify(f.janelas_estado['7']));
t('falha não conta como contato ok', f.contatos_ok === 0);
t('sem alerta ainda', f.tem_alerta === false);

console.log('\n── Contato com sucesso + alerta ──');
r = await post(`/isc/admin/ficha/${fid}/contato?inst=HUSF`, {
  janela: '7', canal: 'whatsapp', data_contato: addDays(D0, 8), informante: 'João (filho)',
  r_febre: 'Sim', r_ferida: ['Secreção purulenta', 'Hiperemia local'], r_alta: 'Sim',
  r_atb_pos: 'Não', recomendacoes: ['Procurar UBS / PS'], suspeita_isc: '1', responsavel: 'Ana',
});
t('registra contato', r.status === 302);
({ rows: [f] } = await pool.query('SELECT * FROM isc_fichas WHERE id=$1', [fid]));
t('janela 7 concluída → avança p/ 30', f.proxima_janela === 30, `=${f.proxima_janela}`);
t('alerta acendeu', f.tem_alerta === true);
t('suspeita marcada', f.suspeita_isc === true);
t('contatos_ok = 1', f.contatos_ok === 1);
t('estado da janela 7', f.janelas_estado['7'].status === 'concluida', JSON.stringify(f.janelas_estado['7']));

const { rows: [c] } = await pool.query('SELECT * FROM isc_contatos WHERE ficha_id=$1 AND sucesso=true', [fid]);
t('respostas gravadas em JSONB', c.respostas.febre === 'Sim' && c.respostas.ferida.length === 2, JSON.stringify(c.respostas));
t('recomendações gravadas', JSON.stringify(c.recomendacoes) === '["Procurar UBS / PS"]');

console.log('\n── Injeção no checklist ──');
await post(`/isc/admin/ficha/${fid}/contato?inst=HUSF`, {
  janela: '30', r_febre: 'PWNED', r_ferida: ['OPÇÃO FALSA'], campo_injetado: 'x', recomendacoes: ['REC FALSA'],
});
const { rows: [c2] } = await pool.query(`SELECT * FROM isc_contatos WHERE ficha_id=$1 AND janela=30`, [fid]);
t('valor inválido em sim_nao descartado', c2.respostas.febre === undefined, JSON.stringify(c2.respostas));
t('opção falsa em multi descartada', c2.respostas.ferida === undefined);
t('campo fora do checklist descartado', c2.respostas.campo_injetado === undefined);
t('recomendação falsa descartada', JSON.stringify(c2.recomendacoes) === '[]');

console.log('\n── Classificação SCIH ──');
r = await post(`/isc/admin/ficha/${fid}/classificar?inst=HUSF`, {
  isc_classificacao: 'confirmada', isc_tipo: 'incisional_profunda',
  isc_data_diagnostico: addDays(D0, 9), isc_criterios: ['Drenagem purulenta da incisão', 'CRITÉRIO FALSO'],
  isc_patogeno: 'S. aureus MSSA', isc_reabordagem: '1', classificado_por: 'Dr. Leandro',
});
t('classifica', r.status === 302);
({ rows: [f] } = await pool.query('SELECT * FROM isc_fichas WHERE id=$1', [fid]));
t('classificação salva', f.isc_classificacao === 'confirmada');
t('tipo NHSN salvo', f.isc_tipo === 'incisional_profunda');
t('critério falso filtrado', f.isc_criterios.length === 1, JSON.stringify(f.isc_criterios));
t('patógeno salvo', f.isc_patogeno === 'S. aureus MSSA');
t('carimbo de autoria', !!f.classificado_em && f.classificado_por === 'Dr. Leandro');

r = await post(`/isc/admin/ficha/${fid}/classificar?inst=HUSF`, { isc_classificacao: 'VALOR_INVALIDO' });
({ rows: [f] } = await pool.query('SELECT * FROM isc_fichas WHERE id=$1', [fid]));
t('enum inválido cai p/ nao_avaliada', f.isc_classificacao === 'nao_avaliada', f.isc_classificacao);
await post(`/isc/admin/ficha/${fid}/classificar?inst=HUSF`, {
  isc_classificacao: 'confirmada', isc_tipo: 'incisional_profunda', isc_patogeno: 'S. aureus MSSA',
});

console.log('\n── Isolamento entre tenants ──');
const { rows: [scmi] } = await pool.query(
  `INSERT INTO isc_fichas (instituicao_id, paciente_nome, data_cirurgia, atendimento)
   VALUES ($1,'PACIENTE SCMI',$2,'AT-SCMI-1') RETURNING id`, [SCMI, D0]);
r = await get(`/isc/admin/ficha/${scmi.id}?inst=HUSF`);
t('ficha SCMI vista como HUSF → 404 opaco', r.status === 404, `status=${r.status}`);
r = await get(`/isc/admin/ficha/${scmi.id}?inst=SCMI`);
t('ficha SCMI vista como SCMI → 200', r.status === 200);
r = await post(`/isc/admin/ficha/${scmi.id}/classificar?inst=HUSF`, { isc_classificacao: 'confirmada' });
t('escrita cross-tenant bloqueada', r.status === 404, `status=${r.status}`);
({ rows: [f] } = await pool.query('SELECT * FROM isc_fichas WHERE id=$1', [scmi.id]));
t('ficha SCMI intacta', f.isc_classificacao === 'nao_avaliada');

let html = await (await get('/isc/admin/grid?inst=HUSF')).text();
t('grid HUSF mostra paciente HUSF', html.includes('MARIA DAS DORES'));
t('grid HUSF NÃO vaza paciente SCMI', !html.includes('PACIENTE SCMI'));
html = await (await get('/isc/admin/grid?inst=SCMI')).text();
t('grid SCMI não vaza paciente HUSF', !html.includes('MARIA DAS DORES'));

console.log('\n── Grid: filtros e XSS ──');
html = await (await get('/isc/admin/grid?inst=HUSF')).text();
t('métrica ISC confirmada = 1', /">1<\/div><div class="ml">ISC confirmadas/.test(html));
t('badge de janela renderiza', html.includes('7d ✓'));
t('filtro por classificação', (await (await get('/isc/admin/grid?inst=HUSF&classif=confirmada')).text()).includes('MARIA DAS DORES'));
t('filtro classif que não bate → vazio', (await (await get('/isc/admin/grid?inst=HUSF&classif=descartada')).text()).includes('Nenhuma ficha'));
t('filtro por mês (range)', (await (await get(`/isc/admin/grid?inst=HUSF&mes=${D0.slice(0, 7)}`)).text()).includes('MARIA DAS DORES'));
t('filtro mês errado → vazio', (await (await get('/isc/admin/grid?inst=HUSF&mes=1999-01')).text()).includes('Nenhuma ficha'));
t('busca por prontuário', (await (await get('/isc/admin/grid?inst=HUSF&busca=123456')).text()).includes('MARIA DAS DORES'));
t('só alerta', (await (await get('/isc/admin/grid?inst=HUSF&alerta=1')).text()).includes('MARIA DAS DORES'));
r = await get(`/isc/admin/grid?inst=HUSF&busca=${encodeURIComponent("'; DROP TABLE isc_fichas; --")}`);
t('SQL injection na busca não derruba', r.status === 200);
t('tabela sobreviveu', (await pool.query('SELECT count(*) FROM isc_fichas')).rows[0].count >= '2');

await pool.query(`UPDATE isc_fichas SET paciente_nome='<script>alert(1)</script>' WHERE id=$1`, [scmi.id]);
html = await (await get('/isc/admin/grid?inst=SCMI')).text();
t('XSS escapado no grid', !html.includes('<script>alert(1)</script>') && html.includes('&lt;script&gt;'));

console.log('\n── Agenda ──');
// Ficha nova e limpa: a MARIA já teve 7d e 30d registrados, só resta a 90d
// (no futuro) — não deve mesmo aparecer na fila.
const D1 = addDays(hojeISO(), -10);   // janela 7d aberta, nada registrado
r = await post('/isc/admin/fichas?inst=HUSF', {
  paciente_nome: 'JOSE PEREIRA', prontuario: '777', atendimento: 'AT-9002',
  telefone: '11987654321', equipe_id: NEURO, procedimento: 'Artrodese', data_cirurgia: D1,
});
const fid2 = Number(r.headers.get('location').split('/').pop());

html = await (await get('/isc/admin/agenda?inst=HUSF&dias=0')).text();
t('agenda NÃO lista quem só tem janela futura', !html.includes('MARIA DAS DORES'));
t('agenda lista quem tem contato vencido', html.includes('JOSE PEREIRA'));
t('mensagem renderizada com primeiro nome', html.includes('Olá, Jose!'));
t('link wa.me montado', html.includes('https://wa.me/5511987654321'));
t('janela certa na fila', html.includes('janela 7d'));
t('não vaza placeholder', !html.includes('{{'));

console.log('\n── Número institucional e autoteste de remetente ──');
// O wa.me NÃO escolhe o remetente — sai da conta logada no navegador, e o
// servidor não tem como saber qual é. O que dá para fazer é lembrar qual
// DEVERIA ser e oferecer um autoteste seguro (conversa com o próprio Business).
await pool.query('DELETE FROM isc_config');
html = await (await get('/isc/admin/agenda?inst=HUSF&dias=0')).text();
t('sem número → agenda avisa', html.includes('não configurado'));
t('link wa.me do paciente continua funcionando', html.includes('https://wa.me/5511987654321'));

r = await post('/isc/admin/config?inst=HUSF', { whatsapp_business: '11 24901268' });
t('salva o número', r.status === 302);
t('grava em E.164 (fixo institucional é válido no Business)',
  (await pool.query('SELECT whatsapp_business w FROM isc_config')).rows[0].w === '551124901268');
r = await post('/isc/admin/config?inst=HUSF', { whatsapp_business: '24901268' });
t('sem DDD → 400', r.status === 400, `status=${r.status}`);
t('e não sobrescreve o número bom',
  (await pool.query('SELECT whatsapp_business w FROM isc_config')).rows[0].w === '551124901268');
r = await post('/isc/admin/config?inst=HUSF', { whatsapp_business: 'abc' });
t('lixo → 400', r.status === 400);

html = await (await get('/isc/admin/agenda?inst=HUSF&dias=0')).text();
t('banner mostra o número formatado', html.includes('(11) 2490-1268'));
t('autoteste aponta para o próprio Business', html.includes('https://wa.me/551124901268'));
t('explica o sinal "(Você)"', html.includes('(Você)'));
t('avisa que sai da conta do navegador', html.includes('neste navegador'));
html = await (await get('/isc/admin/templates?inst=HUSF')).text();
t('tela de mensagens tem o form do número', html.includes('name="whatsapp_business"'));
html = await (await get('/isc/admin/agenda?inst=SCMI')).text();
t('SCMI não vê o número do HUSF', !html.includes('2490-1268'));

console.log('\n── Cron ──');
r = await post('/isc/cron/agendar', {});
t('cron responde 202 imediato', r.status === 202, `status=${r.status}`);
t('cron responde JSON ok', (await r.json()).ok === true);
await new Promise(s => setTimeout(s, 900));
let { rows: env } = await pool.query('SELECT * FROM isc_envios');
t('envio agendado na fila', env.length >= 1, `n=${env.length}`);
t('corpo renderizado no snapshot', env[0] && env[0].corpo.includes('Jose'));
t('status pendente', env[0]?.status === 'pendente');
await post('/isc/cron/agendar', {});
await new Promise(s => setTimeout(s, 900));
const { rows: env2 } = await pool.query('SELECT * FROM isc_envios');
t('cron idempotente (não duplica)', env2.length === env.length, `${env.length} → ${env2.length}`);

r = await post('/isc/cron/sincronizar', {});
t('sincronizar responde 202', r.status === 202);
await new Promise(s => setTimeout(s, 900));

console.log('\n── CSV ──');
r = await get('/isc/admin/export.csv?inst=HUSF');
const csvBytes = new Uint8Array(await r.clone().arrayBuffer());
const csv = await r.text();
t('CSV content-type', (r.headers.get('content-type') || '').includes('text/csv'));
// fetch.text() remove o BOM por spec — conferir nos BYTES.
t('CSV tem BOM (Excel-BR abre acento certo)',
  csvBytes[0] === 0xEF && csvBytes[1] === 0xBB && csvBytes[2] === 0xBF,
  `bytes=${csvBytes.slice(0, 3)}`);
t('CSV tem cabeçalho', csv.includes('paciente_nome;'));
t('CSV tem o paciente', csv.includes('MARIA DAS DORES SILVA'));
t('CSV não vaza SCMI', !csv.includes('PACIENTE SCMI'));

console.log('\n── Ficha (render) ──');
html = await (await get(`/isc/admin/ficha/${fid}?inst=HUSF`)).text();
t('ficha renderiza', html.includes('MARIA DAS DORES'));
t('timeline mostra contato', html.includes('contato realizado'));
t('timeline mostra tentativa falha', html.includes('sem sucesso'));
t('checklist no form', html.includes('Como está a ferida?'));
t('classificação carregada', html.includes('S. aureus MSSA'));
r = await get('/isc/admin/ficha/999999?inst=HUSF');
t('ficha inexistente → 404', r.status === 404);

console.log('\n── Templates ──');
html = await (await get('/isc/admin/templates?inst=HUSF')).text();
t('lista templates', html.includes('Busca ativa · 7 dias'));
r = await post('/isc/admin/templates?inst=HUSF', { nome: 'Teste', janela: '15', corpo: 'Oi {{primeiro_nome}}', ativo: '1', ordem: '99' });
t('cria template', r.status === 302);
t('template persistido', (await pool.query(`SELECT count(*)::int n FROM isc_msg_templates WHERE nome='Teste'`)).rows[0].n === 1);

srv.close(); await pool.end();
console.log(`\n${'═'.repeat(52)}\n${ok} passaram · ${fail} falharam\n`);
process.exit(fail ? 1 : 0);
