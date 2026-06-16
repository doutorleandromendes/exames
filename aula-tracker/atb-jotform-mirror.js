// atb-jotform-mirror.js
// ─────────────────────────────────────────────────────────────────────────
// Espelhamento (PUSH) do sistema novo → JotForm, durante o SOFT LAUNCH.
//
// Liga com a env JOTFORM_MIRROR=on (e a JOTFORM_API_KEY que já existe).
// É TEMPORÁRIO: depois do soft launch, basta tirar a env (ou pôr =off).
//
// Princípio: NÃO-BLOQUEANTE. Qualquer falha aqui só gera log e segue —
// o sistema novo NUNCA quebra por causa do espelho.
//
// Escopo (campos do FORMULÁRIO, que viram submission e aparecem no Tables):
//   • Ficha do prescritor (identificação, internação, clínica, ATB, SOFA…)
//   • Parecer / complemento do SCIH (veredito, especificação, adicionais,
//     esquema, avaliador, complemento)
// FORA do escopo (colunas nativas do Tables, sem caminho de escrita na API):
//   • IrAS, Etiol IrAS, Micro (texto), SAPS3, Tempo_SAPS, Desfecho — ficam
//     só no sistema novo no período de soft launch.
// FASE 2 (não incluído aqui — codificação [linha][coluna] é mais trabalhosa):
//   • Matrizes: atb_previos(39), culturas_colhidas(42), culturas_previas(58),
//     posologia(45), parecer_evolutivo(61); e óbito(90)/data_obito(91).
// ─────────────────────────────────────────────────────────────────────────

const JOTFORM_API = 'https://api.jotform.com';

export function mirrorAtivo() {
  return String(process.env.JOTFORM_MIRROR || '').toLowerCase() === 'on'
      && !!process.env.JOTFORM_API_KEY;
}

// Coluna própria p/ o ID da submission-espelho (separada da
// jotform_submission_id, que o sistema novo usa como chave local).
export async function ensureMirrorSchema(pool) {
  await pool.query(`ALTER TABLE atb_fichas ADD COLUMN IF NOT EXISTS jotform_mirror_id TEXT`);
  await pool.query(`ALTER TABLE atb_fichas ADD COLUMN IF NOT EXISTS jotform_mirror_at TIMESTAMPTZ`);
}

// ── Mapa coluna_db → { qid, tipo } ────────────────────────────────────────
// tipos: 'simples' | 'bool' | 'nome' | 'data' | 'lista'
const MAPA_FICHA = [
  ['paciente_nome',          3,   'nome'],
  ['paciente_dn',            14,  'data'],
  ['paciente_idade',         95,  'simples'],
  ['prontuario',             107, 'simples'],
  ['atendimento',            63,  'simples'],
  ['setor',                  17,  'simples'],
  ['leito',                  36,  'simples'],
  ['equipe_responsavel',     75,  'simples'],
  ['data_internacao',        11,  'data'],
  ['data_admissao_uti',      113, 'data'],
  ['tipo_terapia',           60,  'simples'],
  ['historia_clinica',       10,  'simples'],
  ['cirurgia',               76,  'simples'],
  ['foco_infeccao',          40,  'simples'],
  ['sepse',                  41,  'bool'],
  ['gestante',               97,  'bool'],
  ['lactante',               98,  'bool'],
  ['comorbidades',           37,  'lista'],
  ['uso_atb_7d',             38,  'bool'],
  ['dispositivos_invasivos', 43,  'lista'],
  ['dialise',                59,  'bool'],
  ['acesso_dialise',         52,  'simples'],
  ['data_insercao_cateter',  87,  'data'],
  ['sitio_cvc',              116, 'lista'],
  ['sitio_cdl',              117, 'lista'],
  ['sitio_pai',              118, 'lista'],
  ['peso_nascimento',        54,  'simples'],
  ['acesso_vascular_neo',    55,  'lista'],
  ['insuficiencia_renal',    47,  'lista'],
  ['clcr',                   66,  'simples'],
  ['peso',                   67,  'simples'],
  ['altura',                 65,  'simples'],
  ['faz_quimio',             82,  'bool'],
  ['cateter_quimio',         84,  'bool'],
  ['acesso_quimio',          83,  'simples'],
  ['classificacao_fratura',  111, 'simples'],
  ['atb_solicitado',         44,  'lista'],
  ['tempo_previsto',         62,  'simples'],
  ['oxacilina_associacao',   152, 'bool'],
  ['crm',                    34,  'simples'],
  ['prescritor_nome',        32,  'simples'],
  ['sofa',                   142, 'simples'],
  ['sofa_renal',             141, 'simples'],
];

const MAPA_PARECER = [
  ['recomendacao_scih',           30,  'lista'],    // veredito (checkbox)
  ['recomendacoes_especificacao', 88,  'simples'],  // dropdown
  ['recomendacoes_adicionais',    35,  'simples'],  // textarea
  ['ha_esquema_sugerido',         164, 'simples'],  // radio
  ['avaliador',                   50,  'simples'],  // textbox
  ['complemento_scih',            99,  'simples'],  // textarea
];

const MAPA_TODOS = [...MAPA_FICHA, ...MAPA_PARECER];

// ── Codificação de valores p/ a API ───────────────────────────────────────
function val(v) { return (v === null || v === undefined) ? '' : String(v); }
function simNao(b) { return b === true ? 'Sim' : b === false ? 'Não' : ''; }
function arr(j) {
  if (Array.isArray(j)) return j;
  if (typeof j === 'string') { try { const p = JSON.parse(j); return Array.isArray(p) ? p : []; } catch { return []; } }
  return [];
}
function dmy(d) {
  if (!d) return null;
  const s = (d instanceof Date) ? d.toISOString().slice(0, 10) : String(d).slice(0, 10);
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(s);
  return m ? { year: m[1], month: m[2], day: m[3] } : null;
}

function setSimple(p, qid, v) { const s = val(v); if (s !== '') p.append(`submission[${qid}]`, s); }
function setNome(p, qid, nome) {
  const s = val(nome).trim(); if (!s) return;
  const partes = s.split(/\s+/);
  const first = partes.shift();
  const last = partes.join(' ');
  p.append(`submission[${qid}_first]`, first);
  if (last) p.append(`submission[${qid}_last]`, last);
}
function setData(p, qid, d) {
  const o = dmy(d); if (!o) return;
  p.append(`submission[${qid}_day]`,   o.day);
  p.append(`submission[${qid}_month]`, o.month);
  p.append(`submission[${qid}_year]`,  o.year);
}
function setLista(p, qid, j) {
  arr(j).forEach((v, i) => { const s = val(v); if (s !== '') p.append(`submission[${qid}][${i}]`, s); });
}

function montarParams(ficha, campos) {
  const p = new URLSearchParams();
  for (const [col, qid, tipo] of campos) {
    const v = ficha[col];
    if (tipo === 'nome')       setNome(p, qid, v);
    else if (tipo === 'data')  setData(p, qid, v);
    else if (tipo === 'lista') setLista(p, qid, v);
    else if (tipo === 'bool')  setSimple(p, qid, simNao(v));
    else                       setSimple(p, qid, v);
  }
  return p;
}

async function jotformPost(url, params) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });
  let data = null;
  try { data = await res.json(); } catch { /* resposta não-JSON */ }
  if (!res.ok || !data || Number(data.responseCode) !== 200) {
    throw new Error('JotForm ' + (data?.responseCode || res.status) + ': ' + (data?.message || res.statusText));
  }
  return data.content;
}

// Qual submission é o "espelho" desta ficha?
//  • ficha nova do sistema → jotform_mirror_id (a que criamos)
//  • ficha migrada/antiga  → jotform_submission_id (a submission ORIGINAL real)
//  • senão                 → null (precisa criar)
function idEspelho(f) {
  if (f.jotform_mirror_id) return f.jotform_mirror_id;
  if (f.jotform_submission_id && !/^form_/.test(f.jotform_submission_id)) return f.jotform_submission_id;
  return null;
}

// ── API pública ───────────────────────────────────────────────────────────

// Cria a submission-espelho de uma ficha nova. Guarda o ID em jotform_mirror_id.
export async function espelharNovaFicha(pool, fichaId) {
  if (!mirrorAtivo()) return;
  try {
    const f = (await pool.query('SELECT * FROM atb_fichas WHERE id=$1', [fichaId])).rows[0];
    if (!f) return;
    if (idEspelho(f)) return; // já tem espelho (mirror ou submission original)

    const formId = (await pool.query(
      'SELECT jotform_form_id FROM atb_instituicoes WHERE id=$1', [f.instituicao_id]
    )).rows[0]?.jotform_form_id;
    if (!formId) { console.warn('[mirror] sem jotform_form_id p/ instituição', f.instituicao_id); return; }

    const params = montarParams(f, MAPA_TODOS); // campos vazios são ignorados
    const key = process.env.JOTFORM_API_KEY;
    const content = await jotformPost(`${JOTFORM_API}/form/${formId}/submissions?apiKey=${key}`, params);
    const subId = content?.submissionID || content?.submissionId || null;
    if (!subId) { console.warn('[mirror] create sem submissionID:', JSON.stringify(content).slice(0, 200)); return; }

    await pool.query(
      'UPDATE atb_fichas SET jotform_mirror_id=$1, jotform_mirror_at=now() WHERE id=$2',
      [String(subId), fichaId]
    );
    console.log('[mirror] ficha', fichaId, '→ submission', subId);
  } catch (e) {
    console.error('[mirror] espelharNovaFicha', fichaId, '-', e.message);
  }
}

// Edita a submission-espelho (parecer, complemento, ou edição de campos).
// `colunas` = lista de colunas_db a re-enviar (ex.: ['recomendacao_scih','avaliador']).
export async function espelharEdicao(pool, fichaId, colunas) {
  if (!mirrorAtivo()) return;
  try {
    const f = (await pool.query('SELECT * FROM atb_fichas WHERE id=$1', [fichaId])).rows[0];
    if (!f) return;

    const subId = idEspelho(f);
    if (!subId) { await espelharNovaFicha(pool, fichaId); return; } // ainda sem espelho → cria do zero

    const cols = Array.isArray(colunas) ? colunas : [colunas];
    const sel = MAPA_TODOS.filter(([col]) => cols.includes(col));
    if (!sel.length) return;

    const params = montarParams(f, sel);
    if ([...params.keys()].length === 0) return; // nada a enviar (tudo vazio)

    const key = process.env.JOTFORM_API_KEY;
    await jotformPost(`${JOTFORM_API}/submission/${subId}?apiKey=${key}`, params);
    console.log('[mirror] ficha', fichaId, 'editou [' + cols.join(',') + '] → sub', subId);
  } catch (e) {
    console.error('[mirror] espelharEdicao', fichaId, '-', e.message);
  }
}

// Colunas usadas em cada gancho (atalhos p/ a integração).
export const CAMPOS_PARECER = [
  'recomendacao_scih', 'recomendacoes_especificacao', 'recomendacoes_adicionais',
  'ha_esquema_sugerido', 'avaliador',
];
export const CAMPOS_COMPLEMENTO = ['complemento_scih'];
