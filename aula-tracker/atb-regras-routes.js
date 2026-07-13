// atb-regras-routes.js
// ─────────────────────────────────────────────────────────────────────────
// PAINEL DE REGRAS DE TRIAGEM (Fase 2 — o "controle").  Super-admin.
//   /atb/admin/regras            → lista (ligar/desligar, prioridade, editar, excluir)
//   /atb/admin/regras/nova|:id   → editor (construtor de condições + ações)
//   POST .../salvar[/:id]        → cria/edita
//   POST .../:id/toggle          → ativa/desativa
//   POST .../:id/excluir         → remove
//   POST .../testar              → roda a regra nas fichas históricas (dry-run)
//
// IMPORTANTE: o catálogo de campos abaixo fala a LÍNGUA DO BANCO (as colunas
// que a aplicarRegras enxerga), não a do formulário. Ex.: equipe_responsavel
// (não 'equipe'), e os bool vão como true/false (não 'Sim'/'Não').
//
// Integração em atb-routes.js:
//   import { registerRegrasRoutes } from './atb-regras-routes.js';
//   // em registerAtbRoutes:  registerRegrasRoutes(app, pool, scihRequired);
// ─────────────────────────────────────────────────────────────────────────

import { PARECER_VEREDITOS } from './atb-parecer-edit-routes.js';
import { avaliaCond, contextoFicha, aplicarRegras } from './atb-triagem-regras.js';

// Subquery correlacionada: nº de OUTRAS fichas (mesmo tenant + prontuário + setor) nas
// 72h ANTERIORES à própria. Espelha fichas_72h_mesmo_setor do aplicarRegras (cross-ficha),
// para que /testar e o backfill avaliem regras que usam esse campo derivado.
const SUB_FICHAS_72H = `(
  SELECT COUNT(*)::int FROM atb_fichas o
   WHERE o.id <> f.id AND o.deletado_em IS NULL
     AND o.instituicao_id IS NOT DISTINCT FROM f.instituicao_id
     AND o.prontuario = f.prontuario AND o.setor = f.setor
     AND COALESCE(o.data_referencia,o.jotform_created_at,o.created_at) >= (COALESCE(f.data_referencia,f.jotform_created_at,f.created_at) - interval '72 hours')
     AND COALESCE(o.data_referencia,o.jotform_created_at,o.created_at) <  COALESCE(f.data_referencia,f.jotform_created_at,f.created_at)
)`;

// Fichas REPETIDAS: nº de OUTRAS fichas (mesmo tenant + prontuário) com ATB sobreposto,
// nas 72h anteriores à própria. Espelha fichas_72h_mesmo_atb do aplicarRegras.
const SUB_FICHAS_72H_ATB = `(
  SELECT COUNT(*)::int FROM atb_fichas o
   WHERE o.id <> f.id AND o.deletado_em IS NULL
     AND o.instituicao_id IS NOT DISTINCT FROM f.instituicao_id
     AND o.prontuario = f.prontuario
     AND jsonb_typeof(f.atb_solicitado)='array' AND jsonb_typeof(o.atb_solicitado)='array'
     AND o.atb_solicitado ?| ARRAY(SELECT jsonb_array_elements_text(f.atb_solicitado))
     AND COALESCE(o.data_referencia,o.jotform_created_at,o.created_at) >= (COALESCE(f.data_referencia,f.jotform_created_at,f.created_at) - interval '72 hours')
     AND COALESCE(o.data_referencia,o.jotform_created_at,o.created_at) <  COALESCE(f.data_referencia,f.jotform_created_at,f.created_at)
)`;

// Match cultura↔ficha por ATENDIMENTO na janela −30d/+5d (backfill/testar). O caminho
// VIVO (aplicarRegras) usa buscarCulturasDaFicha, que também casa por nome; aqui, por
// simplicidade/perf no lote, casamos só por atendimento (cobre os internados do HUSF).
const _CULT_MATCH = `c.instituicao_id IS NOT DISTINCT FROM f.instituicao_id
     AND ( (COALESCE(f.prontuario,'') <> '' AND c.prontuario = f.prontuario)
          OR (COALESCE(f.atendimento,'') <> '' AND c.atendimento = f.atendimento) )
     AND c.data_coleta >= (COALESCE(f.data_referencia,f.jotform_created_at,f.created_at)::date - interval '30 days')
     AND c.data_coleta <= (COALESCE(f.data_referencia,f.jotform_created_at,f.created_at)::date + interval '5 days')`;
// Variante da janela p/ o trigger de monitoramento: hemocultura −5d/+5d.
const _CULT_MATCH_55 = `c.instituicao_id IS NOT DISTINCT FROM f.instituicao_id
     AND ( (COALESCE(f.prontuario,'') <> '' AND c.prontuario = f.prontuario)
          OR (COALESCE(f.atendimento,'') <> '' AND c.atendimento = f.atendimento) )
     AND c.data_coleta >= (COALESCE(f.data_referencia,f.jotform_created_at,f.created_at)::date - interval '5 days')
     AND c.data_coleta <= (COALESCE(f.data_referencia,f.jotform_created_at,f.created_at)::date + interval '5 days')`;
const SUB_CULT_POS = `EXISTS(SELECT 1 FROM atb_culturas c WHERE ${_CULT_MATCH})`;
const SUB_CULT_MR  = `ARRAY(SELECT DISTINCT c.resistencia FROM atb_culturas c WHERE ${_CULT_MATCH} AND c.resistencia IS NOT NULL)`;
const SUB_CULT_ORG = `(SELECT string_agg(DISTINCT c.microorganismo, ' | ') FROM atb_culturas c WHERE ${_CULT_MATCH} AND c.microorganismo IS NOT NULL)`;
const SUB_CULT_MAT = `(SELECT string_agg(DISTINCT c.material, ' | ') FROM atb_culturas c WHERE ${_CULT_MATCH} AND c.material IS NOT NULL)`;
const SUB_CULT_HEMO = `(EXISTS(SELECT 1 FROM atb_culturas c WHERE ${_CULT_MATCH} AND c.material ILIKE '%hemocultura%') OR EXISTS(SELECT 1 FROM atb_hemocultura_alertas h WHERE ${_HEMO_AL_MATCH}))`;
const SUB_CULT_HEMO_55 = `(EXISTS(SELECT 1 FROM atb_culturas c WHERE ${_CULT_MATCH_55} AND c.material ILIKE '%hemocultura%') OR EXISTS(SELECT 1 FROM atb_hemocultura_alertas h WHERE ${_HEMO_AL_MATCH_55}))`;
// 2ª fonte de hemocultura positiva: alerta de e-mail (atb_hemocultura_alertas).
const _HEMO_AL_MATCH = `h.instituicao_id IS NOT DISTINCT FROM f.instituicao_id
     AND ( (COALESCE(f.prontuario,'') <> '' AND h.prontuario = f.prontuario)
          OR (COALESCE(f.atendimento,'') <> '' AND h.atendimento = f.atendimento) )
     AND COALESCE(h.data_positividade, h.recebido_em::date) >= (COALESCE(f.data_referencia,f.jotform_created_at,f.created_at)::date - interval '30 days')
     AND COALESCE(h.data_positividade, h.recebido_em::date) <= (COALESCE(f.data_referencia,f.jotform_created_at,f.created_at)::date + interval '5 days')`;
const _HEMO_AL_MATCH_55 = `h.instituicao_id IS NOT DISTINCT FROM f.instituicao_id
     AND ( (COALESCE(f.prontuario,'') <> '' AND h.prontuario = f.prontuario)
          OR (COALESCE(f.atendimento,'') <> '' AND h.atendimento = f.atendimento) )
     AND COALESCE(h.data_positividade, h.recebido_em::date) >= (COALESCE(f.data_referencia,f.jotform_created_at,f.created_at)::date - interval '5 days')
     AND COALESCE(h.data_positividade, h.recebido_em::date) <= (COALESCE(f.data_referencia,f.jotform_created_at,f.created_at)::date + interval '5 days')`;

// Só computa as subqueries (caras, correlacionadas por ficha) que a(s) regra(s)
// realmente referenciam — evita rodar todas no /testar e no backfill (timeout).
const SUB_MAP = [
  ['fichas_72h_mesmo_setor', `${SUB_FICHAS_72H} AS _fichas72h`],
  ['fichas_72h_mesmo_atb',   `${SUB_FICHAS_72H_ATB} AS _fichas72hatb`],
  ['cultura_positiva',       `${SUB_CULT_POS} AS _cult_pos`],
  ['cultura_mr',             `${SUB_CULT_MR} AS _cult_mr`],
  ['cultura_organismos',     `${SUB_CULT_ORG} AS _cult_org`],
  ['cultura_materiais',      `${SUB_CULT_MAT} AS _cult_mat`],
  ['cultura_hemocultura',    `${SUB_CULT_HEMO} AS _cult_hemo`],
  ['hemocultura_5d5d',       `${SUB_CULT_HEMO_55} AS _hemo55`],
];
function camposDaRegra(cond, acc) {
  acc = acc || new Set();
  if (!cond) return acc;
  if (cond.all) cond.all.forEach(c => camposDaRegra(c, acc));
  if (cond.any) cond.any.forEach(c => camposDaRegra(c, acc));
  if (cond.campo) acc.add(cond.campo);
  return acc;
}
function subSqlDe(campos) {
  const sel = SUB_MAP.filter(([k]) => campos.has(k)).map(([, frag]) => frag);
  return sel.length ? ', ' + sel.join(', ') : '';
}
import { getFormSchema } from './atb-form-schema.js';

export const IRAS_VALORES = ['PAV','PAV/EVA','IPCSLab','IPCSClin','ITU','ISC','(HD)ILAV','(HD)ICS',
  '(HD)Bact','HD_Bact_FAV','HD_Bact_CDL','HD_Bact_PC','HD_ILAV_FAV','HD_ILAV_CDL','HD_ILAV_PC',
  'CDI','Onco_Bact','Sem dados','Descartado','Repetida'];

// ── Catálogo de campos DERIVADO DO SCHEMA do formulário ─────────────────
// Antes era uma lista fixa que sempre atrasava em relação ao formulário. Agora
// TODO campo do schema vira condição automaticamente. O catálogo fala a LÍNGUA
// DO BANCO (colunas que a aplicarRegras enxerga): chaves do schema que diferem
// da coluna são renomeadas, Sim/Não que viram boolean entram como 'bool', e os
// calculados (SOFA/idade) entram como extras.

// chave do schema → coluna real (quando diferem; ver atb-parser.js)
const COLUNA_DE = {
  pac_nome: 'paciente_nome', pac_dn: 'paciente_dn',
  equipe: 'equipe_responsavel', data_uti: 'data_admissao_uti',
};
// Sim/Não gravados como BOOLEAN no banco (parser toB) → tipo 'bool'.
// (sinais_dialise NÃO entra aqui: é TEXT 'Sim'/'Não' → vira 'select'.)
const BOOL_KEYS = new Set(['sepse','gestante','lactante','uso_atb_7d','dialise',
  'faz_quimio','cateter_quimio','oxacilina_associacao']);
// Calculados/derivados (não existem no schema). idade_* são computados em
// contextoFicha; sofa/sofa_renal são colunas reais preenchidas pelo parser.
const EXTRAS = [
  { key:'sofa', label:'SOFA', tipo:'numero' },
  { key:'sofa_renal', label:'SOFA renal', tipo:'numero' },
  { key:'idade_dias', label:'Idade (dias)', tipo:'numero', calc:true },
  { key:'idade_meses', label:'Idade (meses)', tipo:'numero', calc:true },
  { key:'idade_anos', label:'Idade (anos)', tipo:'numero', calc:true },
  { key:'dias_internacao', label:'Dias desde a internação', tipo:'numero', calc:true },
  { key:'dias_uti', label:'Dias desde admissão na UTI', tipo:'numero', calc:true },
  { key:'fichas_72h_mesmo_setor', label:'Outras fichas (mesmo prontuário+setor, 72h)', tipo:'numero', calc:true },
  { key:'fichas_72h_mesmo_atb', label:'Solicitações repetidas (mesmo prontuário+ATB, 72h)', tipo:'numero', calc:true },
  { key:'cultura_positiva',   label:'Cultura positiva (30d antes / 5d depois)', tipo:'bool',  calc:true },
  { key:'cultura_mr',         label:'Resistências em cultura (MR, 30d/5d)',     tipo:'multi', calc:true, opcoes:['EPC','ESBL','KPC','METALO','MR','MRSA','OXA-R','VRE'] },
  { key:'cultura_organismos', label:'Microrganismos em cultura (30d/5d)',       tipo:'texto', calc:true },
  { key:'cultura_materiais',  label:'Materiais de cultura (30d/5d)',            tipo:'texto', calc:true },
  { key:'cultura_hemocultura', label:'Hemocultura positiva (30d/5d)',            tipo:'bool',  calc:true },
  { key:'hemocultura_5d5d',    label:'Hemocultura positiva (−5d/+5d, monitoramento)', tipo:'bool',  calc:true },
  { key:'dias_desde_submissao', label:'Dias desde a submissão', tipo:'numero', calc:true },
];
// Chaves CALCULADAS em contextoFicha (sem coluna real em atb_fichas): aparecem no
// catálogo, mas NUNCA entram no SELECT do dry-run. Fonte única para os dois filtros.
const CALC_KEYS = new Set(EXTRAS.filter(e => e.calc).map(e => e.key));

function tipoTriagemCampo(c){
  switch(c.type){
    case 'number': return 'numero';
    case 'checkbox': return 'multi';
    case 'radio': case 'select': return BOOL_KEYS.has(c.key) ? 'bool' : 'select';
    case 'text': case 'textarea': case 'crm': case 'date': return 'texto';
    default: return null; // matrix, sofa(_bloco), check — não viram condição
  }
}
function construirCampos(schema){
  const out = [], vis = new Set();
  for(const sec of (schema?.secoes || [])){
    for(const c of (sec.campos || [])){
      if(!c || !c.key || c.key.charAt(0) === '_') continue;   // pula _sofa_bloco
      const tipo = tipoTriagemCampo(c); if(!tipo) continue;    // pula matriz/sofa/check
      const key = COLUNA_DE[c.key] || c.key;
      if(vis.has(key)) continue; vis.add(key);
      const item = { key, label: c.label || key, tipo };
      if((tipo === 'select' || tipo === 'multi') && Array.isArray(c.options) && c.options.length)
        item.opcoes = c.options.slice();
      out.push(item);
    }
  }
  for(const e of EXTRAS) if(!vis.has(e.key)){ out.push(e); vis.add(e.key); }
  return out;
}

// Colunas reais de atb_fichas (cache por processo) — blinda contra chaves do
// schema sem coluna correspondente, que quebrariam o SELECT do dry-run.
let _colsCache = null;
async function colunasReais(pool){
  if(_colsCache) return _colsCache;
  const r = await pool.query(
    `SELECT column_name FROM information_schema.columns WHERE table_name='atb_fichas'`);
  _colsCache = new Set(r.rows.map(x => x.column_name));
  return _colsCache;
}
// Catálogo final por-request: schema vivo ∩ colunas reais (+ idade_* calculados).
export async function catalogoCampos(pool, inst='HUSF'){
  const schema = await getFormSchema(pool, inst);
  const cols = await colunasReais(pool);
  return construirCampos(schema).filter(c => cols.has(c.key) || CALC_KEYS.has(c.key));
}

export const OPERADORES = {
  select: [['eq','é igual a'],['neq','é diferente de'],['in','é um de'],['filled','está preenchido'],['not_filled','está vazio']],
  multi:  [['contains','contém'],['contains_any','contém algum de'],['filled','está preenchido'],['not_filled','está vazio']],
  bool:   [['eq','é']],
  numero: [['lt','<'],['lte','≤'],['gt','>'],['gte','≥'],['eq','='],['neq','≠'],['filled','preenchido'],['not_filled','vazio']],
  texto:  [['text_contains_any','contém (texto) algum de'],['eq','é igual a'],['neq','é diferente de'],['filled','preenchido'],['not_filled','vazio']],
};

export function esc(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }

export function page(titulo, corpo){
  return `<!doctype html><html lang="pt-br"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(titulo)}</title>
<style>
  :root{ --pri:#0c447c; --bg:#f4f6f9; --card:#fff; --txt:#1b2330; --mut:#6b7685; --bd:#e2e8f0; --danger:#d9534f; }
  *{ box-sizing:border-box; } body{ margin:0; background:var(--bg); color:var(--txt); font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; }
  .wrap{ max-width:980px; margin:0 auto; padding:24px 16px 80px; }
  .card{ background:var(--card); border:1px solid var(--bd); border-radius:12px; padding:20px; margin-bottom:16px; }
  h1{ font-size:22px; margin:0 0 4px; color:var(--pri); } h2{ font-size:17px; margin:0 0 12px; }
  .mut{ color:var(--mut); } a{ color:var(--pri); }
  table{ width:100%; border-collapse:collapse; } th,td{ text-align:left; padding:9px 8px; border-bottom:1px solid var(--bd); vertical-align:top; }
  th{ font-size:12px; text-transform:uppercase; letter-spacing:.04em; color:var(--mut); }
  .row{ display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
  button,.btn{ font:inherit; padding:9px 14px; border-radius:8px; border:1px solid var(--pri); background:var(--pri); color:#fff; cursor:pointer; text-decoration:none; display:inline-block; }
  button.ghost,.btn.ghost{ background:#fff; color:var(--pri); } button.danger{ background:#fff; color:var(--danger); border-color:var(--danger); }
  input,select,textarea{ font:inherit; padding:9px 10px; border:1px solid var(--bd); border-radius:8px; background:#fff; color:var(--txt); }
  textarea{ width:100%; min-height:70px; } label.lbl{ display:block; font-size:13px; color:var(--mut); margin:10px 0 4px; }
  .pill{ display:inline-block; padding:2px 9px; border-radius:999px; font-size:12px; }
  .pill.on{ background:#e8f0fb; color:var(--pri); } .pill.off{ background:#eef0f3; color:var(--mut); }
  .cond-row{ display:grid; grid-template-columns: 1fr 1fr 1.4fr auto; gap:8px; margin-bottom:8px; }
  .acao-grid{ display:grid; grid-template-columns:1fr 1fr; gap:12px; }
  @media(max-width:640px){ .cond-row{ grid-template-columns:1fr; } .acao-grid{ grid-template-columns:1fr; } }
  .nota{ font-size:13px; color:var(--mut); }
</style></head><body><div class="wrap">${corpo}</div></body></html>`;
}

function resumoCond(cond){
  if(!cond) return '—';
  const tipo = cond.all ? 'all' : cond.any ? 'any' : null;
  const lista = cond.all || cond.any;
  if(!tipo || !Array.isArray(lista)) return JSON.stringify(cond).slice(0,80);
  const sep = tipo==='all' ? ' E ' : ' OU ';
  return lista.map(c => `${esc(c.campo)} ${esc(c.op)} ${esc(Array.isArray(c.valor)?c.valor.join('/'):c.valor)}`).join(sep);
}
function resumoAcoes(a){
  if(!a) return '—';
  const p=[]; if(a.veredito) p.push('Parecer: '+a.veredito); if(a.iras) p.push('IrAS: '+a.iras);
  if(a.etiol_iras) p.push('Etiol: '+a.etiol_iras);
  return p.join(' · ') || '—';
}

export function registerRegrasRoutes(app, pool, scihRequired) {
  // Instituição por requisição: tenant-lock > ?inst= > default HUSF (legado idêntico).
  const instReq = (req) =>
    req.atbTenant ||
    String((req.query && req.query.inst) || 'HUSF').replace(/[^A-Za-z0-9_]/g, '') ||
    'HUSF';
  // Escopo de fichas por instituição (inclui fichas legadas sem instituição no HUSF).
  const escopoFichaSql = (idx) =>
    `(f.instituicao_id = (SELECT id FROM atb_instituicoes WHERE sigla=$${idx}) OR (f.instituicao_id IS NULL AND $${idx}='HUSF'))`;

  // super-admin (ou break-glass)
  const soSuper = [scihRequired, (req,res,next)=>{
    if (req.user?.super_admin || req.cookies?.adm === '1') return next();
    res.status(403).send(page('Sem acesso','<div class="card"><h1>Acesso restrito</h1><p class="mut">Apenas o administrador pode gerenciar regras de triagem.</p></div>'));
  }];

  // ── Lista ────────────────────────────────────────────────────────────────
  app.get('/atb/admin/regras', soSuper, async (req,res)=>{
    const inst = instReq(req);
    try{
      const regras = (await pool.query('SELECT * FROM atb_triagem_regras WHERE instituicao=$1 ORDER BY prioridade ASC, id ASC',[inst])).rows;
      const linhas = regras.map(r=>`
        <tr>
          <td><strong>${esc(r.nome)}</strong>${r.descricao?`<br><span class="nota">${esc(r.descricao)}</span>`:''}</td>
          <td>${r.prioridade}</td>
          <td><span class="nota">${esc(resumoCond(r.condicoes))}</span></td>
          <td><span class="nota">${esc(resumoAcoes(r.acoes))}</span></td>
          <td>${r.ativo?'<span class="pill on">ativa</span>':'<span class="pill off">inativa</span>'}</td>
          <td class="row">
            <a class="btn ghost" href="/atb/admin/regras/${r.id}">Editar</a>
            <a class="btn ghost" href="/atb/admin/regras/${r.id}/backfill">Backfill</a>
            <form method="POST" action="/atb/admin/regras/${r.id}/toggle" style="display:inline"><button class="ghost">${r.ativo?'Desativar':'Ativar'}</button></form>
            <form method="POST" action="/atb/admin/regras/${r.id}/excluir" style="display:inline" onsubmit="return confirm('Excluir esta regra?')"><button class="danger">Excluir</button></form>
          </td>
        </tr>`).join('') || '<tr><td colspan="6" class="mut">Nenhuma regra ainda.</td></tr>';
      res.send(page('Regras de triagem',`
        <div class="card"><h1>Regras de triagem</h1>
          <p class="mut">As regras são avaliadas na criação da ficha, por prioridade (menor primeiro). A primeira que casar preenche Parecer/IrAS — só em campo vazio, marcado e auditado.</p>
          <a class="btn" href="/atb/admin/regras/nova">+ Nova regra</a>
        </div>
        <div class="card">
          <table><thead><tr><th>Nome</th><th>Prior.</th><th>Condições</th><th>Ações</th><th>Estado</th><th></th></tr></thead>
          <tbody>${linhas}</tbody></table>
        </div>`));
    }catch(e){ console.error('[regras] lista:',e.message); res.status(500).send(page('Erro',`<div class="card"><h1>Falha</h1><p class="mut">${esc(e.message)}</p></div>`)); }
  });

  // ── Editor (nova / editar) ────────────────────────────────────────────────
  async function editor(req,res,regra){
    const CAMPOS = await catalogoCampos(pool, instReq(req));
    const dados = JSON.stringify({ campos:CAMPOS, ops:OPERADORES, iras:IRAS_VALORES, vereditos:PARECER_VEREDITOS, regra });
    res.send(page(regra?'Editar regra':'Nova regra',`
      <div class="card"><h1>${regra?'Editar regra':'Nova regra'}</h1>
        <label class="lbl">Nome</label><input id="r_nome" style="width:100%" value="${esc(regra?.nome||'')}">
        <label class="lbl">Descrição (opcional)</label><input id="r_desc" style="width:100%" value="${esc(regra?.descricao||'')}">
        <div class="row" style="margin-top:10px">
          <div><label class="lbl">Prioridade</label><input id="r_prio" type="number" value="${regra?.prioridade??100}" style="width:110px"></div>
          <div><label class="lbl">Ativa</label><br><select id="r_ativo"><option value="true"${regra&&!regra.ativo?'':' selected'}>Sim</option><option value="false"${regra&&!regra.ativo?' selected':''}>Não</option></select></div>
        </div>
      </div>
      <div class="card"><h2>Condições</h2>
        <div class="row"><label class="lbl" style="margin:0">Combinar com</label>
          <select id="r_combinador"><option value="all">TODAS (E)</option><option value="any">QUALQUER (OU)</option></select></div>
        <div id="conds" style="margin-top:12px"></div>
        <button class="ghost" type="button" onclick="addRow()">+ condição</button>
      </div>
      <div class="card"><h2>Ações (o que preencher)</h2>
        <div class="acao-grid">
          <div><label class="lbl">Parecer (veredito)</label><select id="a_veredito"><option value="">— não mexer —</option>${PARECER_VEREDITOS.map(v=>`<option value="${esc(v)}">${esc(v)}</option>`).join('')}</select></div>
          <div><label class="lbl">IrAS</label><select id="a_iras"><option value="">— não mexer —</option>${IRAS_VALORES.map(v=>`<option value="${esc(v)}">${esc(v)}</option>`).join('')}</select></div>
        </div>
        <label class="lbl">Especificação do parecer (opcional)</label><textarea id="a_espec"></textarea>
        <label class="lbl">Etiologia IrAS (opcional)</label><input id="a_etiol" style="width:100%">
      </div>
      <div class="card"><h2>Testar contra o histórico</h2>
        <p class="nota">Roda as condições nas fichas já existentes (sem alterar nada) e mostra quantas casariam.</p>
        <button class="ghost" type="button" onclick="testar()">Testar agora</button>
        <select id="teste_janela" style="margin-left:8px;padding:4px 6px">
          <option value="30">Últimos 30 dias</option>
          <option value="180" selected>Últimos 6 meses</option>
          <option value="365">Último ano</option>
          <option value="0">Todo o histórico</option>
        </select>
        <div id="teste" class="nota" style="margin-top:10px"></div>
      </div>
      <div class="card row">
        <button type="button" onclick="salvar()">Salvar regra</button>
        <a class="btn ghost" href="/atb/admin/regras">Cancelar</a>
        <span id="msg" class="nota"></span>
      </div>
      <script>
        var D = ${dados};
        var CAMPOS = D.campos, OPS = D.ops, byKey = {}; CAMPOS.forEach(function(c){ byKey[c.key]=c; });
        var condsEl = document.getElementById('conds');

        function opt(v,t){ var o=document.createElement('option'); o.value=v; o.textContent=t==null?v:t; return o; }
        function rowEl(c){
          c = c || {};
          var div = document.createElement('div'); div.className='cond-row';
          var selCampo = document.createElement('select');
          CAMPOS.forEach(function(cp){ selCampo.appendChild(opt(cp.key, cp.label)); });
          var selOp = document.createElement('select');
          var valWrap = document.createElement('span');
          var rm = document.createElement('button'); rm.type='button'; rm.className='ghost'; rm.textContent='×';
          rm.onclick=function(){ div.remove(); };

          function repop(){
            var cp = byKey[selCampo.value]; selOp.innerHTML='';
            (OPS[cp.tipo]||OPS.texto).forEach(function(o){ selOp.appendChild(opt(o[0],o[1])); });
            renderVal();
          }
          function renderVal(){
            var cp = byKey[selCampo.value], op = selOp.value; valWrap.innerHTML='';
            if(op==='filled'||op==='not_filled'){ return; }
            if(cp.tipo==='bool'){ var s=document.createElement('select'); s.appendChild(opt('true','Sim')); s.appendChild(opt('false','Não')); valWrap.appendChild(s); return; }
            if(cp.tipo==='numero'){ var n=document.createElement('input'); n.type='number'; valWrap.appendChild(n); return; }
            var multiVal = (op==='in'||op==='contains_any'||op==='text_contains_any');
            if((cp.tipo==='select'||cp.tipo==='multi') && cp.opcoes && cp.opcoes.length){
              var s2=document.createElement('select'); if(multiVal) s2.multiple=true, s2.size=Math.min(6,cp.opcoes.length);
              cp.opcoes.forEach(function(o){ s2.appendChild(opt(o)); }); valWrap.appendChild(s2); return;
            }
            var t=document.createElement('input'); t.style.width='100%';
            t.placeholder = multiVal ? 'valores separados por vírgula' : 'valor';
            valWrap.appendChild(t);
          }
          selCampo.onchange=repop; selOp.onchange=renderVal;
          div.appendChild(selCampo); div.appendChild(selOp); div.appendChild(valWrap); div.appendChild(rm);
          condsEl.appendChild(div);
          // preencher se veio do banco
          if(c.campo){ selCampo.value=c.campo; } repop();
          if(c.op){ selOp.value=c.op; renderVal(); }
          if(c.valor!==undefined){
            var cp=byKey[selCampo.value], inp=valWrap.querySelector('select,input');
            if(inp){ if(inp.multiple && Array.isArray(c.valor)){ Array.prototype.forEach.call(inp.options,function(o){ o.selected=c.valor.indexOf(o.value)!==-1; }); }
                     else { inp.value = cp.tipo==='bool' ? String(c.valor) : (Array.isArray(c.valor)?c.valor.join(', '):c.valor); } }
          }
        }
        function addRow(c){ rowEl(c); }

        function coletarCond(){
          var rows=[]; Array.prototype.forEach.call(condsEl.children, function(div){
            var sels=div.querySelectorAll('select'), campo=sels[0].value, op=sels[1].value;
            var cp=byKey[campo], valEl=div.querySelector('.cond-row > span').querySelector('select,input'), valor;
            if(op==='filled'||op==='not_filled'){ valor=undefined; }
            else if(cp.tipo==='bool'){ valor = (valEl.value==='true'); }
            else if(cp.tipo==='numero'){ valor = Number(valEl.value); }
            else if(valEl && valEl.multiple){ valor = Array.prototype.filter.call(valEl.options,function(o){return o.selected;}).map(function(o){return o.value;}); }
            else if(op==='text_contains_any' || op==='contains_any' || op==='in'){ valor = (valEl.value||'').split(',').map(function(s){return s.trim();}).filter(Boolean); }
            else { valor = valEl ? valEl.value : ''; }
            var o={campo:campo, op:op}; if(valor!==undefined) o.valor=valor; rows.push(o);
          });
          var comb = document.getElementById('r_combinador').value;
          var c={}; c[comb]=rows; return c;
        }
        function coletarAcoes(){
          var a={}; var v=document.getElementById('a_veredito').value; if(v)a.veredito=v;
          var ir=document.getElementById('a_iras').value; if(ir)a.iras=ir;
          var es=document.getElementById('a_espec').value.trim(); if(es)a.especificacao=es;
          var et=document.getElementById('a_etiol').value.trim(); if(et)a.etiol_iras=et;
          return a;
        }
        function payload(){
          return { nome:document.getElementById('r_nome').value.trim(),
                   descricao:document.getElementById('r_desc').value.trim(),
                   prioridade:Number(document.getElementById('r_prio').value)||100,
                   ativo:document.getElementById('r_ativo').value==='true',
                   condicoes:coletarCond(), acoes:coletarAcoes() }; }

        function salvar(){
          var p=payload(); if(!p.nome){ document.getElementById('msg').textContent='Dê um nome à regra.'; return; }
          var url = D.regra ? '/atb/admin/regras/salvar/'+D.regra.id : '/atb/admin/regras/salvar';
          fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(p)})
            .then(function(r){return r.json();}).then(function(j){
              if(j.ok){ location.href='/atb/admin/regras'; } else { document.getElementById('msg').textContent=j.error||'Falha ao salvar'; }
            }).catch(function(e){ document.getElementById('msg').textContent=String(e); });
        }
        function testar(){
          var el=document.getElementById('teste'); el.textContent='Rodando...';
          var _body=Object.assign({}, payload(), {janela:+document.getElementById('teste_janela').value});
          fetch('/atb/admin/regras/testar',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(_body)})
            .then(function(r){return r.json();}).then(function(j){
              if(!j.ok){ el.textContent=j.error||'Falha'; return; }
              el.innerHTML='Casariam <strong>'+j.casam+'</strong> de '+j.total+' fichas. '
                + 'Dessas, '+j.ja_iras+' já têm IrAS preenchido e '+j.vazias+' estão vazias.'
                + (j.divergentes!=null ? ' <strong>'+j.divergentes+'</strong> divergem do IrAS que esta regra aplicaria.' : '');
            }).catch(function(e){ el.textContent=String(e); });
        }

        // init
        var rc = D.regra && D.regra.condicoes || {};
        var comb = rc.all ? 'all' : 'any'; document.getElementById('r_combinador').value = rc.all||rc.any ? comb : 'all';
        var lista = rc.all || rc.any || [];
        if(lista.length){ lista.forEach(function(c){ addRow(c); }); } else { addRow(); }
        if(D.regra){
          var a=D.regra.acoes||{};
          if(a.veredito) document.getElementById('a_veredito').value=a.veredito;
          if(a.iras) document.getElementById('a_iras').value=a.iras;
          if(a.especificacao) document.getElementById('a_espec').value=a.especificacao;
          if(a.etiol_iras) document.getElementById('a_etiol').value=a.etiol_iras;
        }
      </script>`));
  }

  app.get('/atb/admin/regras/nova', soSuper, (req,res)=> editor(req,res,null).catch(e=>{ console.error('[regras] editor:',e.message); res.status(500).send(page('Erro','<div class="card"><h1>Falha ao abrir o editor</h1></div>')); }));
  app.get('/atb/admin/regras/:id', soSuper, async (req,res)=>{
    const r=(await pool.query('SELECT * FROM atb_triagem_regras WHERE id=$1 AND instituicao=$2',[parseInt(req.params.id,10), instReq(req)])).rows[0];
    if(!r) return res.status(404).send(page('Não encontrada','<div class="card"><h1>Regra não encontrada</h1><a href="/atb/admin/regras">Voltar</a></div>'));
    editor(req,res,r).catch(e=>{ console.error('[regras] editor:',e.message); res.status(500).send(page('Erro','<div class="card"><h1>Falha ao abrir o editor</h1></div>')); });
  });

  // ── Salvar ─────────────────────────────────────────────────────────────────
  async function salvar(req,res,id){
    const inst = instReq(req);
    try{
      const b=req.body||{};
      const nome=(b.nome||'').trim();
      if(!nome) return res.status(400).json({ok:false,error:'Nome obrigatório'});
      if(b.acoes?.veredito && !PARECER_VEREDITOS.includes(b.acoes.veredito)) return res.status(400).json({ok:false,error:'veredito inválido'});
      if(b.acoes?.iras && !IRAS_VALORES.includes(b.acoes.iras)) return res.status(400).json({ok:false,error:'IrAS inválido'});
      const vals=[nome, b.descricao||null, Number(b.prioridade)||100, b.ativo!==false,
                  JSON.stringify(b.condicoes||{}), JSON.stringify(b.acoes||{})];
      if(id){
        await pool.query(`UPDATE atb_triagem_regras SET nome=$1,descricao=$2,prioridade=$3,ativo=$4,condicoes=$5::jsonb,acoes=$6::jsonb,updated_at=now() WHERE id=$7 AND instituicao=$8`, [...vals, id, inst]);
      }else{
        await pool.query(`INSERT INTO atb_triagem_regras (nome,descricao,prioridade,ativo,condicoes,acoes,created_by,instituicao) VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,$8)`, [...vals, req.user?.id||null, inst]);
      }
      res.json({ok:true});
    }catch(e){ console.error('[regras] salvar:',e.message); res.status(500).json({ok:false,error:e.message}); }
  }
  app.post('/atb/admin/regras/salvar', soSuper, (req,res)=> salvar(req,res,null));
  app.post('/atb/admin/regras/salvar/:id', soSuper, (req,res)=> salvar(req,res,parseInt(req.params.id,10)));

  app.post('/atb/admin/regras/:id/toggle', soSuper, async (req,res)=>{
    try{ await pool.query('UPDATE atb_triagem_regras SET ativo=NOT ativo, updated_at=now() WHERE id=$1 AND instituicao=$2',[parseInt(req.params.id,10), instReq(req)]); }
    catch(e){ console.error('[regras] toggle:',e.message); }
    res.redirect('/atb/admin/regras');
  });
  app.post('/atb/admin/regras/:id/excluir', soSuper, async (req,res)=>{
    try{ await pool.query('DELETE FROM atb_triagem_regras WHERE id=$1 AND instituicao=$2',[parseInt(req.params.id,10), instReq(req)]); }
    catch(e){ console.error('[regras] excluir:',e.message); }
    res.redirect('/atb/admin/regras');
  });

  // ── Dry-run contra o histórico ──────────────────────────────────────────────
  app.post('/atb/admin/regras/testar', soSuper, async (req,res)=>{
    const inst = instReq(req);
    try{
      const cond = req.body?.condicoes;
      const irasRegra = req.body?.acoes?.iras || null;
      if(!cond || (!cond.all && !cond.any)) return res.json({ok:true, total:0, casam:0, ja_iras:0, vazias:0, divergentes:null});
      const COLS_BANCO = (await catalogoCampos(pool, inst)).map(c => c.key).filter(k => !CALC_KEYS.has(k));
      const cols = ['id','paciente_dn','data_referencia','jotform_created_at','created_at', ...COLS_BANCO]
        .filter((v,i,a)=>a.indexOf(v)===i).map(c=>'f.'+c).join(',');
      const subs = subSqlDe(camposDaRegra(cond));
      const _jan = parseInt(req.body?.janela, 10);
      const diasJan = [30, 180, 365].indexOf(_jan) >= 0 ? _jan : 0;   // 0 = todo o histórico
      const filtroData = diasJan > 0
        ? ` AND COALESCE(f.data_referencia,f.jotform_created_at,f.created_at) >= (now() - interval '${diasJan} days')`
        : '';
      const { rows } = await pool.query(`SELECT ${cols}, a.iras AS _iras${subs} FROM atb_fichas f LEFT JOIN atb_avaliacoes a ON a.ficha_id=f.id WHERE ${escopoFichaSql(1)}${filtroData}`, [inst]);
      let casam=0, ja=0, vaz=0, div=0;
      for(const f of rows){
        const ctx = contextoFicha(f);
        ctx.fichas_72h_mesmo_setor = f._fichas72h || 0;
      ctx.fichas_72h_mesmo_atb = f._fichas72hatb || 0;
        ctx.cultura_positiva = !!f._cult_pos;
        ctx.cultura_mr = f._cult_mr || [];
        ctx.cultura_organismos = f._cult_org || '';
        ctx.cultura_materiais = f._cult_mat || '';
        ctx.cultura_hemocultura = !!f._cult_hemo;
        ctx.hemocultura_5d5d = !!f._hemo55;
        if(avaliaCond(cond, ctx)){
          casam++;
          const temIras = f._iras!=null && String(f._iras).trim()!=='';
          if(temIras){ ja++; if(irasRegra && f._iras!==irasRegra) div++; } else vaz++;
        }
      }
      res.json({ok:true, total:rows.length, casam, ja_iras:ja, vazias:vaz, divergentes: irasRegra?div:null});
    }catch(e){ console.error('[regras] testar:',e.message); res.status(500).json({ok:false,error:e.message}); }
  });

  // ── Backfill por regra: aplica a regra às fichas existentes que se encaixam ──
  // Só fichas AINDA NÃO triadas (sem triagem_regra_id) e onde ESTA é a 1ª regra a
  // casar (respeita prioridade). Preenche Parecer/IrAS apenas em campo vazio, via
  // aplicarRegras (mesmo motor da criação). Requer contextoFicha já corrigido.
  async function coletarBackfill(regra, de, ate, inst){
    const ativas = (await pool.query(
      'SELECT id, condicoes FROM atb_triagem_regras WHERE ativo=true AND instituicao=$1 ORDER BY prioridade ASC, id ASC',[inst]
    )).rows;
    const COLS_BANCO = (await catalogoCampos(pool, inst)).map(c => c.key).filter(k => !CALC_KEYS.has(k));
    const base = ['id','paciente_nome','setor','data_internacao','paciente_dn','data_referencia','jotform_created_at','created_at'];
    const cols = [...base, ...COLS_BANCO].filter((v,i,a)=>a.indexOf(v)===i).map(c=>'f.'+c).join(',');
    const filtros = ['f.deletado_em IS NULL'], params = [];
    params.push(inst); filtros.push(escopoFichaSql(params.length));
    const dataCanon = 'COALESCE(f.data_referencia, f.jotform_created_at, f.created_at)';
    if(de){  params.push(de);  filtros.push(`${dataCanon} >= $${params.length}::date`); }
    if(ate){ params.push(ate); filtros.push(`${dataCanon} < ($${params.length}::date + interval '1 day')`); }
    const _campos = new Set(); ativas.forEach(r => camposDaRegra(r.condicoes, _campos)); if (regra) camposDaRegra(regra.condicoes, _campos);
    const subs = subSqlDe(_campos);
    const { rows } = await pool.query(
      `SELECT ${cols}, a.iras AS _iras, a.triagem_regra_id AS _trid${subs}
         FROM atb_fichas f LEFT JOIN atb_avaliacoes a ON a.ficha_id=f.id
        WHERE ${filtros.join(' AND ')}`, params);
    const primeira = (ctx)=> ativas.find(r=>avaliaCond(r.condicoes, ctx));
    const candidatos=[], amostra=[]; let casamTotal=0, jaTriada=0, outraRegra=0;
    for(const f of rows){
      const ctx = contextoFicha(f);
      ctx.fichas_72h_mesmo_setor = f._fichas72h || 0;
      ctx.fichas_72h_mesmo_atb = f._fichas72hatb || 0;
      ctx.cultura_positiva = !!f._cult_pos;
      ctx.cultura_mr = f._cult_mr || [];
      ctx.cultura_organismos = f._cult_org || '';
      ctx.cultura_materiais = f._cult_mat || '';
      ctx.cultura_hemocultura = !!f._cult_hemo;
        ctx.hemocultura_5d5d = !!f._hemo55;
      if(!avaliaCond(regra.condicoes, ctx)) continue;
      casamTotal++;
      if(f._trid != null){ jaTriada++; continue; }
      const dono = primeira(ctx);
      if(dono && dono.id === regra.id){ candidatos.push(f.id); if(amostra.length<30) amostra.push({id:f.id, nome:f.paciente_nome, setor:f.setor}); }
      else outraRegra++;
    }
    return { candidatos, amostra, casamTotal, jaTriada, outraRegra };
  }

  // preview (não altera nada)
  app.get('/atb/admin/regras/:id/backfill', soSuper, async (req,res)=>{
    const inst = instReq(req);
    try{
      const id = parseInt(req.params.id,10);
      const regra = (await pool.query('SELECT * FROM atb_triagem_regras WHERE id=$1 AND instituicao=$2',[id, inst])).rows[0];
      if(!regra) return res.status(404).send(page('Não encontrada',`<div class="card"><h1>Regra não encontrada</h1><a href="/atb/admin/regras">Voltar</a></div>`));
      const de = req.query.de === undefined ? new Date(Date.now()-90*864e5).toISOString().slice(0,10) : String(req.query.de||'');
      const ate = String(req.query.ate||'');
      const { candidatos, amostra, casamTotal, jaTriada, outraRegra } = await coletarBackfill(regra, de, ate, inst);
      const tab = amostra.map(a=>`<tr><td>#${a.id}</td><td>${esc(a.nome||'')}</td><td>${esc(a.setor||'')}</td></tr>`).join('');
      res.send(page('Backfill — '+regra.nome,`
        <div class="card"><h1>Backfill: ${esc(regra.nome)}</h1>
          <p class="mut">Aplica esta regra às fichas existentes que se encaixam <strong>e ainda não foram triadas</strong>, respeitando a prioridade (só onde esta é a 1ª regra a casar). Preenche Parecer/IrAS só em campo vazio — igual ao fluxo de criação.</p>
          ${regra.ativo?'':'<p class="nota" style="color:#c0392b">Regra inativa — ative-a para que o backfill possa aplicá-la.</p>'}
        </div>
        <div class="card">
          <form method="GET" action="/atb/admin/regras/${id}/backfill" class="row" style="align-items:flex-end;gap:12px">
            <div><label class="lbl">De</label><br><input type="date" name="de" value="${esc(de)}"></div>
            <div><label class="lbl">Até</label><br><input type="date" name="ate" value="${esc(ate)}"></div>
            <button class="ghost">Atualizar período</button>
            <span class="nota">Vazio = sem limite nesse lado. Filtra pela data clínica (referência → criação).</span>
          </form>
        </div>
        <div class="card">
          <p>Casam com a regra: <strong>${casamTotal}</strong></p>
          <p class="nota">• já triadas (puladas): ${jaTriada} &nbsp;•&nbsp; pertencem a outra regra de maior precedência: ${outraRegra}</p>
          <p style="margin-top:10px">Serão aplicadas a <strong>${candidatos.length}</strong> ficha(s).</p>
          ${candidatos.length?`<form method="POST" action="/atb/admin/regras/${id}/backfill/aplicar" onsubmit="return confirm('Aplicar a ${candidatos.length} ficha(s)?')"><input type="hidden" name="de" value="${esc(de)}"><input type="hidden" name="ate" value="${esc(ate)}"><button>Aplicar a ${candidatos.length} ficha(s)</button></form>`:''}
          <a class="btn ghost" href="/atb/admin/regras">Voltar</a>
        </div>
        ${amostra.length?`<div class="card"><h2>Amostra (até 30)</h2><table><thead><tr><th>Ficha</th><th>Paciente</th><th>Setor</th></tr></thead><tbody>${tab}</tbody></table></div>`:''}`));
    }catch(e){ console.error('[regras] backfill preview:',e.message); res.status(500).send(page('Erro',`<div class="card"><h1>Falha</h1><p class="mut">${esc(e.message)}</p></div>`)); }
  });

  // aplicar (recalcula candidatos e roda aplicarRegras em cada)
  app.post('/atb/admin/regras/:id/backfill/aplicar', soSuper, async (req,res)=>{
    const inst = instReq(req);
    try{
      const id = parseInt(req.params.id,10);
      const regra = (await pool.query('SELECT * FROM atb_triagem_regras WHERE id=$1 AND instituicao=$2',[id, inst])).rows[0];
      if(!regra) return res.status(404).send(page('Não encontrada',`<div class="card"><h1>Regra não encontrada</h1></div>`));
      const de = String(req.body?.de||''); const ate = String(req.body?.ate||'');
      const { candidatos } = await coletarBackfill(regra, de, ate, inst);
      let aplicadas=0, outras=0;
      for(const fid of candidatos){
        const r = await aplicarRegras(pool, fid);
        if(r && r.regra_id === id) aplicadas++; else outras++;
      }
      res.send(page('Backfill concluído',`
        <div class="card"><h1>Backfill concluído — ${esc(regra.nome)}</h1>
          <p>Fichas processadas: <strong>${candidatos.length}</strong></p>
          <p>Aplicaram esta regra: <strong>${aplicadas}</strong>${outras?` · outras: ${outras}`:''}</p>
          <a class="btn" href="/atb/admin/regras">Voltar às regras</a>
        </div>`));
    }catch(e){ console.error('[regras] backfill aplicar:',e.message); res.status(500).send(page('Erro',`<div class="card"><h1>Falha</h1><p class="mut">${esc(e.message)}</p></div>`)); }
  });
}
