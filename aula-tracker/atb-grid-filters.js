// ════════════════════════════════════════════════════════════════════════════
//  FILTROS AVANÇADOS + SELETOR DE COLUNAS DA GRADE
//
//  Para fechamentos mensais: filtrar por qualquer campo essencial e adicionar
//  campos como colunas read-only à direita das colunas fixas. Tudo via URL
//  (recorte compartilhável/bookmarkável). Combinação E (todas as condições).
//
//  Filtros essenciais (param na URL):
//    setor (setor)            · Data referência (data_de/data_ate)
//    Submission (sub_de/sub_ate, com atalhos)   · IrAS Sim/Não (iras_sn)
//    Tipo de IrAS (iras_classe) · Etiologia (etiol) · Tipo de terapia (tipo_terapia)
//    Veredito (veredito)      · Acesso diálise (acesso_dialise)
//    SOFA (sofa_min/sofa_max) · Sepse (sepse) · busca (q) · hospital (inst)
//
//  Integração em atb-routes.js (na rota /atb/admin/grid):
//    import { applyGridFilters, extraSelectSql, renderExtraHeaders,
//             renderExtraCells, gridControlsUI } from './atb-grid-filters.js';
//    const cols = (req.query.cols || '').split(',').filter(Boolean);
//    // depois dos filtros existentes:  applyGridFilters(req.query, where, params);
//    // no SELECT principal:            ${extraSelectSql(cols)}  (antes das subqueries n_pdf)
//    // no <thead>:                     ${renderExtraHeaders(cols, safe)}  (antes de <th>Links)
//    // na linha:                       ${renderExtraCells(f, cols, safe)} (antes do <td> de Links)
//    // colspan do vazio:               15 + cols.length
//    // substitui o <form> de filtros:  ${gridControlsUI(req.query, pager)}
//  Sem schema novo — só leitura.
// ════════════════════════════════════════════════════════════════════════════

// ── Opções (autoritativas: schema / banco) ──────────────────────────────────
const OPC = {
  setor: ['PS','EPM','Cuidados Intermediários','Psiquiatria','Apartamento','Oncologia','Clínica Cirúrgica','Semi','Hemodiálise','Pediatria','UTI','UTI Neo / Infantil','UTI C','Ginecologia/Obstetrícia','Clínica Médica'],
  iras: ['PAV','PAV/EVA','IPCSLab','IPCSClin','ITU','ISC','(HD)ILAV','(HD)ICS','(HD)Bact','HD_Bact_FAV','HD_Bact_CDL','HD_Bact_PC','HD_ILAV_FAV','HD_ILAV_CDL','HD_ILAV_PC','CDI','Onco_Bact','Sem dados','Descartado','Repetida'],
  desfecho: ['Sobrev_int','Sobrev_alta','Obito_R','Obito_NR','Alta'],
  tipo_terapia: ['Empírica','Guiada por cultura','Profilaxia cirúrgica'],
  veredito: ['Sim','Não','Com ajustes (especificados abaixo)','ATB não controlado','Suspenso','Ficha Repetida','Audit_post'],
  acesso_dialise: ['FAV','CDL (Shilley)','Perm-cath','PTFE'],
  foco: ['Corrente sanguínea (bacteremia)','Pneumonia','Infecção do trato urinário','Infecção do sítio cirúrgico','Meningite/Encefalite','Abdominal','Osteoarticular','Pele/Partes moles','Neutropenia Febril'],
  status: ['pendente','em_avaliacao','avaliado','arquivado'],
  inst: ['HUSF','H2'],
};

function _safe(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ════════════════════════════════════════════════════════════════════════════
//  WHERE — adiciona as cláusulas dos filtros NOVOS (não duplica q/inst/setor/mes/iras,
//  que a rota já trata). Combinação E. Muta `where` e `params`.
// ════════════════════════════════════════════════════════════════════════════
export function applyGridFilters(query, where, params) {
  const q = query || {};
  const push = (clause, val) => { params.push(val); where.push(clause.replace('$$', '$' + params.length)); };

  // Data de referência (intervalo)
  if (q.data_de)  push('f.data_referencia >= $$::date', q.data_de);
  if (q.data_ate) push('f.data_referencia <  ($$::date + interval \'1 day\')', q.data_ate);

  // Submission date (jotform_created_at, fallback created_at) — intervalo
  if (q.sub_de)  push('COALESCE(f.jotform_created_at, f.created_at) >= $$::date', q.sub_de);
  if (q.sub_ate) push('COALESCE(f.jotform_created_at, f.created_at) <  ($$::date + interval \'1 day\')', q.sub_ate);

  // IrAS Sim/Não (derivado)
  if (q.iras_sn === 'sim') {
    where.push(`(a.iras IS NOT NULL AND a.iras <> '' AND a.iras NOT IN ('Descartado','Repetida','Sem dados'))`);
  } else if (q.iras_sn === 'nao') {
    where.push(`(a.iras IS NULL OR a.iras = '' OR a.iras IN ('Descartado','Repetida','Sem dados'))`);
  }

  // Tipo de IrAS (classe específica; ILIKE p/ pegar classificações duplas)
  if (q.iras_classe) push('a.iras ILIKE $$', '%' + q.iras_classe + '%');

  // Etiologia IrAS (texto livre)
  if (q.etiol && q.etiol.trim()) push('a.etiol_iras ILIKE $$', '%' + q.etiol.trim() + '%');

  // Tipo de terapia (igual) — útil pra excluir profilaxia: selecione Empírica/Guiada
  if (q.tipo_terapia) push('f.tipo_terapia = $$', q.tipo_terapia);

  // Veredito do parecer (recomendacao_scih é array JSONB)
  if (q.veredito) push('f.recomendacao_scih @> $$::jsonb', JSON.stringify([q.veredito]));

  // Acesso para diálise
  if (q.acesso_dialise) push('f.acesso_dialise = $$', q.acesso_dialise);

  // SOFA (intervalo)
  if (q.sofa_min !== undefined && q.sofa_min !== '') push('f.sofa >= $$', parseInt(q.sofa_min, 10));
  if (q.sofa_max !== undefined && q.sofa_max !== '') push('f.sofa <= $$', parseInt(q.sofa_max, 10));

  // Sepse
  if (q.sepse === 'sim') push('f.sepse = $$', true);
  else if (q.sepse === 'nao') push('f.sepse = $$', false);
}

// ════════════════════════════════════════════════════════════════════════════
//  REGISTRO DE CAMPOS p/ COLUNAS (campo → expressão SQL + tipo de render)
// ════════════════════════════════════════════════════════════════════════════
const COLS = {
  // numéricos
  sofa:            { label: 'SOFA',            grupo: 'Números',  expr: 'f.sofa',            tipo: 'num' },
  saps3:           { label: 'SAPS3',           grupo: 'Números',  expr: 'a.saps3',           tipo: 'num' },
  tempo_previsto:  { label: 'Tempo previsto',  grupo: 'Números',  expr: 'f.tempo_previsto',  tipo: 'num' },
  clcr:            { label: 'ClCr',            grupo: 'Números',  expr: 'f.clcr',            tipo: 'num' },
  peso:            { label: 'Peso (kg)',       grupo: 'Números',  expr: 'f.peso',            tipo: 'num' },
  altura:          { label: 'Altura',          grupo: 'Números',  expr: 'f.altura',          tipo: 'num' },
  peso_nascimento: { label: 'Peso nasc. (g)',  grupo: 'Números',  expr: 'f.peso_nascimento', tipo: 'num' },
  // datas
  data_ref:        { label: 'Data (ref.)',     grupo: 'Datas',    expr: 'COALESCE(f.data_referencia, f.jotform_created_at, f.created_at)', tipo: 'date' },
  submission:      { label: 'Submission',      grupo: 'Datas',    expr: 'COALESCE(f.jotform_created_at, f.created_at)', tipo: 'datetime' },
  data_internacao: { label: 'Internação',      grupo: 'Datas',    expr: 'f.data_internacao', tipo: 'date' },
  data_admissao_uti:{label: 'Admissão UTI',    grupo: 'Datas',    expr: 'f.data_admissao_uti', tipo: 'date' },
  desfecho_data:   { label: 'Dt. desfecho',    grupo: 'Datas',    expr: 'a.desfecho_data',   tipo: 'date' },
  data_obito:      { label: 'Dt. óbito',       grupo: 'Datas',    expr: 'f.data_obito',      tipo: 'date' },
  // categóricos
  setor:           { label: 'Setor',           grupo: 'Categóricos', expr: 'f.setor',        tipo: 'txt' },
  instituicao:     { label: 'Hospital',        grupo: 'Categóricos', expr: 'i.sigla',        tipo: 'txt' },
  tipo_terapia:    { label: 'Tipo de terapia', grupo: 'Categóricos', expr: 'f.tipo_terapia', tipo: 'txt' },
  foco_infeccao:   { label: 'Foco',            grupo: 'Categóricos', expr: 'f.foco_infeccao',tipo: 'txt' },
  status:          { label: 'Status',          grupo: 'Categóricos', expr: 'f.status',       tipo: 'txt' },
  acesso_dialise:  { label: 'Acesso diálise',  grupo: 'Categóricos', expr: 'f.acesso_dialise', tipo: 'txt' },
  iras:            { label: 'IrAS',            grupo: 'Categóricos', expr: 'a.iras',         tipo: 'txt' },
  desfecho_iras:   { label: 'Desfecho',        grupo: 'Categóricos', expr: 'a.desfecho_iras',tipo: 'txt' },
  veredito:        { label: 'Veredito',        grupo: 'Categóricos', expr: 'f.recomendacao_scih', tipo: 'arr' },
  // booleanos
  sepse:           { label: 'Sepse',           grupo: 'Sim/Não',  expr: 'f.sepse',           tipo: 'bool' },
  obito:           { label: 'Óbito',           grupo: 'Sim/Não',  expr: 'f.obito',           tipo: 'bool' },
  gestante:        { label: 'Gestante',        grupo: 'Sim/Não',  expr: 'f.gestante',        tipo: 'bool' },
  faz_quimio:      { label: 'Quimio',          grupo: 'Sim/Não',  expr: 'f.faz_quimio',      tipo: 'bool' },
  dialise:         { label: 'Em diálise',      grupo: 'Sim/Não',  expr: 'f.dialise',         tipo: 'bool' },
  uso_atb_7d:      { label: 'ATB prévio 7d',   grupo: 'Sim/Não',  expr: 'f.uso_atb_7d',      tipo: 'bool' },
  // listas
  atb_solicitado:  { label: 'ATB solicitado',  grupo: 'Listas',   expr: 'f.atb_solicitado',  tipo: 'arr' },
  comorbidades:    { label: 'Comorbidades',    grupo: 'Listas',   expr: 'f.comorbidades',    tipo: 'arr' },
  dispositivos_invasivos: { label: 'Dispositivos', grupo: 'Listas', expr: 'f.dispositivos_invasivos', tipo: 'arr' },
  insuficiencia_renal: { label: 'Insuf. renal', grupo: 'Listas',  expr: 'f.insuficiencia_renal', tipo: 'arr' },
  // texto livre
  etiol_iras:      { label: 'Etiologia',       grupo: 'Texto',    expr: 'a.etiol_iras',      tipo: 'txt' },
  micro:           { label: 'Microbiologia',   grupo: 'Texto',    expr: 'a.micro',           tipo: 'txt' },
  prescritor_nome: { label: 'Prescritor',      grupo: 'Texto',    expr: 'f.prescritor_nome', tipo: 'txt' },
  crm:             { label: 'CRM',             grupo: 'Texto',    expr: 'f.crm',             tipo: 'txt' },
  recomendacoes_especificacao: { label: 'Especificação', grupo: 'Texto', expr: 'f.recomendacoes_especificacao', tipo: 'txt' },
  leito:           { label: 'Leito',           grupo: 'Texto',    expr: 'f.leito',           tipo: 'txt' },
  equipe_responsavel: { label: 'Equipe',       grupo: 'Texto',    expr: 'f.equipe_responsavel', tipo: 'txt' },
};

// ── SELECT extra (aliases gx_<key> p/ não colidir com a SELECT base) ─────────
export function extraSelectSql(cols) {
  const list = (cols || []).filter(k => COLS[k]);
  if (!list.length) return '';
  return list.map(k => `${COLS[k].expr} AS gx_${k}`).join(', ') + ', ';
}

// ── cabeçalhos extras ────────────────────────────────────────────────────────
export function renderExtraHeaders(cols, safe) {
  const s = safe || _safe;
  return (cols || []).filter(k => COLS[k])
    .map(k => `<th class="grp">${s(COLS[k].label)}</th>`).join('');
}

// ── células extras (read-only, formatadas por tipo) ──────────────────────────
function _fmtArr(v) {
  let a = v;
  if (typeof v === 'string') { try { a = JSON.parse(v); } catch { a = [v]; } }
  return Array.isArray(a) ? a.join(', ') : (v == null ? '' : String(v));
}
export function renderExtraCells(row, cols, safe) {
  const s = safe || _safe;
  return (cols || []).filter(k => COLS[k]).map(k => {
    const v = row['gx_' + k];
    const t = COLS[k].tipo;
    let out;
    if (v == null || v === '') out = '—';
    else if (t === 'bool') out = (v === true ? 'Sim' : v === false ? 'Não' : '—');
    else if (t === 'num') out = String(v);
    else if (t === 'date') out = new Date(v).toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit', year: '2-digit' });
    else if (t === 'datetime') out = new Date(v).toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit', timeZone: 'America/Sao_Paulo' });
    else if (t === 'arr') out = s(_fmtArr(v));
    else out = s(String(v));
    const align = (t === 'num') ? ' style="text-align:center"' : '';
    return `<td class="gx-cell"${align}>${out}</td>`;
  }).join('');
}

// ════════════════════════════════════════════════════════════════════════════
//  UI — barra de busca + painéis "Filtros" e "Colunas" (forms GET p/ a própria grade)
//  Substitui o <form> simples de filtros. Recebe o pager pra posicionar à direita.
// ════════════════════════════════════════════════════════════════════════════
function _opt(val, sel, label) {
  return `<option value="${_safe(val)}" ${String(sel) === String(val) ? 'selected' : ''}>${_safe(label != null ? label : val)}</option>`;
}
function _sel(name, value, opcoes, placeholder) {
  const opts = [`<option value="">${_safe(placeholder)}</option>`]
    .concat(opcoes.map(o => _opt(o, value, o))).join('');
  return `<select name="${name}" class="gf-in">${opts}</select>`;
}

export function gridControlsUI(query, pager) {
  const q = query || {};
  const val = k => _safe(q[k] || '');
  const colsAtivas = []
    .concat(q.cols || [])
    .flatMap(c => String(c).split(','))
    .map(c => c.trim())
    .filter(Boolean);

  // contagem de filtros ativos (exceto q/inst que ficam visíveis na barra)
  const filtroKeys = ['setor','data_de','data_ate','sub_de','sub_ate','iras_sn','iras_classe','etiol','tipo_terapia','veredito','acesso_dialise','sofa_min','sofa_max','sepse'];
  const nAtivos = filtroKeys.filter(k => q[k]).length;

  // hidden p/ preservar estado ao submeter cada form
  const hidden = (excetuar) => Object.keys(q)
    .filter(k => !excetuar.includes(k) && k !== 'page' && q[k] !== '' && q[k] != null)
    .map(k => `<input type="hidden" name="${_safe(k)}" value="${_safe(q[k])}">`).join('');

  // ── painel de FILTROS ──────────────────────────────────────────────────────
  const filtrosForm = `
    <form method="GET" action="/atb/admin/grid" class="gf-panel" id="gf-filtros" style="display:none">
      ${hidden(filtroKeys.concat(['inst','cols']))}
      <input type="hidden" name="cols" value="${_safe(q.cols || '')}">
      <div class="gf-grid">
        <label>Hospital ${_sel('inst', q.inst, OPC.inst, 'Todos')}</label>
        <label>Setor ${_sel('setor', q.setor, OPC.setor, 'Todos')}</label>
        <label>Tipo de terapia ${_sel('tipo_terapia', q.tipo_terapia, OPC.tipo_terapia, 'Todos')}</label>
        <label>Sepse ${_sel('sepse', q.sepse === 'sim' ? 'Sim' : q.sepse === 'nao' ? 'Não' : '', ['Sim','Não'], 'Todos').replace('value="Sim"', 'value="sim"').replace('value="Não"', 'value="nao"')}</label>

        <label>Data (ref.) de <input type="date" name="data_de" value="${val('data_de')}" class="gf-in"></label>
        <label>até <input type="date" name="data_ate" value="${val('data_ate')}" class="gf-in"></label>

        <label class="gf-sub">Submission de <input type="date" name="sub_de" id="gf-sub-de" value="${val('sub_de')}" class="gf-in"></label>
        <label class="gf-sub">até <input type="date" name="sub_ate" id="gf-sub-ate" value="${val('sub_ate')}" class="gf-in"></label>
        <div class="gf-atalhos">
          <button type="button" data-range="mes">Último mês</button>
          <button type="button" data-range="sem">Último semestre</button>
          <button type="button" data-range="ano">Este ano</button>
        </div>

        <label>IrAS ${_sel('iras_sn', q.iras_sn === 'sim' ? 'Sim' : q.iras_sn === 'nao' ? 'Não' : '', ['Sim','Não'], 'Todas').replace('value="Sim"', 'value="sim"').replace('value="Não"', 'value="nao"')}</label>
        <label>Tipo de IrAS ${_sel('iras_classe', q.iras_classe, OPC.iras, 'Todos')}</label>
        <label>Etiologia <input name="etiol" value="${val('etiol')}" placeholder="contém…" class="gf-in"></label>
        <label>Veredito ${_sel('veredito', q.veredito, OPC.veredito, 'Todos')}</label>
        <label>Acesso diálise ${_sel('acesso_dialise', q.acesso_dialise, OPC.acesso_dialise, 'Todos')}</label>
        <label>SOFA mín <input type="number" name="sofa_min" value="${val('sofa_min')}" class="gf-in" style="width:64px"></label>
        <label>máx <input type="number" name="sofa_max" value="${val('sofa_max')}" class="gf-in" style="width:64px"></label>
      </div>
      <div class="gf-acoes">
        <button type="submit" class="gf-ok">Aplicar filtros</button>
        <a href="/atb/admin/grid?${_safe('cols=' + (q.cols || '') + (q.iras ? '&iras=' + q.iras : ''))}" class="gf-limpar">Limpar filtros</a>
      </div>
    </form>`;

  // ── painel de COLUNAS ──────────────────────────────────────────────────────
  const grupos = {};
  Object.keys(COLS).forEach(k => { (grupos[COLS[k].grupo] = grupos[COLS[k].grupo] || []).push(k); });
  const colunasForm = `
    <form method="GET" action="/atb/admin/grid" class="gf-panel" id="gf-colunas" style="display:none">
      ${hidden(['cols'])}
      <div class="gf-cols">
        ${Object.keys(grupos).map(g => `
          <div class="gf-colgrp"><div class="gf-colgrp-t">${_safe(g)}</div>
            ${grupos[g].map(k => `<label class="gf-chk"><input type="checkbox" name="cols" value="${k}" ${colsAtivas.includes(k) ? 'checked' : ''}> ${_safe(COLS[k].label)}</label>`).join('')}
          </div>`).join('')}
      </div>
      <div class="gf-acoes">
        <button type="submit" class="gf-ok">Aplicar colunas</button>
        <a href="/atb/admin/grid?${_safe(Object.keys(q).filter(k => k !== 'cols' && k !== 'page' && q[k]).map(k => k + '=' + encodeURIComponent(q[k])).join('&'))}" class="gf-limpar">Limpar colunas</a>
      </div>
    </form>`;

  return `
  <style>
    .gf-bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
    .gf-bar .gf-in{padding:7px 11px;border-radius:7px;border:1px solid #dadce0;background:#fff;color:#202124;font-size:13px}
    .gf-btn{padding:7px 14px;border-radius:7px;border:1px solid #dadce0;background:#fff;color:#3b6fd4;font-size:13px;cursor:pointer;font-weight:500}
    .gf-btn .badge{background:#3b6fd4;color:#fff;border-radius:10px;padding:0 6px;font-size:11px;margin-left:5px}
    .gf-panel{background:#fff;border:1px solid #e3e6ea;border-radius:10px;padding:14px 16px;margin-bottom:12px;box-shadow:0 4px 14px rgba(60,80,120,.06)}
    .gf-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:10px 14px;align-items:end}
    .gf-grid label{display:flex;flex-direction:column;gap:4px;font-size:11px;color:#5f6368;text-transform:uppercase;letter-spacing:.03em}
    .gf-grid .gf-in,.gf-grid select{font-size:13px;padding:7px 9px;border:1px solid #dadce0;border-radius:7px;text-transform:none;color:#202124;background:#fff}
    .gf-atalhos{display:flex;gap:6px;align-items:flex-end;flex-wrap:wrap}
    .gf-atalhos button{font-size:12px;padding:7px 10px;border:1px solid #cdd5e0;background:#eef3fb;color:#2c5aa8;border-radius:7px;cursor:pointer}
    .gf-acoes{display:flex;gap:12px;align-items:center;margin-top:14px}
    .gf-ok{background:#3b6fd4;color:#fff;border:none;border-radius:7px;padding:9px 18px;font-size:13px;font-weight:600;cursor:pointer}
    .gf-limpar{color:#80868b;font-size:13px}
    .gf-cols{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:10px 18px}
    .gf-colgrp-t{font-size:11px;font-weight:700;color:#3b6fd4;text-transform:uppercase;letter-spacing:.04em;margin-bottom:6px}
    .gf-chk{display:flex;align-items:flex-start;gap:7px;font-size:13px;color:#3c4043;padding:2px 0;cursor:pointer;line-height:1.35}
    .gf-chk input{flex:0 0 auto;margin:2px 0 0;width:15px;height:15px}
    .gx-cell{color:#3c4043;font-size:13px;white-space:nowrap}
  </style>
  <div class="gf-bar">
    <form method="GET" action="/atb/admin/grid" style="display:flex;gap:8px;align-items:center">
      ${hidden(['q'])}
      <input name="q" value="${val('q')}" placeholder="Paciente, prontuário…" class="gf-in" style="width:210px">
      <button class="gf-btn" type="submit">Buscar</button>
    </form>
    <button type="button" class="gf-btn" onclick="var p=document.getElementById('gf-filtros');p.style.display=p.style.display==='none'?'block':'none';document.getElementById('gf-colunas').style.display='none'">🔍 Filtros${nAtivos ? `<span class="badge">${nAtivos}</span>` : ''}</button>
    <button type="button" class="gf-btn" onclick="var p=document.getElementById('gf-colunas');p.style.display=p.style.display==='none'?'block':'none';document.getElementById('gf-filtros').style.display='none'">▦ Colunas${colsAtivas.length ? `<span class="badge">${colsAtivas.length}</span>` : ''}</button>
    <div style="margin-left:auto">${pager || ''}</div>
  </div>
  ${filtrosForm}
  ${colunasForm}
  <script>
  (function(){
    function fmt(d){ return d.toISOString().slice(0,10); }
    document.querySelectorAll('#gf-filtros .gf-atalhos button').forEach(function(b){
      b.addEventListener('click', function(){
        var hoje = new Date(), de, ate;
        var r = b.getAttribute('data-range');
        if(r === 'mes'){ // mês calendário anterior
          de = new Date(hoje.getFullYear(), hoje.getMonth()-1, 1);
          ate = new Date(hoje.getFullYear(), hoje.getMonth(), 0);
        } else if(r === 'sem'){ // 6 meses anteriores
          de = new Date(hoje.getFullYear(), hoje.getMonth()-6, 1);
          ate = new Date(hoje.getFullYear(), hoje.getMonth(), 0);
        } else { // este ano
          de = new Date(hoje.getFullYear(), 0, 1);
          ate = hoje;
        }
        document.getElementById('gf-sub-de').value = fmt(de);
        document.getElementById('gf-sub-ate').value = fmt(ate);
      });
    });
  })();
  </script>`;
}
