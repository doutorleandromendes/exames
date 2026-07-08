// ════════════════════════════════════════════════════════════════════════════
//  GRADE MOBILE (iPhone-friendly)  —  /atb/m
//
//  Versão enxuta da grade de Controle ATB para uso no celular:
//    • sem os cards de métricas do topo
//    • cada ficha vira um card: Nome · Setor · ATB · Parecer
//    • parecer editável inline (veredito + especificação em bottom-sheet,
//      com as frases pré-configuradas do banco) → POST /atb/admin/api/parecer/:id
//    • busca (nome/prontuário) + chips (Todas / A classificar / Sem parecer)
//    • paginação prev/next
//
//  Reuso:
//    • buildGridWhere (atb-grid-filters.js) → mesmos filtros/recortes da grade;
//      o tenant-lock (atb-tenant.js) já injeta req.query.inst por domínio,
//      então app.lcmendes.med.br mostra só HUSF e scmi.lcmendes.med.br só SCMI.
//    • PARECER_VEREDITOS / CORES (atb-parecer-edit-routes.js)
//    • getParecerFrases (atb-parecer-frases.js)
//
//  Integração em atb-routes.js (dentro de registerAtbRoutes):
//    import { registerGridMobileRoutes } from './atb-grid-mobile-routes.js';
//    registerGridMobileRoutes(app, pool, gridRequired);
//
//  Sem schema novo — só leitura + o endpoint de parecer que já existe.
// ════════════════════════════════════════════════════════════════════════════

import { buildGridWhere } from './atb-grid-filters.js';
import { PARECER_VEREDITOS, PARECER_VEREDITO_CORES, PARECER_VEREDITO_FG } from './atb-parecer-edit-routes.js';
import { getParecerFrases } from './atb-parecer-frases.js';

function safe(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ── Paleta clara (cópia local; fonte: _C em atb-routes.js — função-escopada lá) ──
const _C = {
  laranjaClaro:'#fcd9b6', pessego:'#fcdcd2', rosa:'#f8d7e8', roxoClaro:'#e3d4f5',
  tealClaro:'#c3efe0', azulClaro:'#cfe9f7', azulClaro2:'#b8e0ed', verdeClaro:'#d4f0c4',
  amareloClaro:'#f0ead0', cinzaAzul:'#c5cce0', lilas:'#ecd6f7',
};
const _FG = '#3a3a3a';
const SETOR_CORES = {
  'PS':_C.laranjaClaro,'EPM':_C.pessego,'Cuidados Intermediários':_C.rosa,
  'Psiquiatria':_C.roxoClaro,'Apartamento':_C.tealClaro,'Oncologia':_C.azulClaro,
  'Clínica Cirúrgica':_C.verdeClaro,'Semi':_C.amareloClaro,'Hemodiálise':_C.laranjaClaro,
  'Pediatria':_C.cinzaAzul,'UTI':_C.azulClaro2,'UTI Neo / Infantil':_C.pessego,
  'UTI C':_C.lilas,'UTI Respiratória':_C.azulClaro,'Ginecologia/Obstetrícia':_C.cinzaAzul,
  'Clínica Médica':_C.amareloClaro,
};
const ATB_CORES = {
  'Cefepime':_C.laranjaClaro,'Ceftriaxone':_C.pessego,'Fosfomicina':_C.rosa,
  'Anfotericina B':_C.roxoClaro,'Daptomicina':_C.tealClaro,'Tigeciclina':_C.azulClaro,
  'Micafungina':_C.verdeClaro,'Meropenem':_C.amareloClaro,
  'Piperacilina/Tazobactam':_C.laranjaClaro,'Vancomicina':_C.cinzaAzul,
  'Teicoplanina':_C.azulClaro2,'Polimixina B':_C.pessego,
  'Polimixina E (colestimetato)':_C.lilas,'Amicacina':_C.roxoClaro,
  'Gentamicina':_C.amareloClaro,'LINEZOLIDA':_C.cinzaAzul,
};

const _pill = (mapa, val) =>
  `<span class="pill" style="background:${mapa[val] || '#eceff3'};color:${_FG}">${safe(val)}</span>`;

const _atbPills = (arr) => {
  const items = Array.isArray(arr) ? arr : (arr ? [arr] : []);
  return items.map(v => _pill(ATB_CORES, v)).join('');
};

const _veredito1 = (f) => {
  const a = Array.isArray(f.recomendacao_scih) ? f.recomendacao_scih
    : (typeof f.recomendacao_scih === 'string'
        ? (() => { try { const x = JSON.parse(f.recomendacao_scih); return Array.isArray(x) ? x : []; } catch { return []; } })()
        : []);
  return a[0] || '';
};

// ── Opções dos filtros (espelham OPC de atb-grid-filters.js) ─────────────────
const OPC = {
  setor: ['PS','EPM','Cuidados Intermediários','Psiquiatria','Apartamento','Oncologia','Clínica Cirúrgica','Semi','Hemodiálise','Pediatria','UTI','UTI Neo / Infantil','UTI C','Ginecologia/Obstetrícia','Clínica Médica'],
  iras: ['PAV','PAV/EVA','IPCSLab','IPCSClin','ITU','ISC','(HD)ILAV','(HD)ICS','(HD)Bact','HD_Bact_FAV','HD_Bact_CDL','HD_Bact_PC','HD_ILAV_FAV','HD_ILAV_CDL','HD_ILAV_PC','CDI','Onco_Bact','Sem dados','Descartado','Repetida'],
  tipo_terapia: ['Empírica','Guiada por cultura','Profilaxia cirúrgica'],
  veredito: ['Sim','Não','Com ajustes (especificados abaixo)','ATB não controlado','Suspenso','Ficha Repetida','Audit_post'],
  acesso_dialise: ['FAV','CDL (Shilley)','Perm-cath','PTFE'],
  mr: ['EPC','ESBL','KPC','METALO','MR','MRSA','OXA-R','VRE'],
};
// chaves que contam como "filtro ativo" (fora de q/iras/parecer, que têm UI própria)
const FILTRO_KEYS = ['setor','data_de','data_ate','sub_de','sub_ate','iras_sn','iras_classe','etiol','tipo_terapia','veredito','acesso_dialise','sofa_min','sofa_max','cult_pos','cult_hemo','cult_mr'];

const _arr = v => Array.isArray(v) ? v : String(v || '').split(',').map(x => x.trim()).filter(Boolean);
const _v = (q, k) => safe(q[k] || '');

// <option> helper
function _opt(val, sel, label) {
  return `<option value="${safe(val)}"${String(sel) === String(val) ? ' selected' : ''}>${safe(label != null ? label : val)}</option>`;
}
function _sel(name, value, opcoes, placeholder) {
  return `<select name="${name}" class="fin">` +
    `<option value="">${safe(placeholder)}</option>` +
    opcoes.map(o => _opt(o, value, o)).join('') + `</select>`;
}
// grupo de chips-checkbox (multi) — muito melhor que <select multiple> no iPhone
function _chipset(name, opcoes, selecionados) {
  return `<div class="chipset">` + opcoes.map(o =>
    `<label class="cch"><input type="checkbox" name="${name}" value="${safe(o)}"${selecionados.indexOf(o) !== -1 ? ' checked' : ''}><span>${safe(o)}</span></label>`
  ).join('') + `</div>`;
}
// Sim/Não select cujos values são sim/nao
function _selSN(name, cur, placeholder) {
  return `<select name="${name}" class="fin">` +
    `<option value="">${safe(placeholder)}</option>` +
    `<option value="sim"${cur === 'sim' ? ' selected' : ''}>Sim</option>` +
    `<option value="nao"${cur === 'nao' ? ' selected' : ''}>Não</option></select>`;
}

// hidden inputs p/ preservar q/iras/parecer (e cols) dentro do form de filtros/busca
function _hidden(q, exceto) {
  return Object.keys(q)
    .filter(k => !exceto.includes(k) && k !== 'page' && q[k] !== '' && q[k] != null)
    .map(k => {
      const v = Array.isArray(q[k]) ? q[k].join(',') : q[k];   // arrays (setor/cult_mr) → CSV, que buildGridWhere entende
      return v === '' ? '' : `<input type="hidden" name="${safe(k)}" value="${safe(v)}">`;
    }).join('');
}

export function registerGridMobileRoutes(app, pool, gridRequired) {

  // atalho legível a partir da grade desktop
  app.get('/atb/admin/grid/mobile', (req, res) => {
    const qs = new URLSearchParams(req.query).toString();
    res.redirect('/atb/m' + (qs ? '?' + qs : ''));
  });

  app.get('/atb/m', gridRequired, async (req, res) => {
    try {
      const soMicro = !!(req.user && req.user.micro && !req.user.scih && !req.user.super_admin) && req.cookies?.adm !== '1';
      const q = (req.query.q || '').trim();
      const pageNum = Math.max(1, parseInt(req.query.page || '1', 10) || 1);
      const pageSize = 30;
      const offset = (pageNum - 1) * pageSize;
      const sigla = req.atbTenant || '';
      const mostrarCult = !sigla || sigla === 'HUSF';          // culturas só existem no HUSF
      const nFiltros = FILTRO_KEYS.filter(k => {
        const v = req.query[k];
        return Array.isArray(v) ? v.length : (v != null && v !== '');
      }).length;
      const setSel = _arr(req.query.setor);
      const mrSel  = _arr(req.query.cult_mr);

      const { whereSql, params } = buildGridWhere(req.query);

      const { rows: [{ total }] } = await pool.query(`
        SELECT COUNT(*) AS total FROM atb_fichas f
        LEFT JOIN atb_instituicoes i ON i.id=f.instituicao_id
        LEFT JOIN atb_avaliacoes a ON a.ficha_id=f.id WHERE ${whereSql}`, params);

      // contagem dos chips sobre o recorte-base (sem os próprios chips)
      const base = buildGridWhere({ ...req.query, iras: '', parecer: '' });
      const { rows: [cnt] } = await pool.query(`
        SELECT COUNT(*) AS todas,
               COUNT(*) FILTER (WHERE a.iras IS NULL OR a.iras='') AS pendentes,
               COUNT(*) FILTER (WHERE f.recomendacao_scih IS NULL OR (jsonb_typeof(f.recomendacao_scih)='array' AND jsonb_array_length(f.recomendacao_scih)=0)) AS sem_parecer
        FROM atb_fichas f
        LEFT JOIN atb_instituicoes i ON i.id=f.instituicao_id
        LEFT JOIN atb_avaliacoes a ON a.ficha_id=f.id WHERE ${base.whereSql}`, base.params);

      const { rows } = await pool.query(`
        SELECT f.id, f.paciente_nome, f.paciente_nome_raw, f.prontuario, f.setor,
               f.atb_solicitado, f.recomendacao_scih, f.recomendacoes_especificacao,
               f.obito, f.retrospectiva,
               f.data_referencia, f.jotform_created_at, f.created_at,
               i.sigla AS instituicao
        FROM atb_fichas f
        LEFT JOIN atb_instituicoes i ON i.id=f.instituicao_id
        LEFT JOIN atb_avaliacoes a ON a.ficha_id=f.id
        WHERE ${whereSql}
        ORDER BY COALESCE(f.data_referencia, f.jotform_created_at, f.created_at) DESC
        LIMIT $${params.length + 1} OFFSET $${params.length + 2}`, [...params, pageSize, offset]);

      const totalPages = Math.max(1, Math.ceil(parseInt(total, 10) / pageSize));
      const dtFmt = d => d ? new Date(d).toLocaleDateString('pt-BR', { day:'2-digit', month:'2-digit', year:'2-digit' }) : '—';

      const vOpts = (sel) => ['<option value="">— veredito —</option>']
        .concat(PARECER_VEREDITOS.map(v =>
          `<option value="${safe(v)}" ${sel === v ? 'selected' : ''}>${safe(v)}</option>`)).join('');

      const cards = rows.map(f => {
        const nome = f.paciente_nome || f.paciente_nome_raw || '—';
        const ver = _veredito1(f);
        const cor = PARECER_VEREDITO_CORES[ver] || '';
        const espec = f.recomendacoes_especificacao || '';
        const preview = espec ? (espec.length > 60 ? espec.slice(0, 60) + '…' : espec) : '';
        return `<div class="fcard" data-fid="${f.id}">
          <a class="nome" href="/atb/admin/fichas/${f.id}">${safe(nome)}${f.retrospectiva ? ' <span class="tag tR">R</span>' : ''}${f.obito ? ' <span class="obito">✝</span>' : ''}</a>
          <div class="sub">${dtFmt(f.data_referencia || f.jotform_created_at || f.created_at)}${f.prontuario ? ' · pront. ' + safe(f.prontuario) : ''}${!sigla && f.instituicao ? ' · ' + safe(f.instituicao) : ''}</div>
          <div class="pills">${f.setor ? _pill(SETOR_CORES, f.setor) : ''}${_atbPills(f.atb_solicitado)}</div>
          <div class="parecer">
            <select class="ver" data-fid="${f.id}"${cor ? ` style="background:${cor};border-color:${cor}"` : ''}${soMicro ? ' disabled' : ''}>${vOpts(ver)}</select>
            <button type="button" class="esp${espec ? ' tem' : ''}" data-fid="${f.id}" data-espec="${safe(espec)}"${soMicro ? ' disabled' : ''}>${espec ? '✎ ' + safe(preview) : '+ especificação'}</button>
          </div>
        </div>`;
      }).join('');

      const mkUrl = (extra) => '/atb/m?' + new URLSearchParams({ ...req.query, ...extra });
      const chip = (label, n, extra, ativo) =>
        `<a class="chip${ativo ? ' on' : ''}" href="${mkUrl({ ...extra, page: '1' })}">${label} <b>${n}</b></a>`;
      const chips =
        chip('Todas', cnt.todas, { iras: '', parecer: '' }, !req.query.iras && req.query.parecer !== 'sem') +
        chip('A classificar', cnt.pendentes, { iras: 'pendente', parecer: '' }, req.query.iras === 'pendente' && req.query.parecer !== 'sem') +
        chip('Sem parecer', cnt.sem_parecer, { iras: '', parecer: 'sem' }, req.query.parecer === 'sem');

      const pager = totalPages > 1 ? `<div class="pager">
          ${pageNum > 1 ? `<a class="pgbtn" href="${mkUrl({ page: String(pageNum - 1) })}">‹ Anterior</a>` : '<span class="pgbtn off">‹ Anterior</span>'}
          <span class="pginfo">${pageNum}/${totalPages} · ${total}</span>
          ${pageNum < totalPages ? `<a class="pgbtn" href="${mkUrl({ page: String(pageNum + 1) })}">Próxima ›</a>` : '<span class="pgbtn off">Próxima ›</span>'}
        </div>` : `<div class="pager"><span class="pginfo">${total} fichas</span></div>`;

      const frases = (await getParecerFrases(pool)).map(r => r.texto);
      const microAviso = soMicro ? `<div class="aviso">Perfil Microbiologia — edição de parecer indisponível neste perfil.</div>` : '';

      // ── sheet de FILTROS (form GET → a própria /atb/m) ──────────────────────
      // Preserva q/iras/parecer (chips + busca) via hidden; envia os campos de filtro.
      const filtroSheet = `
      <div id="filt-bg"></div>
      <form id="filt" method="get" action="/atb/m">
        ${_hidden(req.query, FILTRO_KEYS.concat(['page','setor','cult_mr']))}
        <div class="fhead">
          <div class="ttl">Filtros</div>
          <button type="button" class="fx" id="filt-x">✕</button>
        </div>
        <div class="fbody">
          <label class="fl"><span>Setor</span>${_chipset('setor', OPC.setor, setSel)}</label>

          <div class="frow">
            <label class="fl"><span>IrAS</span>${_selSN('iras_sn', req.query.iras_sn || '', 'Todas')}</label>
            <label class="fl"><span>Tipo de IrAS</span>${_sel('iras_classe', req.query.iras_classe, OPC.iras, 'Todos')}</label>
          </div>

          <div class="frow">
            <label class="fl"><span>Veredito</span>${_sel('veredito', req.query.veredito, OPC.veredito, 'Todos')}</label>
            <label class="fl"><span>Tipo de terapia</span>${_sel('tipo_terapia', req.query.tipo_terapia, OPC.tipo_terapia, 'Todos')}</label>
          </div>

          <label class="fl"><span>Etiologia (contém)</span><input class="fin" name="etiol" value="${_v(req.query,'etiol')}" placeholder="ex.: Klebsiella…"></label>

          <div class="frow">
            <label class="fl"><span>Acesso diálise</span>${_sel('acesso_dialise', req.query.acesso_dialise, OPC.acesso_dialise, 'Todos')}</label>
            <label class="fl"><span>SOFA</span>
              <span class="minmax"><input class="fin" type="number" inputmode="numeric" name="sofa_min" value="${_v(req.query,'sofa_min')}" placeholder="mín"><input class="fin" type="number" inputmode="numeric" name="sofa_max" value="${_v(req.query,'sofa_max')}" placeholder="máx"></span></label>
          </div>

          <label class="fl"><span>Data de referência</span>
            <span class="minmax"><input class="fin" type="date" name="data_de" value="${_v(req.query,'data_de')}"><input class="fin" type="date" name="data_ate" value="${_v(req.query,'data_ate')}"></span></label>

          <label class="fl"><span>Submission</span>
            <span class="minmax"><input class="fin" type="date" id="sub-de" name="sub_de" value="${_v(req.query,'sub_de')}"><input class="fin" type="date" id="sub-ate" name="sub_ate" value="${_v(req.query,'sub_ate')}"></span></label>
          <div class="atalhos">
            <button type="button" data-range="mes_atual">Este mês</button>
            <button type="button" data-range="mes">Mês anterior</button>
            <button type="button" data-range="sem">Semestre</button>
            <button type="button" data-range="ano">Este ano</button>
          </div>

          ${mostrarCult ? `
          <div class="frow">
            <label class="fl"><span>Cultura positiva</span><select class="fin" name="cult_pos"><option value="">Todas</option><option value="1"${req.query.cult_pos==='1'?' selected':''}>Sim</option></select></label>
            <label class="fl"><span>Hemocultura</span><select class="fin" name="cult_hemo"><option value="">Todas</option><option value="1"${req.query.cult_hemo==='1'?' selected':''}>Sim</option></select></label>
          </div>
          <label class="fl"><span>Resistência (MR)</span>${_chipset('cult_mr', OPC.mr, mrSel)}</label>
          ` : ''}
        </div>
        <div class="facoes">
          <a class="fbtn" href="/atb/m${q||req.query.iras||req.query.parecer ? '?'+new URLSearchParams(Object.fromEntries(Object.entries(req.query).filter(([k,v])=>['q','iras','parecer'].includes(k)&&v))) : ''}">Limpar</a>
          <button type="submit" class="fbtn ok">Aplicar${nFiltros?` (${nFiltros})`:''}</button>
        </div>
      </form>`;

      res.send(`<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover, maximum-scale=1, user-scalable=no">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="ATB ${safe(sigla)}">
<meta name="mobile-web-app-capable" content="yes">
<meta name="theme-color" content="#0c447c">
<title>ATB${sigla ? ' · ' + safe(sigla) : ''} — Controle</title>
<link rel="apple-touch-icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='180' height='180'%3E%3Crect width='180' height='180' rx='40' fill='%230c447c'/%3E%3Ctext x='90' y='118' font-size='72' font-family='Georgia,serif' fill='white' text-anchor='middle'%3EATB%3C/text%3E%3C/svg%3E">
<style>
  :root{
    --pri:#0c447c; --pri-d:#093461; --bg:#eef2f7; --card:#fff; --ink:#1e293b;
    --mut:#64748b; --line:#e2e8f0; --ok:#0e7a4b;
    --sat:env(safe-area-inset-top); --sab:env(safe-area-inset-bottom);
  }
  *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
  html,body{margin:0}
  body{font:15px/1.4 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--ink);
    padding-bottom:calc(16px + var(--sab))}
  .top{position:sticky;top:0;z-index:50;background:var(--pri);color:#fff;padding:calc(10px + var(--sat)) 14px 10px;
    box-shadow:0 2px 8px rgba(0,0,0,.15)}
  .top .l1{display:flex;align-items:center;gap:10px}
  .top h1{font-size:16px;font-weight:700;margin:0;flex:1;letter-spacing:.2px}
  .top a.full{color:#fff;font-size:12px;opacity:.85;text-decoration:none;background:rgba(255,255,255,.14);border-radius:8px;padding:6px 10px}
  .top form{display:flex;gap:8px;margin-top:9px}
  .top input[type=search]{flex:1;font:inherit;border:0;border-radius:9px;padding:9px 12px;outline:none;background:#fff;color:var(--ink);-webkit-appearance:none}
  .top button{background:rgba(255,255,255,.16);border:0;color:#fff;font-size:14px;border-radius:9px;padding:9px 13px;cursor:pointer}
  .top .filt-btn{position:relative;white-space:nowrap}
  .top .filt-btn .badge{background:#fff;color:var(--pri);border-radius:10px;padding:0 6px;font-size:11px;font-weight:700;margin-left:5px}
  .wrap{max-width:640px;margin:0 auto;padding:12px 12px 0}
  .chips{display:flex;gap:8px;overflow-x:auto;padding:2px 0 10px;-webkit-overflow-scrolling:touch}
  .chip{flex:0 0 auto;background:#fff;border:1px solid var(--line);color:var(--mut);border-radius:16px;padding:6px 13px;
    font-size:13px;text-decoration:none;white-space:nowrap}
  .chip b{font-weight:700;font-size:11px;opacity:.8;margin-left:2px}
  .chip.on{background:var(--pri);border-color:var(--pri);color:#fff}
  .fcard{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:13px 14px;margin:0 0 11px;
    box-shadow:0 1px 3px rgba(15,23,42,.05)}
  .fcard .nome{display:block;font-weight:700;font-size:15px;color:var(--ink);text-decoration:none;line-height:1.3}
  .fcard .tag{display:inline-block;font-size:9px;font-weight:700;border-radius:4px;padding:1px 4px;vertical-align:middle}
  .fcard .tR{background:#d98a3d;color:#fff}
  .fcard .obito{color:#c0392b}
  .fcard .sub{font-size:12px;color:var(--mut);margin:2px 0 8px}
  .pills{display:flex;flex-wrap:wrap;gap:5px;margin:0 0 10px}
  .pill{display:inline-block;padding:3px 9px;border-radius:5px;font-size:12px;line-height:1.35;white-space:nowrap}
  .parecer{display:flex;flex-direction:column;gap:6px}
  .parecer .ver{width:100%;font:inherit;font-size:14px;padding:10px 12px;border:1.5px solid var(--line);border-radius:10px;
    background:#fff;color:var(--ink);-webkit-appearance:none;appearance:none;
    background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%2364748b' stroke-width='2' fill='none'/%3E%3C/svg%3E");
    background-repeat:no-repeat;background-position:right 13px center;padding-right:34px}
  .parecer .esp{text-align:left;font:inherit;font-size:12.5px;line-height:1.35;padding:9px 11px;border:1.5px dashed #c6cdd6;
    border-radius:10px;background:#fafbfc;color:var(--mut);cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .parecer .esp.tem{border-style:solid;border-color:#bcd0ec;background:#eef4fc;color:var(--pri-d)}
  .parecer .ver:disabled,.parecer .esp:disabled{opacity:.5;pointer-events:none}
  .fcard.salvo{outline:2px solid rgba(14,122,75,.45);outline-offset:1px;transition:outline-color .3s}
  .aviso{background:#e6f1fb;color:var(--pri-d);border:1px solid #b5d4f4;border-radius:10px;padding:9px 12px;margin:0 0 12px;font-size:13px}
  .vazio{padding:34px 12px;text-align:center;color:var(--mut)}
  .pager{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:6px 2px 14px}
  .pgbtn{background:#fff;border:1px solid var(--line);border-radius:10px;padding:9px 14px;font-size:14px;color:var(--pri);text-decoration:none}
  .pgbtn.off{color:#c3cad4;border-color:#e9edf2}
  .pginfo{font-size:12.5px;color:var(--mut)}
  .foot{text-align:center;color:var(--mut);font-size:11.5px;padding:4px 0 8px}
  /* bottom-sheet da especificação */
  #sheet-bg{position:fixed;inset:0;background:rgba(15,23,42,.45);z-index:90;display:none}
  #sheet{position:fixed;left:0;right:0;bottom:0;z-index:95;background:#fff;border-radius:16px 16px 0 0;
    box-shadow:0 -8px 30px rgba(12,68,124,.25);padding:14px 14px calc(14px + var(--sab));display:none;
    max-height:82vh;overflow:auto}
  #sheet .ttl{font-size:11px;font-weight:700;color:var(--pri);text-transform:uppercase;letter-spacing:.04em;margin:0 0 9px}
  #sheet input.busca{width:100%;font:inherit;padding:10px 12px;border:1.5px solid var(--line);border-radius:10px;margin:0 0 7px;outline:none}
  #sheet input.busca:focus{border-color:var(--pri)}
  #sheet .lista{max-height:170px;overflow-y:auto;border:1px solid #eef1f5;border-radius:10px;margin:0 0 8px}
  #sheet .lista .item{padding:9px 11px;font-size:13px;line-height:1.35;border-bottom:1px solid #f1f4f8;cursor:pointer}
  #sheet .lista .item:last-child{border-bottom:0}
  #sheet .lista .item:active{background:#eef4fc}
  #sheet .lista .nada{padding:11px;font-size:13px;color:var(--mut);text-align:center}
  #sheet .dica{font-size:11px;color:var(--mut);margin:0 0 8px}
  #sheet textarea{width:100%;min-height:100px;font:inherit;font-size:14px;padding:10px 12px;border:1.5px solid var(--line);
    border-radius:10px;resize:vertical;outline:none}
  #sheet textarea:focus{border-color:var(--pri)}
  #sheet .acoes{display:flex;gap:9px;margin-top:11px}
  #sheet .acoes button{flex:1;font:inherit;font-size:15px;font-weight:600;padding:12px;border-radius:11px;cursor:pointer;
    border:1.5px solid var(--line);background:#fff;color:var(--mut)}
  #sheet .acoes button.ok{background:var(--pri);border-color:var(--pri);color:#fff}
  /* sheet de FILTROS (tela quase cheia) */
  #filt-bg{position:fixed;inset:0;background:rgba(15,23,42,.45);z-index:96;display:none}
  #filt{position:fixed;left:0;right:0;bottom:0;z-index:97;background:var(--bg);border-radius:16px 16px 0 0;
    box-shadow:0 -8px 30px rgba(12,68,124,.25);display:none;flex-direction:column;max-height:92vh}
  #filt.open{display:flex}
  #filt .fhead{display:flex;align-items:center;padding:14px 16px calc(12px);border-bottom:1px solid var(--line);background:#fff;border-radius:16px 16px 0 0}
  #filt .fhead .ttl{flex:1;font-size:15px;font-weight:700;color:var(--pri-d)}
  #filt .fhead .fx{background:none;border:0;font-size:20px;color:var(--mut);cursor:pointer;padding:2px 6px;line-height:1}
  #filt .fbody{overflow-y:auto;padding:14px 16px 6px;-webkit-overflow-scrolling:touch}
  #filt .fl{display:block;margin:0 0 13px}
  #filt .fl>span{display:block;font-size:12px;color:var(--mut);font-weight:600;margin:0 0 6px}
  #filt .frow{display:flex;gap:11px}#filt .frow>.fl{flex:1}
  #filt .fin{width:100%;font:inherit;font-size:15px;padding:11px 12px;border:1.5px solid var(--line);border-radius:10px;
    background:#fff;color:var(--ink);-webkit-appearance:none;appearance:none}
  #filt select.fin{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%2364748b' stroke-width='2' fill='none'/%3E%3C/svg%3E");
    background-repeat:no-repeat;background-position:right 12px center;padding-right:32px}
  #filt .minmax{display:flex;gap:9px}#filt .minmax .fin{flex:1}
  #filt .chipset{display:flex;flex-wrap:wrap;gap:7px}
  #filt .cch{position:relative}
  #filt .cch input{position:absolute;opacity:0;width:0;height:0}
  #filt .cch span{display:inline-block;padding:8px 13px;border:1.5px solid var(--line);border-radius:16px;font-size:13px;
    background:#fff;color:var(--ink);cursor:pointer}
  #filt .cch input:checked+span{background:var(--pri);border-color:var(--pri);color:#fff}
  #filt .atalhos{display:flex;flex-wrap:wrap;gap:7px;margin:-4px 0 14px}
  #filt .atalhos button{font:inherit;font-size:12.5px;padding:8px 12px;border:1px solid #cdd5e0;background:#e9f0fb;
    color:#2c5aa8;border-radius:9px;cursor:pointer}
  #filt .facoes{display:flex;gap:10px;padding:12px 16px calc(14px + var(--sab));border-top:1px solid var(--line);background:#fff}
  #filt .fbtn{flex:1;text-align:center;font:inherit;font-size:15px;font-weight:600;padding:13px;border-radius:12px;
    border:1.5px solid var(--line);background:#fff;color:var(--mut);text-decoration:none;cursor:pointer}
  #filt .fbtn.ok{background:var(--pri);border-color:var(--pri);color:#fff}
</style>
</head>
<body>
<div class="top">
  <div class="l1">
    <h1>Controle ATB${sigla ? ' · ' + safe(sigla) : ''}</h1>
    <a class="full" href="/atb/admin/grid">grade completa</a>
  </div>
  <form method="get" action="/atb/m">
    <input type="search" name="q" value="${safe(q)}" placeholder="Buscar nome ou prontuário…" autocomplete="off">
    ${_hidden(req.query, ['q','page'])}
    <button type="submit">Buscar</button>
    <button type="button" id="filt-open" class="filt-btn">Filtros${nFiltros?`<span class="badge">${nFiltros}</span>`:''}</button>
  </form>
</div>
<div class="wrap">
  <div class="chips">${chips}</div>
  ${microAviso}
  ${cards || '<div class="vazio">Nenhuma ficha no recorte.</div>'}
  ${pager}
  <div class="foot">SCIH · stewardship — versão mobile</div>
</div>

${filtroSheet}

<div id="sheet-bg"></div>
<div id="sheet">
  <div class="ttl">Especificação do parecer</div>
  <input type="text" class="busca" placeholder="Buscar frase pré-configurada…">
  <div class="lista"></div>
  <div class="dica">Toque numa frase p/ inserir no texto. Edite e combine livremente.</div>
  <textarea placeholder="Texto livre — ou comece por uma frase acima."></textarea>
  <div class="acoes">
    <button type="button" class="cancelar">Cancelar</button>
    <button type="button" class="ok salvar">Salvar</button>
  </div>
</div>

<script>
(function(){
  var FRASES = ${JSON.stringify(frases)};
  var CORES  = ${JSON.stringify(PARECER_VEREDITO_CORES)};
  var FG     = '${PARECER_VEREDITO_FG}';

  function postParecer(fid, body, onok){
    fetch('/atb/admin/api/parecer/'+fid, {
      method:'POST', headers:{'Content-Type':'application/json'},
      credentials:'same-origin', body:JSON.stringify(body)
    }).then(function(r){return r.json();})
      .then(function(j){ if(j && j.ok && onok) onok(); })
      .catch(function(){});
  }
  function flash(fid){
    var c=document.querySelector('.fcard[data-fid="'+fid+'"]'); if(!c) return;
    c.classList.add('salvo'); setTimeout(function(){c.classList.remove('salvo');},900);
  }

  // veredito: salva no change e pinta o select
  document.querySelectorAll('select.ver').forEach(function(sel){
    sel.addEventListener('change', function(){
      var fid=sel.getAttribute('data-fid'), v=sel.value;
      postParecer(fid, {veredito:v}, function(){
        var cor=CORES[v]||'';
        sel.style.background=cor||'#fff';
        sel.style.borderColor=cor||'';
        sel.style.color=FG;
        flash(fid);
      });
    });
  });

  // especificação: bottom-sheet
  var bg=document.getElementById('sheet-bg'), sh=document.getElementById('sheet');
  var busca=sh.querySelector('.busca'), lista=sh.querySelector('.lista'), ta=sh.querySelector('textarea');
  var atual=null;

  function renderLista(f){
    var t=(f||'').toLowerCase();
    var itens=FRASES.filter(function(x){return !t || x.toLowerCase().indexOf(t)!==-1;});
    lista.innerHTML='';
    if(!itens.length){ lista.innerHTML='<div class="nada">Nenhuma frase encontrada.</div>'; return; }
    itens.forEach(function(x){
      var d=document.createElement('div'); d.className='item'; d.textContent=x;
      d.onclick=function(){ ta.value=(ta.value?ta.value.replace(/\\s*$/,'')+'\\n':'')+x; };
      lista.appendChild(d);
    });
  }
  function abrir(btn){
    atual=btn;
    ta.value=btn.getAttribute('data-espec')||'';
    busca.value=''; renderLista('');
    bg.style.display='block'; sh.style.display='block';
  }
  function fechar(){ bg.style.display='none'; sh.style.display='none'; atual=null; }

  busca.addEventListener('input', function(){ renderLista(busca.value); });
  bg.addEventListener('click', fechar);
  sh.querySelector('.cancelar').onclick=fechar;
  sh.querySelector('.salvar').onclick=function(){
    if(!atual) return fechar();
    var fid=atual.getAttribute('data-fid'), txt=ta.value.trim(), btn=atual;
    postParecer(fid, {especificacao:txt}, function(){
      btn.setAttribute('data-espec', txt);
      if(txt){ btn.classList.add('tem'); btn.textContent='✎ '+(txt.length>60?txt.slice(0,60)+'…':txt); }
      else   { btn.classList.remove('tem'); btn.textContent='+ especificação'; }
      flash(fid); fechar();
    });
  };
  document.querySelectorAll('button.esp').forEach(function(btn){
    btn.addEventListener('click', function(){ abrir(btn); });
  });

  // ── sheet de filtros ──
  var fbg=document.getElementById('filt-bg'), fsh=document.getElementById('filt');
  var fopen=document.getElementById('filt-open'), fx=document.getElementById('filt-x');
  function abreFiltros(){ fbg.style.display='block'; fsh.classList.add('open'); }
  function fechaFiltros(){ fbg.style.display='none'; fsh.classList.remove('open'); }
  if(fopen) fopen.addEventListener('click', abreFiltros);
  if(fx) fx.addEventListener('click', fechaFiltros);
  if(fbg) fbg.addEventListener('click', fechaFiltros);

  // atalhos de intervalo p/ Submission
  function fmt(d){ return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0'); }
  document.querySelectorAll('#filt .atalhos button').forEach(function(b){
    b.addEventListener('click', function(){
      var h=new Date(), de, ate, r=b.getAttribute('data-range');
      if(r==='mes_atual'){ de=new Date(h.getFullYear(),h.getMonth(),1); ate=h; }
      else if(r==='mes'){ de=new Date(h.getFullYear(),h.getMonth()-1,1); ate=new Date(h.getFullYear(),h.getMonth(),0); }
      else if(r==='sem'){ de=new Date(h.getFullYear(),h.getMonth()-6,1); ate=new Date(h.getFullYear(),h.getMonth(),0); }
      else { de=new Date(h.getFullYear(),0,1); ate=h; }
      document.getElementById('sub-de').value=fmt(de);
      document.getElementById('sub-ate').value=fmt(ate);
    });
  });
})();
</script>
</body>
</html>`);
    } catch (e) {
      console.error('[atb] grid mobile error:', e);
      res.status(500).send('Erro: ' + safe(e.message));
    }
  });
}
