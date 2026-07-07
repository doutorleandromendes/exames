// ════════════════════════════════════════════════════════════════════════════
//  REGRAS CONDICIONAIS DO FORMULÁRIO — editor vivo + checagem no servidor
//
//  Edita, sem mexer no código, as regras de:
//    • VISIBILIDADE   (campo.cond)         → quando um campo aparece
//    • OBRIGATORIEDADE (campo.requiredCond) → quando um campo é exigido
//  As regras vivem no schema (atb_form_schema), fonte única já lida pelo engine
//  do cliente. Este módulo também porta o avaliador pro servidor e oferece um
//  validador genérico (backstop) que substitui travas fixas no POST de fichas.
//
//  Integração em atb-routes.js:
//    import { registerRegrasFormRoutes, validarObrigatoriosServidor }
//      from './atb-regras-form-routes.js';
//    // rotas:  registerRegrasFormRoutes(app, pool, adminRequired);
//    // no POST /atb/api/fichas (troca a trava fixa da história):
//    //   const schema = await getFormSchema(pool, inst);
//    //   const faltas = validarObrigatoriosServidor(schema, d);
//    //   if (faltas.length) return res.status(400).json({ error: faltas[0].msg, campos: faltas.map(f=>f.key) });
// ════════════════════════════════════════════════════════════════════════════
import { getFormSchema, saveFormSchema } from './atb-form-schema.js';

// ── Avaliação server-side (porta fiel do atb-form-engine.js) ─────────────────
function _normTxt(s) {
  return String(s == null ? '' : s).toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}
function _filled(v) {
  if (v == null) return false;
  if (Array.isArray(v)) return v.length > 0;
  return String(v).trim() !== '';  // espelha exatamente o _filled do engine do cliente
}
function _textContainsAny(v, tokens) {
  const hay = _normTxt(v);
  if (!hay || !Array.isArray(tokens)) return false;
  return tokens.some(t => {
    const nt = _normTxt(t);
    if (!nt) return false;
    if (nt.length <= 3) {
      const esc = nt.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      return new RegExp('(^|[^a-z0-9])' + esc + '([^a-z0-9]|$)').test(hay);
    }
    return hay.indexOf(nt) !== -1;
  });
}
export function avaliaCondServer(cond, valores) {
  if (!cond) return true;
  if (cond.all) return cond.all.every(c => avaliaCondServer(c, valores));
  if (cond.any) return cond.any.some(c => avaliaCondServer(c, valores));
  const v = valores ? valores[cond.campo] : undefined;
  switch (cond.op) {
    case 'eq':  return v === cond.valor;
    case 'neq': return v !== cond.valor;
    case 'in':  return Array.isArray(cond.valor) && cond.valor.indexOf(v) !== -1;
    case 'filled':     return _filled(v);
    case 'not_filled': return !_filled(v);
    case 'contains':     return Array.isArray(v) && v.indexOf(cond.valor) !== -1;
    case 'not_contains': return !(Array.isArray(v) && v.indexOf(cond.valor) !== -1);
    case 'contains_any': return Array.isArray(v) && Array.isArray(cond.valor) &&
                                cond.valor.some(x => v.indexOf(x) !== -1);
    case 'not_contains_any': return !(Array.isArray(v) && Array.isArray(cond.valor) &&
                                cond.valor.some(x => v.indexOf(x) !== -1));
    case 'text_contains_any': return _textContainsAny(v, cond.valor);
    default: return true;
  }
}

// ── Validador genérico de obrigatórios (backstop server-side) ────────────────
// Espelha o que o engine do cliente já exige: campo VISÍVEL e (required ||
// Aplica schema.preenchimentos sobre `dados` (mutação in-place), espelhando o cliente.
export function aplicarPreenchimentosServidor(schema, dados) {
  const aplicados = [];
  if (!schema || !Array.isArray(schema.preenchimentos) || !dados) return aplicados;
  for (const r of schema.preenchimentos) {
    if (!r || !r.campo || !avaliaCondServer(r.quando, dados)) continue;
    const atual = dados[r.campo];
    const vazio = atual === undefined || atual === null || atual === ''
      || (Array.isArray(atual) && atual.length === 0);
    if (!r.sobrescrever && !vazio) continue;
    if (atual === r.valor) continue;
    dados[r.campo] = r.valor;
    aplicados.push(r.campo);
  }
  return aplicados;
}

// requiredCond satisfeito) precisa estar preenchido (e respeitar minChars).
export function validarObrigatoriosServidor(schema, dados) {
  const faltas = [];
  if (!schema || !Array.isArray(schema.secoes)) return faltas;
  for (const sec of schema.secoes) {
    if (sec.cond && !avaliaCondServer(sec.cond, dados)) continue;
    for (const c of (sec.campos || [])) {
      if (!c.key) continue;
      // Bloco composto SOFA: os dados ficam em sub-chaves (sofa_*), nunca na key
      // do bloco (_sofa_bloco). O engine do cliente já valida a completude do SOFA;
      // checar dados[c.key] aqui daria sempre "obrigatório" (falso positivo → 400).
      if (c.type === 'sofa') continue;
      if (c.cond && !avaliaCondServer(c.cond, dados)) continue;
      const obrig = c.required === true || (c.requiredCond && avaliaCondServer(c.requiredCond, dados));
      if (!obrig) continue;
      const v = dados[c.key];
      const lbl = c.label || c.key;
      if (!_filled(v)) { faltas.push({ key: c.key, label: lbl, msg: `${lbl}: campo obrigatório.` }); continue; }
      if (c.minChars && String(v).trim().length < c.minChars) {
        faltas.push({ key: c.key, label: lbl, msg: c.minMsg || `${lbl}: descreva com mais detalhes.` });
      }
    }
  }
  return faltas;
}

// ── Catálogo de operadores ───────────────────────────────────────────────────
const OPS = [
  { op: 'eq',                label: 'é igual a',               valor: 'um' },
  { op: 'neq',               label: 'é diferente de',          valor: 'um' },
  { op: 'contains',          label: 'contém (lista)',          valor: 'um' },
  { op: 'contains_any',      label: 'contém algum de (lista)', valor: 'varios' },
  { op: 'in',                label: 'está entre',              valor: 'varios' },
  { op: 'text_contains_any', label: 'texto contém algum de',   valor: 'varios' },
  { op: 'filled',            label: 'está preenchido',         valor: 'nenhum' },
  { op: 'not_filled',        label: 'está vazio',              valor: 'nenhum' },
];
const OP_LABEL = Object.fromEntries(OPS.map(o => [o.op, o.label]));
const OP_VALOR = Object.fromEntries(OPS.map(o => [o.op, o.valor])); // 'um' | 'varios' | 'nenhum'
const MAX_COND = 6;

function esc(v) {
  return String(v == null ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// lista plana de campos (key, label, options) para dropdowns
function listarCampos(schema) {
  const out = [];
  for (const sec of (schema.secoes || []))
    for (const c of (sec.campos || []))
      if (c.key) out.push({ key: c.key, label: c.label || c.key, options: Array.isArray(c.options) ? c.options : [] });
  return out;
}
function acharCampo(schema, key) {
  for (const sec of (schema.secoes || []))
    for (const c of (sec.campos || []))
      if (c.key === key) return c;
  return null;
}
function acharSecao(schema, id) {
  return (schema.secoes || []).find(s => (s.id || s.titulo) === id) || null;
}
function secaoId(sec) { return sec.id || sec.titulo || ''; }
function secaoTitulo(sec) { return sec.titulo || sec.id || '(seção)'; }
function rotuloCampo(campos, key) {
  const f = campos.find(c => c.key === key);
  return f ? f.label : key;
}

// resolve um alvo "escopo:id" → { escopo, id, obj }
function resolverAlvo(schema, alvo) {
  const s = String(alvo || '');
  const i = s.indexOf(':');
  const escopo = i >= 0 ? s.slice(0, i) : 'campo';
  const id = i >= 0 ? s.slice(i + 1) : s;
  const obj = escopo === 'secao' ? acharSecao(schema, id) : acharCampo(schema, id);
  return { escopo, id, obj };
}

// ── Descrição legível ─────────────────────────────────────────────────────────
function valorTxt(v) {
  if (Array.isArray(v)) return v.map(x => `"${x}"`).join(', ');
  if (v == null || v === '') return '';
  return `"${v}"`;
}
function descreverCond(cond, campos) {
  if (!cond) return '<span class="mut">(sempre)</span>';
  const parte = c => { const t = descreverCond(c, campos); return (c && (c.all || c.any)) ? '(' + t + ')' : t; };
  if (cond.all) return cond.all.map(parte).join(' <b>E</b> ');
  if (cond.any) return cond.any.map(parte).join(' <b>OU</b> ');
  const lbl = esc(rotuloCampo(campos, cond.campo));
  const op  = esc(OP_LABEL[cond.op] || cond.op);
  const vt  = esc(valorTxt(cond.valor));
  return `${lbl} <i>${op}</i>${vt ? ' ' + vt : ''}`;
}
function descreverPreench(r, campos) {
  const alvo = esc(rotuloCampo(campos, r.campo));
  const val  = esc(valorTxt(r.valor));
  const modo = r.sobrescrever ? '<span class="tag ob">sobrescreve</span>' : '<span class="tag se">só se vazio</span>';
  return `Define <b>${alvo}</b> = ${val || '<span class="mut">(vazio)</span>'} ${modo}<br><span class="nota">quando ${descreverCond(r.quando, campos)}</span>`;
}
function ehFolha(c) { return !!(c && c.campo && !c.all && !c.any); }
function flatRepresentavel(cond) {
  if (!cond) return true;
  if (cond.all) return cond.all.every(ehFolha);
  if (cond.any) return cond.any.every(ehFolha);
  return !!cond.campo;
}
function extrairRegra(cond) {
  if (!cond) return { complexo: false, juncao: 'all', conds: [] };
  if (!flatRepresentavel(cond)) return { complexo: true, raw: cond, juncao: 'all', conds: [] };
  if (cond.all) return { complexo: false, juncao: 'all', conds: cond.all };
  if (cond.any) return { complexo: false, juncao: 'any', conds: cond.any };
  if (cond.campo) return { complexo: false, juncao: 'all', conds: [cond] };
  return { complexo: false, juncao: 'all', conds: [] };
}

// editor avançado (regra aninhada) — preserva a estrutura via JSON
function paginaEditorAvancado(schema, { alvo, tipo, raw, campos }) {
  return shell('Editar regra (avançada)', `
    <a class="voltar" href="/atb/admin/regras-form">← Regras</a>
    <h1>Regra avançada</h1>
    <p class="sub">Esta regra combina <b>E/OU em níveis</b> (condições aninhadas). O construtor visual não a representa sem perder a estrutura, então a edição aqui é pelo JSON. <b>Cancele para mantê-la intacta.</b></p>
    <div class="card"><div class="sec" style="margin-top:0">Condição atual</div><p>${descreverCond(raw, campos)}</p></div>
    <form method="post" action="/atb/admin/regras-form/salvar" class="card">
      <input type="hidden" name="alvo" value="${esc(alvo)}">
      <input type="hidden" name="tipo" value="${esc(tipo)}">
      <input type="hidden" name="modo" value="json">
      <label class="f">Estrutura (JSON) — edite com cuidado</label>
      <textarea name="cond_json" rows="16" style="width:100%;font:13px/1.5 ui-monospace,Menlo,monospace">${esc(JSON.stringify(raw, null, 2))}</textarea>
      <div style="margin-top:14px">
        <button class="btn pri" type="submit">Salvar (avançado)</button>
        <a class="btn" href="/atb/admin/regras-form">Cancelar</a>
      </div>
    </form>`);
}

const TIPOS = { cond: 'Visibilidade', requiredCond: 'Obrigatoriedade' };

function shell(titulo, body) {
  return `<!DOCTYPE html><html lang="pt-BR"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(titulo)}</title>
<style>
  :root{ --pri:#0c447c; --bg:#f4f6f9; --line:#e3e7ee; --mut:#5f6368; }
  *{box-sizing:border-box} body{margin:0;background:var(--bg);font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;color:#1f2733}
  .wrap{max-width:1000px;margin:0 auto;padding:24px 18px 70px}
  h1{font-size:22px;margin:0 0 2px} .sub{color:var(--mut);margin:0 0 18px;font-size:14px}
  a.voltar{color:var(--pri);text-decoration:none;font-size:14px}
  .card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:16px}
  .sec{font-weight:600;color:var(--pri);margin:6px 0 10px;font-size:14px}
  table{width:100%;border-collapse:collapse} td,th{border-top:1px solid var(--line);padding:9px 8px;vertical-align:top;text-align:left}
  th{border-top:0;color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
  .tag{display:inline-block;font-size:11px;padding:2px 8px;border-radius:8px;background:#eef2f8;color:var(--pri);font-weight:600;white-space:nowrap}
  .tag.ob{background:#fdeee6;color:#a85b1b} .tag.se{background:#e9f6ee;color:#1c7a43} .tag.sempre{background:#fbe9ee;color:#9c2447}
  .acoes{white-space:nowrap;width:1%} .mut{color:var(--mut)} .nota{color:var(--mut);font-size:12px}
  .btn{border:1px solid var(--line);background:#fff;border-radius:8px;padding:7px 12px;cursor:pointer;font-size:13px;color:#1f2733;text-decoration:none;display:inline-block}
  .btn.pri{background:var(--pri);color:#fff;border-color:var(--pri)}
  .btn.del{color:#b3261e;border-color:#f0c9c5}
  .btn.sm{padding:5px 9px;font-size:12px;margin-left:4px}
  label.f{display:block;margin:10px 0 4px;font-size:13px;color:var(--mut)}
  select,input{font:14px inherit;padding:7px 8px;border:1px solid var(--line);border-radius:8px;background:#fff}
  select{min-width:150px}
  .row{display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap}
  .row .campo{min-width:230px} .row .op{min-width:180px} .row .val{min-width:200px;flex:1}
  .inl{display:inline}
</style></head><body><div class="wrap">${body}</div></body></html>`;
}

function paginaLista(schema) {
  const campos = listarCampos(schema);
  const linhas = [];
  const linhaRegra = (alvoVal, alvoLabel, tipoTag, tagCls, descHtml, podeExcluir) => `
    <tr>
      <td>${alvoLabel}</td>
      <td><span class="tag ${tagCls}">${tipoTag}</span></td>
      <td>${descHtml}</td>
      <td class="acoes">
        <a class="btn sm" href="/atb/admin/regras-form/editar?alvo=${encodeURIComponent(alvoVal.alvo)}&tipo=${alvoVal.tipo}">Editar</a>
        ${podeExcluir ? `<form class="inl" method="post" action="/atb/admin/regras-form/excluir" onsubmit="return confirm('Remover esta regra?')">
          <input type="hidden" name="alvo" value="${esc(alvoVal.alvo)}"><input type="hidden" name="tipo" value="${alvoVal.tipo}">
          <button class="btn sm del" type="submit">Excluir</button></form>` : ''}
      </td>`;

  for (const sec of (schema.secoes || [])) {
    const sid = secaoId(sec);
    // visibilidade da SEÇÃO
    if (sec.cond) {
      linhas.push('<tr>' + linhaRegra(
        { alvo: 'secao:' + sid, tipo: 'cond' },
        `<strong>Seção: ${esc(secaoTitulo(sec))}</strong>`,
        'Visibilidade (seção)', 'se', descreverCond(sec.cond, campos), true) + '</tr>');
    }
    for (const c of (sec.campos || [])) {
      if (!c.key) continue;
      const alvoLabel = `<strong>${esc(c.label || c.key)}</strong><br><span class="nota">${esc(c.key)} · seção: ${esc(secaoTitulo(sec))}</span>`;
      if (c.cond) linhas.push('<tr>' + linhaRegra({ alvo: 'campo:' + c.key, tipo: 'cond' }, alvoLabel, 'Visibilidade', '', descreverCond(c.cond, campos), true) + '</tr>');
      if (c.requiredCond) linhas.push('<tr>' + linhaRegra({ alvo: 'campo:' + c.key, tipo: 'requiredCond' }, alvoLabel, 'Obrigatoriedade', 'ob', descreverCond(c.requiredCond, campos), true) + '</tr>');
      if (c.required === true) {
        const nota = c.minChars ? `mínimo de ${c.minChars} caracteres` : 'preenchimento exigido';
        linhas.push(`
          <tr>
            <td>${alvoLabel}</td>
            <td><span class="tag sempre">Sempre obrigatório</span></td>
            <td><span class="mut">${esc(nota)}${sec.cond ? ' — quando a seção está visível' : ''}</span></td>
            <td class="acoes">
              <form class="inl" method="post" action="/atb/admin/regras-form/required-off" onsubmit="return confirm('Tornar este campo OPCIONAL? Ele deixará de ser exigido.')">
                <input type="hidden" name="campo" value="${esc(c.key)}">
                <button class="btn sm del" type="submit">Tornar opcional</button>
              </form>
            </td>
          </tr>`);
      }
    }
  }

  const preench = Array.isArray(schema.preenchimentos) ? schema.preenchimentos : [];
  const linhasP = preench.map((r, i) => `
    <tr>
      <td>${descreverPreench(r, campos)}</td>
      <td class="acoes">
        <a class="btn sm" href="/atb/admin/regras-form/preench?idx=${i}">Editar</a>
        <form class="inl" method="post" action="/atb/admin/regras-form/preench/excluir" onsubmit="return confirm('Remover este preenchimento?')">
          <input type="hidden" name="idx" value="${i}">
          <button class="btn sm del" type="submit">Excluir</button></form>
      </td></tr>`).join('');

  return shell('Regras condicionais', `
    <a class="voltar" href="/scih">← Portal SCIH</a>
    <h1>Regras condicionais do formulário</h1>
    <p class="sub">Visibilidade de seções e campos, obrigatoriedade condicional e campos sempre obrigatórios. Tudo vale na hora no formulário e também é checado no servidor ao salvar a ficha.</p>
    <div class="card"><a class="btn pri" href="/atb/admin/regras-form/editar">+ Nova regra</a></div>
    <div class="card">
      <table>
        <thead><tr><th>Alvo</th><th>Tipo</th><th>Condição</th><th></th></tr></thead>
        <tbody>${linhas.join('') || '<tr><td colspan="4" class="nota">Nenhuma regra definida.</td></tr>'}</tbody>
      </table>
    </div>
    <div class="card">
      <div class="sec">Preenchimento condicional</div>
      <p class="nota">Deriva ou sobrescreve o valor de um campo quando as condições valerem (ex.: marcar "Profilaxia cirúrgica").</p>
      <a class="btn pri" href="/atb/admin/regras-form/preench">+ Novo preenchimento</a>
      <table style="margin-top:12px">
        <thead><tr><th>Regra</th><th></th></tr></thead>
        <tbody>${linhasP || '<tr><td colspan="2" class="nota">Nenhum preenchimento definido.</td></tr>'}</tbody>
      </table>
    </div>`);
}

function paginaEditor(schema, { alvo, escopo, tipo, juncao, conds, complexo, raw }) {
  const campos = listarCampos(schema);
  if (complexo) return paginaEditorAvancado(schema, { alvo, tipo, raw, campos });
  const optsAlvo = [
    `<optgroup label="Seções (visibilidade)">` +
      (schema.secoes || []).map(s => { const v = 'secao:' + secaoId(s); return `<option value="${esc(v)}" ${v === alvo ? 'selected' : ''}>Seção: ${esc(secaoTitulo(s))}</option>`; }).join('') +
    `</optgroup>`,
    `<optgroup label="Campos">` +
      campos.map(c => { const v = 'campo:' + c.key; return `<option value="${esc(v)}" ${v === alvo ? 'selected' : ''}>${esc(c.label)} (${esc(c.key)})</option>`; }).join('') +
    `</optgroup>`,
  ].join('');
  const optsTipo = Object.entries(TIPOS).map(([k, v]) => `<option value="${k}" ${k === tipo ? 'selected' : ''}>${v}</option>`).join('');
  const optsJuncao = [['all', 'TODAS as condições (E)'], ['any', 'QUALQUER condição (OU)']].map(([k, v]) => `<option value="${k}" ${k === juncao ? 'selected' : ''}>${v}</option>`).join('');

  const rows = [];
  for (let i = 0; i < MAX_COND; i++) {
    const cur = conds[i] || {};
    const v = Array.isArray(cur.valor) ? cur.valor.join(', ') : (cur.valor == null ? '' : cur.valor);
    const opSel = OPS.map(o => `<option value="${o.op}" ${o.op === cur.op ? 'selected' : ''}>${esc(o.label)}</option>`).join('');
    const campoSel = ['<option value="">— campo —</option>']
      .concat(campos.map(c => `<option value="${esc(c.key)}" ${c.key === cur.campo ? 'selected' : ''}>${esc(c.label)}</option>`)).join('');
    rows.push(`
      <div class="row" data-row="${i}">
        <select class="campo" name="campo_${i}" onchange="syncVal(${i})">${campoSel}</select>
        <select class="op" name="op_${i}" onchange="syncVal(${i})">${opSel}</select>
        <input class="val" name="val_${i}" value="${esc(v)}" list="dl_${i}" placeholder="valor (vários: separe por vírgula)">
        <datalist id="dl_${i}"></datalist>
      </div>`);
  }
  const CAMPOS_JSON = JSON.stringify(campos.reduce((m, c) => (m[c.key] = c.options, m), {}));
  const OPVALOR_JSON = JSON.stringify(OP_VALOR);

  return shell('Editar regra', `
    <a class="voltar" href="/atb/admin/regras-form">← Regras</a>
    <h1>${alvo ? 'Editar regra' : 'Nova regra'}</h1>
    <p class="sub">Para uma <b>seção</b>, defina quando ela aparece (a obrigatoriedade dos campos dela depende disso). Para um <b>campo</b>, defina visibilidade ou obrigatoriedade condicional. Campos "sempre obrigatórios" são geridos na lista.</p>
    <form method="post" action="/atb/admin/regras-form/salvar" class="card">
      <input type="hidden" name="modo" value="builder">
      <div class="row">
        <div><label class="f">Alvo</label><select name="alvo" id="alvo" class="campo" onchange="syncTipo()">${optsAlvo}</select></div>
        <div><label class="f">Tipo de regra</label><select name="tipo" id="tipo">${optsTipo}</select></div>
        <div><label class="f">Satisfazer</label><select name="juncao">${optsJuncao}</select></div>
      </div>
      <div class="sec" style="margin-top:14px">Condições</div>
      <p class="nota">Linhas em branco são ignoradas. Para "preenchido"/"vazio", o valor é ignorado.</p>
      ${rows.join('')}
      <div style="margin-top:14px">
        <button class="btn pri" type="submit">Salvar regra</button>
        <a class="btn" href="/atb/admin/regras-form">Cancelar</a>
      </div>
    </form>
    <script>
      var CAMPOS = ${CAMPOS_JSON}, OPVALOR = ${OPVALOR_JSON};
      function syncVal(i){
        var row=document.querySelector('[data-row="'+i+'"]'); if(!row) return;
        var campo=row.querySelector('.campo').value, op=row.querySelector('.op').value;
        var val=row.querySelector('.val'), dl=document.getElementById('dl_'+i);
        var ops=CAMPOS[campo]||[];
        dl.innerHTML=ops.map(function(o){return '<option value="'+String(o).replace(/"/g,'&quot;')+'">';}).join('');
        var modo=OPVALOR[op]||'um';
        if(modo==='nenhum'){ val.value=''; val.disabled=true; val.placeholder='(sem valor)'; }
        else { val.disabled=false; val.placeholder=(modo==='varios')?'vários: separe por vírgula':'valor'; }
      }
      function syncTipo(){
        // seção só tem visibilidade
        var alvo=document.getElementById('alvo').value, tipo=document.getElementById('tipo');
        var ehSecao=alvo.indexOf('secao:')===0;
        tipo.value = ehSecao ? 'cond' : tipo.value;
        tipo.disabled = ehSecao;
      }
      for(var i=0;i<${MAX_COND};i++) syncVal(i);
      syncTipo();
    </script>`);
}

function montarCond(body) {
  const juncao = body.juncao === 'any' ? 'any' : 'all';
  const conds = [];
  for (let i = 0; i < MAX_COND; i++) {
    const campo = String(body['campo_' + i] || '').trim();
    const op = String(body['op_' + i] || '').trim();
    if (!campo || !op) continue;
    const modo = OP_VALOR[op] || 'um';
    const raw = String(body['val_' + i] || '').trim();
    const c = { campo, op };
    if (modo === 'varios') c.valor = raw.split(',').map(s => s.trim()).filter(Boolean);
    else if (modo === 'um') c.valor = raw;
    if (modo !== 'nenhum' && (c.valor === '' || (Array.isArray(c.valor) && c.valor.length === 0))) continue;
    conds.push(c);
  }
  if (conds.length === 0) return null;
  return { [juncao]: conds };
}

function paginaEditorPreench(schema, { idx, juncao, conds, complexo, raw, campo, valor, sobrescrever }) {
  const campos = listarCampos(schema);
  const novo = (idx == null || idx === '');
  const alvoSel = ['<option value="">— campo a preencher —</option>']
    .concat(campos.map(c => `<option value="${esc(c.key)}" ${c.key === campo ? 'selected' : ''}>${esc(c.label)} (${esc(c.key)})</option>`)).join('');
  const modoSel = [['', 'inserir — só se estiver vazio'], ['1', 'sobrescrever — força o valor']]
    .map(([k, v]) => `<option value="${k}" ${((sobrescrever ? '1' : '') === k) ? 'selected' : ''}>${v}</option>`).join('');
  const CAMPOS_JSON = JSON.stringify(campos.reduce((m, c) => (m[c.key] = c.options, m), {}));
  const OPVALOR_JSON = JSON.stringify(OP_VALOR);
  const cabAlvo = `
      <div class="row">
        <div><label class="f">Campo a preencher</label><select name="campo_alvo" id="campo_alvo" class="campo" onchange="syncAlvo()">${alvoSel}</select></div>
        <div><label class="f">Valor</label><input name="valor" id="valor_alvo" value="${esc(valor == null ? '' : valor)}" list="dl_alvo" placeholder="valor a inserir"><datalist id="dl_alvo"></datalist></div>
        <div><label class="f">Modo</label><select name="sobrescrever">${modoSel}</select></div>
      </div>`;
  const jsAlvo = `function syncAlvo(){var c=document.getElementById('campo_alvo').value,dl=document.getElementById('dl_alvo'),ops=(CAMPOS[c]||[]);dl.innerHTML=ops.map(function(o){return '<option value="'+String(o).replace(/"/g,'&quot;')+'">';}).join('');}`;

  if (complexo) {
    return shell('Editar preenchimento (avançado)', `
    <a class="voltar" href="/atb/admin/regras-form">← Regras</a>
    <h1>Editar preenchimento (condição avançada)</h1>
    <p class="sub">A condição "quando" é aninhada e é editada como JSON. Os demais campos seguem normais.</p>
    <form method="post" action="/atb/admin/regras-form/preench/salvar" class="card">
      <input type="hidden" name="idx" value="${novo ? '' : esc(idx)}">
      <input type="hidden" name="modo" value="json">
      ${cabAlvo}
      <label class="f">Condição "quando" (JSON)</label>
      <textarea name="quando_json" style="width:100%;min-height:170px;font-family:monospace;font-size:13px;border:1px solid var(--line);border-radius:8px;padding:10px">${esc(JSON.stringify(raw || {}, null, 2))}</textarea>
      <div style="margin-top:14px"><button class="btn pri" type="submit">Salvar preenchimento</button> <a class="btn" href="/atb/admin/regras-form">Cancelar</a></div>
    </form>
    <script>var CAMPOS=${CAMPOS_JSON};${jsAlvo}syncAlvo();</script>`);
  }

  const optsJuncao = [['all', 'TODAS as condições (E)'], ['any', 'QUALQUER condição (OU)']]
    .map(([k, v]) => `<option value="${k}" ${k === juncao ? 'selected' : ''}>${v}</option>`).join('');
  const rows = [];
  for (let i = 0; i < MAX_COND; i++) {
    const cur = conds[i] || {};
    const v = Array.isArray(cur.valor) ? cur.valor.join(', ') : (cur.valor == null ? '' : cur.valor);
    const opSel = OPS.map(o => `<option value="${o.op}" ${o.op === cur.op ? 'selected' : ''}>${esc(o.label)}</option>`).join('');
    const campoSel = ['<option value="">— campo —</option>']
      .concat(campos.map(c => `<option value="${esc(c.key)}" ${c.key === cur.campo ? 'selected' : ''}>${esc(c.label)}</option>`)).join('');
    rows.push(`
      <div class="row" data-row="${i}">
        <select class="campo" name="campo_${i}" onchange="syncVal(${i})">${campoSel}</select>
        <select class="op" name="op_${i}" onchange="syncVal(${i})">${opSel}</select>
        <input class="val" name="val_${i}" value="${esc(v)}" list="dl_${i}" placeholder="valor (vários: separe por vírgula)">
        <datalist id="dl_${i}"></datalist>
      </div>`);
  }
  return shell(novo ? 'Novo preenchimento' : 'Editar preenchimento', `
    <a class="voltar" href="/atb/admin/regras-form">← Regras</a>
    <h1>${novo ? 'Novo preenchimento condicional' : 'Editar preenchimento'}</h1>
    <p class="sub">Quando as condições valerem, o campo-alvo recebe o valor. "Sobrescrever" força; "inserir" preenche só se vazio. Vale no formulário e no servidor ao salvar a ficha.</p>
    <form method="post" action="/atb/admin/regras-form/preench/salvar" class="card">
      <input type="hidden" name="idx" value="${novo ? '' : esc(idx)}">
      <input type="hidden" name="modo" value="builder">
      ${cabAlvo}
      <div class="sec" style="margin-top:14px">Quando (condições)</div>
      <div class="row"><div><label class="f">Satisfazer</label><select name="juncao">${optsJuncao}</select></div></div>
      <p class="nota">Linhas em branco são ignoradas. Para "preenchido"/"vazio", o valor é ignorado.</p>
      ${rows.join('')}
      <div style="margin-top:14px">
        <button class="btn pri" type="submit">Salvar preenchimento</button>
        <a class="btn" href="/atb/admin/regras-form">Cancelar</a>
      </div>
    </form>
    <script>
      var CAMPOS=${CAMPOS_JSON}, OPVALOR=${OPVALOR_JSON};
      function syncVal(i){
        var row=document.querySelector('[data-row="'+i+'"]'); if(!row) return;
        var campo=row.querySelector('.campo').value, op=row.querySelector('.op').value;
        var val=row.querySelector('.val'), dl=document.getElementById('dl_'+i);
        var ops=CAMPOS[campo]||[];
        dl.innerHTML=ops.map(function(o){return '<option value="'+String(o).replace(/"/g,'&quot;')+'">';}).join('');
        var modo=OPVALOR[op]||'um';
        if(modo==='nenhum'){ val.value=''; val.disabled=true; val.placeholder='(sem valor)'; }
        else { val.disabled=false; val.placeholder=(modo==='varios')?'vários: separe por vírgula':'valor'; }
      }
      ${jsAlvo}
      for(var i=0;i<MAXC;i++) syncVal(i);
      syncAlvo();
    </script>`.replace(/MAXC/g, String(MAX_COND)));
}

// ════════════════════════════════════════════════════════════════════════════
//  Rotas
// ════════════════════════════════════════════════════════════════════════════
export function registerRegrasFormRoutes(app, pool, authRequired, inst = 'HUSF') {
  // Resolve a instituição POR REQUISIÇÃO: tenant-lock (req.atbTenant) > ?inst= > default.
  // Antes o 'inst' era fixo no closure (sempre HUSF), o que impedia editar a ficha do H2.
  // Em modo legado (sem tenant e sem ?inst) cai no default 'HUSF' — idêntico ao atual.
  const instReq = (req) =>
    req.atbTenant ||
    String((req.query && req.query.inst) || inst).replace(/[^A-Za-z0-9_]/g, '') ||
    inst;

  const soSuper = [authRequired, (req, res, next) => {
    if (req.user?.super_admin || req.cookies?.adm === '1') return next();
    res.status(403).send('Acesso restrito ao administrador.');
  }];

  app.get('/atb/admin/regras-form', soSuper, async (req, res) => {
    const inst = instReq(req);
    try { res.send(paginaLista(await getFormSchema(pool, inst))); }
    catch (e) { res.status(500).send('Erro: ' + esc(e.message)); }
  });

  app.get('/atb/admin/regras-form/editar', soSuper, async (req, res) => {
    const inst = instReq(req);
    try {
      const schema = await getFormSchema(pool, inst);
      const alvo = req.query.alvo ? String(req.query.alvo) : '';
      let tipo = req.query.tipo === 'requiredCond' ? 'requiredCond' : 'cond';
      let juncao = 'all', conds = [], escopo = 'campo', complexo = false, raw = null;
      if (alvo) {
        const r = resolverAlvo(schema, alvo);
        escopo = r.escopo;
        if (escopo === 'secao') tipo = 'cond';
        const ex = extrairRegra(r.obj ? r.obj[tipo] : null);
        juncao = ex.juncao; conds = ex.conds; complexo = !!ex.complexo; raw = ex.raw || null;
      }
      res.send(paginaEditor(schema, { alvo, escopo, tipo, juncao, conds, complexo, raw }));
    } catch (e) { res.status(500).send('Erro: ' + esc(e.message)); }
  });

  app.post('/atb/admin/regras-form/salvar', soSuper, async (req, res) => {
    const inst = instReq(req);
    try {
      const b = req.body || {};
      if (!b.alvo) return res.redirect('/atb/admin/regras-form');
      const schema = await getFormSchema(pool, inst);
      const r = resolverAlvo(schema, b.alvo);
      if (!r.obj) return res.status(400).send('Alvo não encontrado: ' + esc(b.alvo));
      let tipo = b.tipo === 'requiredCond' ? 'requiredCond' : 'cond';
      if (r.escopo === 'secao') tipo = 'cond'; // seção só tem visibilidade
      if (b.modo === 'json') {
        const txt = String(b.cond_json || '').trim();
        if (!txt) { delete r.obj[tipo]; }
        else {
          let parsed;
          try { parsed = JSON.parse(txt); }
          catch (e2) { return res.status(400).send('JSON inválido: ' + esc(e2.message) + ' — <a href="javascript:history.back()">voltar</a>'); }
          if (parsed && typeof parsed === 'object') r.obj[tipo] = parsed; else delete r.obj[tipo];
        }
      } else {
        const cond = montarCond(b);
        if (cond) r.obj[tipo] = cond; else delete r.obj[tipo];
      }
      await saveFormSchema(pool, inst, schema, req.user?.id || null);
      res.redirect('/atb/admin/regras-form');
    } catch (e) { res.status(500).send('Erro ao salvar: ' + esc(e.message)); }
  });

  app.post('/atb/admin/regras-form/excluir', soSuper, async (req, res) => {
    const inst = instReq(req);
    try {
      const b = req.body || {};
      const schema = await getFormSchema(pool, inst);
      const r = resolverAlvo(schema, b.alvo);
      let tipo = b.tipo === 'requiredCond' ? 'requiredCond' : 'cond';
      if (r.escopo === 'secao') tipo = 'cond';
      if (r.obj) { delete r.obj[tipo]; await saveFormSchema(pool, inst, schema, req.user?.id || null); }
      res.redirect('/atb/admin/regras-form');
    } catch (e) { res.status(500).send('Erro ao excluir: ' + esc(e.message)); }
  });

  // torna um campo "sempre obrigatório" opcional (remove required:true)
  app.post('/atb/admin/regras-form/required-off', soSuper, async (req, res) => {
    const inst = instReq(req);
    try {
      const key = String((req.body || {}).campo || '').trim();
      const schema = await getFormSchema(pool, inst);
      const f = acharCampo(schema, key);
      if (f && f.required === true) { delete f.required; await saveFormSchema(pool, inst, schema, req.user?.id || null); }
      res.redirect('/atb/admin/regras-form');
    } catch (e) { res.status(500).send('Erro: ' + esc(e.message)); }
  });

  // ── Preenchimento condicional ──────────────────────────────────────────────
  app.get('/atb/admin/regras-form/preench', soSuper, async (req, res) => {
    const inst = instReq(req);
    try {
      const schema = await getFormSchema(pool, inst);
      const lista = Array.isArray(schema.preenchimentos) ? schema.preenchimentos : [];
      const idxRaw = req.query.idx;
      const idx = (idxRaw != null && idxRaw !== '') ? parseInt(idxRaw, 10) : null;
      let juncao = 'all', conds = [], complexo = false, raw = null, campo = '', valor = '', sobrescrever = false;
      if (idx != null && lista[idx]) {
        const r = lista[idx];
        const ex = extrairRegra(r.quando);
        juncao = ex.juncao; conds = ex.conds; complexo = !!ex.complexo; raw = ex.raw || null;
        campo = r.campo || ''; valor = r.valor == null ? '' : r.valor; sobrescrever = !!r.sobrescrever;
      }
      res.send(paginaEditorPreench(schema, { idx, juncao, conds, complexo, raw, campo, valor, sobrescrever }));
    } catch (e) { res.status(500).send('Erro: ' + esc(e.message)); }
  });

  app.post('/atb/admin/regras-form/preench/salvar', soSuper, async (req, res) => {
    const inst = instReq(req);
    try {
      const b = req.body || {};
      const campo = String(b.campo_alvo || '').trim();
      if (!campo) return res.redirect('/atb/admin/regras-form');
      const schema = await getFormSchema(pool, inst);
      if (!Array.isArray(schema.preenchimentos)) schema.preenchimentos = [];
      let quando = null;
      if (b.modo === 'json') {
        const txt = String(b.quando_json || '').trim();
        if (txt) { try { quando = JSON.parse(txt); } catch (e2) { return res.status(400).send('JSON inválido: ' + esc(e2.message) + ' — <a href="javascript:history.back()">voltar</a>'); } }
      } else {
        quando = montarCond(b);
      }
      const regra = { quando: quando || null, campo, valor: String(b.valor == null ? '' : b.valor) };
      if (b.sobrescrever === '1') regra.sobrescrever = true;
      const idxRaw = b.idx;
      if (idxRaw != null && idxRaw !== '' && schema.preenchimentos[parseInt(idxRaw, 10)]) {
        schema.preenchimentos[parseInt(idxRaw, 10)] = regra;
      } else {
        schema.preenchimentos.push(regra);
      }
      await saveFormSchema(pool, inst, schema, req.user?.id || null);
      res.redirect('/atb/admin/regras-form');
    } catch (e) { res.status(500).send('Erro ao salvar: ' + esc(e.message)); }
  });

  app.post('/atb/admin/regras-form/preench/excluir', soSuper, async (req, res) => {
    const inst = instReq(req);
    try {
      const i = parseInt(String((req.body || {}).idx || ''), 10);
      const schema = await getFormSchema(pool, inst);
      if (Array.isArray(schema.preenchimentos) && schema.preenchimentos[i]) {
        schema.preenchimentos.splice(i, 1);
        await saveFormSchema(pool, inst, schema, req.user?.id || null);
      }
      res.redirect('/atb/admin/regras-form');
    } catch (e) { res.status(500).send('Erro ao excluir: ' + esc(e.message)); }
  });
}
