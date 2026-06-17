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
    case 'contains_any': return Array.isArray(v) && Array.isArray(cond.valor) &&
                                cond.valor.some(x => v.indexOf(x) !== -1);
    case 'text_contains_any': return _textContainsAny(v, cond.valor);
    default: return true;
  }
}

// ── Validador genérico de obrigatórios (backstop server-side) ────────────────
// Espelha o que o engine do cliente já exige: campo VISÍVEL e (required ||
// requiredCond satisfeito) precisa estar preenchido (e respeitar minChars).
export function validarObrigatoriosServidor(schema, dados) {
  const faltas = [];
  if (!schema || !Array.isArray(schema.secoes)) return faltas;
  for (const sec of schema.secoes) {
    if (sec.cond && !avaliaCondServer(sec.cond, dados)) continue;
    for (const c of (sec.campos || [])) {
      if (!c.key) continue;
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
  { op: 'eq',               label: 'é igual a',            valor: 'um' },
  { op: 'neq',              label: 'é diferente de',       valor: 'um' },
  { op: 'contains',         label: 'contém (lista)',       valor: 'um' },
  { op: 'contains_any',     label: 'contém algum de (lista)', valor: 'varios' },
  { op: 'in',               label: 'está entre',           valor: 'varios' },
  { op: 'text_contains_any',label: 'texto contém algum de',valor: 'varios' },
  { op: 'filled',           label: 'está preenchido',      valor: 'nenhum' },
  { op: 'not_filled',       label: 'está vazio',           valor: 'nenhum' },
];
const OP_LABEL = Object.fromEntries(OPS.map(o => [o.op, o.label]));
const OP_VALOR = Object.fromEntries(OPS.map(o => [o.op, o.valor])); // 'um' | 'varios' | 'nenhum'
const MAX_COND = 6;

function esc(v) {
  return String(v == null ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// lista plana de campos do schema (key, label, options)
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
function rotuloCampo(campos, key) {
  const f = campos.find(c => c.key === key);
  return f ? f.label : key;
}

// ── Descrição legível de uma cond ────────────────────────────────────────────
function valorTxt(v) {
  if (Array.isArray(v)) return v.map(x => `"${x}"`).join(', ');
  if (v == null || v === '') return '';
  return `"${v}"`;
}
function descreverCond(cond, campos) {
  if (!cond) return '<span class="mut">(sempre)</span>';
  if (cond.all) return cond.all.map(c => descreverCond(c, campos)).join(' <b>E</b> ');
  if (cond.any) return cond.any.map(c => descreverCond(c, campos)).join(' <b>OU</b> ');
  const lbl = esc(rotuloCampo(campos, cond.campo));
  const op  = esc(OP_LABEL[cond.op] || cond.op);
  const vt  = esc(valorTxt(cond.valor));
  return `${lbl} <i>${op}</i>${vt ? ' ' + vt : ''}`;
}

// extrai as condições-folha de uma cond (assume um nível de all/any) p/ prefill
function extrairRegra(cond) {
  if (!cond) return { juncao: "all", conds: [] };
  if (cond.all) return { juncao: 'all', conds: cond.all.filter(c => c.campo) };
  if (cond.any) return { juncao: 'any', conds: cond.any.filter(c => c.campo) };
  if (cond.campo) return { juncao: 'all', conds: [cond] };
  return { juncao: 'all', conds: [] };
}

const TIPOS = { cond: 'Visibilidade', requiredCond: 'Obrigatoriedade' };

// ════════════════════════════════════════════════════════════════════════════
//  Páginas
// ════════════════════════════════════════════════════════════════════════════
function shell(titulo, body) {
  return `<!DOCTYPE html><html lang="pt-BR"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(titulo)}</title>
<style>
  :root{ --pri:#0c447c; --bg:#f4f6f9; --line:#e3e7ee; --mut:#5f6368; }
  *{box-sizing:border-box} body{margin:0;background:var(--bg);font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;color:#1f2733}
  .wrap{max-width:980px;margin:0 auto;padding:24px 18px 70px}
  h1{font-size:22px;margin:0 0 2px} .sub{color:var(--mut);margin:0 0 18px;font-size:14px}
  a.voltar{color:var(--pri);text-decoration:none;font-size:14px}
  .card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:16px}
  .sec{font-weight:600;color:var(--pri);margin:6px 0 10px;font-size:14px}
  table{width:100%;border-collapse:collapse} td,th{border-top:1px solid var(--line);padding:9px 8px;vertical-align:top;text-align:left}
  th{border-top:0;color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
  .tag{display:inline-block;font-size:11px;padding:2px 8px;border-radius:8px;background:#eef2f8;color:var(--pri);font-weight:600}
  .tag.ob{background:#fdeee6;color:#a85b1b}
  .acoes{white-space:nowrap;width:1%}
  .btn{border:1px solid var(--line);background:#fff;border-radius:8px;padding:7px 12px;cursor:pointer;font-size:13px;color:#1f2733;text-decoration:none;display:inline-block}
  .btn.pri{background:var(--pri);color:#fff;border-color:var(--pri)}
  .btn.del{color:#b3261e;border-color:#f0c9c5}
  .btn.sm{padding:5px 9px;font-size:12px;margin-left:4px}
  label.f{display:block;margin:10px 0 4px;font-size:13px;color:var(--mut)}
  select,input{font:14px inherit;padding:7px 8px;border:1px solid var(--line);border-radius:8px;background:#fff}
  select{min-width:150px}
  .row{display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap}
  .row .campo{min-width:230px} .row .op{min-width:180px} .row .val{min-width:200px;flex:1}
  .inl{display:inline} .nota{color:var(--mut);font-size:12px}
</style></head><body><div class="wrap">${body}</div></body></html>`;
}

function paginaLista(schema) {
  const campos = listarCampos(schema);
  const linhas = [];
  for (const sec of (schema.secoes || [])) {
    for (const c of (sec.campos || [])) {
      if (!c.key) continue;
      const add = (tipo, cond) => linhas.push(`
        <tr>
          <td><strong>${esc(c.label || c.key)}</strong><br><span class="nota">${esc(c.key)}</span></td>
          <td><span class="tag ${tipo === 'requiredCond' ? 'ob' : ''}">${TIPOS[tipo]}</span></td>
          <td>${descreverCond(cond, campos)}</td>
          <td class="acoes">
            <a class="btn sm" href="/atb/admin/regras-form/editar?campo=${encodeURIComponent(c.key)}&tipo=${tipo}">Editar</a>
            <form class="inl" method="post" action="/atb/admin/regras-form/excluir" onsubmit="return confirm('Remover esta regra?')">
              <input type="hidden" name="campo" value="${esc(c.key)}"><input type="hidden" name="tipo" value="${tipo}">
              <button class="btn sm del" type="submit">Excluir</button>
            </form>
          </td>
        </tr>`);
      if (c.cond) add('cond', c.cond);
      if (c.requiredCond) add('requiredCond', c.requiredCond);
    }
  }
  return shell('Regras condicionais', `
    <a class="voltar" href="/scih">← Portal SCIH</a>
    <h1>Regras condicionais do formulário</h1>
    <p class="sub">Visibilidade (quando um campo aparece) e obrigatoriedade (quando um campo é exigido). As regras valem na hora no formulário; a checagem também roda no servidor ao salvar a ficha.</p>
    <div class="card">
      <a class="btn pri" href="/atb/admin/regras-form/editar">+ Nova regra</a>
    </div>
    <div class="card">
      <table>
        <thead><tr><th>Campo</th><th>Tipo</th><th>Condição</th><th></th></tr></thead>
        <tbody>${linhas.join('') || '<tr><td colspan="4" class="nota">Nenhuma regra condicional definida.</td></tr>'}</tbody>
      </table>
    </div>`);
}

function paginaEditor(schema, { campoAlvo, tipo, juncao, conds }) {
  const campos = listarCampos(schema);
  const optsCampoAlvo = campos.map(c =>
    `<option value="${esc(c.key)}" ${c.key === campoAlvo ? 'selected' : ''}>${esc(c.label)} (${esc(c.key)})</option>`).join('');
  const optsTipo = Object.entries(TIPOS).map(([k, v]) =>
    `<option value="${k}" ${k === tipo ? 'selected' : ''}>${v}</option>`).join('');
  const optsJuncao = [['all', 'TODAS as condições (E)'], ['any', 'QUALQUER condição (OU)']].map(([k, v]) =>
    `<option value="${k}" ${k === juncao ? 'selected' : ''}>${v}</option>`).join('');
  const optsOp = OPS.map(o => `<option value="${o.op}">${esc(o.label)}</option>`).join('');

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
    <h1>${campoAlvo ? 'Editar regra' : 'Nova regra'}</h1>
    <p class="sub">Defina quando o campo-alvo deve <b>aparecer</b> (visibilidade) ou ser <b>exigido</b> (obrigatoriedade), com base no valor de outros campos.</p>
    <form method="post" action="/atb/admin/regras-form/salvar" class="card">
      <div class="row">
        <div><label class="f">Campo-alvo</label><select name="campo" class="campo">${optsCampoAlvo}</select></div>
        <div><label class="f">Tipo de regra</label><select name="tipo">${optsTipo}</select></div>
        <div><label class="f">Satisfazer</label><select name="juncao">${optsJuncao}</select></div>
      </div>
      <div class="sec" style="margin-top:14px">Condições</div>
      <p class="nota">Deixe linhas em branco para ignorá-las. Para "preenchido"/"vazio", o valor é ignorado.</p>
      ${rows.join('')}
      <div style="margin-top:14px">
        <button class="btn pri" type="submit">Salvar regra</button>
        <a class="btn" href="/atb/admin/regras-form">Cancelar</a>
      </div>
    </form>
    <script>
      var CAMPOS = ${CAMPOS_JSON}, OPVALOR = ${OPVALOR_JSON};
      function syncVal(i){
        var row = document.querySelector('[data-row="'+i+'"]'); if(!row) return;
        var campo = row.querySelector('.campo').value;
        var op = row.querySelector('.op').value;
        var val = row.querySelector('.val');
        var dl = document.getElementById('dl_'+i);
        // opções do campo escolhido viram sugestões
        var ops = CAMPOS[campo] || [];
        dl.innerHTML = ops.map(function(o){ return '<option value="'+String(o).replace(/"/g,'&quot;')+'">'; }).join('');
        // operadores sem valor desabilitam o input
        var modo = OPVALOR[op] || 'um';
        if(modo === 'nenhum'){ val.value=''; val.disabled=true; val.placeholder='(sem valor)'; }
        else { val.disabled=false; val.placeholder = (modo==='varios') ? 'vários: separe por vírgula' : 'valor'; }
      }
      for(var i=0;i<${MAX_COND};i++) syncVal(i);
    </script>`);
}

// constrói a cond a partir das linhas do formulário
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
    // 'nenhum' (filled/not_filled): sem valor
    if (modo !== 'nenhum' && (c.valor === '' || (Array.isArray(c.valor) && c.valor.length === 0))) continue; // valor exigido mas vazio → ignora linha
    conds.push(c);
  }
  if (conds.length === 0) return null;
  return { [juncao]: conds };
}

// ════════════════════════════════════════════════════════════════════════════
//  Rotas
// ════════════════════════════════════════════════════════════════════════════
export function registerRegrasFormRoutes(app, pool, authRequired, inst = 'HUSF') {
  const soSuper = [authRequired, (req, res, next) => {
    if (req.user?.super_admin || req.cookies?.adm === '1') return next();
    res.status(403).send('Acesso restrito ao administrador.');
  }];

  app.get('/atb/admin/regras-form', soSuper, async (req, res) => {
    try {
      const schema = await getFormSchema(pool, inst);
      res.send(paginaLista(schema));
    } catch (e) { res.status(500).send('Erro: ' + esc(e.message)); }
  });

  app.get('/atb/admin/regras-form/editar', soSuper, async (req, res) => {
    try {
      const schema = await getFormSchema(pool, inst);
      const campoAlvo = req.query.campo ? String(req.query.campo) : '';
      const tipo = req.query.tipo === 'requiredCond' ? 'requiredCond' : 'cond';
      let juncao = 'all', conds = [];
      if (campoAlvo) {
        const f = acharCampo(schema, campoAlvo);
        const r = extrairRegra(f ? f[tipo] : null);
        juncao = r.juncao; conds = r.conds;
      }
      res.send(paginaEditor(schema, { campoAlvo, tipo, juncao, conds }));
    } catch (e) { res.status(500).send('Erro: ' + esc(e.message)); }
  });

  app.post('/atb/admin/regras-form/salvar', soSuper, async (req, res) => {
    try {
      const b = req.body || {};
      const campoAlvo = String(b.campo || '').trim();
      const tipo = b.tipo === 'requiredCond' ? 'requiredCond' : 'cond';
      if (!campoAlvo) return res.redirect('/atb/admin/regras-form');
      const schema = await getFormSchema(pool, inst);
      const f = acharCampo(schema, campoAlvo);
      if (!f) return res.status(400).send('Campo-alvo não encontrado: ' + esc(campoAlvo));
      const cond = montarCond(b);
      if (cond) f[tipo] = cond; else delete f[tipo];
      await saveFormSchema(pool, inst, schema, req.user?.id || null);
      res.redirect('/atb/admin/regras-form');
    } catch (e) { res.status(500).send('Erro ao salvar: ' + esc(e.message)); }
  });

  app.post('/atb/admin/regras-form/excluir', soSuper, async (req, res) => {
    try {
      const b = req.body || {};
      const campoAlvo = String(b.campo || '').trim();
      const tipo = b.tipo === 'requiredCond' ? 'requiredCond' : 'cond';
      const schema = await getFormSchema(pool, inst);
      const f = acharCampo(schema, campoAlvo);
      if (f) { delete f[tipo]; await saveFormSchema(pool, inst, schema, req.user?.id || null); }
      res.redirect('/atb/admin/regras-form');
    } catch (e) { res.status(500).send('Erro ao excluir: ' + esc(e.message)); }
  });
}
