// atb-form-editor-routes.js
// ════════════════════════════════════════════════════════════════════════════
// EDITOR ESTRUTURAL DO FORMULÁRIO — /atb/admin/form/estrutura
//
// Edita a ESTRUTURA do schema vivo (atb_form_schema): adicionar / editar /
// remover / reordenar campos e seções, tipo, rótulo, hint, obrigatório,
// opções e condicionais de exibição — gravando nova versão via saveFormSchema
// (o formulário passa a usar imediatamente, sem deploy).
//
// Integra com o Registro de Campos (atb-field-registry.js): cada campo mostra
// seu status de integração — Coluna (existe em atb_fichas), Grade (aparece em
// COLS de atb-grid-filters), Regras (schema ∩ colunas = catálogo automático).
// Campo novo nasce "Extras": renderiza e grava (via payload_raw) sem coluna;
// a promoção a coluna é uma fase à parte (botão futuro).
//
// Princípios de segurança:
//  • Estado do cliente = o PRÓPRIO JSON do schema; a UI muta só o que edita,
//    então propriedades que o editor não conhece (sincronizaCom, maxLinhas,
//    preenche, requiredCond, validate, minChars, colunas de matrix, …) são
//    preservadas por construção.
//  • Tipo TRAVADO para campos com coluna real (mudar o tipo quebraria a
//    serialização scalar↔jsonb) e para tipos não-criáveis (matrix, crm,
//    sofa, dose_vanco).
//  • pac_nome / prontuario / crm não podem ser removidos (o POST /fichas os
//    exige); chaves iniciadas em '_' (blocos de sistema) também não.
//  • Toda gravação passa por validarDefinicao() no servidor — a UI é só
//    conveniência, a validação é autoritativa aqui.
//
// Wire (em registerAtbRoutes, DEPOIS deste arquivo estar no main):
//   import { registerFormEditorRoutes } from './atb-form-editor-routes.js';
//   registerFormEditorRoutes(app, pool, adminRequired, renderShell);
// ════════════════════════════════════════════════════════════════════════════

import { getFormSchema, saveFormSchema } from './atb-form-schema.js';
import { camposDoSchema, colunasReaisFichas, COLUNA_DE, COLUNAS_SISTEMA } from './atb-field-registry.js';
import { COLS as GRID_COLS } from './atb-grid-filters.js';

// ── constantes de política ────────────────────────────────────────────────────
export const TIPOS_CRIAVEIS = ['text', 'textarea', 'number', 'date', 'select', 'radio', 'checkbox'];
const TIPOS_CONHECIDOS = new Set([...TIPOS_CRIAVEIS, 'matrix', 'crm', 'sofa', 'dose_vanco', 'check']);
const TIPOS_COM_OPCOES = new Set(['select', 'radio', 'checkbox']);
export const KEYS_INDELETAVEIS = new Set(['pac_nome', 'prontuario', 'crm']);
const OPS = new Set(['eq', 'neq', 'in', 'filled', 'not_filled', 'contains', 'not_contains', 'contains_any', 'not_contains_any', 'text_contains_any']);
const SLUG = /^[a-z][a-z0-9_]{1,40}$/;

// chaves que não podem ser usadas por campos novos (colisão com sistema/banco)
const KEYS_RESERVADAS = new Set([
  ...COLUNAS_SISTEMA.map(c => c.col),
  ...Object.values(COLUNA_DE), ...Object.keys(COLUNA_DE),
  'id', 'created_at', 'updated_at', 'data_referencia', 'recomendacao_scih',
  'desfecho', 'data_desfecho', 'instituicao',
]);

// ── validação de condicional (recursiva, espelha avaliaCond do engine) ────────
function validarCond(cond, keysValidas, caminho, erros) {
  if (cond == null) return;
  if (typeof cond !== 'object') { erros.push(`${caminho}: cond deve ser objeto`); return; }
  if (Array.isArray(cond.all) || Array.isArray(cond.any)) {
    const lista = cond.all || cond.any;
    if (!lista.length) erros.push(`${caminho}: all/any vazio`);
    lista.forEach((c, i) => validarCond(c, keysValidas, `${caminho}[${i}]`, erros));
    return;
  }
  if (!cond.campo) { erros.push(`${caminho}: cond sem "campo"`); return; }
  if (!keysValidas.has(cond.campo)) erros.push(`${caminho}: cond referencia campo inexistente "${cond.campo}"`);
  if (!OPS.has(cond.op)) erros.push(`${caminho}: op desconhecido "${cond.op}"`);
  if (['eq', 'neq', 'contains', 'not_contains'].includes(cond.op) && (cond.valor == null || cond.valor === ''))
    erros.push(`${caminho}: op "${cond.op}" exige valor`);
  if (['in', 'contains_any', 'not_contains_any', 'text_contains_any'].includes(cond.op) && !Array.isArray(cond.valor))
    erros.push(`${caminho}: op "${cond.op}" exige valor em lista`);
}

// ── validação da definição inteira ────────────────────────────────────────────
// ctx (opcional): { schemaAtual, colunasReais } habilita as regras de trava:
//   • key existente com coluna real → type não pode mudar
//   • tipos não-criáveis → type não pode mudar
//   • KEYS_INDELETAVEIS e '_'-prefixadas do schema atual não podem sumir
// Retorna { ok, erros: [string] }. Função PURA (não toca banco) — testável.
export function validarDefinicao(def, ctx = {}) {
  const erros = [];
  if (!def || typeof def !== 'object') return { ok: false, erros: ['definição ausente'] };
  if (!Array.isArray(def.secoes) || !def.secoes.length)
    return { ok: false, erros: ['schema precisa de ao menos uma seção'] };
  if (!def.titulo || !String(def.titulo).trim()) erros.push('título do formulário vazio');

  const keys = new Set(), secIds = new Set();
  for (const [si, sec] of def.secoes.entries()) {
    const sTag = `seção #${si + 1}`;
    if (!sec || typeof sec !== 'object') { erros.push(`${sTag}: inválida`); continue; }
    if (!sec.id || !SLUG.test(sec.id)) erros.push(`${sTag}: id inválido ("${sec.id || ''}")`);
    else if (secIds.has(sec.id)) erros.push(`${sTag}: id duplicado "${sec.id}"`);
    else secIds.add(sec.id);
    if (!sec.titulo || !String(sec.titulo).trim()) erros.push(`${sTag}: título vazio`);
    if (!Array.isArray(sec.campos)) { erros.push(`${sTag}: campos ausentes`); continue; }
    for (const [ci, c] of sec.campos.entries()) {
      const tag = `${sec.id || sTag} › campo #${ci + 1}`;
      if (!c || typeof c !== 'object') { erros.push(`${tag}: inválido`); continue; }
      if (!c.key || !SLUG.test(String(c.key).replace(/^_/, 'x'))) erros.push(`${tag}: key inválida ("${c.key || ''}")`);
      else if (keys.has(c.key)) erros.push(`${tag}: key duplicada "${c.key}"`);
      else keys.add(c.key);
      if (!TIPOS_CONHECIDOS.has(c.type)) erros.push(`${tag} (${c.key}): tipo desconhecido "${c.type}"`);
      if (!c.label || !String(c.label).trim()) {
        if (c.key !== '_sofa_bloco') erros.push(`${tag} (${c.key}): rótulo vazio`);
      }
      if (TIPOS_COM_OPCOES.has(c.type)) {
        const ops = (c.options || []).filter(o => o != null && String(o).trim() !== '');
        if (!ops.length) erros.push(`${tag} (${c.key}): tipo "${c.type}" exige ao menos uma opção`);
      }
      if (c.type === 'matrix' && !Array.isArray(c.colunas))
        erros.push(`${tag} (${c.key}): matrix sem colunas`);
    }
  }

  // conds só depois de conhecer todas as keys (podem referenciar campo de outra seção)
  for (const sec of def.secoes) {
    if (sec.cond) validarCond(sec.cond, keys, `seção ${sec.id}: cond`, erros);
    for (const c of (sec.campos || [])) {
      if (c.cond) validarCond(c.cond, keys, `${c.key}: cond`, erros);
      if (c.requiredCond) validarCond(c.requiredCond, keys, `${c.key}: requiredCond`, erros);
    }
  }

  // travas relativas ao schema atual
  const { schemaAtual, colunasReais } = ctx;
  if (schemaAtual) {
    const antigos = {};
    for (const sec of (schemaAtual.secoes || []))
      for (const c of (sec.campos || [])) if (c && c.key) antigos[c.key] = c;

    for (const key of Object.keys(antigos)) {
      const sumiu = !keys.has(key);
      if (sumiu && (KEYS_INDELETAVEIS.has(key) || key.startsWith('_')))
        erros.push(`campo obrigatório do sistema removido: "${key}"`);
    }
    for (const sec of def.secoes) {
      for (const c of (sec.campos || [])) {
        const antigo = antigos[c.key];
        if (!antigo) {
          // campo NOVO: só tipos criáveis, key não reservada
          if (!TIPOS_CRIAVEIS.includes(c.type))
            erros.push(`${c.key}: tipo "${c.type}" não pode ser criado pelo editor`);
          if (KEYS_RESERVADAS.has(c.key))
            erros.push(`${c.key}: key reservada pelo sistema`);
          continue;
        }
        if (antigo.type !== c.type) {
          const col = COLUNA_DE[c.key] || c.key;
          const temColuna = colunasReais ? colunasReais.has(col) : true; // sem info → conservador
          if (temColuna || !TIPOS_CRIAVEIS.includes(antigo.type))
            erros.push(`${c.key}: tipo travado ("${antigo.type}" → "${c.type}" não permitido; campo integrado ou tipo de sistema)`);
        }
      }
    }
  }

  return { ok: erros.length === 0, erros };
}

// ── status de integração por campo (pro badge da UI) ─────────────────────────
export function statusCampos(def, colunasReais) {
  const gridCols = new Set();
  for (const k of Object.keys(GRID_COLS || {})) {
    const m = String(GRID_COLS[k].expr || '').match(/\bf\.([a-z0-9_]+)/);
    if (m) gridCols.add(m[1]);
  }
  const st = {};
  for (const c of camposDoSchema(def)) {
    const temColuna = colunasReais.has(c.col);
    st[c.key] = {
      col: c.col,
      temColuna,
      naGrade: gridCols.has(c.col),
      nasRegras: temColuna,               // catálogo de regras = schema ∩ colunas reais
      origem: temColuna ? 'coluna' : 'extras',
    };
  }
  return st;
}

// ── rotas ─────────────────────────────────────────────────────────────────────
export function registerFormEditorRoutes(app, pool, adminRequired, renderShell) {
  const safe = s => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

  // página do editor
  app.get('/atb/admin/form/estrutura', adminRequired, async (req, res) => {
    const inst = (req.query.inst || 'HUSF').replace(/[^A-Za-z0-9_]/g, '');
    try {
      const def = await getFormSchema(pool, inst);
      if (!def) return res.send(renderShell('ATB · Editor estrutural',
        `<div class="card"><p>Schema não encontrado para ${safe(inst)}.</p></div>`));
      const colunasReais = await colunasReaisFichas(pool);
      const status = statusCampos(def, colunasReais);
      const boot = JSON.stringify({
        inst, def, status,
        tiposCriaveis: TIPOS_CRIAVEIS,
        indeletaveis: [...KEYS_INDELETAVEIS],
      }).replace(/</g, '\\u003c');
      res.send(renderShell('ATB · Editor estrutural', paginaEditor(inst, def, boot, safe)));
    } catch (e) {
      res.status(500).send(renderShell('Erro', `<div class="card"><p class="mut">${safe(e.message)}</p></div>`));
    }
  });

  // gravação (valida + nova versão)
  // Promove um campo "extra" (só payload_raw) a COLUNA REAL: ALTER TABLE + backfill
  // do payload_raw. Como INSERT/edição/grade/regras são derivados de (schema ∩
  // colunas reais), a promoção religa tudo automaticamente — sem wiring parcial.
  app.post('/atb/admin/form/promover-campo', adminRequired, async (req, res) => {
    const inst = (req.query.inst || req.body?.inst || 'HUSF').replace(/[^A-Za-z0-9_]/g, '');
    const key = String(req.body?.key || '').trim();
    try {
      if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key)) return res.status(400).json({ ok: false, error: 'chave inválida' });
      const schema = await getFormSchema(pool, inst);
      let campo = null;
      for (const sec of (schema?.secoes || [])) for (const c of (sec.campos || [])) if (c.key === key) campo = c;
      if (!campo) return res.status(404).json({ ok: false, error: 'campo não encontrado no schema' });
      if (!TIPOS_CRIAVEIS.includes(campo.type)) return res.status(400).json({ ok: false, error: `tipo "${campo.type}" não é promovível` });
      const col = COLUNA_DE[key] || key;
      if (!/^[a-z][a-z0-9_]{0,62}$/.test(col)) return res.status(400).json({ ok: false, error: `nome de coluna inválido: ${col}` });
      const cols = await colunasReaisFichas(pool);
      if (cols.has(col)) return res.json({ ok: true, col, tipo: '(já era coluna)', migrados: 0, jaExistia: true });

      const tipo = campo.type === 'date' ? 'DATE' : campo.type === 'number' ? 'NUMERIC' : campo.type === 'checkbox' ? 'JSONB' : 'TEXT';
      await pool.query(`ALTER TABLE atb_fichas ADD COLUMN IF NOT EXISTS ${col} ${tipo}`);

      let expr;
      if (tipo === 'DATE')        expr = `CASE WHEN payload_raw->>'${key}' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}' THEN (payload_raw->>'${key}')::date END`;
      else if (tipo === 'NUMERIC') expr = `CASE WHEN payload_raw->>'${key}' ~ '^-?[0-9]+([.][0-9]+)?$' THEN (payload_raw->>'${key}')::numeric END`;
      else if (tipo === 'JSONB')   expr = `payload_raw->'${key}'`;
      else                         expr = `NULLIF(payload_raw->>'${key}', '')`;
      const up = await pool.query(`UPDATE atb_fichas SET ${col} = ${expr} WHERE payload_raw ? '${key}' AND ${col} IS NULL`);

      console.log(`[atb] promover-campo: ${key} -> coluna ${col} ${tipo}, ${up.rowCount} fichas migradas (inst=${inst})`);
      res.json({ ok: true, col, tipo, migrados: up.rowCount });
    } catch (e) {
      console.error('[atb] promover-campo:', e.message);
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  app.post('/atb/admin/form/estrutura/salvar', adminRequired, async (req, res) => {
    const inst = (req.query.inst || req.body?.inst || 'HUSF').replace(/[^A-Za-z0-9_]/g, '');
    try {
      const definicao = req.body?.definicao;
      const schemaAtual = await getFormSchema(pool, inst);
      if (!schemaAtual) return res.status(400).json({ ok: false, erros: ['schema atual não encontrado'] });
      const colunasReais = await colunasReaisFichas(pool);
      const { versao, ...defLimpa } = definicao || {};   // versão é atribuída pelo save
      const v = validarDefinicao(defLimpa, { schemaAtual, colunasReais });
      if (!v.ok) return res.status(400).json({ ok: false, erros: v.erros });
      const versaoNova = await saveFormSchema(pool, inst, defLimpa, null);
      res.json({ ok: true, versao: versaoNova });
    } catch (e) {
      res.status(500).json({ ok: false, erros: [e.message] });
    }
  });
}

// ── página (HTML + CSS + JS vanilla; sem backticks no script do cliente) ─────
function paginaEditor(inst, def, boot, safe) {
  return `
  <style>
    .fe-top{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap}
    .fe-legenda{display:flex;gap:10px;align-items:center;font-size:11px;color:var(--mut);margin:12px 0 4px;flex-wrap:wrap}
    .fe-badge{font-size:11px;padding:2px 8px;border-radius:8px;display:inline-flex;gap:4px;white-space:nowrap;font-weight:600}
    .fe-ok{background:#e3f5ec;color:#0f7a4a}.fe-av{background:#fdf3e0;color:#9a6700}
    .fe-chip{font-size:11px;padding:2px 7px;border-radius:6px;border:1px solid var(--bd);background:#fff;color:var(--mut)}
    .fe-sec{margin-top:22px}
    .fe-sec-h{display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap}
    .fe-sec-h b{font-size:16px}
    .fe-row{display:flex;align-items:center;gap:9px;padding:9px 11px;border:1px solid var(--bd);border-radius:9px;background:#fff;margin-bottom:7px}
    .fe-row.av{border-color:#f1dcae;background:#fffdf8}
    .fe-key{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;color:var(--mut)}
    .fe-mini{background:#fff;color:var(--pri);border:1px solid var(--bd);border-radius:7px;padding:3px 8px;font-size:12px;font-weight:600;cursor:pointer}
    .fe-mini:hover{background:#f2f6fb}
    .fe-mini[disabled]{opacity:.35;cursor:default}
    .fe-mini.warn{color:#9a3a2d}
    .fe-exp{border:1.5px solid var(--pri);border-radius:9px;background:#fff;margin-bottom:7px;overflow:hidden}
    .fe-exp-h{display:flex;align-items:center;gap:9px;padding:9px 11px;background:#eaf1fb;border-bottom:1px solid #bcd4f2;cursor:pointer}
    .fe-exp-b{padding:13px;display:flex;flex-direction:column;gap:13px}
    .fe-grid2{display:grid;grid-template-columns:1fr 1fr;gap:11px}
    .fe-lbl{font-size:11.5px;color:var(--mut);margin:0 0 4px;display:block}
    .fe-exp-b input,.fe-exp-b select,.fe-exp-b textarea{padding:8px 10px;font-size:13.5px}
    .fe-condrow{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-bottom:6px}
    .fe-condrow select,.fe-condrow input{width:auto;min-width:120px;flex:1}
    .fe-note{font-size:12px;color:var(--mut);line-height:1.55}
    .fe-save{position:sticky;bottom:12px;margin-top:20px}
    .fe-save .card{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:14px 18px;flex-wrap:wrap}
    .fe-dirty{color:#9a6700;font-size:13px;font-weight:600;display:none}
    .fe-msg{font-size:13px}
    .fe-msg.err{color:#9a3a2d;white-space:pre-line}
    .fe-msg.ok{color:#0f7a4a;font-weight:600}
    .fe-tag{font-size:10px;border:1px solid var(--bd);border-radius:6px;padding:1px 6px;color:var(--mut)}
    /* preview ao vivo */
    #fe-pv{display:none;position:fixed;top:0;right:0;bottom:0;width:46vw;z-index:50;
      background:#fff;border-left:2px solid var(--pri);box-shadow:-4px 0 14px rgba(0,0,0,.08)}
    #fe-pv iframe{width:100%;height:100%;border:0}
    body.fe-pv-on #fe-pv{display:block}
    body.fe-pv-on .card, body.fe-pv-on #fe-app, body.fe-pv-on .fe-save{margin-right:47vw}
    @media (max-width: 900px){ body.fe-pv-on #fe-pv{width:100vw}
      body.fe-pv-on .card, body.fe-pv-on #fe-app, body.fe-pv-on .fe-save{margin-right:0} }
  </style>

  <div class="card">
    <div class="fe-top">
      <div>
        <h1 style="margin:0">Editor estrutural</h1>
        <p class="mut" style="margin:4px 0 0">${safe(def.titulo || '')} · <b style="color:var(--pri)">${safe(inst)}</b> · versão ${def.versao || 1}</p>
      </div>
      <div class="right">
        <a href="/atb/admin/form?inst=${encodeURIComponent(inst)}">Editor de opções</a>
        <a href="/atb/form?inst=${encodeURIComponent(inst)}" target="_blank">Abrir formulário ↗</a>
        <a href="/atb/admin">← Dashboard</a>
      </div>
    </div>
    <p class="fe-note" style="margin-top:10px">
      Estrutura do formulário: campos, seções, tipos, obrigatoriedade, opções e condicionais.
      Ao salvar, uma <b>nova versão</b> é criada e o formulário passa a usá-la imediatamente.
      Campo novo nasce como <span class="fe-badge fe-av">Extras</span> — funciona e grava (no payload),
      mas ainda sem coluna própria; a promoção a coluna vem numa fase seguinte.
    </p>
    <div class="fe-legenda">
      <span>Status:</span>
      <span class="fe-badge fe-ok">✓ Integrado</span>
      <span class="fe-badge fe-av">△ Extras</span>
      <span style="margin-left:auto;display:flex;gap:8px">
        <span class="fe-chip">🗄 Coluna</span><span class="fe-chip">▦ Grade</span><span class="fe-chip">⚙ Regras</span>
      </span>
    </div>
    <div style="margin-top:6px">
      <label class="mut" style="font-size:12px;display:inline">Instituição: </label>
      <a href="/atb/admin/form/estrutura?inst=HUSF" style="margin-right:10px;${inst === 'HUSF' ? 'font-weight:700' : ''}">HUSF</a>
      <a href="/atb/admin/form/estrutura?inst=SCMI" style="${inst === 'SCMI' ? 'font-weight:700' : ''}">SCMI</a>
    </div>
  </div>

  <div id="fe-app"></div>

  <div class="fe-save">
    <div class="card">
      <div>
        <span class="fe-dirty" id="fe-dirty">● alterações não salvas</span>
        <span class="fe-msg" id="fe-msg"></span>
      </div>
      <div style="display:flex;gap:10px;align-items:center">
        <button type="button" class="fe-mini" id="fe-pv-btn" onclick="fePreview()">👁 Preview ao vivo</button>
        <button type="button" class="fe-mini" onclick="feAddSecao()">+ Seção</button>
        <button type="button" id="fe-salvar" onclick="feSalvar()">Salvar nova versão</button>
      </div>
    </div>
  </div>

  <div id="fe-pv"></div>

  <script>window.__FE_BOOT = ${boot};</script>
  <script>${clienteJS()}</script>`;
}

// ── JS do cliente (string; sem backticks para não colidir com o template) ────
function clienteJS() {
  return String.raw`
(function(){
  var B = window.__FE_BOOT, DEF = B.def, ST = B.status || {};
  var EXP = null;            // key do campo expandido (um por vez)
  var SEC_EXP = null;        // id da seção com painel aberto
  var NOVOS = {};            // keys criadas nesta sessão (tipo editável)
  var DIRTY = false;

  var TIPO_LABEL = { text:'Texto curto', textarea:'Texto longo', number:'Número', date:'Data',
    select:'Seleção', radio:'Escolha única', checkbox:'Múltipla escolha',
    matrix:'Matriz', crm:'CRM', sofa:'Bloco SOFA', dose_vanco:'Widget vancomicina', check:'Check' };
  var OP_LABEL = { eq:'é igual a', neq:'é diferente de', contains:'contém', not_contains:'não contém',
    in:'é um de (lista)', contains_any:'contém algum de (lista)', not_contains_any:'não contém nenhum de (lista)',
    text_contains_any:'texto contém algum de (lista)',
    filled:'está preenchido', not_filled:'não está preenchido' };
  var OPS_VALOR_UNICO = ['eq','neq','contains','not_contains'];
  var OPS_LISTA = ['in','contains_any','not_contains_any','text_contains_any'];
  var OPS_SEM_VALOR = ['filled','not_filled'];

  function esc(s){ var d=document.createElement('div'); d.textContent = (s==null?'':String(s)); return d.innerHTML; }
  function marcaDirty(){ DIRTY = true; document.getElementById('fe-dirty').style.display='inline'; msg(''); pvSync(); }

  // ── preview ao vivo (iframe da ficha real em ?preview=1) ───────────────────
  var PV = { on:false, ready:false, timer:null };
  function pvFrame(){ var h=document.getElementById('fe-pv'); return h ? h.querySelector('iframe') : null; }
  function pvEnvia(){
    var f = pvFrame(); if (!f || !f.contentWindow) return;
    try { f.contentWindow.postMessage({ tipo:'atb-preview-schema', schema: DEF }, window.location.origin); } catch(e){}
  }
  function pvSync(){
    if (!PV.on || !PV.ready) return;
    clearTimeout(PV.timer); PV.timer = setTimeout(pvEnvia, 250);
  }
  window.addEventListener('message', function(ev){
    if (ev.origin !== window.location.origin) return;
    if (ev.data && ev.data.tipo === 'atb-preview-ready'){ PV.ready = true; pvEnvia(); }
  });
  window.fePreview = function(){
    PV.on = !PV.on;
    var host = document.getElementById('fe-pv'), btn = document.getElementById('fe-pv-btn');
    if (PV.on){
      document.body.classList.add('fe-pv-on');
      btn.textContent = '✕ Fechar preview';
      if (!pvFrame()){
        PV.ready = false;
        var f = document.createElement('iframe');
        f.src = '/atb/form?inst=' + encodeURIComponent(B.inst) + '&preview=1';
        host.appendChild(f);
      } else { pvEnvia(); }
    } else {
      document.body.classList.remove('fe-pv-on');
      btn.textContent = '👁 Preview ao vivo';
    }
  };
  function msg(t, cls){ var m=document.getElementById('fe-msg'); m.textContent=t||''; m.className='fe-msg '+(cls||''); }
  window.addEventListener('beforeunload', function(e){ if (DIRTY){ e.preventDefault(); e.returnValue=''; } });

  function todasKeys(){ var ks=[]; DEF.secoes.forEach(function(s){ (s.campos||[]).forEach(function(c){ if(c.key) ks.push(c.key); }); }); return ks; }
  function acharCampo(key){ for (var i=0;i<DEF.secoes.length;i++){ var cs=DEF.secoes[i].campos||[]; for (var j=0;j<cs.length;j++) if (cs[j].key===key) return {sec:DEF.secoes[i], si:i, campo:cs[j], ci:j}; } return null; }
  function slug(s){ s=(s||'').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-z0-9]+/g,'_').replace(/^_+|_+$/g,'').replace(/^[0-9]+/,''); if(!s) s='campo'; var base=s.slice(0,36), k=base, n=2, ks=todasKeys(); while(ks.indexOf(k)>=0){ k=base+'_'+n; n++; } return k; }

  function tipoTravado(c){ if (NOVOS[c.key]) return false; if (ST[c.key] && ST[c.key].temColuna) return true; if (B.tiposCriaveis.indexOf(c.type)<0) return true; return false; }
  function deletavel(c){ if (B.indeletaveis.indexOf(c.key)>=0) return false; if (c.key.charAt(0)==='_') return false; return true; }

  // ── condicional: modelo simples ↔ objeto cond ──────────────────────────────
  function condParaSimples(cond){
    if (!cond) return { juncao:'all', linhas:[] };
    var lista = null, juncao='all';
    if (Array.isArray(cond.all)) { lista=cond.all; juncao='all'; }
    else if (Array.isArray(cond.any)) { lista=cond.any; juncao='any'; }
    else if (cond.campo) { lista=[cond]; }
    else return null;
    var linhas=[];
    for (var i=0;i<lista.length;i++){ var c=lista[i];
      if (!c || !c.campo || Array.isArray(c.all) || Array.isArray(c.any)) return null; // aninhado → avançado
      var valor = c.valor;
      if (OPS_LISTA.indexOf(c.op)>=0){ if(!Array.isArray(valor)) return null; valor = valor.join(', '); }
      linhas.push({ campo:c.campo, op:c.op, valor:(valor==null?'':String(valor)) });
    }
    return { juncao:juncao, linhas:linhas };
  }
  function simplesParaCond(sim){
    var linhas = sim.linhas.filter(function(l){ return l.campo && l.op; });
    if (!linhas.length) return null;
    var conds = linhas.map(function(l){
      var c={ campo:l.campo, op:l.op };
      if (OPS_LISTA.indexOf(l.op)>=0) c.valor = (Array.isArray(l.valor) ? l.valor : String(l.valor||'').split(',')).map(function(x){return String(x).trim();}).filter(Boolean);
      else if (OPS_VALOR_UNICO.indexOf(l.op)>=0) c.valor = l.valor;
      return c;
    });
    if (conds.length===1) return conds[0];
    var o={}; o[sim.juncao]=conds; return o;
  }

  // ── render ─────────────────────────────────────────────────────────────────
  function render(){
    var app = document.getElementById('fe-app'); app.innerHTML='';
    DEF.secoes.forEach(function(sec, si){ app.appendChild(renderSecao(sec, si)); });
  }

  function renderSecao(sec, si){
    var wrap = document.createElement('div'); wrap.className='fe-sec';
    var h = document.createElement('div'); h.className='fe-sec-h';
    var condTag = sec.cond ? ' <span class="fe-tag">condicional</span>' : '';
    h.innerHTML = '<b>'+esc(sec.titulo||sec.id)+'</b>'+condTag+
      ' <span class="fe-key">'+esc(sec.id)+'</span>'+
      '<span style="margin-left:auto;display:flex;gap:6px">'+
      '<button type="button" class="fe-mini" data-a="sec-up" '+(si===0?'disabled':'')+'>↑</button>'+
      '<button type="button" class="fe-mini" data-a="sec-dn" '+(si===DEF.secoes.length-1?'disabled':'')+'>↓</button>'+
      '<button type="button" class="fe-mini" data-a="sec-cfg">⚙</button>'+
      '<button type="button" class="fe-mini" data-a="add-campo">+ Campo</button>'+
      '<button type="button" class="fe-mini warn" data-a="sec-del" '+((sec.campos||[]).length?'disabled title="só seção vazia"':'')+'>×</button>'+
      '</span>';
    h.querySelector('[data-a=sec-up]').onclick=function(){ moveSecao(si,-1); };
    h.querySelector('[data-a=sec-dn]').onclick=function(){ moveSecao(si, 1); };
    h.querySelector('[data-a=sec-cfg]').onclick=function(){ SEC_EXP = (SEC_EXP===sec.id?null:sec.id); render(); };
    h.querySelector('[data-a=add-campo]').onclick=function(){ addCampo(sec); };
    var del = h.querySelector('[data-a=sec-del]'); if (!del.disabled) del.onclick=function(){ if(confirm('Remover a seção "'+(sec.titulo||sec.id)+'"?')){ DEF.secoes.splice(si,1); marcaDirty(); render(); } };
    wrap.appendChild(h);
    if (SEC_EXP===sec.id) wrap.appendChild(painelSecao(sec));
    (sec.campos||[]).forEach(function(c, ci){ wrap.appendChild(EXP===c.key ? renderExpandido(sec,si,c,ci) : renderLinha(sec,si,c,ci)); });
    return wrap;
  }

  function painelSecao(sec){
    var p = document.createElement('div'); p.className='fe-exp'; p.style.marginBottom='10px';
    var b = document.createElement('div'); b.className='fe-exp-b';
    b.innerHTML = '<div><label class="fe-lbl">Título da seção</label><input type="text" data-f="titulo" value="'+esc(sec.titulo||'')+'"></div>'+
      '<div><label class="fe-lbl">Mostrar seção quando</label><div data-cond></div></div>';
    b.querySelector('[data-f=titulo]').oninput=function(){ sec.titulo=this.value; marcaDirty(); };
    montarCondBuilder(b.querySelector('[data-cond]'), sec, 'cond');
    p.appendChild(b); return p;
  }

  function badges(c){
    var s = ST[c.key];
    if (c.key.charAt(0)==='_' || (s===undefined && B.tiposCriaveis.indexOf(c.type)<0))
      return '<span class="fe-tag">widget</span>';
    if (s && s.temColuna){
      var chips = '🗄'+(s.naGrade?' ▦':'')+(s.nasRegras?' ⚙':'');
      return '<span class="fe-badge fe-ok">✓ Integrado</span> <span class="fe-key" title="Coluna'+(s.naGrade?' · Grade':'')+' · Regras">'+chips+'</span>';
    }
    return '<span class="fe-badge fe-av">△ Extras</span> '
      + '<button type="button" onclick="promoverCampo(\''+esc(c.key)+'\')" title="Cria coluna real em atb_fichas e migra os dados já salvos no payload. Habilita o campo em regras, grade e filtros." style="font-size:11px;padding:2px 8px;border-radius:8px;border:1px solid #cdd3db;background:#fff;color:#0c447c;cursor:pointer;font-weight:600">\u2191 Promover a coluna</button>';
  }

  window.promoverCampo = function(key){
    if(!confirm('Promover "'+key+'" a coluna real?\n\nCria a coluna em atb_fichas e migra os dados já preenchidos (do payload). É uma mudança de schema — deliberada e recomendada quando o campo será usado em regras/filtros.')) return;
    fetch('/atb/admin/form/promover-campo?inst='+encodeURIComponent(B.inst), {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:key})})
      .then(function(r){return r.json();}).then(function(j){
        if(j.ok){ alert(j.jaExistia ? ('Campo "'+key+'" já era coluna.') : ('Promovido: coluna '+j.col+' ('+j.tipo+'), '+j.migrados+' fichas migradas.')); location.reload(); }
        else { alert('Falha: '+(j.error||'?')); }
      }).catch(function(e){ alert('Erro: '+e); });
  };

  function renderLinha(sec, si, c, ci){
    var row = document.createElement('div'); row.className='fe-row'+((ST[c.key]&&!ST[c.key].temColuna)||NOVOS[c.key]?' av':'');
    var extras=[]; if (c.required) extras.push('obrigatório'); if (c.cond) extras.push('condicional'); if (c.requiredCond) extras.push('obrig. condicional');
    row.innerHTML =
      '<span style="display:flex;flex-direction:column;gap:2px">'+
        '<button type="button" class="fe-mini" data-a="up" '+(ci===0?'disabled':'')+' style="padding:1px 6px">↑</button>'+
        '<button type="button" class="fe-mini" data-a="dn" '+(ci===(sec.campos.length-1)?'disabled':'')+' style="padding:1px 6px">↓</button>'+
      '</span>'+
      '<div style="flex:1;min-width:0">'+
        '<div style="font-size:14px">'+esc(c.label||c.key)+(extras.length?' <span class="fe-tag">'+extras.join(' · ')+'</span>':'')+'</div>'+
        '<div class="fe-key">'+esc(c.key)+' · '+esc(TIPO_LABEL[c.type]||c.type)+'</div>'+
      '</div>'+
      badges(c)+
      '<button type="button" class="fe-mini" data-a="exp">editar</button>';
    row.querySelector('[data-a=up]').onclick=function(){ moveCampo(sec,ci,-1); };
    row.querySelector('[data-a=dn]').onclick=function(){ moveCampo(sec,ci, 1); };
    row.querySelector('[data-a=exp]').onclick=function(){ EXP=c.key; render(); };
    return row;
  }

  function renderExpandido(sec, si, c, ci){
    var box = document.createElement('div'); box.className='fe-exp';
    var h = document.createElement('div'); h.className='fe-exp-h';
    h.innerHTML = '<b style="font-size:14px">'+esc(c.label||c.key)+'</b> <span class="fe-key">'+esc(c.key)+'</span>'+
      '<span style="margin-left:auto">'+badges(c)+'</span><span>▲</span>';
    h.onclick=function(){ EXP=null; render(); };
    box.appendChild(h);

    var b = document.createElement('div'); b.className='fe-exp-b';
    var travado = tipoTravado(c);
    var tiposOpts = (travado ? [c.type] : B.tiposCriaveis).map(function(t){
      return '<option value="'+t+'"'+(t===c.type?' selected':'')+'>'+esc(TIPO_LABEL[t]||t)+'</option>';
    }).join('');
    b.innerHTML =
      '<div class="fe-grid2">'+
        '<div><label class="fe-lbl">Rótulo</label><input type="text" data-f="label" value="'+esc(c.label||'')+'"></div>'+
        '<div><label class="fe-lbl">Tipo'+(travado?' <span class="fe-tag" title="campo integrado ou tipo de sistema">travado</span>':'')+'</label>'+
        '<select data-f="type" '+(travado?'disabled':'')+'>'+tiposOpts+'</select></div>'+
      '</div>'+
      '<div class="fe-grid2">'+
        '<div><label class="fe-lbl">Dica (hint)</label><input type="text" data-f="hint" value="'+esc(c.hint||'')+'"></div>'+
        '<div style="display:flex;align-items:flex-end;gap:16px">'+
          '<label style="display:flex;align-items:center;gap:6px;font-size:13.5px;margin:0"><input type="checkbox" data-f="required" style="width:auto" '+(c.required?'checked':'')+'> Obrigatório</label>'+
          '<span class="fe-key" title="a key é a identidade do campo em todas as ligações">🔒 '+esc(c.key)+'</span>'+
        '</div>'+
      '</div>'+
      '<div data-opcoes></div>'+
      '<div style="border-top:1px solid var(--bd);padding-top:11px"><label class="fe-lbl">Mostrar quando</label><div data-cond></div></div>'+
      '<div style="display:flex;gap:10px;align-items:center;border-top:1px solid var(--bd);padding-top:11px">'+
        '<label class="fe-lbl" style="margin:0">Mover para seção</label>'+
        '<select data-f="mover" style="width:auto">'+DEF.secoes.map(function(s){ return '<option value="'+esc(s.id)+'"'+(s.id===sec.id?' selected':'')+'>'+esc(s.titulo||s.id)+'</option>'; }).join('')+'</select>'+
        '<span style="margin-left:auto"></span>'+
        (deletavel(c) ? '<button type="button" class="fe-mini warn" data-a="del">Remover campo</button>' : '<span class="fe-tag">não removível</span>')+
      '</div>';

    b.querySelector('[data-f=label]').oninput=function(){ c.label=this.value; marcaDirty(); };
    b.querySelector('[data-f=hint]').oninput=function(){ if(this.value) c.hint=this.value; else delete c.hint; marcaDirty(); };
    b.querySelector('[data-f=required]').onchange=function(){ if(this.checked) c.required=true; else delete c.required; marcaDirty(); };
    var selTipo=b.querySelector('[data-f=type]');
    if (!travado) selTipo.onchange=function(){ c.type=this.value; marcaDirty(); montarOpcoes(b.querySelector('[data-opcoes]'), c); };
    b.querySelector('[data-f=mover]').onchange=function(){
      var alvo=this.value; if (alvo===sec.id) return;
      var dest=null; DEF.secoes.forEach(function(s){ if(s.id===alvo) dest=s; });
      if (!dest) return;
      sec.campos.splice(ci,1); (dest.campos=dest.campos||[]).push(c); marcaDirty(); render();
    };
    var del=b.querySelector('[data-a=del]');
    if (del) del.onclick=function(){
      var aviso = (ST[c.key]&&ST[c.key].temColuna)
        ? 'Este campo TEM coluna no banco. Remover do formulário faz ele parar de ser coletado (dados antigos permanecem na coluna). Remover mesmo assim?'
        : 'Remover o campo "'+(c.label||c.key)+'"?';
      if (confirm(aviso)){ sec.campos.splice(ci,1); if(EXP===c.key) EXP=null; marcaDirty(); render(); }
    };
    montarOpcoes(b.querySelector('[data-opcoes]'), c);
    montarCondBuilder(b.querySelector('[data-cond]'), c, 'cond');
    box.appendChild(b);
    return box;
  }

  function montarOpcoes(host, c){
    host.innerHTML='';
    if (c.type==='matrix'){ host.innerHTML='<span class="fe-note">Matriz: colunas fixas neste editor (edição via schema).</span>'; return; }
    if (['select','radio','checkbox'].indexOf(c.type)<0) return;
    var ta=document.createElement('textarea'); ta.rows=Math.min(8, Math.max(3,(c.options||[]).length));
    ta.value=(c.options||[]).join('\n');
    var lbl=document.createElement('label'); lbl.className='fe-lbl'; lbl.textContent='Opções (uma por linha)';
    ta.oninput=function(){ c.options=this.value.split('\n').map(function(x){return x.trim();}).filter(Boolean); marcaDirty(); };
    host.appendChild(lbl); host.appendChild(ta);
  }

  // ── builder de condicional (obj[prop] = cond) ─────────────────────────────
  function montarCondBuilder(host, obj, prop){
    host.innerHTML='';
    var sim = condParaSimples(obj[prop]);
    if (sim===null){ // não representável → modo avançado (JSON)
      var ta=document.createElement('textarea'); ta.rows=4;
      ta.value=JSON.stringify(obj[prop], null, 2);
      var note=document.createElement('span'); note.className='fe-note'; note.textContent='Condicional avançada (aninhada) — edição em JSON:';
      ta.oninput=function(){ try{ obj[prop]=JSON.parse(this.value); this.style.borderColor=''; marcaDirty(); }catch(e){ this.style.borderColor='#c33'; } };
      host.appendChild(note); host.appendChild(ta); return;
    }
    var ks = todasKeys();
    function linhaEl(l, idx){
      var d=document.createElement('div'); d.className='fe-condrow';
      var opsHtml = Object.keys(OP_LABEL).map(function(o){ return '<option value="'+o+'"'+(o===l.op?' selected':'')+'>'+OP_LABEL[o]+'</option>'; }).join('');
      var ksHtml = ks.map(function(k){ return '<option value="'+esc(k)+'"'+(k===l.campo?' selected':'')+'>'+esc(k)+'</option>'; }).join('');
      var semValor = OPS_SEM_VALOR.indexOf(l.op)>=0;
      // op de lista + campo com opções → multi-select (Shift/Ctrl), sem digitação livre.
      var ref=acharCampo(l.campo); var opc=(ref&&ref.campo&&Array.isArray(ref.campo.options))?ref.campo.options:[];
      var usaLista=OPS_LISTA.indexOf(l.op)>=0 && opc.length>0;
      var valorHtml;
      if (semValor) valorHtml='';
      else if (usaLista){
        var selArr=Array.isArray(l.valor)?l.valor:String(l.valor||'').split(',').map(function(x){return x.trim();}).filter(Boolean);
        valorHtml='<select data-c="valor" multiple size="'+Math.min(6,opc.length)+'" title="Shift/Ctrl para selecionar vários">'+
          opc.map(function(o){ return '<option value="'+esc(o)+'"'+(selArr.indexOf(o)>=0?' selected':'')+'>'+esc(o)+'</option>'; }).join('')+'</select>';
      } else {
        valorHtml='<input type="text" data-c="valor" placeholder="'+(OPS_LISTA.indexOf(l.op)>=0?'valores separados por vírgula':'valor')+'" value="'+esc(Array.isArray(l.valor)?l.valor.join(', '):(l.valor||''))+'">';
      }
      d.innerHTML='<select data-c="campo"><option value="">— campo —</option>'+ksHtml+'</select>'+
        '<select data-c="op">'+opsHtml+'</select>'+ valorHtml +
        '<button type="button" class="fe-mini warn" data-c="x">×</button>';
      d.querySelector('[data-c=campo]').onchange=function(){ l.campo=this.value; aplica(); montarCondBuilder(host,obj,prop); };
      d.querySelector('[data-c=op]').onchange=function(){ l.op=this.value; aplica(); montarCondBuilder(host,obj,prop); };
      var vi=d.querySelector('[data-c=valor]');
      if (vi){
        if (vi.tagName==='SELECT' && vi.multiple) vi.onchange=function(){ l.valor=Array.prototype.filter.call(this.options,function(o){return o.selected;}).map(function(o){return o.value;}); aplica(); };
        else vi.oninput=function(){ l.valor=this.value; aplica(); };
      }
      d.querySelector('[data-c=x]').onclick=function(){ sim.linhas.splice(idx,1); aplica(); montarCondBuilder(host,obj,prop); };
      return d;
    }
    function aplica(){ var c=simplesParaCond(sim); if (c) obj[prop]=c; else delete obj[prop]; marcaDirty(); }
    sim.linhas.forEach(function(l,i){ host.appendChild(linhaEl(l,i)); });
    var rodape=document.createElement('div'); rodape.className='fe-condrow';
    rodape.innerHTML='<button type="button" class="fe-mini" data-c="add">+ condição</button>'+
      (sim.linhas.length>1 ? '<select data-c="junc" style="min-width:auto"><option value="all"'+(sim.juncao==='all'?' selected':'')+'>TODAS (E)</option><option value="any"'+(sim.juncao==='any'?' selected':'')+'>QUALQUER (OU)</option></select>' : '')+
      (sim.linhas.length ? '<span class="fe-note" style="margin-left:auto">sem condição = sempre visível</span>' : '<span class="fe-note">sem condição — sempre visível</span>');
    rodape.querySelector('[data-c=add]').onclick=function(){ sim.linhas.push({campo:'',op:'eq',valor:''}); montarCondBuilder(host,obj,prop); host.querySelector('[data-c=campo]') && aplica(); };
    var jc=rodape.querySelector('[data-c=junc]'); if (jc) jc.onchange=function(){ sim.juncao=this.value; aplica(); };
    host.appendChild(rodape);
  }

  // ── mutações estruturais ───────────────────────────────────────────────────
  function moveCampo(sec, ci, delta){ var cs=sec.campos, alvo=ci+delta; if (alvo<0||alvo>=cs.length) return; var t=cs[ci]; cs[ci]=cs[alvo]; cs[alvo]=t; marcaDirty(); render(); }
  function moveSecao(si, delta){ var alvo=si+delta; if (alvo<0||alvo>=DEF.secoes.length) return; var t=DEF.secoes[si]; DEF.secoes[si]=DEF.secoes[alvo]; DEF.secoes[alvo]=t; marcaDirty(); render(); }
  function addCampo(sec){
    var label = prompt('Rótulo do novo campo:'); if (!label || !label.trim()) return;
    var key = slug(label);
    var c = { key:key, type:'text', label:label.trim() };
    (sec.campos=sec.campos||[]).push(c); NOVOS[key]=true; EXP=key; marcaDirty(); render();
  }
  window.feAddSecao = function(){
    var titulo = prompt('Título da nova seção:'); if (!titulo || !titulo.trim()) return;
    var id = slug(titulo); // slug de campo serve pra id de seção
    DEF.secoes.push({ id:id, titulo:titulo.trim(), campos:[] }); marcaDirty(); render();
  };

  // ── salvar ─────────────────────────────────────────────────────────────────
  window.feSalvar = function(){
    var btn=document.getElementById('fe-salvar'); btn.disabled=true; msg('validando e salvando…');
    fetch('/atb/admin/form/estrutura/salvar?inst='+encodeURIComponent(B.inst), {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ definicao: DEF })
    }).then(function(r){ return r.json().then(function(j){ return {status:r.status, j:j}; }); })
    .then(function(r){
      btn.disabled=false;
      if (r.j && r.j.ok){
        DIRTY=false; document.getElementById('fe-dirty').style.display='none';
        msg('✓ versão '+r.j.versao+' salva e ativa. Recomendado: rodar o healthcheck.', 'ok');
        var m=document.getElementById('fe-msg');
        m.innerHTML += ' <a href="/atb/admin/healthcheck/run?inst='+encodeURIComponent(B.inst)+'" target="_blank">Rodar healthcheck ↗</a> · <a href="/atb/form?inst='+encodeURIComponent(B.inst)+'" target="_blank">Abrir formulário ↗</a>';
      } else {
        msg('Não salvo:\n' + ((r.j && r.j.erros) || ['erro desconhecido']).join('\n'), 'err');
      }
    }).catch(function(e){ btn.disabled=false; msg('Erro de rede: '+e.message, 'err'); });
  };

  render();
})();
`;
}
