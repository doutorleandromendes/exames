// ════════════════════════════════════════════════════════════════════════════
//  atb-ficha-edit-routes.js
//  Edição (SUPER-ADMIN) dos campos preenchidos pelo PRESCRITOR — correção de
//  erros de digitação (ex.: "bactrin" lançado como ATB não-padronizado).
//
//  Cobre só os campos guardados diretamente (escalares, datas, listas). NÃO
//  mexe nas matrizes (posologia/culturas/ATB prévios) nem reconstrói o SOFA a
//  partir das sub-respostas (que não são salvas) — o SOFA aqui é número cru.
//
//  Integração (atb-routes.js):
//    import { ensureFichaEditSchema, registerFichaEditRoutes } from './atb-ficha-edit-routes.js';
//    // no boot:               ensureFichaEditSchema(pool).catch(()=>{});
//    // em registerAtbRoutes:  registerFichaEditRoutes(app, pool, scihRequired);
//  Link (só super-admin) na ficha/grade:
//    <a href="/atb/admin/ficha/${id}/editar">✏️ Editar dados</a>
//
//  Salvaguardas: auditoria (editado_por/editado_em), espelho JotForm dos campos
//  mexidos (no-op se o mirror estiver desligado), e o pull deve respeitar
//  paciente_nome editado (ver patch em atb-sync.js nas instruções).
// ════════════════════════════════════════════════════════════════════════════

import { espelharEdicao } from './atb-jotform-mirror.js';
import { getFormSchema }  from './atb-form-schema.js';

const _safe = s => String(s ?? '').replace(/[&<>"']/g,
  c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));

// ── Campos editáveis (col = coluna no banco · w = widget) ─────────────────────
const GRUPOS = [
  ['Identificação', [
    ['paciente_nome',          'Nome do paciente',            'text'],
    ['paciente_dn',            'Data de nascimento',          'date'],
    ['prontuario',             'Prontuário',                  'text'],
    ['atendimento',            'Número de atendimento',       'text'],
  ]],
  ['Local', [
    ['setor',                  'Setor',                       'sel'],
    ['leito',                  'Leito',                       'text'],
    ['equipe_responsavel',     'Equipe responsável',          'sel'],
  ]],
  ['Datas', [
    ['data_internacao',        'Internação',                  'date'],
    ['data_admissao_uti',      'Admissão na UTI',             'date'],
    ['data_insercao_cateter',  'Inserção do cateter',         'date'],
  ]],
  ['Clínico', [
    ['tipo_terapia',           'Tipo de terapia',             'sel'],
    ['foco_infeccao',          'Foco da infecção',            'sel'],
    ['sepse',                  'Sepse',                       'bool'],
    ['gestante',               'Gestante',                    'bool'],
    ['lactante',               'Lactante',                    'bool'],
    ['historia_clinica',       'História clínica',            'textarea'],
    ['cirurgia',               'Cirurgia',                    'textarea'],
    ['classificacao_fratura',  'Classificação de fratura',    'sel'],
    ['uso_atb_7d',             'Uso de ATB nos últimos 7 dias','bool'],
    ['dialise',                'Em diálise',                  'bool'],
    ['acesso_dialise',         'Acesso para diálise',         'sel'],
    ['faz_quimio',             'Faz quimioterapia',           'bool'],
    ['cateter_quimio',         'Cateter de longa permanência','bool'],
    ['acesso_quimio',          'Tipo de acesso (quimio)',     'sel'],
    ['oxacilina_associacao',   'Oxacilina em associação',     'bool'],
  ]],
  ['Medidas', [
    ['peso',                   'Peso (kg)',                   'num'],
    ['altura',                 'Altura',                      'num'],
    ['clcr',                   'ClCr',                        'num'],
    ['peso_nascimento',        'Peso ao nascer',              'num'],
    ['tempo_previsto',         'Tempo previsto (dias)',       'num'],
  ]],
  ['Listas', [
    ['atb_solicitado',         'ATB solicitado',              'multi'],
    ['comorbidades',           'Comorbidades',                'multi'],
    ['dispositivos_invasivos', 'Dispositivos invasivos',      'multi'],
    ['sitio_cvc',              'Sítio CVC',                   'multi'],
    ['sitio_cdl',              'Sítio CDL',                   'multi'],
    ['sitio_pai',              'Sítio PAi',                   'multi'],
    ['acesso_vascular_neo',    'Acesso vascular neo',         'multi'],
    ['insuficiencia_renal',    'Insuficiência renal',         'multi'],
  ]],
  ['Prescritor', [
    ['crm',                    'CRM',                         'text'],
    ['prescritor_nome',        'Nome do prescritor',          'text'],
  ]],
  ['SOFA (avançado — número cru)', [
    ['sofa',                   'SOFA total',                  'num'],
    ['sofa_renal',             'SOFA renal',                  'num'],
  ]],
];

// col → chave do formulário (p/ herdar opções do schema vivo)
const COL2KEY = {
  setor:'setor', equipe_responsavel:'equipe', tipo_terapia:'tipo_terapia',
  foco_infeccao:'foco', acesso_dialise:'acesso_dialise', acesso_quimio:'acesso_quimio',
  classificacao_fratura:'classificacao_fratura', comorbidades:'comorbidades',
  dispositivos_invasivos:'dispositivos', atb_solicitado:'atb_solicitado',
  sitio_cvc:'sitio_cvc', sitio_cdl:'sitio_cdl', sitio_pai:'sitio_pai',
  acesso_vascular_neo:'acesso_neo', insuficiencia_renal:'ir',
};

const FLAT  = GRUPOS.flatMap(g => g[1]);
const MULTI = new Set(FLAT.filter(([, , w]) => w === 'multi').map(([c]) => c));
const BOOLS = new Set(FLAT.filter(([, , w]) => w === 'bool').map(([c]) => c));
const NUMS  = new Set(FLAT.filter(([, , w]) => w === 'num').map(([c]) => c));
const DATES = new Set(FLAT.filter(([, , w]) => w === 'date').map(([c]) => c));
const COLS  = FLAT.map(([c]) => c);

export async function ensureFichaEditSchema(pool) {
  await pool.query(`ALTER TABLE atb_fichas ADD COLUMN IF NOT EXISTS editado_por INTEGER REFERENCES users(id)`);
  await pool.query(`ALTER TABLE atb_fichas ADD COLUMN IF NOT EXISTS editado_em  TIMESTAMPTZ`);
}

const souSuper = req => !!((req.user && req.user.super_admin) || (req.cookies && req.cookies.adm === '1'));

export function registerFichaEditRoutes(app, pool, adminRequired) {

  // ── Salvar (super-admin) — só atualiza os campos que vieram em body.campos ──
  app.post('/atb/admin/api/ficha/:id', adminRequired, async (req, res) => {
    if (!souSuper(req)) return res.status(403).json({ ok:false, error:'apenas super-admin' });
    const id     = parseInt(req.params.id, 10);
    const campos = (req.body && req.body.campos) || {};
    const sets = [], vals = []; let i = 1; const mexidas = [];

    for (const col of COLS) {
      if (!Object.prototype.hasOwnProperty.call(campos, col)) continue;
      const v = campos[col];
      if (MULTI.has(col)) {
        sets.push(`${col} = $${i++}::jsonb`); vals.push(JSON.stringify(Array.isArray(v) ? v : []));
      } else if (BOOLS.has(col)) {
        sets.push(`${col} = $${i++}`); vals.push(v === 'Sim' ? true : v === 'Não' ? false : null);
      } else if (NUMS.has(col)) {
        const n = (v === '' || v == null) ? null : parseFloat(v);
        sets.push(`${col} = $${i++}`); vals.push(Number.isFinite(n) ? n : null);
      } else {
        sets.push(`${col} = $${i++}`); vals.push((v == null || v === '') ? null : String(v));
      }
      mexidas.push(col);
    }
    if (!sets.length) return res.status(400).json({ ok:false, error:'nada a salvar' });

    // recomputa idade se a DN mudou; espelha nome em paciente_nome_raw
    if (mexidas.includes('paciente_dn')) {
      const dn = campos['paciente_dn'];
      const idade = dn ? String(Math.floor((Date.now() - new Date(dn).getTime()) / 31557600000)) : null;
      sets.push(`paciente_idade = $${i++}`); vals.push(idade);
      mexidas.push('paciente_idade');
    }
    if (mexidas.includes('paciente_nome')) {
      sets.push(`paciente_nome_raw = $${i++}`); vals.push(campos['paciente_nome'] || null);
    }

    sets.push(`editado_por = $${i++}`); vals.push(req.user?.id || null);
    sets.push(`editado_em = now()`);
    sets.push(`updated_at = now()`);
    vals.push(id);

    try {
      const r = await pool.query(`UPDATE atb_fichas SET ${sets.join(', ')} WHERE id = $${i}`, vals);
      if (!r.rowCount) return res.status(404).json({ ok:false, error:'ficha não encontrada' });
      espelharEdicao(pool, id, mexidas);   // espelho JotForm (só campos mexidos); no-op se mirror off
      res.json({ ok:true, atualizados: mexidas.filter(c => c !== 'paciente_idade').length });
    } catch (e) {
      console.error('[atb] editar ficha:', e.message);
      res.status(500).json({ ok:false, error: e.message });
    }
  });

  // ── Página de edição (super-admin) ──────────────────────────────────────────
  app.get('/atb/admin/ficha/:id/editar', adminRequired, async (req, res) => {
    if (!souSuper(req)) return res.status(403).send('Acesso restrito ao super-admin.');
    try {
      const id  = parseInt(req.params.id, 10);
      const sel = COLS.map(c => DATES.has(c) ? `${c}::text AS ${c}` : c).join(', ');
      const { rows:[f] } = await pool.query(
        `SELECT id, ${sel}, instituicao_id FROM atb_fichas WHERE id = $1`, [id]);
      if (!f) return res.status(404).send('Ficha não encontrada');

      const { rows:[inst] } = await pool.query(`SELECT sigla FROM atb_instituicoes WHERE id = $1`, [f.instituicao_id]);
      let schema = null;
      try { schema = await getFormSchema(pool, (inst && inst.sigla) || 'HUSF'); } catch {}
      const campos = {};
      if (schema && schema.secoes) for (const s of schema.secoes) for (const c of (s.campos || [])) campos[c.key] = c;

      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(paginaEdit(f, campos));
    } catch (e) {
      console.error('[atb] editar page:', e.message);
      res.status(500).send('Erro: ' + _safe(e.message));
    }
  });
}

// ── helpers de render ────────────────────────────────────────────────────────
function opcoesDe(col, campos) {
  const k = COL2KEY[col]; if (!k) return null;
  const c = campos[k];
  return (c && Array.isArray(c.options)) ? c.options : null;
}

function selHtml(col, type, opts, cur) {
  const os = opts.map(o => `<option value="${_safe(o)}"${o === cur ? ' selected' : ''}>${_safe(o) || '—'}</option>`).join('');
  return `<select data-col="${col}" data-type="${type}" data-orig="${_safe(cur)}">${os}</select>`;
}

function campoHtml(col, label, w, f, campos) {
  const v = f[col];
  let inner;

  if (w === 'multi') {
    let cur = Array.isArray(v) ? v
      : (typeof v === 'string' ? (() => { try { return JSON.parse(v); } catch { return []; } })() : []);
    const opts = opcoesDe(col, campos);
    if (!opts) {
      const txt = cur.join(', ');
      inner = `<input type="text" data-col="${col}" data-type="multitext" data-orig="${_safe(txt)}" value="${_safe(txt)}" placeholder="separe por vírgula">`;
    } else {
      const boxes = opts.map(o =>
        `<label class="ck"><input type="checkbox" value="${_safe(o)}"${cur.includes(o) ? ' checked' : ''}> ${_safe(o)}</label>`
      ).join('');
      inner = `<div class="multi" data-col="${col}" data-type="multi" data-orig='${_safe(JSON.stringify(cur))}'>${boxes}</div>`;
    }
  } else if (w === 'bool') {
    const cur = v === true ? 'Sim' : v === false ? 'Não' : '';
    inner = selHtml(col, 'bool', ['', 'Sim', 'Não'], cur);
  } else if (w === 'sel') {
    const cur  = (v == null ? '' : String(v));
    const base = opcoesDe(col, campos) || [];
    const opts = [''].concat(base.includes(cur) || cur === '' ? base : [cur].concat(base));
    inner = selHtml(col, 'sel', opts, cur);
  } else if (w === 'date') {
    const cur = (v == null ? '' : String(v)).slice(0, 10);
    inner = `<input type="date" data-col="${col}" data-type="date" data-orig="${_safe(cur)}" value="${_safe(cur)}">`;
  } else if (w === 'num') {
    const cur = (v == null ? '' : String(v));
    inner = `<input type="number" step="any" data-col="${col}" data-type="num" data-orig="${_safe(cur)}" value="${_safe(cur)}">`;
  } else if (w === 'textarea') {
    const cur = (v == null ? '' : String(v));
    inner = `<textarea rows="3" data-col="${col}" data-type="text" data-orig="${_safe(cur)}">${_safe(cur)}</textarea>`;
  } else {
    const cur = (v == null ? '' : String(v));
    inner = `<input type="text" data-col="${col}" data-type="text" data-orig="${_safe(cur)}" value="${_safe(cur)}">`;
  }
  const wide = (w === 'textarea' || w === 'multi') ? ' campo-wide' : '';
  return `<div class="campo${wide}"><label class="lbl">${_safe(label)}</label>${inner}</div>`;
}

function paginaEdit(f, campos) {
  const secoes = GRUPOS.map(([titulo, lista]) =>
    `<section class="grupo"><h2>${_safe(titulo)}</h2><div class="grid">` +
    lista.map(([col, label, w]) => campoHtml(col, label, w, f, campos)).join('') +
    `</div></section>`
  ).join('');

  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Editar ficha #${f.id}</title>
<style>
  :root{ --bg:#f5f6f8; --card:#fff; --bd:#e3e6ea; --tx:#2b2f33; --mut:#6b7280; --ac:#2563eb; }
  *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--tx);
    font:15px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;}
  .wrap{max-width:920px;margin:0 auto;padding:24px 18px 120px;}
  .top{display:flex;align-items:center;gap:12px;margin-bottom:6px;}
  .top a{color:var(--mut);text-decoration:none;font-size:14px;}
  h1{font-size:20px;margin:4px 0 2px;}
  .sub{color:var(--mut);font-size:13px;margin-bottom:18px;}
  .warn{background:#fff7ed;border:1px solid #fed7aa;color:#9a3412;border-radius:8px;
    padding:10px 12px;font-size:13px;margin-bottom:18px;}
  .grupo{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:16px 18px;margin-bottom:16px;}
  .grupo h2{font-size:14px;text-transform:uppercase;letter-spacing:.04em;color:var(--mut);margin:0 0 12px;}
  .grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px 18px;}
  .campo{display:flex;flex-direction:column;gap:4px;}
  .campo-wide{grid-column:1 / -1;}
  .lbl{font-size:12px;color:var(--mut);}
  input,select,textarea{font:inherit;color:var(--tx);background:#fff;border:1px solid var(--bd);
    border-radius:8px;padding:8px 10px;width:100%;}
  input:focus,select:focus,textarea:focus{outline:none;border-color:var(--ac);box-shadow:0 0 0 3px rgba(37,99,235,.12);}
  textarea{resize:vertical;}
  .multi{display:flex;flex-wrap:wrap;gap:6px 14px;border:1px solid var(--bd);border-radius:8px;padding:10px;background:#fafbfc;}
  .ck{display:inline-flex;align-items:center;gap:6px;font-size:14px;width:auto;}
  .ck input{width:auto;}
  .bar{position:fixed;left:0;right:0;bottom:0;background:rgba(255,255,255,.96);
    border-top:1px solid var(--bd);padding:12px 18px;display:flex;align-items:center;gap:14px;justify-content:flex-end;}
  .bar .wrapbar{max-width:920px;margin:0 auto;width:100%;display:flex;align-items:center;gap:14px;justify-content:flex-end;}
  #msg{margin-right:auto;font-size:14px;}
  button{font:inherit;font-weight:600;background:var(--ac);color:#fff;border:0;border-radius:8px;padding:10px 18px;cursor:pointer;}
  button:disabled{opacity:.6;cursor:default;}
  @media(max-width:640px){ .grid{grid-template-columns:1fr;} }
</style></head><body>
<div class="wrap">
  <div class="top"><a href="/atb/admin/grid">← Voltar à grade</a></div>
  <h1>Editar dados da ficha #${f.id}</h1>
  <div class="sub">Paciente: ${_safe(f.paciente_nome || '')} · Prontuário ${_safe(f.prontuario || '—')} · Atend. ${_safe(f.atendimento || '—')}</div>
  <div class="warn">Edição administrativa de dados preenchidos pelo prescritor (correção de erros).
    Só os campos que você alterar serão gravados. O original fica preservado no histórico (payload).</div>
  ${secoes}
</div>
<div class="bar"><div class="wrapbar">
  <span id="msg"></span>
  <button id="btnSalvar" type="button" onclick="salvar()">Salvar alterações</button>
</div></div>
<script>
  var FICHA_ID = ${f.id};
  function gather(){
    var out = {};
    document.querySelectorAll('[data-col]').forEach(function(el){
      var col = el.dataset.col, type = el.dataset.type, orig = el.dataset.orig || '';
      if (type === 'multi') {
        var arr = [].slice.call(el.querySelectorAll('input:checked')).map(function(i){ return i.value; });
        if (JSON.stringify(arr) === orig) return;
        out[col] = arr;
      } else if (type === 'multitext') {
        var arr = el.value.split(',').map(function(s){ return s.trim(); }).filter(Boolean);
        var o   = (orig || '').split(',').map(function(s){ return s.trim(); }).filter(Boolean);
        if (JSON.stringify(arr) === JSON.stringify(o)) return;
        out[col] = arr;
      } else {
        var val = (el.value == null ? '' : el.value);
        if (val === orig) return;
        out[col] = (val === '' ? null : val);
      }
    });
    return out;
  }
  function msg(t,c){ var m = document.getElementById('msg'); m.textContent = t; m.style.color = c; }
  function salvar(){
    var campos = gather();
    var n = Object.keys(campos).length;
    if (!n) { msg('Nenhuma alteração para salvar.', '#777'); return; }
    var btn = document.getElementById('btnSalvar'); btn.disabled = true; btn.textContent = 'Salvando…';
    fetch('/atb/admin/api/ficha/' + FICHA_ID, {
      method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ campos: campos })
    })
    .then(function(r){ return r.json().then(function(d){ return { ok:r.ok, d:d }; }); })
    .then(function(res){
      btn.disabled = false; btn.textContent = 'Salvar alterações';
      if (res.ok) { msg('✓ ' + res.d.atualizados + ' campo(s) atualizado(s).', '#1a8a5a');
        setTimeout(function(){ location.href = '/atb/admin/grid'; }, 900); }
      else msg('Erro: ' + (res.d.error || 'tente novamente'), '#c0392b');
    })
    .catch(function(e){ btn.disabled = false; btn.textContent = 'Salvar alterações';
      msg('Erro de conexão: ' + e.message, '#c0392b'); });
  }
</script>
</body></html>`;
}
