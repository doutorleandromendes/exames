// ════════════════════════════════════════════════════════════════════════════
//  EMISSÃO DE PARECER SCIH  —  veredito + especificação editáveis
//
//  Substitui a entrada manual que hoje só existia no JotForm (qid 30 = veredito,
//  qid 88 = especificação). Disponível em DOIS lugares:
//    1. Inline na grade  → coluna "Parecer": dropdown de veredito + popover de
//       especificação (busca nas 29 frases + texto livre no mesmo campo).
//    2. Página dedicada  → /atb/admin/parecer/:id, na linguagem clara da
//       Complementação (azul #00469e, cartões claros).
//
//  Modelo de dados (sem migração de tabela — colunas já existem em atb_fichas):
//    • recomendacao_scih          JSONB  → veredito (single-select, guardado
//                                          como array de 1 elemento p/ manter o
//                                          visualizador do EMR e os pills da grade)
//    • recomendacoes_especificacao TEXT  → especificação (combobox de campo
//                                          único: o dropdown INSERE a frase, e
//                                          você edita/complementa livremente)
//
//  Integração em atb-routes.js (espelhando o que já é feito p/ Complementação):
//    import { ensureParecerSchema, registerParecerEditRoutes,
//             renderParecerCell, parecerGridAssets, PARECER_VEREDITOS }
//      from './atb-parecer-edit-routes.js';
//    // no boot:               ensureParecerSchema(pool).catch(...);
//    // em registerAtbRoutes:  registerParecerEditRoutes(app, pool, adminRequired);
//    // na grade (célula):     ${renderParecerCell(f, safe)}      // troca o <td> do veredito
//    // na grade (1x no html): ${parecerGridAssets()}             // CSS + popover + JS
// ════════════════════════════════════════════════════════════════════════════

// ── Fonte ÚNICA de verdade das opções ───────────────────────────────────────

// Veredito (qid 30). Single-select. Mesma lista que a paleta REC_CORES reconhece.
export const PARECER_VEREDITOS = [
  'Sim',
  'Não',
  'Com ajustes (especificados abaixo)',
  'ATB não controlado',
  'Suspenso',
  'Ficha Repetida',
  'Audit_post',
];

// Especificação (qid 88). As 29 frases pré-configuradas do JotForm, na ordem original.
export const PARECER_ESPECIFICACOES = [
  '3d (rever com resultado de urocultura)',
  '3 doses (rever com resultado de hemoculturas)',
  '3d (rever com resultado de cultura de secreção traqueal e parcial de hemoculturas)',
  '3d (rever com resultado parcial de culturas e definição diagnóstica)',
  '2d (rever com resultado parcial de culturas e definição diagnóstica)',
  '3d (rever com definição diagnóstica)',
  '2d (rever com resultado final de hemoculturas)',
  '5d (rever com resultado de culturas)',
  'Sugiro rever indicação.',
  'Sugiro rever indicação/preenchimento.',
  'Sugiro rever esquema prescrito.',
  'NOTA: Em caso de contingenciamento de estoque da droga, ressalto a possibilidade de uso de gentamicina.',
  'Tempo máximo = 5 dias',
  'Sugiro fosfomicina e rever com resultado de urocultura.',
  'Sugiro diagnóstico etiológico e terapia guiada.',
  'Sugiro [(ciprofloxacina ou gentamicina) + metronidazol].',
  'Sugiro rever esquema prescrito considerando potencial antagonismo, risco de falha clínica/microbiológica e eventos adversos.',
  'Sugiro associação de glicopeptídeo, revendo com resultado parcial de culturas e definição diagnóstica.',
  'Sugiro rever esquema prescrito. Ceftriaxone não é indicado para nenhum esquema de profilaxia cirúrgica na instituição.',
  'Sugiro rever esquema prescrito por espectro antimicrobiano inadequado de acordo com os dados clínicos informados.',
  'Sugiro rever esquema prescrito por penetração tecidual inadequada conforme dados clínicos informados.',
  'Sugiro rever esquema prescrito por risco de eventos adversos e sequelas de longo prazo conforme dados informados.',
  'Sugiro [cefazolina +/- metronidazol] por, no máximo, 3 dias.',
  'Sugiro rever dados inconsistentes na solicitação considerando potenciais implicações éticas e jurídicas da discrepância.',
  'Sugiro prosseguir investigação diagnóstica',
  'Não há evidências que embasem o uso de antibioticoterapia empírica na ausência de sepse considerando o contexto descrito na ficha. Sugiro prosseguir investigação diagnóstica.',
  'Não há evidências que embasem o uso do esquema de antibioticoterapia profilática ou preemptiva prescrito conforme a ecologia local. Sugiro profilaxia/terapia preemptiva conforme protocolo institucional.',
  'Sugiro prosseguir investigação diagnóstica/etiológica e tratamento guiado',
  'Dados inconsistentes, favor rever preenchimento.',
];

// helper local (caso quem chame não passe um safe)
function _safe(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ── Migração não-destrutiva: rastreabilidade do parecer ──────────────────────
export async function ensureParecerSchema(pool) {
  await pool.query(`ALTER TABLE atb_fichas ADD COLUMN IF NOT EXISTS parecer_emitido_por INTEGER REFERENCES users(id)`);
  await pool.query(`ALTER TABLE atb_fichas ADD COLUMN IF NOT EXISTS parecer_emitido_at  TIMESTAMPTZ`);
}

// ── Normaliza o veredito vindo do banco (array JSONB) p/ string única ────────
function _veredito1(f) {
  const a = Array.isArray(f.recomendacao_scih) ? f.recomendacao_scih
    : (typeof f.recomendacao_scih === 'string'
        ? (() => { try { return JSON.parse(f.recomendacao_scih); } catch { return []; } })()
        : []);
  return a[0] || '';
}

// ════════════════════════════════════════════════════════════════════════════
//  CÉLULA DA GRADE  — troca o <td> que hoje mostra os pills read-only
// ════════════════════════════════════════════════════════════════════════════
export function renderParecerCell(f, safe) {
  const s = safe || _safe;
  const ver = _veredito1(f);
  const espec = f.recomendacoes_especificacao || '';
  const preview = espec ? (espec.length > 38 ? espec.slice(0, 38) + '…' : espec) : '';

  const opts = ['<option value="">— veredito —</option>']
    .concat(PARECER_VEREDITOS.map(v =>
      `<option value="${s(v)}" ${ver === v ? 'selected' : ''}>${s(v)}</option>`))
    .join('');

  const btnLabel = espec ? '✎ ' + s(preview) : '+ especificação';
  const btnCls = espec ? 'parecer-espec-btn tem' : 'parecer-espec-btn';

  return `<td class="parecer-cell">
    <select class="parecer-veredito" data-fid="${f.id}">${opts}</select>
    <button type="button" class="${btnCls}" data-fid="${f.id}"
      data-espec="${s(espec)}" title="${espec ? s(espec) : 'Adicionar especificação'}">${btnLabel}</button>
  </td>`;
}

// ════════════════════════════════════════════════════════════════════════════
//  ASSETS DA GRADE  — CSS + popover + JS (inserir UMA vez no html do grid)
// ════════════════════════════════════════════════════════════════════════════
export function parecerGridAssets() {
  const FRASES = JSON.stringify(PARECER_ESPECIFICACOES);

  // CSS pensado p/ a grade clara (.atb-light). Cores alinhadas à Complementação.
  const css = `
  <style>
    .atb-light .parecer-cell{min-width:172px;vertical-align:top}
    .atb-light .parecer-veredito{width:100%;font-size:12px;padding:5px 6px;border:1px solid #d8dee6;
      border-radius:6px;background:#fff;color:#1a2733}
    .atb-light .parecer-espec-btn{display:block;width:100%;margin-top:4px;text-align:left;cursor:pointer;
      font-size:11px;line-height:1.3;padding:5px 7px;border:1px dashed #c6cdd6;border-radius:6px;
      background:#fafbfc;color:#5f6368;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .atb-light .parecer-espec-btn.tem{border-style:solid;border-color:#bcd0ec;background:#eef4fc;color:#0c447c}
    .atb-light .parecer-espec-btn:hover{border-color:#00469e}

    #parecer-pop{position:absolute;z-index:9999;display:none;width:380px;max-width:92vw;
      background:#fff;border:1px solid #d8dee6;border-radius:10px;box-shadow:0 10px 30px rgba(12,68,124,.18);
      padding:12px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}
    #parecer-pop .ttl{font-size:11px;font-weight:700;color:#0c447c;text-transform:uppercase;
      letter-spacing:.04em;margin-bottom:8px}
    #parecer-pop input.busca{width:100%;padding:8px 10px;border:1px solid #d8dee6;border-radius:7px;
      font-size:13px;margin-bottom:6px}
    #parecer-pop input.busca:focus{outline:none;border-color:#00469e;box-shadow:0 0 0 3px #e6eef8}
    #parecer-pop .lista{max-height:180px;overflow-y:auto;border:1px solid #eef1f5;border-radius:7px;margin-bottom:8px}
    #parecer-pop .lista .item{padding:7px 9px;font-size:12px;line-height:1.35;cursor:pointer;
      border-bottom:1px solid #f1f4f8;color:#1a2733}
    #parecer-pop .lista .item:last-child{border-bottom:none}
    #parecer-pop .lista .item:hover{background:#eef4fc}
    #parecer-pop .lista .vazio{padding:10px;font-size:12px;color:#9aa0a6;text-align:center}
    #parecer-pop textarea{width:100%;min-height:90px;padding:9px 10px;border:1px solid #d8dee6;
      border-radius:7px;font-size:13px;font-family:inherit;resize:vertical;color:#1a2733}
    #parecer-pop textarea:focus{outline:none;border-color:#00469e;box-shadow:0 0 0 3px #e6eef8}
    #parecer-pop .acoes{display:flex;gap:8px;justify-content:flex-end;margin-top:9px}
    #parecer-pop button{font-size:13px;padding:8px 16px;border-radius:7px;cursor:pointer;border:1px solid #d8dee6;background:#fff;color:#5f6368}
    #parecer-pop button.ok{background:#00469e;border-color:#00469e;color:#fff;font-weight:600}
    #parecer-pop .dica{font-size:10px;color:#9aa0a6;margin:2px 0 8px}
  </style>`;

  const popHtml = `
  <div id="parecer-pop">
    <div class="ttl">Especificação do parecer</div>
    <input type="text" class="busca" placeholder="Buscar frase pré-configurada…">
    <div class="lista"></div>
    <div class="dica">Clique numa frase p/ inserir no texto. Você pode editar e combinar livremente.</div>
    <textarea placeholder="Texto livre — ou comece por uma frase acima."></textarea>
    <div class="acoes">
      <button type="button" class="cancelar">Cancelar</button>
      <button type="button" class="ok salvar">Salvar</button>
    </div>
  </div>`;

  // JS sem template-literals aninhados (concatenação), p/ evitar conflito de backticks.
  const js = `
  <script>
  (function(){
    var FRASES = ${FRASES};
    var pop = document.getElementById('parecer-pop');
    if(!pop) return;
    var busca = pop.querySelector('.busca');
    var lista = pop.querySelector('.lista');
    var ta    = pop.querySelector('textarea');
    var atual = null; // botão que abriu o popover

    function postParecer(fid, body, onok){
      fetch('/atb/admin/api/parecer/'+fid, {
        method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)
      }).then(function(r){return r.json();}).then(function(j){ if(j && j.ok && onok) onok(); }).catch(function(){});
    }

    function flash(el){ if(!el) return; el.style.transition='box-shadow .15s'; el.style.boxShadow='0 0 0 3px #cfead8';
      setTimeout(function(){ el.style.boxShadow='none'; }, 700); }

    // ── veredito inline ──────────────────────────────────────────────
    document.querySelectorAll('.parecer-veredito').forEach(function(sel){
      sel.addEventListener('change', function(){
        var fid = sel.getAttribute('data-fid');
        postParecer(fid, {veredito: sel.value}, function(){ flash(sel); });
      });
    });

    // ── popover de especificação ─────────────────────────────────────
    function renderLista(filtro){
      filtro = (filtro||'').toLowerCase();
      var html = '';
      FRASES.forEach(function(fr, idx){
        if(filtro && fr.toLowerCase().indexOf(filtro) === -1) return;
        var esc = fr.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
        html += '<div class="item" data-idx="'+idx+'">'+esc+'</div>';
      });
      lista.innerHTML = html || '<div class="vazio">Nenhuma frase corresponde.</div>';
    }

    function inserir(frase){
      var s = ta.selectionStart, e = ta.selectionEnd;
      var antes = ta.value.slice(0, s), depois = ta.value.slice(e);
      var sep = (antes && !/\\s$/.test(antes)) ? ' ' : '';
      ta.value = antes + sep + frase + depois;
      var pos = (antes + sep + frase).length;
      ta.focus(); ta.selectionStart = ta.selectionEnd = pos;
    }

    function abrir(btn){
      atual = btn;
      ta.value = btn.getAttribute('data-espec') || '';
      busca.value = ''; renderLista('');
      pop.style.display = 'block';
      var r = btn.getBoundingClientRect();
      var top = window.scrollY + r.bottom + 6;
      var left = window.scrollX + r.left;
      var maxLeft = window.scrollX + document.documentElement.clientWidth - pop.offsetWidth - 12;
      if(left > maxLeft) left = Math.max(window.scrollX + 8, maxLeft);
      pop.style.top = top + 'px'; pop.style.left = left + 'px';
      setTimeout(function(){ busca.focus(); }, 30);
    }

    function fechar(){ pop.style.display = 'none'; atual = null; }

    document.querySelectorAll('.parecer-espec-btn').forEach(function(btn){
      btn.addEventListener('click', function(ev){ ev.stopPropagation(); abrir(btn); });
    });

    busca.addEventListener('input', function(){ renderLista(busca.value); });
    lista.addEventListener('click', function(ev){
      var it = ev.target.closest('.item'); if(!it) return;
      inserir(FRASES[parseInt(it.getAttribute('data-idx'),10)]);
    });

    pop.querySelector('.cancelar').addEventListener('click', fechar);
    pop.querySelector('.salvar').addEventListener('click', function(){
      if(!atual) return;
      var fid = atual.getAttribute('data-fid');
      var val = ta.value.trim();
      var btn = atual;
      postParecer(fid, {especificacao: val}, function(){
        btn.setAttribute('data-espec', val);
        if(val){
          btn.classList.add('tem');
          btn.textContent = '✎ ' + (val.length>38 ? val.slice(0,38)+'…' : val);
          btn.title = val;
        } else {
          btn.classList.remove('tem');
          btn.textContent = '+ especificação';
          btn.title = 'Adicionar especificação';
        }
        fechar();
      });
    });

    // fecha ao clicar fora / Esc
    document.addEventListener('click', function(ev){
      if(pop.style.display==='block' && !pop.contains(ev.target)) fechar();
    });
    document.addEventListener('keydown', function(ev){ if(ev.key==='Escape') fechar(); });
  })();
  </script>`;

  return css + popHtml + js;
}

// ════════════════════════════════════════════════════════════════════════════
//  PÁGINA DEDICADA  — /atb/admin/parecer/:id  (linguagem clara da Complementação)
// ════════════════════════════════════════════════════════════════════════════
function paginaParecer(f, safe) {
  const s = safe || _safe;
  const nome = s(f.paciente_nome || f.paciente_nome_raw || '—');
  const atb = Array.isArray(f.atb_solicitado) ? f.atb_solicitado.join(', ')
    : (typeof f.atb_solicitado === 'string' ? f.atb_solicitado : '—');
  const ver = _veredito1(f);
  const espec = f.recomendacoes_especificacao || '';
  const emitido = f.parecer_emitido_at
    ? `<div class="ultimo">Último parecer registrado em ${new Date(f.parecer_emitido_at).toLocaleString('pt-BR')}</div>`
    : '';

  const verOpts = ['<option value="">— selecione o veredito —</option>']
    .concat(PARECER_VEREDITOS.map(v => `<option value="${s(v)}" ${ver === v ? 'selected' : ''}>${s(v)}</option>`))
    .join('');

  const especOpts = ['<option value="">— inserir frase pré-configurada —</option>']
    .concat(PARECER_ESPECIFICACOES.map((v, i) => `<option value="${i}">${s(v)}</option>`))
    .join('');

  const FRASES = JSON.stringify(PARECER_ESPECIFICACOES);

  return `<!DOCTYPE html>
<html lang="pt-BR"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Parecer · ${nome}</title>
<style>
  :root{
    --azul:#00469e; --azul-claro:#e6eef8; --azul-texto:#0c447c;
    --vermelho:#e12229; --tinta:#1a2733; --tinta-suave:#3a4654;
    --borda:#d8dee6; --campo-fundo:#fafbfc; --fundo:#f4f6f9;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
    background:var(--fundo);color:var(--tinta);font-size:14px;line-height:1.5;padding-bottom:90px}
  .cab{background:#fff;border-bottom:2px solid var(--azul);padding:14px 22px;display:flex;
    align-items:center;justify-content:space-between;gap:12px}
  .cab h1{font-size:15px;color:var(--azul)}
  .cab a{font-size:12px;color:var(--azul);text-decoration:none}
  .faixa{background:var(--azul);color:#fff;padding:11px 22px;font-size:13px;font-weight:600}
  .wrap{max-width:760px;margin:18px auto;padding:0 16px}
  .resumo{background:#fff;border:1px solid var(--borda);border-radius:10px;padding:14px 18px;margin-bottom:16px}
  .resumo .pac{font-size:16px;font-weight:700;color:var(--tinta)}
  .resumo .meta{font-size:12px;color:var(--tinta-suave);margin-top:3px}
  .resumo .atb{margin-top:8px;font-size:13px}
  .resumo .atb b{color:var(--azul-texto)}
  .ultimo{font-size:11px;color:var(--tinta-suave);margin-top:8px;padding-top:8px;border-top:1px dashed var(--borda)}
  .bloco{background:#fff;border:1px solid var(--borda);border-radius:10px;padding:16px 18px;margin-bottom:14px}
  .bloco label{display:block;font-size:12px;font-weight:700;color:var(--azul-texto);
    text-transform:uppercase;letter-spacing:.04em;margin-bottom:8px}
  .bloco select,.bloco textarea{width:100%;padding:10px 12px;border:1px solid var(--borda);
    border-radius:8px;font-size:14px;font-family:inherit;background:var(--campo-fundo);color:var(--tinta)}
  .bloco textarea{min-height:120px;resize:vertical;margin-top:8px}
  .bloco select:focus,.bloco textarea:focus{outline:none;border-color:var(--azul);background:#fff;box-shadow:0 0 0 3px var(--azul-claro)}
  .bloco .dica{font-size:11px;color:var(--tinta-suave);margin-top:6px}
  .rodape{position:fixed;bottom:0;left:0;right:0;background:#fff;border-top:1px solid var(--borda);
    padding:12px 22px;display:flex;align-items:center;gap:12px;justify-content:flex-end;z-index:30}
  .salvar{background:var(--azul);color:#fff;border:none;border-radius:8px;padding:11px 26px;
    font-size:14px;font-weight:600;cursor:pointer}
  .salvar:disabled{opacity:.45;cursor:not-allowed}
  .toast{position:fixed;top:16px;left:50%;transform:translateX(-50%);padding:11px 20px;border-radius:8px;
    font-size:13px;font-weight:600;z-index:50;display:none}
  .toast.ok{background:#1a6b3a;color:#fff} .toast.erro{background:var(--vermelho);color:#fff}
</style></head>
<body>
  <div class="cab">
    <h1>Parecer SCIH</h1>
    <a href="/atb/admin/fichas/${f.id}">← voltar à ficha</a>
  </div>
  <div class="faixa">Veredito e especificação da recomendação</div>
  <div class="wrap">
    <div class="resumo">
      <div class="pac">${nome}</div>
      <div class="meta">Pront. ${s(f.prontuario || '—')} · ${s(f.setor || '—')}${f.leito ? ' · Leito ' + s(f.leito) : ''}${f.instituicao ? ' · ' + s(f.instituicao) : ''}</div>
      <div class="atb"><b>ATB:</b> ${s(atb)}</div>
      ${emitido}
    </div>

    <div class="bloco">
      <label>Veredito</label>
      <select id="veredito">${verOpts}</select>
    </div>

    <div class="bloco">
      <label>Especificação</label>
      <select id="insere">${especOpts}</select>
      <div class="dica">Escolher uma frase acima a INSERE no texto abaixo (no ponto do cursor). Edite, combine ou escreva do zero.</div>
      <textarea id="especificacao" placeholder="Texto livre — ou comece por uma frase pré-configurada.">${s(espec)}</textarea>
    </div>
  </div>

  <div class="rodape">
    <button class="salvar" id="btnSalvar">Salvar parecer</button>
  </div>
  <div class="toast" id="toast"></div>

<script>
(function(){
  var FRASES = ${FRASES};
  var ta = document.getElementById('especificacao');
  var insere = document.getElementById('insere');
  var veredito = document.getElementById('veredito');
  var btn = document.getElementById('btnSalvar');
  var toast = document.getElementById('toast');

  insere.addEventListener('change', function(){
    if(insere.value === '') return;
    var frase = FRASES[parseInt(insere.value,10)];
    var sst = ta.selectionStart, sen = ta.selectionEnd;
    var antes = ta.value.slice(0,sst), depois = ta.value.slice(sen);
    var sep = (antes && !/\\s$/.test(antes)) ? ' ' : '';
    ta.value = antes + sep + frase + depois;
    var pos = (antes+sep+frase).length;
    ta.focus(); ta.selectionStart = ta.selectionEnd = pos;
    insere.value = '';
  });

  function showToast(msg, ok){
    toast.textContent = msg; toast.className = 'toast ' + (ok?'ok':'erro');
    toast.style.display='block'; setTimeout(function(){ toast.style.display='none'; }, 2200);
  }

  btn.addEventListener('click', function(){
    btn.disabled = true;
    fetch('/atb/admin/api/parecer/${f.id}', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ veredito: veredito.value, especificacao: ta.value.trim() })
    }).then(function(r){return r.json();}).then(function(j){
      btn.disabled = false;
      if(j && j.ok) showToast('Parecer salvo.', true);
      else showToast((j && j.error) || 'Falha ao salvar.', false);
    }).catch(function(){ btn.disabled=false; showToast('Erro de rede.', false); });
  });
})();
</script>
</body></html>`;
}

// ════════════════════════════════════════════════════════════════════════════
//  ROTAS
// ════════════════════════════════════════════════════════════════════════════
export function registerParecerEditRoutes(app, pool, adminRequired) {

  // ── Save (usado pela grade inline E pela página) ─────────────────────────
  // body: { veredito?: string, especificacao?: string }  — só atualiza o que vier.
  app.post('/atb/admin/api/parecer/:id', adminRequired, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const body = req.body || {};
    const sets = [], vals = [];
    let i = 1;

    if (Object.prototype.hasOwnProperty.call(body, 'veredito')) {
      const v = (body.veredito || '').trim();
      if (v && !PARECER_VEREDITOS.includes(v)) {
        return res.status(400).json({ ok: false, error: 'veredito inválido' });
      }
      sets.push(`recomendacao_scih = $${i++}::jsonb`);
      vals.push(JSON.stringify(v ? [v] : []));
    }

    if (Object.prototype.hasOwnProperty.call(body, 'especificacao')) {
      const t = (body.especificacao || '').trim();
      sets.push(`recomendacoes_especificacao = $${i++}`);
      vals.push(t || null);
    }

    if (!sets.length) return res.status(400).json({ ok: false, error: 'nada a salvar' });

    // rastreabilidade
    sets.push(`parecer_emitido_por = $${i++}`); vals.push(req.user?.id || null);
    sets.push(`parecer_emitido_at = now()`);
    sets.push(`updated_at = now()`);

    vals.push(id);
    try {
      const r = await pool.query(
        `UPDATE atb_fichas SET ${sets.join(', ')} WHERE id = $${i}`, vals);
      if (!r.rowCount) return res.status(404).json({ ok: false, error: 'ficha não encontrada' });
      res.json({ ok: true });
    } catch (e) {
      console.error('[atb] save parecer error:', e.message);
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // ── Página dedicada de emissão de parecer ────────────────────────────────
  app.get('/atb/admin/parecer/:id', adminRequired, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const { rows: [f] } = await pool.query(`
        SELECT f.id, f.paciente_nome, f.paciente_nome_raw, f.prontuario, f.setor, f.leito,
               f.atb_solicitado, f.recomendacao_scih, f.recomendacoes_especificacao,
               f.parecer_emitido_at, i.sigla AS instituicao
        FROM atb_fichas f
        LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
        WHERE f.id = $1
      `, [id]);
      if (!f) return res.status(404).send('Ficha não encontrada');
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(paginaParecer(f, _safe));
    } catch (e) {
      console.error('[atb] parecer page error:', e.message);
      res.status(500).send('Erro: ' + _safe(e.message));
    }
  });
}
