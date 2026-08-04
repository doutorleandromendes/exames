// atb-tags-routes.js
// ════════════════════════════════════════════════════════════════════════════
//  TAGS CLÍNICAS DA FICHA — vocabulário aberto, construído pelo uso.
//
//  Dr. Leandro já dá veredito em todas as fichas. Este módulo pendura um campo
//  de tags nesse fluxo: ele digita ou escolhe, e o vocabulário cresce sozinho.
//  Quando houver massa suficiente, esses rótulos viram o padrão-ouro que treina
//  e valida o classificador — e aí sim o backfill retrospectivo.
//
//  ── NÃO HÁ TABELA DE VOCABULÁRIO ──────────────────────────────────────────
//  O vocabulário É o conjunto de valores em uso:
//      SELECT t, count(*) FROM atb_fichas f, jsonb_array_elements_text(f.tags) t
//  Criar tag = usar tag. Tabela separada sairia de sincronia com o uso na
//  primeira vez que alguém apagasse a última ficha de uma tag.
//  Começa VAZIO, de propósito: tentativa anterior de derivar o vocabulário de
//  clustering falhou porque os ids inventados não eram o que o revisor
//  escreveria, e o modelo ancora no id tanto quanto na definição.
//
//  ── NORMALIZAÇÃO É O RISCO PRINCIPAL ──────────────────────────────────────
//  Entrada livre gera "sepse neonatal precoce" / "sepse neo precoce" / "SNP"
//  como três tags distintas, e em alguns meses nada tabula. Por isso TODO valor
//  passa por `normalizar()` no SERVIDOR (cliente não é confiável): minúscula,
//  sem acento, espaço→_, só [a-z0-9_]. O widget mostra a forma normalizada
//  antes de gravar, para não haver surpresa.
//
//  ── FORA DO ESPELHO JOTFORM ───────────────────────────────────────────────
//  `tags` NÃO entra em CAMPOS_PARECER: é campo novo, sem contraparte no
//  JotForm, e espelhar levantaria erro de campo inexistente.
//
//  Integração (mesmo padrão de registerFichaCardRoutes):
//    import { registerTagsRoutes, tagsAssets } from './atb-tags-routes.js';
//    // em registerAtbRoutes:  registerTagsRoutes(app, pool, adminRequired);
//    // no editor de parecer:  ${tagsAssets()} + <div id="atb-tags"></div>
// ════════════════════════════════════════════════════════════════════════════

const ACENTOS = 'áàâãäéèêëíìîïóòôõöúùûüçñ';
const LIMPOS  = 'aaaaaeeeeiiiiooooouuuucn';

/** Forma canônica de uma tag. Fonte única — usada no salvar e na busca. */
export function normalizar(bruto) {
  let t = String(bruto || '').trim().toLowerCase();
  t = t.replace(/[áàâãäéèêëíìîïóòôõöúùûüçñ]/g, c => LIMPOS[ACENTOS.indexOf(c)]);
  t = t.replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').replace(/_{2,}/g, '_');
  return t.slice(0, 60);
}

/** Migração idempotente de boot, no padrão dos demais módulos. */
async function migrar(pool) {
  await pool.query(
    `ALTER TABLE atb_fichas ADD COLUMN IF NOT EXISTS tags JSONB DEFAULT '[]'::jsonb`);
  // jsonb_path_ops: menor e mais rápido que o padrão para o operador @>, que é
  // o único que a grade e o NL→SQL vão usar.
  await pool.query(
    `CREATE INDEX IF NOT EXISTS atb_fichas_tags_gin
       ON atb_fichas USING GIN (tags jsonb_path_ops)`);
}

/** Vocabulário conhecido, mais usado primeiro. Fonte única — autocomplete do
 *  widget, editor de regras e filtro da grade leem daqui.
 *
 *  DUAS FONTES: a tag vive em atb_fichas.tags E em atb_triagem_regras.acoes.
 *  Tag recém-criada numa regra ainda não está em ficha nenhuma (o backfill não
 *  rodou), e lendo só as fichas ela sumia do autocomplete — não dava para
 *  reaproveitá-la numa segunda regra. Por isso o FULL OUTER JOIN.
 *
 *  comRegras=false para o filtro da GRADE: lá, oferecer tag com zero fichas é
 *  ruído, porque a opção filtraria para nada. */
export async function vocabularioTags(pool, { q = '', limite = 200, comRegras = true } = {}) {
  const alvo = normalizar(q);
  const r = await pool.query(
    `WITH da_ficha AS (
       SELECT t AS tag, count(*)::int AS n
         FROM atb_fichas f, jsonb_array_elements_text(COALESCE(f.tags,'[]'::jsonb)) t
        WHERE f.deletado_em IS NULL
        GROUP BY t
     ), da_regra AS (
       SELECT DISTINCT t AS tag
         FROM atb_triagem_regras r,
              jsonb_array_elements_text(
                CASE WHEN jsonb_typeof(r.acoes->'tags') = 'array'
                     THEN r.acoes->'tags' ELSE '[]'::jsonb END) t
        WHERE $3::boolean
     )
     SELECT COALESCE(a.tag, b.tag) AS tag, COALESCE(a.n, 0) AS n
       FROM da_ficha a FULL OUTER JOIN da_regra b ON b.tag = a.tag
      WHERE ($1 = '' OR COALESCE(a.tag, b.tag) LIKE '%' || $1 || '%')
      ORDER BY COALESCE(a.n, 0) DESC, 1 ASC
      LIMIT $2`, [alvo, limite, comRegras]);
  return r.rows;
}

export function registerTagsRoutes(app, pool, adminRequired) {
  migrar(pool).catch(e => console.error('[atb] migrar tags:', e.message));

  // ── Vocabulário: o que já existe, mais usado primeiro ────────────────────
  // Vocabulário é COMPARTILHADO entre instituições de propósito — o revisor é
  // um só, e dois vocabulários divergiriam sem ninguém decidir que deviam.
  app.get('/atb/admin/api/tags', adminRequired, async (req, res) => {
    try {
      const tags = await vocabularioTags(pool, { q: req.query.q || '', limite: 60 });
      res.json({ ok: true, tags });
    } catch (e) {
      console.error('[atb] vocabulário tags:', e.message);
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // ── Tags da ficha ────────────────────────────────────────────────────────
  app.get('/atb/admin/api/ficha/:id/tags', adminRequired, async (req, res) => {
    try {
      const r = await pool.query(
        `SELECT COALESCE(tags, '[]'::jsonb) AS tags FROM atb_fichas WHERE id = $1`,
        [parseInt(req.params.id, 10)]);
      if (!r.rowCount) return res.status(404).json({ ok: false });
      res.json({ ok: true, tags: r.rows[0].tags });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  app.post('/atb/admin/api/ficha/:id/tags', adminRequired, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const brutas = Array.isArray(req.body?.tags) ? req.body.tags : null;
    if (!brutas) return res.status(400).json({ ok: false, error: 'tags ausente' });
    // Normaliza no servidor e deduplica preservando a ordem de entrada.
    const tags = [...new Set(brutas.map(normalizar).filter(Boolean))].slice(0, 20);
    try {
      const r = await pool.query(
        `UPDATE atb_fichas
            SET tags = $1::jsonb, updated_at = now()
          WHERE id = $2 AND deletado_em IS NULL`,
        [JSON.stringify(tags), id]);
      if (!r.rowCount) return res.status(404).json({ ok: false, error: 'ficha não encontrada' });
      res.json({ ok: true, tags });
    } catch (e) {
      console.error('[atb] salvar tags:', e.message);
      res.status(500).json({ ok: false, error: e.message });
    }
  });
}

// ── Widget (CSS + JS), injetado uma vez na página ──────────────────────────
export function tagsAssets() {
  return `
<style>
  .atbtg{margin-top:10px}
  .atbtg .chips{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:6px}
  .atbtg .chip{display:inline-flex;align-items:center;gap:6px;background:#eef3f2;
    border:1px solid #cfdcd9;border-radius:12px;padding:3px 6px 3px 10px;font-size:13px}
  .atbtg .chip b{font-weight:500;font-family:ui-monospace,Menlo,monospace;font-size:12px}
  .atbtg .chip button{border:0;background:none;cursor:pointer;font-size:15px;
    line-height:1;color:#777;padding:0 2px}
  .atbtg .chip button:hover{color:#a33}
  .atbtg .campo{position:relative}
  .atbtg input{width:100%;padding:7px 9px;font:inherit;font-size:14px;
    border:1px solid #ccc;border-radius:4px;box-sizing:border-box}
  .atbtg .sug{position:absolute;z-index:40;left:0;right:0;top:100%;background:#fff;
    border:1px solid #ccc;border-top:0;max-height:220px;overflow:auto;display:none}
  .atbtg .sug.on{display:block}
  .atbtg .sug div{padding:6px 9px;cursor:pointer;font-size:13.5px;display:flex;
    justify-content:space-between;gap:10px}
  .atbtg .sug div:hover,.atbtg .sug div.sel{background:#eef3f2}
  .atbtg .sug .n{color:#888;font-size:12px;font-family:ui-monospace,Menlo,monospace}
  .atbtg .sug .nova{color:#0f6d63;font-style:italic}
  .atbtg .dica{font-size:11.5px;color:#888;margin-top:4px;min-height:14px}
</style>
<script>
window.ATBTags = (function(){
  var A='áàâãäéèêëíìîïóòôõöúùûüçñ', L='aaaaaeeeeiiiiooooouuuucn';
  // Mesma regra do servidor. Aqui é só para MOSTRAR a forma final antes de
  // gravar — quem decide continua sendo o servidor.
  function norm(s){
    s=String(s||'').trim().toLowerCase().replace(/[áàâãäéèêëíìîïóòôõöúùûüçñ]/g,
      function(c){return L[A.indexOf(c)];});
    return s.replace(/[^a-z0-9]+/g,'_').replace(/^_+|_+$/g,'')
            .replace(/_{2,}/g,'_').slice(0,60);
  }
  // fichaId  -> grava no endpoint da ficha
  // onChange -> modo LIVRE: devolve a lista e não grava nada. Usado no editor
  //             de regras, onde a tag é parte da ação e só persiste com a regra.
  function montar(el, fichaId, opts){
    opts = opts || {};
    var tags = (opts.inicial || []).slice(), voc=[], sel=-1;
    var livre = typeof opts.onChange === 'function';
    el.className='atbtg';
    el.innerHTML='<div class="chips"></div>'
      +'<div class="campo"><input placeholder="digite e Enter — ou escolha uma existente" '
      +'autocomplete="off"><div class="sug"></div></div><div class="dica"></div>';
    var chips=el.querySelector('.chips'), inp=el.querySelector('input'),
        sug=el.querySelector('.sug'), dica=el.querySelector('.dica');

    function pintar(){
      chips.innerHTML = tags.length ? tags.map(function(t,i){
        return '<span class="chip"><b>'+t+'</b><button data-i="'+i+'" title="remover">×</button></span>';
      }).join('') : '<span style="font-size:12.5px;color:#999">nenhuma</span>';
    }
    function salvar(){
      if(livre){ opts.onChange(tags.slice()); return; }
      fetch('/atb/admin/api/ficha/'+fichaId+'/tags',
        {method:'POST',headers:{'Content-Type':'application/json'},
         body:JSON.stringify({tags:tags})})
        .then(function(r){return r.json();})
        .then(function(d){ if(d && d.ok){ tags=d.tags; pintar();
          dica.textContent='salvo'; setTimeout(function(){dica.textContent='';},1200); }
          else dica.textContent='erro ao salvar'; })
        .catch(function(){ dica.textContent='erro de rede'; });
    }
    function add(t){
      t=norm(t); if(!t) return;
      if(tags.indexOf(t)<0){ tags.push(t); pintar(); salvar(); }
      inp.value=''; sug.classList.remove('on'); sel=-1;
    }
    chips.addEventListener('click',function(e){
      var b=e.target.closest('button'); if(!b) return;
      tags.splice(+b.dataset.i,1); pintar(); salvar();
    });

    var timer=null;
    function buscar(){
      var q=inp.value.trim();
      fetch('/atb/admin/api/tags?q='+encodeURIComponent(q))
        .then(function(r){return r.json();})
        .then(function(d){
          voc=(d&&d.tags?d.tags:[]).filter(function(x){return tags.indexOf(x.tag)<0;});
          var n=norm(q), html=voc.map(function(x){
            return '<div data-t="'+x.tag+'"><span>'+x.tag+'</span><span class="n">'+x.n+'</span></div>';
          }).join('');
          // Criar nova só aparece se de fato não existir com a forma normalizada.
          if(n && !voc.some(function(x){return x.tag===n;}))
            html+='<div data-t="'+n+'"><span class="nova">criar «'+n+'»</span></div>';
          sug.innerHTML=html; sug.classList.toggle('on', !!html); sel=-1;
          dica.textContent = (n && n!==q.toLowerCase()) ? 'será gravada como: '+n : '';
        });
    }
    inp.addEventListener('input',function(){ clearTimeout(timer); timer=setTimeout(buscar,140); });
    inp.addEventListener('focus',buscar);
    inp.addEventListener('blur',function(){ setTimeout(function(){sug.classList.remove('on');},180); });
    sug.addEventListener('mousedown',function(e){
      var d=e.target.closest('div[data-t]'); if(d){ e.preventDefault(); add(d.dataset.t); }
    });
    inp.addEventListener('keydown',function(e){
      var itens=sug.querySelectorAll('div[data-t]');
      if(e.key==='ArrowDown'||e.key==='ArrowUp'){
        e.preventDefault(); if(!itens.length) return;
        sel = e.key==='ArrowDown' ? Math.min(sel+1,itens.length-1) : Math.max(sel-1,0);
        itens.forEach(function(x,i){x.classList.toggle('sel',i===sel);});
        itens[sel].scrollIntoView({block:'nearest'});
      } else if(e.key==='Enter'){
        e.preventDefault();
        add(sel>=0 && itens[sel] ? itens[sel].dataset.t : inp.value);
      } else if(e.key==='Escape'){ sug.classList.remove('on'); sel=-1; }
    });

    pintar();
    if(!livre){
      fetch('/atb/admin/api/ficha/'+fichaId+'/tags')
        .then(function(r){return r.json();})
        .then(function(d){ if(d&&d.ok){ tags=d.tags||[]; pintar(); } });
    }
  }
  return { montar: montar, norm: norm };
})();
</script>`;
}
