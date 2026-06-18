// ════════════════════════════════════════════════════════════════════════════
//  atb-form-test-routes.js — harness de testes de preenchimento da ficha
//  /atb/admin/form-test : carrega o schema vivo, COLETA as regras condicionais
//  vigentes (cond de seção, cond de campo, requiredCond) e gera UM CASO POR REGRA,
//  construindo a atribuição que satisfaz aquela condição (satisfazer()) — disparando
//  a regra isoladamente — e depois itera em dry-run preenchendo o que o validador
//  do servidor acusar, até passar. Mais dois casos-base: mínimo e máximo.
//  Opcional: insert real + hard-delete dos dummies (pac_nome "ZZ_TESTE…").
//
//  Wire em registerAtbRoutes:
//    import { registerFormTestRoutes } from './atb-form-test-routes.js';
//    registerFormTestRoutes(app, pool, adminRequired);
//  (depende de POST /atb/api/fichas aceitar { dryrun:true }.)
// ════════════════════════════════════════════════════════════════════════════

export function registerFormTestRoutes(app, pool, adminRequired) {

  app.post('/atb/admin/api/form-test/hard-delete', adminRequired, async (req, res) => {
    try {
      const ids = ((req.body && req.body.ids) || []).map(Number).filter(Number.isFinite);
      const deleted = [];
      for (const id of ids) {
        const { rows: [f] } = await pool.query(
          'SELECT id, paciente_nome FROM atb_fichas WHERE id=$1', [id]);
        if (!f) continue;
        if (!/^ZZ_TESTE/.test(String(f.paciente_nome || ''))) continue; // trava: só dummies
        await pool.query('DELETE FROM atb_avaliacoes WHERE ficha_id=$1', [id]);
        await pool.query('DELETE FROM atb_fichas WHERE id=$1', [id]);
        deleted.push(id);
      }
      res.json({ ok: true, deleted });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.get('/atb/admin/form-test', adminRequired, (req, res) => {
    res.type('html').send(PAGINA);
  });
}

const PAGINA = `<!doctype html><html lang="pt-br"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Teste de preenchimento — ATB</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:920px;margin:24px auto;padding:0 16px;color:#202124}
  h1{font-size:20px;margin:0 0 4px} .sub{color:#5f6368;font-size:13px;margin:0 0 16px}
  .bar{display:flex;align-items:center;gap:14px;margin:14px 0;flex-wrap:wrap}
  button{background:#2bb673;color:#fff;border:0;border-radius:8px;padding:9px 18px;font-size:14px;cursor:pointer}
  button:disabled{opacity:.5;cursor:default}
  label.chk{display:flex;align-items:center;gap:6px;font-size:13px;color:#3a3a3a}
  .inst{font-size:13px;color:#5f6368}
  .hdr{font-size:12px;color:#5f6368;margin:10px 0;padding:8px 12px;background:#f4f6f9;border-radius:8px}
  #sum{font-size:13px;margin:10px 0;font-weight:600}
  #out{margin-top:8px;border:1px solid #e0e2e6;border-radius:10px;overflow:hidden}
  .row{padding:9px 14px;border-top:1px solid #eef0f2;font-size:13px}
  .row:first-child{border-top:0}
  .row.ok{background:#f5fbf7} .row.no{background:#fdf2f2}
  .row b{font-size:13px} .tag{font-size:11px;color:#80868b}
  .pass{color:#1a8a52;font-weight:600} .fail{color:#c0392b;font-weight:600}
  .det{color:#5f6368;font-size:12px;margin-top:3px;word-break:break-word} code{background:#eef0f2;padding:1px 5px;border-radius:4px;font-size:11px}
  .del{padding:10px 14px;color:#5f6368;font-size:12px;background:#fafbfc;border-top:1px solid #eef0f2}
  .fim{padding:10px 14px;color:#80868b;font-size:12px;text-align:center}
  .err{padding:12px 14px;color:#c0392b}
  .warn{background:#fff8e6;border:1px solid #f0d9a0;border-radius:8px;padding:10px 12px;font-size:12px;color:#7a5b00;margin:10px 0}
</style></head><body>
<h1>Teste de preenchimento da ficha</h1>
<p class="sub">Lê as regras condicionais vigentes do schema e gera <b>um caso por regra</b> (disparando-a isolada), mais mínimo e máximo. Cada caso é enviado em <b>dry-run</b>; o que o servidor acusar como faltando é preenchido e re-enviado, até passar. Em dry-run nada é gravado.</p>
<div class="bar">
  <span class="inst">Instituição: <b>HUSF</b></span>
  <label class="chk"><input type="checkbox" id="real"> Insert real + hard-delete dos dummies</label>
  <button id="run">▶ Rodar testes</button>
</div>
<div id="warn" class="warn" style="display:none">Modo <b>real</b>: cada caso vira um insert (pac_nome “ZZ_TESTE…”) e é apagado em seguida. Com muitas regras, são muitos inserts/deletes.</div>
<div id="sum"></div>
<div id="out"></div>
<script>
(function(){
  var INST='HUSF';
  var out=document.getElementById('out'), btn=document.getElementById('run');
  var real=document.getElementById('real'), warn=document.getElementById('warn'), sum=document.getElementById('sum');
  real.addEventListener('change',function(){ warn.style.display=real.checked?'block':'none'; });
  function esc(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;'); }
  function log(h){ out.insertAdjacentHTML('beforeend', h); }

  function fieldMap(schema){ var m={}; (schema.secoes||[]).forEach(function(sec){ (sec.campos||[]).forEach(function(c){ if(c.key) m[c.key]=c; }); }); return m; }
  function opt(c){ return ((c&&c.options)||[]).filter(function(o){ return o && String(o).trim(); }); }
  function simLike(c){ var o=opt(c); for(var i=0;i<o.length;i++){ if(/^sim/i.test(o[i])) return o[i]; } return o[0]; }
  function fill(c){
    if(!c) return 'preenchido';
    var t=c.type, o=opt(c);
    if(t==='select'||t==='radio') return o[0]||'X';
    if(t==='checkbox') return o.length?[o[0]]:[];
    if(t==='date') return '2026-06-01';
    if(t==='number') return '1';
    if(t==='crm') return '999999';
    if(t==='matrix'){ var row={}; (c.colunas||[]).forEach(function(col){ var co=(col.options||[]).filter(Boolean);
      row[col.key]= col.type==='select'?(co[0]||'X'): col.type==='date'?'2026-06-01': col.type==='check'?true:'X'; }); return [row]; }
    var base=(c.validate==='nome_completo')?'Teste Da Silva':'Preenchimento automatico de teste';
    while(c.minChars && base.length < c.minChars) base += ' xxxxx';
    return base;
  }

  // ── regras vigentes ────────────────────────────────────────────────────────
  function coletarRegras(schema){
    var r=[];
    (schema.secoes||[]).forEach(function(sec){
      if(sec.cond) r.push({tipo:'seção visível', alvo:(sec.titulo||sec.id||'?'), cond:sec.cond});
      (sec.campos||[]).forEach(function(c){
        if(c.cond)         r.push({tipo:'campo visível',      alvo:(c.label||c.key), cond:c.cond});
        if(c.requiredCond) r.push({tipo:'obrigatório condic.', alvo:(c.label||c.key), cond:c.requiredCond});
      });
    });
    return r;
  }
  function condResumo(cond){
    if(!cond) return '(sem condição)';
    if(cond.all) return 'TODAS(' + cond.all.map(condResumo).join(' & ') + ')';
    if(cond.any) return 'QUALQUER(' + cond.any.map(condResumo).join(' | ') + ')';
    var sem=(cond.op==='filled'||cond.op==='not_filled');
    var val=Array.isArray(cond.valor)?('['+cond.valor.join(',')+']'):cond.valor;
    return cond.campo+' '+cond.op+(sem?'':(' '+val));
  }
  // devolve a atribuição {campo:valor} que torna a cond verdadeira
  function satisfazer(cond, map){
    if(!cond) return {};
    if(cond.all) return cond.all.reduce(function(a,c){ return Object.assign(a, satisfazer(c,map)); }, {});
    if(cond.any) return cond.any.length ? satisfazer(cond.any[0], map) : {};
    var campo=cond.campo, valor=cond.valor, o={};
    switch(cond.op){
      case 'eq':               o[campo]=valor; break;
      case 'in':               o[campo]=Array.isArray(valor)?valor[0]:valor; break;
      case 'contains':         o[campo]=[valor]; break;
      case 'contains_any':     o[campo]=Array.isArray(valor)?[valor[0]]:[valor]; break;
      case 'text_contains_any':o[campo]=Array.isArray(valor)?String(valor[0]):String(valor); break;
      case 'filled':           o[campo]= map[campo]?fill(map[campo]):'preenchido'; break;
      case 'neq':              if(valor==='') o[campo]='preenchido'; break; // senão, não-setado já satisfaz
      case 'not_filled':       break;                                       // não-setado satisfaz
      default: break;
    }
    return o;
  }

  function postFicha(d, dry){
    return fetch('/atb/api/fichas',{ method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ instituicao:INST, dados:d, dryrun:!!dry }) })
      .then(function(r){ return r.json().then(function(j){ return {status:r.status, ok:r.ok, j:j}; })
        .catch(function(){ return {status:r.status, ok:r.ok, j:{}}; }); });
  }
  // itera em dry-run preenchendo as faltas que o servidor acusar, até passar
  function resolver(map, seed, nome){
    var d=Object.assign({}, seed);
    d.pac_nome='ZZ_TESTE_'+nome+'_'+Date.now();
    d.prontuario=d.prontuario||'9999999'; d.crm=d.crm||'999999'; d.prescritor_nome=d.prescritor_nome||'Teste Da Silva';
    var step=0, preenchidos=[];
    function loop(){
      step++;
      return postFicha(d, true).then(function(res){
        if(res.ok) return {ok:true, iters:step, d:d, preenchidos:preenchidos};
        var campos=(res.j && res.j.campos)||[];
        if(!campos.length || step>=12)
          return {ok:false, iters:step, d:d, preenchidos:preenchidos, erro:(res.j&&(res.j.error||res.j.erro))||('HTTP '+res.status), faltas:campos};
        campos.forEach(function(k){ d[k]=fill(map[k]); if(preenchidos.indexOf(k)<0) preenchidos.push(k); });
        return loop();
      });
    }
    return loop();
  }
  function linha(nome, sub, ok, iters, msg){
    return '<div class="row '+(ok?'ok':'no')+'"><b>'+esc(nome)+'</b> '+(sub?('<span class="tag">— <code>'+esc(sub)+'</code></span>'):'')+
      ' · <span class="'+(ok?'pass':'fail')+'">'+(ok?'PASS':'FAIL')+'</span> · '+iters+'×'+
      '<div class="det">'+esc(msg)+'</div></div>';
  }

  function run(){
    out.innerHTML=''; sum.textContent=''; btn.disabled=true;
    var doReal=real.checked, ids=[], nPass=0, nFail=0;
    fetch('/atb/api/form-schema?inst='+INST).then(function(r){return r.json();}).then(function(schema){
      var map=fieldMap(schema);
      var regras=coletarRegras(schema);
      var casos=[];
      casos.push({nome:'Mínimo (sem triggers)', sub:'', seed:{}, key:'min'});
      var maxSeed={}; Object.keys(map).forEach(function(k){ var c=map[k];
        if(c.type==='radio'||c.type==='select') maxSeed[k]=simLike(c);
        else if(c.type==='checkbox'){ var o=opt(c); if(o.length) maxSeed[k]=[o[0]]; } });
      casos.push({nome:'Máximo (todas as opções)', sub:'', seed:maxSeed, key:'max'});
      regras.forEach(function(rg,i){ casos.push({nome:rg.tipo+': '+rg.alvo, sub:condResumo(rg.cond), seed:satisfazer(rg.cond,map), key:'r'+i}); });

      log('<div class="hdr">'+regras.length+' regra(s) condicional(is) no schema · '+casos.length+' caso(s): mínimo + máximo + 1 por regra'+(doReal?' · modo REAL (insert+delete)':' · dry-run')+'</div>');

      var chain=Promise.resolve();
      casos.forEach(function(caso){
        chain=chain.then(function(){
          return resolver(map, Object.assign({},caso.seed), caso.key).then(function(rr){
            var det = rr.ok
              ? ('OK em dry-run' + (rr.preenchidos.length?(' · preencheu: '+rr.preenchidos.join(', ')):' · nada extra'))
              : ('FALHOU: '+rr.erro + (rr.faltas&&rr.faltas.length?(' · ainda faltam: '+rr.faltas.join(', ')):''));
            if(rr.ok) nPass++; else nFail++;
            if(rr.ok && doReal){
              return postFicha(rr.d, false).then(function(ins){
                if(ins.ok && ins.j && ins.j.id){ ids.push(ins.j.id); log(linha(caso.nome, caso.sub, true, rr.iters, det+' · insert real id '+ins.j.id)); }
                else log(linha(caso.nome, caso.sub, false, rr.iters, det+' · MAS insert real falhou: '+esc((ins.j&&(ins.j.error||ins.j.erro))||('HTTP '+ins.status))));
              });
            }
            log(linha(caso.nome, caso.sub, rr.ok, rr.iters, det));
          });
        });
      });
      chain.then(function(){
        if(doReal && ids.length){
          return fetch('/atb/admin/api/form-test/hard-delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids:ids})})
            .then(function(r){return r.json();}).then(function(j){ log('<div class="del">Hard-delete dos dummies: '+esc((j.deleted||[]).join(', ')||'nenhum')+'</div>'); })
            .catch(function(e){ log('<div class="del">Falha no hard-delete: '+esc(e.message)+' (ids: '+ids.join(', ')+')</div>'); });
        }
      }).then(function(){
        btn.disabled=false;
        sum.innerHTML = '<span class="pass">'+nPass+' PASS</span> · <span class="'+(nFail?'fail':'tag')+'">'+nFail+' FAIL</span>';
        log('<div class="fim">— fim —</div>');
      });
    }).catch(function(e){ btn.disabled=false; log('<div class="err">Erro ao carregar schema: '+esc(e.message)+'</div>'); });
  }
  btn.addEventListener('click', run);
})();
</script></body></html>`;
