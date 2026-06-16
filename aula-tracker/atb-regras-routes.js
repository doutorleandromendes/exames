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
import { avaliaCond, contextoFicha } from './atb-triagem-regras.js';

const IRAS_VALORES = ['PAV','PAV/EVA','IPCSLab','IPCSClin','ITU','ISC','(HD)ILAV','(HD)ICS',
  '(HD)Bact','HD_Bact_FAV','HD_Bact_CDL','HD_Bact_PC','HD_ILAV_FAV','HD_ILAV_CDL','HD_ILAV_PC',
  'CDI','Onco_Bact','Sem dados','Descartado','Repetida'];

// Catálogo de campos (chave = COLUNA DO BANCO). tipo: select|multi|bool|numero|texto
const CAMPOS = [
  { key:'setor', label:'Setor', tipo:'select', opcoes:['PS','EPM','Cuidados Intermediários','Psiquiatria','Apartamento','Oncologia','Clínica Cirúrgica','Semi','Hemodiálise','Pediatria','UTI','UTI Neo / Infantil','UTI C','Ginecologia/Obstetrícia','Clínica Médica'] },
  { key:'tipo_terapia', label:'Tipo de uso', tipo:'select', opcoes:['Empírica','Guiada por cultura','Profilaxia cirúrgica'] },
  { key:'foco_infeccao', label:'Foco de infecção', tipo:'select', opcoes:['Corrente sanguínea (bacteremia)','Pneumonia','Infecção do trato urinário','Infecção do sítio cirúrgico','Meningite/Encefalite','Abdominal','Osteoarticular','Pele/Partes moles','Neutropenia Febril'] },
  { key:'equipe_responsavel', label:'Equipe responsável', tipo:'select', opcoes:['Cx Geral','Proctologia','Urologia','Ortopedia','Ginecologia / Obstetricia','Otorrino','NCR','Clínica Médica','Nefrologia','Cardiologia','Pediatria'] },
  { key:'atb_solicitado', label:'ATB solicitado', tipo:'multi', opcoes:['Cefepime','Ceftriaxone','Fosfomicina','Anfotericina B','Daptomicina','Tigeciclina','Micafungina','Meropenem','Piperacilina/Tazobactam','Vancomicina','Teicoplanina','Polimixina B','Polimixina E (colestimetato)','Amicacina','Gentamicina','NÃO PADRONIZADO'] },
  { key:'comorbidades', label:'Comorbidades', tipo:'multi', opcoes:['DM','Cancer','IRC','Insuficiência cardíaca','DPOC','Cirrose','Institucionalizado','Uso crônico de imunossupressor (corticosteróides, por ex)','HIV/AIDS'] },
  { key:'dispositivos_invasivos', label:'Dispositivos invasivos', tipo:'multi', opcoes:[] },
  { key:'sepse', label:'Sepse', tipo:'bool' },
  { key:'gestante', label:'Gestante', tipo:'bool' },
  { key:'lactante', label:'Lactante', tipo:'bool' },
  { key:'dialise', label:'Diálise', tipo:'bool' },
  { key:'faz_quimio', label:'Faz quimioterapia', tipo:'bool' },
  { key:'cateter_quimio', label:'Cateter de longa permanência', tipo:'bool' },
  { key:'uso_atb_7d', label:'Uso de ATB nos últimos 7d', tipo:'bool' },
  { key:'oxacilina_associacao', label:'Oxacilina em associação', tipo:'bool' },
  { key:'historia_clinica', label:'História clínica (texto livre)', tipo:'texto' },
  { key:'cirurgia', label:'Cirurgia (texto livre)', tipo:'texto' },
  { key:'idade_dias', label:'Idade (dias)', tipo:'numero' },
  { key:'idade_meses', label:'Idade (meses)', tipo:'numero' },
  { key:'idade_anos', label:'Idade (anos)', tipo:'numero' },
  { key:'peso', label:'Peso (kg)', tipo:'numero' },
  { key:'peso_nascimento', label:'Peso ao nascer (g)', tipo:'numero' },
  { key:'altura', label:'Altura (cm)', tipo:'numero' },
  { key:'clcr', label:'ClCr (mL/min)', tipo:'numero' },
  { key:'sofa', label:'SOFA', tipo:'numero' },
  { key:'sofa_renal', label:'SOFA renal', tipo:'numero' },
  { key:'tempo_previsto', label:'Tempo previsto (dias)', tipo:'numero' },
  { key:'acesso_dialise', label:'Acesso p/ diálise', tipo:'texto' },
  { key:'acesso_quimio', label:'Acesso p/ quimio', tipo:'select', opcoes:['PICC','Portocath','Permcath/Hickman'] },
  { key:'classificacao_fratura', label:'Classificação de fratura', tipo:'texto' },
];

// Colunas reais (sem os calculados) — usadas no SELECT do dry-run
const COLS_BANCO = CAMPOS.map(c => c.key).filter(k => !/^idade_/.test(k));

const OPERADORES = {
  select: [['eq','é igual a'],['neq','é diferente de'],['in','é um de'],['filled','está preenchido'],['not_filled','está vazio']],
  multi:  [['contains','contém'],['contains_any','contém algum de'],['filled','está preenchido'],['not_filled','está vazio']],
  bool:   [['eq','é']],
  numero: [['lt','<'],['lte','≤'],['gt','>'],['gte','≥'],['eq','='],['neq','≠'],['filled','preenchido'],['not_filled','vazio']],
  texto:  [['text_contains_any','contém (texto) algum de'],['eq','é igual a'],['neq','é diferente de'],['filled','preenchido'],['not_filled','vazio']],
};

function esc(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }

function page(titulo, corpo){
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
  // super-admin (ou break-glass)
  const soSuper = [scihRequired, (req,res,next)=>{
    if (req.user?.super_admin || req.cookies?.adm === '1') return next();
    res.status(403).send(page('Sem acesso','<div class="card"><h1>Acesso restrito</h1><p class="mut">Apenas o administrador pode gerenciar regras de triagem.</p></div>'));
  }];

  // ── Lista ────────────────────────────────────────────────────────────────
  app.get('/atb/admin/regras', soSuper, async (req,res)=>{
    try{
      const regras = (await pool.query('SELECT * FROM atb_triagem_regras ORDER BY prioridade ASC, id ASC')).rows;
      const linhas = regras.map(r=>`
        <tr>
          <td><strong>${esc(r.nome)}</strong>${r.descricao?`<br><span class="nota">${esc(r.descricao)}</span>`:''}</td>
          <td>${r.prioridade}</td>
          <td><span class="nota">${esc(resumoCond(r.condicoes))}</span></td>
          <td><span class="nota">${esc(resumoAcoes(r.acoes))}</span></td>
          <td>${r.ativo?'<span class="pill on">ativa</span>':'<span class="pill off">inativa</span>'}</td>
          <td class="row">
            <a class="btn ghost" href="/atb/admin/regras/${r.id}">Editar</a>
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
          fetch('/atb/admin/regras/testar',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload())})
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

  app.get('/atb/admin/regras/nova', soSuper, (req,res)=> editor(req,res,null));
  app.get('/atb/admin/regras/:id', soSuper, async (req,res)=>{
    const r=(await pool.query('SELECT * FROM atb_triagem_regras WHERE id=$1',[parseInt(req.params.id,10)])).rows[0];
    if(!r) return res.status(404).send(page('Não encontrada','<div class="card"><h1>Regra não encontrada</h1><a href="/atb/admin/regras">Voltar</a></div>'));
    editor(req,res,r);
  });

  // ── Salvar ─────────────────────────────────────────────────────────────────
  async function salvar(req,res,id){
    try{
      const b=req.body||{};
      const nome=(b.nome||'').trim();
      if(!nome) return res.status(400).json({ok:false,error:'Nome obrigatório'});
      if(b.acoes?.veredito && !PARECER_VEREDITOS.includes(b.acoes.veredito)) return res.status(400).json({ok:false,error:'veredito inválido'});
      if(b.acoes?.iras && !IRAS_VALORES.includes(b.acoes.iras)) return res.status(400).json({ok:false,error:'IrAS inválido'});
      const vals=[nome, b.descricao||null, Number(b.prioridade)||100, b.ativo!==false,
                  JSON.stringify(b.condicoes||{}), JSON.stringify(b.acoes||{})];
      if(id){
        await pool.query(`UPDATE atb_triagem_regras SET nome=$1,descricao=$2,prioridade=$3,ativo=$4,condicoes=$5::jsonb,acoes=$6::jsonb,updated_at=now() WHERE id=$7`, [...vals, id]);
      }else{
        await pool.query(`INSERT INTO atb_triagem_regras (nome,descricao,prioridade,ativo,condicoes,acoes,created_by) VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7)`, [...vals, req.user?.id||null]);
      }
      res.json({ok:true});
    }catch(e){ console.error('[regras] salvar:',e.message); res.status(500).json({ok:false,error:e.message}); }
  }
  app.post('/atb/admin/regras/salvar', soSuper, (req,res)=> salvar(req,res,null));
  app.post('/atb/admin/regras/salvar/:id', soSuper, (req,res)=> salvar(req,res,parseInt(req.params.id,10)));

  app.post('/atb/admin/regras/:id/toggle', soSuper, async (req,res)=>{
    try{ await pool.query('UPDATE atb_triagem_regras SET ativo=NOT ativo, updated_at=now() WHERE id=$1',[parseInt(req.params.id,10)]); }
    catch(e){ console.error('[regras] toggle:',e.message); }
    res.redirect('/atb/admin/regras');
  });
  app.post('/atb/admin/regras/:id/excluir', soSuper, async (req,res)=>{
    try{ await pool.query('DELETE FROM atb_triagem_regras WHERE id=$1',[parseInt(req.params.id,10)]); }
    catch(e){ console.error('[regras] excluir:',e.message); }
    res.redirect('/atb/admin/regras');
  });

  // ── Dry-run contra o histórico ──────────────────────────────────────────────
  app.post('/atb/admin/regras/testar', soSuper, async (req,res)=>{
    try{
      const cond = req.body?.condicoes;
      const irasRegra = req.body?.acoes?.iras || null;
      if(!cond || (!cond.all && !cond.any)) return res.json({ok:true, total:0, casam:0, ja_iras:0, vazias:0, divergentes:null});
      const cols = ['id','paciente_dn','data_referencia','jotform_created_at','created_at', ...COLS_BANCO]
        .filter((v,i,a)=>a.indexOf(v)===i).map(c=>'f.'+c).join(',');
      const { rows } = await pool.query(`SELECT ${cols}, a.iras AS _iras FROM atb_fichas f LEFT JOIN atb_avaliacoes a ON a.ficha_id=f.id`);
      let casam=0, ja=0, vaz=0, div=0;
      for(const f of rows){
        const ctx = contextoFicha(f);
        if(avaliaCond(cond, ctx)){
          casam++;
          const temIras = f._iras!=null && String(f._iras).trim()!=='';
          if(temIras){ ja++; if(irasRegra && f._iras!==irasRegra) div++; } else vaz++;
        }
      }
      res.json({ok:true, total:rows.length, casam, ja_iras:ja, vazias:vaz, divergentes: irasRegra?div:null});
    }catch(e){ console.error('[regras] testar:',e.message); res.status(500).json({ok:false,error:e.message}); }
  });
}
