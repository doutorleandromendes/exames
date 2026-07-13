// atb-monitoramento-routes.js
// ─────────────────────────────────────────────────────────────────────────
// REGRAS DE MONITORAMENTO — reavaliação contínua de fichas ao longo de uma
// janela de dias após a submissão. Diferente da triagem (pontual, no ato), o
// monitoramento re-roda periodicamente (cron 2×/dia) e captura mudanças de
// estado que chegam depois — ex.: hemocultura positiva 2 dias após a ficha.
//
// Reusa o NÚCLEO da triagem (montarContexto + avaliaCond) e o catálogo/HTML
// (catalogoCampos/page/esc). Isolado por tenant: regra de um nunca vaza pro outro.
//
// Política de escrita por-regra (sobrescrever):
//   false → grava IrAS só se estiver VAZIO (idempotente).
//   true  → grava se vazio OU se o IrAS atual foi posto por uma REGRA
//           (triagem/monitoramento); NUNCA sobrescreve entrada MANUAL do revisor.

import express from 'express';
import { montarContexto, avaliaCond } from './atb-triagem-regras.js';
import { page, esc, catalogoCampos, OPERADORES, IRAS_VALORES } from './atb-regras-routes.js';

export async function ensureMonitoramentoSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atb_monitoramento_regras (
      id            SERIAL PRIMARY KEY,
      instituicao   TEXT NOT NULL,
      nome          TEXT NOT NULL,
      descricao     TEXT,
      prioridade    INTEGER DEFAULT 100,
      ativo         BOOLEAN DEFAULT true,
      condicoes     JSONB NOT NULL,
      acao_iras     TEXT,
      acao_etiol    TEXT,
      janela_dias   INTEGER DEFAULT 14,
      sobrescrever  BOOLEAN DEFAULT false,
      created_at    TIMESTAMPTZ DEFAULT now(),
      updated_at    TIMESTAMPTZ DEFAULT now()
    )`);
  await pool.query(`ALTER TABLE atb_avaliacoes ADD COLUMN IF NOT EXISTS monitor_regra_id INTEGER`);
  await pool.query(`ALTER TABLE atb_avaliacoes ADD COLUMN IF NOT EXISTS monitor_regra_at TIMESTAMPTZ`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atb_monitoramento_log (
      id            BIGSERIAL PRIMARY KEY,
      ficha_id      BIGINT,
      regra_id      INTEGER,
      instituicao   TEXT,
      iras_antes    TEXT,
      iras_depois   TEXT,
      sobrescreveu  BOOLEAN,
      executado_em  TIMESTAMPTZ DEFAULT now()
    )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS atb_monitor_log_ficha_idx ON atb_monitoramento_log(ficha_id, executado_em DESC)`);
}

// Executor: reavalia as fichas do tenant dentro da janela e aplica as regras.
export async function executarMonitoramento(pool, inst) {
  const regras = (await pool.query(
    `SELECT id, nome, condicoes, acao_iras, acao_etiol, janela_dias, sobrescrever
       FROM atb_monitoramento_regras
      WHERE ativo=true AND instituicao=$1
      ORDER BY prioridade ASC, id ASC`, [inst]
  )).rows;
  if (!regras.length) return { ok: true, regras: 0, fichas: 0, aplicadas: 0 };

  const maxJanela = Math.max(...regras.map(r => r.janela_dias || 14));
  // Se NENHUMA regra sobrescreve, só precisamos avaliar fichas com IrAS vazio —
  // as já classificadas não mudariam (fill-if-empty). Reduz muito o trabalho.
  const algumSobrescreve = regras.some(r => r.sobrescrever);
  const fichas = (await pool.query(
    `SELECT f.id
       FROM atb_fichas f
       LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
       LEFT JOIN atb_avaliacoes a ON a.ficha_id = f.id
      WHERE f.deletado_em IS NULL
        AND COALESCE(i.sigla,'HUSF') = $1
        AND COALESCE(f.data_referencia,f.jotform_created_at,f.created_at) >= (now() - ($2 || ' days')::interval)
        AND ($3 OR a.iras IS NULL OR a.iras = '')`,
    [inst, String(maxJanela), algumSobrescreve]
  )).rows;

  const agora = Date.now();
  let aplicadas = 0;
  for (const { id: fichaId } of fichas) {
    try {
      const built = await montarContexto(pool, fichaId);
      if (!built) continue;
      const { f, ctx } = built;
      const refData = f.data_referencia || f.jotform_created_at || f.created_at || null;

      const regra = regras.find(r => {
        const dentro = refData ? (agora - new Date(refData).getTime()) <= (r.janela_dias || 14) * 86400000 : true;
        return dentro && avaliaCond(r.condicoes, ctx);
      });
      if (!regra) continue;

      const av = (await pool.query(
        'SELECT iras, triagem_regra_id, monitor_regra_id FROM atb_avaliacoes WHERE ficha_id=$1', [fichaId]
      )).rows[0];
      const irasAtual = av && av.iras != null ? String(av.iras).trim() : '';
      const vazio = irasAtual === '';
      const postoPorRegra = !!(av && (av.triagem_regra_id != null || av.monitor_regra_id != null));
      const alvo = (regra.acao_iras || '').trim();

      const podeEscrever = vazio || (regra.sobrescrever && postoPorRegra);
      if (!podeEscrever || irasAtual === alvo) continue;

      await pool.query(
        `INSERT INTO atb_avaliacoes (ficha_id, iras, etiol_iras, monitor_regra_id, monitor_regra_at, updated_at)
         VALUES ($1,$2,$3,$4, now(), now())
         ON CONFLICT (ficha_id) DO UPDATE SET
           iras = $2,
           etiol_iras = COALESCE(atb_avaliacoes.etiol_iras, $3),
           monitor_regra_id = $4,
           monitor_regra_at = now(),
           updated_at = now()`,
        [fichaId, regra.acao_iras || null, regra.acao_etiol || null, regra.id]
      );
      await pool.query(
        `INSERT INTO atb_monitoramento_log (ficha_id, regra_id, instituicao, iras_antes, iras_depois, sobrescreveu)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [fichaId, regra.id, inst, irasAtual || null, alvo || null, !vazio]
      );
      aplicadas++;
    } catch (e) { console.error('[monitor] ficha', fichaId, '-', e.message); }
  }
  console.log(`[monitor] ${inst}: ${regras.length} regra(s), ${fichas.length} ficha(s) na janela, ${aplicadas} aplicada(s)`);
  return { ok: true, regras: regras.length, fichas: fichas.length, aplicadas };
}

function _tenant(req) { return req.atbTenant || 'HUSF'; }

function resumoCondMon(cond) {
  if (!cond) return '—';
  const linhas = cond.all || cond.any || [];
  const j = cond.all ? ' E ' : ' OU ';
  return linhas.map(c => `${c.campo} ${c.op}${c.valor !== undefined ? ' ' + (Array.isArray(c.valor) ? c.valor.join('/') : c.valor) : ''}`).join(j) || '—';
}

// Editor (reusa o mesmo padrão de builder de condição da triagem).
function paginaEditorMonitor(regra, campos) {
  const dados = JSON.stringify({ campos, ops: OPERADORES, iras: IRAS_VALORES, regra });
  return page(regra ? 'Editar regra de monitoramento' : 'Nova regra de monitoramento', `
    <div class="card"><h1>${regra ? 'Editar' : 'Nova'} regra de monitoramento</h1>
      <p class="mut">Reavaliada 2×/dia nas fichas dentro da janela. Preenche IrAS conforme a política de sobrescrita.</p>
      <label class="lbl">Nome</label><input id="r_nome" style="width:100%" value="${esc(regra?.nome || '')}">
      <label class="lbl">Descrição (opcional)</label><input id="r_desc" style="width:100%" value="${esc(regra?.descricao || '')}">
      <div class="row" style="margin-top:10px">
        <div><label class="lbl">Prioridade</label><input id="r_prio" type="number" value="${regra?.prioridade ?? 100}" style="width:100px"></div>
        <div><label class="lbl">Ativa</label><br><select id="r_ativo"><option value="true"${regra && !regra.ativo ? '' : ' selected'}>Sim</option><option value="false"${regra && !regra.ativo ? ' selected' : ''}>Não</option></select></div>
        <div><label class="lbl">Janela (dias)</label><input id="r_janela" type="number" value="${regra?.janela_dias ?? 14}" style="width:100px"></div>
        <div><label class="lbl">Sobrescrever</label><br><select id="r_sobrescrever"><option value="false"${regra && regra.sobrescrever ? '' : ' selected'}>Não (só se vazio)</option><option value="true"${regra && regra.sobrescrever ? ' selected' : ''}>Sim (reclassifica; protege manual)</option></select></div>
      </div>
    </div>
    <div class="card"><h2>Condições</h2>
      <div class="row"><label class="lbl" style="margin:0">Combinar com</label>
        <select id="r_combinador"><option value="all">TODAS (E)</option><option value="any">QUALQUER (OU)</option></select></div>
      <div id="conds" style="margin-top:12px"></div>
      <button class="ghost" type="button" onclick="addRow()">+ condição</button>
    </div>
    <div class="card"><h2>Ação (o que preencher)</h2>
      <div class="acao-grid">
        <div><label class="lbl">IrAS</label><select id="a_iras"><option value="">— não mexer —</option>${IRAS_VALORES.map(v => `<option value="${esc(v)}">${esc(v)}</option>`).join('')}</select></div>
      </div>
      <label class="lbl">Etiologia IrAS (opcional)</label><input id="a_etiol" style="width:100%">
    </div>
    <div class="card"><h2>Testar condições contra o histórico</h2>
      <p class="nota">Quantas fichas casariam as condições agora (não altera nada).</p>
      <button class="ghost" type="button" onclick="testar()">Testar agora</button>
      <select id="teste_janela" style="margin-left:8px;padding:4px 6px">
        <option value="30">Últimos 30 dias</option><option value="180" selected>Últimos 6 meses</option>
        <option value="365">Último ano</option><option value="0">Todo o histórico</option>
      </select>
      <div id="teste" class="nota" style="margin-top:10px"></div>
    </div>
    <div class="card row">
      <button type="button" onclick="salvar()">Salvar regra</button>
      <a class="btn ghost" href="/atb/admin/monitoramento">Cancelar</a>
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
        function repop(){ var cp=byKey[selCampo.value]; selOp.innerHTML=''; (OPS[cp.tipo]||OPS.texto).forEach(function(o){ selOp.appendChild(opt(o[0],o[1])); }); renderVal(); }
        function renderVal(){
          var cp=byKey[selCampo.value], op=selOp.value; valWrap.innerHTML='';
          if(op==='filled'||op==='not_filled'){ return; }
          if(cp.tipo==='bool'){ var s=document.createElement('select'); s.appendChild(opt('true','Sim')); s.appendChild(opt('false','Não')); valWrap.appendChild(s); return; }
          if(cp.tipo==='numero'){ var n=document.createElement('input'); n.type='number'; valWrap.appendChild(n); return; }
          var multiVal=(op==='in'||op==='contains_any'||op==='text_contains_any');
          if((cp.tipo==='select'||cp.tipo==='multi') && cp.opcoes && cp.opcoes.length){
            var s2=document.createElement('select'); if(multiVal) s2.multiple=true, s2.size=Math.min(6,cp.opcoes.length);
            cp.opcoes.forEach(function(o){ s2.appendChild(opt(o)); }); valWrap.appendChild(s2); return;
          }
          var t=document.createElement('input'); t.style.width='100%';
          t.placeholder=multiVal?'valores separados por vírgula':'valor'; valWrap.appendChild(t);
        }
        selCampo.onchange=repop; selOp.onchange=renderVal;
        div.appendChild(selCampo); div.appendChild(selOp); div.appendChild(valWrap); div.appendChild(rm);
        condsEl.appendChild(div);
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
          else if(cp.tipo==='bool'){ valor=(valEl.value==='true'); }
          else if(cp.tipo==='numero'){ valor=Number(valEl.value); }
          else if(valEl && valEl.multiple){ valor=Array.prototype.filter.call(valEl.options,function(o){return o.selected;}).map(function(o){return o.value;}); }
          else if(op==='text_contains_any'||op==='contains_any'||op==='in'){ valor=(valEl.value||'').split(',').map(function(s){return s.trim();}).filter(Boolean); }
          else { valor=valEl?valEl.value:''; }
          var o={campo:campo, op:op}; if(valor!==undefined) o.valor=valor; rows.push(o);
        });
        var comb=document.getElementById('r_combinador').value; var c={}; c[comb]=rows; return c;
      }
      function payload(){
        var ir=document.getElementById('a_iras').value, et=document.getElementById('a_etiol').value.trim();
        return { nome:document.getElementById('r_nome').value.trim(),
                 descricao:document.getElementById('r_desc').value.trim(),
                 prioridade:Number(document.getElementById('r_prio').value)||100,
                 ativo:document.getElementById('r_ativo').value==='true',
                 janela_dias:Number(document.getElementById('r_janela').value)||14,
                 sobrescrever:document.getElementById('r_sobrescrever').value==='true',
                 condicoes:coletarCond(), acao_iras:ir||null, acao_etiol:et||null }; }
      function salvar(){
        var p=payload(); if(!p.nome){ document.getElementById('msg').textContent='Dê um nome à regra.'; return; }
        var url = D.regra ? '/atb/admin/monitoramento/salvar/'+D.regra.id : '/atb/admin/monitoramento/salvar';
        fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(p)})
          .then(function(r){return r.json();}).then(function(j){
            if(j.ok){ location.href='/atb/admin/monitoramento'; } else { document.getElementById('msg').textContent=j.error||'Falha ao salvar'; }
          }).catch(function(e){ document.getElementById('msg').textContent=String(e); });
      }
      function testar(){
        var el=document.getElementById('teste'); el.textContent='Rodando...';
        var _body={ condicoes:coletarCond(), acoes:{iras:document.getElementById('a_iras').value||''}, janela:+document.getElementById('teste_janela').value };
        fetch('/atb/admin/regras/testar',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(_body)})
          .then(function(r){return r.json();}).then(function(j){
            if(!j.ok){ el.textContent=j.error||'Falha'; return; }
            el.innerHTML='Casariam <strong>'+j.casam+'</strong> de '+j.total+' fichas. '+j.ja_iras+' já têm IrAS, '+j.vazias+' vazias.';
          }).catch(function(e){ el.textContent=String(e); });
      }
      // init
      var rc = D.regra && D.regra.condicoes || {};
      document.getElementById('r_combinador').value = rc.all ? 'all' : (rc.any ? 'any' : 'all');
      var lista = rc.all || rc.any || [];
      if(lista.length){ lista.forEach(function(c){ addRow(c); }); } else { addRow(); }
      if(D.regra){ if(D.regra.acao_iras) document.getElementById('a_iras').value=D.regra.acao_iras;
                   if(D.regra.acao_etiol) document.getElementById('a_etiol').value=D.regra.acao_etiol; }
    </script>`);
}

export function registerMonitoramentoRoutes(app, pool, adminRequired) {
  const jsonMw = express.json({ limit: '256kb' });

  // ── Cron 2×/dia (token). Isolado por tenant; roda os tenants que tiverem regras. ──
  // Guarda contra execuções sobrepostas (o cron 2x/dia não sobrepõe, mas protege
  // contra disparos manuais concorrentes).
  let _monitorRodando = false;
  app.post('/atb/admin/monitoramento/executar', async (req, res) => {
    const tok = process.env.MONITOR_CRON_TOKEN;
    if (!tok || req.get('X-Cron-Token') !== tok) return res.status(401).json({ ok: false, error: 'token' });
    if (_monitorRodando) return res.status(202).json({ ok: true, status: 'ja_em_execucao' });
    // Responde JÁ e processa em BACKGROUND — evita o timeout do cron (o loop por
    // ficha pode passar de 30s). O resultado fica no log e em /monitoramento/log.
    res.status(202).json({ ok: true, status: 'iniciado' });
    _monitorRodando = true;
    (async () => {
      const t0 = Date.now();
      try {
        for (const inst of ['HUSF', 'SCMI']) {
          const r = await executarMonitoramento(pool, inst);
          console.log(`[monitor] ${inst}:`, JSON.stringify(r));
        }
        console.log(`[monitor] execução completa em ${((Date.now() - t0) / 1000).toFixed(1)}s`);
      } catch (e) { console.error('[monitor] execução em background:', e.message); }
      finally { _monitorRodando = false; }
    })();
  });

  // ── Lista ──
  app.get('/atb/admin/monitoramento', adminRequired, async (req, res) => {
    const inst = _tenant(req);
    try {
      const regras = (await pool.query('SELECT * FROM atb_monitoramento_regras WHERE instituicao=$1 ORDER BY prioridade ASC, id ASC', [inst])).rows;
      const linhas = regras.map(r => `
        <tr>
          <td><strong>${esc(r.nome)}</strong>${r.descricao ? `<br><span class="nota">${esc(r.descricao)}</span>` : ''}</td>
          <td>${r.prioridade}</td>
          <td>${r.janela_dias}d</td>
          <td>${r.sobrescrever ? '<span class="pill on">sobrescreve</span>' : '<span class="pill off">só se vazio</span>'}</td>
          <td><span class="nota">${esc(resumoCondMon(r.condicoes))} → IrAS ${esc(r.acao_iras || '—')}</span></td>
          <td>${r.ativo ? '<span class="pill on">ativa</span>' : '<span class="pill off">inativa</span>'}</td>
          <td class="row">
            <a class="btn ghost" href="/atb/admin/monitoramento/${r.id}">Editar</a>
            <form method="POST" action="/atb/admin/monitoramento/${r.id}/toggle" style="display:inline"><button class="ghost">${r.ativo ? 'Desativar' : 'Ativar'}</button></form>
            <form method="POST" action="/atb/admin/monitoramento/${r.id}/excluir" style="display:inline" onsubmit="return confirm('Excluir esta regra?')"><button class="danger">Excluir</button></form>
          </td>
        </tr>`).join('') || '<tr><td colspan="7" class="mut">Nenhuma regra de monitoramento ainda.</td></tr>';
      res.send(page('Regras de monitoramento', `
        <div class="card"><h1>Regras de monitoramento</h1>
          <p class="mut">Reavaliadas 2×/dia nas fichas dentro da janela. Capturam mudanças que chegam após a submissão (ex.: hemocultura positiva). Preenchem IrAS conforme a política de sobrescrita (protege sempre a entrada manual).</p>
          <a class="btn" href="/atb/admin/monitoramento/nova">+ Nova regra</a>
          <a class="btn ghost" href="/atb/admin/monitoramento/log">Ver disparos</a>
        </div>
        <div class="card">
          <table><thead><tr><th>Nome</th><th>Prior.</th><th>Janela</th><th>Sobrescr.</th><th>Condições → Ação</th><th>Estado</th><th></th></tr></thead>
          <tbody>${linhas}</tbody></table>
        </div>`));
    } catch (e) { console.error('[monitor] lista:', e.message); res.status(500).send(page('Erro', `<div class="card"><h1>Falha</h1><p class="mut">${esc(e.message)}</p></div>`)); }
  });

  // ── Editor (nova / editar) ──
  async function editor(req, res, regra) {
    const campos = await catalogoCampos(pool, _tenant(req));
    res.send(paginaEditorMonitor(regra, campos));
  }
  app.get('/atb/admin/monitoramento/nova', adminRequired, (req, res) => editor(req, res, null).catch(e => { console.error('[monitor] editor:', e.message); res.status(500).send('erro'); }));
  app.get('/atb/admin/monitoramento/:id', adminRequired, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id)) return res.redirect('/atb/admin/monitoramento');
    const regra = (await pool.query('SELECT * FROM atb_monitoramento_regras WHERE id=$1 AND instituicao=$2', [id, _tenant(req)])).rows[0];
    if (!regra) return res.redirect('/atb/admin/monitoramento');
    editor(req, res, regra).catch(e => { console.error('[monitor] editor:', e.message); res.status(500).send('erro'); });
  });

  // ── Salvar ──
  async function salvar(req, res, id) {
    const inst = _tenant(req);
    try {
      const b = req.body || {};
      if (!b.nome || !b.condicoes) return res.status(400).json({ ok: false, error: 'nome e condições obrigatórios' });
      const vals = [inst, b.nome, b.descricao || null, Number(b.prioridade) || 100, b.ativo !== false,
        JSON.stringify(b.condicoes), b.acao_iras || null, b.acao_etiol || null,
        Number(b.janela_dias) || 14, b.sobrescrever === true];
      if (id) {
        await pool.query(
          `UPDATE atb_monitoramento_regras SET nome=$2, descricao=$3, prioridade=$4, ativo=$5,
             condicoes=$6::jsonb, acao_iras=$7, acao_etiol=$8, janela_dias=$9, sobrescrever=$10, updated_at=now()
           WHERE id=$1 AND instituicao=$11`, [id, ...vals.slice(1), inst]);
      } else {
        await pool.query(
          `INSERT INTO atb_monitoramento_regras
             (instituicao, nome, descricao, prioridade, ativo, condicoes, acao_iras, acao_etiol, janela_dias, sobrescrever)
           VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10)`, vals);
      }
      res.json({ ok: true });
    } catch (e) { console.error('[monitor] salvar:', e.message); res.status(500).json({ ok: false, error: e.message }); }
  }
  app.post('/atb/admin/monitoramento/salvar', adminRequired, jsonMw, (req, res) => salvar(req, res, null));
  app.post('/atb/admin/monitoramento/salvar/:id', adminRequired, jsonMw, (req, res) => salvar(req, res, parseInt(req.params.id, 10)));

  app.post('/atb/admin/monitoramento/:id/toggle', adminRequired, async (req, res) => {
    try { await pool.query('UPDATE atb_monitoramento_regras SET ativo=NOT ativo, updated_at=now() WHERE id=$1 AND instituicao=$2', [parseInt(req.params.id, 10), _tenant(req)]); }
    catch (e) { console.error('[monitor] toggle:', e.message); }
    res.redirect('/atb/admin/monitoramento');
  });
  app.post('/atb/admin/monitoramento/:id/excluir', adminRequired, async (req, res) => {
    try { await pool.query('DELETE FROM atb_monitoramento_regras WHERE id=$1 AND instituicao=$2', [parseInt(req.params.id, 10), _tenant(req)]); }
    catch (e) { console.error('[monitor] excluir:', e.message); }
    res.redirect('/atb/admin/monitoramento');
  });

  // ── Debug: últimos disparos ──
  app.get('/atb/admin/monitoramento/log', adminRequired, async (req, res) => {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    try {
      const { rows } = await pool.query(
        `SELECT l.executado_em, l.ficha_id, l.iras_antes, l.iras_depois, l.sobrescreveu, r.nome
           FROM atb_monitoramento_log l LEFT JOIN atb_monitoramento_regras r ON r.id=l.regra_id
          ORDER BY l.executado_em DESC LIMIT 50`);
      res.send('Últimos disparos de monitoramento:\n\n' + rows.map(r =>
        `${(r.executado_em && r.executado_em.toISOString) ? r.executado_em.toISOString() : r.executado_em} · ficha ${r.ficha_id} · ${r.nome || '—'} · ${r.iras_antes || '(vazio)'} → ${r.iras_depois}${r.sobrescreveu ? ' [sobrescreveu]' : ''}`
      ).join('\n') || '(nenhum disparo ainda)');
    } catch (e) { res.send('ERRO: ' + e.message); }
  });
}
