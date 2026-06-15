// ════════════════════════════════════════════════════════════════════════════
//  FICHA RETROSPECTIVA  —  /atb/admin/ficha-retrospectiva
//
//  Inclusão manual, EXCLUSIVA do SCIH (atrás de adminRequired), de casos em que
//  houve uso de ATB sem ficha preenchida pelo prescritor — sobretudo Hemodiálise.
//  Serve de registro para a classificação de IrAS.
//
//  A ficha criada entra no fluxo normal: nasce com status='pendente' (aparece em
//  "A classificar" na grade), marcada com retrospectiva=true. Depois de salvar, a
//  página redireciona para a ficha completa, onde se anexa o PDF e se classifica
//  o IrAS inline na grade.
//
//  Instituição fixa: HUSF (resolvida no servidor).
//
//  Integração em atb-routes.js:
//    import { ensureRetroSchema, registerFichaRetroRoutes } from './atb-ficha-retro-routes.js';
//    // no boot:               ensureRetroSchema(pool).catch(...);
//    // em registerAtbRoutes:  registerFichaRetroRoutes(app, pool, adminRequired);
//  Botão na grade (admin): <a href="/atb/admin/ficha-retrospectiva">+ Ficha retrospectiva</a>
// ════════════════════════════════════════════════════════════════════════════

const SETOR_OPCOES = ['Hemodiálise','PS','EPM','Cuidados Intermediários','Psiquiatria','Apartamento','Oncologia','Clínica Cirúrgica','Semi','Pediatria','UTI','UTI Neo / Infantil','UTI C','Ginecologia/Obstetrícia','Clínica Médica'];
const ACESSO_DIALISE = ['FAV','CDL (Shilley)','Perm-cath','PTFE'];

function _safe(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

export async function ensureRetroSchema(pool) {
  await pool.query(`ALTER TABLE atb_fichas ADD COLUMN IF NOT EXISTS retrospectiva BOOLEAN DEFAULT false`);
  await pool.query(`ALTER TABLE atb_fichas ADD COLUMN IF NOT EXISTS criada_por INTEGER REFERENCES users(id)`);
  // sinais_dialise NÃO é coluna — é gravado em payload_raw, como nas fichas nativas
}

function _sel(name, opcoes, sel, placeholder) {
  const opts = [`<option value="">${_safe(placeholder || '—')}</option>`]
    .concat(opcoes.map(o => `<option value="${_safe(o)}" ${o === sel ? 'selected' : ''}>${_safe(o)}</option>`)).join('');
  return `<select name="${name}">${opts}</select>`;
}

function paginaRetro(erro) {
  return `<!DOCTYPE html>
<html lang="pt-BR"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ficha retrospectiva</title>
<style>
  :root{--azul:#00469e;--azul-claro:#e6eef8;--azul-texto:#0c447c;--tinta:#1a2733;--tinta-suave:#3a4654;--borda:#d8dee6;--fundo:#f4f6f9;--vermelho:#e12229}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--fundo);color:var(--tinta);font-size:14px;line-height:1.5;padding-bottom:90px}
  .cab{background:#fff;border-bottom:2px solid var(--azul);padding:14px 22px;display:flex;align-items:center;justify-content:space-between;gap:12px}
  .cab h1{font-size:16px;color:var(--azul)} .cab a{font-size:12px;color:var(--azul);text-decoration:none}
  .faixa{background:var(--azul);color:#fff;padding:11px 22px;font-size:13px;font-weight:600}
  .wrap{max-width:680px;margin:18px auto;padding:0 16px}
  .erro{background:#fdecea;border:1px solid #f5c2c0;color:#a01b1b;border-radius:8px;padding:10px 14px;margin-bottom:14px;font-size:13px}
  .bloco{background:#fff;border:1px solid var(--borda);border-radius:10px;padding:16px 18px}
  .campo{display:flex;flex-direction:column;gap:5px;margin-bottom:14px}
  .campo:last-child{margin-bottom:0}
  .campo label{font-size:12px;font-weight:700;color:var(--azul-texto);text-transform:uppercase;letter-spacing:.03em}
  .campo input,.campo select,.campo textarea{width:100%;padding:10px 12px;border:1px solid var(--borda);border-radius:8px;font-size:14px;font-family:inherit;background:#fafbfc;color:var(--tinta)}
  .campo textarea{min-height:80px;resize:vertical}
  .campo input:focus,.campo select:focus,.campo textarea:focus{outline:none;border-color:var(--azul);background:#fff;box-shadow:0 0 0 3px var(--azul-claro)}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:0 14px}
  .req{color:var(--vermelho)}
  .dica{font-size:11px;color:var(--tinta-suave);margin-top:-8px;margin-bottom:14px}
  .rodape{position:fixed;bottom:0;left:0;right:0;background:#fff;border-top:1px solid var(--borda);padding:12px 22px;display:flex;gap:12px;justify-content:flex-end;z-index:30}
  .salvar{background:var(--azul);color:#fff;border:none;border-radius:8px;padding:11px 26px;font-size:14px;font-weight:600;cursor:pointer}
  @media(max-width:560px){.grid2{grid-template-columns:1fr}}
</style></head>
<body>
  <div class="cab"><h1>Nova ficha retrospectiva</h1><a href="/atb/admin/grid">← voltar à grade</a></div>
  <div class="faixa">Registro de uso de ATB sem ficha (HUSF) — uso interno do SCIH</div>
  <form method="POST" action="/atb/admin/ficha-retrospectiva" id="f-retro" class="wrap">
    ${erro ? `<div class="erro">${_safe(erro)}</div>` : ''}
    <div class="bloco">
      <div class="campo"><label>Setor <span class="req">*</span></label>${_sel('setor', SETOR_OPCOES, 'Hemodiálise', 'Selecione')}</div>
      <div class="grid2">
        <div class="campo"><label>Nome do paciente <span class="req">*</span></label><input name="nome" required></div>
        <div class="campo"><label>Prontuário <span class="req">*</span></label><input name="prontuario" required></div>
        <div class="campo"><label>Atendimento</label><input name="atendimento"></div>
        <div class="campo"><label>Data (uso do ATB) <span class="req">*</span></label><input type="date" name="data" required></div>
      </div>
      <div class="campo"><label>ATB usado <span class="req">*</span></label><input name="atb" placeholder="ex.: Vancomicina + Ceftazidima" required></div>
      <div class="grid2">
        <div class="campo"><label>Acesso para diálise</label>${_sel('acesso_dialise', ACESSO_DIALISE, '', '—')}</div>
        <div class="campo"><label>Sinais de infecção local no acesso?</label>${_sel('sinais_dialise', ['Sim','Não'], '', '—')}</div>
      </div>
      <div class="campo"><label>Observação</label><textarea name="observacao" placeholder="Contexto do caso, motivo da inclusão retrospectiva…"></textarea></div>
      <div class="campo"><label>Anexos (imagem ou PDF)</label>
        <input type="file" id="anexos" multiple accept="image/*,application/pdf">
        <div id="anexos-lista" class="dica" style="margin-top:6px"></div>
      </div>
    </div>
  </form>
  <div class="rodape">
    <span id="retro-status" style="margin-right:auto;font-size:13px"></span>
    <button type="button" id="btn-criar" class="salvar">Criar ficha retrospectiva</button>
  </div>
  <script>
  (function(){
    var form = document.getElementById('f-retro');
    var btn = document.getElementById('btn-criar');
    var inputArq = document.getElementById('anexos');
    var lista = document.getElementById('anexos-lista');
    var status = document.getElementById('retro-status');
    function diz(t, erro){ status.textContent = t; status.style.color = erro ? '#c0392b' : '#0c447c'; }

    inputArq.addEventListener('change', function(){
      var n = inputArq.files ? inputArq.files.length : 0;
      if(!n){ lista.textContent = ''; return; }
      var nomes = []; for(var i=0;i<n;i++) nomes.push(inputArq.files[i].name);
      lista.textContent = n + ' arquivo(s): ' + nomes.join(', ');
    });

    btn.addEventListener('click', function(){
      var campos = ['setor','nome','prontuario','atendimento','data','atb','acesso_dialise','sinais_dialise','observacao'];
      var body = new URLSearchParams();
      campos.forEach(function(n){ var el = form.elements[n]; if(el) body.append(n, el.value || ''); });
      if(!form.elements['nome'].value.trim() || !form.elements['prontuario'].value.trim() ||
         !form.elements['atb'].value.trim() || !form.elements['data'].value || !form.elements['setor'].value){
        diz('Preencha os obrigatórios: setor, nome, prontuário, data e ATB.', true); return;
      }
      btn.disabled = true; diz('Criando ficha…');
      fetch('/atb/admin/ficha-retrospectiva', {
        method:'POST',
        headers:{ 'Content-Type':'application/x-www-form-urlencoded', 'Accept':'application/json' },
        body: body.toString()
      })
      .then(function(r){ return r.json(); })
      .then(function(j){
        if(!j || !j.ok) throw new Error((j && j.error) || 'Falha ao criar a ficha');
        var files = inputArq.files;
        if(!files || !files.length) return j.id;
        diz('Enviando anexos (0/' + files.length + ')…');
        var seq = Promise.resolve(), enviados = 0;
        for(var i=0;i<files.length;i++){ (function(file){
          seq = seq.then(function(){
            return fetch('/atb/admin/ficha/' + j.id + '/anexo?nome=' + encodeURIComponent(file.name) + '&ct=' + encodeURIComponent(file.type || ''),
              { method:'POST', body: file })
              .then(function(){ enviados++; diz('Enviando anexos (' + enviados + '/' + files.length + ')…'); });
          });
        })(files[i]); }
        return seq.then(function(){ return j.id; });
      })
      .then(function(id){ diz('Pronto! Abrindo a ficha…'); window.location.href = '/atb/admin/ficha/' + id; })
      .catch(function(e){ btn.disabled = false; diz('Erro: ' + (e.message || e), true); });
    });
  })();
  </script>
</body></html>`;
}

export function registerFichaRetroRoutes(app, pool, adminRequired) {

  app.get('/atb/admin/ficha-retrospectiva', adminRequired, (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(paginaRetro(null));
  });

  app.post('/atb/admin/ficha-retrospectiva', adminRequired, async (req, res) => {
    const b = req.body || {};
    const wantsJson = (req.get('accept') || '').includes('application/json');
    const nome = (b.nome || '').trim();
    const prontuario = (b.prontuario || '').trim();
    const atb = (b.atb || '').trim();
    const data = (b.data || '').trim();
    const setor = (b.setor || '').trim();

    if (!nome || !prontuario || !atb || !data || !setor) {
      const msg = 'Preencha os campos obrigatórios: setor, nome, prontuário, data e ATB usado.';
      if (wantsJson) return res.status(400).json({ ok: false, error: msg });
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.send(paginaRetro(msg));
    }

    try {
      const { rows: [inst] } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla = 'HUSF' LIMIT 1`);
      const instId = inst ? inst.id : null;

      const acesso = (b.acesso_dialise || '').trim() || null;
      const sinais = (b.sinais_dialise || '').trim() || null;
      const observacao = (b.observacao || '').trim() || null;
      // sinais_dialise vai no payload_raw (mesma forma das fichas nativas → card/ficha leem de lá)
      const payloadRaw = { retrospectiva: true, setor, atb_usado: atb, acesso_dialise: acesso, sinais_dialise: sinais };

      const { rows: [nova] } = await pool.query(`
        INSERT INTO atb_fichas
          (instituicao_id, setor, paciente_nome, paciente_nome_raw, prontuario, atendimento,
           data_referencia, atb_solicitado, acesso_dialise, historia_clinica, payload_raw,
           retrospectiva, criada_por, status, created_at, updated_at)
        VALUES ($1,$2,$3,$3,$4,$5,$6::date,$7::jsonb,$8,$9,$10::jsonb,true,$11,'pendente',now(),now())
        RETURNING id`,
        [instId, setor, nome, prontuario, (b.atendimento || '').trim() || null,
         data, JSON.stringify(atb ? [atb] : []), acesso, observacao,
         JSON.stringify(payloadRaw), req.user?.id || null]);

      // o cliente (JS) envia os anexos com o id retornado e então redireciona
      if (wantsJson) return res.json({ ok: true, id: nova.id });
      res.redirect('/atb/admin/ficha/' + nova.id);
    } catch (e) {
      console.error('[atb] ficha retrospectiva error:', e.message);
      if (wantsJson) return res.status(500).json({ ok: false, error: e.message });
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(paginaRetro('Erro ao criar a ficha: ' + e.message));
    }
  });
}
