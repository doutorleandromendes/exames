// ════════════════════════════════════════════════════════════════════════════
//  CARD DE VISUALIZAÇÃO RÁPIDA DA FICHA  (popup no grid, estilo JotForm Tables)
//
//  Clicar no NOME do paciente na grade abre um popup com o resumo clínico curado
//  + complementos do SCIH (se houver). O popup tem dois botões:
//    • "Ver ficha completa"   → /atb/admin/fichas/:id  (por ora, a tela existente;
//                                será trocada pela leitura clara no próximo passo)
//    • "Emitir / editar parecer" → /atb/admin/parecer/:id  (já pronto)
//
//  Blocos do card (espelham as condicionais `cond` do schema do formulário):
//    SEMPRE  : identidade · ATB solicitado/posologia · história · foco · sepse/SOFA
//    UTI/UTI C            : data de admissão na UTI
//    UTI Neo / Infantil   : peso ao nascimento · acesso vascular Neo
//    Hemodiálise          : acesso p/ diálise · sinais flogísticos (de payload_raw)
//    Oncologia/quimio     : faz quimio · cateter · acesso de quimio
//    Profilaxia cirúrgica : cirurgia · Gustillo-Anderson (se Ortopedia)
//    Insuf. renal         : tipo · ClCr · em diálise
//    Dispositivos         : lista + sítios (CVC/CDL/PAi) + data de inserção
//    COMPLEMENTOS (SCIH)  : Complemento SCIH · Parecer evolutivo · Recom. adicionais
//                           + resumo das séries evolutivas (D-3→D+3) se preenchidas
//
//  Integração em atb-routes.js (mesmo padrão da Complementação/Parecer):
//    import { registerFichaCardRoutes, fichaCardAssets } from './atb-ficha-card-routes.js';
//    // em registerAtbRoutes:  registerFichaCardRoutes(app, pool, adminRequired);
//    // na grade (1x no html): ${fichaCardAssets()}
//  Não há schema novo — só leitura.
// ════════════════════════════════════════════════════════════════════════════

import { buscarCulturasDaFicha, culturasTemMR, renderCulturasCard } from './atb-culturas-routes.js';
import { buscarNomePacs, nomeDivergePacs } from './atb-pacs-nome-routes.js';

function _safe(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
const _arr = v => Array.isArray(v) ? v : (v == null ? [] : (typeof v === 'string'
  ? (() => { try { const x = JSON.parse(v); return Array.isArray(x) ? x : []; } catch { return []; } })()
  : []));
const _bool = b => b === true ? 'Sim' : b === false ? 'Não' : '—';
const _dt = d => d ? new Date(d).toLocaleDateString('pt-BR') : '—';
const _txt = s => (s == null || s === '') ? '—' : String(s);

// idade calculada a partir da DN (anos; meses se <2a; dias se <2m). Fallback: idade armazenada.
function _idade(dn, fallback) {
  if (!dn) return fallback || null;
  const d = new Date(dn);
  if (isNaN(d.getTime())) return fallback || null;
  const now = new Date();
  let anos = now.getFullYear() - d.getFullYear();
  const mDiff = now.getMonth() - d.getMonth();
  if (mDiff < 0 || (mDiff === 0 && now.getDate() < d.getDate())) anos--;
  if (anos >= 2) return anos + ' anos';
  let meses = anos * 12 + mDiff - (now.getDate() < d.getDate() ? 1 : 0);
  if (meses >= 2) return meses + ' meses';
  const dias = Math.max(0, Math.floor((now - d) / 86400000));
  return dias + ' dias';
}

// ── monta um bloco "definição" (lista de pares rótulo/valor) ─────────────────
function _bloco(titulo, itens, s) {
  const linhas = itens
    .filter(([, v]) => v !== null && v !== undefined && v !== '' && v !== '—')
    .map(([k, v]) => `<div class="fc-row"><span class="fc-k">${s(k)}</span><span class="fc-v">${v}</span></div>`)
    .join('');
  if (!linhas) return '';
  return `<div class="fc-bloco"><div class="fc-tit">${s(titulo)}</div>${linhas}</div>`;
}

// ── posologia (array de {droga,dose,intervalo}) → linhas compactas ───────────
function _posologia(p, s) {
  const a = _arr(p);
  if (!a.length) return '';
  const linhas = a.map(r => {
    const d = r.droga || r.Droga || '', dose = r.dose || r.Dose || '', iv = r.intervalo || r.Intervalo || '';
    if (!d && !dose && !iv) return '';
    return `<div class="fc-pos"><b>${s(d)}</b> ${s(dose)}${iv ? ' · ' + s(iv) : ''}</div>`;
  }).filter(Boolean).join('');
  return linhas;
}

// ── corpo do card ────────────────────────────────────────────────────────────
function renderCardBody(f, evol, s) {
  const setor = f.setor || '';
  const blocos = [];

  // sinais_dialise não tem coluna — vem do payload_raw (só fichas nativas)
  let sinaisDialise = f.sinais_dialise || null;
  if (!sinaisDialise) {
    try {
      const pr = typeof f.payload_raw === 'string' ? JSON.parse(f.payload_raw) : (f.payload_raw || {});
      sinaisDialise = pr.sinais_dialise || (pr.dados && pr.dados.sinais_dialise) || null;
    } catch { /* ignore */ }
  }

  // SEMPRE — ATB + clínica base
  const atb = _arr(f.atb_solicitado).join(', ');
  const pos = _posologia(f.posologia, s);
  blocos.push(_bloco('Antimicrobiano solicitado', [
    ['ATB', atb ? s(atb) : ''],
    ['Posologia', pos || ''],
    ['Tempo previsto', f.tempo_previsto != null ? s(f.tempo_previsto) + ' dias' : ''],
    ['Tipo de uso', s(_txt(f.tipo_terapia))],
  ], s));

  const sepseTxt = _bool(f.sepse) + (f.sepse === true && f.sofa != null ? ` · SOFA ${f.sofa}` : '');
  blocos.push(_bloco('Contexto clínico', [
    ['Internação', f.data_internacao ? _dt(f.data_internacao) : '<span class="fc-mut">—</span>'],
    ['História da infecção', f.historia_clinica ? s(f.historia_clinica) : ''],
    ['Foco de infecção', s(_txt(f.foco_infeccao))],
    ['Sepse', sepseTxt],
  ], s));

  // PROFILAXIA CIRÚRGICA
  if (f.tipo_terapia === 'Profilaxia cirúrgica') {
    blocos.push(_bloco('Cirurgia', [
      ['Cirurgia', f.cirurgia ? s(f.cirurgia) : ''],
      ['Fratura (Gustillo-Anderson)', f.classificacao_fratura ? s(f.classificacao_fratura) : ''],
    ], s));
  }

  // UTI / UTI C
  if (setor === 'UTI' || setor === 'UTI C') {
    blocos.push(_bloco('UTI', [
      ['Admissão na UTI', f.data_admissao_uti ? _dt(f.data_admissao_uti) : ''],
    ], s));
  }

  // UTI Neo / Infantil
  if (setor === 'UTI Neo / Infantil') {
    blocos.push(_bloco('Neonatal', [
      ['Peso ao nascimento', f.peso_nascimento != null ? s(f.peso_nascimento) + ' g' : ''],
      ['Acesso vascular (Neo)', _arr(f.acesso_vascular_neo).map(s).join(', ')],
    ], s));
  }

  // Hemodiálise
  if (setor === 'Hemodiálise' || f.dialise === true || f.acesso_dialise || sinaisDialise) {
    blocos.push(_bloco(setor === 'Hemodiálise' ? 'Hemodiálise' : 'Diálise', [
      ['Acesso para diálise', f.acesso_dialise ? s(f.acesso_dialise) : ''],
      ['Sinais flogísticos no acesso', sinaisDialise ? s(sinaisDialise) : ''],
    ], s));
  }

  // Oncologia / quimioterapia
  const temCancer = _arr(f.comorbidades).some(c => /cancer|câncer|onco/i.test(String(c)));
  if (setor === 'Oncologia' || f.faz_quimio === true || temCancer) {
    blocos.push(_bloco('Oncologia', [
      ['Faz quimioterapia', _bool(f.faz_quimio)],
      ['Cateter de quimio', _bool(f.cateter_quimio)],
      ['Acesso de quimio', f.acesso_quimio ? s(f.acesso_quimio) : ''],
    ], s));
  }

  // Função renal
  const insuf = _arr(f.insuficiencia_renal);
  if (insuf.length || f.clcr != null || f.dialise != null) {
    blocos.push(_bloco('Função renal', [
      ['Insuficiência renal', insuf.map(s).join(', ')],
      ['ClCr', f.clcr != null ? s(f.clcr) : ''],
      ['Em diálise', f.dialise != null ? _bool(f.dialise) : ''],
    ], s));
  }

  // Dispositivos invasivos (sempre que marcados) + sítios
  const disp = _arr(f.dispositivos_invasivos);
  if (disp.length) {
    blocos.push(_bloco('Dispositivos invasivos', [
      ['Dispositivos', disp.map(s).join(', ')],
      ['Sítio CVC', _arr(f.sitio_cvc).map(s).join(', ')],
      ['Sítio CDL', _arr(f.sitio_cdl).map(s).join(', ')],
      ['Sítio PAi', _arr(f.sitio_pai).map(s).join(', ')],
      ['Inserção do cateter', f.data_insercao_cateter ? _dt(f.data_insercao_cateter) : ''],
    ], s));
  }

  // ── COMPLEMENTOS DO SCIH (sempre que houver) ───────────────────────────────
  const parecerEvol = _arr(f.parecer_evolutivo).map(s).filter(Boolean).join('<br>');
  const series = [];
  if (evol) {
    const tem = o => o && typeof o === 'object' && Object.keys(o).length;
    if (tem(evol.ventilatorio)) series.push('EVA');
    if (tem(evol.hemodinamica)) series.push('DVA');
    if (tem(evol.labs)) series.push('Labs');
    if (tem(evol.acesso_vascular_neo_evol)) series.push('Acesso Neo');
  }
  const compItens = [
    ['Complemento SCIH', f.complemento_scih ? s(f.complemento_scih) : ''],
    ['Parecer evolutivo', parecerEvol || ''],
    ['Recomendações adicionais', f.recomendacoes_adicionais ? s(f.recomendacoes_adicionais) : ''],
    ['Séries evolutivas (D-3→D+3)', series.length
      ? `${series.join(' · ')} <span class="fc-mut">— ver completo na ficha</span>` : ''],
  ];
  const compHtml = _bloco('Complementos do SCIH', compItens, s);
  if (compHtml) {
    const por = evol && evol.preenchido_por_nome
      ? `<div class="fc-mut" style="margin-top:6px">Complementado por ${s(evol.preenchido_por_nome)}${evol.evol_updated ? ' · ' + new Date(evol.evol_updated).toLocaleDateString('pt-BR') : ''}</div>`
      : '';
    blocos.push(compHtml.replace('</div>', por + '</div>'));
  }

  // ── ACESSOS (links gerados) — sempre no topo quando existirem ──────────────
  const links = [];
  if (f.link_exames) links.push(`<a href="${s(f.link_exames)}" target="_blank" rel="noopener" class="fc-link">🔗 Exames / imagens</a>`);
  if (f.link_labs)   links.push(`<a href="${s(f.link_labs)}" target="_blank" rel="noopener" class="fc-link">🔬 LIS (labs)</a>`);
  if (links.length) {
    blocos.unshift(`<div class="fc-bloco"><div class="fc-tit">Acessos</div><div class="fc-links">${links.join('')}</div></div>`);
  }

  // ── ANEXOS (PDFs + imagens) — sempre que houver ───────────────────────────
  const anexos = f._anexos || [];
  if (anexos.length) {
    const pdfs = anexos.filter(a => a.tipo === 'pdf');
    const imgs = anexos.filter(a => a.tipo !== 'pdf');
    const pdfHtml = pdfs.map(a => `<a class="fc-anexo-pdf" target="_blank" rel="noopener" href="/atb/admin/ficha/${f.id}/anexo/${a.id}">📄 ${s(a.nome_original || ('PDF ' + a.id))}</a>`).join('');
    const imgHtml = imgs.map(a => `<a target="_blank" rel="noopener" href="/atb/admin/ficha/${f.id}/anexo/${a.id}" title="${s(a.nome_original || '')}"><img class="fc-anexo-img" loading="lazy" src="/atb/admin/ficha/${f.id}/anexo/${a.id}"></a>`).join('');
    blocos.push(`<div class="fc-bloco"><div class="fc-tit">Anexos</div>${pdfHtml ? `<div class="fc-anexo-pdfs">${pdfHtml}</div>` : ''}${imgHtml ? `<div class="fc-anexo-imgs">${imgHtml}</div>` : ''}</div>`);
  }

  return blocos.filter(Boolean).join('');
}

// ════════════════════════════════════════════════════════════════════════════
//  ASSETS DO MODAL (CSS + overlay + JS) — inserir UMA vez no html da grade
// ════════════════════════════════════════════════════════════════════════════
export function fichaCardAssets() {
  const css = `
  <style>
    #fc-overlay{position:fixed;inset:0;background:rgba(12,68,124,.28);z-index:9998;display:none;
      align-items:flex-start;justify-content:center;padding:40px 16px;overflow-y:auto}
    #fc-modal{background:#fff;border-radius:12px;max-width:640px;width:100%;box-shadow:0 18px 50px rgba(12,68,124,.25);
      font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#1a2733;overflow:hidden}
    #fc-modal .fc-head{background:#fff;border-bottom:2px solid #00469e;padding:14px 18px;display:flex;
      align-items:flex-start;justify-content:space-between;gap:12px;position:sticky;top:0}
    #fc-modal .fc-head .nome{font-size:16px;font-weight:700;color:#0c447c}
    #fc-modal .fc-head .meta{font-size:12px;color:#3a4654;margin-top:2px}
    #fc-modal .fc-head .nome-row{display:flex;align-items:center;justify-content:space-between;gap:10px}
    #fc-modal #fc-mr{background:#fcebeb;color:#a32d2d;border:1px solid #f0a0a0;font-size:12px;font-weight:600;padding:2px 9px;border-radius:999px;white-space:nowrap;flex:none}
    #fc-modal #fc-pacs{margin-top:6px;font-size:12px;color:#8a5a00;background:#fdf6e9;border:1px solid #f2d9a0;border-radius:8px;padding:6px 10px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
    #fc-modal #fc-pacs button{padding:4px 10px;border:0;border-radius:6px;background:#1a6b3a;color:#fff;font-weight:600;font-size:12px;cursor:pointer}
    #fc-modal #fc-pacs button:disabled{opacity:.6;cursor:default}
    #fc-modal .fc-x{background:none;border:none;font-size:22px;line-height:1;cursor:pointer;color:#9aa0a6;padding:0 4px}
    #fc-modal .fc-body{padding:14px 18px;max-height:62vh;overflow-y:auto}
    #fc-modal .fc-loading{padding:40px;text-align:center;color:#9aa0a6;font-size:13px}
    #fc-modal .fc-bloco{border:1px solid #eef1f5;border-radius:9px;padding:11px 13px;margin-bottom:11px}
    #fc-modal .fc-tit{font-size:11px;font-weight:700;color:#0c447c;text-transform:uppercase;letter-spacing:.04em;margin-bottom:7px}
    #fc-modal .fc-row{display:flex;gap:10px;font-size:13px;padding:3px 0;align-items:flex-start}
    #fc-modal .fc-k{flex:0 0 150px;color:#5f6368;font-size:12px}
    #fc-modal .fc-v{flex:1;color:#1a2733;white-space:pre-wrap;word-break:break-word}
    #fc-modal .fc-pos{font-size:13px}
    #fc-modal .fc-mut{color:#9aa0a6;font-size:11px}
    #fc-modal .fc-links{display:flex;flex-wrap:wrap;gap:8px}
    #fc-modal .fc-link{display:inline-flex;align-items:center;gap:5px;font-size:13px;text-decoration:none;
      padding:7px 12px;border:1px solid #bcd0ec;border-radius:8px;background:#eef4fc;color:#0c447c;font-weight:500}
    #fc-modal .fc-link:hover{background:#e0ebfa}
    #fc-modal .fc-anexo-pdfs{display:flex;flex-direction:column;gap:5px;margin-bottom:8px}
    #fc-modal .fc-anexo-pdf{font-size:13px;color:#0c447c;text-decoration:none}
    #fc-modal .fc-anexo-imgs{display:flex;flex-wrap:wrap;gap:7px}
    #fc-modal .fc-anexo-img{width:80px;height:80px;object-fit:cover;border:1px solid #d8dee6;border-radius:8px}
    #fc-modal .fc-foot{border-top:1px solid #eef1f5;padding:12px 18px;display:flex;gap:10px;justify-content:flex-end;background:#fafbfc}
    #fc-modal .fc-btn{font-size:13px;padding:9px 16px;border-radius:8px;cursor:pointer;text-decoration:none;
      border:1px solid #d8dee6;background:#fff;color:#0c447c;font-weight:500}
    #fc-modal .fc-btn.prim{background:#00469e;border-color:#00469e;color:#fff;font-weight:600}
    #fc-modal .fc-btn.fc-ico{padding:8px 11px;font-size:15px;line-height:1}
    #fc-modal .fc-btn:hover{filter:brightness(.97)}
  </style>`;

  const html = `
  <div id="fc-overlay">
    <div id="fc-modal">
      <div class="fc-head">
        <div style="flex:1;min-width:0"><div class="nome-row"><div class="nome" id="fc-nome">—</div><span id="fc-mr" style="display:none"></span></div><div class="meta" id="fc-meta"></div><div id="fc-pacs" style="display:none"></div></div>
        <button type="button" class="fc-x" id="fc-close">×</button>
      </div>
      <div class="fc-body" id="fc-content"><div class="fc-loading">Carregando…</div></div>
      <div class="fc-foot">
        <button type="button" class="fc-btn fc-ico" id="fc-pront" title="Copiar prontuário">📋🔢</button>
        <a class="fc-btn fc-ico" id="fc-imagem" href="#" title="Copiar imagem do parecer">📋🖼️</a>
        <a class="fc-btn" id="fc-completa" href="#">Ver ficha completa</a>
        <a class="fc-btn prim" id="fc-parecer" href="#">✎ Emitir / editar parecer</a>
      </div>
    </div>
  </div>
  <div id="fc-img-fonte" style="position:fixed;left:-99999px;top:0;pointer-events:none"></div>`;

  const js = `
  <script>
  (function(){
    var ov = document.getElementById('fc-overlay');
    if(!ov) return;
    var nomeEl = document.getElementById('fc-nome');
    var metaEl = document.getElementById('fc-meta');
    var contentEl = document.getElementById('fc-content');
    var btnCompleta = document.getElementById('fc-completa');
    var btnParecer = document.getElementById('fc-parecer');
    var btnImagem = document.getElementById('fc-imagem');
    var btnPront = document.getElementById('fc-pront');
    var prontAtual = '';
    var idAtual = null;

    var _h2c = null;
    function carregarH2C(){
      if(window.html2canvas) return Promise.resolve();
      if(_h2c) return _h2c;
      _h2c = new Promise(function(res, rej){
        var sc = document.createElement('script');
        sc.src = 'https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js';
        sc.onload = res; sc.onerror = rej;
        document.head.appendChild(sc);
      });
      return _h2c;
    }

    function fechar(){ ov.style.display='none'; }
    function abrir(id){
      idAtual = id;
      btnCompleta.href = '/atb/admin/ficha/' + id;
      btnParecer.href  = '/atb/admin/parecer/' + id;
      btnImagem.href   = '/atb/admin/parecer/' + id + '/imagem';
      prontAtual = '';
      carregarH2C().catch(function(){});  // pré-carrega p/ a cópia de imagem ser rápida
      nomeEl.textContent = '—'; metaEl.textContent = '';
      contentEl.innerHTML = '<div class="fc-loading">Carregando…</div>';
      ov.style.display = 'flex';
      fetch('/atb/admin/api/ficha/' + id)
        .then(function(r){return r.json();})
        .then(function(j){
          if(!j || !j.ok){ contentEl.innerHTML = '<div class="fc-loading">Não foi possível carregar.</div>'; return; }
          nomeEl.textContent = j.nome || '—';
          var mrEl = document.getElementById('fc-mr');
          if(mrEl){ if(j.mr){ mrEl.textContent = j.mr; mrEl.style.display=''; } else { mrEl.style.display='none'; mrEl.textContent=''; } }
          var pacsEl = document.getElementById('fc-pacs');
          if(pacsEl){
            if(j.nomePacs){
              pacsEl.innerHTML = '⚠ Nome no PACS: <b>'+j.nomePacs+'</b> <button type="button" id="fc-atu-nome">Atualizar nome</button>';
              pacsEl.style.display='';
              document.getElementById('fc-atu-nome').addEventListener('click', function(){
                var b=this; b.disabled=true; b.textContent='atualizando…';
                fetch('/atb/admin/ficha/'+idAtual+'/atualizar-nome-pacs',{method:'POST'})
                  .then(function(r){return r.json();})
                  .then(function(res){ if(res&&res.ok){ nomeEl.textContent=res.nome; pacsEl.style.display='none'; pacsEl.innerHTML=''; }
                    else { b.disabled=false; b.textContent='Atualizar nome'; } })
                  .catch(function(){ b.disabled=false; b.textContent='Atualizar nome'; });
              });
            } else { pacsEl.style.display='none'; pacsEl.innerHTML=''; }
          }
          metaEl.textContent = j.meta || '';
          prontAtual = j.prontuario || '';
          contentEl.innerHTML = j.html || '<div class="fc-loading">Sem dados.</div>';
        })
        .catch(function(){ contentEl.innerHTML = '<div class="fc-loading">Erro de rede.</div>'; });
    }

    btnPront.addEventListener('click', function(){
      if(!prontAtual){ btnPront.title = 'Sem prontuário'; return; }
      if(navigator.clipboard && navigator.clipboard.writeText){
        navigator.clipboard.writeText(prontAtual).then(function(){
          var antes = btnPront.textContent; btnPront.textContent = '✓';
          setTimeout(function(){ btnPront.textContent = antes; }, 1200);
        }).catch(function(){});
      }
    });

    btnImagem.addEventListener('click', function(ev){
      ev.preventDefault();
      if(!idAtual) return;
      var orig = btnImagem.textContent;
      var abrirPopup = function(){ window.open(btnImagem.href, 'parecer', 'width=1060,height=940'); btnImagem.textContent = orig; };
      if(!(navigator.clipboard && window.ClipboardItem)){ abrirPopup(); return; }
      btnImagem.textContent = '⏳';
      // gera a tabela do parecer (oculta) e copia o PNG; passa Promise<Blob> ao ClipboardItem
      var blobPromise = carregarH2C()
        .then(function(){ return fetch('/atb/admin/parecer/' + idAtual + '/imagem.json'); })
        .then(function(r){ return r.json(); })
        .then(function(j){
          if(!j || !j.ok) throw new Error('fragmento');
          var fonte = document.getElementById('fc-img-fonte');
          fonte.innerHTML = '<style>' + j.css + '</style>' + j.html;
          var card = fonte.querySelector('.parecer-card');
          return window.html2canvas(card, { scale: 2, backgroundColor: null, useCORS: true, logging: false });
        })
        .then(function(canvas){ return new Promise(function(res, rej){ canvas.toBlob(function(b){ b ? res(b) : rej(new Error('blob')); }, 'image/png'); }); });
      navigator.clipboard.write([ new ClipboardItem({ 'image/png': blobPromise }) ])
        .then(function(){ btnImagem.textContent = '✓'; setTimeout(function(){ btnImagem.textContent = orig; }, 1200); })
        .catch(function(){ abrirPopup(); });
    });

    // intercepta o clique no nome do paciente (mantém href como fallback)
    document.querySelectorAll('tr[data-ficha] .pac-link').forEach(function(a){
      a.addEventListener('click', function(ev){
        var tr = a.closest('tr[data-ficha]');
        if(!tr) return;
        ev.preventDefault();
        abrir(tr.getAttribute('data-ficha'));
      });
    });

    document.getElementById('fc-close').addEventListener('click', fechar);
    ov.addEventListener('click', function(ev){ if(ev.target === ov) fechar(); });
    document.addEventListener('keydown', function(ev){ if(ev.key==='Escape') fechar(); });
  })();
  </script>`;

  return css + html + js;
}

// ════════════════════════════════════════════════════════════════════════════
//  ROTA
// ════════════════════════════════════════════════════════════════════════════
export function registerFichaCardRoutes(app, pool, adminRequired) {
  app.get('/atb/admin/api/ficha/:id', adminRequired, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const { rows: [f] } = await pool.query(`
        SELECT f.*, i.sigla AS instituicao,
               e.labs, e.hemodinamica, e.ventilatorio, e.acesso_vascular_neo_evol,
               e.preenchido_por_nome, e.updated_at AS evol_updated
        FROM atb_fichas f
        LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
        LEFT JOIN atb_evolutivos   e ON e.ficha_id = f.id
        WHERE f.id = $1
      `, [id]);
      if (!f) return res.status(404).json({ ok: false, error: 'Ficha não encontrada' });

      // anexos (PDFs + imagens) — servidos por /atb/admin/ficha/:id/anexo/:aid
      const { rows: anexos } = await pool.query(
        `SELECT id, tipo, nome_original FROM atb_ficha_imagens WHERE ficha_id = $1 ORDER BY tipo, id`, [id]);
      f._anexos = anexos;

      const evol = {
        labs: f.labs, hemodinamica: f.hemodinamica, ventilatorio: f.ventilatorio,
        acesso_vascular_neo_evol: f.acesso_vascular_neo_evol,
        preenchido_por_nome: f.preenchido_por_nome, evol_updated: f.evol_updated,
      };
      const nome = f.paciente_nome || f.paciente_nome_raw || '—';
      const idade = _idade(f.paciente_dn, f.paciente_idade);
      const dataFicha = f.data_referencia || f.jotform_created_at || f.created_at;  // data canônica (HUSF e SCMI)
      const metaParts = [
        dataFicha ? 'Ficha ' + _dt(dataFicha) : '',
        f.prontuario ? 'Pront. ' + f.prontuario : '',
        idade || '',
        f.setor || '',
        f.leito ? 'Leito ' + f.leito : '',
        f.equipe_responsavel || '',
        f.instituicao || '',
      ].filter(Boolean);
      if (f.obito) metaParts.push('✝ óbito' + (f.data_obito ? ' ' + _dt(f.data_obito) : ''));

      const culturas = await buscarCulturasDaFicha(pool, f);
      const _np = await buscarNomePacs(pool, f.instituicao_id, f.prontuario);
      const _divergePacs = _np && nomeDivergePacs(f.paciente_nome_raw || f.paciente_nome, _np.nome_pacs_norm);
      res.json({
        ok: true,
        nome: _safe(nome),
        meta: _safe(metaParts.join(' · ')),
        prontuario: f.prontuario || '',
        html: renderCulturasCard(culturas) + renderCardBody(f, evol, _safe),
        mr: culturasTemMR(culturas) ? '⚠ Multirresistente' : null,
        nomePacs: _divergePacs ? _safe(_np.nome_pacs) : null,
      });
    } catch (e) {
      console.error('[atb] ficha card error:', e.message);
      res.status(500).json({ ok: false, error: e.message });
    }
  });
}
