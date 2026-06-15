// ════════════════════════════════════════════════════════════════════════════
//  IMAGEM DO PARECER  —  /atb/admin/parecer/:id/imagem
//
//  Gera a tabela do parecer (idêntica à do JotForm, cabeçalho "Sistema de Uso
//  Racional de Antimicrobianos") para colar como IMAGEM no EMR. Substitui o
//  Apps Script: a página tem botões "Copiar imagem" (clipboard, via html2canvas)
//  e "Baixar PNG".
//
//  Faixa colorida por veredito (recomendacao_scih[0]):
//    Sim          → FAVORÁVEL  (verde)   "Prescrição Adequada de ATB"
//    Não          → NEGATIVO   (vermelho)"Necessário ALTERAR prescrição"
//    Com ajustes… → CONDICIONAL(amarelo) "Necessário AJUSTAR prescrição"
//
//  Integração em atb-routes.js:
//    import { registerParecerImagemRoutes } from './atb-parecer-imagem-routes.js';
//    // em registerAtbRoutes:  registerParecerImagemRoutes(app, pool, adminRequired);
//
//  Botão (abre o popup) — adicione onde quiser (página de parecer, card, ficha):
//    <button onclick="window.open('/atb/admin/parecer/ID/imagem','parecer','width=1060,height=940')">🖼️ Imagem do parecer</button>
//  Sem schema novo — só leitura.
// ════════════════════════════════════════════════════════════════════════════

function _safe(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
const _arr = v => Array.isArray(v) ? v : (v == null ? [] : (typeof v === 'string'
  ? (() => { try { const x = JSON.parse(v); return Array.isArray(x) ? x : []; } catch { return []; } })()
  : []));

function _fmtData(d) {
  if (!d) return '';
  const x = new Date(d);
  if (isNaN(x.getTime())) return '';
  const dd = String(x.getDate()).padStart(2, '0');
  const mm = String(x.getMonth() + 1).padStart(2, '0');
  const yyyy = x.getFullYear();
  let h = x.getHours(); const min = String(x.getMinutes()).padStart(2, '0');
  const ap = h >= 12 ? 'PM' : 'AM'; h = h % 12; if (h === 0) h = 12;
  return `${dd}-${mm}-${yyyy} ${h}:${min} ${ap}`;
}

// veredito → estilo da faixa
function _veredictStyle(v) {
  if (v === 'Sim')
    return { bg: '#138a13', fg: '#ffffff', titulo: 'Parecer FAVORÁVEL - Prescrição Adequada de ATB', rodape: 'fav' };
  if (v === 'Não')
    return { bg: '#8a1414', fg: '#ffffff', titulo: 'Parecer NEGATIVO - Necessário ALTERAR prescrição', rodape: 'padrao' };
  if (/Com ajustes/i.test(v || ''))
    return { bg: '#ffe000', fg: '#8a1414', titulo: 'Parecer CONDICIONAL - Necessário AJUSTAR prescrição', rodape: 'padrao' };
  return { bg: '#5f6368', fg: '#ffffff', titulo: 'Parecer — ' + (v || '—'), rodape: 'padrao' };
}

// ── TABELA DO PARECER (HTML puro, estilável e renderizável por html2canvas) ──
export function renderParecerTabela(f, safe) {
  const s = safe || _safe;
  const inst = f.instituicao || 'HUSF';
  const ver = _arr(f.recomendacao_scih)[0] || '';
  const st = _veredictStyle(ver);
  const dataParecer = _fmtData(f.parecer_emitido_at || f.jotform_created_at || f.created_at);
  const avaliador = 'Dr Leandro Mendes';
  const atb = _arr(f.atb_solicitado).join(', ');

  // linhas (rótulo, valor) — só inclui as condicionais quando há valor
  const linhas = [
    ['Nome*', s(f.paciente_nome || f.paciente_nome_raw || '')],
    ['Data', s(dataParecer)],
    ['Atendimento*', s(f.atendimento || '')],
    ['Prontuário*', s(f.prontuario || '')],
    ['Sepse*', f.sepse === true ? 'Sim' : f.sepse === false ? 'Não' : '—'],
    ['Setor de internação*', s(f.setor || '')],
    ['Leito*', s(f.leito || '')],
    ['Equipe Responsável*', s(f.equipe_responsavel || '')],
    ['ATB solicitado*', s(atb)],
    ['Tempo previsto de tratamento (em dias)*', f.tempo_previsto != null ? s(f.tempo_previsto) : ''],
    ['Médico*', s(f.prescritor_nome || '')],
    ['CRM*', s(f.crm || '')],
    ['Avaliador', s(avaliador)],
    ['Parecer', s(ver || '—')],
  ];
  if (f.recomendacoes_especificacao) linhas.push(['Recomendações do SCIH', s(f.recomendacoes_especificacao)]);
  if (f.ha_esquema_sugerido) linhas.push(['Há sugestão de outro esquema de ATB conforme parecer?', s(f.ha_esquema_sugerido)]);

  const corpo = linhas.map(([k, v, isHtml], idx) => {
    const bg = idx % 2 === 0 ? '#ffffff' : 'transparent';
    return `<tr style="background:${bg}">
      <td class="pk">${s(k)}</td>
      <td class="pv">${isHtml ? v : (v || '')}</td></tr>`;
  }).join('');

  const rodapeFav = '(Parecer inserido no Sistema de Uso Racional de Antimicrobianos e anexado automaticamente; em caso de dúvidas, entrar em contato com o Serviço de Controle de Infecções Hospitalares)';
  const rodapePadrao = '(Parecer emitido com base em informações inseridas pelo prescritor na ficha de solicitação. Em caso de dúvidas quanto ao parecer, considerar solicitação de avaliação da Infectologia)';
  const rodape = st.rodape === 'fav' ? rodapeFav : rodapePadrao;

  return `<div class="parecer-card" id="parecer-card">
    <div class="pc-titulo">Sistema de Uso Racional de Antimicrobianos - ${s(inst)}</div>
    <div class="pc-sub">Parecer sobre solicitação de ATB de uso restrito emitido pelo especialista conforme dados informados na ficha de solicitação pelo prescritor</div>
    <div class="pc-faixa" style="background:${st.bg};color:${st.fg}">${s(st.titulo)}</div>
    <table class="pc-tab"><tbody>${corpo}</tbody></table>
    <div class="pc-rodape">${s(rodape)}</div>
    <div class="pc-rodape">*Dados informados pelo prescritor na ficha de solicitação de ATB</div>
  </div>`;
}

// estilos do cartão (compartilhados entre a página e quem embutir)
function parecerCardCss() {
  return `
    .parecer-card{width:640px;background:#ececec;font-family:Arial,Helvetica,sans-serif;color:#1a1a1a;padding:0 0 12px;border:1px solid #dcdcdc}
    .pc-titulo{text-align:center;font-size:20px;font-weight:700;color:#8a1414;padding:18px 20px 4px;line-height:1.25}
    .pc-sub{text-align:center;font-style:italic;color:#444;font-size:12.5px;padding:6px 44px 14px;line-height:1.4}
    .pc-faixa{text-align:center;font-size:16px;font-weight:700;padding:10px 14px}
    .pc-tab{width:100%;border-collapse:collapse}
    .pc-tab td{padding:9px 18px;font-size:14px;vertical-align:top}
    .pc-tab .pk{width:40%;color:#1a1a1a}
    .pc-tab .pv{color:#1a1a1a}
    .pc-rodape{text-align:center;font-style:italic;color:#777;font-size:11.5px;padding:8px 30px 0;line-height:1.4}`;
}

// ── PÁGINA (popup): tabela + botões Copiar imagem / Baixar PNG ───────────────
function paginaParecerImagem(f, s) {
  const card = renderParecerTabela(f, s);
  const nome = s(f.paciente_nome || f.paciente_nome_raw || 'parecer');
  return `<!DOCTYPE html>
<html lang="pt-BR"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Parecer · ${nome}</title>
<style>
  body{margin:0;background:#eceff3;font-family:Arial,Helvetica,sans-serif}
  .toolbar{position:sticky;top:0;background:#fff;border-bottom:1px solid #dfe3e8;padding:12px 18px;
    display:flex;gap:10px;align-items:center;z-index:10}
  .toolbar button{font-size:14px;padding:9px 18px;border-radius:8px;cursor:pointer;border:1px solid #d0d5dd;background:#fff;color:#0c447c;font-weight:600}
  .toolbar button.prim{background:#00469e;border-color:#00469e;color:#fff}
  .toolbar .msg{font-size:13px;color:#1a6b3a;margin-left:auto}
  .palco{padding:24px;display:flex;justify-content:center}
  ${parecerCardCss()}
</style></head>
<body>
  <div class="toolbar">
    <button class="prim" id="btn-copiar">📋 Copiar imagem</button>
    <button id="btn-baixar">⬇ Baixar PNG</button>
    <button onclick="window.close()">Fechar</button>
    <span class="msg" id="msg"></span>
  </div>
  <div class="palco">
    <div id="fonte" style="position:absolute;left:-99999px;top:0">${card}</div>
    <img id="img-parecer" alt="Parecer" style="max-width:100%;border:1px solid #dcdcdc;box-shadow:0 2px 12px rgba(0,0,0,.08)">
  </div>

  <script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
  <script>
  (function(){
    var fonte = document.getElementById('parecer-card');
    var img = document.getElementById('img-parecer');
    var msg = document.getElementById('msg');
    var nomeArq = ${JSON.stringify((f.paciente_nome || f.paciente_nome_raw || 'parecer').toString().replace(/[^a-zA-Z0-9]+/g, '_'))};
    var blob = null, url = null;

    function show(t, ok){ msg.textContent = t; msg.style.color = ok ? '#1a6b3a' : '#c0392b'; }

    function gerar(){
      return html2canvas(fonte, { scale: 2, backgroundColor: null, useCORS: true, logging: false }).then(function(canvas){
        url = canvas.toDataURL('image/png');
        img.src = url;
        return new Promise(function(res){ canvas.toBlob(function(b){ blob = b; res(b); }, 'image/png'); });
      });
    }

    // gera a imagem assim que a página abre — assim o botão direito "Copiar imagem"
    // já funciona em qualquer navegador (inclusive DuckDuckGo/WebKit)
    gerar().then(function(){
      show('Imagem pronta. Clique com o botão direito → "Copiar imagem", ou use os botões acima.', true);
    }).catch(function(){ show('Erro ao gerar a imagem.', false); });

    document.getElementById('btn-copiar').addEventListener('click', function(){
      if(!(navigator.clipboard && window.ClipboardItem)){
        show('Este navegador não copia via botão — clique com o botão direito na imagem → "Copiar imagem".', false); return;
      }
      var p = blob ? Promise.resolve(blob) : gerar().then(function(){ return blob; });
      navigator.clipboard.write([ new ClipboardItem({ 'image/png': p }) ])
        .then(function(){ show('Imagem copiada! Cole no prontuário (Ctrl+V).', true); })
        .catch(function(){ show('Bloqueado pelo navegador — clique com o botão direito na imagem → "Copiar imagem".', false); });
    });

    document.getElementById('btn-baixar').addEventListener('click', function(){
      if(!url){ show('Aguarde a imagem gerar…', false); return; }
      var a = document.createElement('a');
      a.download = 'parecer_' + nomeArq + '.png';
      a.href = url; a.click();
      show('PNG baixado.', true);
    });
  })();
  </script>
</body></html>`;
}

export function registerParecerImagemRoutes(app, pool, adminRequired) {
  app.get('/atb/admin/parecer/:id/imagem', adminRequired, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const { rows: [f] } = await pool.query(`
        SELECT f.paciente_nome, f.paciente_nome_raw, f.atendimento, f.prontuario, f.sepse,
               f.setor, f.leito, f.equipe_responsavel, f.atb_solicitado, f.tempo_previsto,
               f.posologia, f.prescritor_nome, f.crm, f.avaliador, f.recomendacao_scih,
               f.recomendacoes_especificacao, f.ha_esquema_sugerido,
               f.parecer_emitido_at, f.jotform_created_at, f.created_at,
               i.sigla AS instituicao, u.full_name AS avaliador_user
        FROM atb_fichas f
        LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
        LEFT JOIN users u ON u.id = f.parecer_emitido_por
        WHERE f.id = $1
      `, [id]);
      if (!f) return res.status(404).send('Ficha não encontrada');
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(paginaParecerImagem(f, _safe));
    } catch (e) {
      console.error('[atb] parecer imagem error:', e.message);
      res.status(500).send('Erro: ' + _safe(e.message));
    }
  });
}
