// ════════════════════════════════════════════════════════════════════════════
//  FICHA COMPLETA (LEITURA)  —  /atb/admin/ficha/:id
//
//  Substitui a antiga tela "detalhe" (dark theme) por uma leitura clara, fiel ao
//  que o prescritor preencheu, montada a partir das colunas normalizadas (logo,
//  uniforme para as ~17 mil históricas e para as novas). Inclui:
//    • todas as seções do formulário (identificação → prescritor)
//    • culturas, dispositivos, função renal, comorbidades, ATB prévios
//    • séries evolutivas completas (D-3→D+3: EVA, DVA, Labs, Acesso Neo)
//    • complementos do SCIH + parecer (com botão "emitir / editar")
//    • anexos (PDFs e imagens) e acessos (Exames/imagens, LIS)
//
//  Integração em atb-routes.js:
//    import { registerFichaViewRoutes } from './atb-ficha-view-routes.js';
//    // em registerAtbRoutes:  registerFichaViewRoutes(app, pool, adminRequired);
//
//  Repontar links da tela antiga p/ a nova (opcional, recomendado):
//    grade: o nome já abre o popup; troque o fallback e o 📄 de anexos de
//           '/atb/admin/fichas/${f.id}' p/ '/atb/admin/ficha/${f.id}'.
//    Complementação: o "voltar à ficha" → '/atb/admin/ficha/${f.id}'.
//  Sem schema novo — só leitura.
// ════════════════════════════════════════════════════════════════════════════

const DIAS = ['D-3', 'D-2', 'D-1', 'D0', 'D+1', 'D+2', 'D+3'];
const EXAMES = {
  ventilatorio: { titulo: 'Evento Ventilatório Agudo (EVA)', exames: ['PEEP', 'FiO2', 'Rel', 'ST', 'Data'] },
  hemodinamica: { titulo: 'Parâmetros Hemodinâmicos (DVA)', exames: ['Nora', 'Vaso', 'Dobu', 'Lactato', 'Data'] },
  labs:         { titulo: 'Laboratório', exames: ['Leuco', 'Bast', 'Seg', 'Linf', 'Eos', 'Plq', 'Lactato', 'PCR', 'Data'] },
};

function _safe(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
const _arr = v => Array.isArray(v) ? v : (v == null ? [] : (typeof v === 'string'
  ? (() => { try { const x = JSON.parse(v); return Array.isArray(x) ? x : []; } catch { return []; } })()
  : []));
const _obj = v => (v && typeof v === 'object' && !Array.isArray(v)) ? v
  : (typeof v === 'string' ? (() => { try { return JSON.parse(v) || {}; } catch { return {}; } })() : {});
const _bool = b => b === true ? 'Sim' : b === false ? 'Não' : null;
const _dt = d => d ? new Date(d).toLocaleDateString('pt-BR') : null;

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

// bloco de leitura (pares rótulo/valor) — só renderiza itens preenchidos
function bloco(titulo, itens, s) {
  const linhas = itens
    .filter(([, v]) => v !== null && v !== undefined && v !== '' && (!Array.isArray(v) || v.length))
    .map(([k, v]) => {
      const val = Array.isArray(v) ? v.map(s).join(', ') : v;
      return `<div class="row"><div class="k">${s(k)}</div><div class="v">${val}</div></div>`;
    }).join('');
  if (!linhas) return '';
  return `<div class="bloco"><h3>${s(titulo)}</h3>${linhas}</div>`;
}

// tabela de série evolutiva (exames × dias)
function tabelaSerie(cfg, dados, s) {
  const o = _obj(dados);
  if (!Object.keys(o).length) return '';
  const temAlgum = cfg.exames.some(ex => o[ex] && Object.values(_obj(o[ex])).some(x => x !== '' && x != null));
  if (!temAlgum) return '';
  const head = '<th>Exame</th>' + DIAS.map(d => `<th>${d}</th>`).join('');
  const linhas = cfg.exames.map(ex => {
    const serie = _obj(o[ex]);
    const cels = DIAS.map(d => `<td>${s(serie[d] != null && serie[d] !== '' ? serie[d] : '·')}</td>`).join('');
    return `<tr><th class="ex">${s(ex)}</th>${cels}</tr>`;
  }).join('');
  return `<div class="serie"><div class="serie-tit">${s(cfg.titulo)}</div>
    <div class="serie-scroll"><table class="serie-tab"><thead><tr>${head}</tr></thead><tbody>${linhas}</tbody></table></div></div>`;
}

// culturas_colhidas é objeto {tipo: valor/bool}
function culturas(obj, s) {
  const o = _obj(obj);
  const keys = Object.keys(o).filter(k => o[k] === true || (o[k] && o[k] !== false));
  if (!keys.length) return null;
  return keys.map(k => o[k] === true ? s(k) : `${s(k)}: ${s(o[k])}`).join(', ');
}

function paginaFichaView(f, anexos, s) {
  const nome = f.paciente_nome || f.paciente_nome_raw || '—';
  const ver = _arr(f.recomendacao_scih);
  const pos = _arr(f.posologia).map(r => {
    const d = r.droga || r.Droga || '', dose = r.dose || r.Dose || '', iv = r.intervalo || r.Intervalo || '';
    return [d, dose, iv].filter(Boolean).map(s).join(' · ');
  }).filter(Boolean);

  // seções
  const secoes = [];

  secoes.push(bloco('Identificação', [
    ['Nome', s(nome)],
    ['Prontuário', s(f.prontuario)],
    ['Atendimento', s(f.atendimento)],
    ['Idade', _idade(f.paciente_dn, f.paciente_idade)],
    ['Data de nascimento', _dt(f.paciente_dn)],
  ], s));

  secoes.push(bloco('Internação', [
    ['Setor', s(f.setor)],
    ['Leito', s(f.leito)],
    ['Equipe responsável', s(f.equipe_responsavel)],
    ['Data de internação', _dt(f.data_internacao)],
    ['Admissão na UTI', _dt(f.data_admissao_uti)],
    ['Gestante', _bool(f.gestante)],
    ['Lactante', _bool(f.lactante)],
  ], s));

  secoes.push(bloco('Tipo de terapia', [['Tipo de uso', s(f.tipo_terapia)]], s));

  secoes.push(bloco('Contexto clínico', [
    ['História da infecção', f.historia_clinica ? s(f.historia_clinica) : null],
    ['Foco de infecção', s(f.foco_infeccao)],
    ['Sepse', _bool(f.sepse)],
    ['SOFA', f.sofa != null ? s(f.sofa) : null],
  ], s));

  if (f.tipo_terapia === 'Profilaxia cirúrgica' || f.cirurgia) {
    secoes.push(bloco('Cirurgia', [
      ['Cirurgia', f.cirurgia ? s(f.cirurgia) : null],
      ['Fratura (Gustillo-Anderson)', s(f.classificacao_fratura)],
    ], s));
  }

  secoes.push(bloco('Comorbidades / antecedentes', [
    ['Comorbidades', _arr(f.comorbidades)],
    ['Faz quimioterapia', _bool(f.faz_quimio)],
    ['Cateter de quimio', _bool(f.cateter_quimio)],
    ['Acesso de quimio', s(f.acesso_quimio)],
  ], s));

  secoes.push(bloco('Antimicrobianos prévios (7 dias)', [
    ['Usou ATB nos últimos 7 dias', _bool(f.uso_atb_7d)],
    ['ATB prévios', _arr(f.atb_previos)],
  ], s));

  secoes.push(bloco('Culturas', [
    ['Culturas colhidas', culturas(f.culturas_colhidas, s)],
    ['Culturas prévias', _arr(f.culturas_previas)],
  ], s));

  secoes.push(bloco('Dispositivos invasivos', [
    ['Dispositivos', _arr(f.dispositivos_invasivos)],
    ['Sítio CVC', _arr(f.sitio_cvc)],
    ['Sítio CDL', _arr(f.sitio_cdl)],
    ['Sítio PAi', _arr(f.sitio_pai)],
    ['Inserção do cateter', _dt(f.data_insercao_cateter)],
    ['Em diálise', _bool(f.dialise)],
    ['Acesso para diálise', s(f.acesso_dialise)],
    ['Peso ao nascimento', f.peso_nascimento != null ? s(f.peso_nascimento) + ' g' : null],
    ['Acesso vascular (Neo)', _arr(f.acesso_vascular_neo)],
  ], s));

  secoes.push(bloco('Função renal', [
    ['Insuficiência renal', _arr(f.insuficiencia_renal)],
    ['ClCr', f.clcr != null ? s(f.clcr) : null],
    ['Peso', f.peso != null ? s(f.peso) + ' kg' : null],
    ['Altura', f.altura != null ? s(f.altura) : null],
  ], s));

  secoes.push(bloco('Antimicrobiano solicitado', [
    ['ATB', _arr(f.atb_solicitado)],
    ['Posologia', pos.length ? pos.map(p => `<div>${p}</div>`).join('') : null],
    ['Tempo previsto', f.tempo_previsto != null ? s(f.tempo_previsto) + ' dias' : null],
    ['Associação com oxacilina', _bool(f.oxacilina_associacao)],
  ], s));

  secoes.push(bloco('Prescritor', [
    ['Nome', s(f.prescritor_nome)],
    ['CRM', s(f.crm)],
  ], s));

  // séries evolutivas completas
  let seriesHtml = '';
  for (const key of ['ventilatorio', 'hemodinamica', 'labs']) {
    seriesHtml += tabelaSerie(EXAMES[key], f[key], s);
  }

  // complementos SCIH
  const parecerEvol = _arr(f.parecer_evolutivo).map(s).filter(Boolean).join('<br>');
  const compBloco = bloco('Complementos do SCIH', [
    ['Complemento SCIH', f.complemento_scih ? s(f.complemento_scih) : null],
    ['Parecer evolutivo', parecerEvol || null],
    ['Preenchido por', f.preenchido_por_nome ? s(f.preenchido_por_nome) : null],
  ], s);

  // parecer (veredito + especificação) — leitura + botão
  const parecerBloco = `<div class="bloco parecer">
    <h3>Parecer SCIH</h3>
    <div class="row"><div class="k">Veredito</div><div class="v">${ver.length ? ver.map(s).join(', ') : '—'}</div></div>
    <div class="row"><div class="k">Especificação</div><div class="v">${f.recomendacoes_especificacao ? s(f.recomendacoes_especificacao) : '—'}</div></div>
    <div class="row"><div class="k">Recomendações adicionais</div><div class="v">${f.recomendacoes_adicionais ? s(f.recomendacoes_adicionais) : '—'}</div></div>
    <a class="btn-parecer" href="/atb/admin/parecer/${f.id}">✎ Emitir / editar parecer</a>
  </div>`;

  // anexos
  const pdfs = (anexos || []).filter(a => a.tipo === 'pdf');
  const imgs = (anexos || []).filter(a => a.tipo !== 'pdf');
  let anexosHtml = '';
  if (pdfs.length || imgs.length) {
    const pdfLinks = pdfs.map(a => `<a class="anexo-pdf" target="_blank" rel="noopener" href="/atb/admin/ficha/${f.id}/anexo/${a.id}">📄 ${s(a.nome_original || ('PDF ' + a.id))}</a>`).join('');
    const imgThumbs = imgs.map(a => `<a target="_blank" rel="noopener" href="/atb/admin/ficha/${f.id}/anexo/${a.id}" title="${s(a.nome_original || '')}"><img class="anexo-img" loading="lazy" src="/atb/admin/ficha/${f.id}/anexo/${a.id}"></a>`).join('');
    anexosHtml = `<div class="bloco"><h3>Anexos</h3>
      ${pdfLinks ? `<div class="anexo-pdfs">${pdfLinks}</div>` : ''}
      ${imgThumbs ? `<div class="anexo-imgs">${imgThumbs}</div>` : ''}</div>`;
  }

  // acessos
  const links = [];
  if (f.link_exames) links.push(`<a class="acesso" target="_blank" rel="noopener" href="${s(f.link_exames)}">🔗 Exames / imagens</a>`);
  if (f.link_labs)   links.push(`<a class="acesso" target="_blank" rel="noopener" href="${s(f.link_labs)}">🔬 LIS (labs)</a>`);
  const acessosHtml = links.length ? `<div class="bloco"><h3>Acessos</h3><div class="acessos">${links.join('')}</div></div>` : '';

  const meta = [
    f.prontuario ? 'Pront. ' + f.prontuario : '', f.setor || '', f.leito ? 'Leito ' + f.leito : '',
    f.equipe_responsavel || '', f.instituicao || '',
  ].filter(Boolean).map(s).join(' · ');

  return `<!DOCTYPE html>
<html lang="pt-BR"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ficha · ${s(nome)}</title>
<style>
  :root{--azul:#00469e;--azul-claro:#e6eef8;--azul-texto:#0c447c;--tinta:#1a2733;--tinta-suave:#3a4654;
    --borda:#d8dee6;--fundo:#f4f6f9}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--fundo);
    color:var(--tinta);font-size:14px;line-height:1.5;padding-bottom:40px}
  .cab{background:#fff;border-bottom:2px solid var(--azul);padding:14px 22px;display:flex;align-items:flex-start;
    justify-content:space-between;gap:12px;flex-wrap:wrap}
  .cab .nome{font-size:17px;font-weight:700;color:var(--azul-texto)}
  .cab .meta{font-size:12px;color:var(--tinta-suave);margin-top:3px}
  .cab .obito{color:#e12229;font-weight:600}
  .cab a{font-size:12px;color:var(--azul);text-decoration:none;white-space:nowrap}
  .wrap{max-width:860px;margin:18px auto;padding:0 16px;display:grid;grid-template-columns:1fr 1fr;gap:14px}
  .wrap .full{grid-column:1/-1}
  .bloco{background:#fff;border:1px solid var(--borda);border-radius:10px;padding:14px 16px}
  .bloco h3{font-size:11px;font-weight:700;color:var(--azul-texto);text-transform:uppercase;letter-spacing:.04em;
    margin-bottom:9px;padding-bottom:7px;border-bottom:1px solid #eef1f5}
  .row{display:flex;gap:10px;padding:4px 0;align-items:flex-start}
  .row .k{flex:0 0 160px;color:var(--tinta-suave);font-size:12px}
  .row .v{flex:1;color:var(--tinta);white-space:pre-wrap;word-break:break-word}
  .bloco.parecer{grid-column:1/-1;border-color:#bcd0ec;background:#fbfdff}
  .btn-parecer{display:inline-block;margin-top:10px;padding:9px 16px;background:var(--azul);color:#fff;
    border-radius:8px;text-decoration:none;font-size:13px;font-weight:600}
  .serie{margin-top:12px}
  .serie-tit{font-size:12px;font-weight:600;color:var(--azul-texto);margin-bottom:6px}
  .serie-scroll{overflow-x:auto;border:1px solid #eef1f5;border-radius:8px}
  .serie-tab{border-collapse:collapse;width:100%;font-size:12px;min-width:480px}
  .serie-tab th,.serie-tab td{border:1px solid #eef1f5;padding:5px 8px;text-align:center}
  .serie-tab thead th{background:#eef4fc;color:var(--azul-texto);font-weight:600}
  .serie-tab th.ex{text-align:left;background:#fafbfc;color:var(--tinta-suave);font-weight:500}
  .anexo-pdfs{display:flex;flex-direction:column;gap:6px;margin-bottom:10px}
  .anexo-pdf{font-size:13px;color:var(--azul);text-decoration:none}
  .anexo-imgs{display:flex;flex-wrap:wrap;gap:8px}
  .anexo-img{width:96px;height:96px;object-fit:cover;border:1px solid var(--borda);border-radius:8px}
  .acessos{display:flex;flex-wrap:wrap;gap:8px}
  .acesso{display:inline-flex;align-items:center;gap:5px;font-size:13px;text-decoration:none;padding:8px 13px;
    border:1px solid #bcd0ec;border-radius:8px;background:#eef4fc;color:var(--azul-texto);font-weight:500}
  @media(max-width:680px){.wrap{grid-template-columns:1fr}.row .k{flex-basis:120px}}
</style></head>
<body>
  <div class="cab">
    <div>
      <div class="nome">${s(nome)} ${f.obito ? '<span class="obito">✝ óbito' + (f.data_obito ? ' ' + _dt(f.data_obito) : '') + '</span>' : ''}</div>
      <div class="meta">${meta}</div>
    </div>
    <div style="display:flex;gap:14px">
      <a href="/atb/admin/complementar/${f.id}">+ Complementar</a>
      <a href="/atb/admin/grid">← Grade</a>
    </div>
  </div>
  <div class="wrap">
    ${parecerBloco}
    ${secoes.filter(Boolean).join('')}
    ${seriesHtml ? `<div class="bloco full"><h3>Séries evolutivas (D-3 → D+3)</h3>${seriesHtml}</div>` : ''}
    ${compBloco ? `<div class="full">${compBloco}</div>` : ''}
    ${anexosHtml ? `<div class="full">${anexosHtml}</div>` : ''}
    ${acessosHtml ? `<div class="full">${acessosHtml}</div>` : ''}
  </div>
</body></html>`;
}

export function registerFichaViewRoutes(app, pool, adminRequired) {
  app.get('/atb/admin/ficha/:id', adminRequired, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const { rows: [f] } = await pool.query(`
        SELECT f.*, i.sigla AS instituicao,
               e.labs, e.hemodinamica, e.ventilatorio, e.acesso_vascular_neo_evol,
               e.preenchido_por_nome
        FROM atb_fichas f
        LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
        LEFT JOIN atb_evolutivos   e ON e.ficha_id = f.id
        WHERE f.id = $1
      `, [id]);
      if (!f) return res.status(404).send('Ficha não encontrada');
      const { rows: anexos } = await pool.query(
        `SELECT id, tipo, nome_original FROM atb_ficha_imagens WHERE ficha_id = $1 ORDER BY tipo, id`, [id]);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(paginaFichaView(f, anexos, _safe));
    } catch (e) {
      console.error('[atb] ficha view error:', e.message);
      res.status(500).send('Erro: ' + _safe(e.message));
    }
  });
}
