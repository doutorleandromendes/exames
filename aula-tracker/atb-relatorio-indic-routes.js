// atb-relatorio-indic-routes.js
// ════════════════════════════════════════════════════════════════════════════
// RELATÓRIO PDF DOS INDICADORES DO SCIH — competência atual, por escopo.
//
// Gera um relatório diagramado (logo + cabeçalho/rodapé profissionais, A4) com
// os indicadores da COMPETÊNCIA ATUAL exatamente como estão nos portais
// (scih.lcmendes.med.br). A fonte é a MESMA do assistente de indicadores:
// data_iras.json / data_stats.json / data_sahe.json, via carregarDados() —
// então relatório e chatbot leem o mesmo número.
//
// ESCOPOS (querystring ?escopo=):
//   total · isc · mdr · atb · enfermarias · hd · uti · utineo
//
// Restrição: MESMA da consulta/farmácia — admin (cookie) OU IP do hospital
// (temAcesso, fonte única em atb-consulta-routes.js).
//
// Rotas:
//   GET /atb/relatorio-indicadores          — página com os escopos
//   GET /atb/relatorio-indicadores.pdf       — download do PDF
//
// Robustez: cada setor é renderizado percorrendo DINAMICAMENTE as séries
// presentes em data_iras.json — indicadores que o glossário não mapeia (ex.:
// ILAV/Bacteremia da HD, séries da Neo) saem com o valor e o limiar corretos,
// com o rótulo derivado da própria chave quando não há rótulo conhecido.
//
// Montagem (em atb-routes.js, dentro de registerAtbRoutes):
//   import { registerRelatorioIndicRoutes } from './atb-relatorio-indic-routes.js';
//   registerRelatorioIndicRoutes(app, pool, adminRequired);
// (pool não é usado hoje, mas mantém a assinatura homogênea dos módulos.)
// ════════════════════════════════════════════════════════════════════════════

import { temAcesso, paginaRestrito } from './atb-consulta-routes.js';
import { getTenantLogo } from './atb-tenant.js';
import { carregarDados } from './atb-indic-resolver.js';
import { SETORES, INDICADORES } from './atb-indic-glossario.js';

// ── Escopos → setores (chaves do data_iras.json) ────────────────────────────
export const ESCOPOS = {
  total:       { rotulo: 'Panorama institucional',
                 setores: ['global', 'clinicaMedica', 'clinicaCirurgica', 'epm', 'hd', 'utiAB', 'utic', 'utiNeo', 'isc'] },
  isc:         { rotulo: 'Infecções de Sítio Cirúrgico (ISC)', setores: ['isc'] },
  mdr:         { rotulo: 'Microrganismos multirresistentes (MDR)', setores: ['utiAB', 'utic', 'utiNeo'] },
  atb:         { rotulo: 'Consumo de antimicrobianos', setores: ['utiAB', 'utic'] },
  enfermarias: { rotulo: 'Enfermarias — Clínica Médica e Cirúrgica', setores: ['clinicaMedica', 'clinicaCirurgica'] },
  hd:          { rotulo: 'Hemodiálise', setores: ['hd'] },
  uti:         { rotulo: 'UTIs adulto (A/B e C)', setores: ['utiAB', 'utic'] },
  utineo:      { rotulo: 'UTI Neonatal', setores: ['utiNeo'] },
};
function normEscopo(q) {
  const k = String(q || '').trim().toLowerCase();
  return ESCOPOS[k] ? k : 'total';
}

// ── helpers ─────────────────────────────────────────────────────────────────
function safe(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function fmtNum(v) {
  if (v === null || v === undefined || v === '') return '—';
  const n = Number(v);
  if (!isFinite(n)) return safe(v);
  // até 2 casas, sem zeros à toa; vírgula decimal (pt-BR)
  return (Math.round(n * 100) / 100).toString().replace('.', ',');
}
function rotuloSetor(k) { return SETORES[k]?.rotulo || k; }

// Rótulo de um indicador: glossário → tabela extra → chave "humanizada".
// ROTULOS_EXTRA: usado APENAS quando a chave inteira bate (rótulo por extenso).
const ROTULOS_EXTRA = {
  ilav: 'ILAV (infecção de acesso vascular)',
  bact: 'Bacteremia',
  ics: 'ICS (corrente sanguínea)',
  fav: 'FAV', cdl: 'CDL', pc: 'Cateter provisório',
  taxaih: 'Taxa de infecção hospitalar',
};
// ROTULOS_TOKEN: usado na composição de chaves multi-token (forma curta).
// Ex.: 'ilav_cdl' → 'ILAV CDL' (e NÃO 'ILAV (infecção de acesso vascular) CDL').
const ROTULOS_TOKEN = {
  ilav: 'ILAV', bact: 'Bact.', ics: 'ICS', fav: 'FAV', cdl: 'CDL',
  pc: 'PC', taxaih: 'Taxa IH', neo: 'Neo', hd: 'HD',
};
function rotuloIndic(k) {
  if (INDICADORES[k]?.rotulo) return INDICADORES[k].rotulo;
  const low = String(k).toLowerCase();
  if (ROTULOS_EXTRA[low]) return ROTULOS_EXTRA[low];
  // humaniza: separa em _, aplica rótulo curto por token, mantém siglas em caixa alta
  return String(k).replace(/_/g, ' ')
    .split(' ').filter(Boolean)
    .map(t => ROTULOS_TOKEN[t.toLowerCase()] || (t.length <= 4 ? t.toUpperCase() : (t.charAt(0).toUpperCase() + t.slice(1))))
    .join(' ');
}
function unidadeIndic(k) { return INDICADORES[k]?.unidade || ''; }

// Uma "série" é um array não-vazio de pontos { p, v, ... }.
function ehSerie(v) {
  return Array.isArray(v) && v.length > 0 &&
    v.every(x => x && typeof x === 'object' && 'p' in x);
}
function ultimoPonto(serie) { return serie[serie.length - 1]; }

// Zona/percentil/tendência da âncora SAHE, se existir para (setor, indicador).
function saheDe(sahe, setor, ik, periodo) {
  const bloco = sahe?.[setor]?.[ik];
  if (!bloco) return null;
  const meses = bloco.meses || {};
  const mesAtual = meses[periodo] || meses[Object.keys(meses)[Object.keys(meses).length - 1]] || null;
  return {
    zona: mesAtual?.zona ?? null,
    percentil: mesAtual?.pct ?? null,
    p_poisson: mesAtual?.p_poi ?? null,
    mk_p: bloco.mk_p ?? null,
    mk_dir: bloco.mk_dir ?? null,
    mk_tau: bloco.mk_tau ?? null,
    sen: bloco.sen ?? null,
    mk_sig: (bloco.mk_p != null && bloco.mk_p < 0.05),
  };
}

// Extrai as linhas de indicadores de um setor para a competência atual.
function linhasDoSetor(dados, setor) {
  const iras = dados.iras || {};
  const sahe = dados.sahe || null;
  const bloco = iras[setor];
  if (!bloco) return { faltando: true, linhas: [] };
  const limiares = bloco.limiares || {};
  const statusSetor = bloco.status ?? null;
  const linhas = [];

  for (const [k, val] of Object.entries(bloco)) {
    if (k === 'limiares' || k === 'status') continue;
    if (!ehSerie(val)) continue;
    const ult = ultimoPonto(val);
    const periodo = ult?.p ?? null;

    // MDR: pontos trazem e (esbl) / k (kpc) / a (acin).
    const ehMdr = ult && ('e' in ult || 'k' in ult || 'a' in ult);
    const limiarKey = INDICADORES[k]?.limiar;
    const limiar = limiarKey ? (limiares[limiarKey] ?? null) : null;
    const sh = saheDe(sahe, setor, k, periodo);

    linhas.push({
      indicador: k,
      rotulo: rotuloIndic(k),
      unidade: unidadeIndic(k),
      periodo,
      valor: ehMdr ? null : (ult?.v ?? null),
      mdr: ehMdr ? { esbl: ult.e ?? null, kpc: ult.k ?? null, acin: ult.a ?? null, total: ult.v ?? null } : null,
      limiar,
      referencia: INDICADORES[k]?.referencia || null,
      sahe: sh,
      statusSetor,
    });
  }
  // ordem estável: conhecidos (na ordem do glossário) primeiro, extras depois.
  const ordemGloss = Object.keys(INDICADORES);
  linhas.sort((a, b) => {
    const ia = ordemGloss.indexOf(a.indicador), ib = ordemGloss.indexOf(b.indicador);
    const ka = ia < 0 ? 999 : ia, kb = ib < 0 ? 999 : ib;
    return ka - kb || a.rotulo.localeCompare(b.rotulo);
  });
  return { faltando: false, linhas, statusSetor };
}

// ── Renderização de uma linha da tabela ─────────────────────────────────────
function celPosicao(l) {
  // Duas leituras INDEPENDENTES de nível, ambas relevantes e não substituíveis:
  //  (a) SAHE = posição na distribuição histórica do próprio setor (zona/percentil);
  //  (b) limiar = teto pactuado/institucional para o indicador.
  // Um valor pode estar em zona endêmica (normal para a casa) e ainda assim
  // acima do teto — por isso mostramos as duas quando as duas existem.
  const partes = [];
  if (l.sahe && (l.sahe.zona || l.sahe.percentil != null)) {
    const pct = l.sahe.percentil != null ? ` · P${l.sahe.percentil}` : '';
    const zc = {
      'epidemica': '#c0392b', 'epidêmica': '#c0392b', 'alerta': '#d98a1f',
      'endemica': '#2f7d4f', 'endêmica': '#2f7d4f', 'baixa': '#3b7bbf', 'abaixo': '#3b7bbf',
    }[String(l.sahe.zona || '').toLowerCase()] || '#5b6472';
    partes.push(`<span style="color:${zc};font-weight:600">${safe(l.sahe.zona || '—')}${pct}</span>`);
  }
  if (l.limiar != null && l.valor != null) {
    const acima = Number(l.valor) > Number(l.limiar);
    partes.push(acima
      ? `<span style="color:#c0392b;font-weight:600">acima do teto</span>`
      : `<span style="color:#2f7d4f">dentro do previsto</span>`);
  }
  if (!partes.length) return '—';
  if (partes.length === 1) return partes[0];
  return `${partes[0]}<br><span style="font-size:9.5px">${partes[1]}</span>`;
}
// Direção da tendência: o sinal de tau/Sen é a fonte confiável; o texto de
// mk_dir varia de vocabulário ('subindo', 'alta', 'crescente', '+', '↑'…).
function direcaoSobe(sahe) {
  if (sahe.mk_tau != null && isFinite(Number(sahe.mk_tau)) && Number(sahe.mk_tau) !== 0) {
    return Number(sahe.mk_tau) > 0;
  }
  if (sahe.sen != null && isFinite(Number(sahe.sen)) && Number(sahe.sen) !== 0) {
    return Number(sahe.sen) > 0;
  }
  const d = String(sahe.mk_dir ?? '').toLowerCase().trim();
  if (/^\+/.test(d) || d === '↑') return true;
  if (/^-/.test(d) || d === '↓') return false;
  // ATENÇÃO à ordem: 'decrescente' contém 'cresc' — a queda precisa ser testada antes.
  if (/desc|queda|baix|dimin|decres|decreas|down/.test(d)) return false;
  if (/sob|sub|alta|cresc|aument|increas|up/.test(d)) return true;
  return false;
}
function celTendencia(l) {
  if (!l.sahe || l.sahe.mk_p == null) return '—';
  if (!l.sahe.mk_sig) return `<span style="color:#5b6472">sem tendência (p=${fmtNum(l.sahe.mk_p)})</span>`;
  const sobe = direcaoSobe(l.sahe);
  return sobe
    ? `<span style="color:#c0392b;font-weight:600">↑ significativa (p=${fmtNum(l.sahe.mk_p)})</span>`
    : `<span style="color:#2f7d4f;font-weight:600">↓ significativa (p=${fmtNum(l.sahe.mk_p)})</span>`;
}
function celValor(l) {
  if (l.mdr) {
    const p = [];
    if (l.mdr.esbl != null) p.push(`ESBL ${fmtNum(l.mdr.esbl)}`);
    if (l.mdr.kpc != null)  p.push(`KPC ${fmtNum(l.mdr.kpc)}`);
    if (l.mdr.acin != null) p.push(`Acineto ${fmtNum(l.mdr.acin)}`);
    const tot = l.mdr.total != null ? ` <span style="color:#5b6472">(tot ${fmtNum(l.mdr.total)})</span>` : '';
    return (p.join(' · ') || '—') + tot;
  }
  return `<strong>${fmtNum(l.valor)}</strong>`;
}
function celLimiar(l) {
  if (l.referencia) {
    const r = l.referencia;
    const atende = l.valor != null && (r.direcao === 'maior_melhor' ? Number(l.valor) >= r.valor : Number(l.valor) <= r.valor);
    const cor = atende ? '#2f7d4f' : '#c0392b';
    return `<span title="${safe(r.texto || '')}">${r.direcao === 'maior_melhor' ? '≥' : '≤'} ${fmtNum(r.valor)} <span style="color:${cor}">(${atende ? 'atende' : 'não atende'})</span></span>`;
  }
  return l.limiar != null ? `teto ${fmtNum(l.limiar)}` : '—';
}

function tabelaSetor(setor, res) {
  const cab = `<div class="setor-cab">
      <span class="setor-nome">${safe(rotuloSetor(setor))}</span>
      ${res.statusSetor ? `<span class="setor-status">${safe(res.statusSetor)}</span>` : ''}
    </div>`;
  if (res.faltando) {
    return `<section class="setor">${cab}<p class="vazio">Sem dados para este setor na competência atual.</p></section>`;
  }
  if (!res.linhas.length) {
    return `<section class="setor">${cab}<p class="vazio">Nenhum indicador com série ativa.</p></section>`;
  }
  const linhas = res.linhas.map(l => `
      <tr>
        <td class="ind">${safe(l.rotulo)}${l.unidade ? `<span class="un">${safe(l.unidade)}</span>` : ''}</td>
        <td class="comp">${safe(l.periodo || '—')}</td>
        <td class="val">${celValor(l)}</td>
        <td class="lim">${celLimiar(l)}</td>
        <td class="pos">${celPosicao(l)}</td>
        <td class="tend">${celTendencia(l)}</td>
      </tr>`).join('');
  return `<section class="setor">
      ${cab}
      <table class="ind-tab">
        <thead><tr>
          <th>Indicador</th><th>Comp.</th><th>Valor</th><th>Limiar/Ref.</th><th>Posição</th><th>Tendência</th>
        </tr></thead>
        <tbody>${linhas}</tbody>
      </table>
    </section>`;
}

// ── Monta o HTML completo do relatório (PURO — testável sem Puppeteer) ───────
export function montarHtmlRelatorio({ escopoKey, dados, logoDataUri, competencia, statsAviso }) {
  const esc = ESCOPOS[escopoKey] || ESCOPOS.total;
  const emissao = new Date().toLocaleDateString('pt-BR', { timeZone: 'America/Sao_Paulo' });
  const secoes = esc.setores
    .map(s => tabelaSetor(s, linhasDoSetor(dados, s)))
    .join('\n');

  const logo = logoDataUri
    ? `<img class="logo" src="${logoDataUri}" alt="logo">`
    : `<div class="logo-txt">SCIH</div>`;

  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<style>
  @page { size: A4; margin: 18mm 14mm 16mm; }
  *{box-sizing:border-box}
  body{margin:0;font:12px/1.45 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1b2330}
  .cab{display:flex;align-items:center;gap:14px;border-bottom:2px solid #1f6feb;padding-bottom:12px;margin-bottom:6px}
  .logo{height:46px;width:auto;object-fit:contain}
  .logo-txt{height:46px;display:flex;align-items:center;font-weight:800;color:#1f6feb;font-size:22px;letter-spacing:.04em}
  .cab-tit{flex:1}
  .cab-tit h1{margin:0;font-size:18px;letter-spacing:-.01em}
  .cab-tit .sub{color:#5b6472;font-size:12px;margin-top:2px}
  .meta{display:flex;gap:18px;flex-wrap:wrap;margin:10px 0 16px;font-size:12px;color:#3a4453}
  .meta b{color:#1b2330}
  .aviso{background:#fff7e6;border:1px solid #f0d493;color:#8a6410;border-radius:8px;padding:8px 12px;font-size:11.5px;margin-bottom:14px}
  .setor{margin-bottom:16px;page-break-inside:avoid}
  .setor-cab{display:flex;align-items:baseline;gap:10px;margin-bottom:5px}
  .setor-nome{font-size:14px;font-weight:700;color:#12325e}
  .setor-status{font-size:11px;color:#5b6472;background:#eef2f8;border-radius:20px;padding:1px 10px}
  .ind-tab{width:100%;border-collapse:collapse;font-size:11.5px}
  .ind-tab th{text-align:left;background:#f4f6fb;color:#3a4453;font-weight:600;padding:5px 8px;border-bottom:1px solid #dde3ee}
  .ind-tab td{padding:5px 8px;border-bottom:1px solid #eef1f6;vertical-align:top}
  .ind-tab tr:last-child td{border-bottom:none}
  .ind .un{display:block;color:#8a929e;font-size:10px;font-weight:400}
  .comp{white-space:nowrap;color:#3a4453}
  .val strong{font-size:13px}
  .lim,.pos,.tend{white-space:nowrap}
  .vazio{color:#8a929e;font-style:italic;font-size:11.5px;margin:4px 0 0}
  .rodape{margin-top:18px;padding-top:10px;border-top:1px solid #dde3ee;color:#5b6472;font-size:10px;line-height:1.5}
  .rodape b{color:#3a4453}
</style></head><body>
  <div class="cab">
    ${logo}
    <div class="cab-tit">
      <h1>Relatório de Indicadores — SCIH</h1>
      <div class="sub">${safe(esc.rotulo)}</div>
    </div>
  </div>
  <div class="meta">
    <span><b>Competência:</b> ${safe(competencia || '—')}</span>
    <span><b>Escopo:</b> ${safe(esc.rotulo)}</span>
    <span><b>Emitido em:</b> ${safe(emissao)}</span>
  </div>
  ${statsAviso ? `<div class="aviso">${safe(statsAviso)}</div>` : ''}
  ${secoes}
  <div class="rodape">
    <b>Leitura:</b> a coluna <b>Posição</b> traz a zona/percentil histórico (SAHE) quando disponível — nível na
    distribuição histórica, não tendência. A coluna <b>Tendência</b> traz o teste de Mann-Kendall (só quando significativo,
    p&lt;0,05). Onde não há SAHE, a posição compara o valor ao intervalo de predição do modelo (limiar). Um valor pode estar
    em zona alta <b>sem</b> tendência de alta (pico isolado). MDR e consumo de ATB têm veredito estatístico próprio nos portais.<br>
    <b>Dr. Leandro Mendes</b> · Infectologia · CRM 134.985/SP · SCIH — dados agregados, sem identificadores de paciente.
  </div>
</body></html>`;
}

// ── Puppeteer (mesma mecânica do lab-pdf-v2.js) ─────────────────────────────
let _browser = null;
async function getBrowser() {
  const puppeteer = (await import('puppeteer')).default;
  if (!_browser || !_browser.connected) {
    _browser = await puppeteer.launch({
      headless: true,
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || puppeteer.executablePath(),
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
    });
  }
  return _browser;
}
export async function gerarPdfRelatorio(html) {
  const browser = await getBrowser();
  const page = await browser.newPage();
  try {
    await page.setContent(html, { waitUntil: 'networkidle0' });
    return await page.pdf({ format: 'A4', printBackground: true });
  } finally {
    await page.close();
  }
}

// ── Página de seleção de escopo ─────────────────────────────────────────────
function paginaEscopos() {
  const botoes = Object.entries(ESCOPOS).map(([k, v]) =>
    `<a class="btn" href="/atb/relatorio-indicadores.pdf?escopo=${k}" target="_blank" rel="noopener">${safe(v.rotulo)}</a>`).join('');
  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Relatório de Indicadores — SCIH</title>
<style>
  :root{--az:#1f6feb;--bg:#f4f6fb;--tx:#1b2330;--mut:#5b6472;--ln:#dde3ee}
  *{box-sizing:border-box}
  body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--tx);padding:28px 16px}
  .wrap{max-width:680px;margin:0 auto;background:#fff;border:1px solid var(--ln);border-radius:14px;padding:26px 24px;box-shadow:0 1px 3px rgba(20,30,50,.05)}
  h1{margin:0 0 4px;font-size:20px}
  .sub{color:var(--mut);margin:0 0 20px;font-size:14px}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  .btn{display:flex;align-items:center;justify-content:center;text-align:center;padding:15px 14px;border:1px solid var(--ln);border-radius:10px;background:#fbfcfe;color:var(--tx);text-decoration:none;font-weight:600;transition:.12s}
  .btn:hover{border-color:var(--az);background:#eef4ff;color:var(--az)}
  .nota{margin-top:20px;padding-top:16px;border-top:1px solid var(--ln);color:var(--mut);font-size:13px}
  @media(max-width:520px){.grid{grid-template-columns:1fr}}
</style></head><body>
  <div class="wrap">
    <h1>Relatório de Indicadores — SCIH</h1>
    <p class="sub">PDF diagramado da competência atual. Escolha o escopo (abre em nova aba).</p>
    <div class="grid">${botoes}</div>
    <div class="nota">Fonte: mesmos dados dos portais (<code>scih.lcmendes.med.br</code>). A leitura estatística
      (zona/percentil, Mann-Kendall) é idêntica à do assistente de indicadores.</div>
  </div>
</body></html>`;
}

export function registerRelatorioIndicRoutes(app, pool, adminRequired) {
  // Página de escolha — restrita (IP do hospital OU admin).
  app.get('/atb/relatorio-indicadores', (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    if (!temAcesso(req)) return res.send(paginaRestrito(req));
    res.send(paginaEscopos());
  });

  // PDF — mesma restrição.
  app.get('/atb/relatorio-indicadores.pdf', async (req, res) => {
    if (!temAcesso(req)) {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.send(paginaRestrito(req));
    }
    const escopoKey = normEscopo(req.query.escopo);
    try {
      const dados = await carregarDados();
      const competencia = dados.iras?.periodo || null;
      let statsAviso = null;
      const pIras = dados.iras?.periodo, pStats = dados.stats?.meta?.periodo;
      if (pStats && pIras && pStats !== pIras) {
        statsAviso = `As análises estatísticas (tendências) referem-se a ${pStats}; os indicadores estão atualizados até ${pIras}.`;
      }

      const inst = req.atbTenant;
      const logoDataUri = getTenantLogo(inst || 'HUSF') || '';

      const html = montarHtmlRelatorio({ escopoKey, dados, logoDataUri, competencia, statsAviso });
      const pdf = await gerarPdfRelatorio(html);

      const hoje = new Date().toISOString().slice(0, 10);
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition',
        `inline; filename="indicadores_${escopoKey}_${hoje}.pdf"`);
      res.send(pdf);
    } catch (e) {
      console.error('[atb] relatorio-indicadores:', e.message);
      res.status(500).send('Erro ao gerar o relatório: ' + safe(e.message));
    }
  });
}
