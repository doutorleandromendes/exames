// atb-posologia-normalizar-routes.js
// ─────────────────────────────────────────────────────────────────────────
// Normalização da posologia histórica: converte os campos de TEXTO LIVRE
// (dose / intervalo) para o modelo estruturado, de forma ADITIVA.
//
// Cada linha da matriz ganha chaves novas, sem perder as antigas:
//   dose_valor    NUMBER   ex.: 4.5
//   dose_unidade  TEXT     mg | g | UI | amp | mg/kg
//   freq_tipo     TEXT     cada | unica | hd
//   freq_horas    NUMBER   6, 8, 12, 24... (só quando freq_tipo='cada')
//
// Por que aditivo: os textos originais ficam intactos, então (a) nada quebra
// durante a transição, (b) o "de → para" é auditável, e (c) reverter é
// possível. Os leitores usam o estruturado quando existir e caem no texto
// legado quando não.
//
// O parser NUNCA chuta: valor sem unidade só é resolvido via a droga da mesma
// linha (que já vem normalizada do catálogo). Sem essa âncora, vai para revisão
// manual — inventar unidade contaminaria justamente o dado que queremos limpar.

import { page, esc } from './atb-regras-routes.js';

// Faixas de dose PLAUSÍVEIS por droga e unidade — usadas SÓ para desambiguar um
// valor digitado sem unidade (ex.: "1" em Amicacina = 1 g; "500" = 500 mg).
// NÃO são validação clínica: existem apenas para separar g de mg, e são
// deliberadamente largas. A separação funciona porque as faixas não se
// sobrepõem — o que dissolve o caso adulto (g) vs pediatria/neo (mg) sem
// precisar olhar o setor: a magnitude denuncia a unidade.
// Se um valor cair em NENHUMA faixa, ou em DUAS, vai para revisão — nunca chute.
export const DOSE_PLAUSIVEL = {
  'Cefepime':                     { g: [0.25, 4] },
  'Ceftriaxone':                  { g: [0.25, 4] },
  'Fosfomicina':                  { g: [1, 12] },
  'Meropenem':                    { g: [0.25, 3] },
  'Piperacilina/Tazobactam':      { g: [2, 6] },
  'Vancomicina':                  { g: [0.25, 3],  mg: [50, 3000] },
  'Amicacina':                    { g: [0.25, 2],  mg: [50, 2000] },
  'Gentamicina':                  { mg: [5, 600] },
  'Teicoplanina':                 { mg: [100, 1200] },
  'Daptomicina':                  { mg: [100, 1000] },
  'Tigeciclina':                  { mg: [25, 200] },
  'Micafungina':                  { mg: [50, 300] },
  'Anfotericina B':               { mg: [5, 500] },
  'Polimixina B':                 { UI: [100000, 3000000], mg: [10, 400] },
  'Polimixina E (colestimetato)': { mg: [50, 1000] },
  // Fora do catálogo atual de 16, mas presentes no histórico (era JotForm):
  'Ampicilina/Sulbactam':         { g: [0.75, 6] },
  'Oxacilina':                    { g: [0.5, 3],  mg: [100, 3000] },
  'NÃO PADRONIZADO':              {},
};

const _norm = (v) => String(v == null ? '' : v).toLowerCase().trim().replace(/\s+/g, ' ');

// ── INTERVALO ──
export function parseIntervalo(txt) {
  const s = _norm(txt);
  if (!s) return null;
  // "dose única" (com ou sem observação entre parênteses)
  if (/^(dose )?[uú]nic[ao]\b/.test(s) || s === 'agora') return { freq_tipo: 'unica', freq_horas: null };
  if (/^1 ?x( ?\/? ?(dia|ao dia))?$/.test(s)) return { freq_tipo: 'cada', freq_horas: 24 };
  if (/(p[oó]s|ap[oó]s)\s+(cada\s+)?(hd|di[aá]lise)|dias de di[aá]lise/.test(s)) return { freq_tipo: 'hd', freq_horas: null };
  // Esquema em duas fases ("cada 8h nas primeiras 24h, depois cada 24h") → revisão:
  // extrair só o primeiro perderia o esquema real.
  if (/primeir[ao]s?\s+\d+\s*h|logo\b|depois\b/.test(s)) return null;
  // X/Xh no INÍCIO — a nota que vem depois ("> ajuste renal", "inalatória") é
  // observação clínica, não altera a frequência.
  let m = s.match(/^(\d{1,2})\s*\/\s*(\d{1,2})\s*(h|hs|hrs|horas?)?\b/);
  if (m && m[1] === m[2]) return { freq_tipo: 'cada', freq_horas: +m[1] };
  m = s.match(/^(?:1\s+dose\s+)?a?\s*cada\s+(\d{1,2})\s*(h|hs|hrs|horas?)/);
  if (m) return { freq_tipo: 'cada', freq_horas: +m[1] };
  m = s.match(/^(\d{1,2})\s*(h|hs|hrs|horas?)\b/);
  if (m) return { freq_tipo: 'cada', freq_horas: +m[1] };
  m = s.match(/^(\d{1,2})$/);
  if (m) return { freq_tipo: 'cada', freq_horas: +m[1] };
  return null;
}

// ── DOSE ── (droga é usada só para resolver valor sem unidade)
export function parseDose(txt, droga) {
  let s = _norm(txt);
  if (!s) return null;
  // Múltiplas doses (ataque + manutenção, "1g / 500mg") → NUNCA extrair: qual das
  // duas seria "a" dose? Vai para revisão. Essa nuance mora na história clínica.
  if (/ataque|manuten|;|\+|\d\s*\/\s*\d\s*(mg|g)/.test(s)) return null;
  // Nome de droga escrito junto (ficha com droga trocada) → revisão.
  if (/amoxicilina|clavulanato|meropenem|vancomicina|cefepime|ceftriaxone/.test(s) && droga && !s.startsWith(_norm(droga)))
    return null;
  s = s.replace(/^\D*?(?=[\d])/, '');          // tira prefixo textual ("meropenem 1g" → "1g")
  // mg/kg em todas as grafias: "mg/kg", "mg kg", "mgkg", "mgkgdose"
  let m = s.match(/^([\d.,]+)\s*mg\s*\/?\s*kg/);
  if (m) return { dose_valor: +m[1].replace(',', '.'), dose_unidade: 'mg/kg' };
  // frasco-ampola / ampola / frascos
  m = s.match(/^(\d{1,2})\s*(amp|ampola|fa|frasco)/);
  if (m) return { dose_valor: +m[1], dose_unidade: 'amp' };
  // número + unidade (aceita U/UI para polimixina; "mk" é erro de digitação de mg)
  m = s.match(/^([\d.,]+)\s*(mg|mk|g|gr|ui|u)\b/);
  if (m) {
    const u = m[2];
    const un = (u === 'gr') ? 'g' : (u === 'mk') ? 'mg' : (u === 'ui' || u === 'u') ? 'UI' : u;
    return { dose_valor: +m[1].replace(',', '.'), dose_unidade: un };
  }
  // número puro → desambigua pela faixa plausível da droga
  m = s.match(/^([\d.,]+)\b/);
  if (m) {
    const v = +m[1].replace(',', '.');
    const faixas = DOSE_PLAUSIVEL[String(droga || '').trim()] || {};
    const cabem = Object.entries(faixas).filter(([, [lo, hi]]) => v >= lo && v <= hi).map(([u]) => u);
    if (cabem.length === 1) return { dose_valor: v, dose_unidade: cabem[0], _porDroga: true };
    return { _ambiguo: true, dose_valor: v, droga: droga || '(sem droga)',
             motivo: cabem.length ? `cabe em ${cabem.join(' e ')}` : 'fora das faixas plausíveis' };
  }
  return null;
}

// Normaliza uma linha; devolve as chaves novas + o diagnóstico.
export function normalizarLinha(row) {
  if (!row || typeof row !== 'object') return null;
  const droga = row.droga || row.Droga || '';
  const dTxt = row.dose || row.Dose || '';
  const iTxt = row.intervalo || row.Intervalo || '';
  const d = parseDose(dTxt, droga);
  const i = parseIntervalo(iTxt);
  return {
    droga, dTxt, iTxt,
    dose: d, intervalo: i,
    doseOk: !!(d && !d._ambiguo), doseAmbigua: !!(d && d._ambiguo), doseFalha: !!(dTxt && !d),
    intOk: !!i, intFalha: !!(iTxt && !i),
  };
}

export function textoPosologia(row) {
  if (!row || typeof row !== 'object') return null;
  const temEstrut = row.dose_valor !== undefined && row.dose_valor !== null && row.dose_valor !== '';
  const dose = temEstrut
    ? String(row.dose_valor).replace('.', ',') + (row.dose_unidade ? ' ' + row.dose_unidade : '')
    : String(row.dose || row.Dose || '');
  let freq;
  if (row.freq_tipo === 'cada' && row.freq_horas) freq = row.freq_horas + '/' + row.freq_horas + 'h';
  else if (row.freq_tipo === 'unica') freq = 'dose \u00fanica';
  else if (row.freq_tipo === 'hd') freq = 'ap\u00f3s cada HD';
  else freq = String(row.intervalo || row.Intervalo || '');
  return { droga: String(row.droga || row.Droga || ''), dose, freq };
}

export function registerPosologiaNormalizarRoutes(app, pool, adminRequired) {
  const soSuper = [adminRequired, (req, res, next) => {
    if (req.user?.super_admin || req.cookies?.adm === '1') return next();
    res.status(403).send(page('Sem acesso', '<div class="card"><h1>Acesso restrito</h1></div>'));
  }];

  async function coletar() {
    const { rows } = await pool.query(
      `SELECT id, posologia FROM atb_fichas
        WHERE deletado_em IS NULL AND jsonb_typeof(posologia) = 'array'`);
    const st = { fichas: rows.length, linhas: 0, doseOk: 0, dosePorDroga: 0, doseAmbigua: 0, doseFalha: 0,
                 intOk: 0, intFalha: 0, vazias: 0, comDose: 0, comInt: 0, fichasComDose: 0 };
    const falhas = [], ambiguas = new Map(), amostra = [];
    const porFicha = new Map();
    for (const f of rows) {
      const novas = [];
      let mudou = false;
      for (const row of (f.posologia || [])) {
        const r = normalizarLinha(row);
        if (!r) { novas.push(row); continue; }
        st.linhas++;
        if (!r.dTxt && !r.iTxt) st.vazias++;
        if (r.dTxt) st.comDose++;
        if (r.iTxt) st.comInt++;
        if (r.doseOk) { st.doseOk++; if (r.dose._porDroga) st.dosePorDroga++; }
        if (r.doseAmbigua) {
          st.doseAmbigua++;
          const k = `${r.dose.droga} · "${r.dTxt}" — ${r.dose.motivo || "sem faixa"}`;
          ambiguas.set(k, (ambiguas.get(k) || 0) + 1);
        }
        if (r.doseFalha) { st.doseFalha++; falhas.push({ id: f.id, campo: 'dose', droga: r.droga, txt: r.dTxt }); }
        if (r.intOk) st.intOk++;
        if (r.intFalha) { st.intFalha++; falhas.push({ id: f.id, campo: 'intervalo', droga: r.droga, txt: r.iTxt }); }
        // monta a linha nova (aditiva)
        const nova = { ...row };
        if (r.doseOk) { nova.dose_valor = r.dose.dose_valor; nova.dose_unidade = r.dose.dose_unidade; mudou = true; }
        if (r.intOk) { nova.freq_tipo = r.intervalo.freq_tipo; nova.freq_horas = r.intervalo.freq_horas; mudou = true; }
        novas.push(nova);
        if (amostra.length < 12 && (r.doseOk || r.intOk))
          amostra.push({ id: f.id, droga: r.droga, de: `${r.dTxt} · ${r.iTxt}`,
            para: `${r.doseOk ? r.dose.dose_valor + ' ' + r.dose.dose_unidade : '—'} · ${r.intOk ? (r.intervalo.freq_tipo === 'cada' ? 'a cada ' + r.intervalo.freq_horas + 'h' : r.intervalo.freq_tipo === 'unica' ? 'dose única' : 'após HD') : '—'}` });
      }
      if (mudou) porFicha.set(f.id, novas);
      if ((f.posologia || []).some((r) => r && typeof r === 'object' && String(r.dose || r.Dose || '').trim())) st.fichasComDose++;
    }
    // Auto-checagem: se a aritmética não fecha, o preview mente — e um preview que
    // mente é pior que preview nenhum. Melhor gritar do que exibir número errado.
    st.coerente = (st.doseOk + st.doseAmbigua + st.doseFalha === st.comDose)
               && (st.intOk + st.intFalha === st.comInt);
    return { st, falhas, ambiguas, amostra, porFicha };
  }

  // ── PREVIEW (dry-run — não escreve nada) ──
  app.get('/atb/admin/posologia/normalizar', soSuper, async (req, res) => {
    try {
      const { st, falhas, ambiguas, amostra, porFicha } = await coletar();
      const pct = (n, t) => t ? ((100 * n) / t).toFixed(1) + '%' : '—';
      const linhasAmb = [...ambiguas.entries()].sort((a, b) => b[1] - a[1])
        .map(([k, n]) => `<tr><td style="padding:3px 8px">${esc(k)}</td><td style="padding:3px 8px">${n}</td></tr>`).join('');
      const linhasFalha = falhas.slice(0, 60)
        .map((f) => `<tr><td style="padding:3px 8px"><a href="/atb/admin/ficha/${f.id}">${f.id}</a></td><td style="padding:3px 8px">${esc(f.droga)}</td><td style="padding:3px 8px">${esc(f.campo)}</td><td style="padding:3px 8px"><code>${esc(f.txt)}</code></td></tr>`).join('');
      const linhasAmostra = amostra
        .map((a) => `<tr><td style="padding:3px 8px">${a.id}</td><td style="padding:3px 8px">${esc(a.droga)}</td><td style="padding:3px 8px"><code>${esc(a.de)}</code></td><td style="padding:3px 8px">→ <strong>${esc(a.para)}</strong></td></tr>`).join('');
      const semUnidade = Object.entries(DOSE_PLAUSIVEL).filter(([, v]) => !v || !Object.keys(v).length).map(([k]) => k);

      res.send(page('Normalizar posologia — preview', `
        <div class="card">
          <h1>Normalizar posologia <span class="nota">(preview — nada foi gravado)</span></h1>
          <p class="mut">Converte <code>dose</code>/<code>intervalo</code> de texto livre para o modelo estruturado, de forma aditiva: os textos originais permanecem.</p>
        </div>
        ${st.coerente ? '' : `<div class="card" style="border-left:3px solid #c5221f">
          <h2>⚠ Números inconsistentes</h2>
          <p class="nota">A soma dos classificadores não fecha com o total de linhas — os percentuais abaixo não são confiáveis. Isto é bug do preview, não do dado.</p>
        </div>`}
        <div class="card">
          <h2>Resumo</h2>
          <table style="font-size:14px">
            <tr><td style="padding:4px 10px">Fichas com linhas de posologia</td><td><strong>${st.fichas}</strong></td><td class="nota">${st.fichasComDose} têm dose escrita (as demais são da era JotForm, que não tinha o campo)</td></tr>
            <tr><td style="padding:4px 10px">Linhas de posologia</td><td><strong>${st.linhas}</strong></td><td class="nota">${st.vazias} sem dose nem intervalo</td></tr>
            <tr style="border-top:1px solid #eee"><td style="padding:4px 10px"><strong>Linhas com dose escrita</strong></td><td><strong>${st.comDose}</strong></td><td class="nota">← denominador da dose</td></tr>
            <tr><td style="padding:4px 10px">· reconhecida</td><td><strong>${st.doseOk}</strong></td><td class="nota">${pct(st.doseOk, st.comDose)} — sendo ${st.dosePorDroga} pela faixa da droga</td></tr>
            <tr><td style="padding:4px 10px">· ambígua</td><td><strong>${st.doseAmbigua}</strong></td><td class="nota">${pct(st.doseAmbigua, st.comDose)}</td></tr>
            <tr><td style="padding:4px 10px">· não reconhecida</td><td><strong>${st.doseFalha}</strong></td><td class="nota">${pct(st.doseFalha, st.comDose)} — revisão manual</td></tr>
            <tr style="border-top:1px solid #eee"><td style="padding:4px 10px"><strong>Linhas com intervalo escrito</strong></td><td><strong>${st.comInt}</strong></td><td class="nota">← denominador do intervalo</td></tr>
            <tr><td style="padding:4px 10px">· reconhecido</td><td><strong>${st.intOk}</strong></td><td class="nota">${pct(st.intOk, st.comInt)}</td></tr>
            <tr><td style="padding:4px 10px">· não reconhecido</td><td><strong>${st.intFalha}</strong></td><td class="nota">${pct(st.intFalha, st.comInt)} — revisão manual</td></tr>
            <tr><td style="padding:4px 10px">Fichas que seriam alteradas</td><td><strong>${porFicha.size}</strong></td><td></td></tr>
          </table>
        </div>
        ${semUnidade.length ? `<div class="card" style="border-left:3px solid #e8a33d">
          <h2>⚠ Definir antes de aplicar</h2>
          <p class="nota">Estas drogas não têm unidade padrão, então valores sem unidade ficam ambíguos:</p>
          <p style="font-size:14px"><strong>${semUnidade.map(esc).join(' · ')}</strong></p>
          <p class="nota">Ajuste <code>DOSE_PLAUSIVEL</code> em <code>atb-posologia-normalizar-routes.js</code>.</p>
        </div>` : ''}
        <div class="card">
          <h2>Amostra do "de → para"</h2>
          <table style="font-size:13px;border-collapse:collapse;width:100%">
            <thead><tr style="text-align:left;color:#80868b"><th style="padding:3px 8px">Ficha</th><th style="padding:3px 8px">Droga</th><th style="padding:3px 8px">Hoje</th><th style="padding:3px 8px">Viraria</th></tr></thead>
            <tbody>${linhasAmostra || '<tr><td class="mut">—</td></tr>'}</tbody>
          </table>
        </div>
        ${linhasAmb ? `<div class="card">
          <h2>Ambíguas <span class="nota">(valor sem unidade)</span></h2>
          <table style="font-size:13px;border-collapse:collapse">
            <thead><tr style="text-align:left;color:#80868b"><th style="padding:3px 8px">Droga · valor</th><th style="padding:3px 8px">Linhas</th></tr></thead>
            <tbody>${linhasAmb}</tbody></table>
        </div>` : ''}
        ${linhasFalha ? `<div class="card">
          <h2>Não reconhecidas <span class="nota">(${falhas.length} — mostrando até 60)</span></h2>
          <table style="font-size:13px;border-collapse:collapse;width:100%">
            <thead><tr style="text-align:left;color:#80868b"><th style="padding:3px 8px">Ficha</th><th style="padding:3px 8px">Droga</th><th style="padding:3px 8px">Campo</th><th style="padding:3px 8px">Texto</th></tr></thead>
            <tbody>${linhasFalha}</tbody></table>
        </div>` : ''}
        <div class="card">
          <h2>Aplicar</h2>
          <p class="nota">Grava as chaves novas nas ${porFicha.size} fichas. Aditivo: <code>dose</code> e <code>intervalo</code> originais permanecem. As linhas ambíguas e não reconhecidas ficam como estão.</p>
          <form method="POST" action="/atb/admin/posologia/normalizar/aplicar" onsubmit="return confirm('Gravar as chaves normalizadas em ${porFicha.size} fichas?')">
            <button type="submit">Aplicar normalização</button>
          </form>
        </div>`));
    } catch (e) {
      console.error('[atb] posologia preview:', e.message);
      res.status(500).send(page('Erro', `<div class="card"><h1>Falha</h1><p class="mut">${esc(e.message)}</p></div>`));
    }
  });

  // ── APLICAR ──
  app.post('/atb/admin/posologia/normalizar/aplicar', soSuper, async (req, res) => {
    try {
      const { porFicha } = await coletar();
      let n = 0;
      for (const [id, novas] of porFicha) {
        await pool.query('UPDATE atb_fichas SET posologia = $2::jsonb WHERE id = $1', [id, JSON.stringify(novas)]);
        n++;
      }
      console.log(`[atb] posologia normalizada em ${n} fichas`);
      res.send(page('Normalização aplicada', `
        <div class="card"><h1>Pronto</h1>
          <p class="mut">${n} ficha(s) normalizada(s). Os textos originais foram preservados.</p>
          <p><a href="/atb/admin/posologia/normalizar">← Ver o preview de novo</a></p>
        </div>`));
    } catch (e) {
      console.error('[atb] posologia aplicar:', e.message);
      res.status(500).send(page('Erro', `<div class="card"><h1>Falha</h1><p class="mut">${esc(e.message)}</p></div>`));
    }
  });
}
