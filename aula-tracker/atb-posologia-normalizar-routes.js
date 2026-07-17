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

// Unidade padrão por droga — resolve os valores digitados sem unidade
// (ex.: "4,5" em Piperacilina/Tazobactam = 4,5 g). CONFIRMAR com o SCIH.
export const UNIDADE_PADRAO = {
  'Cefepime': 'g',
  'Ceftriaxone': 'g',
  'Fosfomicina': 'g',
  'Meropenem': 'g',
  'Piperacilina/Tazobactam': 'g',
  'Vancomicina': 'g',
  'Teicoplanina': 'mg',
  'Anfotericina B': 'mg',
  'Daptomicina': 'mg',
  'Tigeciclina': 'mg',
  'Micafungina': 'mg',
  'Amicacina': 'mg',
  'Gentamicina': 'mg',
  'Polimixina B': null,                   // ⚠ UI ou mg? — definir antes de aplicar
  'Polimixina E (colestimetato)': null,   // ⚠ mg ou MUI? — definir antes de aplicar
  'NÃO PADRONIZADO': null,                // sem catálogo → sem inferência
};

const _norm = (v) => String(v == null ? '' : v).toLowerCase().trim().replace(/\s+/g, ' ');

// ── INTERVALO ──
export function parseIntervalo(txt) {
  const s = _norm(txt);
  if (!s) return null;
  if (/^(dose )?[uú]nica$/.test(s) || s === 'agora') return { freq_tipo: 'unica', freq_horas: null };
  if (/^1 ?x( ?\/? ?(dia|ao dia))?$/.test(s)) return { freq_tipo: 'cada', freq_horas: 24 };
  if (/(p[oó]s|ap[oó]s).*(hd|di[aá]lise)|dias de di[aá]lise/.test(s)) return { freq_tipo: 'hd', freq_horas: null };
  let m = s.match(/^(\d{1,2})\s*\/\s*(\d{1,2})\s*(h|hs|hrs|horas?)?$/);
  if (m && m[1] === m[2]) return { freq_tipo: 'cada', freq_horas: +m[1] };
  m = s.match(/^(\d{1,2})\s*(h|hs|hrs|horas?)$/);
  if (m) return { freq_tipo: 'cada', freq_horas: +m[1] };
  m = s.match(/^(\d{1,2})$/);
  if (m) return { freq_tipo: 'cada', freq_horas: +m[1] };
  return null;
}

// ── DOSE ── (droga é usada só para resolver valor sem unidade)
export function parseDose(txt, droga) {
  const s = _norm(txt);
  if (!s) return null;
  let m = s.match(/^(\d{1,2})\s*amp\.?$/);
  if (m) return { dose_valor: +m[1], dose_unidade: 'amp' };
  m = s.match(/^([\d.,]+)\s*mg\s*\/\s*kg/);
  if (m) return { dose_valor: +m[1].replace(',', '.'), dose_unidade: 'mg/kg' };
  m = s.match(/^([\d.,]+)\s*(mg|g|gr|ui)$/);
  if (m) return { dose_valor: +m[1].replace(',', '.'), dose_unidade: m[2] === 'gr' ? 'g' : (m[2] === 'ui' ? 'UI' : m[2]) };
  m = s.match(/^([\d.,]+)$/);
  if (m) {
    const un = UNIDADE_PADRAO[String(droga || '').trim()];
    if (!un) return { _ambiguo: true, dose_valor: +m[1].replace(',', '.'), droga: droga || '(sem droga)' };
    return { dose_valor: +m[1].replace(',', '.'), dose_unidade: un, _porDroga: true };
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
                 intOk: 0, intFalha: 0, vazias: 0 };
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
        if (r.doseOk) { st.doseOk++; if (r.dose._porDroga) st.dosePorDroga++; }
        if (r.doseAmbigua) {
          st.doseAmbigua++;
          const k = `${r.dose.droga} · "${r.dTxt}"`;
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
    }
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
      const semUnidade = Object.entries(UNIDADE_PADRAO).filter(([, v]) => !v).map(([k]) => k);

      res.send(page('Normalizar posologia — preview', `
        <div class="card">
          <h1>Normalizar posologia <span class="nota">(preview — nada foi gravado)</span></h1>
          <p class="mut">Converte <code>dose</code>/<code>intervalo</code> de texto livre para o modelo estruturado, de forma aditiva: os textos originais permanecem.</p>
        </div>
        <div class="card">
          <h2>Resumo</h2>
          <table style="font-size:14px">
            <tr><td style="padding:4px 10px">Fichas com posologia</td><td><strong>${st.fichas}</strong></td><td></td></tr>
            <tr><td style="padding:4px 10px">Linhas de posologia</td><td><strong>${st.linhas}</strong></td><td></td></tr>
            <tr><td style="padding:4px 10px">Dose reconhecida</td><td><strong>${st.doseOk}</strong></td><td class="nota">${pct(st.doseOk, st.linhas)} — sendo ${st.dosePorDroga} resolvidas pela droga</td></tr>
            <tr><td style="padding:4px 10px">Dose ambígua</td><td><strong>${st.doseAmbigua}</strong></td><td class="nota">${pct(st.doseAmbigua, st.linhas)} — valor sem unidade e droga sem padrão definido</td></tr>
            <tr><td style="padding:4px 10px">Dose não reconhecida</td><td><strong>${st.doseFalha}</strong></td><td class="nota">${pct(st.doseFalha, st.linhas)} — revisão manual</td></tr>
            <tr><td style="padding:4px 10px">Intervalo reconhecido</td><td><strong>${st.intOk}</strong></td><td class="nota">${pct(st.intOk, st.linhas)}</td></tr>
            <tr><td style="padding:4px 10px">Intervalo não reconhecido</td><td><strong>${st.intFalha}</strong></td><td class="nota">${pct(st.intFalha, st.linhas)} — revisão manual</td></tr>
            <tr><td style="padding:4px 10px">Fichas que seriam alteradas</td><td><strong>${porFicha.size}</strong></td><td></td></tr>
          </table>
        </div>
        ${semUnidade.length ? `<div class="card" style="border-left:3px solid #e8a33d">
          <h2>⚠ Definir antes de aplicar</h2>
          <p class="nota">Estas drogas não têm unidade padrão, então valores sem unidade ficam ambíguos:</p>
          <p style="font-size:14px"><strong>${semUnidade.map(esc).join(' · ')}</strong></p>
          <p class="nota">Ajuste <code>UNIDADE_PADRAO</code> em <code>atb-posologia-normalizar-routes.js</code>.</p>
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
