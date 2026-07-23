// atb-indic-resolver.js
// ════════════════════════════════════════════════════════════════════════════
// Resolvedor DETERMINÍSTICO dos indicadores do SCIH. Zero LLM aqui.
//
// Recebe um localizador { setores, indicadores, periodo } e devolve FATOS:
// valor real da série + limiar de endemicidade + status + o veredito
// estatístico que EXISTE para aquela família (ou a ausência dele, explícita).
//
// É esta camada que impede o delírio: o modelo verbalizador só vê o que sai
// daqui — nunca o JSON cru, nunca "se vira aí".
//
// Fontes (públicas, agregadas, sem PHI):
//   https://scih.lcmendes.med.br/data_iras.json   (séries dos indicadores)
//   https://scih.lcmendes.med.br/data_stats.json  (saída do R: MK, CUSUM, IC)
// ════════════════════════════════════════════════════════════════════════════

import { SETORES, INDICADORES, ANCORAS, GRUPOS_SETOR } from './atb-indic-glossario.js';

const BASE = process.env.ATB_INDIC_BASE || 'https://scih.lcmendes.med.br';
const TTL_MS = 10 * 60 * 1000;   // cache de 10 min (os JSONs mudam 1x/semana)

const _cache = { iras: null, stats: null, em: 0 };

export async function carregarDados(fetchImpl = fetch) {
  if (_cache.iras && (Date.now() - _cache.em) < TTL_MS) return _cache;
  const [ri, rs] = await Promise.all([
    fetchImpl(`${BASE}/data_iras.json`),
    fetchImpl(`${BASE}/data_stats.json`),
  ]);
  if (!ri.ok) throw new Error(`data_iras.json HTTP ${ri.status}`);
  _cache.iras = await ri.json();
  _cache.stats = rs.ok ? await rs.json() : null;
  _cache.em = Date.now();
  return _cache;
}

// Setor → sufixo usado nas chaves do R (dot_mensal_por_par: 'pip_utiab')
const SUFIXO_STATS = {
  utiAB: 'utiab', utic: 'utic', clinicaMedica: 'clin',
  clinicaCirurgica: 'cir', epm: 'epm',
};

// Converte rótulo de período em chave ordenável. Séries misturam pontos
// ANUAIS ("2025") e MENSAIS ("jun/26") — a chave normaliza os dois.
const MESES = { jan: 1, fev: 2, mar: 3, abr: 4, mai: 5, jun: 6,
                jul: 7, ago: 8, set: 9, out: 10, nov: 11, dez: 12 };
function chaveOrdem(rot) {
  const s = String(rot || '').trim().toLowerCase();
  let m = s.match(/^(\d{4})$/);
  if (m) return { tipo: 'ano', k: Number(m[1]) * 100 };
  m = s.match(/^([a-zç]{3})\/(\d{2})$/);
  if (m && MESES[m[1]]) return { tipo: 'mes', k: (2000 + Number(m[2])) * 100 + MESES[m[1]] };
  return null;
}

// ── Extrai o(s) ponto(s) da série conforme o período pedido ─────────────────
function pontos(serie, periodo) {
  if (!Array.isArray(serie) || !serie.length) return [];
  const p = periodo || { tipo: 'ultimo' };
  if (p.tipo === 'ultimo')   return [serie[serie.length - 1]];
  if (p.tipo === 'serie')    return serie;
  if (p.tipo === 'ponto') {
    const exato = serie.filter(x => String(x.p) === String(p.valor));
    if (exato.length) return exato;
    // "2026" pedido mas a série só tem meses de 26 → devolve os meses daquele ano
    const alvo = chaveOrdem(p.valor);
    if (alvo?.tipo === 'ano') {
      const ano = Math.floor(alvo.k / 100);
      return serie.filter(x => { const c = chaveOrdem(x.p); return c?.tipo === 'mes' && Math.floor(c.k / 100) === ano; });
    }
    return [];
  }
  if (p.tipo === 'intervalo') {
    // Janela por chave temporal: pega o que EXISTE dentro dela (não exige
    // que os extremos estejam na série — "1º semestre" com série a partir
    // de fev/26 deve devolver fev..jun, não vazio).
    const a = chaveOrdem(p.de), b = chaveOrdem(p.ate);
    if (!a || !b) return [];
    const lo = Math.min(a.k, b.k), hi = Math.max(a.k, b.k);
    return serie.filter(x => { const c = chaveOrdem(x.p); return c && c.k >= lo && c.k <= hi; });
  }
  return [serie[serie.length - 1]];
}

// ── Veredito estatístico disponível para a família ─────────────────────────
function anexarEstatistica(stats, setor, indicKey, indic) {
  const fam = indic.familia;
  const base = { familia: fam, ...ANCORAS[fam] };
  if (!stats || fam === 'iras') {
    return { ...base, veredito: null,
      nota: 'Sem teste de significância disponível para esta série.' };
  }
  const suf = SUFIXO_STATS[setor];
  if (fam === 'dot' && indic.chaveStats && suf) {
    const mk = stats.dot_mensal_por_par?.[`${indic.chaveStats}_${suf}`]?.mann_kendall
            || stats.dot_institucional?.[indic.chaveStats]?.mann_kendall || null;
    return { ...base, veredito: mk ? { teste: 'Mann-Kendall', ...mk } : null,
      nota: mk ? null : 'Teste não encontrado para esta combinação.' };
  }
  if (fam === 'mdr') {
    const germes = ['kpc', 'esbl', 'acin'];
    const mk = {}, ic = {}, cs = {};
    for (const g of germes) {
      const m = stats.mdr_mensal?.[`${setor}_${g}`]?.mann_kendall;
      if (m) mk[g] = { teste: 'Mann-Kendall', ...m };
      const i = stats.ic_poisson_2026?.[setor]?.[g];
      if (i) ic[g] = { teste: 'IC-Poisson 2026', ...i };
      const c = stats.cusum?.[setor]?.[g];
      if (c) cs[g] = c;
    }
    return { ...base, veredito: { mann_kendall: mk, ic_poisson: ic, cusum: cs } };
  }
  return { ...base, veredito: null, nota: 'Sem teste para esta combinação.' };
}

// ── Resolve um localizador em FATOS ────────────────────────────────────────
export function resolver(dados, loc) {
  const iras = dados.iras, stats = dados.stats;
  const out = { periodoBase: iras?.periodo || null, itens: [], avisos: [] };
  if (stats?.meta?.periodo && iras?.periodo && stats.meta.periodo !== iras.periodo) {
    out.avisos.push(`As análises estatísticas são de ${stats.meta.periodo}; os indicadores estão atualizados até ${iras.periodo}.`);
  }

  // expande grupos ("uti adulto" → utiAB+utic)
  let setores = [];
  for (const s of (loc.setores || [])) {
    if (GRUPOS_SETOR[s]) setores.push(...GRUPOS_SETOR[s]);
    else setores.push(s);
  }
  setores = [...new Set(setores)];

  for (const setor of setores) {
    const bloco = iras?.[setor];
    if (!bloco) { out.avisos.push(`Setor desconhecido nos dados: ${setor}`); continue; }
    for (const ik of (loc.indicadores || [])) {
      const indic = INDICADORES[ik];
      if (!indic) { out.avisos.push(`Indicador desconhecido: ${ik}`); continue; }
      if (!indic.setores.includes(setor)) {
        out.avisos.push(`${indic.rotulo} não é medido em ${SETORES[setor]?.rotulo || setor}.`);
        continue;
      }
      const serie = bloco[ik];
      if (!Array.isArray(serie) || !serie.length) {
        out.avisos.push(`Sem série para ${indic.rotulo} em ${SETORES[setor]?.rotulo || setor}.`);
        continue;
      }
      const pts = pontos(serie, loc.periodo);
      const limiar = indic.limiar ? (bloco.limiares?.[indic.limiar] ?? null) : null;
      out.itens.push({
        setor, setorRotulo: SETORES[setor]?.rotulo || setor,
        indicador: ik, indicadorRotulo: indic.rotulo, unidade: indic.unidade,
        pontos: pts.map(x => ({ periodo: x.p, valor: x.v ?? null, ...(x.e !== undefined ? { esbl: x.e, kpc: x.k, acin: x.a } : {}) })),
        serieCompleta: (loc.periodo?.tipo === 'serie') ? undefined : serie.slice(-8).map(x => ({ periodo: x.p, valor: x.v ?? null })),
        limiarEndemicidade: limiar,
        statusSetor: bloco.status ?? null,
        estatistica: anexarEstatistica(stats, setor, ik, indic),
      });
      if (!pts.length) out.avisos.push(`Período não encontrado na série de ${indic.rotulo} (${SETORES[setor]?.rotulo || setor}).`);
    }
  }
  return out;
}
