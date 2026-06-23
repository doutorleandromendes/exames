// parser-texto.mjs — extração DETERMINÍSTICA de laudos em PDF com camada de texto.
// Abordagem ANCORADA EM RÓTULO: para cada analito conhecido, acha o rótulo e pega o
// valor na MESMA linha (ex.: UNILAB "GLICOSE 84 mg/dL") ou logo ABAIXO (ex.: NA
// Diagnósticos, valor numa linha própria). Cobre os formatos comuns de lab no Brasil.
//
// Layouts muito fora do padrão podem exigir ajuste de rótulos — natureza de parser
// determinístico. Para esses, o modelo de visão continua como rede geral.

import { normalizeAnalito } from "./pront-normalizador.js";

const UNID = "(?:milh[õo]es\\/mm3|milh[õo]es\\/mm³|mil\\/mm3|mil\\/mm³|M\\/mm3|\\/mm3|\\/mm³|\\/mm|\\/mL|mg\\/dL|g\\/dL|mUI\\/mL|µU\\/mL|μU\\/mL|uUI\\/mL|ng\\/dL|ng\\/mL|pg\\/mL|U\\/L|mmol\\/L|mEq\\/L|mg\\/L|pg|fL|%|segundos|mcg\\/mg)";
const reUnit = new RegExp(UNID, "i");

// rótulos -> canônico. hemo: 1 = 1º número da linha; 2 = 2º (absoluto do diferencial).
// Ordem importa: padrões mais específicos primeiro.
const LABELS = [
  // hemograma (valor na mesma linha)
  { c: "eritrocitos", re: /^Eritr[óo]citos\b/i, hemo: 1 },
  { c: "hemoglobina", re: /^Hemoglobina\b/i, hemo: 1 },
  { c: "hematocrito", re: /^Hemat[óo]crito\b/i, hemo: 1 },
  { c: "rdw", re: /^R\.?\s?D\.?\s?W\b/i, hemo: 1 },
  { c: "vcm", re: /^V\.?\s?C\.?\s?M\b/i, hemo: 1 },
  { c: "hcm", re: /^H\.?\s?C\.?\s?M\b/i, hemo: 1 },
  { c: "chcm", re: /^C\.?\s?H\.?\s?C\.?\s?M\b/i, hemo: 1 },
  { c: "leucocitos", re: /^Leuc[óo]citos(\s+Totais)?\b/i, hemo: 1 },
  { c: "segmentados", re: /^Segmentados\b/i, hemo: 2 },
  { c: "bastonetes", re: /^Bastonetes\b/i, hemo: 2 },
  { c: "eosinofilos", re: /^Eosin[óo]filos\b/i, hemo: 2 },
  { c: "basofilos", re: /^Bas[óo]filos\b/i, hemo: 2 },
  { c: "linfocitos_atip", re: /^Linf(\.|[óo]citos)?\s*At[íi]picos\b/i, hemo: 2 },
  { c: "linfocitos", re: /^Linf(\.|[óo]citos)?\.?\s*(T[íi]picos)?\b/i, hemo: 2 },
  { c: "monocitos", re: /^Mon[óo]citos\b/i, hemo: 2 },
  { c: "plaquetas", re: /^Plaquetas\b/i, hemo: 1 },
  // bioquímica / hormônios / lipídico (valor na mesma linha OU abaixo)
  { c: "creatinina", re: /^Creatinina\b(?!\s+Urin)/i },
  { c: "glicose", re: /^Glicose\b/i },
  { c: "hba1c", re: /^(Glicohemoglobina|Hemoglobina\s+Glicada|HbA1c)\b/i },
  { c: "ureia", re: /^Ur[ée]ia\b/i },
  { c: "acido_urico", re: /^[ÁA]cido\s+[ÚU]rico\b/i },
  { c: "ast", re: /^(TGO\b.*|.*ASPARTATO AMINOTRANSFERASE)/i },
  { c: "alt", re: /^(TGP\b.*|.*ALANINA AMINOTRANSFERASE)/i },
  { c: "ggt", re: /^(Gama\s*GT|Gama\s*Glutamil|GGT)\b/i },
  { c: "fosfatase_alc", re: /^Fosfatase\s+Alcalina\b/i },
  { c: "ldh", re: /^(Lactato\s+Desidrogenase|.*\bDHL\b|LDH)/i },
  { c: "cpk", re: /^(Creatinafosfoquinase|CK\s*Total|CPK)\b/i },
  { c: "colesterol_total", re: /^Colesterol\s+Total\b/i },
  { c: "hdl", re: /^(COLESTEROL\s+)?HDL\b/i },
  { c: "ldl", re: /^(COLESTEROL\s+)?LDL\b/i },
  { c: "triglicerides", re: /^Triglic[ée]rides?\b/i },
  { c: "bilirrubina_total", re: /^Bilirrubina\s+Total\b/i },
  { c: "bilirrubina_direta", re: /^Bilirrubina\s+Direta\b/i },
  { c: "albumina", re: /^Albumina\b/i },
  { c: "sodio", re: /^S[óo]dio\b/i },
  { c: "potassio", re: /^Pot[áa]ssio\b/i },
  { c: "magnesio", re: /^Magn[ée]sio\b/i },
  { c: "fosforo", re: /^F[óo]sforo\b/i },
  { c: "calcio", re: /^C[áa]lcio\b/i },
  { c: "tsh", re: /^TSH\b|TIREOESTIMULANTE/i },
  { c: "t4_livre", re: /^(T4\b.*LIVRE|.*TIROXINA\s+LIVRE)/i },
  { c: "vitamina_b12", re: /^(Vitamina\s*B12|B12|Cobalamina)\b/i },
  { c: "acido_folico", re: /^([ÁA]cido\s+F[óo]lico|Folato)\b/i },
  { c: "reticulocitos", re: /^Reticul[óo]citos\b/i },
  { c: "insulina", re: /^Insulina\b/i },
  { c: "pcr", re: /^(PCR\b|Prote[íi]na\s+C\s+Reativa)/i, sero: true },
  { c: "ferritina", re: /^Ferritina\b/i },
  { c: "vhs", re: /^(VHS\b|Primeira hora)/i },
  { c: "microalbuminuria", re: /^Microalbumin[úu]ria\b/i },
  { c: "ttpa", re: /^TTPA\b/i },
  { c: "tap", re: /^(TAP\b|Tempo de protrombina)/i },
  { c: "inr", re: /^INR\b/i },
  // CD4/CD8/carga viral + sorologias (valor pode ser conclusão textual)
  { c: "cd4", re: /^(Linf[óo]citos\s+TCD4|CD4)\b/i },
  { c: "cd8", re: /^(Linf[óo]citos\s+TCD8|CD8)\b/i },
  { c: "cv_hiv", re: /^(HIV\b.*PCR|HIV\b.*QUANTIFICA|Carga\s+viral)/i, sero: true },
  { c: "hiv_sorologia", re: /^HIV\s+I\s+e\s+II\b/i, sero: true },
  { c: "anti_hcv", re: /Anti-?HCV/i, sero: true },
  { c: "hbsag", re: /HBSAG|HBsAg/i, sero: true },
  { c: "anti_hbs", re: /HBs,?\s*Anti/i },
  { c: "vdrl", re: /^VDRL\b/i, sero: true },
  { c: "beta_hcg", re: /Beta\s*HCG/i, sero: true },
  { c: "herpes_igg", re: /Herpes.*IGG/i, sero: true },
  { c: "herpes_igm", re: /Herpes.*IGM/i, sero: true },
  { c: "urocultura", re: /Urocultura/i, sero: true },
];

const NOISE = /^(material|m[ée]todo|valores de ref|^vr:|^v\.r|nota|observa|conforme|amostra reagente|somente|^\d\)|http|exame realizado|exame repetido|os anticorpos|como realmente|resultados falso|- |refer[êe]ncia ped|pediatric|interpreta|limite|atenc|aten[çc]|paciente|c[óo]digo|solicita|conv[êe]nio|impress|prontuario|assinad|assinatura|data nascimento|data do cadastro|data libera|destino|prescr|ritmo de fil|glicemia media|^\||categoria|risco|com jejum|sem jejum|para adultos|para crian|adultos|crian|homens|mulheres|recém|recem|neonatos|cordao|>=|< 6 meses|> 6 meses|=<|faixa et|limite|obs:|observ)/i;
const ehNoise = l => NOISE.test(l.trim());
const REFLINE = /\b(inferior|superior|maior|menor)\s+(ou igual\s+)?a\b|\d[\d.,]*\s*(a|-|à)\s*\d|reagente\s*\.*\s*:|n[ãa]o reagente\s*\.*\s*:|indeterminado|até\s+\d|ate\s+\d|^vr:|^v\.r/i;
const QUALI = /(n[ãa]o\s+detectado|detectado|n[ãa]o\s+reagente|reagente|negativ\w*|positiv\w*|n[ãa]o\s+houve\s+crescimento|ausente)/i;
const CENS = /((superior|inferior|maior|menor)\s+a\s+[\d.,]+|[<>]=?\s*[\d.,]+)/i;

const reNumUnid = new RegExp(`(-?\\d[\\d.,]*)\\s*(${UNID})`, "i");

// extrai o valor de UMA linha: conclusão (sorologia), censurado, ou 1º número+unidade
function valorLinha(txt, sero) {
  const t = (txt || "").trim();
  if (!t) return null;
  if (sero && QUALI.test(t) && !REFLINE.test(t)) {
    const idx = t.search(QUALI);
    return { valor: t.slice(idx).replace(/\s+/g, " ").trim() };
  }
  const mNum = t.match(reNumUnid);
  const mCens = (!REFLINE.test(t)) ? t.match(CENS) : null;
  const iNum = mNum ? mNum.index : Infinity;
  const iCens = mCens ? mCens.index : Infinity;
  // o valor vem ANTES da referência na linha → escolhe o que aparece primeiro
  if (iCens < iNum) return { valor: mCens[1] };
  if (mNum) {
    const antes = t.slice(0, mNum.index);
    if (/\d[\d.,]*\s*(a|à|-)\s*$/i.test(antes)) return null; // lado direito de faixa
    return { valor: mNum[1], unidade: mNum[2] };
  }
  if (mCens) return { valor: mCens[1] };
  return null;
}
function valorHemo(resto, which) {
  const nums = [...resto.matchAll(/(-?\d[\d.,]*)/g)].map(x => x[1]);
  const idx = which - 1;
  if (nums.length <= idx) return null;
  const after = resto.split(nums[idx])[1] || "";
  const u = (after.match(reUnit) || [""])[0];
  return { valor: nums[idx], unidade: u };
}

export function parseLaudoTexto(texto) {
  const linhas = texto.split(/\r?\n/);
  // paciente / data de coleta
  let paciente = null, data = null;
  for (let i = 0; i < linhas.length && (!paciente || !data); i++) {
    const t = linhas[i].trim();
    if (!paciente) {
      const m = t.match(/^(?:Paciente|Nome)\s*:?\s*(.*)/i);
      if (m) {
        let nome = (m[1] || "").trim();
        if (!nome || /^(idade|c[óo]digo|sexo|conv|data|requisi)/i.test(nome)) {
          nome = ((linhas[i + 1] || "").split(/\s{2,}/).map(s => s.trim()).filter(Boolean)[0]) || "";
        } else nome = nome.split(/\s{2,}/)[0].trim();
        nome = nome.replace(/,\s*\d+\s*[AaMm]\b.*$/, "").trim(); // remove idade "53 A 1 M"
        if (nome && !/^(idade|c[óo]digo|data)/i.test(nome)) paciente = nome;
      }
    }
    if (!data) { const m = t.match(/Data\s+(?:d[ae]\s+)?coleta:?\s*(\d{2}\/\d{2}\/\d{4})/i); if (m) { const [d, mo, y] = m[1].split("/"); data = `${y}-${mo}-${d}`; } }
  }
  if (!data) {
    for (let i = 0; i < linhas.length; i++) {
      if (/Data\s+Atendimento/i.test(linhas[i])) {
        let m = linhas[i].match(/(\d{2}\/\d{2}\/\d{4})/);
        if (!m) for (let j = i + 1; j < Math.min(i + 3, linhas.length); j++) { m = linhas[j].match(/(\d{2}\/\d{2}\/\d{4})/); if (m) break; }
        if (m) { const [d, mo, y] = m[1].split("/"); data = `${y}-${mo}-${d}`; break; }
      }
    }
  }

  const achados = [];
  const usados = new Set();
  for (const lab of LABELS) {
    if (usados.has(lab.c)) continue;
    const i = linhas.findIndex(l => lab.re.test(l.trim()));
    if (i < 0) continue;
    const linha = linhas[i].trim();
    const resto = linha.replace(lab.re, "").trim();
    let v = null;

    if (lab.hemo) v = valorHemo(resto, lab.hemo);
    else {
      // 1) mesma linha (UNILAB: "GLICOSE 84 mg/dL")
      v = valorLinha(linha, lab.sero);
      // 2) abaixo (NA: valor em linha própria), pulando ruído/referências
      if (!v) {
        for (let j = i + 1; j < Math.min(i + 12, linhas.length); j++) {
          const lj = linhas[j];
          if (!lj.trim()) continue;
          if (ehNoise(lj)) continue;
          if (LABELS.some(o => o.c !== lab.c && o.re.test(lj.trim()))) break;
          if (/resultados anteriores/i.test(lj)) break;
          v = valorLinha(lj, lab.sero);
          if (v) break;
        }
      }
    }
    if (v && v.valor != null && String(v.valor).trim() !== "") { achados.push({ nome: linha.slice(0, 40), canon: lab.c, ...v }); usados.add(lab.c); }
  }

  const analitos = achados.map(a => {
    const n = normalizeAnalito({ nome: a.nome, valor: a.valor, unidade: a.unidade, ref: "" });
    n.canonico = a.canon;
    return n;
  });
  return { paciente, data_coleta: data, analitos, fonte: "texto (determinístico)" };
}
