// normalizador.mjs — camada determinística que converte um analito "cru"
// (nome do laudo + valor em texto + referência em texto) em um registro
// canônico, tipado e comparável ao longo do tempo.
//
// É independente do OCR/extração: recebe o que o PDF-texto OU o modelo de
// visão produziram e padroniza. Nenhuma interpretação clínica é feita aqui —
// só normalização de nome, tipo de valor e faixa de referência.

/* ============================================================
 * 1) DICIONÁRIO CANÔNICO  (canônico -> rótulo + apelidos)
 * Os apelidos são casados de forma acento-insensível e por
 * "contém a frase". O apelido mais específico (mais longo) vence,
 * para "Linfócitos Atípicos" não cair em "Linfócitos".
 * ============================================================ */
export const CANONICOS = {
  // --- Hemograma / série vermelha ---
  hemoglobina:        { rotulo:"Hemoglobina",        sin:["hemoglobina","hb","hgb"] },
  hematocrito:        { rotulo:"Hematócrito",        sin:["hematocrito","ht","hct"] },
  eritrocitos:        { rotulo:"Eritrócitos",        sin:["eritrocitos","hemacias","glóbulos vermelhos","globulos vermelhos"] },
  vcm:                { rotulo:"VCM",                sin:["vcm","volume corpuscular medio","v.c.m"] },
  hcm:                { rotulo:"HCM",                sin:["hcm","hemoglobina corpuscular media","h.c.m"] },
  chcm:               { rotulo:"CHCM",               sin:["chcm","c.h.c.m","concentracao de hemoglobina corpuscular media"] },
  rdw:                { rotulo:"RDW",                sin:["rdw","r.d.w"] },
  // --- Hemograma / série branca ---
  leucocitos:         { rotulo:"Leucócitos",         sin:["leucocitos","leucograma","globulos brancos","wbc"] },
  segmentados:        { rotulo:"Segmentados",        sin:["segmentados","neutrofilos segmentados","neutrofilos"] },
  bastonetes:         { rotulo:"Bastonetes",         sin:["bastonetes","bastoes"] },
  eosinofilos:        { rotulo:"Eosinófilos",        sin:["eosinofilos","eosinofilo"] },
  basofilos:          { rotulo:"Basófilos",          sin:["basofilos"] },
  linfocitos:         { rotulo:"Linfócitos",         sin:["linfocitos tipicos","linfocitos"] },
  linfocitos_atip:    { rotulo:"Linfócitos atípicos",sin:["linfocitos atipicos"] },
  monocitos:          { rotulo:"Monócitos",          sin:["monocitos"] },
  blastos:            { rotulo:"Blastos",            sin:["blastos"] },
  plaquetas:          { rotulo:"Plaquetas",          sin:["plaquetas","contagem de plaquetas"] },
  // --- Coagulação ---
  inr:                { rotulo:"INR",                sin:["inr","rni"] },
  tap_atividade:      { rotulo:"TAP (atividade)",    sin:["atividade do paciente","atividade de protrombina","tap atividade"] },
  tap:                { rotulo:"TAP",                sin:["tempo de protrombina","tap","tp"] },
  ttpa:               { rotulo:"TTPA",               sin:["ttpa","ttpa relacao","tempo de tromboplastina"] },
  // --- Função renal / eletrólitos ---
  creatinina:         { rotulo:"Creatinina",         sin:["creatinina"] },
  ureia:              { rotulo:"Ureia",              sin:["ureia","uréia"] },
  acido_urico:        { rotulo:"Ácido úrico",        sin:["acido urico"] },
  sodio:              { rotulo:"Sódio",              sin:["sodio","na+"] },
  potassio:           { rotulo:"Potássio",           sin:["potassio","k+"] },
  calcio:             { rotulo:"Cálcio",             sin:["calcio serico","calcio"] },
  fosforo:            { rotulo:"Fósforo",            sin:["fosforo inorganico","fosforo"] },
  // --- Hepático ---
  ast:                { rotulo:"AST (TGO)",          sin:["aspartato aminotransferase","tgo - ast","tgo ast","tgo","ast"] },
  alt:                { rotulo:"ALT (TGP)",          sin:["alanina aminotransferase","tgp - alt","tgp alt","tgp","alt"] },
  fosfatase_alc:      { rotulo:"Fosfatase alcalina", sin:["fosfatase alcalina","fal","falc"] },
  ggt:                { rotulo:"GGT",                sin:["gama gt","gama glutamil","ggt"] },
  bilirrubina_total:  { rotulo:"Bilirrubina total",  sin:["bilirrubina total","bilirrubinas totais"] },
  bilirrubina_direta: { rotulo:"Bilirrubina direta", sin:["bilirrubina direta"] },
  albumina:           { rotulo:"Albumina",           sin:["albumina"] },
  ldh:                { rotulo:"LDH",                sin:["desidrogenase latica","ldh","dhl"] },
  // --- Metabólico / lipídico ---
  glicose:            { rotulo:"Glicose",            sin:["glicemia de jejum","glicemia","glicose"] },
  hba1c:              { rotulo:"Hemoglobina glicada",sin:["hemoglobina glicada","hba1c","a1c"] },
  insulina:           { rotulo:"Insulina",           sin:["insulina"] },
  colesterol_total:   { rotulo:"Colesterol total",   sin:["colesterol total"] },
  ldl:                { rotulo:"LDL",                sin:["ldl colesterol","colesterol ldl","ldl"] },
  hdl:                { rotulo:"HDL",                sin:["hdl colesterol","colesterol hdl","hdl"] },
  triglicerides:      { rotulo:"Triglicérides",      sin:["triglicerides","triglicerideos","tg"] },
  // --- Tireoide ---
  tsh:                { rotulo:"TSH",                sin:["tsh","hormonio tireoestimulante"] },
  t4_livre:           { rotulo:"T4 livre",           sin:["t4 livre","tiroxina livre"] },
  // --- Inflamatórios ---
  pcr:                { rotulo:"Proteína C reativa", sin:["proteina c reativa","pcr"] },
  vhs:                { rotulo:"VHS",                sin:["vhs","velocidade de hemossedimentacao"] },
  ferritina:          { rotulo:"Ferritina",          sin:["ferritina"] },
  procalcitonina:     { rotulo:"Procalcitonina",     sin:["procalcitonina","pct"] },
  // --- HIV / monitorização ---
  cd4:                { rotulo:"CD4 (TCD4+)",        sin:["linfocitos tcd4","cd4+","cd4","t cd4"] },
  cd8:                { rotulo:"CD8 (TCD8+)",        sin:["linfocitos tcd8","cd8+","cd8"] },
  cv_hiv:             { rotulo:"Carga viral HIV",    sin:["carga viral do hiv","carga viral hiv","cv hiv","rna hiv"] },
  // --- Sorologias (qualitativas) ---
  hiv_sorologia:      { rotulo:"HIV (sorologia)",    sin:["hiv i e ii","hiv 1 e 2","anti hiv","antihiv","hiv"] },
  anti_hcv:           { rotulo:"Anti-HCV",           sin:["hepatite c anti hcv","anti hcv","antihcv","hcv anticorpos"] },
  hbsag:              { rotulo:"HBsAg",              sin:["hepatite b hbsag","hbsag","ag hbs"] },
  anti_hbs:           { rotulo:"Anti-HBs",           sin:["hbs anti","anti hbs","antihbs"] },
  anti_hbc:           { rotulo:"Anti-HBc",           sin:["anti hbc total","anti hbc","antihbc"] },
  vdrl:               { rotulo:"VDRL",               sin:["vdrl"] },
  sifilis:            { rotulo:"Sífilis (anticorpos)",sin:["sifilis anticorpos totais","sifilis"] },
  herpes_igg:         { rotulo:"Herpes 1/2 IgG",     sin:["herpes 1 e 2 anticorpos igg","herpes igg","herpes simplex igg"] },
  herpes_igm:         { rotulo:"Herpes 1/2 IgM",     sin:["herpes 1 e 2 anticorpos igm","herpes igm","herpes simplex igm"] },
  toxo_igg:           { rotulo:"Toxoplasmose IgG",   sin:["toxoplasmose igg"] },
  toxo_igm:           { rotulo:"Toxoplasmose IgM",   sin:["toxoplasmose igm"] },
  cmv_igg:            { rotulo:"CMV IgG",            sin:["cmv igg","citomegalovirus igg"] },
  cmv_igm:            { rotulo:"CMV IgM",            sin:["cmv igm","citomegalovirus igm"] },
  beta_hcg:           { rotulo:"Beta HCG",           sin:["beta hcg","bhcg","b hcg","gonadotrofina corionica"] },
  // --- Urina ---
  urocultura:         { rotulo:"Urocultura",         sin:["urocultura com contagem de colonia","urocultura"] },
  cd4_ratio:          { rotulo:"Relação CD4/CD8",    sin:["relacao cd4 cd8","cd4 cd8 ratio"] },
  reticulocitos:      { rotulo:"Reticulócitos",      sin:["reticulocitos"] },
  saturacao_transf:   { rotulo:"Saturação de transferrina", sin:["saturacao de transferrina","indice de saturacao"] },
  vitamina_b12:       { rotulo:"Vitamina B12",       sin:["vitamina b12","cobalamina"] },
  acido_folico:       { rotulo:"Ácido fólico",       sin:["acido folico","folato"] },
  eletroforese_hb:    { rotulo:"Eletroforese de Hb", sin:["eletroforese de hemoglobina"] },
  frutosamina:        { rotulo:"Frutosamina",        sin:["frutosamina"] },
  insulina:           { rotulo:"Insulina",           sin:["insulina"] },
  homa_ir:            { rotulo:"HOMA-IR",            sin:["homa ir","homa"] },
  relacao_prot_creat: { rotulo:"Relação proteína/creatinina", sin:["relacao proteina creatinina"] },
  microalbuminuria:   { rotulo:"Microalbuminúria",   sin:["microalbuminuria","microalbumina"] },
  pth:                { rotulo:"PTH",                sin:["paratormonio","pth intacto"] },
  magnesio:           { rotulo:"Magnésio",           sin:["magnesio"] },
  fosforo_urinario:   { rotulo:"Fósforo urinário",   sin:["fosforo urinario"] },
  cpk:                { rotulo:"CPK",                sin:["creatinofosfoquinase","cpk total","ck total"] },
  vitamina_d:         { rotulo:"Vitamina D (25-OH)", sin:["25 hidroxivitamina d","25-hidroxi","vitamina d"] },
  fta_sifilis:        { rotulo:"FTA-Abs (sífilis)",  sin:["fta abs","fta-abs"] },
  sarampo_igg:        { rotulo:"Sarampo IgG",        sin:["sarampo igg"] },
  bilirrubina_di:     { rotulo:"Bilirrubina D/I",    sin:["bilirrubina direta indireta"] },
  tarv:               { rotulo:"TARV (esquema)",     sin:["esquema antirretroviral"] },
  urina_leucocitos:   { rotulo:"Urina I — leucócitos",sin:["leucocitos urina"] },
  urina_hemacias:     { rotulo:"Urina I — eritrócitos",sin:["eritrocitos urina"] },
};

/* índice de apelidos, ordenado do mais longo para o mais curto */
const ALIAS_IDX = [];
for (const [canon, def] of Object.entries(CANONICOS))
  for (const s of def.sin) ALIAS_IDX.push({ canon, alias: norm(s), len: s.length });
ALIAS_IDX.sort((a, b) => b.len - a.len);

/* ============================================================
 * 2) UTILIDADES
 * ============================================================ */
export function norm(s) {
  return (s || "").toString().toLowerCase()
    .normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9+/% ]/g, " ").replace(/\s+/g, " ").trim();
}
// minúsculas + sem acento, mas PRESERVA vírgulas/pontos/operadores (p/ números)
function low(s) {
  return (s || "").toString().toLowerCase()
    .normalize("NFD").replace(/[\u0300-\u036f]/g, "");
}

// "7.000" -> 7000 ; "0,6" -> 0.6 ; "1,03" -> 1.03 ; "4,39" -> 4.39 ; "350" -> 350
export function brNum(s) {
  if (s == null) return null;
  let t = String(s).trim().replace(/\s/g, "");
  if (t === "") return null;
  const hasComma = t.includes(","), hasDot = t.includes(".");
  if (hasComma && hasDot) t = t.replace(/\./g, "").replace(",", ".");     // 1.234,5
  else if (hasComma) t = t.replace(",", ".");                            // 0,6
  else if (hasDot) {                                                     // só ponto
    const after = t.split(".").pop();
    if (after.length === 3) t = t.replace(/\./g, "");                    // 7.000 -> milhar
    // senão (1.03) trata como decimal, mantém
  }
  const n = parseFloat(t);
  return Number.isFinite(n) ? n : null;
}

/* ============================================================
 * 3) NOME -> CANÔNICO
 * ============================================================ */
export function normalizeName(raw) {
  const n = norm(raw);
  if (!n) return null;
  for (const a of ALIAS_IDX) {
    if (n === a.alias) return a.canon;                       // match exato
    const re = new RegExp(`(^| )${a.alias.replace(/[+/]/g, "\\$&")}( |$)`);
    if (re.test(n)) return a.canon;                          // contém a frase
  }
  return null;
}

/* ============================================================
 * 4) VALOR -> TIPADO  (numérico | censurado | qualitativo)
 * ============================================================ */
const QUALI = /(nao reagente|reagente|nao reativ|reativ|negativ|positiv|ausente|presente|indeterminad|nao houve crescimento|sem crescimento|nao detectad|detectad|nao observ|normais|limpido|amarelo)/;

export function parseValue(raw) {
  const t = (raw || "").toString().trim();
  if (!t) return { tipo_valor: "vazio" };
  const n = norm(t);
  const nl = low(t);

  // censurado: "Superior a 30,0", "Inferior a 0,5", "< 40", ">= 1,1"
  const cen = nl.match(/^(superior ou igual|inferior ou igual|maior ou igual|menor ou igual|superior|inferior|maior|menor|>=|<=|>|<)\s*a?\s*([\d.,]+)/);
  if (cen) {
    const map = { "superior":">", "maior":">", ">":">", "superior ou igual":">=", "maior ou igual":">=", ">=":">=",
                  "inferior":"<", "menor":"<", "<":"<", "inferior ou igual":"<=", "menor ou igual":"<=", "<=":"<=" };
    return { tipo_valor:"censurado", operador: map[cen[1]] || cen[1], valor: brNum(cen[2]), texto: t };
  }

  // numérico: primeiro número + unidade textual após ele
  const num = t.match(/(-?[\d][\d.,]*)\s*([a-zA-ZµμÀ-ÿ%/³²·°]+(?:\/[a-zA-ZµμÀ-ÿ³²]+)?)?/i);
  const val = num ? brNum(num[1]) : null;
  const temLetraResultado = QUALI.test(n);
  if (val != null && !(/^[a-z]/.test(t.trim()))) {
    return { tipo_valor:"numerico", valor: val, unidade: (num[2] || "").trim() || null, texto: t };
  }

  // qualitativo
  if (temLetraResultado) return { tipo_valor:"qualitativo", resultado: t.replace(/\s+/g," ").trim(), texto: t };

  return { tipo_valor:"texto", texto: t };
}

/* ============================================================
 * 5) REFERÊNCIA -> {min,max}
 * ============================================================ */
export function parseRef(raw) {
  if (!raw) return null;
  const t = String(raw).trim();
  const nl = low(t);
  let m;
  if ((m = t.match(/([\d.,]+)\s*(?:a|-|à|até)\s*([\d.,]+)/i)))
    return { min: brNum(m[1]), max: brNum(m[2]) };
  if ((m = nl.match(/(?:ate|inferior(?: ou igual)? a|menor que|abaixo de|<)\s*([\d.,]+)/)))
    return { max: brNum(m[1]) };
  if ((m = nl.match(/(?:superior(?: ou igual)? a|maior que|acima de|>)\s*([\d.,]+)/)))
    return { min: brNum(m[1]) };
  return null;
}

/* ============================================================
 * 6) STATUS  (só factual: dentro/fora da faixa, p/ valores numéricos)
 * Nunca interpreta sorologia/qualitativo — isso é decisão do médico.
 * ============================================================ */
export function flagStatus(v) {
  if (v.tipo_valor !== "numerico" || !v.ref) return null;
  const { min, max } = v.ref;
  if (min != null && v.valor < min) return "baixo";
  if (max != null && v.valor > max) return "alto";
  if (min != null || max != null) return "normal";
  return null;
}

/* ============================================================
 * 7) NORMALIZA UM ANALITO  (entrada crua -> registro final)
 * ============================================================ */
export function normalizeAnalito(e) {
  const canon = normalizeName(e.nome);
  const v = parseValue(e.valor);
  if (e.unidade && !v.unidade) v.unidade = e.unidade;
  v.ref = parseRef(e.ref) || null;
  const status = flagStatus(v);
  return {
    nome_original: e.nome,
    canonico: canon,                          // null => fica em "outros"
    rotulo: canon ? CANONICOS[canon].rotulo : e.nome,
    ...v,
    status,
  };
}

export function normalizeExame(analitos) {
  const out = analitos.map(normalizeAnalito);
  return {
    mapeados: out.filter(a => a.canonico),    // viram coluna do histórico
    outros:   out.filter(a => !a.canonico),   // guardados, sem tendência
  };
}
