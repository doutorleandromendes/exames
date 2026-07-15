// pront-classificador.js — decide a NATUREZA do documento antes de extrair, e
// organiza laudos narrativos sem passar por modelo nenhum.
//
// Três classes:
//   analitos   -> laudo de análises clínicas (tabela nome/valor/unidade/VR)
//   narrativo  -> laudo de imagem, histopatologia, relatório, alta  (transcrever + organizar)
//   imagem     -> não extrai nada; fica como anexo visualizável     (só por escolha humana)
//
// REGRA DE SEGURANÇA: na dúvida, SEMPRE 'narrativo'.
// 'narrativo' apenas transcreve — o pior caso é texto mal quebrado. 'analitos'
// afirma um número dentro do prontuário; classificador em dúvida não pode
// promover para a classe que afirma valor. Mesmo princípio da regra de dose por OCR.

import { parseLaudoTexto } from "./pront-parser-texto.js";

export const CLASSES = ["analitos", "narrativo", "imagem"];
export const CORTE_CONFIANCA = 0.6;   // abaixo disso a fila mostra "dúvida"

// ---------- âncoras de seção de laudo narrativo ----------
// Títulos que laudos de imagem / anatomia patológica / relatórios usam.
const ANCORA = /^(t[ée]cnica|m[ée]todo(\s+de\s+exame)?|achados?|an[áa]lise|impress[ãa]o(\s+diagn[óo]stica)?|conclus[ãa]o|coment[áa]rios?|indica[çc][ãa]o(\s+cl[íi]nica)?|hist[óo]rico|informa[çc][õo]es\s+cl[íi]nicas|dados\s+cl[íi]nicos|macroscopia|microscopia|descri[çc][ãa]o\s+(macrosc[óo]pica|microsc[óo]pica)|diagn[óo]stico|exame\s+f[íi]sico|relat[óo]rio|protocolo|nota|opini[ãa]o|correla[çc][ãa]o|compara[çc][ãa]o|imunoistoqu[íi]mica|imuno-histoqu[íi]mica)\b\s*:?\s*$/i;

// versão frouxa: aceita a âncora com conteúdo na mesma linha ("ACHADOS: fígado de ...")
const ANCORA_INLINE = /^(t[ée]cnica|m[ée]todo|achados?|an[áa]lise|impress[ãa]o|conclus[ãa]o|coment[áa]rios?|indica[çc][ãa]o|hist[óo]rico|macroscopia|microscopia|diagn[óo]stico|relat[óo]rio|opini[ãa]o)\b\s*:/i;

const chave = l => l.toLowerCase().normalize("NFD").replace(/[^a-z]/g, "");

// ---------- classificador determinístico ----------
// entrada: texto puro (pdftotext, ou transcrição de visão)
// saída:   { classe, confianca, motivos[] }
export function classificarTexto(texto) {
  const t = String(texto || "");
  const linhas = t.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const motivos = [];

  if (linhas.length === 0) {
    return { classe: "narrativo", confianca: 0, motivos: ["documento sem texto legível"] };
  }

  // sinal 1 (o mais forte): quantos analitos CANÔNICOS o parser determinístico reconhece.
  // É o mesmo parser que faria a extração — se ele acha muita coisa, é laudo de análises.
  let nCanon = 0;
  try {
    const r = parseLaudoTexto(t);
    nCanon = (r.analitos || []).filter(a => a.canonico).length;
  } catch { nCanon = 0; }
  if (nCanon) motivos.push(`${nCanon} analito(s) canônico(s) reconhecido(s)`);

  // sinal 2: seções narrativas distintas
  const anc = new Set();
  for (const l of linhas) {
    if (l.length <= 70 && (ANCORA.test(l) || ANCORA_INLINE.test(l))) anc.add(chave(l).slice(0, 12));
  }
  const nAnc = anc.size;
  if (nAnc) motivos.push(`${nAnc} seção(ões) típica(s) de laudo narrativo`);

  // sinal 3: densidade de prosa — linhas longas com poucos dígitos
  const longas = linhas.filter(l => l.length >= 60 && (l.match(/\d/g) || []).length <= l.length * 0.08).length;
  const prosa = longas / linhas.length;
  if (prosa >= 0.15) motivos.push(`prosa contínua em ${Math.round(prosa * 100)}% das linhas`);

  // sinal 4: vocabulário de tabela de resultados
  const vr = /valores?\s+de\s+refer[êe]ncia|valor\s+de\s+refer[êe]ncia|\bV\.?R\.?\b|material\s*:|m[ée]todo\s*:/i.test(t);
  if (vr && nCanon >= 3) motivos.push("cabeçalho de tabela de resultados");

  // ---------- escada de decisão ----------
  // Ordem importa: só cai em 'analitos' com evidência positiva e forte.
  if (nCanon >= 5 && nAnc <= 1) {
    return { classe: "analitos", confianca: Math.min(0.98, 0.62 + nCanon * 0.04), motivos };
  }
  if (nAnc >= 2 && nCanon <= 2) {
    return { classe: "narrativo", confianca: Math.min(0.95, 0.62 + nAnc * 0.07), motivos };
  }
  if (nCanon >= 3 && nAnc === 0 && prosa < 0.15) {
    return { classe: "analitos", confianca: vr ? 0.78 : 0.68, motivos };
  }
  if (nAnc >= 1 && prosa >= 0.2) {
    return { classe: "narrativo", confianca: 0.7, motivos };
  }
  // misto ou irreconhecível -> narrativo com baixa confiança (a fila sinaliza "dúvida")
  motivos.push("sinais mistos ou fracos — mantido em narrativo por segurança");
  return { classe: "narrativo", confianca: 0.35, motivos };
}

// ---------- organizador determinístico de laudo narrativo ----------
// Recebe o texto LITERAL (pdftotext) e devolve {titulo, data, texto} com os
// títulos do próprio documento marcados com "##" — o mesmo marcador que
// renderConsulta()/a prévia da conferência já entendem.
//
// NÃO reescreve, NÃO resume, NÃO reordena. Só marca o que já é título e limpa
// linhas em branco repetidas. Nenhum modelo envolvido.
export function organizarTexto(texto) {
  const bruto = String(texto || "").split(/\r?\n/).map(l => l.replace(/\s+$/, ""));
  const out = [];
  let vazias = 0;

  for (let i = 0; i < bruto.length; i++) {
    const l = bruto[i].trim();
    if (!l) { vazias++; if (vazias <= 1) out.push(""); continue; }
    vazias = 0;

    const prox = (bruto.slice(i + 1).find(x => x.trim()) || "").trim();
    if (ehTitulo(l, prox)) {
      const m = l.match(ANCORA_INLINE);
      if (m && !/:\s*$/.test(l)) {
        // "ACHADOS: fígado de dimensões normais" -> título + conteúdo em linhas separadas
        const i = l.indexOf(":");
        out.push("## " + titulize(l.slice(0, i)));
        const resto = l.slice(i + 1).trim();
        if (resto) out.push(resto);
      } else {
        out.push("## " + titulize(l.replace(/:\s*$/, "")));
      }
      continue;
    }
    out.push(l);
  }

  const limpo = out.join("\n").replace(/\n{3,}/g, "\n\n").trim();
  return { titulo: acharTitulo(bruto), data: acharData(texto), texto: limpo };
}

// linha de metadado de cabeçalho: "Paciente: X", "Data do exame: Y", "CRM: Z"
const METADADO = /^[A-Za-zÀ-ÿ][^:]{0,34}:\s*\S/;

// título = seção conhecida do laudo, ou linha CURTA em caixa alta sem números.
// `prox` = próxima linha não-vazia. Caixa alta seguida de metadado é papel
// timbrado (nome da clínica), não seção — não vira título.
function ehTitulo(l, prox = "") {
  if (l.length > 70) return false;
  if (ANCORA.test(l) || ANCORA_INLINE.test(l)) return true;
  const letras = l.replace(/[^A-Za-zÀ-ÿ]/g, "");
  if (letras.length < 4) return false;
  const caixaAlta = letras === letras.toUpperCase();
  const semNumero = !/\d/.test(l);
  if (!(caixaAlta && semNumero && l.length <= 45)) return false;
  return !METADADO.test(prox);
}

// palavras que não capitalizam no meio do título
const MINUSCULAS = new Set(["de", "da", "do", "das", "dos", "e", "em", "no", "na", "nos", "nas", "com", "sem", "por", "para", "a", "o", "as", "os", "ao", "à"]);
// siglas que devem permanecer em caixa alta
const SIGLAS = new Set(["tc", "rm", "rx", "us", "pet", "ct", "ecg", "eeg", "emg", "hiv", "hcv", "hbv", "dna", "rna", "pcr", "baar", "ihq"]);

// "ACHADOS" -> "Achados"; "TOMOGRAFIA DE TORAX" -> "Tomografia de Torax"
function titulize(s) {
  const palavras = String(s).trim().toLowerCase().split(/\s+/);
  return palavras.map((w, i) => {
    if (SIGLAS.has(w)) return w.toUpperCase();
    if (i > 0 && MINUSCULAS.has(w)) return w;
    return w.length <= 1 ? w : w[0].toUpperCase() + w.slice(1);
  }).join(" ");
}

// título do documento = primeira linha "de cara" plausível (nome do exame)
function acharTitulo(linhas) {
  const EXAME = /(tomografia|resson[âa]ncia|ultrassonografia|ultrassom|radiografia|raio\s*-?\s*x|densitometria|mamografia|cintilografia|pet[\s-]?ct|doppler|ecocardiograma|eletrocardiograma|endoscopia|colonoscopia|bi[óo]psia|an[áa]tomo?[\s-]?patol[óo]gic\w*|histopatol[óo]gic\w*|citol[óo]gic\w*|imunoistoqu[íi]mic\w*|laudo|relat[óo]rio|sum[áa]rio\s+de\s+alta)/i;
  for (const raw of linhas.slice(0, 40)) {
    const l = raw.trim();
    if (l.length >= 6 && l.length <= 90 && EXAME.test(l)) return l.replace(/\s{2,}/g, " ");
  }
  for (const raw of linhas.slice(0, 15)) {
    const l = raw.trim();
    if (l.length >= 8 && l.length <= 70 && !/\d{2}[\/.-]\d{2}/.test(l)) return l.replace(/\s{2,}/g, " ");
  }
  return "";
}

// data do exame: dd/mm/aaaa (primeira ocorrência plausível) -> ISO
function acharData(texto) {
  const m = String(texto || "").match(/\b(\d{2})[\/.-](\d{2})[\/.-](\d{4})\b/);
  if (m) {
    const [, d, mo, y] = m;
    const Y = +y, M = +mo, D = +d;
    if (Y >= 1990 && Y <= 2100 && M >= 1 && M <= 12 && D >= 1 && D <= 31) {
      return `${y}-${mo}-${d}`;
    }
  }
  const iso = String(texto || "").match(/\b(\d{4})-(\d{2})-(\d{2})\b/);
  return iso ? iso[0] : "";
}

// ---------- prompts de visão (só para foto / PDF escaneado) ----------

// classificação: chamada curta e barata, roda antes de qualquer extração
export const PROMPT_CLASSE = `Olhe este documento médico e diga qual é o tipo dele.

"analitos" = laudo de análises clínicas / laboratório: uma TABELA de exames com nome, valor numérico, unidade e valores de referência (hemograma, bioquímica, sorologia).
"narrativo" = laudo escrito em texto corrido: laudo de imagem (tomografia, ultrassom, ressonância, raio-X), anatomia patológica, relatório médico, sumário de alta. Tem seções como Técnica, Achados, Impressão, Conclusão.

Se tiver dúvida, responda "narrativo".
Responda SOMENTE com JSON: {"classe":"analitos"|"narrativo","confianca":0.0-1.0}`;

export const SCHEMA_CLASSE = {
  type: "object",
  properties: { classe: { type: "string", enum: ["analitos", "narrativo"] }, confianca: { type: "number" } },
  required: ["classe"]
};

// transcrição fiel de laudo narrativo — transcreve e organiza, NÃO interpreta
export const PROMPT_NARRATIVO = `Você é um transcritor de documentos médicos. Transcreva FIELMENTE o texto visível.

Regras:
- Copie o texto como está escrito. NÃO resuma, NÃO reescreva, NÃO corrija, NÃO interprete.
- NÃO invente nada. Se algo estiver ilegível, escreva [ilegível] no lugar — nunca adivinhe.
- NÃO acrescente achado, conclusão, negativa ou seção que não esteja no documento.
- Preserve números, medidas, unidades e lateralidade (direita/esquerda) EXATAMENTE como aparecem.
- Organize usando APENAS os títulos que o próprio documento tem. Marque cada título com "##" (ex.: "## Técnica", "## Achados", "## Impressão").
- Itens de lista começam com "-".
- Não crie seção vazia. Não invente título que o documento não usa.
- "titulo" = o nome do exame como aparece no documento. "data" = data do exame em AAAA-MM-DD, ou vazio se não houver.

Responda SOMENTE com JSON: {"titulo":"...","data":"...","texto":"..."}`;

export const SCHEMA_NARRATIVO = {
  type: "object",
  properties: { titulo: { type: "string" }, data: { type: "string" }, texto: { type: "string" } },
  required: ["texto"]
};
