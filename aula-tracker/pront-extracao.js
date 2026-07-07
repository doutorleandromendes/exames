// pront-extracao.js — motor de extração do prontuário (lado worker).
// Roteia cada entrada para o melhor caminho e devolve SEMPRE no formato canônico,
// pronto para conferência humana (nada é salvo aqui).
//
//   PDF com camada de texto  -> parser determinístico (pdftotext + parser-texto)
//   Foto / scan / PDF s/texto -> provedor de visão (Ollama agora, Claude depois)
//
// O modelo só TRANSCREVE; a tipagem e o mapeamento canônico são determinísticos
// (pront-normalizador.js). Trocar o provedor não muda a camada determinística.

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { writeFile, unlink, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { parseLaudoTexto } from "./pront-parser-texto.js";
import { normalizeAnalito, CANONICOS } from "./pront-normalizador.js";

const exec = promisify(execFile);

// ---------- prompt + schema da visão (iguais ao harness validado) ----------
const PROMPT = `Você é um extrator de laudos laboratoriais. Transcreva EXATAMENTE o que está visível, sem inventar nem interpretar.
Regras:
- Extraia TODOS os analitos, sem pular nenhum. Em hemograma, inclua série vermelha, série branca completa (leucócitos, segmentados, bastonetes, eosinófilos, basófilos, linfócitos, monócitos) e plaquetas.
- Para cada analito informe: nome (como aparece), valor (texto literal: "0,6", "Superior a 30,0", "Não reagente", "<20"), unidade, referencia, secao (título da seção) e material (Sangue/Soro/Urina).
- Em sorologias com índice numérico E conclusão (HIV, HBsAg, etc.): use a CONCLUSÃO textual como "valor" e o índice em "leitura".
- NÃO converta valores. Copie como está, com vírgula decimal. Não invente exames.
- Responda SOMENTE com JSON no formato pedido.`;

const SCHEMA = {
  type: "object",
  properties: {
    paciente: { type: "string" }, data_coleta: { type: "string" }, laboratorio: { type: "string" },
    analitos: { type: "array", items: { type: "object", properties: {
      nome: { type: "string" }, valor: { type: "string" }, unidade: { type: "string" },
      referencia: { type: "string" }, secao: { type: "string" }, material: { type: "string" }, leitura: { type: "string" }
    }, required: ["nome", "valor"] } }
  }, required: ["analitos"]
};

// ---------- provedores de visão (interface: extrairImagens(b64[]) -> bruto[]) ----------
export function ollamaProvider(opts = {}) {
  const base = opts.base || process.env.OLLAMA_URL || "http://localhost:11434";
  const model = opts.model || process.env.OLLAMA_MODEL || "qwen2.5vl:7b";
  return {
    nome: "ollama:" + model,
    async extrairImagens(imagensB64) {
      const out = [];
      for (const b64 of imagensB64) {
        const body = { model, stream: false, format: SCHEMA, options: { temperature: 0.1, num_ctx: 8192, num_predict: 4096 },
          messages: [{ role: "user", content: PROMPT, images: [b64] }] };
        const r = await fetch(base + "/api/chat", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
        if (!r.ok) throw new Error("Ollama HTTP " + r.status);
        const data = await r.json();
        out.push(...(parseJSON(data.message?.content || "").analitos || []));
      }
      return out;
    }
  };
}

export function claudeProvider(opts = {}) {
  const model = opts.model || "claude-sonnet-4-6";
  return {
    nome: "claude:" + model,
    async extrairImagens(imagensB64, mime = "image/jpeg") {
      const out = [];
      for (const b64 of imagensB64) {
        const r = await fetch("https://api.anthropic.com/v1/messages", {
          method: "POST",
          headers: { "Content-Type": "application/json", "x-api-key": process.env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01" },
          body: JSON.stringify({ model, max_tokens: 4096, messages: [{ role: "user", content: [
            { type: "image", source: { type: "base64", media_type: mime, data: b64 } },
            { type: "text", text: PROMPT + "\nResponda só com JSON {analitos:[...]}." }
          ] }] })
        });
        if (!r.ok) throw new Error("Claude HTTP " + r.status);
        const data = await r.json();
        const txt = (data.content || []).filter(b => b.type === "text").map(b => b.text).join("\n");
        out.push(...(parseJSON(txt).analitos || []));
      }
      return out;
    }
  };
}

function escolheProvedor() {
  const p = (process.env.PRONT_PROVIDER || "ollama").toLowerCase();
  return p === "claude" ? claudeProvider() : ollamaProvider();
}

// ---------- util: parse tolerante de JSON (cercas + truncamento) ----------
function parseJSON(s) {
  let t = String(s || "").replace(/```json|```/gi, "").trim();
  const i = t.indexOf("{"); if (i >= 0) t = t.slice(i);
  try { const j = t.lastIndexOf("}"); return JSON.parse(t.slice(0, j + 1)); }
  catch {
    const objs = []; const re = /\{[^{}]*\}/g; let m;
    while ((m = re.exec(t))) { try { objs.push(JSON.parse(m[0])); } catch {} }
    const analitos = objs.filter(o => o && o.nome != null && o.valor != null);
    return { analitos };
  }
}

// ---------- desambiguação por seção (Leucócitos sangue ≠ urina) + dedup ----------
const REMAP_URINA = { leucocitos: "urina_leucocitos", eritrocitos: "urina_hemacias", hemoglobina: null, glicose: null, proteinas: null };
function normalizarBrutos(brutos) {
  const seen = new Set();
  return brutos.map(b => {
    const n = normalizeAnalito({ nome: b.nome, valor: b.valor, unidade: b.unidade, ref: b.referencia });
    const ctx = `${b.secao || ""} ${b.material || ""}`;
    if (/urina/i.test(ctx) && n.canonico in REMAP_URINA) {
      const novo = REMAP_URINA[n.canonico];
      n.canonico = novo; n.rotulo = novo ? (CANONICOS[novo]?.rotulo || n.nome_original) : n.nome_original;
    }
    return n;
  }).filter(n => { if (!n.canonico) return true; if (seen.has(n.canonico)) return false; seen.add(n.canonico); return true; });
}

// ---------- PDF: texto via pdftotext; sem texto -> rasteriza p/ visão ----------
async function pdfParaTexto(path) {
  try { const { stdout } = await exec("pdftotext", ["-layout", path, "-"], { maxBuffer: 50e6 }); return stdout; }
  catch { return ""; }
}
async function pdfParaImagens(path, prefix) {
  // pdftoppm -> PNGs; devolve base64 de cada página
  await exec("pdftoppm", ["-png", "-r", "150", path, prefix]);
  const dir = tmpdir();
  const files = (await readdir(dir)).filter(f => f.startsWith(prefix.split("/").pop()) && f.endsWith(".png")).sort();
  const { readFile } = await import("node:fs/promises");
  const out = [];
  for (const f of files) { const buf = await readFile(join(dir, f)); out.push(buf.toString("base64")); await unlink(join(dir, f)).catch(() => {}); }
  return out;
}

// ---------- auto-orientação de foto (EXIF) antes da visão ----------
// Fotos de celular costumam trazer a orientação só como flag EXIF; o modelo de
// visão pode recebê-las deitadas. sharp(buffer).rotate() aplica a orientação EXIF
// e grava os pixels já na posição correta. Import preguiçoso com fallback: se o
// sharp não estiver instalado, devolve a imagem original (sem rotacionar) em vez
// de quebrar a extração.
async function autoOrientarB64(buffer) {
  try {
    const sharp = (await import("sharp")).default;
    const out = await sharp(buffer).rotate().toBuffer();
    return out.toString("base64");
  } catch {
    return buffer.toString("base64");
  }
}

// ---------- API principal ----------
// entrada: { buffer, mime, nomeArquivo }  ->  { paciente, data_coleta, laboratorio, analitos[], fonte, provedor }
export async function extrairDocumento({ buffer, mime, nomeArquivo }, provider = escolheProvedor()) {
  const ehPdf = /pdf/i.test(mime) || /\.pdf$/i.test(nomeArquivo || "");
  const ehImg = /image\//i.test(mime) || /\.(png|jpe?g|webp|gif|tiff?)$/i.test(nomeArquivo || "");

  if (ehPdf) {
    const tmp = join(tmpdir(), randomUUID() + ".pdf");
    await writeFile(tmp, buffer);
    try {
      const texto = await pdfParaTexto(tmp);
      if (texto.replace(/\s/g, "").length > 80) {
        const r = parseLaudoTexto(texto);
        return { ...r, fonte: "pdf_texto", provedor: "parser_texto" };
      }
      // PDF sem texto -> rasteriza e manda pra visão
      const prefix = join(tmpdir(), "p_" + randomUUID());
      const imgs = await pdfParaImagens(tmp, prefix);
      const brutos = await provider.extrairImagens(imgs);
      return { analitos: normalizarBrutos(brutos), fonte: "pdf_imagem", provedor: provider.nome };
    } finally { await unlink(tmp).catch(() => {}); }
  }

  if (ehImg) {
    const b64 = await autoOrientarB64(buffer);
    const brutos = await provider.extrairImagens([b64]);
    return { analitos: normalizarBrutos(brutos), fonte: "foto", provedor: provider.nome };
  }

  throw new Error("Tipo não suportado para extração: " + (mime || nomeArquivo));
}

export { normalizarBrutos };
