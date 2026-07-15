// pront-extracao.js — motor de extração do prontuário (lado worker).
// Roteia cada entrada para o melhor caminho e devolve SEMPRE no formato canônico,
// pronto para conferência humana (nada é salvo aqui).
//
//   PDF com camada de texto  -> pdftotext, e daí SEM MODELO:
//                                 analitos  -> parser determinístico (parser-texto)
//                                 narrativo -> organizador determinístico (classificador)
//   Foto / scan / PDF s/texto -> visão: classifica (chamada curta) e então
//                                 analitos  -> extrairImagens   narrativo -> transcrever
//
// A classe sai de pront-classificador.js. Na dúvida ele devolve 'narrativo':
// transcrever no máximo quebra mal o texto; extrair analitos errado inventa
// número no prontuário.
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
import {
  classificarTexto, organizarTexto,
  PROMPT_CLASSE, SCHEMA_CLASSE, PROMPT_NARRATIVO, SCHEMA_NARRATIVO
} from "./pront-classificador.js";

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
    },
    // classificação: 1 chamada curta (num_predict baixo) só para decidir a rota
    async classificar(b64) {
      const body = { model, stream: false, format: SCHEMA_CLASSE, options: { temperature: 0, num_ctx: 4096, num_predict: 64 },
        messages: [{ role: "user", content: PROMPT_CLASSE, images: [b64] }] };
      const r = await fetch(base + "/api/chat", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      if (!r.ok) throw new Error("Ollama HTTP " + r.status);
      const j = parseJSON((await r.json()).message?.content || "");
      return { classe: j.classe === "analitos" ? "analitos" : "narrativo", confianca: Number(j.confianca) || 0.5 };
    },
    // transcrição fiel de laudo narrativo (página a página, concatenado)
    async transcrever(imagensB64) {
      const partes = [];
      let titulo = "", data = "";
      for (const b64 of imagensB64) {
        const body = { model, stream: false, format: SCHEMA_NARRATIVO, options: { temperature: 0, num_ctx: 8192, num_predict: 4096 },
          messages: [{ role: "user", content: PROMPT_NARRATIVO, images: [b64] }] };
        const r = await fetch(base + "/api/chat", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
        if (!r.ok) throw new Error("Ollama HTTP " + r.status);
        const j = parseJSON((await r.json()).message?.content || "");
        if (j.texto) partes.push(String(j.texto).trim());
        if (!titulo && j.titulo) titulo = String(j.titulo).trim();
        if (!data && j.data) data = String(j.data).trim();
      }
      return { titulo, data, texto: partes.join("\n\n") };
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
    },
    async classificar(b64, mime = "image/jpeg") {
      const txt = await chamar(model, b64, mime, PROMPT_CLASSE, 128);
      const j = parseJSON(txt);
      return { classe: j.classe === "analitos" ? "analitos" : "narrativo", confianca: Number(j.confianca) || 0.5 };
    },
    async transcrever(imagensB64, mime = "image/jpeg") {
      const partes = [];
      let titulo = "", data = "";
      for (const b64 of imagensB64) {
        const j = parseJSON(await chamar(model, b64, mime, PROMPT_NARRATIVO, 4096));
        if (j.texto) partes.push(String(j.texto).trim());
        if (!titulo && j.titulo) titulo = String(j.titulo).trim();
        if (!data && j.data) data = String(j.data).trim();
      }
      return { titulo, data, texto: partes.join("\n\n") };
    }
  };
}

// chamada única de visão à API (usada por classificar/transcrever do provedor Claude)
async function chamar(model, b64, mime, prompt, maxTokens) {
  const r = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-api-key": process.env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01" },
    body: JSON.stringify({ model, max_tokens: maxTokens, messages: [{ role: "user", content: [
      { type: "image", source: { type: "base64", media_type: mime, data: b64 } },
      { type: "text", text: prompt }
    ] }] })
  });
  if (!r.ok) throw new Error("Claude HTTP " + r.status);
  const data = await r.json();
  return (data.content || []).filter(b => b.type === "text").map(b => b.text).join("\n");
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

// ---------- rota de visão (foto / PDF escaneado) ----------
// Classifica primeiro (chamada curta), depois extrai pela rota escolhida.
// `forcado` vem da escolha humana e pula a classificação.
async function viaVisao(imgs, provider, forcado, fonte) {
  let classe = forcado, confianca = 1, motivos = ["classe definida por você"];

  if (!classe) {
    try {
      const c = await provider.classificar(imgs[0]);
      classe = c.classe; confianca = c.confianca;
      motivos = [`classificado por visão (${provider.nome})`];
    } catch (e) {
      // classificação falhou -> narrativo (rota segura), nunca analitos
      classe = "narrativo"; confianca = 0.3;
      motivos = ["classificação falhou (" + (e?.message || e) + ") — mantido em narrativo por segurança"];
    }
  }

  if (classe === "narrativo") {
    const r = await provider.transcrever(imgs);
    return { ...r, analitos: [], classe: "narrativo", confianca, motivos, fonte, provedor: provider.nome };
  }
  const brutos = await provider.extrairImagens(imgs);
  return { analitos: normalizarBrutos(brutos), classe: "analitos", confianca, motivos, fonte, provedor: provider.nome };
}

// ---------- API principal ----------
// entrada: { buffer, mime, nomeArquivo, classe? }
//   classe: 'analitos' | 'narrativo' -> pula o classificador (escolha humana tem precedência)
//           ausente/null             -> classifica automaticamente
// saída:  { classe, confianca, motivos[], fonte, provedor, ... }
//   classe='analitos'  -> { paciente, data_coleta, laboratorio, analitos[] }
//   classe='narrativo' -> { titulo, data, texto, analitos: [] }
export async function extrairDocumento({ buffer, mime, nomeArquivo, classe }, provider = escolheProvedor()) {
  const forcado = (classe === "analitos" || classe === "narrativo") ? classe : null;
  const ehPdf = /pdf/i.test(mime) || /\.pdf$/i.test(nomeArquivo || "");
  const ehImg = /image\//i.test(mime) || /\.(png|jpe?g|webp|gif|tiff?)$/i.test(nomeArquivo || "");

  if (ehPdf) {
    const tmp = join(tmpdir(), randomUUID() + ".pdf");
    await writeFile(tmp, buffer);
    try {
      const texto = await pdfParaTexto(tmp);
      if (texto.replace(/\s/g, "").length > 80) {
        // PDF COM camada de texto: o texto literal já está na mão.
        // Nenhum modelo entra aqui — nem para classificar, nem para transcrever.
        const c = forcado
          ? { classe: forcado, confianca: 1, motivos: ["classe definida por você"] }
          : classificarTexto(texto);
        if (c.classe === "narrativo") {
          const r = organizarTexto(texto);
          return { ...r, analitos: [], classe: "narrativo", confianca: c.confianca, motivos: c.motivos,
                   fonte: "pdf_texto", provedor: "transcricao_texto" };
        }
        const r = parseLaudoTexto(texto);
        return { ...r, classe: "analitos", confianca: c.confianca, motivos: c.motivos,
                 fonte: "pdf_texto", provedor: "parser_texto" };
      }
      // PDF sem texto -> rasteriza e manda pra visão
      const prefix = join(tmpdir(), "p_" + randomUUID());
      const imgs = await pdfParaImagens(tmp, prefix);
      return await viaVisao(imgs, provider, forcado, "pdf_imagem");
    } finally { await unlink(tmp).catch(() => {}); }
  }

  if (ehImg) {
    const b64 = await autoOrientarB64(buffer);
    return await viaVisao([b64], provider, forcado, "foto");
  }

  throw new Error("Tipo não suportado para extração: " + (mime || nomeArquivo));
}

export { normalizarBrutos };
