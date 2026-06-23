// pront-transcricao.js — motor de transcrição de consultas (lado worker, na clínica).
//
// Fluxo: áudio -> ffmpeg (wav 16k mono) -> Whisper (ASR LOCAL) -> transcript
//        -> Ollama (estrutura LOCAL) -> rascunho de consulta (##/#/-)
//
// Tudo roda na máquina da clínica; o áudio NUNCA sai. O modelo só transcreve e
// organiza — NÃO inventa. A consulta só entra no prontuário após conferência humana
// (mesma regra de ouro do resto do módulo).
//
// Dois modos:
//   "resumo"   -> médico dita um resumo. Entrada limpa, 1 voz; estrutura direto.
//   "consulta" -> grava a consulta inteira. Diarização (quem falou) opcional.
//
// Providers de ASR são plugáveis via PRONT_ASR (whispercpp | fasterwhisper).
// O estruturador usa Ollama (texto) via OLLAMA_URL / OLLAMA_TEXT_MODEL.

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { writeFile, readFile, unlink, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const exec = promisify(execFile);

// ----------------------------------------------------------------------------
// 0) preparo do áudio: qualquer formato -> wav 16kHz mono (o que o Whisper quer)
// ----------------------------------------------------------------------------
async function prepararWav(inPath, outPath) {
  await exec("ffmpeg", ["-y", "-i", inPath, "-ar", "16000", "-ac", "1",
    "-af", "highpass=f=80,loudnorm", outPath], { maxBuffer: 1 << 26 });
  return outPath;
}

// ----------------------------------------------------------------------------
// 1) Providers de ASR — interface: transcrever(wavPath, {idioma,diarizar})
//    -> { transcript, segments:[{speaker?,text,start,end}] }
// ----------------------------------------------------------------------------

// whisper.cpp — acelerado por Metal no Apple Silicon. Sem diarização nativa.
export function whisperCppProvider(opts = {}) {
  const bin = opts.bin || process.env.WHISPER_CPP_BIN || "whisper-cli";
  const model = opts.model || process.env.WHISPER_CPP_MODEL || "models/ggml-large-v3.bin";
  return {
    nome: "whisper.cpp:" + model.split("/").pop(),
    diariza: false,
    async transcrever(wavPath, { idioma = "pt" } = {}) {
      // -oj => escreve <wav>.json com segments
      await exec(bin, ["-m", model, "-l", idioma, "-oj", "-of", wavPath, "-f", wavPath],
        { maxBuffer: 1 << 26 });
      const j = JSON.parse(await readFile(wavPath + ".json", "utf8"));
      const segs = (j.transcription || []).map(s => ({
        text: (s.text || "").trim(),
        start: s.offsets?.from != null ? s.offsets.from / 1000 : null,
        end: s.offsets?.to != null ? s.offsets.to / 1000 : null,
      })).filter(s => s.text);
      return { transcript: segs.map(s => s.text).join(" ").trim(), segments: segs };
    }
  };
}

// faster-whisper (CTranslate2/INT8, ~4x). Diarização opcional via whisperx+pyannote.
// Roda um script Python efêmero — a clínica só precisa de `pip install faster-whisper`
// (e `whisperx` se quiser diarização).
export function fasterWhisperProvider(opts = {}) {
  const py = opts.python || process.env.PYTHON_BIN || "python3";
  const model = opts.model || process.env.FASTER_WHISPER_MODEL || "large-v3";
  const device = opts.device || process.env.FASTER_WHISPER_DEVICE || "auto";
  const compute = opts.compute || process.env.FASTER_WHISPER_COMPUTE || "int8";
  return {
    nome: "faster-whisper:" + model,
    diariza: true, // se whisperx estiver instalado e diarizar=true
    async transcrever(wavPath, { idioma = "pt", diarizar = false } = {}) {
      const script = `
import json, sys
wav, lang, diar = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
from faster_whisper import WhisperModel
m = WhisperModel("${model}", device="${device}", compute_type="${compute}")
segs, _ = m.transcribe(wav, language=lang, vad_filter=True)
out = [{"text": s.text.strip(), "start": s.start, "end": s.end} for s in segs]
if diar:
    try:
        import whisperx
        dm = whisperx.DiarizationPipeline(use_auth_token=__import__("os").environ.get("HF_TOKEN"), device="cpu")
        # alinhamento simples por janela de tempo
        diary = dm(wav)
        for o in out:
            mid = (o["start"] + o["end"]) / 2
            row = diary[(diary["start"] <= mid) & (diary["end"] >= mid)]
            o["speaker"] = (row.iloc[0]["speaker"] if len(row) else None)
    except Exception as e:
        sys.stderr.write("diar-falhou: %s\\n" % e)
print(json.dumps({"transcript": " ".join(o["text"] for o in out).strip(), "segments": out}))
`;
      const dir = await mkdtemp(join(tmpdir(), "fw-"));
      const sp = join(dir, "fw.py");
      await writeFile(sp, script);
      const { stdout } = await exec(py, [sp, wavPath, idioma, diarizar ? "1" : "0"], { maxBuffer: 1 << 26 });
      await unlink(sp).catch(() => {});
      return JSON.parse(stdout);
    }
  };
}

function escolheASR() {
  const p = (process.env.PRONT_ASR || "whispercpp").toLowerCase();
  return p === "fasterwhisper" ? fasterWhisperProvider() : whisperCppProvider();
}

// ----------------------------------------------------------------------------
// 2) Estruturador (Ollama, texto) — transcript -> rascunho de consulta
// ----------------------------------------------------------------------------
const REGRAS = `REGRAS ABSOLUTAS:
- Use SOMENTE o que está na transcrição. NÃO invente sintomas, exames, doses ou diagnósticos.
- Se algo não foi dito, não preencha a seção (melhor faltar do que inventar).
- Preserve EXATAMENTE nomes de medicação, doses e termos técnicos como foram ditos. Se um nome ficou duvidoso na transcrição, mantenha e marque com "(?)".
- Não dê conselho médico nem complete raciocínio clínico. Você organiza, não decide.
- Saída em texto, no formato: "## " para título, "# " para seção, "- " para itens. Sem comentários fora do texto.`;

const PROMPT_RESUMO = (t) => `Você recebe a transcrição de um médico DITANDO o resumo de uma consulta (uma só voz).
Organize fielmente no formato do prontuário. ${REGRAS}

Transcrição:
"""${t}"""

Responda SOMENTE com JSON: {"texto":"<a evolução formatada com ## / # / ->","data":"<AAAA-MM-DD se uma data foi dita, senão vazio>"}`;

const PROMPT_CONSULTA = (t) => `Você recebe a transcrição de uma CONSULTA inteira (médico e paciente; pode haver rótulos de quem falou).
Produza a evolução em formato SOAP, atribuindo: relato/queixas do paciente em "# Subjetivo"; achados ditos pelo médico em "# Objetivo"; impressão em "# Avaliação"; e o que o médico determinou em "# Conduta". ${REGRAS}

Transcrição:
"""${t}"""

Responda SOMENTE com JSON: {"texto":"<a evolução em ## Consulta + # Subjetivo/# Objetivo/# Avaliação/# Conduta>","data":"<AAAA-MM-DD se dita, senão vazio>"}`;

function salvarJSON(s) {
  if (!s) return null;
  const m = s.match(/\{[\s\S]*\}/);
  try { return JSON.parse(m ? m[0] : s); } catch { return null; }
}

export function ollamaStructurer(opts = {}) {
  const base = opts.base || process.env.OLLAMA_URL || "http://localhost:11434";
  const model = opts.model || process.env.OLLAMA_TEXT_MODEL || "llama3.1:8b";
  return {
    nome: "ollama:" + model,
    async estruturar(transcript, { modo = "resumo" } = {}) {
      const prompt = (modo === "consulta" ? PROMPT_CONSULTA : PROMPT_RESUMO)(transcript);
      const body = { model, stream: false, options: { temperature: 0.1, num_ctx: 16384 },
        format: "json", messages: [{ role: "user", content: prompt }] };
      const r = await fetch(base + "/api/chat", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      if (!r.ok) throw new Error("Ollama HTTP " + r.status);
      const data = await r.json();
      const j = salvarJSON(data.message?.content || "") || {};
      return { texto: (j.texto || data.message?.content || "").trim(), data_sugerida: (j.data || "").slice(0, 10) || null };
    }
  };
}

// ----------------------------------------------------------------------------
// 3) Orquestrador — buffer de áudio -> rascunho de consulta para conferência
// ----------------------------------------------------------------------------
function montarTranscriptComFalas(segments, transcriptPlano) {
  if (!segments?.some(s => s.speaker)) return transcriptPlano;
  // agrupa turnos consecutivos do mesmo falante
  const linhas = []; let atual = null;
  for (const s of segments) {
    const who = s.speaker || "?";
    if (atual && atual.who === who) atual.text += " " + s.text;
    else { atual = { who, text: s.text }; linhas.push(atual); }
  }
  return linhas.map(l => `${l.who}: ${l.text}`).join("\n");
}

export async function processarAudio(
  { buffer, mime, nomeArquivo, modo = "resumo", diarizar = false },
  { asr = escolheASR(), structurer = ollamaStructurer() } = {}
) {
  const avisos = [];
  const dir = await mkdtemp(join(tmpdir(), "pront-audio-"));
  const ext = (nomeArquivo || "").match(/\.[a-z0-9]+$/i)?.[0] || (/wav/i.test(mime || "") ? ".wav" : ".m4a");
  const inPath = join(dir, "in" + ext);
  const wavPath = join(dir, "audio.wav");
  await writeFile(inPath, buffer);
  try {
    await prepararWav(inPath, wavPath);
    if (diarizar && modo === "consulta" && !asr.diariza) {
      avisos.push("Diarização indisponível neste provedor de ASR; transcrição sem rótulo de falante.");
      diarizar = false;
    }
    const { transcript, segments } = await asr.transcrever(wavPath, { idioma: "pt", diarizar });
    if (!transcript || transcript.length < 4) {
      return { tipo: "consulta_rascunho", modo, transcript: transcript || "", texto: "", data_sugerida: null,
        avisos: [...avisos, "Transcrição vazia ou muito curta — verifique o áudio."], provedor: asr.nome };
    }
    const txtParaLLM = montarTranscriptComFalas(segments, transcript);
    const { texto, data_sugerida } = await structurer.estruturar(txtParaLLM, { modo });
    return { tipo: "consulta_rascunho", modo, transcript, texto, data_sugerida, avisos, provedor: `${asr.nome} + ${structurer.nome}` };
  } finally {
    await Promise.all([unlink(inPath), unlink(wavPath), unlink(wavPath + ".json")].map(p => p.catch(() => {})));
  }
}

// mocks para teste sem Whisper/Ollama
export function mockASR(transcript, segments = null) {
  return { nome: "mock-asr", diariza: !!segments?.some(s => s.speaker),
    async transcrever() { return { transcript, segments: segments || transcript.split(/(?<=\.)\s+/).map(t => ({ text: t })) }; } };
}
export function mockStructurer(fn) {
  return { nome: "mock-structurer", async estruturar(t, o) { return fn(t, o); } };
}
