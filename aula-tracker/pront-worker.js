// pront-worker.js — worker de extração. Roda na MÁQUINA DA CLÍNICA (onde estão
// o Ollama e o poppler). Puxa documentos 'pendente' da fila, extrai e devolve o
// JSON para conferência humana. NÃO cria coletas — isso é feito pelo médico/secretária
// na tela de conferência, depois de revisar.
//
// Ambiente necessário:
//   DATABASE_URL  -> Postgres do Render (connection string externa)
//   R2_*          -> credenciais do bucket (mesmas do servidor; lib lab-storage)
//   PRONT_PROVIDER=ollama|claude   (default ollama)
//   OLLAMA_URL / OLLAMA_MODEL      (se ollama)
//   ANTHROPIC_API_KEY              (se claude)
//
// Uso:  node pront-worker.js        (loop contínuo)
//       node pront-worker.js --once (processa um e sai — útil para teste/cron)

import "dotenv/config";
import pg from "pg";
import { fetchR2Stream } from "./lab-storage.js";
import { extrairDocumento } from "./pront-extracao.js";
import { processarAudio } from "./pront-transcricao.js";

const POLL_MS = Number(process.env.PRONT_POLL_MS || 5000);
const MAX_TENT = Number(process.env.PRONT_MAX_TENT || 3);

// SSL para conexão externa (Postgres do Render exige TLS); PGSSL=disable desliga (ex.: dentro da rede do Render)
const __ssl = process.env.PGSSL === "disable" ? false : { rejectUnauthorized: false };
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 2, ssl: __ssl });

// reivindica 1 documento de forma segura mesmo com vários workers
async function claimPendente() {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { rows } = await client.query(
      `SELECT * FROM pront_documentos
        WHERE status='pendente' AND tentativas < $1
        ORDER BY criado_em
        LIMIT 1
        FOR UPDATE SKIP LOCKED`, [MAX_TENT]);
    if (!rows.length) { await client.query("COMMIT"); return null; }
    const doc = rows[0];
    await client.query(`UPDATE pront_documentos SET status='processando' WHERE id=$1`, [doc.id]);
    await client.query("COMMIT");
    return doc;
  } catch (e) { await client.query("ROLLBACK").catch(() => {}); throw e; }
  finally { client.release(); }
}

async function processa(doc) {
  // classe 'imagem' = você decidiu que este documento fica só como anexo visual.
  // Nada a extrair: nem baixa do R2, nem acorda o Ollama. Vai direto pra conferência.
  if (doc.tipo !== "audio" && doc.classe_pedida === "imagem") {
    await pool.query(
      `UPDATE pront_documentos
          SET status='extraido', classe='imagem', classe_conf=1, provedor=NULL,
              extraido_json=$2::jsonb, processado_em=now(), erro=NULL
        WHERE id=$1`,
      [doc.id, JSON.stringify({ classe: "imagem", motivos: ["mantido como imagem por sua escolha"] })]);
    console.log(`[worker] doc#${doc.id} IMAGEM — sem extração (escolha do usuário)`);
    return;
  }

  const resp = await fetchR2Stream(doc.r2_key);
  const buffer = Buffer.from(await resp.arrayBuffer());
  const mime = doc.mime || resp.headers.get("content-type") || "";

  if (doc.tipo === "audio") {
    const r = await processarAudio({ buffer, mime, nomeArquivo: doc.nome_arquivo, modo: doc.modo || "resumo", diarizar: !!doc.diarizar });
    await pool.query(
      `UPDATE pront_documentos
          SET status='extraido', provedor=$2, extraido_json=$3, transcricao=$4,
              data_coleta_sugerida = NULLIF($5,'')::date,
              processado_em=now(), erro=NULL
        WHERE id=$1`,
      [doc.id, r.provedor || null, JSON.stringify(r), r.transcript || null, r.data_sugerida || ""]);
    console.log(`[worker] doc#${doc.id} AUDIO OK — ${r.modo}/${r.provedor} — ${r.texto?.length || 0} chars`);
    return;
  }

  // classe_pedida (escolha humana) tem precedência; NULL = o classificador decide
  const r = await extrairDocumento({ buffer, mime, nomeArquivo: doc.nome_arquivo, classe: doc.classe_pedida || null });

  // data sugerida: analitos -> data da coleta; narrativo -> data do exame
  const dataSug = (r.classe === "narrativo" ? r.data : r.data_coleta) || "";
  await pool.query(
    `UPDATE pront_documentos
        SET status='extraido', provedor=$2, extraido_json=$3,
            classe=$4, classe_conf=$5,
            data_coleta_sugerida = NULLIF($6,'')::date,
            processado_em=now(), erro=NULL
      WHERE id=$1`,
    [doc.id, r.provedor || null, JSON.stringify(r), r.classe || null, r.confianca ?? null, dataSug]);

  const detalhe = r.classe === "narrativo"
    ? `${(r.texto || "").length} chars — "${(r.titulo || "sem título").slice(0, 40)}"`
    : `${r.analitos?.length || 0} analitos`;
  console.log(`[worker] doc#${doc.id} OK — ${r.classe} (conf ${Number(r.confianca ?? 0).toFixed(2)}) — ${r.fonte}/${r.provedor} — ${detalhe}`);
}

async function falha(doc, e) {
  await pool.query(
    `UPDATE pront_documentos
        SET status = CASE WHEN tentativas+1 >= $2 THEN 'erro' ELSE 'pendente' END,
            tentativas = tentativas+1, erro=$3, processado_em=now()
      WHERE id=$1`, [doc.id, MAX_TENT, String(e?.message || e).slice(0, 500)]);
  console.warn(`[worker] doc#${doc.id} FALHA (tent ${doc.tentativas + 1}/${MAX_TENT}): ${e?.message || e}`);
}

async function tick() {
  const doc = await claimPendente();
  if (!doc) return false;
  try { await processa(doc); } catch (e) { await falha(doc, e); }
  return true;
}

async function main() {
  const once = process.argv.includes("--once");
  console.log(`[worker] iniciado — provider=${process.env.PRONT_PROVIDER || "ollama"} once=${once}`);
  if (once) { await tick(); await pool.end(); return; }
  // loop: processa tudo que puder, depois dorme
  for (;;) {
    let trabalhou = false;
    try { trabalhou = await tick(); } catch (e) { console.error("[worker] erro no tick:", e.message); }
    if (!trabalhou) await new Promise(r => setTimeout(r, POLL_MS));
  }
}

main().catch(e => { console.error("[worker] fatal:", e); process.exit(1); });
