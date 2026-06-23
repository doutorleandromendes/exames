// pront-migra-jotform.js — migra a exportação do JotForm (formulário "Consultorio")
// para o schema pront_*. Uma submissão = um paciente; o widget "Consultas" (qid 12)
// vira pront_consultas; a grade de seguimento (qid 14, poucos pacientes) vira
// pront_coletas + pront_resultados.
//
// Uso:
//   node pront-migra-jotform.js submissions.json            (insere; pula já existentes)
//   node pront-migra-jotform.js submissions.json --reset     (apaga pront_* antes)
//   import { migrarJotform } from './pront-migra-jotform.js'  (programático)

import { readFile } from "node:fs/promises";
import { brNum } from "./pront-normalizador.js";

// ---- helpers de leitura da exportação ----
const ans = (s, qid) => s?.answers?.[qid] || {};
const aval = (s, qid) => ans(s, qid).answer;

function nomeDe(s) {
  const a = aval(s, "3");
  if (a && typeof a === "object") return [a.first, a.middle, a.last].filter(Boolean).join(" ").replace(/\s+/g, " ").trim();
  return (ans(s, "3").prettyFormat || "").replace(/\s+/g, " ").trim();
}
function dnDe(s) {
  const a = aval(s, "17");
  if (a && a.datetime) return a.datetime.slice(0, 10);     // "1996-06-21"
  if (a && a.year) return `${a.year}-${String(a.month).padStart(2, "0")}-${String(a.day).padStart(2, "0")}`;
  return null;
}
function dataBR(str) { // "08-06-2026" ou "07/08/2019" -> "2026-06-08"
  const m = String(str || "").trim().match(/^(\d{2})[-/](\d{2})[-/](\d{4})$/);
  if (!m) return null;
  return `${m[3]}-${m[2]}-${m[1]}`;
}
function consultasDe(s) {
  let raw = aval(s, "12"); if (!raw) return [];
  let arr; try { arr = typeof raw === "string" ? JSON.parse(raw) : raw; } catch { return []; }
  if (!Array.isArray(arr)) return [];
  return arr.map(e => ({ data: dataBR(e.Data), texto: (e.Consulta || "").trim() }))
            .filter(e => e.texto || e.data);
}

// grade qid 14: linha=analito (por índice), coluna=coleta. Linha 1 = datas.
const ROW_CANON = { 2: "cd4", 3: "cv_hiv", 4: "hemoglobina", 5: "segmentados", 6: "eosinofilos",
  7: "linfocitos", 8: "creatinina", 9: "ureia", 10: "ast", 11: "alt", 12: "fosfatase_alc",
  13: "ggt", 14: "bilirrubina_total", 15: "ldl", 16: "hdl", 17: "triglicerides", 18: "glicose", 19: "hba1c" };
// Seg/Eos/Linf na grade eram digitados em % (não absoluto) — sinalizamos.
const PCT_LEGADO = new Set(["segmentados", "eosinofilos", "linfocitos"]);

// resolve uma data de grade que pode vir como dd/mm/aaaa OU dd/mm (sem ano).
// Para dd/mm, infere o ano casando dd/mm com as datas de consulta; senão usa anoBase.
function dataGrade(str, consultaDatas, anoBase, infer) {
  const full = dataBR(str);
  if (full) return { data: full, inferido: false };
  const m = String(str || "").trim().match(/^(\d{2})[-/](\d{2})$/);
  if (!m) return null;
  const dd = m[1], mm = m[2];
  const match = consultaDatas.find(d => d.slice(5) === `${mm}-${dd}`);
  const ano = match ? match.slice(0, 4) : (infer.anoMaisComum || anoBase);
  return { data: `${ano}-${mm}-${dd}`, inferido: true };
}

function gradeDe(s, consultaDatas = [], anoSubmissao = null) {
  let raw = aval(s, "14"); if (!raw) return null;
  let grid; try { grid = typeof raw === "string" ? JSON.parse(raw) : raw; } catch { return null; }
  if (!Array.isArray(grid) || grid.length < 2) return null;
  const linha = {};
  for (const row of grid) { if (Array.isArray(row) && typeof row[0] === "number") linha[row[0]] = row.slice(1); }
  const brutas = (linha[1] || []).map(x => String(x ?? "").trim());
  const anosCasados = brutas.map(b => { const mm = b.match(/^(\d{2})[-/](\d{2})$/); if (!mm) return null;
    const c = consultaDatas.find(d => d.slice(5) === `${mm[2]}-${mm[1]}`); return c ? c.slice(0, 4) : null; }).filter(Boolean);
  const anoMaisComum = anosCasados.sort((a, b) =>
    anosCasados.filter(x => x === b).length - anosCasados.filter(x => x === a).length)[0];
  const anoBase = anoMaisComum || (consultaDatas[0] || "").slice(0, 4) || (anoSubmissao || "").slice(0, 4) || String(new Date().getFullYear());
  const datas = brutas.map(b => dataGrade(b, consultaDatas, anoBase, { anoMaisComum }));
  const coletas = [];
  datas.forEach((dt, col) => {
    if (!dt || !dt.data) return;
    const resultados = [];
    for (const [idx, canon] of Object.entries(ROW_CANON)) {
      const cell = (linha[idx] || [])[col];
      const v = String(cell ?? "").trim();
      if (!v) continue;
      const num = brNum(v);
      if (num != null && isFinite(num)) resultados.push({ canonico: canon, tipo_valor: "numerico", valor_num: num, pct_legado: PCT_LEGADO.has(canon) });
      else resultados.push({ canonico: canon, tipo_valor: "qualitativo", resultado_txt: v });
    }
    if (resultados.length) coletas.push({ data: dt.data, ano_inferido: dt.inferido, resultados });
  });
  return coletas.length ? coletas : null;
}

// ---- monta pacientes (com merge de submissões do mesmo nome) ----
export function montarPacientes(subs) {
  const porChave = new Map();
  const merges = [];
  for (const s of subs) {
    const nome = nomeDe(s); if (!nome) continue;
    const dn = dnDe(s);
    const chave = nome.toLowerCase() + "|" + (dn || "");
    const consultas = consultasDe(s);
    const consultaDatas = consultas.map(c => c.data).filter(Boolean).sort();
    const reg = {
      nome, dn, cpf: aval(s, "21") || null, telefone: aval(s, "22") || null,
      endereco: aval(s, "20") || null, acompanhante: aval(s, "18") || null,
      consultas, grade: gradeDe(s, consultaDatas, s.created_at), jotform_id: s.id,
      criado_em: s.created_at || null
    };
    if (porChave.has(chave)) {
      const ex = porChave.get(chave);
      ex.consultas.push(...reg.consultas);
      if (reg.grade) ex.grade = (ex.grade || []).concat(reg.grade);
      for (const k of ["cpf", "telefone", "endereco", "acompanhante", "dn"]) if (!ex[k] && reg[k]) ex[k] = reg[k];
      ex.jotform_id += "," + reg.jotform_id;
      merges.push(nome);
    } else porChave.set(chave, reg);
  }
  // ordena consultas por data
  for (const p of porChave.values())
    p.consultas.sort((a, b) => String(a.data || "").localeCompare(String(b.data || "")));
  return { pacientes: [...porChave.values()], merges };
}

// ---- grava no Postgres ----
export async function migrarJotform(pool, subs, { reset = false, log = console.log } = {}) {
  if (reset) { await pool.query(`TRUNCATE pront_pacientes RESTART IDENTITY CASCADE`); log("[migra] pront_* zerado"); }
  const { pacientes, merges } = montarPacientes(subs);
  let nPac = 0, nCons = 0, nCol = 0, nRes = 0, pulados = 0;
  const avisos = [];
  for (const p of pacientes) {
    // idempotência: pula se já existe paciente com mesmo nome+dn
    const ex = await pool.query(`SELECT id FROM pront_pacientes WHERE lower(nome)=lower($1) AND dn IS NOT DISTINCT FROM $2::date`, [p.nome, p.dn]);
    if (ex.rows.length) { pulados++; continue; }
    const obs = [p.endereco && `Endereço: ${p.endereco}`, p.acompanhante && `Acompanhante: ${p.acompanhante}`,
      `Origem JotForm #${p.jotform_id}`].filter(Boolean).join("\n");
    const pac = (await pool.query(
      `INSERT INTO pront_pacientes(nome,dn,cpf,telefone,obs,criado_por) VALUES($1,$2::date,$3,$4,$5,'migracao') RETURNING id`,
      [p.nome, p.dn, p.cpf, p.telefone, obs])).rows[0];
    nPac++;
    for (const c of p.consultas) {
      await pool.query(`INSERT INTO pront_consultas(paciente_id,data,texto,criado_por) VALUES($1,COALESCE($2::date,current_date),$3,'migracao')`,
        [pac.id, c.data, c.texto]); nCons++;
    }
    for (const col of (p.grade || [])) {
      const lab = col.ano_inferido ? "JotForm (grade, ano inferido)" : "JotForm (grade)";
      if (col.ano_inferido) avisos.push(`${p.nome}: coleta ${col.data} — ano inferido (confirmar)`);
      const c = (await pool.query(
        `INSERT INTO pront_coletas(paciente_id,data_coleta,laboratorio,fonte,criado_por) VALUES($1,$2::date,$3,'xlsx','migracao')
         ON CONFLICT (paciente_id,data_coleta,laboratorio) DO UPDATE SET fonte=EXCLUDED.fonte RETURNING id`,
        [pac.id, col.data, lab])).rows[0];
      nCol++;
      for (const r of col.resultados) {
        if (r.pct_legado) avisos.push(`${p.nome}: ${r.canonico} importado como % (grade legada)`);
        await pool.query(
          `INSERT INTO pront_resultados(coleta_id,canonico,tipo_valor,valor_num,resultado_txt) VALUES($1,$2,$3,$4,$5)`,
          [c.id, r.canonico, r.tipo_valor, r.valor_num ?? null, r.resultado_txt ?? null]); nRes++;
      }
    }
  }
  log(`[migra] pacientes=${nPac} (pulados=${pulados}), consultas=${nCons}, coletas=${nCol}, resultados=${nRes}`);
  if (merges.length) log(`[migra] submissões mescladas por nome+DN: ${[...new Set(merges)].join("; ")}`);
  return { nPac, nCons, nCol, nRes, pulados, merges: [...new Set(merges)], avisos };
}

// ---- CLI ----
if (import.meta.url === `file://${process.argv[1]}`) {
  const file = process.argv[2]; const reset = process.argv.includes("--reset");
  if (!file) { console.error("uso: node pront-migra-jotform.js submissions.json [--reset]"); process.exit(1); }
  const pg = (await import("pg")).default;
  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
  const subs = JSON.parse(await readFile(file, "utf8"));
  await migrarJotform(pool, subs, { reset });
  await pool.end();
}
