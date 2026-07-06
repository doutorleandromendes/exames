// pront-routes.js — rotas do prontuário eletrônico (módulo pront_*).
// Uso em app.js:
//   import { registerProntRoutes } from './pront-routes.js';
//   await runProntMigrations(pool);
//   registerProntRoutes(app, pool, authRequired, adminRequired, renderShell);
//
// authRequired  -> secretária e médico (qualquer usuário logado)
// adminRequired -> médico (ações sensíveis: apagar, etc.)
import express from "express";
import { uploadToR2, fetchR2Stream, deleteFromR2 } from "./lab-storage.js";
import { readFile } from "node:fs/promises";
import { gerarDocumentoPDF } from "./pront-doc-pdf.js";
import { generateLabPdf } from "./lab-pdf.js";
import { preverImportacao, gravarTudo } from "./pront-importador-db.js";
import { parseValue } from "./pront-normalizador.js";
import { randomUUID } from "node:crypto";
import { abrirSessao, descobrirCertificado } from "./birdid.js";
import { makeBirdIdRawSigner, assinarPdfCades } from "./birdid-cades.js";

function safe(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function toBR(d) {
  if (!d) return "—";
  const s = String(d);
  if (/^\d{2}\/\d{2}\/\d{4}$/.test(s)) return s;
  const dt = new Date(s.length === 10 ? s + "T12:00:00" : s);
  return isNaN(dt) ? s : dt.toLocaleDateString("pt-BR");
}
function idade(dn) {
  if (!dn) return null;
  const d = dn instanceof Date ? dn : new Date(String(dn).slice(0, 10) + "T12:00:00");
  if (isNaN(d)) return null;
  const h = new Date(); let a = h.getFullYear() - d.getFullYear();
  const m = h.getMonth() - d.getMonth(); if (m < 0 || (m === 0 && h.getDate() < d.getDate())) a--;
  return a;
}
// formata o texto da consulta preservando os marcadores "#"/"##" e quebras
function renderConsulta(txt) {
  const linhas = String(txt || "").split(/\r?\n/);
  let out = "", emLista = false;
  const fechaLista = () => { if (emLista) { out += "</ul>"; emLista = false; } };
  for (const raw of linhas) {
    const l = raw.trim();
    if (!l) { fechaLista(); out += '<div style="height:6px"></div>'; continue; }
    if (/^##\s*/.test(l)) { fechaLista(); out += `<div style="font-weight:700;font-size:1.05em;margin:8px 0 2px">${safe(l.replace(/^##\s*/, ""))}</div>`; }
    else if (/^#\s*/.test(l)) { fechaLista(); out += `<div style="font-weight:600;color:var(--pri);margin:6px 0 2px">${safe(l.replace(/^#\s*/, ""))}</div>`; }
    else if (/^[-•]\s*/.test(l)) { if (!emLista) { out += '<ul style="margin:2px 0 2px 18px">'; emLista = true; } out += `<li>${safe(l.replace(/^[-•]\s*/, ""))}</li>`; }
    else { fechaLista(); out += `<div>${safe(l)}</div>`; }
  }
  fechaLista();
  return out;
}

export function registerProntRoutes(app, pool, authRequired, adminRequired, renderShell, medicoRequired) {
  // gate do gerador de documentos = médico (super_admin). Se não vier (compat), recai no de prontuário.
  medicoRequired = medicoRequired || authRequired;
  const quem = req => req.user?.full_name || req.user?.email || "sistema";

  // ---- API: cadastro mestre de pacientes (consumido pelo dropdown do lab) ----
  app.get("/pront/api/pacientes", authRequired, async (req, res) => {
    const { rows } = await pool.query(
      `SELECT id, nome, to_char(dn,'YYYY-MM-DD') dn FROM pront_pacientes ORDER BY lower(nome)`);
    res.json(rows);
  });

  // ---- dashboard: resumo + fila + busca + lista ----
  app.get("/pront", authRequired, async (req, res) => {
    const q = (req.query.q || "").trim();
    // ordenação por cabeçalho — allowlist (nunca interpola entrada do usuário no SQL)
    const SORTS = {
      nome:    "lower(p.nome)",
      dn:      "p.dn",
      ncons:   "ncons",
      ncol:    "ncol",
      ultima:  "ultima",
    };
    const sort = SORTS[req.query.sort] ? req.query.sort : null;
    const dir = req.query.dir === "asc" ? "ASC" : req.query.dir === "desc" ? "DESC" : null;
    const orderBy = (sort && dir)
      ? `${SORTS[sort]} ${dir} NULLS LAST, lower(p.nome)`
      : `ultima DESC NULLS LAST, lower(p.nome)`;   // padrão
    const { rows } = await pool.query(
      `SELECT p.id, p.nome, p.dn,
              (SELECT count(*) FROM pront_consultas c WHERE c.paciente_id=p.id)::int ncons,
              (SELECT max(data)  FROM pront_consultas c WHERE c.paciente_id=p.id) ultima,
              (SELECT count(*) FROM pront_coletas  k WHERE k.paciente_id=p.id)::int ncol
         FROM pront_pacientes p
        WHERE ($1='' OR p.nome ILIKE '%'||$1||'%')
        ORDER BY ${orderBy}
        LIMIT 400`, [q]);

    // estatísticas do resumo
    const st = (await pool.query(`SELECT
        (SELECT count(*) FROM pront_pacientes)::int pac,
        (SELECT count(*) FROM pront_consultas)::int cons,
        (SELECT count(*) FROM pront_coletas)::int col,
        (SELECT count(*) FROM pront_documentos WHERE status IN ('pendente','processando'))::int fila,
        (SELECT count(*) FROM pront_documentos WHERE status='extraido')::int conf`)).rows[0];

    const card = (n, label, href, cor) => `
      <a class="dashcard" href="${href}" style="border-left:4px solid ${cor}">
        <div class="dashnum">${n.toLocaleString("pt-BR")}</div>
        <div class="mut">${label}</div>
      </a>`;
    const cards = `
      <div class="dashgrid mt">
        ${card(st.pac, "Pacientes", "/pront", "#0c447c")}
        ${card(st.cons, "Consultas", "#", "#2563eb")}
        ${card(st.col, "Coletas de exame", "#", "#0e9f6e")}
        ${card(st.conf, "Aguardando conferência", "/pront/conferencia", st.conf ? "#d97706" : "#cbd5e1")}
        ${card(st.fila, "Na fila de OCR", "/pront/conferencia", "#7c3aed")}
      </div>`;

    const linhas = rows.map(r => `
      <tr>
        <td><a href="/pront/paciente/${r.id}">${safe(r.nome)}</a></td>
        <td class="mut">${r.dn ? toBR(r.dn) + (idade(r.dn) != null ? ` · ${idade(r.dn)}a` : "") : "—"}</td>
        <td>${r.ncons}</td>
        <td>${r.ncol ? `<a href="/pront/paciente/${r.id}/exames" title="ver evolução">${r.ncol}</a>` : "—"}</td>
        <td class="mut">${toBR(r.ultima)}</td>
      </tr>`).join("");

    res.send(renderShell("Prontuário", `
      <style>
        .dashgrid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}
        .dashcard{display:block;background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:16px 18px;text-decoration:none;color:var(--txt);box-shadow:0 1px 3px rgba(16,24,40,.05)}
        .dashcard:hover{box-shadow:0 4px 14px rgba(16,24,40,.10)}
        .dashnum{font-size:1.9em;font-weight:700;line-height:1}
      </style>
      <div class="right" style="justify-content:space-between">
        <h1 style="margin:0">Prontuário</h1>
        <div style="display:flex;gap:8px">
          ${req.user?.super_admin ? `<a href="/pront/documentos-avulsos"><button type="button" style="background:#b45309">Avulsos</button></a>` : ""}
          <a href="/pront/novo"><button type="button">+ Novo paciente</button></a>
        </div>
      </div>
      ${cards}
      ${st.conf ? `<div class="card mt" style="border-left:4px solid #d97706"><b>${st.conf}</b> documento(s) aguardando sua conferência. <a href="/pront/conferencia">Revisar →</a></div>` : ""}
      <div class="card mt2">
        <form method="get" action="/pront">
          <input name="q" value="${safe(q)}" placeholder="Buscar paciente por nome…" autofocus/>
        </form>
        <div class="mut mt">${rows.length} paciente(s)${q ? ` para “${safe(q)}”` : ""}</div>
        <table class="mt">
          <thead><tr>${(() => {
            const cols = [["nome", "Nome"], ["dn", "Nascimento"], ["ncons", "Consultas"], ["ncol", "Coletas"], ["ultima", "Última consulta"]];
            return cols.map(([key, label]) => {
              const ativo = sort === key;
              // ciclo: sem ordem -> asc -> desc -> reset
              const prox = !ativo ? "asc" : dir === "ASC" ? "desc" : "";
              const seta = ativo ? (dir === "ASC" ? " ▲" : " ▼") : "";
              const qs = new URLSearchParams();
              if (q) qs.set("q", q);
              if (prox) { qs.set("sort", key); qs.set("dir", prox); }
              const href = "/pront" + (qs.toString() ? "?" + qs.toString() : "");
              return `<th><a href="${href}" style="color:inherit;text-decoration:none">${label}${seta}</a></th>`;
            }).join("");
          })()}</tr></thead>
          <tbody>${linhas || `<tr><td colspan="5" class="mut">Nenhum paciente.</td></tr>`}</tbody>
        </table>
      </div>`));
  });

  // ---- ficha do paciente: dados + linha do tempo de consultas ----
  app.get("/pront/paciente/:id", authRequired, async (req, res) => {
    const id = req.params.id;
    const p = (await pool.query(`SELECT * FROM pront_pacientes WHERE id=$1`, [id])).rows[0];
    if (!p) return res.status(404).send(renderShell("Não encontrado", `<div class="card"><h1>Paciente não encontrado</h1><a href="/pront">← Pacientes</a></div>`));

    const consultas = (await pool.query(
      `SELECT id, data, texto, criado_por, transcricao FROM pront_consultas WHERE paciente_id=$1 ORDER BY data DESC, id DESC`, [id])).rows;
    const ncol = (await pool.query(`SELECT count(*)::int n FROM pront_coletas WHERE paciente_id=$1`, [id])).rows[0].n;

    // coletas do laboratório ligadas a este paciente (via lab_patients.pront_id); guardado se o lab não existir
    let labColetas = [];
    try {
      labColetas = (await pool.query(
        `SELECT lc.id, to_char(lc.collected_at,'YYYY-MM-DD') data,
                (SELECT count(*) FROM lab_results r WHERE r.collection_id=lc.id)::int nex
           FROM lab_collections lc
           JOIN lab_patients lp ON lp.id=lc.patient_id
          WHERE lp.pront_id=$1
          ORDER BY lc.collected_at DESC`, [id])).rows;
    } catch { labColetas = []; }

    // documentos emitidos pelo gerador (receita/pedido/relatório/atestado)
    const docsEmitidos = (await pool.query(
      `SELECT id, tipo, paper, assinado, secret_code, verif_token, descricao, to_char(criado_em,'YYYY-MM-DD') data
         FROM pront_docs_emitidos WHERE paciente_id=$1 ORDER BY criado_em DESC`, [id])).rows;
    const TIPO_DOC = { receituario: "Receituário", pedido: "Pedido de exames", relatorio: "Relatório", atestado: "Atestado", laudo: "Laudo" };

    const dados = [
      p.dn && `<b>Nasc.:</b> ${toBR(p.dn)}${idade(p.dn) != null ? ` (${idade(p.dn)} anos)` : ""}`,
      p.cpf && `<b>CPF:</b> ${safe(p.cpf)}`,
      p.telefone && `<b>Tel.:</b> ${safe(p.telefone)}`,
    ].filter(Boolean).join(" &nbsp;·&nbsp; ");

    const timeline = consultas.map(c => `
      <div class="card mt" style="padding:16px">
        <div class="right" style="justify-content:space-between">
          <div style="font-weight:700">${toBR(c.data)}${c.criado_por ? ` <span class="mut" style="font-weight:400;font-size:.85em">· por ${safe(c.criado_por)}</span>` : ""}</div>
          ${req.user?.super_admin ? `<a class="mut" style="font-size:.85em" href="/pront/paciente/${id}/consulta/${c.id}/editar">editar</a>` : ""}
        </div>
        <div class="mt" style="line-height:1.5">${renderConsulta(c.texto)}</div>
        ${(c.transcricao && req.user?.super_admin) ? `<details class="mt"><summary class="mut" style="cursor:pointer;font-size:.85em">Ver transcrição do áudio</summary><div class="mut mt" style="white-space:pre-wrap;font-size:.9em;line-height:1.5">${safe(c.transcricao)}</div></details>` : ""}
      </div>`).join("");

    res.send(renderShell(`Prontuário — ${safe(p.nome)}`, `
      <div class="admin-back-top"><a href="/pront">← Pacientes</a></div>
      <div class="card">
        <div class="right" style="justify-content:space-between">
          <h1 style="margin:0">${safe(p.nome)}</h1>
          <div class="right">
            ${ncol ? `<a href="/pront/paciente/${id}/exames"><button type="button">Exames (${ncol})</button></a>` : ""}
            <a href="/pront/paciente/${id}/exames/importar"><button type="button" style="background:#0369a1">Importar exames</button></a>
            <a href="/pront/paciente/${id}/upload"><button type="button" style="background:#0e9f6e">Enviar exame</button></a>
            ${p.nome ? `<a href="${safe('http://localhost:3000/api/buscar?nome=' + String(p.nome).trim().replace(/\s+/g,'+'))}" target="_blank"><button type="button" style="background:#0891b2">🔬 LIS</button></a>` : ""}
            <a href="/pront/paciente/${id}/orcamento" target="_blank"><button type="button" style="background:#0d9488">Orçamento</button></a>
            ${req.user?.super_admin ? `<a href="/pront/paciente/${id}/documento" target="_blank"><button type="button" style="background:#b45309">Emitir documento</button></a>` : ""}
            ${req.user?.super_admin ? `<a href="/pront/paciente/${id}/consulta/audio"><button type="button" style="background:#6d28d9">Áudio</button></a>` : ""}
            <a href="/pront/paciente/${id}/consulta/nova"><button type="button">+ Consulta</button></a>
          </div>
        </div>
        ${dados ? `<div class="mut mt">${dados}</div>` : ""}
        ${p.obs ? `<div class="mut mt" style="white-space:pre-line">${safe(p.obs)}</div>` : ""}
        <div class="mt"><a class="mut" style="font-size:.85em" href="/pront/paciente/${id}/editar">editar dados</a></div>
      </div>
      ${labColetas.length ? `
      <h2 class="mt2" style="margin-bottom:0">Exames do laboratório <span class="mut" style="font-weight:400">(${labColetas.length})</span></h2>
      <div class="card mt">
        <table>
          <thead><tr><th>Data da coleta</th><th>Exames</th><th></th></tr></thead>
          <tbody>${labColetas.map(c => `
            <tr>
              <td>${toBR(c.data)}</td>
              <td>${c.nex}</td>
              <td><a href="/lab/admin/coletas/${c.id}">abrir</a> · <a href="/lab/admin/coletas/${c.id}/preview" target="_blank">laudo PDF</a></td>
            </tr>`).join("")}</tbody>
        </table>
      </div>` : ""}
      ${docsEmitidos.length ? `
      <h2 class="mt2" style="margin-bottom:0">Documentos emitidos <span class="mut" style="font-weight:400">(${docsEmitidos.length})</span></h2>
      <div class="card mt">
        <table>
          <thead><tr><th>Data</th><th>Documento</th><th>Papel</th><th>Assinatura</th><th>Ações</th></tr></thead>
          <tbody>${docsEmitidos.map(d => `
            <tr>
              <td>${toBR(d.data)}</td>
              <td><b>${TIPO_DOC[d.tipo] || safe(d.tipo)}</b>${d.descricao ? `<div class="mut" style="font-size:.88em;line-height:1.3;margin-top:2px;max-width:38ch">${safe(d.descricao)}</div>` : ""}</td>
              <td class="mut">${safe(d.paper || "")}</td>
              <td>${d.assinado
                ? `<span style="color:#0e7a4b;font-weight:600">✔ ICP-Brasil</span>${d.secret_code ? ` · <span class="mut">código:</span> <code style="font-weight:700;letter-spacing:.5px">${safe(d.secret_code)}</code>` : ""}${d.verif_token ? ` · <a href="/verificar/${d.verif_token}" target="_blank">verificar</a>` : ""}`
                : `<span class="mut">—</span>`}</td>
              <td style="white-space:nowrap">
                <a href="/pront/documento-emitido/${d.id}/pdf" target="_blank">abrir PDF</a>
                · <a href="/pront/paciente/${id}/documento?dup=${d.id}">duplicar</a>
                · <a href="#" class="doc-del" data-del="${d.id}" data-desc="${safe((TIPO_DOC[d.tipo] || d.tipo) + (d.descricao ? " — " + d.descricao : ""))}" style="color:#b91c1c">excluir</a>
              </td>
            </tr>`).join("")}</tbody>
        </table>
      </div>
      <script>(function(){
        document.querySelectorAll('a.doc-del').forEach(function(a){
          a.addEventListener('click',function(ev){
            ev.preventDefault();
            var did=a.getAttribute('data-del'), desc=a.getAttribute('data-desc')||'este documento';
            if(!confirm('Excluir '+desc+' ?\\n\\nRemove o documento da ficha. Esta ação não pode ser desfeita.'))return;
            a.textContent='excluindo…';a.style.pointerEvents='none';
            fetch('/pront/documento-emitido/'+did,{method:'DELETE'}).then(function(r){
              if(r.ok){var tr=a.closest('tr');if(tr)tr.parentNode.removeChild(tr);}
              else{a.textContent='falhou';a.style.color='#b91c1c';a.style.pointerEvents='';}
            }).catch(function(){a.textContent='erro';a.style.pointerEvents='';});
          });
        });
      })();</script>` : ""}
      <h2 class="mt2" style="margin-bottom:0">Consultas <span class="mut" style="font-weight:400">(${consultas.length})</span></h2>
      ${timeline || `<div class="card mt mut">Sem consultas registradas.</div>`}
    `));
  });

  // ---- evolução de exames: tabela datas × analitos + gráfico inline ----
  app.get("/pront/paciente/:id/exames", authRequired, async (req, res) => {
    const id = req.params.id;
    const p = (await pool.query(`SELECT id,nome FROM pront_pacientes WHERE id=$1`, [id])).rows[0];
    if (!p) return res.status(404).send(renderShell("Não encontrado", `<div class="card"><h1>Paciente não encontrado</h1><a href="/pront">← Pacientes</a></div>`));

    const coletas = (await pool.query(
      `SELECT id, to_char(data_coleta,'YYYY-MM-DD') data, laboratorio, fonte FROM pront_coletas WHERE paciente_id=$1 ORDER BY data_coleta`, [id])).rows;
    const resultados = (await pool.query(
      `SELECT r.coleta_id, r.canonico, r.rotulo, r.tipo_valor, r.valor_num, r.operador, r.unidade, r.resultado_txt, r.status_flag
         FROM pront_resultados r JOIN pront_coletas c ON c.id=r.coleta_id
        WHERE c.paciente_id=$1`, [id])).rows;

    if (!coletas.length) return res.send(renderShell(`Exames — ${safe(p.nome)}`, `
      <div class="admin-back-top"><a href="/pront/paciente/${id}">← ${safe(p.nome)}</a></div>
      <div class="card"><h1>Exames</h1><div class="mut">Nenhuma coleta registrada.</div></div>`));

    // ordem clínica (monitoramento HIV primeiro), depois grupos; "outros" ao fim
    const ORDEM = ["cd4","cd8","cd4_ratio","cv_hiv","carga_viral",
      "hemoglobina","hematocrito","eritrocitos","vcm","leucocitos","segmentados","bastonetes","eosinofilos","linfocitos","monocitos","plaquetas",
      "creatinina","ureia","acido_urico","sodio","potassio","magnesio","calcio","fosforo","microalbuminuria",
      "ast","alt","ggt","fosfatase_alc","bilirrubina_total","bilirrubina_direta","albumina","ldh",
      "colesterol_total","ldl","hdl","triglicerides","glicose","hba1c","insulina",
      "tsh","t4_livre","vitamina_b12","acido_folico","reticulocitos","ferritina","vhs","pcr","cpk"];
    const colIdx = new Map(coletas.map((c, i) => [c.id, i]));
    // ordem de exibição da TABELA: mais recente à esquerda -> mais antiga à direita.
    // (o array `coletas` continua cronológico; isto afeta só cabeçalho e células.
    //  o gráfico abaixo segue usando a ordem cronológica original.)
    const ordemExib = coletas.map((_, i) => coletas.length - 1 - i);
    const ordC = c => { const i = ORDEM.indexOf(c); return i < 0 ? 999 : i; };

    // monta matriz canonico -> {rotulo, unidade, celulas[col], pontos[]}
    const linhas = new Map();
    for (const r of resultados) {
      const key = r.canonico || ("outros:" + (r.rotulo || r.resultado_txt || "?"));
      if (!linhas.has(key)) linhas.set(key, { canonico: r.canonico, rotulo: r.rotulo || ROTULO(r.canonico) || key.replace(/^outros:/, ""), unidade: r.unidade || "", celulas: Array(coletas.length).fill(null) });
      const L = linhas.get(key);
      if (!L.unidade && r.unidade) L.unidade = r.unidade;
      const ci = colIdx.get(r.coleta_id);
      if (ci != null) L.celulas[ci] = r;
    }
    const linhasOrd = [...linhas.values()].sort((a, b) =>
      (ordC(a.canonico) - ordC(b.canonico)) || String(a.rotulo).localeCompare(String(b.rotulo)));

    const COR = { alto: "#fde68a", baixo: "#bfdbfe", normal: "" };
    const STICKY = "position:sticky;left:0;z-index:1;background:var(--card);";
    const cell = (r, coletaId, canon, rotulo) => {
      let raw = "";
      if (r) {
        if (r.tipo_valor === "qualitativo") raw = r.resultado_txt || "";
        else if (r.tipo_valor === "censurado") raw = `${r.operador || ""}${fmtNum(r.valor_num)}`;
        else if (r.valor_num != null) raw = String(fmtNum(r.valor_num));
        else raw = r.resultado_txt || "";
      }
      const meta = `data-coleta="${coletaId}" data-canon="${canon || ""}" data-rotulo="${safe(rotulo || "")}" data-raw="${safe(raw)}" class="evcell" style="cursor:text;`;
      const rev = r && r.status_flag === "revisar";
      const revStyle = rev ? "outline:2px solid #f59e0b;outline-offset:-2px;" : "";
      if (!r) return `<td ${meta}text-align:center;color:var(--mut)">·</td>`;
      if (r.tipo_valor === "qualitativo") return `<td ${meta}${revStyle}"><span style="display:inline-block;padding:1px 8px;border-radius:999px;background:#ede9fe;border:1px solid #ddd6fe;font-size:.85em">${safe(r.resultado_txt || "—")}</span></td>`;
      let txt, bg = "";
      if (r.tipo_valor === "censurado") { txt = `${safe(r.operador || "")} ${fmtNum(r.valor_num)}`; bg = "#e9d5ff"; }
      else { txt = fmtNum(r.valor_num); bg = COR[r.status_flag] || ""; }
      const u = r.unidade ? `<span class="mut" style="font-size:.8em"> ${safe(r.unidade)}</span>` : "";
      return `<td ${meta}${bg ? `background:${bg};` : ""}${revStyle}text-align:right;font-variant-numeric:tabular-nums">${txt}${u}</td>`;
    };

    const head = ordemExib.map(ci => {
      const c = coletas[ci];
      const inf = /inferido/i.test(c.laboratorio || "");
      return `<th style="text-align:right;white-space:nowrap">${toBR(c.data)}${inf ? ' <span title="ano inferido na migração — confirmar">⚠</span>' : ""}${req.user?.super_admin ? `<form method="POST" action="/pront/paciente/${id}/coleta/${c.id}/excluir" style="display:inline;margin-left:5px" onsubmit="return confirm('Excluir a coleta de ${toBR(c.data)} e TODOS os resultados dela? Esta ação não pode ser desfeita.')"><button type="submit" title="Excluir esta coluna" style="border:0;background:none;color:#b91c1c;cursor:pointer;padding:0;font-size:.9em">✕</button></form>` : ""}</th>`;
    }).join("");

    const corpo = linhasOrd.map((L, i) => {
      const temSerie = L.celulas.filter(c => c && c.tipo_valor === "numerico").length >= 2;
      const rotulo = `${safe(L.rotulo)}${L.unidade ? ` <span class="mut" style="font-weight:400;font-size:.8em">(${safe(L.unidade)})</span>` : ""}`;
      const clic = temSerie ? ` data-i="${i}" class="evrow"` : "";
      const cels = ordemExib.map(ci => cell(L.celulas[ci], coletas[ci].id, L.canonico, L.rotulo)).join("");
      return `<tr${clic}><th style="text-align:left;white-space:nowrap;${STICKY}">${temSerie ? `<span class="evtrend" data-i="${i}" style="cursor:pointer">📈 </span>` : ""}${rotulo}</th>${cels}</tr>` +
             (temSerie ? `<tr id="chart-${i}" style="display:none"><td colspan="${coletas.length + 1}" style="padding:0"><div class="chart-host" style="padding:8px 4px"></div></td></tr>` : "");
    }).join("");

    // dados p/ o gráfico client-side
    const datas = coletas.map(c => c.data);
    const series = linhasOrd.map(L => ({
      rotulo: L.rotulo, unidade: L.unidade,
      pontos: L.celulas.map((c, ci) => c && c.tipo_valor === "numerico" ? { x: ci, v: c.valor_num, st: c.status_flag || "" }
                                  : c && c.tipo_valor === "censurado" ? { x: ci, v: c.valor_num, op: c.operador, cens: true } : null)
    }));

    res.send(renderShell(`Exames — ${safe(p.nome)}`, `
      <div class="admin-back-top"><a href="/pront/paciente/${id}">← ${safe(p.nome)}</a></div>
      <div class="card">
        <div class="right" style="justify-content:space-between"><h1 style="margin:0">Evolução de exames</h1><div class="mut">${coletas.length} coleta(s)</div></div>
        <div class="mut mt" style="font-size:.85em">Clique numa linha com 📈 para ver a tendência. Cores: <span style="background:#fde68a;padding:0 6px;border-radius:4px">alto</span> <span style="background:#bfdbfe;padding:0 6px;border-radius:4px">baixo</span> <span style="background:#e9d5ff;padding:0 6px;border-radius:4px">censurado</span></div>
        <div style="overflow:auto" class="mt">
          <table style="min-width:600px">
            <thead><tr><th style="text-align:left;${STICKY}z-index:2">Analito</th>${head}</tr></thead>
            <tbody>${corpo}</tbody>
          </table>
        </div>
      </div>
      <script id="evdata" type="application/json">${JSON.stringify({ datas, series }).replace(/</g, "\\u003c")}</script>
      <script>window.__PAC_ID=${id};</script>
      <script>${CHART_JS}</script>
    `));
  });

  // ===== UPLOAD -> FILA =====
  const jsonGrande = express.json({ limit: "25mb" });
  const jsonAudio = express.json({ limit: "50mb" });   // áudio (base64 infla ~33%) — comporta consulta inteira do iPhone

  // form de upload (foto/PDF) a partir do paciente
  app.get("/pront/paciente/:id/upload", authRequired, async (req, res) => {
    const p = (await pool.query(`SELECT id,nome FROM pront_pacientes WHERE id=$1`, [req.params.id])).rows[0];
    if (!p) return res.status(404).send(renderShell("Não encontrado", `<div class="card"><h1>Paciente não encontrado</h1></div>`));
    res.send(renderShell(`Enviar exame — ${safe(p.nome)}`, `
      <div class="admin-back-top"><a href="/pront/paciente/${p.id}">← ${safe(p.nome)}</a></div>
      <div class="card">
        <h1 style="margin-top:0">Enviar exame</h1>
        <p class="mut">Foto ou PDF do laudo. Vai para a fila de leitura; você confere os valores antes de salvar.</p>
        <input type="file" id="arq" accept="image/*,application/pdf" capture="environment"/>
        <div class="mt"><button type="button" id="env">Enviar para a fila</button></div>
        <div id="msg" class="mt mut"></div>
      </div>
      <script>
        const arq=document.getElementById('arq'), msg=document.getElementById('msg'), bt=document.getElementById('env');
        bt.onclick=async()=>{
          const f=arq.files[0]; if(!f){msg.textContent='Escolha um arquivo.';return;}
          if(f.size>24*1024*1024){msg.textContent='Arquivo grande demais (máx 24MB).';return;}
          bt.disabled=true; msg.textContent='Enviando…';
          const b64=await new Promise((ok,er)=>{const r=new FileReader();r.onload=()=>ok(String(r.result).split(',')[1]);r.onerror=er;r.readAsDataURL(f);});
          const r=await fetch(location.pathname,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({data:b64,contentType:f.type,nome:f.name})});
          const j=await r.json().catch(()=>({}));
          if(r.ok&&j.ok){msg.innerHTML='Enviado! Entrou na fila. <a href="/pront/conferencia">Ver fila →</a>';}
          else{bt.disabled=false;msg.textContent='Falha no envio: '+(j.erro||r.status);}
        };
      </script>`));
  });

  app.post("/pront/paciente/:id/upload", authRequired, jsonGrande, async (req, res) => {
    try {
      const { data, contentType, nome } = req.body || {};
      if (!data) return res.status(400).json({ erro: "sem dados" });
      const buffer = Buffer.from(data, "base64");
      if (buffer.length > 25e6) return res.status(413).json({ erro: "arquivo grande demais" });
      const tipo = /pdf/i.test(contentType || "") ? "pdf" : "foto";
      const ext = (nome || "").match(/\.[a-z0-9]+$/i)?.[0] || (tipo === "pdf" ? ".pdf" : ".jpg");
      const r2key = `pront/uploads/${req.params.id}/${Date.now()}_${Math.random().toString(36).slice(2, 8)}${ext}`;
      await uploadToR2(r2key, buffer, contentType || "application/octet-stream");
      const doc = (await pool.query(
        `INSERT INTO pront_documentos(paciente_id,tipo,nome_arquivo,mime,r2_key,tamanho,status,criado_por)
         VALUES($1,$2,$3,$4,$5,$6,'pendente',$7) RETURNING id`,
        [req.params.id, tipo, nome || null, contentType || null, r2key, buffer.length, quem(req)])).rows[0];
      res.json({ ok: true, docId: doc.id });
    } catch (e) { res.status(500).json({ erro: String(e.message || e) }); }
  });

  // ===== IMPORTAR .xlsx DE EXAMES EXTERNOS (planilha longitudinal) =====
  // lê a planilha (SheetJS) -> matriz -> motor importarPlanilha -> prévia -> grava no grid
  async function lerMatrizXlsx(b64) {
    const XLSX = await import("xlsx");
    const wb = XLSX.read(b64, { type: "base64", cellDates: true });
    const ws = wb.Sheets[wb.SheetNames[0]];
    return XLSX.utils.sheet_to_json(ws, { header: 1, raw: true, defval: null });
  }

  app.get("/pront/paciente/:id/exames/importar", authRequired, async (req, res) => {
    const p = (await pool.query(`SELECT id, nome FROM pront_pacientes WHERE id=$1`, [req.params.id])).rows[0];
    if (!p) return res.status(404).send(renderShell("Não encontrado", `<div class="card"><h1>Paciente não encontrado</h1></div>`));
    const id = p.id;
    res.send(renderShell("Importar exames", `
      <div class="admin-back-top"><a href="/pront/paciente/${id}">← Ficha de ${safe(p.nome)}</a></div>
      <div class="card">
        <h1 style="margin-top:0">Importar exames (.xlsx)</h1>
        <p class="mut">Planilha longitudinal (datas nas colunas, exames nas linhas). Os resultados limpos vão direto pro grid; os duvidosos entram marcados como <b>revisar</b>.</p>
        <input type="file" id="f" accept=".xlsx,.xls" />
        <div id="msg" class="mut mt"></div>
        <div id="previa"></div>
      </div>
      <script>
        var pac=${id}, b64="";
        var f=document.getElementById("f"), msg=document.getElementById("msg"), previa=document.getElementById("previa");
        f.addEventListener("change", async function(){
          var file=f.files[0]; if(!file) return;
          msg.textContent="Lendo planilha…"; previa.innerHTML="";
          b64=await new Promise(function(ok,er){var r=new FileReader();r.onload=function(){ok(String(r.result).split(",")[1]);};r.onerror=er;r.readAsDataURL(file);});
          try{
            var r=await fetch("/pront/paciente/"+pac+"/exames/importar/previa",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({b64:b64})});
            var j=await r.json();
            if(!j.ok){msg.textContent="Falha: "+(j.erro||r.status);return;}
            msg.textContent="";
            var alerta = j.mismatchPaciente ? '<div class="card" style="border-color:#b45309;background:#fffbeb"><b>Atenção:</b> a planilha diz <b>'+j.paciente+'</b>, mas a ficha é de outro paciente. Confira antes de gravar.</div>' : '';
            var marc = j.marcados.map(function(m){return '<tr><td>'+m.data+'</td><td>'+m.rotulo+'</td><td>'+m.resultado_txt+'</td><td class="mut">'+m.motivos.join("; ")+'</td></tr>';}).join("");
            previa.innerHTML = alerta +
              '<div class="mt"><b>Paciente da planilha:</b> '+(j.paciente||"—")+' · <b>DN:</b> '+(j.dn||"—")+'</div>'+
              '<div class="mut">Datas: '+j.datas.join(", ")+'</div>'+
              '<div class="mt2"><b style="color:#0e7a4b">'+j.limposCount+'</b> resultados limpos (gravam direto) · <b style="color:#b45309">'+j.marcados.length+'</b> marcados pra revisar</div>'+
              (marc?'<table class="mt"><thead><tr><th>Data</th><th>Exame</th><th>Valor</th><th>Motivo</th></tr></thead><tbody>'+marc+'</tbody></table>':'')+
              (j.naoMapeados.length?'<div class="mut mt">Não reconhecidos (entram como "outros"): '+j.naoMapeados.join(", ")+'</div>':'')+
              '<div class="mt2"><button id="go" type="button" style="background:#0e9f6e">Confirmar e gravar no grid</button></div>';
            document.getElementById("go").addEventListener("click", async function(){
              this.disabled=true; msg.textContent="Gravando…";
              var rg=await fetch("/pront/paciente/"+pac+"/exames/importar/gravar",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({b64:b64})});
              var jg=await rg.json();
              if(rg.ok&&jg.ok){location.href="/pront/paciente/"+pac+"/exames";}
              else{msg.textContent="Falha ao gravar: "+(jg.erro||rg.status); document.getElementById("go").disabled=false;}
            });
          }catch(e){msg.textContent="Erro: "+e.message;}
        });
      </script>
    `));
  });

  app.post("/pront/paciente/:id/exames/importar/previa", authRequired, jsonGrande, async (req, res) => {
    try {
      const p = (await pool.query(`SELECT nome, to_char(dn,'YYYY-MM-DD') dn FROM pront_pacientes WHERE id=$1`, [req.params.id])).rows[0];
      if (!p) return res.status(404).json({ ok: false, erro: "paciente não encontrado" });
      const rows = await lerMatrizXlsx(req.body?.b64 || "");
      const prev = preverImportacao(rows);
      const mismatchPaciente = !!(prev.paciente && p.nome && semAcento(prev.paciente) !== semAcento(p.nome));
      res.json({
        ok: true, paciente: prev.paciente, dn: prev.dn, datas: prev.datas,
        limposCount: prev.limpos.length,
        marcados: prev.marcados.map(m => ({ data: m.data, rotulo: m.rotulo || m.nome_original, resultado_txt: m.resultado_txt, motivos: m.motivos })),
        naoMapeados: prev.naoMapeados, mismatchPaciente,
      });
    } catch (e) { res.status(500).json({ ok: false, erro: String(e.message || e) }); }
  });

  app.post("/pront/paciente/:id/exames/importar/gravar", authRequired, jsonGrande, async (req, res) => {
    try {
      const p = (await pool.query(`SELECT id FROM pront_pacientes WHERE id=$1`, [req.params.id])).rows[0];
      if (!p) return res.status(404).json({ ok: false, erro: "paciente não encontrado" });
      const rows = await lerMatrizXlsx(req.body?.b64 || "");
      const prev = preverImportacao(rows);
      const stats = await gravarTudo(pool, p.id, prev, quem(req));
      res.json({ ok: true, ...stats });
    } catch (e) { res.status(500).json({ ok: false, erro: String(e.message || e) }); }
  });

  // edição inline de uma célula do grid: re-tipa o valor, cria/atualiza, e limpa flag 'revisar'
  // exclui uma coleta inteira (uma coluna da grid). pront_resultados cai por ON DELETE CASCADE. Restrito ao médico.
  app.post("/pront/paciente/:id/coleta/:coletaId/excluir", medicoRequired, async (req, res) => {
    try {
      await pool.query(`DELETE FROM pront_coletas WHERE id=$1 AND paciente_id=$2`, [req.params.coletaId, req.params.id]);
      res.redirect(`/pront/paciente/${req.params.id}/exames`);
    } catch (e) {
      console.error("EXCLUIR COLETA ERROR", e);
      res.status(500).send("Falha ao excluir a coleta");
    }
  });

  app.post("/pront/paciente/:id/exames/resultado/editar", authRequired, jsonGrande, async (req, res) => {
    try {
      const { coleta_id, canonico, rotulo, valor } = req.body || {};
      if (!coleta_id) return res.status(400).json({ ok: false, erro: "coleta ausente" });
      // garante que a coleta é deste paciente
      const col = (await pool.query(`SELECT id FROM pront_coletas WHERE id=$1 AND paciente_id=$2`, [coleta_id, req.params.id])).rows[0];
      if (!col) return res.status(404).json({ ok: false, erro: "coleta não encontrada" });

      const v = parseValue(valor);                 // re-tipa: numerico | censurado | qualitativo | texto | vazio
      const valor_num = (v.tipo_valor === "numerico" || v.tipo_valor === "censurado") ? (v.valor ?? null) : null;
      const status = null;                          // edição manual = já revisado; sem flag automática
      const resultado_txt = (v.tipo_valor === "qualitativo" || v.tipo_valor === "texto") ? (v.texto || v.resultado || null) : (v.texto || null);

      // localiza a linha existente (por canônico, ou por rótulo quando "outros")
      const cond = canonico ? `canonico=$2` : `canonico IS NULL AND rotulo=$2`;
      const arg = canonico || rotulo;
      const existente = (await pool.query(
        `SELECT id FROM pront_resultados WHERE coleta_id=$1 AND ${cond} LIMIT 1`, [coleta_id, arg])).rows[0];

      if ((valor == null || String(valor).trim() === "") && existente) {
        // valor apagado -> remove a célula
        await pool.query(`DELETE FROM pront_resultados WHERE id=$1`, [existente.id]);
        return res.json({ ok: true, removido: true });
      }

      if (existente) {
        await pool.query(
          `UPDATE pront_resultados SET tipo_valor=$1, valor_num=$2, operador=$3, unidade=$4, resultado_txt=$5, status_flag=$6
             WHERE id=$7`,
          [v.tipo_valor, valor_num, v.operador || null, v.unidade || null, resultado_txt, status, existente.id]);
      } else {
        await pool.query(
          `INSERT INTO pront_resultados (coleta_id, canonico, rotulo, nome_original, tipo_valor, valor_num, operador, unidade, resultado_txt, status_flag)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          [coleta_id, canonico || null, rotulo || null, rotulo || null, v.tipo_valor, valor_num, v.operador || null, v.unidade || null, resultado_txt, status]);
      }
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ ok: false, erro: String(e.message || e) }); }
  });

  // serve o arquivo do R2 (imagem/pdf) para a conferência
  app.get("/pront/documento/:id/arquivo", authRequired, async (req, res) => {
    const d = (await pool.query(`SELECT r2_key, mime FROM pront_documentos WHERE id=$1`, [req.params.id])).rows[0];
    if (!d) return res.status(404).send("não encontrado");
    try {
      const r = await fetchR2Stream(d.r2_key);
      res.setHeader("Content-Type", d.mime || r.headers.get("content-type") || "application/octet-stream");
      res.setHeader("Cache-Control", "private, max-age=600");
      res.send(Buffer.from(await r.arrayBuffer()));
    } catch (e) { res.status(502).send("erro ao buscar arquivo"); }
  });

  // ===== FILA / CONFERÊNCIA =====
  app.get("/pront/conferencia", authRequired, async (req, res) => {
    const docs = (await pool.query(
      `SELECT d.id, d.tipo, d.nome_arquivo, d.status, d.tentativas, d.erro, d.criado_em,
              to_char(d.data_coleta_sugerida,'YYYY-MM-DD') data_sug,
              jsonb_array_length(COALESCE(d.extraido_json->'analitos','[]'::jsonb)) nanalitos,
              p.id pid, p.nome
         FROM pront_documentos d LEFT JOIN pront_pacientes p ON p.id=d.paciente_id
        WHERE d.status IN ('extraido','pendente','processando','erro')
        ORDER BY (d.status='extraido') DESC, d.criado_em`)).rows;
    const badge = s => ({ extraido: '<span style="background:#fef3c7;color:#92400e;padding:1px 8px;border-radius:999px">conferir</span>',
      pendente: '<span class="mut">na fila…</span>', processando: '<span class="mut">lendo…</span>',
      erro: '<span style="background:#fee2e2;color:#991b1b;padding:1px 8px;border-radius:999px">erro</span>' }[s] || s);
    const linhas = docs.map(d => `
      <tr>
        <td>${d.status === "extraido" ? `<a href="/pront/conferencia/${d.id}">${safe(d.nome_arquivo || d.tipo)}</a>` : safe(d.nome_arquivo || d.tipo)}</td>
        <td>${d.nome ? `<a href="/pront/paciente/${d.pid}">${safe(d.nome)}</a>` : '<span class="mut">—</span>'}</td>
        <td>${badge(d.status)}${d.status === "erro" && d.erro ? `<div class="mut" style="font-size:.8em">${safe(d.erro)}</div>` : ""}</td>
        <td>${d.status === "extraido" ? d.nanalitos : "—"}</td>
      </tr>`).join("");
    res.send(renderShell("Conferência", `
      <div class="admin-back-top"><a href="/pront">← Prontuário</a></div>
      <div class="card">
        <h1 style="margin-top:0">Fila de conferência</h1>
        <p class="mut">Documentos lidos pela máquina. Nada vira coleta sem você confirmar.</p>
        <table class="mt">
          <thead><tr><th>Arquivo</th><th>Paciente</th><th>Situação</th><th>Analitos</th></tr></thead>
          <tbody>${linhas || `<tr><td colspan="4" class="mut">Fila vazia.</td></tr>`}</tbody>
        </table>
      </div>`));
  });

  // tela de conferência de um documento
  app.get("/pront/conferencia/:docId", authRequired, async (req, res) => {
    const d = (await pool.query(`SELECT * FROM pront_documentos WHERE id=$1`, [req.params.docId])).rows[0];
    if (!d) return res.status(404).send(renderShell("Não encontrado", `<div class="card"><h1>Documento não encontrado</h1></div>`));
    const ex = d.extraido_json || {};

    // --- conferência de ÁUDIO: rascunho de consulta para revisar e salvar ---
    if (d.tipo === "audio") {
      const pacs = (await pool.query(`SELECT id, nome FROM pront_pacientes ORDER BY lower(nome)`)).rows;
      const optP = pacs.map(p => `<option value="${p.id}" ${String(p.id) === String(d.paciente_id) ? "selected" : ""}>${safe(p.nome)}</option>`).join("");
      const avisos = (ex.avisos || []).map(a => `<div class="mut" style="font-size:.85em">⚠ ${safe(a)}</div>`).join("");
      const dataSug = (ex.data_sugerida || d.data_coleta_sugerida || new Date().toISOString().slice(0,10)).toString().slice(0,10);
      return res.send(renderShell("Conferência da consulta", `
        <div class="admin-back-top"><a href="/pront/conferencia">← Fila</a></div>
        <div class="card" style="border-left:4px solid #d97706">
          <b>Rascunho gerado por transcrição.</b> <span class="mut">Modo: ${safe(d.modo || "resumo")}. Revise e corrija — a transcrição pode errar nomes de medicação e termos. Só vira consulta quando você salvar.</span>
          ${avisos}
        </div>
        <div class="card mt">
          <div class="row" style="grid-template-columns:1fr 1fr">
            <div><label>Paciente</label><select id="pac">${optP || '<option value="">—</option>'}</select></div>
            <div><label>Data da consulta</label><input id="data" type="date" value="${safe(dataSug)}"/></div>
          </div>
          <label class="mt">Evolução (rascunho)</label>
          <div class="mut" style="font-size:.82em;margin-bottom:4px">Edite à vontade. <code>##</code> título, <code>#</code> tópico, <code>-</code> itens.</div>
          <div class="row" style="grid-template-columns:1fr 1fr;align-items:start">
            <textarea id="txt" rows="16">${safe(ex.texto || "")}</textarea>
            <div class="card" style="background:#fbfcfd"><div class="mut" style="font-size:.8em;margin-bottom:6px">pré-visualização</div><div id="prev" style="line-height:1.5"></div></div>
          </div>
          <details class="mt"><summary class="mut" style="cursor:pointer">Ver transcrição bruta</summary>
            <div class="mut mt" style="white-space:pre-wrap;font-size:.85em;border:1px solid var(--bd);border-radius:8px;padding:10px;max-height:240px;overflow:auto">${safe(d.transcricao || ex.transcript || "(sem transcrição)")}</div>
          </details>
          <div class="right mt2" style="justify-content:space-between">
            <form class="inline" method="post" action="/pront/conferencia/${d.id}/descartar"><button type="submit" style="background:#9aa3af">Descartar</button></form>
            <button type="button" id="salvar">Salvar consulta</button>
          </div>
          <div id="msg" class="mut mt"></div>
        </div>
        <script>
          const txt=document.getElementById('txt'),prev=document.getElementById('prev'),msg=document.getElementById('msg');
          const esc=s=>s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
          function render(t){let o='',li=false;const fl=()=>{if(li){o+='</ul>';li=false;}};
            for(const raw of (t||'').split(/\\n/)){const l=raw.trim();
              if(!l){fl();o+='<div style="height:6px"></div>';continue;}
              if(/^##\\s*/.test(l)){fl();o+='<div style="font-weight:700;font-size:1.05em;margin:8px 0 2px">'+esc(l.replace(/^##\\s*/,''))+'</div>';}
              else if(/^#\\s*/.test(l)){fl();o+='<div style="font-weight:600;color:#0c447c;margin:6px 0 2px">'+esc(l.replace(/^#\\s*/,''))+'</div>';}
              else if(/^[-•]\\s*/.test(l)){if(!li){o+='<ul style="margin:2px 0 2px 18px">';li=true;}o+='<li>'+esc(l.replace(/^[-•]\\s*/,''))+'</li>';}
              else{fl();o+='<div>'+esc(l)+'</div>';}}
            fl();return o;}
          const upd=()=>prev.innerHTML=render(txt.value);txt.addEventListener('input',upd);upd();
          document.getElementById('salvar').onclick=async()=>{
            const pac=document.getElementById('pac').value,data=document.getElementById('data').value,texto=txt.value.trim();
            if(!pac){msg.textContent='Selecione o paciente.';return;}
            if(!texto){msg.textContent='O rascunho está vazio.';return;}
            msg.textContent='Salvando…';
            const r=await fetch('/pront/conferencia/${d.id}/confirmar-consulta',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paciente_id:+pac,data,texto})});
            const j=await r.json().catch(()=>({}));
            if(r.ok&&j.ok){location.href='/pront/paciente/'+pac;}else{msg.textContent='Falha: '+(j.erro||r.status);}
          };
        </script>`));
    }

    const analitos = Array.isArray(ex.analitos) ? ex.analitos : [];
    const pacientes = (await pool.query(`SELECT id, nome FROM pront_pacientes ORDER BY lower(nome)`)).rows;
    const optPac = pacientes.map(p => `<option value="${p.id}" ${String(p.id) === String(d.paciente_id) ? "selected" : ""}>${safe(p.nome)}</option>`).join("");

    const valFmt = a => a.tipo_valor === "qualitativo" ? (a.resultado || a.texto || "")
      : a.tipo_valor === "censurado" ? `${a.operador || ""} ${a.valor ?? ""}`.trim()
      : (a.valor ?? "");
    const rows = analitos.map((a, i) => `
      <tr data-i="${i}">
        <td style="text-align:center"><input type="checkbox" class="inc" checked style="width:auto"/></td>
        <td>${safe(a.rotulo || a.nome_original || a.canonico || "—")}${a.canonico ? "" : ' <span class="mut" title="não mapeado — guardado sem tendência">(outros)</span>'}</td>
        <td><input class="val" value="${safe(String(valFmt(a)))}" style="padding:6px"/></td>
        <td class="mut">${safe(a.unidade || "")}</td>
        <td>${a.status ? `<span class="mut">${safe(a.status)}</span>` : ""}</td>
      </tr>`).join("");

    const preview = d.tipo === "pdf"
      ? `<iframe src="/pront/documento/${d.id}/arquivo" style="width:100%;height:560px;border:1px solid var(--bd);border-radius:10px"></iframe>`
      : `<img src="/pront/documento/${d.id}/arquivo" style="max-width:100%;border:1px solid var(--bd);border-radius:10px"/>`;

    res.send(renderShell("Conferência do documento", `
      <div class="admin-back-top"><a href="/pront/conferencia">← Fila</a></div>
      <div class="card" style="border-left:4px solid #d97706">
        <b>Confira antes de salvar.</b> <span class="mut">Os valores foram lidos por máquina — corrija o que precisar. Só viram registro quando você confirmar.</span>
      </div>
      <div class="row mt" style="grid-template-columns:1fr 1fr;align-items:start">
        <div class="card">${preview}</div>
        <div class="card">
          <label>Paciente</label>
          <select id="pac">${optPac || '<option value="">—</option>'}</select>
          <div class="row mt" style="grid-template-columns:1fr 1fr">
            <div><label>Data da coleta</label><input id="data" type="date" value="${safe((ex.data_coleta || d.data_coleta_sugerida || "").toString().slice(0,10))}"/></div>
            <div><label>Laboratório</label><input id="lab" value="${safe(ex.laboratorio || "")}"/></div>
          </div>
          ${ex.paciente ? `<div class="mut mt" style="font-size:.85em">Nome lido no laudo: ${safe(ex.paciente)}</div>` : ""}
          <table class="mt">
            <thead><tr><th></th><th>Analito</th><th>Valor</th><th>Un.</th><th>Status</th></tr></thead>
            <tbody id="tb">${rows || `<tr><td colspan="5" class="mut">Nenhum analito extraído.</td></tr>`}</tbody>
          </table>
          <div class="right mt2" style="justify-content:space-between">
            <form class="inline" method="post" action="/pront/conferencia/${d.id}/descartar"><button type="submit" style="background:#9aa3af">Descartar</button></form>
            <button type="button" id="salvar">Confirmar e salvar</button>
          </div>
          <div id="msg" class="mut mt"></div>
        </div>
      </div>
      <script id="exraw" type="application/json">${JSON.stringify(analitos).replace(/</g, "\\u003c")}</script>
      <script>
        const raw=JSON.parse(document.getElementById('exraw').textContent);
        document.getElementById('salvar').onclick=async()=>{
          const data=document.getElementById('data').value, pac=document.getElementById('pac').value, lab=document.getElementById('lab').value;
          if(!pac){msg.textContent='Selecione o paciente.';return;}
          if(!data){msg.textContent='Informe a data da coleta.';return;}
          const trs=[...document.querySelectorAll('#tb tr[data-i]')];
          const analitos=trs.map(tr=>{const i=+tr.dataset.i;const a={...raw[i]};
            a.incluir=tr.querySelector('.inc').checked; const v=tr.querySelector('.val').value.trim();
            if(a.tipo_valor==='qualitativo'||a.tipo_valor==='texto'){a.resultado=v;}
            else{const mm=v.match(/-?[\\d.,]+/);let s=mm?mm[0]:'';const hc=s.includes(','),hd=s.includes('.');if(hc&&hd)s=s.replace(/\\./g,'').replace(',','.');else if(hc)s=s.replace(',','.');else if(hd){const af=s.split('.').pop();if(af.length===3)s=s.replace(/\\./g,'');}const n=parseFloat(s);a.valor=Number.isFinite(n)?n:a.valor;}
            return a;}).filter(a=>a.incluir);
          msg.textContent='Salvando…';
          const r=await fetch('/pront/conferencia/${d.id}/confirmar',{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({paciente_id:+pac,data_coleta:data,laboratorio:lab,analitos})});
          const j=await r.json().catch(()=>({}));
          if(r.ok&&j.ok){location.href='/pront/paciente/'+pac+'/exames';}else{msg.textContent='Falha: '+(j.erro||r.status);}
        };
      </script>`));
  });

  app.post("/pront/conferencia/:docId/confirmar", authRequired, jsonGrande, async (req, res) => {
    try {
      const { paciente_id, data_coleta, laboratorio, analitos } = req.body || {};
      if (!paciente_id || !data_coleta) return res.status(400).json({ erro: "paciente e data são obrigatórios" });
      const d = (await pool.query(`SELECT id FROM pront_documentos WHERE id=$1`, [req.params.docId])).rows[0];
      if (!d) return res.status(404).json({ erro: "documento não encontrado" });
      const c = (await pool.query(
        `INSERT INTO pront_coletas(paciente_id,data_coleta,laboratorio,fonte,documento_id,criado_por)
         VALUES($1,$2::date,$3,$4,$5,$6)
         ON CONFLICT (paciente_id,data_coleta,laboratorio) DO UPDATE SET documento_id=EXCLUDED.documento_id RETURNING id`,
        [paciente_id, data_coleta, laboratorio || null, "ocr", req.params.docId, quem(req)])).rows[0];
      for (const a of (analitos || [])) {
        const qual = a.tipo_valor === "qualitativo" || a.tipo_valor === "texto";
        await pool.query(
          `INSERT INTO pront_resultados(coleta_id,canonico,rotulo,nome_original,tipo_valor,valor_num,operador,unidade,resultado_txt,status_flag)
           VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          [c.id, a.canonico || null, a.rotulo || null, a.nome_original || null, a.tipo_valor || null,
           qual ? null : (a.valor ?? null), a.operador || null, a.unidade || null,
           qual ? (a.resultado || a.texto || null) : null, a.status || null]);
      }
      await pool.query(`UPDATE pront_documentos SET status='confirmado', paciente_id=$2, processado_em=now() WHERE id=$1`, [req.params.docId, paciente_id]);
      res.json({ ok: true, coletaId: c.id });
    } catch (e) { res.status(500).json({ erro: String(e.message || e) }); }
  });

  app.post("/pront/conferencia/:docId/descartar", authRequired, async (req, res) => {
    await pool.query(`UPDATE pront_documentos SET status='descartado', processado_em=now() WHERE id=$1`, [req.params.docId]);
    res.redirect("/pront/conferencia");
  });

  // confirmar rascunho de consulta (áudio) -> pront_consultas
  app.post("/pront/conferencia/:docId/confirmar-consulta", authRequired, jsonGrande, async (req, res) => {
    try {
      const { paciente_id, data, texto } = req.body || {};
      if (!paciente_id || !texto || !texto.trim()) return res.status(400).json({ erro: "paciente e texto são obrigatórios" });
      const doc = (await pool.query(`SELECT transcricao FROM pront_documentos WHERE id=$1`, [req.params.docId])).rows[0];
      const transcricao = (doc && doc.transcricao) ? doc.transcricao : null;   // anexa a transcrição bruta do áudio à consulta
      const c = (await pool.query(
        `INSERT INTO pront_consultas(paciente_id,data,texto,criado_por,transcricao) VALUES($1,COALESCE(NULLIF($2,'')::date,current_date),$3,$4,$5) RETURNING id`,
        [paciente_id, data || "", texto.trim(), quem(req), transcricao])).rows[0];
      await pool.query(`UPDATE pront_documentos SET status='confirmado', paciente_id=$2, processado_em=now() WHERE id=$1`, [req.params.docId, paciente_id]);
      res.json({ ok: true, consultaId: c.id });
    } catch (e) { res.status(500).json({ erro: String(e.message || e) }); }
  });

  // ===== ÁUDIO DA CONSULTA: envio -> fila =====
  app.get("/pront/paciente/:id/consulta/audio", medicoRequired, async (req, res) => {
    const p = (await pool.query(`SELECT id,nome FROM pront_pacientes WHERE id=$1`, [req.params.id])).rows[0];
    if (!p) return res.status(404).send(renderShell("Não encontrado", `<div class="card"><h1>Paciente não encontrado</h1></div>`));
    res.send(renderShell(`Áudio da consulta — ${safe(p.nome)}`, `
      <div class="admin-back-top"><a href="/pront/paciente/${p.id}">← ${safe(p.nome)}</a></div>
      <div class="card">
        <h1 style="margin-top:0">Áudio da consulta</h1>
        <p class="mut">Envie o áudio da consulta — serve o Gravador de Voz do iPhone (.m4a), o PlaudNote, ou WAV/MP3. A transcrição roda na máquina da clínica — o áudio não vai pra nuvem. Vira um rascunho que você revisa antes de salvar.</p>
        <label>Modo</label>
        <div class="row" style="grid-template-columns:1fr 1fr">
          <label style="font-weight:400;border:1px solid var(--bd);border-radius:10px;padding:10px;cursor:pointer"><input type="radio" name="modo" value="resumo" checked style="width:auto"/> <b>Resumo ditado</b><div class="mut" style="font-size:.85em">você narra o resumo; uma voz</div></label>
          <label style="font-weight:400;border:1px solid var(--bd);border-radius:10px;padding:10px;cursor:pointer"><input type="radio" name="modo" value="consulta" style="width:auto"/> <b>Consulta inteira</b><div class="mut" style="font-size:.85em">médico + paciente</div></label>
        </div>
        <label class="mt" id="diarwrap" style="display:none"><input type="checkbox" id="diar" style="width:auto"/> Tentar separar quem falou (diarização)</label>
        <label class="mt">Arquivo de áudio</label>
        <input type="file" id="arq" accept="audio/*,.m4a,.mp3,.wav,.aac,.caf"/>
        <div class="mt"><button type="button" id="env">Enviar para transcrição</button></div>
        <div id="msg" class="mt mut"></div>
      </div>
      <script>
        const diarwrap=document.getElementById('diarwrap');
        document.querySelectorAll('input[name=modo]').forEach(r=>r.addEventListener('change',()=>{diarwrap.style.display=(document.querySelector('input[name=modo]:checked').value==='consulta')?'block':'none';}));
        const arq=document.getElementById('arq'),msg=document.getElementById('msg'),bt=document.getElementById('env');
        bt.onclick=async()=>{
          const f=arq.files[0]; if(!f){msg.textContent='Escolha um arquivo de áudio.';return;}
          if(f.size>35*1024*1024){msg.textContent='Arquivo grande demais (máx 35 MB). Grave em qualidade "Comprimida" no iPhone, exporte em MP3, ou divida o áudio.';return;}
          bt.disabled=true; msg.textContent='Enviando…';
          const b64=await new Promise((ok,er)=>{const r=new FileReader();r.onload=()=>ok(String(r.result).split(',')[1]);r.onerror=er;r.readAsDataURL(f);});
          const modo=document.querySelector('input[name=modo]:checked').value;
          const diarizar=modo==='consulta'&&document.getElementById('diar').checked;
          const r=await fetch(location.pathname,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({data:b64,contentType:f.type,nome:f.name,modo,diarizar})});
          const j=await r.json().catch(()=>({}));
          if(r.ok&&j.ok){msg.innerHTML='Enviado! Entrou na fila de transcrição. <a href="/pront/conferencia">Ver fila →</a>';}
          else{bt.disabled=false;msg.textContent='Falha: '+(j.erro||r.status);}
        };
      </script>`));
  });

  app.post("/pront/paciente/:id/consulta/audio", medicoRequired, jsonAudio, async (req, res) => {
    try {
      const { data, contentType, nome, modo, diarizar } = req.body || {};
      if (!data) return res.status(400).json({ erro: "sem dados" });
      const buffer = Buffer.from(data, "base64");
      if (buffer.length > 38e6) return res.status(413).json({ erro: "arquivo grande demais" });
      const ext = (nome || "").match(/\.[a-z0-9]+$/i)?.[0] || ".m4a";
      const r2key = `pront/audio/${req.params.id}/${Date.now()}_${Math.random().toString(36).slice(2, 8)}${ext}`;
      await uploadToR2(r2key, buffer, contentType || "application/octet-stream");
      const doc = (await pool.query(
        `INSERT INTO pront_documentos(paciente_id,tipo,nome_arquivo,mime,r2_key,tamanho,status,modo,diarizar,criado_por)
         VALUES($1,'audio',$2,$3,$4,$5,'pendente',$6,$7,$8) RETURNING id`,
        [req.params.id, nome || null, contentType || null, r2key, buffer.length,
         modo === "consulta" ? "consulta" : "resumo", !!diarizar, quem(req)])).rows[0];
      res.json({ ok: true, docId: doc.id });
    } catch (e) { res.status(500).json({ erro: String(e.message || e) }); }
  });

  // ===== PORTAL DE CONSULTAS: cadastro, nova consulta, edição =====

  // formulário reutilizável de paciente
  const formPaciente = (p = {}, action, titulo) => `
    <div class="card">
      <h1 style="margin-top:0">${titulo}</h1>
      <form method="post" action="${action}">
        <label>Nome *</label>
        <input name="nome" required value="${safe(p.nome || "")}" autofocus/>
        <div class="row mt">
          <div><label>Nascimento</label><input name="dn" type="date" value="${safe((p.dn || "").toString().slice(0,10))}"/></div>
          <div><label>Sexo</label>
            <select name="sexo">
              <option value="">—</option>
              <option value="M" ${p.sexo === "M" ? "selected" : ""}>Masculino</option>
              <option value="F" ${p.sexo === "F" ? "selected" : ""}>Feminino</option>
            </select>
          </div>
        </div>
        <div class="row mt">
          <div><label>CPF</label><input name="cpf" value="${safe(p.cpf || "")}"/></div>
          <div><label>Telefone</label><input name="telefone" value="${safe(p.telefone || "")}"/></div>
        </div>
        <label class="mt">Endereço</label>
        <input name="endereco" value="${safe(p.endereco || "")}" placeholder="Rua, nº, bairro, cidade"/>
        <label class="mt">Observações</label>
        <textarea name="obs" rows="3">${safe(p.obs || "")}</textarea>
        <div class="mt2"><button type="submit">Salvar</button></div>
      </form>
    </div>`;

  // novo paciente
  app.get("/pront/novo", authRequired, (req, res) =>
    res.send(renderShell("Novo paciente", `<div class="admin-back-top"><a href="/pront">← Prontuário</a></div>${formPaciente({}, "/pront/novo", "Novo paciente")}`)));

  app.post("/pront/novo", authRequired, async (req, res) => {
    const { nome, dn, sexo, cpf, telefone, endereco, obs } = req.body || {};
    if (!nome || !nome.trim()) return res.send(renderShell("Novo paciente", `<div class="card"><p>Nome é obrigatório.</p><a href="/pront/novo">Voltar</a></div>`));
    const r = (await pool.query(
      `INSERT INTO pront_pacientes(nome,dn,sexo,cpf,telefone,endereco,obs,criado_por) VALUES($1,NULLIF($2,'')::date,NULLIF($3,''),NULLIF($4,''),NULLIF($5,''),NULLIF($6,''),NULLIF($7,''),$8) RETURNING id`,
      [nome.trim(), dn || "", sexo || "", cpf || "", telefone || "", endereco || "", obs || "", quem(req)])).rows[0];
    res.redirect(`/pront/paciente/${r.id}`);
  });

  // editar paciente
  app.get("/pront/paciente/:id/editar", authRequired, async (req, res) => {
    const p = (await pool.query(`SELECT * FROM pront_pacientes WHERE id=$1`, [req.params.id])).rows[0];
    if (!p) return res.status(404).send(renderShell("Não encontrado", `<div class="card"><h1>Paciente não encontrado</h1></div>`));
    res.send(renderShell(`Editar — ${safe(p.nome)}`, `<div class="admin-back-top"><a href="/pront/paciente/${p.id}">← ${safe(p.nome)}</a></div>${formPaciente(p, `/pront/paciente/${p.id}/editar`, "Editar paciente")}`));
  });

  app.post("/pront/paciente/:id/editar", authRequired, async (req, res) => {
    const { nome, dn, sexo, cpf, telefone, endereco, obs } = req.body || {};
    if (!nome || !nome.trim()) return res.redirect(`/pront/paciente/${req.params.id}/editar`);
    await pool.query(
      `UPDATE pront_pacientes SET nome=$2, dn=NULLIF($3,'')::date, sexo=NULLIF($4,''), cpf=NULLIF($5,''), telefone=NULLIF($6,''), endereco=NULLIF($7,''), obs=NULLIF($8,''), atualizado_em=now() WHERE id=$1`,
      [req.params.id, nome.trim(), dn || "", sexo || "", cpf || "", telefone || "", endereco || "", obs || ""]);
    res.redirect(`/pront/paciente/${req.params.id}`);
  });

  // formulário reutilizável de consulta (com preview ao vivo)
  const formConsulta = (pid, c, action, titulo) => `
    <div class="card">
      <h1 style="margin-top:0">${titulo}</h1>
      <form method="post" action="${action}">
        <div style="max-width:200px"><label>Data</label><input name="data" type="date" value="${safe((c?.data || new Date().toISOString().slice(0,10)).toString().slice(0,10))}"/></div>
        <label class="mt">Evolução</label>
        <div class="mut" style="font-size:.82em;margin-bottom:4px">Use <code>##</code> para título, <code>#</code> para tópico, <code>-</code> para itens.</div>
        <div class="row" style="grid-template-columns:1fr 1fr;align-items:start">
          <textarea name="texto" id="txt" rows="16" placeholder="## Caso novo&#10;&#10;# História&#10;- ...">${safe(c?.texto || "")}</textarea>
          <div class="card" style="background:#fbfcfd;min-height:120px"><div class="mut" style="font-size:.8em;margin-bottom:6px">pré-visualização</div><div id="prev" style="line-height:1.5"></div></div>
        </div>
        <div class="mt2"><button type="submit">Salvar consulta</button></div>
      </form>
    </div>
    <script>
      const txt=document.getElementById('txt'), prev=document.getElementById('prev');
      const esc=s=>s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      function render(t){let out='',lista=false;const fl=()=>{if(lista){out+='</ul>';lista=false;}};
        for(const raw of (t||'').split(/\\n/)){const l=raw.trim();
          if(!l){fl();out+='<div style="height:6px"></div>';continue;}
          if(/^##\\s*/.test(l)){fl();out+='<div style="font-weight:700;font-size:1.05em;margin:8px 0 2px">'+esc(l.replace(/^##\\s*/,''))+'</div>';}
          else if(/^#\\s*/.test(l)){fl();out+='<div style="font-weight:600;color:#0c447c;margin:6px 0 2px">'+esc(l.replace(/^#\\s*/,''))+'</div>';}
          else if(/^[-•]\\s*/.test(l)){if(!lista){out+='<ul style="margin:2px 0 2px 18px">';lista=true;}out+='<li>'+esc(l.replace(/^[-•]\\s*/,''))+'</li>';}
          else{fl();out+='<div>'+esc(l)+'</div>';}}
        fl();return out;}
      const upd=()=>prev.innerHTML=render(txt.value); txt.addEventListener('input',upd); upd();
    </script>`;

  // nova consulta
  app.get("/pront/paciente/:id/consulta/nova", authRequired, async (req, res) => {
    const p = (await pool.query(`SELECT id,nome FROM pront_pacientes WHERE id=$1`, [req.params.id])).rows[0];
    if (!p) return res.status(404).send(renderShell("Não encontrado", `<div class="card"><h1>Paciente não encontrado</h1></div>`));
    res.send(renderShell(`Nova consulta — ${safe(p.nome)}`, `<div class="admin-back-top"><a href="/pront/paciente/${p.id}">← ${safe(p.nome)}</a></div>${formConsulta(p.id, null, `/pront/paciente/${p.id}/consulta/nova`, "Nova consulta")}`));
  });

  app.post("/pront/paciente/:id/consulta/nova", authRequired, async (req, res) => {
    const { data, texto } = req.body || {};
    if (!texto || !texto.trim()) return res.redirect(`/pront/paciente/${req.params.id}/consulta/nova`);
    await pool.query(`INSERT INTO pront_consultas(paciente_id,data,texto,criado_por) VALUES($1,COALESCE(NULLIF($2,'')::date,current_date),$3,$4)`,
      [req.params.id, data || "", texto.trim(), quem(req)]);
    res.redirect(`/pront/paciente/${req.params.id}`);
  });

  // editar consulta
  app.get("/pront/paciente/:id/consulta/:cid/editar", medicoRequired, async (req, res) => {
    const c = (await pool.query(`SELECT id, to_char(data,'YYYY-MM-DD') data, texto FROM pront_consultas WHERE id=$1 AND paciente_id=$2`, [req.params.cid, req.params.id])).rows[0];
    if (!c) return res.status(404).send(renderShell("Não encontrado", `<div class="card"><h1>Consulta não encontrada</h1></div>`));
    res.send(renderShell("Editar consulta", `<div class="admin-back-top"><a href="/pront/paciente/${req.params.id}">← voltar</a></div>${formConsulta(req.params.id, c, `/pront/paciente/${req.params.id}/consulta/${c.id}/editar`, "Editar consulta")}`));
  });

  app.post("/pront/paciente/:id/consulta/:cid/editar", medicoRequired, async (req, res) => {
    const { data, texto } = req.body || {};
    if (!texto || !texto.trim()) return res.redirect(`/pront/paciente/${req.params.id}/consulta/${req.params.cid}/editar`);
    await pool.query(`UPDATE pront_consultas SET data=COALESCE(NULLIF($3,'')::date,data), texto=$4 WHERE id=$1 AND paciente_id=$2`,
      [req.params.cid, req.params.id, data || "", texto.trim()]);
    res.redirect(`/pront/paciente/${req.params.id}`);
  });

  // excluir consulta (médico)
  app.post("/pront/paciente/:id/consulta/:cid/excluir", authRequired, adminRequired, async (req, res) => {
    await pool.query(`DELETE FROM pront_consultas WHERE id=$1 AND paciente_id=$2`, [req.params.cid, req.params.id]);
    res.redirect(`/pront/paciente/${req.params.id}`);
  });

  // ===== GERADOR DE DOCUMENTOS: abre pré-preenchido + salva o emitido na ficha =====
  // Gancho injetado DENTRO da IIFE do gerador (acesso a S/applyPaper/renderPanel/renderDoc),
  // sem tocar no arquivo do gerador. Âncora única: setTimeout(fitPreview,80);
  const HOOK_JS = `
window.__GETSTATE=function(){return S;};
window.__RENDER_FOR_PDF=function(s){try{Object.assign(S,s);document.body.classList.toggle("pp",S.impressao==="pp");applyPaper();renderPanel();renderDoc();}catch(e){console.error(e);}};
window.__READY=1;`;
  let __gerBase = null;
  async function geradorBase() {
    if (!__gerBase) {
      let h = await readFile(new URL("./gerador-documentos.html", import.meta.url), "utf8");
      h = h.replace("setTimeout(fitPreview,80);", "setTimeout(fitPreview,80);" + HOOK_JS);
      __gerBase = h;
    }
    return __gerBase;
  }
  // botão flutuante "Salvar no prontuário" (oculto na impressão), injetado só na versão servida ao humano
  const SAVE_UI = `<script>(function(){
    var st=document.createElement('style');st.textContent='@media print{#__save,#__dl,#__savemsg{display:none!important}}';document.head.appendChild(st);
    var b=document.createElement('button');b.id='__save';b.textContent='Salvar no prontuário';
    b.style.cssText='position:fixed;right:18px;bottom:18px;z-index:99999;background:#0c447c;color:#fff;border:0;border-radius:10px;padding:11px 16px;font:600 14px system-ui;cursor:pointer;box-shadow:0 3px 10px rgba(0,0,0,.25)';
    var d=document.createElement('button');d.id='__dl';d.textContent='Abrir PDF p/ papel timbrado';
    d.style.cssText='position:fixed;right:18px;bottom:64px;z-index:99999;background:#b45309;color:#fff;border:0;border-radius:10px;padding:11px 16px;font:600 14px system-ui;cursor:pointer;box-shadow:0 3px 10px rgba(0,0,0,.25)';
    var m=document.createElement('div');m.id='__savemsg';m.style.cssText='position:fixed;right:18px;bottom:112px;z-index:99999;font:600 13px system-ui';
    document.body.appendChild(b);document.body.appendChild(d);document.body.appendChild(m);
    b.onclick=async function(){
      if(!window.__GETSTATE){m.style.color='#b91c1c';m.textContent='Estado indisponível';return;}
      var __st0=window.__GETSTATE();
      if(__st0&&__st0.assina==='digital'){m.style.color='#b45309';m.innerHTML='Documento com assinatura digital — use <b>“Baixar PDF assinado (ICP-Brasil)”</b>: ele salva na ficha com o código de acesso.';return;}
      b.disabled=true;m.style.color='#0c447c';m.textContent='Salvando…';
      try{
        var r=await fetch(window.__SAVE_URL,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({state:window.__GETSTATE()})});
        var j=await r.json();
        if(r.ok&&j.ok){m.style.color='#0e7a4b';m.innerHTML="Salvo na ficha ✓ &nbsp;<a href='#' id='__novo' style='color:#0c447c;font-weight:600'>Novo documento</a>";var nv=document.getElementById('__novo');if(nv)nv.onclick=function(ev){ev.preventDefault();if(window.novoDocumento)window.novoDocumento();m.textContent='';b.disabled=false;};}
        else{m.style.color='#b91c1c';m.textContent='Falha: '+(j.erro||r.status);b.disabled=false;}
      }catch(e){m.style.color='#b91c1c';m.textContent='Erro: '+e.message;b.disabled=false;}
    };
    d.onclick=async function(){
      if(!window.__GETSTATE){m.style.color='#b91c1c';m.textContent='Estado indisponível';return;}
      var w=window.open('','_blank');   // abre a aba JÁ no clique, senão o navegador bloqueia como pop-up
      if(w){try{w.document.write('<!doctype html><meta charset=utf-8><title>Gerando…</title><body style="font:15px system-ui;padding:24px;color:#444">Gerando PDF para impressão…</body>');}catch(e){}}
      d.disabled=true;m.style.color='#b45309';m.textContent='Gerando PDF…';
      try{
        var st0=window.__GETSTATE();
        var r=await fetch(window.__PP_URL,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({state:st0})});
        if(!r.ok){var j=await r.json().catch(function(){return {};});if(w)w.close();m.style.color='#b91c1c';m.textContent='Falha: '+(j.erro||r.status);d.disabled=false;return;}
        var blob=await r.blob();
        var url=URL.createObjectURL(blob);
        if(w){w.location=url;}
        else{var a=document.createElement('a');a.href=url;a.target='_blank';document.body.appendChild(a);a.click();a.remove();}
        setTimeout(function(){URL.revokeObjectURL(url);},120000);   // some sozinho; nada fica no disco
        m.style.color='#0e7a4b';m.textContent=w?'PDF aberto em nova aba ✓ — imprima em "Tamanho real"':'Habilite pop-ups p/ abrir o PDF';d.disabled=false;
      }catch(e){if(w)w.close();m.style.color='#b91c1c';m.textContent='Erro: '+e.message;d.disabled=false;}
    };
  })();</script>`;

  // botão "Baixar PDF assinado (ICP-Brasil)" — assinatura qualificada via Bird ID
  const SIGN_UI = `<script>(function(){
    var st=document.createElement('style');st.textContent='@media print{#__sign{display:none!important}}';document.head.appendChild(st);
    var s=document.createElement('button');s.id='__sign';s.textContent='Baixar PDF assinado (ICP-Brasil)';
    s.style.cssText='position:fixed;right:18px;bottom:160px;z-index:99999;background:#0e7a4b;color:#fff;border:0;border-radius:10px;padding:11px 16px;font:600 14px system-ui;cursor:pointer;box-shadow:0 3px 10px rgba(0,0,0,.25)';
    document.body.appendChild(s);
    function say(c,t){var m=document.getElementById('__savemsg');if(m){m.style.color=c;m.textContent=t;}}
    s.onclick=async function(){
      if(!window.__GETSTATE){say('#b91c1c','Estado indisponível');return;}
      s.disabled=true;
      try{
        var stt=await (await fetch(window.__ASSINA_STATUS_URL)).json();
        if(!stt.ativa){
          var otp=prompt('Assinatura ICP-Brasil (Bird ID) — digite o OTP de 6 dígitos do app:');
          if(!otp){s.disabled=false;return;}
          say('#0c447c','Abrindo sessão de assinatura…');
          var ra=await fetch(window.__ASSINA_ABRIR_URL,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({otp:String(otp).trim()})});
          var ja=await ra.json().catch(function(){return{};});
          if(!ra.ok||!ja.ok){say('#b91c1c','Falha na sessão: '+(ja.erro||ra.status));s.disabled=false;return;}
        }
        var w=window.open('','_blank');
        if(w){try{w.document.write('<!doctype html><meta charset=utf-8><body style="font:15px system-ui;padding:24px;color:#444">Assinando documento…');}catch(e){}}
        say('#0e7a4b','Assinando…');
        var r=await fetch(window.__ASSINA_PDF_URL,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({state:window.__GETSTATE()})});
        if(!r.ok){var j=await r.json().catch(function(){return{};});if(w)w.close();say('#b91c1c','Falha: '+(j.erro||r.status));s.disabled=false;return;}
        var vcode=r.headers.get('X-Verif-Code')||'';
        var blob=await r.blob();var url=URL.createObjectURL(blob);
        if(w){w.location=url;}else{var a=document.createElement('a');a.href=url;a.download='documento-assinado.pdf';document.body.appendChild(a);a.click();a.remove();}
        setTimeout(function(){URL.revokeObjectURL(url);},120000);
        say('#0e7a4b','PDF assinado ✓ salvo na ficha'+(vcode?(' — código de acesso: '+vcode):'')+' · valide em validar.iti.gov.br');s.disabled=false;
      }catch(e){say('#b91c1c','Erro: '+e.message);s.disabled=false;}
    };
  })();</script>`;

  // orçamento de exames complementares: injeta o nome do paciente no campo e serve a página
  app.get("/pront/paciente/:id/orcamento", authRequired, async (req, res) => {
    const p = (await pool.query(`SELECT id, nome FROM pront_pacientes WHERE id=$1`, [req.params.id])).rows[0];
    if (!p) return res.status(404).send(renderShell("Não encontrado", `<div class="card"><h1>Paciente não encontrado</h1></div>`));
    try {
      let html = await readFile(new URL("./orcamento_extra.html", import.meta.url), "utf8");
      const nomeAttr = String(p.nome || "").replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");
      html = html.replace('<input id="nome" type="text"/>', `<input id="nome" type="text" value="${nomeAttr}"/>`);
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(html);
    } catch (e) {
      res.status(500).send(renderShell("Erro", `<div class="card"><h1>Orçamento indisponível</h1><div class="mut">${safe(e.message)}</div></div>`));
    }
  });

  // gerador AVULSO (sem paciente): só assinatura digital + QR. Link direto autenticado.
  app.get("/pront/documento", medicoRequired, async (req, res) => {
    try {
      let html = await geradorBase();
      let dupJson = "null";                                   // duplicação de um avulso
      if (req.query.dup) {
        const drow = (await pool.query(`SELECT state_json FROM pront_docs_emitidos WHERE id=$1 AND paciente_id IS NULL`, [req.query.dup])).rows[0];
        if (drow && drow.state_json) dupJson = JSON.stringify(drow.state_json).replace(/</g, "\\u003c");
      }
      html = html.replace("<body>", `<body><script>window.__DUP_STATE=${dupJson};</script>`);
      // cria o #__savemsg (o say() do SIGN_UI escreve nele) + injeta as URLs de assinatura e o botão
      const msgUi = `<script>(function(){var m=document.createElement('div');m.id='__savemsg';m.style.cssText='position:fixed;right:18px;bottom:112px;z-index:99999;font:600 13px system-ui';document.body.appendChild(m);var st=document.createElement('style');st.textContent='@media print{#__savemsg{display:none!important}}';document.head.appendChild(st);})();</script>`;
      html = html.replace("</body>", `<script>window.__ASSINA_STATUS_URL="/pront/assinatura/status";window.__ASSINA_ABRIR_URL="/pront/assinatura/abrir";window.__ASSINA_PDF_URL="/pront/documento/pdf-assinado";</script>${msgUi}${SIGN_UI}</body>`);
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(html);
    } catch (e) {
      console.error("GERADOR AVULSO ERROR", e);
      res.status(500).send("Gerador indisponível");
    }
  });

  // lista dos documentos avulsos (só médico). Ordenável por descrição, tipo, data.
  app.get("/pront/documentos-avulsos", medicoRequired, async (req, res) => {
    try {
      const TIPO_DOC = { receituario: "Receituário", pedido: "Pedido de exames", relatorio: "Relatório", atestado: "Atestado", laudo: "Laudo" };
      const sortMap = { descricao: "LOWER(COALESCE(descricao,''))", tipo: "LOWER(COALESCE(tipo,''))", data: "criado_em" };
      const sort = sortMap[req.query.sort] ? req.query.sort : "data";
      const dir = (req.query.dir === "asc") ? "ASC" : "DESC";
      const orderBy = `${sortMap[sort]} ${dir}, criado_em DESC`;
      const docs = (await pool.query(
        `SELECT id, tipo, paper, assinado, secret_code, verif_token, descricao, to_char(criado_em,'YYYY-MM-DD') data
           FROM pront_docs_emitidos WHERE paciente_id IS NULL ORDER BY ${orderBy}`)).rows;

      const th = (key, label) => {
        const active = sort === key;
        const nextDir = (active && dir === "ASC") ? "desc" : "asc";
        const arrow = active ? (dir === "ASC" ? " ↑" : " ↓") : "";
        return `<th><a href="/pront/documentos-avulsos?sort=${key}&dir=${nextDir}" style="color:inherit;text-decoration:none;white-space:nowrap">${label}${arrow}</a></th>`;
      };

      const corpo = `
        <div class="admin-back-top"><a href="/pront">← Prontuário</a></div>
        <div class="right" style="justify-content:space-between">
          <h1 style="margin:0">Documentos avulsos <span class="mut" style="font-weight:400">(${docs.length})</span></h1>
          <a href="/pront/documento" target="_blank"><button type="button" style="background:#b45309">+ Novo avulso</button></a>
        </div>
        ${docs.length ? `
        <div class="card mt">
          <table>
            <thead><tr>${th("data", "Data")}${th("tipo", "Tipo")}${th("descricao", "Descrição")}<th>Assinatura</th><th>Ações</th></tr></thead>
            <tbody>${docs.map(d => `
              <tr>
                <td>${toBR(d.data)}</td>
                <td><b>${TIPO_DOC[d.tipo] || safe(d.tipo)}</b></td>
                <td>${d.descricao ? `<span style="font-size:.95em;line-height:1.3;max-width:44ch;display:inline-block">${safe(d.descricao)}</span>` : `<span class="mut">—</span>`}</td>
                <td>${d.assinado
                  ? `<span style="color:#0e7a4b;font-weight:600">✔ ICP-Brasil</span>${d.secret_code ? ` · <span class="mut">código:</span> <code style="font-weight:700;letter-spacing:.5px">${safe(d.secret_code)}</code>` : ""}${d.verif_token ? ` · <a href="/verificar/${d.verif_token}" target="_blank">verificar</a>` : ""}`
                  : `<span class="mut">—</span>`}</td>
                <td style="white-space:nowrap">
                  <a href="/pront/documento-emitido/${d.id}/pdf" target="_blank">abrir PDF</a>
                  · <a href="/pront/documento?dup=${d.id}" target="_blank">duplicar</a>
                  · <a href="#" class="doc-del" data-del="${d.id}" data-desc="${safe((TIPO_DOC[d.tipo] || d.tipo) + (d.descricao ? " — " + d.descricao : ""))}" style="color:#b91c1c">excluir</a>
                </td>
              </tr>`).join("")}</tbody>
          </table>
        </div>
        <script>(function(){
          document.querySelectorAll('a.doc-del').forEach(function(a){
            a.addEventListener('click',function(ev){
              ev.preventDefault();
              var did=a.getAttribute('data-del'), desc=a.getAttribute('data-desc')||'este documento';
              if(!confirm('Excluir '+desc+' ?\\n\\nRemove o documento avulso. Esta ação não pode ser desfeita.'))return;
              a.textContent='excluindo…';a.style.pointerEvents='none';
              fetch('/pront/documento-emitido/'+did,{method:'DELETE'}).then(function(r){
                if(r.ok){var tr=a.closest('tr');if(tr)tr.parentNode.removeChild(tr);}
                else{a.textContent='falhou';a.style.color='#b91c1c';a.style.pointerEvents='';}
              }).catch(function(){a.textContent='erro';a.style.pointerEvents='';});
            });
          });
        })();</script>` : `<div class="card mt"><p class="mut">Nenhum documento avulso emitido ainda. <a href="/pront/documento" target="_blank">Emitir o primeiro →</a></p></div>`}`;
      res.send(renderShell("Documentos avulsos", corpo));
    } catch (e) {
      console.error("AVULSOS LIST ERROR", e);
      res.status(500).send("Erro ao listar documentos avulsos");
    }
  });

  app.get("/pront/paciente/:id/documento", medicoRequired, async (req, res) => {
    const p = (await pool.query(`SELECT id, nome, endereco FROM pront_pacientes WHERE id=$1`, [req.params.id])).rows[0];
    if (!p) return res.status(404).send(renderShell("Não encontrado", `<div class="card"><h1>Paciente não encontrado</h1></div>`));
    try {
      let html = await geradorBase();
      const nomeJS = JSON.stringify(p.nome).replace(/</g, "\\u003c");   // injeta nome no estado inicial
      html = html.replace('paciente:""', `paciente:${nomeJS}`);
      const endJS = JSON.stringify(p.endereco || "").replace(/</g, "\\u003c");   // injeta endereço (receituário de controle)
      html = html.replace('pacEnd:""', `pacEnd:${endJS}`);
      const saveUrl = `/pront/paciente/${p.id}/documento/salvar`;
      const ppUrl = `/pront/paciente/${p.id}/documento/pdf-timbrado`;
      const assinaPdfUrl = `/pront/paciente/${p.id}/documento/pdf-assinado`;
      let dupJson = "null";                                   // duplicação: pré-carrega o estado de um doc emitido
      if (req.query.dup) {
        const drow = (await pool.query(`SELECT state_json FROM pront_docs_emitidos WHERE id=$1 AND paciente_id=$2`, [req.query.dup, p.id])).rows[0];
        if (drow && drow.state_json) dupJson = JSON.stringify(drow.state_json).replace(/</g, "\\u003c");
      }
      // __DUP_STATE precisa estar setado ANTES do script principal (o init roda applyDupState em microtask, antes do fim do body)
      html = html.replace("<body>", `<body><script>window.__DUP_STATE=${dupJson};</script>`);
      html = html.replace("</body>", `<script>window.__SAVE_URL=${JSON.stringify(saveUrl)};window.__PP_URL=${JSON.stringify(ppUrl)};window.__ASSINA_STATUS_URL="/pront/assinatura/status";window.__ASSINA_ABRIR_URL="/pront/assinatura/abrir";window.__ASSINA_PDF_URL=${JSON.stringify(assinaPdfUrl)};</script>${SAVE_UI}${SIGN_UI}</body>`);
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(html);
    } catch (e) {
      res.status(500).send(renderShell("Erro", `<div class="card"><h1>Gerador indisponível</h1><div class="mut">${safe(e.message)}</div></div>`));
    }
  });

  // salva o documento emitido: estado S -> PDF (puppeteer) -> R2 -> ficha
  app.post("/pront/paciente/:id/documento/salvar", medicoRequired, async (req, res) => {
    const id = req.params.id;
    try {
      const p = (await pool.query(`SELECT id FROM pront_pacientes WHERE id=$1`, [id])).rows[0];
      if (!p) return res.status(404).json({ ok: false, erro: "paciente não encontrado" });
      const state = req.body && req.body.state;
      if (!state || typeof state !== "object") return res.status(400).json({ ok: false, erro: "estado ausente" });
      if (state.assina === "digital")
        return res.status(409).json({ ok: false, erro: "documento em modo de assinatura digital — use 'Baixar PDF assinado' para salvar a versão assinada com código", use_assinado: true });
      state.impressao = "digital";   // a cópia da ficha mantém SEMPRE o timbrado digital

      const html = await geradorBase();
      const pdf = await gerarDocumentoPDF(html, state);   // puppeteer (roda no Render)

      const tipo = String(state.doc || "documento").slice(0, 40);
      const paper = String(state.paper || "A4").slice(0, 8);
      const r2key = `pront/docs/${id}/${Date.now()}-${tipo}.pdf`;
      await uploadToR2(r2key, pdf, "application/pdf");

      const { rows: [row] } = await pool.query(
        `INSERT INTO pront_docs_emitidos (paciente_id, tipo, paper, r2_key, criado_por, descricao, state_json)
         VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb) RETURNING id`,
        [id, tipo, paper, r2key, quem(req), resumoDocumento(state), JSON.stringify(state)]);
      res.json({ ok: true, id: row.id });
    } catch (e) {
      console.error("SALVAR DOC ERROR", e);
      res.status(500).json({ ok: false, erro: e.message });
    }
  });

  // gera o PDF SEM o timbrado digital (para imprimir sobre o papel timbrado físico).
  // NÃO salva na ficha: é só um download. Imprimir em "Tamanho real" / escala 100%.
  app.post("/pront/paciente/:id/documento/pdf-timbrado", medicoRequired, async (req, res) => {
    const id = req.params.id;
    try {
      const p = (await pool.query(`SELECT id FROM pront_pacientes WHERE id=$1`, [id])).rows[0];
      if (!p) return res.status(404).json({ ok: false, erro: "paciente não encontrado" });
      const state = req.body && req.body.state;
      if (!state || typeof state !== "object") return res.status(400).json({ ok: false, erro: "estado ausente" });
      state.impressao = "pp";   // suprime o timbrado digital — o papel já tem o timbrado impresso

      const html = await geradorBase();
      const pdf = await gerarDocumentoPDF(html, state);   // puppeteer (roda no Render)

      const tipo = String(state.doc || "documento").replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 40) || "documento";
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", `attachment; filename="${tipo}-timbrado.pdf"`);
      res.send(pdf);
    } catch (e) {
      console.error("PDF TIMBRADO ERROR", e);
      res.status(500).json({ ok: false, erro: e.message });
    }
  });

  // serve o PDF de um documento emitido (inline)
  app.get("/pront/documento-emitido/:id/pdf", authRequired, async (req, res) => {
    const d = (await pool.query(`SELECT r2_key FROM pront_docs_emitidos WHERE id=$1`, [req.params.id])).rows[0];
    if (!d) return res.status(404).send("Documento não encontrado");
    try {
      const r = await fetchR2Stream(d.r2_key);
      const buf = Buffer.from(await r.arrayBuffer());
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", "inline");
      res.send(buf);
    } catch (e) {
      res.status(500).send("Falha ao abrir o documento");
    }
  });

  // exclui um documento emitido: remove do R2 (best-effort) e da ficha
  app.delete("/pront/documento-emitido/:id", medicoRequired, async (req, res) => {
    try {
      const d = (await pool.query(`SELECT r2_key FROM pront_docs_emitidos WHERE id=$1`, [req.params.id])).rows[0];
      if (!d) return res.status(404).json({ ok: false, erro: "não encontrado" });
      await pool.query(`DELETE FROM pront_docs_emitidos WHERE id=$1`, [req.params.id]);
      try { if (d.r2_key) await deleteFromR2(d.r2_key); } catch (e) { console.error("R2 del", e.message); }
      res.json({ ok: true });
    } catch (e) {
      console.error("DEL DOC ERROR", e);
      res.status(500).json({ ok: false, erro: e.message });
    }
  });
  // ===== ASSINATURA DIGITAL ICP-BRASIL (Bird ID) =====
  const _sessoesBird = new Map();                       // userKey -> { access_token, expira_em, alias, pem }
  const userKey = req => String(req.user?.id || req.user?.email || "medico");
  const gerarSecretCode = () => { const A = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; let x = ""; for (let i = 0; i < 6; i++) x += A[Math.floor(Math.random() * A.length)]; return x; };

  // resumo curto do documento (meds da receita / exames pedidos) p/ exibir na ficha
  function resumoDocumento(state) {
    try {
      const trunc = (s) => { s = String(s || "").replace(/\s+/g, " ").trim(); return s.length > 200 ? s.slice(0, 197) + "…" : s; };
      const d = state && state.doc;
      if (d === "receituario") {
        const meds = ((state.rx && state.rx.itens) || []).map(i => String((i && i.med) || "").trim()).filter(Boolean);
        return trunc(meds.join(", ")) || "Receituário";
      }
      if (d === "pedido") {
        const sel = (state.ped && Array.isArray(state.ped.sel)) ? state.ped.sel : [];
        const outros = String((state.ped && state.ped.outros) || "").split("\n").map(s => s.trim()).filter(Boolean);
        return trunc([...sel, ...outros].join(", ")) || "Pedido de exames";
      }
      if (d === "relatorio") return trunc((state.rel && state.rel.titulo) || "") || "Relatório médico";
      if (d === "atestado") {
        const a = state.ate || {};
        if (a.modelo === "afastamento") { const n = Number(a.dias) || 0; return `Afastamento — ${n} dia${n === 1 ? "" : "s"}`; }
        if (a.modelo === "retorno") return "Retorno às atividades";
        if (a.modelo === "comp_pac") return "Comparecimento do paciente";
        if (a.modelo === "comp_acomp") return "Comparecimento de acompanhante";
        return "Atestado";
      }
      return "";
    } catch (e) { return ""; }
  }

  app.get("/pront/assinatura/status", medicoRequired, (req, res) => {
    const sx = _sessoesBird.get(userKey(req));
    const ativa = !!(sx && sx.expira_em > Date.now());
    res.json({ ativa, expira_em: ativa ? sx.expira_em : null });
  });

  app.post("/pront/assinatura/abrir", medicoRequired, async (req, res) => {
    try {
      const otp = String(req.body?.otp || "").trim();
      if (!/^\d{6,8}$/.test(otp)) return res.status(400).json({ ok: false, erro: "OTP inválido" });
      if (!process.env.BIRDID_CLIENT_ID || !process.env.BIRDID_CLIENT_SECRET || !process.env.BIRDID_CPF)
        return res.status(500).json({ ok: false, erro: "Credenciais Bird ID não configuradas no servidor" });
      const sessao = await abrirSessao({ cpf: process.env.BIRDID_CPF, otp, lifetimeSeg: 4 * 3600 });
      const cert = await descobrirCertificado(sessao.access_token);
      _sessoesBird.set(userKey(req), { access_token: sessao.access_token, expira_em: sessao.expira_em, alias: cert.alias, pem: cert.pem });
      res.json({ ok: true, expira_em: sessao.expira_em });
    } catch (e) {
      console.error("BIRDID ABRIR", e);
      res.status(502).json({ ok: false, erro: e.message });
    }
  });

  // gera o PDF (com bloco digital + QR por-documento), assina ICP-Brasil e devolve p/ download
  app.post("/pront/paciente/:id/documento/pdf-assinado", medicoRequired, async (req, res) => {
    const id = req.params.id;
    try {
      const sess = _sessoesBird.get(userKey(req));
      if (!sess || sess.expira_em <= Date.now())
        return res.status(401).json({ ok: false, erro: "sessão de assinatura expirada", precisa_otp: true });
      const p = (await pool.query(`SELECT id FROM pront_pacientes WHERE id=$1`, [id])).rows[0];
      if (!p) return res.status(404).json({ ok: false, erro: "paciente não encontrado" });
      const state = req.body && req.body.state;
      if (!state || typeof state !== "object") return res.status(400).json({ ok: false, erro: "estado ausente" });
      state.impressao = "digital";                       // mantém o timbrado digital
      state.assina = "digital";                          // usa o bloco de assinatura digital + QR

      const token = randomUUID();
      const secretCode = gerarSecretCode();               // código de acesso do QR (protocolo ITI)
      const base = (process.env.PUBLIC_BASE_URL || `${req.protocol}://${req.get("host")}`).replace(/\/+$/, "");
      const verifUrl = `${base}/verificar/${token}`;

      let html = await geradorBase();
      html = html.replace("</body>", `<script>window.VERIFY_URL=${JSON.stringify(verifUrl)};window.VERIFY_CODE=${JSON.stringify(secretCode)};</script></body>`);
      const pdf = await gerarDocumentoPDF(html, state);   // puppeteer

      const rawSignHex = makeBirdIdRawSigner({ access_token: sess.access_token, certificateAlias: sess.alias });
      const assinado = await assinarPdfCades({ pdfBuffer: pdf, certificadosPem: [sess.pem], rawSignHex, meta: { reason: "Documento médico assinado digitalmente" } });

      const tipo = String(state.doc || "documento").replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 40) || "documento";
      const paper = String(state.paper || "A4").slice(0, 8);
      const r2key = `pront/docs-assinados/${id}/${Date.now()}-${tipo}.pdf`;
      await uploadToR2(r2key, assinado, "application/pdf");
      await pool.query(
        `INSERT INTO pront_docs_emitidos (paciente_id, tipo, paper, r2_key, criado_por, verif_token, assinado, secret_code, descricao, state_json)
         VALUES ($1,$2,$3,$4,$5,$6,true,$7,$8,$9::jsonb)`,
        [id, tipo, paper, r2key, quem(req), token, secretCode, resumoDocumento(state), JSON.stringify(state)]);

      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", `attachment; filename="${tipo}-assinado.pdf"`);
      res.setHeader("X-Verif-Url", verifUrl);
      res.setHeader("X-Verif-Code", secretCode);
      res.send(assinado);
    } catch (e) {
      console.error("PDF ASSINADO ERROR", e);
      res.status(500).json({ ok: false, erro: e.message });
    }
  });

  // assinatura AVULSA (sem paciente): assina, grava em pront_docs_emitidos com paciente_id NULL, mantém QR/código
  app.post("/pront/documento/pdf-assinado", medicoRequired, async (req, res) => {
    try {
      const sess = _sessoesBird.get(userKey(req));
      if (!sess || sess.expira_em <= Date.now())
        return res.status(401).json({ ok: false, erro: "sessão de assinatura expirada", precisa_otp: true });
      const state = req.body && req.body.state;
      if (!state || typeof state !== "object") return res.status(400).json({ ok: false, erro: "estado ausente" });
      state.impressao = "digital";
      state.assina = "digital";

      const token = randomUUID();
      const secretCode = gerarSecretCode();
      const base = (process.env.PUBLIC_BASE_URL || `${req.protocol}://${req.get("host")}`).replace(/\/+$/, "");
      const verifUrl = `${base}/verificar/${token}`;

      let html = await geradorBase();
      html = html.replace("</body>", `<script>window.VERIFY_URL=${JSON.stringify(verifUrl)};window.VERIFY_CODE=${JSON.stringify(secretCode)};</script></body>`);
      const pdf = await gerarDocumentoPDF(html, state);

      const rawSignHex = makeBirdIdRawSigner({ access_token: sess.access_token, certificateAlias: sess.alias });
      const assinado = await assinarPdfCades({ pdfBuffer: pdf, certificadosPem: [sess.pem], rawSignHex, meta: { reason: "Documento médico assinado digitalmente" } });

      const tipo = String(state.doc || "documento").replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 40) || "documento";
      const paper = String(state.paper || "A4").slice(0, 8);
      const r2key = `pront/docs-assinados/avulso/${Date.now()}-${tipo}.pdf`;
      await uploadToR2(r2key, assinado, "application/pdf");
      await pool.query(
        `INSERT INTO pront_docs_emitidos (paciente_id, tipo, paper, r2_key, criado_por, verif_token, assinado, secret_code, descricao, state_json)
         VALUES (NULL,$1,$2,$3,$4,$5,true,$6,$7,$8::jsonb)`,
        [tipo, paper, r2key, quem(req), token, secretCode, resumoDocumento(state), JSON.stringify(state)]);

      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", `attachment; filename="${tipo}-assinado.pdf"`);
      res.setHeader("X-Verif-Url", verifUrl);
      res.setHeader("X-Verif-Code", secretCode);
      res.send(assinado);
    } catch (e) {
      console.error("PDF ASSINADO AVULSO ERROR", e);
      res.status(500).json({ ok: false, erro: e.message });
    }
  });

  // ===== app mobile (PWA enxuto p/ emitir + assinar on-the-go) =====
  // shell sem auth (só UI; login inline via /api/login). Toda AÇÃO real usa medicoRequired.
  app.get("/pront/mobile", async (req, res) => {
    try {
      const html = await readFile(new URL("./mobile.html", import.meta.url), "utf8");
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.setHeader("Cache-Control", "no-cache");
      res.send(html);
    } catch (e) {
      console.error("MOBILE SHELL ERROR", e);
      res.status(500).send("App mobile indisponível");
    }
  });

  // busca de nomes de medicamentos p/ o app mobile (med-seed.js decodificado 1x em memória)
  let _medIdx = null;
  async function _carregarMedIdx() {
    if (_medIdx) return _medIdx;
    const { gunzipSync } = await import("node:zlib");
    const js = await readFile(new URL("./med-seed.js", import.meta.url), "utf8");
    const m = js.match(/window\.MEDGZ\s*=\s*"([^"]+)"/);
    if (!m) { _medIdx = []; return _medIdx; }
    const raw = gunzipSync(Buffer.from(m[1], "base64")).toString("utf8");
    const nrm = s => String(s || "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9]+/g, " ").trim();
    _medIdx = raw.split("\n").filter(Boolean).map(l => { const p = l.split("\t"); return { s: p[0] || "", p: p[1] || "", a: p[2] || "", n: nrm((p[0] || "") + " " + (p[1] || "")) }; });
    return _medIdx;
  }
  app.get("/pront/api/med-busca", medicoRequired, async (req, res) => {
    try {
      const nrm = s => String(s || "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9]+/g, " ").trim();
      const q = nrm(req.query.q);
      if (q.length < 2) return res.json([]);
      const terms = q.split(" ").filter(Boolean);
      const idx = await _carregarMedIdx();
      const out = [];
      for (const o of idx) {
        if (terms.every(t => o.n.includes(t))) { out.push({ s: o.s, p: o.p, a: o.a }); if (out.length >= 20) break; }
      }
      res.json(out);
    } catch (e) {
      console.error("MED-BUSCA ERROR", e);
      res.status(500).json([]);
    }
  });

  // busca de pacientes do prontuário p/ o app mobile (nome + endereço, p/ puxar dados)
  app.get("/pront/api/pacientes-busca", medicoRequired, async (req, res) => {
    try {
      const q = String(req.query.q || "").trim();
      if (q.length < 2) return res.json([]);
      const { rows } = await pool.query(
        `SELECT id, nome, to_char(dn,'YYYY-MM-DD') dn, COALESCE(endereco,'') endereco
           FROM pront_pacientes WHERE nome ILIKE $1 ORDER BY lower(nome) LIMIT 20`,
        ["%" + q + "%"]);
      res.json(rows);
    } catch (e) {
      console.error("PAC-BUSCA ERROR", e);
      res.status(500).json([]);
    }
  });

  // ===== LAUDOS de testes rápidos: template do /lab + assinatura ICP-Brasil =====
  // catálogo dos exames oferecidos (products.csv na raiz do repo)
  let _laudoExames = null;
  async function _carregarLaudoExames() {
    if (_laudoExames) return _laudoExames;
    try {
      const csv = await readFile(new URL("../products.csv", import.meta.url), "utf8");
      const nomes = [];
      for (const l of csv.split(/\r?\n/)) {
        if (!l.trim()) continue;
        const nome = (l.split(";")[0] || "").replace(/^"|"$/g, "").trim();
        if (nome) nomes.push(nome);
      }
      _laudoExames = [...new Set(nomes)].sort((a, b) => a.localeCompare(b, "pt-BR", { sensitivity: "base" }));
    } catch (e) { console.error("LAUDO EXAMES ERROR", e); _laudoExames = []; }
    return _laudoExames;
  }
  app.get("/pront/api/laudo-exames", medicoRequired, async (req, res) => {
    const nrm = s => String(s || "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9]+/g, " ").trim();
    const q = nrm(req.query.q);
    const lista = await _carregarLaudoExames();
    if (!q) return res.json(lista.slice(0, 30));
    const terms = q.split(" ").filter(Boolean);
    res.json(lista.filter(n => { const nn = nrm(n); return terms.every(t => nn.includes(t)); }).slice(0, 30));
  });

  // monta {patient, collection, results}, gera o PDF do laudo (template /lab), assina ICP-Brasil e grava
  async function _emitirLaudoAssinado(req, res, pacienteId) {
    const sess = _sessoesBird.get(userKey(req));
    if (!sess || sess.expira_em <= Date.now())
      return res.status(401).json({ ok: false, erro: "sessão de assinatura expirada", precisa_otp: true });
    const b = req.body || {};
    const nome = String(b.paciente || "").trim();
    if (!nome) return res.status(400).json({ ok: false, erro: "nome do paciente ausente" });
    const itens = Array.isArray(b.itens) ? b.itens.filter(it => it && it.exam_name && it.result_value) : [];
    if (!itens.length) return res.status(400).json({ ok: false, erro: "nenhum teste informado" });

    const patient = { full_name: nome, birth_date: b.dn || null };
    const collection = { collected_at: b.data || new Date().toISOString().slice(0, 10) };
    const results = itens.map((it, i) => ({
      exam_name: String(it.exam_name).slice(0, 200),
      sample_type: String(it.sample_type || "Soro").slice(0, 60),
      method: String(it.method || "Imunocromatografia").slice(0, 80),
      result_value: String(it.result_value).slice(0, 400),
      reference_value: String(it.reference_value || "").slice(0, 120),
      observation: String(it.observation || "").slice(0, 500),
      result_color: ["positivo", "negativo", "neutro", "auto"].includes(it.result_color) ? it.result_color : "auto",
      sort_index: i,
    }));

    const token = randomUUID();
    const secretCode = gerarSecretCode();
    const base = (process.env.PUBLIC_BASE_URL || `${req.protocol}://${req.get("host")}`).replace(/\/+$/, "");
    const verifUrl = `${base}/verificar/${token}`;

    const pdf = await generateLabPdf({ patient, collection, results, sign: { verifUrl, verifCode: secretCode } });
    const rawSignHex = makeBirdIdRawSigner({ access_token: sess.access_token, certificateAlias: sess.alias });
    const assinado = await assinarPdfCades({ pdfBuffer: pdf, certificadosPem: [sess.pem], rawSignHex, meta: { reason: "Laudo de teste rápido assinado digitalmente" } });

    const descricao = ("Laudo — " + results.map(r => `${r.exam_name}: ${r.result_value}`).join("; ")).slice(0, 300);
    const r2key = `pront/docs-assinados/${pacienteId || "avulso"}/${Date.now()}-laudo.pdf`;
    await uploadToR2(r2key, assinado, "application/pdf");
    await pool.query(
      `INSERT INTO pront_docs_emitidos (paciente_id, tipo, paper, r2_key, criado_por, verif_token, assinado, secret_code, descricao, state_json)
       VALUES ($1,'laudo','A4',$2,$3,$4,true,$5,$6,$7::jsonb)`,
      [pacienteId, r2key, quem(req), token, secretCode, descricao,
       JSON.stringify({ doc: "laudo", paciente: nome, dn: b.dn || null, data: collection.collected_at, itens: results })]);

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="laudo-assinado.pdf"`);
    res.setHeader("X-Verif-Url", verifUrl);
    res.setHeader("X-Verif-Code", secretCode);
    res.send(assinado);
  }
  app.post("/pront/laudo/pdf-assinado", medicoRequired, async (req, res) => {
    try { await _emitirLaudoAssinado(req, res, null); }
    catch (e) { console.error("LAUDO ASSINADO ERROR", e); res.status(500).json({ ok: false, erro: e.message }); }
  });
  app.post("/pront/paciente/:id/laudo/pdf-assinado", medicoRequired, async (req, res) => {
    try {
      const p = (await pool.query(`SELECT id FROM pront_pacientes WHERE id=$1`, [req.params.id])).rows[0];
      if (!p) return res.status(404).json({ ok: false, erro: "paciente não encontrado" });
      await _emitirLaudoAssinado(req, res, req.params.id);
    } catch (e) { console.error("LAUDO ASSINADO PAC ERROR", e); res.status(500).json({ ok: false, erro: e.message }); }
  });

  // verificação PÚBLICA (o QR aponta pra cá). O token uuid é a capability (não-adivinhável).
  app.get("/verificar/:token", async (req, res) => {
    const t = String(req.params.token || "");
    if (!/^[0-9a-fA-F-]{36}$/.test(t)) return res.status(400).send("Token inválido");
    const d = (await pool.query(`SELECT tipo, criado_em, secret_code FROM pront_docs_emitidos WHERE verif_token=$1 AND assinado=true`, [t])).rows[0];

    // Protocolo do Portal VALIDAR do ITI (Cap. IV do Guia) — scan-and-validate direto na farmácia.
    // O `+` de application/validador-iti+json pode virar espaço no parser de query; detecta por substring.
    if (/validador-iti/.test(String(req.query?._format || ""))) {
      res.setHeader("Content-Type", "application/validador-iti+json; charset=utf-8");
      if (!d) return res.status(404).json({ erro: "prescrição não encontrada" });
      const enviado = String(req.query._secretCode || "").trim().toUpperCase();
      if (enviado !== String(d.secret_code || "").toUpperCase()) return res.status(401).json({ erro: "código de acesso incorreto" });
      const baseIti = (process.env.PUBLIC_BASE_URL || `${req.protocol}://${req.get("host")}`).replace(/\/+$/, "");
      return res.status(200).json({ version: "1.0.0", prescription: { signatureFiles: [{ url: `${baseIti}/verificar/${t}/pdf` }] } });
    }

    if (!d) { res.status(404); }
    const dt = d ? new Date(d.criado_em).toLocaleString("pt-BR") : "";
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(d
      ? `<!doctype html><html lang=pt-br><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Verificação de documento</title>
<body style="font:16px/1.55 system-ui,Segoe UI,Arial;max-width:640px;margin:0 auto;padding:28px;color:#1a1d23">
<div style="display:inline-block;background:#e8f5ee;color:#0e7a4b;font-weight:700;font-size:13px;padding:4px 10px;border-radius:20px">● Documento assinado digitalmente</div>
<h1 style="font-size:21px;margin:14px 0 6px">${safe(d.tipo || "Documento")}</h1>
<p>Emitido e assinado digitalmente por <b>Dr. Leandro Mendes</b> — CRM/SP 134.985 — em ${dt}, com certificado <b>ICP-Brasil</b> (assinatura qualificada).</p>
<p><a href="/verificar/${t}/pdf" style="display:inline-block;background:#0c447c;color:#fff;text-decoration:none;padding:11px 18px;border-radius:8px;font-weight:600">Abrir o documento assinado (PDF)</a></p>
<p style="color:#5b6470;font-size:14px;margin-top:22px">Para conferir a validade criptográfica da assinatura, baixe o PDF e valide em <a href="https://validar.iti.gov.br">validar.iti.gov.br</a>.</p>
</body></html>`
      : `<!doctype html><meta charset=utf-8><title>Não encontrado</title><body style="font:16px system-ui;max-width:560px;margin:60px auto;padding:24px;color:#1a1d23"><h1 style="font-size:20px">Documento não encontrado</h1><p style="color:#5b6470">O código informado não corresponde a nenhum documento assinado.</p></body>`);
  });
  app.get("/verificar/:token/pdf", async (req, res) => {
    const t = String(req.params.token || "");
    if (!/^[0-9a-fA-F-]{36}$/.test(t)) return res.status(400).send("Token inválido");
    const d = (await pool.query(`SELECT r2_key FROM pront_docs_emitidos WHERE verif_token=$1 AND assinado=true`, [t])).rows[0];
    if (!d) return res.status(404).send("Documento não encontrado");
    try {
      const r = await fetchR2Stream(d.r2_key);
      const buf = Buffer.from(await r.arrayBuffer());
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", "inline");
      res.send(buf);
    } catch (e) {
      res.status(500).send("Falha ao abrir o documento");
    }
  });

  const semAcento = s => String(s || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/\s+/g, " ").trim();

  app.get("/pront/reconciliar", authRequired, adminRequired, async (req, res) => {
    // lab_patients ainda não ligados, com contagem de coletas
    let labs;
    try {
      labs = (await pool.query(
        `SELECT lp.id, lp.full_name, to_char(lp.birth_date,'YYYY-MM-DD') dn,
                (SELECT count(*) FROM lab_collections lc WHERE lc.patient_id=lp.id)::int ncol
           FROM lab_patients lp
          WHERE lp.pront_id IS NULL
          ORDER BY lp.full_name`)).rows;
    } catch (e) {
      return res.send(renderShell("Reconciliação", `<div class="card"><h1>Reconciliação</h1><div class="mut">Módulo de laboratório não encontrado neste banco (${safe(e.message)}).</div></div>`));
    }
    const pacs = (await pool.query(`SELECT id, nome, to_char(dn,'YYYY-MM-DD') dn FROM pront_pacientes`)).rows;
    const porNome = new Map();
    for (const p of pacs) { const k = semAcento(p.nome); (porNome.get(k) || porNome.set(k, []).get(k)).push(p); }

    const linhas = labs.map(l => {
      const cand = porNome.get(semAcento(l.full_name)) || [];
      const forte = cand.find(c => c.dn && l.dn && c.dn === l.dn);
      const sugerido = forte || cand[0] || null;
      const conf = forte ? `<span style="background:#d1fae5;color:#065f46;padding:1px 8px;border-radius:999px;font-size:.8em">nome+DN</span>`
                 : cand.length ? `<span style="background:#fef3c7;color:#92400e;padding:1px 8px;border-radius:999px;font-size:.8em">só nome</span>`
                 : `<span class="mut" style="font-size:.8em">sem candidato</span>`;
      const opts = pacs.map(p => `<option value="${p.id}" ${sugerido && sugerido.id === p.id ? "selected" : ""}>${safe(p.nome)}${p.dn ? " · " + toBR(p.dn) : ""}</option>`).join("");
      return `<tr>
        <td>${safe(l.full_name)}<div class="mut" style="font-size:.8em">${l.dn ? toBR(l.dn) : "sem DN"} · ${l.ncol} coleta(s)</div></td>
        <td>${conf}</td>
        <td>
          <form method="post" action="/pront/reconciliar/ligar" class="inline" style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">
            <input type="hidden" name="lab_id" value="${l.id}"/>
            <select name="pront_id" style="max-width:280px"><option value="">— escolha —</option>${opts}</select>
            <button type="submit">Ligar</button>
          </form>
          <form method="post" action="/pront/reconciliar/criar" class="inline" style="margin-top:4px">
            <input type="hidden" name="lab_id" value="${l.id}"/>
            <button type="submit" style="background:#0e9f6e">Criar no prontuário</button>
          </form>
        </td>
      </tr>`;
    }).join("");

    res.send(renderShell("Reconciliação de pacientes", `
      <div class="admin-back-top"><a href="/pront">← Prontuário</a></div>
      <div class="card">
        <h1 style="margin-top:0">Reconciliar pacientes do laboratório</h1>
        <p class="mut">Pacientes do lab ainda não ligados ao cadastro mestre. Confirme o casamento (ou crie um novo no prontuário). Nada é ligado sem você confirmar.</p>
        ${labs.length ? `<table class="mt">
          <thead><tr><th>Paciente do lab</th><th>Sugestão</th><th>Ação</th></tr></thead>
          <tbody>${linhas}</tbody></table>`
        : `<div class="mut mt">Tudo reconciliado — nenhum paciente do lab pendente. 🎉</div>`}
      </div>`));
  });

  app.post("/pront/reconciliar/ligar", authRequired, adminRequired, async (req, res) => {
    const { lab_id, pront_id } = req.body || {};
    if (lab_id && pront_id) await pool.query(`UPDATE lab_patients SET pront_id=$1 WHERE id=$2`, [pront_id, lab_id]);
    res.redirect("/pront/reconciliar");
  });

  app.post("/pront/reconciliar/criar", authRequired, adminRequired, async (req, res) => {
    const { lab_id } = req.body || {};
    const lp = (await pool.query(`SELECT full_name, to_char(birth_date,'YYYY-MM-DD') dn FROM lab_patients WHERE id=$1`, [lab_id])).rows[0];
    if (lp) {
      const novo = (await pool.query(
        `INSERT INTO pront_pacientes(nome,dn,criado_por) VALUES($1,NULLIF($2,'')::date,$3) RETURNING id`,
        [lp.full_name, lp.dn || "", quem(req)])).rows[0];
      await pool.query(`UPDATE lab_patients SET pront_id=$1 WHERE id=$2`, [novo.id, lab_id]);
    }
    res.redirect("/pront/reconciliar");
  });
}

// rótulo a partir do canônico (sem depender do normalizador no cliente)
const ROTULOS = {
  cd4:"CD4", cd8:"CD8", cd4_ratio:"CD4/CD8", cv_hiv:"Carga viral HIV", carga_viral:"Carga viral",
  hemoglobina:"Hemoglobina", leucocitos:"Leucócitos", segmentados:"Segmentados", linfocitos:"Linfócitos",
  plaquetas:"Plaquetas", creatinina:"Creatinina", ureia:"Ureia", ast:"AST (TGO)", alt:"ALT (TGP)",
  ggt:"GGT", fosfatase_alc:"Fosfatase alcalina", colesterol_total:"Colesterol total", ldl:"LDL", hdl:"HDL",
  triglicerides:"Triglicérides", glicose:"Glicose", hba1c:"Hemoglobina glicada", pcr:"PCR", vhs:"VHS"
};
function ROTULO(c) { return c ? (ROTULOS[c] || c) : null; }
function fmtNum(n) {
  if (n == null) return "—";
  const s = Number(n);
  if (!isFinite(s)) return "—";
  return (Number.isInteger(s) ? s.toLocaleString("pt-BR") : s.toLocaleString("pt-BR", { maximumFractionDigits: 2 }));
}

// SVG de tendência montado no cliente (sem libs)
const CHART_JS = `
(function(){
  var data = JSON.parse(document.getElementById('evdata').textContent);
  var COR = { alto:'#d97706', baixo:'#2563eb', normal:'#0c447c', '':'#0c447c' };
  function draw(host, s){
    var pts = s.pontos.filter(function(p){return p;});
    if(pts.length<2){ host.innerHTML='<div class="mut">Sem série suficiente.</div>'; return; }
    var W=Math.max(320, data.datas.length*70), H=170, m={l:46,r:12,t:14,b:28};
    var vs=pts.map(function(p){return p.v;}); var mn=Math.min.apply(null,vs), mx=Math.max.apply(null,vs);
    if(mn===mx){ mn=mn*0.95; mx=mx*1.05||1; }
    var pad=(mx-mn)*0.12; mn-=pad; mx+=pad;
    var x=function(i){return m.l+(data.datas.length<=1?0:(W-m.l-m.r)*i/(data.datas.length-1));};
    var y=function(v){return m.t+(H-m.t-m.b)*(1-(v-mn)/(mx-mn));};
    var svg='<svg viewBox="0 0 '+W+' '+H+'" style="width:100%;max-width:'+W+'px;height:auto;font-family:system-ui;font-size:11px">';
    // grades y (min/max/meio)
    [mn,(mn+mx)/2,mx].forEach(function(v){ var yy=y(v).toFixed(1);
      svg+='<line x1="'+m.l+'" y1="'+yy+'" x2="'+(W-m.r)+'" y2="'+yy+'" stroke="#eef1f5"/>';
      svg+='<text x="'+(m.l-6)+'" y="'+(+yy+3)+'" text-anchor="end" fill="#9aa3af">'+(Math.round(v*100)/100)+'</text>'; });
    // linha
    var d=pts.map(function(p,i){return (i?'L':'M')+x(p.x).toFixed(1)+' '+y(p.v).toFixed(1);}).join(' ');
    svg+='<path d="'+d+'" fill="none" stroke="#0c447c" stroke-width="2"/>';
    // pontos (censurado = oco)
    pts.forEach(function(p){ var c=COR[p.st]||'#0c447c';
      svg+= p.cens
        ? '<circle cx="'+x(p.x).toFixed(1)+'" cy="'+y(p.v).toFixed(1)+'" r="4" fill="#fff" stroke="#7c3aed" stroke-width="2"/>'
        : '<circle cx="'+x(p.x).toFixed(1)+'" cy="'+y(p.v).toFixed(1)+'" r="4" fill="'+c+'"/>'; });
    // rótulos x
    data.datas.forEach(function(dt,i){ var br=dt.split('-').reverse().slice(0,2).join('/');
      svg+='<text x="'+x(i).toFixed(1)+'" y="'+(H-8)+'" text-anchor="middle" fill="#9aa3af">'+br+'</text>'; });
    svg+='</svg>';
    host.innerHTML='<div style="font-weight:600;color:#0c447c;margin:2px 0 4px">'+s.rotulo+(s.unidade?' ('+s.unidade+')':'')+'</div>'+svg;
  }
  document.querySelectorAll('.evtrend').forEach(function(t){
    t.addEventListener('click', function(ev){
      ev.stopPropagation();
      var i=t.getAttribute('data-i'); var tr=document.getElementById('chart-'+i);
      if(!tr) return; var open=tr.style.display!=='none';
      tr.style.display=open?'none':'';
      if(!open && !tr.dataset.drawn){ draw(tr.querySelector('.chart-host'), data.series[i]); tr.dataset.drawn='1'; }
    });
  });

  // ---- edição inline: clicar numa célula abre input; Enter salva (re-tipa e limpa flag) ----
  var PAC = window.__PAC_ID;
  function valorAtual(td){
    var raw = td.getAttribute('data-raw');
    if(raw!=null) return raw;
    return (td.textContent||'').replace(/·/,'').trim();
  }
  function editar(td){
    if(td.querySelector('input')) return;
    var antigo = td.innerHTML;
    var atual = valorAtual(td);
    td.innerHTML = '<input value="'+atual.replace(/"/g,'&quot;')+'" style="width:90px;font:inherit;text-align:right;padding:2px 4px" />';
    var inp = td.querySelector('input'); inp.focus(); inp.select();
    function cancelar(){ td.innerHTML = antigo; }
    inp.addEventListener('keydown', function(e){
      if(e.key==='Escape'){ cancelar(); }
      else if(e.key==='Enter'){ salvar(td, inp.value); }
    });
    inp.addEventListener('blur', function(){ cancelar(); });   // sair sem Enter = cancela
  }
  async function salvar(td, valor){
    var body = { coleta_id: td.getAttribute('data-coleta'), canonico: td.getAttribute('data-canon')||null,
                 rotulo: td.getAttribute('data-rotulo')||null, valor: valor };
    td.innerHTML = '<span class="mut">…</span>';
    try{
      var r = await fetch('/pront/paciente/'+PAC+'/exames/resultado/editar',
        { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
      var j = await r.json();
      if(r.ok && j.ok){ location.reload(); }   // recarrega: re-tipa, re-cor, remove flag, atualiza gráfico
      else { td.innerHTML = '<span style="color:#b91c1c">erro</span>'; }
    }catch(e){ td.innerHTML = '<span style="color:#b91c1c">erro</span>'; }
  }
  document.querySelectorAll('.evcell').forEach(function(td){
    td.addEventListener('click', function(){ editar(td); });
  });
})();
`;
