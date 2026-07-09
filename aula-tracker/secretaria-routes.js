// secretaria-routes.js — app mobile da secretária (flag agenda).
// Não toca em pront-routes.js (assinatura ICP-Brasil intocada).
// Endpoints próprios, gated por secretariaRequired (agenda || super_admin || adm). Recepção não entra.
import { readFile } from "node:fs/promises";

const TIPO_DOC = {
  receituario: "Receituário",
  pedido: "Pedido de exames",
  relatorio: "Relatório",
  atestado: "Atestado",
  laudo: "Laudo",
};

const safe = (s) => String(s ?? "");
const waNumber = (tel) => {
  const dg = safe(tel).replace(/\D/g, "");
  return dg ? (dg.length <= 11 ? "55" + dg : dg) : "";
};

export function registerSecretariaRoutes(app, pool, secretariaRequired, renderShell) {
  // ---- SPA da secretária (login trata a autenticação; APIs abaixo são gated) ----
  app.get(["/secretaria", "/secretaria/mobile"], async (req, res) => {
    try {
      const html = await readFile(new URL("./mobile-secretaria.html", import.meta.url), "utf8");
      res.type("html").send(html);
    } catch (e) {
      console.error("SECRETARIA HTML ERROR", e);
      res.status(500).send("Erro ao carregar a recepção.");
    }
  });

  // ---- Busca de pacientes (espelha a query do prontuário, gate de recepção) ----
  app.get("/secretaria/api/pacientes-busca", secretariaRequired, async (req, res) => {
    try {
      const q = String(req.query.q || "").trim();
      if (q.length < 2) return res.json([]);
      const { rows } = await pool.query(
        `SELECT id, nome, to_char(dn,'YYYY-MM-DD') dn,
                COALESCE(telefone,'') telefone, COALESCE(endereco,'') endereco
           FROM pront_pacientes WHERE nome ILIKE $1 ORDER BY lower(nome) LIMIT 20`,
        ["%" + q + "%"]);
      res.json(rows);
    } catch (e) {
      console.error("RECEP PAC-BUSCA ERROR", e);
      res.status(500).json([]);
    }
  });

  // ---- Documentos emitidos de um paciente (para reemitir/enviar) ----
  app.get("/secretaria/api/paciente/:id/docs", secretariaRequired, async (req, res) => {
    try {
      const id = req.params.id;
      const p = (await pool.query(
        `SELECT id, nome, COALESCE(telefone,'') telefone FROM pront_pacientes WHERE id=$1`, [id])).rows[0];
      if (!p) return res.status(404).json({ erro: "paciente não encontrado" });

      const docs = (await pool.query(
        `SELECT id, tipo, paper, assinado, secret_code, verif_token, descricao,
                to_char(criado_em,'YYYY-MM-DD') data
           FROM pront_docs_emitidos WHERE paciente_id=$1 ORDER BY criado_em DESC`, [id])).rows;

      const pubBase = (process.env.PUBLIC_BASE_URL || `${req.protocol}://${req.get("host")}`).replace(/\/+$/, "");
      const wa = waNumber(p.telefone);

      const out = docs.map((d) => {
        const label = TIPO_DOC[d.tipo] || d.tipo;
        const verifUrl = d.verif_token ? pubBase + "/verificar/" + d.verif_token : "";
        const podeCompartilhar = !!(d.assinado && d.verif_token);
        const waMsg = label + " — Dr. Leandro Mendes: " + verifUrl;
        return {
          id: d.id,
          tipo: d.tipo,
          tipoLabel: label,
          paper: safe(d.paper),
          assinado: !!d.assinado,
          data: d.data,
          descricao: safe(d.descricao),
          pdfUrl: "/pront/documento-emitido/" + d.id + "/pdf",
          verifUrl,
          waUrl: podeCompartilhar && wa
            ? "https://wa.me/" + wa + "?text=" + encodeURIComponent(waMsg)
            : "",
          podeCompartilhar,
        };
      });

      res.json({ paciente: { id: p.id, nome: p.nome, telefone: p.telefone }, docs: out });
    } catch (e) {
      console.error("RECEP DOCS ERROR", e);
      res.status(500).json({ erro: "falha ao listar documentos" });
    }
  });
}
