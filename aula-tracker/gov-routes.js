// gov-routes.js
// ──────────────────────────────────────────────────────────────────────────
// Painel de Governança — rotas.
//
// Registro em app.js (após registerPavRoutes):
//   import { registerGovRoutes } from './gov-routes.js';
//   registerGovRoutes(app, pool, gestaoRequired, renderShell);
//
// LEITURA  (sessão + papel `gestao`):  GET /gov, /gov/api/dados[/AAAA-MM]
// ESCRITA  (chave de máquina):         POST /gov/api/publicar
//
// A escrita não usa sessão porque quem chama é o pipeline, não uma pessoa.
// Mesmo desenho do CVE_API_KEY em atb-cve-routes.js, com duas diferenças:
//   · a chave é obrigatória (sem GOV_API_KEY, a rota responde 503 e não 'aberto');
//   · a comparação é em tempo constante.
//
// O corpo é parseado pelo express.json global do app (limite 2 MB); a
// competência tem ~20 kB. Não há parser próprio aqui de propósito.
// ──────────────────────────────────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Campos que jamais podem existir num payload publicado. Redundante com o
// testes.py do pipeline, e de propósito: a verificação local pode ser pulada
// com --sem-testes, esta não pode.
const CAMPOS_PROIBIDOS =
  /"(paciente|prontuario|prontu[áa]rio|atendimento|medico|m[ée]dico|cpf|nome_completo|data_nasc)"/i;

function chaveValida(req) {
  const esperada = process.env.GOV_API_KEY || '';
  if (!esperada) return null;                       // não configurada
  const enviada = req.get('X-Gov-Key')
    || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const a = Buffer.from(String(enviada));
  const b = Buffer.from(esperada);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export function registerGovRoutes(app, pool, gestaoRequired, renderShell) {

  const inst = req => String(req.atbTenant || req.query.inst || 'HUSF');

  // O gestaoRequired zera req.user quando a entrada é por break-glass (cookie
  // adm, ADMIN_SECRET). Sem registrar a via, esse acesso ficaria com usuario_id
  // nulo e indistinguível de um nulo por defeito — inaceitável num painel cujo
  // log de leitura é peça de governança.
  function registrarAcesso(req, competencia) {
    const via = req.cookies?.adm === '1' && !req.user?.id ? 'break-glass' : 'sessao';
    pool.query(
      `INSERT INTO gov_acesso_log (usuario_id, competencia, rota, ip, via)
       VALUES ($1,$2,$3,$4,$5)`,
      [req.user?.id ?? null, competencia, req.originalUrl, req.ip, via]
    ).catch(() => { /* log nunca derruba a requisição */ });
  }

  // ---------- publicação (máquina) ----------
  app.post('/gov/api/publicar', async (req, res) => {
    const ok = chaveValida(req);
    if (ok === null) return res.status(503).json({ erro: 'GOV_API_KEY não configurada' });
    if (!ok) return res.status(401).json({ erro: 'não autorizado' });

    const p = req.body;
    if (!p || !Array.isArray(p.meses) || !p.meses.length)
      return res.status(400).json({ erro: 'payload sem a chave meses' });
    if (CAMPOS_PROIBIDOS.test(JSON.stringify(p)))
      return res.status(422).json({ erro: 'payload contém campo identificável; publicação recusada' });

    const competencia = p.meses[p.meses.length - 1];
    if (!/^\d{4}-\d{2}$/.test(competencia))
      return res.status(400).json({ erro: 'última competência fora do formato AAAA-MM' });

    try {
      await pool.query(
        `INSERT INTO gov_competencia (competencia, publicado_por, origem, instituicao, payload)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (competencia) DO UPDATE
           SET payload = EXCLUDED.payload,
               origem = EXCLUDED.origem,
               publicado_por = EXCLUDED.publicado_por,
               gerado_em = now()`,
        [competencia,
         req.get('X-Gov-Autor') || 'pipeline',
         (p.meta?.fontes || []).join('; '),
         String(req.get('X-Gov-Inst') || 'HUSF'),
         p]);
      res.json({ ok: true, competencia, competencias: p.meses.length });
    } catch (e) {
      console.error('gov publicar', e);
      res.status(500).json({ erro: 'falha ao gravar a competência' });
    }
  });

  // ---------- leitura (pessoas) ----------
  app.get('/gov/api/dados', gestaoRequired, async (req, res) => {
    try {
      const { rows } = await pool.query(
        `SELECT competencia, gerado_em, payload
           FROM gov_competencia
          WHERE instituicao = $1
          ORDER BY competencia DESC LIMIT 1`, [inst(req)]);
      if (!rows.length) return res.status(404).json({ erro: 'nenhuma competência publicada' });
      registrarAcesso(req, rows[0].competencia);
      res.set('Cache-Control', 'no-store, private');
      res.json(rows[0].payload);
    } catch (e) {
      console.error('gov dados', e);
      res.status(500).json({ erro: 'falha ao ler a competência' });
    }
  });

  app.get('/gov/api/dados/:competencia', gestaoRequired, async (req, res) => {
    if (!/^\d{4}-\d{2}$/.test(req.params.competencia))
      return res.status(400).json({ erro: 'competência no formato AAAA-MM' });
    try {
      const { rows } = await pool.query(
        `SELECT payload FROM gov_competencia WHERE competencia = $1 AND instituicao = $2`,
        [req.params.competencia, inst(req)]);
      if (!rows.length) return res.status(404).json({ erro: 'competência não publicada' });
      registrarAcesso(req, req.params.competencia);
      res.set('Cache-Control', 'no-store, private');
      res.json(rows[0].payload);
    } catch (e) {
      console.error('gov dados competencia', e);
      res.status(500).json({ erro: 'falha ao ler a competência' });
    }
  });

  app.get('/gov/api/competencias', gestaoRequired, async (req, res) => {
    try {
      const { rows } = await pool.query(
        `SELECT competencia, gerado_em, origem FROM gov_competencia
          WHERE instituicao = $1 ORDER BY competencia DESC`, [inst(req)]);
      res.json(rows);
    } catch (e) {
      console.error('gov competencias', e);
      res.status(500).json({ erro: 'falha ao listar competências' });
    }
  });

  // ---------- painel ----------
  app.get('/gov', gestaoRequired, (req, res) => {
    let html;
    try {
      html = fs.readFileSync(path.join(__dirname, 'gov-painel.html'), 'utf8');
    } catch {
      return res.status(500).send(renderShell('Painel indisponível',
        `<div class="card"><h1>Painel indisponível</h1>
         <p class="mut">O arquivo gov-painel.html não foi encontrado no servidor.</p>
         <a href="/inicio">Início</a></div>`));
    }
    res.set({
      'Cache-Control': 'no-store, private',
      'X-Robots-Tag': 'noindex, nofollow, noarchive'
    });
    res.type('html').send(html);
  });
}
