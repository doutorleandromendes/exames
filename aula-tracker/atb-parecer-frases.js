// ════════════════════════════════════════════════════════════════════════════
//  FRASES DO PARECER — gestão viva das sugestões de especificação
//
//  Substitui o array hardcoded por uma tabela editável + página admin. A
//  especificação do parecer é gravada como TEXTO (não índice), então
//  editar/reordenar/remover frases NUNCA afeta pareceres já emitidos.
//
//  Integração em atb-routes.js:
//    import { ensureParecerFrasesTable, getParecerFrases, registerParecerFrasesRoutes }
//      from './atb-parecer-frases.js';
//    // boot:   ensureParecerFrasesTable(pool).catch(e=>console.error('[atb] frases:', e.message));
//    // rotas:  registerParecerFrasesRoutes(app, pool, adminRequired);
//    // grade:  const frasesParecer = (await getParecerFrases(pool)).map(r=>r.texto);
//    //         ${parecerGridAssets(frasesParecer)}
// ════════════════════════════════════════════════════════════════════════════

// Semente: as 29 frases originais do JotForm, na ordem original. Só é usada
// para popular a tabela na primeira vez (seed-once). Depois, a fonte viva é o banco.
export const PARECER_ESPECIFICACOES_SEED = [
  '3d (rever com resultado de urocultura)',
  '3 doses (rever com resultado de hemoculturas)',
  '3d (rever com resultado de cultura de secreção traqueal e parcial de hemoculturas)',
  '3d (rever com resultado parcial de culturas e definição diagnóstica)',
  '2d (rever com resultado parcial de culturas e definição diagnóstica)',
  '3d (rever com definição diagnóstica)',
  '2d (rever com resultado final de hemoculturas)',
  '5d (rever com resultado de culturas)',
  'Sugiro rever indicação.',
  'Sugiro rever indicação/preenchimento.',
  'Sugiro rever esquema prescrito.',
  'NOTA: Em caso de contingenciamento de estoque da droga, ressalto a possibilidade de uso de gentamicina.',
  'Tempo máximo = 5 dias',
  'Sugiro fosfomicina e rever com resultado de urocultura.',
  'Sugiro diagnóstico etiológico e terapia guiada.',
  'Sugiro [(ciprofloxacina ou gentamicina) + metronidazol].',
  'Sugiro rever esquema prescrito considerando potencial antagonismo, risco de falha clínica/microbiológica e eventos adversos.',
  'Sugiro associação de glicopeptídeo, revendo com resultado parcial de culturas e definição diagnóstica.',
  'Sugiro rever esquema prescrito. Ceftriaxone não é indicado para nenhum esquema de profilaxia cirúrgica na instituição.',
  'Sugiro rever esquema prescrito por espectro antimicrobiano inadequado de acordo com os dados clínicos informados.',
  'Sugiro rever esquema prescrito por penetração tecidual inadequada conforme dados clínicos informados.',
  'Sugiro rever esquema prescrito por risco de eventos adversos e sequelas de longo prazo conforme dados informados.',
  'Sugiro [cefazolina +/- metronidazol] por, no máximo, 3 dias.',
  'Sugiro rever dados inconsistentes na solicitação considerando potenciais implicações éticas e jurídicas da discrepância.',
  'Sugiro prosseguir investigação diagnóstica',
  'Não há evidências que embasem o uso de antibioticoterapia empírica na ausência de sepse considerando o contexto descrito na ficha. Sugiro prosseguir investigação diagnóstica.',
  'Não há evidências que embasem o uso do esquema de antibioticoterapia profilática ou preemptiva prescrito conforme a ecologia local. Sugiro profilaxia/terapia preemptiva conforme protocolo institucional.',
  'Sugiro prosseguir investigação diagnóstica/etiológica e tratamento guiado',
  'Dados inconsistentes, favor rever preenchimento.',
];

function esc(v) {
  return String(v == null ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Tabela (seed-once) ───────────────────────────────────────────────────────
export async function ensureParecerFrasesTable(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atb_parecer_frases (
      id        SERIAL PRIMARY KEY,
      texto     TEXT       NOT NULL,
      ordem     INTEGER    NOT NULL DEFAULT 0,
      ativa     BOOLEAN    NOT NULL DEFAULT true,
      criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
    )`);
  const { rows: [{ n }] } = await pool.query('SELECT COUNT(*)::int AS n FROM atb_parecer_frases');
  if (n === 0) {
    for (let i = 0; i < PARECER_ESPECIFICACOES_SEED.length; i++) {
      await pool.query(
        'INSERT INTO atb_parecer_frases (texto, ordem, ativa) VALUES ($1, $2, true)',
        [PARECER_ESPECIFICACOES_SEED[i], i]
      );
    }
    console.log(`[atb] atb_parecer_frases semeada com ${PARECER_ESPECIFICACOES_SEED.length} frases`);
  }
}

// ── Leitura (fonte viva) ─────────────────────────────────────────────────────
// Por padrão retorna só as ativas, na ordem definida. {todas:true} traz tudo.
export async function getParecerFrases(pool, { todas = false } = {}) {
  try {
    const where = todas ? '' : 'WHERE ativa = true';
    const { rows } = await pool.query(
      `SELECT id, texto, ordem, ativa FROM atb_parecer_frases ${where} ORDER BY ordem ASC, id ASC`);
    return rows;
  } catch {
    // fallback defensivo: se a tabela ainda não existir, devolve a semente
    return PARECER_ESPECIFICACOES_SEED.map((texto, i) => ({ id: -1 - i, texto, ordem: i, ativa: true }));
  }
}

// ── Página admin (server-rendered, sem JS) ───────────────────────────────────
function pagina(frases) {
  const linhas = frases.map((f, i) => {
    const cls = f.ativa ? '' : ' style="opacity:.5"';
    return `
    <tr${cls}>
      <td class="num">${i + 1}</td>
      <td>
        <form method="post" action="/atb/admin/parecer-frases/${f.id}/salvar" class="rowform">
          <textarea name="texto" rows="2">${esc(f.texto)}</textarea>
          <button class="btn sm" type="submit">Salvar</button>
        </form>
      </td>
      <td class="acoes">
        <form method="post" action="/atb/admin/parecer-frases/${f.id}/mover?dir=up" class="inl"><button class="btn ic" title="Subir">↑</button></form>
        <form method="post" action="/atb/admin/parecer-frases/${f.id}/mover?dir=down" class="inl"><button class="btn ic" title="Descer">↓</button></form>
        <form method="post" action="/atb/admin/parecer-frases/${f.id}/toggle" class="inl"><button class="btn ic" title="${f.ativa ? 'Desativar' : 'Ativar'}">${f.ativa ? '◉' : '○'}</button></form>
        <form method="post" action="/atb/admin/parecer-frases/${f.id}/excluir" class="inl" onsubmit="return confirm('Excluir esta frase?')"><button class="btn ic del" title="Excluir">✕</button></form>
      </td>
    </tr>`;
  }).join('');

  return `<!DOCTYPE html><html lang="pt-BR"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Frases do Parecer</title>
<style>
  :root{ --pri:#0c447c; --bg:#f4f6f9; --line:#e3e7ee; --mut:#5f6368; }
  *{box-sizing:border-box} body{margin:0;background:var(--bg);font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;color:#1f2733}
  .wrap{max-width:900px;margin:0 auto;padding:24px 18px 60px}
  h1{font-size:22px;margin:0 0 2px} .sub{color:var(--mut);margin:0 0 20px}
  a.voltar{color:var(--pri);text-decoration:none;font-size:14px}
  .card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:18px}
  table{width:100%;border-collapse:collapse} td{border-top:1px solid var(--line);padding:8px 6px;vertical-align:top}
  tr:first-child td{border-top:0}
  .num{color:var(--mut);width:28px;text-align:right;padding-top:14px}
  textarea{width:100%;border:1px solid var(--line);border-radius:8px;padding:8px;font:14px/1.45 inherit;resize:vertical}
  .rowform{display:flex;gap:8px;align-items:flex-start}
  .acoes{white-space:nowrap;width:1%} .inl{display:inline}
  .btn{border:1px solid var(--line);background:#fff;border-radius:8px;padding:6px 10px;cursor:pointer;font-size:13px;color:#1f2733}
  .btn.sm{padding:6px 12px;background:var(--pri);color:#fff;border-color:var(--pri)}
  .btn.ic{padding:5px 8px;margin-left:2px;min-width:30px}
  .btn.del{color:#b3261e;border-color:#f0c9c5}
  .addform{display:flex;gap:8px;align-items:flex-start}
  .addform textarea{min-height:46px}
</style></head><body>
<div class="wrap">
  <a class="voltar" href="/atb/admin/grid">← Grade</a>
  <h1>Frases do Parecer</h1>
  <p class="sub">Sugestões de especificação que aparecem no editor de parecer. Editar, reordenar ou desativar aqui não altera pareceres já emitidos (a especificação é gravada como texto).</p>

  <div class="card">
    <form method="post" action="/atb/admin/parecer-frases/nova" class="addform">
      <textarea name="texto" rows="2" placeholder="Nova frase de sugestão…" required></textarea>
      <button class="btn sm" type="submit">Adicionar</button>
    </form>
  </div>

  <div class="card">
    <table><tbody>${linhas || '<tr><td class="sub">Nenhuma frase cadastrada.</td></tr>'}</tbody></table>
  </div>
</div></body></html>`;
}

// ── Rotas ────────────────────────────────────────────────────────────────────
export function registerParecerFrasesRoutes(app, pool, authRequired) {
  const soSuper = [authRequired, (req, res, next) => {
    if (req.user?.super_admin || req.cookies?.adm === '1') return next();
    res.status(403).send('Acesso restrito ao administrador.');
  }];
  const back = (res) => res.redirect('/atb/admin/parecer-frases');

  app.get('/atb/admin/parecer-frases', soSuper, async (req, res) => {
    try {
      const frases = await getParecerFrases(pool, { todas: true });
      res.send(pagina(frases));
    } catch (e) { res.status(500).send('Erro: ' + e.message); }
  });

  app.post('/atb/admin/parecer-frases/nova', soSuper, async (req, res) => {
    const texto = String(req.body?.texto || '').trim();
    if (texto) {
      const { rows: [{ m }] } = await pool.query('SELECT COALESCE(MAX(ordem),-1)::int AS m FROM atb_parecer_frases');
      await pool.query('INSERT INTO atb_parecer_frases (texto, ordem, ativa) VALUES ($1,$2,true)', [texto, m + 1]);
    }
    back(res);
  });

  app.post('/atb/admin/parecer-frases/:id/salvar', soSuper, async (req, res) => {
    const texto = String(req.body?.texto || '').trim();
    if (texto) await pool.query('UPDATE atb_parecer_frases SET texto=$1 WHERE id=$2', [texto, parseInt(req.params.id, 10)]);
    back(res);
  });

  app.post('/atb/admin/parecer-frases/:id/toggle', soSuper, async (req, res) => {
    await pool.query('UPDATE atb_parecer_frases SET ativa = NOT ativa WHERE id=$1', [parseInt(req.params.id, 10)]);
    back(res);
  });

  app.post('/atb/admin/parecer-frases/:id/excluir', soSuper, async (req, res) => {
    await pool.query('DELETE FROM atb_parecer_frases WHERE id=$1', [parseInt(req.params.id, 10)]);
    back(res);
  });

  app.post('/atb/admin/parecer-frases/:id/mover', soSuper, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const dir = req.query.dir === 'up' ? 'up' : 'down';
    const { rows } = await pool.query('SELECT id, ordem FROM atb_parecer_frases ORDER BY ordem ASC, id ASC');
    const idx = rows.findIndex(r => r.id === id);
    const swapIdx = dir === 'up' ? idx - 1 : idx + 1;
    if (idx >= 0 && swapIdx >= 0 && swapIdx < rows.length) {
      const a = rows[idx], b = rows[swapIdx];
      // garante ordens distintas antes de trocar (caso haja empate herdado)
      if (a.ordem === b.ordem) { a.ordem = idx; b.ordem = swapIdx; }
      await pool.query('UPDATE atb_parecer_frases SET ordem=$1 WHERE id=$2', [b.ordem, a.id]);
      await pool.query('UPDATE atb_parecer_frases SET ordem=$1 WHERE id=$2', [a.ordem, b.id]);
    }
    back(res);
  });
}
