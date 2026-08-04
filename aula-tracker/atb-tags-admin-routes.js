// atb-tags-admin-routes.js
// ════════════════════════════════════════════════════════════════════════════
//  GERENCIAR TAGS CLÍNICAS — listar, renomear, fundir, excluir.
//
//  O vocabulário é aberto e nasce do uso, então quase-duplicata é questão de
//  tempo: `bact_dialise` digitada numa ficha e `bacteremia_dialise` vinda de
//  uma regra são a mesma coisa para quem lê, e coisas diferentes para o `@>`.
//  Sem esta tela, o vocabulário apodrece em silêncio e nada tabula.
//
//  ── DUAS FONTES, SEMPRE AS DUAS ───────────────────────────────────────────
//  Tag vive em atb_fichas.tags E em atb_triagem_regras.acoes->'tags'. Mexer só
//  nas fichas é armadilha: a regra recria a tag no próximo backfill ou na
//  próxima ficha que casar. Toda operação aqui roda nos dois lugares, na mesma
//  transação, e o relatório mostra as duas contagens.
//
//  ── RENOMEAR É FUNDIR ─────────────────────────────────────────────────────
//  Não há operação separada de fusão: renomear para um nome que já existe
//  funde, porque o jsonb_agg(DISTINCT) deduplica. A tela avisa quando o destino
//  já está em uso, para não haver fusão acidental.
//
//  ── ESCOPO ────────────────────────────────────────────────────────────────
//  O vocabulário é COMPARTILHADO entre instituições (decisão de atb-tags-routes),
//  então renomear vale para HUSF e SCMI de uma vez, inclusive nas regras das
//  duas. Isso é deliberado: dois vocabulários divergiriam sem ninguém decidir.
//
//  Integração:
//    import { registerTagsAdminRoutes } from './atb-tags-admin-routes.js';
//    registerTagsAdminRoutes(app, pool, superGate);
// ════════════════════════════════════════════════════════════════════════════

import { page } from './atb-regras-routes.js';
import { normalizar } from './atb-tags-routes.js';

const esc = (v) => String(v == null ? '' : v)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;')
  .replace(/>/g, '&gt;').replace(/"/g, '&quot;');

// acoes->'tags' pode não ser array se a regra foi salva antes do campo existir,
// ou editada à mão no banco. Sem esta guarda, jsonb_array_elements_text estoura.
const TAGS_DA_REGRA = `
  CASE WHEN jsonb_typeof(r.acoes->'tags') = 'array'
       THEN r.acoes->'tags' ELSE '[]'::jsonb END`;

export function registerTagsAdminRoutes(app, pool, soSuper) {

  async function inventario() {
    const { rows } = await pool.query(`
      WITH da_ficha AS (
        SELECT t AS tag, count(*)::int AS n
          FROM atb_fichas f, jsonb_array_elements_text(COALESCE(f.tags,'[]'::jsonb)) t
         WHERE f.deletado_em IS NULL
         GROUP BY t
      ), da_regra AS (
        SELECT t AS tag, count(*)::int AS nr,
               string_agg(r.nome, ' · ' ORDER BY r.nome) AS regras
          FROM atb_triagem_regras r, jsonb_array_elements_text(${TAGS_DA_REGRA}) t
         GROUP BY t
      )
      SELECT COALESCE(a.tag, b.tag) AS tag,
             COALESCE(a.n, 0)  AS n_fichas,
             COALESCE(b.nr, 0) AS n_regras,
             b.regras
        FROM da_ficha a FULL OUTER JOIN da_regra b ON b.tag = a.tag
       ORDER BY COALESCE(a.n,0) DESC, 1 ASC`);
    return rows;
  }

  // ── Lista ─────────────────────────────────────────────────────────────────
  app.get('/atb/admin/tags', soSuper, async (req, res) => {
    try {
      const tags = await inventario();
      const msg = req.query.msg ? `<p class="nota">${esc(req.query.msg)}</p>` : '';
      const orfas = tags.filter(t => t.n_fichas === 0).length;
      const linhas = tags.map(t => `
        <tr>
          <td><code>${esc(t.tag)}</code></td>
          <td style="text-align:right">${t.n_fichas}</td>
          <td>${t.n_regras
            ? `<span title="${esc(t.regras || '')}">${t.n_regras} regra(s)</span>`
            : '<span class="mut">—</span>'}</td>
          <td style="white-space:nowrap">
            <form method="POST" action="/atb/admin/tags/renomear" style="display:inline"
                  onsubmit="return confirm('Renomear ${esc(t.tag)}? Se o destino ja existir, as duas serao fundidas.')">
              <input type="hidden" name="de" value="${esc(t.tag)}">
              <input name="para" placeholder="novo nome" required style="width:190px">
              <button class="ghost">Renomear / fundir</button>
            </form>
            <form method="POST" action="/atb/admin/tags/excluir" style="display:inline"
                  onsubmit="return confirm('Excluir ${esc(t.tag)} de ${t.n_fichas} ficha(s)${t.n_regras ? ' e de ' + t.n_regras + ' regra(s)' : ''}? Nao ha desfazer.')">
              <input type="hidden" name="tag" value="${esc(t.tag)}">
              <button class="ghost">Excluir</button>
            </form>
          </td>
        </tr>`).join('');

      res.send(page('Tags clínicas', `
        <div class="card">
          <h1>Tags clínicas</h1>
          <p class="mut">Vocabulário aberto, construído pelo uso. Renomear para um
             nome existente <strong>funde</strong> as duas. Toda operação vale para
             fichas <em>e</em> para as regras de triagem que citam a tag — mexer só
             nas fichas faria a regra recriar a tag no próximo backfill.</p>
          ${msg}
        </div>
        <div class="card">
          <table>
            <tr><th>tag</th><th style="text-align:right">fichas</th><th>regras</th><th>ações</th></tr>
            ${linhas || '<tr><td colspan="4" class="mut">Nenhuma tag ainda.</td></tr>'}
          </table>
          ${orfas ? `<p class="nota">${orfas} tag(s) sem nenhuma ficha — só citadas em regra.</p>` : ''}
          <p style="margin-top:12px"><a class="btn ghost" href="/atb/admin/regras">Regras de triagem</a></p>
        </div>`));
    } catch (e) {
      console.error('[tags-admin] lista:', e.message);
      res.status(500).send(page('Erro', `<div class="card"><h1>Falha</h1><p class="mut">${esc(e.message)}</p></div>`));
    }
  });

  // ── Renomear / fundir ─────────────────────────────────────────────────────
  app.post('/atb/admin/tags/renomear', soSuper, async (req, res) => {
    const de = normalizar(req.body?.de || '');
    const para = normalizar(req.body?.para || '');
    if (!de || !para) return res.redirect('/atb/admin/tags?msg=' + encodeURIComponent('Nome inválido.'));
    if (de === para) return res.redirect('/atb/admin/tags?msg=' + encodeURIComponent('Origem e destino iguais.'));
    const cli = await pool.connect();
    try {
      await cli.query('BEGIN');
      // DISTINCT resolve a fusão sozinho: se a ficha já tinha as duas tags,
      // a renomeada colapsa na existente em vez de duplicar.
      const f = await cli.query(`
        UPDATE atb_fichas
           SET tags = (SELECT COALESCE(jsonb_agg(DISTINCT CASE WHEN t = $1 THEN $2 ELSE t END), '[]'::jsonb)
                         FROM jsonb_array_elements_text(tags) t),
               updated_at = now()
         WHERE deletado_em IS NULL AND tags @> jsonb_build_array($1::text)`, [de, para]);
      const r = await cli.query(`
        UPDATE atb_triagem_regras r
           SET acoes = jsonb_set(r.acoes, '{tags}',
                         (SELECT COALESCE(jsonb_agg(DISTINCT CASE WHEN t = $1 THEN $2 ELSE t END), '[]'::jsonb)
                            FROM jsonb_array_elements_text(${TAGS_DA_REGRA}) t)),
               updated_at = now()
         WHERE jsonb_typeof(r.acoes->'tags') = 'array'
           AND r.acoes->'tags' @> jsonb_build_array($1::text)`, [de, para]);
      await cli.query('COMMIT');
      res.redirect('/atb/admin/tags?msg=' + encodeURIComponent(
        `${de} → ${para}: ${f.rowCount} ficha(s) e ${r.rowCount} regra(s).`));
    } catch (e) {
      await cli.query('ROLLBACK').catch(() => {});
      console.error('[tags-admin] renomear:', e.message);
      res.status(500).send(page('Erro', `<div class="card"><h1>Falha ao renomear</h1><p class="mut">${esc(e.message)}</p></div>`));
    } finally { cli.release(); }
  });

  // ── Excluir ───────────────────────────────────────────────────────────────
  app.post('/atb/admin/tags/excluir', soSuper, async (req, res) => {
    const tag = normalizar(req.body?.tag || '');
    if (!tag) return res.redirect('/atb/admin/tags?msg=' + encodeURIComponent('Nome inválido.'));
    const cli = await pool.connect();
    try {
      await cli.query('BEGIN');
      const f = await cli.query(`
        UPDATE atb_fichas
           SET tags = (SELECT COALESCE(jsonb_agg(t), '[]'::jsonb)
                         FROM jsonb_array_elements_text(tags) t WHERE t <> $1),
               updated_at = now()
         WHERE deletado_em IS NULL AND tags @> jsonb_build_array($1::text)`, [tag]);
      // Sem tirar da regra, ela recria a tag na próxima ficha que casar.
      const r = await cli.query(`
        UPDATE atb_triagem_regras r
           SET acoes = jsonb_set(r.acoes, '{tags}',
                         (SELECT COALESCE(jsonb_agg(t), '[]'::jsonb)
                            FROM jsonb_array_elements_text(${TAGS_DA_REGRA}) t WHERE t <> $1)),
               updated_at = now()
         WHERE jsonb_typeof(r.acoes->'tags') = 'array'
           AND r.acoes->'tags' @> jsonb_build_array($1::text)`, [tag]);
      await cli.query('COMMIT');
      res.redirect('/atb/admin/tags?msg=' + encodeURIComponent(
        `${tag} removida de ${f.rowCount} ficha(s) e ${r.rowCount} regra(s).`));
    } catch (e) {
      await cli.query('ROLLBACK').catch(() => {});
      console.error('[tags-admin] excluir:', e.message);
      res.status(500).send(page('Erro', `<div class="card"><h1>Falha ao excluir</h1><p class="mut">${esc(e.message)}</p></div>`));
    } finally { cli.release(); }
  });
}
