// ════════════════════════════════════════════════════════════════════════════
//  Duplicação de ficha para IrAS múltipla
//
//  Quando o mesmo paciente tem mais de uma IrAS na mesma internação (ex.: PAV
//  + ITU), cada infecção precisa do seu próprio registro: a etiologia e a
//  microbiologia são diferentes entre elas. Como `atb_avaliacoes` é 1:1 com a
//  ficha (ficha_id UNIQUE) e todo o resto do sistema conta COUNT(*) por classe
//  de IrAS, a saída limpa é clonar a ficha — cada cópia carrega uma infecção.
//
//  O clone guarda `ficha_origem_id` apontando para a ficha original. Isso
//  permite (a) mostrar o ícone de duplicada na grade e (b) excluir a cópia das
//  contagens que são POR SOLICITAÇÃO, não por infecção (adesão, p.ex.), já que
//  o parecer do SCIH é o mesmo para as duas.
//
//  O que NÃO é copiado:
//    • id / created_at / updated_at  → novos
//    • jotform_submission_id         → é UNIQUE e tem sonda de integridade
//                                      ("jotform_submission_id duplicado")
//    • ficha_origem_id               → definido como a ficha de origem
//
//  Da avaliação, copia só o desfecho (é o mesmo para todas as infecções da
//  internação). iras / etiol_iras / micro ficam VAZIOS: é justamente o que o
//  SCIH vai preencher diferente na cópia.
//
//  Integração em atb-routes.js:
//    import { registerFichaDuplicarRoutes } from './atb-ficha-duplicar-routes.js';
//    // em registerAtbRoutes:  registerFichaDuplicarRoutes(app, pool, adminRequired);
// ════════════════════════════════════════════════════════════════════════════

// Colunas que nunca são copiadas para a cópia.
const NAO_COPIA = new Set([
  'id',
  'created_at',
  'updated_at',
  'jotform_submission_id',
  'ficha_origem_id',
]);

// Lista de colunas reais de atb_fichas, lida do banco (não hardcoded: colunas
// novas promovidas pelo form-editor entram sozinhas).
async function colunasDeFichas(pool) {
  const { rows } = await pool.query(
    `SELECT column_name FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'atb_fichas'
      ORDER BY ordinal_position`
  );
  return rows.map((r) => r.column_name).filter((c) => !NAO_COPIA.has(c));
}

/**
 * Clona a ficha `id` para receber uma segunda IrAS.
 * Devolve { ok, novaFichaId } ou { ok:false, erro }.
 */
export async function duplicarFichaParaIras(pool, id) {
  const orig = (await pool.query(
    `SELECT id, ficha_origem_id, deletado_em FROM atb_fichas WHERE id = $1`, [id]
  )).rows[0];
  if (!orig) return { ok: false, erro: 'ficha não encontrada' };
  if (orig.deletado_em) return { ok: false, erro: 'ficha excluída' };

  // Sem cadeias: a cópia de uma cópia aponta para a ficha original.
  const origemId = orig.ficha_origem_id || orig.id;

  const cols = await colunasDeFichas(pool);
  const lista = cols.map((c) => `"${c}"`).join(', ');

  // INSERT ... SELECT: copia a linha inteira sem trafegar os dados pela aplicação.
  const ins = await pool.query(
    `INSERT INTO atb_fichas (${lista}, ficha_origem_id, created_at, updated_at)
     SELECT ${lista}, $1, now(), now()
       FROM atb_fichas WHERE id = $2
     RETURNING id`,
    [origemId, id]
  );
  const novaId = ins.rows[0].id;

  // Avaliação da cópia: só o desfecho vem junto (é o mesmo da internação).
  // A classificação de IrAS, a etiologia e a micro ficam em branco de propósito.
  await pool.query(
    `INSERT INTO atb_avaliacoes (ficha_id, desfecho_iras, desfecho_data, created_at, updated_at)
     SELECT $1, a.desfecho_iras, a.desfecho_data, now(), now()
       FROM atb_avaliacoes a WHERE a.ficha_id = $2
     ON CONFLICT (ficha_id) DO NOTHING`,
    [novaId, id]
  );

  return { ok: true, novaFichaId: novaId, origemId };
}

export function registerFichaDuplicarRoutes(app, pool, adminRequired) {
  // Cria a cópia e devolve o id da nova ficha (o cliente redireciona para ela).
  app.post('/atb/admin/fichas/:id/duplicar-iras', adminRequired, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id)) return res.status(400).json({ ok: false, erro: 'id inválido' });
    try {
      const r = await duplicarFichaParaIras(pool, id);
      if (!r.ok) return res.status(404).json(r);
      console.log(`[atb] ficha ${id} duplicada para IrAS adicional → ficha ${r.novaFichaId}`);
      res.json(r);
    } catch (e) {
      console.error('[atb] duplicar-iras:', e.message);
      res.status(500).json({ ok: false, erro: e.message });
    }
  });
}
