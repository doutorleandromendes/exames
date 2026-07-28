// pav-import-routes.js
// ──────────────────────────────────────────────────────────────────────────
// Entrada de dados por PAPEL (OCR/OMR de smartphone) → grid do PAV.
//
// O app /pav/scan lê a folha no aparelho (visão em JS puro, offline) e envia
// aqui um JSON já decodificado. Este módulo é a COSTURA: transforma células
// lidas em pav_checks, com proveniência (origem='papel', lote_id) e disciplina
// de idempotência.
//
// IDEMPOTÊNCIA (reler a mesma folha é seguro — o requisito central):
//   A chave natural (ficha, data, turno, categoria) já é UNIQUE. Para cada
//   célula recebida comparamos com o que já existe:
//     • não existe        → INSERE (novo dado)
//     • existe e IGUAL     → no-op (ignorado)
//     • existe e DIVERGE   → NÃO sobrescreve; registra a divergência no lote
//                            para o SCIH decidir (o digital "ao vivo" tem
//                            precedência sobre uma releitura de papel).
//
// Um lote = uma folha-semana escaneada. Nasce 'pendente' e o SCIH confere.
//
//    registerPavImportRoutes(app, pool, pavRequired, renderShell, scihRequired);
// ──────────────────────────────────────────────────────────────────────────
import { REGISTRO, TURNOS } from './pav-core.js';

const KEYS = new Set(REGISTRO.map(r => r.key));
const TURNOS_VALIDOS = new Set(TURNOS.map(t => t.turno));   // 'D','N'
const CATS = new Set(['fisio', 'enf']);

// Normaliza o valor factual de uma célula para comparação estável.
// (sim/não → 'sim'|'nao'; número → Number; secreção → aspecto)
function valorCanonico(item) {
  if (item == null) return null;
  if (typeof item.resp === 'string') return item.resp.toLowerCase();
  if (item.valor != null && item.valor !== '') return String(Number(item.valor));
  if (typeof item === 'string') return item.toLowerCase();
  return null;
}

// Compara o conjunto factual de dois checks (só as chaves presentes no novo).
function divergem(itensNovos, itensExistentes) {
  for (const [k, v] of Object.entries(itensNovos)) {
    const a = valorCanonico(v);
    const b = valorCanonico(itensExistentes?.[k]);
    if (a == null) continue;                 // não afirma nada sobre esta chave
    if (b != null && a !== b) return true;
  }
  return false;
}

export function registerPavImportRoutes(app, pool, pavRequired, renderShell, scihRequired) {
  const confGuard = scihRequired || pavRequired;

  // ── fichas ativas (o app escolhe o paciente; o prontuário-crop só ajuda) ──
  app.get('/pav/api/fichas-ativas', pavRequired, async (req, res) => {
    try {
      const inst = req.user?.instituicao_id;
      const { rows } = await pool.query(`
        SELECT f.id, f.prontuario, f.paciente, f.leito, f.salao, f.data_intubacao
          FROM pav_fichas f
         WHERE f.instituicao_id = $1 AND f.estado IN ('ativo','extubacao_pendente')
         ORDER BY f.salao, f.leito`, [inst]);
      res.json({ fichas: rows });
    } catch (e) { res.status(500).json({ erro: 'falha ao listar fichas' }); }
  });

  // ── importação de uma folha-semana lida ──────────────────────────────────
  // body: { ficha_id, semana_ini, origem_app, celulas: [ { data, turno,
  //         categoria, itens:{key:{resp|valor|...}}, hora } ] }
  app.post('/pav/api/import', pavRequired, async (req, res) => {
    const b = req.body || {};
    const fichaId = Number(b.ficha_id);
    if (!fichaId) return res.status(400).json({ erro: 'ficha_id obrigatório' });
    if (!Array.isArray(b.celulas) || !b.celulas.length)
      return res.status(400).json({ erro: 'nenhuma célula para importar' });

    const inst = req.user?.instituicao_id;
    const uid = req.user?.id ?? null;
    const unome = req.user?.full_name ?? null;

    const client = await pool.connect();
    try {
      // a ficha existe e é desta instituição?
      const fq = await client.query(
        `SELECT id FROM pav_fichas WHERE id = $1 AND instituicao_id = $2`, [fichaId, inst]);
      if (!fq.rowCount) { client.release(); return res.status(404).json({ erro: 'ficha não encontrada' }); }

      await client.query('BEGIN');
      const lote = await client.query(`
        INSERT INTO pav_lotes (instituicao_id, ficha_id, criado_por, criado_por_nome, semana_ini, estado)
        VALUES ($1,$2,$3,$4,$5,'pendente') RETURNING id`,
        [inst, fichaId, uid, unome, b.semana_ini || null]);
      const loteId = lote.rows[0].id;

      const resumo = { inseridos: 0, ignorados: 0, divergencias: [], rejeitados: [] };

      for (const cel of b.celulas) {
        const data = String(cel.data || '').slice(0, 10);
        const turno = String(cel.turno || '');
        const categoria = String(cel.categoria || '');
        if (!/^\d{4}-\d{2}-\d{2}$/.test(data) || !TURNOS_VALIDOS.has(turno) || !CATS.has(categoria)) {
          resumo.rejeitados.push({ data, turno, categoria, motivo: 'coordenada inválida' });
          continue;
        }
        // filtra itens a chaves conhecidas e não-nulas
        const itens = {};
        for (const [k, v] of Object.entries(cel.itens || {})) {
          if (KEYS.has(k) && valorCanonico(v) != null) itens[k] = v;
        }
        if (!Object.keys(itens).length) { resumo.ignorados++; continue; }

        const ex = await client.query(
          `SELECT id, itens, origem FROM pav_checks
            WHERE ficha_id=$1 AND data=$2 AND turno=$3 AND categoria=$4`,
          [fichaId, data, turno, categoria]);

        if (!ex.rowCount) {
          await client.query(`
            INSERT INTO pav_checks
              (ficha_id, instituicao_id, data, turno, categoria, itens,
               preenchido_por, preenchido_por_nome, origem, lote_id, hora_papel)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'papel',$9,$10)`,
            [fichaId, inst, data, turno, categoria, JSON.stringify(itens),
             uid, unome, loteId, cel.hora || null]);
          resumo.inseridos++;
        } else {
          const atual = ex.rows[0].itens || {};
          if (divergem(itens, atual)) {
            // NÃO sobrescreve: registra a divergência para conferência
            resumo.divergencias.push({
              data, turno, categoria,
              origem_atual: ex.rows[0].origem,
              novo: itens, atual,
            });
          } else {
            resumo.ignorados++;               // igual → no-op idempotente
          }
        }
      }

      // log das amostras de OCR (auditoria + dataset de treino da caligrafia local)
      if (Array.isArray(b.ocr_amostras)) {
        for (const a of b.ocr_amostras.slice(0, 400)) {   // teto de segurança
          await client.query(`
            INSERT INTO pav_ocr_amostras
              (instituicao_id, lote_id, check_key, data, turno, recorte_png,
               valor_ocr, confianca, valor_final, revisado)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
            [inst, loteId, String(a.key || '').slice(0, 20), a.data || null, a.turno || null,
             String(a.png || '').slice(0, 60000), String(a.valor_ocr ?? '').slice(0, 10),
             Number(a.conf) || 0, String(a.valor_final ?? '').slice(0, 10), !!a.revisado]);
        }
        resumo.ocr_amostras = b.ocr_amostras.length;
      }

      await client.query(`UPDATE pav_lotes SET resumo=$1 WHERE id=$2`,
        [JSON.stringify(resumo), loteId]);
      await client.query('COMMIT');
      res.json({ ok: true, lote_id: loteId, resumo });
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      res.status(500).json({ erro: 'falha na importação' });
    } finally {
      client.release();
    }
  });

  // ── fila de lotes pendentes (conferência do SCIH) ─────────────────────────
  app.get('/pav/admin/lotes', confGuard, async (req, res) => {
    try {
      const inst = req.user?.instituicao_id;
      const { rows } = await pool.query(`
        SELECT l.id, l.semana_ini, l.estado, l.criado_em, l.criado_por_nome,
               l.resumo, f.paciente, f.leito, f.salao
          FROM pav_lotes l
          LEFT JOIN pav_fichas f ON f.id = l.ficha_id
         WHERE l.instituicao_id = $1
         ORDER BY (l.estado='pendente') DESC, l.criado_em DESC
         LIMIT 100`, [inst]);
      res.json({ lotes: rows });
    } catch (e) { res.status(500).json({ erro: 'falha ao listar lotes' }); }
  });

  // ── confirmar um lote (marca conferido) ───────────────────────────────────
  app.post('/pav/admin/lotes/:id/conferir', confGuard, async (req, res) => {
    try {
      const inst = req.user?.instituicao_id;
      const id = Number(req.params.id);
      const r = await pool.query(`
        UPDATE pav_lotes SET estado='conferido', conferido_por=$1, conferido_em=now()
         WHERE id=$2 AND instituicao_id=$3 AND estado='pendente' RETURNING id`,
        [req.user?.id ?? null, id, inst]);
      if (!r.rowCount) return res.status(404).json({ erro: 'lote não encontrado ou já conferido' });
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ erro: 'falha ao conferir' }); }
  });
}
