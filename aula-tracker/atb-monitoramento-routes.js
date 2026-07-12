// atb-monitoramento-routes.js
// ─────────────────────────────────────────────────────────────────────────
// REGRAS DE MONITORAMENTO — reavaliação contínua de fichas ao longo de uma
// janela de dias após a submissão. Diferente da triagem (pontual, no ato),
// o monitoramento re-roda periodicamente (cron 2×/dia) e captura mudanças de
// estado que chegam depois — ex.: hemocultura positiva 2 dias após a ficha.
//
// Reusa o NÚCLEO da triagem (montarContexto + avaliaCond): mesmos campos,
// mesmos gatilhos derivados (culturas/hemo/fichas_72h_*). Não duplica nada.
//
// Política de escrita por-regra (sobrescrever):
//   false → grava IrAS só se estiver VAZIO (idempotente).
//   true  → grava se vazio OU se o IrAS atual foi posto por uma REGRA
//           (triagem/monitoramento); NUNCA sobrescreve entrada MANUAL do revisor.

import { montarContexto, avaliaCond } from './atb-triagem-regras.js';

export async function ensureMonitoramentoSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atb_monitoramento_regras (
      id                  SERIAL PRIMARY KEY,
      instituicao         TEXT NOT NULL,
      nome                TEXT NOT NULL,
      descricao           TEXT,
      prioridade          INTEGER DEFAULT 100,
      ativo               BOOLEAN DEFAULT true,
      condicoes           JSONB NOT NULL,
      acao_iras           TEXT,
      acao_etiol          TEXT,
      janela_dias         INTEGER DEFAULT 14,
      sobrescrever        BOOLEAN DEFAULT false,
      created_at          TIMESTAMPTZ DEFAULT now(),
      updated_at          TIMESTAMPTZ DEFAULT now()
    )`);
  // Auditoria separada da triagem: distingue "posto por monitoramento" de
  // "posto por triagem" de "posto na mão" (ambos nulos = manual).
  await pool.query(`ALTER TABLE atb_avaliacoes ADD COLUMN IF NOT EXISTS monitor_regra_id INTEGER`);
  await pool.query(`ALTER TABLE atb_avaliacoes ADD COLUMN IF NOT EXISTS monitor_regra_at TIMESTAMPTZ`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atb_monitoramento_log (
      id            BIGSERIAL PRIMARY KEY,
      ficha_id      BIGINT,
      regra_id      INTEGER,
      instituicao   TEXT,
      iras_antes    TEXT,
      iras_depois   TEXT,
      sobrescreveu  BOOLEAN,
      executado_em  TIMESTAMPTZ DEFAULT now()
    )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS atb_monitor_log_ficha_idx ON atb_monitoramento_log(ficha_id, executado_em DESC)`);
}

// Executor: reavalia as fichas do tenant dentro da janela e aplica as regras.
export async function executarMonitoramento(pool, inst) {
  const regras = (await pool.query(
    `SELECT id, nome, condicoes, acao_iras, acao_etiol, janela_dias, sobrescrever
       FROM atb_monitoramento_regras
      WHERE ativo=true AND instituicao=$1
      ORDER BY prioridade ASC, id ASC`, [inst]
  )).rows;
  if (!regras.length) return { ok: true, regras: 0, fichas: 0, aplicadas: 0 };

  const maxJanela = Math.max(...regras.map(r => r.janela_dias || 14));
  const fichas = (await pool.query(
    `SELECT f.id
       FROM atb_fichas f
       LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
      WHERE f.deletado_em IS NULL
        AND COALESCE(i.sigla,'HUSF') = $1
        AND COALESCE(f.data_referencia,f.jotform_created_at,f.created_at) >= (now() - ($2 || ' days')::interval)`,
    [inst, String(maxJanela)]
  )).rows;

  const agora = Date.now();
  let aplicadas = 0;
  for (const { id: fichaId } of fichas) {
    try {
      const built = await montarContexto(pool, fichaId);
      if (!built) continue;
      const { f, ctx } = built;
      const refData = f.data_referencia || f.jotform_created_at || f.created_at || null;

      // 1ª regra (por prioridade) que casa E cuja janela ainda cobre esta ficha
      const regra = regras.find(r => {
        const dentro = refData ? (agora - new Date(refData).getTime()) <= (r.janela_dias || 14) * 86400000 : true;
        return dentro && avaliaCond(r.condicoes, ctx);
      });
      if (!regra) continue;

      // Estado atual da avaliação → política de sobrescrita
      const av = (await pool.query(
        'SELECT iras, triagem_regra_id, monitor_regra_id FROM atb_avaliacoes WHERE ficha_id=$1', [fichaId]
      )).rows[0];
      const irasAtual = av && av.iras != null ? String(av.iras).trim() : '';
      const vazio = irasAtual === '';
      const postoPorRegra = !!(av && (av.triagem_regra_id != null || av.monitor_regra_id != null));
      const alvo = (regra.acao_iras || '').trim();

      const podeEscrever = vazio || (regra.sobrescrever && postoPorRegra);
      if (!podeEscrever || irasAtual === alvo) continue; // protegido, ou já está no valor

      await pool.query(
        `INSERT INTO atb_avaliacoes (ficha_id, iras, etiol_iras, monitor_regra_id, monitor_regra_at, updated_at)
         VALUES ($1,$2,$3,$4, now(), now())
         ON CONFLICT (ficha_id) DO UPDATE SET
           iras = $2,
           etiol_iras = COALESCE(atb_avaliacoes.etiol_iras, $3),
           monitor_regra_id = $4,
           monitor_regra_at = now(),
           updated_at = now()`,
        [fichaId, regra.acao_iras || null, regra.acao_etiol || null, regra.id]
      );
      await pool.query(
        `INSERT INTO atb_monitoramento_log (ficha_id, regra_id, instituicao, iras_antes, iras_depois, sobrescreveu)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [fichaId, regra.id, inst, irasAtual || null, alvo || null, !vazio]
      );
      aplicadas++;
    } catch (e) { console.error('[monitor] ficha', fichaId, '-', e.message); }
  }
  console.log(`[monitor] ${inst}: ${regras.length} regra(s), ${fichas.length} ficha(s) na janela, ${aplicadas} aplicada(s)`);
  return { ok: true, regras: regras.length, fichas: fichas.length, aplicadas };
}

export function registerMonitoramentoRoutes(app, pool, adminRequired) {
  // Cron 2×/dia. Auth por token (X-Cron-Token == MONITOR_CRON_TOKEN).
  app.post('/atb/admin/monitoramento/executar', async (req, res) => {
    const tok = process.env.MONITOR_CRON_TOKEN;
    if (!tok || req.get('X-Cron-Token') !== tok) return res.status(401).json({ ok: false, error: 'token' });
    try {
      const out = {};
      for (const inst of ['HUSF', 'SCMI']) out[inst] = await executarMonitoramento(pool, inst);
      res.json({ ok: true, resultado: out });
    } catch (e) {
      console.error('[monitor] executar:', e.message);
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // Debug: últimos disparos de monitoramento (adminRequired).
  app.get('/atb/admin/monitoramento/log', adminRequired, async (req, res) => {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    try {
      const { rows } = await pool.query(
        `SELECT l.executado_em, l.ficha_id, l.iras_antes, l.iras_depois, l.sobrescreveu, r.nome
           FROM atb_monitoramento_log l LEFT JOIN atb_monitoramento_regras r ON r.id=l.regra_id
          ORDER BY l.executado_em DESC LIMIT 50`);
      res.send('Últimos disparos de monitoramento:\n\n' + rows.map(r =>
        `${r.executado_em?.toISOString?.() || r.executado_em} · ficha ${r.ficha_id} · ${r.nome || '—'} · ${r.iras_antes || '(vazio)'} → ${r.iras_depois}${r.sobrescreveu ? ' [sobrescreveu]' : ''}`
      ).join('\n'));
    } catch (e) { res.send('ERRO: ' + e.message); }
  });
}
