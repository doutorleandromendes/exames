// ════════════════════════════════════════════════════════════════════════════
//  atb-integridade.js — monitoramento de INTEGRIDADE dos dados + importações
//  Irmão do atb-healthcheck.js: enquanto aquele vigia o PIPELINE do formulário
//  ("Sistema NORMAL/SUSPENSO"), este vigia os DADOS já gravados — com foco na
//  saúde das importações do JotForm. Cada check é uma sonda SQL com limite e
//  severidade; um check que estoura o esperado acende o painel.
//
//  Nasceu do incidente de 2026-07: a carga histórica trouxe só o núcleo do
//  Tables e a camada de submission (peso ao nascimento, história, culturas…)
//  nunca aterrissou — payload_raw NULL foi a impressão digital, e ninguém viu
//  por meses. Os checks abaixo teriam gritado no dia. O carro-chefe é
//  "neonato sem peso ao nascimento" (obrigatório na ficha) e "camada de
//  submission vazia" (assinatura de import quebrado).
//
//  Cada sonda roda em try/catch isolado: se referenciar coluna/tabela que sumiu,
//  ela mesma reporta o erro (isso É o sinal de drift) sem derrubar o painel.
//
//  Wire (junto do healthcheck, em registerAtbRoutes):
//    import { ensureIntegridadeTable, startIntegridadeSchedule, registerIntegridadeRoutes } from './atb-integridade.js';
//    ensureIntegridadeTable(pool).then(() => startIntegridadeSchedule(pool)).catch(e => console.error('[atb] integridade:', e.message));
//    registerIntegridadeRoutes(app, pool, adminRequired);
//  Opcional, embutir o card no /consulta ou no painel do healthcheck:
//    import { getLatestIntegridade, renderIntegridadeCard } from './atb-integridade.js';
//    const it = await getLatestIntegridade(pool).catch(() => null);
//    ...renderIntegridadeCard(it)...
// ════════════════════════════════════════════════════════════════════════════
import { envTenant } from './atb-tenant.js';

const SETOR_NEO = 'UTI Neo / Infantil';

// Colunas/tabelas críticas de que o sistema depende. Ausência = drift estrutural
// (o quase-incidente do `iras`: código espera coluna que o banco não tem).
const COLUNAS_CRITICAS = {
  atb_fichas: ['jotform_submission_id', 'payload_raw', 'editado_em', 'setor',
               'peso_nascimento', 'historia_clinica', 'foco_infeccao',
               'culturas_colhidas', 'atb_solicitado', 'instituicao_id'],
  atb_avaliacoes: ['ficha_id', 'iras'],
};

const num = async (pool, sql, params = []) => {
  const { rows } = await pool.query(sql, params);
  const v = rows[0] ? Object.values(rows[0])[0] : null;
  return v == null ? null : Number(v);
};

// ── Bateria de sondas ────────────────────────────────────────────────────────
// Cada sonda: { nome, categoria, severidade, run(ctx) → { ok, valor, limite, detalhe, sql } }
// severidade: 'critico' (derruba o ok geral) | 'aviso' | 'info'
function sondas() {
  return [
    // ═══ IMPORTAÇÃO JOTFORM ═══════════════════════════════════════════════════
    {
      nome: 'payload_raw ausente em fichas recentes',
      categoria: 'Importação JotForm', severidade: 'critico',
      async run({ pool, instId }) {
        const v = await num(pool,
          `SELECT count(*) FROM atb_fichas
            WHERE instituicao_id = $1 AND jotform_submission_id IS NOT NULL
              AND created_at > now() - interval '30 days' AND payload_raw IS NULL`, [instId]);
        return { ok: v === 0, valor: v, limite: '0',
          detalhe: v ? `${v} fichas importadas nos últimos 30d sem o JotForm cru — a persistência do raw regrediu (foi ISSO que causou o incidente).` : 'Toda importação recente guardou o payload cru.',
          sql: `SELECT id, jotform_submission_id, created_at FROM atb_fichas WHERE instituicao_id=${instId} AND jotform_submission_id IS NOT NULL AND created_at > now()-interval '30 days' AND payload_raw IS NULL ORDER BY created_at DESC;` };
      },
    },
    {
      nome: 'Camada de submission vazia (assinatura de parse-gap)',
      categoria: 'Importação JotForm', severidade: 'aviso',
      async run({ pool, instId }) {
        // Ficha com pedido de ATB mas SEM nenhum campo clínico do formulário.
        const v = await num(pool,
          `SELECT count(*) FROM atb_fichas
            WHERE instituicao_id = $1 AND atb_solicitado <> '[]'::jsonb
              AND (historia_clinica IS NULL OR historia_clinica = '')
              AND foco_infeccao IS NULL
              AND (culturas_colhidas IS NULL OR culturas_colhidas = '{}'::jsonb)`, [instId]);
        const LIM = 50;
        return { ok: v <= LIM, valor: v, limite: `≤ ${LIM}`,
          detalhe: v > LIM ? `${v} fichas têm pedido de ATB mas nenhum campo clínico — sinal de import trazendo só o núcleo do Tables.` : 'Camada clínica presente onde deveria.',
          sql: `SELECT id, jotform_submission_id FROM atb_fichas WHERE instituicao_id=${instId} AND atb_solicitado <> '[]'::jsonb AND (historia_clinica IS NULL OR historia_clinica='') AND foco_infeccao IS NULL AND (culturas_colhidas IS NULL OR culturas_colhidas='{}'::jsonb) LIMIT 200;` };
      },
    },
    {
      nome: 'Frescor do sync (última importação bem-sucedida)',
      categoria: 'Importação JotForm', severidade: 'aviso',
      async run({ pool, instId }) {
        const h = await num(pool,
          `SELECT extract(epoch from now() - max(created_at)) / 3600
             FROM atb_sync_log WHERE instituicao_id = $1 AND status = 'ok'`, [instId]);
        const LIM = 48;
        if (h == null) return { ok: true, valor: 'sem registro', limite: `< ${LIM}h`,
          detalhe: 'Nenhum sync registrado ainda (ou log limpo).', sql: `SELECT max(created_at) FROM atb_sync_log WHERE instituicao_id=${instId} AND status='ok';` };
        return { ok: h < LIM, valor: `${h.toFixed(1)}h`, limite: `< ${LIM}h`,
          detalhe: h >= LIM ? `Sem importação bem-sucedida há ${h.toFixed(1)}h — o pipeline pode estar parado.` : 'Pipeline de importação ativo.',
          sql: `SELECT * FROM atb_sync_log WHERE instituicao_id=${instId} ORDER BY created_at DESC LIMIT 20;` };
      },
    },
    {
      nome: 'jotform_submission_id duplicado',
      categoria: 'Importação JotForm', severidade: 'critico',
      async run({ pool }) {
        const v = await num(pool,
          `SELECT count(*) FROM (SELECT jotform_submission_id FROM atb_fichas
             WHERE jotform_submission_id IS NOT NULL GROUP BY 1 HAVING count(*) > 1) x`);
        return { ok: v === 0, valor: v, limite: '0',
          detalhe: v ? `${v} submission_ids aparecem em mais de uma ficha (a UNIQUE deveria impedir).` : 'Sem duplicatas de submissão.',
          sql: `SELECT jotform_submission_id, count(*) FROM atb_fichas WHERE jotform_submission_id IS NOT NULL GROUP BY 1 HAVING count(*)>1;` };
      },
    },

    // ═══ CAMPOS OBRIGATÓRIOS ══════════════════════════════════════════════════
    {
      nome: 'Neonato sem peso ao nascimento',   // ← O check que teria pego o incidente
      categoria: 'Campos obrigatórios', severidade: 'critico',
      async run({ pool, instId }) {
        const total = await num(pool,
          `SELECT count(*) FROM atb_fichas WHERE instituicao_id=$1 AND setor=$2 AND jotform_submission_id IS NOT NULL`, [instId, SETOR_NEO]);
        const sem = await num(pool,
          `SELECT count(*) FROM atb_fichas WHERE instituicao_id=$1 AND setor=$2
             AND jotform_submission_id IS NOT NULL AND peso_nascimento IS NULL`, [instId, SETOR_NEO]);
        const pct = total ? (100 * sem / total) : 0;
        const LIM = 5;  // tolera resíduo pequeno (fichas legítimas sem o campo no dump)
        return { ok: pct <= LIM, valor: `${sem}/${total} (${pct.toFixed(1)}%)`, limite: `≤ ${LIM}%`,
          detalhe: pct > LIM ? `${sem} fichas neonatais sem peso ao nascimento (obrigatório na ficha) — mesma assinatura do incidente de 2026-07.` : 'Peso ao nascimento presente na quase totalidade das fichas neonatais.',
          sql: `SELECT id, jotform_submission_id FROM atb_fichas WHERE instituicao_id=${instId} AND setor='${SETOR_NEO}' AND jotform_submission_id IS NOT NULL AND peso_nascimento IS NULL;` };
      },
    },
    {
      nome: 'Ficha importada sem setor',
      categoria: 'Campos obrigatórios', severidade: 'aviso',
      async run({ pool, instId }) {
        const v = await num(pool,
          `SELECT count(*) FROM atb_fichas WHERE instituicao_id=$1
             AND jotform_submission_id IS NOT NULL AND (setor IS NULL OR setor='')`, [instId]);
        return { ok: v === 0, valor: v, limite: '0',
          detalhe: v ? `${v} fichas importadas sem setor (obrigatório e usado no roteamento).` : 'Setor presente em todas as fichas importadas.',
          sql: `SELECT id, jotform_submission_id FROM atb_fichas WHERE instituicao_id=${instId} AND jotform_submission_id IS NOT NULL AND (setor IS NULL OR setor='');` };
      },
    },

    // ═══ ESTRUTURA / CONSISTÊNCIA ═════════════════════════════════════════════
    {
      nome: 'Colunas críticas ausentes (drift código × banco)',
      categoria: 'Estrutura', severidade: 'critico',
      async run({ pool }) {
        const { rows } = await pool.query(
          `SELECT table_name, column_name FROM information_schema.columns
            WHERE table_name = ANY($1)`, [Object.keys(COLUNAS_CRITICAS)]);
        const existe = new Set(rows.map(r => r.table_name + '.' + r.column_name));
        const faltando = [];
        for (const [t, cols] of Object.entries(COLUNAS_CRITICAS))
          for (const c of cols) if (!existe.has(t + '.' + c)) faltando.push(t + '.' + c);
        return { ok: faltando.length === 0, valor: faltando.length ? faltando.join(', ') : 'todas presentes', limite: '0',
          detalhe: faltando.length ? `Coluna esperada pelo código não existe no banco: ${faltando.join(', ')}. Um CREATE TABLE IF NOT EXISTS não adiciona coluna a tabela já existente — precisa de ALTER.` : 'Todas as colunas críticas existem.',
          sql: `SELECT table_name, column_name FROM information_schema.columns WHERE table_name IN ('atb_fichas','atb_avaliacoes') ORDER BY 1,2;` };
      },
    },
    {
      nome: 'Avaliações órfãs (sem ficha)',
      categoria: 'Estrutura', severidade: 'aviso',
      async run({ pool }) {
        const v = await num(pool,
          `SELECT count(*) FROM atb_avaliacoes a LEFT JOIN atb_fichas f ON f.id = a.ficha_id WHERE f.id IS NULL`);
        return { ok: v === 0, valor: v, limite: '0',
          detalhe: v ? `${v} avaliações apontam para ficha inexistente.` : 'Toda avaliação tem ficha correspondente.',
          sql: `SELECT a.id, a.ficha_id FROM atb_avaliacoes a LEFT JOIN atb_fichas f ON f.id=a.ficha_id WHERE f.id IS NULL;` };
      },
    },
  ];
}

// ── Execução ─────────────────────────────────────────────────────────────────
export async function runIntegridade(pool, inst = 'HUSF') {
  let instId = null;
  try {
    const { rows: [r] } = await pool.query('SELECT id FROM atb_instituicoes WHERE sigla=$1', [inst]);
    instId = r ? r.id : null;
  } catch { /* segue com instId null; sondas tenant-scoped reportam erro */ }

  const ctx = { pool, inst, instId };
  const detalhe = [];
  for (const s of sondas()) {
    const base = { nome: s.nome, categoria: s.categoria, severidade: s.severidade };
    try {
      const r = await s.run(ctx);
      detalhe.push({ ...base, ...r });
    } catch (e) {
      // Erro na sonda = sinal (tabela/coluna sumiu, etc.), não falha silenciosa.
      detalhe.push({ ...base, ok: false, valor: 'erro', limite: '—',
        detalhe: 'Sonda falhou: ' + e.message + ' (possível drift estrutural).', sql: '' });
    }
  }
  const passed = detalhe.filter(d => d.ok).length;
  const failed = detalhe.length - passed;
  // ok geral = nenhuma sonda CRÍTICA falhando.
  const ok = !detalhe.some(d => !d.ok && d.severidade === 'critico');

  try {
    await pool.query(
      `INSERT INTO atb_integridade (ran_at, ok, total, passed, failed, detalhe, instituicao)
       VALUES (now(), $1, $2, $3, $4, $5, $6)`,
      [ok, detalhe.length, passed, failed, JSON.stringify(detalhe), inst]);
  } catch (e) { console.error('[integridade] gravar resultado:', e.message); }

  return { ok, total: detalhe.length, passed, failed, detalhe };
}

export async function ensureIntegridadeTable(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atb_integridade (
      id          SERIAL PRIMARY KEY,
      ran_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
      ok          BOOLEAN     NOT NULL,
      total       INTEGER     NOT NULL,
      passed      INTEGER     NOT NULL,
      failed      INTEGER     NOT NULL,
      detalhe     JSONB,
      instituicao TEXT
    )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS atb_integridade_inst_idx
    ON atb_integridade(instituicao, ran_at DESC)`);
}

export async function getLatestIntegridade(pool, inst = 'HUSF') {
  const { rows: [row] } = await pool.query(
    `SELECT id, ran_at, ok, total, passed, failed, detalhe FROM atb_integridade
      WHERE instituicao = $1 ORDER BY ran_at DESC LIMIT 1`, [inst]);
  return row || null;
}

export function startIntegridadeSchedule(pool) {
  const run = async () => {
    try {
      const fixo = envTenant();
      const alvos = fixo ? [fixo]
        : (await pool.query('SELECT sigla FROM atb_instituicoes WHERE ativo=true ORDER BY id')).rows.map(r => r.sigla);
      for (const sigla of alvos) {
        await runIntegridade(pool, sigla)
          .then(r => r && console.log('[integridade]', sigla, r.ok ? 'OK' : 'ALERTA', r.passed + '/' + r.total))
          .catch(e => console.error('[integridade]', sigla, 'erro:', e.message));
      }
    } catch (e) { console.error('[integridade] schedule:', e.message); }
  };
  setTimeout(run, 45 * 1000);              // ~45s após o boot
  setInterval(run, 8 * 60 * 60 * 1000);    // a cada 8 horas
}

// ── Card compacto (para embutir noutro painel) ───────────────────────────────
export function renderIntegridadeCard(it) {
  const esc = (v) => String(v == null ? '' : v).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  if (!it) return `<div style="padding:10px 14px;border-radius:10px;background:#f3f4f6;color:#6b7280">Integridade: sem dados ainda</div>`;
  const cor = it.ok ? '#16a34a' : '#dc2626';
  const txt = it.ok ? 'ÍNTEGRO' : 'ALERTA';
  return `<div style="padding:10px 14px;border-radius:10px;background:${it.ok ? '#f0fdf4' : '#fef2f2'};border:1px solid ${cor}33;color:${cor};font-weight:600">
    Integridade dos dados: ${txt} <span style="font-weight:400;color:#6b7280">(${esc(it.passed)}/${esc(it.total)} checks · ${esc(new Date(it.ran_at).toLocaleString('pt-BR'))})</span></div>`;
}

// ── Rotas admin ──────────────────────────────────────────────────────────────
export function registerIntegridadeRoutes(app, pool, adminRequired) {
  // dispara agora (JSON resumido)
  app.get('/atb/admin/integridade/run', adminRequired, async (req, res) => {
    try {
      const r = await runIntegridade(pool, req.atbTenant || 'HUSF');
      res.json({ ok: r.ok, total: r.total, passed: r.passed, failed: r.failed,
                 alertas: r.detalhe.filter(d => !d.ok) });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });
  // último resultado (JSON)
  app.get('/atb/admin/integridade', adminRequired, async (req, res) => {
    try { res.json((await getLatestIntegridade(pool, req.atbTenant || 'HUSF')) || { vazio: true }); }
    catch (e) { res.status(500).json({ error: e.message }); }
  });
  // painel HTML: agrupa por categoria, colore por severidade, botão "rodar agora" (?run=1)
  app.get('/atb/admin/integridade/painel', adminRequired, async (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    try {
      const inst = req.atbTenant || 'HUSF';
      const it = req.query.run === '1' ? await runIntegridade(pool, inst) : (await getLatestIntegridade(pool, inst));
      const esc = (v) => String(v == null ? '' : v).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
      const dets = (it && it.detalhe) || [];
      const cats = [...new Set(dets.map(d => d.categoria))];
      const badge = (d) => {
        const cor = d.ok ? '#16a34a' : (d.severidade === 'critico' ? '#dc2626' : '#d97706');
        const lbl = d.ok ? 'OK' : (d.severidade === 'critico' ? 'CRÍTICO' : 'AVISO');
        return `<span style="display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700;color:#fff;background:${cor}">${lbl}</span>`;
      };
      const secoes = cats.map(cat => {
        const linhas = dets.filter(d => d.categoria === cat).map(d => `
          <tr>
            <td style="padding:8px 10px;border-top:1px solid #eee">${badge(d)}</td>
            <td style="padding:8px 10px;border-top:1px solid #eee;font-weight:600">${esc(d.nome)}</td>
            <td style="padding:8px 10px;border-top:1px solid #eee;font-variant-numeric:tabular-nums">${esc(d.valor)} <span style="color:#9ca3af">/ ${esc(d.limite)}</span></td>
            <td style="padding:8px 10px;border-top:1px solid #eee;color:#4b5563">${esc(d.detalhe)}${d.sql ? `<br><code style="font-size:11px;color:#6b7280;background:#f9fafb;padding:2px 4px;border-radius:4px">${esc(d.sql)}</code>` : ''}</td>
          </tr>`).join('');
        return `<h3 style="margin:22px 0 6px;font-size:15px;color:#374151">${esc(cat)}</h3>
          <table style="width:100%;border-collapse:collapse;font-size:14px"><tbody>${linhas}</tbody></table>`;
      }).join('');
      const cor = !it ? '#6b7280' : (it.ok ? '#16a34a' : '#dc2626');
      const status = !it ? 'SEM DADOS' : (it.ok ? 'ÍNTEGRO' : 'ALERTA');
      res.send(`<!doctype html><meta charset="utf-8"><title>Integridade dos dados</title>
        <div style="max-width:960px;margin:24px auto;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#111">
          <div style="display:flex;align-items:center;justify-content:space-between">
            <h1 style="font-size:20px;margin:0">Integridade dos dados — ${esc(inst)}</h1>
            <a href="?run=1" style="padding:8px 14px;border-radius:8px;background:#111;color:#fff;text-decoration:none;font-size:14px">Rodar agora</a>
          </div>
          <div style="margin:12px 0;padding:12px 16px;border-radius:10px;background:${it && it.ok ? '#f0fdf4' : '#fef2f2'};border:1px solid ${cor}33">
            <span style="font-weight:700;color:${cor}">${status}</span>
            ${it ? `<span style="color:#6b7280"> · ${esc(it.passed)}/${esc(it.total)} checks · ${esc(new Date(it.ran_at).toLocaleString('pt-BR'))}</span>` : ''}
          </div>
          ${secoes || '<p style="color:#6b7280">Clique em "Rodar agora" para a primeira verificação.</p>'}
        </div>`);
    } catch (e) { res.status(500).send('Erro: ' + e.message); }
  });
}
