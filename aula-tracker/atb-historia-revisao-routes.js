// atb-historia-revisao-routes.js
// ════════════════════════════════════════════════════════════════════════════
// REVISÃO DA QUALIDADE DO GATILHO DE HISTÓRIA (Fase C).
//
// Por que existe: o nudge bloqueia o envio quando o modelo julga a história
// telegráfica. Com bloqueio duro o prescritor nunca discorda por dentro do
// sistema — então o "rótulo de ouro" (override) nunca é coletado. Sem rótulo,
// não há como saber se o gatilho ajuda ou atrapalha.
//
// A saída: o rótulo vem do REVISOR (infectologista), não do prescritor. Todos os
// ingredientes já são gravados por atb-historia-routes.js em
// atb_historia_checagens (o texto da história + o veredito do modelo). Esta tela
// só acrescenta o julgamento humano: "a IA acertou" / "a IA errou".
//
// Rótulo do revisor > rótulo do prescritor: quem está com pressa clica em
// "enviar assim mesmo" para passar, não porque avaliou a história. O revisor lê
// o caso sem essa pressão.
//
// Mede as DUAS direções de erro:
//   • narrativa=false revisada como "errou" → FALSO POSITIVO (bloqueou à toa —
//     o custo clínico real: atrasa a solicitação de ATB).
//   • narrativa=true  revisada como "errou" → FALSO NEGATIVO (deixou passar uma
//     história ruim — custo menor, mas mede a sensibilidade).
//
// Não toca o backend do nudge nem o engine: é só leitura + um UPDATE de rótulo.
// Migração aditiva (ADD COLUMN IF NOT EXISTS), segura em tabela com dados.
// ════════════════════════════════════════════════════════════════════════════

import { page, esc } from './atb-regras-routes.js';

// Filtros permitidos → cláusula SQL. Allowlist: o valor nunca entra na query.
const FILTROS = {
  pendentes: { rotulo: 'Sinalizadas pendentes', where: `narrativa = false AND revisao IS NULL` },
  sinalizadas: { rotulo: 'Todas as sinalizadas', where: `narrativa = false` },
  passou: { rotulo: 'Passaram (amostra)', where: `narrativa = true` },
  errou: { rotulo: 'Marcadas como erro da IA', where: `revisao = 'errou'` },
  todas: { rotulo: 'Todas', where: `TRUE` },
};

// Allowlist imune à cadeia de protótipos: FILTROS['constructor'] seria truthy
// via Object.prototype e produziria where=undefined → SQL inválido.
function filtroValido(k) {
  return typeof k === 'string' && Object.prototype.hasOwnProperty.call(FILTROS, k);
}

// Escopo de tenant. As checagens gravam a sigla em `inst`; linhas antigas sem
// inst contam como HUSF, mesma convenção das fichas. Vale para LEITURA e para
// ESCRITA — sem o filtro no UPDATE, um admin de um hospital poderia rotular
// checagem do outro adivinhando o id.
function escopoInst(n) {
  return `(inst = $${n} OR (inst IS NULL AND $${n} = 'HUSF'))`;
}

async function garantirColunas(pool) {
  // Aditivo: a tabela é criada por atb-historia-routes.js; aqui só o rótulo.
  await pool.query(`ALTER TABLE atb_historia_checagens ADD COLUMN IF NOT EXISTS revisao TEXT`);
  await pool.query(`ALTER TABLE atb_historia_checagens ADD COLUMN IF NOT EXISTS revisado_em TIMESTAMPTZ`);
}

function pct(n, d) {
  if (!d) return '—';
  return (100 * n / d).toFixed(0) + '%';
}

export function registerHistoriaRevisaoRoutes(app, pool, adminRequired) {
  garantirColunas(pool).catch((e) => console.error('[historia-revisao] migration', e.message));

  const gate = adminRequired || ((req, res, next) => next());

  // ── TELA ──────────────────────────────────────────────────────────────────
  app.get('/atb/admin/historia/revisao', gate, async (req, res) => {
    try {
      const tenant = req.atbTenant || 'HUSF';
      const chave = filtroValido(req.query.f) ? req.query.f : 'pendentes';
      const filtro = FILTROS[chave];

      // Resumo — uma passada só, sem depender do filtro.
      const { rows: [m] } = await pool.query(`
        SELECT
          count(*)::int                                                        AS total,
          count(*) FILTER (WHERE disponivel = false)::int                      AS indisponivel,
          count(*) FILTER (WHERE narrativa = false)::int                       AS sinalizadas,
          count(*) FILTER (WHERE narrativa = true)::int                        AS passaram,
          count(*) FILTER (WHERE narrativa = false AND revisao IS NULL)::int   AS pendentes,
          count(*) FILTER (WHERE narrativa = false AND revisao = 'acertou')::int AS fp_ok,
          count(*) FILTER (WHERE narrativa = false AND revisao = 'errou')::int   AS fp_erro,
          count(*) FILTER (WHERE narrativa = true  AND revisao = 'acertou')::int AS fn_ok,
          count(*) FILTER (WHERE narrativa = true  AND revisao = 'errou')::int   AS fn_erro,
          count(*) FILTER (WHERE override = true)::int                         AS overrides
        FROM atb_historia_checagens
         WHERE ${escopoInst(1)}`, [tenant]);

      const revFalse = m.fp_ok + m.fp_erro;      // sinalizadas já revisadas
      const revTrue = m.fn_ok + m.fn_erro;       // passadas já revisadas

      const { rows } = await pool.query(`
        SELECT id, inst, historia, disponivel, narrativa, aviso, override, motivo,
               revisao, revisado_em, created_at
          FROM atb_historia_checagens
         WHERE (${filtro.where}) AND ${escopoInst(1)}
         ORDER BY created_at DESC
         LIMIT 60`, [tenant]);

      const abas = Object.keys(FILTROS).map((k) =>
        k === chave
          ? `<span class="pill on">${esc(FILTROS[k].rotulo)}</span>`
          : `<a class="pill off" href="/atb/admin/historia/revisao?f=${esc(k)}">${esc(FILTROS[k].rotulo)}</a>`
      ).join(' ');

      const lista = rows.length ? rows.map((r) => {
        const quando = r.created_at ? new Date(r.created_at).toLocaleString('pt-BR') : '—';
        const veredito = r.disponivel === false
          ? '<span class="pill off">indisponível (passou por fail-open)</span>'
          : (r.narrativa === false
              ? '<span class="pill" style="background:#fdecea;color:#b3261e">IA: telegráfica → bloqueou</span>'
              : '<span class="pill" style="background:#e6f4ea;color:#1a7f37">IA: narrativa → passou</span>');
        const jaRev = r.revisao
          ? `<span class="pill" style="background:${r.revisao === 'errou' ? '#fdecea;color:#b3261e' : '#e6f4ea;color:#1a7f37'}">revisado: IA ${esc(r.revisao)}</span>`
          : '';
        const botoes = `
          <form method="POST" action="/atb/admin/historia/revisao/${r.id}" class="row" style="margin-top:10px">
            <input type="hidden" name="f" value="${esc(chave)}">
            <button type="submit" name="revisao" value="acertou" class="ghost">IA acertou</button>
            <button type="submit" name="revisao" value="errou" class="danger">IA errou</button>
            ${r.revisao ? '<button type="submit" name="revisao" value="" class="ghost">limpar</button>' : ''}
          </form>`;
        return `<div class="card">
          <div class="row" style="justify-content:space-between">
            <div class="row">${veredito} ${jaRev}</div>
            <span class="nota">#${r.id} · ${esc(r.inst || '—')} · ${esc(quando)}</span>
          </div>
          <div style="margin-top:10px;padding:10px 12px;background:#f8fafc;border:1px solid var(--bd);border-radius:8px;white-space:pre-wrap;font-size:14px">${esc(r.historia || '(vazio)')}</div>
          ${r.aviso ? `<p class="nota" style="margin:8px 0 0">aviso do modelo: ${esc(r.aviso)}</p>` : ''}
          ${r.override ? `<p class="nota" style="margin:6px 0 0">override do prescritor${r.motivo ? ': ' + esc(r.motivo) : ''}</p>` : ''}
          ${botoes}
        </div>`;
      }).join('') : '<div class="card"><p class="mut">Nada neste filtro.</p></div>';

      res.send(page('Revisão do gatilho de história', `
        <div class="card">
          <h1>Qualidade do gatilho de história</h1>
          <p class="nota">Instituição: <strong>${esc(tenant)}</strong></p>
          <p class="mut">O modelo classifica a história como narrativa ou telegráfica. Aqui você julga o classificador: lendo o caso, a IA acertou? Os rótulos medem as duas direções de erro e servem de conjunto de avaliação para calibrar o gatilho.</p>
        </div>

        <div class="card">
          <h2>Resumo</h2>
          <table>
            <tr><td>Checagens no total</td><td><strong>${m.total}</strong></td></tr>
            <tr><td>Bloqueadas (IA: telegráfica)</td><td><strong>${m.sinalizadas}</strong> · <span class="nota">${m.pendentes} pendentes de revisão</span></td></tr>
            <tr><td>Passaram (IA: narrativa)</td><td><strong>${m.passaram}</strong></td></tr>
            <tr><td>Indisponível (fail-open)</td><td><strong>${m.indisponivel}</strong> <span class="nota">— falha de infra, a ficha passou direto</span></td></tr>
          </table>
          <h2 style="margin-top:18px">Acurácia entre as revisadas</h2>
          <table>
            <tr><th>direção</th><th>revisadas</th><th>IA acertou</th><th>IA errou</th><th>taxa de erro</th></tr>
            <tr>
              <td><strong>Falso positivo</strong><br><span class="nota">bloqueou à toa — atrasa a solicitação</span></td>
              <td>${revFalse}</td><td>${m.fp_ok}</td><td>${m.fp_erro}</td>
              <td><strong>${pct(m.fp_erro, revFalse)}</strong></td>
            </tr>
            <tr>
              <td><strong>Falso negativo</strong><br><span class="nota">deixou passar história ruim</span></td>
              <td>${revTrue}</td><td>${m.fn_ok}</td><td>${m.fn_erro}</td>
              <td><strong>${pct(m.fn_erro, revTrue)}</strong></td>
            </tr>
          </table>
          <p class="nota" style="margin-top:10px">A taxa de falso positivo é a que importa clinicamente: cada bloqueio indevido é uma solicitação de ATB atrasada. Para medir o falso negativo, revise uma amostra do filtro “Passaram”.</p>
        </div>

        <div class="card">
          <h2>Casos</h2>
          <div class="row" style="margin-bottom:4px">${abas}</div>
          <p class="nota">Mostrando até 60, mais recentes primeiro.</p>
        </div>

        ${lista}`));
    } catch (e) {
      console.error('[historia-revisao] painel:', e.message);
      res.status(500).send(page('Erro', `<div class="card"><h1>Falha</h1><p class="mut">${esc(e.message)}</p></div>`));
    }
  });

  // ── GRAVAR O RÓTULO ───────────────────────────────────────────────────────
  app.post('/atb/admin/historia/revisao/:id', gate, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const bruto = String(req.body?.revisao ?? '').trim();
    const valor = (bruto === 'acertou' || bruto === 'errou') ? bruto : null;   // allowlist
    const f = filtroValido(req.body?.f) ? req.body.f : 'pendentes';
    try {
      if (Number.isInteger(id)) {
        await pool.query(
          `UPDATE atb_historia_checagens
              SET revisao = $2, revisado_em = CASE WHEN $2 IS NULL THEN NULL ELSE now() END
            WHERE id = $1 AND ${escopoInst(3)}`, [id, valor, req.atbTenant || 'HUSF']);
      }
    } catch (e) {
      console.error('[historia-revisao] gravar:', e.message);
    }
    res.redirect('/atb/admin/historia/revisao?f=' + encodeURIComponent(f));
  });
}
