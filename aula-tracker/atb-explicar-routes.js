// atb-explicar-routes.js
// ─────────────────────────────────────────────────────────────────────────
// "Por que esta ficha foi classificada assim?" — explicabilidade das regras.
//
// Duas camadas, deliberadamente separadas porque respondem perguntas diferentes:
//
//  1. AUDITORIA (o que de fato aconteceu): atb_avaliacoes.triagem_regra_id /
//     monitor_regra_id registram QUAL regra gravou o IrAS e QUANDO. É o histórico.
//
//  2. REAVALIAÇÃO AGORA (por que casa/não casa): roda o motor no contexto ATUAL
//     e mostra cada condição com o valor real. Diagnostica a regra.
//
// ⚠ As duas podem divergir — e isso é informação, não bug: o contexto muda
// (cultura que chegou depois, campo editado) e as regras podem ter sido editadas
// desde a classificação. A tela deixa isso explícito.
//
// O explicador usa explicaCond(), que delega a decisão ao avaliaCond() do motor
// — nunca reimplementa operador, então não pode divergir do comportamento real.

import { montarContexto, explicaCond } from './atb-triagem-regras.js';
import { page, esc, catalogoCampos, OPERADORES } from './atb-regras-routes.js';

// rótulo amigável do operador (achata OPERADORES; 1ª ocorrência vence)
const _OP_LABEL = (() => {
  const m = {};
  for (const tipo of Object.keys(OPERADORES))
    for (const [op, label] of OPERADORES[tipo]) if (!m[op]) m[op] = label;
  return m;
})();

function _fmtVal(v) {
  if (v === undefined || v === null || v === '') return '<i style="color:#9aa0a6">(vazio)</i>';
  if (typeof v === 'boolean') return v ? 'Sim' : 'Não';
  if (Array.isArray(v)) return v.length ? esc(v.join(', ')) : '<i style="color:#9aa0a6">(lista vazia)</i>';
  if (v instanceof Date) return esc(v.toISOString().slice(0, 10));
  return esc(String(v));
}

// Renderiza a árvore de condições anotada (indentada, com passa/falha por nó).
function _renderNo(no, byKey, nivel = 0) {
  const pad = `margin-left:${nivel * 18}px`;
  const cor = no.ok ? '#1a8a52' : '#c5221f';
  const marca = no.ok ? '✓' : '✗';
  if (no.tipo === 'all' || no.tipo === 'any') {
    const rot = no.tipo === 'all' ? 'TODAS (E)' : 'QUALQUER (OU)';
    return `<div style="${pad};margin-top:4px">
        <span style="color:${cor};font-weight:700">${marca}</span>
        <span style="font-size:12px;color:#5f6368;letter-spacing:.03em">${rot}</span>
      </div>` + (no.filhos || []).map((f) => _renderNo(f, byKey, nivel + 1)).join('');
  }
  if (no.tipo === 'vazio') return `<div style="${pad};font-size:13px;color:#5f6368">(sem condições — casa sempre)</div>`;
  const cp = byKey[no.campo];
  const label = cp ? cp.label : no.campo;
  const opLab = _OP_LABEL[no.op] || no.op;
  const esperado = (no.op === 'filled' || no.op === 'not_filled') ? '' :
    ` <strong>${Array.isArray(no.valor) ? esc(no.valor.join(' / ')) : _fmtVal(no.valor)}</strong>`;
  return `<div style="${pad};margin-top:3px;font-size:13px">
      <span style="color:${cor};font-weight:700">${marca}</span>
      ${esc(label)} <span style="color:#5f6368">${esc(opLab)}</span>${esperado}
      <span style="color:#9aa0a6"> · valor da ficha:</span> ${_fmtVal(no.atual)}
    </div>`;
}

function _cardRegra(r, exp, byKey, vencedora) {
  const bg = exp.ok ? (vencedora ? '#eaf5ec' : '#f6faf7') : '#fafafa';
  const br = exp.ok ? (vencedora ? '#8fd0a3' : '#dbe9de') : '#e8eaed';
  const selo = vencedora
    ? '<span style="background:#1a8a52;color:#fff;font-size:11px;font-weight:700;border-radius:10px;padding:2px 9px">SERIA APLICADA AGORA</span>'
    : exp.ok
      ? '<span style="background:#e8f0ea;color:#1a8a52;font-size:11px;font-weight:600;border-radius:10px;padding:2px 9px">casa (mas outra vem antes)</span>'
      : '<span style="background:#f1f3f4;color:#80868b;font-size:11px;border-radius:10px;padding:2px 9px">não casa</span>';
  const acoes = r.acoes || {};
  const acaoTxt = [
    acoes.iras || r.acao_iras ? `IrAS → <strong>${esc(acoes.iras || r.acao_iras)}</strong>` : null,
    acoes.veredito ? `Parecer → ${esc(acoes.veredito)}` : null,
  ].filter(Boolean).join(' · ') || '<i style="color:#9aa0a6">sem ação de IrAS</i>';
  return `<div style="border:1px solid ${br};background:${bg};border-radius:10px;padding:10px 12px;margin-top:8px">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <strong style="font-size:14px">${esc(r.nome)}</strong>
        <span style="font-size:12px;color:#80868b">prioridade ${r.prioridade}</span>
        ${selo}
      </div>
      <div style="font-size:12px;color:#5f6368;margin:4px 0 6px">${acaoTxt}</div>
      ${_renderNo(exp, byKey, 0)}
    </div>`;
}

export function registerExplicarRoutes(app, pool, adminRequired) {
  app.get('/atb/admin/ficha/:id/explicar', adminRequired, async (req, res) => {
    const fichaId = parseInt(req.params.id, 10);
    if (!Number.isFinite(fichaId)) return res.redirect('/atb/admin/grid');
    try {
      const built = await montarContexto(pool, fichaId);
      if (!built) return res.status(404).send(page('Ficha', '<div class="card"><h1>Ficha não encontrada</h1></div>'));
      const { f, ctx, sigla } = built;

      // ── 1. Auditoria: quem gravou o IrAS ──
      const av = (await pool.query(
        `SELECT a.iras, a.triagem_regra_id, a.triagem_regra_at, a.monitor_regra_id, a.monitor_regra_at,
                t.nome AS triagem_nome, m.nome AS monitor_nome
           FROM atb_avaliacoes a
           LEFT JOIN atb_triagem_regras t ON t.id = a.triagem_regra_id
           LEFT JOIN atb_monitoramento_regras m ON m.id = a.monitor_regra_id
          WHERE a.ficha_id = $1`, [fichaId])).rows[0] || {};
      const irasAtual = (av.iras == null || String(av.iras).trim() === '') ? null : String(av.iras);
      const dt = (d) => d ? new Date(d).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' }) : '—';

      let origem;
      if (!irasAtual) origem = '<i style="color:#9aa0a6">IrAS ainda não definido nesta ficha.</i>';
      else if (av.monitor_regra_id) origem = `Gravado pela regra de <strong>monitoramento</strong> “${esc(av.monitor_nome || ('#' + av.monitor_regra_id))}” em ${esc(dt(av.monitor_regra_at))}.`;
      else if (av.triagem_regra_id) origem = `Gravado pela regra de <strong>triagem</strong> “${esc(av.triagem_nome || ('#' + av.triagem_regra_id))}” em ${esc(dt(av.triagem_regra_at))}.`;
      else origem = 'Preenchido <strong>manualmente</strong> (nenhuma regra registrada) — as regras não sobrescrevem entrada manual.';

      // ── 2. Reavaliação agora ──
      const campos = await catalogoCampos(pool, sigla);
      const byKey = {}; campos.forEach((c) => { byKey[c.key] = c; });

      const triagem = (await pool.query(
        'SELECT id, nome, prioridade, condicoes, acoes FROM atb_triagem_regras WHERE ativo=true AND instituicao=$1 ORDER BY prioridade ASC, id ASC',
        [sigla])).rows;
      let venceuT = false;
      const htmlT = triagem.map((r) => {
        const exp = explicaCond(r.condicoes, ctx);
        const venc = exp.ok && !venceuT;      // motor aplica a 1ª que casa
        if (venc) venceuT = true;
        return _cardRegra(r, exp, byKey, venc);
      }).join('') || '<p style="color:#5f6368;font-size:13px">Nenhuma regra de triagem ativa.</p>';

      const monit = (await pool.query(
        'SELECT id, nome, prioridade, condicoes, acao_iras, janela_dias FROM atb_monitoramento_regras WHERE ativo=true AND instituicao=$1 ORDER BY prioridade ASC, id ASC',
        [sigla])).rows;
      let venceuM = false;
      const htmlM = monit.length ? monit.map((r) => {
        const exp = explicaCond(r.condicoes, ctx);
        const venc = exp.ok && !venceuM;
        if (venc) venceuM = true;
        return _cardRegra(r, exp, byKey, venc);
      }).join('') : '';

      // ── contexto (valores usados) ──
      const ctxLinhas = Object.keys(ctx).sort().map((k) => {
        const cp = byKey[k];
        return `<tr><td style="padding:3px 8px;color:#5f6368">${esc(cp ? cp.label : k)}</td>
                <td style="padding:3px 8px;font-family:ui-monospace,monospace;font-size:12px;color:#80868b">${esc(k)}</td>
                <td style="padding:3px 8px">${_fmtVal(ctx[k])}</td></tr>`;
      }).join('');

      res.send(page(`Por que esta classificação? · ficha ${fichaId}`, `
        <div class="card">
          <h1>Por que esta classificação?</h1>
          <p class="mut">Ficha <strong>${fichaId}</strong> · ${esc(f.paciente_nome || f.paciente_nome_raw || '—')} · ${esc(f.setor || '—')} · ${esc(sigla)}</p>
          <div style="margin-top:10px;padding:10px 12px;border:1px solid #e8eaed;border-radius:10px;background:#fafbfc">
            <div style="font-size:13px">IrAS atual: <strong>${irasAtual ? esc(irasAtual) : '—'}</strong></div>
            <div style="font-size:13px;margin-top:4px;color:#3c4043">${origem}</div>
          </div>
          <p class="nota" style="margin-top:10px">Abaixo, o motor é rodado <strong>agora</strong>, no contexto atual da ficha. Como o contexto muda com o tempo (culturas que chegam depois, campos editados) e as regras podem ter sido editadas, o resultado de agora pode diferir do que foi gravado — a divergência costuma ser a explicação.</p>
          <p style="font-size:13px"><a href="/atb/admin/ficha/${fichaId}">← Ver ficha completa</a></p>
        </div>

        <div class="card">
          <h2>Regras de triagem <span class="nota">(o motor aplica a primeira que casa, por prioridade)</span></h2>
          ${htmlT}
        </div>

        ${monit.length ? `<div class="card">
          <h2>Regras de monitoramento <span class="nota">(reavaliam a ficha dentro da janela)</span></h2>
          ${htmlM}
        </div>` : ''}

        <div class="card">
          <h2>Valores usados na avaliação</h2>
          <p class="nota">O contexto que o motor enxerga desta ficha — inclui campos calculados (idade, dias de UTI, culturas...).</p>
          <details><summary style="cursor:pointer;font-size:13px;color:#1a73e8">Mostrar ${Object.keys(ctx).length} valores</summary>
            <table style="border-collapse:collapse;width:100%;font-size:13px;margin-top:8px">
              <thead><tr style="text-align:left;color:#80868b"><th style="padding:3px 8px">Campo</th><th style="padding:3px 8px">Chave</th><th style="padding:3px 8px">Valor</th></tr></thead>
              <tbody>${ctxLinhas}</tbody>
            </table>
          </details>
        </div>`));
    } catch (e) {
      console.error('[atb] explicar:', e.message);
      res.status(500).send(page('Erro', `<div class="card"><h1>Falha ao explicar</h1><p class="mut">${esc(e.message)}</p></div>`));
    }
  });
}
