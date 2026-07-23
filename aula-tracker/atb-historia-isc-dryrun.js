// atb-historia-isc-dryrun.js
// ════════════════════════════════════════════════════════════════════════════
// DRY-RUN do classificador de ISC contra fichas REAIS.
//
// Mesmo padrão do preview da normalização de posologia: roda o classificador
// sobre as últimas N fichas, mostra o que o modelo respondeu e NÃO ESCREVE NADA
// — nem em atb_fichas, nem no log de checagens. Serve para o revisor julgar a
// qualidade do prompt ANTES de cabear o gatilho em qualquer regra.
//
// O sinal que interessa não é "quantas o modelo achou ISC", e sim as
// DIVERGÊNCIAS contra o foco_infeccao que o prescritor marcou:
//   • modelo=ISC e foco≠ISC  → possível captura (o que motivou a feature)
//   • modelo≠ISC e foco=ISC  → possível escape (falso negativo)
// A tela ordena e destaca essas duas colunas, porque é onde está a informação.
//
// Não roda sozinha ao abrir: exige clicar em "Rodar". Cada execução são N
// chamadas de API — um refresh acidental não deve queimar cota.
// ════════════════════════════════════════════════════════════════════════════

import { montarMensagensIsc, parseSaidaIsc, RESPONSE_FORMAT_ISC } from './atb-historia-isc.js';
import { deidentificar } from './atb-historia-routes.js';
import { page, esc } from './atb-regras-routes.js';

const API_URL = (process.env.ATB_NARRATIVA_API_URL || 'https://api.deepinfra.com/v1/openai').replace(/\/$/, '');
const API_KEY = process.env.ATB_NARRATIVA_API_KEY || '';
const MODEL   = process.env.ATB_NARRATIVA_MODEL || 'meta-llama/Llama-3.3-70B-Instruct-Turbo';
const DEID_ON = process.env.ATB_HISTORIA_DEID === '1';
const TIMEOUT = 20000;
const CONCORRENCIA = 4;      // gentil com a API; 30 fichas saem em ~8 rodadas
const ISC = 'Infecção do sítio cirúrgico';

async function classificarIsc(historia) {
  if (!API_KEY) return { erro: 'sem ATB_NARRATIVA_API_KEY' };
  const texto = DEID_ON ? deidentificar(historia) : historia;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT);
  try {
    const r = await fetch(`${API_URL}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${API_KEY}` },
      signal: ctrl.signal,
      body: JSON.stringify({
        model: MODEL, temperature: 0,
        response_format: RESPONSE_FORMAT_ISC,
        messages: montarMensagensIsc(texto),
      }),
    });
    if (!r.ok) {
      const corpo = await r.text().catch(() => '');
      return { erro: `HTTP ${r.status}: ${corpo.slice(0, 120)}` };
    }
    const data = await r.json();
    const out = parseSaidaIsc(data?.choices?.[0]?.message?.content || '');
    if (!out) return { erro: 'resposta ilegível do modelo' };
    return { ...out, custo: data?.usage?.estimated_cost ?? null };
  } catch (e) {
    return { erro: e.name === 'AbortError' ? 'timeout (20s)' : e.message };
  } finally {
    clearTimeout(t);
  }
}

// Executa em lotes de CONCORRENCIA, preservando a ordem de entrada.
async function emLotes(itens, fn) {
  const out = new Array(itens.length);
  for (let i = 0; i < itens.length; i += CONCORRENCIA) {
    const fatia = itens.slice(i, i + CONCORRENCIA);
    const res = await Promise.all(fatia.map(fn));
    res.forEach((r, j) => { out[i + j] = r; });
  }
  return out;
}

export function registerIscDryrunRoutes(app, pool, adminRequired) {
  const soSuper = [adminRequired, (req, res, next) => {
    if (req.user?.super_admin || req.cookies?.adm === '1') return next();
    res.status(403).send(page('Sem acesso', '<div class="card"><h1>Acesso restrito</h1></div>'));
  }];

  app.get('/atb/admin/historia/isc-dryrun', soSuper, async (req, res) => {
    // n inválido/negativo cai no padrão (30); teto de 100 para não estourar cota.
    const nBruto = parseInt(req.query.n, 10);
    const n = Math.min(nBruto > 0 ? nBruto : 30, 100);
    const rodar = req.query.run === '1';

    const cab = `
      <div class="card">
        <h1>Dry-run — classificador de ISC</h1>
        <p class="mut">Roda o classificador sobre as últimas fichas com história preenchida e mostra o veredito. <strong>Não grava nada</strong> — nem na ficha, nem no log de checagens. É para você julgar o prompt antes de ligar o gatilho.</p>
        <form method="GET" class="row" style="margin-top:10px">
          <input type="hidden" name="run" value="1">
          <div><label class="f">Quantas fichas</label><input name="n" value="${n}" style="width:80px"></div>
          <div style="align-self:flex-end"><button type="submit">Rodar classificador</button></div>
        </form>
        <p class="nota" style="margin-top:8px">Modelo: <code>${esc(MODEL)}</code>${DEID_ON ? ' · de-id ligada' : ''}${API_KEY ? '' : ' · <span style="color:#c5221f">ATB_NARRATIVA_API_KEY ausente</span>'}</p>
      </div>`;

    if (!rodar) {
      return res.send(page('Dry-run ISC', cab +
        '<div class="card"><p class="mut">Clique em “Rodar classificador” para executar. Cada execução consome N chamadas de API.</p></div>'));
    }

    try {
      const { rows } = await pool.query(`
        SELECT f.id, f.historia_clinica, f.foco_infeccao, f.tipo_terapia, i.sigla,
               COALESCE(f.data_referencia, f.jotform_created_at, f.created_at) AS quando
          FROM atb_fichas f
          LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
         WHERE f.deletado_em IS NULL
           AND f.historia_clinica IS NOT NULL
           AND btrim(f.historia_clinica) <> ''
         ORDER BY COALESCE(f.data_referencia, f.jotform_created_at, f.created_at) DESC
         LIMIT $1`, [n]);

      if (!rows.length) return res.send(page('Dry-run ISC', cab + '<div class="card"><p class="mut">Nenhuma ficha com história preenchida.</p></div>'));

      const vereditos = await emLotes(rows, (f) => classificarIsc(f.historia_clinica));

      let capturas = 0, escapes = 0, concord = 0, falhas = 0, custo = 0;
      const linhas = rows.map((f, i) => {
        const v = vereditos[i] || {};
        const focoIsc = (f.foco_infeccao || '') === ISC;
        let marca = '', cor = '';
        if (v.erro) { falhas++; marca = '<span class="pill off">falha</span>'; }
        else if (v.isc && !focoIsc)  { capturas++; cor = '#fff8e1'; marca = '<span class="pill" style="background:#fdecea;color:#b3261e">possível captura</span>'; }
        else if (!v.isc && focoIsc)  { escapes++;  cor = '#fff8e1'; marca = '<span class="pill" style="background:#fff4e5;color:#a4700a">possível escape</span>'; }
        else { concord++; marca = '<span class="pill" style="background:#e6f4ea;color:#1a7f37">concorda</span>'; }
        if (typeof v.custo === 'number') custo += v.custo;

        const vered = v.erro
          ? `<span style="color:#c5221f">${esc(v.erro)}</span>`
          : (v.isc ? '<strong>ISC: sim</strong>' : 'ISC: não');
        return `<tr style="${cor ? 'background:' + cor : ''}">
          <td class="nota" style="white-space:nowrap">#${f.id}<br>${esc(f.sigla || '—')}</td>
          <td style="max-width:520px;white-space:pre-wrap;font-size:13px">${esc(f.historia_clinica)}</td>
          <td class="nota" style="white-space:nowrap">${esc(f.foco_infeccao || '—')}<br><span class="nota">${esc(f.tipo_terapia || '')}</span></td>
          <td style="white-space:nowrap">${vered}<br><span class="nota">${esc(v.indicios || '')}</span></td>
          <td style="white-space:nowrap">${marca}</td>
        </tr>`;
      }).join('');

      res.send(page('Dry-run ISC', cab + `
        <div class="card">
          <h2>Resumo de ${rows.length} fichas</h2>
          <table>
            <tr><td><strong>Possível captura</strong> <span class="nota">modelo diz ISC, foco marcado é outro</span></td><td><strong>${capturas}</strong></td></tr>
            <tr><td><strong>Possível escape</strong> <span class="nota">foco marcado é ISC, modelo diz que não</span></td><td><strong>${escapes}</strong></td></tr>
            <tr><td>Concordam</td><td>${concord}</td></tr>
            <tr><td>Falhas de API</td><td>${falhas}</td></tr>
            ${custo ? `<tr><td>Custo estimado</td><td>US$ ${custo.toFixed(4)}</td></tr>` : ''}
          </table>
          <p class="nota" style="margin-top:10px">As linhas em amarelo são as divergências — é nelas que está a informação. Concordância alta sem capturas pode significar prompt tímido; muitas capturas erradas, prompt agressivo demais.</p>
        </div>
        <div class="card">
          <h2>Fichas</h2>
          <div class="serie-scroll"><table class="mtab">
            <thead><tr><th>ficha</th><th>história</th><th>foco marcado</th><th>modelo</th><th></th></tr></thead>
            <tbody>${linhas}</tbody>
          </table></div>
        </div>`));
    } catch (e) {
      console.error('[isc-dryrun]', e.message);
      res.status(500).send(page('Erro', `<div class="card"><h1>Falha</h1><p class="mut">${esc(e.message)}</p></div>`));
    }
  });
}
