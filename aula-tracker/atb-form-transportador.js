// atb-form-transportador.js
// ════════════════════════════════════════════════════════════════════════════
// O TRANSPORTADOR — a terceira peça do pipeline de teste do formulário.
//
// Responsabilidade única: levar uma mudança testada do ambiente de teste para
// produção, COM SEGURANÇA e SOB CONTROLE HUMANO. Nunca escreve no engine de
// produção em runtime (o Render é efêmero e o commit é manual via GitHub) — em
// vez disso GERA UM ARTEFATO para o usuário baixar e commitar. Isso não é
// limitação: é o que preserva a vocação do ambiente. Produção só muda quando o
// humano commita.
//
// Duas promoções, naturezas distintas:
//   • ENGINE (código) → artefato .js gerado = produção + intervenções PROMOVÍVEIS
//     (as marcadas promovivel:true; o schema-override só-teste fica de fora).
//   • SCHEMA (dado)  → ação em runtime: aplica a transformação de colunas ao
//     schema HUSF real e grava nova versão (o banco persiste, então aqui pode).
//
// A tela mostra o diff legível, o que será promovido e o que ficará de fora, e
// só então oferece os botões. Ler antes de agir.
// ════════════════════════════════════════════════════════════════════════════

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { aplicarPilha, descreverIntervencao, validarIntervencao, checarTransformacao } from './atb-intervencoes.js';
import { getFormSchema, saveFormSchema } from './atb-form-schema.js';
import { schemaPosologiaEstruturada } from './atb-form-teste-schema.js';
import { listarIntervencoes } from './atb-intervencoes-registry.js';
import { page, esc } from './atb-regras-routes.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ENGINE_PROD = path.join(__dirname, 'atb-form-engine.js');

// Intervenções vêm do registry EMBUTIDO (código), já na ordem correta — não de
// arquivos em disco: o Render é efêmero e o GitHub web UI achata subpastas.
function carregarIntervencoes() {
  return listarIntervencoes().map((i) => ({ ...i, _arquivo: i._nome + '.json' }));
}

// Estado de cada intervenção contra o engine de produção ATUAL: aplicável?
function diagnosticar(prod, intervencoes) {
  return intervencoes.map((interv) => {
    const problemas = validarIntervencao(interv);
    const anc = (interv.transformacoes || []).map((t, i) => {
      const c = checarTransformacao(prod, t.ancora);
      return { i, ...c, nota: t.nota || null };
    });
    return {
      nome: interv.nome, arquivo: interv._arquivo, descricao: interv.descricao || '',
      promovivel: interv.promovivel === true, dependeDe: interv.dependeDe || [],
      formatoOk: problemas.length === 0, problemas,
      // aplicável DIRETO em produção (só as sem dependeDe podem ser checadas isoladamente)
      ancoras: anc, aplicavelDireto: anc.every((a) => a.ok),
    };
  });
}

export function registerFormTransportadorRoutes(app, pool, adminRequired) {
  const soSuper = [adminRequired, (req, res, next) => {
    if (req.user?.super_admin || req.cookies?.adm === '1') return next();
    res.status(403).send(page('Sem acesso', '<div class="card"><h1>Acesso restrito</h1></div>'));
  }];

  // ── PAINEL (GET) ──────────────────────────────────────────────────────────
  app.get('/atb/admin/form-transportador', soSuper, async (req, res) => {
    try {
      const prod = fs.readFileSync(ENGINE_PROD, 'utf8');
      const intervencoes = carregarIntervencoes();
      const diag = diagnosticar(prod, intervencoes);
      const promoviveis = intervencoes.filter((i) => i.promovivel === true);

      // Tenta gerar a pilha promovível (dry) para saber se o conjunto aplica limpo.
      let pilhaOk = true, pilhaErro = '';
      try { aplicarPilha(prod, promoviveis, { dry: false }); }
      catch (e) { pilhaOk = false; pilhaErro = e.message; }

      const cardInterv = diag.map((d) => {
        const cor = d.promovivel ? '#1a8a52' : '#80868b';
        const tag = d.promovivel
          ? '<span style="color:#1a8a52">✓ será promovida</span>'
          : '<span style="color:#a4700a">só-teste — fica de fora</span>';
        const estado = d.aplicavelDireto
          ? '<span style="color:#1a8a52">aplicável</span>'
          : (d.dependeDe.length
              ? `<span class="nota">depende de ${esc(d.dependeDe.join(', '))} (aplicada na pilha)</span>`
              : '<span style="color:#c5221f">âncora não casa — re-ancorar</span>');
        return `<div style="border-left:3px solid ${cor};padding:8px 12px;margin:8px 0">
          <div><strong>${esc(d.nome)}</strong> · ${tag}</div>
          <div class="nota">${esc(d.descricao)}</div>
          <div class="nota">alvo: ${esc(intervencoes.find((i)=>i.nome===d.nome).alvo)} · ${estado} · ${d.ancoras.length} transformação(ões)</div>
        </div>`;
      }).join('');

      // diff legível das promovíveis
      const diffs = promoviveis.map((interv) => {
        const d = descreverIntervencao(interv);
        const trs = d.transformacoes.map((t) => `
          <details style="margin:6px 0">
            <summary class="nota">${esc(t.nota || ('transformação ' + t.i))}</summary>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:6px">
              <pre style="background:#fef2f2;border:1px solid #f3c2c2;border-radius:6px;padding:8px;font-size:11px;overflow:auto;white-space:pre-wrap">${esc(t.de)}</pre>
              <pre style="background:#f2f9f4;border:1px solid #cfe8d6;border-radius:6px;padding:8px;font-size:11px;overflow:auto;white-space:pre-wrap">${esc(t.para)}</pre>
            </div>
          </details>`).join('');
        return `<div class="card"><h3>${esc(interv.nome)}</h3>${trs}</div>`;
      }).join('');

      const husfSchema = await getFormSchema(pool, 'HUSF');
      const husfEstrut = (() => {
        if (!husfSchema) return null;
        for (const s of (husfSchema.secoes || [])) for (const c of (s.campos || []))
          if (c.key === 'posologia') return (c.colunas || []).some((x) => x.key === 'dose_valor');
        return false;
      })();

      res.send(page('Transportador do formulário', `
        <div class="card">
          <h1>Transportador do formulário</h1>
          <p class="mut">Promove uma mudança testada para produção. O engine é gerado como <strong>artefato para você baixar e commitar</strong> (o servidor não escreve no próprio código). O schema do HUSF é promovido no banco por ação direta.</p>
        </div>

        <div class="card">
          <h2>Intervenções</h2>
          ${cardInterv}
          ${pilhaOk
            ? '<p class="nota" style="color:#1a8a52;margin-top:8px">✓ a pilha promovível aplica limpo sobre a produção atual.</p>'
            : `<p style="color:#c5221f;margin-top:8px">⚠ a pilha não aplica: ${esc(pilhaErro)} — produção mudou? Re-ancore antes de promover.</p>`}
        </div>

        <div class="card">
          <h2>1 · Promover o ENGINE <span class="nota">(gera artefato)</span></h2>
          <p class="nota">Gera <code>atb-form-engine.js</code> = produção + as intervenções promovíveis (${promoviveis.map((i)=>esc(i.nome)).join(' + ') || 'nenhuma'}). O <code>form-teste-schema-override</code> NÃO entra. Baixe e commite via GitHub.</p>
          <form method="POST" action="/atb/admin/form-transportador/gerar-engine" ${pilhaOk ? '' : 'onsubmit="alert(\'A pilha não aplica limpo — resolva antes.\');return false"'}>
            <button type="submit">⬇ Gerar atb-form-engine.js promovido</button>
          </form>
        </div>

        <div class="card">
          <h2>2 · Promover o SCHEMA do HUSF <span class="nota">(ação no banco)</span></h2>
          <p class="nota">Estado atual do schema HUSF: ${husfSchema ? ('versão ' + esc(String(husfSchema.versao)) + ' — posologia ' + (husfEstrut ? '<span style="color:#1a8a52">já estruturada</span>' : '<span style="color:#a4700a">texto livre</span>')) : 'não encontrado'}. Promover grava uma NOVA versão do HUSF com a posologia estruturada (as fichas novas passam a nascer no formato novo).</p>
          <p style="color:#a4700a;font-size:13px"><strong>Ordem importa:</strong> só promova o schema DEPOIS que o engine promovido E os leitores (card/parecer/ficha) estiverem no ar. Senão, fichas novas gravam no formato novo e os leitores antigos mostram vazio.</p>
          <form method="POST" action="/atb/admin/form-transportador/promover-schema" onsubmit="return confirm('Gravar nova versão do schema HUSF com posologia estruturada? Confirme que o engine e os leitores já estão no ar.')">
            <button type="submit">Promover schema HUSF no banco</button>
          </form>
        </div>

        <div class="card">
          <h2>Diff das intervenções promovíveis</h2>
          <p class="nota">Vermelho = produção atual · verde = após promoção. Revise antes de commitar.</p>
          ${diffs || '<p class="nota">nenhuma intervenção promovível.</p>'}
        </div>`));
    } catch (e) {
      console.error('[atb] transportador painel:', e.message);
      res.status(500).send(page('Erro', `<div class="card"><h1>Falha</h1><p class="mut">${esc(e.message)}</p></div>`));
    }
  });

  // ── GERAR ENGINE PROMOVIDO (download) ─────────────────────────────────────
  app.post('/atb/admin/form-transportador/gerar-engine', soSuper, async (req, res) => {
    try {
      const prod = fs.readFileSync(ENGINE_PROD, 'utf8');
      const promoviveis = carregarIntervencoes().filter((i) => i.promovivel === true);
      const r = aplicarPilha(prod, promoviveis, { dry: false });
      res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="atb-form-engine.js"');
      res.send(r.conteudo);
    } catch (e) {
      console.error('[atb] gerar-engine:', e.message);
      res.status(500).send(page('Erro', `<div class="card"><h1>Falha ao gerar</h1><p class="mut">${esc(e.message)}</p><p class="nota">Provável causa: a produção mudou e uma âncora não casa mais. Re-ancore a intervenção.</p></div>`));
    }
  });

  // ── PROMOVER SCHEMA HUSF (banco) ──────────────────────────────────────────
  app.post('/atb/admin/form-transportador/promover-schema', soSuper, async (req, res) => {
    try {
      const base = await getFormSchema(pool, 'HUSF');
      if (!base) throw new Error('schema HUSF não encontrado');
      const { def, mudou } = schemaPosologiaEstruturada(base);
      if (!mudou) {
        return res.send(page('Nada a promover', `<div class="card"><h1>Já estruturado</h1>
          <p class="mut">O schema HUSF já tem a posologia estruturada — nada a fazer.</p>
          <p><a href="/atb/admin/form-transportador">← Voltar</a></p></div>`));
      }
      const versao = await saveFormSchema(pool, 'HUSF', def, null);
      console.log(`[atb] schema HUSF promovido a v${versao} (posologia estruturada)`);
      res.send(page('Schema HUSF promovido', `<div class="card"><h1>Pronto</h1>
        <p class="mut">Schema HUSF agora na versão <strong>${esc(String(versao))}</strong>, posologia estruturada. Fichas novas nascem no formato novo.</p>
        <p class="nota">Se algo parecer errado, o schema é versionado — dá para reativar a versão anterior no banco.</p>
        <p><a href="/atb/admin/form-transportador">← Voltar</a></p></div>`));
    } catch (e) {
      console.error('[atb] promover-schema:', e.message);
      res.status(500).send(page('Erro', `<div class="card"><h1>Falha</h1><p class="mut">${esc(e.message)}</p></div>`));
    }
  });
}
