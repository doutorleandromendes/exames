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
import { aplicarPilha, descreverIntervencao, validarIntervencao, checarTransformacao, estadoTransformacao } from './atb-intervencoes.js';
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

// Estado de cada intervenção contra o engine de produção ATUAL.
// Distingue três situações (o que acaba com o "âncora não casa" assustador):
//   • pronta      → a âncora original casa no engine → ainda não aplicada, pode publicar
//   • ja_aplicada → a mudança já está no engine → já publicada
//   • erro        → nem a âncora nem o resultado aparecem → o código mudou de forma inesperada
//
// A classificação vem de estadoTransformacao() — a MESMA função que aplicarIntervencao
// usa. Antes daqui havia heurística própria (amostra dos 120 primeiros caracteres do
// "vira"), e as duas discordavam: o painel pintava "já no ar" em verde enquanto o botão
// de baixar o motor recusava, porque o "vira" inteiro já não casava. Com uma função só,
// esse tipo de mentira não tem como voltar.
function diagnosticar(prod, intervencoes) {
  return intervencoes.map((interv) => {
    const problemas = validarIntervencao(interv);
    const anc = (interv.transformacoes || []).map((t, i) => {
      const e = estadoTransformacao(prod, t, i);
      const c = checarTransformacao(prod, t.ancora);
      return { i, ...c, jaAplicada: e.estado === 'promovida', estado: e.estado,
               por: e.por || null, nota: t.nota || null };
    });
    const todasCasam = anc.every((a) => a.ok);
    const todasJa = anc.length > 0 && anc.every((a) => a.jaAplicada);
    // situação da intervenção como um todo:
    let situacao;
    if (todasCasam) situacao = 'pronta';
    else if (todasJa) situacao = 'ja_aplicada';
    else situacao = 'erro';
    return {
      nome: interv.nome, arquivo: interv._arquivo, descricao: interv.descricao || '',
      titulo: interv.titulo || interv.nome, explicacao: interv.explicacao || '',
      promovivel: interv.promovivel === true, dependeDe: interv.dependeDe || [],
      formatoOk: problemas.length === 0, problemas,
      ancoras: anc, aplicavelDireto: todasCasam, situacao,
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

      // Cada intervenção vira um card com ESTADO claro (badge colorido) + explicação
      // humana. A descrição técnica fica num "ver detalhes" para quem quiser rastrear.
      const badgeDe = (d) => {
        if (!d.promovivel) return { cor:'#80868b', bg:'#f1efe8', txt:'só do teste', desc:'Não entra no formulário real — é ferramenta de teste.' };
        if (d.situacao === 'ja_aplicada') return { cor:'#1a8a52', bg:'#e6f4ea', txt:'já no ar', desc:'Já está no formulário. Nada a fazer.' };
        if (d.situacao === 'pronta') return { cor:'#185fa5', bg:'#e6f1fb', txt:'pronta para publicar', desc:'Testada e pronta. Entra quando você baixar o motor.' };
        return { cor:'#c5221f', bg:'#fcebeb', txt:'precisa reconferir', desc:'O código mudou de um jeito inesperado. Reconfira antes de publicar.' };
      };
      const cardInterv = diag.map((d) => {
        const b = badgeDe(d);
        const tecnico = d.descricao
          ? `<details style="margin-top:8px"><summary class="nota" style="cursor:pointer">ver detalhes técnicos</summary><div class="nota" style="margin-top:6px;white-space:pre-wrap">${esc(d.descricao)}<br>alvo: ${esc(intervencoes.find((i)=>i.nome===d.nome).alvo)} · ${d.ancoras.length} transformação(ões)</div></details>`
          : '';
        return `<div style="border:0.5px solid #e3e3dd;border-radius:12px;padding:14px 16px;margin:10px 0">
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:4px">
            <span style="font-weight:600;font-size:15px">${esc(d.titulo)}</span>
            <span style="font-size:12px;background:${b.bg};color:${b.cor};padding:2px 10px;border-radius:20px">${esc(b.txt)}</span>
          </div>
          ${d.explicacao ? `<div style="font-size:13px;color:#444;line-height:1.6">${esc(d.explicacao)}</div>` : ''}
          <div style="font-size:12px;color:#80868b;margin-top:6px">${esc(b.desc)}</div>
          ${tecnico}
        </div>`;
      }).join('');

      // Resumo do topo: há algo a publicar, ou está tudo no ar?
      const promProntas = diag.filter((d) => d.promovivel && d.situacao === 'pronta');
      const promErro = diag.filter((d) => d.promovivel && d.situacao === 'erro');
      const tudoNoAr = promProntas.length === 0 && promErro.length === 0;

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

      res.send(page('Publicar mudanças do formulário', `
        <div class="card">
          <h1>Publicar mudanças do formulário</h1>
          <p class="mut">Leva o que você testou para o formulário de verdade. São dois passos, nesta ordem: primeiro o <strong>motor</strong> (o código), depois os <strong>campos</strong> (no banco). Nada muda no formulário sem você agir aqui.</p>
        </div>

        ${tudoNoAr
          ? `<div class="card" style="border-left:4px solid #1a8a52;background:#f3faf5">
               <div style="font-weight:600;color:#1a7f37">✓ Tudo já publicado — nada a fazer agora</div>
               <p class="nota" style="margin-top:4px">As melhorias testadas já estão no formulário. Esta tela só tem trabalho quando você cria algo novo para publicar.</p>
             </div>`
          : (promErro.length
             ? `<div class="card" style="border-left:4px solid #c5221f;background:#fdf3f3">
                  <div style="font-weight:600;color:#b3261e">⚠ Uma melhoria precisa ser reconferida</div>
                  <p class="nota" style="margin-top:4px">O código de produção mudou de um jeito que não bate com o que foi testado. Veja qual abaixo antes de publicar.</p>
                </div>`
             : `<div class="card" style="border-left:4px solid #185fa5;background:#f3f8fd">
                  <div style="font-weight:600;color:#185fa5">${promProntas.length} melhoria(s) pronta(s) para publicar</div>
                  <p class="nota" style="margin-top:4px">Testadas e prontas. Siga o passo 1 abaixo para levá-las ao formulário.</p>
                </div>`)}

        <div class="card">
          <h2>Melhorias testadas</h2>
          <p class="nota">Cada uma mostra o que faz e em que situação está.</p>
          ${cardInterv}
        </div>

        <div class="card">
          <h2>Passo 1 · Baixar o motor <span class="nota">(o código)</span></h2>
          <p class="nota">Gera o arquivo <code>atb-form-engine.js</code> com as melhorias prontas já embutidas (${promProntas.map((i)=>esc(i.titulo)).join(' + ') || (tudoNoAr ? 'nenhuma nova — as atuais já estão no ar' : 'nenhuma')}). Você baixa e sobe no GitHub. As ferramentas de teste ficam de fora.</p>
          <form method="POST" action="/atb/admin/form-transportador/gerar-engine" ${pilhaOk ? '' : 'onsubmit="alert(\'Uma melhoria precisa ser reconferida — resolva antes.\');return false"'}>
            <button type="submit">⬇ Baixar arquivo do motor</button>
          </form>
          ${pilhaOk ? '' : `<p class="nota" style="color:#c5221f;margin-top:8px">Não dá para baixar agora: ${esc(pilhaErro)}</p>`}
        </div>

        <div class="card">
          <h2>Passo 2 · Atualizar os campos <span class="nota">(no banco) · só depois do deploy</span></h2>
          <p class="nota">Estado atual: schema HUSF ${husfSchema ? ('versão <strong>' + esc(String(husfSchema.versao)) + '</strong> — posologia ' + (husfEstrut ? '<span style="color:#1a8a52">estruturada</span>' : '<span style="color:#a4700a">texto livre</span>')) : 'não encontrado'}. Atualizar grava uma nova versão dos campos no banco.</p>
          <div style="background:#faeeda;border-radius:8px;padding:10px 14px;margin:8px 0;font-size:13px;color:#854f0b;line-height:1.6">
            <strong>A ordem importa:</strong> só faça o passo 2 depois que o motor (passo 1) já estiver no ar. Se inverter, fichas novas gravam campos que os leitores ainda não sabem ler, e aparecem vazias.
          </div>
          <form method="POST" action="/atb/admin/form-transportador/promover-schema" onsubmit="return confirm('Atualizar os campos do HUSF no banco? Confirme que o motor (passo 1) já está no ar.')">
            <button type="submit">Atualizar campos no banco</button>
          </form>
        </div>

        <div class="card">
          <h2>O que exatamente vai mudar no código</h2>
          <p class="nota">Para quem quiser conferir linha a linha. Vermelho = como está hoje · verde = como fica depois de publicar.</p>
          ${diffs || '<p class="nota">nenhuma mudança nova a publicar.</p>'}
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
