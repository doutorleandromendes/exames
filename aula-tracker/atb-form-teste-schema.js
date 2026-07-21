// atb-form-teste-schema.js
// ════════════════════════════════════════════════════════════════════════════
// MÁQUINA DE SCHEMA DE TESTE — o schema isolado que ATIVA as capacidades novas
// do engine no ambiente de teste, sem tocar o schema de produção.
//
// Fluxo: pega o schema ATIVO de produção (HUSF), aplica transformações de schema
// NOMEADAS (aqui: posologia estruturada), e grava como instituição 'HUSF_TESTE'.
// A rota /atb/form-teste pede ?inst=HUSF_TESTE; produção pede HUSF. Isolamento
// total: fichas ZZ_TESTE gravam com instituicao=HUSF_TESTE e nunca aparecem nos
// dados reais.
//
// Diferente do engine (código → intervenção por âncora), o schema é DADO (jsonb).
// A "intervenção de schema" transforma o objeto, não texto. Mesma filosofia:
// nomeada, aplicável sobre a produção atual, idempotente.
// ════════════════════════════════════════════════════════════════════════════

import { getFormSchema, saveFormSchema } from './atb-form-schema.js';
import { page, esc } from './atb-regras-routes.js';

export const INST_TESTE = 'HUSF_TESTE';

// ── Transformação de schema: posologia estruturada ───────────────────────────
// Troca as colunas de texto livre (dose/intervalo) pelo modelo estruturado.
// Idempotente: se já estiver estruturada, não faz nada. Retorna { def, mudou }.
export function schemaPosologiaEstruturada(def) {
  const clone = JSON.parse(JSON.stringify(def || {}));
  let mudou = false;
  for (const sec of (clone.secoes || [])) {
    for (const campo of (sec.campos || [])) {
      if (campo.key !== 'posologia' || campo.type !== 'matrix') continue;
      const jaEstruturada = (campo.colunas || []).some((c) => c.key === 'dose_valor');
      if (jaEstruturada) continue;
      campo.colunas = [
        { key: 'droga', label: 'Droga', type: 'text', readonly: true },
        { key: 'dose_valor', label: 'Dose', type: 'number', step: 'any', min: 0, placeholder: '4,5' },
        { key: 'dose_unidade', label: 'Unid.', type: 'select', options: ['mg', 'g', 'UI', 'amp', 'mg/kg'] },
        { key: 'freq_tipo', label: 'Frequência', type: 'select',
          options: [{ v: 'cada', l: 'A cada X horas' }, { v: 'unica', l: 'Dose única' }, { v: 'hd', l: 'Após cada HD' }] },
        { key: 'freq_horas', label: 'A cada (h)', type: 'number', min: 1, max: 168, step: 1, placeholder: '8',
          mostrarSe: { campo: 'freq_tipo', valor: 'cada' } },
      ];
      mudou = true;
    }
  }
  return { def: clone, mudou };
}

// Registro nomeado das transformações de schema disponíveis (espelha as
// intervenções de engine, para o transportador listar o que há).
export const TRANSFORMACOES_SCHEMA = {
  'posologia-estruturada': schemaPosologiaEstruturada,
};

// ── Sincronizar HUSF_TESTE ← HUSF (produção), aplicando transformações ───────
// Recria o schema de teste a partir da produção atual. Chamado quando você quer
// começar um teste limpo (ou depois que produção mudou).
export async function sincronizarSchemaTeste(pool, nomesTransformacoes = ['posologia-estruturada']) {
  const base = await getFormSchema(pool, 'HUSF');
  if (!base) throw new Error('schema de produção (HUSF) não encontrado');
  let def = JSON.parse(JSON.stringify(base));
  const aplicadas = [];
  for (const nome of nomesTransformacoes) {
    const fn = TRANSFORMACOES_SCHEMA[nome];
    if (!fn) throw new Error('transformação de schema desconhecida: ' + nome);
    const r = fn(def);
    def = r.def;
    aplicadas.push({ nome, mudou: r.mudou });
  }
  const versao = await saveFormSchema(pool, INST_TESTE, def, null);
  return { versao, aplicadas, baseVersao: base.versao };
}

export function registerFormTesteSchemaRoutes(app, pool, adminRequired) {
  const gate = adminRequired || ((req, res, next) => next());

  // ── PAINEL (GET) — porta de entrada do ambiente de teste ──────────────────
  app.get('/atb/admin/form-teste', gate, async (req, res) => {
    try {
      const prod = await getFormSchema(pool, 'HUSF');
      const teste = await getFormSchema(pool, INST_TESTE);
      const nFichas = (await pool.query(
        `SELECT count(*) n FROM atb_fichas WHERE instituicao=$1 AND deletado_em IS NULL`, [INST_TESTE]
      )).rows[0].n;
      const posColsTeste = (() => {
        if (!teste) return null;
        for (const sec of (teste.secoes || [])) for (const c of (sec.campos || []))
          if (c.key === 'posologia') return (c.colunas || []).map((x) => x.key).join(', ');
        return '(sem posologia)';
      })();
      const estruturado = posColsTeste && posColsTeste.includes('dose_valor');

      res.send(page('Ambiente de teste do formulário', `
        <div class="card">
          <h1>Ambiente de teste do formulário</h1>
          <p class="mut">Testa mudanças no formulário sem tocar em produção. O engine de teste é <strong>gerado</strong> a partir do de produção + intervenções nomeadas; o schema de teste (<code>${esc(INST_TESTE)}</code>) é isolado.</p>
        </div>

        <div class="card">
          <h2>Estado</h2>
          <table style="font-size:14px">
            <tr><td style="padding:4px 10px">Schema de produção (HUSF)</td><td>${prod ? 'versão <strong>' + esc(String(prod.versao)) + '</strong>' : '<span style="color:#c5221f">não encontrado</span>'}</td></tr>
            <tr><td style="padding:4px 10px">Schema de teste (${esc(INST_TESTE)})</td><td>${teste ? 'versão <strong>' + esc(String(teste.versao)) + '</strong>' : '<span class="mut">ainda não criado</span>'}</td></tr>
            <tr><td style="padding:4px 10px">Posologia no teste</td><td>${teste ? '<code>' + esc(posColsTeste) + '</code> ' + (estruturado ? '<span style="color:#1a8a52">✓ estruturada</span>' : '<span style="color:#e8a33d">texto livre</span>') : '—'}</td></tr>
            <tr><td style="padding:4px 10px">Fichas de teste (ZZ_TESTE)</td><td><strong>${esc(String(nFichas))}</strong></td></tr>
          </table>
        </div>

        <div class="card">
          <h2>1 · Preparar o schema de teste</h2>
          <p class="nota">Recria <code>${esc(INST_TESTE)}</code> a partir da produção atual + a intervenção de posologia estruturada. Idempotente — pode rodar quantas vezes quiser.</p>
          <form method="POST" action="/atb/admin/form-teste/sincronizar" onsubmit="return confirm('Recriar o schema de teste a partir da produção atual?')">
            <button type="submit">↻ Sincronizar schema de teste ← produção</button>
          </form>
        </div>

        <div class="card">
          <h2>2 · Testar no formulário</h2>
          <p class="nota">Abre o formulário de teste (engine gerado + schema ${esc(INST_TESTE)}). Nomeie o paciente como <strong>ZZ_TESTE…</strong> — as fichas são descartáveis.</p>
          <p><a href="/atb/form-teste" style="font-size:14px">→ Abrir formulário de teste</a></p>
        </div>

        <div class="card">
          <h2>3 · Promover <span class="nota">(em breve — Passo 3)</span></h2>
          <p class="nota">Quando a mudança estiver aprovada, o transportador gera o arquivo de produção (produção + intervenção) para você baixar e comitar. Ainda não construído.</p>
        </div>`));
    } catch (e) {
      console.error('[atb] painel form-teste:', e.message);
      res.status(500).send(page('Erro', `<div class="card"><h1>Falha</h1><p class="mut">${esc(e.message)}</p></div>`));
    }
  });

  // Recria HUSF_TESTE a partir da produção + transformações.
  app.post('/atb/admin/form-teste/sincronizar', gate, async (req, res) => {
    try {
      const r = await sincronizarSchemaTeste(pool);
      // Navegador → volta ao painel; API (Accept: json) → JSON.
      if ((req.get('accept') || '').includes('application/json')) return res.json({ ok: true, ...r });
      res.send(page('Schema de teste sincronizado', `
        <div class="card"><h1>Pronto</h1>
          <p class="mut">Schema <code>${esc(INST_TESTE)}</code> recriado como versão <strong>${esc(String(r.versao))}</strong>, a partir da produção v${esc(String(r.baseVersao))}.</p>
          <p><a href="/atb/admin/form-teste">← Voltar ao painel</a> · <a href="/atb/form-teste">Abrir formulário de teste →</a></p>
        </div>`));
    } catch (e) {
      console.error('[atb] sincronizar schema teste:', e.message);
      res.status(500).json({ ok: false, error: e.message });
    }
  });
}
