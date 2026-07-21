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

  // Recria HUSF_TESTE a partir da produção + transformações.
  app.post('/atb/admin/form-teste/sincronizar', gate, async (req, res) => {
    try {
      const r = await sincronizarSchemaTeste(pool);
      res.json({ ok: true, ...r });
    } catch (e) {
      console.error('[atb] sincronizar schema teste:', e.message);
      res.status(500).json({ ok: false, error: e.message });
    }
  });
}
