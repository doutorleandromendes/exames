// atb-export-routes.js
// ════════════════════════════════════════════════════════════════════════════
// EXPORTAÇÃO DE DADOS EM CSV  —  duas portas, dois escopos.
//
//  A) TOTALIDADE (admin-only) — todo o conteúdo do sistema ATB:
//       colunas de atb_fichas (ficha + parecer/SCIH + adesão) + atb_avaliacoes
//       (classificação IrAS, etiologia, micro, desfecho, SAPS3, triagem).
//     Rotas:  GET /atb/admin/export         (página com os recortes)
//             GET /atb/admin/export.csv      (download)
//     Gate:   adminRequired (super_admin / break-glass adm=1).
//
//  B) PRESCRITORES (restrito por IP, IGUAL à consulta/farmácia) — EXCLUSIVAMENTE
//       o conteúdo que o prescritor inseriu na ficha (campos do formulário),
//       tanto do sistema novo quanto das fichas importadas do JotForm. NÃO sai
//       nada de parecer SCIH, IrAS, adesão, links ou colunas de sistema.
//     Rotas:  GET /atb/export                (página com os recortes)
//             GET /atb/export/prescritores.csv (download)
//     Gate:   temAcesso = admin (cookie) OU IP do hospital (mesma função do
//             /consulta — fonte única do gate; ver atb-consulta-routes.js).
//
//  RECORTES DE TEMPO (querystring ?periodo=): 30d · 3m · 1a · total.
//  A data canônica é a MESMA do resto do projeto:
//     COALESCE(data_referencia, jotform_created_at, created_at)
//
//  Colunas do CSV de prescritores são DERIVADAS do registro de campos
//  (atb-field-registry.js → camposDoSchema), interseção com as colunas reais
//  de atb_fichas, menos uma BLOCKLIST de segurança (defesa em profundidade:
//  campos SCIH/sistema nunca vazam mesmo se um dia forem parte do schema).
//
//  Montagem (dentro de registerAtbRoutes, em atb-routes.js):
//     import { registerExportRoutes } from './atb-export-routes.js';
//     registerExportRoutes(app, pool, adminRequired);
// ════════════════════════════════════════════════════════════════════════════

import { temAcesso, paginaRestrito } from './atb-consulta-routes.js';
import { getFormSchema } from './atb-form-schema.js';
import { camposDoSchema, colunasReaisFichas } from './atb-field-registry.js';

// ── Recortes de tempo pré-definidos ─────────────────────────────────────────
// chave → { intervalo SQL (null = sem corte), rótulo }
const PERIODOS = {
  '30d':   { sql: '30 days',  rotulo: 'Últimos 30 dias' },
  '3m':    { sql: '3 months', rotulo: 'Últimos 3 meses' },
  '1a':    { sql: '1 year',   rotulo: 'Último ano' },
  'total': { sql: null,       rotulo: 'Total (histórico completo)' },
};
function normPeriodo(q) {
  const k = String(q || '').trim().toLowerCase();
  return PERIODOS[k] ? k : 'total';
}

// Data canônica (idêntica ao /consulta, cartões e grade mobile do projeto).
const DATA_CANONICA = `COALESCE(f.data_referencia, f.jotform_created_at, f.created_at)`;

// ── BLOCKLIST: colunas que NUNCA saem na porta de prescritores ──────────────
// Parecer/SCIH, classificação, adesão, desfecho, links, auditoria e sistema.
// É defesa em profundidade: mesmo que uma delas apareça no schema do form
// (o JotForm histórico tinha campos SCIH embutidos), ela é removida aqui.
const BLOQUEADAS_PRESCRITOR = new Set([
  'recomendacao_scih', 'recomendacoes_especificacao', 'recomendacoes_adicionais',
  'ha_esquema_sugerido', 'avaliador', 'complemento_scih', 'parecer_evolutivo',
  'parecer_emitido_at',
  'adesao_desfecho', 'adesao_troca_atb', 'adesao_por', 'adesao_em',
  'obito', 'data_obito',
  'link_exames', 'link_labs',
  'payload_raw', 'historia_narrativa', 'status',
  'instituicao_id', 'jotform_submission_id', 'jotform_created_at',
  'synced_at', 'created_at', 'updated_at', 'deletado_em',
  'retrospectiva', 'data_referencia', 'paciente_nome_raw',
]);

// Nome de coluna aceitável para interpolar em SQL (as colunas vêm do registro,
// mas validamos mesmo assim — nunca confie, sempre verifique).
const COL_RE = /^[a-z_][a-z0-9_]*$/;

// ── Serialização de célula CSV ──────────────────────────────────────────────
// JSONB (array/objeto) → JSON compacto; Date → ISO curto; null/undefined → ''.
// Escapa com aspas quando há vírgula, aspas, ; ou quebra de linha.
function csvCell(v) {
  if (v === null || v === undefined) return '';
  let s;
  if (v instanceof Date) {
    s = isNaN(v.getTime()) ? '' : v.toISOString();
  } else if (typeof v === 'object') {
    try { s = JSON.stringify(v); } catch { s = String(v); }
  } else {
    s = String(v);
  }
  if (/[",;\n\r]/.test(s)) s = '"' + s.replace(/"/g, '""') + '"';
  return s;
}
function csvRow(cells) { return cells.map(csvCell).join(','); }

// Monta o corpo do CSV a partir de result.fields (ordem real das colunas
// retornadas) + result.rows. À prova de schema drift: coluna nova aparece só.
function montarCsv(result) {
  const cols = result.fields.map(f => f.name);
  const linhas = [cols.join(',')];               // cabeçalho (nomes já seguros)
  for (const r of result.rows) linhas.push(csvRow(cols.map(c => r[c])));
  return '\uFEFF' + linhas.join('\r\n') + '\r\n'; // BOM p/ Excel abrir acentos
}

function nomeArquivo(prefixo, periodoKey) {
  const hoje = new Date().toISOString().slice(0, 10);
  return `${prefixo}_${periodoKey}_${hoje}.csv`;
}

// ── Cláusula de tenant (idêntica ao /consulta) ──────────────────────────────
// Fichas HUSF antigas têm instituicao_id NULL → tratadas como HUSF.
function escopoTenant(inst, params) {
  if (!inst) return '';
  params.push(inst);
  const n = params.length;
  return ` AND (f.instituicao_id = (SELECT id FROM atb_instituicoes WHERE sigla=$${n})`
       + ` OR (f.instituicao_id IS NULL AND $${n}='HUSF'))`;
}

// ── Página de seleção de recorte (compartilhada pelas duas portas) ──────────
function paginaEscolha({ titulo, subtitulo, hrefBase, nota }) {
  const botoes = Object.entries(PERIODOS).map(([k, v]) =>
    `<a class="btn" href="${hrefBase}?periodo=${k}">${v.rotulo}</a>`).join('');
  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${titulo}</title>
<style>
  :root{--az:#1f6feb;--bg:#f4f6fb;--tx:#1b2330;--mut:#5b6472;--ln:#dde3ee}
  *{box-sizing:border-box}
  body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--tx);padding:28px 16px}
  .wrap{max-width:620px;margin:0 auto;background:#fff;border:1px solid var(--ln);border-radius:14px;padding:26px 24px;box-shadow:0 1px 3px rgba(20,30,50,.05)}
  h1{margin:0 0 4px;font-size:20px}
  .sub{color:var(--mut);margin:0 0 20px;font-size:14px}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  .btn{display:flex;align-items:center;justify-content:center;text-align:center;padding:16px 14px;border:1px solid var(--ln);border-radius:10px;background:#fbfcfe;color:var(--tx);text-decoration:none;font-weight:600;transition:.12s}
  .btn:hover{border-color:var(--az);background:#eef4ff;color:var(--az)}
  .nota{margin-top:20px;padding-top:16px;border-top:1px solid var(--ln);color:var(--mut);font-size:13px}
  @media(max-width:480px){.grid{grid-template-columns:1fr}}
</style></head><body>
  <div class="wrap">
    <h1>${titulo}</h1>
    <p class="sub">${subtitulo}</p>
    <div class="grid">${botoes}</div>
    ${nota ? `<div class="nota">${nota}</div>` : ''}
  </div>
</body></html>`;
}

export function registerExportRoutes(app, pool, adminRequired) {

  // ══════════════════════════════════════════════════════════════════════════
  // A) TOTALIDADE — admin-only
  // ══════════════════════════════════════════════════════════════════════════
  app.get('/atb/admin/export', adminRequired, (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(paginaEscolha({
      titulo: 'Exportar dados do ATB (completo)',
      subtitulo: 'Conteúdo integral das fichas + parecer/IrAS + adesão, em CSV. Escolha o recorte de tempo.',
      hrefBase: '/atb/admin/export.csv',
      nota: 'Inclui todas as colunas de <code>atb_fichas</code> e da avaliação SCIH '
          + '(<code>atb_avaliacoes</code>). Dados sensíveis — uso restrito.',
    }));
  });

  app.get('/atb/admin/export.csv', adminRequired, async (req, res) => {
    const periodoKey = normPeriodo(req.query.periodo);
    const per = PERIODOS[periodoKey];
    try {
      const inst = req.atbTenant;
      const params = [];
      const escT = escopoTenant(inst, params);
      const corte = per.sql
        ? ` AND ${DATA_CANONICA} >= now() - interval '${per.sql}'` : '';

      // f.* traz todas as colunas de atb_fichas na ordem física; as da avaliação
      // recebem prefixo av_ para não colidir com id/created_at/updated_at.
      const sql = `
        SELECT f.*,
               a.iras          AS av_iras,
               a.etiol_iras    AS av_etiol_iras,
               a.micro         AS av_micro,
               a.micro_at      AS av_micro_at,
               a.desfecho_iras AS av_desfecho_iras,
               a.desfecho_data AS av_desfecho_data,
               a.saps3         AS av_saps3,
               a.tempo_saps    AS av_tempo_saps,
               a.triagem_ia    AS av_triagem_ia,
               a.triagem_ia_at AS av_triagem_ia_at,
               a.avaliado_por  AS av_avaliado_por
          FROM atb_fichas f
          LEFT JOIN atb_avaliacoes a ON a.ficha_id = f.id
         WHERE f.deletado_em IS NULL${corte}${escT}
         ORDER BY ${DATA_CANONICA} DESC`;
      const result = await pool.query(sql, params);

      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition',
        `attachment; filename="${nomeArquivo('atb_completo', periodoKey)}"`);
      res.send(montarCsv(result));
    } catch (e) {
      console.error('[atb] export completo:', e.message);
      res.status(500).send('Erro ao exportar: ' + e.message);
    }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // B) PRESCRITORES — restrito por IP (igual à consulta/farmácia)
  // ══════════════════════════════════════════════════════════════════════════
  app.get('/atb/export', (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    if (!temAcesso(req)) return res.send(paginaRestrito(req));
    res.send(paginaEscolha({
      titulo: 'Exportar dados das fichas',
      subtitulo: 'Conteúdo inserido pelos prescritores no formulário. Escolha o recorte de tempo.',
      hrefBase: '/atb/export/prescritores.csv',
      nota: 'Abrange fichas do sistema novo e importadas do JotForm.',
    }));
  });

  app.get('/atb/export/prescritores.csv', async (req, res) => {
    if (!temAcesso(req)) {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.send(paginaRestrito(req));
    }
    const periodoKey = normPeriodo(req.query.periodo);
    const per = PERIODOS[periodoKey];
    try {
      const inst = req.atbTenant;

      // Colunas do prescritor = campos do formulário (registro) ∩ colunas reais,
      // menos a blocklist. O schema é por tenant; sem tenant, usa HUSF (base).
      const schema = await getFormSchema(pool, inst || 'HUSF').catch(() => null);
      const reais = await colunasReaisFichas(pool);
      const campos = schema ? camposDoSchema(schema) : [];
      const colunas = [];
      const vistos = new Set();
      for (const c of campos) {
        const col = c.col;
        if (!COL_RE.test(col)) continue;          // segurança de interpolação
        if (BLOQUEADAS_PRESCRITOR.has(col)) continue;
        if (!reais.has(col)) continue;            // extras (em payload_raw) ficam fora
        if (vistos.has(col)) continue; vistos.add(col);
        colunas.push(col);
      }
      // Fallback defensivo: se o schema não trouxe campos (banco de teste, etc.),
      // usa um conjunto seguro de colunas de prescritor conhecidas presentes.
      if (!colunas.length) {
        const conhecidas = [
          'paciente_nome', 'paciente_dn', 'paciente_idade', 'prontuario', 'atendimento',
          'setor', 'leito', 'equipe_responsavel', 'data_internacao', 'data_admissao_uti',
          'tipo_terapia', 'historia_clinica', 'cirurgia', 'foco_infeccao', 'sepse',
          'gestante', 'lactante', 'comorbidades', 'uso_atb_7d', 'atb_previos',
          'culturas_colhidas', 'culturas_previas', 'dispositivos_invasivos', 'dialise',
          'acesso_dialise', 'data_insercao_cateter', 'peso_nascimento', 'insuficiencia_renal',
          'clcr', 'peso', 'altura', 'faz_quimio', 'classificacao_fratura',
          'atb_solicitado', 'posologia', 'tempo_previsto', 'crm', 'prescritor_nome',
          'sofa', 'sofa_renal',
        ];
        for (const col of conhecidas) if (reais.has(col) && !BLOQUEADAS_PRESCRITOR.has(col)) colunas.push(col);
      }

      const params = [];
      const escT = escopoTenant(inst, params);
      const corte = per.sql
        ? ` AND ${DATA_CANONICA} >= now() - interval '${per.sql}'` : '';

      // Colunas de contexto úteis (não são de parecer): id e data de envio (BRT).
      const selCtx = `f.id,
        to_char(${DATA_CANONICA} AT TIME ZONE 'America/Sao_Paulo', 'YYYY-MM-DD') AS data_envio`;
      const selCampos = colunas.map(c => `f."${c}"`).join(',\n               ');

      const sql = `
        SELECT ${selCtx}${selCampos ? ',\n               ' + selCampos : ''}
          FROM atb_fichas f
         WHERE f.deletado_em IS NULL${corte}${escT}
         ORDER BY ${DATA_CANONICA} DESC`;
      const result = await pool.query(sql, params);

      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition',
        `attachment; filename="${nomeArquivo('atb_prescritores', periodoKey)}"`);
      res.send(montarCsv(result));
    } catch (e) {
      console.error('[atb] export prescritores:', e.message);
      res.status(500).send('Erro ao exportar: ' + e.message);
    }
  });
}
