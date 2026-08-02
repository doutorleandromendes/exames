// ════════════════════════════════════════════════════════════════════════════
//  Link de formulário pré-preenchido
//
//  Caso de uso: o SCIH orienta uma troca de antimicrobiano e o prescritor vai
//  acatar. Em vez de ele redigitar todo o contexto do paciente, o SCIH gera um
//  link a partir da ficha atual; ao abrir, o formulário já vem com os dados do
//  paciente e do quadro, e ele preenche só a prescrição nova.
//
//  POR QUE UM TOKEN, E NÃO OS DADOS NA URL
//  O link é enviado por mensagem. Se os dados fossem para a querystring, o nome
//  e o prontuário do paciente apareceriam no log de acesso do servidor, no
//  histórico do navegador e — o pior — na pré-visualização do link gerada pelo
//  aplicativo de mensagens, que busca a página. Com token, a URL não carrega
//  nada identificável: o servidor troca o token pelos dados só quando o
//  prescritor abre a página.
//
//  O QUE VEM PREENCHIDO
//  Tudo que descreve o paciente e o quadro (identificação, internação, clínica,
//  comorbidades, ATB prévios, culturas, dispositivos, função renal, peso/altura).
//
//  O QUE NÃO VEM (e por quê)
//    • atb_solicitado / posologia / widgets de dose / tempo previsto
//        → é justamente o que está mudando; pré-preencher transformaria a
//          prescrição num carimbo.
//    • crm / prescritor_nome
//        → a prescrição é ato do prescritor; o campo tem de ser dele.
//    • bloco SOFA
//        → é do dia; reaproveitar seria registrar um escore que não foi medido.
//
//  Integração em atb-routes.js:
//    import { registerPrefillRoutes, ensurePrefillSchema, resolverPrefill }
//      from './atb-prefill-routes.js';
//    // no boot:      await ensurePrefillSchema(pool);
//    // nas rotas:    registerPrefillRoutes(app, pool, adminRequired);
//    // em servirFicha: const pre = await resolverPrefill(pool, req.query.pre, inst);
// ════════════════════════════════════════════════════════════════════════════

import crypto from 'crypto';
import { COLUNA_DE } from './atb-field-registry.js';
import { getFormSchema } from './atb-form-schema.js';

// Validade do link. Tempo de o prescritor ver a mensagem, sem deixar link vivo
// indefinidamente. O uso é múltiplo dentro da validade (abrir e fechar por
// engano não queima o link).
const VALIDADE_HORAS = 24;

// Campos que nunca vão no pré-preenchimento (ver cabeçalho para o porquê).
const NAO_PREFILL = new Set([
  'atb_solicitado', 'posologia', 'dose_vanco', 'dose_bactrim',
  'tempo_previsto', 'oxacilina_associacao',
  'crm', 'prescritor_nome',
  '_sofa_bloco', 'sofa',
  // historia_clinica NÃO vem herdada, por dois motivos que se somam:
  //   1) A prescrição nova é de outro momento clínico (a troca). A história
  //      precisa dizer por que está trocando, não repetir a da admissão.
  //   2) O gatilho de IA da história avalia justamente esse campo. Herdando um
  //      texto que já passou na checagem, o aviso nunca dispara e a salvaguarda
  //      fica neutralizada — o prescritor envia sem revisar.
  'historia_clinica',
]);

export async function ensurePrefillSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atb_prefill_tokens (
      token        TEXT PRIMARY KEY,
      ficha_id     INTEGER NOT NULL REFERENCES atb_fichas(id) ON DELETE CASCADE,
      instituicao  TEXT,
      criado_por   TEXT,
      criado_em    TIMESTAMPTZ DEFAULT now(),
      expira_em    TIMESTAMPTZ NOT NULL,
      aberturas    INTEGER DEFAULT 0
    )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_prefill_expira
    ON atb_prefill_tokens(expira_em)`);
  // Faxina dos vencidos: o token perde a validade em horas, não faz sentido
  // guardar o histórico. Roda no boot; barato porque a tabela é pequena.
  await pool.query(`DELETE FROM atb_prefill_tokens WHERE expira_em < now() - interval '7 days'`);
}

// Monta os valores iniciais do formulário a partir de uma ficha, no formato que
// o motor espera (chaves do SCHEMA, não colunas do banco).
async function valoresDaFicha(pool, ficha, inst) {
  const schema = await getFormSchema(pool, inst);
  if (!schema || !Array.isArray(schema.secoes)) return {};
  const extras = (ficha.payload_raw && typeof ficha.payload_raw === 'object') ? ficha.payload_raw : {};
  const out = {};
  for (const sec of schema.secoes) {
    for (const campo of (sec.campos || [])) {
      const key = campo.key;
      if (!key || NAO_PREFILL.has(key)) continue;
      // Campo promovido a coluna usa o nome mapeado; senão vem de payload_raw.
      const col = COLUNA_DE[key] || key;
      let v = Object.prototype.hasOwnProperty.call(ficha, col) ? ficha[col] : undefined;
      if (v === undefined) v = extras[key];
      if (v === null || v === undefined || v === '') continue;
      // Datas viram YYYY-MM-DD (o input date do formulário espera assim).
      if (v instanceof Date) {
        const mm = String(v.getUTCMonth() + 1).padStart(2, '0');
        const dd = String(v.getUTCDate()).padStart(2, '0');
        v = `${v.getUTCFullYear()}-${mm}-${dd}`;
      }
      out[key] = v;
    }
  }
  return out;
}

/**
 * Troca um token pelos valores de pré-preenchimento.
 * Devolve null (silenciosamente) se o token não existe, venceu ou é de outro
 * tenant — o formulário abre em branco, sem revelar nada.
 */
export async function resolverPrefill(pool, token, inst) {
  if (!token || typeof token !== 'string' || !/^[A-Za-z0-9_-]{16,64}$/.test(token)) return null;
  try {
    const { rows } = await pool.query(
      `SELECT t.ficha_id, t.instituicao
         FROM atb_prefill_tokens t
        WHERE t.token = $1 AND t.expira_em > now()`, [token]);
    const reg = rows[0];
    if (!reg) return null;
    if (reg.instituicao && inst && reg.instituicao !== inst) return null;

    const ficha = (await pool.query(
      `SELECT * FROM atb_fichas WHERE id = $1 AND deletado_em IS NULL`, [reg.ficha_id])).rows[0];
    if (!ficha) return null;

    // Contador de aberturas: só para diagnóstico (uso múltiplo é permitido).
    pool.query(`UPDATE atb_prefill_tokens SET aberturas = COALESCE(aberturas,0) + 1 WHERE token = $1`,
      [token]).catch(() => {});

    return await valoresDaFicha(pool, ficha, reg.instituicao || inst);
  } catch (e) {
    console.error('[atb] resolverPrefill:', e.message);
    return null;
  }
}

export function registerPrefillRoutes(app, pool, adminRequired) {
  // Gera o link a partir de uma ficha. Devolve a URL pronta para copiar.
  app.post('/atb/admin/fichas/:id/link-prefill', adminRequired, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id)) return res.status(400).json({ ok: false, erro: 'id inválido' });
    try {
      const ficha = (await pool.query(
        `SELECT f.id, i.sigla AS instituicao
           FROM atb_fichas f LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
          WHERE f.id = $1 AND f.deletado_em IS NULL`, [id])).rows[0];
      if (!ficha) return res.status(404).json({ ok: false, erro: 'ficha não encontrada' });

      const inst = ficha.instituicao || req.atbTenant || null;
      const token = crypto.randomBytes(24).toString('base64url');   // 32 chars, não adivinhável
      await pool.query(
        `INSERT INTO atb_prefill_tokens (token, ficha_id, instituicao, criado_por, expira_em)
         VALUES ($1, $2, $3, $4, now() + interval '${VALIDADE_HORAS} hours')`,
        [token, id, inst, (req.user && (req.user.email || req.user.nome)) || null]);

      const base = `${req.protocol}://${req.get('host')}`;
      res.json({
        ok: true,
        url: `${base}/atb/form?pre=${token}`,
        validade_horas: VALIDADE_HORAS,
      });
    } catch (e) {
      console.error('[atb] link-prefill:', e.message);
      res.status(500).json({ ok: false, erro: e.message });
    }
  });
}
