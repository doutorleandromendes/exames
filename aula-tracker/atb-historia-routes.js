// atb-historia-routes.js
// ════════════════════════════════════════════════════════════════════════════
// /atb/api/checar-historia — nudge de história narrativa (fase 1).
//
// CAMINHO 2: classificação via API externa OpenAI-compatible (DeepInfra por
// padrão). Escolhido porque nenhum modelo LOCAL serve nesse hardware — o 3B
// erra o julgamento e o 8B na CPU do PACS PC leva ~30s (sempre fail-open). Um
// 70B hospedado acerta em <1s por centavos. PHI: o campo História, no corpus
// deste serviço, não carrega identificadores (verificado ficha a ficha); ainda
// assim há uma REDE-FINA opcional de mascaramento (ATB_HISTORIA_DEID=1) que
// remove marcas de identificador se um dia aparecerem — proteção do futuro.
//
// FILOSOFIA (inalterada): nunca bloqueia por infra nem por julgamento. API fora,
// lenta, ou lixo → { disponivel:false } → o formulário envia direto (fail-open).
// Só quando o modelo responde "telegráfica" o cliente mostra o acknowledgment.
//
// LOG COMO RÓTULOS: cada checagem grava em atb_historia_checagens; overrides são
// o rótulo de ouro pro conjunto de avaliação/treino futuro.
//
// Env:
//   ATB_NARRATIVA_API_URL — base OpenAI-compatible.
//       default 'https://api.deepinfra.com/v1/openai'
//   ATB_NARRATIVA_API_KEY — token do provedor (SÓ na env, NUNCA no código).
//   ATB_NARRATIVA_MODEL   — default 'meta-llama/Llama-3.3-70B-Instruct-Turbo'.
//   ATB_HISTORIA_DEID     — '1' liga a rede-fina de de-id (default desligada).
//
// Registro no app.js: registerHistoriaRoutes(app, pool);  (sem gate, igual /fichas)
// ════════════════════════════════════════════════════════════════════════════

import { montarMensagensNarrativa, parseSaidaNarrativa } from './atb-historia-narrativa.js';
import { montarMensagensIsc, parseSaidaIsc, RESPONSE_FORMAT_ISC } from './atb-historia-isc.js';

const API_URL   = (process.env.ATB_NARRATIVA_API_URL || 'https://api.deepinfra.com/v1/openai').replace(/\/$/, '');
const API_KEY   = process.env.ATB_NARRATIVA_API_KEY || '';
const MODEL     = process.env.ATB_NARRATIVA_MODEL || 'meta-llama/Llama-3.3-70B-Instruct-Turbo';
const DEID_ON   = process.env.ATB_HISTORIA_DEID === '1';

const CHAT_TIMEOUT = 20000;  // ms — geração da classificação (fail-open acima disso).
                             // Folga p/ picos de latência do provedor externo; no
                             // form (Fase C) segue fail-open — acima disso, envia direto.

// Schema OpenAI (json_schema) — força saída válida no decodificador.
const RESPONSE_FORMAT = {
  type: 'json_schema',
  json_schema: {
    name: 'narrativa',
    strict: true,
    schema: {
      type: 'object',
      additionalProperties: false,
      properties: { narrativa: { type: 'boolean' }, aviso: { type: 'string' } },
      required: ['narrativa', 'aviso'],
    },
  },
};

// ── Rede-fina de de-id (opcional) ────────────────────────────────────────────
// NÃO é de-identificação robusta — é um guarda-chuva leve para o caso raro de
// alguém, no futuro, digitar um identificador no texto livre. Mascaramento
// conservador: prefixos de nome (Sr./Sra./Dr./RN), prontuário/registro com
// número, e datas. Roda em ~0ms.
export function deidentificar(texto) {
  let t = String(texto);
  // "Sr./Sra./Dr./Dra./RN + Nome Próprio" → prefixo + [NOME]
  t = t.replace(/\b(Sr\.?|Sra\.?|Dr\.?|Dra\.?|RN)\s+[A-ZÀ-Ý][\wÀ-ÿ]+(?:\s+(?:d[aeo]s?\s+)?[A-ZÀ-Ý][\wÀ-ÿ]+){0,3}/g, '$1 [NOME]');
  // prontuário/registro/matrícula seguido de número
  t = t.replace(/\b(prontu[aá]rio|registro|matr[ií]cula|reg\.?|pront\.?)\s*n?[ºo°.:]*\s*\d+/gi, '$1 [NUM]');
  // datas dd/mm/aaaa ou dd-mm-aaaa
  t = t.replace(/\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b/g, '[DATA]');
  return t;
}

// ── Chamada à API (OpenAI-compatible) ────────────────────────────────────────
// Retorna { narrativa, aviso } ou null (null → fail-open no chamador).
// Chamada única ao provedor. Compartilhada pelos dois classificadores para que
// timeout, de-id, tratamento de erro e log de custo não divirjam em duas cópias.
// Devolve { conteudo, custo } ou { erro }.
async function chamarModelo(messages, responseFormat, tag) {
  if (!API_KEY) return { erro: 'sem ATB_NARRATIVA_API_KEY' };
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), CHAT_TIMEOUT);
  try {
    const r = await fetch(`${API_URL}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${API_KEY}` },
      signal: ctrl.signal,
      body: JSON.stringify({ model: MODEL, temperature: 0, response_format: responseFormat, messages }),
    });
    if (!r.ok) {
      const corpo = await r.text().catch(() => '');
      console.error(`[historia:${tag}] API HTTP`, r.status, '| model:', MODEL, '| body:', corpo.slice(0, 300));
      return { erro: `HTTP ${r.status}` };
    }
    const data = await r.json();
    const custo = data?.usage?.estimated_cost ?? null;
    if (custo != null) console.log(`[historia:${tag}] custo_estimado`, custo);
    return { conteudo: data?.choices?.[0]?.message?.content || '', custo };
  } catch (e) {
    console.error(`[historia:${tag}] API erro`, e.message);
    return { erro: e.name === 'AbortError' ? 'timeout' : e.message };
  } finally {
    clearTimeout(t);
  }
}

// Rótulo 1 — FORMA (narrativa vs telegráfica). Contrato preservado: devolve o
// objeto ou null (o chamador trata null como fail-open).
async function classificar(historia) {
  const texto = DEID_ON ? deidentificar(historia) : historia;
  const r = await chamarModelo(montarMensagensNarrativa(texto), RESPONSE_FORMAT, 'narrativa');
  if (r.erro) return null;
  return parseSaidaNarrativa(r.conteudo);
}

// Rótulo 2 — CONTEÚDO (indícios de ISC). Avaliação independente, prompt e
// few-shots próprios: fundir com a de forma contaminaria as duas.
// Devolve { isc, indicios, custo } ou { erro } — o chamador decide o que fazer.
export async function classificarIsc(historia) {
  const texto = DEID_ON ? deidentificar(historia) : historia;
  const r = await chamarModelo(montarMensagensIsc(texto), RESPONSE_FORMAT_ISC, 'isc');
  if (r.erro) return { erro: r.erro };
  const o = parseSaidaIsc(r.conteudo);
  return o ? { ...o, custo: r.custo } : { erro: 'resposta ilegível do modelo' };
}

async function garantirTabela(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atb_historia_checagens (
      id           SERIAL PRIMARY KEY,
      inst         TEXT,
      historia     TEXT,
      disponivel   BOOLEAN,
      narrativa    BOOLEAN,
      aviso        TEXT,
      override     BOOLEAN DEFAULT false,
      motivo       TEXT,
      created_at   TIMESTAMPTZ DEFAULT now()
    )
  `);
}

export function registerHistoriaRoutes(app, pool) {
  garantirTabela(pool)
    .then(() => Promise.all([
      pool.query(`ALTER TABLE atb_historia_checagens ADD COLUMN IF NOT EXISTS isc BOOLEAN`),
      pool.query(`ALTER TABLE atb_historia_checagens ADD COLUMN IF NOT EXISTS isc_indicios TEXT`),
    ]))
    .catch(e => console.error('[historia] migration', e));

  // Página de teste (isolada, sem o form real) — valida o endpoint no navegador.
  app.get('/atb/api/checar-historia', (req, res) => {
    res.send(`<!doctype html><meta charset="utf-8">
<title>Teste — checar história</title>
<style>body{font:14px system-ui,sans-serif;max-width:720px;margin:24px auto;padding:0 16px}
textarea{width:100%;min-height:90px;font:inherit;padding:10px;border:1px solid #dadce0;border-radius:8px;box-sizing:border-box}
button{margin-top:8px;padding:9px 16px;border:0;border-radius:8px;background:#1a73e8;color:#fff;font:inherit;cursor:pointer}
pre{background:#f1f3f4;padding:12px;border-radius:8px;white-space:pre-wrap}.t{color:#188038}.f{color:#c5221f}</style>
<h2>Teste — checar história <span style="color:#5f6368;font-weight:normal">(Fase B isolada)</span></h2>
<p style="color:#5f6368">Cola uma história clínica e veja como o modelo classifica. Não envia ficha nenhuma.</p>
<textarea id="h" placeholder="Ex.: BRONCOASPIRAÇÃO"></textarea>
<div><button onclick="ir()">Checar</button></div>
<div id="out"></div>
<script>
async function ir(){
  var h=document.getElementById('h').value, out=document.getElementById('out');
  out.innerHTML='<p>checando…</p>'; var t0=Date.now();
  try{
    var r=await fetch('/atb/api/checar-historia',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({historia:h,inst:'HUSF'})});
    var d=await r.json(); var ms=Date.now()-t0;
    var veredito = !d.disponivel ? '<b>indisponível</b> (fail-open: enviaria direto)'
      : (d.narrativa ? '<b class=t>NARRATIVA</b> (passa)' : '<b class=f>TELEGRÁFICA</b> (nudge apareceria)');
    out.innerHTML='<p>'+veredito+' · '+ms+'ms</p><pre>'+JSON.stringify(d,null,2)+'</pre>';
  }catch(e){ out.innerHTML='<pre class=f>erro: '+e.message+'</pre>'; }
}
</script>`);
  });

  // Checagem chamada pelo formulário antes do envio.
  app.post('/atb/api/checar-historia', async (req, res) => {
    const historia = String(req.body?.historia || '').trim();
    // O rótulo de instituição vem do TENANT (servidor), não do corpo da
    // requisição: cliente não decide em qual hospital sua checagem é logada.
    const inst = req.atbTenant || String(req.body?.inst || '') || null;

    if (!historia) return res.json({ disponivel: false });   // nada a checar → fail-open

    // Quais rótulos o cliente quer. Ausente = só 'narrativa' — assim o engine
    // já implantado (que não manda `quer`) segue funcionando idêntico, e não se
    // paga por uma classificação que nenhuma regra pediu.
    const pedidos = Array.isArray(req.body?.quer) && req.body.quer.length
      ? req.body.quer.map(String) : ['narrativa'];
    const querNarrativa = pedidos.includes('narrativa');
    const querIsc = pedidos.includes('isc');
    if (!querNarrativa && !querIsc) return res.json({ disponivel: false });

    // Em paralelo: a latência é a da mais lenta, não a soma.
    const [rn, ri] = await Promise.all([
      querNarrativa ? classificar(historia) : Promise.resolve(null),
      querIsc ? classificarIsc(historia) : Promise.resolve(null),
    ]);

    // Fail-open POR RÓTULO: se um falhar e o outro vier, usa-se o que veio.
    const okNarrativa = querNarrativa && !!rn;
    const okIsc = querIsc && !!ri && !ri.erro;
    if (!okNarrativa && !okIsc) return res.json({ disponivel: false });

    // Log (rótulo). Não deixa erro de log travar o fluxo.
    let checagem_id = null;
    try {
      const ins = await pool.query(
        `INSERT INTO atb_historia_checagens (inst, historia, disponivel, narrativa, aviso, isc, isc_indicios)
         VALUES ($1,$2,true,$3,$4,$5,$6) RETURNING id`,
        [inst, historia,
         okNarrativa ? rn.narrativa : null, okNarrativa ? (rn.aviso || null) : null,
         okIsc ? ri.isc : null, okIsc ? (ri.indicios || null) : null]);
      checagem_id = ins.rows[0].id;
    } catch (e) { console.error('[historia] log', e.message); }

    // Rótulo não pedido ou que falhou vai como null — o cliente ignora nulos.
    return res.json({
      disponivel: true,
      narrativa: okNarrativa ? rn.narrativa : null,
      aviso: okNarrativa ? (rn.aviso || '') : '',
      isc: okIsc ? ri.isc : null,
      indicios: okIsc ? (ri.indicios || '') : '',
      checagem_id,
    });
  });

  // Registra o override (enviou apesar do aviso de telegráfica) — o rótulo de ouro.
  app.post('/atb/api/checar-historia/override', async (req, res) => {
    const id = parseInt(req.body?.checagem_id, 10);
    const motivo = String(req.body?.motivo || '').trim() || null;
    if (!Number.isInteger(id)) return res.json({ ok: false });
    try {
      await pool.query(
        `UPDATE atb_historia_checagens SET override=true, motivo=$2 WHERE id=$1`,
        [id, motivo]);
      return res.json({ ok: true });
    } catch (e) {
      console.error('[historia] override', e.message);
      return res.json({ ok: false });
    }
  });
}
