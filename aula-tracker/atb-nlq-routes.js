// atb-nlq-routes.js
// ════════════════════════════════════════════════════════════════════════════
// /atb/admin/pergunta — pergunta em português → SQL (via Ollama) → executa em
// conexão read-only → formata no servidor. Ferramenta admin sob demanda.
//
// PRIVACIDADE: o modelo recebe SÓ a pergunta + o glossário. Os RESULTADOS (linhas
// de paciente) são formatados aqui no servidor e NUNCA voltam ao modelo.
//
// DEFESA EM PROFUNDIDADE:
//   1ª parede — roPool usa DATABASE_URL_RO (role atb_nlq_ro, read-only no banco).
//   2ª parede — cada query roda em START TRANSACTION READ ONLY + statement_timeout.
//   3ª parede — o guard (atb-nlq-guard) só deixa passar SELECT/WITH, um statement.
//
// Montagem no app.js:
//   import { registerNlqRoutes } from './atb-nlq-routes.js';
//   const roPool = new Pool({ connectionString: process.env.DATABASE_URL_RO || DATABASE_URL,
//                             ssl: { rejectUnauthorized: false } });
//   try { registerNlqRoutes(app, roPool, { adminRequired }); }
//   catch (e) { console.error('ERRO registerNlqRoutes', e); }
//
// Env vars:
//   DATABASE_URL_RO       — conn string do role read-only (ver receita no chat).
//   ── Transporte primário: API OpenAI-compatible (DeepInfra) ──
//   ATB_NLQ_API_URL       — base (default 'https://api.deepinfra.com/v1/openai').
//   ATB_NLQ_API_KEY       — token do provedor (SÓ na env). Se setada, usa a API.
//   ATB_NLQ_MODEL         — modelo. Com API: default 'meta-llama/Llama-3.3-70B-Instruct-Turbo'.
//       ⚠ Se você tinha ATB_NLQ_MODEL='qwen2.5-coder:7b' (era do Ollama), APAGUE ou troque —
//         senão o DeepInfra dá 404 model_not_found.
//   ── Fallback: Ollama local (usado só se ATB_NLQ_API_KEY estiver vazia) ──
//   ATB_OLLAMA_URL / ATB_OLLAMA_CF_ID / ATB_OLLAMA_CF_SECRET / ATB_OLLAMA_TOKEN.
// ════════════════════════════════════════════════════════════════════════════

import { GLOSSARIO_ATB, ENUMS_ATB, FEWSHOTS_ATB } from './atb-nlq-glossario.js';
import { prepararSQL } from './atb-nlq-guard.js';

// Transporte primário: API OpenAI-compatible (DeepInfra). Fallback: Ollama local.
const NLQ_API_URL  = (process.env.ATB_NLQ_API_URL || 'https://api.deepinfra.com/v1/openai').replace(/\/$/, '');
const NLQ_API_KEY  = process.env.ATB_NLQ_API_KEY || '';
const NLQ_MODEL    = process.env.ATB_NLQ_MODEL || (NLQ_API_KEY ? 'meta-llama/Llama-3.3-70B-Instruct-Turbo' : 'qwen2.5-coder:7b');
// Fallback Ollama (usado só quando NLQ_API_KEY está vazia):
const OLLAMA_URL       = process.env.ATB_OLLAMA_URL       || '';
const OLLAMA_TOKEN     = process.env.ATB_OLLAMA_TOKEN     || '';
const OLLAMA_CF_ID     = process.env.ATB_OLLAMA_CF_ID     || '';
const OLLAMA_CF_SECRET = process.env.ATB_OLLAMA_CF_SECRET || '';
const NLQ_TIMEOUT  = 45000;   // ms — teto (DeepInfra responde em segundos; folga p/ fallback local)
const SQL_TIMEOUT  = '5s';    // statement_timeout por query

const esc = (s) => String(s ?? '').replace(/[&<>"]/g, c =>
  ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;' }[c]));

// ── Monta o system prompt: glossário + valores de enum + few-shots ───────────
function blocoEnums() {
  const linhas = Object.entries(ENUMS_ATB).map(([col, vals]) =>
    `- ${col}: ${vals.map(v => `'${v}'`).join(' | ')}`);
  return '# VALORES VÁLIDOS DE ENUM\n' +
    'Para estas colunas, use EXATAMENTE um dos valores abaixo (copie o texto literal). ' +
    'NUNCA invente, traduza ou parafraseie o texto da pergunta para um valor de enum — ' +
    'mapeie a intenção do usuário para a string exata da lista.\n' +
    linhas.join('\n');
}

function systemPrompt() {
  const shots = FEWSHOTS_ATB.map(f =>
    `-- Pergunta: ${f.pergunta}\n${f.sql}`).join('\n\n');
  return `${GLOSSARIO_ATB}\n\n${blocoEnums()}\n\n# EXEMPLOS\n${shots}`;
}

// ── Gera o SQL: DeepInfra (OpenAI-compatible) se houver key; senão Ollama ─────
async function gerarSQL(pergunta) {
  const messages = [
    { role: 'system', content: systemPrompt() },
    { role: 'user',   content: pergunta },
  ];
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), NLQ_TIMEOUT);
  try {
    if (NLQ_API_KEY) {
      // Transporte primário: API OpenAI-compatible (DeepInfra). Sem response_format:
      // a saída é SQL cru; o guard (prepararSQL) remove cercas de markdown.
      const resp = await fetch(`${NLQ_API_URL}/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${NLQ_API_KEY}` },
        body: JSON.stringify({ model: NLQ_MODEL, temperature: 0, messages }),
        signal: ctrl.signal,
      });
      if (!resp.ok) {
        const corpo = await resp.text().catch(() => '');
        throw new Error(`API HTTP ${resp.status} (model:${NLQ_MODEL}) ${corpo.slice(0, 200)}`);
      }
      const data = await resp.json();
      return (data?.choices?.[0]?.message?.content || '').trim();
    }
    // Fallback: Ollama local (formato nativo /api/chat).
    if (!OLLAMA_URL) throw new Error('Configure ATB_NLQ_API_KEY (DeepInfra) ou ATB_OLLAMA_URL.');
    const resp = await fetch(`${OLLAMA_URL.replace(/\/$/,'')}/api/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(OLLAMA_CF_ID     ? { 'CF-Access-Client-Id':     OLLAMA_CF_ID }     : {}),
        ...(OLLAMA_CF_SECRET ? { 'CF-Access-Client-Secret': OLLAMA_CF_SECRET } : {}),
        ...(OLLAMA_TOKEN     ? { 'x-nlq-token':             OLLAMA_TOKEN }     : {}),
      },
      body: JSON.stringify({ model: NLQ_MODEL, stream: false, options: { temperature: 0 }, messages }),
      signal: ctrl.signal,
    });
    if (!resp.ok) throw new Error(`Ollama HTTP ${resp.status}`);
    const data = await resp.json();
    return (data?.message?.content || '').trim();
  } finally {
    clearTimeout(t);
  }
}

// ── Executa em transação read-only, com timeout curto ────────────────────────
async function executarLeitura(roPool, sql) {
  const client = await roPool.connect();
  try {
    await client.query('START TRANSACTION READ ONLY');
    await client.query(`SET LOCAL statement_timeout = '${SQL_TIMEOUT}'`);
    const r = await client.query(sql);
    await client.query('COMMIT');
    return r;
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch { /* noop */ }
    throw e;
  } finally {
    client.release();
  }
}

// ── Render de uma tabela HTML a partir do resultado ──────────────────────────
function tabelaHTML(rows, fields) {
  if (!rows.length) return '<p class="muted">Nenhuma linha.</p>';
  const cols = fields.map(f => f.name);
  const th = cols.map(c => `<th>${esc(c)}</th>`).join('');
  const tr = rows.slice(0, 500).map(r =>
    `<tr>${cols.map(c => {
      let v = r[c];
      if (v && typeof v === 'object') v = JSON.stringify(v);
      return `<td>${esc(v)}</td>`;
    }).join('')}</tr>`).join('');
  return `<table class="res"><thead><tr>${th}</tr></thead><tbody>${tr}</tbody></table>`;
}

function pagina({ pergunta = '', corpo = '' } = {}) {
  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pergunta ao banco — ATB</title>
<style>
  body{font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#202124;max-width:960px;margin:24px auto;padding:0 16px}
  h1{font-size:18px;margin:0 0 4px} .muted{color:#5f6368}
  form{margin:14px 0} textarea{width:100%;min-height:70px;font:inherit;padding:10px;border:1px solid #dadce0;border-radius:8px;box-sizing:border-box}
  button{margin-top:8px;padding:9px 16px;border:0;border-radius:8px;background:#1a73e8;color:#fff;font:inherit;cursor:pointer}
  pre{background:#f1f3f4;padding:12px;border-radius:8px;overflow:auto;white-space:pre-wrap}
  table.res{border-collapse:collapse;width:100%;margin-top:10px;font-size:13px}
  table.res th,table.res td{border:1px solid #e0e0e0;padding:6px 9px;text-align:left;vertical-align:top}
  table.res th{background:#f8f9fa}
  .erro{background:#fce8e6;color:#c5221f;padding:10px 12px;border-radius:8px}
  .sqlbox{margin-top:14px} .sqlbox summary{cursor:pointer;color:#5f6368;font-size:13px}
</style></head><body>
<h1>Pergunta ao banco <span class="muted">(ATB)</span></h1>
<p class="muted">Pergunte em português. A resposta é o resultado real do banco — sempre confira o SQL gerado antes de confiar.</p>
<form method="post" action="/atb/admin/pergunta">
  <textarea name="pergunta" placeholder="Ex.: quantos dias de ATB foram solicitados para pneumonia sob VM nas UTIs adulto do HUSF nos últimos 6 meses?">${esc(pergunta)}</textarea>
  <button type="submit">Perguntar</button>
</form>
${corpo}
<p style="margin-top:22px"><a href="/scih" class="muted">&#8592; Voltar ao Portal do SCIH</a></p>
</body></html>`;
}

export function registerNlqRoutes(app, roPool, deps = {}) {
  const { adminRequired } = deps;
  const gate = adminRequired || ((req, res, next) => next());

  app.get('/atb/admin/pergunta', gate, (req, res) => {
    res.send(pagina());
  });

  app.post('/atb/admin/pergunta', gate, async (req, res) => {
    const pergunta = String(req.body?.pergunta || '').trim();
    if (!pergunta) return res.send(pagina({ corpo: '<p class="erro">Escreva uma pergunta.</p>' }));

    let sqlBruto = '';
    try {
      sqlBruto = await gerarSQL(pergunta);
    } catch (e) {
      return res.send(pagina({ pergunta,
        corpo: `<p class="erro">Falha ao gerar SQL: ${esc(e.message)}</p>` }));
    }

    const v = prepararSQL(sqlBruto, 500);
    // Auditoria: sempre logar o que o modelo produziu.
    console.log('[nlq]', JSON.stringify({ pergunta, sql: v.sql, ok: v.ok, erros: v.erros }));

    if (!v.ok) {
      return res.send(pagina({ pergunta, corpo:
        `<p class="erro">SQL rejeitado pelo guard: ${esc(v.erros.join('; '))}</p>` +
        `<details class="sqlbox" open><summary>SQL gerado (bloqueado)</summary><pre>${esc(sqlBruto)}</pre></details>` }));
    }

    try {
      const r = await executarLeitura(roPool, v.sql);
      return res.send(pagina({ pergunta, corpo:
        tabelaHTML(r.rows, r.fields) +
        `<details class="sqlbox"><summary>Ver SQL usado</summary><pre>${esc(v.sql)}</pre></details>` }));
    } catch (e) {
      return res.send(pagina({ pergunta, corpo:
        `<p class="erro">Erro ao executar: ${esc(e.message)}</p>` +
        `<details class="sqlbox" open><summary>SQL usado</summary><pre>${esc(v.sql)}</pre></details>` }));
    }
  });
}
