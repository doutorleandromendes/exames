// atb-historia-routes.js
// ════════════════════════════════════════════════════════════════════════════
// /atb/api/checar-historia — nudge de história narrativa (fase 1).
//
// FILOSOFIA: nunca bloqueia por infra nem por julgamento. Se o Ollama está fora,
// lento, ou devolve lixo → { disponivel:false } e o formulário envia direto
// (fail-open no cliente). Só quando o LLM responde "telegráfica" o cliente mostra
// o modal de acknowledgment (revisar / enviar assim mesmo + motivo).
//
// LOG COMO RÓTULOS: cada checagem grava uma linha em atb_historia_checagens.
// Os OVERRIDES ("o modelo disse telegráfica e o humano enviou assim mesmo") são
// o rótulo de maior sinal — a matéria-prima do conjunto de avaliação/treino
// futuro. É a fase 0 construindo o dataset enquanto ajuda.
//
// Env:
//   ATB_NARRATIVA_OLLAMA_URL — URL do Ollama da história (default: ATB_OLLAMA_URL).
//     Permite apontar a história pro PC do PACS (permanente) enquanto o NL→SQL
//     usa o Mac. Enquanto não setar, cai no ATB_OLLAMA_URL (mesmo host do NL→SQL).
//   ATB_NARRATIVA_MODEL — modelo (default: 'llama3.2'). Tarefa fácil (prosa vs
//     telegrama) → modelo pequeno basta e roda rápido mesmo em CPU modesta.
//   ATB_OLLAMA_CF_ID / ATB_OLLAMA_CF_SECRET — Cloudflare Access (se houver).
//
// Registro no app.js: registerHistoriaRoutes(app, pool);  (sem gate, igual /fichas)
// ════════════════════════════════════════════════════════════════════════════

import { montarMensagensNarrativa, parseSaidaNarrativa } from './atb-historia-narrativa.js';

const OLLAMA_URL       = process.env.ATB_NARRATIVA_OLLAMA_URL || process.env.ATB_OLLAMA_URL || '';
const OLLAMA_CF_ID     = process.env.ATB_OLLAMA_CF_ID     || '';
const OLLAMA_CF_SECRET = process.env.ATB_OLLAMA_CF_SECRET || '';
const NARRATIVA_MODEL  = process.env.ATB_NARRATIVA_MODEL || 'llama3.2';

// Schema de saída — força o Ollama a devolver JSON válido no nível do decodificador
// (resolve JSON quebrado e tipos errados que modelos pequenos produzem).
const FORMATO_NARRATIVA = {
  type: 'object',
  properties: {
    narrativa: { type: 'boolean' },
    aviso: { type: 'string' },
  },
  required: ['narrativa', 'aviso'],
};

const PING_TIMEOUT = 1500;   // ms — decidir "disponível" rápido
const CHAT_TIMEOUT = 8000;   // ms — geração da classificação

function headersOllama() {
  return {
    'Content-Type': 'application/json',
    ...(OLLAMA_CF_ID     ? { 'CF-Access-Client-Id':     OLLAMA_CF_ID }     : {}),
    ...(OLLAMA_CF_SECRET ? { 'CF-Access-Client-Secret': OLLAMA_CF_SECRET } : {}),
  };
}

async function comTimeout(promiseFn, ms) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try { return await promiseFn(ctrl.signal); }
  finally { clearTimeout(t); }
}

// Ollama está de pé e alcançável? (ping curto em /api/tags)
async function ollamaDisponivel() {
  if (!OLLAMA_URL) return false;
  try {
    const r = await comTimeout((signal) => fetch(`${OLLAMA_URL.replace(/\/$/,'')}/api/tags`,
      { headers: headersOllama(), signal }), PING_TIMEOUT);
    return r.ok;
  } catch { return false; }
}

// Classifica a história. Retorna { narrativa, aviso } ou null (trata como fail-open).
async function classificar(historia) {
  try {
    const r = await comTimeout((signal) => fetch(`${OLLAMA_URL.replace(/\/$/,'')}/api/chat`, {
      method: 'POST', headers: headersOllama(), signal,
      body: JSON.stringify({
        model: NARRATIVA_MODEL, stream: false, format: FORMATO_NARRATIVA,
        options: { temperature: 0 },
        messages: montarMensagensNarrativa(historia),
      }),
    }), CHAT_TIMEOUT);
    if (!r.ok) return null;
    const data = await r.json();
    return parseSaidaNarrativa(data?.message?.content || '');
  } catch { return null; }
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
  garantirTabela(pool).catch(e => console.error('[historia] migration', e));

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
    const inst = String(req.body?.inst || '') || null;

    if (!historia) return res.json({ disponivel: false });   // nada a checar → fail-open

    const up = await ollamaDisponivel();
    if (!up) return res.json({ disponivel: false });         // infra fora → fail-open

    const r = await classificar(historia);
    if (!r) return res.json({ disponivel: false });          // lixo/timeout → fail-open

    // Log (rótulo). Não deixa erro de log travar o fluxo.
    let checagem_id = null;
    try {
      const ins = await pool.query(
        `INSERT INTO atb_historia_checagens (inst, historia, disponivel, narrativa, aviso)
         VALUES ($1,$2,true,$3,$4) RETURNING id`,
        [inst, historia, r.narrativa, r.aviso || null]);
      checagem_id = ins.rows[0].id;
    } catch (e) { console.error('[historia] log', e.message); }

    return res.json({ disponivel: true, narrativa: r.narrativa, aviso: r.aviso || '', checagem_id });
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
