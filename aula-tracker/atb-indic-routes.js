// atb-indic-routes.js
// ════════════════════════════════════════════════════════════════════════════
// Perguntas em linguagem natural AOS INDICADORES do SCIH.
//
// FLUXO EM 3 PASSOS (o que impede delírio estatístico):
//   1. LOCALIZAR  (LLM) — pergunta → localizador JSON {setores,indicadores,periodo}
//   2. RESOLVER   (determinístico) — extrai valor real + limiar + status + o
//                 veredito estatístico que EXISTE (ou a ausência dele, explícita)
//   3. VERBALIZAR (LLM) — recebe SÓ os fatos resolvidos e responde em português
//
// O modelo nunca vê o JSON cru e nunca calcula estatística. Se não há teste de
// significância para a série, ele é obrigado a dizer isso — não a opinar.
//
// Dados: agregados e públicos (sem PHI).
//
// Acesso:
//   POST /scih/indic/pergunta   — público, com RATE-LIMIT por IP (CORS p/ o
//                                 domínio do dashboard). Admin (cookie adm=1,
//                                 same-origin) passa sem limite.
//   GET  /atb/admin/indicadores — página de uso/teste no próprio app (admin).
//
// Env:
//   ATB_NLQ_API_KEY    — chave DeepInfra (a mesma do NL→SQL).
//   ATB_NLQ_API_URL    — default https://api.deepinfra.com/v1/openai
//   ATB_INDIC_MODEL    — default meta-llama/Llama-3.3-70B-Instruct-Turbo
//   ATB_INDIC_ORIGENS  — origens CORS permitidas (csv). Default: o dashboard.
//   ATB_INDIC_LIMITE   — perguntas/hora por IP (default 8).
// ════════════════════════════════════════════════════════════════════════════

import { promptLocalizador, promptVerbalizador } from './atb-indic-glossario.js';
import { carregarDados, resolver } from './atb-indic-resolver.js';

const API_URL = (process.env.ATB_NLQ_API_URL || 'https://api.deepinfra.com/v1/openai').replace(/\/$/, '');
const API_KEY = process.env.ATB_NLQ_API_KEY || '';
const MODEL   = process.env.ATB_INDIC_MODEL || 'meta-llama/Llama-3.3-70B-Instruct-Turbo';
const ORIGENS = (process.env.ATB_INDIC_ORIGENS || 'https://scih.lcmendes.med.br')
  .split(',').map(s => s.trim()).filter(Boolean);
const LIMITE_HORA = parseInt(process.env.ATB_INDIC_LIMITE || '8', 10);
const TIMEOUT = 45000;   // igual ao NL→SQL (proven): 25s era curto p/ o passo de verbalizar

// ── Rate-limit em memória (janela deslizante de 1h por IP) ──────────────────
// Em memória basta: reinício do Render zera, e o custo por pergunta é ínfimo.
const _hits = new Map();
function limitar(ip) {
  const agora = Date.now(), janela = 3600000;
  const lista = (_hits.get(ip) || []).filter(t => agora - t < janela);
  if (lista.length >= LIMITE_HORA) {
    _hits.set(ip, lista);
    return { ok: false, restam: 0, reset: Math.ceil((janela - (agora - lista[0])) / 60000) };
  }
  lista.push(agora);
  _hits.set(ip, lista);
  if (_hits.size > 5000) _hits.clear();   // guarda contra crescimento indefinido
  return { ok: true, restam: LIMITE_HORA - lista.length };
}

async function chamarLLM(system, user, maxTokens = 400, rotulo = 'llm') {
  if (!API_KEY) throw new Error('ATB_NLQ_API_KEY não configurada.');
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT);
  const t0 = Date.now();
  const entradaChars = system.length + user.length;
  try {
    const r = await fetch(`${API_URL}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${API_KEY}` },
      signal: ctrl.signal,
      body: JSON.stringify({
        model: MODEL, temperature: 0,
        // Sem response_format: é a configuração comprovada nesta stack (NL→SQL).
        // O modo json_object sem schema pode gerar saída sem parada e estourar o
        // timeout. O parse do localizador já extrai o primeiro {...} com robustez.
        max_tokens: maxTokens,   // guarda contra geração desenfreada
        messages: [{ role: 'system', content: system }, { role: 'user', content: user }],
      }),
    });
    if (!r.ok) {
      const corpo = await r.text().catch(() => '');
      throw new Error(`API HTTP ${r.status} ${corpo.slice(0, 200)}`);
    }
    const d = await r.json();
    console.log(`[indic] ${rotulo}: ${Date.now()-t0}ms | entrada ${entradaChars} chars | custo ${d?.usage?.estimated_cost ?? '?'}`);
    return (d?.choices?.[0]?.message?.content || '').trim();
  } catch (e) {
    console.error(`[indic] ${rotulo} FALHOU após ${Date.now()-t0}ms | entrada ${entradaChars} chars | ${e.message}`);
    throw e;
  } finally { clearTimeout(t); }
}

function parseLocalizador(txt) {
  const m = String(txt).match(/\{[\s\S]*\}/);
  if (!m) return null;
  try { return JSON.parse(m[0]); } catch { return null; }
}

export function registerIndicRoutes(app, deps = {}) {
  const isAdmin = deps.isAdmin || (req => req.cookies?.adm === '1');
  const adminRequired = deps.adminRequired || ((req, res, next) => next());

  function cors(req, res) {
    const origem = req.headers.origin;
    if (origem && ORIGENS.includes(origem)) {
      res.setHeader('Access-Control-Allow-Origin', origem);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    }
  }
  app.options('/scih/indic/pergunta', (req, res) => { cors(req, res); res.sendStatus(204); });

  app.post('/scih/indic/pergunta', async (req, res) => {
    cors(req, res);
    const admin = isAdmin(req);
    if (!admin) {
      const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip || 'x';
      const lim = limitar(ip);
      if (!lim.ok) return res.status(429).json({
        erro: `Limite de ${LIMITE_HORA} perguntas por hora atingido. Tente novamente em ~${lim.reset} min.` });
    }
    const pergunta = String(req.body?.pergunta || '').trim().slice(0, 400);
    if (!pergunta) return res.status(400).json({ erro: 'Pergunta vazia.' });

    let passo = 'inicio';
    try {
      // 1) LOCALIZAR
      passo = 'localizar';
      const bruto = await chamarLLM(promptLocalizador(), pergunta, 300, 'localizar');
      const loc = parseLocalizador(bruto);
      if (!loc) return res.json({ resposta: 'Não consegui interpretar a pergunta. Tente citar o setor e o indicador (ex.: "PAV na UTI A/B em 2025").' });
      if (loc.erro) return res.json({ resposta: `Não reconheci um termo da pergunta: ${loc.erro}. Os indicadores disponíveis são de IRAS, MDR e consumo de ATB por setor.`, localizador: loc });

      // 2) RESOLVER (determinístico)
      passo = 'carregar-dados';
      const dados = await carregarDados();
      const fatos = resolver(dados, loc);
      if (!fatos.itens.length) {
        return res.json({
          resposta: `Não encontrei dados para essa combinação. ${fatos.avisos.join(' ')}`.trim(),
          localizador: loc, fatos });
      }

      // 3) VERBALIZAR (ancorado só nos fatos)
      const contexto = JSON.stringify({ pergunta, dados_resolvidos: fatos }, null, 1);
      passo = 'verbalizar';
      const msgUser = `PERGUNTA DO USUÁRIO: ${pergunta}\n\nDADOS RESOLVIDOS (use apenas estes):\n${contexto}`;
      let resposta;
      try {
        resposta = await chamarLLM(promptVerbalizador(), msgUser, 260, 'verbalizar');
      } catch (e1) {
        // Uma nova tentativa: a falha observada é intermitente (mesma pergunta
        // funciona em outra hora), compatível com latência transitória do provedor.
        console.warn('[indic] verbalizar falhou; tentando 1x mais');
        resposta = await chamarLLM(promptVerbalizador(), msgUser, 260, 'verbalizar-retry');
      }

      return res.json({ resposta, localizador: loc, fatos, periodoBase: fatos.periodoBase });
    } catch (e) {
      console.error(`[indic] falha no passo "${passo}":`, e.message);
      return res.status(503).json({ erro: 'Serviço de perguntas indisponível no momento.' });
    }
  });

  // Página de uso/teste no próprio app (same-origin → cookie admin → sem limite)
  app.get('/atb/admin/indicadores', adminRequired, (req, res) => {
    res.send(`<!doctype html><meta charset="utf-8"><title>Pergunta aos indicadores</title>
<style>body{font:15px system-ui,sans-serif;max-width:760px;margin:28px auto;padding:0 16px;color:#202124}
h2{margin:0 0 4px} p.sub{color:#5f6368;margin:0 0 16px}
textarea{width:100%;min-height:74px;font:inherit;padding:11px;border:1px solid #dadce0;border-radius:10px;box-sizing:border-box}
button{margin-top:10px;padding:10px 18px;border:0;border-radius:9px;background:#0c447c;color:#fff;font:inherit;cursor:pointer}
.resp{margin-top:18px;padding:15px;background:#f6f8fb;border:1px solid #e3e7ee;border-radius:10px;line-height:1.55;white-space:pre-wrap}
details{margin-top:12px}pre{background:#f1f3f4;padding:11px;border-radius:8px;overflow:auto;font-size:12px}
.ex{color:#0c447c;cursor:pointer;text-decoration:underline;font-size:13.5px;margin-right:12px}</style>
<h2>Pergunta aos indicadores (SCIH)</h2>
<p class="sub">Respostas ancoradas nos dados publicados e nas análises estatísticas existentes. Quando não há teste de significância para a série, a resposta diz isso.</p>
<textarea id="q" placeholder="Ex.: qual a taxa de PAV na UTI A/B no primeiro semestre de 2026?"></textarea>
<div>
  <span class="ex" onclick="pre(this)">taxa de PAV na UTI adulto no 1º semestre de 2026</span>
  <span class="ex" onclick="pre(this)">tivemos aumento real de infecção na UTI?</span>
  <span class="ex" onclick="pre(this)">o consumo de carbapenêmico na UTI A/B está caindo?</span>
</div>
<div><button onclick="ir()">Perguntar</button></div>
<div id="out"></div>
<script>
function pre(el){ document.getElementById('q').value = el.textContent; }
async function ir(){
  var q=document.getElementById('q').value, out=document.getElementById('out');
  if(!q.trim()) return;
  out.innerHTML='<p style="color:#5f6368">consultando…</p>';
  try{
    var r=await fetch('/scih/indic/pergunta',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pergunta:q})});
    var d=await r.json();
    if(d.erro){ out.innerHTML='<div class="resp">'+d.erro+'</div>'; return; }
    out.innerHTML='<div class="resp">'+(d.resposta||'')+'</div>'+
      '<details><summary>Ver dados usados (localizador + fatos)</summary><pre>'+
      JSON.stringify({localizador:d.localizador,fatos:d.fatos},null,1)+'</pre></details>';
  }catch(e){ out.innerHTML='<div class="resp">Erro: '+e.message+'</div>'; }
}
</script>`);
  });
}
