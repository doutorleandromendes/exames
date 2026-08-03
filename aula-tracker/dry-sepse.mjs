// ════════════════════════════════════════════════════════════════════════════
//  ENSAIO do classificador de sepse — NÃO grava nada
//
//  Roda o classificador sobre histórias reais do banco e imprime o resultado
//  para revisão do SCIH. Serve para calibrar os few-shots ANTES de ligar o
//  gatilho em produção.
//
//  Só LÊ: nenhum INSERT, UPDATE ou DELETE. Pode rodar com o sistema no ar.
//
//  COMO RODAR (shell do Render, ou local com as env vars):
//     node dry-sepse.mjs                 → 30 fichas com "Sepse = Não"
//     node dry-sepse.mjs 50              → 50 fichas
//     node dry-sepse.mjs 30 controle     → 30 com "Não" + 15 com "Sim"
//
//  A amostra com "Sepse = Sim" é o CONTROLE: nela o classificador deveria
//  concordar com o prescritor na maioria dos casos. Se ele disser "não é
//  sepse" para muitos casos que o prescritor marcou como sepse, o critério
//  está apertado demais — e isso só aparece olhando os dois lados.
//
//  Precisa das mesmas env vars do app: DATABASE_URL e ATB_NARRATIVA_API_KEY.
// ════════════════════════════════════════════════════════════════════════════

import pg from 'pg';
import { montarMensagensSepse, RESPONSE_FORMAT_SEPSE, parseSaidaSepse } from './atb-historia-sepse.js';

const N          = parseInt(process.argv[2], 10) || 30;
const COM_CONTROLE = String(process.argv[3] || '').toLowerCase().startsWith('c');
const API_URL = (process.env.ATB_NARRATIVA_API_URL || 'https://api.deepinfra.com/v1/openai').replace(/\/$/, '');
const API_KEY = process.env.ATB_NARRATIVA_API_KEY || '';
const MODEL   = process.env.ATB_NARRATIVA_MODEL || 'meta-llama/Llama-3.3-70B-Instruct-Turbo';
const PAUSA_MS = 250;   // respiro entre chamadas, para não estourar limite

if (!API_KEY) { console.error('Falta ATB_NARRATIVA_API_KEY.'); process.exit(1); }
if (!process.env.DATABASE_URL) { console.error('Falta DATABASE_URL.'); process.exit(1); }

const URL_DB = process.env.DATABASE_URL;
// SSL é exigido na conexão EXTERNA do Render Postgres e desnecessário na
// interna. Detecta pelo host: o interno não tem ponto no nome. PGSSL=0 força
// desligar, PGSSL=1 força ligar, se a detecção falhar.
const _host = (() => { try { return new URL(URL_DB).hostname; } catch { return ''; } })();
const _sslAuto = _host.includes('.');
const _ssl = process.env.PGSSL === '0' ? false
           : process.env.PGSSL === '1' ? { rejectUnauthorized: false }
           : (_sslAuto ? { rejectUnauthorized: false } : false);

const pool = new pg.Pool({ connectionString: URL_DB, ssl: _ssl });

async function classificar(historia) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 30000);
  try {
    const r = await fetch(`${API_URL}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${API_KEY}` },
      body: JSON.stringify({
        model: MODEL, temperature: 0,
        response_format: RESPONSE_FORMAT_SEPSE,
        messages: montarMensagensSepse(historia),
      }),
      signal: ctrl.signal,
    });
    if (!r.ok) return { erro: `HTTP ${r.status}` };
    const j = await r.json();
    const txt = j?.choices?.[0]?.message?.content || '';
    const o = parseSaidaSepse(txt);
    return o || { erro: 'ilegível', bruto: txt.slice(0, 200) };
  } catch (e) {
    return { erro: e.name === 'AbortError' ? 'timeout' : e.message };
  } finally { clearTimeout(timer); }
}

// Amostra aleatória entre as fichas COM história preenchida e substancial.
// `sepse` é BOOLEAN na tabela (o formulário guarda Sim/Não e o registry converte).
async function amostrar(valorSepse, quantos) {
  const { rows } = await pool.query(
    `SELECT f.id, f.setor, f.historia_clinica,
            to_char(COALESCE(f.data_referencia, f.jotform_created_at, f.created_at)
                    AT TIME ZONE 'America/Sao_Paulo', 'DD/MM/YYYY') AS data
       FROM atb_fichas f
      WHERE f.deletado_em IS NULL
        AND f.sepse IS NOT DISTINCT FROM $1
        AND f.historia_clinica IS NOT NULL
        AND length(btrim(f.historia_clinica)) >= 30
      ORDER BY random()
      LIMIT $2`, [valorSepse, quantos]);
  return rows;
}

function corta(s, n) {
  const t = String(s || '').replace(/\s+/g, ' ').trim();
  return t.length > n ? t.slice(0, n - 1) + '…' : t;
}

async function rodar(rotulo, valorSepse, quantos, esperado) {
  const fichas = await amostrar(valorSepse, quantos);
  if (!fichas.length) { console.log(`\n(${rotulo}: nenhuma ficha encontrada)`); return null; }

  console.log(`\n${'═'.repeat(78)}`);
  console.log(`${rotulo} — ${fichas.length} fichas (prescritor marcou "${esperado}")`);
  console.log('═'.repeat(78));

  let positivos = 0, erros = 0;
  const divergentes = [];

  for (const f of fichas) {
    const r = await classificar(f.historia_clinica);
    await new Promise((res) => setTimeout(res, PAUSA_MS));
    if (r.erro) { erros++; console.log(`\n#${f.id}  ⚠ erro: ${r.erro}`); continue; }
    if (r.sepse) positivos++;

    // Divergência = o classificador discorda do que o prescritor marcou.
    const divergiu = (valorSepse === false && r.sepse === true)
                  || (valorSepse === true  && r.sepse === false);
    if (divergiu) divergentes.push({ f, r });

    const marca = r.sepse ? 'SEPSE' : '  —  ';
    const flag  = divergiu ? ' ◄ diverge' : '';
    console.log(`\n#${f.id} · ${f.data} · ${corta(f.setor, 22)}  [${marca}]${flag}`);
    console.log(`   ${corta(f.historia_clinica, 300)}`);
    if (r.indicios) console.log(`   → indício: ${r.indicios}`);
  }

  const n = fichas.length - erros;
  console.log(`\n${'─'.repeat(78)}`);
  console.log(`${rotulo}: ${positivos}/${n} classificadas como sepse` + (erros ? ` · ${erros} erro(s)` : ''));
  console.log(`Divergências do prescritor: ${divergentes.length}/${n}`);
  return { rotulo, n, positivos, erros, divergentes: divergentes.length };
}

(async () => {
  console.log(`Modelo: ${MODEL}`);
  console.log(`Banco: ${_host || '(local)'} · SSL ${_ssl ? 'ligado' : 'desligado'}`);
  console.log('Somente leitura — nada é gravado no banco.');

  const resumo = [];
  // Principal: o caso de uso real — prescritor marcou "Não".
  const r1 = await rodar('AMOSTRA PRINCIPAL', false, N, 'Não');
  if (r1) resumo.push(r1);

  if (COM_CONTROLE) {
    // Controle: prescritor marcou "Sim". Aqui a divergência mede se o critério
    // ficou apertado demais (deixaria passar sepse de verdade).
    const r2 = await rodar('CONTROLE', true, Math.max(5, Math.round(N / 2)), 'Sim');
    if (r2) resumo.push(r2);
  }

  console.log(`\n${'═'.repeat(78)}`);
  console.log('RESUMO');
  console.log('═'.repeat(78));
  for (const r of resumo) {
    const pct = r.n ? Math.round((r.divergentes / r.n) * 100) : 0;
    console.log(`${r.rotulo.padEnd(20)} ${String(r.positivos).padStart(3)}/${String(r.n).padEnd(3)} como sepse · ${r.divergentes} divergência(s) (${pct}%)`);
  }
  console.log(`
Como ler:
  • AMOSTRA PRINCIPAL — cada "diverge" é um caso em que o gatilho ABRIRIA a
    pergunta. Revise se a pergunta faz sentido clínico. Muitos falsos aqui =
    critério frouxo (o prescritor vai se irritar com a pergunta).
  • CONTROLE — cada "diverge" é uma sepse de verdade que o classificador NÃO
    reconheceria. Muitos aqui = critério apertado (perderia casos).`);

  await pool.end();
})().catch((e) => { console.error(e); process.exit(1); });
