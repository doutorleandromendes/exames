// atb-prescritores.js
// ════════════════════════════════════════════════════════════════════════════
// Fonte de prescritores: CSV vivo no GitHub, com cache em memória.
// Editar o CSV no repo → recarregar (boot, intervalo, ou botão admin) → vale.
//
// Salvaguardas contra "qualquer número passa":
//   1. Formato: 4–7 dígitos, sem zeros/letras (barra 012, 00000, etc.)
//   2. Lookup no CSV: se achar → cadastrado (preenche nome).
//   3. Se não achar mas formato ok → fora do cadastro: o motor exige
//      nome manual + declaração ativa antes de permitir submissão.
//
// Exporta:
//   - carregarPrescritores(force?)  → baixa/recarrega o CSV (cacheado)
//   - validarFormatoCRM(crm)        → { ok, motivo }
//   - buscarCRM(crm)                → { cadastrado, nome|null }
//   - statusCache()                 → metadados do cache (para o admin)
// ════════════════════════════════════════════════════════════════════════════

// URL do CSV vivo. Ajuste para o repo/branch/caminho onde o arquivo mora.
// raw.githubusercontent.com serve o conteúdo bruto do arquivo no repo.
const CSV_URL = process.env.ATB_PRESCRITORES_CSV
  || 'https://raw.githubusercontent.com/doutorleandromendes/exames/refs/heads/main/aula-tracker/prescritores.csv';

// Recarrega automaticamente a cada N minutos (além do boot e do botão admin)
const TTL_MIN = parseInt(process.env.ATB_PRESCRITORES_TTL_MIN || '15', 10);

// Cache em memória
let _mapa = new Map();          // chave: crm (string) → { nome, uf }
let _carregadoEm = null;        // timestamp da última carga bem-sucedida
let _fonte = CSV_URL;
let _erro = null;               // última mensagem de erro, se houve
let _total = 0;

// ── Parser de CSV simples (lida com vírgula e aspas básicas) ──────────────────
function parseCSV(texto) {
  const linhas = texto.split(/\r?\n/).filter(l => l.trim().length);
  if (!linhas.length) return [];
  const head = splitLinhaCSV(linhas[0]).map(h => h.trim().toLowerCase());
  const iNome = head.indexOf('nome');
  const iCrm = head.indexOf('crm');
  const iUf = head.indexOf('uf');
  const out = [];
  for (let i = 1; i < linhas.length; i++) {
    const cols = splitLinhaCSV(linhas[i]);
    const crm = (cols[iCrm] || '').replace(/\D/g, ''); // só dígitos
    if (!crm) continue;
    out.push({
      crm,
      nome: (cols[iNome] || '').trim(),
      uf: iUf >= 0 ? (cols[iUf] || '').trim() : ''
    });
  }
  return out;
}

// split que respeita aspas duplas
function splitLinhaCSV(linha) {
  const res = []; let cur = ''; let dentro = false;
  for (let i = 0; i < linha.length; i++) {
    const c = linha[i];
    if (c === '"') { dentro = !dentro; continue; }
    if (c === ',' && !dentro) { res.push(cur); cur = ''; continue; }
    cur += c;
  }
  res.push(cur);
  return res;
}

// ── Carrega/recarrega o CSV (com cache) ───────────────────────────────────────
export async function carregarPrescritores(force = false) {
  const agora = Date.now();
  if (!force && _carregadoEm && (agora - _carregadoEm) < TTL_MIN * 60000 && _mapa.size) {
    return { jaEmCache: true, total: _total };
  }
  try {
    const resp = await fetch(CSV_URL, { headers: { 'Cache-Control': 'no-cache' } });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const texto = await resp.text();
    const linhas = parseCSV(texto);
    if (!linhas.length) throw new Error('CSV vazio ou sem linhas válidas');
    const novo = new Map();
    // primeiro match vence (opção 2: valida só pelo número, 1º match)
    for (const r of linhas) {
      if (!novo.has(r.crm)) novo.set(r.crm, { nome: r.nome, uf: r.uf });
    }
    _mapa = novo;
    _total = novo.size;
    _carregadoEm = agora;
    _erro = null;
    console.log(`[atb-prescritores] carregados ${_total} prescritores do CSV`);
    return { jaEmCache: false, total: _total };
  } catch (e) {
    _erro = e.message;
    console.error('[atb-prescritores] falha ao carregar CSV:', e.message);
    // mantém o cache antigo se existir (degradação graciosa)
    return { jaEmCache: false, total: _mapa.size, erro: e.message };
  }
}

// ── Salvaguarda 1: formato do CRM ─────────────────────────────────────────────
// CRMs reais no cadastro têm 4–6 dígitos; uso 4–7 com folga. Sem letras, sem zero.
// (Regras anti-sequência foram descartadas: CRMs reais incluem 1234, 99999, etc.)
export function validarFormatoCRM(crm) {
  const s = String(crm == null ? '' : crm).trim();
  if (!s) return { ok: false, motivo: 'CRM não informado' };
  if (!/^\d+$/.test(s)) return { ok: false, motivo: 'CRM deve conter apenas números' };
  if (s.length < 4 || s.length > 7) return { ok: false, motivo: 'CRM deve ter entre 4 e 7 dígitos' };
  if (parseInt(s, 10) === 0) return { ok: false, motivo: 'CRM inválido' };
  return { ok: true };
}

// ── Lookup ────────────────────────────────────────────────────────────────────
export function buscarCRM(crm) {
  const s = String(crm == null ? '' : crm).replace(/\D/g, '');
  const reg = _mapa.get(s);
  if (reg) return { cadastrado: true, nome: reg.nome, uf: reg.uf };
  return { cadastrado: false, nome: null };
}

// ── Status do cache (para o painel admin) ─────────────────────────────────────
export function statusCache() {
  return {
    total: _total,
    carregadoEm: _carregadoEm ? new Date(_carregadoEm).toISOString() : null,
    fonte: _fonte,
    ttlMin: TTL_MIN,
    erro: _erro
  };
}
