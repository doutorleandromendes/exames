// backcheck-nomes.mjs  —  FASE 1: AUDITORIA (read-only, não grava nada)
// Examina paciente_nome_raw (nome canônico; migrados têm paciente_nome=null),
// categoriza problemas e mostra o que a normalização FARIA (antes -> depois).
//
// Uso:
//   node backcheck-nomes.mjs            resumo + amostras por categoria
//   node backcheck-nomes.mjs --csv      dump CSV de TODAS as mudanças (id;tipo;antes;depois)
import pg from 'pg';

const CSV = process.argv.includes('--csv');
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL || process.env.SUPABASE_POOLER_URL,
  ssl: { rejectUnauthorized: false },
});

// ── normalização CANDIDATA (transformações SEGURAS apenas) ───────────────────
// Faz: colapsa/apara espaços; CAIXA ALTA (pt-BR); remove tokens idênticos
// consecutivos; remove repetição total "P P" -> "P".
// NÃO faz: remover "aberrações" (dígitos/símbolos/mojibake) nem consertar
// truncamento — isso fica só FLAGGED para revisão manual (decisão sua).
function normalizeNome(raw) {
  if (raw == null) return '';
  let s = String(raw).replace(/[\u00A0\s]+/g, ' ').trim().toLocaleUpperCase('pt-BR');
  let toks = s.split(' ').filter(Boolean);
  toks = toks.filter((t, i) => i === 0 || t !== toks[i - 1]); // dedup consecutivo
  if (toks.length >= 2 && toks.length % 2 === 0) {            // repetição total P P
    const h = toks.length / 2;
    if (toks.slice(0, h).join(' ') === toks.slice(h).join(' ')) toks = toks.slice(0, h);
  }
  return toks.join(' ');
}

// chars "aberrantes": fora de letras (com acento), espaço, hífen, apóstrofo, ponto
const ABERRANTE = /[^A-Za-zÀ-ÖØ-öø-ÿ '.\-]/;

function problemas(raw) {
  const p = [];
  if (raw == null || String(raw).trim() === '') { p.push('vazio'); return p; }
  const s = String(raw);
  if (s !== s.trim() || /\s{2,}/.test(s) || /[\u00A0]/.test(s)) p.push('espacos');
  if (s !== s.toLocaleUpperCase('pt-BR')) p.push('caixa');
  if (ABERRANTE.test(s)) p.push('aberracao');
  const toks = s.replace(/\s+/g, ' ').trim().split(' ').filter(Boolean);
  if (toks.some((t, i) => i > 0 && t === toks[i - 1])) p.push('repeticao_token');
  if (toks.length >= 2 && toks.length % 2 === 0) {
    const h = toks.length / 2;
    if (toks.slice(0, h).join(' ').toUpperCase() === toks.slice(h).join(' ').toUpperCase()) p.push('repeticao_total');
  }
  if (toks.length === 1) p.push('token_unico');        // suspeita de truncamento/incompleto
  if (s.replace(/\s/g, '').length < 3) p.push('muito_curto');
  return p;
}

const { rows } = await pool.query(`
  SELECT id, paciente_nome, paciente_nome_raw,
         (jotform_submission_id LIKE 'form_%') AS nativo
  FROM atb_fichas
  WHERE deletado_em IS NULL`);

const cats = {};                    // contagem por categoria
let totalRaw = 0, mudariam = 0, nomeNull = 0, nomeDifereRaw = 0, semRaw = 0;
const exemplos = {};                // amostras por categoria
const csvLin = [];

for (const f of rows) {
  if (f.paciente_nome == null) nomeNull++;
  else if (f.paciente_nome !== f.paciente_nome_raw) nomeDifereRaw++;

  const raw = f.paciente_nome_raw;
  if (raw == null || String(raw).trim() === '') { semRaw++; continue; }
  totalRaw++;

  const probs = problemas(raw);
  for (const c of probs) {
    cats[c] = (cats[c] || 0) + 1;
    (exemplos[c] = exemplos[c] || []);
    if (exemplos[c].length < 6) exemplos[c].push(`#${f.id} «${raw}»`);
  }
  const norm = normalizeNome(raw);
  if (norm !== raw) {
    mudariam++;
    if (CSV) csvLin.push(`${f.id};${probs.join('|')};"${String(raw).replace(/"/g,'""')}";"${norm.replace(/"/g,'""')}"`);
  }
}

if (CSV) {
  console.log('id;problemas;antes;depois');
  console.log(csvLin.join('\n'));
  await pool.end();
} else {
  console.log('════════════════════════════════════════════════');
  console.log(`Fichas (não deletadas): ${rows.length}`);
  console.log(`  • com paciente_nome_raw preenchido: ${totalRaw}`);
  console.log(`  • sem paciente_nome_raw:            ${semRaw}`);
  console.log(`  • paciente_nome NULL (migrados):    ${nomeNull}`);
  console.log(`  • paciente_nome != raw:             ${nomeDifereRaw}`);
  console.log('--------------------------------------------------');
  console.log('PROBLEMAS detectados (um nome pode ter vários):');
  for (const c of Object.keys(cats).sort((a, b) => cats[b] - cats[a])) {
    console.log(`  ${c.padEnd(16)} ${String(cats[c]).padStart(5)}`);
    (exemplos[c] || []).forEach(e => console.log(`        ${e}`));
  }
  console.log('--------------------------------------------------');
  console.log(`A normalização SEGURA mudaria: ${mudariam} nome(s).`);
  console.log('(espaços + CAIXA ALTA + dedup de tokens/repetição total)');
  console.log('Categorias só-FLAG (não auto-corrigidas): aberracao, token_unico, muito_curto.');
  console.log('Rode com --csv para o diff completo (antes -> depois).');
  console.log('════════════════════════════════════════════════');
  await pool.end();
}
