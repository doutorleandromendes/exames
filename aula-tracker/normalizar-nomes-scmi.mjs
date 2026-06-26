// normalizar-nomes-scmi.mjs — normalização de nomes do SCMI (FASE 2, grava).
// MESMA lógica determinística do HUSF (normalizar-nomes.mjs), SEM API da Anthropic,
// porém ESCOPADA à instituição SCMI — o HUSF não é tocado.
//
// Objetivo: paciente_nome = paciente_nome_raw = <normalizado> nas fichas do SCMI.
// Segurança: backup dos originais em atb_nomes_backup (reversível), pula casos de
// revisão manual (token colado) e registros de teste, recomputa link_labs (LIS).
//
//   node normalizar-nomes-scmi.mjs            DRY-RUN: mostra o que mudaria
//   node normalizar-nomes-scmi.mjs --execute  aplica (com backup)
import pg from 'pg';

const EXECUTE = process.argv.includes('--execute');
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true },
});

// ── normalização SEGURA (idêntica ao HUSF, com dedup geral) ──────────────────
function collapseRepeats(toks) {
  let ch = true;
  while (ch) {
    ch = false;
    for (let n = Math.floor(toks.length / 2); n >= 1 && !ch; n--)
      for (let i = 0; i + 2 * n <= toks.length; i++)
        if (toks.slice(i, i + n).join('\u0001') === toks.slice(i + n, i + 2 * n).join('\u0001')) {
          toks.splice(i + n, n); ch = true; break;
        }
  }
  return toks;
}
function normalizeNome(raw) {
  if (raw == null) return '';
  const s = String(raw).replace(/[\u00A0\s]+/g, ' ').trim().toLocaleUpperCase('pt-BR');
  return collapseRepeats(s.split(' ').filter(Boolean)).join(' ');
}
// revisão MANUAL: token de palavra duplicada (X+X) ou repetição residual de frase
function precisaManual(norm) {
  const t = norm.split(' ').filter(Boolean);
  if (t.some(x => { const h = x.length / 2; return x.length >= 8 && x.length % 2 === 0 && x.slice(0, h) === x.slice(h); })) return true;
  for (let n = 2; n <= Math.floor(t.length / 2); n++)
    for (let i = 0; i + 2 * n <= t.length; i++)
      if (t.slice(i, i + n).join('\u0001') === t.slice(i + n, i + 2 * n).join('\u0001')) return true;
  return false;
}
const ehTeste = (raw) => /textbox|sample|teste_|^x{3,}$/i.test(String(raw));
// link_labs (LIS) — MESMA construção do parser; localhost:3000 mantido de propósito
const buildLabs = (nome) => nome ? `http://localhost:3000/api/buscar?nome=${String(nome).trim().replace(/\s+/g, '+')}` : null;

// ── resolve a instituição SCMI (escopo) ──────────────────────────────────────
const { rows: [inst] } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla='SCMI'`);
if (!inst) { console.error('ERRO: instituição SCMI não encontrada em atb_instituicoes.'); await pool.end(); process.exit(1); }
const scmiId = inst.id;

await pool.query(`
  CREATE TABLE IF NOT EXISTS atb_nomes_backup (
    ficha_id       INTEGER PRIMARY KEY,
    nome_old       TEXT,
    nome_raw_old   TEXT,
    link_labs_old  TEXT,
    normalizado_at TIMESTAMPTZ DEFAULT now()
  )`);

const { rows } = await pool.query(`
  SELECT id, paciente_nome, paciente_nome_raw, link_labs
  FROM atb_fichas
  WHERE deletado_em IS NULL AND instituicao_id = $1`, [scmiId]);

let mudamRaw = 0, soPopulaNome = 0, semRaw = 0, manual = 0, teste = 0, aplicadas = 0;
const amostra = [], manualLista = [], testeLista = [];

for (const f of rows) {
  const raw = f.paciente_nome_raw;
  if (raw == null || String(raw).trim() === '') { semRaw++; continue; }
  if (ehTeste(raw)) { teste++; testeLista.push(`#${f.id} «${raw}»`); continue; }

  const norm = normalizeNome(raw);
  if (precisaManual(norm)) { manual++; manualLista.push(`#${f.id} «${raw}» → «${norm}»`); continue; }

  const rawMudou  = norm !== raw;
  const nomeMudou = f.paciente_nome !== norm;     // inclui NULL
  if (!rawMudou && !nomeMudou) continue;          // já normalizado

  if (rawMudou) mudamRaw++; else soPopulaNome++;
  if (amostra.length < 30)
    amostra.push(`#${f.id} ${f.paciente_nome === null ? '[migrado]' : ''} «${raw}» → «${norm}»`);

  if (EXECUTE) {
    const newLabs = buildLabs(norm);
    await pool.query('INSERT INTO atb_nomes_backup (ficha_id, nome_old, nome_raw_old, link_labs_old) VALUES ($1,$2,$3,$4) ON CONFLICT (ficha_id) DO NOTHING',
      [f.id, f.paciente_nome, f.paciente_nome_raw, f.link_labs]);
    await pool.query('UPDATE atb_fichas SET paciente_nome=$2, paciente_nome_raw=$2, link_labs=$3, updated_at=now() WHERE id=$1',
      [f.id, norm, newLabs]);
    aplicadas++;
  }
}

console.log('════════════════════════════════════════════');
console.log(EXECUTE ? '>>> MODO EXECUTE (gravou, com backup) <<<' : '>>> DRY-RUN — use --execute para aplicar <<<');
console.log(`Instituição SCMI = id ${scmiId}`);
console.log(`Fichas SCMI não deletadas: ${rows.length}`);
console.log('--------------------------------------------');
console.log(`Normalização altera o nome (raw):     ${mudamRaw}`);
console.log(`Só popula paciente_nome (migrado ok): ${soPopulaNome}`);
console.log(`Total a atualizar:                    ${mudamRaw + soPopulaNome}`);
console.log(`Pulados — revisão MANUAL (colados):   ${manual}`);
console.log(`Pulados — registro de teste:          ${teste}`);
console.log(`Sem paciente_nome_raw:                ${semRaw}`);
if (EXECUTE) console.log(`>>> Gravadas: ${aplicadas} (originais em atb_nomes_backup)`);
console.log('--------------------------------------------');
console.log('Amostra (até 30):');
amostra.forEach(a => console.log('  ' + a));
if (manualLista.length) { console.log('\nREVISÃO MANUAL (não tocados — montar corrigir-manuais-scmi se necessário):'); manualLista.forEach(m => console.log('  ' + m)); }
if (testeLista.length) { console.log('\nTESTE (não tocados):'); testeLista.forEach(t => console.log('  ' + t)); }
console.log('════════════════════════════════════════════');
console.log('Reverter (só SCMI): UPDATE atb_fichas f SET paciente_nome=b.nome_old,');
console.log('  paciente_nome_raw=b.nome_raw_old, link_labs=b.link_labs_old');
console.log('  FROM atb_nomes_backup b WHERE b.ficha_id=f.id');
console.log(`  AND f.instituicao_id=${scmiId};`);

await pool.end();
