// diag-regra-rn.mjs
// Diagnóstico: por que uma regra de triagem não casa numa ficha.
// Mostra idade_dias pelo _toDate BUGADO vs CORRIGIDO e avalia cada nó da regra.
// Uso:  node diag-regra-rn.mjs [fichaId]
//   sem id: pega a ficha mais recente com Gentamicina + setor ~Neo.
import pg from 'pg';
import { avaliaCond } from './atb-triagem-regras.js';

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL || process.env.SUPABASE_POOLER_URL,
  ssl: { rejectUnauthorized: false },
});

// _toDate BUGADO (como está em produção antes do fix)
const toDateBug = (x) => { if (!x) return null; const d = new Date(String(x).slice(0,10)+'T00:00:00'); return isNaN(d)?null:d; };
// _toDate CORRIGIDO
const toDateFix = (x) => { if (!x) return null; if (x instanceof Date) return isNaN(x.getTime())?null:x; const d = new Date(String(x).slice(0,10)+'T00:00:00'); return isNaN(d)?null:d; };
const idadeDias = (toDate, dn, ref) => { const d = toDate(dn); if (!d) return undefined; const r = toDate(ref) || new Date(); const k = Math.floor((r-d)/86400000); return k<0?undefined:k; };
const diasDesde = (toDate, dt, ref) => { const d = toDate(dt); if (!d) return null; const r = toDate(ref) || new Date(); const k = Math.floor((r-d)/86400000); return k>=0?k:null; };

const argId = process.argv[2];
const sel = argId
  ? await pool.query('SELECT * FROM atb_fichas WHERE id=$1', [argId])
  : await pool.query(`SELECT * FROM atb_fichas
       WHERE deletado_em IS NULL AND atb_solicitado::text ILIKE '%gentamicina%' AND setor ILIKE '%neo%'
       ORDER BY created_at DESC LIMIT 1`);
const f = sel.rows[0];
if (!f) { console.log('Nenhuma ficha encontrada (passe um id: node diag-regra-rn.mjs <id>)'); await pool.end(); process.exit(0); }

const ref = f.data_referencia || f.jotform_created_at || f.created_at || null;
console.log('========================================');
console.log(`Ficha #${f.id}  ${f.paciente_nome || ''}`);
console.log('paciente_dn :', JSON.stringify(f.paciente_dn), '· tipo:', (f.paciente_dn instanceof Date) ? 'Date' : typeof f.paciente_dn);
console.log('setor       :', JSON.stringify(f.setor));
console.log('atb_solicit :', JSON.stringify(f.atb_solicitado), '· tipo:', Array.isArray(f.atb_solicitado) ? 'array' : typeof f.atb_solicitado);
console.log('data_intern :', JSON.stringify(f.data_internacao));
console.log('ref (idade) :', JSON.stringify(ref));
console.log('----------------------------------------');
console.log('idade_dias  BUGADO   :', idadeDias(toDateBug, f.paciente_dn, ref));
console.log('idade_dias  CORRIGIDO:', idadeDias(toDateFix, f.paciente_dn, ref));
console.log('dias_intern BUGADO   :', diasDesde(toDateBug, f.data_internacao, ref));
console.log('dias_intern CORRIGIDO:', diasDesde(toDateFix, f.data_internacao, ref));
console.log('========================================\n');

// contexto CORRIGIDO (o que a regra enxergará após o fix)
const ctx = { ...f,
  idade_dias: idadeDias(toDateFix, f.paciente_dn, ref),
  dias_internacao: diasDesde(toDateFix, f.data_internacao, ref) };

// walker por-nó
function walk(cond, prefixo='') {
  if (!cond) return;
  if (cond.all) { console.log(prefixo+'AND'); cond.all.forEach(c => walk(c, prefixo+'  ')); return; }
  if (cond.any) { console.log(prefixo+'OR');  cond.any.forEach(c => walk(c, prefixo+'  ')); return; }
  const atual = ctx[cond.campo];
  const ok = avaliaCond(cond, ctx);
  console.log(`${prefixo}${ok?'✓':'✗'} ${cond.campo} ${cond.op} ${JSON.stringify(cond.valor)}  | atual=${JSON.stringify(atual)}`);
}

const regras = (await pool.query(
  'SELECT id, nome, prioridade, condicoes FROM atb_triagem_regras WHERE ativo=true ORDER BY prioridade ASC, id ASC'
)).rows;

console.log(`Regras ativas: ${regras.length}\n`);
for (const r of regras) {
  const casa = avaliaCond(r.condicoes, ctx);
  console.log(`#${r.id} [${casa ? 'CASA' : 'não casa'}] ${r.nome}  (prio ${r.prioridade})`);
  walk(r.condicoes, '   ');
  console.log('');
}
const primeira = regras.find(r => avaliaCond(r.condicoes, ctx));
console.log('----------------------------------------');
console.log('1ª regra que casaria (após fix):', primeira ? `#${primeira.id} ${primeira.nome}` : 'NENHUMA');

await pool.end();
