// ════════════════════════════════════════════════════════════════════════════
//  scmi-import.mjs — importa as submissões históricas do JotForm do SCMI
//  (form 210473106708652) para atb_fichas, tagueadas com a instituição SCMI.
//
//  O form do SCMI é da mesma linhagem do HUSF, mas com 5 qids divergentes.
//  Em vez de um parser novo, normalizamos os qids do SCMI para os canônicos
//  que parseAnswers() (já validado em 16.989 fichas do HUSF) entende:
//
//    SCMI 74 (Equipe)        → 75   (equipe_responsavel)
//    SCMI 73 (Especificação) → 88   (recomendacoes_especificacao)
//    SCMI 82 (Idade)         → 95   (paciente_idade)
//    apaga 82  → impede faz_quimio espúrio (HUSF lê faz_quimio do 82)
//    apaga 66  → impede clcr=e-mail        (HUSF lê clcr do 66)
//    (IrAS, SCMI 75, é descartada — sobrescrita por 74; é classificação pós-hoc)
//
//  Dedup: o upsert usa ON CONFLICT (jotform_submission_id) DO UPDATE, e preserva
//  campos do SCIH já escritos. Re-rodar é seguro (idempotente).
//
//  Uso:
//    node scmi-import.mjs <submissions.json> --dry [--limit 20]   # só parseia e mostra
//    node scmi-import.mjs <submissions.json>                      # importa de verdade
//
//  Requer DATABASE_URL no ambiente (mesmo do app).
// ════════════════════════════════════════════════════════════════════════════
import fs from 'fs';
import pg from 'pg';
import { parseAnswers } from './atb-parser.js';
import { upsertFicha } from './atb-sync.js';

const { Pool } = pg;
const SCMI_FORM_ID = '210473106708652';

const args = process.argv.slice(2);
const DRY = args.includes('--dry');
const fileArg = args.find(a => a.endsWith('.json'));
const limIdx = args.indexOf('--limit');
const LIMIT = limIdx >= 0 ? parseInt(args[limIdx + 1], 10) : Infinity;

// ── normalizador de qid: SCMI → canônico HUSF ────────────────────────────────
export function normalizeScmiQids(answers) {
  const a = { ...answers };
  if (a['74']) a['75'] = a['74'];   // Equipe responsável
  if (a['73']) a['88'] = a['73'];   // Recomendações (especificação)
  if (a['82']) a['95'] = a['82'];   // Idade → paciente_idade
  delete a['82'];                   // senão vira faz_quimio (HUSF lê toBool(82))
  delete a['66'];                   // senão vira clcr=e-mail (HUSF lê toNum(66))
  return a;
}

function carregarSubmissoes(file) {
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (Array.isArray(raw)) return raw;
  if (Array.isArray(raw.content)) return raw.content;   // alguns exports embrulham em {content:[...]}
  if (raw.answers) return [raw];                          // submissão única
  return Object.values(raw);
}

async function main() {
  if (!fileArg) {
    console.error('uso: node scmi-import.mjs <submissions.json> [--dry] [--limit N]');
    process.exit(1);
  }
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: true },
    max: 4,
  });

  const { rows: [inst] } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla='SCMI'`);
  if (!inst) { console.error('ERRO: instituição SCMI não encontrada em atb_instituicoes.'); process.exit(1); }
  const scmiId = inst.id;
  console.log(`Instituição SCMI = id ${scmiId}${DRY ? '  [DRY-RUN: nada será gravado]' : ''}`);

  const subs = carregarSubmissoes(fileArg);
  console.log(`Submissões no arquivo: ${subs.length}${LIMIT !== Infinity ? ` (limitando a ${LIMIT})` : ''}\n`);

  let n = 0, ins = 0, upd = 0, err = 0, vazias = 0;
  const amostra = [];
  for (const sub of subs) {
    if (n >= LIMIT) break;
    n++;
    try {
      const answers = sub.answers || {};
      if (!Object.keys(answers).length) { vazias++; continue; }
      const parsed = parseAnswers(normalizeScmiQids(answers), SCMI_FORM_ID);

      if (DRY) {
        if (amostra.length < 8) amostra.push({
          id: sub.id,
          nome: parsed.paciente_nome,
          dn: parsed.paciente_dn, idade: parsed.paciente_idade,
          setor: parsed.setor, equipe: parsed.equipe_responsavel, leito: parsed.leito,
          crm: parsed.crm, prescritor: parsed.prescritor_nome,
          atb: parsed.atb_solicitado, tipo: parsed.tipo_terapia, sepse: parsed.sepse,
          espec: parsed.recomendacoes_especificacao,
          _faz_quimio: parsed.faz_quimio, _clcr: parsed.clcr,   // devem ficar vazios
        });
        continue;
      }
      const r = await upsertFicha(pool, String(sub.id), parsed, scmiId, sub, sub.created_at || null);
      if (r?.inserted) ins++; else upd++;
    } catch (e) {
      err++;
      if (err <= 10) console.error(`  erro submissão ${sub.id}: ${e.message}`);
    }
    if (!DRY && n % 500 === 0) console.log(`  ...${n} processadas (ins ${ins} / upd ${upd} / err ${err})`);
  }

  console.log('\n' + (DRY ? '[DRY-RUN]' : '[IMPORT]'), { total: n, inseridos: ins, atualizados: upd, vazias, erros: err });
  if (DRY) console.log('\nAmostra parseada:\n' + JSON.stringify(amostra, null, 2));
  await pool.end();
}

// Só executa quando rodado direto (permite importar normalizeScmiQids em testes).
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(e => { console.error(e); process.exit(1); });
}
