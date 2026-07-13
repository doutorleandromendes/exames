// atb-mdr-routes.js
// ─────────────────────────────────────────────────────────────────────────
// Alertas de MDR (multirresistentes) por e-mail da microbiologia — 2ª fonte
// para o selo/tag "multirresistente", em OR com a planilha de culturas.
// Espelha o módulo de hemocultura (atb-hemocultura-routes.js).
//
// Um alerta de MDR é, por definição, uma CULTURA POSITIVA + RESISTENTE — então
// alimenta tanto "cultura positiva" quanto "MR" nos triggers/selos.

import express from 'express';

const SIGLA = 'HUSF';   // alertas de MDR são HUSF-only (como o de hemo)

async function instHUSF(pool) {
  const { rows } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla=$1`, [SIGLA]);
  return rows[0] ? rows[0].id : null;
}
function _norm(s) {
  return String(s == null ? '' : s).normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().trim();
}
function _data(v) {
  const m = String(v || '').trim().match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  if (m) { const [, d, mo, y] = m; return `${y}-${mo.padStart(2, '0')}-${d.padStart(2, '0')}`; }
  const iso = String(v || '').trim().match(/^(\d{4})-(\d{2})-(\d{2})/);
  return iso ? `${iso[1]}-${iso[2]}-${iso[3]}` : null;
}
const _dig = v => String(v == null ? '' : v).replace(/\D/g, '') || null;
const _nn = v => { const t = String(v == null ? '' : v).trim(); return t || null; };

// Deriva um rótulo curto de resistência a partir do texto do microrganismo.
// Qualquer alerta de MDR é multirresistente por definição → fallback 'MDR'.
function _resistenciaDeMicro(micro) {
  const s = _norm(micro);
  if (/carbapenemase|kpc|\bndm\b|\boxa|carbapenem/.test(s)) return 'Carbapenemase/KPC';
  if (/esbl/.test(s)) return 'ESBL';
  if (/mrsa|meticilin|oxacilin/.test(s)) return 'MRSA';
  if (/\bvre\b|resist.*vancomicina|vancomicin.*resist/.test(s)) return 'VRE';
  if (/amp\s*-?\s*c/.test(s)) return 'AmpC';
  if (/polimixina|colistina/.test(s)) return 'Resist. polimixina';
  return 'MDR';
}

export async function ensureMdrSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atb_mdr_alertas (
      id                  BIGSERIAL PRIMARY KEY,
      instituicao_id      INTEGER REFERENCES atb_instituicoes(id),
      prontuario          TEXT,
      atendimento         TEXT,
      paciente_nome       TEXT,
      paciente_nome_norm  TEXT,
      setor               TEXT,
      data_entrada        DATE,
      data_positividade   DATE,
      material            TEXT,
      microrganismo       TEXT,
      resistencia         TEXT,
      raw                 TEXT,
      email_id            TEXT,
      chave               TEXT UNIQUE,
      recebido_em         TIMESTAMPTZ DEFAULT now()
    )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS atb_mdr_pront_idx
    ON atb_mdr_alertas(instituicao_id, prontuario, data_positividade) WHERE prontuario IS NOT NULL`);
  await pool.query(`CREATE INDEX IF NOT EXISTS atb_mdr_atend_idx
    ON atb_mdr_alertas(instituicao_id, atendimento, data_positividade) WHERE atendimento IS NOT NULL`);
}

// Alertas de MDR que casam a ficha (prontuário OU atendimento), na janela.
export async function buscarMdrDaFicha(pool, ficha, diasAntes = 30, diasDepois = 5) {
  if (!ficha) return [];
  const ref = ficha.data_referencia || ficha.jotform_created_at || ficha.created_at;
  if (!ref) return [];
  const pront = String(ficha.prontuario || '').replace(/\D/g, '').trim();
  const atend = String(ficha.atendimento || '').trim();
  if (!pront && !atend) return [];
  const { rows } = await pool.query(`
    SELECT prontuario, atendimento, paciente_nome, setor, data_entrada, data_positividade, material, microrganismo, resistencia
      FROM atb_mdr_alertas
     WHERE instituicao_id IS NOT DISTINCT FROM $1
       AND COALESCE(data_positividade, recebido_em::date) >= ($2::date - ($5 || ' days')::interval)
       AND COALESCE(data_positividade, recebido_em::date) <= ($2::date + ($6 || ' days')::interval)
       AND ( ($3 <> '' AND prontuario = $3) OR ($4 <> '' AND atendimento = $4) )
     ORDER BY data_positividade DESC NULLS LAST, id DESC`,
    [ficha.instituicao_id, ref, pront, atend, String(diasAntes), String(diasDepois)]);
  return rows;
}

export function mdrTemAlerta(alertas) { return !!(alertas && alertas.length); }
export function mdrResistencias(alertas) {
  return [...new Set((alertas || []).map(a => a.resistencia).filter(Boolean))];
}

export function registerMdrRoutes(app, pool, adminRequired) {
  // Ingestão dos alertas de MDR (Apps Script). Token X-Mdr-Token == MDR_ALERTA_TOKEN.
  app.post('/atb/api/mdr-alerta', express.json({ limit: '512kb' }), async (req, res) => {
    const tok = process.env.MDR_ALERTA_TOKEN;
    if (!tok || req.get('X-Mdr-Token') !== tok) return res.status(401).json({ ok: false, error: 'token' });
    const body = req.body || {};
    const lista = Array.isArray(body.alertas) ? body.alertas : (body.prontuario || body.atendimento ? [body] : []);
    if (!lista.length) return res.status(400).json({ ok: false, error: 'sem alertas' });
    try {
      const inst = await instHUSF(pool);
      let inseridos = 0;
      for (const a of lista) {
        const pront = _dig(a.prontuario);
        const atend = _dig(a.atendimento);
        if (!pront && !atend) continue;
        const nome = _nn(a.nome || a.paciente_nome);
        const dpos = _data(a.data_positividade || a.dataPos);
        const material = _nn(a.material);
        const micro = _nn(a.microrganismo || a.microorganismo);
        const resist = _nn(a.resistencia) || _resistenciaDeMicro(micro || '');
        // dedup: paciente + data positividade + material + microrganismo
        const chave = [inst, pront || atend, dpos || '', _norm(material || ''), _norm(micro || '')].join('|');
        const r = await pool.query(`
          INSERT INTO atb_mdr_alertas
            (instituicao_id, prontuario, atendimento, paciente_nome, paciente_nome_norm, setor,
             data_entrada, data_positividade, material, microrganismo, resistencia, raw, email_id, chave, recebido_em)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14, now())
          ON CONFLICT (chave) DO UPDATE SET
            setor=EXCLUDED.setor, paciente_nome=EXCLUDED.paciente_nome,
            paciente_nome_norm=EXCLUDED.paciente_nome_norm, resistencia=EXCLUDED.resistencia
          RETURNING (xmax = 0) AS novo`,
          [inst, pront, atend, nome, _norm(nome || ''), _nn(a.setor),
           _data(a.data_entrada || a.dataEntrada), dpos, material, micro, resist,
           _nn(a.raw), _nn(a.email_id), chave]);
        if (r.rows[0] && r.rows[0].novo) inseridos++;
      }
      res.json({ ok: true, recebidos: lista.length, inseridos });
    } catch (e) {
      console.error('[atb] mdr-alerta:', e.message);
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // Debug: últimos alertas de MDR recebidos.
  app.get('/atb/admin/mdr', adminRequired, async (req, res) => {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    try {
      const { rows } = await pool.query(
        `SELECT recebido_em, prontuario, atendimento, paciente_nome, setor, data_positividade, material, microrganismo, resistencia
           FROM atb_mdr_alertas ORDER BY recebido_em DESC LIMIT 50`);
      res.send('Últimos alertas de MDR:\n\n' + rows.map(r =>
        `${(r.recebido_em && r.recebido_em.toISOString) ? r.recebido_em.toISOString() : r.recebido_em} · pront ${r.prontuario || '—'} / atend ${r.atendimento || '—'} · ${r.paciente_nome || '—'} · ${r.data_positividade || '?'} · ${r.material || '—'} · ${r.microrganismo || '—'} [${r.resistencia || '—'}]`
      ).join('\n') || '(nenhum alerta ainda)');
    } catch (e) { res.send('ERRO: ' + e.message); }
  });
}
