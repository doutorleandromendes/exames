// atb-hemocultura-routes.js
// ─────────────────────────────────────────────────────────────────────────
// Alertas de HEMOCULTURA PARCIAL (Gram precoce) enviados por e-mail pela
// microbiologia (Unilab). Um Apps Script no Gmail que recebe esses e-mails
// parseia cada alerta e faz POST aqui (com token). O app guarda e sinaliza no
// grid/card, cruzando por prontuário/atendimento — sinal precoce de bacteremia,
// antes do resultado definitivo da planilha.
//
// Wiring (atb-routes.js):
//   import { ensureHemoSchema, registerHemoRoutes } from './atb-hemocultura-routes.js';
//   ensureHemoSchema(pool).catch(...);  registerHemoRoutes(app, pool, adminRequired);

import express from 'express';

const SIGLA = 'HUSF';

async function instHUSF(pool) {
  const { rows } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla=$1`, [SIGLA]);
  return rows[0] ? rows[0].id : null;
}

function _norm(s) {
  return String(s == null ? '' : s).normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .toUpperCase().replace(/\s+/g, ' ').trim();
}
// 'DD/MM/AAAA' -> 'AAAA-MM-DD' (ou null)
function _data(v) {
  const m = String(v || '').trim().match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  if (!m) return null;
  const [, d, mo, y] = m;
  return `${y}-${mo.padStart(2, '0')}-${d.padStart(2, '0')}`;
}
const _dig = v => String(v == null ? '' : v).replace(/\D/g, '') || null;
const _nn = v => { const t = String(v == null ? '' : v).trim(); return t || null; };

export async function ensureHemoSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atb_hemocultura_alertas (
      id                  BIGSERIAL PRIMARY KEY,
      instituicao_id      INTEGER REFERENCES atb_instituicoes(id),
      prontuario          TEXT,
      atendimento         TEXT,
      paciente_nome       TEXT,
      paciente_nome_norm  TEXT,
      setor               TEXT,
      data_entrada        DATE,
      data_positividade   DATE,
      gram                TEXT,
      amostras            TEXT,
      raw                 TEXT,
      email_id            TEXT,
      chave               TEXT UNIQUE,
      recebido_em         TIMESTAMPTZ DEFAULT now()
    )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS atb_hemo_pront_idx
    ON atb_hemocultura_alertas(instituicao_id, prontuario, data_positividade) WHERE prontuario IS NOT NULL`);
  await pool.query(`CREATE INDEX IF NOT EXISTS atb_hemo_atend_idx
    ON atb_hemocultura_alertas(instituicao_id, atendimento, data_positividade) WHERE atendimento IS NOT NULL`);
}

// Alertas de hemocultura que casam com uma ficha: mesma instituição, janela
// [ref-30d, ref+5d] pela data de positividade, por prontuário OU atendimento.
export async function buscarHemoDaFicha(pool, ficha, diasAntes = 30, diasDepois = 5) {
  if (!ficha) return [];
  const ref = ficha.data_referencia || ficha.jotform_created_at || ficha.created_at;
  if (!ref) return [];
  const pront = String(ficha.prontuario || '').replace(/\D/g, '').trim();
  const atend = String(ficha.atendimento || '').trim();
  if (!pront && !atend) return [];
  const { rows } = await pool.query(`
    SELECT prontuario, atendimento, paciente_nome, setor, data_entrada, data_positividade, gram, amostras
      FROM atb_hemocultura_alertas
     WHERE instituicao_id IS NOT DISTINCT FROM $1
       AND COALESCE(data_positividade, recebido_em::date) >= ($2::date - ($5 || ' days')::interval)
       AND COALESCE(data_positividade, recebido_em::date) <= ($2::date + ($6 || ' days')::interval)
       AND ( ($3 <> '' AND prontuario = $3) OR ($4 <> '' AND atendimento = $4) )
     ORDER BY data_positividade DESC NULLS LAST, id DESC`,
    [ficha.instituicao_id, ref, pront, atend, String(diasAntes), String(diasDepois)]);
  return rows;
}

export function hemoTemAlerta(alertas) { return !!(alertas && alertas.length); }

// Banner do card: alerta precoce de bacteremia (Gram parcial), em destaque vermelho.
export function renderHemoCard(alertas) {
  if (!alertas || !alertas.length) return '';
  const esc = v => String(v == null ? '' : v).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const dt = d => d ? new Date(d).toLocaleDateString('pt-BR') : '—';
  const itens = alertas.slice(0, 5).map(a =>
    `<div style="margin-top:4px;font-size:12px">🩸 <b>${esc(a.gram || 'Hemocultura positiva (parcial)')}</b>`
    + ` <span style="color:#b45309">${dt(a.data_positividade)}</span>`
    + (a.amostras ? ` · ${esc(a.amostras)}` : '')
    + (a.setor ? ` · ${esc(a.setor)}` : '') + `</div>`
  ).join('');
  return `<div style="background:#fef2f2;border:1px solid #fca5a5;border-left:3px solid #dc2626;border-radius:8px;padding:10px 12px;margin-bottom:10px">`
    + `<div style="font-weight:700;color:#b91c1c;font-size:13px">⚠ Hemocultura parcial positiva — alerta precoce</div>`
    + itens + `</div>`;
}

export function registerHemoRoutes(app, pool, adminRequired) {
  // Ingestão dos alertas (Apps Script). Aceita 1 alerta ou vários (um e-mail
  // pode conter múltiplos pacientes). Auth por token (X-Hemo-Token).
  app.post('/atb/api/hemocultura-alerta', express.json({ limit: '256kb' }), async (req, res) => {
    const tok = process.env.HEMO_ALERTA_TOKEN;
    if (!tok || req.get('X-Hemo-Token') !== tok) return res.status(401).json({ ok: false, error: 'token' });
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
        const gram = _nn(a.gram);
        // dedup estável: prontuário/atendimento + data positividade + gram
        const chave = [inst, pront || atend, dpos || '', _norm(gram || '')].join('|');
        const r = await pool.query(`
          INSERT INTO atb_hemocultura_alertas
            (instituicao_id, prontuario, atendimento, paciente_nome, paciente_nome_norm, setor,
             data_entrada, data_positividade, gram, amostras, raw, email_id, chave, recebido_em)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13, now())
          ON CONFLICT (chave) DO UPDATE SET
            setor=EXCLUDED.setor, amostras=EXCLUDED.amostras, paciente_nome=EXCLUDED.paciente_nome,
            paciente_nome_norm=EXCLUDED.paciente_nome_norm
          RETURNING (xmax = 0) AS novo`,
          [inst, pront, atend, nome, _norm(nome || ''), _nn(a.setor),
           _data(a.data_entrada || a.dataEntrada), dpos, gram, _nn(a.amostras),
           _nn(a.raw), _nn(a.email_id), chave]);
        if (r.rows[0] && r.rows[0].novo) inseridos++;
      }
      res.json({ ok: true, recebidos: lista.length, inseridos });
    } catch (e) {
      console.error('[atb] hemocultura-alerta:', e.message);
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // Debug: últimos alertas recebidos (adminRequired).
  app.get('/atb/admin/hemocultura', adminRequired, async (req, res) => {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    try {
      const { rows } = await pool.query(`
        SELECT prontuario, atendimento, paciente_nome, setor, data_positividade, gram, amostras, recebido_em
          FROM atb_hemocultura_alertas ORDER BY recebido_em DESC LIMIT 30`);
      res.send('Últimos alertas de hemocultura:\n\n' + rows.map(r =>
        `${r.data_positividade || '—'} · pront ${r.prontuario || '—'} / atend ${r.atendimento || '—'} · ${r.paciente_nome || '—'} (${r.setor || '—'})\n  ${r.gram || ''} · ${r.amostras || ''}`
      ).join('\n\n'));
    } catch (e) { res.send('ERRO: ' + e.message); }
  });
}
