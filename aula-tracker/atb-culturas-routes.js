// atb-culturas-routes.js
// Fase 1 da integração de culturas (microbiologia HUSF via Google Sheets).
// - Espelha a aba "2026" da planilha viva em atb_culturas (fonte da verdade local).
// - Sync via Sheets API v4 com JWT de service account assinado por crypto nativo
//   (sem dependência nova). Credenciais só em env vars do Render.
// - Parser POSICIONAL (o cabeçalho do microrganismo é vazio → índice 9).
// - Escopo HUSF (a planilha é da microbio do HUSF). Isolado por instituicao_id.
//
// Wiring (em atb-routes.js):
//   import { ensureCulturasSchema, registerCulturasRoutes } from './atb-culturas-routes.js';
//   ensureCulturasSchema(pool).catch(e => console.error('[atb] ensureCulturasSchema:', e.message));
//   registerCulturasRoutes(app, pool, adminRequired);
//
// Env vars esperadas:
//   GOOGLE_SA_EMAIL        client_email da service account
//   GOOGLE_SA_PRIVATE_KEY  private_key do JSON (pode conter \n literais)
//   CULTURAS_SHEET_ID      id da planilha (trecho da URL entre /d/ e /edit)
//   CULTURAS_SHEET_RANGE   faixa; default '2026!A:O'

import crypto from 'crypto';

const SHEET_RANGE_DEFAULT = '2026!A:O';
const SIGLA = 'HUSF';

// ── schema ────────────────────────────────────────────────────────────────
export async function ensureCulturasSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atb_culturas (
      id                  BIGSERIAL PRIMARY KEY,
      instituicao_id      INTEGER REFERENCES atb_instituicoes(id),
      data_coleta         DATE,
      paciente_nome       TEXT,
      paciente_nome_norm  TEXT,
      atendimento         TEXT,
      material            TEXT,
      microorganismo      TEXT,
      resistencia         TEXT,
      mic_poli            TEXT,
      mic_vanco           TEXT,
      classe              TEXT,
      tempo_positividade  TEXT,
      clinica             TEXT,
      os                  TEXT,
      raw                 JSONB,
      chave               TEXT UNIQUE,
      sincronizado_em     TIMESTAMPTZ DEFAULT now()
    )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS atb_culturas_atend_idx
    ON atb_culturas(instituicao_id, atendimento, data_coleta)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS atb_culturas_nome_idx
    ON atb_culturas(instituicao_id, paciente_nome_norm, data_coleta)`);
}

async function instId(pool) {
  const { rows } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla=$1`, [SIGLA]);
  return rows[0] ? rows[0].id : null;
}

// ── helpers de parsing ──────────────────────────────────────────────────────
const _norm = s => (s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '')
  .toUpperCase().replace(/\s+/g, ' ').trim();
const _nn = v => { v = (v == null ? '' : String(v)).trim(); return (v === '-' || v === '') ? null : v; };

// DD/MM/AAAA → 'AAAA-MM-DD' (ou null)
function _data(v) {
  const m = String(v || '').trim().match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  if (!m) return null;
  const [, d, mo, y] = m;
  const dd = d.padStart(2, '0'), mm = mo.padStart(2, '0');
  if (+mm < 1 || +mm > 12 || +dd < 1 || +dd > 31) return null;
  return `${y}-${mm}-${dd}`;
}

// Mapeamento POSICIONAL (validado contra a planilha):
// 0 DATA · 1 NOME · 2 ATENDIMENTO · 3 PRESCRIÇÃO · 4 O.S · 5 CLÍNICA · 6 MATERIAL
// 7 BACT · 8 TEMPO DE POSITIVIDADE · 9 (cabeçalho vazio = MICRORGANISMO)
// 10 MR · 11 MIC POLI · 12 CLASSE · 13 MIC VANCO · 14 Rotina ou Admissão
const COL = {
  data: 0, nome: 1, atendimento: 2, os: 4, clinica: 5, material: 6,
  tempo_pos: 8, organismo: 9, mr: 10, mic_poli: 11, classe: 12, mic_vanco: 13,
};

// values: matriz [[...linha]] vinda do Sheets (linha 0 = cabeçalho).
// Retorna só linhas POSITIVAS (com microrganismo) e com data válida.
export function parseCulturas(values) {
  const out = [];
  if (!Array.isArray(values)) return out;
  for (let i = 1; i < values.length; i++) {
    const c = values[i] || [];
    const at = i => (c[i] == null ? '' : String(c[i]));
    const data_coleta = _data(at(COL.data));
    const microorganismo = _nn(at(COL.organismo));
    if (!data_coleta || !microorganismo) continue; // não-positiva / sem data → ignora
    const nome = at(COL.nome).trim();
    out.push({
      data_coleta,
      paciente_nome: nome || null,
      paciente_nome_norm: _norm(nome) || null,
      atendimento: _nn(at(COL.atendimento)),
      material: _nn(at(COL.material)),
      microorganismo,
      resistencia: _nn(at(COL.mr)),
      mic_poli: _nn(at(COL.mic_poli)),
      mic_vanco: _nn(at(COL.mic_vanco)),
      classe: _nn(at(COL.classe)),
      tempo_positividade: _nn(at(COL.tempo_pos)),
      clinica: _nn(at(COL.clinica)),
      os: _nn(at(COL.os)),
      raw: c,
    });
  }
  return out;
}

// ── Sheets API v4 via JWT de service account ────────────────────────────────
function _b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function getAccessToken() {
  const email = process.env.GOOGLE_SA_EMAIL;
  let key = process.env.GOOGLE_SA_PRIVATE_KEY || '';
  key = key.replace(/\\n/g, '\n'); // \n literais do env → quebras reais
  if (!email || !key) throw new Error('faltam GOOGLE_SA_EMAIL / GOOGLE_SA_PRIVATE_KEY');
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const claim = {
    iss: email,
    scope: 'https://www.googleapis.com/auth/spreadsheets.readonly',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now, exp: now + 3600,
  };
  const unsigned = _b64url(JSON.stringify(header)) + '.' + _b64url(JSON.stringify(claim));
  const sig = crypto.createSign('RSA-SHA256').update(unsigned).sign(key);
  const jwt = unsigned + '.' + _b64url(sig);
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }),
  });
  const j = await r.json().catch(() => ({}));
  if (!j.access_token) throw new Error('token: ' + (j.error_description || j.error || 'sem access_token'));
  return j.access_token;
}

async function fetchSheetValues() {
  const id = process.env.CULTURAS_SHEET_ID;
  const range = process.env.CULTURAS_SHEET_RANGE || SHEET_RANGE_DEFAULT;
  if (!id) throw new Error('falta CULTURAS_SHEET_ID');
  const token = await getAccessToken();
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(id)}/values/${encodeURIComponent(range)}`;
  const r = await fetch(url, { headers: { Authorization: 'Bearer ' + token } });
  const j = await r.json().catch(() => ({}));
  if (!j.values) throw new Error('sheet: ' + (j.error && j.error.message ? j.error.message : 'sem values'));
  return j.values;
}

// ── sync ────────────────────────────────────────────────────────────────────
export async function sincronizarCulturas(pool) {
  await ensureCulturasSchema(pool);
  const inst = await instId(pool);
  if (!inst) throw new Error(`instituição ${SIGLA} não encontrada em atb_instituicoes`);
  const values = await fetchSheetValues();
  const linhas = parseCulturas(values);
  let inseridas = 0, atualizadas = 0;
  for (const c of linhas) {
    const chave = [inst, c.atendimento || '', c.data_coleta, c.material || '', c.microorganismo].join('|');
    const q = await pool.query(`
      INSERT INTO atb_culturas
        (instituicao_id, data_coleta, paciente_nome, paciente_nome_norm, atendimento,
         material, microorganismo, resistencia, mic_poli, mic_vanco, classe,
         tempo_positividade, clinica, os, raw, chave, sincronizado_em)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16, now())
      ON CONFLICT (chave) DO UPDATE SET
        resistencia=EXCLUDED.resistencia, mic_poli=EXCLUDED.mic_poli, mic_vanco=EXCLUDED.mic_vanco,
        classe=EXCLUDED.classe, tempo_positividade=EXCLUDED.tempo_positividade, clinica=EXCLUDED.clinica,
        os=EXCLUDED.os, raw=EXCLUDED.raw, paciente_nome=EXCLUDED.paciente_nome,
        paciente_nome_norm=EXCLUDED.paciente_nome_norm, sincronizado_em=now()
      RETURNING (xmax = 0) AS inserted`,
      [inst, c.data_coleta, c.paciente_nome, c.paciente_nome_norm, c.atendimento,
       c.material, c.microorganismo, c.resistencia, c.mic_poli, c.mic_vanco, c.classe,
       c.tempo_positividade, c.clinica, c.os, JSON.stringify(c.raw), chave]);
    if (q.rows[0].inserted) inseridas++; else atualizadas++;
  }
  return { lidas: linhas.length, inseridas, atualizadas };
}

// ── rotas ─────────────────────────────────────────────────────────────────
export function registerCulturasRoutes(app, pool, adminRequired) {
  // POST: dispara o sync (usado pelo botão e pelo cron do Render)
  app.post('/atb/admin/culturas/sync', adminRequired, async (req, res) => {
    try {
      const r = await sincronizarCulturas(pool);
      res.json({ ok: true, ...r });
    } catch (e) {
      console.error('[atb] culturas sync:', e.message);
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // GET: tela read-only de conferência (parsing + match por atendimento)
  app.get('/atb/admin/culturas', adminRequired, async (req, res) => {
    try {
      await ensureCulturasSchema(pool);
      const inst = await instId(pool);
      const s = (await pool.query(`
        SELECT
          COUNT(*)::int AS total,
          COUNT(*) FILTER (WHERE resistencia IS NOT NULL)::int AS com_mr,
          COUNT(DISTINCT atendimento)::int AS atendimentos,
          MAX(sincronizado_em) AS ultimo_sync
        FROM atb_culturas WHERE instituicao_id IS NOT DISTINCT FROM $1`, [inst])).rows[0];
      // quantos atendimentos das culturas casam com alguma ficha HUSF
      const match = (await pool.query(`
        SELECT COUNT(DISTINCT c.atendimento)::int AS casados
        FROM atb_culturas c
        WHERE c.instituicao_id IS NOT DISTINCT FROM $1 AND c.atendimento IS NOT NULL
          AND EXISTS (SELECT 1 FROM atb_fichas f
                       WHERE f.instituicao_id IS NOT DISTINCT FROM $1
                         AND f.atendimento = c.atendimento AND f.deletado_em IS NULL)`, [inst])).rows[0];
      const linhas = (await pool.query(`
        SELECT c.data_coleta, c.paciente_nome, c.atendimento, c.material, c.microorganismo,
               c.resistencia, c.mic_vanco, c.tempo_positividade,
               EXISTS (SELECT 1 FROM atb_fichas f
                        WHERE f.instituicao_id IS NOT DISTINCT FROM $1
                          AND f.atendimento = c.atendimento AND f.deletado_em IS NULL) AS casa
        FROM atb_culturas c
        WHERE c.instituicao_id IS NOT DISTINCT FROM $1
        ORDER BY c.data_coleta DESC NULLS LAST, c.id DESC
        LIMIT 200`, [inst])).rows;

      const esc = v => String(v == null ? '' : v).replace(/[&<>"]/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[m]));
      const dt = d => d ? new Date(d).toLocaleDateString('pt-BR') : '—';
      const chip = v => v ? `<span style="background:#fcebeb;color:#a32d2d;font-size:11px;padding:1px 7px;border-radius:6px">${esc(v)}</span>` : '';
      const rows = linhas.map(r => `<tr style="border-top:1px solid #eee">
        <td style="padding:6px 8px">${dt(r.data_coleta)}</td>
        <td style="padding:6px 8px">${esc(r.paciente_nome)}</td>
        <td style="padding:6px 8px;font-variant-numeric:tabular-nums">${esc(r.atendimento)} ${r.casa ? '<span style="color:#0f6e56">✓</span>' : '<span style="color:#a32d2d">✗</span>'}</td>
        <td style="padding:6px 8px;color:#555">${esc(r.material)}</td>
        <td style="padding:6px 8px;font-weight:500">${esc(r.microorganismo)}</td>
        <td style="padding:6px 8px">${chip(r.resistencia)}</td>
        <td style="padding:6px 8px;color:#555">${esc([r.mic_vanco ? 'vanco ' + r.mic_vanco : '', r.tempo_positividade].filter(Boolean).join(' · '))}</td>
      </tr>`).join('');

      res.send(`<!doctype html><meta charset="utf-8"><title>Culturas · conferência</title>
<style>body{font-family:system-ui,Segoe UI,Arial;margin:24px;color:#1a1a1a}
h1{font-size:20px} .card{border:1px solid #e5e7eb;border-radius:10px;padding:14px 16px;margin:12px 0}
.stat{display:inline-block;margin-right:22px} .stat b{font-size:20px;display:block}
button{padding:9px 14px;border:0;border-radius:8px;background:#1a6b3a;color:#fff;font-weight:600;cursor:pointer}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}
th{text-align:left;padding:6px 8px;color:#666;font-size:12px;border-bottom:1px solid #ddd}
#msg{margin-left:12px;font-size:13px}</style>
<h1>Culturas — conferência (Fase 1)</h1>
<div class="card">
  <div class="stat"><b>${s.total}</b>culturas positivas</div>
  <div class="stat"><b>${s.com_mr}</b>com resistência (MR)</div>
  <div class="stat"><b>${s.atendimentos}</b>atendimentos</div>
  <div class="stat"><b>${match.casados}</b>atendimentos que casam com ficha</div>
  <div class="stat"><b style="font-size:14px">${s.ultimo_sync ? new Date(s.ultimo_sync).toLocaleString('pt-BR') : '—'}</b>último sync</div>
</div>
<div class="card">
  <button id="sync">Sincronizar agora</button><span id="msg"></span>
  <p style="color:#666;font-size:12px;margin:10px 0 0">Espelha a aba "2026" da planilha da microbiologia. Coluna "atendimento": ✓ = existe ficha HUSF com esse atendimento, ✗ = sem ficha correspondente.</p>
</div>
<div class="card">
  <table><thead><tr><th>Data</th><th>Paciente</th><th>Atend.</th><th>Material</th><th>Microrganismo</th><th>Resist.</th><th>MIC/tempo</th></tr></thead>
  <tbody>${rows || '<tr><td colspan="7" style="padding:14px;color:#888">Sem culturas ainda — clique em "Sincronizar agora".</td></tr>'}</tbody></table>
</div>
<script>
document.getElementById('sync').addEventListener('click', function(){
  var b=this, m=document.getElementById('msg'); b.disabled=true; m.textContent='sincronizando…';
  fetch('/atb/admin/culturas/sync',{method:'POST'}).then(r=>r.json()).then(j=>{
    b.disabled=false;
    if(j.ok){ m.textContent='OK: '+j.lidas+' lidas · '+j.inseridas+' novas · '+j.atualizadas+' atualizadas. Recarregando…'; setTimeout(()=>location.reload(),900); }
    else m.textContent='Falha: '+(j.error||'erro');
  }).catch(()=>{ b.disabled=false; m.textContent='Erro de rede.'; });
});
</script>`);
    } catch (e) {
      console.error('[atb] culturas view:', e.message);
      res.status(500).send('Erro: ' + e.message);
    }
  });
}
