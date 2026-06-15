// ════════════════════════════════════════════════════════════════════════════
//  ADESÃO AOS PARECERES  —  /atb/admin/adesao
//
//  Tela dedicada (SCIH / adminRequired) para registrar a adesão aos pareceres
//  NEGATIVOS ("Não") emitidos há mais de 3 dias. Base dos indicadores mensais.
//
//  Para cada ficha da worklist, o SCIH preenche inline:
//    • Desfecho da adesão: Mantido | Suspenso_troca | Suspenso_alta |
//      Suspenso_semATB | Suspenso_obito
//    • ATB de troca (só quando Suspenso_troca)
//
//  Worklist = veredito "Não"  E  parecer há > 3 dias, escopada por mês
//  (padrão: mês atual; seletor permite fechar meses anteriores).
//
//  Integração em atb-routes.js:
//    import { ensureAdesaoSchema, registerAdesaoRoutes } from './atb-adesao-routes.js';
//    // no boot:               ensureAdesaoSchema(pool).catch(...);
//    // em registerAtbRoutes:  registerAdesaoRoutes(app, pool, adminRequired);
//  Link na grade (admin): <a href="/atb/admin/adesao">Adesão</a>
//
//  A tabulação dos indicadores é um esqueleto (contagem por desfecho) — será
//  refinada depois conforme orientação.
// ════════════════════════════════════════════════════════════════════════════

export const ADESAO_DESFECHOS = ['Mantido', 'Suspenso_troca', 'Suspenso_alta', 'Suspenso_semATB', 'Suspenso_obito'];

// lista de ATB de troca (alfabética, com Levofloxacina incluída)
export const ATB_TROCA = [
  'Amicacina', 'Amoxicilina/Clavulanato', 'Ampicilina', 'Ampicilina/Sulbactam',
  'Cefazolina', 'Cefepime', 'Ceftriaxone', 'Ciprofloxacina', 'Fosfomicina',
  'Gentamicina', 'Levofloxacina', 'Meropenem', 'Piperacilina/Tazobactam',
  'Teicoplanina', 'Vancomicina',
];

function _safe(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
const _arr = v => Array.isArray(v) ? v : (v == null ? [] : (typeof v === 'string'
  ? (() => { try { const x = JSON.parse(v); return Array.isArray(x) ? x : []; } catch { return []; } })()
  : []));

export async function ensureAdesaoSchema(pool) {
  await pool.query(`ALTER TABLE atb_fichas ADD COLUMN IF NOT EXISTS adesao_desfecho TEXT`);
  await pool.query(`ALTER TABLE atb_fichas ADD COLUMN IF NOT EXISTS adesao_troca_atb TEXT`);
  await pool.query(`ALTER TABLE atb_fichas ADD COLUMN IF NOT EXISTS adesao_por INTEGER REFERENCES users(id)`);
  await pool.query(`ALTER TABLE atb_fichas ADD COLUMN IF NOT EXISTS adesao_em TIMESTAMPTZ`);
}

// data de referência do parecer (emissão; cai pra data da ficha nas históricas)
const DATA_PARECER_SQL = `COALESCE(f.parecer_emitido_at, f.jotform_created_at, f.data_referencia, f.created_at)`;

function _selDesfecho(id, sel) {
  const opts = ['<option value="">— desfecho —</option>']
    .concat(ADESAO_DESFECHOS.map(o => `<option value="${o}" ${o === sel ? 'selected' : ''}>${o}</option>`)).join('');
  return `<select class="ad-desf" data-id="${id}">${opts}</select>`;
}
function _selTroca(id, sel, ativo) {
  const opts = ['<option value="">— troca —</option>']
    .concat(ATB_TROCA.map(o => `<option value="${_safe(o)}" ${o === sel ? 'selected' : ''}>${_safe(o)}</option>`)).join('');
  return `<select class="ad-troca" data-id="${id}" ${ativo ? '' : 'disabled'}>${opts}</select>`;
}

function paginaAdesao(rows, mes, somentePendentes) {
  const dt = d => d ? new Date(d).toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit', year: 'numeric' }) : '—';

  // resumo (esqueleto de tabulação) — contagem por desfecho no recorte
  const cont = {}; ADESAO_DESFECHOS.forEach(d => cont[d] = 0);
  let avaliadas = 0;
  rows.forEach(f => { if (f.adesao_desfecho) { avaliadas++; if (cont[f.adesao_desfecho] != null) cont[f.adesao_desfecho]++; } });
  const pendentes = rows.length - avaliadas;
  const chips = ADESAO_DESFECHOS.map(d =>
    `<span class="chip"><b>${cont[d]}</b> ${d}</span>`).join('');

  const linhas = rows.map(f => {
    const nome = f.paciente_nome || f.paciente_nome_raw || '—';
    const atb = _arr(f.atb_solicitado).join(', ');
    const ehTroca = f.adesao_desfecho === 'Suspenso_troca';
    return `<tr data-id="${f.id}">
      <td class="dt">${dt(f.data_parecer)}</td>
      <td><a href="/atb/admin/ficha/${f.id}" class="nome">${_safe(nome)}</a></td>
      <td>${_safe(f.prontuario || '')}</td>
      <td>${_safe(f.setor || '')}</td>
      <td class="atb">${_safe(atb)}</td>
      <td>${_selDesfecho(f.id, f.adesao_desfecho || '')}</td>
      <td>${_selTroca(f.id, f.adesao_troca_atb || '', ehTroca)}</td>
      <td class="acao"><a href="/atb/admin/parecer/${f.id}/imagem" target="_blank" title="Imagem do parecer">🖼️</a></td>
    </tr>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="pt-BR"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Adesão aos pareceres</title>
<style>
  :root{--azul:#00469e;--azul-claro:#e6eef8;--borda:#d8dee6;--fundo:#f4f6f9;--tinta:#202124;--mut:#5f6368}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--fundo);color:var(--tinta);font-size:13px}
  .cab{background:#fff;border-bottom:2px solid var(--azul);padding:14px 22px;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
  .cab h1{font-size:17px;color:var(--azul)}
  .cab a{font-size:13px;color:var(--azul);text-decoration:none}
  .controles{display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding:12px 22px;background:#fff;border-bottom:1px solid var(--borda)}
  .controles label{font-size:12px;color:var(--mut)}
  .controles input,.controles select{padding:7px 10px;border:1px solid var(--borda);border-radius:7px;font-size:13px;font-family:inherit}
  .resumo{display:flex;gap:8px;flex-wrap:wrap;padding:12px 22px;align-items:center}
  .chip{background:#fff;border:1px solid var(--borda);border-radius:16px;padding:5px 12px;font-size:12px;color:var(--mut)}
  .chip b{color:var(--tinta)}
  .tot{font-size:13px;color:var(--mut);margin-right:6px}
  .wrap{padding:0 16px 60px}
  table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--borda);border-radius:10px;overflow:hidden}
  th{background:#fff;color:var(--mut);text-align:left;font-size:11px;font-weight:600;padding:10px 12px;border-bottom:1px solid var(--borda);white-space:nowrap}
  td{padding:8px 12px;border-bottom:1px solid #f0f1f3;vertical-align:middle}
  tr:hover td{background:#fafbfc}
  td.dt{white-space:nowrap;color:var(--mut)}
  td.atb{max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .nome{font-weight:600;color:var(--tinta);text-decoration:none}
  td select{padding:6px 8px;border:1px solid var(--borda);border-radius:7px;font-size:12px;font-family:inherit;background:#fafbfc;max-width:200px}
  td select:disabled{opacity:.5;background:#f0f1f3}
  td.acao a{text-decoration:none;font-size:15px}
  .vazio{padding:30px;text-align:center;color:var(--mut)}
  .saved{outline:2px solid #1a8a5a55}
</style></head>
<body>
  <div class="cab">
    <h1>Adesão aos pareceres</h1>
    <a href="/atb/admin/grid">← voltar à grade</a>
  </div>
  <form class="controles" method="GET" action="/atb/admin/adesao">
    <label>Mês <input type="month" name="mes" value="${_safe(mes)}" onchange="this.form.submit()"></label>
    <label><input type="checkbox" name="status" value="pendente" ${somentePendentes ? 'checked' : ''} onchange="this.form.submit()"> só pendentes</label>
  </form>
  <div class="resumo">
    <span class="tot">${rows.length} no recorte · ${avaliadas} avaliadas · ${pendentes} pendentes</span>
    ${chips}
  </div>
  <div class="wrap">
    <table>
      <thead><tr>
        <th>Data parecer</th><th>Paciente</th><th>Prontuário</th><th>Setor</th>
        <th>ATB solicitado</th><th>Desfecho da adesão</th><th>ATB de troca</th><th></th>
      </tr></thead>
      <tbody>${linhas || `<tr><td colspan="8" class="vazio">Nenhum parecer negativo (&gt;3 dias) neste mês.</td></tr>`}</tbody>
    </table>
  </div>

  <script>
  (function(){
    function salvar(tr){
      var id = tr.getAttribute('data-id');
      var desf = tr.querySelector('.ad-desf');
      var troca = tr.querySelector('.ad-troca');
      var ehTroca = desf.value === 'Suspenso_troca';
      troca.disabled = !ehTroca;
      if(!ehTroca) troca.value = '';
      var body = new URLSearchParams({ desfecho: desf.value, troca: troca.value });
      fetch('/atb/admin/api/adesao/' + id, {
        method:'POST', headers:{ 'Content-Type':'application/x-www-form-urlencoded' }, body: body.toString()
      }).then(function(r){ return r.json(); }).then(function(j){
        if(j && j.ok){ tr.classList.add('saved'); setTimeout(function(){ tr.classList.remove('saved'); }, 700); }
      }).catch(function(){});
    }
    document.querySelector('tbody').addEventListener('change', function(ev){
      var sel = ev.target;
      if(sel.classList.contains('ad-desf') || sel.classList.contains('ad-troca')){
        salvar(sel.closest('tr'));
      }
    });
  })();
  </script>
</body></html>`;
}

export function registerAdesaoRoutes(app, pool, adminRequired) {

  app.get('/atb/admin/adesao', adminRequired, async (req, res) => {
    try {
      const agora = new Date();
      const mesAtual = agora.getFullYear() + '-' + String(agora.getMonth() + 1).padStart(2, '0');
      const mes = /^\d{4}-\d{2}$/.test(req.query.mes || '') ? req.query.mes : mesAtual;
      const [ano, m] = mes.split('-').map(Number);
      const somentePendentes = req.query.status === 'pendente';

      const where = [
        `jsonb_typeof(f.recomendacao_scih)='array'`,
        `f.recomendacao_scih @> '["Não"]'::jsonb`,
        `${DATA_PARECER_SQL} <= now() - interval '3 days'`,
        `EXTRACT(YEAR FROM ${DATA_PARECER_SQL}) = $1`,
        `EXTRACT(MONTH FROM ${DATA_PARECER_SQL}) = $2`,
      ];
      if (somentePendentes) where.push(`f.adesao_desfecho IS NULL`);

      const { rows } = await pool.query(`
        SELECT f.id, f.paciente_nome, f.paciente_nome_raw, f.prontuario, f.setor,
               f.atb_solicitado, f.adesao_desfecho, f.adesao_troca_atb,
               ${DATA_PARECER_SQL} AS data_parecer
        FROM atb_fichas f
        WHERE ${where.join(' AND ')}
        ORDER BY ${DATA_PARECER_SQL} ASC`, [ano, m]);

      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(paginaAdesao(rows, mes, somentePendentes));
    } catch (e) {
      console.error('[atb] adesao page error:', e.message);
      res.status(500).send('Erro: ' + _safe(e.message));
    }
  });

  app.post('/atb/admin/api/adesao/:id', adminRequired, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      let desfecho = (req.body.desfecho || '').trim();
      let troca = (req.body.troca || '').trim();
      if (desfecho && !ADESAO_DESFECHOS.includes(desfecho)) return res.status(400).json({ ok: false, error: 'desfecho inválido' });
      if (troca && !ATB_TROCA.includes(troca)) return res.status(400).json({ ok: false, error: 'ATB de troca inválido' });
      if (desfecho !== 'Suspenso_troca') troca = '';  // troca só faz sentido em Suspenso_troca

      await pool.query(`
        UPDATE atb_fichas
           SET adesao_desfecho = $1, adesao_troca_atb = $2, adesao_por = $3, adesao_em = now()
         WHERE id = $4`,
        [desfecho || null, troca || null, req.user?.id || null, id]);

      res.json({ ok: true });
    } catch (e) {
      console.error('[atb] adesao save error:', e.message);
      res.status(500).json({ ok: false, error: e.message });
    }
  });
}
