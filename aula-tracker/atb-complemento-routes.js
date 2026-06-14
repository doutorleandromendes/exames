// ════════════════════════════════════════════════════════════════════════════
//  Tela de COMPLEMENTAÇÃO de dados evolutivos (DVA/EVA/Labs/Acesso Neo)
//  + Complemento SCIH + Parecer Evolutivo.
//
//  Preenchida por colaboradoras. Acesso compartilhado (adminRequired);
//  a rastreabilidade é por NOME digitado antes de salvar (preenchido_por_nome).
//
//  Linguagem visual do formulário do prescritor: azul #00469e, cartões claros.
//
//  Integração em atb-routes.js:
//    import { ensureComplementoSchema, registerComplementoRoutes } from './atb-complemento-routes.js';
//    // no boot:        await ensureComplementoSchema(pool);
//    // em registerAtbRoutes:  registerComplementoRoutes(app, pool, adminRequired);
// ════════════════════════════════════════════════════════════════════════════
import { anexosManagerWidget } from './atb-anexos-routes.js';
const DIAS = ['D-3', 'D-2', 'D-1', 'D0', 'D+1', 'D+2', 'D+3'];

const GRUPOS = {
  ventilatorio: { titulo: 'Evento Ventilatório Agudo (EVA)', exames: ['PEEP', 'FiO2', 'Rel', 'ST', 'Data'] },
  hemodinamica: { titulo: 'Parâmetros Hemodinâmicos (DVA)', exames: ['Nora', 'Vaso', 'Dobu', 'Lactato', 'Data'] },
  labs:         { titulo: 'Laboratório', exames: ['Leuco', 'Bast', 'Seg', 'Linf', 'Eos', 'Plq', 'Lactato', 'PCR', 'Data'] },
  acesso:       { titulo: 'Acesso Vascular Neo', exames: ['PICC', 'CUV', 'Flebo', 'CVC', 'Data'] },
};
// chave do banco (acesso_vascular_neo_evol) ≠ chave curta da UI (acesso)
const COL_BANCO = { ventilatorio: 'ventilatorio', hemodinamica: 'hemodinamica', labs: 'labs', acesso: 'acesso_vascular_neo_evol' };

function safe(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ── Migração de schema: coluna do nome de quem preencheu (texto) ─────────────
export async function ensureComplementoSchema(pool) {
  await pool.query(`ALTER TABLE atb_evolutivos ADD COLUMN IF NOT EXISTS preenchido_por_nome TEXT`);
  await pool.query(`ALTER TABLE atb_evolutivos ADD COLUMN IF NOT EXISTS historico JSONB DEFAULT '[]'`);
}

export function registerComplementoRoutes(app, pool, adminRequired) {

  // ── Tela de complementação ──────────────────────────────────────────────
  app.get('/atb/admin/complementar/:id', adminRequired, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const { rows: [f] } = await pool.query(`
        SELECT f.id, f.paciente_nome, f.paciente_nome_raw, f.prontuario, f.atendimento,
               f.setor, f.leito, f.atb_solicitado, f.complemento_scih, f.parecer_evolutivo,
               i.sigla AS instituicao,
               e.labs, e.hemodinamica, e.ventilatorio, e.acesso_vascular_neo_evol,
               e.preenchido_por_nome, e.updated_at AS evol_updated
        FROM atb_fichas f
        LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
        LEFT JOIN atb_evolutivos   e ON e.ficha_id = f.id
        WHERE f.id = $1
      `, [id]);
      if (!f) return res.status(404).send(paginaErro('Ficha não encontrada'));
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(paginaComplemento(f));
    } catch (e) {
      console.error('[atb] complementar GET error:', e);
      res.status(500).send(paginaErro(e.message));
    }
  });

  // ── Salvar complementação ───────────────────────────────────────────────
  app.post('/atb/admin/complementar/:id', adminRequired, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const b = req.body || {};
      const nome = (b._preenchido_por_nome || '').trim();
      if (!nome) return res.status(400).json({ ok: false, error: 'Informe seu nome antes de salvar.' });

      // remonta as 4 séries a partir dos campos achatados grupo__exame__dia
      const series = {};
      for (const [gkey, g] of Object.entries(GRUPOS)) {
        const obj = {};
        for (const ex of g.exames) {
          const porDia = {};
          for (const dia of DIAS) {
            const v = (b[`${gkey}__${ex}__${dia}`] || '').trim();
            if (v) porDia[dia] = v;
          }
          if (Object.keys(porDia).length) obj[ex] = porDia;
        }
        series[gkey] = obj;
      }

      const complementoScih = (b.complemento_scih || '').trim() || null;

      // append no histórico de quem mexeu (rastreabilidade acumulada)
      await pool.query(`
        INSERT INTO atb_evolutivos
          (ficha_id, labs, hemodinamica, ventilatorio, acesso_vascular_neo_evol,
           preenchido_por_nome, historico, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,
                jsonb_build_array(jsonb_build_object('nome',$6::text,'em',now()::text)), now())
        ON CONFLICT (ficha_id) DO UPDATE SET
          labs = $2, hemodinamica = $3, ventilatorio = $4, acesso_vascular_neo_evol = $5,
          preenchido_por_nome = $6,
          historico = COALESCE(atb_evolutivos.historico,'[]'::jsonb)
                      || jsonb_build_object('nome',$6::text,'em',now()::text),
          updated_at = now()
      `, [id,
          JSON.stringify(series.labs || {}),
          JSON.stringify(series.hemodinamica || {}),
          JSON.stringify(series.ventilatorio || {}),
          JSON.stringify(series.acesso || {}),
          nome]);

      if (complementoScih !== null) {
        await pool.query(`UPDATE atb_fichas SET complemento_scih=$2, updated_at=now() WHERE id=$1`,
          [id, complementoScih]);
      }

      res.json({ ok: true });
    } catch (e) {
      console.error('[atb] complementar POST error:', e);
      res.status(500).json({ ok: false, error: e.message });
    }
  });
}

// ── Render: grade editável de uma série ──────────────────────────────────────
function gradeSerie(gkey, grupo, dados) {
  dados = dados || {};
  const cabDias = DIAS.map(d => `<th>${d}</th>`).join('');
  const linhas = grupo.exames.map(ex => {
    const porDia = dados[ex] || {};
    const cels = DIAS.map(d => {
      const v = porDia[d] != null ? safe(porDia[d]) : '';
      const tipo = ex === 'Data' ? 'text' : 'text';
      return `<td><input type="${tipo}" name="${gkey}__${ex}__${d}" value="${v}" autocomplete="off"></td>`;
    }).join('');
    return `<tr><td class="exame">${safe(ex)}</td>${cels}</tr>`;
  }).join('');
  return `
    <div class="grupo">
      <div class="grupo-tit">${safe(grupo.titulo)}</div>
      <div class="grade-wrap">
        <table class="grade">
          <thead><tr><th class="canto">Exame</th>${cabDias}</tr></thead>
          <tbody>${linhas}</tbody>
        </table>
      </div>
    </div>`;
}

function paginaComplemento(f) {
  const nome = safe(f.paciente_nome || f.paciente_nome_raw || '—');
  const atb = Array.isArray(f.atb_solicitado) ? f.atb_solicitado.join(', ')
    : (typeof f.atb_solicitado === 'string' ? safe(f.atb_solicitado) : '—');
  const ultimo = f.preenchido_por_nome
    ? `<div class="ultimo">Última edição por <strong>${safe(f.preenchido_por_nome)}</strong>${f.evol_updated ? ' · ' + new Date(f.evol_updated).toLocaleString('pt-BR') : ''}</div>`
    : '';

  const grades = Object.entries(GRUPOS)
    .map(([gkey, g]) => gradeSerie(gkey, g, f[COL_BANCO[gkey]]))
    .join('');

  return `<!DOCTYPE html>
<html lang="pt-BR"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Complementação · ${nome}</title>
<style>
  :root{
    --azul:#00469e; --azul-claro:#e6eef8; --azul-texto:#0c447c;
    --vermelho:#e12229; --tinta:#1a2733; --tinta-suave:#3a4654;
    --borda:#d8dee6; --campo-fundo:#fafbfc; --fundo:#f4f6f9;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
    background:var(--fundo);color:var(--tinta);font-size:14px;line-height:1.5;padding-bottom:90px}
  .cab{background:#fff;border-bottom:2px solid var(--azul);padding:14px 22px;display:flex;
    align-items:center;justify-content:space-between;gap:12px}
  .cab h1{font-size:15px;color:var(--azul)}
  .cab a{font-size:12px;color:var(--azul);text-decoration:none}
  .faixa{background:var(--azul);color:#fff;padding:11px 22px;font-size:13px;font-weight:600}
  .wrap{max-width:920px;margin:18px auto;padding:0 16px}
  .resumo{background:#fff;border:1px solid var(--borda);border-radius:10px;padding:14px 18px;margin-bottom:16px}
  .resumo .pac{font-size:16px;font-weight:700;color:var(--tinta)}
  .resumo .meta{font-size:12px;color:var(--tinta-suave);margin-top:3px}
  .resumo .atb{margin-top:8px;font-size:13px}
  .resumo .atb b{color:var(--azul-texto)}
  .ultimo{font-size:11px;color:var(--tinta-suave);margin-top:8px;padding-top:8px;border-top:1px dashed var(--borda)}
  .grupo{background:#fff;border:1px solid var(--borda);border-radius:10px;margin-bottom:14px;overflow:hidden}
  .grupo-tit{background:var(--azul-claro);color:var(--azul-texto);font-size:12px;font-weight:700;
    padding:9px 16px;text-transform:uppercase;letter-spacing:.04em}
  .grade-wrap{overflow-x:auto;padding:6px}
  table.grade{width:100%;border-collapse:collapse;min-width:560px}
  table.grade th{font-size:11px;color:var(--tinta-suave);font-weight:600;padding:6px 4px;text-align:center;
    border-bottom:1px solid var(--borda)}
  table.grade th.canto,table.grade td.exame{text-align:left;padding-left:12px;min-width:84px;
    font-weight:600;color:var(--azul-texto);font-size:12px}
  table.grade td{padding:3px 4px;border-bottom:1px solid #eef1f5}
  table.grade tr:last-child td{border-bottom:none}
  table.grade input{width:100%;min-width:58px;padding:6px 6px;border:1px solid var(--borda);
    border-radius:6px;font-size:13px;background:var(--campo-fundo);color:var(--tinta);text-align:center}
  table.grade input:focus{outline:none;border-color:var(--azul);background:#fff;
    box-shadow:0 0 0 3px var(--azul-claro)}
  .bloco{background:#fff;border:1px solid var(--borda);border-radius:10px;padding:16px 18px;margin-bottom:14px}
  .bloco label{display:block;font-size:12px;font-weight:700;color:var(--azul-texto);
    text-transform:uppercase;letter-spacing:.04em;margin-bottom:8px}
  .bloco textarea{width:100%;min-height:90px;padding:10px 12px;border:1px solid var(--borda);
    border-radius:8px;font-size:14px;font-family:inherit;background:var(--campo-fundo);resize:vertical}
  .bloco textarea:focus{outline:none;border-color:var(--azul);background:#fff;box-shadow:0 0 0 3px var(--azul-claro)}
  .rodape{position:fixed;bottom:0;left:0;right:0;background:#fff;border-top:1px solid var(--borda);
    padding:12px 22px;display:flex;align-items:center;gap:12px;justify-content:flex-end;z-index:30}
  .rodape .nome-campo{display:flex;align-items:center;gap:8px;margin-right:auto}
  .rodape .nome-campo label{font-size:12px;color:var(--tinta-suave);white-space:nowrap}
  .rodape .nome-campo input{padding:8px 11px;border:1px solid var(--borda);border-radius:8px;
    font-size:13px;min-width:200px}
  .rodape .nome-campo input:focus{outline:none;border-color:var(--azul);box-shadow:0 0 0 3px var(--azul-claro)}
  .rodape .nome-campo .req{color:var(--vermelho)}
  .salvar{background:var(--azul);color:#fff;border:none;border-radius:8px;padding:11px 26px;
    font-size:14px;font-weight:600;cursor:pointer}
  .salvar:disabled{opacity:.45;cursor:not-allowed}
  .toast{position:fixed;top:16px;left:50%;transform:translateX(-50%);padding:11px 20px;border-radius:8px;
    font-size:13px;font-weight:600;z-index:50;display:none}
  .toast.ok{background:#1a6b3a;color:#fff} .toast.erro{background:var(--vermelho);color:#fff}
</style></head>
<body>
  <div class="cab"><h1>Complementação de dados evolutivos</h1>
    <a href="/atb/admin/fichas/${f.id}">← Voltar à ficha</a></div>
  <div class="faixa">${safe(f.instituicao || 'HUSF')} · SCIH</div>

  <div id="toast" class="toast"></div>

  <form id="form" class="wrap">
    <div class="resumo">
      <div class="pac">${nome}</div>
      <div class="meta">${safe(f.instituicao || '')} · ${safe(f.setor || '—')}${f.leito ? ' · Leito ' + safe(f.leito) : ''}
        · Prontuário ${safe(f.prontuario || '—')} · Atend. ${safe(f.atendimento || '—')}</div>
      <div class="atb"><b>ATB solicitado:</b> ${atb}</div>
      ${ultimo}
    </div>

    ${grades}

    <div class="bloco">
      <label>Complemento SCIH</label>
      <textarea name="complemento_scih" placeholder="Observações complementares do SCIH...">${safe(f.complemento_scih || '')}</textarea>
    </div>
  </form>
   <div class="wrap">
    ${anexosManagerWidget(f.id)}
  </div>
  <div class="rodape">
    <div class="nome-campo">
      <label>Quem está preenchendo <span class="req">*</span></label>
      <input id="quem" type="text" placeholder="Seu nome" autocomplete="off">
    </div>
    <button id="btn" class="salvar" disabled>Salvar complementação</button>
  </div>

<script>
  var quem = document.getElementById('quem');
  var btn  = document.getElementById('btn');
  var form = document.getElementById('form');
  var toast= document.getElementById('toast');
  function mostra(msg, ok){ toast.textContent=msg; toast.className='toast '+(ok?'ok':'erro');
    toast.style.display='block'; setTimeout(function(){toast.style.display='none';}, 3500); }
  quem.addEventListener('input', function(){ btn.disabled = quem.value.trim().length < 2; });
  btn.addEventListener('click', async function(){
    btn.disabled = true; btn.textContent = 'Salvando...';
    var dados = { _preenchido_por_nome: quem.value.trim() };
    new FormData(form).forEach(function(v,k){ dados[k]=v; });
    try{
      var r = await fetch(location.pathname, {method:'POST',
        headers:{'Content-Type':'application/json'}, body:JSON.stringify(dados)});
      var j = await r.json();
      if(j.ok){ mostra('Complementação salva. Obrigado, '+quem.value.trim()+'.', true); }
      else { mostra('Erro: '+(j.error||'desconhecido'), false); }
    }catch(e){ mostra('Erro de conexão. Tente novamente.', false); }
    btn.disabled = false; btn.textContent = 'Salvar complementação';
  });
</script>
</body></html>`;
}

function paginaErro(msg) {
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Erro</title></head>
  <body style="font-family:system-ui;padding:40px;color:#e12229">
    <h2>Erro</h2><p>${safe(msg)}</p>
    <p><a href="/atb/admin/fichas" style="color:#00469e">← Voltar</a></p></body></html>`;
}
