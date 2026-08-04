// ════════════════════════════════════════════════════════════════════════════
//  DESFECHO DAS IrAS  —  /atb/admin/desfecho
//
//  Tela dedicada para registrar o desfecho das fichas com IrAS confirmada.
//  Existe por um motivo de acesso: o perfil `scih` enxerga a grade limitado aos
//  últimos 90 dias, e o fechamento de desfecho às vezes alcança meses
//  anteriores. Em vez de afrouxar a grade inteira, esta tela abre uma janela
//  estreita — 12 meses — mostrando SÓ o necessário para essa tarefa.
//
//  O QUE A TELA MOSTRA (e o que não mostra)
//  Paciente, prontuário, setor e a data da ficha. NÃO mostra a IrAS atribuída:
//  ela serve de FILTRO (só entram fichas com IrAS confirmada), não de
//  informação — quem preenche o desfecho não precisa saber a classificação, e
//  não vê-la evita que a classificação influencie o registro.
//
//  REGRA DAS 72h
//  Mesma da grade: desfecho só a partir de 72h da solicitação. Na prática toda
//  ficha desta tela já passou disso, mas o critério fica explícito na query
//  para as duas telas nunca divergirem.
//
//  CÓPIAS DE IrAS MÚLTIPLA
//  A worklist lista só as fichas ORIGINAIS. Quando o desfecho é gravado, ele
//  se propaga para as cópias da mesma internação — o desfecho é da internação,
//  não da infecção, então preencher duas vezes seria trabalho repetido e fonte
//  de divergência.
//
//  Integração em atb-routes.js:
//    import { registerDesfechoRoutes } from './atb-desfecho-routes.js';
//    // em registerAtbRoutes:  registerDesfechoRoutes(app, pool, adminRequired);
// ════════════════════════════════════════════════════════════════════════════

// Janela desta tela, em meses. Deliberadamente maior que os 90 dias da grade:
// a exposição aqui é menor (poucos campos, edição só do desfecho).
const JANELA_MESES = 12;

// Mesmas opções da grade — fonte única do vocabulário evita divergência.
export const DESFECHO_OPCOES = ['Sobrev_int', 'Sobrev_alta', 'Obito_R', 'Obito_NR', 'Alta'];

// "IrAS confirmada": idêntico ao painel CVE e aos numeradores.
const IRAS_OK = `a.iras IS NOT NULL AND a.iras <> '' AND a.iras NOT IN ('Descartado','Repetida','Sem dados','Audit_post')`;

// Data canônica da ficha (a mesma âncora do resto do sistema).
const DATA_FICHA = `COALESCE(f.data_referencia, f.jotform_created_at, f.created_at)`;

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Escopo por instituição, no mesmo molde da Adesão.
function escopoInst(inst, params) {
  if (!inst) return '';
  params.push(inst);
  const n = params.length;
  return ` AND (f.instituicao_id = (SELECT id FROM atb_instituicoes WHERE sigla=$${n})`
       + ` OR (f.instituicao_id IS NULL AND $${n}='HUSF'))`;
}

// Meses disponíveis no seletor: o atual e os anteriores dentro da janela.
function mesesDisponiveis() {
  const agora = new Date(new Intl.DateTimeFormat('en-CA', {
    timeZone: 'America/Sao_Paulo', year: 'numeric', month: '2-digit', day: '2-digit',
  }).format(new Date()) + 'T12:00:00Z');
  const out = [];
  for (let i = 0; i < JANELA_MESES; i++) {
    const d = new Date(Date.UTC(agora.getUTCFullYear(), agora.getUTCMonth() - i, 1));
    out.push({ ano: d.getUTCFullYear(), mes: d.getUTCMonth() + 1 });
  }
  return out;
}

const NOME_MES = ['', 'janeiro', 'fevereiro', 'março', 'abril', 'maio', 'junho',
  'julho', 'agosto', 'setembro', 'outubro', 'novembro', 'dezembro'];

// Worklist do mês: IrAS confirmada, desfecho em branco, > 72h, ficha original.
async function buscarPendentes(pool, ano, mes, inst) {
  const params = [ano, mes];
  const escopo = escopoInst(inst, params);
  const { rows } = await pool.query(`
    SELECT f.id, f.paciente_nome, f.prontuario, f.setor,
           to_char(${DATA_FICHA} AT TIME ZONE 'America/Sao_Paulo', 'DD/MM/YYYY') AS data_ficha,
           a.desfecho_iras, a.desfecho_data
      FROM atb_fichas f
      JOIN atb_avaliacoes a ON a.ficha_id = f.id
     WHERE f.deletado_em IS NULL
       AND ${IRAS_OK}
       -- Cópia de IrAS múltipla não entra: o desfecho é da internação e se
       -- propaga a partir da ficha original quando gravado.
       AND f.ficha_origem_id IS NULL
       -- Mesma régua de 72h da grade.
       AND ${DATA_FICHA} < now() - interval '72 hours'
       AND EXTRACT(YEAR  FROM ${DATA_FICHA} AT TIME ZONE 'America/Sao_Paulo') = $1
       AND EXTRACT(MONTH FROM ${DATA_FICHA} AT TIME ZONE 'America/Sao_Paulo') = $2
       ${escopo}
     ORDER BY (a.desfecho_iras IS NOT NULL), ${DATA_FICHA} ASC`, params);
  return rows;
}

function pagina({ rows, ano, mes, inst, pendentes, total }) {
  const opcoes = mesesDisponiveis().map((m) => {
    const sel = (m.ano === ano && m.mes === mes) ? ' selected' : '';
    return `<option value="${m.ano}-${m.mes}"${sel}>${NOME_MES[m.mes]} de ${m.ano}</option>`;
  }).join('');

  const linhas = rows.length ? rows.map((r) => {
    const jaTem = !!r.desfecho_iras;
    const sel = DESFECHO_OPCOES.map((v) =>
      `<option value="${v}"${r.desfecho_iras === v ? ' selected' : ''}>${v}</option>`).join('');
    const dataVal = r.desfecho_data ? String(r.desfecho_data).slice(0, 10) : '';
    return `<tr class="${jaTem ? 'feito' : ''}">
      <td><strong>${esc(r.paciente_nome || '—')}</strong>
          <div class="nota">Pront. ${esc(r.prontuario || '—')} · ${esc(r.setor || '—')} · ficha ${esc(r.data_ficha)}</div></td>
      <td>
        <form method="POST" action="/atb/admin/desfecho/${r.id}" class="linha">
          <input type="hidden" name="volta" value="${ano}-${mes}">
          <select name="desfecho_iras">
            <option value="">— selecione —</option>${sel}
          </select>
          <input type="date" name="desfecho_data" value="${esc(dataVal)}">
          <button type="submit">${jaTem ? 'atualizar' : 'salvar'}</button>
        </form>
      </td>
    </tr>`;
  }).join('') : `<tr><td colspan="2" class="nota">Nenhuma ficha com IrAS confirmada neste mês.</td></tr>`;

  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Desfecho das IrAS</title>
<style>
  :root{--bd:#dde3ee;--mut:#5b6472}
  *{box-sizing:border-box}
  body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f6fb;color:#1b2330;padding:24px 16px}
  .wrap{max-width:900px;margin:0 auto}
  .card{background:#fff;border:1px solid var(--bd);border-radius:14px;padding:20px 22px;margin-bottom:14px}
  h1{margin:0 0 4px;font-size:20px}
  .nota{color:var(--mut);font-size:13px}
  table{border-collapse:collapse;width:100%;margin-top:10px}
  td{border-top:1px solid var(--bd);padding:10px 8px;vertical-align:top}
  tr.feito td{background:#f6fbf7}
  .linha{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
  select,input[type=date]{padding:8px 10px;border:1px solid var(--bd);border-radius:8px;font:inherit}
  button{padding:8px 14px;border:0;border-radius:8px;background:#0c447c;color:#fff;font:inherit;cursor:pointer}
  .topo{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:10px}
</style></head><body>
  <div class="wrap">
    <div class="card">
      <h1>Desfecho das IrAS</h1>
      <p class="nota">Fichas com infecção confirmada aguardando o registro do desfecho.
      A classificação da IrAS não é exibida aqui — ela serve apenas para selecionar as fichas.</p>
      <form method="GET" class="topo">
        <label class="nota">Mês da ficha</label>
        <select name="m" onchange="this.form.submit()">${opcoes}</select>
        <span class="nota">${pendentes} pendente(s) de ${total} no mês · ${esc(inst || 'HUSF')}</span>
      </form>
    </div>
    <div class="card">
      <table><tbody>${linhas}</tbody></table>
    </div>
    <p class="nota"><a href="/atb/admin/grid">← voltar à grade</a></p>
  </div>
</body></html>`;
}

export function registerDesfechoRoutes(app, pool, adminRequired) {
  app.get('/atb/admin/desfecho', adminRequired, async (req, res) => {
    try {
      const disp = mesesDisponiveis();
      let ano = disp[0].ano, mes = disp[0].mes;
      const m = String(req.query.m || '');
      if (/^\d{4}-\d{1,2}$/.test(m)) {
        const [a, s] = m.split('-').map(Number);
        // Allowlist: só meses dentro da janela — a URL não abre o histórico todo.
        if (disp.some((x) => x.ano === a && x.mes === s)) { ano = a; mes = s; }
      }
      const rows = await buscarPendentes(pool, ano, mes, req.atbTenant);
      const pendentes = rows.filter((r) => !r.desfecho_iras).length;
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(pagina({ rows, ano, mes, inst: req.atbTenant, pendentes, total: rows.length }));
    } catch (e) {
      console.error('[atb] desfecho:', e.message);
      res.status(500).send('Erro ao montar a lista: ' + esc(e.message));
    }
  });

  app.post('/atb/admin/desfecho/:id', adminRequired, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const volta = String(req.body?.volta || '');
    const desfecho = String(req.body?.desfecho_iras || '').trim();
    const data = String(req.body?.desfecho_data || '').trim();
    try {
      // Allowlist do valor: nada fora do vocabulário entra no banco.
      const valor = DESFECHO_OPCOES.includes(desfecho) ? desfecho : null;
      if (Number.isFinite(id)) {
        await pool.query(
          `UPDATE atb_avaliacoes
              SET desfecho_iras = $2,
                  desfecho_data = NULLIF($3,'')::date,
                  updated_at = now()
            WHERE ficha_id = $1`, [id, valor, data]);
        // Propaga para as cópias de IrAS múltipla: o desfecho é da internação.
        await pool.query(
          `UPDATE atb_avaliacoes
              SET desfecho_iras = $2,
                  desfecho_data = NULLIF($3,'')::date,
                  updated_at = now()
            WHERE ficha_id IN (SELECT id FROM atb_fichas WHERE ficha_origem_id = $1)`,
          [id, valor, data]);
      }
    } catch (e) {
      console.error('[atb] desfecho gravar:', e.message);
    }
    res.redirect('/atb/admin/desfecho' + (volta ? '?m=' + encodeURIComponent(volta) : ''));
  });
}
