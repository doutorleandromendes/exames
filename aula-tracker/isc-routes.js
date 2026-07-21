// isc-routes.js
// ──────────────────────────────────────────────────────────────────────────
// Módulo ISC — Vigilância pós-alta de Infecção de Sítio Cirúrgico.
//
// TELAS
//   /isc/admin/grid        → o grid (1 linha = 1 paciente-cirurgia)
//   /isc/admin/agenda      → worklist da colaboradora: quem contatar HOJE,
//                            com a mensagem já renderizada e link wa.me
//   /isc/admin/ficha/:id   → ficha longitudinal (timeline + registrar contato
//                            + classificação SCIH)
//   /isc/admin/nova        → cadastro do paciente-cirurgia
//   /isc/admin/templates   → editor das mensagens padronizadas
//   /isc/admin/export.csv  → extração
//
// CRON
//   POST /isc/cron/agendar → 202 imediato, agenda envios das janelas vencendo.
//
// TENANCY: o tenantLock do atb-routes.js é app.use(), então roda em TODA
// requisição e já popula req.atbTenant aqui — é o que faz o scihRequired barrar
// usuário vinculado a outra unidade. Mas o lock só FORÇA o filtro (req.query.inst)
// em rotas /atb. Por isso a separação do ISC é explícita e não depende dele:
// resolveInst() decide o instituicao_id e TODA query de ficha passa por ele;
// ficha de outro tenant → 404 opaco (anti-enumeração).
// ──────────────────────────────────────────────────────────────────────────

import { tenantFromReq, getTenantLogo, sanitizeSigla } from './atb-tenant.js';
import {
  CHECKLIST, RECOMENDACOES, MOTIVOS_INSUCESSO, CANAIS, ISC_TIPOS,
  ISC_CLASSIFICACOES, ISC_CRITERIOS, POTENCIAL_CONTAMINACAO, STATUS_VIGILANCIA,
  PLACEHOLDERS, recomputarEstado, normalizaTelefone, formataTelefone,
  linkWhatsApp, renderTemplate, toISODate, dataBR, addDays, diffDias, hojeISO, JANELA_IDENTIDADE,
  boolDe, enumDe, extraiRespostas, janelasDe, contatoTemAlerta,
} from './isc-core.js';

function safe(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const CORES = { HUSF: '#0c447c', SCMI: '#F0D000' };
const STATUS_LABEL = Object.fromEntries(STATUS_VIGILANCIA);
const CLASSIF_LABEL = Object.fromEntries(ISC_CLASSIFICACOES);
const TIPO_LABEL = Object.fromEntries(ISC_TIPOS);

const BADGE_JANELA = {
  concluida:   ['#e6f4ea', '#1e7e34', '✓'],
  pendente:    ['#f1f3f4', '#80868b', '·'],
  aberta:      ['#fff4e5', '#b06000', '!'],
  atrasada:    ['#fdecea', '#c0392b', '!!'],
  sem_contato: ['#f3e8fd', '#7b1fa2', '✕'],
};

export function registerIscRoutes(app, pool, scihRequired, renderShell) {

  // ── Ato médico ──────────────────────────────────────────────────────────
  // Classificar ISC é decisão médica e alimenta o numerador do CVE: no SCIH do
  // HUSF só o médico classifica. `scih` sozinho dá acesso à operação (agenda,
  // contato, importação) — não a esta. Mesmo padrão do ensureSuper do
  // atb-scih-acesso-routes.js, inclusive o break-glass pelo cookie adm.
  function ehMedico(req) {
    return !!((req.user && req.user.super_admin) || req.cookies?.adm === '1');
  }
  function ensureMedico(req, res, next) {
    if (ehMedico(req)) return next();
    return res.status(403).send(renderShell('Sem permissão', `<div class="card">
      <h1>Restrito ao médico do SCIH</h1>
      <p class="mut">A classificação de ISC é ato médico e alimenta os numeradores do CVE.
      Sua conta registra contatos e opera a vigilância, mas não classifica.</p>
      <a href="/isc/admin/grid">← Voltar ao grid</a></div>`));
  }
  const medicoRequired = [scihRequired, ensureMedico];

  // ── Tenancy ─────────────────────────────────────────────────────────────
  const _instCache = new Map();
  async function instIdDeSigla(sigla) {
    const key = sanitizeSigla(sigla);
    if (!key) return null;
    if (_instCache.has(key)) return _instCache.get(key);
    const { rows } = await pool.query('SELECT id FROM atb_instituicoes WHERE sigla = $1', [key]);
    const id = rows[0]?.id ?? null;
    if (id) _instCache.set(key, id);
    return id;
  }

  // Devolve { sigla, instId } do deploy. sigla null = modo legado (sem lock):
  // aceita ?inst= como o ATB faz, e sem ?inst= enxerga tudo.
  //
  // Lê o body também: form POST manda `inst` como campo escondido, não na query.
  // Só a query fazia o tenant virar null em todo POST de formulário — e, sem
  // tenant, carregarFicha() não tinha o que comparar e a guarda cross-tenant
  // deixava passar. Em produção o subdomínio salva (tenantFromReq), mas depender
  // disso é ter uma guarda que só funciona por acidente.
  async function resolveInst(req) {
    const travado = tenantFromReq(req);
    const sigla = travado || sanitizeSigla(req.query?.inst || req.body?.inst || '') || null;
    const instId = sigla ? await instIdDeSigla(sigla) : null;
    return { sigla, instId, travado: !!travado };
  }

  async function nomeInst(sigla) {
    if (!sigla) return '';
    const { rows } = await pool.query('SELECT nome FROM atb_instituicoes WHERE sigla = $1', [sigla]);
    return rows[0]?.nome || sigla;
  }

  async function configDe(instId) {
    if (instId == null) return {};
    const { rows } = await pool.query('SELECT * FROM isc_config WHERE instituicao_id = $1', [instId]);
    return rows[0] || {};
  }

  async function equipesDe(instId) {
    const { rows } = await pool.query(
      `SELECT * FROM isc_equipes
        WHERE ativo = true AND ($1::int IS NULL OR instituicao_id = $1)
        ORDER BY ordem, nome`, [instId]);
    return rows;
  }

  // Carrega ficha + contatos + equipe, já com guarda de tenant.
  // Devolve null se não existe OU se é de outro tenant (404 opaco: não revela
  // a existência da ficha do outro hospital).
  async function carregarFicha(id, instId) {
    const { rows } = await pool.query('SELECT * FROM isc_fichas WHERE id = $1', [id]);
    const f = rows[0];
    if (!f) return null;
    if (instId != null && f.instituicao_id !== instId) return null;
    const { rows: contatos } = await pool.query(
      'SELECT * FROM isc_contatos WHERE ficha_id = $1 ORDER BY data_contato ASC, id ASC', [id]);
    let equipe = null;
    if (f.equipe_id) {
      const { rows: eq } = await pool.query('SELECT * FROM isc_equipes WHERE id = $1', [f.equipe_id]);
      equipe = eq[0] || null;
    }
    return { ficha: f, contatos, equipe };
  }

  // Recomputa os derivados e grava. Chamada após QUALQUER escrita que possa
  // mudar o estado (contato novo, edição de janelas, mudança de status).
  async function sincronizarEstado(id) {
    const dados = await carregarFicha(id, null);
    if (!dados) return null;
    const est = recomputarEstado(dados.ficha, dados.contatos, dados.equipe);
    await pool.query(
      `UPDATE isc_fichas SET
         janelas = $2, janelas_estado = $3, proxima_janela = $4, proximo_contato_em = $5,
         contatos_ok = $6, tentativas_falhas = $7, tem_alerta = $8, ultimo_contato_em = $9,
         status_vigilancia = $10, updated_at = now()
       WHERE id = $1`,
      [id, JSON.stringify(est.janelas), JSON.stringify(est.janelas_estado),
       est.proxima_janela, est.proximo_contato_em, est.contatos_ok,
       est.tentativas_falhas, est.tem_alerta, est.ultimo_contato_em, est.status_vigilancia]);
    return est;
  }

  // ── Chrome comum ────────────────────────────────────────────────────────
  function chrome(sigla, titulo, sub, acoes) {
    const cor = CORES[String(sigla).toUpperCase()] || '#0c447c';
    const logo = sigla ? getTenantLogo(sigla) : '';
    return `
      ${sigla ? `<div style="height:5px;background:${cor};border-radius:3px;margin-bottom:14px"></div>
      <div aria-hidden="true" style="position:fixed;right:26px;bottom:22px;pointer-events:none;z-index:0;opacity:.07"><img src="${logo}" alt="" style="height:120px;width:auto"></div>` : ''}
      <div style="display:flex;justify-content:space-between;align-items:baseline;flex-wrap:wrap;gap:10px;margin-bottom:14px">
        <div style="display:flex;align-items:baseline;gap:14px">
          <h1 style="margin:0;color:#202124">${safe(titulo)}${sigla ? ` <span style="color:#00469e;font-weight:600">— ${safe(sigla)}</span>` : ''}</h1>
          <span style="color:#80868b;font-size:13px">${safe(sub)}</span>
        </div>
        ${sigla && logo ? `<img src="${logo}" alt="${safe(sigla)}" style="height:40px;width:auto;max-width:230px;object-fit:contain">` : ''}
        <div style="display:flex;gap:14px">${acoes}</div>
      </div>`;
  }

  const nav = (req) => `<a href="/isc/admin/grid">Grid</a><a href="/isc/admin/agenda">Agenda</a>`
    + `<a href="/isc/admin/nova">+ Nova ficha</a><a href="/isc/admin/importar">Importar mapa</a>`
    + (ehMedico(req) ? `<a href="/isc/admin/triagem">Triagem</a>` : '')
    + `<a href="/isc/admin/templates">Mensagens</a>`;

  const CSS = `
    <style>
      .isc{position:relative;left:50%;right:50%;margin-left:-49vw;margin-right:-49vw;width:98vw;background:#f5f6f8;min-height:100vh;margin-top:-40px;padding:28px 24px 60px}
      .isc h1{font-weight:600}
      .isc a{color:#3b6fd4;text-decoration:none}
      .isc .metric{background:#fff;border:1px solid #e8eaed;border-left:3px solid;border-radius:8px;padding:10px 14px}
      .isc .metric .mv{font-size:20px;font-weight:600}
      .isc .metric .ml{font-size:10px;color:#80868b;text-transform:uppercase;letter-spacing:.05em;margin-top:1px}
      .isc .fil{padding:7px 11px;border-radius:7px;border:1px solid #dadce0;background:#fff;color:#202124;font-size:13px}
      .isc .btn{padding:7px 16px;background:#2bb673;color:#fff;border:0;border-radius:7px;font-size:13px;cursor:pointer;font-weight:600}
      .isc .btn-sec{background:#fff;color:#3b6fd4;border:1px solid #dadce0}
      .isc .grid-wrap{overflow-x:auto;border:1px solid #e8eaed;border-radius:10px;background:#fff}
      table.g{border-collapse:separate;border-spacing:0;width:max-content;min-width:100%;font-size:13px}
      table.g th{position:sticky;top:0;z-index:5;background:#fff;color:#5f6368;text-align:left;font-size:11px;font-weight:600;padding:11px 12px;border-bottom:1px solid #e0e2e6;border-right:1px solid #f0f1f3;white-space:nowrap}
      table.g th.grp{background:#f3faf6;color:#1a8a5a}
      table.g td{padding:8px 12px;border-bottom:1px solid #f0f1f3;border-right:1px solid #f6f7f8;white-space:nowrap;vertical-align:middle;color:#202124}
      table.g tbody tr:hover td{background:#fafbfc}
      .isc .sticky-col{position:sticky;left:0;z-index:4;background:#fff;box-shadow:1px 0 0 #e8eaed;min-width:180px;max-width:180px}
      table.g th.sticky-col{z-index:6}
      .isc .th-sort{color:inherit;text-decoration:none;cursor:pointer}
      .isc .th-sort:hover,.isc .th-sort.on{color:#2bb673}
      .isc .th-sort .arr{font-size:9px}
      .isc .pac{font-weight:600;color:#202124!important;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
      .isc .sub{font-size:11px;color:#9aa0a6}
      .isc .jb{display:inline-flex;align-items:center;justify-content:center;min-width:34px;height:22px;border-radius:6px;font-size:11px;font-weight:600;margin-right:4px}
      .isc .card2{background:#fff;border:1px solid #e8eaed;border-radius:10px;padding:18px;margin-bottom:14px}
      .isc .card2 h2{margin:0 0 12px;font-size:15px;color:#202124}
      .isc .ff{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}
      .isc label.l{display:block;font-size:11px;color:#5f6368;text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px;font-weight:600}
      .isc input,.isc select,.isc textarea{width:100%;padding:8px 10px;border:1px solid #dadce0;border-radius:7px;font-size:13px;background:#fff;color:#202124;font-family:inherit}
      .isc .chk{display:flex;align-items:center;gap:6px;font-size:13px;font-weight:400;text-transform:none;letter-spacing:0;color:#202124}
      .isc .chk input{width:auto}
      .isc .tl{border-left:2px solid #e8eaed;padding-left:16px;margin-left:6px}
      .isc .tl-item{position:relative;padding-bottom:16px}
      .isc .tl-item:before{content:'';position:absolute;left:-23px;top:4px;width:10px;height:10px;border-radius:50%;background:#dadce0;border:2px solid #fff}
      .isc .tl-item.ok:before{background:#2bb673}
      .isc .tl-item.al:before{background:#e85d5d}
      .isc .tl-item.fail:before{background:#b8bcc2}
      .isc .pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}
      .isc .msg{white-space:pre-wrap;background:#f8f9fa;border:1px solid #e8eaed;border-radius:8px;padding:12px;font-size:13px;line-height:1.5}
    </style>`;

  function erro(res, e, titulo = 'ISC · Erro') {
    console.error('[isc]', e);
    return res.status(500).send(renderShell(titulo, `<div class="card"><p class="mut">${safe(e.message)}</p></div>`));
  }

  // ═══════════════════════════════════════════════════════════════════════
  // GRID
  // ═══════════════════════════════════════════════════════════════════════
  app.get('/isc/admin', scihRequired, (req, res) => res.redirect('/isc/admin/grid'));

  app.get('/isc/admin/grid', scihRequired, async (req, res) => {
    try {
      const { sigla, instId, travado } = await resolveInst(req);
      const q = req.query || {};
      const w = [], p = [];
      const add = (sql, val) => { p.push(val); w.push(sql.replace('$?', '$' + p.length)); };

      if (instId != null) add('f.instituicao_id = $?', instId);
      w.push(`f.status_vigilancia <> 'excluida'`);
      if (q.equipe) add('f.equipe_id = $?', Number(q.equipe));
      if (q.classif) add('f.isc_classificacao = $?', String(q.classif));
      if (q.status) add('f.status_vigilancia = $?', String(q.status));
      if (q.tipo) add('f.isc_tipo = $?', String(q.tipo));
      // Range em vez de to_char(): usa o índice btree de data_cirurgia.
      if (/^\d{4}-\d{2}$/.test(String(q.mes || ''))) {
        p.push(`${q.mes}-01`);
        w.push(`f.data_cirurgia >= $${p.length}::date`);
        p.push(`${q.mes}-01`);
        w.push(`f.data_cirurgia < ($${p.length}::date + INTERVAL '1 month')`);
      }
      if (q.de) add('f.data_cirurgia >= $?', String(q.de));
      if (q.ate) add('f.data_cirurgia <= $?', String(q.ate));
      if (q.lote) add('f.import_lote_id = $?', Number(q.lote));
      if (q.alerta === '1') w.push('f.tem_alerta = true');
      if (q.implante === '1') w.push('f.implante = true');
      if (q.pendente === '1') w.push(`f.status_vigilancia = 'em_vigilancia' AND f.proximo_contato_em <= CURRENT_DATE`);
      if (q.busca) {
        // Um único placeholder reusado nas 5 colunas (add() só numera o primeiro).
        p.push(`%${String(q.busca).trim()}%`);
        const n = '$' + p.length;
        w.push(`(f.paciente_nome ILIKE ${n} OR f.paciente_iniciais ILIKE ${n} OR f.prontuario ILIKE ${n} OR f.atendimento ILIKE ${n} OR f.procedimento ILIKE ${n})`);
      }
      const where = w.length ? 'WHERE ' + w.join(' AND ') : '';

      // ── Ordenação (server-side; whitelist de colunas) ──
      // Mesmo contrato do grid do ATB: ?sort=<chave>&dir=asc|desc, ciclo de 3
      // cliques (asc → desc → sem ordenação) e desempate pela data da cirurgia.
      // A whitelist é o que impede injeção: `sort` nunca entra cru no SQL.
      const sort = String(q.sort || '');
      const dir = String(q.dir || 'asc').toLowerCase() === 'desc' ? 'desc' : 'asc';
      const SORT_MAP = {
        paciente: 'f.paciente_nome', pront: 'f.prontuario', equipe: 'e.nome',
        proc: 'f.procedimento', cirurgia: 'f.data_cirurgia',
        janelas: 'f.contatos_ok', prox: 'f.proximo_contato_em',
        sinal: 'f.tem_alerta', classif: 'f.isc_classificacao',
        tipo: 'f.isc_tipo', dtdx: 'f.isc_data_diagnostico', patogeno: 'f.isc_patogeno',
      };
      const orderSql = SORT_MAP[sort]
        ? `${SORT_MAP[sort]} ${dir.toUpperCase()} NULLS LAST, f.data_cirurgia DESC, f.id DESC`
        : `f.data_cirurgia DESC, f.id DESC`;   // padrão: cirurgia mais recente primeiro

      const sortLink = (label, key) => {
        const ativo = sort === key;
        const u = new URLSearchParams({ ...q, page: '1' });
        let arr = '';
        if (!ativo) { u.set('sort', key); u.set('dir', 'asc'); }
        else if (dir === 'asc') { u.set('sort', key); u.set('dir', 'desc'); arr = '▲'; }
        else { u.delete('sort'); u.delete('dir'); arr = '▼'; }   // 3º clique: volta ao padrão
        const tt = !ativo ? 'Ordenar' : (dir === 'asc' ? 'Inverter (desc)' : 'Remover ordenação');
        return `<a class="th-sort${ativo ? ' on' : ''}" href="/isc/admin/grid?${u}" title="${tt}">${safe(label)}${arr ? `<span class="arr"> ${arr}</span>` : ''}</a>`;
      };

      const page = Math.max(1, parseInt(q.page || '1', 10) || 1);
      const LIM = 100;

      const { rows: totRows } = await pool.query(`SELECT count(*)::int n FROM isc_fichas f ${where}`, p);
      const total = totRows[0]?.n || 0;
      const totalPages = Math.max(1, Math.ceil(total / LIM));

      const { rows } = await pool.query(
        `SELECT f.*, e.nome AS equipe_nome, e.sigla AS equipe_sigla
           FROM isc_fichas f
           LEFT JOIN isc_equipes e ON e.id = f.equipe_id
          ${where}
          ORDER BY ${orderSql}
          LIMIT ${LIM} OFFSET ${(page - 1) * LIM}`, p);

      // Métricas do recorte
      const { rows: mRows } = await pool.query(
        `SELECT
           count(*) FILTER (WHERE f.isc_classificacao = 'confirmada')::int confirmadas,
           count(*) FILTER (WHERE f.isc_classificacao = 'investigando')::int investigando,
           count(*) FILTER (WHERE f.tem_alerta AND f.isc_classificacao = 'nao_avaliada')::int triagem,
           count(*) FILTER (WHERE f.status_vigilancia = 'em_vigilancia' AND f.proximo_contato_em <= CURRENT_DATE)::int vencidos,
           count(*) FILTER (WHERE f.status_vigilancia = 'perda_seguimento')::int perdas,
           count(*)::int total
         FROM isc_fichas f ${where}`, p);
      const m = mRows[0] || {};
      const taxa = m.total ? ((m.confirmadas / m.total) * 100).toFixed(1) : '0.0';

      const equipes = await equipesDe(instId);
      const hoje = hojeISO();

      const linhas = rows.map((f, i) => {
        const est = f.janelas_estado || {};
        const janelas = Array.isArray(f.janelas) ? f.janelas : [];
        const badges = janelas.map(d => {
          const e = est[String(d)] || {};
          const [bg, fg, ic] = BADGE_JANELA[e.status] || BADGE_JANELA.pendente;
          const tt = `${d}d · ${e.status || 'pendente'}${e.data_prevista ? ' · previsto ' + dataBR(e.data_prevista) : ''}${e.data_contato ? ' · contato ' + dataBR(e.data_contato) : ''}`;
          return `<span class="jb" style="background:${bg};color:${fg}" title="${safe(tt)}">${d}d ${ic}</span>`;
        }).join('');

        const cl = f.isc_classificacao;
        const clCor = cl === 'confirmada' ? ['#fdecea', '#c0392b']
                    : cl === 'investigando' ? ['#e8f0fe', '#1a73e8']
                    : cl === 'descartada' ? ['#e6f4ea', '#1e7e34']
                    : ['#f1f3f4', '#80868b'];
        const clTxt = CLASSIF_LABEL[cl] || '—';

        const atraso = f.proximo_contato_em && f.status_vigilancia === 'em_vigilancia'
          ? diffDias(toISODate(f.proximo_contato_em), hoje) : null;
        const prox = f.status_vigilancia !== 'em_vigilancia'
          ? `<span class="sub">${safe(STATUS_LABEL[f.status_vigilancia] || '')}</span>`
          : f.proximo_contato_em
            ? `<span style="${atraso > 0 ? 'color:#c0392b;font-weight:600' : ''}">${dataBR(f.proximo_contato_em)}${atraso > 0 ? ` (+${atraso}d)` : ''}</span><br><span class="sub">janela ${f.proxima_janela}d</span>`
            : '—';

        const dpo = diffDias(toISODate(f.data_cirurgia), hoje);

        return `<tr>
          <td style="color:#bdc1c6;font-size:12px;text-align:center;width:34px">${(page - 1) * LIM + i + 1}</td>
          <td class="sticky-col">
            <a class="pac" href="/isc/admin/ficha/${f.id}">${safe(f.paciente_nome || f.paciente_iniciais || '(sem nome)')}</a>
            <span class="sub">${safe(f.prontuario || '')}${f.atendimento ? ' · at. ' + safe(f.atendimento) : ''}</span>
          </td>
          <td>${safe(f.equipe_sigla || f.especialidade || '—')}</td>
          <td style="white-space:normal;max-width:220px">${safe(f.procedimento || '—')}${f.implante ? ' <span class="pill" style="background:#eef2ff;color:#4c51bf">implante</span>' : ''}</td>
          <td>${dataBR(f.data_cirurgia) || '—'}<br><span class="sub">${dpo != null ? dpo + ' DPO' : ''}</span></td>
          <td>${badges || '—'}</td>
          <td>${prox}</td>
          <td style="text-align:center">${f.tem_alerta ? '<span title="Alerta na triagem do contato">🔺</span>' : ''}${f.suspeita_isc ? ' <span title="Suspeita marcada pela colaboradora">👁</span>' : ''}</td>
          <td class="grp"><span class="pill" style="background:${clCor[0]};color:${clCor[1]}">${safe(clTxt)}</span></td>
          <td class="grp">${safe(TIPO_LABEL[f.isc_tipo] || '—')}</td>
          <td class="grp">${dataBR(f.isc_data_diagnostico) || '—'}</td>
          <td class="grp">${safe(f.isc_patogeno || '—')}</td>
          <td style="text-align:center">${f.telefone ? `<a href="${linkWhatsApp(f.telefone, '')}" target="_blank" rel="noopener" title="${safe(formataTelefone(f.telefone))}">📱</a>` : ''}</td>
        </tr>`;
      }).join('');

      const mkUrl = pp => `/isc/admin/grid?${new URLSearchParams({ ...q, page: pp })}`;
      const pager = totalPages > 1
        ? `<div style="display:flex;align-items:center;gap:10px;font-size:13px">
             ${page > 1 ? `<a href="${mkUrl(page - 1)}">←</a>` : '<span style="color:#ccc">←</span>'}
             <span style="color:#80868b">Pág. ${page}/${totalPages} · ${total} fichas</span>
             ${page < totalPages ? `<a href="${mkUrl(page + 1)}">→</a>` : '<span style="color:#ccc">→</span>'}
           </div>`
        : `<span style="color:#80868b;font-size:13px">${total} fichas</span>`;

      const opt = (lista, sel, vazio) =>
        `<option value="">${vazio}</option>` + lista.map(([v, l]) =>
          `<option value="${safe(v)}" ${String(sel) === String(v) ? 'selected' : ''}>${safe(l)}</option>`).join('');

      const html = `<div class="isc">
        ${chrome(sigla, 'Vigilância ISC', 'Busca ativa pós-alta · classificação · indicadores', nav(req) + `<a href="/isc/admin/export.csv?${new URLSearchParams(q)}">CSV</a>`)}
        <div style="display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-bottom:14px">
          <div class="metric" style="border-left-color:#e85d5d"><div class="mv" style="color:#c0392b">${m.confirmadas || 0}</div><div class="ml">ISC confirmadas</div></div>
          <div class="metric" style="border-left-color:#5a9bf0"><div class="mv" style="color:#2c6fb5">${m.investigando || 0}</div><div class="ml">Em investigação</div></div>
          <div class="metric" style="border-left-color:#f0a500"><div class="mv" style="color:#b06000">${m.triagem || 0}</div><div class="ml">Alerta a classificar</div></div>
          <div class="metric" style="border-left-color:#d98a3d"><div class="mv" style="color:#a35e14">${m.vencidos || 0}</div><div class="ml">Contatos vencidos</div></div>
          <div class="metric" style="border-left-color:#a9b0c7"><div class="mv" style="color:#5f6368">${m.perdas || 0}</div><div class="ml">Perdas de seguimento</div></div>
          <div class="metric" style="border-left-color:#74c47d"><div class="mv" style="color:#3a8a4a">${taxa}%</div><div class="ml">Taxa ISC no recorte</div></div>
        </div>
        <form method="get" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px">
          ${travado ? '' : `<input type="hidden" name="inst" value="${safe(q.inst || '')}">`}
          ${sort ? `<input type="hidden" name="sort" value="${safe(sort)}"><input type="hidden" name="dir" value="${safe(dir)}">` : ''}
          <input class="fil" name="busca" placeholder="Paciente, prontuário, procedimento…" value="${safe(q.busca || '')}" style="min-width:230px">
          <select class="fil" name="equipe">${opt(equipes.map(e => [e.id, e.nome]), q.equipe, 'Todas as equipes')}</select>
          <select class="fil" name="classif">${opt(ISC_CLASSIFICACOES, q.classif, 'Toda classificação')}</select>
          <select class="fil" name="tipo">${opt(ISC_TIPOS, q.tipo, 'Todo tipo')}</select>
          <select class="fil" name="status">${opt(STATUS_VIGILANCIA, q.status, 'Todo status')}</select>
          <input class="fil" type="month" name="mes" value="${safe(q.mes || '')}" title="Mês da cirurgia">
          <label class="chk"><input type="checkbox" name="alerta" value="1" ${q.alerta === '1' ? 'checked' : ''}> só alerta</label>
          <label class="chk"><input type="checkbox" name="implante" value="1" ${q.implante === '1' ? 'checked' : ''}> só implante</label>
          <label class="chk"><input type="checkbox" name="pendente" value="1" ${q.pendente === '1' ? 'checked' : ''}> contato vencido</label>
          <button class="btn" type="submit">Filtrar</button>
          <a class="fil" href="/isc/admin/grid" style="text-decoration:none">Limpar</a>
          <div style="margin-left:auto">${pager}</div>
        </form>
        <div class="grid-wrap"><table class="g">
          <thead><tr>
            <th>#</th>
            <th class="sticky-col">${sortLink('Paciente', 'paciente')}</th>
            <th>${sortLink('Equipe', 'equipe')}</th>
            <th>${sortLink('Procedimento', 'proc')}</th>
            <th>${sortLink('Cirurgia', 'cirurgia')}</th>
            <th>${sortLink('Janelas', 'janelas')}</th>
            <th>${sortLink('Próx. contato', 'prox')}</th>
            <th style="text-align:center">${sortLink('Sinal', 'sinal')}</th>
            <th class="grp">${sortLink('Classificação', 'classif')}</th>
            <th class="grp">${sortLink('Tipo', 'tipo')}</th>
            <th class="grp">${sortLink('Dt. dx', 'dtdx')}</th>
            <th class="grp">${sortLink('Patógeno', 'patogeno')}</th>
            <th style="text-align:center">Zap</th>
          </tr></thead>
          <tbody>${linhas || `<tr><td colspan="13" style="padding:30px;text-align:center;color:#80868b">Nenhuma ficha no recorte.</td></tr>`}</tbody>
        </table></div>
      </div>${CSS}`;

      res.send(renderShell(`ISC · Vigilância${sigla ? ' · ' + sigla : ''}`, html, sigla ? getTenantLogo(sigla) : undefined));
    } catch (e) { erro(res, e); }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // AGENDA — a tela da colaboradora
  // ═══════════════════════════════════════════════════════════════════════
  app.get('/isc/admin/agenda', scihRequired, async (req, res) => {
    try {
      const { sigla, instId } = await resolveInst(req);
      const hospital = await nomeInst(sigla);
      const horizonte = Math.min(30, Math.max(0, parseInt(req.query.dias || '2', 10) || 0));
      const limite = addDays(hojeISO(), horizonte);

      // O LEFT JOIN na fila é o que separa "a enviar" de "já mandei, aguardando".
      // Sem isso a agenda mostra os mesmos 15 o dia inteiro e ela reenvia.
      const { rows } = await pool.query(
        `SELECT f.*, e.nome AS equipe_nome,
                ev.status AS envio_status, ev.enviado_em, ev.enviado_por
           FROM isc_fichas f
           LEFT JOIN isc_equipes e ON e.id = f.equipe_id
           LEFT JOIN isc_envios ev ON ev.ficha_id = f.id AND ev.janela = f.proxima_janela
          WHERE f.status_vigilancia = 'em_vigilancia'
            AND f.proximo_contato_em IS NOT NULL
            AND f.proximo_contato_em <= $1
            AND ($2::int IS NULL OR f.instituicao_id = $2)
          ORDER BY (ev.enviado_em IS NOT NULL), f.proximo_contato_em ASC, f.id ASC
          LIMIT 300`, [limite, instId]);   // quem falta enviar vem primeiro

      const { rows: tpls } = await pool.query(
        `SELECT * FROM isc_msg_templates
          WHERE ativo = true AND ($1::int IS NULL OR instituicao_id = $1)
          ORDER BY ordem, id`, [instId]);

      // O link wa.me NÃO escolhe o remetente: sai de qualquer conta logada no
      // navegador. Não há como o servidor saber qual é — então o que dá para
      // fazer é lembrar qual DEVERIA ser, no momento exato do envio.
      const cfg = await configDe(instId);
      const zapInst = cfg.whatsapp_business || null;

      const tplIdent = tpls.find(t => Number(t.janela) === JANELA_IDENTIDADE) || null;
      const hoje = hojeISO();
      const aEnviar = rows.filter(f => !f.enviado_em).length;
      const jaEnviadas = rows.length - aEnviar;
      const visiveis = req.query.pendentes === '1' ? rows.filter(f => !f.enviado_em) : rows;
      const cards = visiveis.map(f => {
        const dias = f.proxima_janela;
        const tpl = tpls.find(t => Number(t.janela) === Number(dias)) || tpls.find(t => t.janela == null);
        const dpo = diffDias(toISODate(f.data_cirurgia), hoje);
        const corpo = tpl ? renderTemplate(tpl.corpo, {
          paciente_nome: f.paciente_nome, paciente_iniciais: f.paciente_iniciais,
          procedimento: f.procedimento, data_cirurgia: f.data_cirurgia,
          dias_pos_op: dpo, equipe: f.equipe_nome, cirurgiao: f.cirurgiao, hospital,
        }) : '(sem template para esta janela — cadastre em Mensagens)';
        const atraso = diffDias(toISODate(f.proximo_contato_em), hoje);
        const tent = f.tentativas_falhas || 0;
        const enviada = !!f.enviado_em;

        // Passo 0: enquanto a identidade não é confirmada, o card fala em CONFIRMAR
        // IDENTIDADE, não em busca ativa. A mensagem clínica não pode sair antes —
        // senão o primeiro texto já revela a cirurgia para um número não confirmado
        // (ainda mais com DDD presumido).
        const identPendente = f.identidade_status !== 'confirmada' && f.identidade_status !== 'negada';
        const identNegada = f.identidade_status === 'negada';
        const corpoIdent = tplIdent ? renderTemplate(tplIdent.corpo, {
          paciente_nome: f.paciente_nome, paciente_iniciais: f.paciente_iniciais, hospital,
        }) : 'Olá! Sou da equipe do ' + hospital + '. Este é um número de contato de ' +
             ((f.paciente_nome || '').trim().split(/\s+/)[0] || 'paciente') + '?';
        // O que o botão "Abrir WhatsApp" leva: identidade primeiro, clínica depois.
        const corpoEnvio = identPendente ? corpoIdent : corpo;
        const wa = f.telefone ? linkWhatsApp(f.telefone, corpoEnvio) : null;

        return `<div class="card2"${enviada ? ' style="opacity:.62"' : ''}>
          <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap">
            <div>
              <a href="/isc/admin/ficha/${f.id}" style="font-weight:600;font-size:15px">${safe(f.paciente_nome || f.paciente_iniciais || '(sem nome)')}</a>
              <span class="pill" style="background:${atraso > 0 ? '#fdecea' : '#e8f0fe'};color:${atraso > 0 ? '#c0392b' : '#1a73e8'};margin-left:8px">janela ${dias}d${atraso > 0 ? ` · atrasado ${atraso}d` : atraso === 0 ? ' · hoje' : ` · em ${-atraso}d`}</span>
              ${tent > 0 ? `<span class="pill" style="background:#fff4e5;color:#b06000;margin-left:6px">${tent} tentativa${tent > 1 ? 's' : ''} sem sucesso</span>` : ''}
              ${f.telefone_presumido ? `<span class="pill" style="background:#fdecea;color:#c0392b;margin-left:6px" title="O DDD foi deduzido da cidade no import. Confirme o número antes de enviar: mensagem para o número errado revela a cirurgia a terceiros.">⚠ DDD presumido — confira</span>` : ''}
              ${enviada ? `<span class="pill" style="background:#e6f4ea;color:#1e7e34;margin-left:6px">✓ enviada ${dataBR(f.enviado_em)}${f.enviado_por ? ' por ' + safe(f.enviado_por) : ''} · aguardando resposta</span>` : ''}
              ${identPendente ? `<span class="pill" style="background:#fef7e0;color:#b06000;margin-left:6px" title="Antes de qualquer pergunta sobre a cirurgia, confirme que o número é do paciente.">🔒 confirmar identidade primeiro</span>` : ''}
              ${identNegada ? `<span class="pill" style="background:#fdecea;color:#c0392b;margin-left:6px">✗ identidade negada — número não é do paciente</span>` : ''}
              ${f.identidade_status === 'confirmada' ? `<span class="pill" style="background:#e6f4ea;color:#1e7e34;margin-left:6px" title="Identidade confirmada${f.identidade_por ? ' por ' + safe(f.identidade_por) : ''}${f.identidade_em ? ' em ' + dataBR(f.identidade_em) : ''}">✓ identidade confirmada</span>` : ''}
              <div class="sub" style="margin-top:4px">${safe(f.procedimento || '')} · ${safe(f.equipe_nome || '')} · cirurgia ${dataBR(f.data_cirurgia)} (${dpo} DPO) · ${f.telefone ? safe(formataTelefone(f.telefone)) : '<span style="color:#c0392b">sem telefone</span>'}</div>
            </div>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              ${wa ? `<a class="btn" style="text-decoration:none;background:${(enviada && !identPendente) ? '#8bcfa4' : '#25D366'}" href="${wa}" target="_blank" rel="noopener">${identPendente ? 'Abrir WhatsApp · confirmar identidade' : (enviada ? 'Reabrir conversa' : 'Abrir WhatsApp')}</a>` : ''}
              ${identPendente
                ? `${wa ? `<form method="post" action="/isc/admin/ficha/${f.id}/identidade" style="display:inline">
                       <input type="hidden" name="inst" value="${safe(sigla || '')}"><input type="hidden" name="status" value="confirmada">
                       <button class="btn btn-sec" style="border-color:#2bb673;color:#1e7e34" title="O paciente confirmou que o número é dele">✓ Confirmou identidade</button></form>
                     <form method="post" action="/isc/admin/ficha/${f.id}/identidade" style="display:inline">
                       <input type="hidden" name="inst" value="${safe(sigla || '')}"><input type="hidden" name="status" value="negada">
                       <button class="btn btn-sec" style="border-color:#e0a3a3;color:#c0392b" title="Não é o número do paciente">✗ Não é o paciente</button></form>` : ''}`
                : `${enviada
                    ? `<form method="post" action="/isc/admin/envio/desmarcar" style="display:inline">
                         <input type="hidden" name="inst" value="${safe(sigla || '')}">
                         <input type="hidden" name="ficha_id" value="${f.id}"><input type="hidden" name="janela" value="${dias}">
                         <button class="btn btn-sec" title="Marquei sem querer / não cheguei a enviar">Desmarcar</button></form>`
                    : (wa ? `<form method="post" action="/isc/admin/envio/marcar" style="display:inline">
                         <input type="hidden" name="inst" value="${safe(sigla || '')}">
                         <input type="hidden" name="ficha_id" value="${f.id}"><input type="hidden" name="janela" value="${dias}">
                         <button class="btn btn-sec" title="Sai da fila de envio e passa a aguardar resposta">Já enviei</button></form>` : '')}`}
              <a class="btn btn-sec" style="text-decoration:none" href="/isc/admin/ficha/${f.id}#contato">Registrar resposta</a>
            </div>
          </div>
          <details style="margin-top:10px"><summary style="cursor:pointer;font-size:12px;color:#5f6368">Ver mensagem (${safe(tpl?.nome || '—')})</summary>
            <div class="msg" style="margin-top:8px">${safe(corpo)}</div>
            <button class="btn btn-sec" style="margin-top:8px" onclick="navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='Copiado!'">Copiar</button>
          </details>
        </div>`;
      }).join('');

      const html = `<div class="isc">
        ${chrome(sigla, 'Agenda de contatos', 'Quem precisa ser contatado — mensagem já pronta', nav(req))}
        ${zapInst ? `
        <div class="card2" style="border-left:3px solid #25D366;background:#f4fbf6">
          <b style="font-size:13px">Enviar sempre pelo WhatsApp Business: ${safe(formataTelefone(zapInst))}</b>
          <p class="sub" style="margin:6px 0 8px;line-height:1.6">
            O botão abaixo abre a conversa com o paciente pela conta que estiver logada <b>neste navegador</b> —
            se for a sua conta pessoal, a mensagem sai dela e o paciente fica com o seu contato particular.
          </p>
          <a class="btn btn-sec" style="text-decoration:none;display:inline-block"
             href="${linkWhatsApp(zapInst, 'Teste de remetente — SCIH')}" target="_blank" rel="noopener">
            Testar de qual número estou enviando
          </a>
          <span class="sub" style="margin-left:8px">Abre conversa com o próprio Business: se aparecer <b>“(Você)”</b>, está certo. Se abrir como contato normal, você está em outra conta.</span>
        </div>` : `
        <div class="card2" style="border-left:3px solid #f0a500;background:#fffaf2">
          <b style="font-size:13px">Número do WhatsApp Business não configurado</b>
          <p class="sub" style="margin:6px 0 0">Sem ele não dá para conferir de qual número as mensagens estão saindo. <a href="/isc/admin/templates">Configurar agora</a>.</p>
        </div>`}
        <form method="get" style="margin-bottom:14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
          <label class="l" style="margin:0">Horizonte</label>
          <select class="fil" name="dias" onchange="this.form.submit()">
            ${[0, 2, 7, 15, 30].map(d => `<option value="${d}" ${String(horizonte) === String(d) ? 'selected' : ''}>${d === 0 ? 'Vencidos + hoje' : `Próximos ${d} dias`}</option>`).join('')}
          </select>
          <label class="chk"><input type="checkbox" name="pendentes" value="1" ${req.query.pendentes === '1' ? 'checked' : ''} onchange="this.form.submit()"> só as que faltam enviar</label>
          <span class="pill" style="background:#fff4e5;color:#b06000">${aEnviar} a enviar</span>
          <span class="pill" style="background:#e6f4ea;color:#1e7e34">${jaEnviadas} aguardando resposta</span>
        </form>
        ${cards || `<div class="card2" style="text-align:center;color:#80868b;padding:40px">${aEnviar === 0 && jaEnviadas > 0 ? 'Tudo enviado — aguardando as respostas. 🎉' : 'Nada pendente neste horizonte. 🎉'}</div>`}
      </div>${CSS}`;

      res.send(renderShell(`ISC · Agenda${sigla ? ' · ' + sigla : ''}`, html, sigla ? getTenantLogo(sigla) : undefined));
    } catch (e) { erro(res, e); }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // NOVA FICHA
  // ═══════════════════════════════════════════════════════════════════════
  app.get('/isc/admin/nova', scihRequired, async (req, res) => {
    try {
      const { sigla, instId } = await resolveInst(req);
      const equipes = await equipesDe(instId);
      const html = `<div class="isc">
        ${chrome(sigla, 'Nova ficha de vigilância', '1 paciente-cirurgia = 1 ficha', nav(req))}
        <form method="post" action="/isc/admin/fichas">
          <div class="card2"><h2>Paciente</h2><div class="ff">
            <div><label class="l">Nome completo</label><input name="paciente_nome" required></div>
            <div><label class="l">Iniciais</label><input name="paciente_iniciais" placeholder="J.S.M."></div>
            <div><label class="l">Data de nascimento</label><input type="date" name="paciente_dn"></div>
            <div><label class="l">Prontuário</label><input name="prontuario"></div>
            <div><label class="l">Atendimento</label><input name="atendimento"></div>
            <div><label class="l">WhatsApp (com DDD)</label><input name="telefone" placeholder="(11) 91234-5678"></div>
            <div><label class="l">Contato alternativo</label><input name="contato_alternativo"></div>
          </div></div>
          <div class="card2"><h2>Cirurgia</h2><div class="ff">
            <div><label class="l">Equipe</label><select name="equipe_id" required><option value="">—</option>${equipes.map(e => `<option value="${e.id}" data-impl="${e.implante_default ? 1 : 0}">${safe(e.nome)}</option>`).join('')}</select></div>
            <div><label class="l">Procedimento</label><input name="procedimento" required></div>
            <div><label class="l">Cirurgião</label><input name="cirurgiao"></div>
            <div><label class="l">Data da cirurgia</label><input type="date" name="data_cirurgia" required value="${hojeISO()}"></div>
            <div><label class="l">Data da alta</label><input type="date" name="data_alta"></div>
            <div><label class="l">Potencial de contaminação</label><select name="potencial_contaminacao"><option value="">—</option>${POTENCIAL_CONTAMINACAO.map(([v, l]) => `<option value="${v}">${safe(l)}</option>`).join('')}</select></div>
            <div><label class="l">Duração (min)</label><input type="number" name="duracao_min" min="0"></div>
            <div><label class="l">ASA</label><select name="asa"><option value="">—</option>${['I', 'II', 'III', 'IV', 'V'].map(a => `<option>${a}</option>`).join('')}</select></div>
            <div><label class="l">Antibioticoprofilaxia</label><input name="antibioticoprofilaxia" placeholder="Cefazolina 2g"></div>
            <div style="display:flex;align-items:flex-end"><label class="chk"><input type="checkbox" name="implante" value="1" id="implante"> Cirurgia com implante / prótese</label></div>
          </div>
          <p class="sub" style="margin:10px 0 0">Implante marca vigilância de 90 dias (NHSN pós-2016). As janelas vêm do padrão da equipe; dá para sobrescrever abaixo.</p>
          <div style="margin-top:10px"><label class="l">Janelas (dias pós-op, separados por vírgula — vazio = padrão da equipe)</label><input name="janelas" placeholder="7,30,90" style="max-width:260px"></div>
          </div>
          <div class="card2"><h2>Observação</h2><textarea name="observacao" rows="3"></textarea></div>
          <button class="btn" type="submit">Criar ficha</button>
          <a class="fil" href="/isc/admin/grid" style="text-decoration:none;margin-left:8px">Cancelar</a>
        </form>
        <script>
          document.querySelector('select[name=equipe_id]').addEventListener('change', function(){
            var o = this.options[this.selectedIndex];
            if (o && o.dataset.impl === '1') document.getElementById('implante').checked = true;
          });
        </script>
      </div>${CSS}`;
      res.send(renderShell('ISC · Nova ficha', html, sigla ? getTenantLogo(sigla) : undefined));
    } catch (e) { erro(res, e); }
  });

  app.post('/isc/admin/fichas', scihRequired, async (req, res) => {
    try {
      const { instId } = await resolveInst(req);
      const b = req.body || {};
      if (!b.data_cirurgia) return res.status(400).send('Data da cirurgia é obrigatória');

      const tel = normalizaTelefone(b.telefone);
      const janelas = String(b.janelas || '').split(',').map(s => parseInt(s.trim(), 10))
        .filter(n => Number.isInteger(n) && n > 0 && n <= 365).sort((a, b2) => a - b2);

      const { rows } = await pool.query(
        `INSERT INTO isc_fichas
           (instituicao_id, paciente_nome, paciente_iniciais, paciente_dn, prontuario, atendimento,
            telefone, telefone_raw, contato_alternativo, equipe_id, procedimento, cirurgiao,
            data_cirurgia, data_alta, implante, potencial_contaminacao, duracao_min, asa,
            antibioticoprofilaxia, janelas, observacao)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,
                 COALESCE($20::jsonb, (SELECT CASE WHEN $15 THEN janelas_implante ELSE janelas_default END
                                         FROM isc_equipes WHERE id = $10), '[7,30]'::jsonb), $21)
         RETURNING id`,
        [instId, b.paciente_nome || null, b.paciente_iniciais || null, b.paciente_dn || null,
         b.prontuario || null, b.atendimento || null, tel, b.telefone || null,
         b.contato_alternativo || null, b.equipe_id ? Number(b.equipe_id) : null,
         b.procedimento || null, b.cirurgiao || null, b.data_cirurgia,
         b.data_alta || null, boolDe(b.implante) === true,
         enumDe(b.potencial_contaminacao, POTENCIAL_CONTAMINACAO.map(x => x[0])),
         b.duracao_min ? Number(b.duracao_min) : null, b.asa || null,
         b.antibioticoprofilaxia || null,
         janelas.length ? JSON.stringify(janelas) : null, b.observacao || null]);

      const id = rows[0].id;
      await sincronizarEstado(id);
      res.redirect(`/isc/admin/ficha/${id}`);
    } catch (e) {
      if (e.code === '23505') {
        return res.status(409).send(renderShell('ISC · Duplicata',
          `<div class="card"><h1>Ficha já existe</h1><p class="mut">Já há ficha para este atendimento nesta data de cirurgia.</p><a href="/isc/admin/grid">← Voltar ao grid</a></div>`));
      }
      erro(res, e);
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // FICHA
  // ═══════════════════════════════════════════════════════════════════════
  app.get('/isc/admin/ficha/:id', scihRequired, async (req, res) => {
    try {
      const { sigla, instId } = await resolveInst(req);
      const dados = await carregarFicha(Number(req.params.id), instId);
      if (!dados) return res.status(404).send(renderShell('ISC', '<div class="card"><h1>Ficha não encontrada</h1></div>'));
      const { ficha: f, contatos, equipe } = dados;
      const hospital = await nomeInst(sigla);
      const equipes = await equipesDe(instId);
      const hoje = hojeISO();
      const dpo = diffDias(toISODate(f.data_cirurgia), hoje);
      const est = f.janelas_estado || {};
      const janelas = janelasDe(f, equipe);

      // Timeline
      const tl = contatos.map(c => {
        const cls = c.sucesso === false ? 'fail'
                  : (contatoTemAlerta(c.respostas, c.suspeita_isc) ? 'al' : 'ok');
        const resp = Object.entries(c.respostas || {}).map(([k, v]) => {
          const campo = CHECKLIST.find(x => x.key === k);
          return `<div style="font-size:12px"><span style="color:#5f6368">${safe(campo?.label || k)}:</span> <b>${safe(Array.isArray(v) ? v.join(', ') : v)}</b></div>`;
        }).join('');
        const rec = Array.isArray(c.recomendacoes) && c.recomendacoes.length
          ? `<div style="margin-top:6px;font-size:12px"><span style="color:#5f6368">Recomendações:</span> ${safe(c.recomendacoes.join(' · '))}</div>` : '';
        return `<div class="tl-item ${cls}">
          <div style="font-size:13px;font-weight:600">
            ${c.janela ? `Janela ${c.janela}d` : 'Contato avulso'} · ${dataBR(c.data_contato)}
            <span class="pill" style="background:${c.sucesso === false ? '#f1f3f4' : '#e6f4ea'};color:${c.sucesso === false ? '#80868b' : '#1e7e34'};margin-left:6px">${c.sucesso === false ? 'sem sucesso' : 'contato realizado'}</span>
            ${c.suspeita_isc ? '<span class="pill" style="background:#fdecea;color:#c0392b;margin-left:4px">suspeita ISC</span>' : ''}
          </div>
          <div class="sub">${safe((CANAIS.find(x => x[0] === c.canal) || [, c.canal])[1] || '')}${c.informante ? ' · informante: ' + safe(c.informante) : ''}${c.responsavel ? ' · por ' + safe(c.responsavel) : ''}${c.motivo_insucesso ? ' · ' + safe((MOTIVOS_INSUCESSO.find(x => x[0] === c.motivo_insucesso) || [, c.motivo_insucesso])[1]) : ''}</div>
          <div style="margin-top:6px">${resp}</div>${rec}
          ${c.observacao ? `<div style="margin-top:6px;font-size:12px;color:#5f6368">${safe(c.observacao)}</div>` : ''}
        </div>`;
      }).join('') || '<p class="sub">Nenhum contato registrado ainda.</p>';

      // Checklist do form de contato
      const chkHtml = CHECKLIST.map(c => {
        if (c.tipo === 'multi') {
          return `<div style="grid-column:1/-1"><label class="l">${safe(c.label)}</label>
            <div style="display:flex;gap:14px;flex-wrap:wrap">${c.opcoes.map(o =>
              `<label class="chk"><input type="checkbox" name="r_${c.key}" value="${safe(o)}"> ${safe(o)}</label>`).join('')}</div></div>`;
        }
        return `<div><label class="l">${safe(c.label)}</label>
          <select name="r_${c.key}"><option value="">—</option><option>Sim</option><option>Não</option><option>Não sabe</option></select></div>`;
      }).join('');

      const janelaOpts = janelas.map(d => {
        const e = est[String(d)] || {};
        const feito = e.status === 'concluida';
        const sel = String(f.proxima_janela) === String(d);
        return `<option value="${d}" ${sel ? 'selected' : ''}>${d} dias${feito ? ' (já registrado)' : ''}${e.data_prevista ? ' · previsto ' + dataBR(e.data_prevista) : ''}</option>`;
      }).join('');

      const badges = janelas.map(d => {
        const e = est[String(d)] || {};
        const [bg, fg, ic] = BADGE_JANELA[e.status] || BADGE_JANELA.pendente;
        return `<div style="background:${bg};color:${fg};border-radius:8px;padding:8px 12px;min-width:110px">
          <div style="font-size:16px;font-weight:700">${d}d ${ic}</div>
          <div style="font-size:11px;opacity:.85">${safe(e.status || 'pendente')}</div>
          <div style="font-size:11px;opacity:.7">${dataBR(e.data_contato || e.data_prevista) || ''}</div>
        </div>`;
      }).join('');

      const sel = (lista, v) => lista.map(([val, lab]) =>
        `<option value="${safe(val)}" ${String(v) === String(val) ? 'selected' : ''}>${safe(lab)}</option>`).join('');

      const html = `<div class="isc">
        ${chrome(sigla, f.paciente_nome || f.paciente_iniciais || 'Ficha', `${dpo} DPO · cirurgia ${dataBR(f.data_cirurgia)}`, nav(req))}

        <div class="card2">
          <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px">${badges}</div>
          <div class="ff" style="font-size:13px">
            <div><span class="l">Prontuário</span>${safe(f.prontuario || '—')} · at. ${safe(f.atendimento || '—')}</div>
            <div><span class="l">Equipe</span>${safe(equipe?.nome || f.especialidade || '—')}</div>
            <div><span class="l">Procedimento</span>${safe(f.procedimento || '—')}${f.implante ? ' <span class="pill" style="background:#eef2ff;color:#4c51bf">implante</span>' : ''}</div>
            <div><span class="l">Cirurgião</span>${safe(f.cirurgiao || '—')}</div>
            <div><span class="l">Alta</span>${dataBR(f.data_alta) || '—'}</div>
            <div><span class="l">WhatsApp</span>${f.telefone ? `<a href="${linkWhatsApp(f.telefone, '')}" target="_blank" rel="noopener">${safe(formataTelefone(f.telefone))}</a>` : '<span style="color:#c0392b">não informado</span>'}</div>
            <div><span class="l">Status</span>${safe(STATUS_LABEL[f.status_vigilancia] || f.status_vigilancia)}</div>
            <div><span class="l">Profilaxia</span>${safe(f.antibioticoprofilaxia || '—')}</div>
          </div>
          <details style="margin-top:12px"><summary style="cursor:pointer;font-size:12px;color:#5f6368">Editar dados da cirurgia</summary>
            <form method="post" action="/isc/admin/ficha/${f.id}/editar" style="margin-top:12px">
              <div class="ff">
                <div><label class="l">Nome</label><input name="paciente_nome" value="${safe(f.paciente_nome || '')}"></div>
                <div><label class="l">Prontuário</label><input name="prontuario" value="${safe(f.prontuario || '')}"></div>
                <div><label class="l">Atendimento</label><input name="atendimento" value="${safe(f.atendimento || '')}"></div>
                <div><label class="l">WhatsApp</label><input name="telefone" value="${safe(f.telefone_raw || formataTelefone(f.telefone) || '')}"></div>
                <div><label class="l">Equipe</label><select name="equipe_id"><option value="">—</option>${equipes.map(e => `<option value="${e.id}" ${e.id === f.equipe_id ? 'selected' : ''}>${safe(e.nome)}</option>`).join('')}</select></div>
                <div><label class="l">Procedimento</label><input name="procedimento" value="${safe(f.procedimento || '')}"></div>
                <div><label class="l">Cirurgião</label><input name="cirurgiao" value="${safe(f.cirurgiao || '')}"></div>
                <div><label class="l">Data da cirurgia</label><input type="date" name="data_cirurgia" value="${toISODate(f.data_cirurgia) || ''}"></div>
                <div><label class="l">Data da alta</label><input type="date" name="data_alta" value="${toISODate(f.data_alta) || ''}"></div>
                <div><label class="l">Janelas</label><input name="janelas" value="${janelas.join(',')}"></div>
                <div><label class="l">Status da vigilância</label><select name="status_vigilancia">${sel(STATUS_VIGILANCIA, f.status_vigilancia)}</select></div>
                <div style="display:flex;align-items:flex-end"><label class="chk"><input type="checkbox" name="implante" value="1" ${f.implante ? 'checked' : ''}> Implante</label></div>
              </div>
              <button class="btn" style="margin-top:12px">Salvar</button>
            </form>
          </details>
        </div>

        <div style="display:grid;grid-template-columns:1.1fr .9fr;gap:14px;align-items:start">
          <div>
            <div class="card2" id="contato"><h2>Registrar contato</h2>
              <form method="post" action="/isc/admin/ficha/${f.id}/contato">
                <div class="ff">
                  <div><label class="l">Janela</label><select name="janela"><option value="">Avulso</option>${janelaOpts}</select></div>
                  <div><label class="l">Data do contato</label><input type="date" name="data_contato" value="${hoje}"></div>
                  <div><label class="l">Canal</label><select name="canal">${CANAIS.map(([v, l]) => `<option value="${v}">${safe(l)}</option>`).join('')}</select></div>
                  <div><label class="l">Responsável</label><input name="responsavel"></div>
                  <div style="grid-column:1/-1"><label class="chk"><input type="checkbox" name="sem_sucesso" value="1" id="ss"> <b>Tentativa sem sucesso</b> (não falou com o paciente)</label></div>
                  <div id="bx-motivo" style="display:none"><label class="l">Motivo</label><select name="motivo_insucesso">${MOTIVOS_INSUCESSO.map(([v, l]) => `<option value="${v}">${safe(l)}</option>`).join('')}</select></div>
                </div>
                <div id="bx-resp" style="margin-top:14px">
                  <div><label class="l">Informações prestadas por (nome / parentesco)</label><input name="informante" style="max-width:340px"></div>
                  <div class="ff" style="margin-top:12px">${chkHtml}</div>
                  <div style="margin-top:12px"><label class="l">Recomendações SCIH</label>
                    <div style="display:flex;gap:14px;flex-wrap:wrap">${RECOMENDACOES.map(r => `<label class="chk"><input type="checkbox" name="recomendacoes" value="${safe(r)}"> ${safe(r)}</label>`).join('')}</div>
                  </div>
                  <div style="margin-top:12px"><label class="chk"><input type="checkbox" name="suspeita_isc" value="1"> <b>Suspeita de ISC</b> — sinaliza para avaliação médica</label></div>
                </div>
                <div style="margin-top:12px"><label class="l">Observação</label><textarea name="observacao" rows="2"></textarea></div>
                <button class="btn" style="margin-top:12px">Registrar contato</button>
              </form>
              <script>
                (function(){
                  var ss = document.getElementById('ss');
                  function t(){ document.getElementById('bx-resp').style.display = ss.checked ? 'none' : '';
                                document.getElementById('bx-motivo').style.display = ss.checked ? '' : 'none'; }
                  ss.addEventListener('change', t); t();
                })();
              </script>
            </div>
            <div class="card2"><h2>Histórico de contatos</h2><div class="tl">${tl}</div></div>
          </div>

          <div class="card2" style="border-left:3px solid #e85d5d">
            <h2>Classificação SCIH</h2>
            <p class="sub" style="margin-top:-6px">Ato médico. O contato da colaboradora nunca sobrescreve isto.</p>
            ${!ehMedico(req) ? `
            <!-- Leitura para quem não classifica: mostrar um formulário que dá 403
                 ao salvar seria pior que não mostrar nada. -->
            <div style="display:grid;gap:10px;font-size:13px">
              <div><span class="l">Classificação</span><span class="pill" style="background:${f.isc_classificacao === 'confirmada' ? '#fdecea' : '#f1f3f4'};color:${f.isc_classificacao === 'confirmada' ? '#c0392b' : '#5f6368'}">${safe(CLASSIF_LABEL[f.isc_classificacao] || '—')}</span></div>
              <div><span class="l">Tipo</span>${safe(TIPO_LABEL[f.isc_tipo] || '—')}</div>
              <div><span class="l">Data do diagnóstico</span>${dataBR(f.isc_data_diagnostico) || '—'}</div>
              <div><span class="l">Patógeno</span>${safe(f.isc_patogeno || '—')}</div>
              ${f.isc_observacao ? `<div><span class="l">Parecer</span><div style="white-space:pre-wrap">${safe(f.isc_observacao)}</div></div>` : ''}
              ${f.classificado_em ? `<p class="sub">Classificado em ${dataBR(f.classificado_em)} por ${safe(f.classificado_por || '—')}</p>` : '<p class="sub">Aguardando avaliação médica.</p>'}
              ${f.tem_alerta || f.suspeita_isc ? `<div class="pill" style="background:#fff4e5;color:#b06000;padding:8px 10px;line-height:1.5">Esta ficha está sinalizada e aparece na fila de classificação do médico.</div>` : ''}
            </div>` : `
            <form method="post" action="/isc/admin/ficha/${f.id}/classificar">
              <div style="display:grid;gap:12px">
                <div><label class="l">Classificação</label><select name="isc_classificacao">${sel(ISC_CLASSIFICACOES, f.isc_classificacao)}</select></div>
                <div><label class="l">Tipo (NHSN)</label><select name="isc_tipo"><option value="">—</option>${sel(ISC_TIPOS, f.isc_tipo)}</select></div>
                <div><label class="l">Data do diagnóstico</label><input type="date" name="isc_data_diagnostico" value="${toISODate(f.isc_data_diagnostico) || ''}"></div>
                <div><label class="l">Critérios</label>
                  <div style="display:grid;gap:4px">${ISC_CRITERIOS.map(c => `<label class="chk"><input type="checkbox" name="isc_criterios" value="${safe(c)}" ${(Array.isArray(f.isc_criterios) && f.isc_criterios.includes(c)) ? 'checked' : ''}> ${safe(c)}</label>`).join('')}</div>
                </div>
                <div><label class="l">Patógeno</label><input name="isc_patogeno" value="${safe(f.isc_patogeno || '')}" placeholder="S. aureus MSSA"></div>
                <div style="display:grid;gap:4px">
                  <label class="chk"><input type="checkbox" name="isc_readmissao" value="1" ${f.isc_readmissao ? 'checked' : ''}> Readmissão</label>
                  <label class="chk"><input type="checkbox" name="isc_reabordagem" value="1" ${f.isc_reabordagem ? 'checked' : ''}> Reabordagem cirúrgica</label>
                  <label class="chk"><input type="checkbox" name="obito" value="1" ${f.obito ? 'checked' : ''}> Óbito</label>
                  <label class="chk"><input type="checkbox" name="isc_obito_relacionado" value="1" ${f.isc_obito_relacionado ? 'checked' : ''}> Óbito relacionado ao procedimento</label>
                </div>
                <div><label class="l">Data do óbito</label><input type="date" name="obito_data" value="${toISODate(f.obito_data) || ''}"></div>
                <div><label class="l">Parecer / observação</label><textarea name="isc_observacao" rows="4">${safe(f.isc_observacao || '')}</textarea></div>
                <div><label class="l">Assinado por</label><input name="classificado_por" value="${safe(f.classificado_por || '')}"></div>
              </div>
              <button class="btn" style="margin-top:12px;background:#c0392b">Salvar classificação</button>
              ${f.classificado_em ? `<p class="sub" style="margin-top:8px">Última classificação: ${dataBR(f.classificado_em)} por ${safe(f.classificado_por || '—')}</p>` : ''}
            </form>`}
          </div>
        </div>
      </div>${CSS}`;

      res.send(renderShell(`ISC · ${f.paciente_nome || 'Ficha'}`, html, sigla ? getTenantLogo(sigla) : undefined));
    } catch (e) { erro(res, e); }
  });

  // ── Registrar contato ───────────────────────────────────────────────────
  app.post('/isc/admin/ficha/:id/contato', scihRequired, async (req, res) => {
    try {
      const { instId } = await resolveInst(req);
      const id = Number(req.params.id);
      const dados = await carregarFicha(id, instId);
      if (!dados) return res.status(404).send('Ficha não encontrada');

      const b = req.body || {};
      const semSucesso = boolDe(b.sem_sucesso) === true;
      const respostas = semSucesso ? {} : extraiRespostas(b);
      const recs = semSucesso ? [] :
        (Array.isArray(b.recomendacoes) ? b.recomendacoes : (b.recomendacoes ? [b.recomendacoes] : []))
          .map(String).filter(r => RECOMENDACOES.includes(r));

      await pool.query(
        `INSERT INTO isc_contatos
           (ficha_id, janela, data_contato, canal, sucesso, motivo_insucesso, informante,
            respostas, suspeita_isc, recomendacoes, responsavel, observacao)
         VALUES ($1,$2,COALESCE($3::timestamptz, now()),$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [id, b.janela ? Number(b.janela) : null, b.data_contato || null,
         enumDe(b.canal, CANAIS.map(x => x[0]), 'whatsapp'), !semSucesso,
         semSucesso ? enumDe(b.motivo_insucesso, MOTIVOS_INSUCESSO.map(x => x[0]), 'outro') : null,
         semSucesso ? null : (b.informante || null),
         JSON.stringify(respostas), !semSucesso && boolDe(b.suspeita_isc) === true,
         JSON.stringify(recs), b.responsavel || null, b.observacao || null]);

      // A suspeita da colaboradora é ADITIVA: uma vez levantada, só o médico
      // baixa (via classificação). Contato posterior sem suspeita não apaga.
      if (!semSucesso && boolDe(b.suspeita_isc) === true) {
        await pool.query('UPDATE isc_fichas SET suspeita_isc = true WHERE id = $1', [id]);
      }
      // Fecha o envio correspondente à janela, se houver.
      if (b.janela) {
        await pool.query(
          `UPDATE isc_envios SET status = CASE WHEN status = 'pendente' THEN 'manual' ELSE status END,
                                 enviado_em = COALESCE(enviado_em, now()), updated_at = now()
            WHERE ficha_id = $1 AND janela = $2 AND status = 'pendente'`, [id, Number(b.janela)]);
      }

      await sincronizarEstado(id);
      res.redirect(`/isc/admin/ficha/${id}`);
    } catch (e) { erro(res, e); }
  });

  // ── Classificar ─────────────────────────────────────────────────────────
  app.post('/isc/admin/ficha/:id/classificar', medicoRequired, async (req, res) => {
    try {
      const { instId } = await resolveInst(req);
      const id = Number(req.params.id);
      const dados = await carregarFicha(id, instId);
      if (!dados) return res.status(404).send('Ficha não encontrada');

      const b = req.body || {};
      const criterios = (Array.isArray(b.isc_criterios) ? b.isc_criterios : (b.isc_criterios ? [b.isc_criterios] : []))
        .map(String).filter(c => ISC_CRITERIOS.includes(c));
      const obito = boolDe(b.obito) === true;

      await pool.query(
        `UPDATE isc_fichas SET
           isc_classificacao = $2, isc_tipo = $3, isc_data_diagnostico = $4, isc_criterios = $5,
           isc_patogeno = $6, isc_readmissao = $7, isc_reabordagem = $8, isc_obito_relacionado = $9,
           isc_observacao = $10, classificado_por = $11, classificado_em = now(),
           obito = $12, obito_data = $13,
           obito_causa = CASE WHEN $12 THEN (CASE WHEN $9 THEN 'relacionado_procedimento' ELSE 'outras_causas' END) ELSE NULL END,
           status_vigilancia = CASE WHEN $12 THEN 'obito' ELSE status_vigilancia END,
           updated_at = now()
         WHERE id = $1`,
        [id, enumDe(b.isc_classificacao, ISC_CLASSIFICACOES.map(x => x[0]), 'nao_avaliada'),
         enumDe(b.isc_tipo, ISC_TIPOS.map(x => x[0])), b.isc_data_diagnostico || null,
         JSON.stringify(criterios), b.isc_patogeno || null,
         boolDe(b.isc_readmissao) === true, boolDe(b.isc_reabordagem) === true,
         boolDe(b.isc_obito_relacionado) === true, b.isc_observacao || null,
         b.classificado_por || null, obito, b.obito_data || null]);

      await sincronizarEstado(id);
      res.redirect(`/isc/admin/ficha/${id}`);
    } catch (e) { erro(res, e); }
  });

  // ── Editar dados estáveis ───────────────────────────────────────────────
  app.post('/isc/admin/ficha/:id/editar', scihRequired, async (req, res) => {
    try {
      const { instId } = await resolveInst(req);
      const id = Number(req.params.id);
      const dados = await carregarFicha(id, instId);
      if (!dados) return res.status(404).send('Ficha não encontrada');

      const b = req.body || {};
      const janelas = String(b.janelas || '').split(',').map(s => parseInt(s.trim(), 10))
        .filter(n => Number.isInteger(n) && n > 0 && n <= 365).sort((a, b2) => a - b2);
      const tel = b.telefone ? normalizaTelefone(b.telefone) : null;

      await pool.query(
        `UPDATE isc_fichas SET
           paciente_nome = COALESCE($2, paciente_nome), prontuario = $3, atendimento = $4,
           telefone = COALESCE($5, telefone), telefone_raw = COALESCE($6, telefone_raw),
           equipe_id = $7, procedimento = $8, cirurgiao = $9,
           data_cirurgia = COALESCE($10::date, data_cirurgia), data_alta = $11,
           implante = $12, janelas = COALESCE($13::jsonb, janelas),
           status_vigilancia = $14, updated_at = now()
         WHERE id = $1`,
        [id, b.paciente_nome || null, b.prontuario || null, b.atendimento || null,
         tel, b.telefone || null, b.equipe_id ? Number(b.equipe_id) : null,
         b.procedimento || null, b.cirurgiao || null, b.data_cirurgia || null,
         b.data_alta || null, boolDe(b.implante) === true,
         janelas.length ? JSON.stringify(janelas) : null,
         enumDe(b.status_vigilancia, STATUS_VIGILANCIA.map(x => x[0]), dados.ficha.status_vigilancia)]);

      await sincronizarEstado(id);
      res.redirect(`/isc/admin/ficha/${id}`);
    } catch (e) { erro(res, e); }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // TEMPLATES DE MENSAGEM
  // ═══════════════════════════════════════════════════════════════════════
  app.get('/isc/admin/templates', scihRequired, async (req, res) => {
    try {
      const { sigla, instId } = await resolveInst(req);
      const { rows } = await pool.query(
        `SELECT * FROM isc_msg_templates WHERE ($1::int IS NULL OR instituicao_id = $1) ORDER BY ordem, id`, [instId]);

      const cards = rows.map(t => `
        <div class="card2"${Number(t.janela) === JANELA_IDENTIDADE ? ' style="border-left:3px solid #b06000"' : ''}>
          ${Number(t.janela) === JANELA_IDENTIDADE ? `<p class="sub" style="margin:0 0 10px"><b>🔒 Passo 0 — confirmação de identidade.</b> É a PRIMEIRA mensagem, antes de qualquer pergunta clínica. Use <code>{{primeiro_nome}}</code> (não o nome completo — para o paciente confirmar, não qualquer um). Janela <b>-1</b> é reservada; não mude.</p>` : ''}
          <form method="post" action="/isc/admin/templates">
            <input type="hidden" name="id" value="${t.id}">
            <div class="ff" style="margin-bottom:10px">
              <div><label class="l">Nome</label><input name="nome" value="${safe(t.nome)}"></div>
              <div><label class="l">Janela (dias · -1 = identidade · vazio = avulso)</label><input name="janela" type="number" value="${t.janela ?? ''}"></div>
              <div><label class="l">Ordem</label><input name="ordem" type="number" value="${t.ordem ?? 100}"></div>
              <div style="display:flex;align-items:flex-end"><label class="chk"><input type="checkbox" name="ativo" value="1" ${t.ativo ? 'checked' : ''}> Ativo</label></div>
            </div>
            <textarea name="corpo" rows="8" style="font-family:ui-monospace,Menlo,monospace;font-size:12px">${safe(t.corpo)}</textarea>
            <button class="btn" style="margin-top:10px">Salvar</button>
          </form>
        </div>`).join('');

      const cfg = await configDe(instId);
      const html = `<div class="isc">
        ${chrome(sigla, 'Mensagens padronizadas', 'Texto enviado pelo WhatsApp Business em cada janela', nav(req))}
        <div class="card2" style="border-left:3px solid #25D366">
          <h2>Número institucional (WhatsApp Business)</h2>
          <p class="sub" style="margin-top:-8px">Aparece na agenda como lembrete e alimenta o autoteste de remetente. Fixo é aceito no Business.</p>
          <form method="post" action="/isc/admin/config" style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap">
            <div><label class="l">Número com DDD</label><input name="whatsapp_business" value="${safe(cfg.whatsapp_business ? formataTelefone(cfg.whatsapp_business) : '')}" placeholder="(11) 2490-1268" style="max-width:220px"></div>
            <button class="btn">Salvar</button>
            ${cfg.whatsapp_business ? `<span class="sub">Gravado: ${safe(cfg.whatsapp_business)}</span>` : ''}
          </form>
        </div>
        <div class="card2" style="background:#f8f9fa">
          <b style="font-size:13px">Placeholders disponíveis</b>
          <div style="margin-top:6px;display:flex;gap:8px;flex-wrap:wrap">${PLACEHOLDERS.map(p => `<code style="background:#fff;border:1px solid #e8eaed;border-radius:6px;padding:2px 6px;font-size:12px">${safe(p)}</code>`).join('')}</div>
          <p class="sub" style="margin-bottom:0">Placeholder desconhecido vira texto vazio — nunca vaza <code>{{x}}</code> para o paciente.</p>
        </div>
        ${cards}
        <div class="card2" style="border:1px dashed #dadce0">
          <h2>Novo template</h2>
          <form method="post" action="/isc/admin/templates">
            <div class="ff" style="margin-bottom:10px">
              <div><label class="l">Nome</label><input name="nome" required></div>
              <div><label class="l">Janela (dias · vazio = avulso)</label><input name="janela" type="number"></div>
              <div><label class="l">Ordem</label><input name="ordem" type="number" value="100"></div>
              <div style="display:flex;align-items:flex-end"><label class="chk"><input type="checkbox" name="ativo" value="1" checked> Ativo</label></div>
            </div>
            <textarea name="corpo" rows="6" required placeholder="Olá, {{primeiro_nome}}! ..."></textarea>
            <button class="btn" style="margin-top:10px">Criar</button>
          </form>
        </div>
      </div>${CSS}`;
      res.send(renderShell('ISC · Mensagens', html, sigla ? getTenantLogo(sigla) : undefined));
    } catch (e) { erro(res, e); }
  });

  app.post('/isc/admin/config', scihRequired, async (req, res) => {
    try {
      const { instId } = await resolveInst(req);
      if (instId == null) return res.status(400).send('Instituição não resolvida');
      // Fixo institucional (10 dígitos) é número válido de Business — o
      // normalizaTelefone já aceita; o que ele rejeita é número sem DDD.
      const tel = normalizaTelefone(req.body?.whatsapp_business);
      if (!tel) {
        return res.status(400).send(renderShell('ISC · Config', `<div class="card">
          <h1>Número inválido</h1>
          <p class="mut">Informe com DDD, ex.: (11) 2490-1268.</p>
          <a href="/isc/admin/templates">← Voltar</a></div>`));
      }
      await pool.query(
        `INSERT INTO isc_config (instituicao_id, whatsapp_business, updated_at)
         VALUES ($1,$2,now())
         ON CONFLICT (instituicao_id) DO UPDATE SET whatsapp_business=EXCLUDED.whatsapp_business, updated_at=now()`,
        [instId, tel]);
      res.redirect('/isc/admin/templates');
    } catch (e) { erro(res, e); }
  });

  // ── Passo 0: identidade ─────────────────────────────────────────────────
  // Registra que a colaboradora confirmou (ou não) que o número é do paciente.
  // Vale por PACIENTE (a ficha): confirmou uma vez, as janelas clínicas liberam.
  // Identidade negada é registrada, mas a decisão do que fazer com a ficha fica
  // com a colaboradora (número novo, encerrar, etc.) — por isso não mexe no
  // status de vigilância aqui.
  app.post('/isc/admin/ficha/:id/identidade', scihRequired, async (req, res) => {
    try {
      const { sigla, instId } = await resolveInst(req);
      const id = Number(req.params.id);
      const status = ['confirmada', 'negada', 'pendente'].includes(req.body?.status) ? req.body.status : null;
      if (!status) return res.status(400).send('Status inválido');
      const dados = await carregarFicha(id, instId);
      if (!dados) return res.status(404).send('Ficha não encontrada');
      await pool.query(
        `UPDATE isc_fichas
            SET identidade_status = $2,
                identidade_em = CASE WHEN $2 = 'pendente' THEN NULL ELSE now() END,
                identidade_por = CASE WHEN $2 = 'pendente' THEN NULL ELSE $3 END,
                updated_at = now()
          WHERE id = $1 AND ($4::int IS NULL OR instituicao_id = $4)`,
        [id, status, (req.user && req.user.full_name) || null, instId]);
      const back = req.get('referer') && /\/ficha\//.test(req.get('referer'))
        ? `/isc/admin/ficha/${id}?${new URLSearchParams({ inst: sigla || '' })}`
        : `/isc/admin/agenda?${new URLSearchParams({ ...req.query, inst: sigla || '' })}`;
      res.redirect(back);
    } catch (e) { erro(res, e); }
  });

  // ── Marcar envio ────────────────────────────────────────────────────────
  // O sistema NÃO envia: ela dispara no WhatsApp e volta aqui para dizer que
  // enviou. Sem este passo a agenda não distingue "mandei, esperando resposta"
  // de "nem mandei" — e o paciente recebe a mesma mensagem duas vezes.
  //
  // Deliberadamente NÃO marcamos no clique do botão "Abrir WhatsApp": abrir a
  // conversa não é enviar. Registrar envio que não aconteceu é pior que não
  // registrar — some da fila e ninguém contata o paciente.
  app.post('/isc/admin/envio/marcar', scihRequired, async (req, res) => {
    try {
      const { sigla, instId } = await resolveInst(req);
      const id = Number(req.body?.ficha_id);
      const janela = Number(req.body?.janela);
      if (!id || !janela) return res.status(400).send('Ficha e janela obrigatórias');

      const dados = await carregarFicha(id, instId);
      if (!dados) return res.status(404).send('Ficha não encontrada');
      const { ficha: f, equipe } = dados;

      // Portão do passo 0: marcar como enviada uma mensagem clínica (janela ≥ 0)
      // exige identidade confirmada. Sem isso a colaboradora poderia "Já enviei"
      // a busca ativa antes de saber se o número é do paciente. O passo 0 em si
      // (janela -1) passa sempre — é ele que confirma.
      if (janela >= 0 && f.identidade_status !== 'confirmada') {
        return res.status(409).send(renderShell('Confirmar identidade primeiro', `<div class="card">
          <h1>Confirme a identidade antes</h1>
          <p class="mut">Esta ficha ainda não teve a identidade confirmada. Envie a mensagem de
          confirmação (passo 0) e, quando o paciente responder que o número é dele, use
          <b>✓ Confirmou identidade</b> na agenda. Só então a busca ativa pode ser enviada.</p>
          <a href="/isc/admin/agenda">← Voltar à agenda</a></div>`));
      }

      // Snapshot do que foi enviado: o template pode mudar depois, e aí não se
      // saberia mais o que o paciente recebeu.
      const hospital = await nomeInst(sigla);
      const { rows: tpls } = await pool.query(
        `SELECT * FROM isc_msg_templates
          WHERE ativo = true AND ($1::int IS NULL OR instituicao_id = $1)
          ORDER BY ordem, id`, [instId]);
      const tpl = tpls.find(t => Number(t.janela) === janela) || tpls.find(t => t.janela == null) || null;
      const corpo = tpl ? renderTemplate(tpl.corpo, {
        paciente_nome: f.paciente_nome, paciente_iniciais: f.paciente_iniciais,
        procedimento: f.procedimento, data_cirurgia: f.data_cirurgia,
        dias_pos_op: diffDias(toISODate(f.data_cirurgia), hojeISO()),
        equipe: equipe?.nome, cirurgiao: f.cirurgiao, hospital,
      }) : null;

      await pool.query(
        `INSERT INTO isc_envios (ficha_id, janela, template_id, telefone, corpo, status,
                                 agendado_para, enviado_em, enviado_por, provider)
         VALUES ($1,$2,$3,$4,$5,'manual',$6,now(),$7,'manual')
         ON CONFLICT (ficha_id, janela) WHERE janela IS NOT NULL DO UPDATE
           SET status='manual', enviado_em=now(), enviado_por=EXCLUDED.enviado_por,
               corpo=COALESCE(EXCLUDED.corpo, isc_envios.corpo),
               telefone=COALESCE(EXCLUDED.telefone, isc_envios.telefone), updated_at=now()`,
        [id, janela, tpl?.id || null, f.telefone, corpo,
         toISODate(f.proximo_contato_em), (req.user && req.user.full_name) || null]);

      res.redirect(`/isc/admin/agenda?${new URLSearchParams({ ...req.query, inst: sigla || '' })}`);
    } catch (e) { erro(res, e); }
  });

  // Desfazer: marcou sem querer, ou o envio falhou. Volta para a fila.
  app.post('/isc/admin/envio/desmarcar', scihRequired, async (req, res) => {
    try {
      const { sigla, instId } = await resolveInst(req);
      const id = Number(req.body?.ficha_id);
      const janela = Number(req.body?.janela);
      if (!id || !janela) return res.status(400).send('Ficha e janela obrigatórias');
      const dados = await carregarFicha(id, instId);
      if (!dados) return res.status(404).send('Ficha não encontrada');
      await pool.query(
        `UPDATE isc_envios SET status='pendente', enviado_em=NULL, enviado_por=NULL, updated_at=now()
          WHERE ficha_id=$1 AND janela=$2`, [id, janela]);
      res.redirect(`/isc/admin/agenda?${new URLSearchParams({ ...req.query, inst: sigla || '' })}`);
    } catch (e) { erro(res, e); }
  });

  app.post('/isc/admin/templates', scihRequired, async (req, res) => {
    try {
      const { instId } = await resolveInst(req);
      const b = req.body || {};
      const janela = b.janela === '' || b.janela == null ? null : Number(b.janela);
      const ativo = boolDe(b.ativo) === true;
      if (b.id) {
        await pool.query(
          `UPDATE isc_msg_templates SET nome=$2, janela=$3, corpo=$4, ativo=$5, ordem=$6, updated_at=now()
            WHERE id=$1 AND ($7::int IS NULL OR instituicao_id=$7)`,
          [Number(b.id), b.nome, janela, b.corpo, ativo, Number(b.ordem || 100), instId]);
      } else {
        await pool.query(
          `INSERT INTO isc_msg_templates (instituicao_id, nome, janela, corpo, ativo, ordem)
           VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (instituicao_id, nome) DO NOTHING`,
          [instId, b.nome, janela, b.corpo, ativo, Number(b.ordem || 100)]);
      }
      res.redirect('/isc/admin/templates');
    } catch (e) { erro(res, e); }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // CRON — agendamento de envios
  // Padrão do projeto: responde 202 IMEDIATO, trabalha em background, com
  // guarda de sobreposição. Um dia isto vira o disparo real pela Cloud API;
  // hoje só materializa a fila que a Agenda consome.
  // ═══════════════════════════════════════════════════════════════════════
  let _agendando = false;

  async function agendarEnvios() {
    const hoje = hojeISO();
    const { rows } = await pool.query(
      `SELECT f.*, e.nome AS equipe_nome, i.sigla AS inst_sigla, i.nome AS inst_nome
         FROM isc_fichas f
         LEFT JOIN isc_equipes e ON e.id = f.equipe_id
         LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
        WHERE f.status_vigilancia = 'em_vigilancia'
          AND f.proximo_contato_em IS NOT NULL
          AND f.proximo_contato_em <= $1
        LIMIT 500`, [hoje]);

    const { rows: tpls } = await pool.query('SELECT * FROM isc_msg_templates WHERE ativo = true');
    let criados = 0;

    for (const f of rows) {
      try {
        const dias = f.proxima_janela;
        if (!dias) continue;
        const tpl = tpls.find(t => t.instituicao_id === f.instituicao_id && Number(t.janela) === Number(dias))
                 || tpls.find(t => t.instituicao_id === f.instituicao_id && t.janela == null);
        if (!tpl) continue;
        const corpo = renderTemplate(tpl.corpo, {
          paciente_nome: f.paciente_nome, paciente_iniciais: f.paciente_iniciais,
          procedimento: f.procedimento, data_cirurgia: f.data_cirurgia,
          dias_pos_op: diffDias(toISODate(f.data_cirurgia), hoje),
          equipe: f.equipe_nome, cirurgiao: f.cirurgiao, hospital: f.inst_nome,
        });
        const r = await pool.query(
          `INSERT INTO isc_envios (ficha_id, janela, template_id, telefone, corpo, status, agendado_para, provider)
           VALUES ($1,$2,$3,$4,$5,'pendente',$6,'manual')
           ON CONFLICT (ficha_id, janela) WHERE janela IS NOT NULL DO NOTHING
           RETURNING id`,
          [f.id, dias, tpl.id, f.telefone, corpo, toISODate(f.proximo_contato_em)]);
        if (r.rowCount) criados++;
      } catch (e) { console.error('[isc-cron] ficha', f.id, e.message); }
    }

    // Perda de seguimento: janela final estourada há mais de 30 dias e sem
    // nenhum contato com sucesso → sai da fila ativa (mas continua no grid).
    await pool.query(
      `UPDATE isc_fichas SET status_vigilancia = 'perda_seguimento', updated_at = now()
        WHERE status_vigilancia = 'em_vigilancia'
          AND contatos_ok = 0
          AND tentativas_falhas >= 3
          AND proximo_contato_em < CURRENT_DATE - INTERVAL '30 days'`);

    console.log(`[isc-cron] ${criados} envio(s) agendado(s) de ${rows.length} ficha(s) elegíveis`);
    return criados;
  }

  app.post('/isc/cron/agendar', async (req, res) => {
    const token = process.env.ISC_CRON_TOKEN || process.env.ATB_CRON_TOKEN || null;
    if (token) {
      const dado = req.get('x-cron-token') || req.query.token || '';
      if (dado !== token) return res.status(401).json({ erro: 'token inválido' });
    }
    if (_agendando) return res.status(202).json({ ok: true, nota: 'execução já em andamento' });
    _agendando = true;
    res.status(202).json({ ok: true, iniciado_em: new Date().toISOString() });
    (async () => {
      try { await agendarEnvios(); }
      catch (e) { console.error('[isc-cron] falha', e); }
      finally { _agendando = false; }
    })();
  });

  // Ressincroniza os derivados de todas as fichas ativas (o "aberta/atrasada"
  // muda com a passagem do tempo, não só com escrita). Fire-and-forget.
  app.post('/isc/cron/sincronizar', async (req, res) => {
    const token = process.env.ISC_CRON_TOKEN || process.env.ATB_CRON_TOKEN || null;
    if (token) {
      const dado = req.get('x-cron-token') || req.query.token || '';
      if (dado !== token) return res.status(401).json({ erro: 'token inválido' });
    }
    res.status(202).json({ ok: true });
    (async () => {
      try {
        const { rows } = await pool.query(
          `SELECT id FROM isc_fichas WHERE status_vigilancia = 'em_vigilancia' LIMIT 2000`);
        for (const r of rows) { try { await sincronizarEstado(r.id); } catch (e) { console.error('[isc-sync]', r.id, e.message); } }
        console.log(`[isc-sync] ${rows.length} ficha(s) ressincronizada(s)`);
      } catch (e) { console.error('[isc-sync] falha', e); }
    })();
  });

  // ═══════════════════════════════════════════════════════════════════════
  // EXPORT CSV
  // ═══════════════════════════════════════════════════════════════════════
  app.get('/isc/admin/export.csv', scihRequired, async (req, res) => {
    try {
      const { instId } = await resolveInst(req);
      const q = req.query || {};
      const w = [], p = [];
      if (instId != null) { p.push(instId); w.push(`f.instituicao_id = $${p.length}`); }
      w.push(`f.status_vigilancia <> 'excluida'`);
      if (/^\d{4}-\d{2}$/.test(String(q.mes || ''))) {
        p.push(`${q.mes}-01`); w.push(`f.data_cirurgia >= $${p.length}::date`);
        p.push(`${q.mes}-01`); w.push(`f.data_cirurgia < ($${p.length}::date + INTERVAL '1 month')`);
      }
      if (q.equipe) { p.push(Number(q.equipe)); w.push(`f.equipe_id = $${p.length}`); }
      if (q.classif) { p.push(String(q.classif)); w.push(`f.isc_classificacao = $${p.length}`); }

      const { rows } = await pool.query(
        `SELECT f.id, f.paciente_nome, f.paciente_iniciais, f.prontuario, f.atendimento,
                e.nome AS equipe, f.procedimento, f.cirurgiao, f.data_cirurgia, f.data_alta,
                f.implante, f.potencial_contaminacao, f.asa, f.duracao_min,
                f.janelas, f.status_vigilancia, f.contatos_ok, f.tentativas_falhas,
                f.suspeita_isc, f.tem_alerta, f.isc_classificacao, f.isc_tipo,
                f.isc_data_diagnostico, f.isc_patogeno, f.isc_readmissao, f.isc_reabordagem,
                f.obito, f.obito_causa, f.classificado_por, f.classificado_em
           FROM isc_fichas f LEFT JOIN isc_equipes e ON e.id = f.equipe_id
          WHERE ${w.join(' AND ')}
          ORDER BY f.data_cirurgia DESC`, p);

      const cols = rows.length ? Object.keys(rows[0]) : ['id'];
      const esc = v => {
        if (v == null) return '';
        if (v instanceof Date) return toISODate(v);
        const s = typeof v === 'object' ? JSON.stringify(v) : String(v);
        return /[";\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
      };
      const csv = [cols.join(';'), ...rows.map(r => cols.map(c => esc(r[c])).join(';'))].join('\n');

      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="isc-${hojeISO()}.csv"`);
      res.send('\uFEFF' + csv);   // BOM: Excel-BR abre acentuação certa
    } catch (e) { erro(res, e); }
  });

  console.log('[isc-routes] rotas ISC registradas');
}
