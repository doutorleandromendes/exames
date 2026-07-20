// pav-routes.js
// ════════════════════════════════════════════════════════════════════════════
//  Rotas do módulo PAV (bundle de prevenção de PAV).
//
//  /pav/m               → FORM DO PLANTÃO (mobile-first, também serve desktop).
//                         Cada leito em VM vira um card; o profissional preenche
//                         o turno vigente da sua categoria. SSR no molde do /atb/m.
//  POST /pav/api/check/:fichaId → grava o registro do turno (fato, não julgamento).
//
//  Reuso / disciplina:
//   • turnoVigente / podeEscrever / itensDaCategoria / leitosVisiveis / saloesDoContexto
//     e extraiRegistro vêm do pav-core.js — a regra vive lá, testada. Aqui é só
//     I/O: query da população ativa, render, e persistência.
//   • tenant-lock por domínio (req.atbTenant) já restringe a instituição, como no
//     ATB. O recorte NOVO é o de SALÃO (leitosVisiveis), empilhado sobre o tenant.
//   • O grid do SCIH (/pav/admin/grid) e o painel entram DEPOIS, neste mesmo arquivo.
//
//  Assinatura (registrada no app.js):
//    registerPavRoutes(app, pool, pavRequired, renderShell);
// ════════════════════════════════════════════════════════════════════════════

import {
  turnoVigente, podeEscrever, itensDaCategoria, leitosVisiveis, saloesDoContexto,
  extraiRegistro, relacaoPF, REGISTRO, SALOES, SECRECAO_QUANTIDADE, SECRECAO_ASPECTO,
  SUBGLOTICA_VIA, SUBGLOTICA_VIA_DEFAULT, CATEGORIAS_PAV,
} from './pav-core.js';

function safe(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const SALAO_LABEL = Object.fromEntries(SALOES);
const TURNO_LABEL = { M: 'Manhã', T: 'Tarde', N: 'Noite', E: 'Madrugada' };

// Categoria de trabalho do req.user. super_admin sem categoria assume 'fisio'
// (só para poder ver/testar a tela — a escrita dele é sempre retroativa/livre).
function categoriaDe(user, adm) {
  if (user?.categoria_pav) return user.categoria_pav;
  if (user?.super_admin || adm) return 'fisio';
  return null;
}

// Contexto de escopo (turno × salão) a partir do req.user + sessão.
// O salão da enf vem do cookie de sessão pav_salao (seleção por sessão); a fisio
// alcança os dois. super_admin alcança tudo.
function contextoDe(req, adm) {
  return {
    super_admin: !!(req.user?.super_admin) || adm,
    categoria_pav: categoriaDe(req.user, adm),
    salao_sessao: req.cookies?.pav_salao || null,
  };
}

export function registerPavRoutes(app, pool, pavRequired, renderShell) {

  // Dias de VM (D+n) de um episódio até hoje — só para exibição no card.
  const dPlus = (intub) => {
    if (!intub) return '';
    const ini = new Date(intub); ini.setHours(0,0,0,0);
    const hoje = new Date(); hoje.setHours(0,0,0,0);
    const n = Math.floor((hoje - ini) / 86400000);
    return n >= 0 ? `D+${n}` : '';
  };

  // ── FORM DO PLANTÃO ───────────────────────────────────────────────────────
  app.get('/pav/m', pavRequired, async (req, res) => {
    try {
      const adm = req.cookies?.adm === '1';
      const ctx = contextoDe(req, adm);
      const vig = turnoVigente(new Date());
      const sigla = req.atbTenant || '';

      // A enfermagem precisa ter escolhido o salão da sessão. Se não escolheu
      // (e não é fisio/super), mostra o seletor de salão antes de tudo.
      const precisaEscolherSalao = ctx.categoria_pav === 'enf' && !ctx.salao_sessao && !ctx.super_admin;
      if (precisaEscolherSalao) {
        return res.send(renderSalaoPicker(sigla));
      }

      const saloesAlcance = saloesDoContexto(ctx);

      // População ativa: episódios em VM, no tenant, nos salões do contexto.
      const params = [];
      let where = 'f.ativo = true';
      if (sigla) { params.push(sigla); where += ` AND i.sigla = $${params.length}`; }
      if (saloesAlcance.length) {
        params.push(saloesAlcance);
        where += ` AND f.salao = ANY($${params.length}::text[])`;
      } else {
        where += ' AND false'; // sem alcance de salão → nada visível
      }

      const { rows: fichas } = await pool.query(`
        SELECT f.id, f.paciente_nome, f.paciente_nome_raw, f.prontuario, f.leito, f.salao,
               f.data_intubacao, f.numero_tubo, f.rima_labial,
               i.sigla AS instituicao
          FROM pav_fichas f
          LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
         WHERE ${where}
         ORDER BY f.salao, f.leito NULLS LAST, f.id`, params);

      // Já preenchidos neste turno vigente (para marcar o card como "feito").
      let feitos = new Set();
      if (vig && fichas.length) {
        const ids = fichas.map(f => f.id);
        const { rows } = await pool.query(
          `SELECT ficha_id FROM pav_checks WHERE ficha_id = ANY($1::int[]) AND data = $2 AND turno = $3`,
          [ids, vig.data, vig.turno]);
        feitos = new Set(rows.map(r => r.ficha_id));
      }

      res.send(renderForm({ sigla, ctx, vig, fichas, feitos, dPlus }));
    } catch (e) {
      console.error('ERRO /pav/m', e);
      res.status(500).send(renderShell('Erro', `<div class="card"><h1>Erro</h1><p class="mut">${safe(e.message)}</p></div>`));
    }
  });

  // Seleção de salão da enfermagem (grava cookie de sessão).
  app.post('/pav/salao', pavRequired, (req, res) => {
    const salao = SALAO_LABEL[req.body?.salao] ? req.body.salao : null;
    if (salao) res.cookie('pav_salao', salao, { httpOnly: true, sameSite: 'lax', maxAge: 16 * 3600 * 1000 });
    res.redirect('/pav/m');
  });
  app.get('/pav/trocar-salao', pavRequired, (req, res) => {
    res.clearCookie('pav_salao'); res.redirect('/pav/m');
  });

  // ── GRAVAÇÃO DO REGISTRO DO TURNO ─────────────────────────────────────────
  app.post('/pav/api/check/:fichaId', pavRequired, async (req, res) => {
    try {
      const adm = req.cookies?.adm === '1';
      const ctx = contextoDe(req, adm);
      const fichaId = parseInt(req.params.fichaId, 10);
      if (!Number.isFinite(fichaId)) return res.status(400).json({ erro: 'ficha inválida' });

      const { rows } = await pool.query(
        `SELECT f.id, f.salao, f.instituicao_id, i.sigla
           FROM pav_fichas f LEFT JOIN atb_instituicoes i ON i.id=f.instituicao_id
          WHERE f.id=$1 AND f.ativo=true`, [fichaId]);
      const ficha = rows[0];
      if (!ficha) return res.status(404).json({ erro: 'episódio não encontrado ou já encerrado' });

      // Tenant: não deixa gravar em ficha de outra unidade quando o portal é travado.
      if (req.atbTenant && ficha.sigla && ficha.sigla !== req.atbTenant && !ctx.super_admin)
        return res.status(403).json({ erro: 'episódio de outra unidade' });

      const vig = turnoVigente(new Date());
      const alvo = vig
        ? { data: vig.data, turno: vig.turno, salao: ficha.salao }
        : { data: null, turno: null, salao: ficha.salao };

      const perm = podeEscrever(alvo, ctx, new Date());
      if (!perm.permitido) return res.status(403).json({ erro: perm.motivo || 'sem permissão para este turno/salão' });

      // Registro factual (pav-core sanitiza e valida; motivos = rejeições factuais).
      const reg = extraiRegistro(req.body);
      if (reg.motivos.length) return res.status(400).json({ erro: reg.motivos[0], motivos: reg.motivos });

      const categoria = vig ? vig.categoria : ctx.categoria_pav;
      const nome = req.user?.full_name || null;
      // enf compartilhada: identificação digitada no ato (nome + COREN).
      const identificacao = (categoria === 'enf')
        ? String(req.body?.identificacao || '').trim().slice(0, 200) || null
        : null;

      // Upsert por (ficha, data, turno, categoria). Correção dentro do turno
      // vigente acumula histórico (mesma disciplina de atb_evolutivos). O
      // timestamp do histórico vem como parâmetro ($14) — evita depender de
      // função de formatação do banco e mantém o SQL portável.
      await pool.query(`
        INSERT INTO pav_checks
          (ficha_id, instituicao_id, data, turno, categoria, salao,
           itens, vent, secrecao, preenchido_por, preenchido_por_nome,
           identificacao_manual, retroativo)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
        ON CONFLICT (ficha_id, data, turno, categoria) DO UPDATE SET
          itens = EXCLUDED.itens, vent = EXCLUDED.vent, secrecao = EXCLUDED.secrecao,
          preenchido_por = EXCLUDED.preenchido_por, preenchido_por_nome = EXCLUDED.preenchido_por_nome,
          identificacao_manual = EXCLUDED.identificacao_manual, retroativo = EXCLUDED.retroativo,
          historico = pav_checks.historico || jsonb_build_object(
            'em', $14::text,
            'por', pav_checks.preenchido_por_nome,
            'itens', pav_checks.itens),
          updated_at = now()`,
        [ficha.id, ficha.instituicao_id, alvo.data, alvo.turno, categoria, ficha.salao,
         JSON.stringify(reg.itens), JSON.stringify(reg.vent),
         reg.secrecao ? JSON.stringify(reg.secrecao) : null,
         req.user?.id || null, nome, identificacao, !!perm.retroativo,
         new Date().toISOString()]);

      await pool.query(`UPDATE pav_fichas SET ultimo_check_em = now(), updated_at = now() WHERE id=$1`, [ficha.id]);

      res.json({ ok: true, retroativo: !!perm.retroativo });
    } catch (e) {
      console.error('ERRO POST /pav/api/check', e);
      res.status(500).json({ erro: e.message });
    }
  });

  // ══════════════════════════════════════════════════════════════════════════
  //  RENDER
  // ══════════════════════════════════════════════════════════════════════════
  function renderSalaoPicker(sigla) {
    const botoes = SALOES.map(([k, label]) =>
      `<form method="post" action="/pav/salao"><input type="hidden" name="salao" value="${safe(k)}">
       <button class="salao-btn" type="submit">${safe(label)}<span>${safe(k)}</span></button></form>`).join('');
    return `${HEAD(sigla, 'Selecionar salão')}
<div class="top"><div class="l1"><h1>Bundle PAV${sigla ? ' · ' + safe(sigla) : ''}</h1></div></div>
<div class="wrap">
  <p class="mut" style="margin:16px 4px">Selecione o salão em que você está neste plantão. Você só verá e registrará os leitos deste salão.</p>
  <div class="salao-grid">${botoes}</div>
</div>${FOOT()}`;
  }

  function renderForm({ sigla, ctx, vig, fichas, feitos, dPlus }) {
    const cat = ctx.categoria_pav;
    const catLabel = (CATEGORIAS_PAV.find(c => c[0] === cat) || [null, cat])[1] || '—';
    const itens = itensDaCategoria(cat);
    const semTurno = !vig;
    const turnoTxt = vig ? `${TURNO_LABEL[vig.turno]} · ${vig.data.split('-').reverse().join('/')}` : 'Fora de turno';

    // Aviso quando a categoria do usuário não bate com o turno vigente.
    const turnoDaOutra = vig && ctx.categoria_pav && vig.categoria !== ctx.categoria_pav && !ctx.super_admin;

    const salaoInfo = cat === 'enf' && ctx.salao_sessao
      ? `<a class="full" href="/pav/trocar-salao">${safe(SALAO_LABEL[ctx.salao_sessao] || ctx.salao_sessao)} ⇄</a>` : '';

    let corpo;
    if (semTurno) {
      corpo = `<div class="aviso">Nenhum turno vigente agora. O registro só é possível durante o turno cronológico da sua categoria.</div>`;
    } else if (turnoDaOutra) {
      corpo = `<div class="aviso">O turno vigente (${safe(TURNO_LABEL[vig.categoria] || vig.categoria)}) é da ${safe(vig.categoria)}. Sua categoria (${safe(catLabel)}) não registra agora.</div>`;
    } else if (!fichas.length) {
      corpo = `<div class="aviso">Nenhum paciente em ventilação mecânica ${cat === 'enf' && ctx.salao_sessao ? 'neste salão' : 'nos seus salões'} no momento.</div>`;
    } else {
      corpo = fichas.map(f => card(f, itens, feitos.has(f.id), cat, dPlus)).join('');
    }

    return `${HEAD(sigla, 'Plantão')}
<div class="top">
  <div class="l1">
    <h1>Bundle PAV${sigla ? ' · ' + safe(sigla) : ''}</h1>
    ${salaoInfo}
  </div>
  <div class="l2"><span class="turno">${safe(turnoTxt)}</span><span class="cat">${safe(catLabel)}</span></div>
</div>
<div class="wrap">${corpo}</div>
${SHEET(itens, cat)}
${FOOT()}
${SCRIPT()}`;
  }

  // Card de um leito.
  function card(f, itens, feito, cat, dPlus) {
    const nome = safe(f.paciente_nome || f.paciente_nome_raw || 'Paciente');
    const dp = dPlus(f.data_intubacao);
    const sub = [
      f.leito ? 'Leito ' + safe(f.leito) : '',
      SALAO_LABEL[f.salao] ? safe(SALAO_LABEL[f.salao]) : safe(f.salao || ''),
      f.numero_tubo ? 'TOT ' + safe(f.numero_tubo) : '',
      f.rima_labial ? 'rima ' + safe(f.rima_labial) : '',
    ].filter(Boolean).join(' · ');
    return `<div class="fcard ${feito ? 'done' : ''}" data-ficha="${f.id}" data-nome="${nome}" data-sub="${safe(sub)}">
      <div class="fc-head">
        <span class="nome">${nome}</span>
        ${dp ? `<span class="dp">${dp}</span>` : ''}
        ${feito ? '<span class="badge-ok">✓ turno</span>' : ''}
      </div>
      <div class="sub">${sub || '—'}</div>
      <button class="abrir" type="button" onclick="abrir(${f.id})">${feito ? 'Revisar turno' : 'Registrar turno'}</button>
    </div>`;
  }

  // Bottom-sheet: um formulário genérico para os itens da categoria + parâmetros.
  function SHEET(itens, cat) {
    const linhasItem = itens.map(c => {
      if (c.tipo === 'valor') {
        return `<div class="row"><label>${safe(c.label)}</label>
          <input type="number" inputmode="decimal" name="v_${c.key}" placeholder="${safe(c.unidade || '')}"></div>`;
      }
      // sim_nao
      let extra = '';
      if (c.via) {
        const opts = SUBGLOTICA_VIA.map(([k, l]) =>
          `<option value="${safe(k)}"${k === SUBGLOTICA_VIA_DEFAULT ? ' selected' : ''}>${safe(l)}</option>`).join('');
        extra = `<select class="via" name="via_${c.key}" style="display:none">${opts}</select>`;
      }
      let just = '';
      if (c.justifica_se_nao) {
        just = `<input class="just" name="j_${c.key}" placeholder="Justificativa (obrigatória se Não)" style="display:none">`;
      }
      return `<div class="row simnao" data-key="${c.key}"${c.via ? ' data-via="1"' : ''}${c.justifica_se_nao ? ' data-just="1"' : ''}>
        <label>${safe(c.label)}${c.per === 'dia' ? ' <span class="tag1x">1×/dia</span>' : ''}</label>
        <div class="sn">
          <button type="button" class="sim" onclick="sn(this,'sim')">Sim</button>
          <button type="button" class="nao" onclick="sn(this,'nao')">Não</button>
          <input type="hidden" name="r_${c.key}" value="">
        </div>
        ${extra}${just}
      </div>`;
    }).join('');

    const secQtd = SECRECAO_QUANTIDADE.map(([k, l]) => `<option value="${safe(k)}">${safe(l)}</option>`).join('');
    const secAsp = SECRECAO_ASPECTO.map(([k, l]) => `<option value="${safe(k)}">${safe(l)}</option>`).join('');

    const idEnf = cat === 'enf'
      ? `<div class="row"><label>Identificação (nome · COREN)</label>
         <input name="identificacao" placeholder="Seu nome e COREN" autocomplete="name"></div>` : '';

    return `<div class="sheet-bg" id="bg" onclick="fechar()"></div>
<div class="sheet" id="sheet">
  <div class="sh-head"><b id="sh-nome">—</b><span id="sh-sub" class="mut"></span><button class="x" onclick="fechar()">✕</button></div>
  <div class="sh-body">
    ${linhasItem}
    <div class="sec-tit">Parâmetros ventilatórios</div>
    <div class="grid2">
      <div class="row"><label>FiO₂ (%)</label><input type="number" inputmode="decimal" name="fio2" oninput="calcPF()"></div>
      <div class="row"><label>PEEP (cmH₂O)</label><input type="number" inputmode="decimal" name="peep"></div>
    </div>
    <div class="grid2">
      <div class="row"><label>PaO₂ (mmHg)</label><input type="number" inputmode="decimal" name="pao2" oninput="calcPF()"></div>
      <div class="row"><label>PaO₂/FiO₂</label><div class="pf" id="pf">—</div></div>
    </div>
    <div class="sec-tit">Secreção traqueal</div>
    <div class="grid2">
      <div class="row"><label>Quantidade</label><select name="sec_quantidade"><option value="">—</option>${secQtd}</select></div>
      <div class="row"><label>Aspecto</label><select name="sec_aspecto"><option value="">—</option>${secAsp}</select></div>
    </div>
    ${idEnf}
  </div>
  <div class="sh-foot">
    <span id="sh-msg" class="mut"></span>
    <button class="salvar" id="btn-salvar" onclick="salvar()">Salvar turno</button>
  </div>
</div>`;
  }

  // ── HTML shell (mobile PWA, paleta verde-clínico p/ distinguir do ATB azul) ──
  function HEAD(sigla, titulo) {
    return `<!doctype html><html lang="pt-BR"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover, maximum-scale=1, user-scalable=no">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="theme-color" content="#0e6b52">
<title>PAV${sigla ? ' · ' + safe(sigla) : ''} — ${safe(titulo)}</title>
<style>
  :root{--pri:#0e6b52;--pri-d:#0a5240;--bg:#eef4f1;--card:#fff;--ink:#1e293b;--mut:#64748b;
    --line:#e2e8f0;--ok:#0e7a4b;--warn:#b45309;--warn-bg:#fef3e2;--danger:#c0392b;
    --sat:env(safe-area-inset-top);--sab:env(safe-area-inset-bottom)}
  *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
  html,body{margin:0}
  body{font:15px/1.4 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--ink);padding-bottom:calc(16px + var(--sab))}
  .mut{color:var(--mut)}
  .top{position:sticky;top:0;z-index:50;background:var(--pri);color:#fff;padding:calc(10px + var(--sat)) 14px 10px;box-shadow:0 2px 8px rgba(0,0,0,.15)}
  .top .l1{display:flex;align-items:center;gap:10px}
  .top h1{font-size:16px;font-weight:700;margin:0;flex:1;letter-spacing:.2px}
  .top a.full{color:#fff;font-size:12px;opacity:.9;text-decoration:none;background:rgba(255,255,255,.16);border-radius:8px;padding:6px 10px}
  .top .l2{display:flex;gap:10px;margin-top:7px;font-size:12.5px}
  .top .turno{background:rgba(255,255,255,.18);border-radius:7px;padding:3px 9px;font-weight:600}
  .top .cat{background:rgba(255,255,255,.1);border-radius:7px;padding:3px 9px}
  .wrap{max-width:640px;margin:0 auto;padding:12px 12px 0}
  .aviso{background:var(--warn-bg);border:1px solid #f0d8b0;color:var(--warn);border-radius:12px;padding:14px 15px;font-size:14px;margin-top:6px}
  .fcard{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:13px 14px;margin:0 0 11px;box-shadow:0 1px 3px rgba(15,23,42,.05)}
  .fcard.done{border-color:#bfe3d3;background:#f6fbf9}
  .fc-head{display:flex;align-items:center;gap:8px}
  .fcard .nome{font-weight:700;font-size:15px;flex:1}
  .fcard .dp{font-size:12px;font-weight:700;color:var(--pri);background:#e2f2ec;border-radius:6px;padding:2px 7px}
  .fcard .badge-ok{font-size:11px;font-weight:700;color:var(--ok);background:#dff2e8;border-radius:6px;padding:2px 7px}
  .fcard .sub{font-size:12px;color:var(--mut);margin:3px 0 10px}
  .fcard .abrir{width:100%;font:inherit;font-size:14px;font-weight:600;padding:10px;border:0;border-radius:10px;background:var(--pri);color:#fff;cursor:pointer}
  .fcard.done .abrir{background:#fff;color:var(--pri);border:1.5px solid var(--pri)}
  .salao-grid{display:flex;flex-direction:column;gap:12px;margin-top:8px}
  .salao-btn{width:100%;font:inherit;font-size:17px;font-weight:600;padding:22px;border:1.5px solid var(--line);border-radius:14px;background:#fff;color:var(--ink);cursor:pointer;display:flex;flex-direction:column;gap:4px}
  .salao-btn span{font-size:12px;color:var(--mut);font-weight:400}
  /* bottom-sheet */
  .sheet-bg{position:fixed;inset:0;background:rgba(15,23,42,.4);opacity:0;pointer-events:none;transition:.2s;z-index:60}
  .sheet-bg.on{opacity:1;pointer-events:auto}
  .sheet{position:fixed;left:0;right:0;bottom:0;z-index:70;background:var(--bg);border-radius:18px 18px 0 0;transform:translateY(100%);transition:.25s;max-height:92vh;display:flex;flex-direction:column}
  .sheet.on{transform:translateY(0)}
  .sh-head{display:flex;align-items:center;gap:8px;padding:14px 16px calc(12px);border-bottom:1px solid var(--line);background:#fff;border-radius:18px 18px 0 0}
  .sh-head b{font-size:15px}.sh-head .x{margin-left:auto;background:none;border:0;font-size:18px;color:var(--mut);cursor:pointer}
  .sh-body{overflow-y:auto;padding:12px 16px;-webkit-overflow-scrolling:touch}
  .row{margin-bottom:12px}
  .row label{display:block;font-size:13px;color:var(--mut);margin-bottom:5px}
  .row input,.row select{width:100%;font:inherit;font-size:15px;padding:10px 12px;border:1.5px solid var(--line);border-radius:10px;background:#fff;-webkit-appearance:none;appearance:none}
  .tag1x{font-size:10px;background:#eef2f7;color:var(--mut);border-radius:5px;padding:1px 5px;font-weight:600}
  .sn{display:flex;gap:8px}
  .sn button{flex:1;font:inherit;font-size:14px;font-weight:600;padding:11px 0;border:1.5px solid var(--line);border-radius:10px;background:#fff;color:var(--ink);cursor:pointer}
  .sn button.sim.on{background:#dff2e8;border-color:#9fd8bf;color:var(--ok)}
  .sn button.nao.on{background:#fdecea;border-color:#f2b8b0;color:var(--danger)}
  .just{margin-top:8px}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  .sec-tit{font-size:13px;color:var(--mut);margin:16px 0 10px;padding-top:12px;border-top:1px solid var(--line)}
  .pf{font-size:18px;font-weight:700;padding:8px 0}
  .sh-foot{display:flex;align-items:center;gap:10px;padding:12px 16px calc(12px + var(--sab));border-top:1px solid var(--line);background:#fff}
  .sh-foot .salvar{margin-left:auto;font:inherit;font-size:15px;font-weight:700;padding:11px 22px;border:0;border-radius:10px;background:var(--pri);color:#fff;cursor:pointer}
  .sh-foot .salvar:disabled{opacity:.5}
</style></head><body>`;
  }
  function FOOT() { return `</body></html>`; }

  // ── Client: bottom-sheet, sim/não, P/F ao vivo, POST ──────────────────────
  function SCRIPT() {
    return `<script>
var atual=null;
function abrir(id){
  atual=id;
  var c=document.querySelector('.fcard[data-ficha="'+id+'"]');
  document.getElementById('sh-nome').textContent=c.dataset.nome||'';
  document.getElementById('sh-sub').textContent=c.dataset.sub||'';
  document.getElementById('sh-msg').textContent='';
  // limpa o form
  document.querySelectorAll('#sheet input,#sheet select').forEach(function(el){
    if(el.type==='hidden'){el.value='';} else if(el.tagName==='SELECT'){el.selectedIndex=el.classList.contains('via')?[].findIndex.call(el.options,function(o){return o.defaultSelected}):0;} else {el.value='';}
  });
  document.querySelectorAll('#sheet .sn button').forEach(function(b){b.classList.remove('on')});
  document.querySelectorAll('#sheet .via,#sheet .just').forEach(function(e){e.style.display='none'});
  document.getElementById('pf').textContent='—';
  document.getElementById('bg').classList.add('on');
  document.getElementById('sheet').classList.add('on');
}
function fechar(){document.getElementById('bg').classList.remove('on');document.getElementById('sheet').classList.remove('on');atual=null;}
function sn(btn,val){
  var row=btn.closest('.simnao');
  row.querySelectorAll('.sn button').forEach(function(b){b.classList.remove('on')});
  btn.classList.add('on');
  row.querySelector('input[type=hidden]').value=val;
  var via=row.querySelector('.via'), just=row.querySelector('.just');
  if(via) via.style.display=(val==='sim')?'block':'none';
  if(just) just.style.display=(val==='nao')?'block':'none';
}
function calcPF(){
  var f=parseFloat(document.querySelector('#sheet [name=fio2]').value);
  var p=parseFloat(document.querySelector('#sheet [name=pao2]').value);
  var el=document.getElementById('pf');
  if(f>0 && p>0){el.textContent=Math.round(p/(f/100));}else{el.textContent='—';}
}
function salvar(){
  if(!atual) return;
  var btn=document.getElementById('btn-salvar'); btn.disabled=true;
  var msg=document.getElementById('sh-msg'); msg.textContent='Salvando…';
  var data={};
  document.querySelectorAll('#sheet input,#sheet select').forEach(function(el){
    if(el.name && el.value!=='') data[el.name]=el.value;
  });
  fetch('/pav/api/check/'+atual,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)})
    .then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j}})})
    .then(function(x){
      if(!x.ok){ msg.textContent=x.j.erro||'Erro ao salvar'; btn.disabled=false; return; }
      var c=document.querySelector('.fcard[data-ficha="'+atual+'"]');
      if(c){c.classList.add('done'); var b=c.querySelector('.abrir'); if(b) b.textContent='Revisar turno';
        if(!c.querySelector('.badge-ok')){var s=document.createElement('span');s.className='badge-ok';s.textContent='✓ turno';c.querySelector('.fc-head').appendChild(s);}}
      fechar();
    })
    .catch(function(){ msg.textContent='Falha de conexão'; btn.disabled=false; });
}
</script>`;
  }
}
