// agenda-routes.js — Agenda do consultório (Lote 1).
// Visões dia/semana, CRUD de agendamentos, check-in com log, faturamento por
// evento (consulta + itens), feriados (BrasilAPI + seeds SP/Bragança/Campinas)
// e relatório mensal de faturamento (médico).
//
// Papéis (flags em users):
//   super_admin (médico)  → tudo, incl. relatório de faturamento
//   agenda (secretária)   → criar/editar/cancelar, registrar pagamento
//   recepcao (recepção)   → ver o dia + botão "Chegou" (log de horário)
//
// Uso em app.js:
//   import { registerAgendaRoutes } from './agenda-routes.js';
//   registerAgendaRoutes(app, pool, agendaRequired, renderShell);

import { criarEventoCalendar, atualizarEventoCalendar, removerEvento, googleConfigurado, testarConexao } from './agenda-google.js';

const safe = s => String(s ?? '')
  .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
  .replace(/"/g,'&quot;').replace(/'/g,'&#39;');

const TZ = 'America/Sao_Paulo';
const hojeSP = () => new Date().toLocaleDateString('en-CA', { timeZone: TZ }); // YYYY-MM-DD
const isDataValida = s => /^\d{4}-\d{2}-\d{2}$/.test(s || '') && !isNaN(new Date(s + 'T12:00:00').getTime());

const DIAS = ['domingo','segunda-feira','terça-feira','quarta-feira','quinta-feira','sexta-feira','sábado'];
const DIAS_ABREV = ['dom','seg','ter','qua','qui','sex','sáb'];
const MESES = ['janeiro','fevereiro','março','abril','maio','junho','julho','agosto','setembro','outubro','novembro','dezembro'];

function dObj(iso){ return new Date(iso + 'T12:00:00'); }               // meio-dia evita rollover de fuso
// node-postgres devolve coluna DATE como objeto Date; normaliza (Date OU string) para 'YYYY-MM-DD'
function isoDate(v){
  if (v instanceof Date && !isNaN(v)) {
    const y = v.getFullYear(), m = String(v.getMonth()+1).padStart(2,'0'), d = String(v.getDate()).padStart(2,'0');
    return `${y}-${m}-${d}`;
  }
  return String(v ?? '').slice(0,10);
}
function isoAdd(iso, dias){ const d = dObj(iso); if (isNaN(d)) return isoDate(iso); d.setDate(d.getDate()+dias); return d.toISOString().slice(0,10); }
function dataExtenso(iso){ const d = dObj(iso); return `${DIAS[d.getDay()]}, ${d.getDate()} de ${MESES[d.getMonth()]} de ${d.getFullYear()}`; }
function dataCurta(iso){ const d = dObj(iso); return `${String(d.getDate()).padStart(2,'0')}/${String(d.getMonth()+1).padStart(2,'0')}`; }
function dataBR(iso){ const d = dObj(iso); return `${String(d.getDate()).padStart(2,'0')}/${String(d.getMonth()+1).padStart(2,'0')}/${d.getFullYear()}`; }
function segundaDaSemana(iso){ const d = dObj(iso); const dow = d.getDay(); const delta = dow === 0 ? -6 : 1 - dow; return isoAdd(iso, delta); }
function horaHM(t){ return String(t || '').slice(0,5); }                 // '12:00:00' → '12:00'
function brl(n){ return Number(n || 0).toLocaleString('pt-BR', { style:'currency', currency:'BRL' }); }
function fmtTs(ts){ return ts ? new Date(ts).toLocaleString('pt-BR', { timeZone: TZ, day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit' }) : ''; }
function horaTs(ts){ return ts ? new Date(ts).toLocaleTimeString('pt-BR', { timeZone: TZ, hour:'2-digit', minute:'2-digit' }) : ''; }

// WhatsApp: normaliza telefone BR e monta link wa.me com a mensagem de lembrete pronta
function waNumero(tel){
  let d = String(tel || '').replace(/\D/g, '');
  if (!d) return null;
  if (d.length === 10 || d.length === 11) d = '55' + d;   // DDD+numero → prefixa país
  if (d.length < 12 || d.length > 13) return null;
  return d;
}
function waLink(ev){
  const n = waNumero(ev.paciente_telefone);
  if (!n) return null;
  const data = isoDate(ev.data);
  const onde = ev.modalidade === 'teleconsulta'
    ? (ev.link_video ? `por teleconsulta, no link: ${ev.link_video}` : 'por teleconsulta (o link será enviado em breve)')
    : (ev.local === 'campinas' ? 'na unidade de Campinas'
       : 'na Clínica Kadri (Praça Maastrich, 200, sala 64, Bragança Paulista)');
  const msg = `Olá, ${ev.paciente_nome}! Lembrete da sua consulta com o Dr. Leandro Mendes: ${dataBR(data)} às ${horaHM(ev.hora_inicio)}, ${onde}. Em caso de imprevisto, por favor avise. Obrigado!`;
  return `https://wa.me/${n}?text=${encodeURIComponent(msg)}`;
}

const TIPOS = {
  caso_novo:   { rotulo:'Caso novo',   cor:'#0c447c' },
  retorno:     { rotulo:'Retorno',     cor:'#1a7f4e' },
  reavaliacao: { rotulo:'Reavaliação', cor:'#b07d1a' },
  social:      { rotulo:'Social',      cor:'#7b4bb7' },
};
const STATUS = {
  agendado:       { rotulo:'Agendado',        cor:'#5b6472' },
  confirmado:     { rotulo:'Confirmado',      cor:'#0c447c' },
  chegou:         { rotulo:'Chegou',          cor:'#1a7f4e' },
  em_atendimento: { rotulo:'Em atendimento',  cor:'#b07d1a' },
  finalizado:     { rotulo:'Finalizado',      cor:'#2d6a4f' },
  faltou:         { rotulo:'Faltou',          cor:'#b3261e' },
  cancelado:      { rotulo:'Cancelado',       cor:'#8a8f98' },
};
const PAG = { pendente:{ rotulo:'Pendente', cor:'#b07d1a' }, pago:{ rotulo:'Pago', cor:'#1a7f4e' }, isento:{ rotulo:'Isento', cor:'#5b6472' } };
const MEIOS = { pix:'PIX', cartao_credito:'Cartão de crédito', cartao_debito:'Cartão de débito', dinheiro:'Dinheiro', transferencia:'Transferência', convenio:'Convênio', outro:'Outro' };
const LOCAIS = { braganca:'Bragança Paulista', campinas:'Campinas' };
const ESCOPOS = { nacional:'Nacional', estadual_sp:'Estadual (SP)', municipal_braganca:'Municipal — Bragança', municipal_campinas:'Municipal — Campinas' };

// Seeds fixos por ano (o que a BrasilAPI não cobre). Móveis nacionais vêm da API.
function seedsFixos(ano){
  return [
    { data:`${ano}-07-09`, nome:'Revolução Constitucionalista', escopo:'estadual_sp', facultativo:false },
    { data:`${ano}-12-08`, nome:'N. Sra. da Conceição (padroeira)', escopo:'municipal_braganca', facultativo:false },
    { data:`${ano}-12-15`, nome:'Aniversário de Bragança (facultativo)', escopo:'municipal_braganca', facultativo:true },
    { data:`${ano}-12-08`, nome:'N. Sra. da Conceição (padroeira)', escopo:'municipal_campinas', facultativo:false },
  ];
}

export function registerAgendaRoutes(app, pool, agendaRequired, renderShell) {

  // ===== papéis =====
  const isAdm    = req => req.cookies?.adm === '1';
  const isMedico = req => isAdm(req) || !!(req.user?.super_admin);
  const canEdit  = req => isMedico(req) || !!(req.user?.agenda);
  const canCheck = req => canEdit(req) || !!(req.user?.recepcao);
  const quem     = req => req.user?.full_name || req.user?.email || 'admin';
  const negar    = (res, msg) => res.status(403).send(renderShell('Sem permissão',
    `<div class="card"><h1>Sem permissão</h1><p class="mut">${safe(msg)}</p><a href="/agenda">← Agenda</a></div>`));

  // ===== fragmentos de UI =====
  const css = `
  <style>
    /* ===== app bar fixo ===== */
    .agbar{position:sticky;top:0;z-index:20;background:var(--pri);border-radius:16px;padding:12px 14px;margin-bottom:14px;box-shadow:0 4px 14px rgba(12,68,124,.18)}
    .agbar .r1{display:flex;align-items:center;justify-content:space-between;gap:8px}
    .agbar .r1 .t{color:#fff;font-size:16px;font-weight:700}
    .agmenu{position:relative}
    .agmenu>summary{list-style:none;cursor:pointer;color:#cfe1f5;width:38px;height:38px;border-radius:10px;background:rgba(255,255,255,.14);display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:700}
    .agmenu>summary::-webkit-details-marker{display:none}
    .agmenu[open]>summary{background:rgba(255,255,255,.28);color:#fff}
    .agmenu .drop{position:absolute;right:0;top:44px;background:#fff;border:1px solid var(--bd);border-radius:12px;box-shadow:0 8px 24px rgba(16,24,40,.16);min-width:180px;padding:6px;z-index:30}
    .agmenu .drop a{display:block;padding:11px 12px;border-radius:8px;text-decoration:none;color:var(--txt);font-weight:600;font-size:14px}
    .agmenu .drop a:hover{background:#f1f5ff}
    .agstep{display:flex;align-items:center;gap:8px;margin-top:12px}
    .agstep .arw{width:42px;height:42px;flex-shrink:0;border-radius:12px;background:rgba(255,255,255,.16);color:#fff;display:flex;align-items:center;justify-content:center;font-size:22px;text-decoration:none;font-weight:700}
    .agstep .arw:active{background:rgba(255,255,255,.32)}
    .agstep .ctr{flex:1;text-align:center;text-decoration:none;color:#fff;min-width:0}
    .agstep .ctr b{display:block;font-size:15px;font-weight:700;line-height:1.15;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .agstep .ctr span{font-size:11px;color:#b5d4f4}
    .agseg{display:flex;background:rgba(255,255,255,.16);border-radius:12px;padding:3px;margin-top:12px}
    .agseg a{flex:1;text-align:center;font-size:14px;font-weight:700;color:#cfe1f5;padding:9px;border-radius:9px;text-decoration:none}
    .agseg a.on{background:#fff;color:var(--pri)}

    /* ===== cards de evento ===== */
    .evcard{background:#fff;border:1px solid var(--bd);border-radius:14px;margin-top:10px;display:flex;overflow:hidden;box-shadow:0 1px 2px rgba(16,24,40,.05)}
    .evcard.cancelado{opacity:.5}
    .evrail{width:6px;flex-shrink:0}
    .evbody{flex:1;min-width:0;padding:11px 12px;display:flex;align-items:center;gap:11px}
    .evhr{text-align:center;flex-shrink:0;min-width:46px}
    .evhr b{display:block;font-size:16px;font-weight:800;color:var(--txt);line-height:1.1}
    .evhr span{font-size:10px;color:var(--mut)}
    .evmid{flex:1;min-width:0}
    .evmid .nm{display:block;font-size:14.5px;font-weight:700;color:var(--txt);text-decoration:none;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .evmeta{display:flex;align-items:center;gap:6px;margin-top:3px;min-width:0}
    .evmeta .dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
    .evmeta small{font-size:11.5px;color:var(--mut);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .evtag{font-size:10px;font-weight:700;padding:2px 7px;border-radius:999px;flex-shrink:0;white-space:nowrap}
    .evarrived{display:flex;align-items:center;gap:3px;font-size:10.5px;color:#1a7f4e;margin-top:4px}
    .evact{display:flex;gap:6px;flex-shrink:0}
    .evact form{margin:0}
    .tapbtn{width:46px;height:46px;border-radius:12px;display:flex;align-items:center;justify-content:center;text-decoration:none;font-size:19px;border:0;cursor:pointer;padding:0}
    .tapbtn.ch{background:var(--pri);color:#fff;font-size:20px;font-weight:700}
    .tapbtn.wa{background:#e1f5ee;color:#0f6e56;border:1px solid #b9e4d5}

    .fer-banner{background:#fdf3f3;border:1px solid #eecaca;border-radius:12px;padding:10px 14px;margin-top:10px;font-size:13px}

    /* ===== semana (grid no desktop, lista por dia no mobile) ===== */
    .semana{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-top:4px}
    .semana .dia{border:1px solid var(--bd);border-radius:14px;background:#fff;padding:10px}
    .semana .dia.hoje{border-color:var(--pri);box-shadow:0 0 0 2px rgba(12,68,124,.15)}
    .semana .dia.feriado{background:#fdf3f3}
    .semana .dia h3{margin:0 0 8px;font-size:13px}
    .semana .dia h3 a{text-decoration:none;color:var(--pri);font-weight:700}
    .semana .mini-ev{display:flex;align-items:center;gap:6px;font-size:12.5px;padding:8px 9px;border-radius:9px;color:#fff;margin-top:6px;text-decoration:none;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

    .kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:14px 0}
    .kpi{border:1px solid var(--bd);border-radius:14px;padding:14px;background:#fff}
    .kpi b{display:block;font-size:22px}.kpi span{color:var(--mut);font-size:12px}

    /* usados nas telas de detalhe / faturamento / feriados */
    .badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600;color:#fff;white-space:nowrap}
    .btn-mini{padding:8px 12px;font-size:13px;border-radius:9px}
    .btn-ghost{background:#fff;color:var(--pri);border:1px solid var(--pri)}
    .btn-red{background:#b3261e}
    .ag-nav{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
    .ag-nav a{display:inline-block;padding:8px 12px;border:1px solid var(--bd);border-radius:10px;background:#fff;text-decoration:none;font-weight:600}

    /* FAB */
    .fab{position:fixed;right:18px;bottom:22px;width:58px;height:58px;border-radius:18px;background:var(--pri);color:#fff;display:flex;align-items:center;justify-content:center;font-size:32px;line-height:1;text-decoration:none;box-shadow:0 8px 20px rgba(12,68,124,.4);z-index:40}
    .fab:active{filter:brightness(1.12)}

    @media (max-width:720px){
      .semana{grid-template-columns:1fr;gap:12px}
      .semana .dia{padding:12px}
      .semana .mini-ev{font-size:13.5px;padding:10px 11px}
    }
  </style>`;

  function badge(txt, cor){ return `<span class="badge" style="background:${cor}">${safe(txt)}</span>`; }
  function badgeTipo(t){ const x = TIPOS[t] || { rotulo:t, cor:'#5b6472' }; return badge(x.rotulo, x.cor); }
  function badgeStatus(s){ const x = STATUS[s] || { rotulo:s, cor:'#5b6472' }; return badge(x.rotulo, x.cor); }
  function badgePag(p){ const x = PAG[p] || { rotulo:p, cor:'#5b6472' }; return badge(x.rotulo, x.cor); }

  function topNav(req, dataIso, visao, subtitle){
    const isSem = visao === 'semana';
    const prev = isoAdd(dataIso, isSem ? -7 : -1);
    const next = isoAdd(dataIso, isSem ? 7 : 1);
    const base = isSem ? '/agenda/semana' : '/agenda/dia';
    let ctrB, ctrS;
    if (isSem){
      const seg = segundaDaSemana(dataIso), sab = isoAdd(seg, 5);
      ctrB = `${dataCurta(seg)} – ${dataCurta(sab)}`;
      const h = hojeSP();
      ctrS = (h >= seg && h <= sab) ? 'esta semana' : 'semana';
    } else {
      const d = dObj(dataIso);
      ctrB = `${DIAS_ABREV[d.getDay()]}, ${d.getDate()} ${MESES[d.getMonth()].slice(0,3)}`;
      ctrS = dataIso === hojeSP() ? 'hoje' : `${d.getFullYear()}`;
    }
    if (subtitle != null) ctrS = subtitle;
    const links = [];
    if (canEdit(req))  links.push(`<a href="/agenda/feriados">Feriados</a>`);
    if (isMedico(req)) links.push(`<a href="/agenda/faturamento">Faturamento</a>`);
    links.push(`<a href="/pront">Prontuário</a>`);
    return `<div class="agbar">
      <div class="r1">
        <span class="t">Agenda</span>
        <details class="agmenu"><summary aria-label="mais opções">⋯</summary>
          <div class="drop">${links.join('')}</div>
        </details>
      </div>
      <div class="agstep">
        <a class="arw" href="${base}/${prev}" aria-label="anterior">‹</a>
        <a class="ctr" href="${base}/${hojeSP()}"><b>${ctrB}</b><span>${ctrS}</span></a>
        <a class="arw" href="${base}/${next}" aria-label="próximo">›</a>
      </div>
      <div class="agseg">
        <a href="/agenda/dia/${dataIso}" class="${visao==='dia'?'on':''}">Dia</a>
        <a href="/agenda/semana/${dataIso}" class="${visao==='semana'?'on':''}">Semana</a>
      </div>
    </div>`;
  }

  // botão flutuante de novo agendamento (só para quem pode criar)
  function fab(dataIso){
    return `<a class="fab" href="/agenda/novo?data=${dataIso}" title="Novo agendamento" aria-label="Novo agendamento">+</a>`;
  }

  async function feriadosEntre(ini, fim){
    const { rows } = await pool.query(
      `SELECT * FROM agenda_feriados WHERE data BETWEEN $1 AND $2 ORDER BY data, escopo`, [ini, fim]);
    return rows;
  }

  function eventoCard(req, ev){
    const t = TIPOS[ev.tipo] || { cor:'#5b6472', rotulo:ev.tipo };
    const st = STATUS[ev.status] || { cor:'#5b6472', rotulo:ev.status };
    const isTele = ev.modalidade === 'teleconsulta';
    const localTxt = isTele ? 'Teleconsulta' : (LOCAIS[ev.local] || ev.local || '');
    // status no texto só quando é informativo (agendado é o "normal"; chegou tem linha própria)
    const statusExtra = ['agendado','chegou'].includes(ev.status) ? '' : ` · ${st.rotulo}`;
    const metaTxt = `${t.rotulo} · ${localTxt}${statusExtra}`;
    const dur = isTele ? 'tele' : `${ev.duracao_min}min`;
    const podeChegar = canCheck(req) && ['agendado','confirmado'].includes(ev.status);
    const wa = canEdit(req) && ['agendado','confirmado'].includes(ev.status) ? waLink(ev) : null;
    const pagTag = ev.pagamento_status === 'pendente'
      ? `<span class="evtag" style="background:#fbf0dc;color:#8a5d12">Pend.</span>`
      : ev.pagamento_status === 'pago'
        ? `<span class="evtag" style="background:#e1f3e8;color:#1a6b42">Pago</span>` : '';
    const arrived = ev.chegou_em ? `<div class="evarrived">✔ chegou ${horaTs(ev.chegou_em)}</div>` : '';
    const actions = (wa || podeChegar) ? `<div class="evact">
        ${wa ? `<a class="tapbtn wa" href="${wa}" target="_blank" rel="noopener" title="Lembrar via WhatsApp">💬</a>` : ''}
        ${podeChegar ? `<form method="post" action="/agenda/evento/${ev.id}/chegou">
          <button class="tapbtn ch" type="submit" title="Marcar chegada">✓</button></form>` : ''}
      </div>` : '';
    return `<div class="evcard ${ev.status==='cancelado'?'cancelado':''}">
      <div class="evrail" style="background:${t.cor}"></div>
      <div class="evbody">
        <div class="evhr"><b>${horaHM(ev.hora_inicio)}</b><span>${dur}</span></div>
        <div class="evmid">
          <a class="nm" href="/agenda/evento/${ev.id}">${safe(ev.paciente_nome)}</a>
          <div class="evmeta"><span class="dot" style="background:${st.cor}"></span><small>${safe(metaTxt)}</small></div>
          ${arrived}
        </div>
        ${pagTag}
        ${actions}
      </div>
    </div>`;
  }

  // ===== VISÃO DIA =====
  app.get(['/agenda','/agenda/dia','/agenda/dia/:data'], agendaRequired, async (req, res) => {
    const dataIso = isDataValida(req.params.data) ? req.params.data : hojeSP();
    const { rows: evs } = await pool.query(
      `SELECT * FROM agenda_eventos WHERE data=$1 ORDER BY hora_inicio, id`, [dataIso]);
    const fers = await feriadosEntre(dataIso, dataIso);
    const ferHtml = fers.length ? `<div class="fer-banner">🎌 ${fers.map(f =>
      `<b>${safe(f.nome)}</b> <span class="mut">(${ESCOPOS[f.escopo] || f.escopo}${f.facultativo ? ', facultativo' : ''})</span>`).join(' · ')}</div>` : '';
    const ativos = evs.filter(e => e.status !== 'cancelado').length;
    const sub = `${ativos} ${ativos === 1 ? 'paciente' : 'pacientes'}${dataIso === hojeSP() ? ' · hoje' : ''}`;
    const body = `${css}${topNav(req, dataIso, 'dia', sub)}
      ${ferHtml}
      ${evs.length ? evs.map(e => eventoCard(req, e)).join('')
        : '<div class="card"><p class="mut" style="margin:0">Nenhum agendamento neste dia.</p></div>'}
      ${canEdit(req) ? fab(dataIso) : ''}`;
    res.send(renderShell('Agenda — ' + dataBR(dataIso), body));
  });

  // ===== VISÃO SEMANA =====
  app.get(['/agenda/semana','/agenda/semana/:data'], agendaRequired, async (req, res) => {
    const ref = isDataValida(req.params.data) ? req.params.data : hojeSP();
    const seg = segundaDaSemana(ref);
    const sab = isoAdd(seg, 5);
    const { rows: evs } = await pool.query(
      `SELECT * FROM agenda_eventos WHERE data BETWEEN $1 AND $2 ORDER BY data, hora_inicio, id`, [seg, sab]);
    const fers = await feriadosEntre(seg, sab);
    const porDia = {}; for (let i=0;i<6;i++) porDia[isoAdd(seg,i)] = [];
    for (const e of evs) (porDia[isoDate(e.data)] ||= []).push(e);
    const ferPorDia = {}; for (const f of fers) (ferPorDia[isoDate(f.data)] ||= []).push(f);
    const hoje = hojeSP();
    const cols = Object.keys(porDia).map((iso, i) => {
      const fs = ferPorDia[iso] || [];
      const doDia = porDia[iso] || [];
      const ativosDia = doDia.filter(e => e.status !== 'cancelado').length;
      const evHtml = doDia.map(e => {
        const t = TIPOS[e.tipo] || { cor:'#5b6472' };
        const stc = (STATUS[e.status] || { cor:'#fff' }).cor;
        const risco = e.status === 'cancelado' ? 'text-decoration:line-through;opacity:.6;' : '';
        return `<a class="mini-ev" style="background:${t.cor};${risco}" href="/agenda/evento/${e.id}">
          <span style="width:7px;height:7px;border-radius:50%;background:${stc};flex-shrink:0;box-shadow:0 0 0 1.5px rgba(255,255,255,.7)"></span>
          ${horaHM(e.hora_inicio)} ${safe(e.paciente_nome)}${e.modalidade==='teleconsulta'?' 🖥':''}</a>`;
      }).join('');
      return `<div class="dia ${iso===hoje?'hoje':''} ${fs.length?'feriado':''}">
        <h3><a href="/agenda/dia/${iso}">${DIAS_ABREV[dObj(iso).getDay()]} ${dataCurta(iso)}${ativosDia?` · ${ativosDia}`:''}</a></h3>
        ${fs.map(f=>`<div style="font-size:11px;color:#a33">🎌 ${safe(f.nome)}</div>`).join('')}
        ${evHtml || '<span class="mut" style="font-size:12px">—</span>'}
      </div>`;
    }).join('');
    const body = `${css}${topNav(req, ref, 'semana')}
      <div class="semana">${cols}</div>
      ${canEdit(req) ? fab(ref) : ''}`;
    res.send(renderShell('Agenda — semana', body));
  });

  // ===== BUSCA DE PACIENTES (picker do formulário) =====
  app.get('/agenda/api/pacientes-busca', agendaRequired, async (req, res) => {
    const q = String(req.query.q || '').trim();
    if (q.length < 2) return res.json([]);
    const { rows } = await pool.query(
      `SELECT id, nome, to_char(dn,'DD/MM/YYYY') AS dn, telefone
         FROM pront_pacientes
        WHERE lower(nome) LIKE '%'||lower($1)||'%' OR id::text = $1
        ORDER BY nome LIMIT 12`, [q]);
    res.json(rows);
  });

  // ===== FORMULÁRIO (novo / editar) =====
  function formEvento(req, ev, erro){
    const e = ev || {};
    const dataIso = e.data ? isoDate(e.data) : (isDataValida(req.query?.data) ? req.query.data : hojeSP());
    const sel = (v, atual) => v === atual ? 'selected' : '';
    return `${css}
    <div class="card" style="max-width:680px;margin:0 auto">
      <h1 style="margin-top:0">${ev ? 'Editar agendamento' : 'Novo agendamento'}</h1>
      ${erro ? `<p style="color:#b3261e"><b>${safe(erro)}</b></p>` : ''}
      <form method="post" id="form-evento" action="${ev ? `/agenda/evento/${ev.id}/editar` : '/agenda/novo'}">
        <label>Paciente</label>
        <input id="pac-busca" autocomplete="off" placeholder="Buscar no prontuário (nome ou nº)…" value="">
        <div id="pac-result" style="border:1px solid var(--bd);border-radius:10px;display:none;background:#fff;max-height:180px;overflow:auto"></div>
        <input type="hidden" name="paciente_id" id="paciente_id" value="${safe(e.paciente_id || '')}">
        <div class="row mt">
          <div><label>Nome *</label><input name="paciente_nome" id="paciente_nome" required value="${safe(e.paciente_nome || '')}"></div>
          <div><label>Telefone</label><input name="paciente_telefone" id="paciente_telefone" value="${safe(e.paciente_telefone || '')}"></div>
        </div>
        <label>E-mail (lembrete)</label><input name="paciente_email" type="email" value="${safe(e.paciente_email || '')}">
        <div class="row mt">
          <div><label>Data *</label><input name="data" type="date" required value="${safe(dataIso)}"></div>
          <div><label>Hora *</label><input name="hora_inicio" type="time" required value="${safe(horaHM(e.hora_inicio) || '12:00')}" step="300"></div>
        </div>
        <div class="row mt">
          <div><label>Duração (min)</label><input name="duracao_min" type="number" min="5" step="5" value="${safe(e.duracao_min || 30)}"></div>
          <div><label>Tipo</label>
            <select name="tipo" id="f-tipo">
              ${Object.entries(TIPOS).map(([k,v]) => `<option value="${k}" ${sel(k, e.tipo || 'caso_novo')}>${v.rotulo}</option>`).join('')}
            </select></div>
        </div>
        <div class="row mt">
          <div><label>Modalidade</label>
            <select name="modalidade" id="f-modal">
              <option value="presencial" ${sel('presencial', e.modalidade || 'presencial')}>Presencial</option>
              <option value="teleconsulta" ${sel('teleconsulta', e.modalidade)}>Teleconsulta</option>
            </select></div>
          <div id="wrap-local"><label>Local</label>
            <select name="local">
              <option value="braganca" ${sel('braganca', e.local || 'braganca')}>Bragança Paulista</option>
              <option value="campinas" ${sel('campinas', e.local)}>Campinas</option>
            </select></div>
        </div>
        <div id="wrap-link" style="display:none"><label>Link da teleconsulta (Meet)</label>
          <input name="link_video" placeholder="deixe vazio para gerar um Meet automaticamente" value="${safe(e.link_video || '')}">
          <p class="mut" style="font-size:12px;margin:4px 0 0">Se ficar em branco, o sistema cria uma sala do Google Meet e a inclui no lembrete por e-mail e WhatsApp.</p></div>
        <div class="row mt">
          <div><label>Valor da consulta (R$)</label><input name="valor_consulta" id="f-valor" type="number" min="0" step="0.01" value="${safe(e.valor_consulta ?? '')}" placeholder="0,00"></div>
          <div><label>Pagamento</label>
            <select name="pagamento_status" id="f-pag">
              ${Object.entries(PAG).map(([k,v]) => `<option value="${k}" ${sel(k, e.pagamento_status || 'pendente')}>${v.rotulo}</option>`).join('')}
            </select></div>
        </div>
        <label>Observações</label><textarea name="obs" rows="2">${safe(e.obs || '')}</textarea>
        <div class="mt2" style="display:flex;gap:10px">
          <button type="submit" id="btn-salvar">${ev ? 'Salvar alterações' : 'Agendar'}</button>
          <a href="/agenda/dia/${dataIso}" style="align-self:center">Cancelar</a>
        </div>
      </form>
    </div>
    <script>
      (function(){
        var busca = document.getElementById('pac-busca'), box = document.getElementById('pac-result'), t;
        busca.addEventListener('input', function(){
          clearTimeout(t); var q = busca.value.trim();
          if (q.length < 2) { box.style.display='none'; return; }
          t = setTimeout(async function(){
            try{
              var r = await fetch('/agenda/api/pacientes-busca?q=' + encodeURIComponent(q));
              var list = await r.json();
              box.innerHTML = list.length ? list.map(function(p){
                return '<div class="pac-opt" data-id="'+p.id+'" data-nome="'+p.nome.replace(/"/g,'&quot;')+'" data-tel="'+(p.telefone||'')+'" style="padding:8px 12px;cursor:pointer;border-bottom:1px solid #eee">'+p.nome+' <span style="color:#888;font-size:12px">'+(p.dn||'')+'</span></div>';
              }).join('') : '<div style="padding:8px 12px;color:#888">Nenhum paciente encontrado — preencha o nome manualmente</div>';
              box.style.display='block';
            }catch(e){}
          }, 250);
        });
        box.addEventListener('click', function(ev){
          var el = ev.target.closest('.pac-opt'); if(!el) return;
          document.getElementById('paciente_id').value = el.dataset.id;
          document.getElementById('paciente_nome').value = el.dataset.nome;
          if (el.dataset.tel) document.getElementById('paciente_telefone').value = el.dataset.tel;
          busca.value = el.dataset.nome; box.style.display='none';
        });
        var tipo = document.getElementById('f-tipo'), pag = document.getElementById('f-pag'), valor = document.getElementById('f-valor');
        tipo.addEventListener('change', function(){
          if (tipo.value === 'reavaliacao' || tipo.value === 'social') { pag.value = 'isento'; if(!valor.value || valor.value==='0') valor.value = '0'; }
          else if (pag.value === 'isento') pag.value = 'pendente';
        });
        var modal = document.getElementById('f-modal'), wl = document.getElementById('wrap-local'), wk = document.getElementById('wrap-link');
        function ajModal(){ var tele = modal.value === 'teleconsulta'; wl.style.display = tele?'none':''; wk.style.display = tele?'':'none'; }
        modal.addEventListener('change', ajModal); ajModal();
      })();
      // trava anti-duplo-clique: desabilita o botão no 1º envio (o INSERT pode demorar se gerar Meet)
      (function(){
        var f = document.getElementById('form-evento'), b = document.getElementById('btn-salvar');
        if (!f || !b) return;
        f.addEventListener('submit', function(){
          if (f.dataset.enviando) return;
          f.dataset.enviando = '1';
          setTimeout(function(){ b.disabled = true; b.textContent = 'Aguarde…'; }, 0);
        });
      })();
    </script>`;
  }

  app.get('/agenda/novo', agendaRequired, (req, res) => {
    if (!canEdit(req)) return negar(res, 'Somente a secretaria ou o médico criam agendamentos.');
    res.send(renderShell('Novo agendamento', formEvento(req, null)));
  });

  function lerEvento(req){
    const b = req.body || {};
    const tipo = TIPOS[b.tipo] ? b.tipo : 'caso_novo';
    const isento = ['reavaliacao','social'].includes(tipo);
    return {
      paciente_id: b.paciente_id ? Number(b.paciente_id) : null,
      paciente_nome: String(b.paciente_nome || '').trim(),
      paciente_telefone: String(b.paciente_telefone || '').trim() || null,
      paciente_email: String(b.paciente_email || '').trim() || null,
      data: b.data, hora_inicio: b.hora_inicio,
      duracao_min: Math.max(5, Number(b.duracao_min) || 30),
      tipo,
      modalidade: b.modalidade === 'teleconsulta' ? 'teleconsulta' : 'presencial',
      local: b.modalidade === 'teleconsulta' ? null : (LOCAIS[b.local] ? b.local : 'braganca'),
      link_video: String(b.link_video || '').trim() || null,
      obs: String(b.obs || '').trim() || null,
      valor_consulta: b.valor_consulta !== '' && b.valor_consulta != null ? Number(b.valor_consulta) : (isento ? 0 : 0),
      pagamento_status: PAG[b.pagamento_status] ? b.pagamento_status : (isento ? 'isento' : 'pendente'),
    };
  }

  app.post('/agenda/novo', agendaRequired, async (req, res) => {
    if (!canEdit(req)) return negar(res, 'Somente a secretaria ou o médico criam agendamentos.');
    const e = lerEvento(req);
    if (!e.paciente_nome || !isDataValida(e.data) || !/^\d{2}:\d{2}/.test(e.hora_inicio || ''))
      return res.send(renderShell('Novo agendamento', formEvento(req, { ...req.body }, 'Preencha nome, data e hora.')));
    // Backstop anti-duplicata: se um evento idêntico foi criado há menos de 20s, é reenvio
    // acidental (duplo clique / timeout na criação do Meet) — reaproveita em vez de duplicar.
    // Overbooking intencional (mesmo horário de propósito) é feito com minutos de intervalo, então não é pego.
    const dup = await pool.query(
      `SELECT id FROM agenda_eventos
        WHERE paciente_nome=$1 AND data=$2 AND hora_inicio=$3 AND tipo=$4
          AND status <> 'cancelado' AND criado_em > now() - interval '20 seconds'
        ORDER BY id LIMIT 1`,
      [e.paciente_nome, e.data, e.hora_inicio, e.tipo]);
    if (dup.rows[0]) return res.redirect(`/agenda/evento/${dup.rows[0].id}`);
    const { rows } = await pool.query(
      `INSERT INTO agenda_eventos (paciente_id,paciente_nome,paciente_telefone,paciente_email,data,hora_inicio,duracao_min,
         tipo,modalidade,local,link_video,obs,valor_consulta,pagamento_status,criado_por)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id`,
      [e.paciente_id, e.paciente_nome, e.paciente_telefone, e.paciente_email, e.data, e.hora_inicio, e.duracao_min,
       e.tipo, e.modalidade, e.local, e.link_video, e.obs, e.valor_consulta, e.pagamento_status, quem(req)]);
    const novoId = rows[0].id;
    // Cria o evento no Google Calendar para TODO agendamento (best-effort, não bloqueia).
    // Teleconsulta sem link manual também gera uma sala do Meet.
    if (googleConfigurado()) {
      const comMeet = e.modalidade === 'teleconsulta' && !e.link_video;
      const g = await criarEventoCalendar({ id: novoId, ...e }, { comMeet });
      if (g) {
        const link = comMeet ? (g.meetLink || e.link_video) : e.link_video;
        await pool.query(
          `UPDATE agenda_eventos SET google_event_id=$1, link_video=$2 WHERE id=$3`,
          [g.eventId, link, novoId]);
      }
    }
    res.redirect(`/agenda/evento/${novoId}`);
  });

  // ===== AUTOTESTE DA CONEXÃO COM O GOOGLE CALENDAR (médico) =====
  app.get('/agenda/google/status', agendaRequired, async (req, res) => {
    if (!isMedico(req)) return negar(res, 'Diagnóstico restrito ao médico.');
    const r = await testarConexao();
    const cor = r.ok ? '#1a7f4e' : '#b3261e';
    const msg = !r.configurado
      ? 'As variáveis GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_REFRESH_TOKEN não estão no ambiente do Render.'
      : r.ok
        ? 'Conexão OK — o refresh token está válido e os agendamentos serão criados no Google Calendar.'
        : `Falha ao renovar o token. Isso normalmente significa refresh token expirado (app OAuth em modo "Testing" expira em 7 dias — publique o app) ou credenciais trocadas.<br><br><code>${safe(r.erro || '')}</code>`;
    const body = `${css}${topNav(req, hojeSP(), 'dia')}
      <div class="card" style="max-width:680px;margin:0 auto">
        <h1 style="margin-top:0;font-size:20px">Google Calendar — diagnóstico</h1>
        <p style="font-size:16px"><b style="color:${cor}">${r.ok ? '✓ Conectado' : '✕ Não conectado'}</b></p>
        <p class="mut">${msg}</p>
        <p class="mt"><a href="/agenda">← Voltar à agenda</a></p>
      </div>`;
    res.send(renderShell('Google Calendar — status', body));
  });

  // ===== DETALHE DO EVENTO =====
  app.get('/agenda/evento/:id', agendaRequired, async (req, res) => {
    const { rows } = await pool.query(`SELECT * FROM agenda_eventos WHERE id=$1`, [req.params.id]);
    const ev = rows[0];
    if (!ev) return res.status(404).send(renderShell('Não encontrado', `<div class="card"><h1>Agendamento não encontrado</h1><a href="/agenda">← Agenda</a></div>`));
    const { rows: itens } = await pool.query(`SELECT * FROM agenda_fatura_itens WHERE evento_id=$1 ORDER BY id`, [ev.id]);
    const { rows: lembretes } = await pool.query(`SELECT * FROM agenda_lembretes WHERE evento_id=$1 ORDER BY canal`, [ev.id]);
    const totalItens = itens.reduce((s,i) => s + Number(i.valor), 0);
    const total = Number(ev.valor_consulta) + totalItens;
    const dataIso = isoDate(ev.data);
    const podeEditar = canEdit(req);
    const sel = (v, atual) => v === atual ? 'selected' : '';

    const acoesStatus = podeEditar && ev.status !== 'cancelado' ? `
      <div class="mt" style="display:flex;gap:8px;flex-wrap:wrap">
        ${['confirmado','chegou','em_atendimento','finalizado','faltou'].filter(s => s !== ev.status).map(s =>
          `<form method="post" action="/agenda/evento/${ev.id}/status" style="display:inline">
             <input type="hidden" name="status" value="${s}">
             <button class="btn-mini btn-ghost" type="submit">${STATUS[s].rotulo}</button></form>`).join('')}
      </div>` : (canCheck(req) && ['agendado','confirmado'].includes(ev.status) ? `
      <form method="post" action="/agenda/evento/${ev.id}/chegou" class="mt">
        <button type="submit">Marcar chegada</button></form>` : '');

    const blocoPag = podeEditar ? `
      <form method="post" action="/agenda/evento/${ev.id}/pagamento" class="mt">
        <div class="row">
          <div><label>Valor da consulta (R$)</label><input name="valor_consulta" type="number" min="0" step="0.01" value="${safe(ev.valor_consulta)}"></div>
          <div><label>Status</label><select name="pagamento_status">
            ${Object.entries(PAG).map(([k,v]) => `<option value="${k}" ${sel(k, ev.pagamento_status)}>${v.rotulo}</option>`).join('')}
          </select></div>
        </div>
        <label>Meio de pagamento</label>
        <select name="pagamento_meio">
          <option value="">—</option>
          ${Object.entries(MEIOS).map(([k,v]) => `<option value="${k}" ${sel(k, ev.pagamento_meio)}>${v}</option>`).join('')}
        </select>
        <button class="mt" type="submit">Salvar pagamento</button>
      </form>` : '';

    const blocoItens = `
      <h3 class="mt2">Itens adicionais (exames / procedimentos)</h3>
      ${itens.length ? `<table><tr><th>Descrição</th><th>Valor</th>${podeEditar?'<th></th>':''}</tr>
        ${itens.map(i => `<tr><td>${safe(i.descricao)}</td><td>${brl(i.valor)}</td>
          ${podeEditar?`<td><form method="post" action="/agenda/item/${i.id}/excluir" class="inline"><button class="btn-mini btn-red" type="submit">×</button></form></td>`:''}</tr>`).join('')}
      </table>` : '<p class="mut">Nenhum item.</p>'}
      ${podeEditar ? `<form method="post" action="/agenda/evento/${ev.id}/item" class="mt">
        <div class="row">
          <div><label>Descrição</label><input name="descricao" required placeholder="ex.: Coleta de exames"></div>
          <div><label>Valor (R$)</label><input name="valor" type="number" min="0" step="0.01" required></div>
        </div>
        <button class="mt btn-mini" type="submit">+ Adicionar item</button>
      </form>` : ''}
      <p class="mt"><b>Total: ${brl(total)}</b> <span class="mut">(consulta ${brl(ev.valor_consulta)} + itens ${brl(totalItens)})</span></p>`;

    const blocoCancelar = podeEditar && ev.status !== 'cancelado' ? `
      <details class="mt2"><summary style="cursor:pointer;color:#b3261e">Cancelar agendamento…</summary>
        <form method="post" action="/agenda/evento/${ev.id}/cancelar" class="mt">
          <label>Motivo</label><input name="motivo" placeholder="opcional">
          <button class="mt btn-red" type="submit">Confirmar cancelamento</button>
        </form></details>` : '';

    const body = `${css}${topNav(req, dataIso, 'dia')}
    <div class="card" style="max-width:760px;margin:0 auto">
      <div style="display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;align-items:center">
        <h1 style="margin:0;font-size:22px">${safe(ev.paciente_nome)}</h1>
        <div>${badgeTipo(ev.tipo)} ${badgeStatus(ev.status)} ${badgePag(ev.pagamento_status)}</div>
      </div>
      <p class="mut" style="margin:6px 0 0">
        ${safe(dataExtenso(dataIso))} às ${horaHM(ev.hora_inicio)} (${ev.duracao_min} min) ·
        ${ev.modalidade === 'teleconsulta' ? `Teleconsulta${ev.link_video ? ` — <a href="${safe(ev.link_video)}" target="_blank" rel="noopener">abrir link</a>` : ' (sem link)'}` : safe(LOCAIS[ev.local] || '')}
      </p>
      ${ev.paciente_telefone || ev.paciente_email ? `<p class="mut" style="margin:4px 0 0">${safe(ev.paciente_telefone || '')} ${ev.paciente_email ? ' · ' + safe(ev.paciente_email) : ''}</p>` : ''}
      ${ev.paciente_id ? `<p style="margin:6px 0 0"><a href="/pront/paciente/${ev.paciente_id}">→ Ficha no prontuário</a></p>` : ''}
      ${ev.obs ? `<p class="mt">${safe(ev.obs)}</p>` : ''}
      ${ev.chegou_em ? `<p class="mut mt">✔ Chegada registrada em ${fmtTs(ev.chegou_em)} por ${safe(ev.chegou_por || '')}</p>` : ''}
      ${ev.status === 'cancelado' ? `<p class="mt" style="color:#b3261e">Cancelado em ${fmtTs(ev.cancelado_em)} por ${safe(ev.cancelado_por || '')}${ev.cancelamento_motivo ? ' — ' + safe(ev.cancelamento_motivo) : ''}</p>` : ''}
      ${ev.pagamento_status === 'pago' ? `<p class="mut">Pago em ${fmtTs(ev.pago_em)}${ev.pagamento_meio ? ' via ' + safe(MEIOS[ev.pagamento_meio] || ev.pagamento_meio) : ''} (${safe(ev.pagamento_por || '')})</p>` : ''}
      ${lembretes.length ? `<p class="mut" style="margin:4px 0 0">Lembretes: ${lembretes.map(l =>
        `${l.canal === 'email' ? '✉' : '💬'} ${l.status === 'enviado' ? 'enviado ' + fmtTs(l.enviado_em) : l.status}${l.status === 'erro' && l.erro ? ' <span title="' + safe(l.erro) + '">(!)</span>' : ''}`).join(' · ')}</p>`
        : (ev.paciente_email && !['cancelado','finalizado','faltou'].includes(ev.status) ? `<p class="mut" style="margin:4px 0 0">✉ Lembrete por e-mail será enviado automaticamente na véspera.</p>` : '')}
      ${isMedico(req) && ev.status !== 'cancelado' ? (ev.google_event_id
        ? `<p class="mut" style="margin:4px 0 0">📅 No Google Calendar</p>`
        : (googleConfigurado() ? `<p class="mut" style="margin:4px 0 0">📅 <span style="color:#b3261e">Não sincronizado</span> — <a href="/agenda/google/status">verificar conexão</a></p>` : '')) : ''}
      ${(() => { const wa = canEdit(req) && ev.status !== 'cancelado' ? waLink(ev) : null;
        return wa ? `<p class="mt"><a class="btn-mini btn-ghost" style="text-decoration:none;display:inline-block" href="${wa}" target="_blank" rel="noopener">💬 Enviar lembrete pelo WhatsApp</a></p>` : ''; })()}
      ${acoesStatus}
      ${podeEditar ? `<p class="mt"><a href="/agenda/evento/${ev.id}/editar">✎ Editar dados do agendamento</a></p>` : ''}
      <hr style="border:none;border-top:1px solid var(--bd);margin:18px 0">
      <h2 style="font-size:17px;margin:0">Faturamento</h2>
      ${blocoPag}
      ${blocoItens}
      ${blocoCancelar}
      <p class="mut mt2" style="font-size:12px">Criado por ${safe(ev.criado_por || '—')} em ${fmtTs(ev.criado_em)}${ev.atualizado_por ? ` · última alteração: ${safe(ev.atualizado_por)} em ${fmtTs(ev.atualizado_em)}` : ''}</p>
    </div>`;
    res.send(renderShell('Agendamento — ' + ev.paciente_nome, body));
  });

  app.get('/agenda/evento/:id/editar', agendaRequired, async (req, res) => {
    if (!canEdit(req)) return negar(res, 'Somente a secretaria ou o médico editam agendamentos.');
    const { rows } = await pool.query(`SELECT * FROM agenda_eventos WHERE id=$1`, [req.params.id]);
    if (!rows[0]) return res.redirect('/agenda');
    res.send(renderShell('Editar agendamento', formEvento(req, rows[0])));
  });

  app.post('/agenda/evento/:id/editar', agendaRequired, async (req, res) => {
    if (!canEdit(req)) return negar(res, 'Somente a secretaria ou o médico editam agendamentos.');
    const e = lerEvento(req);
    if (!e.paciente_nome || !isDataValida(e.data) || !/^\d{2}:\d{2}/.test(e.hora_inicio || ''))
      return res.send(renderShell('Editar agendamento', formEvento(req, { id: req.params.id, ...req.body }, 'Preencha nome, data e hora.')));

    // estado anterior para decidir a sincronização com o Calendar
    const prev = (await pool.query(`SELECT modalidade, google_event_id, link_video FROM agenda_eventos WHERE id=$1`, [req.params.id])).rows[0] || {};
    let googleId = prev.google_event_id || null;
    let linkFinal = e.link_video;

    if (googleConfigurado()) {
      const querMeet = e.modalidade === 'teleconsulta' && !e.link_video;
      const jaTemMeet = (prev.link_video || '').includes('meet.google.com');
      if (!prev.google_event_id) {
        // não havia evento no Calendar (agendamento antigo ou criação que falhou) → cria agora
        const g = await criarEventoCalendar({ id: req.params.id, ...e }, { comMeet: querMeet });
        if (g) { googleId = g.eventId; if (querMeet) linkFinal = g.meetLink || linkFinal; }
      } else if (querMeet && !jaTemMeet) {
        // passou a precisar de sala do Meet e ainda não tinha → recria (apaga o antigo, cria com Meet)
        await removerEvento(prev.google_event_id);
        const g = await criarEventoCalendar({ id: req.params.id, ...e }, { comMeet: true });
        if (g) { googleId = g.eventId; linkFinal = g.meetLink || linkFinal; }
      } else {
        // evento já existe e não precisa gerar Meet novo → só atualiza data/hora/dados
        await atualizarEventoCalendar(prev.google_event_id, { id: req.params.id, ...e });
        if (e.modalidade === 'teleconsulta' && !linkFinal) linkFinal = prev.link_video;
      }
    }

    await pool.query(
      `UPDATE agenda_eventos SET paciente_id=$1,paciente_nome=$2,paciente_telefone=$3,paciente_email=$4,data=$5,hora_inicio=$6,
         duracao_min=$7,tipo=$8,modalidade=$9,local=$10,link_video=$11,obs=$12,valor_consulta=$13,pagamento_status=$14,
         google_event_id=$15,atualizado_por=$16,atualizado_em=now()
       WHERE id=$17`,
      [e.paciente_id, e.paciente_nome, e.paciente_telefone, e.paciente_email, e.data, e.hora_inicio, e.duracao_min,
       e.tipo, e.modalidade, e.local, linkFinal, e.obs, e.valor_consulta, e.pagamento_status, googleId, quem(req), req.params.id]);
    res.redirect(`/agenda/evento/${req.params.id}`);
  });

  // check-in (recepção): grava horário e autor
  app.post('/agenda/evento/:id/chegou', agendaRequired, async (req, res) => {
    if (!canCheck(req)) return negar(res, 'Sua conta não tem permissão para registrar chegada.');
    const { rows } = await pool.query(
      `UPDATE agenda_eventos SET status='chegou', chegou_em=now(), chegou_por=$1, atualizado_por=$1, atualizado_em=now()
        WHERE id=$2 AND status IN ('agendado','confirmado') RETURNING data`, [quem(req), req.params.id]);
    res.redirect(rows[0] ? `/agenda/dia/${isoDate(rows[0].data)}` : '/agenda');
  });

  app.post('/agenda/evento/:id/status', agendaRequired, async (req, res) => {
    if (!canEdit(req)) return negar(res, 'Sem permissão para alterar o status.');
    const s = req.body?.status;
    if (!STATUS[s] || s === 'cancelado') return res.redirect(`/agenda/evento/${req.params.id}`);
    const extra = s === 'chegou' ? `, chegou_em=COALESCE(chegou_em, now()), chegou_por=COALESCE(chegou_por,$1)` : '';
    await pool.query(
      `UPDATE agenda_eventos SET status=$2, atualizado_por=$1, atualizado_em=now()${extra} WHERE id=$3`,
      [quem(req), s, req.params.id]);
    res.redirect(`/agenda/evento/${req.params.id}`);
  });

  app.post('/agenda/evento/:id/cancelar', agendaRequired, async (req, res) => {
    if (!canEdit(req)) return negar(res, 'Somente a secretaria ou o médico cancelam agendamentos.');
    // remove a sala do Meet do Calendar, se houver (best-effort); mantém link_video no registro para histórico
    const g = (await pool.query(`SELECT google_event_id FROM agenda_eventos WHERE id=$1`, [req.params.id])).rows[0];
    if (g?.google_event_id && googleConfigurado()) await removerEvento(g.google_event_id);
    await pool.query(
      `UPDATE agenda_eventos SET status='cancelado', cancelado_em=now(), cancelado_por=$1, cancelamento_motivo=$2,
         google_event_id=NULL, atualizado_por=$1, atualizado_em=now() WHERE id=$3`,
      [quem(req), String(req.body?.motivo || '').trim() || null, req.params.id]);
    res.redirect(`/agenda/evento/${req.params.id}`);
  });

  app.post('/agenda/evento/:id/pagamento', agendaRequired, async (req, res) => {
    if (!canEdit(req)) return negar(res, 'Sem permissão para registrar pagamento.');
    const st = PAG[req.body?.pagamento_status] ? req.body.pagamento_status : 'pendente';
    const meio = MEIOS[req.body?.pagamento_meio] ? req.body.pagamento_meio : null;
    const valor = Number(req.body?.valor_consulta) >= 0 ? Number(req.body.valor_consulta) : 0;
    await pool.query(
      `UPDATE agenda_eventos SET valor_consulta=$1, pagamento_status=$2, pagamento_meio=$3,
         pago_em = CASE WHEN $2='pago' THEN COALESCE(pago_em, now()) ELSE NULL END,
         pagamento_por = CASE WHEN $2='pago' THEN $4 ELSE NULL END,
         atualizado_por=$4, atualizado_em=now()
       WHERE id=$5`, [valor, st, meio, quem(req), req.params.id]);
    res.redirect(`/agenda/evento/${req.params.id}`);
  });

  app.post('/agenda/evento/:id/item', agendaRequired, async (req, res) => {
    if (!canEdit(req)) return negar(res, 'Sem permissão para editar o faturamento.');
    const desc = String(req.body?.descricao || '').trim();
    const valor = Number(req.body?.valor);
    if (desc && valor >= 0)
      await pool.query(`INSERT INTO agenda_fatura_itens (evento_id, descricao, valor, criado_por) VALUES ($1,$2,$3,$4)`,
        [req.params.id, desc, valor, quem(req)]);
    res.redirect(`/agenda/evento/${req.params.id}`);
  });

  app.post('/agenda/item/:id/excluir', agendaRequired, async (req, res) => {
    if (!canEdit(req)) return negar(res, 'Sem permissão para editar o faturamento.');
    const { rows } = await pool.query(`DELETE FROM agenda_fatura_itens WHERE id=$1 RETURNING evento_id`, [req.params.id]);
    res.redirect(rows[0] ? `/agenda/evento/${rows[0].evento_id}` : '/agenda');
  });

  // ===== FERIADOS =====
  app.get(['/agenda/feriados','/agenda/feriados/:ano'], agendaRequired, async (req, res) => {
    if (!canEdit(req)) return negar(res, 'Área da secretaria/médico.');
    const ano = /^\d{4}$/.test(req.params.ano || '') ? Number(req.params.ano) : Number(hojeSP().slice(0,4));
    const { rows: fers } = await pool.query(
      `SELECT * FROM agenda_feriados WHERE EXTRACT(YEAR FROM data)=$1 ORDER BY data, escopo`, [ano]);
    const body = `${css}${topNav(req, hojeSP(), 'dia')}
    <div class="card" style="max-width:760px;margin:0 auto">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
        <h1 style="margin:0;font-size:20px">Feriados de ${ano}</h1>
        <div class="ag-nav">
          <a href="/agenda/feriados/${ano-1}">‹ ${ano-1}</a>
          <a href="/agenda/feriados/${ano+1}">${ano+1} ›</a>
        </div>
      </div>
      <form method="post" action="/agenda/feriados/sync" class="mt">
        <input type="hidden" name="ano" value="${ano}">
        <button type="submit">↺ Sincronizar ${ano} (BrasilAPI + SP/Bragança/Campinas)</button>
      </form>
      ${fers.length ? `<table class="mt"><tr><th>Data</th><th>Feriado</th><th>Escopo</th><th></th></tr>
        ${fers.map(f => `<tr>
          <td>${dataBR(isoDate(f.data))}</td>
          <td>${safe(f.nome)}${f.facultativo ? ' <span class="mut">(facultativo)</span>' : ''}</td>
          <td>${ESCOPOS[f.escopo] || safe(f.escopo)}</td>
          <td><form method="post" action="/agenda/feriados/${f.id}/excluir" class="inline"><button class="btn-mini btn-red" type="submit">×</button></form></td>
        </tr>`).join('')}</table>` : '<p class="mut mt">Nenhum feriado cadastrado para este ano — use o sincronizar acima.</p>'}
      <h3 class="mt2">Adicionar manualmente</h3>
      <form method="post" action="/agenda/feriados/novo">
        <div class="row">
          <div><label>Data</label><input name="data" type="date" required></div>
          <div><label>Nome</label><input name="nome" required></div>
        </div>
        <div class="row mt">
          <div><label>Escopo</label><select name="escopo">
            ${Object.entries(ESCOPOS).map(([k,v]) => `<option value="${k}">${v}</option>`).join('')}
          </select></div>
          <div><label>Facultativo?</label><select name="facultativo"><option value="0">Não</option><option value="1">Sim</option></select></div>
        </div>
        <button class="mt" type="submit">Adicionar</button>
      </form>
    </div>`;
    res.send(renderShell('Feriados ' + ano, body));
  });

  app.post('/agenda/feriados/sync', agendaRequired, async (req, res) => {
    if (!canEdit(req)) return negar(res, 'Área da secretaria/médico.');
    const ano = /^\d{4}$/.test(req.body?.ano || '') ? Number(req.body.ano) : Number(hojeSP().slice(0,4));
    let inseridos = 0, erroApi = null;
    try {
      const r = await fetch(`https://brasilapi.com.br/api/feriados/v1/${ano}`);
      if (!r.ok) throw new Error('BrasilAPI HTTP ' + r.status);
      const nacionais = await r.json();
      for (const f of nacionais) {
        const q = await pool.query(
          `INSERT INTO agenda_feriados (data, nome, escopo, facultativo, origem)
           VALUES ($1,$2,'nacional',false,'api') ON CONFLICT (data, escopo, nome) DO NOTHING`, [f.date, f.name]);
        inseridos += q.rowCount;
      }
    } catch (e) { erroApi = e.message; }
    for (const f of seedsFixos(ano)) {
      const q = await pool.query(
        `INSERT INTO agenda_feriados (data, nome, escopo, facultativo, origem)
         VALUES ($1,$2,$3,$4,'seed') ON CONFLICT (data, escopo, nome) DO NOTHING`,
        [f.data, f.nome, f.escopo, f.facultativo]);
      inseridos += q.rowCount;
    }
    if (erroApi) console.error('[agenda] sync feriados: BrasilAPI falhou —', erroApi);
    res.redirect(`/agenda/feriados/${ano}`);
  });

  app.post('/agenda/feriados/novo', agendaRequired, async (req, res) => {
    if (!canEdit(req)) return negar(res, 'Área da secretaria/médico.');
    const b = req.body || {};
    if (isDataValida(b.data) && (b.nome || '').trim())
      await pool.query(
        `INSERT INTO agenda_feriados (data, nome, escopo, facultativo, origem)
         VALUES ($1,$2,$3,$4,'manual') ON CONFLICT (data, escopo, nome) DO NOTHING`,
        [b.data, b.nome.trim(), ESCOPOS[b.escopo] ? b.escopo : 'nacional', b.facultativo === '1']);
    res.redirect(`/agenda/feriados/${String(b.data || '').slice(0,4) || ''}`);
  });

  app.post('/agenda/feriados/:id/excluir', agendaRequired, async (req, res) => {
    if (!canEdit(req)) return negar(res, 'Área da secretaria/médico.');
    const { rows } = await pool.query(`DELETE FROM agenda_feriados WHERE id=$1 RETURNING data`, [req.params.id]);
    res.redirect(rows[0] ? `/agenda/feriados/${isoDate(rows[0].data).slice(0,4)}` : '/agenda/feriados');
  });

  // ===== FATURAMENTO MENSAL (médico) =====
  app.get('/agenda/faturamento', agendaRequired, async (req, res) => {
    if (!isMedico(req)) return negar(res, 'Relatório restrito ao médico.');
    const mes = /^\d{4}-\d{2}$/.test(req.query.mes || '') ? req.query.mes : hojeSP().slice(0,7);
    const ini = mes + '-01';
    const fim = isoAdd(isoAdd(ini, 32).slice(0,7) + '-01', -1);
    const { rows: evs } = await pool.query(
      `SELECT e.*, COALESCE((SELECT SUM(i.valor) FROM agenda_fatura_itens i WHERE i.evento_id=e.id),0) AS itens_total
         FROM agenda_eventos e
        WHERE e.data BETWEEN $1 AND $2 AND e.status <> 'cancelado'
        ORDER BY e.data, e.hora_inicio`, [ini, fim]);
    let previsto = 0, pago = 0, pendente = 0;
    const porMeio = {};
    for (const e of evs) {
      const tot = Number(e.valor_consulta) + Number(e.itens_total);
      previsto += tot;
      if (e.pagamento_status === 'pago') { pago += tot; porMeio[e.pagamento_meio || 'outro'] = (porMeio[e.pagamento_meio || 'outro'] || 0) + tot; }
      else if (e.pagamento_status === 'pendente') pendente += tot;
    }
    const [ano, m] = mes.split('-').map(Number);
    const prevMes = m === 1 ? `${ano-1}-12` : `${ano}-${String(m-1).padStart(2,'0')}`;
    const nextMes = m === 12 ? `${ano+1}-01` : `${ano}-${String(m+1).padStart(2,'0')}`;
    const body = `${css}${topNav(req, hojeSP(), 'dia')}
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
        <h1 style="margin:0;font-size:20px">Faturamento — ${MESES[m-1]} de ${ano}</h1>
        <div class="ag-nav"><a href="/agenda/faturamento?mes=${prevMes}">‹</a><a href="/agenda/faturamento?mes=${nextMes}">›</a></div>
      </div>
      <div class="kpis">
        <div class="kpi"><b>${brl(previsto)}</b><span>Previsto</span></div>
        <div class="kpi"><b style="color:#1a7f4e">${brl(pago)}</b><span>Recebido</span></div>
        <div class="kpi"><b style="color:#b07d1a">${brl(pendente)}</b><span>Pendente</span></div>
        <div class="kpi"><b>${evs.length}</b><span>Atendimentos (não cancelados)</span></div>
      </div>
      ${Object.keys(porMeio).length ? `<p class="mut">Recebido por meio: ${Object.entries(porMeio).map(([k,v]) => `${MEIOS[k] || k} ${brl(v)}`).join(' · ')}</p>` : ''}
      <table class="mt"><tr><th>Data</th><th>Paciente</th><th>Tipo</th><th>Status</th><th>Total</th><th>Pagamento</th></tr>
        ${evs.map(e => {
          const tot = Number(e.valor_consulta) + Number(e.itens_total);
          return `<tr>
            <td>${dataBR(isoDate(e.data))} ${horaHM(e.hora_inicio)}</td>
            <td><a href="/agenda/evento/${e.id}">${safe(e.paciente_nome)}</a></td>
            <td>${badgeTipo(e.tipo)}</td>
            <td>${badgeStatus(e.status)}</td>
            <td>${brl(tot)}</td>
            <td>${badgePag(e.pagamento_status)}${e.pagamento_meio ? ' <span class="mut">' + safe(MEIOS[e.pagamento_meio] || '') + '</span>' : ''}</td>
          </tr>`;
        }).join('')}
      </table>
      ${!evs.length ? '<p class="mut mt">Nenhum atendimento no mês.</p>' : ''}
    </div>`;
    res.send(renderShell('Faturamento ' + mes, body));
  });

  console.log('[agenda-routes] rotas registradas');
}
