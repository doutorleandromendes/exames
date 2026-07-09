// agenda-lembretes.js — lembretes de consulta por e-mail, na véspera (D-1).
// Roda DENTRO do servidor (Render), num loop leve — não depende do worker do Mac.
// Reaproveita o mesmo Gmail do mailer.js (MAIL_USER / MAIL_PASS via env).
//
// Regras:
//   - Alvo: eventos de AMANHÃ (fuso America/Sao_Paulo) com status agendado|confirmado
//     e paciente_email preenchido.
//   - Janela de envio: 08:00–20:00 (hora de SP), para não mandar e-mail de madrugada.
//   - Idempotente: agenda_lembretes tem UNIQUE(evento_id, canal); só envia uma vez.
//     'erro' é retentado no ciclo seguinte (dentro da janela).
//   - Evento cancelado ou remarcado para outra data simplesmente sai do alvo.
//
// Uso em app.js:
//   import { startAgendaLembretes } from './agenda-lembretes.js';
//   startAgendaLembretes(pool);

import nodemailer from 'nodemailer';

const TZ = 'America/Sao_Paulo';
const INTERVALO_MS = 10 * 60 * 1000;   // verifica a cada 10 min

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.MAIL_USER, pass: process.env.MAIL_PASS }
});

const DIAS = ['domingo','segunda-feira','terça-feira','quarta-feira','quinta-feira','sexta-feira','sábado'];
const MESES = ['janeiro','fevereiro','março','abril','maio','junho','julho','agosto','setembro','outubro','novembro','dezembro'];

function hojeSP(){ return new Date().toLocaleDateString('en-CA', { timeZone: TZ }); }
function horaSP(){ return Number(new Date().toLocaleString('en-US', { timeZone: TZ, hour: '2-digit', hour12: false })); }
function amanhaSP(){ const d = new Date(hojeSP() + 'T12:00:00'); d.setDate(d.getDate() + 1); return d.toISOString().slice(0,10); }
function dataExtenso(iso){ const d = new Date(iso + 'T12:00:00'); return `${DIAS[d.getDay()]}, ${d.getDate()} de ${MESES[d.getMonth()]} de ${d.getFullYear()}`; }
function horaHM(t){ return String(t || '').slice(0,5); }

const ENDERECOS = {
  braganca: 'Clínica Kadri — Euroville Tower Corporate, Praça Maastrich, 200, sala 64, Bragança Paulista-SP',
  campinas: 'Unidade Campinas',
};

function montarEmail(ev){
  const data = String(ev.data).slice(0,10);
  const quando = `${dataExtenso(data)}, às ${horaHM(ev.hora_inicio)}`;
  const onde = ev.modalidade === 'teleconsulta'
    ? (ev.link_video
        ? `A consulta será por teleconsulta. Acesse pelo link: ${ev.link_video}`
        : 'A consulta será por teleconsulta — o link de acesso será enviado em breve.')
    : `Local: ${ENDERECOS[ev.local] || ev.local || 'Clínica Kadri, Bragança Paulista-SP'}.`;
  const texto = `Olá, ${ev.paciente_nome}!

Este é um lembrete da sua consulta com o Dr. Leandro Mendes (Infectologia):

${quando}
${onde}

Em caso de imprevisto, por favor avise com antecedência pelo telefone (11) 99611-2338.

Até breve!
Clínica Kadri`;
  const html = `<p>Olá, <b>${ev.paciente_nome}</b>!</p>
<p>Este é um lembrete da sua consulta com o <b>Dr. Leandro Mendes</b> (Infectologia):</p>
<p style="font-size:16px"><b>${quando}</b><br>${
    ev.modalidade === 'teleconsulta'
      ? (ev.link_video ? `Teleconsulta — <a href="${ev.link_video}">acessar pelo link</a>` : 'Teleconsulta — o link de acesso será enviado em breve.')
      : (ENDERECOS[ev.local] || 'Clínica Kadri, Bragança Paulista-SP')
  }</p>
<p>Em caso de imprevisto, por favor avise com antecedência pelo telefone <b>(11) 99611-2338</b>.</p>
<p>Até breve!<br>Clínica Kadri</p>`;
  return {
    from: `"Dr. Leandro Mendes — Clínica Kadri" <${process.env.MAIL_USER}>`,
    to: ev.paciente_email,
    subject: `Lembrete: consulta amanhã, ${horaHM(ev.hora_inicio)} — Dr. Leandro Mendes`,
    text: texto,
    html,
  };
}

async function processar(pool){
  if (!process.env.MAIL_USER || !process.env.MAIL_PASS) return;   // sem credencial, não faz nada
  const h = horaSP();
  if (h < 8 || h >= 20) return;                                   // janela 08–20h SP
  const alvo = amanhaSP();

  const { rows: eventos } = await pool.query(
    `SELECT e.* FROM agenda_eventos e
      WHERE e.data = $1
        AND e.status IN ('agendado','confirmado')
        AND e.paciente_email IS NOT NULL AND e.paciente_email <> ''
        AND NOT EXISTS (SELECT 1 FROM agenda_lembretes l
                         WHERE l.evento_id = e.id AND l.canal = 'email'
                           AND l.status IN ('enviado','cancelado'))
      ORDER BY e.hora_inicio`, [alvo]);

  for (const ev of eventos) {
    // garante a linha da fila (idempotente) e "reivindica" o envio
    await pool.query(
      `INSERT INTO agenda_lembretes (evento_id, canal, status, enviar_em)
       VALUES ($1,'email','pendente', now())
       ON CONFLICT (evento_id, canal) DO NOTHING`, [ev.id]);
    const claim = await pool.query(
      `UPDATE agenda_lembretes SET status='enviando'
        WHERE evento_id=$1 AND canal='email' AND status IN ('pendente','erro')
        RETURNING id`, [ev.id]);
    if (!claim.rows[0]) continue;   // outro ciclo já pegou / já enviado

    try {
      await transporter.sendMail(montarEmail(ev));
      await pool.query(
        `UPDATE agenda_lembretes SET status='enviado', enviado_em=now(), erro=NULL WHERE id=$1`,
        [claim.rows[0].id]);
      console.log(`[agenda-lembretes] enviado: evento ${ev.id} (${ev.paciente_email})`);
    } catch (e) {
      await pool.query(
        `UPDATE agenda_lembretes SET status='erro', erro=$2 WHERE id=$1`,
        [claim.rows[0].id, String(e.message || e).slice(0, 500)]);
      console.error(`[agenda-lembretes] erro no evento ${ev.id}:`, e.message);
    }
  }
}

export function startAgendaLembretes(pool){
  const tick = () => processar(pool).catch(e => console.error('[agenda-lembretes] ciclo falhou:', e.message));
  setInterval(tick, INTERVALO_MS);
  setTimeout(tick, 30 * 1000);   // primeiro ciclo 30 s após o boot (dá tempo das migrações)
  console.log('[agenda-lembretes] loop iniciado (a cada 10 min, janela 08–20h SP)');
}
