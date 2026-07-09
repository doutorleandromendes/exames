// agenda-google.js — integração com Google Calendar para teleconsultas.
// Cria um evento no Calendar do Dr. Leandro com uma sala do Meet única (gerada
// pelo próprio Google), retornando { eventId, meetLink }. Também atualiza e
// remove esse evento quando a consulta é remarcada ou cancelada.
//
// Autenticação: OAuth2 refresh-token flow, sem SDK — só fetch.
//   Env necessários (já no Render): GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN.
//
// Filosofia: falha da API NUNCA derruba o agendamento. Se algo der errado aqui,
// o helper retorna null e a rota segue normalmente (link fica vazio, editável à mão).

const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const CAL_BASE = 'https://www.googleapis.com/calendar/v3/calendars/primary/events';
const TZ = 'America/Sao_Paulo';

export function googleConfigurado(){
  return !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && process.env.GOOGLE_REFRESH_TOKEN);
}

// cache simples de access_token (vale ~1h; renova sob demanda com margem)
let _tok = null, _exp = 0;
async function accessToken(){
  if (_tok && Date.now() < _exp - 60000) return _tok;
  const r = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      refresh_token: process.env.GOOGLE_REFRESH_TOKEN,
      grant_type: 'refresh_token',
    }),
  });
  const j = await r.json();
  if (!r.ok || !j.access_token) throw new Error('token: ' + JSON.stringify(j));
  _tok = j.access_token;
  _exp = Date.now() + (Number(j.expires_in) || 3600) * 1000;
  return _tok;
}

// monta start/end RFC3339 com offset de São Paulo (-03:00; sem horário de verão no Brasil desde 2019)
function janela(dataIso, horaHM, duracaoMin){
  const [h, m] = String(horaHM).slice(0,5).split(':').map(Number);
  const iniMin = h * 60 + m;
  const fimMin = iniMin + (Number(duracaoMin) || 30);
  const fmt = (min) => `${String(Math.floor(min/60)).padStart(2,'0')}:${String(min%60).padStart(2,'0')}:00`;
  // fim pode passar de 24h em teoria (consulta longa de madrugada) — improvável aqui; clampa no mesmo dia
  const fimHHMM = fim => fmt(Math.min(fim, 23*60+59));
  return {
    start: { dateTime: `${dataIso}T${fmt(iniMin)}-03:00`, timeZone: TZ },
    end:   { dateTime: `${dataIso}T${fimHHMM(fimMin)}-03:00`, timeZone: TZ },
  };
}

function corpoEvento(ev){
  const data = String(ev.data).slice(0,10);
  const { start, end } = janela(data, ev.hora_inicio, ev.duracao_min);
  const body = {
    summary: `Teleconsulta — ${ev.paciente_nome}`,
    description: `Consulta (${ev.tipo}) com Dr. Leandro Mendes.${ev.obs ? '\n\n' + ev.obs : ''}`,
    start, end,
  };
  if (ev.paciente_email) body.attendees = [{ email: ev.paciente_email }];
  return body;
}

// cria evento com sala do Meet. Retorna { eventId, meetLink } ou null em falha.
export async function criarTeleconsulta(ev){
  if (!googleConfigurado()) return null;
  try {
    const at = await accessToken();
    const body = {
      ...corpoEvento(ev),
      conferenceData: {
        createRequest: {
          requestId: `kadri-${ev.id}-${Date.now()}`,
          conferenceSolutionKey: { type: 'hangoutsMeet' },
        },
      },
    };
    const r = await fetch(`${CAL_BASE}?conferenceDataVersion=1&sendUpdates=none`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${at}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const j = await r.json();
    if (!r.ok) throw new Error(JSON.stringify(j));
    const meetLink = j.hangoutLink
      || (j.conferenceData?.entryPoints || []).find(e => e.entryPointType === 'video')?.uri
      || null;
    return { eventId: j.id, meetLink };
  } catch (e) {
    console.error('[agenda-google] criarTeleconsulta falhou:', e.message);
    return null;
  }
}

// atualiza horário/dados de um evento já existente. Retorna true/false.
export async function atualizarTeleconsulta(eventId, ev){
  if (!googleConfigurado() || !eventId) return false;
  try {
    const at = await accessToken();
    const r = await fetch(`${CAL_BASE}/${encodeURIComponent(eventId)}?sendUpdates=none`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${at}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(corpoEvento(ev)),
    });
    if (!r.ok) throw new Error(JSON.stringify(await r.json()));
    return true;
  } catch (e) {
    console.error('[agenda-google] atualizarTeleconsulta falhou:', e.message);
    return false;
  }
}

// remove o evento do Calendar (cancelamento ou virou presencial). Retorna true/false.
export async function removerEvento(eventId){
  if (!googleConfigurado() || !eventId) return false;
  try {
    const at = await accessToken();
    const r = await fetch(`${CAL_BASE}/${encodeURIComponent(eventId)}?sendUpdates=none`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${at}` },
    });
    if (!r.ok && r.status !== 404 && r.status !== 410) throw new Error('HTTP ' + r.status);
    return true;
  } catch (e) {
    console.error('[agenda-google] removerEvento falhou:', e.message);
    return false;
  }
}
