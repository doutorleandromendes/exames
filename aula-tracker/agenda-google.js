// agenda-google.js — integração com Google Calendar para TODOS os agendamentos.
// Cria um evento no Calendar do Dr. Leandro para cada consulta (presencial ou
// teleconsulta). Para teleconsulta sem link manual, gera também uma sala do Meet.
// Atualiza e remove o evento quando a consulta é remarcada ou cancelada.
//
// Autenticação: OAuth2 refresh-token flow, sem SDK — só fetch.
//   Env necessários (no Render): GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN.
//
// Filosofia: falha da API NUNCA derruba o agendamento. Em erro, o helper retorna
// null/false e a rota segue normalmente (o evento fica sem google_event_id).

const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const CAL_BASE = 'https://www.googleapis.com/calendar/v3/calendars/primary/events';
const TZ = 'America/Sao_Paulo';

const ENDERECOS = {
  braganca: 'Clínica Kadri — Euroville Tower Corporate, Praça Maastrich, 200, sala 64, Bragança Paulista-SP',
  campinas: 'Unidade Campinas',
};

export function googleConfigurado(){
  return !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && process.env.GOOGLE_REFRESH_TOKEN);
}

// normaliza data (objeto Date do pg OU string) para 'YYYY-MM-DD'
function isoDateLocal(v){
  if (v instanceof Date && !isNaN(v)) {
    const y = v.getFullYear(), m = String(v.getMonth()+1).padStart(2,'0'), d = String(v.getDate()).padStart(2,'0');
    return `${y}-${m}-${d}`;
  }
  return String(v ?? '').slice(0,10);
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
  const fimHHMM = fim => fmt(Math.min(fim, 23*60+59));
  return {
    start: { dateTime: `${dataIso}T${fmt(iniMin)}-03:00`, timeZone: TZ },
    end:   { dateTime: `${dataIso}T${fimHHMM(fimMin)}-03:00`, timeZone: TZ },
  };
}

function corpoEvento(ev){
  const data = isoDateLocal(ev.data);
  const { start, end } = janela(data, ev.hora_inicio, ev.duracao_min);
  const tele = ev.modalidade === 'teleconsulta';
  const body = {
    summary: `${tele ? 'Teleconsulta' : 'Consulta'} — ${ev.paciente_nome}`,
    description: `Consulta (${ev.tipo}) com Dr. Leandro Mendes.`
      + (ev.paciente_telefone ? `\nTelefone: ${ev.paciente_telefone}` : '')
      + (tele && ev.link_video ? `\nLink: ${ev.link_video}` : '')
      + (ev.obs ? `\n\n${ev.obs}` : ''),
    start, end,
  };
  const loc = tele ? '' : (ENDERECOS[ev.local] || '');
  if (loc) body.location = loc;
  if (ev.paciente_email) body.attendees = [{ email: ev.paciente_email }];
  return body;
}

// cria evento no Calendar. opts.comMeet=true anexa uma sala do Meet.
// Retorna { eventId, meetLink } ou null em falha.
export async function criarEventoCalendar(ev, opts = {}){
  if (!googleConfigurado()) return null;
  try {
    const at = await accessToken();
    const body = corpoEvento(ev);
    let url = `${CAL_BASE}?sendUpdates=none`;
    if (opts.comMeet) {
      body.conferenceData = {
        createRequest: {
          requestId: `kadri-${ev.id}-${Date.now()}`,
          conferenceSolutionKey: { type: 'hangoutsMeet' },
        },
      };
      url = `${CAL_BASE}?conferenceDataVersion=1&sendUpdates=none`;
    }
    const r = await fetch(url, {
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
    console.error('[agenda-google] criarEventoCalendar falhou:', e.message);
    return null;
  }
}

// atualiza data/hora/dados de um evento existente. Retorna true/false.
export async function atualizarEventoCalendar(eventId, ev){
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
    console.error('[agenda-google] atualizarEventoCalendar falhou:', e.message);
    return false;
  }
}

// remove o evento do Calendar (cancelamento). Retorna true/false.
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

// autoteste: verifica se o refresh token ainda gera access token válido.
// Retorna { configurado, ok, erro }.
export async function testarConexao(){
  if (!googleConfigurado()) return { configurado: false, ok: false, erro: 'GOOGLE_CLIENT_ID/SECRET/REFRESH_TOKEN ausentes no ambiente' };
  try {
    _tok = null; _exp = 0;          // força renovação real (não usa cache)
    await accessToken();
    return { configurado: true, ok: true, erro: null };
  } catch (e) {
    return { configurado: true, ok: false, erro: e.message };
  }
}
