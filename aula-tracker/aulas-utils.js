// ====== Utils compartilhados das rotas de aulas ======
// Extraído do app.js — sem alterações de comportamento.
// (fmtDT, que existia no app.js, era código morto e foi descartado.)

export const fmt = d => d ? new Date(d).toLocaleString('pt-BR') : '';

export function normalizeDateStr(s) {
  if (!s) return null;
  s = String(s).trim();
  if (!s) return null;
  if (/[zZ]|[+\-]\d{2}:\d{2}$/.test(s)) return s;
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return `${s}T23:59:59-03:00`;
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(s)) return `${s}:00-03:00`;
  const d = new Date(s);
  return isFinite(d) ? d.toISOString() : null;
}

export const fmtDTLocal = d => d ? new Date(d).toISOString().replace('T',' ').slice(0,16) : '';
