// atb-tenant.js
// ──────────────────────────────────────────────────────────────────────────
// Tenant-lock (chokepoint único) para DASHBOARDS SEPARADOS sobre BANCO COMPARTILHADO.
//
// Modelo: todas as submissões dos dois hospitais vivem na MESMA base
// (atb_fichas, taggeadas por instituicao_id). O que precisa ser totalmente
// separado é a EXPERIÊNCIA DO CLIENTE — cada dashboard só enxerga o seu hospital,
// com sua identidade, e nunca vê o outro.
//
// Este módulo concentra TODA a separação num único ponto, para que haja só um
// lugar a revisar/blindar. Em vez de espalhar filtros por dezenas de rotas, um
// middleware:
//   1. resolve o TENANT do deploy (por env ATB_TENANT ou por subdomínio);
//   2. força req.query.inst = TENANT  → reaproveita o filtro já existente e
//      testado em buildGridWhere/servirFicha/getFormSchema;
//   3. força a instituição no submit público (anti-spoofing: o dashboard do H2
//      não consegue gravar como HUSF, nem o contrário);
//   4. guarda toda leitura/escrita de ficha-por-ID (anti-enumeração cross-tenant):
//      se a ficha não é do tenant → 404 (não revela existência do outro hospital).
//
// SEGURANÇA: o isolamento aqui é garantido EM CÓDIGO (banco compartilhado).
// Mantenha este arquivo como a única fonte da regra de separação.
//
// COMPATIBILIDADE: sem ATB_TENANT e sem ATB_TENANT_MAP, tenantFromReq() devolve
// null e o middleware é um no-op — o comportamento é IDÊNTICO ao atual
// (multi-tenant, seletor "Hospital" visível). O HUSF de hoje não muda em nada.
//
// MODELOS DE DEPLOY suportados (decisão na hora de subir, não trava o código):
//   • Por env  → dois serviços Render no MESMO DATABASE_URL, cada um com ATB_TENANT.
//   • Por host → um serviço só, ATB_TENANT_MAP='{"husf.dominio":"HUSF","h2.dominio":"H2"}'.
// ──────────────────────────────────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Mesma sanitização usada nas rotas (A–Z, 0–9, _), uppercased e limitada.
export function sanitizeSigla(s) {
  return String(s ?? '').toUpperCase().replace(/[^A-Z0-9_]/g, '').slice(0, 32);
}

// ── Resolução do tenant ─────────────────────────────────────────────────────
const ENV_TENANT = sanitizeSigla(process.env.ATB_TENANT || '');

const HOST_MAP = (() => {
  try {
    const raw = process.env.ATB_TENANT_MAP;
    if (!raw) return null;
    const obj = JSON.parse(raw);
    const out = {};
    for (const [host, sig] of Object.entries(obj)) {
      const h = String(host).toLowerCase().split(':')[0];
      const s = sanitizeSigla(sig);
      if (h && s) out[h] = s;
    }
    return Object.keys(out).length ? out : null;
  } catch (e) {
    console.warn('[atb-tenant] ATB_TENANT_MAP inválido (JSON):', e.message);
    return null;
  }
})();

function hostOf(req) {
  const raw = String(req.headers['x-forwarded-host'] || req.headers.host || '');
  return raw.toLowerCase().split(',')[0].trim().split(':')[0];
}

// Devolve a sigla do tenant travado para esta requisição, ou null (modo legado).
export function tenantFromReq(req) {
  if (ENV_TENANT) return ENV_TENANT;            // env trava o serviço inteiro
  if (HOST_MAP) {
    const h = hostOf(req);
    if (HOST_MAP[h]) return HOST_MAP[h];
  }
  return null;                                  // null → sem lock (comportamento atual)
}

export function isLocked(req) { return !!tenantFromReq(req); }

// Para diagnóstico/observabilidade no boot.
export function tenantMode() {
  if (ENV_TENANT) return { modo: 'env', tenant: ENV_TENANT };
  if (HOST_MAP) return { modo: 'host', mapa: HOST_MAP };
  return { modo: 'legado', tenant: null };
}

// ── Logo por tenant (branding) ──────────────────────────────────────────────
// Resolve a logo (data URI base64) do tenant: tenta atb-logo-<SIGLA>.b64 e cai
// no atb-logo.b64 global. Cache em memória por sigla. Usado por servirFicha e
// /atb/logo.png para suportar tanto o modelo por-env quanto o por-host.
const _logoCache = new Map();
export function getTenantLogo(sigla) {
  const key = sanitizeSigla(sigla) || '_default';
  if (_logoCache.has(key)) return _logoCache.get(key);
  let out = '';
  const candidatos = [];
  if (key !== '_default') candidatos.push(`atb-logo-${key}.b64`);
  candidatos.push('atb-logo.b64');
  for (const nome of candidatos) {
    try {
      out = fs.readFileSync(path.join(__dirname, nome), 'utf8').trim();
      if (out) break;
    } catch { /* tenta o próximo */ }
  }
  _logoCache.set(key, out);
  return out;
}

// ── Chokepoint: middleware único ────────────────────────────────────────────
// Captura o id da ficha em qualquer rota de ficha-por-id:
//   /atb/admin/fichas/123 · /atb/admin/ficha/123 · /atb/admin/api/ficha/123
//   /atb/admin/ficha/45/anexo/67 · /atb/admin/fichas/123/avaliar ...
const FICHA_ID_RE = /^\/atb\/admin\/(?:api\/)?fichas?\/(\d+)(?:\/|$)/;
const SUBMIT_PATH = '/atb/api/fichas';

export function tenantLock(pool) {
  return async function tenantLockMw(req, res, next) {
    const tenant = tenantFromReq(req);
    req.atbTenant = tenant;                 // exposto aos renderizadores (esconder seletor)
    if (!tenant) return next();             // modo legado → no-op
    if (!req.path || !req.path.startsWith('/atb')) return next();

    // (1) força o seletor de instituição em TODA rota /atb que o leia.
    if (req.query && typeof req.query === 'object') req.query.inst = tenant;

    // (2) força a instituição no submit público (anti-spoofing). Só no endpoint
    //     de submissão própria — NUNCA no webhook do JotForm (/atb/webhook).
    if (req.method === 'POST' && req.path === SUBMIT_PATH &&
        req.body && typeof req.body === 'object') {
      req.body.instituicao = tenant;
      if (req.body.dados && typeof req.body.dados === 'object') {
        req.body.dados.instituicao = tenant;
      }
    }

    // (3) guarda de ficha-por-id (anti-enumeração cross-tenant).
    const m = FICHA_ID_RE.exec(req.path);
    if (m) {
      const fid = m[1];
      try {
        const { rows } = await pool.query(
          `SELECT i.sigla
             FROM atb_fichas f
             LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
            WHERE f.id = $1`,
          [fid]
        );
        if (rows.length === 0) {
          // ficha inexistente: deixa a rota responder o 404 dela.
          return next();
        }
        const sig = sanitizeSigla(rows[0]?.sigla || '');
        // ficha de outro hospital OU sem instituição definida → 404 opaco.
        if (sig !== tenant) {
          return res.status(404).send('Ficha não encontrada');
        }
      } catch (e) {
        console.error('[atb-tenant] erro ao validar ficha cross-tenant:', e.message);
        return res.status(500).send('Erro interno');
      }
    }

    return next();
  };
}
