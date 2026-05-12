// lab-storage.js
// Helpers de armazenamento R2 para imagens do portal de laudos
// Upload (PUT), fetch como data URI (para PDF) e delete

import crypto from 'crypto';

// ── Lê credenciais do ambiente em cada chamada (evita capturar antes de carregar) ──
const cfg = () => ({
  bucket:   process.env.R2_BUCKET,
  endpoint: (process.env.R2_ENDPOINT || '').replace(/\/+$/, ''),
  keyId:    process.env.R2_ACCESS_KEY_ID,
  secret:   process.env.R2_SECRET_ACCESS_KEY,
});

// ── Helpers SigV4 ──────────────────────────────────────────────────────────────
function hmac(key, msg)  { return crypto.createHmac('sha256', key).update(msg).digest(); }
function sha256hex(data) { return crypto.createHash('sha256').update(data).digest('hex'); }

// Hash canônico para body vazio (usado em GET e DELETE)
const EMPTY_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

function encodeR2Key(key) {
  return key.split('/').map(encodeURIComponent).join('/');
}

function signingKey(secret, datestamp) {
  const kDate    = hmac('AWS4' + secret, datestamp);
  const kRegion  = hmac(kDate,    'auto');
  const kService = hmac(kRegion,  's3');
  return         hmac(kService, 'aws4_request');
}

function buildAuthHeader({ method, key, payloadHash, amzdate, datestamp, host, contentType = null }) {
  const { keyId, secret, bucket } = cfg();
  const credentialScope = `${datestamp}/auto/s3/aws4_request`;
  const canonicalUri    = `/${encodeURIComponent(bucket)}/${encodeR2Key(key)}`;

  const headerLines = [
    contentType ? `content-type:${contentType}` : null,
    `host:${host}`,
    `x-amz-content-sha256:${payloadHash}`,
    `x-amz-date:${amzdate}`,
  ].filter(Boolean);

  const signedHeaders = headerLines.map(l => l.split(':')[0]).join(';');
  const canonicalHeaders = headerLines.join('\n') + '\n';

  const canonicalRequest = [
    method, canonicalUri, '',
    canonicalHeaders, signedHeaders, payloadHash,
  ].join('\n');

  const stringToSign = [
    'AWS4-HMAC-SHA256', amzdate, credentialScope,
    sha256hex(canonicalRequest),
  ].join('\n');

  const signature = crypto
    .createHmac('sha256', signingKey(secret, datestamp))
    .update(stringToSign)
    .digest('hex');

  return {
    authorization: `AWS4-HMAC-SHA256 Credential=${keyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
    signedHeaders,
  };
}

function nowParts() {
  const now       = new Date();
  const amzdate   = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const datestamp = amzdate.slice(0, 8);
  return { amzdate, datestamp };
}

// ── Upload de buffer para R2 (PUT) ─────────────────────────────────────────────
export async function uploadToR2(key, buffer, contentType) {
  const { bucket, endpoint, keyId, secret } = cfg();
  if (!bucket || !endpoint || !keyId || !secret) throw new Error('R2 não configurado');

  const host         = new URL(endpoint).host;
  const { amzdate, datestamp } = nowParts();
  const payloadHash  = sha256hex(buffer);

  const { authorization } = buildAuthHeader({
    method: 'PUT', key, payloadHash, amzdate, datestamp, host, contentType,
  });

  const url  = `${endpoint}/${encodeURIComponent(bucket)}/${encodeR2Key(key)}`;
  const resp = await fetch(url, {
    method: 'PUT',
    headers: {
      'Content-Type':          contentType,
      'Host':                  host,
      'X-Amz-Content-Sha256': payloadHash,
      'X-Amz-Date':           amzdate,
      'Authorization':        authorization,
    },
    body: buffer,
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`R2 PUT ${resp.status}: ${text.slice(0, 300)}`);
  }
  return key;
}

// ── Busca imagem do R2 e retorna como data URI base64 (para embutir no PDF) ────
export async function fetchR2ImageAsDataURI(key) {
  const { bucket, endpoint } = cfg();
  const host       = new URL(endpoint).host;
  const { amzdate, datestamp } = nowParts();

  const { authorization } = buildAuthHeader({
    method: 'GET', key, payloadHash: EMPTY_HASH, amzdate, datestamp, host,
  });

  const url  = `${endpoint}/${encodeURIComponent(bucket)}/${encodeR2Key(key)}`;
  const resp = await fetch(url, {
    headers: {
      'Host':                  host,
      'X-Amz-Content-Sha256': EMPTY_HASH,
      'X-Amz-Date':           amzdate,
      'Authorization':        authorization,
    },
  });

  if (!resp.ok) throw new Error(`R2 GET ${resp.status} — ${key}`);

  const buf  = await resp.arrayBuffer();
  const b64  = Buffer.from(buf).toString('base64');
  const ct   = resp.headers.get('content-type') || 'image/jpeg';
  return `data:${ct};base64,${b64}`;
}

// ── Remove objeto do R2 (best-effort, não lança em 404) ───────────────────────
export async function deleteFromR2(key) {
  try {
    const { bucket, endpoint } = cfg();
    const host       = new URL(endpoint).host;
    const { amzdate, datestamp } = nowParts();

    const { authorization } = buildAuthHeader({
      method: 'DELETE', key, payloadHash: EMPTY_HASH, amzdate, datestamp, host,
    });

    const url = `${endpoint}/${encodeURIComponent(bucket)}/${encodeR2Key(key)}`;
    await fetch(url, {
      method: 'DELETE',
      headers: {
        'Host':                  host,
        'X-Amz-Content-Sha256': EMPTY_HASH,
        'X-Amz-Date':           amzdate,
        'Authorization':        authorization,
      },
    });
  } catch (e) {
    console.warn('[lab-storage] deleteFromR2 best-effort error:', e.message);
  }
}
