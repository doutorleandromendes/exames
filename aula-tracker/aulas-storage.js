// ====== SigV4 (R2) — URLs assinadas para vídeos/PDFs das aulas ======
// Extraído do app.js — sem alterações de comportamento.
// Os helpers hmac/sha256Hex/getV4SigningKey do app.js eram código morto
// (generateSignedUrlForKey faz a cadeia HMAC inline) e foram descartados.

import crypto from 'crypto';

const R2_BUCKET = process.env.R2_BUCKET;
const R2_ENDPOINT = process.env.R2_ENDPOINT; // https://<ACCOUNT>.r2.cloudflarestorage.com
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY;

export function generateSignedUrlForKey(key, opts = {}) {
  const { contentType = 'video/mp4', disposition } = opts;
  if (!R2_BUCKET || !R2_ENDPOINT || !R2_ACCESS_KEY_ID || !R2_SECRET_ACCESS_KEY) return null;

  const urlObj = new URL(R2_ENDPOINT.replace(/\/+$/,''));
  const host = urlObj.host;

  const method = 'GET';
  const service = 's3';
  const region = 'auto';

  const encodedKey = String(key).split('/').map(encodeURIComponent).join('/');
  const canonicalUri = `/${encodeURIComponent(R2_BUCKET)}/${encodedKey}`;

  const now = new Date();
  const amzdate = now.toISOString().replace(/[:-]|\.\d{3}/g,''); // YYYYMMDDTHHMMSSZ
  const datestamp = amzdate.slice(0,8);
  const credentialScope = `${datestamp}/${region}/${service}/aws4_request`;

  const encodeRFC3986 = s => encodeURIComponent(s).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());

  const qp = [
    ['X-Amz-Algorithm','AWS4-HMAC-SHA256'],
    ['X-Amz-Credential', `${R2_ACCESS_KEY_ID}/${credentialScope}`],
    ['X-Amz-Date', amzdate],
    ['X-Amz-Expires', '86400'],
    ['X-Amz-SignedHeaders','host'],
  ];
  if (contentType) qp.push(['response-content-type', contentType]);
  if (disposition) qp.push(['response-content-disposition', disposition]);

  qp.sort((a,b)=> a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
  const canonicalQuerystring = qp.map(([k,v]) => `${encodeRFC3986(k)}=${encodeRFC3986(v)}`).join('&');

  const canonicalHeaders = `host:${host}\n`;
  const signedHeaders = 'host';
  const payloadHash = 'UNSIGNED-PAYLOAD';

  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQuerystring,
    canonicalHeaders,
    signedHeaders,
    payloadHash
  ].join('\n');

  const algorithm = 'AWS4-HMAC-SHA256';
  const stringToSign = [
    algorithm,
    amzdate,
    credentialScope,
    crypto.createHash('sha256').update(canonicalRequest).digest('hex')
  ].join('\n');

  const kDate = crypto.createHmac('sha256', 'AWS4' + R2_SECRET_ACCESS_KEY).update(datestamp).digest();
  const kRegion = crypto.createHmac('sha256', kDate).update(region).digest();
  const kService = crypto.createHmac('sha256', kRegion).update(service).digest();
  const kSigning = crypto.createHmac('sha256', kService).update('aws4_request').digest();

  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex');

  return `${R2_ENDPOINT.replace(/\/+$/,'')}/${encodeURIComponent(R2_BUCKET)}/${encodedKey}?${canonicalQuerystring}&X-Amz-Signature=${signature}`;
}
