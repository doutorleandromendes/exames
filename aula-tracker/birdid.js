// birdid.mjs — Assinatura ICP-Brasil (Bird ID / VaultID nuvem) para o gerador de documentos.
//
// Fluxo (3 chamadas à API Bird ID):
//   1) abrirSessao()   -> POST /v0/oauth/pwd_authorize   (OTP digitado 1x; token cobre a janela)
//   2) descobrirCertificado() -> GET /v0/oauth/certificate-discovery  (alias + PEM; cachear)
//   3) BirdIdSigner.sign() -> POST /v0/oauth/signature    (manda só o hash; recebe o CMS)
//
// A parte de PAdES (placeholder no PDF + embed do CMS + ByteRange) é do @signpdf.
// Requer Node 18+ (fetch global). Deps: @signpdf/signpdf @signpdf/placeholder-plain @signpdf/utils
//
// SEGURANÇA: client_secret e o access_token são SÓ do servidor. Nunca vão ao browser,
// nunca ao git. O access_token assina em nome do Dr. Leandro até expirar — trate como senha.

import crypto from 'crypto';
import { SignPdf, Signer } from '@signpdf/signpdf';
import { plainAddPlaceholder } from '@signpdf/placeholder-plain';
import { SUBFILTER_ETSI_CADES_DETACHED } from '@signpdf/utils';

const BASE = process.env.BIRDID_BASE || 'https://api.birdid.com.br';
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';

// ---------------------------------------------------------------------------
// 1) Abertura de sessão de assinatura. Digite o OTP (6 dígitos do app) UMA vez.
//    Devolve { access_token, expira_em (epoch ms), scope }. Guarde em memória no servidor.
// ---------------------------------------------------------------------------
export async function abrirSessao({ cpf, otp, lifetimeSeg = 4 * 3600 }) {
  const body = {
    client_id: process.env.BIRDID_CLIENT_ID,
    client_secret: process.env.BIRDID_CLIENT_SECRET,
    username: String(cpf).replace(/\D/g, '').padStart(11, '0'),
    password: String(otp).trim(),        // o OTP vai no campo password
    grant_type: 'password',
    scope: 'signature_session',          // sessão que permite múltiplas assinaturas
    lifetime: lifetimeSeg,               // PF: máx. 7 dias
  };
  const r = await fetch(`${BASE}/v0/oauth/pwd_authorize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) {
    throw new Error(`Bird ID auth falhou (${r.status}): ${JSON.stringify(j)}`);
  }
  return {
    access_token: j.access_token,
    scope: j.scope,
    expira_em: Date.now() + (j.expires_in ?? lifetimeSeg) * 1000,
  };
}

// ---------------------------------------------------------------------------
// 2) Lista os certificados da conta. Normalmente o médico tem 1 (e-CPF).
//    Cacheie o alias + PEM; muda só quando renova o certificado.
// ---------------------------------------------------------------------------
export async function descobrirCertificado(access_token) {
  const r = await fetch(`${BASE}/v0/oauth/certificate-discovery`, {
    headers: { Authorization: `Bearer ${access_token}`, Accept: 'application/json' },
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !Array.isArray(j.certificates) || !j.certificates.length) {
    throw new Error(`certificate-discovery falhou (${r.status}): ${JSON.stringify(j)}`);
  }
  const c = j.certificates[0];
  return { alias: c.alias, pem: c.certificate, todos: j.certificates };
}

// ---------------------------------------------------------------------------
// 3) Signer plugável do @signpdf. Recebe o conteúdo do ByteRange, manda só o
//    hash ao Bird ID, recebe o CMS-detached (DER) e o devolve pro @signpdf embutir.
// ---------------------------------------------------------------------------
export class BirdIdSigner extends Signer {
  constructor({ access_token, certificateAlias, incluirCadeia = true }) {
    super();
    this.token = access_token;
    this.alias = certificateAlias;
    this.incluirCadeia = incluirCadeia;
  }
  async sign(pdfBuffer /*, signingTime */) {
    const hashHex = crypto.createHash('sha256').update(pdfBuffer).digest('hex');
    const body = {
      certificate_alias: this.alias,
      include_chain: this.incluirCadeia,
      hashes: [{
        id: '1',
        alias: 'documento',
        hash: hashHex,
        hash_algorithm: OID_SHA256,
        signature_format: 'CMS',        // CMS-detached: messageDigest = o hash acima
      }],
    };
    const r = await fetch(`${BASE}/v0/oauth/signature`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.token}`,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(body),
    });
    const j = await r.json().catch(() => ({}));
    const raw = j?.signatures?.[0]?.raw_signature;
    if (!r.ok || !raw) {
      throw new Error(`Bird ID signature falhou (${r.status}): ${JSON.stringify(j)}`);
    }
    return Buffer.from(raw, 'base64');   // DER do CMS SignedData
  }
}

// ---------------------------------------------------------------------------
// Helper de alto nível: recebe o PDF (Buffer do Puppeteer) + sessão + alias,
// devolve o Buffer do PDF assinado ICP-Brasil.
// ---------------------------------------------------------------------------
export async function assinarPdf({ pdfBuffer, access_token, certificateAlias, meta = {} }) {
  const comPlaceholder = plainAddPlaceholder({
    pdfBuffer,
    reason: meta.reason || 'Documento médico',
    contactInfo: meta.contactInfo || 'lcmendes@gmail.com',
    name: meta.name || 'Dr. Leandro Mendes',
    location: meta.location || 'Bragança Paulista-SP',
    signatureLength: 16384,                      // folga p/ CMS com cadeia
    subFilter: SUBFILTER_ETSI_CADES_DETACHED,     // PAdES/ICP
  });
  const signer = new BirdIdSigner({ access_token, certificateAlias });
  return new SignPdf().sign(comPlaceholder, signer);
}
