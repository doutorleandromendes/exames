// birdid-cades.mjs — Rota A: assinatura PAdES-B / CAdES-BES ICP-Brasil.
//
// Monta o CMS CAdES-B LOCALMENTE (com signing-certificate-v2), e terceiriza SÓ a
// operação RSA ao Bird ID no modo signature_format:"RAW". Assim o DER é limpo
// (sem o prefixo de lixo do modo "CMS") e carrega os atributos de perfil que o
// ITI exige — corrigindo as duas causas do "assinatura desconhecida".
//
// Deps: @signpdf/signpdf @signpdf/placeholder-plain @signpdf/utils asn1js
// Node 18+ (fetch global).

import crypto from 'crypto';
import * as asn1js from 'asn1js';
import { SignPdf, Signer } from '@signpdf/signpdf';
import { plainAddPlaceholder } from '@signpdf/placeholder-plain';
import { SUBFILTER_ETSI_CADES_DETACHED } from '@signpdf/utils';

const BASE = process.env.BIRDID_BASE || 'https://api.birdid.com.br';
const OID = {
  data: '1.2.840.113549.1.7.1', signedData: '1.2.840.113549.1.7.2',
  contentType: '1.2.840.113549.1.9.3', messageDigest: '1.2.840.113549.1.9.4',
  signingTime: '1.2.840.113549.1.9.5', signingCertV2: '1.2.840.113549.1.9.16.2.47',
  sha256: '2.16.840.1.101.3.4.2.1', rsa: '1.2.840.113549.1.1.1',
};

// ---------- mini DER ----------
const B = (ber) => Buffer.from(ber);
function tlv(tag, body) {
  const L = body.length; let len;
  if (L < 0x80) len = Buffer.from([L]);
  else { const b = []; let n = L; while (n > 0) { b.unshift(n & 0xff); n >>= 8; } len = Buffer.from([0x80 | b.length, ...b]); }
  return Buffer.concat([Buffer.from([tag]), len, body]);
}
const oidDer = (v) => B(new asn1js.ObjectIdentifier({ value: v }).toBER());
const nullP = () => Buffer.from([0x05, 0x00]);
const algId = (oid) => tlv(0x30, Buffer.concat([oidDer(oid), nullP()]));
const octet = (buf) => tlv(0x04, buf);
const attr = (typeOID, valueDer) => tlv(0x30, Buffer.concat([oidDer(typeOID), tlv(0x31, valueDer)]));
function setOf(bufs) {
  const s = [...bufs].sort((a, b) => { const n = Math.min(a.length, b.length); for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i]; return a.length - b.length; });
  const body = Buffer.concat(s);
  return { setDer: tlv(0x31, body), a0Der: tlv(0xA0, body) };
}
function pemToDer(pem) {
  const b64 = pem.replace(/-----BEGIN [^-]+-----/, '').replace(/-----END [^-]+-----/, '').replace(/\s+/g, '');
  return Buffer.from(b64, 'base64');
}
// extrai issuer(Name) DER + serialNumber(INTEGER) DER de um cert DER, sem libs pesadas
function certIssuerAndSerial(certDer) {
  const asn = asn1js.fromBER(new Uint8Array(certDer).buffer);
  const tbs = asn.result.valueBlock.value[0];       // TBSCertificate
  let i = 0;
  // pula version [0] EXPLICIT se presente
  if (tbs.valueBlock.value[0].idBlock.tagClass === 3) i = 1;
  const serial = tbs.valueBlock.value[i];            // INTEGER
  const issuer = tbs.valueBlock.value[i + 2];        // Name (após signature AlgId)
  return { issuerDer: B(issuer.toBER()), serialDer: B(serial.toBER()) };
}

// ---------- monta o CAdES-B; assina via rawSignHex(hashHex) => Buffer(RSA) ----------
export async function buildCadesCms({ pdfContent, signerCertDer, chainDers = [], rawSignHex }) {
  const { issuerDer, serialDer } = certIssuerAndSerial(signerCertDer);
  const msgDigest = crypto.createHash('sha256').update(pdfContent).digest();
  const certHash = crypto.createHash('sha256').update(signerCertDer).digest();

  // signing-certificate-v2
  const gnDirName = tlv(0xA4, issuerDer);                       // GeneralName [4] EXPLICIT Name
  const issuerSerial = tlv(0x30, Buffer.concat([tlv(0x30, gnDirName), serialDer]));
  const essCertId = tlv(0x30, Buffer.concat([algId(OID.sha256), octet(certHash), issuerSerial]));
  const scv2 = tlv(0x30, tlv(0x30, essCertId));

  // signed attributes
  const S = setOf([
    attr(OID.contentType, oidDer(OID.data)),
    attr(OID.messageDigest, octet(msgDigest)),
    attr(OID.signingTime, B(new asn1js.UTCTime({ valueDate: new Date() }).toBER())),
    attr(OID.signingCertV2, scv2),
  ]);
  const hashHex = crypto.createHash('sha256').update(S.setDer).digest('hex');

  // >>> operação RSA terceirizada (Bird ID RAW) <<<
  const signature = await rawSignHex(hashHex);

  // SignerInfo
  const sid = tlv(0x30, Buffer.concat([issuerDer, serialDer]));
  const signerInfo = tlv(0x30, Buffer.concat([
    B(new asn1js.Integer({ value: 1 }).toBER()), sid, algId(OID.sha256), S.a0Der, algId(OID.rsa), octet(signature),
  ]));

  // SignedData + ContentInfo
  const certsBag = Buffer.concat([signerCertDer, ...chainDers]);   // [0] IMPLICIT SET/SEQ OF Certificate
  const eci = tlv(0x30, oidDer(OID.data));                          // detached
  const signedData = tlv(0x30, Buffer.concat([
    B(new asn1js.Integer({ value: 1 }).toBER()), tlv(0x31, algId(OID.sha256)), eci, tlv(0xA0, certsBag), tlv(0x31, signerInfo),
  ]));
  return tlv(0x30, Buffer.concat([oidDer(OID.signedData), tlv(0xA0, signedData)]));
}

// ---------- Bird ID: RAW sign de um hash ----------
export function makeBirdIdRawSigner({ access_token, certificateAlias }) {
  return async function rawSignHex(hashHex) {
    const body = {
      certificate_alias: certificateAlias,
      hashes: [{ id: '1', alias: 'documento', hash: hashHex, hash_algorithm: OID.sha256, signature_format: 'RAW' }],
    };
    const r = await fetch(`${BASE}/v0/oauth/signature`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${access_token}`, 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(body),
    });
    const j = await r.json().catch(() => ({}));
    const raw = j?.signatures?.[0]?.raw_signature;
    if (!r.ok || !raw) throw new Error(`Bird ID RAW falhou (${r.status}): ${JSON.stringify(j)}`);
    return Buffer.from(raw, 'base64');
  };
}

// ---------- @signpdf Signer ----------
export class BirdIdCadesSigner extends Signer {
  constructor({ signerCertDer, chainDers = [], rawSignHex }) {
    super();
    this.signerCertDer = signerCertDer;
    this.chainDers = chainDers;
    this.rawSignHex = rawSignHex;
  }
  async sign(pdfBuffer) {
    return buildCadesCms({ pdfContent: pdfBuffer, signerCertDer: this.signerCertDer, chainDers: this.chainDers, rawSignHex: this.rawSignHex });
  }
}

// ---------- helper de alto nível ----------
export async function assinarPdfCades({ pdfBuffer, certificadosPem, rawSignHex, meta = {} }) {
  const [signerPem, ...chainPem] = certificadosPem;
  const signer = new BirdIdCadesSigner({
    signerCertDer: pemToDer(signerPem),
    chainDers: chainPem.map(pemToDer),
    rawSignHex,
  });
  const comPlaceholder = plainAddPlaceholder({
    pdfBuffer,
    reason: meta.reason || 'Documento médico',
    contactInfo: meta.contactInfo || 'lcmendes@gmail.com',
    name: meta.name || 'Dr. Leandro Mendes',
    location: meta.location || 'Bragança Paulista-SP',
    signatureLength: 16384,
    subFilter: SUBFILTER_ETSI_CADES_DETACHED,
  });
  return new SignPdf().sign(comPlaceholder, signer);
}

export { pemToDer };
