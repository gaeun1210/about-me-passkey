// 패스키(WebAuthn) 확인 로직 — Node 내장 crypto만 사용합니다.
// 서버가 하는 일은 두 가지뿐입니다.
//  1) 등록: 기기가 보낸 "공개키"를 꺼내 저장한다 (개인키는 오지 않는다)
//  2) 로그인: 기기가 서버의 질문(challenge)에 한 서명을, 저장해 둔 공개키로 확인한다
import crypto from 'node:crypto';
import { decodeFirst } from './cbor.js';

export const b64u = {
  encode: (buf) => Buffer.from(buf).toString('base64url'),
  decode: (str) => {
    if (typeof str !== 'string' || !/^[A-Za-z0-9_-]*$/.test(str)) throw new AuthError(400, 'BAD_ENCODING', 'base64url 형식이 아닙니다');
    return Buffer.from(str, 'base64url');
  },
};

export class AuthError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}

export function newChallenge() {
  return b64u.encode(crypto.randomBytes(32)); // 32바이트 무작위 = 매번 다른 일회용 질문
}

const sha256 = (data) => crypto.createHash('sha256').update(data).digest();

// clientDataJSON: 브라우저가 "어느 사이트에서, 어떤 질문에, 무슨 목적으로" 서명했는지 적은 문서
export function readClientData(clientDataB64u) {
  const raw = b64u.decode(clientDataB64u);
  let data;
  try { data = JSON.parse(raw.toString('utf8')); } catch { throw new AuthError(400, 'BAD_CLIENT_DATA', 'clientDataJSON을 읽을 수 없습니다'); }
  if (typeof data.challenge !== 'string') throw new AuthError(400, 'BAD_CLIENT_DATA', '질문 값이 없습니다');
  return { raw, data };
}

export function checkClientData(data, expectedType, expectedOrigin) {
  if (data.type !== expectedType) throw new AuthError(400, 'WRONG_TYPE', `요청 종류가 다릅니다 (${data.type})`);
  if (data.origin !== expectedOrigin) throw new AuthError(401, 'WRONG_ORIGIN', `다른 사이트에서 만든 응답입니다 (${data.origin})`);
  if (data.crossOrigin === true) throw new AuthError(401, 'CROSS_ORIGIN', '다른 사이트 안에서 만든 응답입니다');
}

// authenticatorData 구조: rpIdHash(32) | flags(1) | signCount(4) | [aaguid(16) credIdLen(2) credId credentialPublicKey]
export function parseAuthData(buf) {
  if (buf.length < 37) throw new AuthError(400, 'BAD_AUTH_DATA', 'authenticatorData가 너무 짧습니다');
  const rpIdHash = buf.subarray(0, 32);
  const flagsByte = buf[32];
  const flags = {
    userPresent: !!(flagsByte & 0x01),
    userVerified: !!(flagsByte & 0x04),
    backupEligible: !!(flagsByte & 0x08),
    backedUp: !!(flagsByte & 0x10),
    attestedData: !!(flagsByte & 0x40),
    extensionData: !!(flagsByte & 0x80),
  };
  const signCount = buf.readUInt32BE(33);
  const out = { rpIdHash, flags, signCount };
  if (flags.attestedData) {
    if (buf.length < 55) throw new AuthError(400, 'BAD_AUTH_DATA', '공개키 정보가 잘렸습니다');
    const aaguid = buf.subarray(37, 53);
    const idLen = buf.readUInt16BE(53);
    const credId = buf.subarray(55, 55 + idLen);
    if (credId.length !== idLen) throw new AuthError(400, 'BAD_AUTH_DATA', '패스키 ID가 잘렸습니다');
    const [coseKey] = decodeFirst(buf, 55 + idLen);
    out.aaguid = formatAaguid(aaguid);
    out.credId = Buffer.from(credId);
    out.coseKey = coseKey;
  }
  return out;
}

function formatAaguid(b) {
  const h = Buffer.from(b).toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

// COSE 공개키 → JWK (Node crypto가 읽을 수 있는 형식)
// 허용 알고리즘: ES256(-7), EdDSA(-8), RS256(-257)
export function coseToJwk(cose) {
  if (!(cose instanceof Map)) throw new AuthError(400, 'BAD_KEY', '공개키 형식이 아닙니다');
  const kty = cose.get(1);
  const alg = cose.get(3);
  if (kty === 2 && alg === -7) {
    if (cose.get(-1) !== 1) throw new AuthError(400, 'BAD_KEY', 'P-256 곡선만 지원합니다');
    return { alg, jwk: { kty: 'EC', crv: 'P-256', x: b64u.encode(cose.get(-2)), y: b64u.encode(cose.get(-3)) } };
  }
  if (kty === 1 && alg === -8) {
    if (cose.get(-1) !== 6) throw new AuthError(400, 'BAD_KEY', 'Ed25519만 지원합니다');
    return { alg, jwk: { kty: 'OKP', crv: 'Ed25519', x: b64u.encode(cose.get(-2)) } };
  }
  if (kty === 3 && alg === -257) {
    return { alg, jwk: { kty: 'RSA', n: b64u.encode(cose.get(-1)), e: b64u.encode(cose.get(-2)) } };
  }
  throw new AuthError(400, 'UNSUPPORTED_ALG', `지원하지 않는 서명 방식입니다 (kty ${kty}, alg ${alg})`);
}

export function jwkToPem(jwk) {
  return crypto.createPublicKey({ key: jwk, format: 'jwk' }).export({ type: 'spki', format: 'pem' });
}

function verifySignature(alg, jwk, data, signature) {
  const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  if (alg === -7) return crypto.verify('sha256', data, { key, dsaEncoding: 'der' }, signature);
  if (alg === -257) return crypto.verify('sha256', data, key, signature);
  if (alg === -8) return crypto.verify(null, data, key, signature);
  return false;
}

// ── 등록 확인 ─────────────────────────────────────────────
// 들어오는 것: clientDataJSON, attestationObject (둘 다 공개 정보). 개인키 항목은 형식상 존재하지 않습니다.
export function verifyRegistration({ credential, expectedOrigin, rpId }) {
  if (!credential || credential.type !== 'public-key' || !credential.response) {
    throw new AuthError(400, 'BAD_REQUEST', '패스키 등록 응답이 아닙니다');
  }
  const { data: clientData } = readClientData(credential.response.clientDataJSON);
  checkClientData(clientData, 'webauthn.create', expectedOrigin);

  const attObjBuf = b64u.decode(credential.response.attestationObject);
  const [attObj] = decodeFirst(attObjBuf);
  if (!(attObj instanceof Map) || !Buffer.isBuffer(attObj.get('authData'))) {
    throw new AuthError(400, 'BAD_ATTESTATION', 'attestationObject를 읽을 수 없습니다');
  }
  const auth = parseAuthData(attObj.get('authData'));

  if (!auth.rpIdHash.equals(sha256(rpId))) throw new AuthError(401, 'WRONG_RP', '이 사이트용으로 만든 패스키가 아닙니다');
  if (!auth.flags.userPresent) throw new AuthError(401, 'NO_USER_PRESENCE', '사용자 확인(터치)이 없었습니다');
  if (!auth.flags.attestedData || !auth.credId) throw new AuthError(400, 'NO_KEY', '공개키가 들어 있지 않습니다');

  const credId = b64u.encode(auth.credId);
  if (credential.id !== credId) throw new AuthError(400, 'ID_MISMATCH', '패스키 ID가 서로 다릅니다');

  const { alg, jwk } = coseToJwk(auth.coseKey);
  const publicKeyPem = jwkToPem(jwk); // 여기서 한 번 열어 보아 올바른 공개키인지 확인

  return {
    challenge: clientData.challenge,
    credId,
    alg,
    jwk,
    publicKeyPem,
    signCount: auth.signCount,
    aaguid: auth.aaguid,
    userVerified: auth.flags.userVerified,
    backupEligible: auth.flags.backupEligible,
    backedUp: auth.flags.backedUp,
    fmt: attObj.get('fmt'),
  };
}

// ── 로그인 확인 ───────────────────────────────────────────
export function verifyAuthentication({ credential, stored, expectedOrigin, rpId }) {
  const r = credential.response;
  const { raw: clientDataRaw, data: clientData } = readClientData(r.clientDataJSON);
  checkClientData(clientData, 'webauthn.get', expectedOrigin);

  const authDataBuf = b64u.decode(r.authenticatorData);
  const auth = parseAuthData(authDataBuf);
  if (!auth.rpIdHash.equals(sha256(rpId))) throw new AuthError(401, 'WRONG_RP', '이 사이트용 패스키가 아닙니다');
  if (!auth.flags.userPresent) throw new AuthError(401, 'NO_USER_PRESENCE', '사용자 확인(터치)이 없었습니다');

  // 서명 대상 = authenticatorData + SHA-256(clientDataJSON). clientDataJSON 안에 서버의 질문이 들어 있습니다.
  const signedData = Buffer.concat([authDataBuf, sha256(clientDataRaw)]);
  const signature = b64u.decode(r.signature);
  let ok = false;
  try { ok = verifySignature(stored.alg, stored.jwk, signedData, signature); } catch { ok = false; }
  if (!ok) throw new AuthError(401, 'BAD_SIGNATURE', '서명이 저장된 공개키와 맞지 않습니다');

  // 복제된 인증기 감지: 둘 다 0이 아닌데 숫자가 늘지 않았다면 거절
  if ((auth.signCount !== 0 || stored.signCount !== 0) && auth.signCount <= stored.signCount) {
    throw new AuthError(401, 'COUNTER_ROLLBACK', '서명 횟수가 이전보다 작습니다 (복제 의심)');
  }

  return { challenge: clientData.challenge, signCount: auth.signCount, userVerified: auth.flags.userVerified, backedUp: auth.flags.backedUp };
}

// ── 저장 위치 추정 (AAGUID = 인증기 종류 번호) ──────────────────
const AAGUIDS = {
  'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': '구글 비밀번호 관리자',
  'adce0002-35bc-c60a-648b-0b25f1f05503': '맥용 Chrome (기기 자체)',
  '08987058-cadc-4b81-b6e1-30de50dcbe96': 'Windows Hello (기기 자체)',
  '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': 'Windows Hello (기기 자체)',
  '6028b017-b1d4-4c02-b4b3-afcdafc96bb2': 'Windows Hello (기기 자체)',
  'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': 'iCloud 키체인',
  'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': 'iCloud 키체인',
  '53414d53-554e-4700-0000-000000000000': '삼성 패스',
  'bada5566-a7aa-401f-bd96-45619a55120d': '1Password',
  'd548826e-79b4-db40-a3d8-11116f7e8349': 'Bitwarden',
  'cb69481e-8ff7-4039-93ec-0a2729a154a8': '보안 키 (YubiKey 5)',
  'ee882879-721c-4913-9775-3dfcce97072a': '보안 키 (YubiKey 5)',
  'fa2b99dc-9e39-4257-8f92-4a30d23c4118': '보안 키 (YubiKey 5)',
};

export function guessStorage({ aaguid, backupEligible, transports = [] }) {
  if (AAGUIDS[aaguid]) return AAGUIDS[aaguid];
  if (backupEligible) return '동기화되는 패스키 관리자 (종류 미상)';
  if (transports.includes('usb') || transports.includes('nfc')) return '보안 키로 보임';
  return '기기 자체로 보임 (종류 미상)';
}
