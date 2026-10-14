// 패스키(WebAuthn) 보조 도구
// 실제 서명·공개키 확인은 검증된 라이브러리(@simplewebauthn/server)가 합니다 → lib/passkey.js
// 이 파일은 그 앞뒤의 작은 일만 합니다: 질문 값 꺼내기, 공개키를 사람이 읽을 형식으로 바꾸기, 저장 위치 짐작하기
import crypto from 'node:crypto';
import { decodeFirst } from './cbor.js';

export class AuthError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}

export const b64u = {
  encode: (buf) => Buffer.from(buf).toString('base64url'),
  decode: (str) => {
    if (typeof str !== 'string' || !/^[A-Za-z0-9_-]+$/.test(str)) throw new AuthError(400, 'BAD_ENCODING', 'base64url 형식이 아닙니다');
    return Buffer.from(str, 'base64url');
  },
};

// 브라우저가 서명한 문서(clientDataJSON)에서 "서버의 질문" 값을 꺼냅니다.
// 이 값으로 서버가 보관한 질문을 찾고, 찾는 즉시 지웁니다. (진짜 확인은 라이브러리가 다시 합니다)
export function challengeFrom(clientDataB64u) {
  let data;
  try { data = JSON.parse(b64u.decode(clientDataB64u).toString('utf8')); }
  catch { throw new AuthError(400, 'BAD_CLIENT_DATA', 'clientDataJSON을 읽을 수 없습니다'); }
  if (typeof data.challenge !== 'string' || !/^[A-Za-z0-9_-]{20,200}$/.test(data.challenge)) {
    throw new AuthError(400, 'BAD_CLIENT_DATA', '질문 값이 없습니다');
  }
  return data.challenge;
}

// COSE 공개키(라이브러리가 저장하는 형식) → PEM (사람이 읽는 "-----BEGIN PUBLIC KEY-----" 형식)
// 화면과 제출문에 "서버에 저장된 값은 공개키"라는 것을 보여 주는 용도입니다.
export function cosePublicKeyToPem(coseBytes) {
  try {
    const [cose] = decodeFirst(Buffer.from(coseBytes));
    const kty = cose.get(1);
    let jwk;
    if (kty === 2) jwk = { kty: 'EC', crv: 'P-256', x: b64u.encode(cose.get(-2)), y: b64u.encode(cose.get(-3)) };
    else if (kty === 1) jwk = { kty: 'OKP', crv: 'Ed25519', x: b64u.encode(cose.get(-2)) };
    else if (kty === 3) jwk = { kty: 'RSA', n: b64u.encode(cose.get(-1)), e: b64u.encode(cose.get(-2)) };
    else return null;
    return crypto.createPublicKey({ key: jwk, format: 'jwk' }).export({ type: 'spki', format: 'pem' });
  } catch {
    return null;
  }
}

export const ALG_NAME = { '-7': 'ES256', '-8': 'EdDSA', '-257': 'RS256' };
export function coseAlg(coseBytes) {
  try { const [cose] = decodeFirst(Buffer.from(coseBytes)); return ALG_NAME[cose.get(3)] || String(cose.get(3)); } catch { return '알 수 없음'; }
}

// 저장 위치 짐작 (AAGUID = 인증기 종류 번호). 증명(attestation)을 받지 않으므로 "추정"입니다.
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

export function guessStorage({ aaguid, multiDevice, transports = [] }) {
  if (AAGUIDS[aaguid]) return AAGUIDS[aaguid];
  if (multiDevice) return '동기화되는 패스키 관리자 (종류 미상)';
  if (transports.includes('usb') || transports.includes('nfc')) return '보안 키로 보임';
  return '기기 자체로 보임 (종류 미상)';
}
