// 패스키 확인 — 검증된 라이브러리 @simplewebauthn/server 사용
// 라이브러리가 확인하는 것: 질문 일치, 사이트 주소(origin), 사이트 ID(rpId) 해시, 사용자 확인(지문·PIN),
// 서명(저장된 공개키로), 서명 횟수 되돌림(복제 의심) 등
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { AuthError, b64u } from './webauthn.js';
import { CHALLENGE_TTL } from './store.js';

const RP_NAME = 'About Me · 나만의 공간';
const ALGS = [-7, -8, -257]; // ES256, EdDSA, RS256

export async function registrationOptions({ rpId, username, userId, exclude }) {
  return generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: rpId,
    userName: username,
    userDisplayName: username,
    userID: new Uint8Array(b64u.decode(userId)),
    timeout: CHALLENGE_TTL * 1000,
    attestationType: 'none',
    excludeCredentials: exclude.map((c) => ({ id: c.id, transports: c.transports || [] })), // 같은 기기에 중복 등록 막기
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' }, // 지문·얼굴·PIN 필수
    supportedAlgorithmIDs: ALGS,
  });
}

export async function checkRegistration({ credential, challenge, origin, rpId }) {
  let result;
  try {
    result = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRPID: rpId,
      requireUserVerification: true,
      supportedAlgorithmIDs: ALGS,
    });
  } catch (e) {
    throw new AuthError(401, 'REGISTRATION_REJECTED', `등록 응답 확인 실패: ${e.message}`);
  }
  if (!result.verified || !result.registrationInfo) throw new AuthError(401, 'REGISTRATION_REJECTED', '등록 응답을 확인하지 못했습니다');
  const info = result.registrationInfo;
  const cred = info.credential || { id: info.credentialID, publicKey: info.credentialPublicKey, counter: info.counter };
  if (cred.id !== credential.id) throw new AuthError(400, 'ID_MISMATCH', '패스키 ID가 서로 다릅니다');
  return {
    credId: cred.id,
    publicKey: Buffer.from(cred.publicKey), // COSE 형식 공개키
    counter: cred.counter || 0,
    aaguid: info.aaguid,
    multiDevice: info.credentialDeviceType === 'multiDevice',
    backedUp: !!info.credentialBackedUp,
  };
}

export async function authenticationOptions({ rpId }) {
  return generateAuthenticationOptions({
    rpID: rpId,
    timeout: CHALLENGE_TTL * 1000,
    userVerification: 'required',
    allowCredentials: [], // 기기에 저장된 패스키가 스스로 계정을 알려 줌
  });
}

export async function checkAuthentication({ credential, challenge, origin, rpId, stored }) {
  const publicKey = new Uint8Array(b64u.decode(stored.publicKey));
  let result;
  try {
    result = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRPID: rpId,
      requireUserVerification: true,
      credential: { id: stored.id, publicKey, counter: stored.counter, transports: stored.transports },
    });
  } catch (e) {
    throw new AuthError(401, 'BAD_SIGNATURE', `서명 확인 실패: ${e.message}`);
  }
  if (!result.verified) throw new AuthError(401, 'BAD_SIGNATURE', '서명이 저장된 공개키와 맞지 않습니다');
  return { newCounter: result.authenticationInfo.newCounter, backedUp: !!result.authenticationInfo.credentialBackedUp };
}
