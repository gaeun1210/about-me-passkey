// [등록 1단계] 서버가 일회용 질문(challenge)을 만들어 보내고, 확인할 때까지 5분간 보관합니다.
//  - 로그인 안 한 상태: 새 계정 만들기
//  - 로그인 한 상태: 지금 계정에 패스키 하나 더 추가 (기기 분실 대비)
import crypto from 'node:crypto';
import { handler, send, readJson, site, getSession, USERNAME_RE, cleanName } from '../lib/http.js';
import { store, keys, CHALLENGE_TTL } from '../lib/store.js';
import { newChallenge, AuthError } from '../lib/webauthn.js';

export default handler(['POST'], async (req, res) => {
  const body = await readJson(req);
  const { rpId } = site(req);
  const { session } = await getSession(req);

  let username, userId, mode, exclude = [];
  if (session) {
    // 이미 들어와 있으면 요청 본문의 이름은 무시하고 내 계정에만 추가합니다
    mode = 'add';
    username = session.username;
    const user = await store.get(keys.user(username));
    userId = user.userId;
    const credIds = await store.smembers(keys.userCreds(username));
    for (const id of credIds) {
      const c = await store.get(keys.cred(id));
      if (c) exclude.push({ type: 'public-key', id, transports: c.transports || [] });
    }
  } else {
    mode = 'new';
    username = String(body.username || '').trim().toLowerCase();
    if (!USERNAME_RE.test(username)) throw new AuthError(400, 'BAD_USERNAME', '계정 이름은 영어 소문자·숫자·-·_ 로 3~20자입니다');
    if (await store.get(keys.user(username))) throw new AuthError(409, 'USERNAME_TAKEN', '이미 있는 계정 이름입니다. 그 계정이 내 것이라면 "패스키로 들어가기"를 누르세요');
    userId = crypto.randomBytes(16).toString('base64url');
  }

  const challenge = newChallenge();
  await store.set(keys.challenge(challenge), {
    purpose: 'register', mode, username, userId,
    passkeyName: cleanName(body.passkeyName, ''),
    createdAt: new Date().toISOString(),
  }, { ttl: CHALLENGE_TTL });

  send(res, 200, {
    ok: true,
    mode,
    challengeExpiresInSeconds: CHALLENGE_TTL,
    publicKey: {
      challenge,
      rp: { id: rpId, name: 'About Me · 나만의 공간' },
      user: { id: userId, name: username, displayName: username },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }, { type: 'public-key', alg: -257 }],
      timeout: CHALLENGE_TTL * 1000,
      attestation: 'none',
      authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'preferred' },
      excludeCredentials: exclude, // 이미 등록한 패스키는 같은 기기에 또 만들지 않도록
    },
  });
});
