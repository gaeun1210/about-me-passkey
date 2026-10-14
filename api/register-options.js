// [등록 1단계] 서버가 일회용 질문(challenge)을 만들어 보내고, 확인할 때까지 2분간 보관합니다.
//  - 로그인 안 한 상태: 새 계정 만들기 (전체 계정 수 제한 있음)
//  - 로그인 한 상태: 지금 계정에 패스키 하나 더 추가 (기기 분실 대비)
import crypto from 'node:crypto';
import { handler, send, readJson, site, getSession, rateLimit, USERNAME_RE, cleanName } from '../lib/http.js';
import { store, keys, CHALLENGE_TTL, MAX_ACCOUNTS } from '../lib/store.js';
import { registrationOptions } from '../lib/passkey.js';
import { AuthError } from '../lib/webauthn.js';

export default handler(['POST'], async (req, res) => {
  await rateLimit(req, 'register-options', 20, 600);
  const body = await readJson(req);
  const { rpId } = site(req);
  const { session } = await getSession(req);

  let username, userId, mode;
  const exclude = [];
  if (session) {
    // 이미 들어와 있으면 요청 본문의 이름은 무시하고 내 계정에만 추가합니다
    mode = 'add';
    username = session.username;
    const user = await store.get(keys.user(username));
    if (!user) throw new AuthError(401, 'UNKNOWN_USER', '계정이 없습니다');
    userId = user.userId;
    for (const id of await store.smembers(keys.userCreds(username))) {
      const c = await store.get(keys.cred(id));
      if (c) exclude.push({ id, transports: c.transports || [] });
    }
  } else {
    mode = 'new';
    const count = Number((await store.get(keys.accountCount())) || 0);
    if (count >= MAX_ACCOUNTS) throw new AuthError(403, 'SIGNUP_CLOSED', `새 계정 만들기는 닫혀 있습니다 (계정은 ${MAX_ACCOUNTS}개까지). 이미 계정이 있다면 "패스키로 들어가기"를 누르세요`);
    username = String(body.username || '').trim().toLowerCase();
    if (!USERNAME_RE.test(username)) throw new AuthError(400, 'BAD_USERNAME', '계정 이름은 영어 소문자·숫자·-·_ 로 3~20자입니다');
    if (await store.get(keys.user(username))) throw new AuthError(409, 'USERNAME_TAKEN', '이미 있는 계정 이름입니다. 그 계정이 내 것이라면 "패스키로 들어가기"를 누르세요');
    userId = crypto.randomBytes(16).toString('base64url');
  }

  const options = await registrationOptions({ rpId, username, userId, exclude });
  await store.set(keys.challenge(options.challenge), {
    purpose: 'register', mode, username, userId,
    passkeyName: cleanName(body.passkeyName, ''),
    createdAt: new Date().toISOString(),
  }, { ttl: CHALLENGE_TTL });

  send(res, 200, { ok: true, mode, challengeExpiresInSeconds: CHALLENGE_TTL, publicKey: options });
});
