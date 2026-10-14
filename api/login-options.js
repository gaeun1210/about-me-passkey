// [로그인 1단계] 로그인할 때도 매번 새 질문을 만들어 보내고 2분간 보관합니다.
// 계정 이름을 묻지 않습니다 — 기기에 저장된 패스키가 스스로 어느 계정인지 알려 줍니다.
import { handler, send, site, rateLimit } from '../lib/http.js';
import { store, keys, CHALLENGE_TTL } from '../lib/store.js';
import { authenticationOptions } from '../lib/passkey.js';

export default handler(['POST'], async (req, res) => {
  await rateLimit(req, 'login-options', 30, 600);
  const { rpId } = site(req);
  const options = await authenticationOptions({ rpId });
  await store.set(keys.challenge(options.challenge), { purpose: 'login', createdAt: new Date().toISOString() }, { ttl: CHALLENGE_TTL });
  send(res, 200, { ok: true, challengeExpiresInSeconds: CHALLENGE_TTL, publicKey: options });
});
