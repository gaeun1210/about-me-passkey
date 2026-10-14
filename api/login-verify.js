// [로그인 2단계] 기기의 서명을, 서버에 저장해 둔 공개키로 확인한 뒤에만 세션을 줍니다.
import { handler, send, readJson, site, startSession } from '../lib/http.js';
import { store, keys } from '../lib/store.js';
import { verifyAuthentication, readClientData, AuthError } from '../lib/webauthn.js';

export default handler(['POST'], async (req, res) => {
  const { credential } = await readJson(req);
  if (!credential?.response?.clientDataJSON || typeof credential.id !== 'string') throw new AuthError(400, 'BAD_REQUEST', '로그인 응답이 없습니다');
  const { rpId, origin } = site(req);

  // 1) 질문: 서버가 보관 중인 것이어야 하고, 꺼내면서 지웁니다 → 같은 응답을 두 번 보내면 두 번째는 거절
  const { data } = readClientData(credential.response.clientDataJSON);
  const pending = await store.take(keys.challenge(data.challenge));
  if (!pending || pending.purpose !== 'login') {
    throw new AuthError(401, 'CHALLENGE_UNKNOWN', '서버가 보낸 적 없거나, 이미 한 번 쓴, 또는 5분이 지난 질문입니다');
  }

  // 2) 이 패스키가 서버에 등록되어 있는지 (지운 패스키는 여기서 막힙니다)
  const stored = await store.get(keys.cred(credential.id));
  if (!stored) throw new AuthError(401, 'UNKNOWN_PASSKEY', '서버에 등록되지 않은(또는 지운) 패스키입니다');

  // 3) 저장된 공개키로 서명 확인
  const result = verifyAuthentication({ credential, stored, expectedOrigin: origin, rpId });

  // 4) 기기가 알려 준 계정 번호가 패스키 주인과 같은지
  const user = await store.get(keys.user(stored.username));
  if (!user) throw new AuthError(401, 'UNKNOWN_USER', '계정이 없습니다');
  const userHandle = credential.response.userHandle;
  if (userHandle && userHandle !== user.userId) throw new AuthError(401, 'USER_MISMATCH', '패스키와 계정이 맞지 않습니다');

  stored.signCount = result.signCount;
  stored.lastUsedAt = new Date().toISOString();
  stored.backedUp = result.backedUp;
  await store.set(keys.cred(stored.id), stored);

  const sessionFingerprint = await startSession(req, res, stored.username);
  send(res, 200, {
    ok: true,
    username: stored.username,
    passkeyName: stored.name,
    signatureChecked: '저장된 공개키로 서명 확인 성공',
    sessionFingerprint,
    sessionNote: '세션 값은 HttpOnly 쿠키라 화면에서 읽을 수 없고, 여기에는 해시 지문만 보여 줍니다',
  });
});
