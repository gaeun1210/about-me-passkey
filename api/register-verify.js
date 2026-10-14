// [등록 2단계] 기기가 보낸 응답을 확인하고 "공개키"만 저장합니다.
// 요청 본문에는 clientDataJSON·attestationObject(공개키가 들어 있음)만 오며, 개인키는 기기 밖으로 나오지 않습니다.
import { handler, send, readJson, site, getSession, startSession, rateLimit, cleanName } from '../lib/http.js';
import { store, keys, MAX_ACCOUNTS } from '../lib/store.js';
import { checkRegistration } from '../lib/passkey.js';
import { challengeFrom, cosePublicKeyToPem, coseAlg, guessStorage, AuthError, b64u } from '../lib/webauthn.js';
import { seedItems } from '../lib/items.js';

export default handler(['POST'], async (req, res) => {
  await rateLimit(req, 'register-verify', 20, 600);
  const { credential, passkeyName } = await readJson(req);
  if (!credential?.response?.clientDataJSON || typeof credential.id !== 'string') throw new AuthError(400, 'BAD_REQUEST', '등록 응답이 없습니다');
  const { rpId, origin } = site(req);

  // 1) 질문 확인: 서버가 보관한 질문이어야 하고, 꺼내는 순간 지워서 다시는 못 씁니다
  const challenge = challengeFrom(credential.response.clientDataJSON);
  const pending = await store.take(keys.challenge(challenge));
  if (!pending || pending.purpose !== 'register') {
    throw new AuthError(400, 'CHALLENGE_UNKNOWN', '서버가 보낸 적 없거나, 이미 썼거나, 2분이 지난 질문입니다');
  }

  // 2) 라이브러리로 확인: 질문·사이트 주소·사이트 ID·지문/PIN 확인·공개키
  const v = await checkRegistration({ credential, challenge, origin, rpId });

  // 3) 패스키 추가라면 지금도 같은 계정으로 들어와 있어야 합니다
  if (pending.mode === 'add') {
    const { session } = await getSession(req);
    if (!session || session.username !== pending.username) throw new AuthError(401, 'NOT_LOGGED_IN', '패스키 추가는 들어와 있는 동안에만 할 수 있습니다');
  }
  if (await store.get(keys.cred(v.credId))) throw new AuthError(409, 'ALREADY_REGISTERED', '이미 등록된 패스키입니다');

  const now = new Date().toISOString();
  if (pending.mode === 'new') {
    // 계정 수 제한을 한 번 더, 동시에 들어온 요청까지 정확히 셉니다
    const n = await store.incr(keys.accountCount());
    if (n > MAX_ACCOUNTS) { await store.decr(keys.accountCount()); throw new AuthError(403, 'SIGNUP_CLOSED', `새 계정 만들기는 닫혀 있습니다 (계정은 ${MAX_ACCOUNTS}개까지)`); }
    const created = await store.set(keys.user(pending.username), { username: pending.username, userId: pending.userId, createdAt: now }, { onlyIfNew: true });
    if (!created) { await store.decr(keys.accountCount()); throw new AuthError(409, 'USERNAME_TAKEN', '그 사이에 같은 이름의 계정이 생겼습니다'); }
    await store.set(keys.items(pending.username), seedItems(n)); // 첫 계정=owner 내용, 둘째=guest 내용
  }

  const transports = Array.isArray(credential.response.transports)
    ? credential.response.transports.filter((t) => ['usb', 'nfc', 'ble', 'internal', 'hybrid', 'cable', 'smart-card'].includes(t))
    : [];
  const record = {
    id: v.credId,
    username: pending.username,
    name: cleanName(passkeyName || pending.passkeyName, '이름 없는 패스키'),
    // ↓ 서버에 저장하는 것은 "공개키"입니다. 비밀번호도, 개인키도 아닙니다.
    publicKey: b64u.encode(v.publicKey),
    publicKeyPem: cosePublicKeyToPem(v.publicKey),
    algorithm: coseAlg(v.publicKey),
    counter: v.counter,
    transports,
    aaguid: v.aaguid,
    multiDevice: v.multiDevice,
    backedUp: v.backedUp,
    storage: guessStorage({ aaguid: v.aaguid, multiDevice: v.multiDevice, transports }),
    createdAt: now,
    lastUsedAt: null,
  };
  await store.set(keys.cred(v.credId), record);
  await store.sadd(keys.userCreds(pending.username), v.credId);

  let sessionFingerprint = null;
  if (pending.mode === 'new') sessionFingerprint = await startSession(req, res, pending.username, v.credId); // 새 계정은 바로 들어가게

  send(res, 200, {
    ok: true,
    mode: pending.mode,
    username: pending.username,
    sessionFingerprint,
    savedOnServer: {
      설명: '서버가 저장한 값은 공개키입니다. 공개키로는 서명을 "확인"만 할 수 있고 서명을 "만들" 수는 없어서, 유출되어도 이것만으로는 로그인할 수 없습니다.',
      passkeyId: record.id,
      name: record.name,
      algorithm: record.algorithm,
      publicKeyPem: record.publicKeyPem,
      storage: record.storage,
      aaguid: record.aaguid,
      createdAt: record.createdAt,
    },
  });
});
