// [패스키 목록·삭제] 내 계정의 패스키만 보고 지울 수 있습니다.
//  - 남의 패스키 ID로 지우기 → 403
//  - 마지막 하나는 지울 수 없음 → 409 (지우면 이 계정에 들어갈 방법이 사라지기 때문)
import { handler, send, query, requireSession } from '../lib/http.js';
import { store, keys } from '../lib/store.js';
import { AuthError } from '../lib/webauthn.js';

const ALG = { '-7': 'ES256', '-8': 'EdDSA', '-257': 'RS256' };

async function myPasskeys(username) {
  const ids = await store.smembers(keys.userCreds(username));
  const list = [];
  for (const id of ids) {
    const c = await store.get(keys.cred(id));
    if (c) list.push(c);
  }
  return list.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

function view(c) {
  return {
    id: c.id,
    name: c.name,
    storage: c.storage,
    createdAt: c.createdAt,
    lastUsedAt: c.lastUsedAt,
    algorithm: ALG[c.alg],
    publicKeyPem: c.publicKeyPem, // 공개키: 보여 줘도 안전한 값
    aaguid: c.aaguid,
    synced: c.backupEligible ? '여러 기기에 동기화 가능' : '이 기기에만 있음',
    transports: c.transports,
  };
}

export default handler(['GET', 'DELETE'], async (req, res) => {
  const { session } = await requireSession(req);
  const me = session.username;

  if (req.method === 'GET') {
    const list = await myPasskeys(me);
    return send(res, 200, {
      ok: true, owner: me, count: list.length, passkeys: list.map(view),
      storedValueNote: '서버에 저장된 것은 공개키(PUBLIC KEY)입니다. 비밀번호나 개인키는 서버에 없습니다.',
    });
  }

  const id = query(req).id;
  if (!id) throw new AuthError(400, 'NO_ID', '지울 패스키 ID가 없습니다');
  const target = await store.get(keys.cred(id));
  if (!target || target.username !== me) throw new AuthError(403, 'NOT_YOURS', '내 패스키가 아닙니다. 다른 계정의 패스키는 지울 수 없습니다');

  const list = await myPasskeys(me);
  if (list.length <= 1) {
    throw new AuthError(409, 'LAST_PASSKEY', '마지막 남은 패스키는 지울 수 없습니다. 지우면 이 계정에 다시 들어갈 방법이 없어지고, 비밀번호 같은 다른 복구 수단도 없기 때문입니다. 다른 기기에 패스키를 먼저 추가하세요.');
  }
  await store.del(keys.cred(id));
  await store.srem(keys.userCreds(me), id);
  send(res, 200, { ok: true, owner: me, removed: { id, name: target.name }, remaining: list.length - 1, note: '서버에서 공개키를 지웠습니다. 기기에 남은 패스키로는 이제 들어올 수 없습니다.' });
});
