// [비공개 자료 조회] 패스키로 들어온 사람에게, 그 사람 자신의 자료만 돌려줍니다.
//  - 로그인 안 함 → 401
//  - 다른 계정의 항목 ID로 읽기·지우기 → 403
//  - 주소나 본문에 다른 계정 이름을 적어도 → 무시하고 "내 자료"만 돌려줌
// 누구의 자료인지는 오직 세션(서버가 준 쿠키)으로만 정합니다. 요청에 적힌 계정 이름은 믿지 않습니다.
import { handler, send, readJson, query, requireSession, rateLimit } from '../lib/http.js';
import { store, keys } from '../lib/store.js';
import { newItemId } from '../lib/items.js';
import { AuthError } from '../lib/webauthn.js';

export default handler(['GET', 'POST', 'DELETE'], async (req, res) => {
  await rateLimit(req, 'private', 120, 60);
  const { session } = await requireSession(req);
  const me = session.username;
  const q = query(req);
  const items = (await store.get(keys.items(me))) || [];

  const ignored = {};
  for (const k of ['owner', 'user', 'username', 'account']) if (q[k] !== undefined) ignored[k] = q[k];

  if (req.method === 'GET') {
    if (q.item) {
      const item = items.find((i) => i.id === q.item);
      if (!item) throw new AuthError(403, 'NOT_YOURS', '내 자료가 아닙니다. 다른 계정의 항목은 읽을 수 없습니다');
      return send(res, 200, { ok: true, owner: me, item });
    }
    return send(res, 200, {
      ok: true,
      owner: me,
      count: items.length,
      items,
      ...(Object.keys(ignored).length ? { ignoredParams: ignored, note: '요청에 적힌 계정 이름은 무시하고, 세션 주인의 자료만 돌려줬습니다' } : {}),
    });
  }

  if (req.method === 'POST') {
    const body = await readJson(req);
    for (const k of ['owner', 'user', 'username', 'account']) if (body[k] !== undefined) ignored[k] = body[k];
    const title = String(body.title || '').trim().slice(0, 60);
    const text = String(body.body || '').trim().slice(0, 500);
    if (!title) throw new AuthError(400, 'EMPTY', '제목을 적어 주세요');
    if (items.length >= 30) throw new AuthError(400, 'TOO_MANY', '항목은 30개까지만 둘 수 있습니다');
    const item = { id: newItemId(), kind: '메모', title, body: text, createdAt: new Date().toISOString() };
    items.push(item);
    await store.set(keys.items(me), items); // 항상 "내" 목록에만 저장
    return send(res, 200, {
      ok: true, owner: me, count: items.length, added: item,
      ...(Object.keys(ignored).length ? { ignoredParams: ignored, note: '본문에 적힌 계정 이름은 무시하고 내 공간에 저장했습니다' } : {}),
    });
  }

  // DELETE
  if (!q.item) throw new AuthError(400, 'NO_ITEM', '지울 항목 ID가 없습니다');
  // 내 목록에 없는 ID라면 남의 것이든 없는 것이든 똑같이 403 (남의 항목이 있는지조차 알려 주지 않음)
  if (!items.some((i) => i.id === q.item)) throw new AuthError(403, 'NOT_YOURS', '내 자료가 아닙니다. 다른 계정의 항목은 지울 수 없습니다');
  const left = items.filter((i) => i.id !== q.item);
  await store.set(keys.items(me), left);
  send(res, 200, { ok: true, owner: me, count: left.length, removed: q.item });
});
