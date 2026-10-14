// [로그아웃] 서버에서 세션을 지우고 쿠키도 비웁니다.
// ?test=keep-cookie : 검증 도구용. 서버 세션만 지우고 브라우저 쿠키는 남겨 둡니다.
//   → 그 뒤 "같은 쿠키 값"으로 다시 요청하면 401로 거절되는 것을 확인할 수 있습니다. (자기 세션을 지우는 일이라 위험 없음)
import { handler, send, query, getSession, endSession, clearCookie, fingerprint } from '../lib/http.js';

export default handler(['POST'], async (req, res) => {
  const { sid, session } = await getSession(req);
  if (sid) await endSession(sid, session?.username);
  const keepCookie = query(req).test === 'keep-cookie';
  if (!keepCookie) clearCookie(res);
  send(res, 200, {
    ok: true,
    wasLoggedIn: !!session,
    removedSession: sid ? fingerprint(sid) : null,
    cookie: keepCookie ? '검증용: 브라우저 쿠키는 남겨 둠 (서버에서는 이미 무효)' : '브라우저 쿠키도 비움',
  });
});
