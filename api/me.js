// 지금 들어와 있는지 확인 (비공개 내용은 주지 않습니다)
import { handler, send, getSession, fingerprint } from '../lib/http.js';

export default handler(['GET'], async (req, res) => {
  const { sid, session } = await getSession(req);
  if (!session) return send(res, 200, { ok: true, loggedIn: false });
  send(res, 200, { ok: true, loggedIn: true, username: session.username, sessionFingerprint: fingerprint(sid) });
});
