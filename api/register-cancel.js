// [등록 취소] 사용자가 패스키 창을 닫으면, 보관하던 질문을 바로 지웁니다.
// 계정·패스키는 2단계(register-verify)에서만 만들어지므로, 취소하면 서버에 남는 것이 없습니다.
import { handler, send, readJson, rateLimit } from '../lib/http.js';
import { store, keys } from '../lib/store.js';

export default handler(['POST'], async (req, res) => {
  await rateLimit(req, 'register-cancel', 30, 600);
  const { challenge } = await readJson(req);
  let removed = false;
  if (typeof challenge === 'string' && /^[A-Za-z0-9_-]{20,200}$/.test(challenge)) {
    const pending = await store.take(keys.challenge(challenge));
    removed = !!(pending && pending.purpose === 'register');
  }
  send(res, 200, { ok: true, challengeRemoved: removed, savedAccount: false, savedPasskey: false, message: '등록을 취소했습니다. 서버에는 계정도 패스키도 저장되지 않았습니다.' });
});
