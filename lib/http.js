// 요청·응답 공통 도구: 사이트 주소 확인, 세션 쿠키, 요청 횟수 제한, 오류 응답
import crypto from 'node:crypto';
import { store, keys, SESSION_TTL } from './store.js';
import { AuthError } from './webauthn.js';

export function send(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.end(JSON.stringify(body));
}

const MAX_BODY = 20_000; // 20KB 넘는 요청 본문은 받지 않음
export async function readJson(req) {
  if (req.body && typeof req.body === 'object') {
    if (JSON.stringify(req.body).length > MAX_BODY) throw new AuthError(413, 'TOO_LARGE', '요청이 너무 큽니다');
    return req.body;
  }
  let text;
  if (typeof req.body === 'string') text = req.body;
  else {
    const chunks = []; let size = 0;
    for await (const c of req) { size += c.length; if (size > MAX_BODY) throw new AuthError(413, 'TOO_LARGE', '요청이 너무 큽니다'); chunks.push(c); }
    text = Buffer.concat(chunks).toString('utf8');
  }
  if (!text) return {};
  if (text.length > MAX_BODY) throw new AuthError(413, 'TOO_LARGE', '요청이 너무 큽니다');
  try { const v = JSON.parse(text); return v && typeof v === 'object' ? v : {}; } catch { throw new AuthError(400, 'BAD_JSON', 'JSON 형식이 아닙니다'); }
}

export function query(req) {
  return Object.fromEntries(new URL(req.url, 'http://local').searchParams);
}

// 패스키는 사이트 주소(도메인)에 묶입니다.
// 운영 배포에서는 요청 헤더를 믿지 않고 Vercel이 알려 주는 운영 주소로 고정합니다.
export function site(req) {
  const fixed = process.env.RP_ID || (process.env.VERCEL_ENV === 'production' ? process.env.VERCEL_PROJECT_PRODUCTION_URL : null);
  if (fixed) return { rpId: fixed, origin: `https://${fixed}` };
  const host = String(req.headers.host || '');
  const hostname = host.replace(/:\d+$/, '');
  const proto = hostname === 'localhost' ? 'http' : 'https';
  return { rpId: hostname, origin: `${proto}://${host}` };
}

// 다른 사이트에서 몰래 보낸 요청(CSRF) 막기: 상태를 바꾸는 요청은 같은 사이트에서 온 것만 받습니다
function checkSameOrigin(req) {
  if (req.method === 'GET') return;
  const origin = req.headers.origin;
  if (!origin) throw new AuthError(403, 'NO_ORIGIN', '어느 사이트에서 보낸 요청인지 알 수 없어 받지 않습니다');
  if (origin !== site(req).origin) throw new AuthError(403, 'CROSS_SITE', '다른 사이트에서 보낸 요청은 받지 않습니다');
  if (!String(req.headers['content-type'] || '').startsWith('application/json') && ['POST', 'PATCH'].includes(req.method)) {
    throw new AuthError(415, 'NOT_JSON', 'JSON 요청만 받습니다');
  }
}

// ── 요청 횟수 제한 (무차별 대입·도배 막기) ──
function clientIp(req) {
  return String(req.headers['x-real-ip'] || String(req.headers['x-forwarded-for'] || '').split(',')[0] || req.socket?.remoteAddress || 'unknown').trim();
}
export async function rateLimit(req, name, max, windowSec) {
  const who = crypto.createHash('sha256').update(clientIp(req)).digest('hex').slice(0, 16); // IP는 해시로만 저장
  const n = await store.incr(keys.rate(name, who), windowSec);
  if (n > max) throw new AuthError(429, 'TOO_MANY_REQUESTS', `요청이 너무 많습니다. ${windowSec >= 60 ? Math.round(windowSec / 60) + '분' : windowSec + '초'} 뒤에 다시 해 주세요`);
}

// ── 세션 ──
// 로그인에 성공하면 서버가 32바이트 무작위 세션 번호를 만들어 HttpOnly 쿠키로 줍니다.
// __Host- 이름 = Secure 필수, 이 사이트(하위 도메인 제외)에서만 쓰임. 쿠키 값은 화면·기록에 내보내지 않고 해시 지문만 보여 줍니다.
const COOKIE = '__Host-sid';

export function fingerprint(sid) {
  return 'fp-' + crypto.createHash('sha256').update(sid).digest('hex').slice(0, 8);
}

function readCookie(req) {
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === COOKIE) return part.slice(i + 1).trim();
  }
  return null;
}

export async function getSession(req) {
  const sid = readCookie(req);
  if (!sid || !/^[A-Za-z0-9_-]{43}$/.test(sid)) return { sid: null, session: null };
  const session = await store.get(keys.session(sid));
  return { sid, session };
}

export async function requireSession(req) {
  const { sid, session } = await getSession(req);
  if (!session) {
    const hint = sid ? `보낸 세션(${fingerprint(sid)})은 로그아웃했거나 만료되어 더 이상 쓸 수 없습니다` : '세션 쿠키가 없습니다';
    throw new AuthError(401, 'NOT_LOGGED_IN', `패스키로 먼저 들어와야 합니다 · ${hint}`);
  }
  return { sid, session };
}

export async function startSession(req, res, username, passkeyId) {
  // 이미 있던 세션은 지우고 새 번호로 바꿉니다 (세션 고정 공격 방지)
  const { sid: oldSid, session: old } = await getSession(req);
  if (oldSid) { await store.del(keys.session(oldSid)); if (old) await store.srem(keys.userSessions(old.username), oldSid); }
  const sid = crypto.randomBytes(32).toString('base64url');
  await store.set(keys.session(sid), { username, passkeyId, createdAt: new Date().toISOString() }, { ttl: SESSION_TTL });
  await store.sadd(keys.userSessions(username), sid);
  res.setHeader('Set-Cookie', `${COOKIE}=${sid}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL}`);
  return fingerprint(sid);
}

export async function endSession(sid, username) {
  await store.del(keys.session(sid));
  if (username) await store.srem(keys.userSessions(username), sid);
}

// 패스키를 지우면 그 계정의 다른 세션을 모두 끊습니다 (잃어버린 기기에 열려 있던 세션까지)
export async function endOtherSessions(username, keepSid) {
  let n = 0;
  for (const sid of await store.smembers(keys.userSessions(username))) {
    if (sid === keepSid) continue;
    await endSession(sid, username); n++;
  }
  return n;
}

export function clearCookie(res) {
  res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
}

// 모든 API를 감싸서 오류를 같은 모양으로 돌려줍니다 (서버 내부 오류 내용은 밖으로 내보내지 않음)
export function handler(methods, fn) {
  return async (req, res) => {
    try {
      if (!methods.includes(req.method)) throw new AuthError(405, 'METHOD', `${req.method} 요청은 받지 않습니다`);
      checkSameOrigin(req);
      await fn(req, res);
    } catch (e) {
      const status = e.status || 500;
      if (status >= 500) console.error(e);
      send(res, status, { ok: false, code: e.code || 'SERVER_ERROR', message: status >= 500 && !e.code ? '서버 오류가 났습니다' : e.message });
    }
  };
}

export const USERNAME_RE = /^[a-z0-9_-]{3,20}$/;
export function cleanName(s, fallback) {
  const v = String(s ?? '').replace(/[<>\u0000-\u001f]/g, '').trim().slice(0, 40);
  return v || fallback;
}
