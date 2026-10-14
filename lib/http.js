// 요청·응답 공통 도구: 사이트 주소 확인, 세션 쿠키, 오류 응답
import crypto from 'node:crypto';
import { store, keys, SESSION_TTL } from './store.js';
import { AuthError } from './webauthn.js';

export function send(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

export async function readJson(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') { try { return JSON.parse(req.body); } catch { return {}; } }
  const chunks = [];
  for await (const c of req) chunks.push(c);
  if (!chunks.length) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return {}; }
}

export function query(req) {
  return Object.fromEntries(new URL(req.url, 'http://local').searchParams);
}

// 패스키는 사이트 주소(도메인)에 묶입니다. RP ID = 이 사이트의 도메인
export function site(req) {
  const host = String(req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
  const hostname = host.replace(/:\d+$/, '');
  const isLocal = hostname === 'localhost';
  const proto = isLocal ? 'http' : 'https';
  return {
    rpId: process.env.RP_ID || hostname,
    origin: process.env.EXPECTED_ORIGIN || `${proto}://${host}`,
    secure: !isLocal,
  };
}

// 다른 사이트에서 몰래 보낸 요청(CSRF) 막기: 상태를 바꾸는 요청은 같은 사이트에서 온 것만 받습니다
export function checkSameOrigin(req) {
  if (req.method === 'GET') return;
  const origin = req.headers.origin;
  if (origin && origin !== site(req).origin) throw new AuthError(403, 'CROSS_SITE', '다른 사이트에서 보낸 요청은 받지 않습니다');
}

// ── 세션 ──
// 로그인에 성공하면 서버가 무작위 세션 번호를 만들어 HttpOnly 쿠키로 줍니다.
// 쿠키 값 자체는 화면·기록에 내보내지 않고, 대신 해시 앞 8자리(세션 지문)만 보여 줍니다.
const COOKIE = 'sid';

export function fingerprint(sid) {
  return 'fp-' + crypto.createHash('sha256').update(sid).digest('hex').slice(0, 8);
}

function readCookie(req) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === COOKIE) return v.join('=');
  }
  return null;
}

export async function getSession(req) {
  const sid = readCookie(req);
  if (!sid || !/^[A-Za-z0-9_-]{20,100}$/.test(sid)) return { sid: null, session: null };
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

export async function startSession(req, res, username) {
  const sid = crypto.randomBytes(32).toString('base64url');
  await store.set(keys.session(sid), { username, createdAt: new Date().toISOString() }, { ttl: SESSION_TTL });
  const secure = site(req).secure ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${COOKIE}=${sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL}${secure}`);
  return fingerprint(sid);
}

export function clearCookie(req, res) {
  const secure = site(req).secure ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`);
}

// 모든 API를 감싸서 오류를 같은 모양으로 돌려줍니다
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
  const v = String(s ?? '').replace(/[<>]/g, '').trim().slice(0, 40);
  return v || fallback;
}
