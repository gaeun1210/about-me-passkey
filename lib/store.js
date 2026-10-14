// 저장소: Upstash Redis (Vercel에서 연결하면 접속 정보가 환경변수로 자동 등록됩니다)
// 접속 정보는 코드에 쓰지 않고 환경변수에서만 읽습니다.
const URL_ = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

export const CHALLENGE_TTL = 120;        // 질문 보관 시간: 2분 (짧을수록 훔친 질문을 쓸 시간이 줄어듦)
export const SESSION_TTL = 60 * 60 * 2;  // 세션 유지 시간: 2시간
export const MAX_ACCOUNTS = Number(process.env.MAX_ACCOUNTS || 2); // 만들 수 있는 계정 수 (owner, guest)

async function redis(command) {
  const res = await fetch(URL_, {
    method: 'POST',
    headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(command),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok || body.error) throw new Error(`저장소 오류: ${body.error || res.status}`);
  return body.result;
}

// 로컬 개발용 임시 저장소 (Vercel 밖에서 DB 없이 돌릴 때만)
const mem = new Map();
const memSets = new Map();
function memAlive(key) {
  const e = mem.get(key);
  if (!e) return undefined;
  if (e.exp && e.exp < Date.now()) { mem.delete(key); return undefined; }
  return e.v;
}

function useMemory() {
  if (URL_ && TOKEN) return false;
  if (process.env.VERCEL) {
    const err = new Error('저장소가 연결되지 않았습니다. Vercel 프로젝트의 Storage 탭에서 Upstash Redis를 연결한 뒤 다시 배포하세요.');
    err.status = 503; err.code = 'NO_DATABASE';
    throw err;
  }
  return true;
}

export const store = {
  async get(key) {
    if (useMemory()) { const v = memAlive(key); return v === undefined ? null : JSON.parse(v); }
    const v = await redis(['GET', key]);
    return v == null ? null : JSON.parse(v);
  },
  async set(key, value, { ttl, onlyIfNew } = {}) {
    const v = JSON.stringify(value);
    if (useMemory()) {
      if (onlyIfNew && memAlive(key) !== undefined) return false;
      mem.set(key, { v, exp: ttl ? Date.now() + ttl * 1000 : 0 });
      return true;
    }
    const cmd = ['SET', key, v];
    if (ttl) cmd.push('EX', String(ttl));
    if (onlyIfNew) cmd.push('NX');
    const r = await redis(cmd);
    return r === 'OK';
  },
  // 꺼내면서 바로 지우기 — 질문이 딱 한 번만 쓰이게 하는 핵심
  async take(key) {
    if (useMemory()) { const v = memAlive(key); mem.delete(key); return v === undefined ? null : JSON.parse(v); }
    const v = await redis(['GETDEL', key]);
    return v == null ? null : JSON.parse(v);
  },
  async del(key) {
    if (useMemory()) { mem.delete(key); memSets.delete(key); return; }
    await redis(['DEL', key]);
  },
  // 숫자 세기 (요청 횟수 제한·계정 수 제한용). 처음 만들 때만 만료 시간을 붙입니다.
  async incr(key, ttl) {
    if (useMemory()) {
      const cur = memAlive(key);
      const n = (cur === undefined ? 0 : Number(JSON.parse(cur))) + 1;
      const old = mem.get(key);
      mem.set(key, { v: JSON.stringify(n), exp: cur === undefined ? (ttl ? Date.now() + ttl * 1000 : 0) : old.exp });
      return n;
    }
    const n = await redis(['INCR', key]);
    if (n === 1 && ttl) await redis(['EXPIRE', key, String(ttl)]);
    return n;
  },
  async decr(key) {
    if (useMemory()) { const cur = Number(JSON.parse(memAlive(key) || '0')); const old = mem.get(key); mem.set(key, { v: JSON.stringify(cur - 1), exp: old?.exp || 0 }); return cur - 1; }
    return redis(['DECR', key]);
  },
  async sadd(key, member) {
    if (useMemory()) { if (!memSets.has(key)) memSets.set(key, new Set()); memSets.get(key).add(member); return; }
    await redis(['SADD', key, member]);
  },
  async srem(key, member) {
    if (useMemory()) { memSets.get(key)?.delete(member); return; }
    await redis(['SREM', key, member]);
  },
  async smembers(key) {
    if (useMemory()) return [...(memSets.get(key) || [])];
    return (await redis(['SMEMBERS', key])) || [];
  },
};

// 키 이름 정리
export const keys = {
  user: (u) => `user:${u}`,
  userCreds: (u) => `user:${u}:creds`,
  items: (u) => `user:${u}:items`,
  cred: (id) => `cred:${id}`,
  challenge: (c) => `chal:${c}`,
  session: (sid) => `sess:${sid}`,
  userSessions: (u) => `user:${u}:sessions`,
  accountCount: () => 'meta:account-count',
  rate: (name, who) => `rate:${name}:${who}`,
};
