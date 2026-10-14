# about-me-passkey

과제 1 자기소개 페이지([ALEPH_AI](https://github.com/gaeun1210/ALEPH_AI))를 그대로 가져와, 아래쪽에 **패스키로만 열리는 "나만의 공간"**을 붙인 과제 8입니다.

- 첫 화면(01~04 섹션)은 과제 1과 같고 누구나 볼 수 있습니다. 이 저장소의 첫 커밋들이 과제 1 기록 그대로입니다.
- 05 섹션 "나만의 공간"만 패스키로 잠겨 있습니다. 비밀번호는 없습니다.
- 비공개 공간의 내용은 모두 **만들어 넣은 예시**이며 실제 개인정보가 아닙니다.

## 파일 구성

| 파일 | 하는 일 |
|---|---|
| `index.html` | 과제 1 소개 페이지. 바꾼 곳은 메뉴 링크 1개, CSS·JS 연결 2줄, 경계선과 빈 비공개 자리(내용 없음)뿐 |
| `private.css`, `private.js` | 비공개 공간 화면, 패스키 등록·로그인 화면, 검증 도구 |
| `api/*.js` | 서버 (Vercel 서버 함수) |
| `lib/passkey.js` | 패스키 등록·서명 확인 — 라이브러리 [`@simplewebauthn/server`](https://simplewebauthn.dev) 사용 |
| `lib/webauthn.js`, `lib/cbor.js` | 질문 값 꺼내기, 공개키를 PEM으로 보여 주기, 저장 위치 짐작 |
| `lib/http.js` | 세션 쿠키, 운영 주소 고정, 요청 출처 확인, 요청 횟수 제한 |
| `lib/store.js` | Upstash Redis 저장 (접속 정보는 환경변수에서만 읽음) |
| `vercel.json` | 보안 헤더 (CSP, HSTS, 프레임 금지 등) |

## 네 흐름이 지나는 자리

**등록**
1. `api/register-options.js` — 새 계정은 계정 수 제한 확인(L32) → 라이브러리로 질문 생성(L39) → Redis에 2분 보관(L40)
2. 브라우저 `private.js`의 `register()` → `navigator.credentials.create()` (기기가 열쇠 한 쌍 생성)
3. `api/register-verify.js` — 질문을 꺼내면서 삭제(L17) → `checkRegistration()`(lib/passkey.js L31)으로 확인 → **공개키만 저장**(L62)
4. 취소하면 `api/register-cancel.js`가 보관하던 질문을 지움

**로그인**
1. `api/login-options.js` — 새 질문 생성, 2분 보관
2. 브라우저 `login()` → `navigator.credentials.get()` (기기가 개인키로 서명)
3. `api/login-verify.js` — 질문 꺼내면서 삭제(L17, 재사용 거절) → 등록된 패스키인지(L24, 지운 패스키 거절) → `checkAuthentication()`(lib/passkey.js L68)으로 **저장된 공개키로 서명 확인** → 새 세션 발급(L41)

**로그아웃**
- `api/logout.js` — 서버의 세션 삭제(L8) + 쿠키 비우기(L10)

**비공개 자료 조회**
- `api/private.js` — `requireSession()`(lib/http.js L92) 없으면 **401** → 세션 주인의 자료만 반환. 다른 계정 항목 ID는 **403**(L24, L55), 주소·본문에 적은 계정 이름은 무시(L32, L48)
- `api/passkeys.js` — 내 패스키 목록·삭제. 남의 패스키 삭제 **403**(L48), 마지막 패스키 삭제 **409**(L52), 삭제하면 다른 세션 모두 끊기(L56)

## 배포에 필요한 것

Vercel 프로젝트의 **Storage** 탭에서 Upstash Redis를 연결하면 `KV_REST_API_URL`, `KV_REST_API_TOKEN` 환경변수가 자동으로 생깁니다. 이 값은 저장소에 넣지 않습니다.

- `MAX_ACCOUNTS` (선택, 기본 2): 만들 수 있는 계정 수. 두 계정(owner, guest)을 만들면 새 가입은 자동으로 닫힙니다.
