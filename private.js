// 과제 8 — 나만의 공간 (브라우저 쪽)
// 비공개 내용은 이 파일에도, index.html에도 들어 있지 않습니다. 패스키로 들어온 뒤 /api/private 에서 받아 그립니다.
(function () {
  'use strict';
  const app = document.getElementById('pv-app');
  const labBody = document.getElementById('pv-lab-body');
  if (!app) return;

  // ── 작은 도구들 ──────────────────────────────
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid.nodeType ? kid : String(kid));
    return el;
  }
  const toB64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const fromB64u = (s) => { const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)); return Uint8Array.from(b, (c) => c.charCodeAt(0)).buffer; };
  const fmtDate = (s) => s ? new Date(s).toLocaleString('ko-KR', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) : '아직 없음';
  const ss = { get(k) { try { return sessionStorage.getItem(k); } catch { return null; } }, set(k, v) { try { sessionStorage.setItem(k, v); } catch {} } };
  const ls = { get(k) { try { return localStorage.getItem(k); } catch { return null; } }, set(k, v) { try { localStorage.setItem(k, v); } catch {} } };

  function guessDeviceName() {
    const ua = navigator.userAgent;
    const os = /Android/.test(ua) ? '안드로이드' : /iPhone|iPad/.test(ua) ? '아이폰' : /Windows/.test(ua) ? 'Windows' : /Mac/.test(ua) ? '맥' : '이 기기';
    const br = /Edg\//.test(ua) ? 'Edge' : /SamsungBrowser/.test(ua) ? '삼성 인터넷' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : '브라우저';
    return `${os} ${br}`;
  }

  // ── 요청·응답 기록 (검증 도구용) ───────────────────
  // 세션 쿠키는 HttpOnly라 자바스크립트가 읽을 수 없고, 기록에는 "sid=●●●●(가림)"으로만 적습니다.
  let log = [];
  try { log = JSON.parse(ls.get('pv-lab-log') || '[]'); } catch { log = []; }
  let state = { loggedIn: false };

  function shorten(v, key) {
    if (typeof v === 'string') {
      if (key === 'publicKeyPem' || key === 'challenge' || v.length <= 90) return v;
      return v.slice(0, 40) + `…(총 ${v.length}자, 줄임)`;
    }
    if (Array.isArray(v)) return v.map((x) => shorten(x));
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, shorten(x, k)]));
    return v;
  }

  function record(entry) {
    log.push({ n: log.length + 1, time: new Date().toLocaleString('ko-KR'), ...entry });
    if (log.length > 120) log = log.slice(-120);
    ls.set('pv-lab-log', JSON.stringify(log));
    renderLog();
  }

  async function api(method, path, body, opt = {}) {
    const withCookie = opt.omitCookie ? false : true;
    let res, data;
    try {
      res = await fetch(path, {
        method,
        credentials: withCookie ? 'same-origin' : 'omit',
        headers: method === 'GET' ? {} : { 'Content-Type': 'application/json' },
        body: method === 'GET' ? undefined : JSON.stringify(body || {}),
      });
      data = await res.json().catch(() => ({}));
    } catch (e) {
      data = { ok: false, message: '서버에 닿지 못했습니다: ' + e.message };
      res = { status: 0 };
    }
    if (!opt.silent) {
      record({
        label: opt.label || `${method} ${path}`,
        method, path,
        cookie: withCookie ? (opt.cookieNote || (state.loggedIn ? 'sid=●●●●●●(가림)' : '보낼 쿠키 없음')) : '쿠키를 일부러 보내지 않음',
        request: body ? shorten(body) : null,
        status: res.status,
        response: shorten(data),
        note: opt.note || null,
      });
    }
    return { status: res.status, data };
  }

  // ── 패스키 옵션 변환 (서버 JSON ↔ 브라우저 API) ─────────────
  function toCreateOptions(pk) {
    return {
      ...pk,
      challenge: fromB64u(pk.challenge),
      user: { ...pk.user, id: fromB64u(pk.user.id) },
      excludeCredentials: (pk.excludeCredentials || []).map((c) => ({ ...c, id: fromB64u(c.id) })),
    };
  }
  function toGetOptions(pk) {
    return { ...pk, challenge: fromB64u(pk.challenge), allowCredentials: (pk.allowCredentials || []).map((c) => ({ ...c, id: fromB64u(c.id) })) };
  }
  // 기기가 돌려준 결과를 서버로 보낼 JSON으로. 여기 들어가는 것은 공개 정보뿐이고 개인키 칸은 없습니다.
  function regToJSON(cred) {
    const r = cred.response;
    return {
      id: cred.id, rawId: toB64u(cred.rawId), type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      response: {
        clientDataJSON: toB64u(r.clientDataJSON),
        attestationObject: toB64u(r.attestationObject),
        transports: typeof r.getTransports === 'function' ? r.getTransports() : [],
      },
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    };
  }
  function authToJSON(cred) {
    const r = cred.response;
    return {
      id: cred.id, rawId: toB64u(cred.rawId), type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      response: {
        clientDataJSON: toB64u(r.clientDataJSON),
        authenticatorData: toB64u(r.authenticatorData),
        signature: toB64u(r.signature),
        userHandle: r.userHandle ? toB64u(r.userHandle) : null,
      },
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    };
  }

  function supportProblem() {
    if (location.protocol !== 'https:' && location.hostname !== 'localhost') return '패스키는 https 주소에서만 쓸 수 있습니다 (개발 중에는 localhost만 예외).';
    if (!window.PublicKeyCredential || !navigator.credentials) return '이 브라우저는 패스키를 지원하지 않습니다. 최신 Chrome·Edge·Safari·삼성 인터넷에서 열어 주세요.';
    return null;
  }

  function explainError(e, kind) {
    if (e && e.name === 'NotAllowedError') return kind === 'register' ? '등록을 취소했거나 시간이 지났습니다.' : '로그인을 취소했거나 시간이 지났습니다.';
    if (e && e.name === 'InvalidStateError') return '이 기기(또는 이 비밀번호 관리자)에는 이미 이 계정의 패스키가 있습니다.\n휴대폰으로 QR을 찍어 등록하거나, 다른 브라우저·다른 기기에서 추가해 보세요.';
    if (e && e.name === 'SecurityError') return '주소가 맞지 않아 패스키를 쓸 수 없습니다 (https·도메인 확인).';
    return (e && e.message) || '알 수 없는 오류';
  }

  // ── 흐름: 등록 / 로그인 / 로그아웃 ───────────────────
  async function register({ username, passkeyName }, setMsg) {
    const problem = supportProblem(); if (problem) return setMsg(problem, 'bad');
    setMsg('서버에 등록용 질문을 받는 중…');
    const opt = await api('POST', '/api/register-options', { username, passkeyName }, { label: '등록 1단계 — 등록용 질문 받기' });
    if (opt.status !== 200) return setMsg(opt.data.message || '등록을 시작하지 못했습니다', 'bad');
    setMsg('기기의 패스키 창에서 지문·얼굴·PIN으로 확인해 주세요.');
    let cred;
    try {
      cred = await navigator.credentials.create({ publicKey: toCreateOptions(opt.data.publicKey) });
    } catch (e) {
      const cancel = await api('POST', '/api/register-cancel', { challenge: opt.data.publicKey.challenge }, { label: '등록 취소 — 보관하던 질문 지우기' });
      const extra = cancel.data.challengeRemoved ? '\n서버에는 계정도 패스키도 저장되지 않았고, 보관하던 질문도 지웠습니다.' : '';
      return setMsg(explainError(e, 'register') + extra, 'warn');
    }
    const body = regToJSON(cred);
    const fin = await api('POST', '/api/register-verify', { credential: body, passkeyName }, {
      label: '등록 2단계 — 공개키 보내기',
      note: '요청 본문 항목: ' + Object.keys(body.response).join(', ') + ' · 개인키(private key) 항목: 없음',
    });
    if (fin.status !== 200) return setMsg(fin.data.message || '등록에 실패했습니다', 'bad');
    setMsg(`패스키 "${fin.data.savedOnServer.name}"를 등록했습니다. 서버에는 공개키만 저장됐어요.`, 'ok');
    await refresh();
  }

  async function login(setMsg, { tamper = false } = {}) {
    const problem = supportProblem(); if (problem) return setMsg(problem, 'bad');
    setMsg('서버에 로그인용 질문을 받는 중…');
    const opt = await api('POST', '/api/login-options', null, { label: tamper ? '[검증] 로그인 질문 받기' : '로그인 1단계 — 로그인용 질문 받기', omitCookie: tamper });
    if (opt.status !== 200) return setMsg(opt.data.message || '로그인을 시작하지 못했습니다', 'bad');
    setMsg('기기의 패스키 창에서 들어갈 패스키를 고르고 확인해 주세요.');
    let cred;
    try { cred = await navigator.credentials.get({ publicKey: toGetOptions(opt.data.publicKey) }); }
    catch (e) { return setMsg(explainError(e, 'login'), 'warn'); }
    const body = authToJSON(cred);
    if (tamper) {
      const sig = new Uint8Array(fromB64u(body.response.signature)); sig[sig.length - 1] ^= 0xff;
      body.response.signature = toB64u(sig);
      const bad = await api('POST', '/api/login-verify', { credential: body }, { label: '[검증] 서명 마지막 1바이트를 바꿔서 보내기', omitCookie: true, note: '진짜 패스키로 서명한 뒤, 서명 값의 마지막 1바이트만 바꿈' });
      return setMsg(bad.status === 401 ? `예상대로 거절됐습니다 (${bad.status} ${bad.data.code}).` : `거절되지 않았습니다: ${bad.status}`, bad.status === 401 ? 'ok' : 'bad');
    }
    const fin = await api('POST', '/api/login-verify', { credential: body }, { label: '로그인 2단계 — 서명 보내기' });
    if (fin.status !== 200) return setMsg(fin.data.message || '들어가지 못했습니다', 'bad');
    ss.set('pv-last-login', JSON.stringify({ credential: body }));
    setMsg('', '');
    await refresh();
  }

  async function logout() {
    await api('POST', '/api/logout', null, { label: '로그아웃' });
    await refresh();
  }

  // ── 화면 ────────────────────────────────────
  function msgBox() {
    const el = h('p', { class: 'pv-msg', role: 'status' });
    return { el, set: (text, kind) => { el.textContent = text; el.className = 'pv-msg' + (kind ? ' ' + kind : ''); } };
  }

  function renderLocked() {
    const m = msgBox();
    const name = h('input', { type: 'text', autocomplete: 'username webauthn', placeholder: '예: owner', maxlength: '20', 'aria-label': '새 계정 이름' });
    const pkName = h('input', { type: 'text', value: guessDeviceName(), maxlength: '40', 'aria-label': '패스키 이름' });
    const loginBtn = h('button', { class: 'pv-btn', type: 'button', onclick: async () => { loginBtn.disabled = true; await login(m.set); loginBtn.disabled = false; } }, '🔑 패스키로 들어가기');
    const regBtn = h('button', { class: 'pv-btn ghost', type: 'button', onclick: async () => { regBtn.disabled = true; await register({ username: name.value.trim(), passkeyName: pkName.value.trim() }, m.set); regBtn.disabled = false; } }, '패스키 만들기');
    app.replaceChildren(
      h('div', { class: 'pv-box pv-locked' },
        h('div', { class: 'pv-lock-icon', 'aria-hidden': 'true' }, '🔒'),
        h('div', {},
          h('h3', {}, '잠겨 있어요'),
          h('p', {}, '이 공간은 패스키를 가진 본인만 열 수 있습니다. 비밀번호 입력 칸은 없습니다.'),
          h('div', { class: 'pv-row' }, loginBtn),
          h('details', { class: 'pv-new' },
            h('summary', {}, '처음이라면 — 새 계정과 첫 패스키 만들기'),
            h('p', {}, '계정 이름은 실명이 아닌 별명으로 적어 주세요. 기기가 열쇠 한 쌍을 만들고, 서버에는 공개키만 보냅니다.'),
            h('div', { class: 'pv-row' },
              h('label', { class: 'pv-field' }, h('span', {}, '계정 이름 (영어 소문자·숫자 3~20자)'), name),
              h('label', { class: 'pv-field' }, h('span', {}, '패스키 이름 (알아보기 쉽게)'), pkName)),
            h('div', { class: 'pv-row' }, regBtn)),
          m.el)));
  }

  async function renderUnlocked() {
    const [priv, keysRes] = await Promise.all([
      api('GET', '/api/private', null, { label: '비공개 자료 조회', silent: true }),
      api('GET', '/api/passkeys', null, { label: '패스키 목록', silent: true }),
    ]);
    if (priv.status !== 200) { state.loggedIn = false; return renderLocked(); }
    const m = msgBox();
    const km = msgBox();

    // 비공개 항목
    const title = h('input', { type: 'text', maxlength: '60', placeholder: '예: 다음 주 할 일' });
    const text = h('textarea', { maxlength: '500', placeholder: '만들어 넣은 내용만 적어 주세요 (실제 개인정보 X)' });
    const addBtn = h('button', { class: 'pv-btn small', type: 'button', onclick: async () => {
      addBtn.disabled = true;
      const r = await api('POST', '/api/private', { title: title.value, body: text.value }, { label: '비공개 항목 추가' });
      addBtn.disabled = false;
      if (r.status === 200) await refresh(); else m.set(r.data.message, 'bad');
    } }, '항목 추가');

    const items = priv.data.items.map((it) => {
      const card = h('article', { class: 'pv-item' });
      const showView = () => card.replaceChildren(
        h('span', { class: 'pv-kind' }, it.kind || '메모'),
        h('h4', {}, it.title),
        h('p', {}, it.body),
        h('span', { class: 'pv-id', title: '검증 도구에서 "다른 계정 항목 ID"로 쓸 수 있어요' }, 'ID ' + it.id),
        h('div', { class: 'pv-row' },
          h('button', { class: 'pv-btn small ghost', type: 'button', onclick: showEdit }, '고치기'),
          h('button', { class: 'pv-btn danger', type: 'button', onclick: async () => {
            if (!confirm('이 항목을 지울까요?')) return;
            const r = await api('DELETE', '/api/private?item=' + encodeURIComponent(it.id), null, { label: '비공개 항목 삭제' });
            if (r.status === 200) await refresh(); else m.set(r.data.message, 'bad');
          } }, '지우기')));
      function showEdit() {
        const t = h('input', { type: 'text', maxlength: '60', value: it.title, 'aria-label': '제목 고치기' });
        const b = h('textarea', { maxlength: '500', 'aria-label': '내용 고치기' }); b.value = it.body || '';
        const save = h('button', { class: 'pv-btn small', type: 'button', onclick: async () => {
          save.disabled = true;
          const r = await api('PATCH', '/api/private?item=' + encodeURIComponent(it.id), { title: t.value, body: b.value }, { label: '비공개 항목 고치기' });
          save.disabled = false;
          if (r.status === 200) await refresh(); else m.set(r.data.message, 'bad');
        } }, '저장');
        card.replaceChildren(
          h('span', { class: 'pv-kind' }, it.kind || '메모'),
          h('label', { class: 'pv-field' }, h('span', {}, '제목'), t),
          h('label', { class: 'pv-field' }, h('span', {}, '내용'), b),
          h('div', { class: 'pv-row' }, save, h('button', { class: 'pv-btn small ghost', type: 'button', onclick: showView }, '취소')));
        t.focus();
      }
      showView();
      return card;
    });

    // 패스키 목록
    const list = keysRes.data.passkeys || [];
    const keyItems = list.map((k) => h('li', { class: 'pv-key' },
      h('div', {},
        h('strong', {}, '🔑 ' + k.name),
        h('small', {}, `저장 위치(추정): ${k.storage} · ${k.synced}`),
        h('small', {}, `등록: ${fmtDate(k.createdAt)} · 마지막 사용: ${fmtDate(k.lastUsedAt)}`)),
      h('div', {}, h('button', { class: 'pv-btn danger', type: 'button', onclick: async () => {
        if (!confirm(`"${k.name}" 패스키를 지울까요?\n지우면 이 패스키로는 더 이상 들어올 수 없습니다.`)) return;
        const r = await api('DELETE', '/api/passkeys?id=' + encodeURIComponent(k.id), null, { label: `패스키 삭제 — ${k.name}` });
        if (r.status === 200) { await refresh(); } else km.set(r.data.message, r.status === 409 ? 'warn' : 'bad');
      } }, '지우기')),
      h('details', {}, h('summary', {}, '서버에 저장된 값 보기 (공개키)'),
        h('pre', {}, `패스키 ID: ${k.id}\n서명 방식: ${k.algorithm}\nAAGUID(인증기 종류): ${k.aaguid}\n\n${k.publicKeyPem}`),
        h('small', {}, '이 값은 공개키라 보여 줘도 안전합니다. 서명을 확인할 수는 있지만 만들 수는 없어서, 이것만으로는 들어올 수 없습니다.'))));

    const lastWarning = list.length <= 1
      ? h('p', { class: 'pv-msg warn' }, `패스키가 ${list.length}개뿐입니다. 이 기기를 잃어버리면 이 공간에 다시 들어올 방법이 없어요 (비밀번호 같은 복구 수단이 없음).\n그래서 마지막 패스키는 지울 수 없게 막아 두었습니다. 다른 기기에 하나 더 추가해 두세요.`)
      : h('p', { class: 'pv-msg ok' }, `패스키가 ${list.length}개 있습니다. 하나를 잃어버려도 다른 하나로 들어올 수 있어요.`);

    const newName = h('input', { type: 'text', value: guessDeviceName(), maxlength: '40', 'aria-label': '추가할 패스키 이름' });
    const addKeyBtn = h('button', { class: 'pv-btn small', type: 'button', onclick: async () => {
      addKeyBtn.disabled = true; await register({ passkeyName: newName.value.trim() }, km.set); addKeyBtn.disabled = false;
    } }, '+ 이 계정에 패스키 하나 더 추가');

    app.replaceChildren(
      h('div', { class: 'pv-box' },
        h('div', { class: 'pv-top' },
          h('div', {}, h('h3', {}, `🔓 ${priv.data.owner} 님의 공간`), h('span', { class: 'pv-fp' }, `세션 지문 ${state.fp || ''} · 세션 값 자체는 HttpOnly 쿠키라 화면에 나오지 않아요`)),
          h('button', { class: 'pv-btn ghost', type: 'button', onclick: logout }, '로그아웃')),
        h('p', {}, `비공개 항목 ${priv.data.count}개 · 아래 내용은 과제용으로 작성한 메모입니다 (연락처·신분증 번호 같은 개인정보 없음).`),
        h('div', { class: 'pv-items' }, items),
        h('details', { class: 'pv-new' }, h('summary', {}, '항목 추가하기'),
          h('div', { class: 'pv-row' }, h('label', { class: 'pv-field' }, h('span', {}, '제목'), title)),
          h('div', { class: 'pv-row' }, h('label', { class: 'pv-field' }, h('span', {}, '내용'), text)),
          h('div', { class: 'pv-row' }, addBtn)),
        m.el),
      h('div', { class: 'pv-box' },
        h('h3', {}, `내 패스키 ${list.length}개`),
        h('p', {}, '기기를 잃어버렸을 때를 대비해 두 개 이상 등록해 두세요. 같은 기기에는 같은 계정의 패스키를 두 번 만들 수 없어서, 휴대폰(QR)이나 다른 브라우저로 추가하면 됩니다.'),
        h('ul', { class: 'pv-keys' }, keyItems),
        lastWarning,
        h('div', { class: 'pv-row' }, h('label', { class: 'pv-field' }, h('span', {}, '추가할 패스키 이름'), newName), addKeyBtn),
        km.el));
  }

  async function refresh() {
    const me = await api('GET', '/api/me', null, { silent: true });
    state = { loggedIn: !!me.data.loggedIn, username: me.data.username, fp: me.data.sessionFingerprint };
    if (me.status === 503 || me.data.code === 'NO_DATABASE') {
      app.replaceChildren(h('div', { class: 'pv-box' }, h('h3', {}, '준비 중'), h('p', {}, me.data.message)));
    } else if (state.loggedIn) await renderUnlocked();
    else renderLocked();
    renderLab();
  }

  // ── 검증 도구 ─────────────────────────────────
  function test(title, desc, ...controls) {
    return h('div', { class: 'pv-test' }, h('b', {}, title), h('p', {}, desc), ...controls);
  }
  function btn(label, fn) {
    const b = h('button', { class: 'pv-btn small', type: 'button', onclick: async () => { b.disabled = true; try { await fn(); } finally { b.disabled = false; } } }, label);
    return b;
  }

  function renderLab() {
    if (!labBody) return;
    const lm = msgBox();
    const otherItem = h('input', { type: 'text', placeholder: '다른 계정 항목 ID (it_…)' });
    const otherName = h('input', { type: 'text', placeholder: '다른 계정 이름 (예: guest)' });

    labBody.replaceChildren(
      h('p', { class: 'pv-fp' }, '버튼을 누르면 실제 요청과 응답이 아래 기록에 쌓입니다. 기록은 이 브라우저에만 저장되고, 세션 쿠키 값은 들어가지 않습니다. 다 하면 "기록 복사"로 제출문에 붙여 넣으세요.'),
      h('div', { class: 'pv-lab-grid' },
        test('① 로그인 없이 비공개 자료 요청', '쿠키를 빼고 /api/private 를 직접 부릅니다. 401이 나와야 합니다.',
          btn('실행', async () => { await api('GET', '/api/private', null, { omitCookie: true, label: '[검증①] 로그인 없이 비공개 자료 요청' }); })),
        test('② 로그인 없이 받은 페이지 소스 검사', '쿠키 없이 첫 화면 HTML을 받아, 비공개 내용이 들어 있는지 찾습니다.',
          btn('실행', async () => {
            const r = await fetch('/', { credentials: 'omit', cache: 'no-store' });
            const html = await r.text();
            const words = ['느린 우체국', '지원해 보고 싶은 곳', 'ALEPH 과제 회고', '오늘의 감사'];
            const found = words.filter((w) => html.includes(w));
            const start = html.indexOf('<div id="pv-app"');
            record({ label: '[검증②] 로그인 없이 받은 첫 화면 HTML 검사', method: 'GET', path: '/', cookie: '쿠키를 일부러 보내지 않음', request: null, status: r.status,
              response: { 'HTML 길이': html.length, '찾아본 비공개 문구': words, '발견된 비공개 문구': found.length ? found : '없음 (0건)', '비공개 자리의 HTML': html.slice(start, html.indexOf('</div>', start) + 6) } });
          })),
        test('③ 질문 값이 매번 다른지', '로그인용 질문 3번(들어와 있으면 등록용 질문 3번도)을 받아 나란히 적습니다. 등록용 질문은 받은 뒤 바로 취소해서 아무것도 저장되지 않습니다.',
          btn('실행', async () => {
            const regC = [], logC = [];
            if (state.loggedIn) {
              for (let i = 0; i < 3; i++) {
                const r = await api('POST', '/api/register-options', {}, { silent: true });
                if (r.data.publicKey) { regC.push(r.data.publicKey.challenge); await api('POST', '/api/register-cancel', { challenge: r.data.publicKey.challenge }, { silent: true }); }
              }
            }
            for (let i = 0; i < 3; i++) { const r = await api('POST', '/api/login-options', null, { silent: true }); if (r.data.publicKey) logC.push(r.data.publicKey.challenge); }
            const all = [...regC, ...logC];
            record({ label: '[검증③] 질문(challenge) 값 비교', method: 'POST', path: (regC.length ? '/api/register-options ×3, ' : '') + '/api/login-options ×3', cookie: '-', request: null, status: 200,
              response: { 등록용질문: regC.length ? regC : '들어와 있을 때 다시 누르면 함께 기록됩니다', 로그인용질문: logC, '모두 서로 다른가': new Set(all).size === all.length ? `예 (${all.length}개 모두 다름)` : '아니오' } });
          })),
        test('④ 이미 쓴 질문으로 다시 로그인', '마지막으로 성공한 로그인 요청 본문을 그대로 한 번 더 보냅니다. 거절되어야 합니다.',
          btn('실행', async () => {
            const last = ss.get('pv-last-login');
            if (!last) return lm.set('먼저 "패스키로 들어가기"로 한 번 로그인한 뒤 눌러 주세요 (같은 탭에서).', 'warn');
            await api('POST', '/api/login-verify', JSON.parse(last), { omitCookie: true, label: '[검증④] 이미 성공한 로그인 요청을 그대로 다시 보내기' });
          })),
        test('⑤ 일부러 틀린 서명으로 로그인', '진짜 패스키로 서명한 뒤 서명 값 1바이트만 바꿔 보냅니다. 401이 나와야 합니다.',
          btn('실행', async () => { await login(lm.set, { tamper: true }); })),
        test('⑥ 로그아웃 후 같은 세션으로 다시 요청', '서버 세션만 지우고 브라우저 쿠키는 그대로 둔 채 비공개 자료를 다시 요청합니다. (들어와 있을 때만)',
          btn('실행', async () => {
            if (!state.loggedIn) return lm.set('먼저 패스키로 들어온 뒤 눌러 주세요.', 'warn');
            const fp = state.fp;
            await api('POST', '/api/logout?test=keep-cookie', null, { label: '[검증⑥] 로그아웃 (쿠키는 남겨 둠)' });
            await api('GET', '/api/private', null, { label: '[검증⑥] 로그아웃 뒤 같은 쿠키로 비공개 자료 요청', cookieNote: `sid=●●●●●●(가림, 로그아웃 전과 같은 값 · 지문 ${fp})` });
            await api('POST', '/api/logout', null, { silent: true });
            await refresh();
          })),
        test('⑦ 다른 계정의 자료 읽기·지우기', '다른 계정으로 들어가 항목 ID를 복사해 두고, 이 계정으로 들어와 그 ID로 요청합니다. 403이 나와야 합니다.',
          h('label', { class: 'pv-field' }, h('span', {}, '다른 계정 항목 ID'), otherItem),
          h('div', { class: 'pv-row' },
            btn('읽기 시도', async () => {
              await api('GET', '/api/private', null, { label: '[검증⑦] 시도 전 내 자료 건수' });
              await api('GET', '/api/private?item=' + encodeURIComponent(otherItem.value.trim()), null, { label: '[검증⑦] 다른 계정 항목 읽기 시도' });
            }),
            btn('지우기 시도', async () => {
              await api('DELETE', '/api/private?item=' + encodeURIComponent(otherItem.value.trim()), null, { label: '[검증⑦] 다른 계정 항목 지우기 시도' });
              await api('GET', '/api/private', null, { label: '[검증⑦] 시도 후 내 자료 건수' });
            }))),
        test('⑧ 주소에 다른 계정 이름을 넣어 요청', '?owner=다른계정 을 붙여 비공개 자료를 요청합니다. 그래도 내 자료만 와야 합니다.',
          h('label', { class: 'pv-field' }, h('span', {}, '다른 계정 이름'), otherName),
          btn('실행', async () => { await api('GET', '/api/private?owner=' + encodeURIComponent(otherName.value.trim() || 'guest'), null, { label: '[검증⑧] 주소에 다른 계정 이름을 적어 요청' }); })),
        test('⑨ 지금 내 자료 건수 / 패스키 기록', '다른 계정이 시도하기 전과 후에 눌러 건수가 같은지 남기세요. 서버에 저장된 공개키도 함께 기록됩니다.',
          h('div', { class: 'pv-row' },
            btn('내 자료 건수', async () => { await api('GET', '/api/private', null, { label: '[검증⑨] 지금 내 자료 건수' }); }),
            btn('서버에 저장된 내 패스키', async () => { await api('GET', '/api/passkeys', null, { label: '[검증⑨] 서버에 저장된 내 패스키(공개키)' }); })))),
      lm.el,
      h('div', { class: 'pv-log' },
        h('div', { class: 'pv-row' },
          h('b', {}, `요청·응답 기록 ${log.length}건`),
          btn('기록 복사 (제출문용)', async () => {
            try { await navigator.clipboard.writeText(logToMarkdown()); lm.set('기록을 복사했습니다. 제출문에 붙여 넣으세요.', 'ok'); }
            catch { lm.set('복사하지 못했습니다. 아래 기록을 직접 드래그해 복사해 주세요.', 'warn'); }
          }),
          btn('기록 지우기', async () => { if (confirm('기록을 모두 지울까요?')) { log = []; ls.set('pv-lab-log', '[]'); renderLog(); renderLab(); } })),
        h('ol', { id: 'pv-log-list' })));
    renderLog();
  }

  function renderLog() {
    const ol = document.getElementById('pv-log-list');
    if (!ol) return;
    ol.replaceChildren(...log.slice().reverse().map((e) => {
      const cls = e.status >= 500 || e.status === 0 ? 's5' : e.status >= 400 ? 's4' : 's2';
      return h('li', { value: String(e.n) },
        h('b', {}, e.label), h('span', { class: 'pv-st ' + cls }, String(e.status)), ` · ${e.time}`,
        h('pre', {}, `${e.method} ${e.path}\n쿠키: ${e.cookie}` + (e.note ? `\n메모: ${e.note}` : '') + (e.request ? `\n\n[요청 본문]\n${JSON.stringify(e.request, null, 2)}` : '') + `\n\n[응답 ${e.status}]\n${JSON.stringify(e.response, null, 2)}`));
    }));
  }

  function logToMarkdown() {
    return log.map((e) => [
      `### ${e.n}. ${e.label} → ${e.status}`,
      `- 시각: ${e.time}`,
      `- 요청: \`${e.method} ${e.path}\``,
      `- 쿠키: ${e.cookie}`,
      e.note ? `- 메모: ${e.note}` : null,
      e.request ? '\n요청 본문\n```json\n' + JSON.stringify(e.request, null, 2) + '\n```' : null,
      `\n응답 ${e.status}\n` + '```json\n' + JSON.stringify(e.response, null, 2) + '\n```',
    ].filter(Boolean).join('\n')).join('\n\n');
  }

  refresh();
})();
