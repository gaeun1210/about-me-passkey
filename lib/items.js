// 비공개 공간에 처음 넣어 두는 예시 항목 (모두 지어낸 내용입니다. 실제 개인정보 아님)
import crypto from 'node:crypto';

export function newItemId() {
  return 'it_' + crypto.randomBytes(9).toString('base64url');
}

export function seedItems(username) {
  const now = new Date().toISOString();
  return [
    { id: newItemId(), kind: '프로젝트 메모', title: `[${username}] 준비 중인 프로젝트`, body: '(만든 예시) 공부법 앱 아이디어 — 25분 집중이 끝나면 "오늘 배운 것 한 줄" 질문을 띄우기. 다음 주까지 화면 스케치.', createdAt: now },
    { id: newItemId(), kind: '지원 목록', title: `[${username}] 지원해 보고 싶은 곳`, body: '(만든 예시) 가상의 교육기관 A — 디지털교육 지원 / 가상의 재단 B — 학습 플랫폼 운영. 실제 기관·지원 정보 아님.', createdAt: now },
    { id: newItemId(), kind: '회고', title: `[${username}] 이번 주 회고`, body: '(만든 예시) 패스키를 붙이며 알게 된 것: 서버에는 자물쇠(공개키)만 두고, 열쇠(개인키)는 기기에만 있다.', createdAt: now },
  ];
}
