// 비공개 공간에 처음 넣어 두는 항목 (과제용으로 작성한 메모 — 연락처·신분증 번호 같은 개인정보 없음)
// 첫 번째로 만든 계정(owner)과 두 번째 계정(guest)에 서로 다른 내용이 들어갑니다.
import crypto from 'node:crypto';

export function newItemId() {
  return 'it_' + crypto.randomBytes(9).toString('base64url');
}

const OWNER = [
  {
    kind: '프로젝트 메모',
    title: '느린 우체국 앱 아이디어',
    body: '지금 쓴 편지를 정한 날짜에 미래의 나(또는 친구)에게 보내 주는 앱. 받는 날까지는 편지가 잠겨 있어서 열어 볼 수 없다. 먼저 편지 쓰기 화면과 날짜 고르기 화면을 스케치해 보기.',
  },
  {
    kind: '지원 목록',
    title: '지원해 보고 싶은 곳',
    body: '① SK텔레콤 정보보호 조직 — 정보보호 인력을 2배로 늘리겠다고 발표했고 레드팀(공격 시나리오로 보안 점검)을 뽑았다. 경력 요건이 있어 신입 공고는 따로 확인하기. ② 대구 혁신도시 공공기관 — 한국지능정보사회진흥원(NIA), 한국교육학술정보원(KERIS), 한국가스공사의 전산·정보보안 분야. 공고가 나오면 직렬부터 확인하기. (공개된 채용 정보를 보고 적은 목록, 실제 지원 내역 아님)',
  },
  {
    kind: '회고',
    title: 'SKT ALEPH 과제 회고',
    body: '소개 페이지에서 시작해 게임, 이미지 도구, 기온 정보판, 다이어리 앱까지 하나씩 만들어 왔다. 이번 과제 8에서는 비밀번호 대신 공개키와 일회용 질문으로 잠그는 원리를 직접 붙여 보면서, "막았다"는 말보다 막힌 요청과 응답을 보여 주는 것이 중요하다는 걸 배웠다.',
  },
];

const GUEST = [
  {
    kind: '감사 한 줄',
    title: '오늘의 감사',
    body: '함께 취향을 공유한 동료에게 고맙다.',
  },
];

// order: 몇 번째로 만든 계정인지 (1 = owner, 그 밖 = guest)
export function seedItems(order) {
  const now = new Date().toISOString();
  return (order === 1 ? OWNER : GUEST).map((it) => ({ id: newItemId(), ...it, createdAt: now }));
}
