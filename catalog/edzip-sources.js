export const EDZIP_OFFICIAL_SOURCES = [
  {
    id: 'law.school-materials',
    kind: 'law',
    title: '초·중등교육법 제29조의2',
    url: 'https://www.law.go.kr/법령/초·중등교육법/제29조의2',
    effective: '2026-03-01',
    summary: '학습지원 소프트웨어를 교육 자료로 선정할 때 교육부 기준과 학교운영위원회 심의를 요구한다.',
  },
  {
    id: 'law.school-council',
    kind: 'law',
    title: '초·중등교육법 제32조',
    url: 'https://www.law.go.kr/법령/초·중등교육법/제32조',
    effective: 'current',
    summary: '교과용 도서와 교육 자료 선정은 학교운영위원회 심의 사항이다.',
  },
  ...[
    ['3', '개인정보 보호 원칙'], ['15', '수집·이용'], ['16', '수집 제한'], ['17', '제3자 제공'],
    ['21', '파기'], ['22의2', '아동의 개인정보 보호'], ['26', '업무위탁'], ['28의8', '국외 이전'],
    ['29', '안전조치의무'], ['30', '처리방침'], ['31', '보호책임자'], ['35', '열람'], ['36', '정정·삭제'], ['37', '처리정지'],
  ].map(([article, label]) => {
    const articleLabel = article.includes('의') ? `${article.replace('의', '조의')}` : `${article}조`;
    return ({
    id: `law.privacy-${article}`,
    kind: 'law',
    title: `개인정보 보호법 제${articleLabel}`,
    url: `https://www.law.go.kr/법령/개인정보보호법/제${articleLabel}`,
    effective: '2025-10-02',
    summary: label,
  }); }),
  {
    id: 'moe.selection-guideline', kind: 'official-guide',
    title: '교육부 학습지원 소프트웨어 선정 기준 안내',
    url: 'https://www.moe.go.kr/boardCnts/viewRenew.do?boardID=294&boardSeq=105007&lev=0&m=020',
    effective: '2025-12-30',
    summary: '적용 대상, 필수·선택 기준, 선정 절차와 서식의 공식 안내.',
  },
  {
    id: 'edzip.registration-notice', kind: 'official-guide',
    title: '에듀집 회원가입 및 체크리스트 등록 안내',
    url: 'https://edzip.kr/main-notice/6a4de417a450e64b79a52ce9',
    effective: '2026-01-28',
    summary: '사업자 미등록 교사 등 개인의 구글폼 제출 경로를 포함한다.',
  },
  {
    id: 'edzip.checklist-notice', kind: 'official-guide',
    title: '에듀집 학습지원 소프트웨어 필수기준 체크리스트 등록 안내',
    url: 'https://edzip.kr/main-notice/6a17f7ebb8641362b8b5cabc',
    effective: '2026-05-28',
    summary: '체크리스트 등록·보완 절차의 공식 안내.',
  },
  {
    id: 'edzip.individual-form', kind: 'submission',
    title: '교사 등 개인 제작 학습지원 소프트웨어 제출 양식',
    url: 'https://forms.gle/aCa4mjvgtmovEf1eA',
    effective: 'verified-2026-07-27',
    summary: '구글 계정 로그인이 필요하며, 자동 제출하지 않는다.',
  },
  {
    id: 'edzip.results', kind: 'submission',
    title: '에듀집 필수기준 점검결과',
    url: 'https://edzip.kr/learning-sw',
    effective: 'current',
    summary: '확인중·보완요청·확인완료 상태를 확인하는 공식 목록.',
  },
];

export const EDZIP_CONTACTS = [
  {
    topic: '교사 개인 제작 소프트웨어 체크리스트 등록',
    organization: '한국교육학술정보원 교수학습지원부',
    phones: ['053-714-0357', '053-714-0308'],
    sourceId: 'edzip.registration-notice',
  },
  {
    topic: '에듀집 사이트 이용',
    organization: '에듀집 운영센터',
    phones: ['02-450-3550'],
    email: 'support@edzip.net',
    hours: '평일 10:00~17:00, 점심 12:00~13:00',
    sourceUrl: 'https://edzip.kr/user-manual',
  },
];
