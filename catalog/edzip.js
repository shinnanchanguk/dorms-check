// Track 2 "학운위 심사 준비" 카탈로그 (SSOT).
// 원천: 에듀집 「학습지원 소프트웨어 필수기준 체크리스트(공급자용)」 5대기준 9세부 +
//   개인정보처리방침 조항 매핑. 법령은 korean-law MCP 실검증(2026-07-08, 개인정보 보호법 시행 2025-10-02).
// 안전 문안: "학운위 심사 준비 완료" = '심의에 낼 증빙이 갖춰진 상태'. 통과 보장 아님. 심의·최종 결정은 학교.

// 케이스 진단 3문항 → A/B/C/D. 스킬이 init 에서 물어 config 에 기록.
export const EDZIP_CASE_QUESTIONS = [
  { id: 'q1', ask: '이 앱이 학생의 개인정보나 학습 콘텐츠(학생이 쓴 글·답안·이름 등)를 다루나요?' },
  { id: 'q2', ask: '그 정보가 학교 밖(외부 서버·클라우드·외부 AI API)으로 나가나요?' },
  { id: 'q3', ask: '나간다면, 이름 같은 식별정보를 가리거나(가명처리) 학생 정보를 로컬에만 두어 외부로 안 보내나요?' },
];

// 케이스 판정 규칙(참고): q1=아니오 → A(단순 도구), q1=예·q2=아니오 → B(로컬 학습지원),
//   q1=예·q2=예·q3=예 → C(마스킹 외부전송), q1=예·q2=예·q3=아니오 → D(식별정보 외부전송, 최고 주의).

export const EDZIP_ITEMS = [
  { id: 'edzip.1-1', criterion: '1. 최소처리 원칙', title: '개인정보를 최소한으로만 수집', severity: 'high', gate: true, serverVerifiable: true, method: 'hybrid', policy: ['제2조', '제3조'],
    plain: '꼭 필요한 개인정보만 모아야 하고, 무엇을 왜 모으는지 개인정보처리방침에 분명히 적혀 있어야 해요.',
    law: '개인정보 보호법 제3조(개인정보 보호 원칙), 제30조(처리방침)',
    aiFix: '개인정보처리방침 제2조(수집 항목)·제3조(수집 목적)를 만들고, 실제 수집 코드가 방침에 적힌 항목만 모으는지 대조해줘. templates/privacy-policy.ko.md 참고.' },
  { id: 'edzip.1-2', criterion: '1. 최소처리 원칙', title: '수집·이용 목적 명시', severity: 'high', gate: true, serverVerifiable: true, method: 'hybrid', policy: ['제3조'],
    plain: '개인정보를 어디에 쓰는지(목적)를 방침에 적어야 해요.',
    law: '개인정보 보호법 제15조(수집·이용), 제30조',
    aiFix: '개인정보처리방침에 처리 목적을 항목별로 적어줘.' },
  { id: 'edzip.1-3', criterion: '1. 최소처리 원칙', title: '수집 항목·보유기간 고지', severity: 'high', gate: true, serverVerifiable: true, method: 'hybrid', policy: ['제2조', '제4조'],
    plain: '무엇을 얼마 동안 보관하는지 적어야 해요.',
    law: '개인정보 보호법 제21조(파기), 제30조',
    aiFix: '방침에 수집 항목과 보유·이용 기간, 기간 지난 뒤 파기 방법을 적어줘.' },
  { id: 'edzip.2-1', criterion: '2. 안전조치 의무', title: '개인정보 안전조치', severity: 'critical', gate: true, serverVerifiable: true, method: 'hybrid', policy: ['제9조'],
    plain: '개인정보가 새거나 도난·위조되지 않도록 암호화·접근통제 같은 안전조치를 갖추고 방침에 밝혀야 해요.',
    law: '개인정보 보호법 제29조(안전조치 의무)',
    aiFix: 'HTTPS 강제·전송/저장 암호화·접근 통제·RLS 를 갖추고, 방침 제9조(안전성 확보조치)에 관리적/기술적/물리적 조치를 적어줘. (보안 트랙의 RLS·헤더 항목과 연결됨)' },
  { id: 'edzip.3-1', criterion: '3. 정보주체 권리', title: '열람·정정·삭제·처리정지 절차', severity: 'high', gate: true, serverVerifiable: true, method: 'hybrid', policy: ['제7조'],
    plain: '사용자가 자기 정보를 보고·고치고·지워달라고 요청하는 방법을 안내해야 해요(법정 처리 기한 있음).',
    law: '개인정보 보호법 제35~37조(열람·정정·삭제·처리정지)',
    aiFix: '방침 제7조에 정보주체 권리와 행사 방법(연락처·처리 기한)을 적어줘.' },
  { id: 'edzip.4-1', criterion: '4. 만 14세 미만 보호', title: '아동 개인정보 보호', severity: 'critical', gate: true, serverVerifiable: false, method: 'ai', policy: ['제8조'],
    plain: '만 14세 미만 학생 정보는 특별히 조심해야 해요. 이용자를 교사로 한정하거나, 학생 식별정보를 외부로 안 보내고 로컬에만 두는 식으로 다뤄야 해요.',
    law: '개인정보 보호법 제22조의2(만 14세 미만 아동의 개인정보 처리)',
    aiFix: '이용자를 교사로 한정하고, 학생 식별정보는 외부로 보내지 말고(로컬 저장) 외부 AI 로 보낼 때는 이름 등을 가명처리(학생1/학생2)해줘. 방침 제8조에 이 구조와 법적 위치를 적어줘.' },
  { id: 'edzip.5-1', criterion: '5. 책임자·제공·위탁', title: '개인정보 보호책임자', severity: 'medium', gate: true, serverVerifiable: true, method: 'hybrid', policy: ['제10조'],
    plain: '개인정보를 책임지는 담당자와 연락처를 방침에 적어야 해요.',
    law: '개인정보 보호법 제31조(개인정보 보호책임자)',
    aiFix: '방침 제10조에 보호책임자 이름·연락처와 분쟁조정·침해신고 안내를 적어줘.' },
  { id: 'edzip.5-2', criterion: '5. 책임자·제공·위탁', title: '제3자 제공', severity: 'high', gate: true, serverVerifiable: true, method: 'hybrid', policy: ['제5조'],
    plain: '개인정보를 다른 곳에 넘기는지, 넘긴다면 어디에 왜 넘기는지 적고 동의를 받아야 해요.',
    law: '개인정보 보호법 제17조(제3자 제공)',
    aiFix: '제3자 제공이 있으면 방침 제5조에 제공받는 자·목적·항목을 적고 동의를 받아줘. 없으면 "제3자에게 제공하지 않는다"고 명시해줘.' },
  { id: 'edzip.5-3', criterion: '5. 책임자·제공·위탁', title: '처리 위탁(호스팅·AI)', severity: 'high', gate: true, serverVerifiable: true, method: 'hybrid', policy: ['제6조'],
    plain: 'Supabase·외부 AI 처럼 남의 서비스에 처리를 맡기면(위탁), 누구에게 무엇을 맡기는지 방침에 공개해야 해요. 해외 서버면 국외이전도 밝혀야 해요.',
    law: '개인정보 보호법 제26조(위탁), 제28조의8(국외이전)',
    aiFix: '방침 제6조에 수탁자(예: Supabase·OpenAI 등)와 위탁 업무·국외이전(리전) 을 적어줘.' },
];

// 학운위 배경 근거(마크 설명·공지에서 재사용). 검증 라벨 포함.
export const EDZIP_LEGAL_BASIS = [
  { law: '초·중등교육법 제29조의2 제2항', status: 'verified', effective: '2026-03-01',
    note: '학교장이 학습지원 소프트웨어를 교육 자료로 선정하려면 교육부장관이 개인정보 보호위원회와 협의해 정하는 기준을 따르고, 제32조에 따라 학교운영위원회 심의를 거쳐야 한다.',
    link: 'https://www.law.go.kr/법령/초·중등교육법/제29조의2' },
  { law: '초·중등교육법 제32조 제1항 제4호', status: 'verified', effective: '현행',
    note: '교육 자료의 선정은 학교운영위원회 심의사항(국·공·사립 공통).',
    link: 'https://www.law.go.kr/법령/초·중등교육법/제32조' },
  { law: '개인정보 보호법 제30조', status: 'verified', effective: '2025-10-02',
    note: '개인정보처리방침 수립·공개 의무(2026-09-11 시행예정 개정본도 문안 동일 확인).',
    link: 'https://www.law.go.kr/법령/개인정보보호법/제30조' },
  { law: '교육부 「학습지원 소프트웨어 선정 기준 안내」(2025-12-30)', status: 'reference', effective: '행정 안내자료',
    note: '필수기준 5대 영역의 출처(법령 아님).', link: 'https://www.korea.kr' },
];
