// Track 3 "내 앱 보호(비법·저작권)" 카탈로그 (SSOT).
// 교사가 만든 앱의 비법(프롬프트·로직·데이터)과 권리를 지키는 준비 상태를 점검한다.
// 각 항목: id, group, title, severity, method(deterministic|ai|declared), gate, serverVerifiable,
//   plain(비개발자 설명), aiFix(교사 AI용 프롬프트).
//
// 정직성 원칙(전 문구 공통):
// - 난독화·Base64 인코딩은 비밀이 아니다. 브라우저로 전달된 것은 공개로 가정한다.
// - "완전 보호"는 존재하지 않는다. 이 트랙은 점수가 아니라 6가지 상태
//   (서버 분리 확인 / 일부 서버 분리 / 공개 자산 / 복제 비용 상승 조치 / 권리·이용 안내 설정 / 권리관계 확인 필요)
//   로 현재 위치를 구분해 보여준다.

export const PROTECTION_ITEMS = [
  // ── 권리관계 (rights 4) ──
  { id: 'protection.rights.owner-status', group: '권리관계', title: '권리자 확인', severity: 'high', gate: true, serverVerifiable: false, method: 'declared',
    plain: '이 앱을 누가 만들었고 권리가 누구에게 있는지(혼자 만든 건지, 같이 만든 건지, 학교 일로 만든 건지)를 먼저 확인해야 해요. 이게 분명해야 지킬 권리도 분명해져요.',
    aiFix: 'dcheck interview 로 권리자 문항에 답하게 하고, 답을 rights-profile 에 기록해줘. 학교 업무와 관련해 만든 앱이면 소속 기관과의 권리 정리가 필요한지 함께 확인해줘.' },
  { id: 'protection.rights.third-party', group: '권리관계', title: '남이 만든 재료 확인', severity: 'high', gate: true, serverVerifiable: false, method: 'declared',
    plain: '앱에 들어간 남이 만든 재료(이미지·글꼴·코드 조각·템플릿)를 어떤 조건으로 쓸 수 있는지 확인해야 해요. 남의 재료 위에는 내 이용 조건을 마음대로 정할 수 없어요.',
    aiFix: '프로젝트의 외부 자산(이미지·폰트·라이브러리·템플릿)을 훑어 출처와 이용 조건을 확인하고, 문제 소지가 있는 항목을 알려줘.' },
  { id: 'protection.rights.ai-contribution', group: '권리관계', title: 'AI가 만든 부분 확인', severity: 'medium', gate: false, serverVerifiable: false, method: 'declared',
    plain: 'AI가 만들어 준 부분과 내가 직접 만들고 고른 부분을 구분해 두면, 내 권리를 주장할 수 있는 범위가 분명해져요.',
    aiFix: '이 앱에서 AI 생성 비중이 큰 부분과 사용자가 직접 설계·작성한 부분(기획·프롬프트·데이터·문구)을 구분해 기록해줘.' },
  { id: 'protection.rights.license-consistency', group: '권리관계', title: '기존 공개 조건과 충돌 없음', severity: 'medium', gate: true, serverVerifiable: false, method: 'declared',
    plain: '이미 오픈소스로 공개했거나 다른 이용 조건을 붙여 둔 적이 있다면, 새로 정하는 이용 조건과 부딪히지 않는지 확인해야 해요.',
    aiFix: '저장소의 LICENSE·README·배포 이력을 확인해 이미 공개된 이용 조건이 있는지 보고, 새 이용 조건과 충돌하면 알려줘.' },

  // ── 비법 경계 (boundary 7) ──
  { id: 'protection.boundary.client-secrets', group: '비법 경계', title: '배포물에 비밀 키 없음', severity: 'critical', gate: true, serverVerifiable: false, method: 'deterministic',
    plain: '사용자 브라우저로 내려가는 파일(빌드 산출물)에 비밀 키가 들어 있으면 누구나 꺼내 쓸 수 있어요.',
    aiFix: '빌드 산출물에서 검출된 키·토큰을 서버 전용 환경변수로 옮기고, 노출된 키는 즉시 재발급(rotate)해줘.' },
  { id: 'protection.boundary.prompt', group: '비법 경계', title: '비공개 프롬프트가 새지 않음', severity: 'high', gate: true, serverVerifiable: false, method: 'ai',
    plain: 'AI 앱의 비법인 지시문(프롬프트)이 브라우저로 내려가는 파일에 통째로 들어 있으면 누구나 복사할 수 있어요. 비법 지시문은 서버에만 두세요.',
    aiFix: '클라이언트 번들에서 프롬프트로 보이는 긴 지시문을 찾아, 서버(API 라우트·서버 액션) 쪽으로 옮기고 클라이언트에는 호출만 남겨줘.' },
  { id: 'protection.boundary.weights', group: '비법 경계', title: '모델·데이터 파일 비공개', severity: 'high', gate: false, serverVerifiable: false, method: 'deterministic',
    plain: '학습된 모델 파일이나 핵심 데이터 파일이 공개 폴더에 있으면 통째로 내려받을 수 있어요.',
    aiFix: '공개 경로에 있는 모델·데이터 파일을 서버 저장소로 옮기고, 꼭 필요한 결과만 API 로 내려보내줘.' },
  { id: 'protection.boundary.server', group: '비법 경계', title: '핵심 로직 서버 분리', severity: 'high', gate: false, serverVerifiable: false, method: 'ai',
    plain: '앱의 비법(채점 규칙·생성 로직 같은 핵심 계산)이 서버 뒤에 있는지 확인해요. 브라우저로 간 코드는 공개된 것으로 봐야 해요. 서버로 옮기는 것이 가장 근본적인 보호예요.',
    aiFix: '핵심 로직이 클라이언트 번들에 있는지 확인하고, 비법에 해당하는 부분을 서버(API 라우트·서버 액션·엣지 함수)로 옮겨줘. 클라이언트에는 호출과 표시만 남겨줘.' },
  { id: 'protection.boundary.output-leak', group: '비법 경계', title: '응답이 비법 원문을 돌려주지 않음', severity: 'medium', gate: false, serverVerifiable: false, method: 'ai',
    plain: '서버가 결과만 주지 않고 비법 지시문이나 정답 데이터 원문까지 통째로 돌려주면, 서버에 뒀어도 새는 것과 같아요.',
    aiFix: 'API 응답에 프롬프트 원문·정답 데이터 전체·내부 설정이 실려 나가지 않는지 확인하고, 화면에 필요한 결과만 내려보내게 고쳐줘.' },
  { id: 'protection.boundary.api-abuse', group: '비법 경계', title: '무제한 호출 방지', severity: 'medium', gate: false, serverVerifiable: false, method: 'ai',
    plain: '내 서버 기능을 아무나 무한정 부를 수 있으면, 남이 내 API 를 자기 앱처럼 쓰거나 내 비용을 쓰게 할 수 있어요. 호출 제한이나 로그인 확인을 두세요.',
    aiFix: '핵심 API 에 호출 제한(rate limit)이나 로그인 확인을 추가하고, 외부 사이트에서 마음대로 부르지 못하게 출처 확인을 넣어줘.' },
  { id: 'protection.asset.inventory', group: '비법 경계', title: '보호할 자산 목록', severity: 'medium', gate: false, serverVerifiable: false, method: 'declared',
    plain: '무엇이 내 앱의 비법인지(지시문·데이터·디자인·문구 등) 목록으로 적어 두어야 무엇을 지킬지 정할 수 있어요. 목록에는 비밀 원문이 아니라 이름만 적어요.',
    aiFix: 'dcheck interview 로 보호할 자산을 물어 rights-profile 의 protectedAssets 에 이름과 종류만(원문 없이) 기록해줘.' },

  // ── 배포 위생 (release 5) ──
  { id: 'protection.release.sourcemap', group: '배포 위생', title: '소스맵 미포함', severity: 'medium', gate: false, serverVerifiable: false, method: 'deterministic',
    plain: '빌드 산출물에 소스맵(.map)이 있으면 원본 코드 구조를 그대로 복원할 수 있어요.',
    aiFix: '프로덕션 빌드에서 소스맵 생성을 끄거나(protect apply 로 제거 가능), 배포에 포함되지 않게 해줘.' },
  { id: 'protection.release.debug', group: '배포 위생', title: '디버그 흔적 정리', severity: 'low', gate: false, serverVerifiable: false, method: 'deterministic',
    plain: '배포물에 debugger 문이나 비밀스러운 값을 찍는 콘솔 로그가 남아 있으면 내부 동작이 새요.',
    aiFix: '배포 빌드에서 debugger 문과 키·프롬프트를 찍는 console 로그를 제거해줘.' },
  { id: 'protection.release.private-identifiers', group: '배포 위생', title: '내 컴퓨터 경로 미노출', severity: 'low', gate: false, serverVerifiable: false, method: 'deterministic',
    plain: '배포물에 내 컴퓨터의 폴더 경로(사용자 이름 포함)가 남아 있으면 개인 정보와 내부 구조가 새요.',
    aiFix: '빌드 산출물에 남은 절대 경로(/Users/... 등)를 찾아 원인(소스맵·로그·설정)을 제거해줘.' },
  { id: 'protection.release.separation', group: '배포 위생', title: '소스 원본 미포함', severity: 'medium', gate: false, serverVerifiable: false, method: 'deterministic',
    plain: '배포 산출물 안에 원본 소스 파일이 그대로 들어 있으면 빌드를 거치지 않은 비법까지 함께 공개돼요.',
    aiFix: '배포 산출물에 섞여 들어간 원본 소스(.ts·.tsx·src 폴더 등)를 빌드에서 제외해줘.' },
  { id: 'protection.release.integrity', group: '배포 위생', title: '산출물 지문(해시) 기록', severity: 'low', gate: false, serverVerifiable: false, method: 'deterministic',
    plain: '배포물의 파일별 지문(해시)을 기록해 두면, 나중에 "이건 내 원본"임을 보일 근거가 돼요.',
    aiFix: 'dcheck protect apply 를 실행해 산출물 해시 매니페스트를 만들어줘.' },

  // ── 안내·증거 (notice/evidence 6) ──
  { id: 'protection.notice.visible', group: '안내·증거', title: '사람이 읽는 권리 안내', severity: 'medium', gate: false, serverVerifiable: false, method: 'deterministic',
    plain: '이 앱의 권리가 누구에게 있고 어떻게 쓸 수 있는지, 사람이 읽을 수 있는 안내(라이선스 문서·저작권 표시)가 있어야 해요.',
    aiFix: 'dcheck interview 로 권리관계를 확인한 뒤 protect apply 로 권리 안내를 만들어줘. 권리관계가 확인되기 전에는 라이선스 문서를 만들지 마.' },
  { id: 'protection.notice.machine-readable', group: '안내·증거', title: '기계가 읽는 안내', severity: 'medium', gate: false, serverVerifiable: true, method: 'deterministic',
    plain: 'AI 수집기·검색로봇이 읽는 안내 파일(robots.txt 의 AI 수집기 차단, llms.txt, TDM 예약)을 두면 "이 앱은 수집·복제 대상이 아니다"라는 의사를 기계에게도 전할 수 있어요. 다만 지키지 않는 수집기도 있어요.',
    aiFix: 'dcheck protect apply 로 robots.txt AI 수집기 차단 블록·llms.txt·TDM 예약 파일을 만들어줘. 일반 검색로봇은 막지 않아 검색 노출은 유지돼.' },
  { id: 'protection.notice.app-footer', group: '안내·증거', title: '앱 화면 권리 표시', severity: 'low', gate: false, serverVerifiable: false, method: 'ai',
    plain: '앱 화면(푸터 등)에 만든 사람과 이용 조건 안내가 보이면, 쓰는 사람도 지켜야 할 조건을 알 수 있어요.',
    aiFix: '앱 푸터나 정보 화면에 저작권 표시와 이용 안내 링크를 추가해줘. rights-profile 의 attribution 문구를 쓰면 돼.' },
  { id: 'protection.evidence.manifest', group: '안내·증거', title: '증거팩(해시·만든 기록)', severity: 'medium', gate: false, serverVerifiable: false, method: 'deterministic',
    plain: '산출물 지문과 만든 기록(git 이력)을 묶어 두면, 누가 베꼈을 때 "내가 먼저 만들었다"를 보이는 데 도움이 돼요. 소송을 보장하는 것은 아니에요.',
    aiFix: 'dcheck protect apply 를 실행해 증거팩(MANIFEST·git 기록)을 만들어줘.' },
  { id: 'protection.evidence.timestamp', group: '안내·증거', title: '시점 증명(선택)', severity: 'info', gate: false, serverVerifiable: false, method: 'deterministic',
    plain: '증거팩에 블록체인 시점 증명(OpenTimestamps)을 더하면 "이 시점에 존재했다"를 제3자가 확인할 수 있어요. 선택 사항이에요.',
    aiFix: 'opentimestamps-client(ots)를 설치한 뒤 protect apply 를 다시 실행하면 시점 증명이 붙어. 없어도 git 시각과 해시가 기본 증거야.' },
  { id: 'protection.verify.functional', group: '안내·증거', title: '적용 후 기능 확인', severity: 'high', gate: true, serverVerifiable: false, method: 'deterministic',
    plain: '보호 조치를 적용한 뒤 앱이 깨지지 않았는지 확인해야 해요. 깨졌으면 백업으로 되돌릴 수 있어요.',
    aiFix: 'dcheck verify 로 적용 전후 산출물을 비교 검증하고, 문제가 있으면 dcheck protect restore 로 되돌려줘.' },
];
