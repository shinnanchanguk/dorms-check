// 심층 점검(audit) 공격 분류표 (SSOT).
// cloudflare/security-audit-skill(MIT) 의 공격 분류·영역별 규율을 교사 앱 기준으로 한국어로 옮기고 고쳐 썼다.
// 원문 출처는 각 항목의 cf 에 적는다. 저작권 고지는 audit/THIRD-PARTY-NOTICE.md.
//
// 겹치는 것은 넣지 않는다. 보안 헤더·전송·공개 노출·하드코딩 비밀값·RLS 익명 읽기처럼
// dorms-check 결정적 검사가 이미 판정하는 분류는 EXCLUDED_CLASSES 에 사유와 함께 남긴다.
// applies 는 audit/inventory.js 의 표면 종류(kind). 'always' 는 표면과 무관하게 한 단위를 만든다.

export const AUDIT_CLASSES = [
  {
    id: 'access-control',
    title: '접근 권한 우회',
    plain: '로그인·권한 확인이 있어도 다른 길로 같은 일을 할 수 있는지 봐요.',
    cf: 'ATTACK-CLASSES.md#Access control',
    applies: ['api-route', 'server-action', 'edge-function', 'db-function', 'cron-route'],
    hunt: [
      '같은 상태 변경에 이르는 다른 길(다른 API·서버 액션·DB 함수·일괄 처리)이 더 약한 권한 확인을 쓰는가.',
      '요청 본문의 필드(user_id, role, owner, is_admin 등)가 서버가 정한 권한을 덮어쓰는가.',
      '로그인만 확인하고 그 자원이 요청한 사람의 것인지(소유·역할)는 확인하지 않는가.',
      '일괄·내보내기·가져오기·검색 경로가 항목마다 권한을 다시 확인하는가.',
      'cron·웹훅·내부 전용 경로가 비밀값 확인 없이 누구에게나 열려 있는가.',
      'SECURITY DEFINER 함수·서비스 키 클라이언트가 호출자 권한을 다시 확인하지 않고 대신 처리하는가.',
    ],
    validate: [
      '더 낮은 권한의 사람, 그가 보낸 값, 막아야 했던 확인, 넘은 경계, 영향받은 자원을 모두 적는다.',
      '같은 일을 그 사람이 원래 할 수 있다면 우회가 아니다(자기 권한 안의 행동).',
    ],
    overlap: '미인증 호출 후보(code.endpoint.unauth)와 IDOR 지시문(ai/prompts/authz-idor.md)은 그대로 쓰고, 여기서는 다른 길·본문 덮어쓰기·일괄 경로·내부 전용 경로를 본다.',
  },
  {
    id: 'data-isolation',
    title: '데이터 칸막이와 수명',
    plain: '내 반·내 계정 데이터가 다른 사람에게 새는 길이 없는지, 지운 자료가 정말 사라지는지 봐요.',
    cf: 'DATA-ISOLATION-AND-LIFECYCLE.md',
    applies: ['db-migration', 'service-client', 'storage', 'export'],
    hunt: [
      'RLS 정책·서버 쿼리·서비스 키 클라이언트가 서로 다른 조건을 쓰는가(정책은 막는데 서버 경로가 우회).',
      '뷰(security_invoker 없음)·SECURITY DEFINER 함수·기본 권한(GRANT)이 RLS 를 돌아가게 하는가.',
      '파일 저장소 경로·서명 URL·공개 버킷이 다른 사람 파일까지 열거나, 권한이 바뀐 뒤에도 계속 유효한가.',
      '검색·알림·미리보기(OG)·캐시·로그·분석 같은 파생 복사본이 원본의 공개 범위 변경을 따라가는가.',
      '지운(숨긴) 글·탈퇴 계정이 직접 조회·검색·관계 조회·복원 경로로 다시 보이는가.',
      '내보내기·백업이 요청자가 볼 수 없는 칸·다른 사람 행·지운 자료를 담는가.',
    ],
    validate: [
      '원래 정책(정본)과 그것을 어기는 경로를 함께 적고, 다른 층이 같은 조건을 막지 않는지 확인한다.',
      '학교 개인정보 보존 기간 같은 방침만 다르고 실제 읽는 사람이 없으면 위험이 아니라 권고다.',
    ],
    overlap: '익명 키로 실제 읽히는지는 code.rls.anon-read 실측이, 로그인 없는 수정 정책은 code.rls.anon-write 가 이미 본다. 여기서는 로그인한 다른 사용자·서버 우회·파생 복사본·삭제 수명을 본다.',
  },
  {
    id: 'business-logic',
    title: '업무 규칙 깨기',
    plain: '점수·포인트·승인 같은 규칙을 순서 건너뛰기, 동시에 누르기, 이상한 숫자로 깨는지 봐요.',
    cf: 'ATTACK-CLASSES.md#Business logic',
    applies: ['api-route', 'server-action', 'db-function'],
    hunt: [
      '단계를 건너뛰거나 되돌리거나, 끝난 흐름을 다시 보내 같은 보상·승인을 두 번 받을 수 있는가.',
      '확인한 뒤 따로 쓰는(check-then-act) 처리에서 동시 요청으로 이중 적립·이중 승인·한도 초과가 되는가.',
      '음수·0·아주 큰 값·소수·문자열 숫자로 수량·점수·금액 계산이 깨지는가.',
      '마감·만료·하루 한도의 경계 시각, 시간대 차이에서 규칙이 어긋나는가.',
      '설정이 비었거나 외부 서비스가 실패했을 때 막지 않고 열어 주는가(fail-open).',
    ],
    validate: [
      '깨진 규칙과 그 결과(누가 무엇을 더 얻거나 잃었는지)를 구체적으로 적는다.',
      '동시성 주장은 원자적 처리(트랜잭션·유니크 제약·조건부 갱신)가 정말 없는지 코드로 확인한다.',
    ],
  },
  {
    id: 'feature-abuse',
    title: '기능 악용과 정보 새기',
    plain: '정상 기능(검색·내보내기·가입·공유 링크)을 엉뚱하게 써서 남의 정보를 알아내는지 봐요.',
    cf: 'ATTACK-CLASSES.md#Feature abuse and data leakage',
    applies: ['api-route', 'server-action', 'auth-flow', 'outbound-fetch', 'export'],
    hunt: [
      '검색·필터·정렬 결과로 볼 수 없는 자료의 존재나 값을 알아낼 수 있는가.',
      '오류 문구·응답 크기·상태 코드로 "없음"과 "권한 없음"이 갈려 계정·자료를 알아낼 수 있는가(가입·비밀번호 재설정·초대).',
      '미리보기·초안·공유 링크 토큰이 한 자료가 아니라 더 넓은 범위를 연다.',
      '사용자가 넣은 주소를 서버가 가져가는 기능(링크 미리보기·웹훅·이미지 가져오기)이 내부망·메타데이터 주소로 향할 수 있는가(SSRF, 리다이렉트 뒤 포함).',
      '내보내기·가져오기가 화면과 같은 권한 규칙을 따르는가.',
    ],
    validate: [
      '알아낸 비밀 사실(예: 특정 학생 계정이 있다)을 하나로 짚는다. 공개 정보나 응답 시간 흔들림만으로는 위험이 아니다.',
    ],
  },
  {
    id: 'injection',
    title: '주입과 2차 사용',
    plain: '입력이 저장된 뒤 다른 곳에서 HTML·쿼리·주소·파일 경로로 다시 쓰일 때 위험해지는지 봐요.',
    cf: 'ATTACK-CLASSES.md#Injection',
    applies: ['api-route', 'server-action', 'db-function', 'html-sink', 'outbound-fetch'],
    hunt: [
      '입력에서 위험한 곳(SQL·HTML·명령·템플릿·파일 경로·리다이렉트)까지 실제 경로를 따라간다.',
      '안전하게 저장된 값이 다른 코드에서 위험한 문맥으로 다시 쓰이는가(2차 주입: 제목→HTML, 슬러그→경로, 문자열→정규식).',
      '값이 아니라 필드 이름·키·헤더·메타데이터로 들어오는 주입이 있는가.',
      'RPC·동적 SQL(format, EXECUTE)·.or()/.filter() 문자열 조립에 사용자 입력이 섞이는가.',
    ],
    validate: [
      '프레임워크 자동 이스케이프·매개변수 바인딩이 이미 막으면 위험이 아니다. 그 통제를 먼저 확인한다.',
    ],
    overlap: '위험 패턴 목록(code.dangerous-pattern)은 위치만 알려 준다. 여기서는 실제 입력이 그 위치까지 닿는지 끝까지 따라간다.',
  },
  {
    id: 'client-side',
    title: '브라우저 쪽 공격',
    plain: '화면에 그리는 HTML, 창끼리 주고받는 메시지, 브라우저 저장소에서 생기는 문제를 봐요.',
    cf: 'CLIENT-SIDE.md',
    applies: ['html-sink', 'client-message', 'redirect', 'service-worker', 'browser-storage', 'static-html'],
    hunt: [
      'URL 조각·window.name·메시지·저장소 값이 innerHTML·dangerouslySetInnerHTML·마크다운 렌더·javascript: 주소로 흘러가는가(DOM XSS).',
      'postMessage 받는 쪽이 출처(origin)를 정확히 확인하는가. 보내는 쪽이 민감한 값을 "*" 로 보내는가.',
      '로그인 뒤 돌아갈 주소(next·returnTo·redirect)가 외부 주소·javascript: 로 갈 수 있는가(열린 리다이렉트).',
      '서비스 워커가 개인 화면을 계정 구분 없이 캐시해 로그아웃·계정 전환 뒤 남에게 보이는가.',
      '로그아웃·계정 전환 뒤에도 브라우저 저장소의 토큰·개인 자료가 남아 다른 계정이 읽는가.',
      '상태를 바꾸는 화면을 남의 사이트가 iframe 으로 띄워 클릭을 가로챌 수 있는가(읽기 전용 화면은 권고).',
    ],
    validate: [
      '조작 가능한 출처(source)와 실행·노출 지점(sink)을 둘 다 적는다. 자기 화면에 자기가 주입하는 것은 위험이 아니다.',
      'CSP·프레임워크 이스케이프·SameSite·noopener 기본값이 막는지 먼저 확인한다.',
    ],
    overlap: '보안 헤더 존재와 CSP 품질은 sec.header.* 와 csp-quality 지시문이 본다. 여기서는 코드 안 흐름을 본다.',
  },
  {
    id: 'web-auth',
    title: '로그인·세션·인증 흐름',
    plain: '로그인, 소셜 로그인 콜백, 비밀번호 재설정, 로그아웃, 웹훅 서명 확인이 엉뚱한 사람을 통과시키는지 봐요.',
    cf: 'WEB-PROTOCOL-AND-AUTH.md',
    applies: ['auth-flow', 'api-route', 'webhook'],
    hunt: [
      'OAuth·소셜 로그인 콜백이 state·PKCE·redirect 주소를 세션에 묶어 확인하는가.',
      '비밀번호 재설정·이메일 변경·계정 연결 토큰이 사람·행동에 묶이고, 한 번만 쓰이며, 만료되는가.',
      '로그아웃·비밀번호 변경·권한 회수 뒤 기존 세션·리프레시 토큰이 계속 통하는가.',
      '쿠키로 인증하는 상태 변경 요청이 다른 사이트에서 보낸 요청을 막는가(CSRF: 토큰·SameSite·Origin 확인).',
      'JWT 를 서명 확인 없이 decode 만 하거나, aud·iss·exp 를 확인하지 않는가.',
      '웹훅·외부 콜백이 서명(HMAC)을 상수 시간 비교로 확인하는가.',
      'Host·X-Forwarded-* 헤더로 재설정 링크·콜백 주소가 바뀌는가.',
    ],
    validate: [
      '받아들이면 안 되는 요청·토큰을 서버가 실제로 받아들이는 지점(줄)과 빠진 묶음(사람·세션·자원·만료)을 적는다.',
      '쿠키 플래그 누락만으로는 위험이 아니다. 그 쿠키로 무엇을 할 수 있는지까지 본다.',
    ],
    overlap: '쿠키 플래그·HTTPS 는 sec.transport.* 가 공개 응답으로 본다.',
  },
  {
    id: 'ai-llm',
    title: 'AI 기능',
    plain: '앱 안의 AI 가 남이 넣은 글에 휘둘려 다른 사람 정보를 보여주거나, 내 API 요금을 써버리는지 봐요.',
    cf: 'AI-AND-LLM.md',
    applies: ['ai-call'],
    hunt: [
      '다른 사람이 쓴 글·파일·검색 결과가 또 다른 사람의 AI 대화 맥락에 들어가는가(간접 프롬프트 주입). 그때 AI 가 쓸 수 있는 권한은 무엇인가.',
      'AI 출력이 HTML·마크다운·주소·명령으로 이스케이프 없이 실행되는가.',
      'AI 가 고른 도구 인자가 서버에서 다시 권한·값 확인 없이 DB·URL·파일로 가는가.',
      '시스템 프롬프트·맥락에 비밀값·다른 사용자 자료가 들어가 사용자가 꺼낼 수 있는가.',
      '로그인 없이 또는 횟수 제한 없이 운영자 API 키로 AI 를 부를 수 있어 요금이 새는가.',
      '대화 기록·임베딩·캐시 키가 계정·반 구분 없이 섞이는가.',
    ],
    validate: [
      '프롬프트 주입 자체는 위험이 아니다. 그것이 다른 사람 맥락·권한 밖 행동·비밀 노출로 이어지는 코드 지점을 적는다.',
      '"이렇게 답하지 마" 같은 안내 문구는 보안 장치가 아니다. 코드로 된 확인만 통제로 센다.',
    ],
  },
  {
    id: 'resource-cost',
    title: '자원·요금 고갈',
    plain: '작은 요청 하나로 서버를 멈추거나 AI·메일·문자 요금을 크게 쓰게 만드는지 봐요.',
    cf: 'RESOURCE-EXHAUSTION-AND-AVAILABILITY.md',
    applies: ['ai-call', 'upload', 'outbound-fetch', 'mail-send', 'api-route'],
    hunt: [
      '본문·파일·개수 상한 없이 받아 메모리·DB·저장소를 채우는가. 압축 해제·이미지 변환 뒤 크기도 다시 확인하는가.',
      '정규식·재귀·정렬이 짧은 입력으로 아주 오래 걸리는가(ReDoS).',
      '로그인 전에 비싼 일(AI 호출·메일 발송·외부 요청)을 하는가.',
      '한 사람이 반복해 운영자 요금(AI·메일·문자·지도 API)을 쓰게 할 수 있는가. 한도가 IP·클라이언트 값처럼 바꿀 수 있는 값에 걸렸는가.',
      '실패 시 재시도가 끝없이 이어지거나 한 건의 잘못된 자료가 대기열을 막는가.',
    ],
    validate: [
      '실제 서버에 부하를 주는 시험은 하지 않는다. 코드의 상한·한도 확인과 작은 로컬 시험으로만 판단한다.',
      '요청한 본인만 느려지는 것은 위험이 아니다. 다른 사용자·공유 서비스·운영자 요금에 닿아야 한다.',
    ],
  },
  {
    id: 'supply-chain',
    title: '의존성과 배포 경로',
    plain: '설치하는 패키지와 자동 배포 설정이 남의 코드를 들이거나 비밀값을 흘리는지 봐요.',
    cf: 'SUPPLY-CHAIN-AND-RELEASE.md',
    applies: ['manifest', 'ci'],
    hunt: [
      '잠금 파일(package-lock 등)이 없거나 버전이 고정되지 않아 설치할 때마다 다른 코드가 들어오는가.',
      '실재하지 않거나 이름이 비슷한 패키지(오타·환각 패키지)를 쓰는가.',
      'postinstall 같은 설치 스크립트가 무엇을 실행하는가.',
      'GitHub Actions 가 외부 기여자 코드(pull_request_target 등)를 비밀값이 있는 상태로 실행하는가. 워크플로 입력이 셸에 그대로 들어가는가.',
      '배포 권한 토큰의 범위가 필요보다 넓은가.',
    ],
    validate: [
      '오래된 버전 자체는 위험이 아니다. 누가 무엇을 바꿔 넣을 수 있고 어디서 실행되는지 이어서 적는다.',
      '저장소 보호 규칙·배포 서비스 설정처럼 코드에 없는 사실은 미확인으로 남긴다.',
    ],
  },
  {
    id: 'native-shell',
    title: '앱 껍데기와 웹뷰 다리',
    plain: '웹앱을 감싼 데스크톱·모바일 앱이 웹 화면에 지나친 기기 권한을 주는지 봐요.',
    cf: 'DESKTOP-MOBILE-AND-LOCAL-IPC.md',
    applies: ['native-shell'],
    hunt: [
      '웹뷰가 불러오는 주소가 고정돼 있는가. 외부 주소로 이동해도 기기 기능(파일·명령·알림) 다리를 그대로 쓸 수 있는가.',
      '딥링크·사용자 지정 주소 처리기가 받은 값을 확인 없이 화면 이동·로그인·파일 열기에 쓰는가.',
      '앱이 기기 저장소에 토큰을 평문으로 두거나, 로그아웃·계정 전환 뒤에도 남기는가.',
    ],
    validate: [
      '웹 쪽 공격자가 실제로 닿을 수 있는 다리 함수와 그 결과(파일 읽기·명령 실행 등)를 함께 적는다.',
    ],
  },
  {
    id: 'chained',
    title: '이어 붙인 공격과 신뢰 경계',
    plain: '하나씩은 괜찮은 기능들이 이어지면 위험해지는지 봐요.',
    cf: 'ATTACK-CLASSES.md#Chained vulnerabilities and trust boundaries',
    applies: ['always'],
    hunt: [
      '낮은 권한으로 만들 수 있는 산출물(올린 파일·닉네임·링크·초대)이 나중에 더 높은 권한의 판단에 쓰이는가.',
      'A 가 보장한 것과 B 가 가정한 것이 다른가(잘림·형 변환·정규화·반 범위).',
      '토큰·초대·AI 도구 권한이 갱신·역할 변경·위임 뒤 더 넓어지는가.',
      '설치·이전·숨김·복원·취소 사이의 틈에서 낡은 상태가 받아들여지는가.',
    ],
    validate: [
      '이어지는 각 단계의 전제를 모두 확인한다. 하나라도 확인되지 않으면 미확인으로 남긴다.',
    ],
  },
  {
    id: 'wildcard',
    title: '분류 밖 이상한 코드',
    plain: '정해진 분류에 안 들어가는 이상한 코드, 반쯤 만든 기능, 화면이 안 부르는 API 를 봐요.',
    cf: 'ATTACK-CLASSES.md#Wildcard',
    applies: ['always'],
    hunt: [
      '가장 이상한 코드는 무엇이고 왜 있는가. 실험·호환·대체(fallback) 기능은 검토를 덜 받았다.',
      '화면은 안 쓰지만 API 로는 부를 수 있는 기능이 있는가.',
      '시험 파일이 다루지 않는 경계는 무엇인가.',
      'temp·hack·legacy 같은 이름, "안전하다"는 주석을 실제로 확인한다.',
    ],
    validate: [
      '다른 분류와 같은 증거 기준을 쓴다. 이상하다는 느낌만으로는 위험이 아니다.',
    ],
  },
  {
    id: 'obvious-remainder',
    title: '기본 노출 나머지',
    plain: '자동 검사가 안 보는 기본 실수(보안 TODO, 디버그 경로, 시험용 계정)를 빠짐없이 훑어요.',
    cf: 'ATTACK-CLASSES.md#Obvious things',
    applies: ['always'],
    hunt: [
      '"TODO: 권한 추가", "FIXME: 검증" 같은 보안 관련 주석이 남았는가.',
      '디버그·개발 모드를 환경변수·쿼리·헤더로 운영에서 켤 수 있는가.',
      '시험·예시·시드 계정이 운영에서도 통하는가.',
      '/debug·/admin·/test·/metrics 같은 경로가 보호 없이 열렸는가.',
      '.gitignore 가 비밀값·업로드·로컬 설정을 실제로 덮는가.',
      '운영 오류 응답이 SQL 오류·내부 경로를 돌려주는가.',
    ],
    validate: [
      '항목마다 결과를 하나씩 적는다. 표시만 보고 위험이라 하지 말고 그 값이 실제로 민감한지까지 따라간다.',
    ],
    overlap: '비밀값·.env/.git 공개·스택 트레이스·CORS·쿠키 플래그는 결정적 검사가 이미 본다. 그 나머지만 본다.',
  },
];

// 겹치거나 교사 앱 범위 밖이라 뺀 분류. 범위표에 '해당 없음' 사유로 남긴다.
export const EXCLUDED_CLASSES = [
  { ref: 'ATTACK-CLASSES.md#Obvious things (헤더·TLS·쿠키·CORS·비밀값 노출)', reason: '결정적 공개 검사(sec.header.*, sec.transport.*, cors.policy, info.*)와 정적 검사(code.hardcoded-secret, code.client-secret-leak)가 이미 판정한다.' },
  { ref: 'DATA-ISOLATION-AND-LIFECYCLE.md#익명 키 직접 읽기·쓰기', reason: 'code.rls.anon-read 실측과 code.rls.anon-write·firebase 검사가 이미 판정한다.' },
  { ref: 'MEMORY-SAFETY-AND-BINARY.md', reason: '교사 앱은 대부분 메모리 안전 언어(JS·TS)라 기본 범위에서 뺀다. C·C++·러스트 unsafe 코드가 보이면 범위 밖(out_of_scope)으로 표시해 따로 맡긴다.' },
  { ref: 'PROTOCOLS-RPC-AND-MESSAGING.md', reason: 'gRPC·메시지 브로커는 교사 앱에서 드물다. 웹훅 서명은 web-auth 에서 본다.' },
  { ref: 'CLOUD-AND-DEPLOYMENT.md', reason: 'IAM·쿠버네티스·서비스 메시는 저장소 밖 설정이라 기본 범위에서 뺀다. cron·내부 경로 열림은 access-control 에서 본다.' },
];

export const EXECUTION_RULES = [
  '코드 읽기가 기본이다. 실행은 내 컴퓨터의 시험·작은 함수 시험·가짜 계정 데이터로만 한다.',
  '배포된 서버에 공격 요청을 보내지 않는다. dorms-check scan 의 공개 응답 점검(소유 확인 뒤 읽기 요청)만 예외다.',
  '실제 회원 계정·실제 개인정보·운영 DB·공유 서비스를 쓰지 않는다. 유료 API 를 부르지 않는다.',
  '패키지를 새로 설치하거나 내려받지 않는다. 결과를 확인하는 최소한까지만 하고 멈춘다.',
  '저장소 밖 사실(배포 설정·헤더·IdP·버킷 정책·요금 한도)이 결정적이면 추측하지 말고 미확인으로 남기고 확인 방법을 적는다.',
];

export const CORE_PRINCIPLES = [
  '경계와 결과가 있어야 위험이다. 더 낮은 권한의 사람, 그가 보낸 값, 막아야 했던 확인, 넘은 경계, 영향받은 사람·자원, 관찰한 결과를 모두 적는다.',
  '체크리스트에서 벗어난 것만으로는 위험이 아니다. A 층이 막고 있으면 B 층이 없는 것은 권고다.',
  '찾은 사람과 검증하는 사람을 나눈다. 검증하는 쪽은 찾은 내용을 반박하려고 처음부터 다시 읽는다.',
  '확인한 위험에만 심각도를 붙인다. 미확인에는 심각도를 붙이지 않는다.',
  '가장 작은 수정을 제안한다. 마지막으로 믿을 수 있는 판단 지점에서 지켜야 할 규칙(불변식)과 회귀 시험을 함께 적는다.',
  '한 번에 다 볼 수 없다. 범위표에 본 것과 못 본 것을 남기고, 다음 점검은 그 빈칸부터 채운다.',
];

export const SEVERITY_ANCHORS = {
  critical: '로그인 없는 사람이 코드 실행·DB 전체 접근·임의 계정 탈취를 한다.',
  high: '명시된 보안 통제를 완전히 무너뜨린다: 인증 우회, 다른 반·학교 자료 읽기·쓰기, 다른 사용자에게 실행되는 저장형 스크립트, 로그인한 사람의 코드 실행.',
  medium: '실제 경계를 넘지만 피해 범위가 좁거나 드문 조건이 필요하다.',
  low: '비밀이 아닌 내부 정보 노출, 많은 노력에 비해 얻는 것이 적다.',
  informational: '확인됐지만 영향이 아주 작다. 더 큰 위험의 전제로만 의미가 있다.',
};

export const ANTI_PATTERNS = [
  '체크리스트 차이를 위험으로 보고하기',
  '실제로 넘을 수 있는 경계 없이 다층 방어 조언하기',
  '로컬 증거로 충분한데 배포 서버를 시험하기',
  '저장소에 없는 배포·브라우저·인증 서비스 동작을 짐작하기',
  '본인 권한 안의 행동·자기 피해를 경계 넘기로 부르기',
  '관찰한 것보다 센 결과를 주장하기',
  '중복 확인·검증이 불가능한 산문만 남기기',
  '미확인에 심각도를 붙이기',
  '독립 검증 전에 보고서를 쓰거나 글과 JSON 이 다르게 두기',
];

const byId = new Map(AUDIT_CLASSES.map(c => [c.id, c]));
export function auditClass(id) { return byId.get(id) || null; }

// 표면 종류 목록에서 이 분류가 적용되는가.
export function classAppliesTo(cls, kinds) {
  if (cls.applies.includes('always')) return true;
  return cls.applies.some(k => kinds.has(k));
}
