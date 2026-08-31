# dorms-check — 어떤 AI 코딩 도구든 이 안내를 따르세요

이 파일은 Cursor·GitHub Copilot·Codex·Gemini·Cline·Windsurf 등 **어떤 AI 코딩 어시스턴트**가 읽어도 되는 크로스에이전트 안내입니다. (Claude 전용 안내는 `SKILL.md`에, 사람이 복붙할 프롬프트는 `USE-WITH-AI.md`에 있습니다. 내용은 같습니다.)

dorms-check 는 Node CLI이며 Claude·Codex·Gemini·Cursor 등 어떤 AI 코딩 도구에서도 사용할 수 있습니다. HWPX·PDF 생성 엔진과 공식 양식·출처 자산이 설치 패키지에 함께 듭니다.

세 축(트랙)이 있습니다.
- `security` 보안 점검: 헤더·SSL·노출·CORS·RLS 실측.
- `edzip` 에듀집 제출·통과 준비와 승인 뒤 학교 서류: 필수기준 + 개인정보처리방침 + 내부 기안·학운위 안건.
- `protection` 내 앱 비법·저작권 보호: 권리 확인·서버 분리·배포 위생·고지·증거.

## 먼저 사용자에게 전할 것 (정직한 한계)
- security 스캔은 앱을 고치지 않습니다. edzip 서류 생성과 protection 적용은 사용자가 승인한 계획 해시에서만 파일을 바꾸며, 인증은 발급하지 않습니다.
- **protection 의 적용 단계만 파일을 바꿉니다.** 그것도 사용자가 승인한 계획 해시(`--plan-sha256`)와 `--confirm-apply` 플래그가 있을 때만이며, 자동 배포는 하지 않습니다.
- 최종 인증마크는 도름스 서버가 스스로 다시 검증해 발급합니다. 이 도구의 통과는 신청 준비일 뿐입니다.
- "보장·통과 약속·완전 보호"를 쓰지 마세요. 난독화·Base64 는 비밀이 아니고, 브라우저로 전달된 것은 공개로 가정합니다. 판정은 실제로 실행한 검사 결과만 신뢰하세요("대충 통과" 금지).

> 설치 불필요: **깃허브 소스에서 바로 실행**합니다(Node 18+): `npx -y github:shinnanchanguk/dorms-check`.
> 이 도구는 npm 레지스트리에 올리지 않습니다(올린 판은 손볼 때마다 다시 올려야 해서 금방 옛것이 됩니다). 위 깃허브 주소로 실행하면 항상 저장소 최신 판이 돕니다. `dorms-check@latest` 같은 npm 이름은 받아지지 않으니 쓰지 마세요.

## 절차
1. `npx -y github:shinnanchanguk/dorms-check detect`
2. `npx -y github:shinnanchanguk/dorms-check init --name "<앱>" --url "<배포주소>" --track security,edzip,protection --confirm-ownership`
3. `npx -y github:shinnanchanguk/dorms-check scan --url "<배포주소>"` — **먼저 파일을 바꾸지 말고 스캔부터.**
4. 에듀집 서류가 필요하면 `edzip prepare`로 계획과 5가지 비개인정보 질문을 받고, 계획 승인 후 `edzip prepare --apply --plan-sha256 <값> --confirm-apply --answers <JSON>`를 실행하세요. 에듀집 확인 완료 뒤에는 `edzip council --approved-url <공식 주소> --confirm-apply`로 내부 기안문과 학운위 안건문을 만드세요. 자세한 진행은 `skills/edzip-autopilot/SKILL.md`입니다.
4. protection 트랙이면 `interview` 로 문항을 받아 사용자에게 **쉬운 선택지로 1~3문항씩** 묻고(권리자·학교 관여·기존 라이선스·AI 기여·제3자 자산·허용 범위), 답을 모아 `interview --answers <파일>` 로 권리 프로필을 만드세요. 프로필에 비밀 원문·민감 파일명을 넣지 마세요.
5. 스캔이 "AI가 판단해야 할 항목"을 알려주면, 코드/개인정보처리방침을 직접 읽고 판정해 `judge --in answers.json` 으로 **증거(파일:라인)와 함께** 기록하세요. 증거 없는 pass 는 CLI 가 거부합니다. 보호 트랙의 결정적 항목은 judge 로 덮을 수 없습니다(스캔이 우선).
6. protection 적용은 `protect plan` 으로 계획(서버 이전 후보·바꿀 파일·위험·복원 방법)을 사용자에게 보여주고 **동의를 받은 뒤에만** `protect apply --plan-sha256 <계획해시> --confirm-apply`. 적용 후 `verify`, 문제 시 `protect restore`. 재배포는 사용자가 따로 승인할 때만.
7. `npx -y github:shinnanchanguk/dorms-check status` 로 남은 항목과 수정 프롬프트를 보고, 사용자 동의 하에 사용자 앱 코드를 고치세요(이 도구는 관여하지 않음). 고친 뒤 재배포하고 3~7 반복.
8. 설정한 트랙이 모두 통과하면 `npx -y github:shinnanchanguk/dorms-check submit` 으로 증빙팩을 만들고 도름스 마크 신청을 안내하세요(protection 포함 시 v2 페이로드로 시크릿·개인 경로가 자동 마스킹됩니다).
9. 학운위 마크가 "개인정보처리방침 필수 항목이 확인되지 않는다"로 막히면: 도름스는 앱 주소를 바깥에서 열어 방침 글자를 읽습니다. 방침을 별도 주소 없이 앱 안 팝업으로만 띄우는 한 장짜리 앱(React·Vite 등)은 바깥에서 빈 껍데기만 보여 못 읽힐 수 있어요(이 도구는 소스를 읽으니 "이상 없음"으로 갈립니다). ① 방침을 `/privacy` 같은 주소로도 열리게 두거나(권장) ② `submit` 이 만든 `.dorms-check/evidence/report.json` 을 신청 화면의 "dorms-check 결과 올리기"에 올리도록 안내하세요.

## 규칙
- 본인이 만들고 운영하는 앱만 검사(비파괴 GET·SELECT만).
- 파일 변경은 edzip·protection의 명시적 적용 단계뿐이며, 승인한 계획 해시 + `--confirm-apply` 없이는 절대 하지 않습니다. 자동 제출·배포 금지.
- 사용자 노출 설명은 비개발자가 이해하는 쉬운 말로.

## 사용자가 Vercel strict 배포 게이트를 명시적으로 요청한 경우

`docs/STRICT-SECURITY-GATE.ko.md`를 끝까지 읽고 그 순서만 따르세요. 움직이는 기본 브랜치 대신 검토 완료 커밋 SHA를 고정합니다. 운영체제와 셸을 스스로 감지하고, Git SHA와 Vercel stdout URL을 직접 캡처하며, 사용자에게 터미널 명령을 옮겨 적게 하지 마세요. 사람이 해야 하는 동작은 Vercel 로그인, Codex 훅 신뢰, 모르는 dirty 파일 확인처럼 계정 또는 신뢰 경계를 넘는 것뿐입니다.

`judge`로 결정적 보안 결과를 덮지 마세요. 종료 코드 1은 확인된 결함, 2부터 5는 설정 오류, 미완료, 바인딩 불일치, 영수증 오류입니다. 어느 것도 임의로 PASS로 바꾸지 않습니다. `vercel@59.10.0`을 훅 설치 전에 고정하며 다른 버전은 사용하지 않습니다. macOS/Linux/WSL staged production은 현재 Git 루트에서 literal `vercel [deploy] --prod --skip-domain --meta githubDeployment=1 --meta githubCommitSha=<full HEAD>` 단일 명령만 씁니다. native Windows PowerShell은 `hooks status --json`의 검증된 `windowsVercelExecutable` 절대 경로를 직접 넣은 `& '<exact vercel.cmd>' [deploy] --prod ...` 단일 명령만 씁니다. `vc` 축약, 다른 `.cmd`·`.exe`, wrapper, 변수, 스크립트, 복합 명령, override 옵션은 쓰지 않습니다. 선택적 `deploy`는 첫 subcommand로 한 번만 쓸 수 있습니다. promote도 exact URL/ID를 직접 넣은 단일 명령만 씁니다. 훅은 command substitution, caret/backtick, runtime·package·task launcher도 보수적으로 차단합니다. 이 두 쓰기 외 모든 Vercel 변경은 차단하고 명시적 list/inspect/status/get/help/version/whoami 조회만 허용합니다. code 검사 뒤 `.vercel/project.json`, Git에 묶인 배포 입력, 허용된 legacy `.dorms-check` 상태를 바꾸지 마세요. Vercel project/org/team ambient 값은 링크와 정확히 같아야 하고 token/scope/config override는 제거해야 합니다. 훅 `configured`를 활성화 완료로 부르지 말고, 사용자 지정 config root와 절대 Node 경로를 확인한 뒤에도 재시작·신뢰·안전한 차단 challenge 전에는 `activation: unknown`과 NOT READY를 보고하세요.

비대화형 canonical staged에는 `--yes`를 붙입니다. native Windows에서는 훅 설치가 `Get-Command vercel -All -CommandType Application`으로 찾은 exact `vercel.cmd`, 해시, 버전, PowerShell 실행 파일을 고정합니다. Vercel 명령에 변수나 명령 치환을 넣지 말고 status에 보인 절대 경로와 실제 SHA·URL을 literal로 넣으세요.

자세한 내용: `README.ko.md` · `DISCLAIMER.md`
