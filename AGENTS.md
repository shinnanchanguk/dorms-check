# dorms-check — 어떤 AI 코딩 도구든 이 안내를 따르세요

이 파일은 Cursor·GitHub Copilot·Codex·Gemini·Cline·Windsurf 등 **어떤 AI 코딩 어시스턴트**가 읽어도 되는 크로스에이전트 안내입니다. (Claude 전용 안내는 `SKILL.md`에, 사람이 복붙할 프롬프트는 `USE-WITH-AI.md`에 있습니다. 내용은 같습니다.)

dorms-check 는 의존성 0의 순수 Node CLI 입니다. **AI 없이도 실행되고, 어떤 AI로도 오케스트레이션할 수 있습니다.** 판정은 AI의 판단이 아니라 프로그램이 실행한 검사 결과이므로, 어떤 모델을 쓰든 동일하게 결정적입니다.

세 축(트랙)이 있습니다.
- `security` 보안 점검: 헤더·SSL·노출·CORS·RLS 실측.
- `edzip` 학운위·개인정보 준비: 에듀집 필수기준 + 개인정보처리방침.
- `protection` 내 앱 비법·저작권 보호: 권리 확인·서버 분리·배포 위생·고지·증거.

## 먼저 사용자에게 전할 것 (정직한 한계)
- security·edzip 은 앱을 고치지 않고, 인증도 발급하지 않습니다. 무엇을 고쳐야 하는지 알려주는 코치입니다.
- **protection 의 적용 단계만 파일을 바꿉니다.** 그것도 사용자가 승인한 계획 해시(`--plan-sha256`)와 `--confirm-apply` 플래그가 있을 때만이며, 자동 배포는 하지 않습니다.
- 최종 인증마크는 도름스 서버가 스스로 다시 검증해 발급합니다. 이 도구의 통과는 신청 준비일 뿐입니다.
- "보장·통과 약속·완전 보호"를 쓰지 마세요. 난독화·Base64 는 비밀이 아니고, 브라우저로 전달된 것은 공개로 가정합니다. 판정은 실제로 실행한 검사 결과만 신뢰하세요("대충 통과" 금지).

> 설치 불필요: **깃허브 소스에서 바로 실행**합니다(Node 18+): `npx -y github:shinnanchanguk/dorms-check`.
> 이 도구는 npm 레지스트리에 올리지 않습니다(올린 판은 손볼 때마다 다시 올려야 해서 금방 옛것이 됩니다). 위 깃허브 주소로 실행하면 항상 저장소 최신 판이 돕니다. `dorms-check@latest` 같은 npm 이름은 받아지지 않으니 쓰지 마세요.

## 절차
1. `npx -y github:shinnanchanguk/dorms-check detect`
2. `npx -y github:shinnanchanguk/dorms-check init --name "<앱>" --url "<배포주소>" --track security,edzip,protection --confirm-ownership`
3. `npx -y github:shinnanchanguk/dorms-check scan --url "<배포주소>"` — **먼저 파일을 바꾸지 말고 스캔부터.**
4. protection 트랙이면 `interview` 로 문항을 받아 사용자에게 **쉬운 선택지로 1~3문항씩** 묻고(권리자·학교 관여·기존 라이선스·AI 기여·제3자 자산·허용 범위), 답을 모아 `interview --answers <파일>` 로 권리 프로필을 만드세요. 프로필에 비밀 원문·민감 파일명을 넣지 마세요.
5. 스캔이 "AI가 판단해야 할 항목"을 알려주면, 코드/개인정보처리방침을 직접 읽고 판정해 `judge --in answers.json` 으로 **증거(파일:라인)와 함께** 기록하세요. 증거 없는 pass 는 CLI 가 거부합니다. 보호 트랙의 결정적 항목은 judge 로 덮을 수 없습니다(스캔이 우선).
6. protection 적용은 `protect plan` 으로 계획(서버 이전 후보·바꿀 파일·위험·복원 방법)을 사용자에게 보여주고 **동의를 받은 뒤에만** `protect apply --plan-sha256 <계획해시> --confirm-apply`. 적용 후 `verify`, 문제 시 `protect restore`. 재배포는 사용자가 따로 승인할 때만.
7. `npx -y github:shinnanchanguk/dorms-check status` 로 남은 항목과 수정 프롬프트를 보고, 사용자 동의 하에 사용자 앱 코드를 고치세요(이 도구는 관여하지 않음). 고친 뒤 재배포하고 3~7 반복.
8. 설정한 트랙이 모두 통과하면 `npx -y github:shinnanchanguk/dorms-check submit` 으로 증빙팩을 만들고 도름스 마크 신청을 안내하세요(protection 포함 시 v2 페이로드로 시크릿·개인 경로가 자동 마스킹됩니다).
9. 학운위 마크가 "개인정보처리방침 필수 항목이 확인되지 않는다"로 막히면: 도름스는 앱 주소를 바깥에서 열어 방침 글자를 읽습니다. 방침을 별도 주소 없이 앱 안 팝업으로만 띄우는 한 장짜리 앱(React·Vite 등)은 바깥에서 빈 껍데기만 보여 못 읽힐 수 있어요(이 도구는 소스를 읽으니 "이상 없음"으로 갈립니다). ① 방침을 `/privacy` 같은 주소로도 열리게 두거나(권장) ② `submit` 이 만든 `.dorms-check/evidence/report.json` 을 신청 화면의 "dorms-check 결과 올리기"에 올리도록 안내하세요.

## 규칙
- 본인이 만들고 운영하는 앱만 검사(비파괴 GET·SELECT만).
- 파일 변경은 protection 적용 단계뿐이며, 승인한 계획 해시 + `--confirm-apply` 없이는 절대 하지 않습니다. 자동 배포 금지.
- 사용자 노출 설명은 비개발자가 이해하는 쉬운 말로.

자세한 내용: `README.ko.md` · `DISCLAIMER.md`
