# dorms-check — 어떤 AI 코딩 도구든 이 안내를 따르세요

이 파일은 Cursor·GitHub Copilot·Codex·Gemini·Cline·Windsurf 등 **어떤 AI 코딩 어시스턴트**가 읽어도 되는 크로스에이전트 안내입니다. (Claude 전용 안내는 `SKILL.md`에, 사람이 복붙할 프롬프트는 `USE-WITH-AI.md`에 있습니다. 내용은 같습니다.)

dorms-check 는 의존성 0의 순수 Node CLI 입니다. **AI 없이도 실행되고, 어떤 AI로도 오케스트레이션할 수 있습니다.** 판정은 AI의 판단이 아니라 프로그램이 실행한 검사 결과이므로, 어떤 모델을 쓰든 동일하게 결정적입니다.

## 먼저 사용자에게 전할 것 (정직한 한계)
- 이 도구는 앱을 고치지도, 인증을 발급하지도 않습니다. 무엇을 고쳐야 하는지 알려주는 코치입니다.
- 최종 인증마크는 도름스 서버가 스스로 다시 검증해 발급합니다. 이 도구의 통과는 신청 준비일 뿐입니다.
- "보장·통과 약속"을 쓰지 마세요. 판정은 실제로 실행한 검사 결과만 신뢰하세요("대충 통과" 금지).

> 설치 불필요: `npx`가 자동으로 받아 실행합니다(Node 18+). `npx -y dorms-check@latest`가 안 되면(npm 미발행) `npx -y github:shinnanchanguk/dorms-check`로 실행하세요.

## 절차
1. `npx -y dorms-check@latest detect`
2. `npx -y dorms-check@latest init --name "<앱>" --url "<배포주소>" --track security,edzip --confirm-ownership`
3. `npx -y dorms-check@latest scan --url "<배포주소>"`
4. 스캔이 "AI가 판단해야 할 항목"을 알려주면, 코드/개인정보처리방침을 직접 읽고 판정해 `judge --in answers.json` 으로 **증거(파일:라인)와 함께** 기록하세요. 증거 없는 pass 는 CLI 가 거부합니다.
5. `npx -y dorms-check@latest status` 로 남은 항목과 수정 프롬프트를 보고, 사용자 동의 하에 사용자 앱 코드를 고치세요(이 도구는 관여하지 않음). 고친 뒤 재배포하고 3~5 반복.
6. 두 트랙이 통과하면 `npx -y dorms-check@latest submit` 으로 증빙팩을 만들고 도름스 마크 신청을 안내하세요.

## 규칙
- 본인이 만들고 운영하는 앱만 검사(비파괴 GET·SELECT만).
- 사용자 노출 설명은 비개발자가 이해하는 쉬운 말로.

자세한 내용: `README.ko.md` · `DISCLAIMER.md`
