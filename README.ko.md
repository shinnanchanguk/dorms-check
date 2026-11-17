# dorms-check

[English](./README.md) | 한국어

교사가 만든 앱의 공개 응답과 코드를 살펴보는 최소 점검 도구입니다. 확인한 위험, 권고, 확인하지 못한 부분을 나누어 알려줍니다.

## 점검과 앱 등록

도름스 앱 등록과 점검 마크는 별개입니다. 내부 데이터베이스를 읽지 못하거나 개인정보처리방침을 찾지 못했다는 이유만으로 앱 등록을 막지 않습니다.

도름스 기본 보안 점검 마크는 도름스 서버가 공개 HTTPS 주소의 정상 응답과 본문을 실제 검사하고, 근거가 분명한 위험이 발견되지 않았을 때 발급합니다. 로그인 화면이나 한 장짜리 앱도 같은 기준을 씁니다. 확인하지 못한 항목은 마크의 점검 범위에 함께 표시하며, 앱 전체가 안전하다는 보증은 아닙니다.

보안 응답 설정이 없거나 공개 데이터에 익명 접근이 가능하다는 사실만으로 위험을 확정하지 않습니다. 특정 호스팅으로 옮기거나 방침을 특정 HTML 파일에 넣을 필요도 없습니다. 공개 주소에 접속하지 못하면 새 마크는 보류하고 앱 등록은 계속할 수 있습니다.

학운위 서류 준비와 에듀집 확인 표시는 별도로 판단합니다. 방침 내용을 읽지 못하면 학운위 준비 표시만 보류합니다. 에듀집 확인 표시는 공식 확인 근거가 필요합니다.

## 시작하기

Node.js 18 이상이 필요합니다. 아래 명령은 GitHub의 `v0.5.0` 릴리스를 받아 실행하는 예시입니다. 조직이나 교육 자료에서 검토한 커밋을 지정했다면 같은 커밋을 계속 사용하세요.

~~~bash
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.5.0.tar.gz detect
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.5.0.tar.gz init --name "내 앱" --url "https://my-app.example" --track security --confirm-ownership
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.5.0.tar.gz scan --url "https://my-app.example"
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.5.0.tar.gz status
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.5.0.tar.gz report
~~~

AI에게 맡기려면 [복사해 쓰는 프롬프트](./USE-WITH-AI.md)를 사용하세요. 배포 전에는 `scan --code-only`로 코드를 살펴볼 수 있습니다. 이 경우 공개 주소 검사는 미확인입니다.

## 결과 읽기

| 상태 | 뜻 |
| --- | --- |
| `pass` | 해당 검사를 실행해 조건을 확인함 |
| `fail` | 검사에서 문제를 확인함. 마크 보류 여부는 위험 근거와 함께 판단 |
| `info` | 참고 또는 개선 권고 |
| `unknown` | 접근 제한, 지원 범위, 검사 오류 등으로 확인하지 못함 |
| `na` | 해당 앱에 적용하지 않는 항목 |

확인한 수와 미확인 수를 함께 보여줍니다. 전체 항목을 통과할 때까지 반복하거나 미확인을 통과로 바꿀 필요는 없습니다. 실제 문제를 고쳤거나 추가 근거가 생겼을 때 다시 검사하세요. `scan --json`의 종료 코드 0은 명령 완료를 뜻하며, 완전한 안전이나 마크 발급을 뜻하지 않습니다.

## 필요한 기능만 선택하기

기본 점검은 `security`입니다. `--track`으로 필요한 기능을 쉼표로 골라 실행할 수 있습니다.

- `security`: 공개 응답, HTTPS, 노출된 비밀정보, 공개 데이터 접근, 로컬 코드를 점검합니다.
  Supabase 앱은 학교 개인정보 자체점검표 항목(비밀번호 기준, 주민번호·비밀번호 평문 저장, 로그인 없이 수정·삭제가 열린 DB 규칙, 업로드 용량·형식 제한)도 마이그레이션과 설정 파일로 살펴 권고로 알려줍니다. 2단계 인증·자동 로그아웃·접속기록 보관처럼 코드로 확정할 수 없는 항목은 흔적만 참고로 보여줍니다.
- `edzip`: 제출 서류를 준비합니다. `edzip prepare`의 계획과 질문을 확인한 뒤 승인한 계획 해시와 `--confirm-apply`로 HWPX·PDF·Markdown 서류를 만듭니다. 에듀집 확인 완료 뒤에는 `edzip council`로 내부 기안문과 학운위 안건문을 만듭니다. [서류 작성 안내](./skills/edzip-autopilot/SKILL.md)를 따르세요.
- `protection`: 권리와 이용 범위를 묻고 앱 보호 변경 계획을 세웁니다. `protect apply`는 승인한 계획 해시와 `--confirm-apply`가 있을 때 백업 후 적용합니다. `verify`로 확인하고 필요하면 `protect restore`로 복원합니다. 아래 "출처 안내와 앱 안 이용 안내"도 이 기능에 들어 있습니다.

에듀집 서류에는 공식 원본과 제출 안내가 함께 들어갑니다. 이름·학교·전화·결재선·서명은 받거나 저장하지 않고 사용자가 채울 위치를 안내합니다. 구글폼 제출 뒤 며칠이 지나도 연락이 없으면 서류에 적힌 KERIS 담당 부서에 진행 상태를 문의하세요.

## 출처 안내와 앱 안 이용 안내

베끼려는 사람은 dorms-check 를 돌리지 않습니다. 그래서 `protect apply`는 그 사람이 쓰는 AI가 실제로 읽는 자리마다 원작자 안내를 심습니다. 누가 AI에게 "이 앱 똑같이 만들어 줘"라고 하면, AI가 먼저 누구의 앱이고 이용 범위가 어떤지, 허락이 필요하면 도름스 앱 페이지에서 쪽지로 물어볼 수 있다는 점을 말하게 하려는 장치입니다.

| 베끼는 방법 | 안내를 둔 곳 |
| --- | --- |
| 주소를 AI에 주기 | 화면 바닥의 작은 출처 줄, 화면에 안 보이는 안내 글, `llms.txt`, 이용 안내 화면 |
| 소스를 복사해 붙여넣기 | 빌드된 JS·CSS 맨 위 `/*! ... */` 머리 주석(압축해도 남는 형식) |
| 저장소를 통째로 가져가기 | `AGENTS.md`·`CLAUDE.md` 안내 블록(선생님이 쓴 내용은 그대로), `dorms.json` |

- 안내 내용은 도름스 '이용·보호 안내'를 따릅니다. 내용 수정·개작, 소스코드 재사용, 수정본 재배포 중 가장 엄격한 값을 기준으로 허용이면 "출처를 남기고 고쳐 써도 돼요", 먼저 허락이거나 비어 있으면 "먼저 허락을 받으세요"와 허락 요청 쪽지 초안, 허용 안 함이면 "원작자가 허용하지 않았어요"를 먼저 말하게 합니다.
- `interview`에서 도름스 앱 주소(`https://dorms.school/apps/<번호>` 또는 `/arcade/<번호>`만 받음)와 이용·보호 안내 값을 선생님이 보고 옮겨 적습니다. 도름스 사이트를 긁어 오지 않습니다.
- 앱 안에 `usage.html` 이용 안내 화면을 만듭니다. 도름스와 같은 열두 항목·같은 말(허용 / 먼저 허락 / 허용 안 함), 묶음(교육 나눔형·제한 이용형·오픈 협업형·커스텀), 출처 표시 방법, 덧붙인 조건, 저작권법 조문 링크를 담습니다. `public/` 폴더가 있으면 거기에도 두어 다시 빌드해도 남습니다.
- 저작권 고지는 저작권법 제12·16·18·20·22·35조의5·37·136조를 `law.go.kr` 링크로 겁 주지 않게 담고, 법률 자문이 아니라고 밝힙니다.
- 화면 바닥 줄에는 만든 사람과 이용 범위(예: "고쳐 쓰기·재배포는 먼저 허락(도름스 쪽지)")가 함께 보입니다. `interview`의 선택이나 설정 `protection.provenance.visibleFooter: false`로 끌 수 있습니다. `CLAUDE.md` 블록은 `protection.provenance.claudeMd: false`로 끕니다.
- 화면 바탕(`body`)이 격자(grid)·가로 나란히(flex)이거나 넘치는 부분을 숨기는(`overflow: hidden`) 페이지에는 바닥 줄을 넣지 않고 계획·적용 화면에 알립니다. 넣으면 칸이 줄어들거나 줄이 화면 밖에 놓여 안 보이기 때문입니다. 그런 앱은 앱 화면 안 알맞은 곳에 출처 줄을 직접 넣거나, 그래도 넣으려면 `visibleFooter: "force"`로 둡니다. CSS-in-JS 처럼 실행해야 정해지는 배치는 미리 알아내지 못하니 적용 뒤 화면을 한 번 보세요.
- 이미 있는 `usage.html`·`dorms.json`이 dorms-check 가 만든 것이 아니면 덮어쓰지 않습니다. 프로젝트 안의 심볼릭 링크를 따라 밖의 파일을 쓰지 않으며, 그런 링크가 있으면 계획 단계에서 멈춥니다.
- `protect restore`는 적용 뒤 선생님이 직접 고친 파일을 덮거나 지우지 않습니다. `AGENTS.md`·`CLAUDE.md`는 안내 블록만 되돌리고 나머지 내용은 남깁니다. 고친 파일까지 적용 전으로 돌리려면 `--force`, 다시 빌드하고 여러 번 적용했을 때 처음 상태까지 모두 되돌리려면 `--all`을 씁니다.
- 출처 안내를 켜면 `robots.txt`의 AI 수집기 차단과 맞물립니다. 기본은 사용자가 부탁해 페이지를 읽는 AI 도우미(ChatGPT-User·Perplexity-User·Claude-User 등)도 막는데, 그러면 그 도우미는 주소에서 출처 안내를 못 읽습니다. `interview`의 `userFetchers: allow`(또는 권리 프로필 `provenance.allowUserFetchers: true`, 설정 `protection.robots.allowUserFetchers: true`)로 학습용 수집기만 막고 AI 도우미는 열어 둘 수 있습니다.
- 이용 범위가 "출처를 남기면 고쳐 쓰기 허용"이면 새로 만드는 `LICENSE`도 그에 맞는 허락 문구로 만들고, 이미 "허락 없이 수정 불가" LICENSE 가 있으면 어긋난다고 알립니다.
- 도름스 표의 일부만 옮겨 적으면 나머지는 도름스 커스텀의 출발점인 교육 나눔형 값으로 채우고, 채운 항목을 알려 줍니다.
- 메모: AI 가 긴 도름스 주소를 옮겨 적다 틀리는 일이 있었습니다(시험 1회). 도름스 짧은 주소(`/s/...`)를 안내에 함께 쓰는 것은 도름스 쪽 기능이 필요해 아직 하지 않았습니다.
- 모든 안내 문구는 [templates/copy.ko.json](./templates/copy.ko.json) 한 파일에 있습니다.
- 한계: 강제 장치가 아닙니다. 안내를 지우고 베끼거나 AI가 무시하면 막지 못합니다. 숨은 명령이나 과장은 넣지 않습니다.

`dcheck protect compare --url <의심 주소>`는 의심 주소의 공개 HTML·같은 출처 JS/CSS·`llms.txt`·`dorms.json`을 받아, 내 출처 표식 번호·머리 주석·도름스 주소·이름과 빌드 파일 지문(머리 주석만 지운 경우 포함)이 보이는지 사실만 `.dorms-check/protect/evidence/compare-<시각>-<주소>.md`로 남깁니다. 그 주소에는 아무것도 보내거나 바꾸지 않고, 내부망 주소는 기본으로 거부합니다.

### ai-clone-shield 에서 옮긴 것

ai-clone-shield 는 이제 dorms-check 보호 기능으로 대신합니다.

| ai-clone-shield | dorms-check |
| --- | --- |
| A 코드 경화 | 소스맵 제거만 옮김. 난독화는 비밀이 되지 않아 뺐습니다 |
| B 로직 격리 진단 | `scan --track protection`의 비법 경계 항목 |
| C 제로폭 워터마크 | 뺐습니다(편집하면 쉽게 사라지는 것을 증거처럼 보이게 해서). 대신 보이는 출처 표식 번호와 빌드 지문 |
| D AI 고지 | 출처 안내(이용 범위별 문구, 바닥 줄, JS·CSS 머리 주석, AGENTS.md) |
| E 법적 안내 | robots·TDM·LICENSE·무결성 기록 + 저작권법 조문 고지 |
| F 기능 무손상 | `verify`와 적용 직후 자동 검증 |
| G 공격적 억제 | 뺐습니다 |
| watermark-check · evidence-pack | `protect compare` · 증거팩 |

기능별 복사 프롬프트 목록은 [docs/features.ko.json](./docs/features.ko.json)에 있습니다.

## 심층 점검(요청할 때만)

`dcheck audit`은 기본 점검보다 깊이 코드를 나눠 보는 정밀 보안 점검입니다. Cloudflare의 security-audit-skill(MIT) 흐름을 교사 앱에 맞게 옮겼고, 기본 점검과 겹치는 헤더·HTTPS·공개 비밀값·익명 DB 읽기는 빼고 코드 안의 권한 우회·업무 규칙·AI 기능·요금 고갈·데이터 칸막이를 봅니다.

- 범위표: 앱의 서버 API·서버 액션·DB 함수·AI 호출·업로드 같은 표면을 자동으로 찾아 "무엇을 봤고 무엇을 못 봤는지"를 단위로 기록합니다.
- 역할 분리: 찾는 에이전트와 반박 검증하는 에이전트를 나눕니다. 같은 담당자가 자기 후보를 검증하려 하면 도구가 거부합니다.
- 판정 셋: 확인한 위험(심각도 있음), 확인이 더 필요한 것(심각도 없음, 막힌 사실과 직접 확인할 곳), 기각.
- 안전: 배포된 서버에 공격 요청을 보내지 않고, 결과 폴더는 `.gitignore`가 덮는 곳이나 홈 폴더에만 씁니다.
- 이어서 점검: 다음 회차는 이전 보고서의 결과를 이어받고, 코드가 바뀐 곳만 다시 봅니다.

순서는 [AI용 안내](./ai/prompts/audit.md)에 있습니다. `audit plan → prompt → merge → record → check → report`.

## 저장하는 파일

`detect`, `status`, `report`는 조회 명령입니다. `init`은 프로젝트에 `dorms-check.config.json`을 만듭니다. `scan`은 `.dorms-check/`에 검사 결과, 보고서, 이력을 저장합니다. `judge`와 `interview --answers`는 사용자가 제공한 근거와 답변을 저장하고, `submit`은 보관용 증빙팩을 만듭니다.

서류·보호 계획도 로컬 파일로 저장합니다. 서류 생성과 앱 보호 적용은 각 명령에 표시된 승인 절차를 따릅니다. 기본 점검은 앱 소스를 수정하거나 배포하지 않습니다.

## 이전 버전 정리

0.3.0부터 전역 훅 설치와 배포 차단 기능을 제거했습니다. 예전 옵션은 `FEATURE_REMOVED`와 종료 코드 2를 돌려주며, 일반 검사로 바꾸어 실행하지 않습니다.

이전에 설치한 훅이 있으면 [이전 설치 정리 안내](./docs/LEGACY-HOOK-CLEANUP.ko.md)를 보세요. 새 점검에는 훅 설치, Vercel CLI, 배포 토큰이 필요하지 않습니다.

## 제작과 이용

Team DoRm의 교사 홍창욱이 제작했습니다. 이용 조건은 [LICENSE](./LICENSE)와 [NOTICE.md](./NOTICE.md), 점검의 한계는 [DISCLAIMER.md](./DISCLAIMER.md)를 확인하세요.
