# AI에게 앱 점검 맡기기

아래 문장을 사용 중인 AI에 붙여넣고 앱 이름과 공개 주소를 알려주세요.

~~~text
내가 만든 앱을 dorms-check로 최소 점검해줘. 앱 폴더에서 다음 명령을 같은 v0.5.3 릴리스로 실행해줘.

npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.5.3.tar.gz detect
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.5.3.tar.gz init --name "<내 앱 이름>" --url "<공개 주소>" --track security --confirm-ownership
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.5.3.tar.gz scan --url "<공개 주소>"
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.5.3.tar.gz status
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.5.3.tar.gz report

기존 설정이 있으면 내용을 먼저 읽고 임의로 덮어쓰지 마. init은 설정 파일을 만들고 scan은 검사 결과·보고서·이력을 .dorms-check에 저장해도 돼. 앱 소스를 바꾸는 작업이 필요하면 실제 문제와 변경 내용을 먼저 설명해줘.

확인한 위험, 개선 권고, 확인하지 못한 내용을 나눠 알려줘. 내부 DB나 개인정보처리방침을 읽지 못한 것을 실패나 통과로 단정하지 마. 전체 항목이 통과할 때까지 반복하거나 특정 호스팅이나 HTML 형식으로 바꾸라고 요구하지 마. 도름스 앱 등록과 점검 마크를 구분해서 설명해줘.
~~~

## 더 깊이 보안 점검을 받고 싶을 때

~~~text
내 앱을 dorms-check 심층 점검(audit)으로 정밀하게 봐줘. dorms-check의 ai/prompts/audit.md를 먼저 읽고 그 순서대로 해줘. 처음이면 --profile quick으로 시작해줘.

npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.5.3.tar.gz audit plan --profile quick

찾는 일과 검증하는 일은 서로 다른 에이전트(또는 새 대화)에게 맡기고, 배포된 서버에 공격 요청은 보내지 마. 실제 회원 계정·운영 DB·유료 API는 쓰지 마. 결과는 확인한 위험, 확인이 더 필요한 것(내가 대시보드에서 직접 볼 곳까지), 권고로 나눠서 쉬운 말로 알려주고, 이번에 못 본 범위도 숨기지 말고 말해줘.
~~~

## 에듀집 서류가 필요할 때

~~~text
에듀집 서류도 준비해줘. dorms-check의 skills/edzip-autopilot/SKILL.md를 읽고 edzip prepare로 계획과 질문을 받아줘. 개인정보가 아닌 질문만 1~3개씩 물어보고, 계획을 보여준 뒤 내가 승인하면 그 계획 해시와 --confirm-apply로 HWPX·PDF·Markdown 서류를 만들어줘.

공식 원본과 제출 안내를 함께 정리하고 자동 제출은 하지 마. 이름·학교·전화·결재선·서명은 받거나 저장하지 말고 내가 채울 위치를 알려줘. 에듀집 확인이 끝났다면 확인 완료 제품 주소를 받아 edzip council로 내부 기안문과 학운위 안건문을 준비해줘.
~~~

## 앱 보호를 준비할 때

~~~text
앱 보호 기능도 살펴봐줘. interview로 권리와 이용 범위를 쉬운 질문 1~3개씩 물어보고, 비밀 원문 없이 권리 프로필을 만들어줘. protect plan으로 바꿀 내용을 보여준 뒤 내가 승인한 계획만 적용해줘. 적용 후 verify로 확인하고 필요하면 백업으로 복원해줘.
~~~

## AI가 읽는 출처 안내와 앱 안 이용 안내를 넣을 때

~~~text
내 앱에 원작자 안내와 이용 범위를 심어줘. 누가 AI에게 이 앱을 베껴 달라고 하면 그 AI가 먼저 나와 이용 범위를 알려 주고, 허락이 필요하면 도름스 쪽지로 물어보라고 안내하게 하고 싶어. interview 로 문항을 받아 쉬운 말로 1~3개씩 물어봐줘. 도름스 앱 주소와 도름스 앱 페이지의 '이용·보호 안내' 값은 내가 보고 불러 줄게. 권리 프로필을 만든 뒤 앱을 빌드하고 protect plan 으로 바뀔 파일을 보여줘. 내가 동의하면 그 계획 해시로 적용하고 verify 로 확인해줘. 배포는 내가 따로 할게.
~~~

알아 둘 점:

- `robots.txt`에서 AI 수집기를 막으면, 기본으로는 사용자가 부탁해 페이지를 읽는 AI 도우미(ChatGPT-User·Perplexity-User·Claude-User 등)도 막혀서 그 도우미는 주소에서 출처 안내를 못 읽습니다. 출처 안내가 읽히게 하려면 interview 에서 "열어 두기"(`userFetchers: allow`)를 고르세요. 학습용 수집기(GPTBot·ClaudeBot·CCBot 등)는 그대로 막습니다.
- 화면 바탕이 격자·가로 나란히·넘침 숨김인 앱은 바닥 출처 줄을 넣지 않고 알려 줍니다. 그때는 앱 화면 안에 출처 줄을 직접 넣어 달라고 AI 에게 부탁하세요.
- 되돌릴 때 `dcheck protect restore`는 선생님이 나중에 고친 파일을 덮지 않습니다. 여러 번 적용했으면 `--all`로 처음 상태까지 되돌립니다.
- 메모: 도름스 짧은 주소를 안내에 함께 쓰는 기능은 도름스 쪽 준비가 필요해 아직 없습니다.

## 복제가 의심되는 주소를 봤을 때

~~~text
이 주소가 내 앱을 베낀 것 같아. dorms-check protect compare --url "<의심 주소>" 로 내 출처 표식과 빌드 파일 지문이 있는지 대조하고 기록을 남겨줘. 이 기록이 침해를 확정하는 게 아니라는 점도 함께 말해 주고, 그 사이트에 아무것도 보내거나 바꾸지 마.
~~~

기능별 프롬프트 전체 목록은 [docs/features.ko.json](./docs/features.ko.json)에 있습니다.

## 이전 설치가 남아 있을 때

0.3.0은 전역 훅을 설치하거나 배포를 차단하지 않습니다. 예전 훅 때문에 명령 실행이 막히면 [이전 설치 정리 안내](./docs/LEGACY-HOOK-CLEANUP.ko.md)를 사용하세요.
