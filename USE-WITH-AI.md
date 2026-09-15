# AI에게 앱 점검 맡기기

아래 문장을 사용 중인 AI에 붙여넣고 앱 이름과 공개 주소를 알려주세요.

~~~text
내가 만든 앱을 dorms-check로 최소 점검해줘. 앱 폴더에서 다음 명령을 같은 v0.3.1 릴리스로 실행해줘.

npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.3.1.tar.gz detect
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.3.1.tar.gz init --name "<내 앱 이름>" --url "<공개 주소>" --track security --confirm-ownership
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.3.1.tar.gz scan --url "<공개 주소>"
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.3.1.tar.gz status
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.3.1.tar.gz report

기존 설정이 있으면 내용을 먼저 읽고 임의로 덮어쓰지 마. init은 설정 파일을 만들고 scan은 검사 결과·보고서·이력을 .dorms-check에 저장해도 돼. 앱 소스를 바꾸는 작업이 필요하면 실제 문제와 변경 내용을 먼저 설명해줘.

확인한 위험, 개선 권고, 확인하지 못한 내용을 나눠 알려줘. 내부 DB나 개인정보처리방침을 읽지 못한 것을 실패나 통과로 단정하지 마. 전체 항목이 통과할 때까지 반복하거나 특정 호스팅이나 HTML 형식으로 바꾸라고 요구하지 마. 도름스 앱 등록과 점검 마크를 구분해서 설명해줘.
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

## 이전 설치가 남아 있을 때

0.3.0은 전역 훅을 설치하거나 배포를 차단하지 않습니다. 예전 훅 때문에 명령 실행이 막히면 [이전 설치 정리 안내](./docs/LEGACY-HOOK-CLEANUP.ko.md)를 사용하세요.
