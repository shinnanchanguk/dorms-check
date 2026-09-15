# dorms-check

[English](./README.md) | 한국어

교사가 만든 앱의 공개 응답과 코드를 살펴보는 최소 점검 도구입니다. 확인한 위험, 권고, 확인하지 못한 부분을 나누어 알려줍니다.

## 점검과 앱 등록

도름스 앱 등록과 점검 마크는 별개입니다. 내부 데이터베이스를 읽지 못하거나 개인정보처리방침을 찾지 못했다는 이유만으로 앱 등록을 막지 않습니다.

도름스 기본 보안 점검 마크는 도름스 서버가 공개 HTTPS 주소의 정상 응답과 본문을 실제 검사하고, 근거가 분명한 위험이 발견되지 않았을 때 발급합니다. 로그인 화면이나 한 장짜리 앱도 같은 기준을 씁니다. 확인하지 못한 항목은 마크의 점검 범위에 함께 표시하며, 앱 전체가 안전하다는 보증은 아닙니다.

보안 응답 설정이 없거나 공개 데이터에 익명 접근이 가능하다는 사실만으로 위험을 확정하지 않습니다. 특정 호스팅으로 옮기거나 방침을 특정 HTML 파일에 넣을 필요도 없습니다. 공개 주소에 접속하지 못하면 새 마크는 보류하고 앱 등록은 계속할 수 있습니다.

학운위 서류 준비와 에듀집 확인 표시는 별도로 판단합니다. 방침 내용을 읽지 못하면 학운위 준비 표시만 보류합니다. 에듀집 확인 표시는 공식 확인 근거가 필요합니다.

## 시작하기

Node.js 18 이상이 필요합니다. 아래 명령은 GitHub의 `v0.3.1` 릴리스를 받아 실행하는 예시입니다. 조직이나 교육 자료에서 검토한 커밋을 지정했다면 같은 커밋을 계속 사용하세요.

~~~bash
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.3.1.tar.gz detect
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.3.1.tar.gz init --name "내 앱" --url "https://my-app.example" --track security --confirm-ownership
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.3.1.tar.gz scan --url "https://my-app.example"
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.3.1.tar.gz status
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.3.1.tar.gz report
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
- `edzip`: 제출 서류를 준비합니다. `edzip prepare`의 계획과 질문을 확인한 뒤 승인한 계획 해시와 `--confirm-apply`로 HWPX·PDF·Markdown 서류를 만듭니다. 에듀집 확인 완료 뒤에는 `edzip council`로 내부 기안문과 학운위 안건문을 만듭니다. [서류 작성 안내](./skills/edzip-autopilot/SKILL.md)를 따르세요.
- `protection`: 권리와 이용 범위를 묻고 앱 보호 변경 계획을 세웁니다. `protect apply`는 승인한 계획 해시와 `--confirm-apply`가 있을 때 백업 후 적용합니다. `verify`로 확인하고 필요하면 `protect restore`로 복원합니다.

에듀집 서류에는 공식 원본과 제출 안내가 함께 들어갑니다. 이름·학교·전화·결재선·서명은 받거나 저장하지 않고 사용자가 채울 위치를 안내합니다. 구글폼 제출 뒤 며칠이 지나도 연락이 없으면 서류에 적힌 KERIS 담당 부서에 진행 상태를 문의하세요.

## 저장하는 파일

`detect`, `status`, `report`는 조회 명령입니다. `init`은 프로젝트에 `dorms-check.config.json`을 만듭니다. `scan`은 `.dorms-check/`에 검사 결과, 보고서, 이력을 저장합니다. `judge`와 `interview --answers`는 사용자가 제공한 근거와 답변을 저장하고, `submit`은 보관용 증빙팩을 만듭니다.

서류·보호 계획도 로컬 파일로 저장합니다. 서류 생성과 앱 보호 적용은 각 명령에 표시된 승인 절차를 따릅니다. 기본 점검은 앱 소스를 수정하거나 배포하지 않습니다.

## 이전 버전 정리

0.3.0부터 전역 훅 설치와 배포 차단 기능을 제거했습니다. 예전 옵션은 `FEATURE_REMOVED`와 종료 코드 2를 돌려주며, 일반 검사로 바꾸어 실행하지 않습니다.

이전에 설치한 훅이 있으면 [이전 설치 정리 안내](./docs/LEGACY-HOOK-CLEANUP.ko.md)를 보세요. 새 점검에는 훅 설치, Vercel CLI, 배포 토큰이 필요하지 않습니다.

## 제작과 이용

Team DoRm의 교사 홍창욱이 제작했습니다. 이용 조건은 [LICENSE](./LICENSE)와 [NOTICE.md](./NOTICE.md), 점검의 한계는 [DISCLAIMER.md](./DISCLAIMER.md)를 확인하세요.
