# 설치와 사용 안내

## 실행 환경

Node.js 18 이상이 필요합니다. 명령을 실행하면 점검 도구와 문서 생성에 필요한 패키지를 내려받습니다. 점검 대상 프로젝트의 의존성은 바꾸지 않습니다.

아래 예시는 GitHub 릴리스 `v0.3.2`을 지정합니다. 검토한 커밋이 따로 있으면 릴리스 태그 대신 그 커밋을 쓰세요. 이름이 같은 다른 패키지를 대신 설치하거나 움직이는 기본 브랜치를 강제하지 않습니다.

~~~bash
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.3.2.tar.gz detect
~~~

소스를 직접 확인하며 사용하려면 릴리스를 내려받아 의존성을 설치한 뒤 실행합니다.

~~~bash
git clone --branch v0.3.0 https://github.com/shinnanchanguk/dorms-check.git
cd dorms-check
npm ci
node bin/dcheck.js help
~~~

## AI에서 사용하기

[USE-WITH-AI.md](./USE-WITH-AI.md)의 프롬프트를 사용하세요. 전역 에이전트 설정이나 셸 명령 경로를 등록할 필요가 없습니다. AI는 [AGENTS.md](./AGENTS.md)와 [SKILL.md](./SKILL.md)의 점검 기준을 따릅니다.

## 기본 명령

아래 표의 `dcheck`는 `npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.3.2.tar.gz`의 짧은 표기입니다.

| 명령 | 하는 일 |
| --- | --- |
| `dcheck detect` | 프로젝트 구성을 읽습니다 |
| `dcheck init --name "<앱>" --url "<주소>" --track security --confirm-ownership` | 점검 설정 파일을 만듭니다 |
| `dcheck scan --url "<주소>"` | 공개 응답과 코드를 검사하고 결과를 저장합니다 |
| `dcheck scan --code-only` | 코드를 검사하고 공개 주소 확인은 미확인으로 남깁니다 |
| `dcheck status` | 확인한 문제·권고·미확인을 보여줍니다 |
| `dcheck report` | 저장한 보고서를 보여줍니다 |
| `dcheck submit` | 보관용 증빙팩과 신청 안내를 만듭니다 |

`--track edzip`과 `--track protection`은 필요할 때 선택합니다. 계획·답변 저장, 서류 생성, 앱 보호 적용은 [README.ko.md](./README.ko.md)에 안내된 별도 절차를 따릅니다.

## 구버전 정리

[이전 설치 정리 안내](./docs/LEGACY-HOOK-CLEANUP.ko.md)에서 설치 상태를 읽고 도름스 훅만 해제할 수 있습니다. 검사와 정리에 Vercel 로그인·CLI·배포 토큰은 필요하지 않습니다. 정리 도구 자체를 실행할 현재 Node.js는 필요합니다.
