# Vercel 배포 전 strict 보안 게이트

`strict`는 일반 점수표가 아니라 배포를 멈출 수 있는 보안 게이트입니다. 검사하지 못한 critical/high 항목은 통과로 추정하지 않습니다. 코드 검사, 격리 배포 실측, 실제 프로덕션 연결을 서로 다른 단계로 나눕니다.

## 한눈에 보는 흐름

1. 현재 앱 코드를 커밋하고 Git 작업트리를 깨끗하게 만듭니다.
2. 현재 Git SHA로 code strict 검사를 통과합니다.
3. 전역 Vercel 훅을 설치하고 설정 상태를 확인합니다.
4. 현재 HEAD를 두 Git metadata 값에 literal로 넣은 단일 `vercel --prod --skip-domain` 명령으로 staged production을 만듭니다.
5. 그 명령이 stdout으로 돌려준 배포 URL 하나를 live strict 검사에 넣습니다.
6. 영수증과 현재 Git, Vercel 배포 URL/ID가 모두 일치하는지 확인합니다.
7. 같은 URL 또는 검증된 ID만 `vercel promote`로 연결합니다.

훅은 4번 전에 유효한 code 영수증을 요구합니다. 7번 전에는 유효한 code 영수증과 live 영수증을 모두 요구합니다. rollback, redeploy, rolling release, alias 변경, 임의 Vercel API는 자동 실행하지 못하게 차단합니다. 영수증은 발급 후 15분 동안만 유효합니다.

## 설치 버전을 고정하세요

배포 게이트에서는 기본 브랜치의 최신판을 그대로 실행하지 마세요. 검토를 마친 정확한 Git 커밋 SHA를 고정한 실행 명령을 사용합니다.

```text
npx -y github:shinnanchanguk/dorms-check#정확한_40자리_커밋_SHA
```

이 문서의 예시는 읽기 쉽도록 이미 고정 설치된 실행 파일을 `dcheck`라고 씁니다. AI는 교육 자료나 릴리스 노트에 적힌 검토 완료 SHA를 사용하고, 실행할 때마다 같은 SHA인지 확인해야 합니다. 아직 원격 저장소에 push하지 않은 로컬 커밋은 `github:` 주소로 설치할 수 없습니다.

## 최초 설정

본인이 운영 권한을 가진 앱 폴더에서만 실행합니다.

```bash
dcheck detect
dcheck init --name "내 앱" --track security --confirm-ownership
```

`init`이 만든 설정과 배포할 코드가 의도한 변경인지 AI가 확인한 뒤 커밋합니다. 모르는 변경이나 다른 사람이 작업 중인 파일이 있으면 임의로 포함하지 말고 사용자에게 한 번 확인합니다.

## 세 에이전트 전역 훅

한 번에 설치:

```bash
dcheck hooks install --global --agents codex,claude,gemini --provider vercel --security-only
dcheck hooks status --agents codex,claude,gemini --json
```

각 에이전트만 설치하려면 `--agents codex`, `--agents claude`, `--agents gemini` 중 하나를 씁니다. 설정 위치는 다음과 같습니다.

| 에이전트 | 설정 | 이벤트와 matcher |
|---|---|---|
| Codex | `~/.codex/config.toml` | `PreToolUse`, `^Bash$` |
| Claude Code | `~/.claude/settings.json` | `PreToolUse`, `Bash|PowerShell` |
| Gemini CLI | `~/.gemini/settings.json` | `BeforeTool`, `^run_shell_command$` |

세 설정 모두 `~/.dorms-check/hooks/vercel-guard.cjs`를 호출하며 timeout은 120초입니다. 기존 설정은 보존하고, 바꾸기 전 사본은 `~/.dorms-check/backups/`에 둡니다. 모든 선택 설정을 먼저 파싱한 뒤 쓰므로 뒤쪽 JSON이 손상된 경우 앞쪽 설정만 바뀌지 않습니다. 같은 설치 명령을 다시 실행해도 중복 훅을 만들지 않습니다.

`hooks status --json`의 `hostPlatform`, `home`, `isWSL`, `installationScope`, `timeoutSeconds`, `hostTimeoutMayFailOpen`을 확인합니다. 설치 범위는 `current-host-only`입니다. Windows와 WSL은 홈과 프로세스가 다른 별도 호스트이므로 실제 배포에 쓸 쪽마다 설치·확인해야 합니다. 사용하려는 호스트가 덮이지 않으면 READY로 보고하지 않습니다. 호스트 자체가 command hook timeout을 fail-open으로 처리할 가능성은 로컬 훅이 제거할 수 없습니다.

설정 파일이 올바르다는 것과 현재 실행 중인 AI 프로세스가 새 훅을 이미 불러왔다는 것은 다릅니다. 설치 뒤 각 CLI가 재시작이나 신뢰 확인을 요구하면 사용자가 그 동작만 완료해야 합니다. Codex는 `/hooks`에서 새 훅을 검토하고 신뢰해야 할 수 있습니다. 이 신뢰 단계를 자동 우회하지 않습니다.

제거:

```bash
dcheck hooks uninstall --agents codex,claude,gemini --json
```

제거 명령은 dorms-check가 추가한 항목만 지웁니다. 다른 훅과 설정은 남깁니다.

## 결정적 배포 순서

아래 명령은 앱 저장소 루트에서 AI가 실행합니다. 사용자가 터미널에 옮겨 적을 필요는 없습니다.

### 1. 현재 소스 고정과 code strict

macOS, Linux, WSL:

```bash
SHA="$(git rev-parse HEAD)"
dcheck scan --track security --strict --json --code-only --git-sha "$SHA"
```

Windows PowerShell:

```powershell
$sha = (git rev-parse HEAD).Trim()
dcheck scan --track security --strict --json --code-only --git-sha $sha
```

작업트리가 더럽거나 요청 SHA가 현재 HEAD와 다르면 영수증을 만들지 않습니다. AI가 만든 설명이나 `judge` 결과는 하드코딩 시크릿, 클라이언트 시크릿 같은 결정적 판정을 덮을 수 없습니다.

### 2. 도메인을 붙이지 않은 staged production

```bash
vercel --prod --skip-domain --meta githubDeployment=1 --meta githubCommitSha=0123456789abcdef0123456789abcdef01234567
```

위 SHA는 형식 예시입니다. AI는 먼저 `git rev-parse HEAD` 결과를 읽고, 실제 40자리 값을 명령 문자열에 직접 넣어 독립된 한 명령으로 실행합니다. `$SHA`, `${SHA}`, `%SHA%`, 명령 치환을 Vercel 명령에 넣으면 훅이 차단합니다. `githubDeployment=1`과 `githubCommitSha=<실제 HEAD>`는 Vercel CLI 배포에 Git 정보를 연결하는 정확히 두 metadata이며, 중복·추가 metadata도 허용하지 않습니다.

Vercel CLI는 성공하면 stdout에 정확한 Deployment URL을 출력합니다. AI는 그 값을 그대로 보관해야 합니다. `--skip-domain` 없는 직접 production 배포, code 영수증 없음·만료, 저장소 루트가 아닌 위치, `--prebuilt`, `--archive`, `--cwd`, `--local-config`, `--project`, `--scope`, `--env`, `--build-env` 같은 source·artifact·project override는 차단합니다. `deploy`와 비대화형 `--yes`만 선택적으로 덧붙일 수 있습니다.

### 3. 같은 배포의 live strict

macOS, Linux, WSL:

```bash
DEPLOYMENT_URL="vercel_명령이_stdout으로_돌려준_정확한_URL"
dcheck scan --track security --strict --json --url "$DEPLOYMENT_URL" --git-sha "$SHA" --vercel-deployment "$DEPLOYMENT_URL"
```

Windows PowerShell:

```powershell
$deploymentUrl = "vercel_명령이_stdout으로_돌려준_정확한_URL"
dcheck scan --track security --strict --json --url $deploymentUrl --git-sha $sha --vercel-deployment $deploymentUrl
```

`dcheck`는 로컬 `.vercel/project.json`과 `vercel inspect <URL|ID> --json`을 함께 확인합니다. URL/ID, `READY`, production target뿐 아니라 배포 source Git SHA가 현재 HEAD인지, Vercel projectId와 orgId/teamId가 현재 링크와 같은지 확인해 영수증에 묶습니다. Git metadata가 없거나 프로젝트 정보가 없으면 `INCOMPLETE`, 값이 다르면 `BINDING_MISMATCH`입니다. 최초 URL이 다른 origin으로 redirect되어 그쪽 내용을 검사하는 경우도 바인딩 불일치로 중단합니다.

live strict는 다음 critical/high 항목을 모두 관측해야 합니다.

- 하드코딩 시크릿과 클라이언트 시크릿
- CSP 실제 값
- HTTP에서 HTTPS로 강제 이동
- 승인된 TLS 인증서
- `.env`, `.git` 같은 민감 파일 노출
- 위험한 CORS
- Supabase RLS와 Firebase 익명 읽기
- 공개 개인정보처리방침

Supabase나 Firebase를 쓰지 않는다는 사실을 검사로 확인한 경우에만 해당 항목의 `na`를 허용합니다. 시간 초과, 접속 오류, 프로브 실패는 `INCOMPLETE`입니다.

CSP의 `form-action`과 `frame-ancestors`는 각각 정확히 단일 source인 `'self'` 또는 `'none'`만 통과합니다. 외부 HTTPS origin, `data:`, `'unsafe-inline'`, 복수 source는 strict에서 실패합니다.

### 4. 영수증 확인과 promote

macOS, Linux, WSL:

```bash
dcheck gate verify --git-sha 0123456789abcdef0123456789abcdef01234567 --vercel-deployment https://my-app-abc123.vercel.app --url https://my-app-abc123.vercel.app --json
vercel promote https://my-app-abc123.vercel.app
```

Windows PowerShell:

```powershell
dcheck gate verify --git-sha 0123456789abcdef0123456789abcdef01234567 --vercel-deployment https://my-app-abc123.vercel.app --url https://my-app-abc123.vercel.app --json
vercel promote https://my-app-abc123.vercel.app
```

SHA와 URL은 예시를 복사하는 것이 아니라 직전 출력의 실제 literal 값으로 바꿉니다. `vercel promote`는 영수증에 기록된 정확한 URL 또는 검증된 ID 하나만 받는 단일 literal 명령이어야 합니다. 셸 변수, 추가 옵션, `npx`·`pnpm`·`bunx`, package script, 셸·Node 스크립트, `;`, `&&`, pipe, redirect를 쓰면 차단합니다.

### rollback의 정확한 규칙

`vercel rollback`은 즉시 프로덕션 트래픽을 바꾸므로 영수증이 정확해도 모든 쓰기 형태를 차단합니다. AI는 자동 실행하지 않고 사용자에게 복구 절차만 제시합니다. `vercel redeploy`, `vercel rolling-release`, alias 설정·제거·구형 alias 문법, `vercel api`도 모두 차단합니다. `vercel rollback status`, `vercel promote status`, `vercel alias list` 같은 명시적 조회형만 허용합니다.

## 영수증과 종료 코드

영수증은 현재 저장소의 실제 경로 해시, clean Git SHA/tree, 검사 결과 digest, Vercel URL/ID, 배포 source Git SHA, Vercel project/org ID, 게이트 schema와 strict-runtime SHA-256, 발급·만료 시각을 담습니다. 로컬 키로 HMAC-SHA256 서명하고, 신뢰용 사본은 `~/.dorms-check/receipts/`, 프로젝트 확인용 사본은 `.dorms-check/`에 둡니다. 다른 dorms-check 런타임이 만든 영수증은 서명이 유효해도 거부합니다.

| 코드 | 상태 | 뜻 |
|---:|---|---|
| 0 | `PASS` | 필수 검사가 모두 통과함 |
| 1 | `SECURITY_BLOCKED` | 확인된 보안 결함이 있음 |
| 2 | `USAGE_CONFIG` | 인자나 설정이 잘못됨 |
| 3 | `INCOMPLETE` | 필수 검사를 끝내지 못함 |
| 4 | `BINDING_MISMATCH` | Git, URL, 배포 ID 중 하나가 영수증과 다름 |
| 5 | `RECEIPT_INVALID` | 영수증 없음, 만료, 손상, 서명 불일치 |

1만 실제 보안 결함입니다. 2부터 5까지를 “안전”이나 “통과”로 바꾸어 해석하면 안 됩니다. 15분이 지나면 같은 현재 소스에서 code strict와 필요한 live strict를 다시 실행합니다.

## 정확한 한계

- 프로덕션 변경은 현재 Git 루트에서 실행하는 단 하나의 literal `vercel` 또는 `vc` 명령만 허용합니다. 알려진 wrapper와 스크립트뿐 아니라 이름을 바꾼 실행 파일, 동적 변수, 중첩 셸, 복합 명령도 보수적으로 차단합니다. read-only Vercel 명령은 이 제한 대상이 아닙니다.
- 설치는 현재 호스트와 현재 홈만 보호합니다. Windows와 WSL, 다른 사용자, 다른 컴퓨터에는 자동 전파되지 않습니다. 훅 timeout은 120초지만 호스트가 timeout을 fail-open으로 처리할 수 있다는 한계가 있습니다.
- Vercel 대시보드에서 직접 누르는 배포, Git push로 자동 실행되는 production 배포, 다른 CI 사용자의 명령은 이 로컬 훅이 볼 수 없습니다. strict 흐름을 쓸 프로젝트는 Vercel의 Git production 자동 배포와 임의 도메인 자동 연결을 별도로 제한해야 합니다.
- 같은 운영체제 사용자와 같은 권한을 가진 악의적 코드는 로컬 훅이나 로컬 HMAC 키를 바꿀 수 있습니다. 이 게이트는 실수와 AI의 우발적 우회를 막는 장치이지, 관리자 권한 공격자에 대한 보안 경계가 아닙니다.
- 새 훅을 신뢰하지 않았거나 에이전트 설정에서 훅을 껐다면 강제되지 않습니다. `hooks status`는 파일과 설정 무결성을 확인하지만, 실행 중인 호스트 프로세스의 신뢰 UI까지 대신 누르지는 않습니다.
- dorms-check 통과는 인증서가 아닙니다. 최종 도름스 마크는 도름스 서버가 별도로 재검증합니다.

## 공식 근거

- [Vercel staged production과 promote](https://vercel.com/docs/cli/deploying-from-cli)
- [Vercel rollback](https://vercel.com/docs/cli/rollback)
- [Vercel deploy stdout은 Deployment URL](https://vercel.com/docs/cli/deploy)
- [Vercel metadata로 배포 목록 필터링](https://vercel.com/docs/cli/list)
- [Vercel CLI 배포의 Git metadata 연결](https://vercel.com/kb/guide/branch-variables-and-domains-not-linked-to-cli-deployments)
- [Vercel inspect](https://vercel.com/docs/cli/inspect)
- [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- [Gemini CLI hooks reference](https://geminicli.com/docs/hooks/reference/)
- [Codex hooks](https://learn.chatgpt.com/docs/hooks)
