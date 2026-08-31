# Vercel 배포 전 strict 보안 게이트

`strict`는 일반 점수표가 아니라 배포를 멈출 수 있는 보안 게이트입니다. 검사하지 못한 critical/high 항목은 통과로 추정하지 않습니다. 코드 검사, 격리 배포 실측, 실제 프로덕션 연결을 서로 다른 단계로 나눕니다.

## 한눈에 보는 흐름

1. 현재 앱을 `vercel link`로 연결한 뒤 코드를 커밋하고 Git 작업트리를 깨끗하게 만듭니다.
2. 현재 Git SHA와 `.vercel/project.json`의 project/org/digest로 code strict 검사를 통과합니다.
3. 전역 Vercel 훅을 설치하고 설정 상태를 확인합니다.
4. 현재 HEAD를 두 Git metadata 값에 literal로 넣은 단일 `vercel --prod --skip-domain` 명령으로 staged production을 만듭니다.
5. 그 명령이 stdout으로 돌려준 배포 URL 하나를 live strict 검사에 넣습니다.
6. 영수증과 현재 Git, Vercel 배포 URL/ID가 모두 일치하는지 확인합니다.
7. 같은 URL 또는 검증된 ID만 `vercel promote`로 연결합니다.

훅은 4번 전에 유효한 code 영수증을 요구합니다. 7번 전에는 유효한 code 영수증과 live 영수증을 모두 요구합니다. 검증된 staged와 promote 외 모든 Vercel 쓰기는 차단합니다. 영수증은 발급 후 15분 동안만 유효합니다.

## 설치 버전을 고정하세요

배포 게이트에서는 기본 브랜치의 최신판을 그대로 실행하지 마세요. 검토를 마친 정확한 Git 커밋 SHA를 고정한 실행 명령을 사용합니다.

```text
npm install --global github:shinnanchanguk/dorms-check#정확한_40자리_커밋_SHA
```

이 문서의 예시는 이렇게 고정 설치한 실행 파일을 `dcheck`라고 씁니다. AI는 교육 자료나 릴리스 노트에 적힌 검토 완료 SHA를 사용하고, 실행할 때마다 같은 SHA인지 확인해야 합니다. 아직 원격 저장소에 push하지 않은 로컬 커밋은 `github:` 주소로 설치할 수 없습니다.

배포 파일 제외 규칙과 deployment metadata 응답은 Vercel CLI 버전에 따라 달라지므로, strict 게이트가 검토한 버전도 훅을 설치하기 전에 고정합니다.

```text
npm install --global vercel@59.10.0
```

다른 Vercel CLI 버전은 code 영수증이 있어도 staged, live, promote에서 차단됩니다.

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

| 에이전트 | 기본 설정 | 공식 사용자 지정 루트 | 이벤트와 matcher |
|---|---|---|---|
| Codex | `~/.codex/config.toml` | `$CODEX_HOME/config.toml` | `PreToolUse`, `^Bash$` |
| Claude Code | `~/.claude/settings.json` | `$CLAUDE_CONFIG_DIR/settings.json` | `PreToolUse`, `Bash|PowerShell` |
| Gemini CLI | `~/.gemini/settings.json` | `$GEMINI_CLI_HOME/.gemini/settings.json` | `BeforeTool`, `^run_shell_command$` |

사용자 지정 루트는 절대 경로여야 합니다. status는 각 에이전트의 실제 `configRoot`와 `configRootSource`를 보여 줍니다. 세 설정 모두 `~/.dorms-check/hooks/vercel-guard.cjs`를 호출하며, PATH의 `node` 문자열이 아니라 설치 시 검증한 현재 호스트의 절대 Node 실행 파일을 기록합니다. timeout은 120초입니다. 기존 설정은 보존하고, 바꾸기 전 사본은 `~/.dorms-check/backups/`에 둡니다. 모든 선택 설정을 먼저 파싱한 뒤 쓰므로 뒤쪽 JSON이 손상된 경우 앞쪽 설정만 바뀌지 않습니다. 같은 설치 명령을 다시 실행해도 중복 훅을 만들지 않습니다.

native Windows에서 `hooks install`은 기본 제공 Windows PowerShell 5.1 `powershell.exe`와 `Get-Command vercel -All -CommandType Application`으로 exact `vercel.cmd`를 찾고 `vercel@59.10.0`인지 확인한 뒤 절대 경로·SHA-256·버전과 PowerShell 경로·해시를 manifest에 고정합니다. 그 실제 CLI는 직접 노출하지 않고 같은 strict gate를 스스로 실행하는 관리형 `~/.dorms-check/hooks/vercel.cmd` proxy를 `windowsVercelExecutable`로 제공합니다. 이 proxy는 Codex의 `PreToolUse`가 호스트 문제로 발화하지 않아도 영수증 검사 없이 backing Vercel CLI를 실행하지 않습니다. status의 `windowsPowerShellSupported`, `windowsVercelExecutableVerified`, `windowsVercelExecutable`, `windowsVercelExecutableSha256`, `windowsVercelBackingExecutable`, `windowsVercelBackingExecutableSha256`, `windowsVercelVersion`, `windowsPowerShellExecutableSha256`를 모두 확인합니다. 명령은 status가 반환한 proxy 경로 철자를 대소문자까지 그대로 복사해야 합니다. PowerShell 7 셸에서도 proxy 호출은 가능하지만 설치와 Codex CMD launcher 검증에는 Windows PowerShell 5.1이 필요합니다.

Windows 업데이트나 npm 재설치로 proxy, backing `vercel.cmd`, PowerShell 해시 중 하나라도 바뀌면 훅과 proxy는 fail-closed로 멈춥니다. `vercel@59.10.0`을 확인한 뒤 훅 설치를 다시 실행해 새 해시를 고정합니다.

Codex는 Windows의 CMD 훅 런처 제약을 피하도록 고정 PowerShell의 quote-free `-EncodedCommand`를 기록하고, Claude는 절대 Node exec form, Gemini는 PowerShell call-operator 형식으로 같은 guard를 호출합니다. 검사 대상 Vercel 명령은 관리형 proxy 경로를 직접 쓴 `& '<exact windowsVercelExecutable>' <literal args>` 단일 형식만 허용합니다. alias, function, `vercel.ps1`, backing 또는 다른 `.cmd`·`.exe`, 변수, splatting, `--%`, backtick, 동적 cmdlet, wrapper, pipe, redirect, 복합 명령은 차단합니다.

`hooks install`과 `hooks status`는 설정 파일을 쓴 사실만 `configured`로 보고합니다. 현재 실행 중인 호스트가 훅을 로드하고 신뢰했는지는 관찰할 수 없으므로 `activation: unknown`, `ready: false`, 종료 코드 3을 유지합니다. 이것을 PASS로 바꾸어 해석하지 않습니다. `hooks status --json`의 에이전트별 `configRoot`, `configRootSource`와 공통 `nodeExecutable`, `nodeExecutableVerified`, `hostPlatform`, `home`, `isWSL`, `installationScope`, `timeoutSeconds`, `hostTimeoutMayFailOpen`도 확인합니다. 설치 범위는 `current-host-only`입니다. Windows와 WSL은 홈과 프로세스가 다른 별도 호스트이므로 실제 배포에 쓸 쪽마다 설치·확인해야 합니다. 사용하려는 호스트가 덮이지 않으면 READY로 보고하지 않습니다. 호스트 자체가 command hook timeout을 fail-open으로 처리할 가능성은 로컬 훅이 제거할 수 없습니다.

설정 파일이 올바르다는 것과 현재 실행 중인 AI 프로세스가 새 훅을 이미 불러왔다는 것은 다릅니다. 설치 뒤 각 CLI를 재시작하고 필요한 신뢰 확인을 사용자가 완료해야 합니다. Codex는 `/hooks`에서 새 훅을 검토하고 신뢰해야 할 수 있습니다. 이 신뢰 단계를 자동 우회하지 않습니다. Codex TOML이 파싱되지 않거나 `features.hooks=false`, 과거 별칭 `features.codex_hooks=false`이면 configured가 아닙니다. Gemini의 `hooksConfig.enabled=false` 또는 `hooksConfig.disabled`에 dorms-check 훅 이름이 있어도 configured가 아닙니다. Codex의 `--disable hooks`, Claude의 `--bare`, `--safe-mode`, `--settings`, `--setting-sources`, Gemini의 프로젝트·시스템 설정처럼 실행 시점 또는 상위 우선순위 설정은 이 사용자 설정 검사만으로 관찰할 수 없습니다.

재시작과 신뢰 뒤 각 실제 에이전트 셸에서 안전한 invalid-target promote를 한 번 요청합니다. Bash는 `vercel promote https://dcheck-hook-challenge.invalid`, native PowerShell은 status의 실제 경로를 넣은 `& '<exact windowsVercelExecutable>' promote https://dcheck-hook-challenge.invalid`를 씁니다. 올바른 결과는 backing Vercel CLI가 실행되기 전에 exit 2로 차단되는 것입니다. Windows의 관리형 proxy 차단은 호스트 훅 발화 여부와 무관하게 동작합니다. 이 실제 차단을 보지 못하면 NOT READY이며 배포를 진행하지 않습니다.

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

작업트리가 더럽거나 요청 SHA가 현재 HEAD와 다르면 영수증을 만들지 않습니다. `assume-unchanged`나 `skip-worktree` 플래그, Git clean filter로 tracked 변경을 숨긴 경우도 차단합니다. Vercel이 업로드할 모든 파일의 실제 작업 폴더 경로·원본 바이트 SHA-256·크기·mode manifest를 묶으므로 Git tree가 같아도 실제 업로드 바이트나 실행 mode가 바뀌면 중단합니다. Vercel이 업로드할 수 있는 ignored 또는 untracked 파일, symlink가 하나라도 있으면 Git HEAD에 묶을 수 없으므로 차단합니다. `.vercelignore`나 `.nowignore`의 negation 규칙은 Vercel 기본 제외 파일을 다시 포함할 수 있으므로 strict에서 차단하고, 두 ignore 파일의 동시 사용도 허용하지 않습니다. Vercel CLI가 특별히 업로드하는 `.vercel/routes.json`은 ignored 상태여도 원본 manifest에 포함하고, symlink `.vercel`은 허용하지 않습니다. 예전 일반 검사 상태 중 정확히 허용된 `.dorms-check/REPORT.md`, `review.json`, `scan.json`, `state.json`, `strict-code.json`, `strict-live.json`만 내용 digest로 묶고, 그 밖의 `.dorms-check/**` 파일은 배포 입력 우회가 될 수 있어 차단합니다. 파일당 100 MiB, 전체 1 GiB, 20,000개를 넘거나 해시 중 파일이 바뀌어도 실패합니다. strict 검사 자체는 프로젝트 안에 report나 영수증을 새로 쓰지 않습니다.

`.vercel/project.json`을 안전하게 읽을 수 없거나 projectId/orgId가 없으면 code 영수증도 만들지 않습니다. 이 파일의 project/org와 정확한 파일 SHA-256 digest가 code 영수증에 서명됩니다. 이후 `vercel link`, `vercel switch`, `vercel git connect`로 바꾸면 staged와 live가 중단됩니다. `VERCEL_PROJECT_ID`, `NOW_PROJECT_ID`, `VERCEL_ORG_ID`, `NOW_ORG_ID`, `VERCEL_TEAM_ID`가 설정된 경우 서명된 링크와 정확히 같아야 합니다. `VERCEL_TOKEN`, `NOW_TOKEN`, `VERCEL_SCOPE`, `VERCEL_TEAM`, `VERCEL_PROJECT`, `VERCEL_CWD`, `VERCEL_CONFIG`, `VERCEL_GLOBAL_CONFIG`, `VERCEL_LOCAL_CONFIG` 같은 ambient target·token·config override는 strict 흐름에서 차단합니다. AI가 만든 설명이나 `judge` 결과는 하드코딩 시크릿, 클라이언트 시크릿 같은 결정적 판정을 덮을 수 없습니다.

Git 조회는 replace refs를 무시한 실제 HEAD를 사용합니다. `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, object directory/alternate, namespace, replace/config override처럼 repository identity를 바꾸는 ambient Git 환경변수는 차단합니다. Vercel 환경변수는 서명된 값과 같은 project/org/team identity만 허용하며 그 밖의 비어 있지 않은 `VERCEL*`/`NOW*` 값은 artifact·target 우회를 막기 위해 차단합니다. 표준 `core.autocrlf`/EOL 변환은 Git canonical blob으로 HEAD와 비교하고, 실제 업로드 원본 바이트와 mode는 별도 manifest digest에 묶습니다. 정적 시크릿 검사는 manifest의 path·size·mode·SHA-256과 검사 직전/직후 파일 snapshot을 다시 확인하므로 검사 사이에 바뀐 파일을 PASS로 읽지 않습니다.

### 2. 도메인을 붙이지 않은 staged production

macOS, Linux, WSL Bash:

```bash
vercel --prod --skip-domain --meta githubDeployment=1 --meta githubCommitSha=0123456789abcdef0123456789abcdef01234567 --yes
```

native Windows PowerShell:

```powershell
& 'C:\Users\me\.dorms-check\hooks\vercel.cmd' --prod --skip-domain --meta githubDeployment=1 --meta githubCommitSha=0123456789abcdef0123456789abcdef01234567 --yes
```

위 SHA와 Windows 경로는 형식 예시입니다. AI는 `git rev-parse HEAD`의 실제 40자리 값과 `hooks status --json`의 실제 `windowsVercelExecutable`을 명령 문자열에 직접 넣습니다. `$SHA`, `$path`, `${...}`, `%...%`, 명령 치환, splatting을 Vercel 명령에 넣으면 차단합니다. `githubDeployment=1`과 `githubCommitSha=<실제 HEAD>`는 정확히 두 metadata이며, 중복·추가 metadata도 허용하지 않습니다.

Vercel CLI는 성공하면 stdout에 정확한 Deployment URL을 출력합니다. AI는 그 값을 그대로 보관해야 합니다. `--skip-domain` 없는 직접 production 배포, code 영수증 없음·만료, 저장소 루트가 아닌 위치, `--prebuilt`, `--archive`, `--cwd`, `--local-config`, `--project`, `--scope`, `--env`, `--build-env` 같은 source·artifact·project override는 차단합니다. `deploy`는 명령의 첫 subcommand로 정확히 한 번만, 비대화형 `--yes`는 한 번만 선택적으로 덧붙일 수 있습니다. `vercel deploy deploy ...`처럼 두 번째 `deploy`나 다른 positional source path를 넣는 형식은 차단합니다.

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

`dcheck`는 code 영수증, 현재 `.vercel/project.json`, `vercel inspect <URL|ID> --format=json`, 내부 read-only `GET /v13/deployments/<ID>` metadata를 함께 확인합니다. 사용자에게 임의 `vercel api` 실행을 허용하는 것이 아니라 고정 dcheck가 exact deployment ID와 linked org로 GET 한 번만 수행합니다. 두 응답의 URL/ID, `READY`, production target뿐 아니라 `githubDeployment=1`, exact `githubCommitSha`, 배포 source Git SHA가 현재 HEAD인지, Vercel projectId와 ownerId/orgId가 서명된 링크와 같은지 확인해 영수증에 묶습니다. canonical Git metadata가 없거나 프로젝트 정보가 없으면 `INCOMPLETE`, 값이 다르면 `BINDING_MISMATCH`입니다. 최초 URL이 다른 origin으로 redirect되어 그쪽 내용을 검사하는 경우도 바인딩 불일치로 중단합니다. HTTP 강제 이동도 `https://evil.example` 같은 외부 origin이나 malformed Location은 실패하며, 검사 중인 정확한 배포 origin의 HTTPS로 갈 때만 통과합니다.

외부·런타임 검사가 오래 걸릴 수 있으므로 live PASS 영수증을 쓰기 직전에 code 영수증의 15분 만료와 현재 source binding을 다시 확인합니다. 그 사이 만료되거나 바뀌면 live 성공을 보고하지 않고 code strict부터 다시 시작합니다.

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

native Windows PowerShell:

```powershell
dcheck gate verify --git-sha 0123456789abcdef0123456789abcdef01234567 --vercel-deployment https://my-app-abc123.vercel.app --url https://my-app-abc123.vercel.app --json
& 'C:\Users\me\.dorms-check\hooks\vercel.cmd' promote https://my-app-abc123.vercel.app
```

SHA, URL, Windows proxy 경로는 예시를 복사하지 말고 직전 출력의 실제 literal 값으로 바꿉니다. promote는 영수증에 기록된 정확한 URL 또는 검증된 ID 하나만 받는 단일 literal 명령이어야 합니다. 셸 변수, 추가 옵션, wrapper, package script, `;`, `&&`, pipe, redirect를 쓰면 차단합니다.

### Vercel 쓰기 명령의 정확한 규칙

strict 훅은 위의 검증된 staged와 exact promote 두 쓰기만 허용합니다. 그 밖의 직접 Vercel 명령도 기본 차단하며, 명시적 `list`/`ls`, `inspect`, `status`, `get`, `help`, `version`, `whoami` 조합만 read-only allowlist로 통과시킵니다. `vercel rollback`은 즉시 프로덕션 트래픽을 바꾸므로 영수증이 정확해도 차단합니다. `rollback status`만 조회입니다. `redeploy`, `rolling-release`와 별칭 `rr`, alias/domain/DNS/env/project/Git/flag/webhook/route/firewall/deploy-hook 변경, `vercel api`, preview deploy, link/switch도 모두 차단합니다. AI는 자동 실행하지 않고 필요한 절차만 제시합니다.

## 영수증과 종료 코드

영수증은 현재 저장소의 실제 경로 해시, clean Git SHA/tree, 실제 Vercel 업로드 파일 path·bytes·size·mode manifest digest, 허용된 legacy 상태 파일 digest, `.vercel/project.json`의 project/org/name와 정확한 파일 digest, 검사 결과 digest, Vercel URL/ID, 배포 source Git SHA, 게이트 schema와 strict-runtime SHA-256, 발급·만료 시각을 담습니다. 로컬 키로 HMAC-SHA256 서명하고 `~/.dorms-check/receipts/`에만 둡니다. strict 검사 결과와 영수증을 프로젝트의 `.dorms-check/`에 복사하지 않습니다. 다른 dorms-check 런타임이 만든 영수증은 서명이 유효해도 거부합니다.

| 코드 | 상태 | 뜻 |
|---:|---|---|
| 0 | `PASS` | 필수 검사가 모두 통과함 |
| 1 | `SECURITY_BLOCKED` | 확인된 보안 결함이 있음 |
| 2 | `USAGE_CONFIG` | 인자나 설정이 잘못됨 |
| 3 | `INCOMPLETE` | 필수 검사를 끝내지 못함 |
| 4 | `BINDING_MISMATCH` | Git, Vercel project/org/link digest, URL, 배포 ID 중 하나가 영수증과 다름 |
| 5 | `RECEIPT_INVALID` | 영수증 없음, 만료, 손상, 서명 불일치 |

1만 실제 보안 결함입니다. 2부터 5까지를 “안전”이나 “통과”로 바꾸어 해석하면 안 됩니다. 15분이 지나면 같은 현재 소스에서 code strict와 필요한 live strict를 다시 실행합니다.

## 정확한 한계

- 원격 상태 변경은 현재 Git 루트의 검증된 staged 또는 promote 단 하나의 literal 명령만 허용합니다. macOS/Linux/WSL은 canonical `vercel`, native Windows PowerShell은 status의 관리형 `windowsVercelExecutable` proxy 절대 경로만 씁니다. `vc`, backing CLI 직접 실행, 다른 `.cmd`·`.exe`, wrapper, 변수, 중첩 셸, 복합 명령을 차단합니다. read-only도 명시적 command+verb allowlist만 허용합니다.
- 훅은 셸 문법 전체를 증명하지 않습니다. command substitution, 변수 확장, Bash ANSI-C quoting, `eval`, Windows caret·`call`, PowerShell backtick·splatting·동적 cmdlet, runtime·package·workspace·task launcher를 보수적으로 차단합니다. 관리형 Windows proxy는 인자를 받은 뒤 동일한 strict runtime을 다시 실행하여 호스트 훅 미발화에 대비하지만, 같은 사용자가 backing CLI·manifest·proxy를 악의적으로 변조하는 것까지 막는 시스템 보안 경계는 아닙니다.
- backing `vercel.cmd` 해시와 매 쓰기 직전의 `--version` 확인은 예상치 못한 버전 변경을 차단하지만, npm 패키지 트리 전체의 암호학적 공급망 증명은 아닙니다. 정확히 `vercel@59.10.0`을 설치하고 같은 사용자 권한의 악의적 변조는 별도 운영 통제로 다룹니다.
- 설치는 현재 호스트와 현재 홈만 보호합니다. Windows와 WSL, 다른 사용자, 다른 컴퓨터에는 자동 전파되지 않습니다. 훅 timeout은 120초지만 호스트가 timeout을 fail-open으로 처리할 수 있다는 한계가 있습니다.
- Vercel 대시보드에서 직접 누르는 배포, Git push로 자동 실행되는 production 배포, 다른 CI 사용자의 명령은 이 로컬 훅이 볼 수 없습니다. strict 흐름을 쓸 프로젝트는 Vercel의 Git production 자동 배포와 임의 도메인 자동 연결을 별도로 제한해야 합니다.
- 같은 운영체제 사용자와 같은 권한을 가진 악의적 코드는 로컬 훅이나 로컬 HMAC 키를 바꿀 수 있습니다. 이 게이트는 실수와 AI의 우발적 우회를 막는 장치이지, 관리자 권한 공격자에 대한 보안 경계가 아닙니다.
- 이름을 바꾼 임의의 네이티브 실행 파일이나 직접 REST/API 요청까지 모든 프로그램의 내부 동작을 증명하지는 않습니다. 이 흐름에서는 문서에 적힌 명령만 실행하고, 다른 배포 도구나 API 클라이언트로 production을 바꾸지 않습니다.
- source manifest는 고정 `vercel@59.10.0`의 upload 제외 규칙에 맞춥니다. Rust `Cargo.toml`의 동적 `/target` 제외처럼 안전하게 자동 증명하지 못한 프로젝트별 제외는 업로드되지 않더라도 보수적으로 차단될 수 있습니다.
- 새 훅을 신뢰하지 않았거나 에이전트·프로젝트·시스템 설정에서 훅을 껐다면 강제되지 않습니다. `hooks status`는 홈 파일과 설정 무결성만 configured로 확인하며 실제 activation은 항상 unknown입니다. 재시작·신뢰 뒤 안전한 invalid-target 차단 challenge를 각 호스트에서 직접 관측해야 합니다.
- dorms-check 통과는 인증서가 아닙니다. 최종 도름스 마크는 도름스 서버가 별도로 재검증합니다.

## 공식 근거

- [Vercel staged production과 promote](https://vercel.com/docs/cli/deploying-from-cli)
- [Vercel rollback](https://vercel.com/docs/cli/rollback)
- [Vercel deploy stdout은 Deployment URL](https://vercel.com/docs/cli/deploy)
- [Vercel metadata로 배포 목록 필터링](https://vercel.com/docs/cli/list)
- [Vercel CLI 배포의 Git metadata 연결](https://vercel.com/kb/guide/branch-variables-and-domains-not-linked-to-cli-deployments)
- [Vercel inspect](https://vercel.com/docs/cli/inspect)
- [Vercel CLI 명령 목록](https://vercel.com/docs/cli)
- [Vercel domains](https://vercel.com/docs/cli/domains)
- [Vercel DNS](https://vercel.com/docs/cli/dns)
- [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- [Gemini CLI hooks reference](https://geminicli.com/docs/hooks/reference/)
- [Codex hooks](https://learn.chatgpt.com/docs/hooks)
