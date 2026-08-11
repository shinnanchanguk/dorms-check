# 설치와 사용 안내

## 설치는 필요 없어요 (깃허브 소스에서 바로 실행)
dorms-check는 따로 설치하지 않아도 돼요. 아래 한 줄이면 **이 깃허브 저장소의 최신판**을 그때그때 받아 실행해요.

> npm 에는 올리지 않아요. 올린 판은 소스를 손볼 때마다 다시 올려야 해서 금방 옛것이 되고, 실제로 받아지지 않는 일이 생겼거든요. 그래서 패키지 이름(`dorms-check@latest`) 대신 아래처럼 `github:` 주소를 씁니다. 이러면 언제 실행해도 최신판이에요.

```bash
npx -y github:shinnanchanguk/dorms-check detect
```

Node.js만 깔려 있으면 되고, 여러분 프로젝트에 무언가를 추가로 설치하지 않아요. (전체 실행 흐름은 `README.ko.md`와 `USE-WITH-AI.md`를 보세요.)

저장소를 통째로 내려받아 쓰고 싶다면 이렇게 해도 똑같이 동작해요.
```bash
git clone https://github.com/shinnanchanguk/dorms-check.git
node dorms-check/bin/dcheck.js detect
```

## 쓰는 AI에 연결하기

### Claude Code 스킬로 등록 (선택)
이 폴더를 Claude Code 스킬로 등록해두면, "내 앱 점검해줘"라고 말할 때 Claude가 자동으로 이 안내를 따라가요. 심볼릭 링크 한 번이면 돼요.

```bash
ln -s ~/dorms-check ~/.claude/skills/dorms-check
```

등록해두면 `SKILL.md`의 절차대로 알아서 진행해요. 등록하지 않아도 위 `npx` 명령을 직접 부르면 똑같이 동작해요.

### Cursor·Codex·Gemini 등 다른 AI
따로 등록할 게 없어요. 이 폴더의 `AGENTS.md`를 대부분의 AI 코딩 도구가 자동으로 읽어 같은 절차를 따라요. 자동으로 읽지 않는 도구라면 `USE-WITH-AI.md`의 프롬프트를 복사해 붙여넣으면 돼요. 어떤 AI를 쓰든 판정 결과는 같아요. 판정은 AI의 판단이 아니라 프로그램이 실제로 실행한 검사 결과이기 때문이에요.

## 선택: 강화 도구 (semgrep·gitleaks)
`semgrep`이나 `gitleaks`가 컴퓨터에 깔려 있으면 코드 심화 검사를 더 돌려 촘촘히 봐요. 하지만 없어도 괜찮아요. **마크 판정(통과 기준)은 이 도구들이 있든 없든 똑같아요.** 결정적 검사(헤더·SSL·노출·CORS·RLS 실측)만으로 판정하기 때문이에요.

설치는 선택이고, 필요하면 이렇게 깔 수 있어요.
```bash
brew install semgrep gitleaks   # macOS 예시
```

## 필요 환경
- Node.js 18 이상 (내장 fetch·tls를 써요). 추가 설치 의존성 없음.
- 검사할 앱은 배포된 주소(https://...)가 있으면 좋아요. 배포 전이면 `scan --code-only`로 코드만 먼저 볼 수 있어요.

## 명령어 요약

점검은 세 축으로 나뉘어요: `security`(보안 점검) · `edzip`(학운위·개인정보 준비) · `protection`(내 앱 비법·저작권 보호).
보안·학운위는 검사만 하고 파일을 바꾸지 않아요. 보호 축의 적용 단계만, 계획을 보고 동의했을 때(계획 해시 + `--confirm-apply`) 파일을 바꿔요. 자동 배포는 하지 않아요.

| 명령 | 하는 일 |
| --- | --- |
| `dcheck detect` | 스택을 감지해요 (Next.js·Vite·정적, Supabase 여부, 빌드 산출물) |
| `dcheck init --name --url --track security,edzip,protection --confirm-ownership` | 설정을 만들어요 (본인 앱만 검사한다는 동의 포함) |
| `dcheck scan --url <주소> [--code-only]` | 결정적 검사를 돌려요 (외부 표면 + RLS 실측 + 코드 정적 검사 + 보호 상태) |
| `dcheck judge --in <answers.json>` | AI가 판단한 항목을 증거와 함께 기록해요 (증거 없는 통과는 거부) |
| `dcheck interview [--answers <파일>]` | 권리·허용범위 설문 문항을 보여주고, 답으로 권리 프로필을 만들어요 |
| `dcheck protect plan` | 무엇을 바꿀지 계획과 계획 해시를 만들어요 (아직 파일 안 바꿈) |
| `dcheck protect apply --plan-sha256 <값> --confirm-apply` | 동의한 계획대로만 적용해요 (적용 전 백업, 실패 시 복원) |
| `dcheck protect restore` | 마지막 백업으로 되돌려요 |
| `dcheck verify` | 적용 전후 산출물을 비교해 앱이 깨지지 않았는지 확인해요 |
| `dcheck status` | 아직 못 고친 항목과 고치는 법을 보여줘요 |
| `dcheck report` | 전체 리포트를 출력해요 (`.dorms-check/REPORT.md`) |
| `dcheck submit` | 다 통과하면 증빙팩을 만들고 마크 신청 방법을 안내해요 |

> `dcheck`는 `npx -y github:shinnanchanguk/dorms-check`의 짧은 표기예요. 위 표의 `dcheck` 자리에 `npx -y github:shinnanchanguk/dorms-check`를 넣어 실행하면 돼요.
