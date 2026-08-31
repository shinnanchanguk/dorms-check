# AI에게 복붙하기 (교사용)

> **마크는 이 프롬프트가 아니라 도름스에서 받아요.** 도름스에 올린(또는 올릴) 내 앱에서 &lsquo;마크 신청&rsquo; 버튼을 누르면 도름스가 공개된 앱 주소를 직접 확인해서, 통과하면 그 자리에서 마크가 붙어요. **이 도구(dorms-check)는 신청했을 때 아직 통과하지 못한 항목을 고칠 때 쓰는 도우미**예요. 고칠 항목이 나왔을 때 아래 프롬프트를 쓰던 AI에 붙여넣어 고친 뒤, 도름스에서 다시 신청하면 마크가 붙어요.
>
> 흐름: **도름스에서 신청 → 통과하면 바로 마크 / 부족하면 고칠 항목 안내 → (고칠 때) 이 프롬프트로 검사·수정 → 다시 신청.**

만든 앱 폴더를 열어둔 상태에서, 쓰고 있는 AI(Claude Code·Cursor·ChatGPT 등)에게 아래를 그대로 붙여넣으세요. 개발을 몰라도 됩니다. AI가 검사하고, 무엇을 왜 고쳐야 하는지 쉬운 말로 알려주고, 당신 동의 하에 고쳐줍니다.

> 따로 설치할 필요가 없어요. 아래 명령이 **깃허브 소스에서 최신판을 바로 받아 실행**해요(Node.js 18 이상만 있으면 돼요). 이 도구는 npm 에 올리지 않으니 `dorms-check@latest` 같은 이름 말고 아래 깃허브 주소 그대로 쓰세요.

---

이 프로젝트의 보안, 에듀집 제출·통과 준비, 그리고 내 앱의 비법과 저작권 보호 상태를 dorms-check 의 세 축(security 보안 점검, edzip 에듀집 준비와 승인 뒤 학교 서류, protection 내 앱 보호)으로 점검해줘. 이 도구는 npm 에 올라와 있지 않으니 아래처럼 깃허브 주소(github.com/shinnanchanguk/dorms-check)에서 바로 받아 실행해줘. 따로 설치할 건 없어. (너는 코드를 고치는 코치이고, 마크는 도름스에서 신청하면 도름스가 다시 확인해 발급한다는 점만 기억해줘.)

1. **먼저 파일을 바꾸지 말고 스캔부터 해줘.** `npx -y github:shinnanchanguk/dorms-check detect` 로 스택을 확인하고, `npx -y github:shinnanchanguk/dorms-check init --name "내 앱 이름" --url "내 배포 주소" --track security,edzip,protection --confirm-ownership` 로 설정을 만든 다음, `npx -y github:shinnanchanguk/dorms-check scan --url "내 배포 주소"` 로 검사해줘.
2. **먼저 에듀집 통과 준비를 시작해줘.** `npx -y github:shinnanchanguk/dorms-check edzip prepare`로 계획과 해시를 만든 뒤, 도구가 보여 주는 개인정보가 아닌 다섯 질문만 나에게 1~3개씩 물어봐줘. 계획을 보여 주고 내가 승인한 뒤에만 `edzip prepare --apply --plan-sha256 <계획 해시> --confirm-apply --answers <답변 파일>`을 실행해줘. 개인정보처리방침, 필수기준 자가점검표, 에듀집 제품 설명자료와 제출 안내를 HWPX·PDF·Markdown으로 만들고 공식 HWP 원본, 법령 원문 링크, 구글폼 제출 경로, KERIS 담당자 연락처를 함께 정리해줘. 구글폼 제출 뒤 며칠이 지나도 결과나 연락이 없으면 KERIS 한국교육학술정보원 교수학습지원부(053-714-0357, 053-714-0308)로 접수 여부와 진행 상태를 문의해 보라고 꼭 말해줘. 한글에서 표 칸의 글자가 겹쳐 보이면 문서 전체를 드래그해 복사한 다음, 전체가 선택된 그 상태에서 바로 붙여넣으면 해결된다고 안내해줘. 자동 제출은 하지 마.
3. **에듀집 확인이 끝났다면 학교 서류까지 작성해줘.** 나에게 에듀집 확인 완료 제품 주소만 받아 `npx -y github:shinnanchanguk/dorms-check edzip council --approved-url "<공식 에듀집 주소>" --confirm-apply`를 실행해줘. 공식 API에서 공개·확인 완료와 제품명 일치를 검증하고, 에듀집에 냈던 서류와 승인 주소를 붙임으로 연결한 내부 기안문, 학운위 안건문, 학교 제출 안내를 내 프로젝트 정보에 맞춰 HWPX·PDF·Markdown으로 작성해줘. 성명·학교·전화·결재선·서명은 받거나 저장하지 말고 Ctrl+F 검색어와 채울 위치를 알려줘. 내부 결재나 학운위 제출은 자동으로 하지 마.
3. **권리와 허용 범위는 나한테 쉬운 선택지로 1~3문항씩 물어봐줘.** `npx -y github:shinnanchanguk/dorms-check interview` 의 문항을 그대로 어려운 말 없이 물어보고 답을 모아 권리 프로필을 만들어줘.
4. 검사가 "AI가 판단해야 할 항목"을 남기면 내 코드와 개인정보처리방침을 직접 읽고 `judge` 로 증거와 함께 판정해줘. 증거 없이 통과 처리하지 마.
5. **내 앱을 지키는 계획을 한 번에 보여줘.** `protect plan`으로 계획을 보여 주고 내가 동의한 뒤에만 `protect apply --plan-sha256 <계획 해시> --confirm-apply`로 적용해줘.
6. **적용한 뒤에는 `verify`로 앱이 깨지지 않았는지 확인하고 문제가 있으면 `protect restore`로 되돌려줘.** 배포는 내가 따로 승인할 때만 해줘.
7. `status`로 남은 항목을 보고 쉬운 말로 설명한 다음 내 동의를 받고 코드를 고쳐줘.
8. 다 통과하면 `submit`으로 증빙팩을 만들어줘. 비밀 원문이 들어가지 않은 보호 프로필과 이용 안내가 남아야 해.

일반 스캔은 읽기 검사만 하고 내 앱만 검사해. 파일 생성·수정은 학운위 서류 준비와 protection 적용에서 내가 계획에 동의했을 때만 해. "대충 통과"시키지 말고 실제로 확인된 것만 통과로 처리해줘. "완전 보호" 같은 말은 쓰지 말아줘.

---

이게 전부입니다. 붙여넣고 AI가 안내하는 대로 따라가면 됩니다.

## Vercel 배포 전 보안 검사만 강제하기

아래 프롬프트는 일반 세 축 완주가 아니라 `security`만 검사하고, 검사하지 않은 production 배포를 세 AI CLI에서 막을 때 씁니다. 교육 자료에 적힌 **검토 완료 dorms-check 커밋 SHA로 고정된 실행 명령**을 함께 붙여넣으세요. 기본 브랜치 최신판으로 바꾸지 마세요.

---

현재 앱 폴더에서 dorms-check strict 보안 게이트를 설치하고, staged production을 검사한 뒤 같은 배포만 Vercel production에 연결해줘. 먼저 운영체제, 현재 셸, Git 루트, Node, Git, Vercel CLI 로그인과 프로젝트 연결 상태를 스스로 확인해. 사용자인 나에게 터미널 명령을 입력시키지 말고 네가 직접 실행해. 내가 직접 해야 하는 일은 웹 또는 CLI 로그인, Codex `/hooks`의 훅 신뢰, 네가 소유자를 판단할 수 없는 기존 변경 확인뿐이야.

교육 자료가 준 정확한 dorms-check 커밋 SHA를 끝까지 고정해서 사용하고 임의로 최신판으로 바꾸지 마. `detect`와 `init --name "내 앱" --track security --confirm-ownership`을 실행해. 배포할 코드와 설정을 확인하고 작업트리를 깨끗한 커밋으로 만든 뒤 현재 HEAD를 직접 읽어 `scan --track security --strict --json --code-only --git-sha <현재 HEAD>`를 실행해. 모르는 기존 변경은 임의로 커밋하지 말고 그때만 나에게 물어봐.

그다음 `hooks install --global --agents codex,claude,gemini --provider vercel --security-only`와 `hooks status --agents codex,claude,gemini --json`을 실행해. Codex `~/.codex/config.toml`, Claude `~/.claude/settings.json`, Gemini `~/.gemini/settings.json`의 기존 설정을 보존해야 해. 현재 세션에서 새 훅을 불러오기 위해 재시작이나 신뢰 확인이 필요하면 그 한 동작만 쉬운 말로 알려줘.

code strict가 PASS이고 영수증이 유효할 때만 `vercel --prod --skip-domain`을 실행해. stdout의 정확한 Deployment URL을 네가 캡처해. 그 URL 하나를 `--url`과 `--vercel-deployment`에 똑같이 넣어 `scan --track security --strict --json --url <정확한 URL> --git-sha <같은 HEAD> --vercel-deployment <정확한 URL>`을 실행해. 이어서 `gate verify --git-sha <같은 HEAD> --vercel-deployment <정확한 URL> --url <정확한 URL> --json`을 실행해. 모두 PASS일 때만 `vercel promote <정확한 URL>`을 실행해.

종료 코드 0만 PASS야. 1은 확인된 보안 결함, 2는 사용법 또는 설정 오류, 3은 필수 검사 미완료, 4는 Git/URL/배포 바인딩 불일치, 5는 영수증 없음/만료/무결성 오류야. 1부터 5까지 어떤 결과도 설명이나 `judge`로 통과 처리하지 마. 문제를 고치면 새 커밋에서 code strict부터 다시 시작해. 영수증이 15분을 넘겼으면 다시 검사해.

직접 production 배포, `vercel alias set`, 다른 URL 또는 ID promote, Git push 기반 자동 production 배포로 우회하지 마. 마지막에는 Git SHA, code/live 상태, 검사한 정확한 Vercel URL과 ID, 영수증 만료 시각, 훅 상태를 표로 보여줘. dorms-check는 인증서가 아니고 도름스가 별도로 재검증한다는 한계도 한 줄로 알려줘.

---

## 학운위 마크가 "방침 필수 항목이 확인되지 않는다"고 나올 때

도름스는 앱 주소를 바깥에서 열어 개인정보처리방침 글자를 읽습니다. 그런데 방침을 **별도 주소 없이 앱 안 팝업으로만** 띄우는 앱(리액트·Vite 같은 한 장짜리 앱)은 바깥에서 받는 화면이 빈 껍데기라, 방침이 멀쩡히 있어도 글자가 안 보일 수 있어요. 이 도구로는 "이상 없음"인데 도름스에서만 막히는 경우가 이것입니다. 둘 중 하나로 풀면 됩니다.

1. **방침을 주소로도 열리게 만들기** (권장): `/privacy` 처럼 그 주소로 들어가면 방침 본문이 바로 보이게 두면, 도름스가 읽어서 바로 확인합니다.
2. **결과 파일 올리기**: `submit` 이 만든 `.dorms-check/evidence/report.json` 을 도름스 마크 신청 화면의 &lsquo;dorms-check 결과 올리기&rsquo;에 올리면, 이 도구가 소스를 읽어 판정한 학운위 항목을 도름스가 대체 근거로 인정합니다.
