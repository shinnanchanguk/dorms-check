# dorms-check

[English](./README.md) | 한국어

**교사가 바이브코딩으로 만든 앱을 스스로 점검하고, 완전히 안전해질 때까지 자기 AI와 함께 고치는 점검 코치.**

바이브코딩(AI로 코드를 만드는 방식)으로 앱을 만든 선생님이, 개발을 몰라도 자기 앱을 세 축으로 점검하고 고칠 수 있게 돕습니다.
- **보안 점검(security)**: 내 앱이 해킹·정보 유출에 안전한지
- **학운위·개인정보 준비(edzip)**: 학교 심의에 낼 개인정보 서류가 갖춰졌는지
- **내 앱 비법·저작권 보호(protection)**: 내 앱의 비법(프롬프트·로직·데이터)과 권리를 지킬 준비가 됐는지

보안·학운위 축을 통과하면 도름스 커뮤니티의 인증마크를 받을 수 있습니다.

## 마크는 어디서 받나요 (먼저 읽어주세요)
**인증마크는 이 도구가 아니라 도름스에서 받습니다.** 도름스에 올린(또는 올릴) 내 앱에서 &lsquo;마크 신청&rsquo; 버튼을 누르면, 도름스가 공개된 앱 주소를 직접 확인해 통과하면 그 자리에서 마크를 발급합니다. **이 도구(dorms-check)는 신청했을 때 아직 통과하지 못한 항목을 고칠 때 쓰는 도우미**입니다. 설치할 필요 없이, 쓰던 AI에 프롬프트를 붙여넣으면 AI가 알아서 검사하고 고쳐줍니다.

> 흐름: **도름스에서 신청 → 통과하면 바로 마크 / 부족하면 고칠 항목 안내 → (고칠 때) dorms-check로 검사·수정 → 다시 신청.**

## 정직한 한 줄
이 도구는 인증을 발급하지 않습니다. 무엇이 안전하고 무엇을 고쳐야 하는지 알려주는 **코치**입니다. 최종 인증마크는 도름스 서버가 **스스로 다시 검증**해 발급하며, 이 도구의 통과가 마크를 보장하지 않습니다.

**파일 변경 원칙**: 보안 스캔은 검사만 합니다. 학운위 서류 생성(`edzip prepare --apply`)과 내 앱 보호(`protect apply`)는 사용자가 읽고 승인한 계획 해시(`--plan-sha256`)와 `--confirm-apply`가 함께 있을 때만 실행합니다. 자동 제출·배포는 하지 않습니다.

## 고칠 때 쓰는 법
신청했을 때 고칠 항목이 나오면, 쓰고 있는 AI(Claude Code·Cursor 등)에 [`USE-WITH-AI.md`](./USE-WITH-AI.md)의 프롬프트를 붙여넣으세요. 따로 설치할 건 없고 **이 깃허브 저장소에서 바로 최신판이 실행**돼요. npm 에는 올리지 않습니다(올린 판은 소스를 손볼 때마다 다시 올려야 해서 금방 옛것이 돼요). 그래서 패키지 이름 대신 아래처럼 `github:` 주소를 씁니다. 또는 직접:
```bash
npx -y github:shinnanchanguk/dorms-check detect
npx -y github:shinnanchanguk/dorms-check init --name "내 앱" --url "https://내앱주소" --track security,edzip,protection --confirm-ownership
npx -y github:shinnanchanguk/dorms-check scan --url "https://내앱주소"
npx -y github:shinnanchanguk/dorms-check edzip prepare  # 학운위·에듀집 계획과 5가지 확인
npx -y github:shinnanchanguk/dorms-check status     # 남은 항목 + 고치는 법
npx -y github:shinnanchanguk/dorms-check submit      # 다 통과하면 증빙팩 + 신청 안내
```

## 어떤 축을 점검할지 고르기
세 축은 서로 독립입니다. 원하는 축만 골라 점검할 수 있고, 고른 축만 검사·판정합니다(나머지 축은 아예 돌지 않습니다).
- **security**: 보안 점검(헤더·SSL·노출·CORS·RLS 실측). 도름스 "보안 검토" 마크만 원하면 이 축 하나면 됩니다.
- **edzip**: 학운위·개인정보 준비(에듀집 필수기준 + 개인정보처리방침). 학교 심의에 낼 서류가 필요할 때만 고르세요.
- **protection**: 내 앱 비법·저작권 보호(권리 확인·서버 분리·고지·증거). 내 아이디어를 지키고 싶을 때만 고르세요.

`--track` 에 쉼표로 원하는 축만 넣으면 그 부분집합만 돌아갑니다.
```bash
# 보안 마크만 원하면 보안 축만(3번째 보호 축은 할 필요 없습니다)
npx -y github:shinnanchanguk/dorms-check init --name "내 앱" --track security --confirm-ownership

# 보안 + 보호만
npx -y github:shinnanchanguk/dorms-check init --name "내 앱" --track security,protection --confirm-ownership

# 세 축 전부
npx -y github:shinnanchanguk/dorms-check init --name "내 앱" --track security,edzip,protection --confirm-ownership
```
사람이 터미널에서 `--track` 없이 `init` 을 실행하면, 세 축을 보여주고 원하는 것만 고르라고 물어봅니다(번호나 이름을 쉼표로, 예: `1,3` 또는 `security,protection`). AI 가 파이프로 자동 실행할 때(비대화형)는 묻지 않고 `--track` 값을, 없으면 기본값(security)을 그대로 씁니다.

## 무엇을 점검하나

### 축 1: 보안 점검 (security)
- **보안 응답 헤더** 6종(CSP·HSTS·클릭재킹 방어·nosniff·Referrer·Permissions)
- **전송 보안**(HTTPS 강제·SSL 인증서·구버전 TLS·쿠키 플래그)
- **정보 유출**(.env·.git 노출·소스맵·스택트레이스·mixed content). 진짜 노출만 잡습니다(SPA 오탐 방지).
- **CORS**(임의 사이트 허용·인증정보 노출)
- **데이터 접근(RLS)**: 공개 anon 키로 **실제 미인증 요청을 보내** 익명이 개인정보를 읽을 수 있는지 실측(비파괴 SELECT)
- **코드 시크릿**(하드코딩 키·클라이언트 노출)
- 점수(0~100)·등급(A~F)은 참고로 함께. 마크 자격 = 심각·높음 항목 0.

### 축 2: 학운위·개인정보 준비 (edzip)
에듀집 「학습지원 소프트웨어 필수기준 체크리스트」 5대기준 9세부와 개인정보처리방침 공개 상태를 점검합니다. `edzip prepare`는 프로젝트를 분석한 계획과 해시를 만듭니다. 승인 후에는 `.dorms-check/private/edzip/YYYY-MM-DD/`에 개인정보처리방침, 필수기준 자가점검표, 학운위 제공자 자료, 에듀집 제출 안내를 HWPX·PDF·Markdown으로 저장합니다. 양식 HWP 원본, 교육부 가이드라인, 법제처 직링크, 교사 개인 구글폼, KERIS·에듀집 문의처도 포함합니다.

### 축 3: 내 앱 비법·저작권 보호 (protection)
- **권리관계 확인**: 누가 만든 앱인지, 학교 업무와 관련 있는지, 남의 재료·AI 기여는 어떤지(쉬운 설문 → 권리 프로필 생성. 비밀 원문은 넣지 않음)
- **비법 경계**: 배포물에 비밀 키·프롬프트·모델 파일이 새는지, 핵심 로직이 서버 뒤에 있는지
- **배포 위생**: 소스맵·디버그 흔적·내 컴퓨터 경로·소스 원본이 배포물에 남았는지, 산출물 지문(해시) 기록
- **안내와 증거**: 사람용 권리 안내, 기계용 안내(robots.txt AI 수집기 차단·llms.txt·TDM 예약), 증거팩(해시·git 기록, 시점 증명은 선택)
- 판정은 점수가 아니라 **여섯 가지 상태**입니다: 서버 분리 확인 / 일부 서버 분리 / 공개 자산 / 복제 비용 상승 조치 / 권리·이용 안내 설정 / 권리관계 확인 필요.
- **정직한 전제**: 난독화·Base64 는 비밀이 아니고, 브라우저로 전달된 것은 공개로 가정합니다. "완전 보호"는 없습니다.
- 적용 절차: `interview`(권리 설문) → `protect plan`(계획+해시) → 동의 후 `protect apply --plan-sha256 <값> --confirm-apply`(백업 후 적용) → `verify`(깨짐 확인) → 문제 시 `protect restore`(복원).

## 왜 "대충 통과"가 안 되나 (할루시네이션 방지)
성능이 낮은 AI가 "문제 없다"고 착각해도, 판정은 모델의 말이 아니라 **프로그램이 실제로 실행한 검사 결과**입니다. 특히 데이터 접근(RLS)은 실제로 익명 요청을 보내 확인합니다. 그리고 최종 마크는 **도름스 서버가 앱을 스스로 다시 검사**해 통과할 때만 발급됩니다. 자세한 한계·윤리는 [`DISCLAIMER.md`](./DISCLAIMER.md).

## 필요 환경
- Node.js 18 이상. 설치 시 HWPX·PDF 생성 엔진과 한글 글꼴이 함께 포함됩니다.
- 선택: semgrep·gitleaks 등이 설치돼 있으면 심화 검사를 보태지만, 없어도 마크 판정은 동일하게 됩니다.

## 라이선스
MIT
