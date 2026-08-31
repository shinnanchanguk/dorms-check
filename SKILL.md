---
name: dorms-check
description: 교사 제작 앱을 보안·에듀집·지식재산권 세 축으로 점검하고, 에듀집 제출·통과 자료와 승인 뒤 내부 기안문·학운위 안건 HWPX까지 프로젝트에 맞춰 준비하는 코치. 트리거는 보안 검토, 개인정보 점검, 학운위 심의 준비, 에듀집 등록, 도름스 인증마크, 저작권 보호, dorms-check다. 파일 적용은 승인된 계획과 명시적 확인이 있을 때만 하고 자동 제출·배포는 하지 않는다.
---

# dorms-check (교사 앱 점검 코치: 보안 · 에듀집 · 내 앱 보호)

교사가 "내가 만든 앱 안전한지 봐줘 / 인증마크 받고 싶어 / 내 앱 비법을 지키고 싶어"라고 하면, **그 앱 프로젝트 폴더에서** 이 스킬을 따라 점검한다. 이 도구는 의존성 0의 Node CLI(`dcheck`)이며, AI(당신)는 이 CLI를 호출하는 코치로 동작한다.

## 0. 가장 먼저: 정직한 기대치 (반드시 교사에게 먼저 전달)
- **마크의 입구는 도름스의 &lsquo;마크 신청&rsquo; 버튼이다.** 교사가 도름스(dorms.school)에 올린(또는 올릴) 앱에서 신청을 누르면, 도름스 서버가 공개된 앱 주소를 직접 검사해 통과하면 그 자리에서 마크를 발급한다. **이 도구(dorms-check)는 신청했을 때 아직 통과하지 못한 항목을 고칠 때 쓰는 도우미**다. 그러니 아래 절차(detect/scan/status/judge)는 교사에게 "고칠 때 쓰는 법"으로 안내한다: 먼저 도름스에서 신청하게 하고, 고칠 항목이 나오면 이 도구로 검사·수정한 뒤 다시 신청하게 한다. (교사가 아직 앱을 올리기 전이면, 도름스의 &lsquo;미리 인증받기&rsquo;로 공개 주소를 미리 확인받아 둘 수도 있다.)
- **세 축의 역할**: security 스캔은 검사만 한다. edzip 서류 생성과 protection 적용은 사용자가 승인한 계획 해시와 `--confirm-apply`가 맞을 때만 파일을 바꾼다. 코드 보완은 교사의 AI가 계획 범위 안에서 하고, 자동 제출·배포는 하지 않는다.
- **최종 인증마크는 도름스 서버가 스스로 다시 검증해 발급한다.** 이 도구의 통과는 "신청 준비가 됐다"는 뜻일 뿐, 마크를 보장하지 않는다.
- **판정은 모델의 추측이 아니라 실제로 실행한 검사 결과다.** 헤더·SSL·노출 경로·CORS는 라이브 응답을 관측하고, RLS(데이터 접근)는 공개 anon 키로 실제 미인증 요청을 보내 행이 새는지 실측하고, 보호 상태(배포물 시크릿·소스맵·안내 파일)는 빌드 산출물을 직접 검사한다. 그래서 "대충 통과"가 안 된다.
- **"보장·통과 약속·완전 보호" 같은 말을 쓰지 않는다.** 난독화·Base64 는 비밀이 아니고, 브라우저로 전달된 것은 공개로 가정한다. 보호 상태는 여섯 가지로만 말한다: 서버 분리 확인 / 일부 서버 분리 / 공개 자산 / 복제 비용 상승 조치 / 권리·이용 안내 설정 / 권리관계 확인 필요.

> 설치는 따로 필요 없다. **깃허브 소스에서 바로 받아 실행한다**(Node 18+): `npx -y github:shinnanchanguk/dorms-check`.
> 이 도구는 npm 레지스트리에 올리지 않는다. 손볼 때마다 다시 올려야 해서 금방 옛 판이 되기 때문이다. 깃허브 주소로 실행하면 언제 실행해도 저장소의 최신 판이 그대로 돈다. `npx -y dorms-check@latest` 류의 npm 이름으로는 받아지지 않으니 쓰지 않는다.

## 1. 고칠 때 쓰는 법 (평가 → 수정 지시 → 재검 완주 루프)
1. **설치 확인·감지**: `npx -y github:shinnanchanguk/dorms-check detect` — 스택(Next.js/Vite/정적)·Supabase 여부·빌드 산출물 확인.
2. **설정**: `npx -y github:shinnanchanguk/dorms-check init --name "<앱이름>" --url "<배포 주소>" --track security,edzip,protection --confirm-ownership` — 본인이 만들고 운영하는 앱만 스캔한다는 동의 포함. 학운위(에듀집) 트랙이면 케이스 진단 3문항을 교사에게 물어 `dorms-check.config.json`의 `edzipCase`에 A/B/C/D로 적는다.
3. **스캔**: `npx -y github:shinnanchanguk/dorms-check scan --url "<배포 주소>"` — 결정적 스캐너(외부 표면 + RLS 실측) + 로컬 코드 정적 검사 + 보호 상태 검사를 돌린다. 결과는 `.dorms-check/REPORT.md`·`scan.json`에 저장된다. 배포 전이면 `--code-only`. **먼저 파일을 바꾸지 말고 스캔부터.**
4. **에듀집 통과 준비와 승인 뒤 학교 서류 작성**: `skills/edzip-autopilot/SKILL.md`를 읽고 `edzip prepare`의 계획→비개인정보 5문항→해시 승인→코드 보완→에듀집 제출 HWPX·PDF 생성 순서를 따른다. 확인 완료 뒤에는 공식 주소를 검증하고 `edzip council`로 내부 기안문·학운위 안건문을 만든다.
4. **권리 설문(protection 트랙)**: `interview` 로 문항 JSON 을 받아, 교사에게 **쉬운 선택지로 1~3문항씩** 물어본다(권리자·학교 관여·기존 라이선스·AI 기여·제3자 자산·허용 범위). 답을 JSON 파일로 모아 `interview --answers <파일>` 을 실행하면 권리 프로필(`.dorms-check/rights-profile.json`)이 생성된다. **프로필에 비공개 프롬프트 원문·민감 파일명을 넣지 않는다(이름만).**
5. **AI 판단(ai-review 항목)**: 스캔이 "AI가 판단해야 할 항목"을 알려주면(예: `code.endpoint.unauth`, `protection.boundary.server`, 에듀집 방침 의미 판단), 당신이 코드·개인정보처리방침을 **직접 읽고** 판정한다. `judge --in answers.json`으로 기록한다. 형식:
   ```json
   { "edzip.5-3": { "status": "pass", "evidence": "방침 제6조에 Supabase(AWS 서울) 위탁 명시 — src/app/privacy/page.tsx:42" } }
   ```
   **증거(파일:라인 또는 실측 요약) 없는 pass 는 CLI 가 거부한다.** 서술만으로 통과시키지 마라. 보호 트랙의 결정적 항목(배포물 시크릿·소스맵 등)은 judge 로 덮을 수 없다(스캔이 우선).
6. **보호 계획·적용(protection 트랙)**: `protect plan` 으로 계획(서버로 옮길 비법 후보·바꿀 파일·위험·복원 방법)을 만들어 교사에게 **한 화면으로 보여주고 동의를 받는다**. 동의하면 그때만 `protect apply --plan-sha256 <계획해시> --confirm-apply` 로 적용한다(적용 전 백업, 실패 시 자동 복원). 적용 후 `verify` 로 깨짐을 확인하고, 문제가 있으면 `protect restore` 로 되돌린다. **재배포는 교사가 따로 승인할 때만 한다.** 비법을 서버로 옮기는 코드 수정은 이 도구가 아니라 당신이 교사 동의 하에 한다.
7. **수정 지시**: `npx -y github:shinnanchanguk/dorms-check status` 로 남은 항목과 각 항목의 "AI에게 시킬 수정 프롬프트"를 본다. 교사에게 무엇을·왜 고치는지 쉬운 말로 설명하고, 교사 동의 하에 **교사 앱 코드를 당신이 수정**한다(이 스킬은 관여 안 함). 고친 뒤 재배포.
8. **재검 루프**: 3~7을 반복한다. 설정한 트랙이 모두 통과할 때까지. `scan`은 멱등이고 `status`는 남은 것만 보여준다.
9. **증빙팩·신청**: 통과하면 `npx -y github:shinnanchanguk/dorms-check submit` — 증빙팩(`report.json`·`REPORT.md`)을 만들고 도름스 마크 신청 방법을 안내한다. protection 트랙이 포함되면 v2 페이로드로 만들어지며 **시크릿·개인 경로가 자동으로 가려진다(redact)**. 마지막에 비밀 원문이 빠진 권리 프로필과 이용 안내가 남는다.
10. **학운위 마크가 "개인정보처리방침 필수 항목이 확인되지 않는다"로 막히면**: 도름스는 앱 주소를 바깥에서 열어 방침 글자를 읽는다. 방침을 별도 주소 없이 **앱 안 팝업으로만** 띄우는 한 장짜리 앱(React·Vite 등)은 바깥에서 빈 껍데기만 보여, 방침이 멀쩡히 있어도 못 읽힐 수 있다(이 도구는 소스를 읽으니 "이상 없음"이라 갈린다). 교사에게 둘 중 하나를 안내한다. ① 방침을 `/privacy` 같은 주소로도 열리게 두기(권장, 이후 자동으로 확인됨) ② `submit` 이 만든 `.dorms-check/evidence/report.json` 을 신청 화면의 "dorms-check 결과 올리기"에 올리기(도름스가 이 리포트의 `edzip.*` 판정을 대체 근거로 인정). **추측하지 말고 실제로 방침 주소를 열어 확인한 뒤 어느 쪽인지 판단한다.**

## 2. 세 트랙
- **도름스 보안 체크리스트 충족(security)**: 보안 헤더·전송 보안·정보 유출·CORS·RLS(익명 접근)·코드 시크릿. 마크 자격 = 심각(critical)·높음(high) 항목이 0. 점수(0~100)·등급(A~F)은 참고로 함께 보여준다.
- **에듀집 제출·통과 준비(edzip)**: 에듀집 필수기준 5대 영역 9개 항목 + 개인정보처리방침 공개. 1단계는 에듀집 제출 자료를 만들고, 2단계는 확인 완료 주소와 기존 제출 서류를 근거로 내부 기안문·학운위 안건문을 만든다.
- **내 앱 보호(protection)**: 권리관계 확인(설문) · 비법 경계(배포물 시크릿·프롬프트·모델파일·서버 분리) · 배포 위생(소스맵·디버그·경로·소스 분리·지문) · 안내와 증거(사람용·기계용 고지·증거팩). 점수가 아니라 **6가지 상태**로 현재 위치를 보여준다.

## 3. 항상 지킬 것
- **비파괴 스캔**: 읽기(GET·SELECT)만. 익스플로잇·데이터 변경·퍼징 없음. 본인 앱만.
- **파일 변경은 protection apply 뿐**: 승인한 계획 해시 + `--confirm-apply` 없이는 어떤 파일도 바꾸지 않는다. 적용 전 백업, 실패 시 복원. 자동 배포 금지.
- **결정적 우선**: 프로그램이 실측할 수 있는 건 프로그램이 판정한다. 당신의 판단이 필요한 항목만 판단하되, 반드시 코드를 읽고 증거를 남긴다.
- **정직한 한계**: 외부 스캔은 라이브 URL에서 보이는 것만 본다. 내부 설정·WAF는 코드 점검으로 보완한다. 최종 마크는 도름스 서버가 재검증한다. "완전 보호"는 존재하지 않는다.
- 사용자 노출 설명은 비개발자(교사)가 이해하는 쉬운 말로. 개발 용어를 그대로 쓰지 않는다.

상세: `README.ko.md` · 설치: `SETUP.md` · 한계·윤리: `DISCLAIMER.md` · 복붙 프롬프트: `USE-WITH-AI.md`

## 4. 사용자가 strict Vercel 배포 게이트를 요청한 경우

먼저 `docs/STRICT-SECURITY-GATE.ko.md`를 끝까지 읽는다. 일반 점검과 달리 검토 완료 커밋 SHA와 `vercel@59.10.0`을 훅 설치 전에 고정하고, clean Git code strict, 현재 호스트의 전역 훅 상태 확인, 두 Git metadata를 literal로 넣은 단일 staged `vercel` 명령, stdout의 정확한 URL live strict, `gate verify`, 같은 literal URL/ID의 단일 promote 순서를 지킨다. 운영체제와 셸은 직접 감지하고 명령도 직접 실행한다. 사용자는 로그인, 훅 신뢰, 모르는 변경 확인만 한다.

비대화형 staged에는 `--yes`를 붙입니다. macOS/Linux/WSL은 literal `vercel`을 쓰고, native Windows PowerShell은 훅 설치가 `Get-Command`로 backing CLI를 검증·고정한 뒤 제공하는 status의 exact `windowsVercelExecutable` 관리형 proxy를 `& '<exact vercel.cmd>' <literal args>`로 씁니다. 변수, splatting, backtick, wrapper, 복합 명령은 차단합니다.

결정적 검사 누락을 통과로 추정하지 않는다. `SECURITY_BLOCKED`, `INCOMPLETE`, `BINDING_MISMATCH`, `RECEIPT_INVALID`를 `judge`나 설명으로 덮지 않는다. 훅 설치는 자동 배포 권한이 아니며, 사용자가 배포를 명시적으로 요청한 범위에서만 staged production과 promote를 실행한다. Vercel production 변경에 wrapper, 변수, 스크립트, 복합 명령, source/artifact/project override를 쓰지 않는다. command substitution, caret/backtick, runtime·package·workspace·task launcher도 strict 훅이 보수적으로 막는다는 점을 숨기지 않는다. 검증된 staged와 promote 외 모든 Vercel 쓰기는 자동 실행하지 않고 명시적 list/inspect/status/get/help/version/whoami 조회만 허용한다. code 영수증 뒤 `.vercel/project.json`, Git 배포 입력, 허용된 `.dorms-check` 상태 digest를 바꾸지 않는다. `VERCEL_PROJECT_ID`·`VERCEL_ORG_ID`·`VERCEL_TEAM_ID`는 링크와 정확히 같아야 하고 token/scope/config ambient override는 쓰지 않는다. Windows와 WSL은 각각 확인하고, 사용자 지정 config root와 절대 Node 실행 파일을 확인했더라도 훅 파일 configured만으로 활성화라고 하지 않는다. 실제 호스트 활성화는 재시작·신뢰·안전한 차단 challenge 전까지 unknown으로 보고한다.
