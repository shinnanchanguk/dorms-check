---
name: edzip-autopilot
description: 교사가 만든 웹·PWA·모바일·Tauri·Electron 앱의 에듀집 제출·통과를 준비하고, 확인 완료 뒤 기존 제출 서류와 승인 주소를 바탕으로 내부 기안문·학교운영위원회 안건문 HWPX를 프로젝트에 맞춰 작성한다. 외부 제출은 하지 않는다.
---

# 에듀집 통과 준비와 승인 뒤 학교 서류 자율 작성

이 스킬은 `dorms-check` 설치 패키지 안의 자동화를 사용한다. 현재 프로젝트 루트에서 실행한다.

## 안전 경계

- 이름·학교·연락처·서명·인영은 질문하거나 JSON으로 저장하지 않는다. 생성물의 검색 가능한 빈칸으로 남긴다.
- 외부 제출, 서명, 인영, 배포는 하지 않는다.
- 코드·정책·문서 변경은 사용자가 읽은 계획 SHA-256과 `--confirm-apply`가 모두 맞을 때만 한다. 범위가 바뀌면 새 계획을 만든다.
- 1단계의 목적은 에듀집 제출·통과 준비다. 에듀집 확인 완료 뒤에만 2단계 학교 내부 기안·학운위 안건 작성을 시작한다.
- 생성된 학교 서류는 검토용 초안이다. 내부 결재·학운위 심의·최종 선정은 학교가 한다.

## 진행

1. `npx -y github:shinnanchanguk/dorms-check edzip prepare`로 코드·스택·개인정보 방침 표면을 읽은 계획을 만든다. 아직 파일을 바꾸지 않는다.
2. CLI가 출력한 5가지 비개인정보 질문을 1∼3개씩 쉽게 묻고, 답을 프로젝트 안 임시 JSON에 `yes|no|unknown`으로만 저장한다.
3. `.dorms-check/edzip-plan.json`을 읽고 변경 파일·이유·위험·복원 방법을 한 화면에 알린 뒤 해시 승인을 받는다.
4. 승인 후에만 프로젝트 코드의 실제 데이터 흐름을 다시 읽고, 방침과 동작이 다른 부분을 최소 범위로 보완한다. 특히 공개 `/privacy` 표면, 최소 수집, 보유·파기, 제3자 제공, 위탁·국외 이전, 아동 동의, 접근통제를 코드 근거로 맞춘다.
5. `npx -y github:shinnanchanguk/dorms-check edzip prepare --apply --plan-sha256 "<해시>" --confirm-apply --answers <JSON>`로 `.dorms-check/private/edzip/YYYY-MM-DD/`에 개인정보처리방침·필수기준 자가점검표·에듀집 제품 설명자료·제출 안내를 HWPX·PDF·Markdown으로 만든다. 적용 대상이 아닐 가능성이 크면 근거를 보여 주고 중단한다. 사용자가 자발적 계속을 원할 때만 `--continue-out-of-scope`를 추가한다.
6. `manifest.json`의 파일 해시, 출처 접속 상태, `piiStored:false`, `automaticSubmission:false`를 확인한다. HWPX는 `skills/hwpx-edit/SKILL.md`의 검증을 따른다. 한글에서 표 칸의 글자가 겹쳐 보이면 원본 복사본을 먼저 남기고, 문서 전체를 드래그하거나 Ctrl+A로 선택해 복사한 뒤 새 빈 한글 문서에 붙여넣으면 줄 배치가 다시 계산된다고 반드시 안내한다. 붙여넣은 문서는 표와 쪽 나눔을 확인하고 새 이름으로 저장하게 한다.
7. 에듀집 구글폼 제출 뒤에는 접수 결과나 보완 연락을 기다리게 한다. 며칠이 지나도 결과나 연락이 없으면 KERIS 한국교육학술정보원 교수학습지원부 `053-714-0357`, `053-714-0308`로 접수 여부와 진행 상태를 문의해 보라고 반드시 안내한다. 번호의 공식 출처는 `edzip.registration-notice`다.
8. 에듀집 제출 뒤 확인 완료를 기다린다. 사용자가 공식 제품 주소를 주면 `npx -y github:shinnanchanguk/dorms-check edzip council --approved-url "<공식 주소>" --confirm-apply`를 실행한다. 도구가 `api.edzip.kr`의 고정 조회 주소에서 공개·확인 완료와 제품명 일치를 검증하며, 응답의 이메일·전화번호는 저장하거나 출력하지 않는다.
9. 2단계는 에듀집에 냈던 01·02·03 서류와 승인 주소를 붙임으로 연결해 `05-internal-approval-draft`, `06-council-agenda-draft`, `07-school-submission-guide`를 HWPX·PDF·Markdown으로 만든다. 결과에는 빈 내부 기안 HWPX 양식도 포함한다.
10. 완료 보고에 생성 경로와 04·05·06·07 문서의 Ctrl+F 검색어를 적고, 학교명·수신자·결재선·기안자·작성일·회의 회차는 학교가 직접 채워야 한다고 안내한다. 공식 구글폼·에듀집·법제처 직링크와 KERIS·운영센터 문의처, 구글폼 제출 뒤 연락이 없을 때의 KERIS 문의 방법, 한글 표 글자 겹침 대처법도 빠뜨리지 않는다.

자세한 공식 출처는 `catalog/edzip-sources.js`, 양식 원본과 가이드는 `assets/forms/`·`assets/sources/`에 있다. 내부 기안 원본은 `assets/templates/school-internal-approval.md`이고, 편집 가능한 빈 한글 문서는 `assets/forms/school-internal-approval-blank.hwpx`다.
