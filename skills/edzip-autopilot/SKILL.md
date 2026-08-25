---
name: edzip-autopilot
description: 교사가 만든 웹·PWA·모바일·Tauri·Electron 앱의 학교운영위원회 심의와 에듀집 등록을 준비할 때 프로젝트를 진단하고 보완한 뒤 HWPX·PDF 서류 패와 법령·제출 경로·KERIS 문의처를 준비한다. 학교 내부 의결서 작성이나 자동 제출에는 사용하지 않는다.
---

# 학운위·에듀집 자율주행

이 스킬은 `dorms-check` 설치 패키지 안의 자동화를 사용한다. 현재 프로젝트 루트에서 실행한다.

## 안전 경계

- 이름·학교·연락처·서명·인영은 질문하거나 JSON으로 저장하지 않는다. 생성물의 검색 가능한 빈칸으로 남긴다.
- 외부 제출, 서명, 인영, 배포는 하지 않는다.
- 코드·정책·문서 변경은 사용자가 읽은 계획 SHA-256과 `--confirm-apply`가 모두 맞을 때만 한다. 범위가 바뀌면 새 계획을 만든다.
- “준비 완료”는 심의 서류가 갖춰졌다는 뜻이며 심의 통과나 에듀집 확인완료를 보장하지 않는다.

## 진행

1. `npx -y github:shinnanchanguk/dorms-check edzip prepare`로 코드·스택·개인정보 방침 표면을 읽은 계획을 만든다. 아직 파일을 바꾸지 않는다.
2. CLI가 출력한 5가지 비개인정보 질문을 1∼3개씩 쉽게 묻고, 답을 프로젝트 안 임시 JSON에 `yes|no|unknown`으로만 저장한다.
3. `.dorms-check/edzip-plan.json`을 읽고 변경 파일·이유·위험·복원 방법을 한 화면에 알린 뒤 해시 승인을 받는다.
4. 승인 후에만 프로젝트 코드의 실제 데이터 흐름을 다시 읽고, 방침과 동작이 다른 부분을 최소 범위로 보완한다. 특히 공개 `/privacy` 표면, 최소 수집, 보유·파기, 제3자 제공, 위탁·국외 이전, 아동 동의, 접근통제를 코드 근거로 맞춘다.
5. `npx -y github:shinnanchanguk/dorms-check edzip prepare --apply --plan-sha256 "<해시>" --confirm-apply --answers <JSON>`로 `.dorms-check/private/edzip/YYYY-MM-DD/`에 HWPX·PDF·Markdown 패를 만든다. 적용 대상이 아닐 가능성이 크면 근거를 보여 주고 중단한다. 사용자가 자발적 계속을 원할 때만 `--continue-out-of-scope`를 추가한다.
6. `manifest.json`의 파일 해시, 출처 접속 상태, `piiStored:false`, `automaticSubmission:false`를 확인한다. HWPX는 `skills/hwpx-edit/SKILL.md`의 검증을 따른다.
7. 완료 보고에 생성 경로와 `04-submission-guide.hwpx`의 Ctrl+F 검색어를 적고, 공식 구글폼·에듀집·법제처 직링크와 KERIS·운영센터 문의처를 알린다.

자세한 공식 출처는 `catalog/edzip-sources.js`, 양식 원본과 가이드는 `assets/forms/`·`assets/sources/`에 있다.
