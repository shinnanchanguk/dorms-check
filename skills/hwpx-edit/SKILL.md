---
name: hwpx-edit
description: dorms-check가 생성한 학운위·에듀집 HWPX 문서를 편집·검증할 때 사용한다. 구 HWP 원본은 편집하지 않고 근거용으로만 유지한다.
---

# dorms-check HWPX 편집

- `*.hwpx`는 ZIP+OWPML 문서다. `mimetype`은 첫 항목, 무압축, `application/hwp+zip`이어야 한다.
- `assets/forms/*.hwp`는 에듀집 공식 구형 원본이다. HWP 바이너리를 직접 편집하지 말고, 자동 생성된 HWPX를 제출본으로 쓴다.
- 변경 후 ZIP CRC, 중복·상위 경로, DTD·ENTITY, 외부 관계, 매크로·OLE·ActiveX 포함 여부를 검사한다.
- 사용자가 직접 채울 곳은 문서에 실제로 있는 `[작성자가 ... 입력하세요]` 검색어로 남긴다. 검색어 출현 횟수를 세고 1회가 아니면 더 긴 문구로 안내한다.
- 생성된 HWPX를 다시 읽어 표·문단·링크·개인정보 빈칸이 있는지 확인한다. 같은 본문의 PDF·Markdown과 필수 항목을 대조한다.
- Windows 한글 실기기 경로가 없으면 구조 검증까지 하고 “Windows 한글 확인 전”으로 보고한다.
