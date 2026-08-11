// 카탈로그 로더 — 항목 id → 메타(심각도·설명·수정프롬프트) SSOT.
// 실제 인덱스·조회는 트랙 레지스트리(core/tracks.js)가 소유한다.
// 이 파일은 기존 import 표면(도름스 서버·core/index.js)을 위한 얇은 재수출 층이다.
export { catalogItem, allItems, trackItems, SEVERITY_RANK } from '../core/tracks.js';
export { SECURITY_ITEMS } from './security.js';
export { EDZIP_ITEMS, EDZIP_CASE_QUESTIONS, EDZIP_LEGAL_BASIS } from './edzip.js';
