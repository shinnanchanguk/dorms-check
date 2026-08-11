// 점수·등급·마크 게이트 계산 — 구현은 트랙 레지스트리(core/tracks.js)에 있다.
// 마크 게이트(이진) = 점수와 분리. "완전히 안전" = critical/high 0 (점수 100 아님).
// 이 파일은 기존 import 표면(도름스 서버·self-test)을 위한 얇은 재수출 층이다.
export { scoreSecurity, scoreEdzip } from './tracks.js';
