// HTML 후처리 헬퍼 (의존성 0, ai-clone-shield core/html.js 흡수 — ESM 변환).
// 어떤 스택이든 빌드 산출물 HTML 에 안전하게 주입하기 위한 공통 함수.
// 흡수하지 않은 것: 제로폭(ZWC) 워터마크 인코딩 — 편집·재작성으로 쉽게 사라지는 것을
// 증거처럼 표현하는 기능이라 정직성 원칙에 따라 폐기했다.

// 주의: replace 의 2번째 인자를 "문자열"로 주면 snippet 안의 $&, $$, $`, $1 등이
// 치환 특수패턴으로 해석돼 주입 HTML 이 깨진다. 반드시 콜백(함수)으로 넘긴다.
export function insertInHead(html, snippet) {
  if (/<\/head>/i.test(html)) return html.replace(/<\/head>/i, () => snippet + '\n</head>');
  if (/<head[^>]*>/i.test(html)) return html.replace(/<head[^>]*>/i, m => m + '\n' + snippet);
  if (/<html[^>]*>/i.test(html)) return html.replace(/<html[^>]*>/i, m => m + '\n<head>\n' + snippet + '\n</head>');
  return snippet + '\n' + html;
}

export function insertBeforeBodyClose(html, snippet) {
  if (/<\/body>/i.test(html)) return html.replace(/<\/body>/i, () => snippet + '\n</body>');
  if (/<\/html>/i.test(html)) return html.replace(/<\/html>/i, () => snippet + '\n</html>');
  return html + '\n' + snippet;
}

export function hasMarker(html, marker) { return html.indexOf(marker) !== -1; }

// HTML 주석 안에 안전하게 넣기 위해 주석 종료 시퀀스를 무력화
export function escapeForComment(s) {
  return String(s).replace(/--+/g, '-').replace(/>/g, ')');
}

export function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function fill(tpl, vars) {
  return tpl.replace(/\{(\w+)\}/g, (m, k) => (vars[k] !== undefined && vars[k] !== null ? String(vars[k]) : ''));
}
