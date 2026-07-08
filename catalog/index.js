// 카탈로그 로더 — 항목 id → 메타(심각도·설명·수정프롬프트) SSOT.
import { SECURITY_ITEMS } from './security.js';
import { EDZIP_ITEMS, EDZIP_CASE_QUESTIONS, EDZIP_LEGAL_BASIS } from './edzip.js';

const byId = new Map();
for (const it of SECURITY_ITEMS) byId.set(it.id, { ...it, track: 'security' });
for (const it of EDZIP_ITEMS) byId.set(it.id, { ...it, track: 'edzip' });

export function catalogItem(id) {
  return byId.get(id) || null;
}
export function allItems() {
  return [...byId.values()];
}
export function trackItems(track) {
  return [...byId.values()].filter(i => i.track === track);
}
export { SECURITY_ITEMS, EDZIP_ITEMS, EDZIP_CASE_QUESTIONS, EDZIP_LEGAL_BASIS };

// 심각도 순위(정렬·게이트용)
export const SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
