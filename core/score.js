// 점수·등급·마크 게이트 계산.
// 마크 게이트(이진) = 점수와 분리. "완전히 안전" = critical/high 0 (점수 100 아님).
import { catalogItem } from '../catalog/index.js';

function grade(score) {
  if (score >= 97) return 'A+';
  if (score >= 93) return 'A';
  if (score >= 90) return 'A-';
  if (score >= 87) return 'B+';
  if (score >= 83) return 'B';
  if (score >= 80) return 'B-';
  if (score >= 75) return 'C+';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

// results: [{id, status, observed, evidence}], bonus: [{id, points}]
export function scoreSecurity(results, bonus = []) {
  let score = 100;
  const failing = [];
  const failingBySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const r of results) {
    const cat = catalogItem(r.id);
    if (!cat || cat.track !== 'security') continue;
    if (r.status === 'fail') {
      score -= cat.weight || 0;
      failingBySeverity[cat.severity] = (failingBySeverity[cat.severity] || 0) + 1;
      if (cat.gate) failing.push({ id: r.id, severity: cat.severity, title: cat.title });
    }
  }
  for (const b of bonus) score += b.points || 0;
  score = Math.max(0, Math.min(100, score));

  // 마크 게이트: gate 항목 중 critical/high fail 이 0 이어야 자격.
  const blockingFails = failing.filter(f => f.severity === 'critical' || f.severity === 'high');
  return {
    score,
    grade: grade(score),
    eligible: blockingFails.length === 0,
    blockingFails,
    failingBySeverity,
  };
}

// edzip: gate 항목 전부 pass/na 이고 개인정보처리방침(legal.privacy-policy)이 존재해야 자격.
export function scoreEdzip(results) {
  const map = new Map(results.map(r => [r.id, r.status]));
  const unmet = [];
  for (const r of results) {
    const cat = catalogItem(r.id);
    if (!cat || cat.track !== 'edzip' || !cat.gate) continue;
    if (r.status !== 'pass' && r.status !== 'na') unmet.push({ id: r.id, title: cat.title, severity: cat.severity });
  }
  const policyPresent = map.get('legal.privacy-policy') === 'pass';
  return {
    eligible: unmet.length === 0 && policyPresent,
    unmet,
    policyPresent,
  };
}
