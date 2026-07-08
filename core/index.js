// dorms-check 공개 라이브러리 면.
// 도름스 서버(Next.js)가 이 패키지를 import 해 '같은 코드·같은 항목 ID'로 재검증한다.
// 서버는 SSRF 방어 fetch 를 opts.fetchImpl 로 주입한다.
//
// 중요: 마크 발급 게이트는 오직 서버가 실행한 이 결정적 검사 결과다.
// 스킬(CLI)이 만든 report.json 은 참고이고 발급 근거가 아니다.
import { runExternalScan } from '../checks/external/index.js';
import { runRuntimeProbe } from '../checks/runtime/index.js';

export { runExternalScan, runRuntimeProbe };
// 서버(도름스)가 마크 게이트에 쓰는 같은 채점·카탈로그(로직 표류 방지).
export { scoreSecurity, scoreEdzip } from './score.js';
export { catalogItem, allItems, trackItems, SEVERITY_RANK } from '../catalog/index.js';

// 서버 권위 검증: 외부 표면 + 능동 런타임 프로브를 한 번에 실행해 결정적 관측값을 반환.
// 반환 items 의 id 는 CLI 코치와 동일 네임스페이스(로직 표류 방지).
export async function runServerVerification(url, opts = {}) {
  const external = await runExternalScan(url, opts);
  if (!external.reachable) {
    return { reachable: false, error: external.error, items: external.items, raw: external.raw };
  }
  const runtime = await runRuntimeProbe(url, opts);
  return {
    reachable: true,
    items: [...external.items, ...runtime.items],
    bonus: external.bonus,
    raw: { ...external.raw, runtime: true },
    verifiedAt: new Date().toISOString(),
  };
}

// 서버가 스킬 self-report 와 자기 관측을 대조해 mismatch 를 찾는 헬퍼.
// claimedItems: [{id, status}] (스킬 제출), observedItems: 서버 실측.
// 반환: 서버가 fail 인데 스킬이 pass 라 주장한 항목(위조 신호).
export function findMismatches(claimedItems, observedItems) {
  const claimed = new Map((claimedItems || []).map(i => [i.id, i.status]));
  const out = [];
  for (const obs of observedItems || []) {
    const c = claimed.get(obs.id);
    if (c && c === 'pass' && obs.status === 'fail') {
      out.push({ id: obs.id, claimed: c, observed: obs.status, detail: obs.observed });
    }
  }
  return out;
}
