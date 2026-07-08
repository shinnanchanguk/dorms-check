// 로컬 코드 정적 검사 오케스트레이터(코치 층). 결정적 grep 결과를 파일:라인 증거로.
import { checkSecrets } from './secrets.js';
import { checkClientBundle } from './client-bundle.js';
import { checkHeadersConfig } from './headers-config.js';
import { checkDangerous } from './dangerous.js';

export function runStaticScan(root) {
  const items = [];
  try { items.push(...checkSecrets(root)); } catch { /* skip */ }
  try { items.push(...checkClientBundle(root)); } catch { /* skip */ }
  try { items.push(...checkHeadersConfig(root)); } catch { /* skip */ }
  try { items.push(...checkDangerous(root)); } catch { /* skip */ }
  return { items };
}
