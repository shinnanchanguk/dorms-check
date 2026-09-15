// Public exposure requires an actual credential or high-confidence private data.
import { probePath } from '../../core/http.js';
import { classifySensitiveExposure } from '../../core/minimum-policy.js';
const SECRET_PATHS = ['/.env', '/.env.local', '/.env.production', '/.git/config', '/.git/HEAD'];
const CONFIG_PATHS = ['/next.config.js', '/vercel.json', '/.npmrc'];
function looksLikeHtml(body) {
  return !!body && /<!doctype html|<html[\s>]/i.test(body.slice(0, 500));
}
export async function checkExposure(mainRes, url, request) {
  const results = [];
  const probed = [];
  const exposedPaths = [];
  const configExposed = [];
  const mainExposure = classifySensitiveExposure(mainRes.body || '', { path: new URL(mainRes.finalUrl || url).pathname });
  if (mainExposure.confirmed) exposedPaths.push(new URL(mainRes.finalUrl || url).pathname);
  let kind = mainExposure.kind;
  let incomplete = false;
  for (const p of [...SECRET_PATHS, ...CONFIG_PATHS]) {
    const r = await probePath(url, p, { req: request });
    const available = r.status >= 200 && r.status < 300;
    const exposure = available ? classifySensitiveExposure(r.body, { path: p }) : { confirmed: false };
    const failed = !r.status || r.status >= 500 || r.status === 429;
    incomplete ||= failed;
    probed.push({ path: p, httpStatus: r.status, exposed: exposure.confirmed, checked: !failed });
    if (exposure.confirmed) { exposedPaths.push(p); kind ||= exposure.kind; }
    else if (available && r.body && !looksLikeHtml(r.body)) configExposed.push(p);
  }
  const base = new URL(mainRes.finalUrl || url);
  const scripts = [...(mainRes.body || '').matchAll(/<script\b[^>]*src=["']([^"']+)["']/gi)].slice(0, 6);
  for (const match of scripts) {
    let script;
    try { script = new URL(match[1], base); } catch { continue; }
    if (script.origin !== base.origin) continue;
    const r = await request(script.href, { method: 'GET', redirect: 'follow', maxBody: 2 * 1024 * 1024 });
    const checked = r.status >= 200 && r.status < 300;
    const exposure = checked ? classifySensitiveExposure(r.body, { path: script.pathname }) : { confirmed: false };
    incomplete ||= !checked;
    probed.push({ path: script.pathname, httpStatus: r.status, exposed: exposure.confirmed, checked });
    if (exposure.confirmed) { exposedPaths.push(script.pathname); kind ||= exposure.kind; }
  }
  const confirmed = exposedPaths.length > 0;
  results.push({
    id: 'info.secret-exposed', status: confirmed ? 'fail' : (incomplete ? 'unknown' : 'pass'),
    observed: confirmed ? `비공개 인증정보 또는 민감 자료 노출 확인: ${exposedPaths.join(', ')}`
      : (incomplete ? '받은 본문에서 민감정보가 확인되지 않았습니다. 일부 추가 경로는 확인하지 못했습니다.' : '확인한 본문과 경로에서 비공개 인증정보가 발견되지 않았습니다.'),
    evidence: { probed, exposedPaths, mainBodyChecked: true, confirmedSensitiveExposure: confirmed, ...(kind ? { kind } : {}) },
  });
  results.push({
    id: 'info.config-exposed', status: configExposed.length ? 'info' : (incomplete ? 'unknown' : 'pass'),
    observed: configExposed.length ? `공개된 설정 형태의 자료가 있습니다. 공개 의도를 확인해 주세요: ${configExposed.join(', ')}` : '추가로 확인된 설정 자료가 없습니다.',
    evidence: { exposed: configExposed },
  });

  // 소스맵 노출: 메인 응답에 sourceMappingURL 흔적 or /_next 소스맵 200
  const body = mainRes.body || '';
  const hasSourceMapRef = /\/\/[#@]\s*sourceMappingURL=/.test(body);
  results.push({
    id: 'info.source-map',
    status: hasSourceMapRef ? 'fail' : 'pass',
    observed: hasSourceMapRef ? '페이지에 sourceMappingURL 노출' : '소스맵 참조 없음',
    evidence: { sourceMappingURL: hasSourceMapRef },
  });

  // 스택트레이스 흔적(에러 페이지가 내부 경로 노출)
  const stackHit = /at\s+\/(?:Users|home|var|app)\/|\.(?:tsx?|jsx?):\d+:\d+|Traceback \(most recent/.test(body);
  results.push({
    id: 'info.stack-trace',
    status: stackHit ? 'fail' : 'pass',
    observed: stackHit ? '응답에 내부 경로/스택트레이스 흔적' : '스택트레이스 노출 없음',
    evidence: { stackTrace: stackHit },
  });

  // mixed content: https 페이지가 http:// 리소스 참조
  const isHttps = (mainRes.finalUrl || url).startsWith('https://');
  const mixed = isHttps && /(?:src|href)=["']http:\/\//i.test(body);
  results.push({
    id: 'info.mixed-content',
    status: mixed ? 'fail' : 'pass',
    observed: mixed ? 'https 페이지에 http 리소스 참조(mixed content)' : 'mixed content 없음',
    evidence: { mixedContent: mixed },
  });

  return results;
}
