// 정보 유출: 민감 파일 정적 노출 + 소스맵 + 스택트레이스 + mixed content.
// .env 오탐 수정: HTTP 200 여부가 아니라 '본문 시그니처'로 판정한다.
// (SPA fallback 은 모든 경로에 200+HTML 을 주므로 200 만으로는 못 가른다.)
import { probePath } from '../../core/http.js';

const SECRET_PATHS = ['/.env', '/.env.local', '/.env.production', '/.git/config', '/.git/HEAD'];
const CONFIG_PATHS = ['/next.config.js', '/vercel.json', '/.npmrc'];

// 본문이 진짜 그 파일인지 시그니처로 확인.
function looksLikeEnv(body) {
  if (!body) return false;
  const lines = body.split(/\r?\n/).filter(Boolean).slice(0, 40);
  const kv = lines.filter(l => /^[A-Z0-9_]{2,}=/.test(l.trim()));
  return kv.length >= 2; // KEY=value 라인이 2개 이상이면 진짜 .env
}
function looksLikeGitConfig(body) {
  return !!body && /\[core\]|\[remote\b|\[branch\b/.test(body);
}
function looksLikeGitHead(body) {
  return !!body && /^ref:\s+refs\//.test(body.trim());
}
function looksLikeHtml(body) {
  return !!body && /<!doctype html|<html[\s>]/i.test(body.slice(0, 500));
}

export async function checkExposure(mainRes, url, request) {
  const results = [];

  // 시크릿 경로 노출 — 단일 집계 항목(info.secret-exposed). 본문 시그니처로 진짜 노출만 판정.
  const probed = [];
  const exposedPaths = [];
  for (const p of SECRET_PATHS) {
    const r = await probePath(url, p, { req: request });
    let exposed = false;
    if (r.status === 200 && !looksLikeHtml(r.body)) {
      if (p.startsWith('/.env')) exposed = looksLikeEnv(r.body);
      else if (p === '/.git/config') exposed = looksLikeGitConfig(r.body);
      else if (p === '/.git/HEAD') exposed = looksLikeGitHead(r.body);
      else exposed = r.body.length > 0;
    }
    probed.push({ path: p, httpStatus: r.status, exposed });
    if (exposed) exposedPaths.push(p);
  }
  results.push({
    id: 'info.secret-exposed',
    status: exposedPaths.length ? 'fail' : 'pass',
    observed: exposedPaths.length
      ? `민감 파일 노출 확인(본문 시그니처 일치): ${exposedPaths.join(', ')}`
      : '민감 파일(.env/.git) 노출 없음',
    evidence: { probed, exposedPaths },
  });

  // 설정 파일 노출(민감도 낮음, medium)
  const configExposed = [];
  for (const p of CONFIG_PATHS) {
    const r = await probePath(url, p, { req: request });
    if (r.status === 200 && !looksLikeHtml(r.body) && r.body.length > 0) configExposed.push(p);
  }
  results.push({
    id: 'info.config-exposed',
    status: configExposed.length ? 'fail' : 'pass',
    observed: configExposed.length ? `설정 파일 노출: ${configExposed.join(', ')}` : '설정 파일 비노출',
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
