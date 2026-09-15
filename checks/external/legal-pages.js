// 법적 표면: 개인정보처리방침·이용약관·연락처 페이지 존재 확인.
// 홈 HTML의 링크 + 흔한 경로 프로빙. 존재 여부는 결정적, '내용 충족'은 AI(ai-review)로.
import { probePath } from '../../core/http.js';

const POLICY_HINTS = /개인정보|처리방침|privacy/i;
const TERMS_HINTS = /이용약관|약관|terms/i;
const CONTACT_HINTS = /연락처|문의|contact|이메일|@/i;
const POLICY_PATHS = ['/privacy', '/policy', '/개인정보처리방침', '/privacy-policy'];
const TERMS_PATHS = ['/terms', '/약관', '/terms-of-service'];

function linkTexts(body) {
  const out = [];
  const re = /<a\b[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let m;
  while ((m = re.exec(body)) && out.length < 500) {
    out.push({ href: m[1], text: m[2].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim() });
  }
  return out;
}

async function findPage(url, body, hints, paths, req) {
  const links = linkTexts(body);
  const hit = links.find(l => hints.test(l.text) || hints.test(l.href));
  if (hit) return { found: true, via: 'link', where: hit.href };
  for (const p of paths) {
    const r = await probePath(url, p, { req });
    if (r.status >= 200 && r.status < 400) return { found: true, via: 'path', where: p, status: r.status };
  }
  return { found: false };
}

export async function checkLegalPages(mainRes, url, req) {
  const body = mainRes.body || '';
  const results = [];

  const policy = await findPage(url, body, POLICY_HINTS, POLICY_PATHS, req);
  results.push({
    id: 'legal.privacy-policy',
    status: policy.found ? 'pass' : 'unknown',
    observed: policy.found ? `개인정보처리방침 발견(${policy.via}: ${policy.where})` : '받은 HTML과 확인한 주소에서 방침을 찾지 못했습니다. 앱 안 팝업이나 로그인 뒤 화면은 확인하지 않았습니다.',
    evidence: policy,
  });

  const terms = await findPage(url, body, TERMS_HINTS, TERMS_PATHS, req);
  results.push({
    id: 'legal.terms',
    status: terms.found ? 'pass' : 'info',
    observed: terms.found ? `이용약관 발견(${terms.via}: ${terms.where})` : '이용약관 페이지/링크 없음',
    evidence: terms,
  });

  const contact = CONTACT_HINTS.test(body);
  results.push({
    id: 'legal.contact',
    status: contact ? 'pass' : 'info',
    observed: contact ? '연락처/문의 정보 있음' : '연락처/문의 정보 안 보임',
    evidence: { found: contact },
  });

  return results;
}
