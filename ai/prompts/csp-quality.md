# ai-review 지시문: CSP 품질 (sec.header.csp)

## 무엇을 확인하나요
Content-Security-Policy 헤더의 **존재 여부는 스캐너가 결정적으로 판정**합니다(`checks/external/headers.js`가 라이브 응답 헤더를 직접 관측). 이 지시문은 그 위에서 **품질**을 봐요. CSP가 있어도 `'unsafe-inline'`·`'unsafe-eval'`을 남용하면 XSS 방어가 사실상 무력해지기 때문이에요. 헤더가 "있다"는 것과 "실제로 보호한다"는 것은 다릅니다.

## 어디를 봐야 하나요
- 라이브 응답 헤더를 직접 관측합니다: `curl -sI https://<앱주소> | grep -i content-security-policy` (또는 `.dorms-check/scan.json`의 `sec.header.csp` `evidence.value`).
- 코드에서 CSP를 만드는 곳: Next.js면 `middleware.ts`·`next.config.js`의 `headers()`, 정적 앱이면 호스팅 설정(`vercel.json` 등).
- `script-src`(또는 `default-src`)에 `'unsafe-inline'`·`'unsafe-eval'`·와일드카드(`*`)가 있는지, 인라인 스크립트를 nonce·hash로 허용하는지 봅니다.

## pass / fail / na 판정 기준
- **fail**: CSP가 있지만 `script-src`(또는 `default-src`)에 `'unsafe-inline'`이나 `'unsafe-eval'`이 nonce·hash 없이 들어가 있거나, `script-src *`처럼 아무 출처나 허용해 XSS 방어가 무력화됩니다.
- **pass**: CSP가 있고 스크립트 출처가 `'self'`·특정 도메인·nonce·hash로 제한됩니다. `'unsafe-inline'`이 스타일(`style-src`)에만 쓰이는 정도는 허용할 수 있으나, 스크립트에 대한 남용은 없습니다.
- **na**: 스크립트를 전혀 쓰지 않는 순수 정적 문서처럼 품질 판단이 의미 없는 드문 경우. 헤더 자체가 아예 없으면 na가 아니라 스캐너가 이미 fail로 잡으니, 이 지시문은 헤더가 있을 때 품질을 봅니다.

## 증거 남기기 (증거 없는 pass 금지)
실제로 관측한 CSP 문자열을 근거로 남기세요. 예:
- `curl -sI https://myapp.com | grep -i content-security → default-src 'self'; script-src 'self' 'nonce-...'; object-src 'none' (unsafe-inline 없음)`
- `middleware.ts:20, nonce 방식으로 인라인 스크립트 허용, unsafe-eval 없음`

## 결과 기록
`answers.json`에 아래 형식으로 적고 `dcheck judge --in answers.json`으로 병합하세요. 품질에 문제가 있으면 `status`를 `fail`로 적어, 헤더 존재만으로 통과되지 않게 하세요.
```json
{ "sec.header.csp": { "status": "pass", "evidence": "라이브 CSP: script-src 'self' 'nonce-..'; unsafe-inline/eval 없음 (curl -sI 관측)" } }
```
