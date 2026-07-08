# ai-review 지시문: 미인증 접근·권한 우회(IDOR) (code.endpoint.unauth)

## 무엇을 확인하나요
두 가지를 봅니다.
1. **미인증 접근**: 로그인 없이 호출해도 민감한 데이터를 돌려주는 API가 있는지.
2. **IDOR(권한 우회)**: 로그인은 했더라도 요청의 id·번호를 남의 것으로 바꾸면 다른 사용자의 데이터에 접근할 수 있는지.

런타임 프로브(`checks/runtime/endpoint-auth.js`)는 내부 API 경로를 미인증으로 호출해 "데이터를 주는 후보"만 찾는 보조 신호예요. 공개 API도 200을 주므로 결정적이지 않습니다. 실제 판정은 당신이 코드를 읽고 해야 합니다.

## 어디를 봐야 하나요
- API 라우트: `app/api/**/route.ts`, `pages/api/**`, 서버 액션, Edge Function 등.
- 각 핸들러가 시작에서 세션·권한을 확인하는지(`auth()`·`getUser()`·토큰 검증). 확인 없이 바로 DB를 조회·반환하면 위험합니다.
- **IDOR 초점**: 조회 쿼리가 요청 파라미터의 id를 그대로 `where id = <param>`으로 쓰면서, "그 리소스가 지금 로그인한 사용자의 것인지"를 함께 검사하는지 봅니다. 소유자 확인(`where user_id = auth.uid()` 등)이 없으면 IDOR입니다.
- 스캔 결과 `.dorms-check/scan.json`의 `code.endpoint.unauth` `evidence.openCandidates`를 출발점으로 삼되, 그 경로가 정말 개인정보를 주는지 코드로 확인합니다.

## pass / fail / na 판정 기준
- **fail**: 민감 데이터를 주는 API에 인증 확인이 없거나, 소유자 확인 없이 파라미터 id만으로 남의 데이터에 접근할 수 있습니다(IDOR).
- **pass**: 민감 데이터를 다루는 모든 경로가 인증을 확인하고, 리소스 접근 시 소유자·권한을 함께 검사합니다. 미인증으로 열린 경로는 개인정보가 없는 공개 데이터만 반환합니다.
- **na**: 내부 API가 없는 정적 앱이거나 개인화된 데이터를 다루지 않습니다.

## 증거 남기기 (증거 없는 pass 금지)
`파일:라인` 또는 실측 커맨드와 출력으로 남기세요. 예:
- `app/api/notes/[id]/route.ts:12, getUser() 후 where user_id=uid 로 소유자 확인(IDOR 방지)`
- 실측: `미인증 GET /api/notes → 401`, `로그인 후 남의 id 조회 → 403`

## 결과 기록
`answers.json`에 아래 형식으로 적고 `dcheck judge --in answers.json`으로 병합하세요.
```json
{ "code.endpoint.unauth": { "status": "pass", "evidence": "app/api/notes/[id]/route.ts:12 소유자 확인 있음, 미인증 401, 타 사용자 id 403" } }
```
