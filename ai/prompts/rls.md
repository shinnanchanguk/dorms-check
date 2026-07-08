# ai-review 지시문: 데이터 접근(RLS) 정합성 (code.rls.anon-read)

## 무엇을 확인하나요
런타임 프로브(`checks/runtime/rls-probe.js`)가 이미 공개 anon 키로 실제 미인증 SELECT를 보내 "익명 사용자가 개인정보 행을 읽을 수 있는지"를 실측합니다. 그 실측이 이 항목의 1차 판정이며 권위를 가집니다. 이 지시문은 코드(RLS 정책)를 읽어 실측을 보강하는 역할이에요. 런타임 프로브가 닿지 못한 부분(로그인해야 보이는 테이블, 쓰기 정책, 서버 전용 키 사용)을 코드에서 확인해 정책 정합성을 판단하세요.

## 어디를 봐야 하나요
- Supabase 마이그레이션·SQL: `supabase/migrations/*.sql`, 프로젝트의 `*.sql`에서 `enable row level security`, `create policy` 문을 찾습니다.
- 개인정보가 담긴 테이블(users·profiles·students·messages 등)에 RLS가 켜져 있는지, 정책이 `auth.uid()` 등으로 본인·권한자만 읽도록 제한하는지 확인합니다.
- 클라이언트 코드에 `service_role` 키가 브라우저로 내려가지 않는지(`checks/static/client-bundle.js`의 신호와 함께) 확인합니다.
- 스캔 결과 `.dorms-check/scan.json`의 `code.rls.anon-read` 항목 `evidence`(readableTables·piiLeaks·swaggerStatus)를 근거로 봅니다.

## pass / fail / na 판정 기준
- **fail**: 런타임 프로브가 개인정보 컬럼 유출을 실측했거나(이 경우 그대로 fail 확정), 코드에서 개인정보 테이블에 RLS가 꺼져 있거나 정책이 익명 읽기를 허용합니다. **실측된 유출을 코드 리뷰만으로 pass로 뒤집지 마세요.**
- **pass**: 런타임 프로브가 유출 없음으로 나오고, 코드에서도 개인정보 테이블에 RLS가 켜져 있으며 정책이 본인·권한자만 읽도록 제한합니다.
- **na**: Supabase를 쓰지 않는 앱이거나 데이터베이스에 개인정보 테이블이 없습니다(공개 콘텐츠만 다루는 정적 앱 등).

## 증거 남기기 (증거 없는 pass 금지)
`파일:라인` 또는 실제로 실행한 커맨드와 그 출력으로 남기세요. 예:
- `supabase/migrations/0002_rls.sql:14, profiles·messages 테이블 enable RLS + auth.uid() 본인만 select 정책 확인`
- 실측 요약: `anon 키로 /rest/v1/profiles SELECT 요청 → 401 (rls-probe 결과와 일치)`

## 결과 기록
`answers.json`에 아래 형식으로 적고 `dcheck judge --in answers.json`으로 병합하세요.
```json
{ "code.rls.anon-read": { "status": "pass", "evidence": "supabase/migrations/0002_rls.sql:14 profiles·messages RLS 켬 + auth.uid() 정책, 런타임 프로브 유출 0" } }
```
