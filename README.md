# dorms-check

English | [한국어](./README.ko.md)

A minimum inspection tool for teacher-built apps. It reports observed risks, recommendations, and checks it could not complete.

## Provenance notices (new)

`protect apply` now also plants the original creator's notice wherever a copier's AI reads: a small visible footer source line and an in-app usage page (`usage.html`), a `/*! ... */` header in built JS/CSS, an `AGENTS.md`/`CLAUDE.md` block between markers, `dorms.json`, and a permission-aware `llms.txt`. The notice follows the app's DoRms usage settings (strictest of modify / sourceReuse / redistribute; unset counts as "ask first") and cites Korean Copyright Act articles. It is a polite, factual request, not an enforcement mechanism. `dcheck protect compare --url <suspect>` records which of this app's markers and bundle fingerprints appear on a suspect public URL. 0.5.2 (from a member's hands-on review): notices are also written to `public/` and the source HTML (Vite `index.html`, CRA `public/index.html`, SvelteKit `src/app.html`) so they survive a server-side rebuild (Vercel, Netlify); the JS/CSS header is added to build output only and disappears on rebuild, so it is no longer described as surviving minification. `dcheck verify --url` and `scan --track protection --url` check the live site directly and mark records stale when the build changed after apply. A permissive LICENSE or `package.json` license (MIT, Apache, BSD, ISC, CC-BY, CC0) that conflicts with an ask-first usage scope is flagged and no longer counts as a rights notice. `protect compare` skips framework common chunks, reads up to 8 MB, keeps per-version fingerprints, sends a normal browser request and reports partial overlap. Added usage conditions that instruct an AI are dropped from the usage page (a word-list filter: it also catches indirect addressees such as "도우미"/"coding tool", install commands and home-folder or config exfiltration, but cannot catch every paraphrase). Follow-up review: a footer the layout check skips in the build is also skipped in the source HTML (so a rebuilt full-screen game does not get a line over its canvas); `protect compare` counts a generic dorms-check marker as this app's only when this app's id, DoRms URL or creator name appears with it (another teacher's dorms-check app is listed separately), and a file whose name only looks like a framework chunk is still compared for partial overlap (both ways). Limits: a copier who says "I have permission" cannot be verified, and a person can still strip the notices by hand. All user-facing copy lives in `templates/copy.ko.json`. This supersedes the ai-clone-shield skill. Feature catalogue: `docs/features.ko.json`.

## Inspection and app registration

DoRms app registration is independent from its inspection marks. An inaccessible internal database or an undiscovered privacy policy does not prevent registration.

The minimum security mark requires the DoRms server to inspect a successful public HTTPS response and its body, without finding a substantiated blocking risk. Login pages and single-page apps use the same rule. Coverage and unknown checks remain visible; the mark does not guarantee the security of the entire app.

Missing security headers, a public database response, or permissive CORS alone do not establish a vulnerability. Users do not need to move hosting providers or publish a policy in a prescribed HTML file. If the public response cannot be inspected, a new mark is withheld while app registration remains available.

Council document readiness and official EDZIP verification have separate outcomes. An unreadable policy only withholds council readiness. Official EDZIP verification still requires official evidence.

## Start

Use Node.js 18 or newer. These examples pin the `v0.5.5` GitHub release. If your organization reviewed a particular commit, keep using that commit instead.

~~~bash
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.5.5.tar.gz detect
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.5.5.tar.gz init --name "My App" --url "https://my-app.example" --track security --confirm-ownership
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.5.5.tar.gz scan --url "https://my-app.example"
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.5.5.tar.gz status
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.5.5.tar.gz report
~~~

See [USE-WITH-AI.md](./USE-WITH-AI.md) for an assistant prompt. Before deployment, `scan --code-only` inspects local code and leaves public-response checks unknown.

## Results

The states are `pass`, `fail`, `info`, `unknown`, and `na`. A failed check is evaluated with its evidence to determine whether it blocks a mark. Recommendations and unknowns are not blockers. The report shows inspected and unknown counts rather than presenting incomplete scans as a perfect score.

Do not repeat work until every item passes. Re-scan after fixing a verified issue or obtaining new evidence. Exit code 0 from `scan --json` means the command completed, not that the app is completely safe.

## Optional tracks

- `security` is the default: public responses, HTTPS, exposed secrets, public data access, and local code.
  For Supabase apps it also reads migrations and config to flag items from the Korean school privacy self-check (password policy, plaintext resident-number or password columns, rules that let anonymous users update or delete, upload size/type limits) as recommendations. Items code cannot prove, such as MFA, idle logout and access-log retention, are shown as reference signals only. `dcheck ops` goes further: for each school operations step (login lockout, admin and console MFA, idle logout, DB IP allow-list and SSL enforcement, access and permission logs, download reasons, stale accounts and keys, minimal API responses, retention and deletion, rate limits, backups, incident contacts, internal management plan) it writes the current state, the basis in the self-check sheets, side effects and a question to `.dorms-check/OPS.md`, records the teacher's choice with `dcheck ops decide`, and drafts the school self-check table in `.dorms-check/SCHOOL-SELFCHECK.md`. Nothing is forced and it does not affect the mark. Supabase project settings are read (GET only) only with `--supabase-config` and a `SUPABASE_ACCESS_TOKEN` the teacher provides.
- `edzip` prepares submission documents and, after official approval, school documents. Read [the document workflow](./skills/edzip-autopilot/SKILL.md). `edzip prepare --apply` requires the approved plan hash and `--confirm-apply`; `edzip council` requires the official URL and confirmation.
- `protection` prepares a rights profile and a change plan. Applying the plan requires its approved hash and `--confirm-apply`, with a backup and a restore command.

## Deep audit (on request)

`dcheck audit` runs a deeper, multi-agent security review adapted from Cloudflare's security-audit-skill (MIT). It skips what the minimum scan already checks (headers, TLS, exposed secrets, anonymous database reads) and focuses on in-code access control, business logic, AI features, cost exhaustion and data isolation. It keeps a coverage ledger, separates hunters from independent verifiers, records `confirmed`, `needs_validation` and `rejected` verdicts, never sends attack traffic to a deployment, and writes results only to an ignored or out-of-repo folder. See [ai/prompts/audit.md](./ai/prompts/audit.md) (Korean).

## Local files

`detect`, `status`, and `report` are read-only commands. `init` creates `dorms-check.config.json`. `scan` saves findings, reports, and history under `.dorms-check/`. `judge`, interview answers, plans, document generation, and `submit` save their respective local artifacts. Basic scans do not edit app source or deploy it.

## Previous installations

Version 0.3.0 removes global hook installation and deployment blocking. Retired commands return `FEATURE_REMOVED` with exit code 2 before scanning or writing. They never silently fall back to a scan.

`hooks status` and `hooks uninstall` remain solely for inspecting and removing previous installations. Cleanup backs up settings and preserves unrelated entries. It does not execute the old Node, Vercel, or PowerShell paths. See [the cleanup guide](./docs/LEGACY-HOOK-CLEANUP.ko.md).

Made by Hong Changuk of Team DoRm. See [LICENSE](./LICENSE), [NOTICE.md](./NOTICE.md), and [DISCLAIMER.md](./DISCLAIMER.md).
