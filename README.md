# dorms-check

English | [한국어](./README.ko.md)

A minimum inspection tool for teacher-built apps. It reports observed risks, recommendations, and checks it could not complete.

## Inspection and app registration

DoRms app registration is independent from its inspection marks. An inaccessible internal database or an undiscovered privacy policy does not prevent registration.

The minimum security mark requires the DoRms server to inspect a successful public HTTPS response and its body, without finding a substantiated blocking risk. Login pages and single-page apps use the same rule. Coverage and unknown checks remain visible; the mark does not guarantee the security of the entire app.

Missing security headers, a public database response, or permissive CORS alone do not establish a vulnerability. Users do not need to move hosting providers or publish a policy in a prescribed HTML file. If the public response cannot be inspected, a new mark is withheld while app registration remains available.

Council document readiness and official EDZIP verification have separate outcomes. An unreadable policy only withholds council readiness. Official EDZIP verification still requires official evidence.

## Start

Use Node.js 18 or newer. These examples pin the `v0.3.2` GitHub release. If your organization reviewed a particular commit, keep using that commit instead.

~~~bash
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.3.2.tar.gz detect
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.3.2.tar.gz init --name "My App" --url "https://my-app.example" --track security --confirm-ownership
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.3.2.tar.gz scan --url "https://my-app.example"
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.3.2.tar.gz status
npx -y https://github.com/shinnanchanguk/dorms-check/archive/refs/tags/v0.3.2.tar.gz report
~~~

See [USE-WITH-AI.md](./USE-WITH-AI.md) for an assistant prompt. Before deployment, `scan --code-only` inspects local code and leaves public-response checks unknown.

## Results

The states are `pass`, `fail`, `info`, `unknown`, and `na`. A failed check is evaluated with its evidence to determine whether it blocks a mark. Recommendations and unknowns are not blockers. The report shows inspected and unknown counts rather than presenting incomplete scans as a perfect score.

Do not repeat work until every item passes. Re-scan after fixing a verified issue or obtaining new evidence. Exit code 0 from `scan --json` means the command completed, not that the app is completely safe.

## Optional tracks

- `security` is the default: public responses, HTTPS, exposed secrets, public data access, and local code.
  For Supabase apps it also reads migrations and config to flag items from the Korean school privacy self-check (password policy, plaintext resident-number or password columns, rules that let anonymous users update or delete, upload size/type limits) as recommendations. Items code cannot prove, such as MFA, idle logout and access-log retention, are shown as reference signals only.
- `edzip` prepares submission documents and, after official approval, school documents. Read [the document workflow](./skills/edzip-autopilot/SKILL.md). `edzip prepare --apply` requires the approved plan hash and `--confirm-apply`; `edzip council` requires the official URL and confirmation.
- `protection` prepares a rights profile and a change plan. Applying the plan requires its approved hash and `--confirm-apply`, with a backup and a restore command.

## Local files

`detect`, `status`, and `report` are read-only commands. `init` creates `dorms-check.config.json`. `scan` saves findings, reports, and history under `.dorms-check/`. `judge`, interview answers, plans, document generation, and `submit` save their respective local artifacts. Basic scans do not edit app source or deploy it.

## Previous installations

Version 0.3.0 removes global hook installation and deployment blocking. Retired commands return `FEATURE_REMOVED` with exit code 2 before scanning or writing. They never silently fall back to a scan.

`hooks status` and `hooks uninstall` remain solely for inspecting and removing previous installations. Cleanup backs up settings and preserves unrelated entries. It does not execute the old Node, Vercel, or PowerShell paths. See [the cleanup guide](./docs/LEGACY-HOOK-CLEANUP.ko.md).

Made by Hong Changuk of Team DoRm. See [LICENSE](./LICENSE), [NOTICE.md](./NOTICE.md), and [DISCLAIMER.md](./DISCLAIMER.md).
