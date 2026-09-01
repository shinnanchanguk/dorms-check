# dorms-check

English | [한국어](./README.ko.md)

**A coach that helps teachers inspect apps built with vibe coding and reduce verified risks alongside their own AI.**

> Made by teacher Hong Changuk of Team DoRm. DoRms members may use it freely in their own projects.

If you built an app with vibe coding (making code with AI) and you're not a developer, dorms-check helps you inspect and fix your app along three tracks:
- **Security review (`security`)**: is the app safe from hacking and data leaks?
- **EDZIP submission and approval readiness (`edzip`)**: are the EDZIP documents ready, and are the post-approval school documents prepared?
- **Protecting your app (`protection`)**: are your app's secrets (prompts, logic, data) and your rights prepared and protected?

Pass the security and edzip tracks and you can apply for a DoRms community verification mark.

## Where the mark comes from (read this first)
**The verification mark is issued by DoRms, not by this tool.** On your app in DoRms (already posted, or about to be), you press the "Request mark" button, and DoRms checks your public app URL on its own; if it already passes, the mark is attached right there. **dorms-check is the helper you use to fix whatever did not pass** when you requested the mark. No install needed: paste the prompt into the AI you already use, and it runs the checks and fixes for you.

> The flow: **request on DoRms → pass = mark right away / not yet = a list of what to fix → (when fixing) check and repair with dorms-check → request again.**

## The honest line
This tool does not issue any certification. It is a **coach** that tells you what is safe and what needs fixing. The final mark is issued only after the **DoRms server re-checks your app on its own**, and passing this tool does not guarantee the mark.

**File-change policy**: ordinary `security` and `edzip` scans only inspect. `edzip prepare --apply` creates the approved HWPX/PDF/Markdown document set in a private project path, and `protection apply` changes only the approved protection plan. Both require the reviewed plan hash and `--confirm-apply`. The tool never submits or deploys automatically.

## How to fix (check and repair)
When a requested mark comes back with items to fix, paste the prompt from [`USE-WITH-AI.md`](./USE-WITH-AI.md) into whichever AI you use (Claude Code, Cursor, Codex, Gemini, and so on). No install needed: it runs **straight from this GitHub repo**, so you always get the latest source. This package is not published to npm (a published copy goes stale every time the source changes), so use the `github:` spec below rather than a package name. Or run it directly:
```bash
npx -y github:shinnanchanguk/dorms-check detect
npx -y github:shinnanchanguk/dorms-check init --name "My App" --url "https://my-app-url" --track security,edzip,protection --confirm-ownership
npx -y github:shinnanchanguk/dorms-check scan --url "https://my-app-url"
npx -y github:shinnanchanguk/dorms-check edzip prepare # plan first; apply only after approval
npx -y github:shinnanchanguk/dorms-check edzip council --approved-url "https://edzip.kr/learning-sw/<product-id>" --confirm-apply
npx -y github:shinnanchanguk/dorms-check status     # remaining items + how to fix each
npx -y github:shinnanchanguk/dorms-check submit      # once everything passes: evidence pack + how to apply
```

### Strict Vercel deployment gate

For a production-blocking gate, pin an exact reviewed Git commit and install the audited `vercel@59.10.0` CLI instead of running moving versions. Strict mode issues signed 15-minute receipts, stored only in the trusted user home, bound to a clean Git SHA/tree, Git-bound deployment inputs, the linked `.vercel/project.json` project/org and file digest, exact Vercel URL/ID and source SHA, and the gate runtime. macOS/Linux/WSL uses one literal `vercel` command. On native Windows, hook installation resolves `vercel.cmd` with PowerShell `Get-Command`, pins its absolute path, SHA-256, version, and the PowerShell executable, then permits only `& '<status.windowsVercelExecutable>' <literal args>`. The `vc` shorthand, any other `.cmd`/`.exe`, variables, splatting, backticks, wrappers, and compound commands are denied. Staged deploys require both `githubDeployment=1` and the full literal `githubCommitSha` metadata. Apart from the verified staged deploy and promote, all Vercel writes are denied; only explicit list/inspect/status/get/help/version/whoami queries are allowlisted. Indirect runtime, script, workspace, task-runner, and dynamic-shell launchers are conservatively denied. Hook `configured` status verifies configuration and pinned path integrity only; host activation remains `unknown` until restart/trust and a safe blocking challenge.

```bash
npm install --global vercel@59.10.0
dcheck hooks install --global --agents codex,claude,gemini,antigravity --provider vercel --security-only
dcheck hooks status --agents codex,claude,gemini,antigravity --json
```

On Windows, `windowsVercelBackingExecutable` is the discovered real CLI. Run only the managed `windowsVercelExecutable` proxy, which re-checks the strict gate even if the host hook event does not fire.

See the command sequence, exit contract, hook locations, and limitations in [`docs/STRICT-SECURITY-GATE.ko.md`](./docs/STRICT-SECURITY-GATE.ko.md).

## Choosing which axes to check
The three tracks are independent. You can check only the ones you want, and only the chosen tracks are inspected and judged (the rest do not run at all).
- **security**: security review (headers, SSL, exposure, CORS, live RLS). If you only want the DoRms "Security review" mark, this one track is enough.
- **edzip**: EDZIP submission and approval readiness, followed by school approval and committee drafts. Pick it when you need educational-software adoption documents.
- **protection**: protecting your app's secrets and copyright (rights check, server separation, notices, evidence). Pick it only when you want to protect your idea.

Pass a comma-separated subset to `--track` and only that subset runs.
```bash
# Only want the security mark? Just the security track (no need for the 3rd protection track)
npx -y github:shinnanchanguk/dorms-check init --name "My App" --track security --confirm-ownership

# Security + protection only
npx -y github:shinnanchanguk/dorms-check init --name "My App" --track security,protection --confirm-ownership

# All three
npx -y github:shinnanchanguk/dorms-check init --name "My App" --track security,edzip,protection --confirm-ownership
```
When a person runs `init` in a terminal without `--track`, it shows the three axes and asks which to check (numbers or names, comma-separated, e.g. `1,3` or `security,protection`). When an AI runs it non-interactively (piped), it does not prompt and uses the `--track` value, or the default (security) if none is given.

## What it checks

### Track 1: Security review (`security`)
- **Security response headers** (6): CSP, HSTS, clickjacking defense, nosniff, Referrer, Permissions
- **Transport security**: forced HTTPS, SSL certificate, legacy TLS, cookie flags
- **Information exposure**: leaked .env or .git, source maps, stack traces, mixed content. Only real exposure is flagged (no SPA false positives).
- **CORS**: any-origin access, credentialed exposure
- **Data access (RLS)**: using the public anon key, it sends **real unauthenticated requests** to measure whether an anonymous visitor can read personal data (a non-destructive SELECT)
- **Code secrets**: hardcoded keys, client-side exposure
- A score (0 to 100) and grade (A to F) are shown for reference. Mark eligibility means zero critical or high items.

### Track 2: EDZIP submission and approval (`edzip`)
Stage 1, `edzip prepare`, creates the privacy policy, essential-criteria checklist, product brief, and EDZIP submission guide in HWPX, PDF, and Markdown. Stage 2, `edzip council --approved-url <official URL> --confirm-apply`, verifies the public confirmed EDZIP record and creates a project-specific internal approval draft, school committee agenda, and school submission guide. It reuses the documents submitted to EDZIP and attaches the approved URL. A blank editable HWPX template is bundled. Personal identity, school, approval route, date, phone, signature, and seal fields remain searchable blanks.

### Track 3: Protecting your app (`protection`)
- **Rights check**: who made the app, whether school work is involved, third-party assets, AI contribution (a simple survey builds a rights profile; no secret text goes into it)
- **Secret boundary**: does the deployed bundle leak API keys, private prompts, or model files? Is the core logic behind a server?
- **Release hygiene**: source maps, debug traces, personal file paths, raw source files in the build output, plus a hash manifest of the artifacts
- **Notices and evidence**: human-readable rights notice, machine-readable notices (robots.txt AI-crawler block, llms.txt, TDM reservation), and an evidence pack (hashes and git history; blockchain timestamping optional)
- The verdict is not a score but **six states**: server separation verified / partially server-separated / public asset / copy-cost raised / rights and usage notice configured / rights status unresolved.
- **Honest premise**: obfuscation and Base64 are not secrecy. Anything delivered to the browser must be assumed public. There is no such thing as "complete protection".
- Apply flow: `interview` (rights survey) → `protect plan` (plan + hash) → after consent `protect apply --plan-sha256 <hash> --confirm-apply` (backup, then apply) → `verify` (breakage check) → `protect restore` if anything went wrong.

## Why you can't "just pass" (hallucination guard)
Even if a weaker AI mistakenly says "no problems," the verdict comes not from the model's words but from **checks the program actually ran**. Data access (RLS) in particular is confirmed by sending real anonymous requests, and protection status is measured directly on the build artifacts. And the final mark is issued only when the **DoRms server re-inspects the app on its own** and it passes. See [`DISCLAIMER.md`](./DISCLAIMER.md) for the full limits and ethics.

## Requirements
- Node.js 18 or later. The package includes its HWPX/PDF engines and Korean font; it does not add dependencies to the project being checked.
- Optional: if tools like semgrep or gitleaks are installed, they add deeper checks, but the mark verdict is the same without them. `opentimestamps-client` (ots) is optional for blockchain timestamping of the evidence pack.

## License
DoRms Member Community License 1.0. DoRms members may use the tool freely in projects they own or are authorized to maintain. Repackaging, resale, and removal of attribution are restricted. Earlier copies received under MIT remain under that grant. See [`LICENSE`](./LICENSE) and [`NOTICE.md`](./NOTICE.md).
