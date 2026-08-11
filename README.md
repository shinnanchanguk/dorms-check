# dorms-check

English | [한국어](./README.ko.md)

**A coach that helps teachers check the apps they built with vibe coding, and fix them alongside their own AI until they're actually safe.**

If you built an app with vibe coding (making code with AI) and you're not a developer, dorms-check helps you inspect and fix your app along three tracks:
- **Security review (`security`)**: is the app safe from hacking and data leaks?
- **School committee readiness (`edzip`)**: are the privacy documents ready for school review?
- **Protecting your app (`protection`)**: are your app's secrets (prompts, logic, data) and your rights prepared and protected?

Pass the security and edzip tracks and you can apply for a DoRms community verification mark.

## Where the mark comes from (read this first)
**The verification mark is issued by DoRms, not by this tool.** On your app in DoRms (already posted, or about to be), you press the "Request mark" button, and DoRms checks your public app URL on its own; if it already passes, the mark is attached right there. **dorms-check is the helper you use to fix whatever did not pass** when you requested the mark. No install needed: paste the prompt into the AI you already use, and it runs the checks and fixes for you.

> The flow: **request on DoRms → pass = mark right away / not yet = a list of what to fix → (when fixing) check and repair with dorms-check → request again.**

## The honest line
This tool does not issue any certification. It is a **coach** that tells you what is safe and what needs fixing. The final mark is issued only after the **DoRms server re-checks your app on its own**, and passing this tool does not guarantee the mark.

**File-change policy**: the `security` and `edzip` tracks only inspect; they never modify files. Only the apply step of the `protection` track changes files, and only when the user has reviewed the plan and passed its hash with `--plan-sha256 <hash> --confirm-apply`. It never deploys automatically.

## How to fix (check and repair)
When a requested mark comes back with items to fix, paste the prompt from [`USE-WITH-AI.md`](./USE-WITH-AI.md) into whichever AI you use (Claude Code, Cursor, Codex, Gemini, and so on). No install needed: it runs **straight from this GitHub repo**, so you always get the latest source. This package is not published to npm (a published copy goes stale every time the source changes), so use the `github:` spec below rather than a package name. Or run it directly:
```bash
npx -y github:shinnanchanguk/dorms-check detect
npx -y github:shinnanchanguk/dorms-check init --name "My App" --url "https://my-app-url" --track security,edzip,protection --confirm-ownership
npx -y github:shinnanchanguk/dorms-check scan --url "https://my-app-url"
npx -y github:shinnanchanguk/dorms-check status     # remaining items + how to fix each
npx -y github:shinnanchanguk/dorms-check submit      # once everything passes: evidence pack + how to apply
```

## What it checks

### Track 1: Security review (`security`)
- **Security response headers** (6): CSP, HSTS, clickjacking defense, nosniff, Referrer, Permissions
- **Transport security**: forced HTTPS, SSL certificate, legacy TLS, cookie flags
- **Information exposure**: leaked .env or .git, source maps, stack traces, mixed content. Only real exposure is flagged (no SPA false positives).
- **CORS**: any-origin access, credentialed exposure
- **Data access (RLS)**: using the public anon key, it sends **real unauthenticated requests** to measure whether an anonymous visitor can read personal data (a non-destructive SELECT)
- **Code secrets**: hardcoded keys, client-side exposure
- A score (0 to 100) and grade (A to F) are shown for reference. Mark eligibility means zero critical or high items.

### Track 2: School Committee Ready (`edzip`)
The EDZIP "Essential Criteria Checklist for Learning-Support Software": 5 criteria and 9 sub-items (minimal collection, safeguards, access/correction/deletion, protection of children under 14, officer/provision/outsourcing), plus a public privacy policy. Templates for the privacy policy and the school committee submission document are included.

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
- Node.js 18 or later (uses built-in fetch and tls). No extra dependencies to install.
- Optional: if tools like semgrep or gitleaks are installed, they add deeper checks, but the mark verdict is the same without them. `opentimestamps-client` (ots) is optional for blockchain timestamping of the evidence pack.

## License
MIT
