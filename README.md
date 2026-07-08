# dorms-check

English | [한국어](./README.ko.md)

**A security and privacy coach that helps teachers check the apps they built with vibe coding, and fix them alongside their own AI until they're actually safe.**

If you built an app with vibe coding (making code with AI) and you're not a developer, dorms-check helps you inspect and fix how your app handles security and personal data. Pass both tracks and you can apply for a DoRms community verification mark.

## Where the mark comes from (read this first)
**The verification mark is issued by DoRms, not by this tool.** On your app in DoRms (already posted, or about to be), you press the "Request mark" button, and DoRms checks your public app URL on its own; if it already passes, the mark is attached right there. **dorms-check is the helper you use to fix whatever did not pass** when you requested the mark. No install needed: paste the prompt into the AI you already use, and it runs the checks and fixes for you.

> The flow: **request on DoRms → pass = mark right away / not yet = a list of what to fix → (when fixing) check and repair with dorms-check → request again.**

## The honest line
This tool does not fix your app, and it does not issue any certification. It is a **coach** that tells you what is safe and what needs fixing. The final mark is issued only after the **DoRms server re-checks your app on its own**, and passing this tool does not guarantee the mark.

## How to fix (check and repair)
When a requested mark comes back with items to fix, paste the prompt from [`USE-WITH-AI.md`](./USE-WITH-AI.md) into whichever AI you use (Claude Code, Cursor, Codex, Gemini, and so on). No install needed (`npx` fetches and runs it). Or run it directly:
```bash
npx -y dorms-check@latest detect
npx -y dorms-check@latest init --name "My App" --url "https://my-app-url" --track security,edzip --confirm-ownership
npx -y dorms-check@latest scan --url "https://my-app-url"
npx -y dorms-check@latest status     # remaining items + how to fix each
npx -y dorms-check@latest submit      # once everything passes: evidence pack + how to apply
```

## What it checks

### Track 1 — DoRms Security Review
- **Security response headers** (6): CSP, HSTS, clickjacking defense, nosniff, Referrer, Permissions
- **Transport security**: forced HTTPS, SSL certificate, legacy TLS, cookie flags
- **Information exposure**: leaked .env or .git, source maps, stack traces, mixed content. Only real exposure is flagged (no SPA false positives).
- **CORS**: any-origin access, credentialed exposure
- **Data access (RLS)**: using the public anon key, it sends **real unauthenticated requests** to measure whether an anonymous visitor can read personal data (a non-destructive SELECT)
- **Code secrets**: hardcoded keys, client-side exposure
- A score (0 to 100) and grade (A to F) are shown for reference. Mark eligibility means zero critical or high items.

### Track 2 — School Committee Ready
The EDZIP "Essential Criteria Checklist for Learning-Support Software": 5 criteria and 9 sub-items (minimal collection, safeguards, access/correction/deletion, protection of children under 14, officer/provision/outsourcing), plus a public privacy policy. Templates for the privacy policy and the school committee submission document are included.

## Why you can't "just pass" (hallucination guard)
Even if a weaker AI mistakenly says "no problems," the verdict comes not from the model's words but from **checks the program actually ran**. Data access (RLS) in particular is confirmed by sending real anonymous requests. And the final mark is issued only when the **DoRms server re-inspects the app on its own** and it passes. See [`DISCLAIMER.md`](./DISCLAIMER.md) for the full limits and ethics.

## Requirements
- Node.js 18 or later (uses built-in fetch and tls). No extra dependencies to install.
- Optional: if tools like semgrep or gitleaks are installed, they add deeper checks, but the mark verdict is the same without them.

## License
MIT
