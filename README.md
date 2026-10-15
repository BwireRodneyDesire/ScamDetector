# PhishGuard

PhishGuard is a research prototype that scans a website URL for phishing patterns. It combines URL structure, page signals, HTTPS/TLS observations, community reports, and a server-side **Reputation & infrastructure** layer.

## Features

- URL and page-structure heuristics: lookalike domains, IP hosts, forms, cross-domain form destinations, links, hidden elements, favicons, and fetch status.
- Reputation checks: RDAP domain age/registrar/expiry, Google Safe Browsing, URLhaus, Tranco popularity, hosting country/provider, and redirect chains.
- SSRF protection: private, loopback, link-local, and internal addresses are blocked before scanning.
- Bounded parallel lookups with graceful `Not checked` states and 24-hour in-memory caching.
- Optional sign-in with account-backed scan history and community scam reports.
- Public phishing-awareness quiz.
- AI explanation generated only from structured scan findings; it never receives API keys or runs in the browser.

## Scoring

The verdict remains rule-based: `Low risk` (<25), `Review` (25–44), or `High risk` (45+). Strong signals carry the most weight: blocklist matches, brand lookalikes, cross-domain login redirects, and very new domains with login forms. Domain popularity is context only: Tranco top-10k domains receive a score cap when no blocklist hit exists. A popular domain is not automatically safe, and an unlisted domain is not automatically suspicious.

The result page shows the signal category breakdown, domain information, redirect count, and an expandable score explanation. External services that fail or are not configured are shown as `Not checked`; they never crash a scan.

## Setup

```bash
pnpm install
pnpm db:push
pnpm dev
```

For a production build:

```bash
pnpm test
pnpm check
pnpm build
pnpm start
```

On Windows, `pnpm start` works from PowerShell and Command Prompt as well; the
script sets `NODE_ENV` through `cross-env`.

## Environment variables

Copy `.env.example` to `.env` in a local environment and fill in the values. Never commit `.env` files.

- `DATABASE_URL` — MySQL/TiDB connection string.
- `JWT_SECRET` — session cookie signing secret.
- `VITE_APP_ID`, `OAUTH_SERVER_URL`, `VITE_OAUTH_PORTAL_URL` — Manus authentication configuration.
- `BUILT_IN_FORGE_API_URL`, `BUILT_IN_FORGE_API_KEY` — server-side Manus built-in API access for AI explanations.
- `GOOGLE_SAFE_BROWSING_API_KEY` — optional Google Web Risk/Safe Browsing key. If absent, the Google check is `Not checked`; URLhaus remains available without a key.

The deployed Manus environment supplies its platform variables. Add optional reputation secrets through the platform secret manager, not source code.

## Limitations

- Reputation data is time-dependent and can be missing, stale, or unavailable.
- RDAP registration dates and hosting geolocation are informational, not proof of trust.
- Blocklist clean results do not prove safety; blocklist matches can also require context.
- The scanner cannot execute every JavaScript path a browser would execute.
- Heuristics can produce false positives and false negatives. Never enter passwords, payment details, or one-time codes into an unfamiliar page.
- Community reports are unverified user opinions.

## Project structure

- `server/inspection.ts` — rule-based URL/page scanner and score.
- `server/reputation.ts` — server-only RDAP, blocklist, Tranco, hosting, redirect, cache, and timeout logic.
- `server/routers.ts` — tRPC scan, history, report, and AI procedures.
- `client/src/pages/Home.tsx` — scan result interface.
- `client/src/pages/Report.tsx` — signed-in scam reporting.
- `client/src/pages/Quiz.tsx` — public awareness quiz.
- `drizzle/` — schema and database migrations.
