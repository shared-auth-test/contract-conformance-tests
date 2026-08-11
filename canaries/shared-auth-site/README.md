# shared-auth.github.io

Astro-based GitHub Pages marketing site for the Shared Auth identity plane. This repository is intentionally **not** Jekyll or Hugo.

## Development

The Astro dependency is pinned to the exact version certified in `shared-auth-test`, and `package-lock.json` is committed. Install exactly that graph without running dependency lifecycle scripts:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run dev
npm run build
npm test
```

When deliberately changing dependencies, regenerate the lock with `npm install --package-lock-only --ignore-scripts --no-audit --no-fund`, review the lock diff, and verify a fresh `npm ci` before committing it.

The site emits static output to `dist/`, including `public/.nojekyll` so GitHub Pages serves the Astro artifact directly. The Pages workflow uses immutable action commits, does not persist checkout credentials, and grants deployment permissions only to the deploy job.

## Dashboard handoff

The marketing site links to `/dashboard/`. The handoff page never infers authentication state or embeds secrets. After `shared-auth/shared-auth-web-server.js` and its route are provisioned, set both GitHub Pages repository variables:

- `PUBLIC_DASHBOARD_URL` is the single canonical production dashboard URL.
- `PUBLIC_DASHBOARD_URL_ALLOWLIST` is a JSON array containing that exact URL. It can hold at most 16 exact URLs for controlled migrations.

Every configured URL is validated during the Astro build and must:

- use canonical HTTPS with an explicit, non-root dashboard path;
- use a public DNS hostname rather than an IP literal, single-label name, or internal/reserved suffix;
- contain no credentials, non-default port, query, fragment, or encoded/ambiguous path; and
- exactly match an allowlist entry, including its origin, path, and trailing-slash form.

When the target is absent, the page stays fail-closed and displays a provisioning notice rather than redirecting to an invented endpoint. A present but invalid or unlisted target fails the build without echoing the rejected URL.

## Independent evidence

The exact Astro source, ORES contracts, and web-server seed are exercised in `shared-auth-test/contract-conformance-tests`. That lane performs a clean `npm ci`, builds the static site, runs the source tests, and records the build artifact independently of production-organization Actions billing.
