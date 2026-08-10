# shared-auth.github.io

Astro-based GitHub Pages marketing site for the Shared Auth identity plane. This repository is intentionally **not** Jekyll or Hugo.

## Development

The Astro dependency is pinned to the exact version certified in `shared-auth-test`. Resolve a local lock without running lifecycle scripts, then install from that lock:

```sh
npm install --package-lock-only --ignore-scripts --no-audit --no-fund
npm ci --no-audit --no-fund
npm run dev
npm run build
npm test
```

The site emits static output to `dist/`, including `public/.nojekyll` so GitHub Pages serves the Astro artifact directly. The Pages workflow uses immutable action commits, does not persist checkout credentials, and grants deployment permissions only to the deploy job.

## Dashboard handoff

The marketing site links to `/dashboard/`. The handoff page never infers authentication state or embeds secrets. Set the GitHub Pages repository variable `PUBLIC_DASHBOARD_URL` to the deployed dashboard URL after `shared-auth/shared-auth-web-server.js` is provisioned.

The value is validated during the Astro build and must:

- use HTTPS;
- contain no embedded username or password; and
- point to the separately deployed Shared Auth directory dashboard.

When the variable is absent, the page stays fail-closed and displays a provisioning notice rather than redirecting to an invented endpoint.

## Independent evidence

The exact Astro source, ORES contracts, and web-server seed are exercised in `shared-auth-test/contract-conformance-tests`. That lane generates a lock, performs a clean `npm ci`, builds the static site, runs the source tests, and records the build artifact independently of production-organization Actions billing.
