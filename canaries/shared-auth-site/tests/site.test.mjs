import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

const built = new URL("../dist/index.html", import.meta.url);
const dashboard = new URL("../dist/dashboard/index.html", import.meta.url);
const dashboardSource = new URL("../src/pages/dashboard.astro", import.meta.url);
const lockfile = new URL("../package-lock.json", import.meta.url);
const workflows = [
  new URL("../.github/workflows/opto-sync-real-web.yml", import.meta.url),
  new URL("../.github/workflows/pages.yml", import.meta.url),
  new URL("../.github/workflows/repository-policy.yml", import.meta.url),
];

test("Astro emits the Shared Auth landing page and dashboard handoff", () => {
  assert.ok(existsSync(built));
  assert.ok(existsSync(dashboard));
});

test("landing page exposes assurance, polyglot clients, and a dashboard CTA", () => {
  const html = readFileSync(built, "utf8");
  for (const expected of ["Shared Auth", "Select client language", "Protected introspection", "Rust", "TypeScript", "Dart / Flutter", "Swift", "Dashboard", "/dashboard/"]) {
    assert.ok(html.includes(expected), `missing ${expected}`);
  }
  assert.ok(!html.includes("undefined"));
});

test("dashboard handoff documents fail-closed directory guardrails", () => {
  const html = readFileSync(dashboard, "utf8");
  for (const expected of ["Users, sessions, and roles", "Organization isolation", "Session privacy", "Capability truth"]) {
    assert.ok(html.includes(expected), `missing ${expected}`);
  }
  assert.ok(html.includes("Dashboard endpoint pending"));
  assert.ok(html.includes('name="referrer" content="no-referrer"'));
  assert.ok(html.includes('name="robots" content="noindex,nofollow"'));
  assert.ok(!html.includes("Continue to dashboard"));
  assert.ok(!html.includes("Authorization: Bearer"));

  const source = readFileSync(dashboardSource, "utf8");
  assert.ok(source.includes('rel="noreferrer noopener"'));
  assert.ok(source.includes('referrerpolicy="no-referrer"'));
});

test("repository remains Astro-only and opts out of Jekyll processing", () => {
  assert.ok(existsSync(new URL("../public/.nojekyll", import.meta.url)));
  assert.ok(existsSync(new URL("../dist/.nojekyll", import.meta.url)));
  for (const forbidden of ["_config.yml", "Gemfile", "config.toml", "hugo.toml"]) {
    assert.ok(!existsSync(new URL(`../${forbidden}`, import.meta.url)), `unexpected ${forbidden}`);
  }
});

test("the committed lock pins the certified Astro dependency", () => {
  assert.ok(existsSync(lockfile));
  const lock = JSON.parse(readFileSync(lockfile, "utf8"));
  assert.equal(lock.lockfileVersion, 3);
  assert.equal(lock.packages[""].dependencies.astro, "7.2.1");
  assert.equal(lock.packages["node_modules/astro"].version, "7.2.1");
});

test("all workflow dependencies are immutable and checkouts drop credentials", () => {
  let checkoutCount = 0;
  let protectedCheckoutCount = 0;
  for (const workflowPath of workflows) {
    const workflow = readFileSync(workflowPath, "utf8");
    const uses = [...workflow.matchAll(/^\s*(?:-\s+)?uses:\s+\S+@([^\s#]+)\s*$/gm)];
    assert.ok(uses.length > 0, `no workflow dependency found in ${workflowPath.pathname}`);
    for (const [, reference] of uses) {
      assert.match(reference, /^[0-9a-f]{40}$/);
    }
    checkoutCount += (workflow.match(/uses:\s+actions\/checkout@/g) ?? []).length;
    protectedCheckoutCount += (
      workflow.match(/uses:\s+actions\/checkout@[0-9a-f]{40}[\s\S]{0,160}?persist-credentials:\s+false/g) ?? []
    ).length;
  }
  assert.ok(checkoutCount > 0);
  assert.equal(protectedCheckoutCount, checkoutCount);

  const pages = readFileSync(workflows[1], "utf8");
  assert.ok(pages.includes("npm ci --ignore-scripts --no-audit --no-fund"));
  assert.ok(!pages.includes("npm install --package-lock-only"));
});
