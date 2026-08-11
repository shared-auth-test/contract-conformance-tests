import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

const built = new URL("../dist/index.html", import.meta.url);
const dashboard = new URL("../dist/dashboard/index.html", import.meta.url);

test("Astro emits the Shared Auth landing page and dashboard handoff", () => {
  assert.ok(existsSync(built));
  assert.ok(existsSync(dashboard));
});

test("landing page exposes assurance, polyglot clients, and a dashboard CTA", () => {
  const html = readFileSync(built, "utf8");
  for (const expected of ["Shared Auth", "Select client language", "Protected introspection", "Rust", "TypeScript", "Dart / Flutter", "Swift", "Dashboard", "/dashboard/"]) {
    assert.ok(html.includes(expected), `missing ${expected}`);
  }
  const dashboardLinks = html.match(/<a\b[^>]*href="\/dashboard\/"[^>]*>/g) ?? [];
  assert.ok(dashboardLinks.length >= 2, "homepage must expose dashboard links in both the navigation and hero");
  assert.match(html, /<nav>.*<a class="nav-dashboard" href="\/dashboard\/">Dashboard<\/a><\/nav>/);
  assert.match(html, /<div class="actions"><a class="dashboard-cta" href="\/dashboard\/"/);
  assert.ok(
    html.includes('aria-label="Open the Shared Auth dashboard handoff"'),
    "hero dashboard CTA must retain its accessible label",
  );
  assert.ok(!html.includes("undefined"));
});

test("dashboard handoff documents fail-closed directory guardrails", () => {
  const html = readFileSync(dashboard, "utf8");
  for (const expected of ["Users, sessions, and roles", "Organization isolation", "Session privacy", "Capability truth"]) {
    assert.ok(html.includes(expected), `missing ${expected}`);
  }
  assert.ok(!html.includes("Authorization: Bearer"));
});

test("repository remains Astro-only and opts out of Jekyll processing", () => {
  assert.ok(existsSync(new URL("../public/.nojekyll", import.meta.url)));
  for (const forbidden of ["_config.yml", "Gemfile", "config.toml", "hugo.toml"]) {
    assert.ok(!existsSync(new URL(`../${forbidden}`, import.meta.url)), `unexpected ${forbidden}`);
  }
});
