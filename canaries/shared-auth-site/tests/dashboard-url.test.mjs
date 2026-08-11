import test from "node:test";
import assert from "node:assert/strict";

import {
  parseDashboardUrlAllowlist,
  resolveDashboardUrl,
  validateDashboardUrl,
} from "../src/lib/dashboard-url.mjs";

const productionUrl = "https://dashboard.shared-auth.dev/directory";
const allowlist = JSON.stringify([productionUrl]);

test("an unset dashboard target preserves the fail-closed handoff", () => {
  assert.equal(resolveDashboardUrl(undefined, undefined), undefined);
  assert.equal(resolveDashboardUrl("", "[]"), undefined);
});

test("the dashboard target must exactly match a validated allowlist entry", () => {
  assert.equal(resolveDashboardUrl(productionUrl, allowlist), productionUrl);
  assert.throws(
    () =>
      resolveDashboardUrl(
        `${productionUrl}/`,
        allowlist,
      ),
    /exactly match/,
  );
  assert.throws(
    () =>
      resolveDashboardUrl(
        "https://other.shared-auth.dev/directory",
        allowlist,
      ),
    /exactly match/,
  );
});

test("unsafe, ambiguous, and non-production URLs are rejected", () => {
  const rejected = [
    "http://dashboard.shared-auth.dev/directory",
    "https://user:secret@dashboard.shared-auth.dev/directory",
    "https://dashboard.shared-auth.dev/directory?organization=other",
    "https://dashboard.shared-auth.dev/directory#session",
    "https://127.0.0.1/directory",
    "https://2130706433/directory",
    "https://[::1]/directory",
    "https://localhost/directory",
    "https://metadata.google.internal/directory",
    "https://dashboard.local/directory",
    "https://dashboard.home.arpa/directory",
    "https://dashboard.example/directory",
    "https://dashboard.example.com/directory",
    "https://single-label/directory",
    "https://dashboard.shared-auth.dev:8443/directory",
    "https://dashboard.shared-auth.dev/",
    "https://dashboard.shared-auth.dev/%64irectory",
    "https://dashboard.shared-auth.dev//directory",
    "https://DASHBOARD.shared-auth.dev/directory",
    " https://dashboard.shared-auth.dev/directory",
  ];

  for (const candidate of rejected) {
    assert.throws(
      () => validateDashboardUrl(candidate),
      /PUBLIC_DASHBOARD_URL/,
      candidate,
    );
  }
});

test("allowlist configuration is strict and duplicate-free", () => {
  assert.deepEqual(parseDashboardUrlAllowlist(allowlist), [productionUrl]);
  for (const invalid of [
    "not json",
    JSON.stringify(productionUrl),
    JSON.stringify([productionUrl, productionUrl]),
    JSON.stringify(["https://localhost/directory"]),
    JSON.stringify(
      Array.from(
        { length: 17 },
        (_, index) => `https://dashboard-${index}.shared-auth.dev/directory`,
      ),
    ),
  ]) {
    assert.throws(() => parseDashboardUrlAllowlist(invalid));
  }
});

test("configuration errors never echo a URL that could contain credentials", () => {
  const secret = "do-not-log-this";
  assert.throws(
    () =>
      resolveDashboardUrl(
        `https://user:${secret}@dashboard.shared-auth.dev/directory`,
        allowlist,
      ),
    (error) => !error.message.includes(secret),
  );
});
