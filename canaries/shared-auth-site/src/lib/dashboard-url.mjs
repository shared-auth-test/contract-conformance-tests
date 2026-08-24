import { isIP } from "node:net";

const MAX_URL_LENGTH = 2048;
const MAX_ALLOWLIST_LENGTH = 32768;
const MAX_ALLOWLIST_ENTRIES = 16;
const BLOCKED_HOSTS = new Set([
  "broadcasthost",
  "ip6-localhost",
  "ip6-loopback",
  "local",
  "localhost",
  "localhost.localdomain",
]);
const BLOCKED_DOMAIN_TREES = ["example.com", "example.net", "example.org"];
const BLOCKED_SUFFIXES = [
  ".arpa",
  ".corp",
  ".example",
  ".home",
  ".internal",
  ".invalid",
  ".lan",
  ".local",
  ".localdomain",
  ".localhost",
  ".onion",
  ".private",
  ".test",
];

function invalidUrl(setting) {
  return new Error(
    `${setting} must be one canonical HTTPS production URL with an explicit non-root path and no credentials, port, query, fragment, IP literal, internal hostname, or encoded path`,
  );
}

export function validateDashboardUrl(value, setting = "PUBLIC_DASHBOARD_URL") {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_URL_LENGTH ||
    value !== value.trim()
  ) {
    throw invalidUrl(setting);
  }

  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw invalidUrl(setting);
  }

  const hostname = parsed.hostname
    .replace(/^\[|\]$/g, "")
    .toLowerCase();
  const labels = hostname.split(".");
  const blockedHostname =
    BLOCKED_HOSTS.has(hostname) ||
    BLOCKED_DOMAIN_TREES.some(
      (domain) => hostname === domain || hostname.endsWith(`.${domain}`),
    ) ||
    BLOCKED_SUFFIXES.some(
      (suffix) => hostname === suffix.slice(1) || hostname.endsWith(suffix),
    );
  const invalidDnsName =
    hostname.length > 253 ||
    !hostname.includes(".") ||
    hostname.endsWith(".") ||
    /^\d+$/.test(labels.at(-1) ?? "") ||
    labels.some(
      (label) =>
        !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label),
    );
  const ambiguousPath =
    parsed.pathname === "/" ||
    parsed.pathname.includes("//") ||
    parsed.pathname.includes("%") ||
    value.includes("\\");

  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.port ||
    value.includes("?") ||
    value.includes("#") ||
    isIP(hostname) !== 0 ||
    blockedHostname ||
    invalidDnsName ||
    ambiguousPath ||
    parsed.href !== value
  ) {
    throw invalidUrl(setting);
  }

  return parsed.href;
}

export function parseDashboardUrlAllowlist(rawValue) {
  if (rawValue === undefined || rawValue === null || rawValue === "") {
    return [];
  }
  if (
    typeof rawValue !== "string" ||
    rawValue.length > MAX_ALLOWLIST_LENGTH
  ) {
    throw new Error("PUBLIC_DASHBOARD_URL_ALLOWLIST must be a bounded JSON array");
  }

  let entries;
  try {
    entries = JSON.parse(rawValue);
  } catch {
    throw new Error("PUBLIC_DASHBOARD_URL_ALLOWLIST must be a valid JSON array");
  }
  if (!Array.isArray(entries) || entries.length > MAX_ALLOWLIST_ENTRIES) {
    throw new Error(
      `PUBLIC_DASHBOARD_URL_ALLOWLIST must be a JSON array with at most ${MAX_ALLOWLIST_ENTRIES} entries`,
    );
  }

  const validated = entries.map((entry) =>
    validateDashboardUrl(entry, "PUBLIC_DASHBOARD_URL_ALLOWLIST entries"),
  );
  if (new Set(validated).size !== validated.length) {
    throw new Error("PUBLIC_DASHBOARD_URL_ALLOWLIST must not contain duplicates");
  }
  return validated;
}

export function resolveDashboardUrl(candidate, rawAllowlist) {
  const allowlist = parseDashboardUrlAllowlist(rawAllowlist);
  if (candidate === undefined || candidate === null || candidate === "") {
    return undefined;
  }

  const dashboardUrl = validateDashboardUrl(candidate);
  if (!allowlist.includes(dashboardUrl)) {
    throw new Error(
      "PUBLIC_DASHBOARD_URL must exactly match an entry in PUBLIC_DASHBOARD_URL_ALLOWLIST",
    );
  }
  return dashboardUrl;
}
