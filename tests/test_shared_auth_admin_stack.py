from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "fixtures/shared-auth-admin/canary-manifest.json"
SITE = ROOT / "canaries/shared-auth-site"
FIXTURES = ROOT / "fixtures/shared-auth-admin"


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def git_blob_sha(path: Path) -> str:
    payload = path.read_bytes()
    header = f"blob {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload).hexdigest()


class SharedAuthAdminStackCanary(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = read_json(MANIFEST)
        cls.schema = read_json(FIXTURES / "schema.json")
        cls.example = read_json(FIXTURES / "dashboard-response.json")
        cls.runtime = read_json(FIXTURES / "runtime-policy.json")

    def test_sources_are_exactly_pinned(self) -> None:
        self.assertEqual(
            self.manifest["schema"], "shared-auth-test.admin-stack-canary/v1"
        )
        for head in self.manifest["sourceHeads"].values():
            self.assertRegex(head, r"^[0-9a-f]{40}$")
        self.assertRegex(
            self.manifest["webServerSeedArchiveSha256"], r"^[0-9a-f]{64}$"
        )
        for relative, expected in self.manifest["sourceBlobs"].items():
            path = ROOT / relative
            self.assertTrue(path.is_file(), relative)
            self.assertEqual(git_blob_sha(path), expected, relative)

    def test_dashboard_schema_is_fail_closed(self) -> None:
        defs = self.schema["$defs"]
        self.assertEqual(
            set(defs["AuthMethod"]["enum"]),
            {
                "jwt",
                "oidc",
                "webauthn",
                "totp",
                "kerberos",
                "ssh",
                "openpgp",
                "platform_biometric",
                "recovery",
            },
        )
        query = defs["DashboardQuery"]["properties"]
        self.assertIn("organizationId", defs["DashboardQuery"]["required"])
        self.assertEqual(query["limit"]["maximum"], 200)
        response = defs["DashboardResponse"]["properties"]
        scope = response["scope"]["properties"]
        self.assertIs(scope["exactMembershipRequired"]["const"], True)
        self.assertIs(scope["crossOrganizationFallbackAllowed"]["const"], False)
        for rule in response["redaction"]["properties"].values():
            self.assertIs(rule["const"], False)
        capability = defs["CredentialCapabilityProjection"]
        for field in (
            "productionEnabled",
            "requiresOnlineIntrospection",
            "roleClaimsAuthoritative",
            "rawBiometricMaterialPresent",
            "evidence",
        ):
            self.assertIn(field, capability["required"])

    def test_example_preserves_capability_truth(self) -> None:
        self.assertIs(self.example["scope"]["exactMembershipRequired"], True)
        self.assertIs(self.example["scope"]["crossOrganizationFallbackAllowed"], False)
        self.assertTrue(all(value is False for value in self.example["redaction"].values()))
        by_method = {item["method"]: item for item in self.example["capabilities"]}

        ssh = by_method["ssh"]
        self.assertIs(ssh["productionEnabled"], False)
        self.assertIs(ssh["requiresOnlineIntrospection"], True)
        self.assertIn(ssh["maximumAssurance"], {"aal0", "aal1"})
        self.assertIs(ssh["roleClaimsAuthoritative"], False)

        openpgp = by_method["openpgp"]
        self.assertEqual(openpgp["authority"], "provenance_only")
        self.assertIs(openpgp["tokenMintingAllowed"], False)
        self.assertEqual(openpgp["maximumAssurance"], "aal0")

        biometric = by_method["platform_biometric"]
        self.assertEqual(biometric["authority"], "step_up")
        self.assertEqual(biometric["retention"], "none")
        self.assertIs(biometric["rawBiometricMaterialPresent"], False)

    def test_core_runtime_uses_online_introspection_and_ores_logger(self) -> None:
        dependencies = self.runtime["dependencies"]
        self.assertEqual(dependencies["interfaces"], "ores-otel/ores-interfaces")
        self.assertEqual(dependencies["core"], "ores-otel/ores-lib-core")
        self.assertEqual(dependencies["loggerPackage"], "oresoftware/next-loggers")
        self.assertEqual(dependencies["loggerRepository"], "ores-otel/ores.otel.log")

        authorization = self.runtime["authorization"]
        self.assertIs(authorization["requiresOnlineIntrospection"], True)
        self.assertIs(authorization["exactAudienceRequired"], True)
        self.assertIs(authorization["exactOrganizationMembershipRequired"], True)
        self.assertIs(authorization["crossOrganizationFallbackAllowed"], False)
        self.assertIs(authorization["productRoleClaimsAuthoritative"], False)
        self.assertIs(authorization["directAuthDatabaseAccessAllowed"], False)

        pagination = self.runtime["pagination"]
        self.assertLessEqual(pagination["defaultLimit"], pagination["maximumLimit"])
        self.assertEqual(pagination["maximumLimit"], 200)
        self.assertIs(pagination["cursorOpaque"], True)
        self.assertIs(pagination["offsetPaginationAllowed"], False)

        logging = self.runtime["logging"]
        self.assertIs(logging["globalProviderInstallationAllowed"], False)
        for field in (
            "highCardinalityIdentityLabelsAllowed",
            "bearerTokensAllowed",
            "cookiesAllowed",
            "privateKeysAllowed",
            "totpSeedsAllowed",
            "rawBiometricMaterialAllowed",
        ):
            self.assertIs(logging[field], False)

        methods = self.runtime["authenticationCapabilities"]
        self.assertIs(methods["candidateOrContractAdvertisedAsEnabledAllowed"], False)
        self.assertIs(methods["sshRequiresOnlineIntrospection"], True)
        self.assertIs(methods["kerberosRequiresOnlineIntrospection"], True)
        self.assertEqual(methods["openpgpAuthority"], "provenance_only")
        self.assertIs(methods["rawBiometricRetentionAllowed"], False)

    def test_astro_handoff_is_static_and_fail_closed(self) -> None:
        package = read_json(SITE / "package.json")
        self.assertEqual(package["dependencies"], {"astro": "^5.13.2"})
        self.assertEqual(package["scripts"]["build"], "astro build")
        self.assertTrue((SITE / "public/.nojekyll").is_file())
        for forbidden in ("_config.yml", "Gemfile", "config.toml", "hugo.toml"):
            self.assertFalse((SITE / forbidden).exists())

        dashboard = (SITE / "src/pages/dashboard.astro").read_text(encoding="utf-8")
        self.assertIn("PUBLIC_DASHBOARD_URL", dashboard)
        self.assertIn('parsed.protocol !== "https:"', dashboard)
        self.assertIn("parsed.username || parsed.password", dashboard)
        self.assertIn("Dashboard endpoint pending", dashboard)
        self.assertIn("No implicit cross-organization fallback", dashboard)
        self.assertNotIn("Authorization: Bearer", dashboard)

        cta = (SITE / "src/components/DashboardCta.astro").read_text(encoding="utf-8")
        self.assertIn("Users · sessions · roles", cta)
        self.assertIn('href = "/dashboard/"', cta)

    def test_fixture_tree_contains_no_credential_shapes(self) -> None:
        credential = re.compile(
            r"gh[pousr]_[A-Za-z0-9]{20,}|lin_api_[A-Za-z0-9]{20,}|"
            r"BEGIN [A-Z ]*PRIVATE KEY"
        )
        for root in (SITE, FIXTURES):
            for path in root.rglob("*"):
                if path.is_file():
                    text = path.read_text(encoding="utf-8", errors="ignore")
                    self.assertIsNone(credential.search(text), str(path.relative_to(ROOT)))


if __name__ == "__main__":
    unittest.main()
