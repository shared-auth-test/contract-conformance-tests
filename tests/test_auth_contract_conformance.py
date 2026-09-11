import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from deep_tests.auth_contract import (  # noqa: E402
    CREDENTIAL_KINDS,
    ContractViolation,
    CredentialContextV1,
    reject_raw_biometric_material,
)


class AuthContractConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(
            (ROOT / "fixtures/auth/credential-context-v1.cases.json").read_text()
        )

    def test_every_language_binding_has_the_exact_wire_value_set(self) -> None:
        expected = set(self.fixture["wire_values"])
        self.assertEqual(expected, set(CREDENTIAL_KINDS))
        self.assertEqual(
            {"rust", "typescript", "go", "python", "dart"},
            set(self.fixture["language_bindings"]),
        )
        for language, bindings in self.fixture["language_bindings"].items():
            with self.subTest(language=language):
                self.assertEqual(expected, set(bindings.values()))
                self.assertEqual(len(expected), len(bindings))

    def test_valid_cross_language_cases_round_trip_canonically(self) -> None:
        for value in self.fixture["valid"]:
            with self.subTest(kind=value["credential_kind"]):
                context = CredentialContextV1.from_mapping(value)
                self.assertEqual(
                    context,
                    CredentialContextV1.from_mapping(json.loads(context.canonical_json())),
                )

    def test_negative_authority_mutations_fail_closed(self) -> None:
        for mutation in self.fixture["invalid_mutations"]:
            value = copy.deepcopy(self.fixture["valid"][mutation["case"]])
            value.update(mutation["set"])
            with self.subTest(kind=value["credential_kind"], set=mutation["set"]):
                with self.assertRaises(ContractViolation):
                    CredentialContextV1.from_mapping(value)

    def test_unknown_or_extra_fields_are_rejected(self) -> None:
        value = copy.deepcopy(self.fixture["valid"][0])
        value["credential_kind"] = "passwordless_magic"
        with self.assertRaises(ContractViolation):
            CredentialContextV1.from_mapping(value)
        value = copy.deepcopy(self.fixture["valid"][0])
        value["biometric_modality"] = "face"
        with self.assertRaises(ContractViolation):
            CredentialContextV1.from_mapping(value)

    def test_raw_and_derived_biometric_material_is_rejected_recursively(self) -> None:
        reject_raw_biometric_material(
            {
                "provider_reference": "opaque-reference",
                "verdict": "pass",
                "confidence_band": "high",
            }
        )
        for field in (
            "face_image",
            "face_template",
            "face_embedding",
            "fingerprint_template",
            "thumbprint_template",
            "voice_audio",
            "voiceprint",
            "government_id_image",
        ):
            with self.subTest(field=field), self.assertRaises(ContractViolation):
                reject_raw_biometric_material({"nested": [{field: "forbidden"}]})

    def test_webauthn_carries_verification_result_not_biometric_modality(self) -> None:
        value = copy.deepcopy(self.fixture["valid"][0])
        context = CredentialContextV1.from_mapping(value)
        self.assertIn("user_verification", context.amr)
        self.assertNotIn("face", context.canonical_json().lower())
        self.assertNotIn("thumb", context.canonical_json().lower())
        value["aal"] = 1
        value["acr"] = "urn:oresoftware:loa:1"
        with self.assertRaises(ContractViolation):
            CredentialContextV1.from_mapping(value)

    def test_scope_and_list_normalization_is_not_silent(self) -> None:
        for replacement in (
            ["repo:read", "repo:read"],
            ["Repo:Read"],
            ["repo"],
        ):
            value = copy.deepcopy(self.fixture["valid"][1])
            value["scopes"] = replacement
            with self.subTest(scopes=replacement), self.assertRaises(ContractViolation):
                CredentialContextV1.from_mapping(value)


if __name__ == "__main__":
    unittest.main()
