from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping


class ContractViolation(ValueError):
    """Raised when a credential context violates the shared wire contract."""


CREDENTIAL_KINDS = frozenset(
    {
        "interactive_jwt",
        "webauthn",
        "ssh_key",
        "kerberos",
        "openpgp_provenance",
        "external_biometric_recovery",
    }
)

REQUIRED_FIELDS = frozenset(
    {
        "version",
        "credential_kind",
        "subject",
        "audience",
        "scopes",
        "roles",
        "aal",
        "acr",
        "amr",
        "auth_time",
        "opaque",
        "delegable",
        "local_verification_supported",
    }
)

CONTROL_PLANE_SCOPE_PREFIXES = (
    "auth:credentials:",
    "auth:factors:",
    "auth:recovery:",
    "auth:roles:",
    "auth:realms:",
    "auth:delegate",
)

RAW_BIOMETRIC_FIELDS = frozenset(
    {
        "face_image",
        "face_frame",
        "face_template",
        "face_embedding",
        "fingerprint_image",
        "fingerprint_template",
        "thumbprint_template",
        "voice_audio",
        "voiceprint",
        "speaker_embedding",
        "government_id_image",
    }
)

_SCOPE_RE = re.compile(
    r"^[a-z0-9][a-z0-9_.-]{0,63}(?::[a-z0-9][a-z0-9_.-]{0,63})+$"
)


def _string_tuple(value: Any, field: str, *, max_items: int) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > max_items:
        raise ContractViolation(f"{field} must be an array with at most {max_items} entries")
    if not all(isinstance(item, str) and item for item in value):
        raise ContractViolation(f"{field} entries must be non-empty strings")
    if len(set(value)) != len(value):
        raise ContractViolation(f"{field} entries must be unique")
    return tuple(value)


def reject_raw_biometric_material(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = str(key).strip().lower()
            if normalized in RAW_BIOMETRIC_FIELDS:
                raise ContractViolation(f"raw biometric field is forbidden: {normalized}")
            reject_raw_biometric_material(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            reject_raw_biometric_material(nested)


@dataclass(frozen=True)
class CredentialContextV1:
    credential_kind: str
    subject: str
    audience: str
    scopes: tuple[str, ...]
    roles: tuple[str, ...]
    aal: int
    acr: str
    amr: tuple[str, ...]
    auth_time: int | None
    opaque: bool
    delegable: bool
    local_verification_supported: bool

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CredentialContextV1":
        reject_raw_biometric_material(value)
        fields = frozenset(value)
        if fields != REQUIRED_FIELDS:
            missing = sorted(REQUIRED_FIELDS - fields)
            extra = sorted(fields - REQUIRED_FIELDS)
            raise ContractViolation(f"field mismatch: missing={missing}, extra={extra}")
        if value["version"] != 1:
            raise ContractViolation("version must be 1")
        kind = value["credential_kind"]
        if kind not in CREDENTIAL_KINDS:
            raise ContractViolation("unknown credential_kind")
        subject = value["subject"]
        audience = value["audience"]
        if not isinstance(subject, str) or not (1 <= len(subject) <= 255):
            raise ContractViolation("subject length is invalid")
        if not isinstance(audience, str) or not (1 <= len(audience) <= 128):
            raise ContractViolation("audience length is invalid")
        scopes = _string_tuple(value["scopes"], "scopes", max_items=64)
        if any(_SCOPE_RE.fullmatch(scope) is None for scope in scopes):
            raise ContractViolation("scope wire format is invalid")
        roles = _string_tuple(value["roles"], "roles", max_items=32)
        amr = _string_tuple(value["amr"], "amr", max_items=8)
        if not amr:
            raise ContractViolation("amr must not be empty")
        aal = value["aal"]
        if aal not in {1, 2}:
            raise ContractViolation("aal must be 1 or 2")
        acr = value["acr"]
        if acr != f"urn:oresoftware:loa:{aal}":
            raise ContractViolation("acr must agree with aal")
        auth_time = value["auth_time"]
        if auth_time is not None and (not isinstance(auth_time, int) or auth_time < 0):
            raise ContractViolation("auth_time must be a non-negative integer or null")
        for boolean_field in ("opaque", "delegable", "local_verification_supported"):
            if not isinstance(value[boolean_field], bool):
                raise ContractViolation(f"{boolean_field} must be boolean")

        context = cls(
            credential_kind=kind,
            subject=subject,
            audience=audience,
            scopes=scopes,
            roles=roles,
            aal=aal,
            acr=acr,
            amr=amr,
            auth_time=auth_time,
            opaque=value["opaque"],
            delegable=value["delegable"],
            local_verification_supported=value["local_verification_supported"],
        )
        context.validate_authority_boundary()
        return context

    def validate_authority_boundary(self) -> None:
        if self.credential_kind in {"ssh_key", "kerberos"}:
            expected_amr = "ssh_key" if self.credential_kind == "ssh_key" else "krb"
            if self.aal != 1 or self.acr != "urn:oresoftware:loa:1":
                raise ContractViolation("sandbox credentials are fixed at LOA1")
            if self.roles or self.auth_time is not None:
                raise ContractViolation("sandbox credentials have no roles or auth_time")
            if not self.opaque or self.delegable or self.local_verification_supported:
                raise ContractViolation("sandbox credentials require opaque online introspection")
            if self.amr != (expected_amr,):
                raise ContractViolation("sandbox credential amr is invalid")
            if any(scope.startswith(CONTROL_PLANE_SCOPE_PREFIXES) for scope in self.scopes):
                raise ContractViolation("sandbox credentials cannot carry control-plane scopes")

        if self.credential_kind in {
            "openpgp_provenance",
            "external_biometric_recovery",
        }:
            if self.scopes or self.roles or self.delegable:
                raise ContractViolation("non-authorizing evidence cannot carry authority")
            if self.auth_time is not None:
                raise ContractViolation("non-authorizing evidence has no auth_time")

        if self.credential_kind == "webauthn":
            if self.aal != 2 or "user_verification" not in self.amr:
                raise ContractViolation("WebAuthn login requires verified AAL2")

    def canonical_json(self) -> str:
        return json.dumps(
            {
                "version": 1,
                "credential_kind": self.credential_kind,
                "subject": self.subject,
                "audience": self.audience,
                "scopes": list(self.scopes),
                "roles": list(self.roles),
                "aal": self.aal,
                "acr": self.acr,
                "amr": list(self.amr),
                "auth_time": self.auth_time,
                "opaque": self.opaque,
                "delegable": self.delegable,
                "local_verification_supported": self.local_verification_supported,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
