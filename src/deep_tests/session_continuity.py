from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Mapping
from urllib.parse import urlsplit

STATUS_SCHEMA = "shared-auth.consumer-status.v1"
RENEWAL_INTERVAL_SECONDS = 50 * 60
CACHE_GRACE_SECONDS = 30


class SessionState(StrEnum):
    ANONYMOUS = "anonymous"
    AUTHENTICATED = "authenticated"


class PublicStateLeak(ValueError):
    pass


@dataclass(frozen=True)
class ConsumerConfig:
    name: str
    tenant: str
    dashboard_url: str
    required_assurance: int = 1

    def __post_init__(self) -> None:
        parsed = urlsplit(self.dashboard_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("dashboard URL must be absolute HTTPS")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("dashboard URL must not contain credentials, query, or fragment")
        if self.required_assurance < 1:
            raise ValueError("required assurance must be positive")


@dataclass(frozen=True)
class SessionRecord:
    internal_key: str
    tenant: str
    issued_at: int
    expires_at: int
    assurance: int
    generation: int = 1
    revoked: bool = False
    sandboxed: bool = False

    def __post_init__(self) -> None:
        if not self.internal_key:
            raise ValueError("internal session key is required")
        if self.expires_at <= self.issued_at:
            raise ValueError("session expiry must follow issuance")
        if self.assurance < 1 or self.generation < 1:
            raise ValueError("assurance and generation must be positive")


@dataclass(frozen=True)
class PublicStatus:
    state: SessionState
    action: str
    dashboard_url: str | None
    renewal_due_at: int | None
    observed_at: int
    session_generation: int
    fresh: bool = True

    def payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema": STATUS_SCHEMA,
            "state": self.state.value,
            "action": self.action,
            "dashboard_url": self.dashboard_url,
            "renewal_due_at": self.renewal_due_at,
            "observed_at": self.observed_at,
            "session_generation": self.session_generation,
            "fresh": self.fresh,
        }
        validate_public_payload(payload)
        return payload

    def canonical_json(self) -> str:
        return json.dumps(self.payload(), sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class CachedStatus:
    status: PublicStatus
    cached_at: int


class SessionAuthority:
    def __init__(self, session_lifetime_seconds: int = 60 * 60) -> None:
        if session_lifetime_seconds <= RENEWAL_INTERVAL_SECONDS:
            raise ValueError("session lifetime must exceed the renewal interval")
        self._session_lifetime_seconds = session_lifetime_seconds
        self._records: dict[str, SessionRecord] = {}

    def register(self, record: SessionRecord) -> None:
        if record.internal_key in self._records:
            raise ValueError("session key already exists")
        self._records[record.internal_key] = record

    def _valid_record(
        self,
        internal_key: str | None,
        consumer: ConsumerConfig,
        now: int,
    ) -> SessionRecord | None:
        if internal_key is None:
            return None
        record = self._records.get(internal_key)
        if record is None:
            return None
        if (
            record.revoked
            or record.sandboxed
            or record.expires_at <= now
            or record.tenant != consumer.tenant
            or record.assurance < consumer.required_assurance
        ):
            return None
        return record

    def status(
        self,
        internal_key: str | None,
        consumer: ConsumerConfig,
        now: int,
    ) -> PublicStatus:
        record = self._valid_record(internal_key, consumer, now)
        if record is None:
            return PublicStatus(
                state=SessionState.ANONYMOUS,
                action="login_signup",
                dashboard_url=None,
                renewal_due_at=None,
                observed_at=now,
                session_generation=0,
            )
        return PublicStatus(
            state=SessionState.AUTHENTICATED,
            action="user_dashboard",
            dashboard_url=consumer.dashboard_url,
            renewal_due_at=min(
                record.issued_at + RENEWAL_INTERVAL_SECONDS,
                record.expires_at,
            ),
            observed_at=now,
            session_generation=record.generation,
        )

    def renew(
        self,
        internal_key: str,
        consumer: ConsumerConfig,
        now: int,
    ) -> PublicStatus:
        record = self._valid_record(internal_key, consumer, now)
        if record is None:
            return self.status(None, consumer, now)
        if now >= record.issued_at + RENEWAL_INTERVAL_SECONDS:
            record = replace(
                record,
                issued_at=now,
                expires_at=now + self._session_lifetime_seconds,
                generation=record.generation + 1,
            )
            self._records[internal_key] = record
        return self.status(internal_key, consumer, now)

    def logout(self, internal_key: str) -> None:
        record = self._records.get(internal_key)
        if record is not None and not record.revoked:
            self._records[internal_key] = replace(
                record,
                revoked=True,
                generation=record.generation + 1,
            )


_ALLOWED_PUBLIC_FIELDS = frozenset(
    {
        "schema",
        "state",
        "action",
        "dashboard_url",
        "renewal_due_at",
        "observed_at",
        "session_generation",
        "fresh",
    }
)
_SENSITIVE_KEY_PARTS = (
    "access_token",
    "authorization",
    "cookie",
    "email",
    "phone",
    "provider",
    "refresh_token",
    "secret",
    "session_id",
    "sid",
    "subject",
    "token",
)
_SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"(?i)\bbearer\s+\S+"),
    re.compile(r"\b[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(?:access_token|refresh_token|signature|x-amz-signature)="),
)


def _walk(value: object, path: str = "$") -> list[tuple[str, object]]:
    items = [(path, value)]
    if isinstance(value, Mapping):
        for key, child in value.items():
            items.extend(_walk(child, f"{path}.{key}"))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            items.extend(_walk(child, f"{path}[{index}]"))
    return items


def validate_public_payload(payload: Mapping[str, object]) -> None:
    fields = frozenset(payload)
    if fields != _ALLOWED_PUBLIC_FIELDS:
        extra = sorted(fields - _ALLOWED_PUBLIC_FIELDS)
        missing = sorted(_ALLOWED_PUBLIC_FIELDS - fields)
        raise PublicStateLeak(f"unexpected public fields: extra={extra}, missing={missing}")

    for path, value in _walk(payload):
        lowered_path = path.lower()
        if any(part in lowered_path for part in _SENSITIVE_KEY_PARTS):
            raise PublicStateLeak(f"sensitive field at {path}")
        if isinstance(value, str) and any(pattern.search(value) for pattern in _SENSITIVE_VALUE_PATTERNS):
            raise PublicStateLeak(f"sensitive value at {path}")

    state = payload["state"]
    action = payload["action"]
    dashboard_url = payload["dashboard_url"]
    renewal_due_at = payload["renewal_due_at"]
    generation = payload["session_generation"]
    if state == SessionState.ANONYMOUS.value:
        if action != "login_signup" or dashboard_url is not None or renewal_due_at is not None or generation != 0:
            raise ValueError("anonymous status contains authenticated presentation state")
    elif state == SessionState.AUTHENTICATED.value:
        if action != "user_dashboard" or not isinstance(dashboard_url, str):
            raise ValueError("authenticated status is incomplete")
        parsed = urlsplit(dashboard_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment:
            raise ValueError("dashboard URL is not a safe HTTPS presentation URL")
        if not isinstance(renewal_due_at, int) or not isinstance(generation, int) or generation < 1:
            raise ValueError("authenticated renewal metadata is invalid")
    else:
        raise ValueError("unknown public session state")


def render_account_actions(
    network_status: PublicStatus | None,
    cached_status: CachedStatus | None,
    now: int,
) -> tuple[str, ...]:
    if network_status is not None:
        return (
            ("user_dashboard",)
            if network_status.state is SessionState.AUTHENTICATED
            else ("log_in", "sign_up")
        )
    if (
        cached_status is not None
        and cached_status.status.state is SessionState.AUTHENTICATED
        and 0 <= now - cached_status.cached_at <= CACHE_GRACE_SECONDS
    ):
        return ("user_dashboard",)
    return ("log_in", "sign_up")


def public_status_authorizes_product_access(_status: PublicStatus) -> bool:
    """Presentation state is deliberately never an authorization credential."""

    return False
