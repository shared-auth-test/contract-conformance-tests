import json
import unittest

from deep_tests.session_continuity import (
    CACHE_GRACE_SECONDS,
    RENEWAL_INTERVAL_SECONDS,
    CachedStatus,
    ConsumerConfig,
    PublicStateLeak,
    SessionAuthority,
    SessionRecord,
    SessionState,
    public_status_authorizes_product_access,
    render_account_actions,
    validate_public_payload,
)


class SessionContinuityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 1_900_000_000
        self.consumer_a = ConsumerConfig(
            name="product-a",
            tenant="tenant-a",
            dashboard_url="https://app-a.example.test/dashboard",
            required_assurance=2,
        )
        self.consumer_b = ConsumerConfig(
            name="product-b",
            tenant="tenant-a",
            dashboard_url="https://app-b.example.test/dashboard",
            required_assurance=2,
        )
        self.authority = SessionAuthority(session_lifetime_seconds=7_200)
        self.authority.register(
            SessionRecord(
                internal_key="synthetic-session-key",
                tenant="tenant-a",
                issued_at=self.now,
                expires_at=self.now + 7_200,
                assurance=2,
            )
        )

    def test_status_is_token_blind_and_has_exact_presentation_fields(self) -> None:
        status = self.authority.status("synthetic-session-key", self.consumer_a, self.now)
        payload = status.payload()
        self.assertEqual(status.state, SessionState.AUTHENTICATED)
        self.assertEqual(
            set(payload),
            {
                "schema",
                "state",
                "action",
                "dashboard_url",
                "renewal_due_at",
                "observed_at",
                "session_generation",
                "fresh",
            },
        )
        serialized = status.canonical_json()
        self.assertNotIn("synthetic-session-key", serialized)
        self.assertNotIn("tenant-a", serialized)
        self.assertEqual(json.loads(serialized), payload)
        self.assertFalse(public_status_authorizes_product_access(status))

    def test_renewal_rotates_at_exact_fifty_minute_boundary(self) -> None:
        before = self.authority.renew(
            "synthetic-session-key",
            self.consumer_a,
            self.now + RENEWAL_INTERVAL_SECONDS - 1,
        )
        at_boundary = self.authority.renew(
            "synthetic-session-key",
            self.consumer_a,
            self.now + RENEWAL_INTERVAL_SECONDS,
        )
        after = self.authority.status(
            "synthetic-session-key",
            self.consumer_b,
            self.now + RENEWAL_INTERVAL_SECONDS,
        )
        self.assertEqual(before.session_generation, 1)
        self.assertEqual(at_boundary.session_generation, 2)
        self.assertEqual(after.session_generation, 2)
        self.assertEqual(
            at_boundary.renewal_due_at,
            self.now + 2 * RENEWAL_INTERVAL_SECONDS,
        )

    def test_logout_in_one_consumer_propagates_to_every_consumer(self) -> None:
        cached = CachedStatus(
            self.authority.status("synthetic-session-key", self.consumer_b, self.now),
            cached_at=self.now,
        )
        self.authority.logout("synthetic-session-key")
        status_a = self.authority.status("synthetic-session-key", self.consumer_a, self.now + 1)
        status_b = self.authority.status("synthetic-session-key", self.consumer_b, self.now + 1)
        self.assertEqual(status_a.state, SessionState.ANONYMOUS)
        self.assertEqual(status_b.state, SessionState.ANONYMOUS)
        self.assertEqual(render_account_actions(status_b, cached, self.now + 1), ("log_in", "sign_up"))

    def test_expired_cross_tenant_low_assurance_and_sandboxed_fail_closed(self) -> None:
        cases = (
            SessionRecord("expired", "tenant-a", self.now - 10, self.now, 2),
            SessionRecord("cross-tenant", "tenant-b", self.now, self.now + 7_200, 2),
            SessionRecord("low-assurance", "tenant-a", self.now, self.now + 7_200, 1),
            SessionRecord("sandboxed", "tenant-a", self.now, self.now + 7_200, 2, sandboxed=True),
            SessionRecord("revoked", "tenant-a", self.now, self.now + 7_200, 2, revoked=True),
        )
        for record in cases:
            with self.subTest(record=record.internal_key):
                authority = SessionAuthority(session_lifetime_seconds=7_200)
                authority.register(record)
                status = authority.status(record.internal_key, self.consumer_a, self.now)
                self.assertEqual(status.state, SessionState.ANONYMOUS)
                self.assertEqual(status.payload()["session_generation"], 0)

    def test_network_loss_uses_only_a_bounded_non_authoritative_ui_grace(self) -> None:
        status = self.authority.status("synthetic-session-key", self.consumer_a, self.now)
        cached = CachedStatus(status=status, cached_at=self.now)
        self.assertEqual(
            render_account_actions(None, cached, self.now + CACHE_GRACE_SECONDS),
            ("user_dashboard",),
        )
        self.assertEqual(
            render_account_actions(None, cached, self.now + CACHE_GRACE_SECONDS + 1),
            ("log_in", "sign_up"),
        )
        self.assertFalse(public_status_authorizes_product_access(cached.status))

    def test_public_payload_validator_rejects_secret_fields_and_token_shapes(self) -> None:
        valid = self.authority.status("synthetic-session-key", self.consumer_a, self.now).payload()
        for key, value in (
            ("access_token", "synthetic-value"),
            ("cookie", "synthetic-value"),
            ("email", "person@example.test"),
        ):
            with self.subTest(key=key):
                leaked = dict(valid)
                leaked[key] = value
                with self.assertRaises(PublicStateLeak):
                    validate_public_payload(leaked)

        bearer = dict(valid)
        bearer["dashboard_url"] = "Bearer synthetic-secret-value"
        with self.assertRaises(PublicStateLeak):
            validate_public_payload(bearer)

        jwt = dict(valid)
        jwt["dashboard_url"] = "aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc"
        with self.assertRaises(PublicStateLeak):
            validate_public_payload(jwt)

    def test_anonymous_status_is_minimal_and_deterministic(self) -> None:
        first = self.authority.status(None, self.consumer_a, self.now)
        second = self.authority.status("missing", self.consumer_a, self.now)
        self.assertEqual(first.canonical_json(), second.canonical_json())
        self.assertEqual(render_account_actions(first, None, self.now), ("log_in", "sign_up"))


if __name__ == "__main__":
    unittest.main()
