# Token-blind consumer session continuity

Tracking: [DEN-3424](https://linear.app/denman/issue/DEN-3424/shared-auth-test-prove-token-blind-consumer-session-continuity-and)

This suite models the boundary between a Shared Auth authority, product-specific browser-facing backends, and static marketing UI. It is intentionally synthetic and network-free.

## Invariants

* A public status response contains presentation state only. It cannot carry an access token, refresh token, cookie value, provider identity, subject, email, phone number, service credential, or authorization decision.
* Anonymous state renders **Log in** and **Sign up**. Authenticated state renders one **User dashboard** action with a validated HTTPS destination.
* Renewal becomes due exactly 50 minutes after issuance. Renewal rotates an internal generation, but no credential enters the public response.
* Expired, revoked, sandboxed, cross-tenant, and insufficient-assurance sessions fail closed to anonymous presentation state.
* Logout at the authority is visible to every consumer on its next status check.
* A cached authenticated presentation may survive a network failure for at most 30 seconds. Cached or fresh public presentation state never authorizes product access.
* Serialization is canonical and the validator rejects unexpected fields and token-like values.

## Run

```bash
PYTHONPATH=src python -m unittest tests.test_session_continuity -v
```

Product adapters should map their same-origin status endpoint into this model while retaining server-side authorization as a separate, authoritative guard.
