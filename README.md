# shared-auth-test/contract-conformance-tests

Deterministic state-model, idempotency, serialization, and protocol contract conformance tests.

This repository is the `contract` deep-test suite for `shared-auth`. It is intentionally dependency-light and deterministic so failures can be reproduced locally without production credentials or customer data.

## Run

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/verify_repository.py
```

## Contract slices

* The original reference store proves deterministic replay, canonical serialization, tombstones, and idempotency conflict handling.
* [`docs/session-continuity-contract.md`](docs/session-continuity-contract.md) proves token-blind account presentation, the 50-minute renewal boundary, cross-consumer logout propagation, fail-closed tenant/assurance/session checks, bounded offline UI grace, and public-state leak rejection.

Product adapters should be added through focused pull requests while preserving the reference-model tests as an oracle. Public status responses are presentation hints only and must never become product authorization credentials.

Tracking: https://github.com/ORESoftware/ai-agent-coordinator.rs/issues/139
