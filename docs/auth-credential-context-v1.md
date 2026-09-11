# ORE credential-context consumer oracle

This independent test-org oracle freezes the v1 wire vocabulary expected from `ORESoftware/ores-interfaces` and the fail-closed authority rules expected from `ORESoftware/ores-lib-core`.

It does not make the not-yet-created repositories real, and it does not substitute for compiling their Rust, TypeScript, Go, Python, and Dart bindings. It gives every consumer language the same exact six wire values and rejects semantic drift before those repositories are promoted.

The oracle enforces:

- SSH and Kerberos are opaque, online-introspected, role-free, non-delegable LOA1 data-plane credentials;
- their scopes cannot enter the Shared Auth control plane;
- OpenPGP is provenance only;
- external biometric recovery evidence is not an access credential;
- face/thumbprint login remains platform WebAuthn user verification without modality disclosure;
- raw or derived face, fingerprint, voice, and government-ID material is rejected recursively;
- unknown fields, duplicate entries, case-normalized scopes, and mismatched AAL/ACR fail closed.
