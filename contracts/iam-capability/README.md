# Shared Auth IAM capability contract canary

This subtree is an independent test contract for the IAM/CIAM capability catalog.

- `main.tsp` is independently authored TypeSpec.
- `authored.schema.json` is independently authored JSON Schema Draft 2020-12.
- TypeSpec is transpiled to a separate generated JSON Schema B only for comparison.
- `instances/` is a third, independently maintained valid/invalid behavioral corpus.
- parity receipts, Contract IR, generated Schema B, SARIF, and consumer verification receipts are derived evidence and are never editable authorities.

The workflow stops evaluation on any structural or behavioral disagreement and proves both JSON-Schema-side enum drift and TypeSpec-side requiredness drift are rejected.
