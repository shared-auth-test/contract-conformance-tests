# TJSV external peer-authority conformance

Tracking: DEN-3959 / ORESoftware/ores-cli#196.

The TypeSpec and Draft 2020-12 JSON Schema files here are independently authored first-class authorities. CI transpiles TypeSpec to disposable Schema B comparison evidence and compares it against the authored JSON Schema through pinned TJSV. Contract IR and consumer verification are downstream evidence only.

Two negative controls mutate scratch copies one lane at a time. TypeSpec-only drift and JSON-Schema-only drift must each stop parity, proving neither source is merely derivative of the other.
