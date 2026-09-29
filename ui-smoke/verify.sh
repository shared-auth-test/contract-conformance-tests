#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

(cd "$root/ts" && npm install --ignore-scripts --no-audit --no-fund && npm run build)
(cd "$root/rust" && rustup target add wasm32-unknown-unknown && cargo build --target wasm32-unknown-unknown)

if command -v flutter >/dev/null; then
  (cd "$root/flutter" && flutter pub get && flutter analyze)
else
  echo "flutter not installed; skipping Flutter analyzer" >&2
fi
