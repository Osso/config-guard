#!/usr/bin/env bash
set -euo pipefail

cargo fmt -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked

if command -v readability-audit >/dev/null 2>&1; then
  readability-audit . --exclude target
fi
