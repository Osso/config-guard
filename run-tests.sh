#!/usr/bin/env bash
set -euo pipefail

cargo fmt -- --check
cargo test
cargo check

if command -v readability-audit >/dev/null 2>&1; then
  readability-audit . --exclude target
fi
