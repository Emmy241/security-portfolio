#!/usr/bin/env bash
# infra/checks/no-pool-in-repos.sh
# CI check: repositories must use req.withTenant, not req.pool directly.
# Catches V-32 pattern before it returns.

set -euo pipefail

fail=0

for dir in target-app/src/repositories target-app/src/admin target-app/src/money; do
  [ -d "$dir" ] || continue

  if grep -rnF 'req.pool.query' "$dir" 2>/dev/null; then
    echo "FAIL: $dir uses req.pool.query directly (must use req.withTenant)" >&2
    fail=1
  fi

  if grep -rnE "require\(['\"]\.\./db['\"]\)" "$dir" 2>/dev/null; then
    echo "FAIL: $dir imports db pool directly (must use req.withTenant)" >&2
    fail=1
  fi
done

if [ "$fail" -eq 1 ]; then
  exit 1
fi

echo "PASS: no direct pool.query in repositories"
