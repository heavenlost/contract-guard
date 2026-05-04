#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

case "${1:-}" in
  smoke)
    python3 -m compileall -q src tests scripts
    PYTHONPATH=src python3 tests/smoke_cli_contract.py
    PYTHONPATH=src python3 -m contract_guard_ci.cli plan --repo . --json >/tmp/contract_guard_plan.json
    PYTHONPATH=src python3 -m contract_guard_ci.cli scan --repo . --skip-foundry --skip-slither --format json >/tmp/contract_guard_scan.json
    PYTHONPATH=src python3 -m contract_guard_ci.cli scan --repo . --skip-foundry --skip-slither --format markdown >/tmp/contract_guard_scan.md
    PYTHONPATH=src python3 -m contract_guard_ci.cli scan --repo . --skip-foundry --skip-slither --format sarif >/tmp/contract_guard_scan.sarif
    PYTHONPATH=src python3 -m contract_guard_ci.cli dogfood-readiness --format json >/tmp/contract_guard_dogfood_readiness.json
    ;;
  *)
    echo "usage: $0 {smoke}" >&2
    exit 2
    ;;
esac
