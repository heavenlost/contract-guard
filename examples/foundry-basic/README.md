# Foundry basic example fixture

This fixture is a dependency-free Foundry-style Solidity project for beta packaging checks.

It deliberately avoids `forge-std`, external package downloads, live fuzzers, hosted uploads, and live AI provider calls. The Solidity code is a toy access-controlled counter, not a protocol, wallet, payment flow, token, vault, or custody component.

## Layout

```text
foundry.toml
src/GuardedCounter.sol
test/GuardedCounterInvariant.t.sol
.contract-guard-policy.json
.contract-guard-baseline.json
```

## Contract Guard dry run

From the Contract Guard CI repository root:

```bash
PYTHONPATH=src python3 -m contract_guard_ci.cli plan --repo examples/foundry-basic --json
PYTHONPATH=src python3 -m contract_guard_ci.cli policy --repo examples/foundry-basic --policy-file .contract-guard-policy.json --format markdown
PYTHONPATH=src python3 -m contract_guard_ci.cli scan --repo examples/foundry-basic --skip-foundry --skip-slither --baseline-file .contract-guard-baseline.json --format markdown
PYTHONPATH=src python3 -m contract_guard_ci.cli scan --repo examples/foundry-basic --skip-foundry --skip-slither --baseline-file .contract-guard-baseline.json --format sarif
```

The skip flags make the fixture safe for CI packaging environments where Foundry or Slither are not installed yet. They are explicit so beta users can distinguish packaging smoke from real deterministic analysis.

## Real deterministic tools

When Foundry and Slither are installed, beta users can run the same project without skip flags:

```bash
cd examples/foundry-basic
forge test
slither . --json -
contract-guard scan --repo . --baseline-file .contract-guard-baseline.json --format json
```

Real tool behavior should be treated as deterministic evidence. Optional AI explanation, if used later, must remain separate and advisory-only.

## Baseline and policy behavior

The fixture includes:

- `.contract-guard-policy.json` with local-only defaults, no hosted uploads, no private snippet upload, no live AI provider calls, and raw stdout/stderr excluded from reports.
- `.contract-guard-baseline.json` with a sample non-high suppression shape. It is present to exercise baseline loading and review workflow only; high-severity findings are never suppressed.

This fixture is for packaging and onboarding only. It does not prove that a protocol is safe and does not replace a human audit.
