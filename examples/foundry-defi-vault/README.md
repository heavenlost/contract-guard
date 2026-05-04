# Foundry DeFi Vault dogfood fixture

This is a dependency-free Foundry-style fixture for Contract Guard CI dogfood.

It is more realistic than `examples/foundry-basic` because it includes:

- an ERC20-like asset,
- an ERC4626-style vault surface,
- owner/paused access-control paths,
- a plain Solidity invariant harness,
- local-only Contract Guard policy and baseline files.

The fixture is not a real protocol and is not a proof, audit, or guarantee. It exists to exercise plan/scan/report/policy/SARIF dogfood paths without dependency downloads, hosted uploads, private snippets, live AI provider calls, payment/custody scope, or external services by default.

Run from the Contract Guard CI repository root:

```bash
PYTHONPATH=src python3 -m contract_guard_ci.cli dogfood-readiness \
  --fixture-repo examples/foundry-defi-vault \
  --format markdown
```
