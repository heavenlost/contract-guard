# Contract Guard CI dogfood readiness checklist

Date: 2026-05-03
Owner identity: 长砺

This checklist turns the local C0-C6 handoff into a repeatable dogfood path. It is intentionally local-runner friendly: no hosted uploads, no private source-code upload, no live AI provider calls, no payment/billing/custody scope, and no audit-completeness claims.

## Goal

Before asking a real Foundry team to run Contract Guard CI, prove two things:

1. The local example fixture still exercises the expected plan/policy/scan/report surfaces without dependency downloads or external services.
2. A real repo validation has a clear acceptance checklist for GitHub Actions/SARIF, Foundry, Slither, baseline, policy, and false-positive workflows.

Contract Guard CI remains continuous security CI. Deterministic tool evidence is the source of truth; advisory templates and AI triage scaffolds are not proofs, audits, or guarantees.

## Related handoff docs

- `docs/beta-install.md` — local install, dry-run scans, GitHub Actions outputs, and beta limitations.
- `docs/beta-design-partner-checklist.md` — partner fit, permissions, validation commands, and feedback signals.
- `docs/demo-case-study.md` — public DeFi vault demo flow and validation questions.
- `docs/commercial-boundary.md` — hosted/self-hosted/commercial boundaries; documentation-only unless later explicitly approved.
- `README.md` — top-level quickstart and product stance.

## Local fixture command bundle

Preferred one-command verifier through the product CLI:

```bash
PYTHONPATH=src python3 -m contract_guard_ci.cli dogfood-readiness --format markdown
```

The legacy script wrapper still works for local checkout workflows:

```bash
python3 scripts/contract_guard_dogfood_readiness.py --format markdown
```

The verifier writes local artifacts to `/tmp/contract-guard-dogfood-readiness`, checks plan/scan/SARIF schemas, checks policy safety defaults, checks local output containment, checks SARIF no-AI metadata, and exits nonzero if the fixture bundle no longer matches the dogfood acceptance criteria. It does not call external services, upload hosted artifacts, send snippets, call live AI providers, or touch payment/custody scope.

Manual equivalent, run from the repository root:

```bash
rm -rf /tmp/contract-guard-dogfood-readiness
mkdir -p /tmp/contract-guard-dogfood-readiness

PYTHONPATH=src python3 -m contract_guard_ci.cli plan \
  --repo examples/foundry-basic \
  --json \
  > /tmp/contract-guard-dogfood-readiness/plan.json

PYTHONPATH=src python3 -m contract_guard_ci.cli policy \
  --repo examples/foundry-basic \
  --policy-file .contract-guard-policy.json \
  --format markdown \
  > /tmp/contract-guard-dogfood-readiness/policy.md

PYTHONPATH=src python3 -m contract_guard_ci.cli scan \
  --repo examples/foundry-basic \
  --skip-foundry \
  --skip-slither \
  --baseline-file .contract-guard-baseline.json \
  --format json \
  > /tmp/contract-guard-dogfood-readiness/scan.json

PYTHONPATH=src python3 -m contract_guard_ci.cli scan \
  --repo examples/foundry-basic \
  --skip-foundry \
  --skip-slither \
  --baseline-file .contract-guard-baseline.json \
  --format markdown \
  > /tmp/contract-guard-dogfood-readiness/scan.md

PYTHONPATH=src python3 -m contract_guard_ci.cli scan \
  --repo examples/foundry-basic \
  --skip-foundry \
  --skip-slither \
  --baseline-file .contract-guard-baseline.json \
  --format sarif \
  > /tmp/contract-guard-dogfood-readiness/scan.sarif
```

Notes:

- `.contract-guard-policy.json` and `.contract-guard-baseline.json` are resolved relative to the target repo (`examples/foundry-basic`), so keep the short file names in the command.
- `--skip-foundry` and `--skip-slither` are explicit dry-run flags for onboarding environments without those tools installed.
- The output path under `/tmp` avoids modifying the repository and keeps private project output local.

## Local fixture acceptance criteria

The local bundle is healthy when:

- `plan.json` has `schema=contract_guard_plan/v1` and detects `foundry_project=true`.
- `policy.md` reports local deterministic defaults with AI triage, private snippets, hosted uploads, and raw stdout/stderr disabled.
- `scan.json` has `schema=contract_guard_scan/v1` and `status=passed` when both external tools are explicitly skipped.
- `scan.md` renders deterministic evidence without raw stdout/stderr and without AI triage text.
- `scan.sarif` is valid JSON with SARIF version `2.1.0` and no private upload side effect.

Optional quick parser check:

```bash
python3 - <<'PY'
import json
from pathlib import Path
root = Path('/tmp/contract-guard-dogfood-readiness')
plan = json.loads((root / 'plan.json').read_text())
scan = json.loads((root / 'scan.json').read_text())
sarif = json.loads((root / 'scan.sarif').read_text())
assert plan['schema'] == 'contract_guard_plan/v1'
assert plan['summary']['foundry_project'] is True
assert scan['schema'] == 'contract_guard_scan/v1'
assert scan['status'] == 'passed'
assert sarif['version'] == '2.1.0'
print('contract-guard dogfood fixture outputs look healthy')
PY
```


## Richer local DeFi fixture

For a more realistic local dogfood target, use `examples/foundry-defi-vault`:

```bash
PYTHONPATH=src python3 -m contract_guard_ci.cli dogfood-readiness \
  --fixture-repo examples/foundry-defi-vault \
  --format markdown
```

This fixture includes an ERC20-like asset, an ERC4626-style vault surface, owner/paused access-control paths, a plain Solidity invariant harness, and local-only policy/baseline files. It remains dependency-free and does not claim to model a production protocol completely.

## Real Foundry repo validation checklist

For the first real dogfood repository, collect or confirm:

- Repo owner, branch strategy, and whether PR validation should be changed-only or full-scan at first.
- Foundry version, dependency installation path, and expected `forge test` command.
- Slither installation/version and any repository-specific exclude paths.
- Whether the repo can run in GitHub-hosted Actions, or should use a self-hosted runner because private protocol code and tool output must stay inside the team environment.
- Whether SARIF upload is enabled and what GitHub permissions/code-scanning settings are required.
- Initial `.contract-guard-policy.json` values: `changed_only`, `diff_base`, baseline path, failure severity/confidence, report formats, and safety boundaries.
- Initial `.contract-guard-baseline.json` entries, if any; high-severity findings must not be suppressed.
- False-positive review owner, reviewer naming convention, expiry policy, and where reviewed suppressions live.
- Whether advisory invariant templates or scaffold-only fuzzing hooks are useful, with clear wording that they are suggestions/scaffolds only.
- AI triage remains local/advisory-only unless there is explicit opt-in, redaction review, and external provider review.

## Real repo acceptance criteria

A real beta dogfood run is ready to count as validation only when all applicable items are observed and recorded:

1. `contract-guard plan --repo . --json` correctly detects Foundry/Solidity/tool readiness.
2. `contract-guard scan --repo . --format json` runs with real Foundry/Slither, or the reason for an explicit skip is documented.
3. Markdown output is readable as PR-comment deterministic evidence and does not include raw stdout/stderr.
4. SARIF output is accepted by GitHub code scanning, or the exact permission/settings blocker is documented.
5. `--changed-only --diff-base ...` behaves correctly on a PR branch.
6. Baseline suppression hides only exact-match non-high findings and never suppresses high-severity findings.
7. Failure policy exits nonzero for active findings at the configured severity/confidence threshold.
8. False-positive records are auditable and include reason, reviewer, and expiry for any candidate suppression.
9. Policy validation confirms hosted uploads, private snippet upload, raw stdout/stderr rendering, and live AI provider calls remain disabled by default.
10. A human reviewer confirms the output does not claim audit completeness, proof, certification, or legal/compliance guarantee.

## Stop or escalate triggers

Stop local automation and request review if any of these appear:

- A required validation needs private code, secret, raw tool output, or audit findings to leave the local runner.
- GitHub permissions, SARIF upload, or self-hosted runner setup becomes ambiguous.
- Slither/Foundry output semantics are unclear enough to affect failure policy or false-positive handling.
- A live AI provider, hosted dashboard payload, billing/payment, custody, wallet, stablecoin, or settlement scope is proposed.
- Two required smoke tiers fail on the same boundary.

