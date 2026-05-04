# Contract Guard CI beta install guide

This guide is for beta evaluators who want a local or GitHub Actions dry run of Contract Guard CI on a Foundry/EVM repository.

Contract Guard CI is continuous security CI, not a full audit, proof, or legal guarantee. Deterministic tool output from Foundry, Slither, and future fuzzers is the source of truth. Optional AI triage remains advisory-only and is disabled for live provider calls by default.

## Requirements

- Python 3.11 or newer.
- A Foundry project with Solidity sources.
- Foundry installed when running real `forge test` checks.
- Slither installed when running real static-analysis checks.
- GitHub Actions permissions for SARIF upload only when using GitHub code scanning.

The CLI can still produce local dry-run reports when Foundry or Slither are unavailable by using the explicit skip flags shown below.

## Local install from a checkout

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
contract-guard plan --repo . --json
```

Run the project smoke test from the Contract Guard CI checkout:

```bash
./scripts/contract_guard.sh smoke
```

## Local dry run

Use explicit skip flags for packaging or onboarding environments that do not have Foundry/Slither installed yet:

```bash
contract-guard scan --repo . --skip-foundry --skip-slither --format json
contract-guard scan --repo . --skip-foundry --skip-slither --format markdown
contract-guard scan --repo . --skip-foundry --skip-slither --format sarif
```

Use real deterministic tools when they are installed:

```bash
contract-guard scan --repo . --format json
contract-guard scan --repo . --format markdown
contract-guard scan --repo . --format sarif
```

The Markdown report is PR-comment style deterministic evidence and does not render raw stdout/stderr. SARIF is intended for GitHub code scanning. JSON is the policy-gated machine report.

## Example Foundry fixture

This repository includes `examples/foundry-basic`, a dependency-free Foundry-style fixture with a toy access-controlled counter, a plain Solidity invariant harness, a local-only policy file, and a sample non-high baseline shape.

From the Contract Guard CI repository root:

```bash
PYTHONPATH=src python3 -m contract_guard_ci.cli plan --repo examples/foundry-basic --json
PYTHONPATH=src python3 -m contract_guard_ci.cli policy --repo examples/foundry-basic --policy-file .contract-guard-policy.json --format markdown
PYTHONPATH=src python3 -m contract_guard_ci.cli scan --repo examples/foundry-basic --skip-foundry --skip-slither --baseline-file .contract-guard-baseline.json --format markdown
```

The fixture avoids dependency downloads by not importing `forge-std` or external libraries. It is for packaging and onboarding smoke only; it is not a real protocol and does not prove security.

## Pull request mode

For PR-style local checks, run changed-only filtering against a base ref:

```bash
contract-guard scan \
  --repo . \
  --changed-only \
  --diff-base origin/main...HEAD \
  --format markdown
```

Changed-only mode filters to changed Solidity files and applies Slither finding filtering after deterministic analysis normalization.

## Baseline and failure policy

Baselines are optional and explicit:

```bash
cp .contract-guard-baseline.example.json .contract-guard-baseline.json
contract-guard scan --repo . --baseline-file .contract-guard-baseline.json
```

Suppression rules:

- Only exact-match non-high Slither findings can be suppressed.
- High-severity findings are never baseline-suppressed.
- Suppressed findings remain in the machine report under a separate suppressed list.

Default CI gating fails on active high-severity findings with low-or-better confidence:

```bash
contract-guard scan \
  --repo . \
  --changed-only \
  --baseline-file .contract-guard-baseline.json \
  --fail-on-severity high \
  --fail-on-confidence low
```

Use `--fail-on-severity none` only for non-gating artifact generation after a gating JSON scan has already captured the intended exit status.

## Policy file

Project defaults can be reviewed with a local policy file:

```bash
cp .contract-guard-policy.example.json .contract-guard-policy.json
contract-guard policy --repo . --policy-file .contract-guard-policy.json --format markdown
```

The normalized policy keeps these beta safety defaults:

- AI triage disabled by default.
- Private snippet upload disabled.
- Hosted uploads disabled.
- Raw stdout/stderr excluded from reports.
- Fuzzing hooks scaffold-only unless a team deliberately runs tools outside this command.

## GitHub Actions beta path

Copy or adapt `.github/workflows/contract-guard-ci.yml` into the target repository after local dry runs are stable.

Expected outputs:

- `contract-guard-reports/scan.json`
- `contract-guard-reports/scan.md`
- `contract-guard-reports/scan.sarif`

The workflow uploads JSON/Markdown/SARIF as artifacts and attempts SARIF upload for GitHub code scanning. Real SARIF upload behavior still needs validation in the target repository's GitHub permissions and code-scanning settings.

## Optional local helpers

These commands generate local scaffolds only:

```bash
contract-guard invariants --profile erc20 --contract Token
contract-guard fuzz-hooks --tool all --target test/invariants/InvariantTest.sol --contract InvariantTest
contract-guard false-positive --id slither:unchecked-transfer:contracts/Token.sol:7 --check unchecked-transfer --file contracts/Token.sol --start-line 7 --severity medium --confidence high --reason "Reviewed wrapper" --reviewer security-team
```

Invariant templates and fuzzer hooks are suggestions/scaffolds, not proofs, audits, or guarantees. False-positive records generate copyable candidates only for non-high findings and do not edit the baseline file automatically.

## Optional AI triage boundary

AI triage commands currently run locally and do not call external providers:

```bash
contract-guard ai-triage-payload --check reentrancy-eth --file contracts/Vault.sol --start-line 42 --severity high --confidence medium --description "Withdraw sends before state update."
contract-guard ai-triage-explain --check reentrancy-eth --file contracts/Vault.sol --start-line 42 --severity high --confidence medium --description "Withdraw sends before state update."
contract-guard ai-triage-combined --check reentrancy-eth --file contracts/Vault.sol --start-line 42 --severity high --confidence medium --description "Withdraw sends before state update."
```

Private snippets are dropped by default. Even explicit redacted-snippet mode remains local and reports that private snippets are not sent. Combined reports always display deterministic evidence before advisory AI text, and advisory AI text cannot suppress findings.

## Beta limitations

- Real GitHub Actions/SARIF upload must be validated in an actual GitHub repository.
- Real Foundry/Slither results must be dogfooded on target projects.
- Echidna/Medusa execution is not run by default; current hooks are command scaffolds only.
- Live AI provider integration is absent and requires explicit product direction plus external review before implementation.
- The tool complements human review and professional audits; it does not replace them.
