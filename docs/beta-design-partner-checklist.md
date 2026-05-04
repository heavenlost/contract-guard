# Contract Guard CI beta design partner checklist

This checklist defines the first safe beta path for Foundry/EVM teams evaluating Contract Guard CI.

Contract Guard CI is continuous security CI. It does not replace a professional audit, formal verification, legal review, or protocol-specific threat modeling. Deterministic tool evidence is the source of truth; optional AI triage is advisory-only and has no live provider integration by default.

## Partner fit

Good first beta partners:

- Maintain a Foundry-based EVM repository.
- Have at least one security-minded engineer who can review Slither/Foundry findings.
- Can run GitHub Actions on pull requests or a comparable self-hosted CI runner.
- Are comfortable starting with local artifacts rather than hosted dashboards or app installations.
- Can provide feedback about false positives, report clarity, and CI friction without sharing private code externally.

Defer partners that require:

- Wallet custody, payments, settlement, stablecoin routing, or funds movement.
- Hosted code upload as the default path.
- Live AI review of private snippets before the redaction/provider boundary has external review.
- A promise that CI findings are equivalent to a full audit.

## Required repo context

Collect only high-level, non-secret context before onboarding:

- Foundry version and whether `forge test` already passes.
- Slither availability/version, if already pinned by the team.
- Solidity source layout, such as `src/`, `contracts/`, `test/`, `script/`, and ignored generated directories.
- Branch and PR workflow shape, including base branch naming.
- Current audit/pre-audit workflow and pain points.
- Current false-positive handling, if any.
- Whether GitHub code scanning/SARIF upload is enabled for the repository.

Do not request private keys, mnemonics, RPC secrets, deployment credentials, customer data, or proprietary audit findings.

## Permission and privacy boundary

Beta default:

- Run as local CLI or repo-local GitHub Actions workflow.
- Produce JSON/Markdown/SARIF artifacts on the runner.
- Keep raw stdout/stderr out of PR-style Markdown reports.
- Keep AI triage disabled for live provider calls.
- Drop snippets by default; redacted snippets remain local unless a future reviewed provider path exists.
- Keep hosted uploads disabled.

Required confirmation from the partner:

- The workflow can read repository code on the CI runner.
- SARIF upload, if enabled, is acceptable for the repository's GitHub code scanning setup.
- Artifact retention policy is acceptable for JSON/Markdown/SARIF outputs.
- The team understands baseline suppressions only hide matching non-high findings from active gating and never suppress high-severity findings.

## Onboarding validation commands

Start from a local checkout of Contract Guard CI:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
./scripts/contract_guard.sh smoke
```

Validate the bundled fixture before touching a partner repo:

```bash
PYTHONPATH=src python3 -m contract_guard_ci.cli plan --repo examples/foundry-basic --json
PYTHONPATH=src python3 -m contract_guard_ci.cli policy --repo examples/foundry-basic --policy-file .contract-guard-policy.json --format markdown
PYTHONPATH=src python3 -m contract_guard_ci.cli scan --repo examples/foundry-basic --skip-foundry --skip-slither --baseline-file .contract-guard-baseline.json --format markdown
```

Run a partner repo dry scan without external tool assumptions:

```bash
contract-guard plan --repo . --json
contract-guard policy --repo . --policy-file .contract-guard-policy.json --format markdown
contract-guard scan --repo . --skip-foundry --skip-slither --format json
```

Then run deterministic tools when available:

```bash
forge test
slither . --json -
contract-guard scan --repo . --format json
contract-guard scan --repo . --format markdown
contract-guard scan --repo . --format sarif
```

For PR-style validation:

```bash
contract-guard scan \
  --repo . \
  --changed-only \
  --diff-base origin/main...HEAD \
  --baseline-file .contract-guard-baseline.json \
  --fail-on-severity high \
  --fail-on-confidence low \
  --format json
```

Generate non-gating artifacts only after the policy-gated JSON scan captures the intended exit status:

```bash
contract-guard scan --repo . --changed-only --baseline-file .contract-guard-baseline.json --fail-on-severity none --format markdown
contract-guard scan --repo . --changed-only --baseline-file .contract-guard-baseline.json --fail-on-severity none --format sarif
```

## False-positive review loop

For each noisy non-high finding:

1. Confirm the finding is not high severity.
2. Record reviewer, reason, and optional expiry.
3. Generate a deterministic review record:

```bash
contract-guard false-positive \
  --id slither:unchecked-transfer:contracts/Token.sol:7 \
  --check unchecked-transfer \
  --file contracts/Token.sol \
  --start-line 7 \
  --severity medium \
  --confidence high \
  --reason "Reviewed by protocol team; wrapper handles return value." \
  --reviewer security-team \
  --expires 2026-12-31 \
  --format json
```

Only copy `baseline_candidate` entries after human review. High-severity findings must remain visible and unsuppressed.

## Feedback signals to capture

Ask partners to report:

- Time from install to first local JSON/Markdown/SARIF outputs.
- Whether `plan` correctly detects Foundry layout and missing tools.
- Foundry/Slither runtime and failure modes.
- Number of high findings, non-high findings, and suppressions requested.
- Which findings were useful versus noisy.
- Whether changed-only filtering matched PR expectations.
- Whether Markdown is clear enough for PR review without raw stdout/stderr.
- Whether SARIF upload works in their GitHub code scanning setup.
- Whether default failure thresholds are too strict or too loose.
- Whether policy/baseline files are understandable and reviewable.
- Whether invariant/fuzz scaffolds produce useful starting points.
- Any point where the tool appears to imply audit completeness or AI authority.

## Beta readiness acceptance criteria

C5 beta is ready for user-facing handoff only when:

- Local install guide is clear enough to run without direct maintainer intervention.
- Example fixture plan/policy/scan commands pass.
- At least one real Foundry repository has run local `plan` and `scan` with real Foundry/Slither where available.
- At least one repo-local GitHub Actions run produces JSON/Markdown/SARIF artifacts.
- SARIF upload behavior is validated or the limitation is clearly documented for that repo.
- Failure policy by severity/confidence is accepted or adjusted intentionally.
- False-positive review flow has been exercised for at least one non-high finding.
- High-severity findings are confirmed not suppressible by baseline.
- Policy defaults are reviewed: no hosted uploads, no private snippets, no live AI provider, and no raw stdout/stderr in PR-style Markdown.
- Partner confirms the tool is positioned as CI assistance, not an audit replacement.

## Stop or escalate

Stop beta onboarding and review before proceeding if:

- A partner asks for custody, payments, wallet flows, settlement, or stablecoin routing.
- A partner asks to upload private code/snippets to an external AI provider by default.
- SARIF/GitHub permissions are unclear enough that least-privilege behavior cannot be explained.
- Foundry/Slither results are ambiguous and could lead to unsafe suppression decisions.
- The same required smoke tier fails twice.
- Product copy starts to imply complete audit coverage, proof, or legal guarantee.
