# Contract Guard CI demo case study: DeFi vault PR readiness

Date: 2026-05-03
Status: local deterministic demo, not a production audit
Fixture: `examples/foundry-defi-vault`

This case study is the public-facing demo path for Contract Guard CI. It shows how a Web3 team could use the tool before a professional audit or before merging a Solidity pull request.

Contract Guard CI is **continuous security CI**, not an AI auditor, not a proof system, not a certification, and not a replacement for a professional smart contract audit. Deterministic tools and repo policy are the source of truth; optional AI text stays advisory and non-gating.

## Target user

A small EVM team using Foundry that wants to catch obvious issues and manage security findings before audit:

- Solidity developers opening PRs against a protocol repo.
- A technical lead who wants consistent CI evidence instead of ad-hoc local scans.
- A security reviewer who wants baseline suppressions to be auditable and expiry-bound.

## Demo fixture

`examples/foundry-defi-vault` is dependency-free, but closer to a real protocol than the minimal counter fixture:

- `DogfoodAsset`: ERC20-like asset surface.
- `TrainingVault`: ERC4626-style deposit/withdraw surface.
- Owner/paused access-control paths.
- Plain Solidity invariant harness in `test/VaultInvariant.t.sol`.
- Local-only policy and baseline files.

The fixture intentionally avoids dependency downloads and external services so the demo is reproducible in a clean checkout.

## Demo command sequence

Run from the repository root:

```bash
PYTHONPATH=src python3 -m contract_guard_ci.cli plan \
  --repo examples/foundry-defi-vault \
  --json
```

Expected story:

- Contract Guard detects a Foundry-style Solidity repo.
- It reports whether `forge`, `slither`, and `git` are available.
- Missing local tools are surfaced as readiness warnings, not hidden.

Run the packaged dogfood verifier:

```bash
PYTHONPATH=src python3 -m contract_guard_ci.cli dogfood-readiness \
  --fixture-repo examples/foundry-defi-vault \
  --format markdown
```

Expected story:

- The verifier writes JSON, Markdown, and SARIF outputs to a local `/tmp` directory.
- It confirms schema stability and local output containment.
- It confirms the Markdown report keeps deterministic evidence separate from advisory AI text.
- It confirms SARIF marks `deterministic_evidence_only=true` and `ai_triage_included=false`.
- It confirms no external services, hosted uploads, private snippets, live AI calls, payment/custody scope, or audit-completeness claims are involved.

Run dry-run reports directly:

```bash
PYTHONPATH=src python3 -m contract_guard_ci.cli scan \
  --repo examples/foundry-defi-vault \
  --skip-foundry \
  --skip-slither \
  --baseline-file .contract-guard-baseline.json \
  --format markdown

PYTHONPATH=src python3 -m contract_guard_ci.cli scan \
  --repo examples/foundry-defi-vault \
  --skip-foundry \
  --skip-slither \
  --baseline-file .contract-guard-baseline.json \
  --format sarif
```

Expected story:

- Dry-run mode is explicit; it never pretends Foundry/Slither executed.
- Markdown is suitable for PR-comment style deterministic evidence.
- SARIF is ready for GitHub code scanning integration once real repo permissions are validated.

## What the demo proves

This local demo proves:

1. Contract Guard CI has a repeatable CLI workflow for a Foundry-style Solidity repo.
2. Reports are stable across JSON, Markdown, and SARIF outputs.
3. Policy and baseline files are local and deterministic.
4. AI triage is not required and is not mixed into deterministic evidence.
5. The workflow can be smoke-tested without downloading dependencies or uploading private code.

## What the demo does not prove

This local demo does **not** prove:

- The vault fixture is secure.
- Contract Guard CI replaces human review or professional audit.
- GitHub SARIF upload works in every target repo.
- Foundry and Slither are installed or configured correctly in a partner repo.
- A real protocol team will accept the baseline/false-positive workflow.
- A live AI provider, hosted dashboard, billing, payment, or custody path is safe or needed.

## Real repo upgrade path

For a real design partner repo, the demo should become:

```bash
contract-guard plan --repo . --json
contract-guard policy --repo . --policy-file .contract-guard-policy.json --format markdown
contract-guard scan --repo . --format json
contract-guard scan --repo . --changed-only --diff-base origin/main...HEAD --format markdown
contract-guard scan --repo . --changed-only --diff-base origin/main...HEAD --format sarif
```

The dry-run skip flags should be removed once Foundry and Slither are installed. If either tool is skipped in a real validation, the reason must be recorded.

## Buyer hypothesis

The initial buyer is not paying for “AI explains Solidity.” They are paying for a repo-local CI process that:

- catches high-risk findings before merge,
- prevents new high-severity findings from being hidden by baselines,
- keeps false-positive decisions auditable,
- emits GitHub-native artifacts,
- reduces audit-prep noise,
- avoids private-code upload by default.

Early monetization should be support/onboarding/report oriented rather than hosted SaaS by default:

- set up repo-local GitHub Action,
- tune policy and baseline,
- produce an audit-readiness report,
- help teams decide what must be fixed before external audit.

## Demo script for a developer call

Use this 10-minute flow:

1. “This is not an audit replacement. It is PR-level security CI.”
2. Show the fixture layout: `src/TrainingVault.sol`, `test/VaultInvariant.t.sol`, policy, baseline.
3. Run `dogfood-readiness` and show local PASS output.
4. Open the generated Markdown report and point to deterministic evidence.
5. Open SARIF JSON and point to GitHub code-scanning compatibility.
6. Explain baseline rule: non-high exact matches only; high severity never suppressed.
7. Ask whether this would be useful in their PR workflow and what would block adoption.

## Validation questions

Ask 1-2 Web3 developers:

- Would this catch something your team currently misses before audit?
- Do you already run Foundry and Slither in CI? If not, why?
- Would SARIF/GitHub code scanning matter to your team?
- Is baseline governance useful, or too much process?
- What would make you trust or distrust the reports?
- Would you pay for setup/support/audit-readiness reporting? If yes, what price range feels plausible?
- Would you require self-hosted runner support?
- What privacy boundaries are non-negotiable?
