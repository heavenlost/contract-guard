# Contract Guard CI

Open-source smart contract security CI for Foundry projects.

`contract-guard-ci` is a small, automation-friendly security workflow for EVM teams. It wraps deterministic tools first—Foundry, Slither, and later Echidna/Medusa—and uses AI only for triage/explanation, never as the sole source of truth.

## Product stance

- **Do:** PR-level smart contract security checks, diff-aware reporting, SARIF/JSON/Markdown outputs, team policy baselines.
- **Do not:** claim to replace human audits, hold user funds, run payment infrastructure, custody keys, or perform legal/compliance decisions.
- **First customer:** small EVM protocol teams using Foundry that need continuous pre-audit safety checks.

## MVP shape

1. CLI probes repository/tool readiness.
2. GitHub Action runs on pull requests.
3. Foundry tests and Slither static analysis are normalized into one report.
4. Advisory invariant templates help teams start Foundry invariant testing without claiming audit completeness.
5. Scaffold-only Echidna/Medusa hooks define local fuzzer commands without executing external fuzzers by default.
6. False-positive review records generate auditable non-high baseline candidates.
7. Local repo policy files define deterministic scan defaults without enabling private uploads or AI triage.
8. Optional AI triage payloads start with deterministic redaction and never call external AI by default.
9. Future: PR comments, AI-assisted triage, live fuzzer execution, paid team dashboard.

## Quickstart

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
contract-guard plan --repo . --json
```

Run local smoke:

```bash
./scripts/contract_guard.sh smoke
```

## Design partner feedback

If you maintain or review a Foundry/EVM codebase, feedback is welcome in the public design-partner issue: <https://github.com/heavenlost/contract-guard/issues/1>.

Start with `docs/design-partner-feedback.md` for safe trial commands and what not to share publicly. Please do not post private source snippets, secrets, raw private-repo logs, or vulnerability claims about third-party repositories.

## Public beta path

For a public-safe local beta flow:

1. Use `docs/beta-install.md` for local install, dry-run scans, GitHub Actions outputs, baseline/policy setup, and beta limitations.
2. Run the local fixture bundle in `docs/dogfood-readiness.md` before trying a real Foundry repo.
3. Use `docs/demo-case-study.md` for the public DeFi vault demo and developer-call narrative.
4. Use `docs/public-foundry-dogfood-candidates.md` to choose a public read-only dogfood repo.
5. Use `docs/aderyn-integration-feasibility.md` for the optional `contract-guard scan --include-aderyn` analyzer path; default scans still do not enable extra analyzers.
6. Use `docs/beta-design-partner-checklist.md` for broader partner fit, onboarding commands, permission boundaries, and feedback signals.
7. Keep `docs/commercial-boundary.md` as the boundary for any hosted dashboard, self-hosted runner, pricing, or paid beta discussion.

The beta path stays local-runner first: no hosted uploads, no private snippet sharing, no live AI provider calls, no payment/custody scope, and no audit-completeness claims by default.


## Pre-Audit Evidence Pack

Generate a local-first evidence bundle before audits, releases, upgrades, or risky pull requests:

```bash
contract-guard evidence-pack \
  --repo . \
  --output-dir /tmp/contract_guard_evidence_pack \
  --repo-label your-repo-label \
  --format markdown
```

The pack writes Markdown/JSON/SARIF artifacts locally and keeps deterministic tool output as the source of truth. By default it requires no hosted private-code upload, sends no private snippets, includes no raw stdout/stderr in public summaries, makes no live AI provider call, and makes no audit/compliance/guarantee claim.

See `docs/pre-audit-evidence-pack.md` for the public evidence-pack walkthrough and `docs/ci-supply-chain-safety.md` for the local workflow safety checker.

## PR scan outputs

Run a deterministic local scan:

```bash
contract-guard scan --repo . --format json
contract-guard scan --repo . --format markdown
contract-guard scan --repo . --format sarif
```

For pull-request style scoping, use changed-only mode:

```bash
contract-guard scan \
  --repo . \
  --changed-only \
  --diff-base origin/main...HEAD \
  --format markdown
```

The GitHub Action writes three deterministic outputs under `contract-guard-reports/`:

- `scan.json` — policy-gated machine report.
- `scan.md` — PR-comment style deterministic evidence, without raw stdout/stderr.
- `scan.sarif` — GitHub code scanning upload.

AI triage is intentionally not included in these outputs. Deterministic tool evidence stays separate from any future advisory explanation layer.

## Baseline and failure policy

Baseline suppression is optional and explicit:

```bash
cp .contract-guard-baseline.example.json .contract-guard-baseline.json
contract-guard scan --repo . --baseline-file .contract-guard-baseline.json
```

Rules:

- Baselines match by exact finding `id`, or by exact `check` + `file` + `start_line`.
- Only non-high Slither findings can be suppressed.
- High-severity findings are never suppressed by baseline, even if listed.
- Suppressed findings are kept separately in the machine report; they are not deleted.

Default CI policy fails on active high-severity Slither findings with low-or-better confidence:

```bash
contract-guard scan \
  --repo . \
  --changed-only \
  --baseline-file .contract-guard-baseline.json \
  --fail-on-severity high \
  --fail-on-confidence low
```

Use `--fail-on-severity none` only when generating non-gating artifacts such as Markdown or SARIF after the policy-gated JSON scan has already captured the exit status.

## Advisory invariant templates

Generate deterministic Foundry invariant starting points:

```bash
contract-guard invariants --profile erc20 --contract Token --format markdown
contract-guard invariants --profile vault --contract Vault --format json
contract-guard invariants --profile access-control --contract Governor
```

Profiles currently cover common ERC20 accounting, vault/ERC4626-style accounting, and access-control/paused-state checks. These templates are advisory starting points only: they are not proofs, audits, or guarantees, and each snippet must be adapted to the protocol's actual handlers, roles, assets, and expected edge cases.

## Fuzzing hook scaffolds

Generate local-runner fuzzer command scaffolds without executing Echidna or Medusa:

```bash
contract-guard fuzz-hooks --tool all --target test/invariants/InvariantTest.sol --contract InvariantTest
contract-guard fuzz-hooks --tool echidna --target test/invariants/TokenInvariant.t.sol --contract TokenInvariant --format json
contract-guard fuzz-hooks --tool medusa --target test/invariants/VaultInvariant.t.sol --contract VaultInvariant
```

These hooks are deterministic scaffolds only. Before enabling live execution, pin the fuzzer version, review the generated command/config against that version, and keep fuzzer output separate from optional AI explanation. A fuzzing hook is not a proof, audit, or guarantee of safety.

## False-positive workflow

Generate an auditable baseline candidate for a non-high finding:

```bash
contract-guard false-positive \
  --id slither:unchecked-transfer:contracts/Token.sol:7 \
  --check unchecked-transfer \
  --file contracts/Token.sol \
  --start-line 7 \
  --severity medium \
  --confidence high \
  --reason "Known safe return-value wrapper in SafeERC20 adapter." \
  --reviewer security-team \
  --expires 2026-12-31 \
  --format json
```

The command does not edit the baseline file. It emits a deterministic review record and, only for non-high findings with required review metadata, a copyable `baseline_candidate`. High-severity findings always return `blocked_high_severity` and no baseline candidate, preserving the CI rule that new high-risk issues stay visible.

## Repo policy file

Validate local project defaults:

```bash
cp .contract-guard-policy.example.json .contract-guard-policy.json
contract-guard policy --repo . --policy-file .contract-guard-policy.json --format markdown
```

The policy file currently covers scan defaults (`changed_only`, `diff_base`, baseline path, failure thresholds), report formats, scaffold-only fuzzing hook preferences, and safety boundaries. The normalized policy always keeps AI triage disabled by default, private snippet upload disabled, hosted uploads disabled, and raw stdout/stderr out of reports.

## Optional AI triage privacy boundary

Build a local, redacted advisory payload without calling external AI:

```bash
contract-guard ai-triage-payload \
  --check reentrancy-eth \
  --file contracts/Vault.sol \
  --start-line 42 \
  --severity high \
  --confidence medium \
  --description "Vault withdraw sends before state update." \
  --format markdown
```

Snippet text is dropped by default. If a team explicitly asks to include context, `--include-redacted-snippet` emits only a deterministically redacted snippet and still reports `send_private_snippets=false` and `external_ai_call_made=false`. Deterministic analyzer evidence remains separate from any future advisory AI explanation.

Generate a local advisory explanation scaffold from the same redacted payload shape:

```bash
contract-guard ai-triage-explain \
  --check reentrancy-eth \
  --file contracts/Vault.sol \
  --start-line 42 \
  --severity high \
  --confidence medium \
  --description "Vault withdraw sends before state update."
```

This explanation scaffold is not deterministic evidence, not a proof, not an audit, and not a guarantee. It is a local template for review questions and test suggestions; future live AI provider integration must keep the same evidence/advisory separation.

Validate the provider opt-in boundary before any live integration exists:

```bash
contract-guard ai-triage-config --format markdown
contract-guard ai-triage-config \
  --provider openai \
  --enable-external-provider \
  --include-redacted-snippets \
  --format json
```

Even in the explicit opt-in shape, this command makes no external AI call and reports `private_code_leaves_local_runner=false`, `send_private_snippets=false`, and `hosted_uploads_enabled=false`. Private snippets and hosted uploads are blocked, not merely off by convention.

Render a combined triage report with hard section separation:

```bash
contract-guard ai-triage-combined \
  --check reentrancy-eth \
  --file contracts/Vault.sol \
  --start-line 42 \
  --severity high \
  --confidence medium \
  --description "Vault withdraw sends before state update."
```

The combined report always renders `Deterministic evidence (source of truth)` before `Advisory AI text (separate, non-gating)`. AI text cannot suppress findings or replace deterministic tool evidence.
