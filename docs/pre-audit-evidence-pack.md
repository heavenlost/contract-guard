# Contract Guard CI — Pre-Audit Evidence Pack

Contract Guard CI helps Foundry/EVM teams produce a local, reviewable evidence pack before audits, releases, upgrades, or risky pull requests.

It is built around one principle:

> Deterministic tool output is the source of truth. Human reviewers decide what it means.

Contract Guard CI is **not** an audit, formal verification system, vulnerability report, bug bounty submission, compliance opinion, insurance product, hosted private-code scanner, wallet/custody product, payment rail, or AI auditor.

## Why teams might care

Before an audit or release, teams often need to answer practical workflow questions:

- Did tests and static analysis run?
- Which findings are active, suppressed, or accepted risks?
- Who approved a false-positive baseline entry?
- Can high-severity findings be silently ignored? Contract Guard CI says no.
- Are the review artifacts available as Markdown, JSON, and SARIF?
- What GitHub Actions permissions are required?
- Does the workflow require private-code upload, raw log sharing, or live AI calls?

Contract Guard CI packages these answers into a local evidence pack that a developer, security owner, or auditor can review.

## Local-first by default

The evidence pack is designed for local CLI or customer-controlled CI first.

Default boundaries:

- no hosted private-code upload required;
- no live AI provider call;
- no private snippets by default;
- no raw stdout/stderr in public summaries;
- no wallet, custody, payment, settlement, token, or billing scope;
- no audit, proof, compliance, or security guarantee.

Foundry and Slither execution should be enabled only after the team approves local tool execution, dependency expectations, runtime cost, and artifact boundaries.

## Example command

```bash
contract-guard evidence-pack \
  --repo . \
  --output-dir /tmp/contract_guard_evidence_pack \
  --repo-label your-repo-label \
  --format markdown
```

The command writes a local bundle. The exact output directory is chosen by the user.

## Evidence-pack contents

Expected bundle shape:

```text
manifest.json
README.md
deterministic-evidence/
  plan.json
  scan.json
  scan.md
  scan.sarif
policy-and-baseline/
  policy.md
  baseline-review.md
workflow-and-supply-chain/
  workflow-check.md
  permission-matrix.md
  trust-readiness.md
  data-flow.md
  runner-guidance.md
human-review/
  readiness-summary.md
  open-questions.md
```

## What reviewers can inspect

### Deterministic evidence

- repo readiness plan;
- scan JSON;
- scan Markdown;
- optional SARIF;
- Foundry/Slither status when enabled;
- active findings and failure-policy status.

AI text is not required for the pack and is not mixed into deterministic findings.

### Policy and baseline governance

- baseline file status;
- suppression count;
- reviewer, reason, and expiry expectations;
- non-high suppressions only;
- high-severity findings remain visible and cannot be silently suppressed by Contract Guard CI.

### Workflow and supply-chain trust

- GitHub Actions workflow-check output;
- permission matrix;
- `pull_request_target` warning status;
- third-party Action pinning status;
- SARIF permission notes;
- data-flow and runner guidance.

This is not a complete CI/CD security audit, but it makes the trust boundary reviewable.

### Human-review questions

The pack ends with questions such as:

- Do Foundry tests pass locally and in CI?
- Is Slither approved for local execution?
- Are Markdown/JSON artifacts enough if SARIF upload is blocked?
- Who reviews baseline suppressions?
- What evidence does an auditor or security owner want before kickoff?
- Would local/customer-controlled execution change adoption willingness?

## Sample fixture result

A local dry-run sample against a Foundry-style demo fixture produced:

| Field | Observed value | Meaning |
| --- | --- | --- |
| `pack_status` | `ready_for_human_review` | Bundle is complete enough for a human demo review. |
| `source_of_truth` | `deterministic_tools` | Deterministic artifacts are primary. |
| `foundry_detected` | `true` | The fixture has a Foundry-style layout. |
| `hosted_upload_required` | `false` | The pack is local-first. |
| `private_snippets_included` | `false` | No private snippets by default. |
| `live_ai_provider_called` | `false` | No live AI provider by default. |
| `audit_or_compliance_claim` | `false` | No audit/compliance guarantee. |

Important: a dry-run fixture proves artifact shape, not smart-contract safety. A real run still needs team-approved deterministic tools and human review.

## Best fit

Contract Guard CI is most likely useful for teams that:

- maintain a Foundry/EVM codebase;
- are preparing for an audit, release, upgrade, or sensitive PR series;
- care about repeatable Markdown/JSON/SARIF evidence;
- want high-severity findings to remain visible;
- need baseline governance for known false positives;
- prefer local CLI or customer-controlled CI over hosted private-code upload.

## Bad fit

Contract Guard CI is not a fit for teams looking for:

- audit replacement;
- guaranteed bug discovery;
- legal/compliance assurance;
- hosted private-code scanning by default;
- wallet, custody, payment, settlement, token, or billing infrastructure;
- public vulnerability disclosure or bounty submission workflows.

## Feedback wanted

Useful feedback includes:

1. Would this evidence-pack shape help before audits, releases, upgrades, or risky PRs?
2. Which artifacts would a security owner or auditor actually read: Markdown, JSON, SARIF, baseline review, permission matrix, runner guidance, or something else?
3. Is SARIF important enough to justify extra GitHub permissions, or is Markdown/JSON enough?
4. Does local-first/no-private-upload reduce adoption friction?
5. Would teams pay for setup support, policy tuning, SARIF troubleshooting, baseline governance, or recurring readiness reports?
6. What would make this unacceptable even if the CLI is free?

Please do **not** share private code, secrets, raw logs, customer data, exploit details, private audit findings, mnemonics, private keys, RPC credentials, or unpublished vulnerability reports in public channels.

## Current validation status

Locally validated:

- evidence-pack artifact shape;
- local CLI bundle generation;
- deterministic evidence separation;
- policy/baseline governance notes;
- workflow trust notes;
- sample dry-run walkthrough;
- no-hosted-upload / no-live-AI / no-private-snippet default boundary.

Still required before deeper product investment:

- real customer-controlled repo/runner validation;
- real SARIF behavior validation in a team repo;
- real policy/baseline workflow feedback;
- willingness-to-pay signal for setup/support/readiness reporting;
- external review before any hosted private-code, live-AI, GitHub App, Marketplace, billing, payment, custody, or audit-completeness expansion.

## Links

- Public repository: <https://github.com/heavenlost/contract-guard>
- Generic feedback issue: <https://github.com/heavenlost/contract-guard/issues/1>
