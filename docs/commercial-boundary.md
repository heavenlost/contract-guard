# Contract Guard CI commercial boundary

This document defines the C6 commercial boundary before any hosted or paid surface is implemented.

Contract Guard CI remains a deterministic security CI workflow for Foundry/EVM teams. It is not an audit, proof, legal guarantee, payment product, wallet product, custody service, settlement service, or stablecoin routing system.

## Default commercial posture

Default beta/commercial path:

```text
local CLI
→ repo-local GitHub Actions workflow or self-hosted CI runner
→ deterministic JSON/Markdown/SARIF artifacts
→ human review and baseline/policy updates
```

Commercialization should sell workflow reliability, time saved, repeatable evidence, and team visibility. It must not sell audit completeness, AI authority, custody/payment features, or hosted private-code analysis by default.

## Hosted dashboard boundary

A hosted dashboard is a future optional product surface. It is not the default execution path and must not be built before design-partner validation and external privacy/security review.

### Allowed future dashboard scope

A future dashboard may show:

- Repository-level configuration status after explicit opt-in.
- Aggregated counts such as active findings by severity/confidence.
- Check status trends from deterministic tool reports.
- Links to artifacts stored in the customer's CI/GitHub environment.
- Baseline age, expiry, owner, and review metadata.
- Policy conformance summaries, such as whether raw stdout/stderr and private snippets are disabled.
- Design-partner feedback and onboarding status.

### Not allowed by default

A hosted dashboard must not, by default:

- Upload private source code.
- Upload raw stdout/stderr.
- Upload unredacted snippets.
- Upload secrets, env files, RPC credentials, deployment keys, private keys, mnemonics, customer data, or proprietary audit findings.
- Run live AI provider triage on private code.
- Suppress deterministic findings based on AI text.
- Present findings as a full audit, proof, legal guarantee, or certification.
- Add custody, wallet, funds movement, payment routing, settlement, stablecoin routing, or fiat/crypto transaction features.

### Minimum hosted-data rule

If a dashboard is later pursued, the first reviewed payload should be metadata-only:

```text
schema_version
repository_alias or installation_alias
run_id
commit_sha or pull_request_number
tool statuses
summary counts
finding ids/check names/severity/confidence
repo-relative file paths only if explicitly approved
baseline review metadata
policy flags
artifact links controlled by the customer environment
```

Any expansion beyond metadata-only requires explicit product direction, external review, and fixture tests proving private snippets, raw logs, and secrets remain blocked.

### Hosted dashboard review gates

Before implementation:

- At least one real repo-local GitHub Actions/SARIF run must pass.
- At least two design-partner repos must complete local onboarding.
- Dashboard payload fields must be documented and reviewed.
- Retention and deletion expectations must be defined.
- Access control and least-privilege permissions must be mapped.
- Incident response for accidental secret exposure must be defined.
- AI provider integration, if any, must have a separate opt-in and redaction review.

## Self-hosted runner story

Self-hosted runners are the preferred commercial path for serious protocol teams.

The self-hosted story:

```text
customer-controlled runner
→ Foundry/Slither/Echidna/Medusa execution inside customer environment
→ Contract Guard normalized JSON/Markdown/SARIF artifacts
→ optional local policy/baseline review
→ optional metadata-only sync after explicit approval
```

### Why self-hosted first

- Protocol teams can keep source code and secrets inside their own infrastructure.
- Deterministic tools can use the exact compiler, Foundry, Slither, and fuzzer versions pinned by the team.
- Private code and raw tool logs do not need to leave the runner.
- Optional AI triage can remain local/advisory-only until a reviewed provider boundary exists.
- The team can choose artifact retention, SARIF upload behavior, and baseline review process.

### Self-hosted requirements

A self-hosted runner package should require:

- Python 3.11+ and the `contract-guard` CLI.
- Team-pinned Foundry and Slither versions.
- Optional pinned Echidna/Medusa versions when live fuzzing is later enabled.
- Repo-local `.contract-guard-policy.json`.
- Optional `.contract-guard-baseline.json` with reviewed non-high suppressions.
- CI permissions limited to reading the repo, writing artifacts, and optionally uploading SARIF to code scanning.

### Self-hosted non-goals

The self-hosted runner must not:

- Require a hosted dashboard.
- Require private code upload.
- Require live AI provider calls.
- Auto-edit baselines without human review.
- Suppress high-severity findings.
- Send raw stdout/stderr to PR comments by default.
- Introduce custody/payment/wallet functionality.

## Advisory AI boundary in commercial context

Commercial packaging must preserve the C4 boundary:

- AI triage is optional.
- Local payloads drop snippets by default.
- Explicit snippets are deterministically redacted.
- No live AI provider integration exists by default.
- Deterministic evidence remains the source of truth.
- Advisory AI text cannot suppress findings or replace human review.

## Commercial copy guardrails

Allowed phrasing:

- Continuous smart contract security CI.
- Deterministic Foundry/Slither reporting for PR workflows.
- Baseline and policy workflow for recurring findings.
- Advisory invariant/fuzzing scaffolds.
- Optional advisory AI explanation with strict privacy boundaries.

Avoid:

- AI auditor.
- Audit replacement.
- Guaranteed secure.
- Proof of safety.
- Certified safe.
- Hosted private-code analysis by default.
- Any payment, custody, wallet, settlement, stablecoin, or funds movement promise.

## Next commercial questions

Only after this boundary remains intact should C6 continue with:

1. A non-binding pricing hypothesis based on beta feedback.
2. Paid beta acceptance criteria.
3. External review of any hosted dashboard or live AI provider payload.
4. A route self-check before any implementation beyond local docs/fixtures.

## Non-binding pricing hypothesis

This is a hypothesis for beta discovery, not a price sheet, invoice plan, billing implementation, legal offer, or payment flow.

### Packaging hypothesis

- **Open-source local CLI:** free. It should stay useful for individual Foundry teams and public repos.
- **Team beta support package:** paid only if a team wants guided onboarding, policy/baseline review, SARIF workflow help, and design-partner support.
- **Self-hosted team package:** likely the first serious commercial package because it preserves private-code boundaries and lets protocol teams keep deterministic tools inside their own runner.
- **Hosted dashboard package:** defer until metadata-only dashboard payloads, retention, access control, and privacy review are complete.

### Value metric hypothesis

Prefer simple team/repo packaging over usage-based billing during beta:

- Number of active private repositories under CI.
- Number of engineering/security seats reviewing findings.
- Level of support/onboarding needed.
- Whether self-hosted runner packaging is required.

Avoid pricing based on vulnerabilities found, code volume, funds secured, token value, transactions, TVL, or anything that could imply audit completeness, custody, insurance, or legal guarantee.

### Beta price-discovery bands

Use these only as conversation anchors with design partners:

- **Design-partner pilot:** free or nominal, in exchange for structured feedback and permission to improve workflows from anonymized lessons.
- **Small team support:** modest monthly/team support fee after local CI value is proven.
- **Serious protocol self-hosted support:** higher support retainer only when the team needs runner setup, policy tuning, SARIF workflow support, and review-process integration.

Do not implement billing, payment processing, subscription management, token payments, stablecoin payments, invoicing rails, refund flows, or tax/compliance automation in this repo.

### Pricing validation questions

Before any price becomes real:

- Did Contract Guard catch or clarify issues before audit or release?
- Did it reduce PR review time or make findings easier to triage?
- Did the baseline workflow avoid disabling the scanner entirely?
- Did the team accept the high-severity never-suppress policy?
- Did the team prefer self-hosted operation over hosted metadata views?
- Would they pay for support/onboarding, hosted visibility, or policy management?
- What privacy boundary would block purchase?

## Paid beta acceptance criteria

Paid beta should not start until the product has real validation beyond local fixtures.

### Required validation

- At least one real Foundry repository has run `contract-guard plan` and `contract-guard scan` locally.
- At least one repo-local GitHub Actions run has produced JSON/Markdown/SARIF artifacts.
- SARIF upload behavior is validated or documented as unsupported/blocked for that repo.
- Foundry and Slither versions are recorded for the partner environment.
- At least one non-high false-positive review record has been generated and reviewed by a human.
- High-severity findings are confirmed not suppressible by baseline.
- `.contract-guard-policy.json` is reviewed with the partner.
- The partner confirms Markdown output is safe enough for PR discussion because it omits raw stdout/stderr.
- The partner understands Contract Guard CI is not an audit replacement.

### Commercial-boundary acceptance

Before asking for payment, confirm:

- No private code upload is required.
- No hosted dashboard is required for the default package.
- No live AI provider call is required.
- No private snippets are sent.
- No custody, wallet, settlement, payment routing, stablecoin routing, or funds movement feature is involved.
- No legal/compliance guarantee is promised.
- The engagement is framed as security CI workflow support and beta feedback, not a certification.

### Paid beta stop conditions

Do not proceed to paid beta if:

- The team needs hosted private-code analysis before privacy review.
- The team asks for AI to be the sole security decision-maker.
- The team wants to suppress high-severity findings by baseline.
- The workflow cannot produce deterministic artifacts locally.
- GitHub/SARIF permissions are not understood.
- The team needs billing/payment rails implemented in this repository.
- Product copy starts implying full audit coverage, proof, certification, or guaranteed safety.
