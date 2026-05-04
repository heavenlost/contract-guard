# Design partner feedback

Contract Guard CI is looking for practical feedback from Foundry/EVM developers and protocol teams.

Public feedback issue: <https://github.com/heavenlost/contract-guard/issues/1>

## What we are validating

Contract Guard CI is a local-first security CI workflow for smart contract repositories. It wraps deterministic tools such as Foundry and Slither, then emits JSON, Markdown, and SARIF artifacts that are easier to use in pull-request review.

We are not validating an audit replacement, AI auditor, vulnerability scanner guarantee, hosted private-code service, wallet/custody product, payment rail, or legal/compliance product.

## Good feedback topics

Useful feedback answers questions like:

1. Would changed-only Markdown/SARIF reports help reviewers during PRs?
2. Would auditable baseline governance reduce false-positive fatigue, or add too much process?
3. Does local-first/no-private-upload matter for your team?
4. Would high-severity findings staying unsuppressed increase trust or create noise?
5. What would make you reject the workflow even if it is free?
6. Would setup/support/audit-readiness reporting be worth paying for?

## Safe local trial

Run only against code you are allowed to inspect locally. Do not paste private source or secrets into a public issue.

```bash
git clone https://github.com/heavenlost/contract-guard.git
cd contract-guard
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
./scripts/contract_guard.sh smoke
PYTHONPATH=src python3 -m contract_guard_ci.cli dogfood-readiness \
  --fixture-repo examples/foundry-defi-vault \
  --format markdown
```

For a private or partner repo, start with a no-tool dry run:

```bash
contract-guard plan --repo . --json
contract-guard scan --repo . --skip-foundry --skip-slither --format markdown
contract-guard scan --repo . --skip-foundry --skip-slither --format sarif
```

Only run real Foundry/Slither scans locally if the repository owner is comfortable doing so.

## What not to share publicly

Please do not post:

- private keys, mnemonics, RPC credentials, deployment credentials, or API tokens,
- private source snippets,
- raw stdout/stderr from private repositories,
- customer names,
- unpublished audit findings,
- local absolute paths,
- detailed vulnerability claims about third-party repositories.

High-level workflow feedback is enough.

## Feedback format

If you try the workflow, the most useful public comment is short:

```text
Repo shape: Foundry yes/no, public/private, protocol/library
What worked:
What was noisy/confusing:
Would Markdown/SARIF help PR review?
Would baseline governance help?
Does local-first/no-upload matter?
Would you pay for setup/support/reporting?
What would make you reject this?
```

## Boundary reminder

Contract Guard CI output is workflow evidence, not a complete audit, proof, certification, or guarantee. Deterministic tool results remain the source of truth. Optional AI explanation is advisory only and disabled for live providers by default.
