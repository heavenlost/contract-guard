# CI Supply-Chain Safety

Contract Guard CI should make Foundry/EVM security workflows safer, not introduce a new compromise path through GitHub Actions, npm packages, PR comments, or telemetry.

## Default stance

Do not run, recommend, or vendor unreviewed third-party GitHub Actions or packages in security-sensitive CI.

Prefer:

1. `forge build` / `forge test` as deterministic preconditions.
2. Reviewed local tools such as Foundry and Slither.
3. JSON / Markdown / SARIF artifacts generated locally.
4. Optional PR comments only from a trusted, minimal-permission step.
5. Full review before adding networked telemetry, hosted uploads, or live AI provider calls.

## Red flags

Treat these as blocking or requiring review:

- `uses: owner/action@v1`, `@main`, or any mutable tag for a third-party Action.
- `permissions: write-all`.
- `contents: write`, `actions: write`, `packages: write`, or `id-token: write` without a narrow reason.
- `pull_request_target` workflows that run untrusted PR context.
- `curl ... | bash`, `wget ... | sh`, or similar remote shell execution.
- npm/pip packages with `postinstall` or new/low-adoption packages suggested in issue comments.
- Actions that read `.env`, SSH keys, wallet/keystore paths, private keys, token-like environment variables, or raw stdout/stderr.
- Telemetry/analytics enabled by default in security workflows.
- PR comment steps that pass `GITHUB_TOKEN` to unreviewed third-party code.

## Local checker

Use the deterministic local checker before copying external workflow advice:

```bash
PYTHONPATH=src python3 -m contract_guard_ci.cli workflow-check --repo . --format markdown
```

To check one workflow file:

```bash
PYTHONPATH=src python3 -m contract_guard_ci.cli workflow-check \
  --repo . \
  --workflow .github/workflows/security.yml \
  --format json
```

The checker does not execute workflows, actions, packages, or shell commands. It only scans workflow text for high-risk CI supply-chain patterns.

## Non-claims

This is not a complete CI/CD security audit. It is a preflight lint to catch obvious supply-chain risks before a team runs suggested workflow code.
