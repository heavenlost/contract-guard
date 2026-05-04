# Aderyn deterministic tool-source feasibility

Date: 2026-05-03
Status: feasibility complete; wired into `contract-guard scan` only behind explicit `--include-aderyn` opt-in

This note evaluates Cyfrin Aderyn as a future deterministic analyzer source for Contract Guard CI. It is intentionally local-first and does not introduce hosted uploads, private snippets, live AI provider calls, billing/payment/custody features, GitHub App/Marketplace scope, or audit-completeness claims.

## Official source context

Public/official sources reviewed:

- Aderyn repository: <https://github.com/Cyfrin/aderyn>
- Aderyn CLI options: <https://cyfrin.gitbook.io/cyfrin-docs/aderyn/cli-options>
- Aderyn overview: <https://cyfrin.gitbook.io/cyfrin-docs>
- GitHub SARIF support docs: <https://docs.github.com/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning>

Aderyn is relevant because it is open source, Foundry/Hardhat-aware, and can emit Markdown, JSON, and SARIF. That overlaps with Slither/SARIF plumbing, so Contract Guard CI should treat Aderyn as another deterministic evidence source, not as an AI feature or audit replacement.

## Local feasibility probe

Aderyn was installed only into `/tmp/contract-guard-toolchains/aderyn-v0.6.8-aarch64-apple-darwin` using the public GitHub release asset. No global shell/profile/project dependency was modified.

Observed version:

```text
aderyn 0.6.8
```

The local fixture probe ran:

```bash
/tmp/contract-guard-toolchains/aderyn-v0.6.8-aarch64-apple-darwin/aderyn-aarch64-apple-darwin/aderyn \
  examples/foundry-defi-vault \
  -o /tmp/contract_guard_aderyn_fixture/aderyn.json
```

Observed fixture output:

- exit code: `0`
- JSON output size: `8023` bytes
- root keys included `files_summary`, `files_details`, `issue_count`, `high_issues`, `low_issues`, and `detectors_used`
- issue count: `1 high`, `8 low`
- example high detector: `reentrancy-state-change`
- Aderyn stdout included local absolute paths in its configuration banner, so Contract Guard CI should avoid rendering raw stdout in PR-style reports.

## Product implication

Aderyn is a credible future deterministic source, but it should not be wired broadly until developer validation says multi-analyzer evidence is useful. The lowest-risk integration order is:

1. Keep a pure JSON normalizer covered by tests.
2. Add explicit `--include-aderyn` or policy opt-in; do not run it by default until report noise and runtime are validated.
3. Keep Aderyn findings separate as `tool=aderyn`, not merged indistinguishably into Slither findings.
4. Preserve Contract Guard CI's failure policy semantics instead of trusting analyzer exit behavior.
5. Keep raw stdout/stderr out of Markdown/PR reports because tool banners can include local paths.

## Local code foundation added

`src/contract_guard_ci/aderyn.py` now contains a pure `normalize_aderyn_payload` helper. It converts Aderyn JSON into Contract Guard's deterministic finding shape with:

- stable finding IDs: `aderyn:<detector>:<file>:<line>`
- severity bucket mapping from Aderyn issue sections
- `confidence=unknown` because the observed JSON does not provide a confidence field
- path-safe handling for absolute `contract_path` values
- no snippets by default
- diagnostics for invalid JSON root/shape mismatches

## Explicit opt-in scan wiring

`contract-guard scan --include-aderyn` now runs Aderyn as an additional deterministic analyzer only when:

- the flag is explicitly present,
- Solidity files are detected,
- `aderyn` is available on `PATH`, and
- the usual per-tool timeout permits completion.

Default scans are unchanged: Foundry and Slither remain the default deterministic checks, and Aderyn is absent unless opted in. When opted in, Contract Guard CI:

- writes the Aderyn JSON output to a temporary local file,
- normalizes findings through `normalize_aderyn_payload`,
- keeps Aderyn findings under `tool=aderyn`, separate from Slither,
- can render Aderyn findings in JSON, Markdown, and SARIF,
- redacts the temporary output path from the serialized command as `<temporary-json-output>`,
- does not render raw Aderyn stdout/stderr banners in Markdown reports, and
- keeps no hosted upload, private snippet, live AI provider, payment/custody/billing, or audit-completeness behavior.

Because Aderyn confidence is currently normalized as `unknown`, the default failure policy (`--fail-on-severity high --fail-on-confidence low`) does not gate on Aderyn findings. Teams that explicitly want high-severity unknown-confidence analyzer findings to fail CI can combine `--include-aderyn` with `--fail-on-confidence none` after reviewing report noise.
