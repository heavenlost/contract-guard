# Public Foundry dogfood candidates

Date: 2026-05-03
Scope: public metadata plus read-only local dogfood notes; no PRs, issues, maintainer contact, private-code upload, or hosted execution.

This document identifies open-source Foundry repositories that can be used later to test whether Contract Guard CI works beyond local fixtures. The goal is not to audit these projects. The goal is to select dogfood targets that stress real repo layouts, dependencies, Slither/Foundry integration, SARIF output, baseline suppression, and false-positive workflows.

## Source context

Contract Guard CI is being positioned around existing, proven primitives rather than replacing them:

- Foundry's official docs describe `forge test` as Solidity-native testing for files under `test/`, with pass/fail output that CI can normalize: <https://www.getfoundry.sh/forge/testing>
- Slither's official repository describes it as a Solidity/Vyper static analyzer that can run on Hardhat/Foundry apps, integrate into CI, and integrate with GitHub code scanning: <https://github.com/crytic/slither>
- GitHub docs describe uploading third-party SARIF 2.1.0 output to code scanning through GitHub Actions/API, with repository permission and private-repo feature caveats: <https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github>
- GitHub SARIF support docs define the constraints needed for code scanning compatibility: <https://docs.github.com/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning>
- Crytic already provides a Slither GitHub Action, so Contract Guard CI must differentiate beyond “run Slither in CI”: <https://github.com/marketplace/actions/slither-action>

## Candidate scoring rubric

Score each candidate for future dogfood with these dimensions:

- **Foundry fit**: has `foundry.toml`, Solidity primary language, and `test/` style layout.
- **Realism**: production-like protocol or widely used library, not only an educational toy.
- **Complexity**: enough imports/remappings/workflows to expose integration problems, but not so large that first validation becomes unmanageable.
- **CI/SARIF relevance**: has GitHub Actions or strong GitHub workflow fit.
- **Noise value**: likely to produce useful baseline/false-positive governance lessons.
- **Safety**: public code only; no private data or maintainer contact without separate confirmation.

## Recommended candidates

| Rank | Repo | Why it is useful | Metadata observed | First dogfood mode | Risk / caveat |
|---:|---|---|---|---|---|
| 1 | [morpho-org/morpho-blue](https://github.com/morpho-org/morpho-blue) | Real DeFi lending market with Foundry layout; closer to target buyer than libraries or education repos. | Solidity primary language; public; `foundry.toml` present; GitHub workflows present; ~310 stars / 159 forks observed via GitHub metadata. | Start with `contract-guard plan`, then dry-run `scan --skip-*`, then real Foundry/Slither only after dependencies are understood. | License is not MIT/Apache in metadata; treat as public dogfood only, no reuse. |
| 2 | [Uniswap/v4-core](https://github.com/Uniswap/v4-core) | High-profile real protocol core with Foundry/remappings/workflows; strong stress test for changed-only, baseline, SARIF, and dependency handling. | Solidity primary language; public; `foundry.toml`, `remappings.txt`, and GitHub workflows present; ~2479 stars / 1283 forks observed. | Stretch dogfood after smaller repo succeeds. | Very complex and high-profile; first failure may be integration noise, not product failure. |
| 3 | [Vectorized/solady](https://github.com/Vectorized/solady) | Widely used optimized Solidity library; good for detector noise, false-positive review, and Markdown/SARIF report readability. | Solidity primary language; public; `foundry.toml` and GitHub workflows present; ~3303 stars / 466 forks observed. | Library dogfood for baseline/noise governance. | Library findings differ from protocol findings; not enough by itself to validate buyer workflow. |
| 4 | [Uniswap/v4-periphery](https://github.com/Uniswap/v4-periphery) | Real integration/periphery contracts around v4; useful after v4-core for changed-only and dependency-heavy repo behavior. | Solidity primary language; public; `foundry.toml`, `remappings.txt`, and GitHub workflows present; ~880 stars / 650 forks observed. | Secondary Uniswap dogfood target. | Large dependency surface; likely requires careful setup. |
| 5 | [transmissions11/solmate](https://github.com/transmissions11/solmate) | Classic Foundry-era Solidity building-block library; likely manageable and good for baseline examples. | Solidity primary language; public; `foundry.toml` and GitHub workflows present; ~4276 stars / 707 forks observed. | Small library dogfood before larger protocol repos. | Lower recent activity than other candidates; not representative of active protocol PR workflows. |

## Alternates, not first-line buyer validation

| Repo | Use | Why not first-line |
|---|---|---|
| [OpenZeppelin/openzeppelin-contracts](https://github.com/OpenZeppelin/openzeppelin-contracts) | Excellent stress test for library scale, SARIF volume, and baseline noise. | Huge, mature library; not a likely early design partner and may overwhelm early validation. |
| [foundry-rs/forge-std](https://github.com/foundry-rs/forge-std) | Validates Foundry-native library workflow. | Infrastructure library, not a protocol buyer. |
| [SunWeb3Sec/DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) | Vulnerability corpus and case-study inspiration. | Educational/exploit reproduction corpus, not a normal development team workflow. |
| [SunWeb3Sec/DeFiVulnLabs](https://github.com/SunWeb3Sec/DeFiVulnLabs) | Training examples for known vulnerability patterns. | Good learning fixture, weak willingness-to-pay signal. |

## Proposed dogfood sequence

1. **Metadata-only pass**: keep the current document up to date; do not contact maintainers.
2. **Local public clone pass** *(requires no private data, but should still be recorded)*:
   - clone to `/tmp/contract-guard-public-dogfood/<repo>`;
   - run `contract-guard plan --repo <repo> --json`;
   - run dry-run `scan --skip-foundry --skip-slither` to verify report plumbing;
   - inspect dependency/install requirements without uploading artifacts.
3. **Real deterministic tool pass**:
   - install/pin Foundry and Slither only if needed;
   - run real `forge test` and `slither . --json -` locally;
   - record setup blockers and false-positive volume.
4. **Design-partner pass**:
   - only after public repo dogfood is stable;
   - ask 1-2 Web3 developers whether the flow would be useful in PRs;
   - ask willingness-to-pay questions from `docs/demo-case-study.md`.

## First public clone dry-run result

The top candidate, `morpho-org/morpho-blue`, is useful for local read-only dogfood because it is a public Foundry repository with real protocol-style structure. Any dogfood result should be treated only as workflow validation, not as an audit, endorsement, or vulnerability report.

## Product differentiation implied by candidate research

Because official Slither Action already exists, Contract Guard CI should not compete as “one more Slither runner.” The likely differentiated wedge is:

- deterministic Foundry + Slither normalization into one stable v1 report schema;
- PR changed-only scoping;
- baseline suppression that cannot hide high-severity findings;
- auditable false-positive records with reviewer/reason/expiry;
- GitHub SARIF plus Markdown PR evidence;
- optional local/advisory AI explanation kept separate from deterministic evidence;
- pre-audit readiness packaging for teams that want a process, not just raw analyzer output.

## Go/no-go signals to collect

Continue investing if public dogfood and developer conversations show:

- real repos can be onboarded without fragile custom setup;
- high-severity findings and baseline governance are understandable to developers;
- SARIF/Markdown artifacts are useful in PR review;
- at least one developer/team says they would pay for setup, policy tuning, or audit-readiness reporting.

Stop or pivot if:

- most target teams already have equivalent CI and do not value governance/reporting;
- Slither/Foundry setup costs dominate the value;
- SARIF and baseline workflows create more noise than trust;
- willingness to pay is only for manual consulting, not repeatable tooling.
