from __future__ import annotations

import argparse
from pathlib import Path

from .core import dumps_json, plan_payload, render_markdown, render_sarif, scan_repo
from .ai_triage import ai_triage_config, ai_triage_explanation, ai_triage_payload, combined_ai_triage_report, dumps_ai_triage_json, render_ai_triage_config_markdown, render_ai_triage_explanation_markdown, render_ai_triage_markdown, render_combined_ai_triage_markdown
from .false_positives import dumps_false_positive_json, false_positive_review_payload, render_false_positive_markdown
from .fuzzing import dumps_fuzz_hooks_json, fuzz_hooks_payload, render_fuzz_hooks_markdown
from .invariants import dumps_invariant_json, invariant_payload, render_invariant_markdown
from .policy import dumps_policy_json, load_policy, render_policy_markdown
from .dogfood import build_payload as dogfood_payload, render_dogfood_markdown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="contract-guard", description="Smart contract security CI wrapper")
    sub = parser.add_subparsers(dest="command", required=True)

    plan_p = sub.add_parser("plan", help="Probe repository/tool readiness")
    plan_p.add_argument("--repo", default=".", help="Repository path")
    plan_p.add_argument("--json", action="store_true", help="Emit JSON")

    scan_p = sub.add_parser("scan", help="Run available security checks")
    scan_p.add_argument("--repo", default=".", help="Repository path")
    scan_p.add_argument("--timeout", type=int, default=300, help="Timeout per external tool")
    scan_p.add_argument("--skip-foundry", action="store_true", help="Skip forge test")
    scan_p.add_argument("--skip-slither", action="store_true", help="Skip slither")
    scan_p.add_argument("--include-aderyn", action="store_true", help="Explicit opt-in: run Aderyn as an additional deterministic analyzer when available")
    scan_p.add_argument("--format", choices=["json", "markdown", "sarif"], default="json")
    scan_p.add_argument("--changed-only", action="store_true", help="Use git diff --name-only to scope Slither findings to changed Solidity files")
    scan_p.add_argument("--diff-base", default=None, help="Optional git diff base ref, for example origin/main...HEAD")
    scan_p.add_argument("--baseline-file", default=None, help="Optional JSON baseline file with explicit non-high Slither suppressions")
    scan_p.add_argument("--fail-on-severity", choices=["high", "medium", "low", "informational", "none"], default="high", help="Fail CI when active deterministic static findings meet or exceed this severity")
    scan_p.add_argument("--fail-on-confidence", choices=["high", "medium", "low", "none"], default="low", help="Fail CI when active Slither findings meet or exceed this confidence; use none to ignore confidence")

    inv_p = sub.add_parser("invariants", help="Generate advisory Foundry invariant templates")
    inv_p.add_argument("--profile", choices=["all", "erc20", "vault", "access-control"], default="all", help="Protocol pattern to generate templates for")
    inv_p.add_argument("--contract", default="Protocol", help="Target contract type/name used in snippets")
    inv_p.add_argument("--test-contract", default=None, help="Optional invariant test contract name")
    inv_p.add_argument("--format", choices=["json", "markdown"], default="markdown")

    fuzz_p = sub.add_parser("fuzz-hooks", help="Generate scaffold-only Echidna/Medusa hook commands")
    fuzz_p.add_argument("--tool", choices=["all", "echidna", "medusa"], default="all", help="Fuzzer hook to scaffold")
    fuzz_p.add_argument("--target", default="test/invariants/InvariantTest.sol", help="Foundry invariant target path")
    fuzz_p.add_argument("--contract", default="InvariantTest", help="Invariant test contract name")
    fuzz_p.add_argument("--echidna-config", default="echidna.yaml", help="Echidna config path for the command scaffold")
    fuzz_p.add_argument("--medusa-config", default="medusa.json", help="Medusa config path for the command scaffold")
    fuzz_p.add_argument("--format", choices=["json", "markdown"], default="markdown")

    fp_p = sub.add_parser("false-positive", help="Generate an auditable false-positive baseline candidate")
    fp_p.add_argument("--id", default="", help="Optional deterministic finding id")
    fp_p.add_argument("--check", required=True, help="Analyzer check name, for example unchecked-transfer")
    fp_p.add_argument("--file", required=True, help="Repository-relative finding path")
    fp_p.add_argument("--start-line", type=int, required=True, help="Finding start line")
    fp_p.add_argument("--severity", choices=["high", "medium", "low", "informational", "optimization"], required=True)
    fp_p.add_argument("--confidence", choices=["high", "medium", "low", "unknown"], default="unknown")
    fp_p.add_argument("--classification", choices=["false-positive", "accepted-risk", "tool-noise"], default="false-positive")
    fp_p.add_argument("--reason", required=True, help="Human-readable reason for the classification")
    fp_p.add_argument("--reviewer", required=True, help="Reviewer or team owner approving the record")
    fp_p.add_argument("--expires", default="", help="Optional review expiry date")
    fp_p.add_argument("--format", choices=["json", "markdown"], default="markdown")

    policy_p = sub.add_parser("policy", help="Validate and render local Contract Guard repo policy")
    policy_p.add_argument("--repo", default=".", help="Repository path")
    policy_p.add_argument("--policy-file", default=None, help="Optional policy file path; defaults to .contract-guard-policy.json")
    policy_p.add_argument("--format", choices=["json", "markdown"], default="json")

    dogfood_p = sub.add_parser("dogfood-readiness", help="Run the local beta dogfood readiness fixture bundle")
    dogfood_p.add_argument("--fixture-repo", default="examples/foundry-basic", help="Repo path to exercise, relative to this checkout by default")
    dogfood_p.add_argument("--output-dir", default="/tmp/contract-guard-dogfood-readiness", help="Directory for local JSON/Markdown/SARIF outputs")
    dogfood_p.add_argument("--format", choices=["json", "markdown"], default="json")

    triage_p = sub.add_parser("ai-triage-payload", help="Build a redacted advisory-only AI triage payload without external calls")
    triage_p.add_argument("--id", default="", help="Optional deterministic finding id")
    triage_p.add_argument("--tool", default="slither", help="Source deterministic tool")
    triage_p.add_argument("--check", required=True, help="Analyzer check name")
    triage_p.add_argument("--file", required=True, help="Repository-relative finding path")
    triage_p.add_argument("--start-line", type=int, default=None, help="Finding start line")
    triage_p.add_argument("--severity", default="unknown", help="Finding severity")
    triage_p.add_argument("--confidence", default="unknown", help="Finding confidence")
    triage_p.add_argument("--description", default="", help="Short deterministic finding description")
    triage_p.add_argument("--snippet", default="", help="Optional local snippet; dropped unless --include-redacted-snippet is set")
    triage_p.add_argument("--include-redacted-snippet", action="store_true", help="Include a deterministically redacted snippet; never sends private snippets")
    triage_p.add_argument("--format", choices=["json", "markdown"], default="json")

    explain_p = sub.add_parser("ai-triage-explain", help="Build a local advisory explanation from a redacted triage payload")
    explain_p.add_argument("--id", default="", help="Optional deterministic finding id")
    explain_p.add_argument("--tool", default="slither", help="Source deterministic tool")
    explain_p.add_argument("--check", required=True, help="Analyzer check name")
    explain_p.add_argument("--file", required=True, help="Repository-relative finding path")
    explain_p.add_argument("--start-line", type=int, default=None, help="Finding start line")
    explain_p.add_argument("--severity", default="unknown", help="Finding severity")
    explain_p.add_argument("--confidence", default="unknown", help="Finding confidence")
    explain_p.add_argument("--description", default="", help="Short deterministic finding description")
    explain_p.add_argument("--snippet", default="", help="Optional local snippet; dropped unless --include-redacted-snippet is set")
    explain_p.add_argument("--include-redacted-snippet", action="store_true", help="Include a deterministically redacted snippet in the local payload")
    explain_p.add_argument("--format", choices=["json", "markdown"], default="markdown")

    triage_config_p = sub.add_parser("ai-triage-config", help="Validate optional AI triage provider opt-in boundaries without making external calls")
    triage_config_p.add_argument("--provider", choices=["none", "openai", "anthropic", "custom"], default="none", help="Future AI provider selection; none by default")
    triage_config_p.add_argument("--enable-external-provider", action="store_true", help="Explicit opt-in gate for future provider payloads")
    triage_config_p.add_argument("--include-redacted-snippets", action="store_true", help="Explicit opt-in gate for redacted snippets in a future provider payload")
    triage_config_p.add_argument("--allow-private-snippets", action="store_true", help="Blocked: private snippets must never be sent")
    triage_config_p.add_argument("--allow-hosted-uploads", action="store_true", help="Blocked: hosted uploads are not enabled by this CLI")
    triage_config_p.add_argument("--format", choices=["json", "markdown"], default="json")

    combined_p = sub.add_parser("ai-triage-combined", help="Render deterministic evidence and advisory AI text as separate sections")
    combined_p.add_argument("--id", default="", help="Optional deterministic finding id")
    combined_p.add_argument("--tool", default="slither", help="Source deterministic tool")
    combined_p.add_argument("--check", required=True, help="Analyzer check name")
    combined_p.add_argument("--file", required=True, help="Repository-relative finding path")
    combined_p.add_argument("--start-line", type=int, default=None, help="Finding start line")
    combined_p.add_argument("--severity", default="unknown", help="Finding severity")
    combined_p.add_argument("--confidence", default="unknown", help="Finding confidence")
    combined_p.add_argument("--description", default="", help="Short deterministic finding description")
    combined_p.add_argument("--snippet", default="", help="Optional local snippet; dropped unless --include-redacted-snippet is set")
    combined_p.add_argument("--include-redacted-snippet", action="store_true", help="Include a deterministically redacted snippet in the local payload")
    combined_p.add_argument("--format", choices=["json", "markdown"], default="markdown")

    args = parser.parse_args(argv)
    if args.command == "plan":
        repo = Path(args.repo)
        payload = plan_payload(repo)
        if args.json:
            print(dumps_json(payload))
        else:
            print(render_markdown({"ok": True, "plan": payload["plan"], "results": []}))
        return 0

    if args.command == "scan":
        repo = Path(args.repo)
        payload = scan_repo(
            repo,
            timeout_seconds=args.timeout,
            skip_foundry=args.skip_foundry,
            skip_slither=args.skip_slither,
            include_aderyn=args.include_aderyn,
            changed_only=args.changed_only,
            diff_base=args.diff_base,
            baseline_file=args.baseline_file,
            fail_on_severity=args.fail_on_severity,
            fail_on_confidence=args.fail_on_confidence,
        )
        if args.format == "markdown":
            print(render_markdown(payload))
        elif args.format == "sarif":
            print(dumps_json(render_sarif(payload)))
        else:
            print(dumps_json(payload))
        return 0 if payload["ok"] else 1

    if args.command == "invariants":
        payload = invariant_payload(profile=args.profile, contract_name=args.contract, test_contract_name=args.test_contract)
        if args.format == "json":
            print(dumps_invariant_json(payload))
        else:
            print(render_invariant_markdown(payload))
        return 0

    if args.command == "fuzz-hooks":
        payload = fuzz_hooks_payload(
            tool=args.tool,
            target=args.target,
            contract_name=args.contract,
            echidna_config=args.echidna_config,
            medusa_config=args.medusa_config,
        )
        if args.format == "json":
            print(dumps_fuzz_hooks_json(payload))
        else:
            print(render_fuzz_hooks_markdown(payload))
        return 0

    if args.command == "false-positive":
        payload = false_positive_review_payload(
            finding_id=args.id,
            check=args.check,
            file=args.file,
            start_line=args.start_line,
            severity=args.severity,
            confidence=args.confidence,
            classification=args.classification,
            reason=args.reason,
            reviewer=args.reviewer,
            expires=args.expires,
        )
        if args.format == "json":
            print(dumps_false_positive_json(payload))
        else:
            print(render_false_positive_markdown(payload))
        return 0

    if args.command == "policy":
        repo = Path(args.repo)
        payload = load_policy(repo, args.policy_file)
        if args.format == "markdown":
            print(render_policy_markdown(payload))
        else:
            print(dumps_policy_json(payload))
        return 0 if payload["ok"] else 1

    if args.command == "dogfood-readiness":
        payload = dogfood_payload(args.fixture_repo, Path(args.output_dir))
        if args.format == "markdown":
            print(render_dogfood_markdown(payload), end="")
        else:
            print(dumps_json(payload))
        return 0 if payload["ok"] else 1

    if args.command == "ai-triage-payload":
        payload = ai_triage_payload(
            finding_id=args.id,
            tool=args.tool,
            check=args.check,
            severity=args.severity,
            confidence=args.confidence,
            file=args.file,
            start_line=args.start_line,
            description=args.description,
            snippet=args.snippet,
            include_redacted_snippet=args.include_redacted_snippet,
        )
        if args.format == "markdown":
            print(render_ai_triage_markdown(payload))
        else:
            print(dumps_ai_triage_json(payload))
        return 0

    if args.command == "ai-triage-explain":
        payload = ai_triage_payload(
            finding_id=args.id,
            tool=args.tool,
            check=args.check,
            severity=args.severity,
            confidence=args.confidence,
            file=args.file,
            start_line=args.start_line,
            description=args.description,
            snippet=args.snippet,
            include_redacted_snippet=args.include_redacted_snippet,
        )
        explanation = ai_triage_explanation(payload)
        if args.format == "json":
            print(dumps_ai_triage_json(explanation))
        else:
            print(render_ai_triage_explanation_markdown(explanation))
        return 0

    if args.command == "ai-triage-config":
        payload = ai_triage_config(
            provider=args.provider,
            enable_external_provider=args.enable_external_provider,
            include_redacted_snippets=args.include_redacted_snippets,
            allow_private_snippets=args.allow_private_snippets,
            allow_hosted_uploads=args.allow_hosted_uploads,
        )
        if args.format == "markdown":
            print(render_ai_triage_config_markdown(payload))
        else:
            print(dumps_ai_triage_json(payload))
        return 0 if payload["ok"] else 1

    if args.command == "ai-triage-combined":
        payload = ai_triage_payload(
            finding_id=args.id,
            tool=args.tool,
            check=args.check,
            severity=args.severity,
            confidence=args.confidence,
            file=args.file,
            start_line=args.start_line,
            description=args.description,
            snippet=args.snippet,
            include_redacted_snippet=args.include_redacted_snippet,
        )
        report = combined_ai_triage_report(ai_triage_explanation(payload))
        if args.format == "json":
            print(dumps_ai_triage_json(report))
        else:
            print(render_combined_ai_triage_markdown(report))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
