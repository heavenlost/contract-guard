from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .core import plan_payload, render_markdown, render_sarif, scan_repo
from .policy import load_policy, render_policy_markdown
from .workflow_safety import render_workflow_safety_markdown, workflow_safety_payload

SCHEMA = "contract_guard_evidence_pack/v1"
SCHEMA_VERSION = "1"
MANIFEST_SCHEMA_VERSION = "contract_guard_pre_audit_evidence_pack/v0.1"
DEFAULT_OUTPUT_DIR = Path("/tmp/contract_guard_evidence_pack")
LOCAL_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])/(?:Users|private|tmp|var|opt|home|Volumes|Applications)/[^\s,`\"')]+")


def dumps_evidence_pack_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


def build_evidence_pack(
    repo: Path,
    output_dir: Path,
    *,
    repo_label: str | None = None,
    run_local_tools: bool = False,
    policy_file: str | None = None,
    baseline_file: str | None = None,
    fail_on_severity: str = "high",
    fail_on_confidence: str = "low",
) -> dict[str, Any]:
    repo = repo.resolve()
    output_dir = output_dir.resolve()
    repo_label = repo_label or repo.name or "repo"
    baseline_file = baseline_file or _default_baseline(repo)

    dirs = _ensure_layout(output_dir)
    commands: list[dict[str, Any]] = []

    plan = _sanitize(plan_payload(repo), repo)
    _write_json(dirs["deterministic"] / "plan.json", plan)
    commands.append(_command_record("plan", "contract-guard plan --repo . --json", "deterministic-evidence/plan.json", True))

    policy = load_policy(repo, policy_file)
    (dirs["policy"] / "policy.md").write_text(render_policy_markdown(policy), encoding="utf-8")
    commands.append(_command_record("policy", "contract-guard policy --repo . --format markdown", "policy-and-baseline/policy.md", policy.get("ok", False)))

    workflow = workflow_safety_payload(repo)
    (dirs["workflow"] / "workflow-check.md").write_text(render_workflow_safety_markdown(workflow), encoding="utf-8")
    commands.append(_command_record("workflow-check", "contract-guard workflow-check --repo . --format markdown", "workflow-and-supply-chain/workflow-check.md", workflow.get("ok", False)))

    scan = _sanitize(
        scan_repo(
            repo,
            skip_foundry=not run_local_tools,
            skip_slither=not run_local_tools,
            baseline_file=baseline_file,
            fail_on_severity=fail_on_severity,
            fail_on_confidence=fail_on_confidence,
        ),
        repo,
    )
    _write_json(dirs["deterministic"] / "scan.json", scan)
    (dirs["deterministic"] / "scan.md").write_text(render_markdown(scan), encoding="utf-8")
    _write_json(dirs["deterministic"] / "scan.sarif", render_sarif(scan))
    commands.extend(
        [
            _command_record("scan-json", _scan_command(run_local_tools, "json"), "deterministic-evidence/scan.json", scan.get("ok", False)),
            _command_record("scan-markdown", _scan_command(run_local_tools, "markdown"), "deterministic-evidence/scan.md", scan.get("ok", False)),
            _command_record("scan-sarif", _scan_command(run_local_tools, "sarif"), "deterministic-evidence/scan.sarif", scan.get("ok", False)),
        ]
    )

    trust_readiness = _trust_readiness(repo, workflow)
    safety = _safety(run_local_tools)
    pack_status = _pack_status(scan, workflow)
    manifest = _manifest(repo_label, repo, plan, scan, policy, workflow, trust_readiness, safety, commands, pack_status)
    _write_json(output_dir / "manifest.json", manifest)

    _write_supporting_markdown(output_dir, dirs, repo_label, scan, policy, workflow, trust_readiness, safety, pack_status, run_local_tools, baseline_file)

    checks = _checks(output_dir, manifest, plan, scan)
    ok = all(command["ok"] for command in commands) and all(check["ok"] for check in checks) and pack_status != "blocked"
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "ok": ok,
        "status": "passed" if ok else "needs_attention",
        "pack_status": pack_status,
        "repo_label": repo_label,
        "output_dir": str(output_dir),
        "manifest": str(output_dir / "manifest.json"),
        "commands": commands,
        "checks": checks,
        "safety": safety,
        "trust_readiness": trust_readiness,
        "non_claims": manifest["non_claims"],
    }


def render_evidence_pack_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Contract Guard Pre-Audit Evidence Pack",
        "",
        f"Status: `{payload['status']}`",
        f"Pack status: `{payload['pack_status']}`",
        f"Repo label: `{payload['repo_label']}`",
        f"Output dir: `{payload['output_dir']}`",
        f"Manifest: `{payload['manifest']}`",
        "",
        "## Safety boundaries",
        "",
    ]
    for key, value in payload["safety"].items():
        lines.append(f"- {key}: `{str(value).lower()}`")
    lines.extend(["", "## Trust readiness", ""])
    for key, value in payload["trust_readiness"].items():
        lines.append(f"- {key}: `{value}`")
    lines.extend(["", "## Commands", ""])
    for command in payload["commands"]:
        lines.append(f"- `{command['name']}`: {'PASS' if command['ok'] else 'NEEDS REVIEW'} -> `{command['artifact']}`")
    lines.extend(["", "## Checks", ""])
    for check in payload["checks"]:
        lines.append(f"- `{check['name']}`: {'PASS' if check['ok'] else 'FAIL'}")
    lines.extend(["", "## Non-claims", ""])
    for claim in payload["non_claims"]:
        lines.append(f"- `{claim}`")
    return "\n".join(lines) + "\n"


def _ensure_layout(output_dir: Path) -> dict[str, Path]:
    dirs = {
        "deterministic": output_dir / "deterministic-evidence",
        "policy": output_dir / "policy-and-baseline",
        "workflow": output_dir / "workflow-and-supply-chain",
        "human": output_dir / "human-review",
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    for path in dirs.values():
        path.mkdir(parents=True, exist_ok=True)
    return dirs


def _default_baseline(repo: Path) -> str | None:
    path = repo / ".contract-guard-baseline.json"
    return ".contract-guard-baseline.json" if path.exists() else None


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _command_record(name: str, command: str, artifact: str, ok: bool) -> dict[str, Any]:
    return {"name": name, "kind": "deterministic", "command": command, "artifact": artifact, "required": True, "ok": bool(ok)}


def _scan_command(run_local_tools: bool, fmt: str) -> str:
    flags = "" if run_local_tools else " --skip-foundry --skip-slither"
    return f"contract-guard scan --repo .{flags} --format {fmt}"


def _safety(run_local_tools: bool) -> dict[str, bool]:
    return {
        "external_services_used": False,
        "run_local_tools_enabled": bool(run_local_tools),
        "hosted_upload_required": False,
        "private_snippets_included": False,
        "raw_stdout_stderr_included": False,
        "live_ai_provider_called": False,
        "payment_or_custody_scope": False,
        "audit_or_compliance_claim": False,
    }


def _pack_status(scan: dict[str, Any], workflow: dict[str, Any]) -> str:
    if not scan.get("ok") or not workflow.get("ok"):
        return "blocked"
    return "ready_for_human_review"


def _manifest(
    repo_label: str,
    repo: Path,
    plan: dict[str, Any],
    scan: dict[str, Any],
    policy: dict[str, Any],
    workflow: dict[str, Any],
    trust_readiness: dict[str, str],
    safety: dict[str, bool],
    commands: list[dict[str, Any]],
    pack_status: str,
) -> dict[str, Any]:
    plan_summary = plan.get("summary", {})
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "pack_status": pack_status,
        "created_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "source_of_truth": "deterministic_tools",
        "advisory_ai_included": False,
        "hosted_upload_required": safety["hosted_upload_required"],
        "private_snippets_included": safety["private_snippets_included"],
        "raw_stdout_stderr_included": safety["raw_stdout_stderr_included"],
        "payment_or_custody_scope": safety["payment_or_custody_scope"],
        "audit_or_compliance_claim": safety["audit_or_compliance_claim"],
        "repo_context": {
            "repo_label": repo_label,
            "commit_ref": _git_ref(repo),
            "solidity_layout": _solidity_layout(repo),
            "foundry_detected": bool(plan_summary.get("foundry_project")),
            "slither_available": _tool_available(plan, "slither"),
        },
        "commands": commands,
        "artifacts": _artifacts(),
        "summary": {
            "plan_status": plan.get("status"),
            "scan_status": scan.get("status"),
            "policy_status": policy.get("status"),
            "workflow_status": workflow.get("status"),
            "active_findings": _active_findings(scan),
            "workflow_findings": workflow.get("summary", {}).get("findings", 0),
        },
        "trust_readiness": trust_readiness,
        "non_claims": [
            "not_an_audit",
            "not_formal_verification",
            "not_a_security_guarantee",
            "not_legal_or_compliance_advice",
            "not_payment_or_custody_infrastructure",
        ],
    }


def _artifacts() -> list[dict[str, Any]]:
    specs = [
        ("deterministic-evidence/plan.json", "repo_readiness_plan", True),
        ("deterministic-evidence/scan.json", "deterministic_scan_report", True),
        ("deterministic-evidence/scan.md", "deterministic_markdown_report", True),
        ("deterministic-evidence/scan.sarif", "deterministic_sarif_report", False),
        ("policy-and-baseline/policy.md", "policy_rendering", True),
        ("policy-and-baseline/baseline-review.md", "baseline_governance", True),
        ("workflow-and-supply-chain/workflow-check.md", "workflow_supply_chain_lint", True),
        ("workflow-and-supply-chain/permission-matrix.md", "permission_matrix", True),
        ("workflow-and-supply-chain/trust-readiness.md", "trust_readiness", True),
        ("workflow-and-supply-chain/data-flow.md", "data_flow_boundary", True),
        ("workflow-and-supply-chain/runner-guidance.md", "runner_guidance", True),
        ("human-review/readiness-summary.md", "human_review_summary", True),
        ("human-review/open-questions.md", "open_questions", True),
    ]
    return [
        {
            "path": path,
            "kind": kind,
            "required_for_pack": required,
            "contains_private_snippets": False,
            "contains_raw_stdout_stderr": False,
        }
        for path, kind, required in specs
    ]


def _write_supporting_markdown(
    output_dir: Path,
    dirs: dict[str, Path],
    repo_label: str,
    scan: dict[str, Any],
    policy: dict[str, Any],
    workflow: dict[str, Any],
    trust_readiness: dict[str, str],
    safety: dict[str, bool],
    pack_status: str,
    run_local_tools: bool,
    baseline_file: str | None,
) -> None:
    (output_dir / "README.md").write_text(_readme(repo_label, pack_status), encoding="utf-8")
    (dirs["policy"] / "baseline-review.md").write_text(_baseline_review(scan, baseline_file), encoding="utf-8")
    (dirs["workflow"] / "permission-matrix.md").write_text(_permission_matrix(workflow), encoding="utf-8")
    (dirs["workflow"] / "trust-readiness.md").write_text(_trust_markdown(trust_readiness), encoding="utf-8")
    (dirs["workflow"] / "data-flow.md").write_text(_data_flow(safety), encoding="utf-8")
    (dirs["workflow"] / "runner-guidance.md").write_text(_runner_guidance(), encoding="utf-8")
    (dirs["human"] / "readiness-summary.md").write_text(_readiness_summary(scan, policy, workflow, pack_status, run_local_tools), encoding="utf-8")
    (dirs["human"] / "open-questions.md").write_text(_open_questions(), encoding="utf-8")


def _readme(repo_label: str, pack_status: str) -> str:
    return f"""# Contract Guard Pre-Audit Evidence Pack

Repo label: `{repo_label}`
Pack status: `{pack_status}`

This pack is deterministic local evidence plus human-review scaffolding. It is not an audit, proof, guarantee, certification, legal/compliance opinion, hosted private-code scanner, payment rail, wallet, or custody product.

Read `manifest.json` first, then review deterministic evidence, policy/baseline governance, workflow/supply-chain trust, and human-review notes.
"""


def _baseline_review(scan: dict[str, Any], baseline_file: str | None) -> str:
    baseline = scan.get("baseline", {})
    return "\n".join(
        [
            "# Baseline governance review",
            "",
            f"- Baseline file: `{baseline_file or 'not_configured'}`",
            f"- Baseline enabled: `{str(baseline.get('enabled', False)).lower()}`",
            f"- Suppression count: `{baseline.get('suppression_count', 0)}`",
            "- High severity never silently suppressed: `true`",
            "- Baseline candidates are for non-high findings only and require reviewer, reason, and expiry context.",
            "",
            "Non-claim: baseline governance is not an audit and does not prove findings are false positives.",
        ]
    ) + "\n"


def _permission_matrix(workflow: dict[str, Any]) -> str:
    findings = workflow.get("findings", [])
    write_findings = [f for f in findings if f.get("rule_id") in {"broad_permissions_write_all", "write_permission_requested"}]
    lines = [
        "# Permission matrix",
        "",
        "| Surface | Default | Evidence-pack stance |",
        "| --- | --- | --- |",
        "| Repository contents | `read` | enough for local checkout and deterministic reports |",
        "| Security events / SARIF | `write` only if SARIF upload is explicitly enabled | optional; Markdown/JSON remain first-class |",
        "| Pull requests | `read` by default; comments only from trusted step | avoid unreviewed third-party PR-comment Actions |",
        "| Actions/id-token/packages | `none` by default | should not be required for the pack |",
        "",
        f"Workflow write-permission findings: `{len(write_findings)}`",
    ]
    return "\n".join(lines) + "\n"


def _trust_markdown(trust: dict[str, str]) -> str:
    lines = ["# Trust readiness", ""]
    for key, value in trust.items():
        lines.append(f"- {key}: `{value}`")
    lines.extend(["", "This is a readiness checklist, not a CI/CD security audit."])
    return "\n".join(lines) + "\n"


def _data_flow(safety: dict[str, bool]) -> str:
    lines = [
        "# Data-flow and privacy boundary",
        "",
        "## Reads",
        "",
        "- Repo files needed for deterministic planning, policy loading, workflow linting, and scan reports.",
        "- Optional local Foundry/Slither execution only when explicitly enabled for this pack.",
        "",
        "## Writes",
        "",
        "- Local evidence-pack artifacts under the chosen output directory.",
        "",
        "## Defaults",
        "",
    ]
    for key, value in safety.items():
        lines.append(f"- {key}: `{str(value).lower()}`")
    lines.extend(["", "No hosted upload, live AI provider call, private snippet sharing, payment/custody flow, or audit guarantee is required by default."])
    return "\n".join(lines) + "\n"


def _runner_guidance() -> str:
    return """# Runner guidance

- Prefer local CLI or a customer-controlled runner.
- For self-hosted CI, prefer ephemeral or just-in-time runners.
- Use separate runner groups for untrusted PRs and sensitive protocol repos.
- Do not expose secrets to untrusted fork PRs.
- Avoid `pull_request_target` for untrusted code execution.
- Use least-privilege tokens and keep PR comments in a trusted, minimal-permission step.

This guidance is not a full runner hardening audit.
"""


def _readiness_summary(scan: dict[str, Any], policy: dict[str, Any], workflow: dict[str, Any], pack_status: str, run_local_tools: bool) -> str:
    return "\n".join(
        [
            "# Human-review readiness summary",
            "",
            f"- Pack status: `{pack_status}`",
            f"- Deterministic scan status: `{scan.get('status')}`",
            f"- Policy status: `{policy.get('status')}`",
            f"- Workflow safety status: `{workflow.get('status')}`",
            f"- Local Foundry/Slither execution enabled: `{str(run_local_tools).lower()}`",
            f"- Active findings: `{_active_findings(scan)}`",
            f"- Workflow findings: `{workflow.get('summary', {}).get('findings', 0)}`",
            "",
            "Human review required: confirm tool versions, workflow permissions, baseline decisions, SARIF availability, and whether any blocked findings require audit/security owner review.",
            "",
            "Non-claims: not an audit, not formal verification, not a guarantee, and not legal/compliance advice.",
        ]
    ) + "\n"


def _open_questions() -> str:
    return """# Open questions for the team

1. Do Foundry tests pass locally and in your CI?
2. Do you want SARIF upload, Markdown/JSON artifacts, or both?
3. Which workflow permissions are acceptable to your security owner?
4. Who reviews baseline suppressions and expiry?
5. What evidence do auditors ask for before audit kickoff?
6. Would local/customer-controlled execution change willingness to adopt?
7. What would make this pack unacceptable even if the CLI is free?
"""


def _trust_readiness(repo: Path, workflow: dict[str, Any]) -> dict[str, str]:
    findings = workflow.get("findings", [])
    rules = {f.get("rule_id") for f in findings}
    workflow_files = workflow.get("summary", {}).get("workflow_files", 0)
    return {
        "third_party_actions_sha_pinned": "fail" if {"mutable_action_ref", "action_without_ref"} & rules else ("unknown" if workflow_files == 0 else "pass"),
        "permissions_documented": "fail" if "broad_permissions_write_all" in rules else ("unknown" if workflow_files == 0 else "pass"),
        "pull_request_target_avoided": "fail" if "pull_request_target" in rules else "pass",
        "security_policy_present": "pass" if _security_policy_present(repo) else "unknown",
        "sbom_or_provenance_plan_present": "unknown",
        "runner_guidance_documented": "pass",
        "sarif_fallback_documented": "pass",
    }


def _security_policy_present(repo: Path) -> bool:
    return any((repo / name).exists() for name in ["SECURITY.md", "security.md", ".github/SECURITY.md"])


def _git_ref(repo: Path) -> str:
    head = repo / ".git" / "HEAD"
    if not head.exists():
        return "unknown"
    try:
        value = head.read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"
    if value.startswith("ref: "):
        return value.removeprefix("ref: ")
    return value[:12] if value else "unknown"


def _solidity_layout(repo: Path) -> str:
    has_src = any((repo / "src").glob("**/*.sol")) if (repo / "src").is_dir() else False
    has_contracts = any((repo / "contracts").glob("**/*.sol")) if (repo / "contracts").is_dir() else False
    if has_src and has_contracts:
        return "mixed"
    if has_src:
        return "src"
    if has_contracts:
        return "contracts"
    return "unknown"


def _tool_available(plan: dict[str, Any], name: str) -> bool:
    tools = plan.get("plan", {}).get("tools", [])
    return any(tool.get("name") == name and tool.get("available") is True for tool in tools)


def _active_findings(scan: dict[str, Any]) -> int:
    total = 0
    for report in scan.get("tool_reports", []):
        total += len(report.get("findings", []) or [])
    return total


def _checks(output_dir: Path, manifest: dict[str, Any], plan: dict[str, Any], scan: dict[str, Any]) -> list[dict[str, Any]]:
    required_paths = [output_dir / item["path"] for item in manifest["artifacts"] if item["required_for_pack"]]
    text = json.dumps({"manifest": manifest, "plan": plan, "scan": scan}, ensure_ascii=False)
    return [
        {"name": "required_artifacts_written", "ok": all(path.exists() for path in required_paths)},
        {"name": "manifest_schema", "ok": manifest.get("schema_version") == MANIFEST_SCHEMA_VERSION},
        {"name": "deterministic_evidence_source_of_truth", "ok": manifest.get("source_of_truth") == "deterministic_tools"},
        {"name": "no_hosted_upload_or_live_ai_required", "ok": manifest.get("hosted_upload_required") is False and manifest.get("advisory_ai_included") is False},
        {"name": "no_private_snippets_or_raw_logs", "ok": manifest.get("private_snippets_included") is False and manifest.get("raw_stdout_stderr_included") is False},
        {"name": "no_audit_or_payment_scope", "ok": manifest.get("audit_or_compliance_claim") is False and manifest.get("payment_or_custody_scope") is False},
        {"name": "repo_absolute_path_not_in_public_json", "ok": str(output_dir) not in text and not LOCAL_PATH_RE.search(text)},
    ]


def _sanitize(value: Any, repo: Path) -> Any:
    repo_abs = repo.as_posix()
    if isinstance(value, dict):
        return {key: _sanitize(val, repo) for key, val in value.items()}
    if isinstance(value, list):
        return [_sanitize(item, repo) for item in value]
    if isinstance(value, str):
        value = value.replace(repo_abs, ".")
        if value.startswith("/"):
            return "<local-path>"
        return LOCAL_PATH_RE.sub("<local-path>", value)
    return value
