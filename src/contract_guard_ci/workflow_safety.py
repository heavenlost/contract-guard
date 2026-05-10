from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA = "contract_guard_workflow_safety/v1"

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
USES_RE = re.compile(r"\buses\s*:\s*[\"']?([^\"'\s#]+)")

KNOWN_RISKY_ACTIONS = {
    "harunosakura030303-maker/solidity-audit-action",
    "harunosakura030303-maker/solidity-gas-reporter-action",
}

KNOWN_RISKY_PACKAGES = {"evmchain-config"}


@dataclass(frozen=True)
class WorkflowFinding:
    rule_id: str
    severity: str
    title: str
    message: str
    file: str
    line: int
    value: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "value": self.value,
        }


def workflow_safety_payload(repo: Path, workflow: str | None = None) -> dict[str, Any]:
    repo = repo.resolve()
    workflow_files = _workflow_files(repo, workflow)
    findings: list[WorkflowFinding] = []
    diagnostics: list[str] = []

    if workflow and not workflow_files:
        diagnostics.append("workflow_file_missing")
    elif not workflow_files:
        diagnostics.append("no_github_workflows_found")

    for path in workflow_files:
        findings.extend(_scan_workflow(repo, path))

    summary = {
        "workflow_files": len(workflow_files),
        "findings": len(findings),
        "by_severity": _severity_counts(findings),
    }
    ok = not any(f.severity == "high" for f in findings)
    return {
        "schema": SCHEMA,
        "schema_version": "1",
        "ok": ok,
        "status": "passed" if ok else "needs_attention",
        "repo": str(repo),
        "summary": summary,
        "findings": [f.to_dict() for f in findings],
        "diagnostics": diagnostics,
        "non_claims": [
            "This workflow safety check is a deterministic CI supply-chain lint, not a complete audit.",
            "It does not execute third-party actions, npm packages, shell commands, or external services.",
            "Review findings before changing production GitHub Actions permissions.",
        ],
    }


def dumps_workflow_safety_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)


def render_workflow_safety_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Contract Guard Workflow Safety Check",
        "",
        "This is a deterministic CI supply-chain lint. It does not execute third-party actions, npm packages, shell commands, or external services.",
        "",
        "## Summary",
        "",
        f"- Status: `{payload['status']}`",
        f"- Workflow files: `{payload['summary']['workflow_files']}`",
        f"- Findings: `{payload['summary']['findings']}`",
        f"- By severity: `{payload['summary']['by_severity']}`",
    ]
    if payload.get("diagnostics"):
        lines.extend(["", f"- Diagnostics: `{payload['diagnostics']}`"])

    findings = payload.get("findings") or []
    if findings:
        lines.extend(["", "## Findings", ""])
        for finding in findings:
            lines.extend(
                [
                    f"### {finding['title']}",
                    "",
                    f"- Rule: `{finding['rule_id']}`",
                    f"- Severity: `{finding['severity']}`",
                    f"- Location: `{finding['file']}:{finding['line']}`",
                    f"- Value: `{finding.get('value') or 'redacted'}`",
                    f"- Message: {finding['message']}",
                    "",
                ]
            )
    else:
        lines.extend(["", "## Findings", "", "No workflow supply-chain findings detected.", ""])

    lines.extend(["", "## Non-claims", ""])
    for claim in payload.get("non_claims", []):
        lines.append(f"- {claim}")
    return "\n".join(lines).rstrip() + "\n"


def _workflow_files(repo: Path, workflow: str | None) -> list[Path]:
    if workflow:
        path = (repo / workflow).resolve()
        try:
            path.relative_to(repo)
        except ValueError:
            return []
        return [path] if path.is_file() else []

    workflow_dir = repo / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return []
    return sorted(p for p in workflow_dir.rglob("*") if p.suffix.lower() in {".yml", ".yaml"} and p.is_file())


def _scan_workflow(repo: Path, path: Path) -> list[WorkflowFinding]:
    rel = _relpath(repo, path)
    findings: list[WorkflowFinding] = []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    in_permissions = False
    permissions_indent = 0
    seen_write_permission = False
    seen_third_party_action = False

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))

        if in_permissions and indent <= permissions_indent and not stripped.startswith("-"):
            in_permissions = False
        if re.match(r"^permissions\s*:\s*$", stripped):
            in_permissions = True
            permissions_indent = indent
            continue
        if re.match(r"^permissions\s*:\s*write-all\s*$", stripped):
            findings.append(_finding("broad_permissions_write_all", "high", rel, idx, "permissions: write-all"))
            seen_write_permission = True
            continue
        if in_permissions:
            perm_match = re.match(r"^([A-Za-z0-9_-]+)\s*:\s*write\s*$", stripped)
            if perm_match:
                perm = perm_match.group(1)
                seen_write_permission = True
                severity = "high" if perm in {"contents", "actions", "id-token", "packages"} else "medium"
                findings.append(_finding("write_permission_requested", severity, rel, idx, f"{perm}: write"))

        if "pull_request_target" in stripped:
            findings.append(_finding("pull_request_target", "high", rel, idx, "pull_request_target"))

        if "self-hosted" in stripped and re.match(r"^runs-on\s*:", stripped):
            findings.append(_finding("self_hosted_runner", "medium", rel, idx, "self-hosted"))

        uses_match = USES_RE.search(stripped)
        if uses_match:
            action_ref = uses_match.group(1).strip()
            action_name, _, ref = action_ref.partition("@")
            normalized_action = action_name.lower()
            if normalized_action not in {"actions/checkout", "foundry-rs/foundry-toolchain"}:
                seen_third_party_action = True
            if normalized_action in KNOWN_RISKY_ACTIONS:
                findings.append(_finding("known_risky_action", "high", rel, idx, action_ref))
            if not ref:
                findings.append(_finding("action_without_ref", "high", rel, idx, action_ref))
            elif not SHA_RE.match(ref):
                rule = "mutable_action_ref"
                severity = "high" if normalized_action in KNOWN_RISKY_ACTIONS else "medium"
                findings.append(_finding(rule, severity, rel, idx, action_ref))

        lowered = stripped.lower()
        if re.search(r"(curl|wget)\b.*\|\s*(bash|sh|zsh)", lowered):
            findings.append(_finding("pipe_remote_script_to_shell", "high", rel, idx, "remote shell pipe"))
        if re.search(r"\bnpm\s+(install|i|add)\b", lowered):
            for pkg in KNOWN_RISKY_PACKAGES:
                if re.search(rf"(^|\s){re.escape(pkg.lower())}($|\s|@)", lowered):
                    findings.append(_finding("known_risky_npm_package", "high", rel, idx, pkg))
        if "github_token" in lowered and seen_third_party_action:
            findings.append(_finding("github_token_with_third_party_action", "medium", rel, idx, "GITHUB_TOKEN"))

    if seen_write_permission and seen_third_party_action:
        findings.append(
            WorkflowFinding(
                rule_id="write_permissions_with_third_party_actions",
                severity="medium",
                title="Write permissions combined with third-party actions",
                message="Review whether a third-party action needs write-scoped GITHUB_TOKEN permissions; prefer artifact/SARIF outputs or a separate trusted commenting step.",
                file=rel,
                line=1,
                value="workflow-level signal",
            )
        )
    return findings


def _finding(rule_id: str, severity: str, file: str, line: int, value: str) -> WorkflowFinding:
    titles = {
        "broad_permissions_write_all": "Workflow grants broad write-all permissions",
        "write_permission_requested": "Workflow requests write permission",
        "pull_request_target": "Workflow uses pull_request_target",
        "self_hosted_runner": "Workflow uses a self-hosted runner",
        "known_risky_action": "Workflow references a known risky action from validation feedback",
        "action_without_ref": "Action is missing an explicit ref",
        "mutable_action_ref": "Action is not pinned to a full commit SHA",
        "pipe_remote_script_to_shell": "Workflow pipes a remote script into a shell",
        "known_risky_npm_package": "Workflow installs a known risky npm package from validation feedback",
        "github_token_with_third_party_action": "Workflow exposes GITHUB_TOKEN alongside third-party action usage",
    }
    messages = {
        "broad_permissions_write_all": "Use least-privilege permissions instead of write-all.",
        "write_permission_requested": "Keep write permissions isolated to trusted steps; most security scans should only need contents: read.",
        "pull_request_target": "pull_request_target can expose privileged tokens to untrusted PR context if misused; avoid by default.",
        "self_hosted_runner": "Self-hosted runners require explicit isolation and cleanup before processing untrusted PRs.",
        "known_risky_action": "This action was reviewed from public sources and rejected for Contract Guard CI defaults due to telemetry/secret-exfiltration risk.",
        "action_without_ref": "Actions should use an explicit immutable ref; missing refs are not reproducible.",
        "mutable_action_ref": "Pin actions to full commit SHAs for security-sensitive CI, especially third-party actions.",
        "pipe_remote_script_to_shell": "Do not execute unaudited remote scripts directly in CI.",
        "known_risky_npm_package": "This package currently resolves as a security holding package or otherwise failed validation; do not install it in CI.",
        "github_token_with_third_party_action": "Avoid passing write-capable repository tokens to unreviewed third-party code.",
    }
    return WorkflowFinding(rule_id, severity, titles[rule_id], messages[rule_id], file, line, value)


def _severity_counts(findings: list[WorkflowFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def _relpath(repo: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo).as_posix()
    except ValueError:
        return path.name
