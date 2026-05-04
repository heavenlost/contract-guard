from __future__ import annotations

from pathlib import Path
from typing import Any


ADERYN_SEVERITY_BUCKETS = {
    "high_issues": "high",
    "medium_issues": "medium",
    "low_issues": "low",
    "informational_issues": "informational",
    "info_issues": "informational",
}


def normalize_aderyn_payload(payload: dict[str, Any] | Any, *, exit_code: int = 0) -> dict[str, Any]:
    """Normalize Aderyn JSON output into Contract Guard's deterministic finding shape.

    This is intentionally a pure normalizer and does not execute Aderyn. Live CLI
    wiring should remain a separate product decision after design-partner validation.
    """

    diagnostics: list[str] = []
    findings: list[dict[str, Any]] = []

    if not isinstance(payload, dict):
        return {
            "tool": "aderyn",
            "kind": "static_analysis",
            "status": "failed",
            "exit_code": exit_code,
            "summary": {"findings": 0, "by_severity": {}},
            "findings": [],
            "diagnostics": ["aderyn_json_root_not_object"],
        }

    for bucket, severity in ADERYN_SEVERITY_BUCKETS.items():
        section = payload.get(bucket)
        if section is None:
            continue
        if not isinstance(section, dict):
            diagnostics.append(f"{bucket}_not_object")
            continue
        issues = section.get("issues", [])
        if not isinstance(issues, list):
            diagnostics.append(f"{bucket}_issues_not_list")
            continue
        for issue in issues:
            if not isinstance(issue, dict):
                diagnostics.append(f"{bucket}_issue_not_object")
                continue
            findings.extend(_normalize_issue(issue, severity))

    issue_count = payload.get("issue_count")
    if isinstance(issue_count, dict):
        counted = 0
        for value in issue_count.values():
            if isinstance(value, int):
                counted += value
        if counted and counted != len(findings):
            diagnostics.append(f"aderyn_issue_count_{counted}_normalized_{len(findings)}")

    return {
        "tool": "aderyn",
        "kind": "static_analysis",
        "status": "passed" if exit_code == 0 else "failed",
        "exit_code": exit_code,
        "summary": _summarize_aderyn_findings(findings),
        "findings": findings,
        "diagnostics": diagnostics,
    }


def _normalize_issue(issue: dict[str, Any], severity: str) -> list[dict[str, Any]]:
    title = str(issue.get("title") or issue.get("detector_name") or "Aderyn finding")
    detector = str(issue.get("detector_name") or title).strip() or "aderyn"
    description = str(issue.get("description") or "")
    instances = issue.get("instances", [])
    if not isinstance(instances, list) or not instances:
        instances = [{}]

    findings: list[dict[str, Any]] = []
    for instance in instances:
        if not isinstance(instance, dict):
            instance = {}
        file_name = _safe_file_name(instance.get("contract_path") or instance.get("path"))
        line_no = _safe_line(instance.get("line_no") or instance.get("line") or instance.get("start_line"))
        finding = {
            "id": f"aderyn:{detector}:{file_name or 'unknown'}:{line_no or 1}",
            "check": detector,
            "title": title,
            "description": description,
            "severity": severity,
            "confidence": "unknown",
            "location": {
                "file": file_name,
                "start_line": line_no,
                "end_line": line_no,
            },
            "source_location": {
                "file": file_name,
                "start_line": line_no,
                "end_line": line_no,
            },
            "source": {
                "tool": "aderyn",
                "detector": detector,
            },
        }
        hint = instance.get("hint")
        if isinstance(hint, str) and hint.strip():
            finding["hint"] = hint.strip()
        findings.append(finding)
    return findings


def _safe_file_name(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    file_name = value.strip()
    if file_name.startswith("/"):
        return Path(file_name).name
    return file_name.replace("\\", "/")


def _safe_line(value: Any) -> int | None:
    try:
        line = int(value)
    except (TypeError, ValueError):
        return None
    return line if line > 0 else None


def _summarize_aderyn_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "unknown")
        by_severity[severity] = by_severity.get(severity, 0) + 1
    return {"findings": len(findings), "by_severity": by_severity}
