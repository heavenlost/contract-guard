from __future__ import annotations

import json
from pathlib import PurePosixPath
from typing import Any


FALSE_POSITIVE_SCHEMA = "contract_guard_false_positive_review/v1"
FALSE_POSITIVE_SCHEMA_VERSION = "1"
FALSE_POSITIVE_DISCLAIMER = (
    "False-positive review records are deterministic audit trails for baseline candidates. "
    "They are not AI triage, proofs, audits, or guarantees of smart-contract safety."
)
SEVERITY_ORDER = {"informational": 0, "optimization": 0, "low": 1, "medium": 2, "high": 3}


def false_positive_review_payload(
    finding_id: str = "",
    check: str = "",
    file: str = "",
    start_line: int | None = None,
    severity: str = "low",
    confidence: str = "unknown",
    classification: str = "false-positive",
    reason: str = "",
    reviewer: str = "",
    expires: str = "",
) -> dict[str, Any]:
    normalized_severity = _normalize_value(severity, fallback="low")
    safe_file = _safe_report_path(file)
    safe_line = start_line if isinstance(start_line, int) and start_line > 0 else None
    normalized_classification = _normalize_value(classification, fallback="false-positive").replace("_", "-")
    finding = {
        "id": str(finding_id or ""),
        "check": str(check or ""),
        "severity": normalized_severity,
        "confidence": _normalize_value(confidence, fallback="unknown"),
        "source_location": {"file": safe_file, "start_line": safe_line},
    }
    diagnostics: list[str] = []
    if not finding["check"]:
        diagnostics.append("missing_check")
    if not safe_file or safe_file == "unknown":
        diagnostics.append("missing_file")
    if safe_line is None:
        diagnostics.append("missing_start_line")
    if not reason.strip():
        diagnostics.append("missing_reason")
    if not reviewer.strip():
        diagnostics.append("missing_reviewer")

    high_severity = SEVERITY_ORDER.get(normalized_severity, 0) >= SEVERITY_ORDER["high"]
    eligible = not high_severity and not diagnostics
    if high_severity:
        status = "blocked_high_severity"
    elif diagnostics:
        status = "needs_review_metadata"
    else:
        status = "eligible_for_baseline"

    baseline_candidate = None
    if eligible:
        baseline_candidate = {
            "id": finding["id"],
            "check": finding["check"],
            "file": safe_file,
            "start_line": safe_line,
            "reason": reason.strip(),
            "classification": normalized_classification,
            "reviewer": reviewer.strip(),
            "expires": expires.strip(),
        }

    return {
        "schema": FALSE_POSITIVE_SCHEMA,
        "schema_version": FALSE_POSITIVE_SCHEMA_VERSION,
        "ok": True,
        "status": status,
        "ai_triage_included": False,
        "disclaimer": FALSE_POSITIVE_DISCLAIMER,
        "finding": finding,
        "review": {
            "classification": normalized_classification,
            "reason": reason.strip(),
            "reviewer": reviewer.strip(),
            "expires": expires.strip(),
        },
        "policy": {
            "eligible_for_baseline": eligible,
            "high_severity_never_suppressed": True,
            "requires_exact_match": True,
            "keeps_deterministic_evidence_separate_from_ai": True,
        },
        "baseline_candidate": baseline_candidate,
        "diagnostics": diagnostics,
    }


def render_false_positive_markdown(payload: dict[str, Any]) -> str:
    finding = payload["finding"]
    location = finding["source_location"]
    lines = [
        "# Contract Guard CI False-Positive Review",
        "",
        f"Status: `{payload['status']}`",
        "",
        f"> {payload['disclaimer']}",
        "",
        "Deterministic evidence remains separate from optional AI explanation. AI triage is not included.",
        "",
        "## Finding",
        "",
        f"- ID: `{finding['id']}`",
        f"- Check: `{finding['check']}`",
        f"- Severity: `{finding['severity']}`",
        f"- Confidence: `{finding['confidence']}`",
        f"- Location: `{location['file']}:{location['start_line']}`",
        "",
        "## Policy decision",
        "",
        f"- Eligible for baseline: `{str(payload['policy']['eligible_for_baseline']).lower()}`",
        f"- High severity never suppressed: `{str(payload['policy']['high_severity_never_suppressed']).lower()}`",
        "- Baseline matching: exact finding `id`, or exact `check` + `file` + `start_line`.",
        "",
    ]
    if payload["baseline_candidate"]:
        lines.extend(
            [
                "## Baseline candidate",
                "",
                "```json",
                json.dumps(payload["baseline_candidate"], ensure_ascii=False, indent=2, sort_keys=True),
                "```",
                "",
            ]
        )
    else:
        lines.extend(["## Baseline candidate", "", "No baseline candidate was generated.", ""])
    if payload["diagnostics"]:
        lines.extend(["## Diagnostics", ""])
        lines.extend(f"- `{item}`" for item in payload["diagnostics"])
        lines.append("")
    return "\n".join(lines)


def dumps_false_positive_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


def _normalize_value(value: str, fallback: str) -> str:
    normalized = str(value or "").strip().lower().replace(" ", "-")
    return normalized or fallback


def _safe_report_path(value: str) -> str:
    normalized = str(value or "").strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if not normalized:
        return "unknown"
    if normalized.startswith("/"):
        parts = [part for part in PurePosixPath(normalized).parts if part and part != "/"]
        for anchor in ("contracts", "src", "test", "script"):
            if anchor in parts:
                return "/".join(parts[parts.index(anchor) :])
        return PurePosixPath(normalized).name
    return normalized
