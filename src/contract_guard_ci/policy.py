from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path, PurePosixPath
from typing import Any


POLICY_SCHEMA = "contract_guard_policy/v1"
POLICY_SCHEMA_VERSION = "1"
DEFAULT_POLICY_FILE = ".contract-guard-policy.json"
ALLOWED_SEVERITIES = {"high", "medium", "low", "informational", "none"}
ALLOWED_CONFIDENCES = {"high", "medium", "low", "none"}
ALLOWED_FORMATS = {"json", "markdown", "sarif"}
ALLOWED_FUZZERS = {"echidna", "medusa"}


DEFAULT_POLICY: dict[str, Any] = {
    "schema": POLICY_SCHEMA,
    "schema_version": POLICY_SCHEMA_VERSION,
    "local_only": True,
    "scan": {
        "changed_only": True,
        "diff_base": "origin/main...HEAD",
        "baseline_file": ".contract-guard-baseline.json",
        "fail_on_severity": "high",
        "fail_on_confidence": "low",
    },
    "reporting": {
        "formats": ["json", "markdown", "sarif"],
        "include_raw_stdout_stderr": False,
    },
    "fuzzing": {
        "enabled": False,
        "tools": [],
        "target": "test/invariants/InvariantTest.sol",
        "contract": "InvariantTest",
    },
    "ai_triage": {
        "enabled": False,
        "send_private_snippets": False,
    },
    "hosted_uploads": {
        "enabled": False,
    },
}


def load_policy(repo: Path, policy_file: str | None = None) -> dict[str, Any]:
    repo = repo.resolve()
    explicit = policy_file is not None
    requested_path = repo / (policy_file or DEFAULT_POLICY_FILE)
    diagnostics: list[str] = []
    source = {
        "path": _display_policy_path(repo, requested_path),
        "exists": requested_path.exists(),
        "explicit": explicit,
    }

    if not requested_path.exists():
        diagnostics.append("policy_file_missing_using_defaults")
        status = "missing_policy_file" if explicit else "defaults_used"
        return _payload(source=source, policy=deepcopy(DEFAULT_POLICY), diagnostics=diagnostics, status=status, ok=not explicit)

    try:
        raw = json.loads(requested_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        diagnostics.append("policy_json_parse_failed")
        return _payload(source=source, policy=deepcopy(DEFAULT_POLICY), diagnostics=diagnostics, status="invalid_policy", ok=False)

    if not isinstance(raw, dict):
        diagnostics.append("policy_root_must_be_object")
        return _payload(source=source, policy=deepcopy(DEFAULT_POLICY), diagnostics=diagnostics, status="invalid_policy", ok=False)

    normalized = _normalize_policy(raw, diagnostics)
    ok = not diagnostics
    return _payload(source=source, policy=normalized, diagnostics=diagnostics, status="valid" if ok else "needs_attention", ok=ok)


def render_policy_markdown(payload: dict[str, Any]) -> str:
    policy = payload["policy"]
    scan = policy["scan"]
    reporting = policy["reporting"]
    fuzzing = policy["fuzzing"]
    lines = [
        "# Contract Guard CI Repo Policy",
        "",
        f"Status: `{payload['status']}`",
        f"Source: `{payload['source']['path']}`",
        "",
        "Policy is local and deterministic. AI triage, private snippet upload, hosted uploads, and raw stdout/stderr reporting are disabled by default.",
        "",
        "## Scan defaults",
        "",
        f"- Changed-only: `{str(scan['changed_only']).lower()}`",
        f"- Diff base: `{scan['diff_base']}`",
        f"- Baseline file: `{scan['baseline_file']}`",
        f"- Fail on severity: `{scan['fail_on_severity']}`",
        f"- Fail on confidence: `{scan['fail_on_confidence']}`",
        "",
        "## Reporting",
        "",
        f"- Formats: `{', '.join(reporting['formats'])}`",
        f"- Include raw stdout/stderr: `{str(reporting['include_raw_stdout_stderr']).lower()}`",
        "",
        "## Optional fuzzing hooks",
        "",
        f"- Enabled: `{str(fuzzing['enabled']).lower()}`",
        f"- Tools: `{', '.join(fuzzing['tools']) if fuzzing['tools'] else 'none'}`",
        f"- Target: `{fuzzing['target']}`",
        f"- Contract: `{fuzzing['contract']}`",
        "",
        "## Safety boundaries",
        "",
        f"- AI triage enabled: `{str(policy['ai_triage']['enabled']).lower()}`",
        f"- Send private snippets: `{str(policy['ai_triage']['send_private_snippets']).lower()}`",
        f"- Hosted uploads enabled: `{str(policy['hosted_uploads']['enabled']).lower()}`",
        "",
    ]
    if payload["diagnostics"]:
        lines.extend(["## Diagnostics", ""])
        lines.extend(f"- `{item}`" for item in payload["diagnostics"])
        lines.append("")
    return "\n".join(lines)


def dumps_policy_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


def _payload(source: dict[str, Any], policy: dict[str, Any], diagnostics: list[str], status: str, ok: bool) -> dict[str, Any]:
    return {
        "schema": POLICY_SCHEMA,
        "schema_version": POLICY_SCHEMA_VERSION,
        "ok": ok,
        "status": status,
        "source": source,
        "policy": policy,
        "diagnostics": diagnostics,
    }


def _normalize_policy(raw: dict[str, Any], diagnostics: list[str]) -> dict[str, Any]:
    policy = deepcopy(DEFAULT_POLICY)
    unknown_keys = sorted(set(raw) - set(DEFAULT_POLICY))
    if unknown_keys:
        diagnostics.extend(f"unknown_top_level_key_ignored:{key}" for key in unknown_keys)

    if raw.get("schema") not in {None, POLICY_SCHEMA}:
        diagnostics.append("policy_schema_mismatch")
    if raw.get("schema_version") not in {None, POLICY_SCHEMA_VERSION}:
        diagnostics.append("policy_schema_version_mismatch")

    scan = raw.get("scan", {})
    if isinstance(scan, dict):
        policy["scan"]["changed_only"] = _bool_value(scan.get("changed_only"), policy["scan"]["changed_only"], "scan.changed_only", diagnostics)
        policy["scan"]["diff_base"] = str(scan.get("diff_base") or policy["scan"]["diff_base"])
        policy["scan"]["baseline_file"] = _safe_report_path(str(scan.get("baseline_file") or policy["scan"]["baseline_file"]))
        policy["scan"]["fail_on_severity"] = _choice_value(
            scan.get("fail_on_severity"),
            policy["scan"]["fail_on_severity"],
            ALLOWED_SEVERITIES,
            "scan.fail_on_severity",
            diagnostics,
        )
        policy["scan"]["fail_on_confidence"] = _choice_value(
            scan.get("fail_on_confidence"),
            policy["scan"]["fail_on_confidence"],
            ALLOWED_CONFIDENCES,
            "scan.fail_on_confidence",
            diagnostics,
        )
    elif "scan" in raw:
        diagnostics.append("scan_must_be_object")

    reporting = raw.get("reporting", {})
    if isinstance(reporting, dict):
        formats = reporting.get("formats", policy["reporting"]["formats"])
        if isinstance(formats, list) and all(isinstance(item, str) and item in ALLOWED_FORMATS for item in formats):
            policy["reporting"]["formats"] = list(dict.fromkeys(formats))
        else:
            diagnostics.append("reporting.formats_invalid_using_default")
        if reporting.get("include_raw_stdout_stderr") is True:
            diagnostics.append("reporting.include_raw_stdout_stderr_not_allowed")
        policy["reporting"]["include_raw_stdout_stderr"] = False
    elif "reporting" in raw:
        diagnostics.append("reporting_must_be_object")

    fuzzing = raw.get("fuzzing", {})
    if isinstance(fuzzing, dict):
        policy["fuzzing"]["enabled"] = _bool_value(fuzzing.get("enabled"), policy["fuzzing"]["enabled"], "fuzzing.enabled", diagnostics)
        tools = fuzzing.get("tools", policy["fuzzing"]["tools"])
        if isinstance(tools, list) and all(isinstance(item, str) and item in ALLOWED_FUZZERS for item in tools):
            policy["fuzzing"]["tools"] = list(dict.fromkeys(tools))
        else:
            diagnostics.append("fuzzing.tools_invalid_using_default")
        policy["fuzzing"]["target"] = _safe_report_path(str(fuzzing.get("target") or policy["fuzzing"]["target"]))
        policy["fuzzing"]["contract"] = _safe_identifier(str(fuzzing.get("contract") or policy["fuzzing"]["contract"]), "InvariantTest")
    elif "fuzzing" in raw:
        diagnostics.append("fuzzing_must_be_object")

    ai_triage = raw.get("ai_triage", {})
    if isinstance(ai_triage, dict):
        if ai_triage.get("enabled") is True:
            diagnostics.append("ai_triage_default_must_remain_disabled")
        if ai_triage.get("send_private_snippets") is True:
            diagnostics.append("ai_triage.private_snippets_not_allowed")
    elif "ai_triage" in raw:
        diagnostics.append("ai_triage_must_be_object")
    policy["ai_triage"] = {"enabled": False, "send_private_snippets": False}

    hosted_uploads = raw.get("hosted_uploads", {})
    if isinstance(hosted_uploads, dict):
        if hosted_uploads.get("enabled") is True:
            diagnostics.append("hosted_uploads_default_must_remain_disabled")
    elif "hosted_uploads" in raw:
        diagnostics.append("hosted_uploads_must_be_object")
    policy["hosted_uploads"] = {"enabled": False}
    policy["local_only"] = True
    return policy


def _bool_value(value: Any, default: bool, label: str, diagnostics: list[str]) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    diagnostics.append(f"{label}_must_be_boolean_using_default")
    return default


def _choice_value(value: Any, default: str, allowed: set[str], label: str, diagnostics: list[str]) -> str:
    if value is None:
        return default
    normalized = str(value).strip().lower()
    if normalized in allowed:
        return normalized
    diagnostics.append(f"{label}_invalid_using_default")
    return default


def _safe_identifier(value: str, fallback: str) -> str:
    cleaned = "".join(ch for ch in str(value or "") if ch.isalnum() or ch == "_")
    return cleaned or fallback


def _safe_report_path(value: str) -> str:
    normalized = str(value or "").strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if not normalized:
        return "unknown"
    if normalized.startswith("/"):
        parts = [part for part in PurePosixPath(normalized).parts if part and part != "/"]
        for anchor in ("contracts", "src", "test", "script", "config"):
            if anchor in parts:
                return "/".join(parts[parts.index(anchor) :])
        return PurePosixPath(normalized).name
    return normalized


def _display_policy_path(repo: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(repo.resolve()))
    except Exception:
        return path.name
