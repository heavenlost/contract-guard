from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import PurePosixPath
from typing import Any


AI_TRIAGE_PAYLOAD_SCHEMA = "contract_guard_ai_triage_payload/v1"
AI_TRIAGE_EXPLANATION_SCHEMA = "contract_guard_ai_triage_explanation/v1"
AI_TRIAGE_CONFIG_SCHEMA = "contract_guard_ai_triage_config/v1"
AI_TRIAGE_COMBINED_SCHEMA = "contract_guard_ai_triage_combined_report/v1"
AI_TRIAGE_SCHEMA_VERSION = "1"
AI_TRIAGE_DISCLAIMER = (
    "Optional AI triage payloads are advisory-only scaffolds. "
    "This command does not call external AI, does not send private snippets, "
    "and does not replace deterministic tool evidence or human review."
)
AI_EXPLANATION_DISCLAIMER = (
    "This advisory explanation is scaffolded locally without an external AI call. "
    "It is not deterministic evidence, not a proof, not an audit, and not a guarantee of smart-contract safety."
)
AI_CONFIG_DISCLAIMER = (
    "Optional AI provider configuration is disabled by default. "
    "This boundary never sends private snippets, never enables hosted uploads, "
    "and never makes an external AI call."
)


_ENV_SECRET_RE = re.compile(
    r"(?i)\b(?P<key>[A-Z0-9_]*(?:API[_-]?KEY|SECRET|TOKEN|PRIVATE[_-]?KEY|MNEMONIC|SEED[_-]?PHRASE|PASSWORD)[A-Z0-9_]*)"
    r"\s*=\s*(?P<value>[^\s;]+)"
)
_JSON_SECRET_RE = re.compile(
    r"(?i)(?P<prefix>[\"']?(?:api[_-]?key|secret|token|private[_-]?key|mnemonic|password)[\"']?\s*:\s*[\"'])"
    r"(?P<value>[^\"']+)(?P<suffix>[\"'])"
)
_OPENAI_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")
_GITHUB_TOKEN_RE = re.compile(r"\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,})\b")
_AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_HEX_SECRET_RE = re.compile(r"\b0x[a-fA-F0-9]{64}\b")
_UNIX_ABSOLUTE_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])/(?:Users|private|home|var|tmp)/[^\s\"'`),;]+")
_WINDOWS_ABSOLUTE_PATH_RE = re.compile(r"\b[A-Za-z]:\\(?:Users|private|home|tmp)\\[^\s\"'`),;]+")


def ai_triage_payload(
    finding_id: str = "",
    tool: str = "slither",
    check: str = "",
    severity: str = "unknown",
    confidence: str = "unknown",
    file: str = "",
    start_line: int | None = None,
    description: str = "",
    snippet: str = "",
    include_redacted_snippet: bool = False,
) -> dict[str, Any]:
    redacted_description, description_counts = redact_text(description)
    safe_file = safe_report_path(file)
    snippet_payload: dict[str, Any]
    snippet_counts: dict[str, int] = {}
    diagnostics: list[str] = []

    if include_redacted_snippet and snippet:
        redacted_snippet, snippet_counts = redact_text(snippet)
        snippet_payload = {
            "included": True,
            "redacted_text": redacted_snippet,
            "reason": "explicit_redacted_snippet_requested",
        }
    else:
        snippet_payload = {
            "included": False,
            "redacted_text": "",
            "reason": "redacted_snippets_disabled_by_default",
        }
        if snippet:
            diagnostics.append("snippet_dropped_because_redacted_snippets_disabled")

    redaction_summary = Counter(description_counts)
    redaction_summary.update(snippet_counts)

    return {
        "schema": AI_TRIAGE_PAYLOAD_SCHEMA,
        "schema_version": AI_TRIAGE_SCHEMA_VERSION,
        "ok": True,
        "status": "redacted_advisory_payload" if snippet_payload["included"] else "snippets_disabled_by_default",
        "external_ai_call_made": False,
        "send_private_snippets": False,
        "ai_triage_included_in_deterministic_report": False,
        "advisory_only": True,
        "disclaimer": AI_TRIAGE_DISCLAIMER,
        "deterministic_evidence_boundary": "Deterministic Foundry/Slither/Echidna/Medusa evidence remains separate from future AI text.",
        "finding": {
            "id": str(finding_id or ""),
            "tool": str(tool or ""),
            "check": str(check or ""),
            "severity": str(severity or "unknown").lower(),
            "confidence": str(confidence or "unknown").lower(),
            "source_location": {"file": safe_file, "start_line": start_line if isinstance(start_line, int) and start_line > 0 else None},
            "description": redacted_description,
        },
        "snippet": snippet_payload,
        "redaction_summary": dict(sorted(redaction_summary.items())),
        "diagnostics": diagnostics,
    }


def ai_triage_config(
    provider: str = "none",
    enable_external_provider: bool = False,
    include_redacted_snippets: bool = False,
    allow_private_snippets: bool = False,
    allow_hosted_uploads: bool = False,
) -> dict[str, Any]:
    normalized_provider = str(provider or "none").strip().lower().replace("_", "-")
    diagnostics: list[str] = []
    if normalized_provider not in {"none", "openai", "anthropic", "custom"}:
        diagnostics.append("provider_invalid_using_none")
        normalized_provider = "none"

    if allow_private_snippets:
        diagnostics.append("private_snippets_not_allowed")
    if allow_hosted_uploads:
        diagnostics.append("hosted_uploads_not_allowed")
    if normalized_provider != "none" and not enable_external_provider:
        diagnostics.append("external_provider_requires_explicit_opt_in")
    if enable_external_provider and normalized_provider == "none":
        diagnostics.append("external_provider_missing")
    if enable_external_provider and not include_redacted_snippets:
        diagnostics.append("external_provider_requires_redacted_snippet_opt_in")

    provider_payload_allowed = (
        enable_external_provider
        and normalized_provider != "none"
        and include_redacted_snippets
        and not allow_private_snippets
        and not allow_hosted_uploads
    )
    if provider_payload_allowed:
        status = "external_provider_opt_in_ready"
    elif diagnostics:
        status = "needs_attention"
    else:
        status = "local_only_default"

    return {
        "schema": AI_TRIAGE_CONFIG_SCHEMA,
        "schema_version": AI_TRIAGE_SCHEMA_VERSION,
        "ok": not diagnostics or provider_payload_allowed,
        "status": status,
        "disclaimer": AI_CONFIG_DISCLAIMER,
        "external_ai_call_made": False,
        "provider": normalized_provider,
        "external_provider_enabled": provider_payload_allowed,
        "provider_payload_allowed": provider_payload_allowed,
        "private_code_leaves_local_runner": False,
        "send_private_snippets": False,
        "hosted_uploads_enabled": False,
        "requires_explicit_external_provider_opt_in": True,
        "requires_redacted_snippet_opt_in": True,
        "include_redacted_snippets": bool(include_redacted_snippets),
        "diagnostics": diagnostics,
    }


def redact_text(text: str) -> tuple[str, dict[str, int]]:
    redacted = str(text or "")
    counts: Counter[str] = Counter()

    redacted, count = _ENV_SECRET_RE.subn(lambda match: f"{match.group('key')}=[REDACTED_SECRET]", redacted)
    counts["env_secret"] += count
    redacted, count = _JSON_SECRET_RE.subn(lambda match: f"{match.group('prefix')}[REDACTED_SECRET]{match.group('suffix')}", redacted)
    counts["json_secret"] += count
    redacted, count = _OPENAI_KEY_RE.subn("[REDACTED_TOKEN]", redacted)
    counts["openai_token"] += count
    redacted, count = _GITHUB_TOKEN_RE.subn("[REDACTED_TOKEN]", redacted)
    counts["github_token"] += count
    redacted, count = _AWS_ACCESS_KEY_RE.subn("[REDACTED_AWS_KEY]", redacted)
    counts["aws_access_key"] += count
    redacted, count = _HEX_SECRET_RE.subn("[REDACTED_HEX_SECRET]", redacted)
    counts["hex_secret"] += count

    redacted, count = _UNIX_ABSOLUTE_PATH_RE.subn(lambda match: _redact_path(match.group(0)), redacted)
    counts["absolute_path"] += count
    redacted, count = _WINDOWS_ABSOLUTE_PATH_RE.subn("[REDACTED_PATH]", redacted)
    counts["windows_path"] += count

    return redacted, {key: value for key, value in counts.items() if value}


def safe_report_path(value: str) -> str:
    normalized = str(value or "").strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if not normalized:
        return "unknown"
    if normalized.startswith("/"):
        return _redact_path(normalized).removeprefix("[REDACTED_PATH]/")
    return normalized


def render_ai_triage_markdown(payload: dict[str, Any]) -> str:
    finding = payload["finding"]
    location = finding["source_location"]
    lines = [
        "# Contract Guard CI Optional AI Triage Payload",
        "",
        f"Status: `{payload['status']}`",
        "",
        f"> {payload['disclaimer']}",
        "",
        "No external AI call was made. Private snippets are not sent. Deterministic evidence stays separate from future advisory AI text.",
        "",
        "## Deterministic evidence summary",
        "",
        f"- Tool: `{finding['tool']}`",
        f"- Check: `{finding['check']}`",
        f"- Severity: `{finding['severity']}`",
        f"- Confidence: `{finding['confidence']}`",
        f"- Location: `{location['file']}:{location['start_line']}`",
        f"- Description: {finding['description']}",
        "",
        "## Snippet boundary",
        "",
        f"- Included: `{str(payload['snippet']['included']).lower()}`",
        f"- Reason: `{payload['snippet']['reason']}`",
        f"- Send private snippets: `{str(payload['send_private_snippets']).lower()}`",
        "",
    ]
    if payload["snippet"]["included"]:
        lines.extend(["```text", payload["snippet"]["redacted_text"], "```", ""])
    if payload["redaction_summary"]:
        lines.extend(["## Redaction summary", ""])
        lines.extend(f"- `{key}`: {value}" for key, value in payload["redaction_summary"].items())
        lines.append("")
    if payload["diagnostics"]:
        lines.extend(["## Diagnostics", ""])
        lines.extend(f"- `{item}`" for item in payload["diagnostics"])
        lines.append("")
    return "\n".join(lines)


def ai_triage_explanation(payload: dict[str, Any]) -> dict[str, Any]:
    finding = payload.get("finding", {}) if isinstance(payload, dict) else {}
    location = finding.get("source_location", {}) if isinstance(finding, dict) else {}
    severity = str(finding.get("severity") or "unknown").lower()
    check = str(finding.get("check") or "unknown-check")
    tool = str(finding.get("tool") or "unknown-tool")
    description = str(finding.get("description") or "")
    file_name = str(location.get("file") or "unknown") if isinstance(location, dict) else "unknown"
    start_line = location.get("start_line") if isinstance(location, dict) else None

    review_priority = {
        "high": "review immediately before merge",
        "medium": "review before release or before widening baseline",
        "low": "review when touching the affected code",
        "informational": "review as context",
    }.get(severity, "review manually")

    advisory_summary = (
        f"{tool} reported `{check}` at `{file_name}:{start_line}` with `{severity}` severity. "
        f"Treat this as deterministic tool evidence to {review_priority}; use the notes below only as advisory context."
    )
    suggested_questions = [
        "Does the finding still apply after PR diff filtering and baseline suppression?",
        "Can a small Foundry regression or invariant test demonstrate the expected safe behavior?",
        "Is the affected code path reachable by untrusted users or privileged roles only?",
    ]
    if "reentrancy" in check:
        suggested_questions.append("Are external calls ordered after state updates or guarded by a reentrancy lock?")
    if "unchecked" in check:
        suggested_questions.append("Is the ignored return value wrapped by a library or otherwise proven safe in deterministic tests?")

    deterministic_evidence = {
        "tool": tool,
        "check": check,
        "severity": severity,
        "confidence": str(finding.get("confidence") or "unknown").lower(),
        "source_location": {"file": file_name, "start_line": start_line},
        "description": description,
    }
    advisory_explanation = {
        "summary": advisory_summary,
        "review_priority": review_priority,
        "suggested_questions": suggested_questions,
        "suggested_tests": [
            "Add or run the narrowest Foundry test that exercises the reported path.",
            "If the pattern is stateful, add an invariant or handler-based regression before suppressing anything.",
        ],
        "non_claims": [
            "This explanation does not prove the contract is safe.",
            "This explanation is not an audit finding by itself.",
            "This explanation must not suppress deterministic tool evidence.",
        ],
    }
    return {
        "schema": AI_TRIAGE_EXPLANATION_SCHEMA,
        "schema_version": AI_TRIAGE_SCHEMA_VERSION,
        "ok": True,
        "status": "local_advisory_explanation",
        "external_ai_call_made": False,
        "provider": "none",
        "send_private_snippets": False,
        "advisory_only": True,
        "disclaimer": AI_EXPLANATION_DISCLAIMER,
        "deterministic_evidence": deterministic_evidence,
        "advisory_explanation": advisory_explanation,
        "snippet_boundary": payload.get("snippet", {"included": False, "reason": "no_payload_snippet"}) if isinstance(payload, dict) else {"included": False, "reason": "no_payload_snippet"},
        "redaction_summary": payload.get("redaction_summary", {}) if isinstance(payload, dict) else {},
    }


def render_ai_triage_explanation_markdown(explanation: dict[str, Any]) -> str:
    evidence = explanation["deterministic_evidence"]
    advisory = explanation["advisory_explanation"]
    location = evidence["source_location"]
    lines = [
        "# Contract Guard CI Advisory Triage Explanation",
        "",
        f"Status: `{explanation['status']}`",
        "",
        f"> {explanation['disclaimer']}",
        "",
        "No external AI call was made. This advisory text is separate from deterministic evidence.",
        "",
        "## Deterministic evidence",
        "",
        f"- Tool: `{evidence['tool']}`",
        f"- Check: `{evidence['check']}`",
        f"- Severity: `{evidence['severity']}`",
        f"- Confidence: `{evidence['confidence']}`",
        f"- Location: `{location['file']}:{location['start_line']}`",
        f"- Description: {evidence['description']}",
        "",
        "## Advisory explanation",
        "",
        advisory["summary"],
        "",
        f"- Review priority: {advisory['review_priority']}",
        "- Suggested questions:",
    ]
    lines.extend(f"  - {item}" for item in advisory["suggested_questions"])
    lines.append("- Suggested tests:")
    lines.extend(f"  - {item}" for item in advisory["suggested_tests"])
    lines.extend(["", "## Non-claims", ""])
    lines.extend(f"- {item}" for item in advisory["non_claims"])
    lines.extend(
        [
            "",
            "## Privacy boundary",
            "",
            f"- Snippet included: `{str(explanation['snippet_boundary'].get('included', False)).lower()}`",
            f"- Send private snippets: `{str(explanation['send_private_snippets']).lower()}`",
            "",
        ]
    )
    return "\n".join(lines)


def render_ai_triage_config_markdown(config: dict[str, Any]) -> str:
    lines = [
        "# Contract Guard CI AI Triage Configuration Boundary",
        "",
        f"Status: `{config['status']}`",
        "",
        f"> {config['disclaimer']}",
        "",
        "## Local-runner boundary",
        "",
        f"- External AI call made: `{str(config['external_ai_call_made']).lower()}`",
        f"- Provider: `{config['provider']}`",
        f"- Provider payload allowed: `{str(config['provider_payload_allowed']).lower()}`",
        f"- Private code leaves local runner: `{str(config['private_code_leaves_local_runner']).lower()}`",
        f"- Send private snippets: `{str(config['send_private_snippets']).lower()}`",
        f"- Hosted uploads enabled: `{str(config['hosted_uploads_enabled']).lower()}`",
        f"- Include redacted snippets: `{str(config['include_redacted_snippets']).lower()}`",
        "",
        "A future provider payload is allowed only after explicit provider opt-in and explicit redacted-snippet opt-in. Private snippets and hosted uploads remain disabled.",
        "",
    ]
    if config["diagnostics"]:
        lines.extend(["## Diagnostics", ""])
        lines.extend(f"- `{item}`" for item in config["diagnostics"])
        lines.append("")
    return "\n".join(lines)


def combined_ai_triage_report(explanation: dict[str, Any]) -> dict[str, Any]:
    deterministic_evidence = explanation.get("deterministic_evidence", {}) if isinstance(explanation, dict) else {}
    advisory_text = explanation.get("advisory_explanation", {}) if isinstance(explanation, dict) else {}
    return {
        "schema": AI_TRIAGE_COMBINED_SCHEMA,
        "schema_version": AI_TRIAGE_SCHEMA_VERSION,
        "ok": True,
        "status": "separate_deterministic_and_advisory_sections",
        "external_ai_call_made": False,
        "deterministic_evidence_source_of_truth": True,
        "advisory_ai_text_is_non_gating": True,
        "ai_text_can_suppress_findings": False,
        "section_order": ["deterministic_evidence", "advisory_ai_text"],
        "deterministic_evidence": deterministic_evidence,
        "advisory_ai_text": advisory_text,
        "privacy_boundary": {
            "send_private_snippets": False,
            "private_code_leaves_local_runner": False,
            "hosted_uploads_enabled": False,
        },
    }


def render_combined_ai_triage_markdown(report: dict[str, Any]) -> str:
    evidence = report["deterministic_evidence"]
    advisory = report["advisory_ai_text"]
    location = evidence.get("source_location", {})
    lines = [
        "# Contract Guard CI Combined Triage Report",
        "",
        f"Status: `{report['status']}`",
        "",
        "Deterministic analyzer evidence is the source of truth. Advisory AI text is separate, non-gating, and cannot suppress findings.",
        "",
        "## Deterministic evidence (source of truth)",
        "",
        f"- Tool: `{evidence.get('tool', 'unknown')}`",
        f"- Check: `{evidence.get('check', 'unknown')}`",
        f"- Severity: `{evidence.get('severity', 'unknown')}`",
        f"- Confidence: `{evidence.get('confidence', 'unknown')}`",
        f"- Location: `{location.get('file', 'unknown')}:{location.get('start_line')}`",
        f"- Description: {evidence.get('description', '')}",
        "",
        "## Advisory AI text (separate, non-gating)",
        "",
        advisory.get("summary", ""),
        "",
        f"- Review priority: {advisory.get('review_priority', 'review manually')}",
        "- Suggested questions:",
    ]
    lines.extend(f"  - {item}" for item in advisory.get("suggested_questions", []))
    lines.append("- Suggested tests:")
    lines.extend(f"  - {item}" for item in advisory.get("suggested_tests", []))
    lines.extend(["", "## Non-claims", ""])
    lines.extend(f"- {item}" for item in advisory.get("non_claims", []))
    lines.extend(
        [
            "",
            "## Privacy boundary",
            "",
            f"- Send private snippets: `{str(report['privacy_boundary']['send_private_snippets']).lower()}`",
            f"- Private code leaves local runner: `{str(report['privacy_boundary']['private_code_leaves_local_runner']).lower()}`",
            f"- Hosted uploads enabled: `{str(report['privacy_boundary']['hosted_uploads_enabled']).lower()}`",
            "",
        ]
    )
    return "\n".join(lines)


def dumps_ai_triage_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


def _redact_path(path: str) -> str:
    normalized = str(path or "").replace("\\", "/")
    parts = [part for part in PurePosixPath(normalized).parts if part and part != "/"]
    for anchor in ("contracts", "src", "test", "script"):
        if anchor in parts:
            return "[REDACTED_PATH]/" + "/".join(parts[parts.index(anchor) :])
    return "[REDACTED_PATH]"
