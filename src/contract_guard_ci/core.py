from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .aderyn import normalize_aderyn_payload


PLAN_SCHEMA = "contract_guard_plan/v1"
SCAN_SCHEMA = "contract_guard_scan/v1"
REPORT_SCHEMA_VERSION = "1"
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
IGNORED_SOLIDITY_DIRS = {".git", "node_modules", "lib", "out", "cache", ".venv"}
SEVERITY_ORDER = {"informational": 0, "optimization": 0, "low": 1, "medium": 2, "high": 3}
CONFIDENCE_ORDER = {"unknown": 0, "low": 1, "medium": 2, "high": 3}
_FORGE_AGGREGATE_RE = re.compile(
    r"(?P<passed>\d+)\s+tests?\s+passed,\s+"
    r"(?P<failed>\d+)\s+failed,\s+"
    r"(?P<skipped>\d+)\s+skipped\s+"
    r"\((?P<total>\d+)\s+total\s+tests?\)"
)
_FORGE_SUITE_RE = re.compile(
    r"Suite result:\s+\w+\.\s+"
    r"(?P<passed>\d+)\s+passed;\s+"
    r"(?P<failed>\d+)\s+failed;\s+"
    r"(?P<skipped>\d+)\s+skipped;"
)
_FORGE_FAILURE_RE = re.compile(r"^\[FAIL(?::\s*(?P<reason>[^\]]+))?\]\s+(?P<test>.+?)\s+\(gas:", re.MULTILINE)


@dataclass(frozen=True)
class ToolStatus:
    name: str
    available: bool
    path: str | None = None


@dataclass(frozen=True)
class RepoPlan:
    repo: str
    is_git_repo: bool
    solidity_files: int
    foundry_project: bool
    tools: list[ToolStatus]
    recommended_commands: list[str]
    warnings: list[str]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["tools"] = [asdict(tool) for tool in self.tools]
        return payload


@dataclass(frozen=True)
class CommandResult:
    name: str
    command: list[str]
    exit_code: int
    stdout: str
    stderr: str
    skipped: bool = False
    skip_reason: str = ""

    @property
    def ok(self) -> bool:
        return self.skipped or self.exit_code == 0

    @property
    def status(self) -> str:
        if self.skipped:
            return "skipped"
        return "passed" if self.exit_code == 0 else "failed"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["stdout"] = self.stdout[-20000:]
        payload["stderr"] = self.stderr[-20000:]
        return payload | {"ok": self.ok, "status": self.status}


def is_git_repo(repo: Path) -> bool:
    try:
        subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--is-inside-work-tree"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return True
    except Exception:
        return False


def count_solidity_files(repo: Path) -> int:
    total = 0
    for path in repo.rglob("*.sol"):
        if any(part in IGNORED_SOLIDITY_DIRS for part in path.relative_to(repo).parts):
            continue
        total += 1
    return total


def detect_foundry(repo: Path) -> bool:
    return (repo / "foundry.toml").exists() or (repo / "src").exists() and (repo / "test").exists()


def tool_status(name: str) -> ToolStatus:
    path = shutil.which(name)
    return ToolStatus(name=name, available=bool(path), path=path)


def build_plan(repo: Path) -> RepoPlan:
    repo = repo.resolve()
    tools = [tool_status("forge"), tool_status("slither"), tool_status("git")]
    solidity_files = count_solidity_files(repo)
    foundry_project = detect_foundry(repo)
    recommended: list[str] = []
    warnings: list[str] = []

    if foundry_project and any(t.name == "forge" and t.available for t in tools):
        recommended.append("forge test")
    elif foundry_project:
        warnings.append("Foundry project detected but `forge` is not available on PATH.")

    if solidity_files and any(t.name == "slither" and t.available for t in tools):
        recommended.append("slither . --json -")
    elif solidity_files:
        warnings.append("Solidity files detected but `slither` is not available on PATH.")

    if not solidity_files:
        warnings.append("No Solidity files found outside ignored directories; scan will be readiness-only.")

    return RepoPlan(
        repo=str(repo),
        is_git_repo=is_git_repo(repo),
        solidity_files=solidity_files,
        foundry_project=foundry_project,
        tools=tools,
        recommended_commands=recommended,
        warnings=warnings,
    )


def run_command(name: str, command: list[str], cwd: Path, timeout_seconds: int) -> CommandResult:
    try:
        proc = subprocess.run(
            command,
            cwd=str(cwd),
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
        )
        return CommandResult(
            name=name,
            command=command,
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )
    except FileNotFoundError:
        return CommandResult(name=name, command=command, exit_code=127, stdout="", stderr="", skipped=True, skip_reason="tool_not_found")
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            name=name,
            command=command,
            exit_code=124,
            stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
            stderr=(exc.stderr or "") if isinstance(exc.stderr, str) else "timeout_expired",
        )


def scan_repo(
    repo: Path,
    timeout_seconds: int = 300,
    skip_foundry: bool = False,
    skip_slither: bool = False,
    include_aderyn: bool = False,
    changed_only: bool = False,
    diff_base: str | None = None,
    baseline_file: str | None = None,
    fail_on_severity: str = "high",
    fail_on_confidence: str = "low",
) -> dict[str, Any]:
    repo = repo.resolve()
    plan = build_plan(repo)
    diff = build_diff_scope(repo, enabled=changed_only, base_ref=diff_base)
    baseline = load_baseline(repo, baseline_file)
    results: list[CommandResult] = []

    has_forge = any(t.name == "forge" and t.available for t in plan.tools)
    has_slither = any(t.name == "slither" and t.available for t in plan.tools)

    if skip_foundry:
        results.append(CommandResult("foundry", ["forge", "test"], 0, "", "", True, "skip_foundry_requested"))
    elif plan.foundry_project and has_forge:
        results.append(run_command("foundry", ["forge", "test"], repo, timeout_seconds))
    else:
        results.append(CommandResult("foundry", ["forge", "test"], 0, "", "", True, "foundry_unavailable_or_not_detected"))

    if skip_slither:
        results.append(CommandResult("slither", ["slither", ".", "--json", "-", "--fail-none"], 0, "", "", True, "skip_slither_requested"))
    elif changed_only and not diff["changed_solidity_files"]:
        results.append(CommandResult("slither", ["slither", ".", "--json", "-", "--fail-none"], 0, "", "", True, "changed_only_no_solidity_changes"))
    elif plan.solidity_files and has_slither:
        results.append(run_command("slither", ["slither", ".", "--json", "-", "--fail-none"], repo, timeout_seconds))
    else:
        results.append(CommandResult("slither", ["slither", ".", "--json", "-", "--fail-none"], 0, "", "", True, "slither_unavailable_or_no_solidity"))

    command_ok = all(result.ok for result in results)
    tool_reports = [normalize_tool_result(result) for result in results]
    if changed_only:
        tool_reports = filter_tool_reports_to_changed_solidity(tool_reports, diff["changed_solidity_files"])

    if include_aderyn:
        aderyn_result = run_aderyn_check(repo, plan, diff=diff, changed_only=changed_only, timeout_seconds=timeout_seconds)
        results.append(aderyn_result)
        command_ok = command_ok and aderyn_result.ok
        aderyn_report = normalize_tool_result(aderyn_result)
        if changed_only:
            aderyn_report = filter_tool_reports_to_changed_solidity([aderyn_report], diff["changed_solidity_files"])[0]
        tool_reports.append(aderyn_report)

    tool_reports = apply_baseline_suppression(tool_reports, baseline)
    failure_policy = evaluate_failure_policy(tool_reports, fail_on_severity=fail_on_severity, fail_on_confidence=fail_on_confidence)
    ok = command_ok and not failure_policy["failed"]
    return {
        "schema": SCAN_SCHEMA,
        "schema_version": REPORT_SCHEMA_VERSION,
        "ok": ok,
        "status": "passed" if ok else "failed",
        "summary": summarize_results(results),
        "plan": plan.to_dict(),
        "diff": diff,
        "baseline": baseline,
        "failure_policy": failure_policy,
        "results": [result.to_dict() for result in results],
        "tool_reports": tool_reports,
    }


def plan_payload(repo: Path) -> dict[str, Any]:
    plan = build_plan(repo)
    missing_tools = [tool.name for tool in plan.tools if not tool.available]
    return {
        "schema": PLAN_SCHEMA,
        "schema_version": REPORT_SCHEMA_VERSION,
        "ok": True,
        "status": "ready" if not plan.warnings else "needs_attention",
        "summary": {
            "repo": plan.repo,
            "is_git_repo": plan.is_git_repo,
            "foundry_project": plan.foundry_project,
            "solidity_files": plan.solidity_files,
            "missing_tools": missing_tools,
            "warnings": len(plan.warnings),
            "recommended_commands": len(plan.recommended_commands),
        },
        "plan": plan.to_dict(),
    }


def summarize_results(results: list[CommandResult]) -> dict[str, Any]:
    statuses = [result.status for result in results]
    return {
        "checks": len(results),
        "passed": statuses.count("passed"),
        "failed": statuses.count("failed"),
        "skipped": statuses.count("skipped"),
    }


def normalize_tool_result(result: CommandResult) -> dict[str, Any]:
    if result.name == "foundry":
        return normalize_foundry_result(result)
    if result.name == "slither":
        return normalize_slither_result(result)
    if result.name == "aderyn":
        return normalize_aderyn_result(result)
    return {
        "tool": result.name,
        "kind": "raw_command",
        "status": result.status,
        "exit_code": result.exit_code,
        "summary": {},
        "diagnostics": [result.skip_reason] if result.skipped and result.skip_reason else [],
    }


def run_aderyn_check(
    repo: Path,
    plan: RepoPlan,
    *,
    diff: dict[str, Any],
    changed_only: bool,
    timeout_seconds: int,
) -> CommandResult:
    display_command = ["aderyn", ".", "-o", "<temporary-json-output>"]
    if changed_only and not diff.get("changed_solidity_files"):
        return CommandResult("aderyn", display_command, 0, "", "", True, "changed_only_no_solidity_changes")
    if not plan.solidity_files or not shutil.which("aderyn"):
        return CommandResult("aderyn", display_command, 0, "", "", True, "aderyn_unavailable_or_no_solidity")

    with tempfile.TemporaryDirectory(prefix="contract-guard-aderyn-") as tmp:
        output_path = Path(tmp) / "aderyn.json"
        command = ["aderyn", ".", "-o", str(output_path)]
        try:
            proc = subprocess.run(
                command,
                cwd=str(repo),
                text=True,
                capture_output=True,
                timeout=timeout_seconds,
            )
        except FileNotFoundError:
            return CommandResult("aderyn", display_command, 127, "", "", True, "tool_not_found")
        except subprocess.TimeoutExpired as exc:
            stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
            return CommandResult("aderyn", display_command, 124, "", _safe_aderyn_diagnostic(stderr) or "timeout_expired")

        output_text = ""
        if output_path.exists():
            output_text = output_path.read_text(encoding="utf-8", errors="replace")
        elif proc.stdout.strip().startswith("{"):
            output_text = proc.stdout
        if output_text:
            output_text = _sanitize_aderyn_json_output(output_text)

        stderr = "" if output_text else "aderyn_output_json_missing"
        if proc.returncode != 0:
            stderr = _safe_aderyn_diagnostic(proc.stderr) or stderr or "aderyn_failed"
        exit_code = proc.returncode if output_text else (proc.returncode or 1)
        return CommandResult("aderyn", display_command, exit_code, output_text, stderr)


def _safe_aderyn_diagnostic(value: str) -> str:
    if not value.strip():
        return ""
    if "timeout" in value.lower():
        return "timeout_expired"
    return "aderyn_failed"


def _sanitize_aderyn_json_output(value: str) -> str:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return value
    return json.dumps(_strip_absolute_paths(parsed), ensure_ascii=False, sort_keys=True)


def _strip_absolute_paths(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _strip_absolute_paths(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_strip_absolute_paths(item) for item in value]
    if isinstance(value, str) and value.startswith("/"):
        return Path(value).name
    return value


def normalize_aderyn_result(result: CommandResult) -> dict[str, Any]:
    diagnostics: list[str] = []
    if result.skipped and result.skip_reason:
        diagnostics.append(result.skip_reason)
    if result.exit_code == 124:
        diagnostics.append("timeout_expired")
    if result.stderr == "aderyn_output_json_missing":
        diagnostics.append("aderyn_output_json_missing")

    payload: dict[str, Any] | None = None
    if result.stdout.strip():
        try:
            parsed = json.loads(result.stdout)
            if isinstance(parsed, dict):
                payload = parsed
            else:
                diagnostics.append("aderyn_json_root_not_object")
        except json.JSONDecodeError:
            diagnostics.append("aderyn_json_parse_failed")
    elif not result.skipped:
        diagnostics.append("aderyn_json_missing")

    report = normalize_aderyn_payload(payload or {}, exit_code=result.exit_code)
    report["status"] = result.status
    report["diagnostics"] = diagnostics + [item for item in report.get("diagnostics", []) if item not in diagnostics]
    return report


def load_baseline(repo: Path, baseline_file: str | None = None) -> dict[str, Any]:
    if not baseline_file:
        return {"enabled": False, "path": None, "suppression_count": 0, "suppressions": [], "diagnostics": []}

    repo = repo.resolve()
    path = Path(baseline_file)
    if not path.is_absolute():
        path = repo / path
    diagnostics: list[str] = []
    suppressions: list[dict[str, Any]] = []
    if not path.exists():
        diagnostics.append("baseline_file_not_found")
    else:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            raw_suppressions = payload.get("suppressions", []) if isinstance(payload, dict) else []
            if isinstance(raw_suppressions, list):
                suppressions = [_normalize_baseline_suppression(item) for item in raw_suppressions if isinstance(item, dict)]
            else:
                diagnostics.append("baseline_suppressions_not_list")
        except json.JSONDecodeError:
            diagnostics.append("baseline_json_parse_failed")

    return {
        "enabled": True,
        "path": _display_baseline_path(repo, path),
        "suppression_count": len(suppressions),
        "suppressions": suppressions,
        "diagnostics": diagnostics,
    }


def apply_baseline_suppression(tool_reports: list[dict[str, Any]], baseline: dict[str, Any]) -> list[dict[str, Any]]:
    if not baseline.get("enabled"):
        return tool_reports

    filtered_reports: list[dict[str, Any]] = []
    for report in tool_reports:
        if report.get("tool") != "slither":
            filtered_reports.append(report)
            continue

        active: list[dict[str, Any]] = []
        suppressed: list[dict[str, Any]] = []
        high_not_suppressed = 0
        for finding in report.get("findings", []):
            if not isinstance(finding, dict):
                continue
            if _baseline_matches(finding, baseline):
                if finding.get("severity") == "high":
                    high_not_suppressed += 1
                    active.append(finding)
                else:
                    suppressed.append(finding | {"suppression_status": "suppressed_by_baseline"})
            else:
                active.append(finding)

        diagnostics = list(report.get("diagnostics", []))
        diagnostics.append(f"baseline_suppressed_{len(suppressed)}_of_{len(report.get('findings', []))}_slither_findings")
        if high_not_suppressed:
            diagnostics.append(f"baseline_high_severity_not_suppressed_{high_not_suppressed}")

        filtered = dict(report)
        filtered["findings"] = active
        filtered["suppressed_findings"] = suppressed
        filtered["summary"] = _summarize_slither_findings(active) | {"baseline_suppressed": len(suppressed)}
        filtered["diagnostics"] = diagnostics
        filtered_reports.append(filtered)
    return filtered_reports


def evaluate_failure_policy(
    tool_reports: list[dict[str, Any]],
    fail_on_severity: str = "high",
    fail_on_confidence: str = "low",
) -> dict[str, Any]:
    severity_threshold = _normalize_policy_value(fail_on_severity)
    confidence_threshold = _normalize_policy_value(fail_on_confidence)
    enabled = severity_threshold != "none"
    diagnostics: list[str] = []
    matched: list[dict[str, Any]] = []

    if not enabled:
        return {
            "enabled": False,
            "fail_on_severity": "none",
            "fail_on_confidence": confidence_threshold,
            "failed": False,
            "matched_findings": [],
            "diagnostics": diagnostics,
        }

    if severity_threshold not in SEVERITY_ORDER:
        diagnostics.append("invalid_fail_on_severity")
        severity_threshold = "high"
    if confidence_threshold != "none" and confidence_threshold not in CONFIDENCE_ORDER:
        diagnostics.append("invalid_fail_on_confidence")
        confidence_threshold = "low"

    for finding in _active_static_findings(tool_reports):
        severity = _normalize_level(finding.get("severity"))
        confidence = _normalize_level(finding.get("confidence"))
        if SEVERITY_ORDER.get(severity, -1) < SEVERITY_ORDER[severity_threshold]:
            continue
        if confidence_threshold != "none" and CONFIDENCE_ORDER.get(confidence, -1) < CONFIDENCE_ORDER[confidence_threshold]:
            continue
        matched.append(
            {
                "id": str(finding.get("id") or ""),
                "check": str(finding.get("check") or ""),
                "severity": severity,
                "confidence": confidence,
                "source_location": finding.get("source_location", {}),
            }
        )

    return {
        "enabled": True,
        "fail_on_severity": severity_threshold,
        "fail_on_confidence": confidence_threshold,
        "failed": bool(matched),
        "matched_findings": matched,
        "diagnostics": diagnostics,
    }


def build_diff_scope(repo: Path, enabled: bool = False, base_ref: str | None = None) -> dict[str, Any]:
    repo = repo.resolve()
    if not enabled:
        return {
            "enabled": False,
            "available": False,
            "base_ref": base_ref,
            "changed_files": [],
            "changed_solidity_files": [],
            "diagnostics": [],
        }

    diagnostics: list[str] = []
    changed_files: list[str] = []
    if not is_git_repo(repo):
        diagnostics.append("not_a_git_repo")
    else:
        command = ["git", "-C", str(repo), "diff", "--name-only", "--diff-filter=ACMR"]
        if base_ref:
            command.append(base_ref)
        command.append("--")
        try:
            proc = subprocess.run(command, text=True, capture_output=True, check=False, timeout=30)
            if proc.returncode == 0:
                changed_files = [_normalize_repo_relative_path(line) for line in proc.stdout.splitlines() if line.strip()]
            else:
                diagnostics.append("git_diff_name_only_failed")
        except FileNotFoundError:
            diagnostics.append("git_tool_not_found")
        except subprocess.TimeoutExpired:
            diagnostics.append("git_diff_name_only_timeout")

    changed_files = sorted(dict.fromkeys(path for path in changed_files if path))
    changed_solidity_files = [path for path in changed_files if is_scannable_solidity_path(path)]
    return {
        "enabled": True,
        "available": not diagnostics,
        "base_ref": base_ref,
        "changed_files": changed_files,
        "changed_solidity_files": changed_solidity_files,
        "diagnostics": diagnostics,
    }


def is_scannable_solidity_path(path: str) -> bool:
    normalized = _normalize_repo_relative_path(path)
    if not normalized.endswith(".sol"):
        return False
    parts = normalized.split("/")
    return not any(part in IGNORED_SOLIDITY_DIRS for part in parts)


def filter_tool_reports_to_changed_solidity(tool_reports: list[dict[str, Any]], changed_solidity_files: list[str]) -> list[dict[str, Any]]:
    changed = set(changed_solidity_files)
    filtered_reports: list[dict[str, Any]] = []
    for report in tool_reports:
        if report.get("tool") not in {"slither", "aderyn"}:
            filtered_reports.append(report)
            continue
        kept = [
            finding
            for finding in report.get("findings", [])
            if isinstance(finding, dict) and _finding_file(finding) in changed
        ]
        diagnostics = list(report.get("diagnostics", []))
        diagnostics.append(f"diff_filter_kept_{len(kept)}_of_{len(report.get('findings', []))}_{report.get('tool')}_findings")
        filtered = dict(report)
        filtered["findings"] = kept
        filtered["summary"] = _summarize_static_findings(kept)
        filtered["diagnostics"] = diagnostics
        filtered_reports.append(filtered)
    return filtered_reports


def _finding_file(finding: dict[str, Any]) -> str | None:
    location = finding.get("source_location", {})
    if not isinstance(location, dict):
        return None
    value = location.get("file")
    return _normalize_repo_relative_path(value) if isinstance(value, str) else None


def _normalize_repo_relative_path(path: str) -> str:
    normalized = path.strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _normalize_baseline_suppression(item: dict[str, Any]) -> dict[str, Any]:
    start_line = item.get("start_line")
    return {
        "id": str(item.get("id") or ""),
        "check": str(item.get("check") or ""),
        "file": _normalize_repo_relative_path(str(item.get("file") or "")),
        "start_line": start_line if isinstance(start_line, int) else None,
        "reason": str(item.get("reason") or ""),
    }


def _baseline_matches(finding: dict[str, Any], baseline: dict[str, Any]) -> bool:
    finding_id = str(finding.get("id") or "")
    check = str(finding.get("check") or "")
    location = finding.get("source_location", {})
    file_name = _normalize_repo_relative_path(str(location.get("file") or "")) if isinstance(location, dict) else ""
    start_line = location.get("start_line") if isinstance(location, dict) else None

    for suppression in baseline.get("suppressions", []):
        if not isinstance(suppression, dict):
            continue
        if suppression.get("id") and suppression["id"] == finding_id:
            return True
        if (
            suppression.get("check")
            and suppression.get("file")
            and suppression["check"] == check
            and suppression["file"] == file_name
            and suppression.get("start_line") == start_line
        ):
            return True
    return False


def _display_baseline_path(repo: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(repo.resolve()))
    except Exception:
        return path.name


def _active_slither_findings(tool_reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for report in tool_reports:
        if isinstance(report, dict) and report.get("tool") == "slither":
            findings.extend(finding for finding in report.get("findings", []) if isinstance(finding, dict))
    return findings


def _active_static_findings(tool_reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for report in tool_reports:
        if isinstance(report, dict) and report.get("tool") in {"slither", "aderyn"}:
            findings.extend(finding for finding in report.get("findings", []) if isinstance(finding, dict))
    return findings


def _normalize_policy_value(value: str | None) -> str:
    return str(value or "none").strip().lower().replace(" ", "_")


def normalize_slither_result(result: CommandResult) -> dict[str, Any]:
    diagnostics: list[str] = []
    if result.skipped and result.skip_reason:
        diagnostics.append(result.skip_reason)
    if result.exit_code == 124:
        diagnostics.append("timeout_expired")

    payload: dict[str, Any] | None = None
    if result.stdout.strip():
        try:
            parsed = json.loads(result.stdout)
            if isinstance(parsed, dict):
                payload = parsed
            else:
                diagnostics.append("slither_json_root_not_object")
        except json.JSONDecodeError:
            diagnostics.append("slither_json_parse_failed")

    findings: list[dict[str, Any]] = []
    slither_success = payload.get("success") if payload else None
    if payload and slither_success is False:
        diagnostics.append("slither_json_success_false")
    if payload:
        results = payload.get("results", {})
        if not isinstance(results, dict):
            results = {}
            diagnostics.append("slither_results_not_object")
        detectors = results.get("detectors", [])
        if isinstance(detectors, list):
            findings = [_normalize_slither_detector(detector) for detector in detectors if isinstance(detector, dict)]
        else:
            diagnostics.append("slither_detectors_not_list")

    return {
        "tool": "slither",
        "kind": "static_analysis",
        "status": result.status,
        "exit_code": result.exit_code,
        "summary": _summarize_slither_findings(findings),
        "findings": findings,
        "diagnostics": diagnostics,
    }


def normalize_foundry_result(result: CommandResult) -> dict[str, Any]:
    text = "\n".join(part for part in [result.stdout, result.stderr] if part)
    counts = _parse_foundry_counts(text)
    failures = [
        {"test": match.group("test").strip(), "reason": (match.group("reason") or "").strip()}
        for match in _FORGE_FAILURE_RE.finditer(text)
    ]
    diagnostics: list[str] = []
    if result.skipped and result.skip_reason:
        diagnostics.append(result.skip_reason)
    if result.exit_code == 124:
        diagnostics.append("timeout_expired")
    if result.exit_code and not failures and not result.skipped and result.exit_code != 124:
        diagnostics.append("forge_failed_without_parseable_test_failure")

    return {
        "tool": "foundry",
        "kind": "test",
        "status": result.status,
        "exit_code": result.exit_code,
        "summary": counts,
        "failures": failures,
        "diagnostics": diagnostics,
    }


def _parse_foundry_counts(text: str) -> dict[str, int | None]:
    aggregate = None
    for aggregate in _FORGE_AGGREGATE_RE.finditer(text):
        pass
    if aggregate:
        return {
            "passed": int(aggregate.group("passed")),
            "failed": int(aggregate.group("failed")),
            "skipped": int(aggregate.group("skipped")),
            "total": int(aggregate.group("total")),
        }

    suite = None
    for suite in _FORGE_SUITE_RE.finditer(text):
        pass
    if suite:
        passed = int(suite.group("passed"))
        failed = int(suite.group("failed"))
        skipped = int(suite.group("skipped"))
        return {"passed": passed, "failed": failed, "skipped": skipped, "total": passed + failed + skipped}

    return {"passed": None, "failed": None, "skipped": None, "total": None}


def _normalize_slither_detector(detector: dict[str, Any]) -> dict[str, Any]:
    check = str(detector.get("check") or "unknown")
    location = _slither_detector_location(detector)
    return {
        "id": _slither_finding_id(check, location),
        "check": check,
        "title": str(detector.get("title") or detector.get("check") or "Slither finding"),
        "impact": str(detector.get("impact") or "Unknown"),
        "severity": _normalize_level(detector.get("impact")),
        "confidence": _normalize_level(detector.get("confidence")),
        "source_location": location,
        "description": str(detector.get("description") or "").strip(),
        "markdown": str(detector.get("markdown") or "").strip(),
    }


def _normalize_level(value: Any) -> str:
    normalized = str(value or "unknown").strip().lower().replace(" ", "_")
    if normalized in {"high", "medium", "low", "informational", "optimization", "unknown"}:
        return normalized
    return "unknown"


def _slither_detector_location(detector: dict[str, Any]) -> dict[str, Any]:
    mappings = []
    if isinstance(detector.get("source_mapping"), dict):
        mappings.append(detector["source_mapping"])
    elements = detector.get("elements", [])
    if isinstance(elements, list):
        mappings.extend(element.get("source_mapping") for element in elements if isinstance(element, dict) and isinstance(element.get("source_mapping"), dict))

    mapping = mappings[0] if mappings else {}
    lines = mapping.get("lines", [])
    if not isinstance(lines, list):
        lines = []
    int_lines = [line for line in lines if isinstance(line, int)]
    file_name = _safe_slither_file_name(mapping)
    return {
        "file": file_name,
        "start_line": min(int_lines) if int_lines else None,
        "end_line": max(int_lines) if int_lines else None,
        "start_column": mapping.get("starting_column") if isinstance(mapping.get("starting_column"), int) else None,
        "end_column": mapping.get("ending_column") if isinstance(mapping.get("ending_column"), int) else None,
    }


def _safe_slither_file_name(mapping: dict[str, Any]) -> str | None:
    for key in ["filename_relative", "filename_short", "filename_used"]:
        value = mapping.get(key)
        if isinstance(value, str) and value:
            return value
    absolute = mapping.get("filename_absolute")
    if isinstance(absolute, str) and absolute:
        return Path(absolute).name
    return None


def _slither_finding_id(check: str, location: dict[str, Any]) -> str:
    file_name = str(location.get("file") or "unknown")
    line = location.get("start_line") or "unknown"
    return f"slither:{check}:{file_name}:{line}"


def _summarize_slither_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    return _summarize_static_findings(findings)


def _summarize_static_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    for finding in findings:
        severity = str(finding["severity"])
        by_severity[severity] = by_severity.get(severity, 0) + 1
    return {
        "findings": len(findings),
        "by_severity": dict(sorted(by_severity.items())),
    }


def render_sarif(scan: dict[str, Any]) -> dict[str, Any]:
    findings = _sarif_findings(scan)
    rules = _sarif_rules(findings)
    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Contract Guard CI",
                        "semanticVersion": REPORT_SCHEMA_VERSION,
                        "rules": rules,
                    }
                },
                "results": [_sarif_result(finding) for finding in findings],
                "properties": {
                    "contract_guard_schema": scan.get("schema", SCAN_SCHEMA),
                    "contract_guard_schema_version": scan.get("schema_version", REPORT_SCHEMA_VERSION),
                    "deterministic_evidence_only": True,
                    "ai_triage_included": False,
                    "failure_policy_failed": bool(scan.get("failure_policy", {}).get("failed", False)),
                },
            }
        ],
    }


def _sarif_findings(scan: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for report in scan.get("tool_reports", []):
        if isinstance(report, dict) and report.get("tool") in {"slither", "aderyn"}:
            source_tool = str(report.get("tool") or "unknown")
            findings.extend((finding | {"_source_tool": source_tool}) for finding in report.get("findings", []) if isinstance(finding, dict))
    return findings


def _sarif_rules(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_rule: dict[str, dict[str, Any]] = {}
    for finding in findings:
        source_tool = _finding_source_tool(finding)
        rule_id = str(finding.get("check") or source_tool)
        if rule_id in by_rule:
            continue
        severity = str(finding.get("severity") or "unknown")
        confidence = str(finding.get("confidence") or "unknown")
        by_rule[rule_id] = {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": str(finding.get("title") or rule_id)},
            "fullDescription": {"text": str(finding.get("description") or finding.get("markdown") or rule_id)},
            "defaultConfiguration": {"level": _sarif_level(severity)},
            "properties": {
                "source_tool": source_tool,
                "impact": str(finding.get("impact") or "Unknown"),
                "severity": severity,
                "confidence": confidence,
                "precision": _sarif_precision(confidence),
                "security-severity": _sarif_security_severity(severity),
                "tags": ["security", source_tool, rule_id],
            },
        }
    return [by_rule[rule_id] for rule_id in sorted(by_rule)]


def _sarif_result(finding: dict[str, Any]) -> dict[str, Any]:
    severity = str(finding.get("severity") or "unknown")
    source_tool = _finding_source_tool(finding)
    rule_id = str(finding.get("check") or source_tool)
    result = {
        "ruleId": rule_id,
        "level": _sarif_level(severity),
        "message": {"text": str(finding.get("description") or finding.get("title") or rule_id)},
        "properties": {
            "contract_guard_finding_id": str(finding.get("id") or ""),
            "source_tool": source_tool,
            "severity": severity,
            "confidence": str(finding.get("confidence") or "unknown"),
        },
    }
    location = _sarif_location(finding.get("source_location"))
    if location:
        result["locations"] = [location]
    return result


def _finding_source_tool(finding: dict[str, Any]) -> str:
    source = finding.get("source")
    if isinstance(source, dict) and isinstance(source.get("tool"), str) and source["tool"]:
        return source["tool"]
    return str(finding.get("_source_tool") or "slither")


def _sarif_location(location: Any) -> dict[str, Any] | None:
    if not isinstance(location, dict):
        return None
    uri = location.get("file")
    if not isinstance(uri, str) or not uri:
        return None
    region: dict[str, int] = {}
    for source_key, sarif_key in [
        ("start_line", "startLine"),
        ("end_line", "endLine"),
        ("start_column", "startColumn"),
        ("end_column", "endColumn"),
    ]:
        value = location.get(source_key)
        if isinstance(value, int) and value > 0:
            region[sarif_key] = value
    physical_location: dict[str, Any] = {"artifactLocation": {"uri": uri}}
    if region:
        physical_location["region"] = region
    return {"physicalLocation": physical_location}


def _sarif_level(severity: str) -> str:
    if severity == "high":
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _sarif_precision(confidence: str) -> str:
    if confidence in {"high", "medium", "low"}:
        return confidence
    return "low"


def _sarif_security_severity(severity: str) -> str:
    return {
        "high": "8.0",
        "medium": "5.0",
        "low": "2.0",
        "informational": "1.0",
        "optimization": "1.0",
    }.get(severity, "0.0")


def render_markdown(scan: dict[str, Any]) -> str:
    plan = scan["plan"]
    lines = [
        "# Contract Guard CI Report",
        "",
        f"Overall status: **{'PASS' if scan['ok'] else 'FAIL'}**",
        "",
        "> Deterministic tool evidence only. Optional AI triage is not included in this report.",
        "",
        "## Repository",
        "",
        f"- Path: `{plan['repo']}`",
        f"- Git repo: `{plan['is_git_repo']}`",
        f"- Foundry project: `{plan['foundry_project']}`",
        f"- Solidity files: `{plan['solidity_files']}`",
        "",
        "## Tools",
        "",
    ]
    for tool in plan["tools"]:
        lines.append(f"- `{tool['name']}`: {'available' if tool['available'] else 'missing'}")
    if plan["warnings"]:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {warning}" for warning in plan["warnings"])
    diff = scan.get("diff", {})
    if diff.get("enabled"):
        lines.extend(["", "## PR diff scope", ""])
        lines.append(f"- Base ref: `{diff.get('base_ref') or 'working tree'}`")
        lines.append(f"- Changed files: `{len(diff.get('changed_files', []))}`")
        lines.append(f"- Changed Solidity files: `{len(diff.get('changed_solidity_files', []))}`")
        if diff.get("changed_solidity_files"):
            lines.extend(f"  - `{path}`" for path in diff["changed_solidity_files"])
        lines.append(f"- Diagnostics: {_format_diagnostics(diff.get('diagnostics', []))}")
    baseline = scan.get("baseline", {})
    if baseline.get("enabled"):
        lines.extend(["", "## Baseline suppression", ""])
        lines.append(f"- File: `{baseline.get('path') or 'unknown'}`")
        lines.append(f"- Suppressions loaded: `{baseline.get('suppression_count', 0)}`")
        lines.append("- High severity findings: `never suppressed by baseline`")
        lines.append(f"- Diagnostics: {_format_diagnostics(baseline.get('diagnostics', []))}")
    policy = scan.get("failure_policy", {})
    if policy.get("enabled"):
        lines.extend(["", "## Failure policy", ""])
        lines.append(f"- Fail on severity: `{policy.get('fail_on_severity')}`")
        lines.append(f"- Fail on confidence: `{policy.get('fail_on_confidence')}`")
        lines.append(f"- Failed: `{policy.get('failed')}`")
        lines.append(f"- Matching active findings: `{len(policy.get('matched_findings', []))}`")
        lines.append(f"- Diagnostics: {_format_diagnostics(policy.get('diagnostics', []))}")
    lines.extend(["", "## Checks", ""])
    for result in scan["results"]:
        status = "SKIPPED" if result["skipped"] else ("PASS" if result["ok"] else "FAIL")
        lines.append(f"- `{result['name']}`: **{status}**")
        if result["skipped"]:
            lines.append(f"  - reason: `{result['skip_reason']}`")
        elif not result["ok"]:
            lines.append(f"  - exit code: `{result['exit_code']}`")
    tool_reports = scan.get("tool_reports", [])
    if tool_reports:
        lines.extend(["", "## Deterministic tool evidence", ""])
        for report in tool_reports:
            lines.extend(_render_tool_report_markdown(report))
    lines.append("")
    return "\n".join(lines)


def _render_tool_report_markdown(report: dict[str, Any]) -> list[str]:
    tool = str(report.get("tool") or "unknown")
    if tool == "foundry":
        return _render_foundry_markdown(report)
    if tool == "slither":
        return _render_slither_markdown(report)
    if tool == "aderyn":
        return _render_static_findings_markdown(report, title="Aderyn")
    return [
        f"### {tool}",
        "",
        f"- Status: `{report.get('status', 'unknown')}`",
        f"- Diagnostics: {_format_diagnostics(report.get('diagnostics', []))}",
        "",
    ]


def _render_foundry_markdown(report: dict[str, Any]) -> list[str]:
    summary = report.get("summary", {})
    lines = [
        "### Foundry",
        "",
        f"- Status: `{report.get('status', 'unknown')}`",
        "- Tests: "
        f"passed `{_format_count(summary.get('passed'))}`, "
        f"failed `{_format_count(summary.get('failed'))}`, "
        f"skipped `{_format_count(summary.get('skipped'))}`, "
        f"total `{_format_count(summary.get('total'))}`",
        f"- Diagnostics: {_format_diagnostics(report.get('diagnostics', []))}",
        "",
    ]
    failures = report.get("failures", [])
    if failures:
        lines.extend(["| Failed test | Reason |", "| --- | --- |"])
        for failure in failures:
            lines.append(f"| `{_markdown_cell(failure.get('test'))}` | {_markdown_cell(failure.get('reason')) or '`unknown`'} |")
        lines.append("")
    return lines


def _render_slither_markdown(report: dict[str, Any]) -> list[str]:
    return _render_static_findings_markdown(report, title="Slither")


def _render_static_findings_markdown(report: dict[str, Any], *, title: str) -> list[str]:
    summary = report.get("summary", {})
    severity_counts = summary.get("by_severity", {})
    severity_text = ", ".join(f"`{severity}`: `{count}`" for severity, count in severity_counts.items()) or "`none`"
    lines = [
        f"### {title}",
        "",
        f"- Status: `{report.get('status', 'unknown')}`",
        f"- Findings: `{summary.get('findings', 0)}`",
        f"- Severity counts: {severity_text}",
        f"- Diagnostics: {_format_diagnostics(report.get('diagnostics', []))}",
        "",
    ]
    findings = report.get("findings", [])
    if findings:
        lines.extend(["| Severity | Confidence | Check | Location | Description |", "| --- | --- | --- | --- | --- |"])
        for finding in findings:
            lines.append(
                "| "
                f"`{_markdown_cell(finding.get('severity'))}` | "
                f"`{_markdown_cell(finding.get('confidence'))}` | "
                f"`{_markdown_cell(finding.get('check'))}` | "
                f"`{_markdown_cell(_format_location(finding.get('source_location', {})))}` | "
                f"{_markdown_cell(finding.get('description')) or '`no description`'} |"
            )
        lines.append("")
    suppressed = report.get("suppressed_findings", [])
    if suppressed:
        lines.append(f"- Baseline-suppressed non-high findings: `{len(suppressed)}`")
        lines.append("")
    return lines


def _format_count(value: Any) -> str:
    return "unknown" if value is None else str(value)


def _format_diagnostics(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return "`none`"
    return ", ".join(f"`{_markdown_cell(value)}`" for value in values)


def _format_location(location: Any) -> str:
    if not isinstance(location, dict):
        return "unknown"
    file_name = location.get("file") or "unknown"
    start = location.get("start_line")
    end = location.get("end_line")
    if start is None:
        return str(file_name)
    if end is None or end == start:
        return f"{file_name}:{start}"
    return f"{file_name}:{start}-{end}"


def _markdown_cell(value: Any) -> str:
    text = str(value or "").replace("\n", " ").strip()
    return text.replace("|", "\\|")


def dumps_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
