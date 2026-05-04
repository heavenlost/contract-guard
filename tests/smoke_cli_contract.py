from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from contract_guard_ci.core import (
    CommandResult,
    apply_baseline_suppression,
    build_diff_scope,
    evaluate_failure_policy,
    filter_tool_reports_to_changed_solidity,
    load_baseline,
    normalize_aderyn_result,
    normalize_foundry_result,
    normalize_slither_result,
    render_markdown,
    render_sarif,
)
from contract_guard_ci.aderyn import normalize_aderyn_payload
from contract_guard_ci.ai_triage import ai_triage_config, ai_triage_explanation, ai_triage_payload, combined_ai_triage_report, redact_text, render_ai_triage_config_markdown, render_ai_triage_explanation_markdown, render_ai_triage_markdown, render_combined_ai_triage_markdown
from contract_guard_ci.false_positives import false_positive_review_payload, render_false_positive_markdown
from contract_guard_ci.fuzzing import fuzz_hooks_payload, render_fuzz_hooks_markdown
from contract_guard_ci.invariants import invariant_payload, render_invariant_markdown
from contract_guard_ci.policy import load_policy, render_policy_markdown

ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "contract_guard_ci.cli", *args],
        cwd=str(ROOT),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_plan_json_for_empty_repo() -> None:
    proc = run_cli("plan", "--repo", str(ROOT), "--json")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["schema"] == "contract_guard_plan/v1"
    assert payload["schema_version"] == "1"
    assert payload["ok"] is True
    assert payload["status"] in {"ready", "needs_attention"}
    assert payload["plan"]["repo"] == str(ROOT)
    assert "warnings" in payload["plan"]
    assert payload["summary"]["repo"] == str(ROOT)
    assert isinstance(payload["summary"]["missing_tools"], list)


def test_scan_can_skip_external_tools() -> None:
    proc = run_cli("scan", "--repo", str(ROOT), "--skip-foundry", "--skip-slither", "--format", "json")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["schema"] == "contract_guard_scan/v1"
    assert payload["schema_version"] == "1"
    assert payload["ok"] is True
    assert payload["status"] == "passed"
    assert payload["summary"] == {"checks": 2, "passed": 0, "failed": 0, "skipped": 2}
    assert {result["name"] for result in payload["results"]} == {"foundry", "slither"}
    assert all(result["skipped"] for result in payload["results"])
    assert {result["status"] for result in payload["results"]} == {"skipped"}
    reports = {report["tool"]: report for report in payload["tool_reports"]}
    assert reports["foundry"]["summary"] == {"passed": None, "failed": None, "skipped": None, "total": None}
    assert reports["foundry"]["diagnostics"] == ["skip_foundry_requested"]
    assert reports["slither"]["kind"] == "static_analysis"
    assert reports["slither"]["summary"] == {"findings": 0, "by_severity": {}}
    assert reports["slither"]["diagnostics"] == ["skip_slither_requested"]


def test_scan_result_command_schema_is_stable() -> None:
    proc = run_cli("scan", "--repo", str(ROOT), "--skip-foundry", "--skip-slither", "--format", "json")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    results = {result["name"]: result for result in payload["results"]}
    assert results["foundry"]["command"] == ["forge", "test"]
    assert results["slither"]["command"] == ["slither", ".", "--json", "-", "--fail-none"]
    for result in results.values():
        assert set(result) == {
            "command",
            "exit_code",
            "name",
            "ok",
            "skip_reason",
            "skipped",
            "status",
            "stderr",
            "stdout",
        }


def test_plan_detects_solidity_fixture() -> None:
    with TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / "src").mkdir()
        (repo / "test").mkdir()
        (repo / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
        (repo / "src" / "Counter.sol").write_text("contract Counter {}\n", encoding="utf-8")
        proc = run_cli("plan", "--repo", str(repo), "--json")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["plan"]["foundry_project"] is True
    assert payload["plan"]["solidity_files"] == 1


def test_diff_scope_filters_changed_solidity_files() -> None:
    with TemporaryDirectory() as tmp:
        repo = Path(tmp)
        subprocess.run(["git", "init"], cwd=repo, text=True, capture_output=True, check=True)
        (repo / "contracts").mkdir()
        (repo / "lib").mkdir()
        (repo / "contracts" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
        (repo / "lib" / "Ignored.sol").write_text("contract Ignored {}\n", encoding="utf-8")
        (repo / "README.md").write_text("# fixture\n", encoding="utf-8")
        subprocess.run(["git", "add", "-N", "contracts/Vault.sol", "lib/Ignored.sol", "README.md"], cwd=repo, text=True, capture_output=True, check=True)
        diff = build_diff_scope(repo, enabled=True)
    assert diff["enabled"] is True
    assert diff["available"] is True
    assert diff["changed_files"] == ["README.md", "contracts/Vault.sol", "lib/Ignored.sol"]
    assert diff["changed_solidity_files"] == ["contracts/Vault.sol"]
    assert diff["diagnostics"] == []


def test_cli_changed_only_reports_diff_scope() -> None:
    with TemporaryDirectory() as tmp:
        repo = Path(tmp)
        subprocess.run(["git", "init"], cwd=repo, text=True, capture_output=True, check=True)
        (repo / "contracts").mkdir()
        (repo / "contracts" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
        subprocess.run(["git", "add", "-N", "contracts/Vault.sol"], cwd=repo, text=True, capture_output=True, check=True)
        proc = run_cli("scan", "--repo", str(repo), "--skip-foundry", "--skip-slither", "--changed-only", "--format", "json")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["diff"]["enabled"] is True
    assert payload["diff"]["changed_solidity_files"] == ["contracts/Vault.sol"]
    slither_report = next(report for report in payload["tool_reports"] if report["tool"] == "slither")
    assert "diff_filter_kept_0_of_0_slither_findings" in slither_report["diagnostics"]


def test_diff_filter_keeps_only_changed_slither_findings() -> None:
    reports = [
        {
            "tool": "slither",
            "kind": "static_analysis",
            "status": "passed",
            "summary": {"findings": 2, "by_severity": {"high": 1, "medium": 1}},
            "findings": [
                {
                    "id": "slither:reentrancy-eth:contracts/Vault.sol:42",
                    "severity": "high",
                    "source_location": {"file": "contracts/Vault.sol", "start_line": 42},
                },
                {
                    "id": "slither:unchecked-transfer:contracts/Token.sol:7",
                    "severity": "medium",
                    "source_location": {"file": "contracts/Token.sol", "start_line": 7},
                },
            ],
            "diagnostics": [],
        }
    ]
    filtered = filter_tool_reports_to_changed_solidity(reports, ["contracts/Vault.sol"])
    assert filtered[0]["summary"] == {"findings": 1, "by_severity": {"high": 1}}
    assert filtered[0]["findings"] == [reports[0]["findings"][0]]
    assert filtered[0]["diagnostics"] == ["diff_filter_kept_1_of_2_slither_findings"]


def test_baseline_suppresses_non_high_but_never_high() -> None:
    reports = [
        {
            "tool": "slither",
            "kind": "static_analysis",
            "status": "passed",
            "summary": {"findings": 2, "by_severity": {"high": 1, "medium": 1}},
            "findings": [
                {
                    "id": "slither:reentrancy-eth:contracts/Vault.sol:42",
                    "check": "reentrancy-eth",
                    "severity": "high",
                    "source_location": {"file": "contracts/Vault.sol", "start_line": 42},
                },
                {
                    "id": "slither:unchecked-transfer:contracts/Token.sol:7",
                    "check": "unchecked-transfer",
                    "severity": "medium",
                    "source_location": {"file": "contracts/Token.sol", "start_line": 7},
                },
            ],
            "diagnostics": [],
        }
    ]
    baseline = {
        "enabled": True,
        "suppressions": [
            {"id": "slither:reentrancy-eth:contracts/Vault.sol:42"},
            {"check": "unchecked-transfer", "file": "contracts/Token.sol", "start_line": 7},
        ],
    }
    filtered = apply_baseline_suppression(reports, baseline)
    assert filtered[0]["findings"] == [reports[0]["findings"][0]]
    assert filtered[0]["suppressed_findings"] == [
        reports[0]["findings"][1] | {"suppression_status": "suppressed_by_baseline"}
    ]
    assert filtered[0]["summary"] == {"findings": 1, "by_severity": {"high": 1}, "baseline_suppressed": 1}
    assert filtered[0]["diagnostics"] == [
        "baseline_suppressed_1_of_2_slither_findings",
        "baseline_high_severity_not_suppressed_1",
    ]


def test_load_baseline_keeps_report_path_relative() -> None:
    with TemporaryDirectory() as tmp:
        repo = Path(tmp)
        baseline_file = repo / ".contract-guard-baseline.json"
        baseline_file.write_text(
            json.dumps(
                {
                    "schema": "contract_guard_baseline/v1",
                    "suppressions": [
                        {
                            "check": "unchecked-transfer",
                            "file": "./contracts/Token.sol",
                            "start_line": 7,
                            "reason": "known false positive",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        baseline = load_baseline(repo, ".contract-guard-baseline.json")
    assert baseline["enabled"] is True
    assert baseline["path"] == ".contract-guard-baseline.json"
    assert baseline["suppression_count"] == 1
    assert baseline["suppressions"] == [
        {
            "id": "",
            "check": "unchecked-transfer",
            "file": "contracts/Token.sol",
            "start_line": 7,
            "reason": "known false positive",
        }
    ]
    assert baseline["diagnostics"] == []


def test_cli_baseline_file_reports_loaded_suppressions() -> None:
    with TemporaryDirectory() as tmp:
        repo = Path(tmp)
        baseline_file = repo / ".contract-guard-baseline.json"
        baseline_file.write_text(
            json.dumps({"schema": "contract_guard_baseline/v1", "suppressions": [{"id": "known"}]}),
            encoding="utf-8",
        )
        proc = run_cli(
            "scan",
            "--repo",
            str(repo),
            "--skip-foundry",
            "--skip-slither",
            "--baseline-file",
            ".contract-guard-baseline.json",
            "--format",
            "json",
        )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["baseline"]["enabled"] is True
    assert payload["baseline"]["path"] == ".contract-guard-baseline.json"
    assert payload["baseline"]["suppression_count"] == 1
    slither_report = next(report for report in payload["tool_reports"] if report["tool"] == "slither")
    assert slither_report["summary"] == {"findings": 0, "by_severity": {}, "baseline_suppressed": 0}
    assert "baseline_suppressed_0_of_0_slither_findings" in slither_report["diagnostics"]


def test_failure_policy_fails_on_active_high_finding() -> None:
    policy = evaluate_failure_policy(
        [
            {
                "tool": "slither",
                "findings": [
                    {
                        "id": "slither:reentrancy-eth:contracts/Vault.sol:42",
                        "check": "reentrancy-eth",
                        "severity": "high",
                        "confidence": "medium",
                        "source_location": {"file": "contracts/Vault.sol", "start_line": 42},
                    }
                ],
            }
        ],
        fail_on_severity="high",
        fail_on_confidence="low",
    )
    assert policy == {
        "enabled": True,
        "fail_on_severity": "high",
        "fail_on_confidence": "low",
        "failed": True,
        "matched_findings": [
            {
                "id": "slither:reentrancy-eth:contracts/Vault.sol:42",
                "check": "reentrancy-eth",
                "severity": "high",
                "confidence": "medium",
                "source_location": {"file": "contracts/Vault.sol", "start_line": 42},
            }
        ],
        "diagnostics": [],
    }


def test_failure_policy_respects_severity_and_confidence_thresholds() -> None:
    reports = [
        {
            "tool": "slither",
            "findings": [
                {
                    "id": "slither:unchecked-transfer:contracts/Token.sol:7",
                    "check": "unchecked-transfer",
                    "severity": "medium",
                    "confidence": "low",
                    "source_location": {"file": "contracts/Token.sol", "start_line": 7},
                }
            ],
        }
    ]
    assert evaluate_failure_policy(reports, fail_on_severity="medium", fail_on_confidence="medium")["failed"] is False
    assert evaluate_failure_policy(reports, fail_on_severity="medium", fail_on_confidence="low")["failed"] is True
    assert evaluate_failure_policy(reports, fail_on_severity="none", fail_on_confidence="low")["enabled"] is False


def test_failure_policy_runs_after_baseline_suppression() -> None:
    reports = [
        {
            "tool": "slither",
            "findings": [
                {
                    "id": "slither:unchecked-transfer:contracts/Token.sol:7",
                    "check": "unchecked-transfer",
                    "severity": "medium",
                    "confidence": "high",
                    "source_location": {"file": "contracts/Token.sol", "start_line": 7},
                }
            ],
            "diagnostics": [],
        }
    ]
    baseline = {
        "enabled": True,
        "suppressions": [{"check": "unchecked-transfer", "file": "contracts/Token.sol", "start_line": 7}],
    }
    filtered = apply_baseline_suppression(reports, baseline)
    assert evaluate_failure_policy(filtered, fail_on_severity="medium", fail_on_confidence="low")["failed"] is False


def test_cli_failure_policy_defaults_do_not_fail_empty_scan() -> None:
    proc = run_cli("scan", "--repo", str(ROOT), "--skip-foundry", "--skip-slither", "--format", "json")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["failure_policy"]["enabled"] is True
    assert payload["failure_policy"]["fail_on_severity"] == "high"
    assert payload["failure_policy"]["fail_on_confidence"] == "low"
    assert payload["failure_policy"]["failed"] is False
    assert payload["failure_policy"]["matched_findings"] == []


def test_foundry_normalizes_passing_output() -> None:
    result = CommandResult(
        name="foundry",
        command=["forge", "test"],
        exit_code=0,
        stdout=(
            "Ran 1 test for test/Counter.t.sol:CounterTest\n"
            "[PASS] test_Increment() (gas: 28334)\n"
            "Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 514.50µs\n"
            "Ran 1 test suite in 123.45ms: 1 tests passed, 0 failed, 0 skipped (1 total tests)\n"
        ),
        stderr="",
    )
    report = normalize_foundry_result(result)
    assert report["status"] == "passed"
    assert report["summary"] == {"passed": 1, "failed": 0, "skipped": 0, "total": 1}
    assert report["failures"] == []
    assert report["diagnostics"] == []


def test_foundry_normalizes_failing_output() -> None:
    result = CommandResult(
        name="foundry",
        command=["forge", "test"],
        exit_code=1,
        stdout=(
            "Ran 3 tests for test/Vault.t.sol:VaultTest\n"
            "[PASS] test_Deposit() (gas: 42111)\n"
            "[FAIL: panic: arithmetic underflow] test_WithdrawUnderflows() (gas: 9321)\n"
            "Suite result: FAILED. 2 passed; 1 failed; 0 skipped; finished in 1.40ms\n"
            "Ran 1 test suite in 2.30ms: 2 tests passed, 1 failed, 0 skipped (3 total tests)\n"
        ),
        stderr="",
    )
    report = normalize_foundry_result(result)
    assert report["status"] == "failed"
    assert report["summary"] == {"passed": 2, "failed": 1, "skipped": 0, "total": 3}
    assert report["failures"] == [{"test": "test_WithdrawUnderflows()", "reason": "panic: arithmetic underflow"}]
    assert report["diagnostics"] == []


def test_foundry_normalizes_timeout() -> None:
    result = CommandResult(
        name="foundry",
        command=["forge", "test"],
        exit_code=124,
        stdout="",
        stderr="timeout_expired",
    )
    report = normalize_foundry_result(result)
    assert report["status"] == "failed"
    assert report["summary"] == {"passed": None, "failed": None, "skipped": None, "total": None}
    assert report["failures"] == []
    assert report["diagnostics"] == ["timeout_expired"]


def test_slither_normalizes_detector_json() -> None:
    slither_json = {
        "success": True,
        "error": None,
        "results": {
            "detectors": [
                {
                    "check": "reentrancy-eth",
                    "impact": "High",
                    "confidence": "Medium",
                    "description": "Vault.withdraw sends ETH before updating state.",
                    "markdown": "Vault.withdraw has a reentrancy risk.",
                    "elements": [
                        {
                            "type": "function",
                            "name": "withdraw",
                            "source_mapping": {
                                "filename_absolute": "/private/project/contracts/Vault.sol",
                                "filename_relative": "contracts/Vault.sol",
                                "lines": [42, 43],
                                "starting_column": 5,
                                "ending_column": 19,
                            },
                        }
                    ],
                }
            ]
        },
    }
    result = CommandResult(
        name="slither",
        command=["slither", ".", "--json", "-", "--fail-none"],
        exit_code=0,
        stdout=json.dumps(slither_json),
        stderr="",
    )
    report = normalize_slither_result(result)
    assert report["kind"] == "static_analysis"
    assert report["status"] == "passed"
    assert report["summary"] == {"findings": 1, "by_severity": {"high": 1}}
    assert report["diagnostics"] == []
    assert report["findings"] == [
        {
            "id": "slither:reentrancy-eth:contracts/Vault.sol:42",
            "check": "reentrancy-eth",
            "title": "reentrancy-eth",
            "impact": "High",
            "severity": "high",
            "confidence": "medium",
            "source_location": {
                "file": "contracts/Vault.sol",
                "start_line": 42,
                "end_line": 43,
                "start_column": 5,
                "end_column": 19,
            },
            "description": "Vault.withdraw sends ETH before updating state.",
            "markdown": "Vault.withdraw has a reentrancy risk.",
        }
    ]


def test_slither_avoids_absolute_path_when_only_absolute_filename_exists() -> None:
    slither_json = {
        "success": True,
        "results": {
            "detectors": [
                {
                    "check": "unchecked-transfer",
                    "impact": "Medium",
                    "confidence": "High",
                    "source_mapping": {
                        "filename_absolute": "/Users/example/secret/protocol/src/Token.sol",
                        "lines": [7],
                    },
                }
            ]
        },
    }
    result = CommandResult("slither", ["slither", ".", "--json", "-", "--fail-none"], 0, json.dumps(slither_json), "")
    report = normalize_slither_result(result)
    assert report["findings"][0]["source_location"]["file"] == "Token.sol"
    assert "/Users/example/secret" not in json.dumps(report)


def test_slither_invalid_json_is_diagnostic_not_exception() -> None:
    result = CommandResult("slither", ["slither", ".", "--json", "-", "--fail-none"], 1, "not-json", "")
    report = normalize_slither_result(result)
    assert report["status"] == "failed"
    assert report["summary"] == {"findings": 0, "by_severity": {}}
    assert report["findings"] == []
    assert report["diagnostics"] == ["slither_json_parse_failed"]


def test_aderyn_normalizes_json_findings_without_snippets_or_absolute_paths() -> None:
    payload = {
        "issue_count": {"high": 1, "low": 1},
        "high_issues": {
            "issues": [
                {
                    "title": "Reentrancy: State change after external call",
                    "description": "Changing state after an external call can lead to re-entrancy attacks.",
                    "detector_name": "reentrancy-state-change",
                    "instances": [
                        {
                            "contract_path": "/private/tmp/project/src/Vault.sol",
                            "line_no": 100,
                            "hint": "State is changed after external call",
                        }
                    ],
                }
            ]
        },
        "low_issues": {
            "issues": [
                {
                    "title": "Centralization Risk",
                    "description": "Owner can perform admin tasks.",
                    "detector_name": "centralization-risk",
                    "instances": [{"contract_path": "src/Vault.sol", "line_no": 79}],
                }
            ]
        },
    }

    report = normalize_aderyn_payload(payload)

    assert report["tool"] == "aderyn"
    assert report["status"] == "passed"
    assert report["summary"] == {"findings": 2, "by_severity": {"high": 1, "low": 1}}
    assert report["diagnostics"] == []
    first = report["findings"][0]
    assert first["id"] == "aderyn:reentrancy-state-change:Vault.sol:100"
    assert first["location"] == {"file": "Vault.sol", "start_line": 100, "end_line": 100}
    assert first["source_location"] == {"file": "Vault.sol", "start_line": 100, "end_line": 100}
    assert first["confidence"] == "unknown"
    assert "snippet" not in first
    assert "/private/tmp" not in json.dumps(report)


def test_aderyn_invalid_payload_is_diagnostic_not_exception() -> None:
    report = normalize_aderyn_payload(["not", "an", "object"], exit_code=1)
    assert report["tool"] == "aderyn"
    assert report["status"] == "failed"
    assert report["summary"] == {"findings": 0, "by_severity": {}}
    assert report["findings"] == []
    assert report["diagnostics"] == ["aderyn_json_root_not_object"]


def test_scan_does_not_include_aderyn_without_explicit_opt_in() -> None:
    proc = run_cli("scan", "--repo", str(ROOT), "--skip-foundry", "--skip-slither", "--format", "json")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert {result["name"] for result in payload["results"]} == {"foundry", "slither"}
    assert {report["tool"] for report in payload["tool_reports"]} == {"foundry", "slither"}


def test_cli_include_aderyn_runs_fake_tool_without_raw_banner_paths() -> None:
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        repo = root / "repo"
        tool_dir = root / "bin"
        (repo / "src").mkdir(parents=True)
        tool_dir.mkdir()
        (repo / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
        fake_aderyn = tool_dir / "aderyn"
        fake_aderyn.write_text(
            """#!/bin/sh
cat > "$3" <<'JSON'
{"issue_count":{"high":1},"high_issues":{"issues":[{"title":"Reentrancy","description":"State changes after external call.","detector_name":"reentrancy-state-change","instances":[{"contract_path":"/Users/private/project/src/Vault.sol","line_no":7}]}]}}
JSON
echo "config path: /Users/private/project/foundry.toml"
""",
            encoding="utf-8",
        )
        fake_aderyn.chmod(0o755)
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{tool_dir}{os.pathsep}{old_path}"
        try:
            proc = run_cli("scan", "--repo", str(repo), "--skip-foundry", "--skip-slither", "--include-aderyn", "--format", "json")
        finally:
            os.environ["PATH"] = old_path

    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert {result["name"] for result in payload["results"]} == {"foundry", "slither", "aderyn"}
    aderyn_result = next(result for result in payload["results"] if result["name"] == "aderyn")
    assert aderyn_result["command"] == ["aderyn", ".", "-o", "<temporary-json-output>"]
    assert "/Users/private" not in json.dumps(aderyn_result)
    report = next(report for report in payload["tool_reports"] if report["tool"] == "aderyn")
    assert report["summary"] == {"findings": 1, "by_severity": {"high": 1}}
    assert report["findings"][0]["source_location"] == {"file": "Vault.sol", "start_line": 7, "end_line": 7}
    assert "/Users/private" not in json.dumps(report)
    assert payload["failure_policy"]["failed"] is False


def test_aderyn_can_participate_in_sarif_when_explicitly_included() -> None:
    report = normalize_aderyn_result(
        CommandResult(
            "aderyn",
            ["aderyn", ".", "-o", "<temporary-json-output>"],
            0,
            json.dumps(
                {
                    "issue_count": {"low": 1},
                    "low_issues": {
                        "issues": [
                            {
                                "title": "Centralization Risk",
                                "description": "Owner can pause the vault.",
                                "detector_name": "centralization-risk",
                                "instances": [{"contract_path": "src/Vault.sol", "line_no": 12}],
                            }
                        ]
                    },
                }
            ),
            "",
        )
    )
    sarif = render_sarif({"tool_reports": [report], "failure_policy": {"failed": False}})
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["rules"][0]["properties"]["source_tool"] == "aderyn"
    assert run["results"][0]["properties"]["source_tool"] == "aderyn"
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/Vault.sol"


def test_large_slither_json_is_parsed_before_serialized_stdout_truncation() -> None:
    large_description = "x" * 25000
    slither_json = {
        "success": True,
        "results": {
            "detectors": [
                {
                    "check": "large-output-check",
                    "impact": "Medium",
                    "confidence": "High",
                    "description": large_description,
                    "first_markdown_element": "Large output finding",
                    "elements": [
                        {
                            "source_mapping": {
                                "filename_short": "src/Large.sol",
                                "lines": [12],
                            }
                        }
                    ],
                }
            ]
        },
    }
    result = CommandResult("slither", ["slither", ".", "--json", "-", "--fail-none"], 0, json.dumps(slither_json), "")

    report = normalize_slither_result(result)

    assert report["status"] == "passed"
    assert report["summary"]["findings"] == 1
    assert report["diagnostics"] == []
    serialized = result.to_dict()
    assert len(serialized["stdout"]) == 20000
    assert serialized["stdout"] == result.stdout[-20000:]


def test_markdown_report_renders_stable_deterministic_evidence() -> None:
    markdown = render_markdown(
        {
            "ok": False,
            "plan": {
                "repo": "/example/repo",
                "is_git_repo": True,
                "foundry_project": True,
                "solidity_files": 2,
                "tools": [
                    {"name": "forge", "available": True, "path": "/usr/bin/forge"},
                    {"name": "slither", "available": True, "path": "/usr/bin/slither"},
                ],
                "warnings": [],
            },
            "results": [
                {"name": "foundry", "ok": False, "skipped": False, "skip_reason": "", "exit_code": 1},
                {"name": "slither", "ok": True, "skipped": False, "skip_reason": "", "exit_code": 0},
            ],
            "tool_reports": [
                {
                    "tool": "foundry",
                    "status": "failed",
                    "summary": {"passed": 2, "failed": 1, "skipped": 0, "total": 3},
                    "failures": [{"test": "test_WithdrawUnderflows()", "reason": "panic: arithmetic underflow"}],
                    "diagnostics": [],
                },
                {
                    "tool": "slither",
                    "status": "passed",
                    "summary": {"findings": 1, "by_severity": {"high": 1}},
                    "findings": [
                        {
                            "severity": "high",
                            "confidence": "medium",
                            "check": "reentrancy-eth",
                            "source_location": {"file": "contracts/Vault.sol", "start_line": 42, "end_line": 43},
                            "description": "Vault.withdraw sends ETH before updating state.",
                        }
                    ],
                    "diagnostics": [],
                },
            ],
        }
    )
    assert "Deterministic tool evidence only. Optional AI triage is not included" in markdown
    assert "## Deterministic tool evidence" in markdown
    assert "### Foundry" in markdown
    assert "| `test_WithdrawUnderflows()` | panic: arithmetic underflow |" in markdown
    assert "### Slither" in markdown
    assert "| `high` | `medium` | `reentrancy-eth` | `contracts/Vault.sol:42-43` | Vault.withdraw sends ETH before updating state. |" in markdown
    assert "stdout" not in markdown.lower()
    assert "stderr" not in markdown.lower()


def test_cli_markdown_includes_deterministic_boundary() -> None:
    proc = run_cli("scan", "--repo", str(ROOT), "--skip-foundry", "--skip-slither", "--format", "markdown")
    assert proc.returncode == 0, proc.stderr
    assert "Deterministic tool evidence only. Optional AI triage is not included" in proc.stdout
    assert "## Deterministic tool evidence" in proc.stdout
    assert "skip_foundry_requested" in proc.stdout
    assert "skip_slither_requested" in proc.stdout


def test_sarif_report_renders_slither_findings_for_code_scanning() -> None:
    sarif = render_sarif(
        {
            "schema": "contract_guard_scan/v1",
            "schema_version": "1",
            "tool_reports": [
                {
                    "tool": "slither",
                    "findings": [
                        {
                            "id": "slither:reentrancy-eth:contracts/Vault.sol:42",
                            "check": "reentrancy-eth",
                            "title": "reentrancy-eth",
                            "impact": "High",
                            "severity": "high",
                            "confidence": "medium",
                            "source_location": {
                                "file": "contracts/Vault.sol",
                                "start_line": 42,
                                "end_line": 43,
                                "start_column": 5,
                                "end_column": 19,
                            },
                            "description": "Vault.withdraw sends ETH before updating state.",
                            "markdown": "Vault.withdraw has a reentrancy risk.",
                        }
                    ],
                }
            ],
        }
    )
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["properties"]["deterministic_evidence_only"] is True
    assert run["properties"]["ai_triage_included"] is False
    assert run["tool"]["driver"]["rules"][0]["id"] == "reentrancy-eth"
    assert run["tool"]["driver"]["rules"][0]["defaultConfiguration"]["level"] == "error"
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "8.0"
    assert run["results"] == [
        {
            "ruleId": "reentrancy-eth",
            "level": "error",
            "message": {"text": "Vault.withdraw sends ETH before updating state."},
            "properties": {
                "contract_guard_finding_id": "slither:reentrancy-eth:contracts/Vault.sol:42",
                "source_tool": "slither",
                "severity": "high",
                "confidence": "medium",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "contracts/Vault.sol"},
                        "region": {"startLine": 42, "endLine": 43, "startColumn": 5, "endColumn": 19},
                    }
                }
            ],
        }
    ]
    assert "/Users/" not in json.dumps(sarif)


def test_cli_sarif_empty_scan_is_valid_json() -> None:
    proc = run_cli("scan", "--repo", str(ROOT), "--skip-foundry", "--skip-slither", "--format", "sarif")
    assert proc.returncode == 0, proc.stderr
    sarif = json.loads(proc.stdout)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "Contract Guard CI"
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["properties"]["ai_triage_included"] is False


def test_invariant_payload_all_profiles_is_advisory() -> None:
    payload = invariant_payload(profile="all", contract_name="Protocol")
    assert payload["schema"] == "contract_guard_invariant_templates/v1"
    assert payload["schema_version"] == "1"
    assert payload["status"] == "advisory_templates"
    assert "not proofs, audits, or guarantees" in payload["disclaimer"]
    assert {template["profile"] for template in payload["templates"]} == {"erc20", "vault", "access-control"}
    assert len(payload["templates"]) == 6
    assert all("foundry_snippet" in template for template in payload["templates"])


def test_cli_invariants_json_uses_contract_name_without_repo_arg() -> None:
    proc = run_cli("invariants", "--profile", "erc20", "--contract", "Token", "--format", "json")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["schema"] == "contract_guard_invariant_templates/v1"
    assert payload["profile"] == "erc20"
    assert payload["contract"] == "Token"
    assert [template["id"] for template in payload["templates"]] == [
        "erc20-total-supply-accounting",
        "erc20-no-negative-effective-balance",
    ]
    assert "contract TokenInvariantTest is Test" in payload["templates"][0]["foundry_snippet"]
    assert "Token internal token;" in payload["templates"][0]["foundry_snippet"]


def test_invariant_markdown_keeps_templates_advisory() -> None:
    payload = invariant_payload(profile="vault", contract_name="Vault", test_contract_name="VaultPropertyTest")
    markdown = render_invariant_markdown(payload)
    assert "# Contract Guard CI Invariant Templates" in markdown
    assert "Deterministic invariant templates are advisory starting points" in markdown
    assert "They are not proofs, audits, or guarantees" in markdown
    assert "contract VaultPropertyTest is Test" in markdown
    assert "assertGe(assets, vault.convertToAssets(shares)" in markdown
    assert "```solidity" in markdown


def test_fuzz_hooks_payload_all_tools_is_scaffold_only() -> None:
    payload = fuzz_hooks_payload(
        tool="all",
        target="/Users/example/private/test/invariants/InvariantTest.sol",
        contract_name="InvariantTest",
    )
    assert payload["schema"] == "contract_guard_fuzz_hooks/v1"
    assert payload["schema_version"] == "1"
    assert payload["status"] == "scaffold_only"
    assert payload["target"] == "test/invariants/InvariantTest.sol"
    assert "/Users/example/private" not in json.dumps(payload)
    assert "do not execute external fuzzers by default" in payload["disclaimer"]
    assert "not proofs, audits, or guarantees" in payload["disclaimer"]
    assert {hook["tool"] for hook in payload["hooks"]} == {"echidna", "medusa"}
    assert all(hook["executes_by_default"] is False for hook in payload["hooks"])


def test_cli_fuzz_hooks_json_generates_echidna_command() -> None:
    proc = run_cli(
        "fuzz-hooks",
        "--tool",
        "echidna",
        "--target",
        "test/invariants/TokenInvariant.t.sol",
        "--contract",
        "TokenInvariant",
        "--format",
        "json",
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["schema"] == "contract_guard_fuzz_hooks/v1"
    assert payload["tool"] == "echidna"
    assert payload["contract"] == "TokenInvariant"
    assert len(payload["hooks"]) == 1
    assert payload["hooks"][0]["command"] == [
        "echidna",
        "test/invariants/TokenInvariant.t.sol",
        "--contract",
        "TokenInvariant",
        "--config",
        "echidna.yaml",
    ]
    assert payload["hooks"][0]["executes_by_default"] is False


def test_fuzz_hooks_markdown_keeps_execution_boundary() -> None:
    payload = fuzz_hooks_payload(tool="medusa", target="test/invariants/VaultInvariant.t.sol", contract_name="VaultInvariant")
    markdown = render_fuzz_hooks_markdown(payload)
    assert "# Contract Guard CI Fuzzing Hooks" in markdown
    assert "local-runner scaffolds only" in markdown
    assert "They do not execute external fuzzers by default" in markdown
    assert "## Medusa Foundry fuzz hook scaffold" in markdown
    assert "medusa fuzz --config medusa.json" in markdown
    assert "Executes by default: `false`" in markdown
    assert "deterministic fuzzer evidence, separate from optional AI explanation" in markdown


def test_false_positive_review_blocks_high_severity_suppression() -> None:
    payload = false_positive_review_payload(
        finding_id="slither:reentrancy-eth:contracts/Vault.sol:42",
        check="reentrancy-eth",
        file="/Users/example/private/contracts/Vault.sol",
        start_line=42,
        severity="high",
        confidence="medium",
        reason="suspected framework false positive",
        reviewer="security-team",
    )
    assert payload["schema"] == "contract_guard_false_positive_review/v1"
    assert payload["status"] == "blocked_high_severity"
    assert payload["policy"]["eligible_for_baseline"] is False
    assert payload["policy"]["high_severity_never_suppressed"] is True
    assert payload["baseline_candidate"] is None
    assert payload["finding"]["source_location"]["file"] == "contracts/Vault.sol"
    assert "/Users/example/private" not in json.dumps(payload)


def test_cli_false_positive_json_generates_non_high_baseline_candidate() -> None:
    proc = run_cli(
        "false-positive",
        "--id",
        "slither:unchecked-transfer:contracts/Token.sol:7",
        "--check",
        "unchecked-transfer",
        "--file",
        "contracts/Token.sol",
        "--start-line",
        "7",
        "--severity",
        "medium",
        "--confidence",
        "high",
        "--reason",
        "Known safe return-value wrapper in SafeERC20 adapter.",
        "--reviewer",
        "security-team",
        "--expires",
        "2026-12-31",
        "--format",
        "json",
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["status"] == "eligible_for_baseline"
    assert payload["ai_triage_included"] is False
    assert payload["baseline_candidate"] == {
        "id": "slither:unchecked-transfer:contracts/Token.sol:7",
        "check": "unchecked-transfer",
        "file": "contracts/Token.sol",
        "start_line": 7,
        "reason": "Known safe return-value wrapper in SafeERC20 adapter.",
        "classification": "false-positive",
        "reviewer": "security-team",
        "expires": "2026-12-31",
    }


def test_false_positive_markdown_keeps_audit_trail_boundary() -> None:
    payload = false_positive_review_payload(
        check="unchecked-transfer",
        file="contracts/Token.sol",
        start_line=7,
        severity="medium",
        confidence="high",
        reason="Known safe wrapper.",
        reviewer="security-team",
    )
    markdown = render_false_positive_markdown(payload)
    assert "# Contract Guard CI False-Positive Review" in markdown
    assert "AI triage is not included" in markdown
    assert "Eligible for baseline: `true`" in markdown
    assert "High severity never suppressed: `true`" in markdown
    assert '"check": "unchecked-transfer"' in markdown


def test_policy_loads_defaults_when_no_policy_file_exists() -> None:
    with TemporaryDirectory() as tmp:
        payload = load_policy(Path(tmp))
    assert payload["schema"] == "contract_guard_policy/v1"
    assert payload["schema_version"] == "1"
    assert payload["ok"] is True
    assert payload["status"] == "defaults_used"
    assert payload["policy"]["local_only"] is True
    assert payload["policy"]["scan"]["fail_on_severity"] == "high"
    assert payload["policy"]["scan"]["fail_on_confidence"] == "low"
    assert payload["policy"]["ai_triage"] == {"enabled": False, "send_private_snippets": False}
    assert payload["policy"]["hosted_uploads"] == {"enabled": False}


def test_cli_policy_validates_example_policy_file() -> None:
    proc = run_cli("policy", "--repo", str(ROOT), "--policy-file", ".contract-guard-policy.example.json", "--format", "json")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    assert payload["status"] == "valid"
    assert payload["source"]["path"] == ".contract-guard-policy.example.json"
    assert payload["policy"]["scan"] == {
        "changed_only": True,
        "diff_base": "origin/main...HEAD",
        "baseline_file": ".contract-guard-baseline.json",
        "fail_on_severity": "high",
        "fail_on_confidence": "low",
    }
    assert payload["policy"]["reporting"]["include_raw_stdout_stderr"] is False


def test_policy_rejects_ai_private_upload_and_raw_output_defaults() -> None:
    with TemporaryDirectory() as tmp:
        repo = Path(tmp)
        policy_file = repo / ".contract-guard-policy.json"
        policy_file.write_text(
            json.dumps(
                {
                    "schema": "contract_guard_policy/v1",
                    "scan": {"fail_on_severity": "critical", "baseline_file": "/Users/example/private/contracts/.baseline.json"},
                    "reporting": {"formats": ["json"], "include_raw_stdout_stderr": True},
                    "ai_triage": {"enabled": True, "send_private_snippets": True},
                    "hosted_uploads": {"enabled": True, "token": "SECRET_VALUE_SHOULD_NOT_ECHO"},
                }
            ),
            encoding="utf-8",
        )
        payload = load_policy(repo, ".contract-guard-policy.json")
    encoded = json.dumps(payload)
    assert payload["ok"] is False
    assert payload["status"] == "needs_attention"
    assert "scan.fail_on_severity_invalid_using_default" in payload["diagnostics"]
    assert "reporting.include_raw_stdout_stderr_not_allowed" in payload["diagnostics"]
    assert "ai_triage_default_must_remain_disabled" in payload["diagnostics"]
    assert "ai_triage.private_snippets_not_allowed" in payload["diagnostics"]
    assert "hosted_uploads_default_must_remain_disabled" in payload["diagnostics"]
    assert payload["policy"]["ai_triage"]["enabled"] is False
    assert payload["policy"]["ai_triage"]["send_private_snippets"] is False
    assert payload["policy"]["hosted_uploads"]["enabled"] is False
    assert payload["policy"]["reporting"]["include_raw_stdout_stderr"] is False
    assert payload["policy"]["scan"]["baseline_file"] == "contracts/.baseline.json"
    assert "SECRET_VALUE_SHOULD_NOT_ECHO" not in encoded
    assert "/Users/example/private" not in encoded


def test_policy_markdown_states_local_deterministic_boundary() -> None:
    payload = load_policy(ROOT, ".contract-guard-policy.example.json")
    markdown = render_policy_markdown(payload)
    assert "# Contract Guard CI Repo Policy" in markdown
    assert "Policy is local and deterministic" in markdown
    assert "AI triage enabled: `false`" in markdown
    assert "Send private snippets: `false`" in markdown
    assert "Hosted uploads enabled: `false`" in markdown
    assert "Include raw stdout/stderr: `false`" in markdown


def test_ai_triage_payload_drops_snippet_by_default() -> None:
    secret_hex = "0x" + "a" * 64
    payload = ai_triage_payload(
        check="reentrancy-eth",
        severity="high",
        confidence="medium",
        file="/Users/example/private/contracts/Vault.sol",
        start_line=42,
        description=f"PRIVATE_KEY={secret_hex} in /Users/example/private/contracts/Vault.sol",
        snippet=f"PRIVATE_KEY={secret_hex}\ncontract Vault {{}}",
    )
    encoded = json.dumps(payload)
    assert payload["schema"] == "contract_guard_ai_triage_payload/v1"
    assert payload["status"] == "snippets_disabled_by_default"
    assert payload["external_ai_call_made"] is False
    assert payload["send_private_snippets"] is False
    assert payload["snippet"]["included"] is False
    assert "snippet_dropped_because_redacted_snippets_disabled" in payload["diagnostics"]
    assert secret_hex not in encoded
    assert "/Users/example/private" not in encoded
    assert payload["finding"]["source_location"]["file"] == "contracts/Vault.sol"


def test_redact_text_removes_common_secret_patterns_and_paths() -> None:
    secret_hex = "0x" + "b" * 64
    fake_openai_key = "sk-" + "testtoken" + "a" * 24
    fake_github_token = "github_pat_" + "a" * 32
    fake_aws_key = "AKIA" + "ABCDEFGHIJKLMNOP"
    fake_abs_root = "/" + "private" + "/tmp/customer"
    fake_abs_path = f"{fake_abs_root}/contracts/Token.sol"
    text = (
        f"OPENAI_API_KEY={fake_openai_key} "
        f"{fake_github_token} "
        f"{fake_aws_key} "
        f"privateKey: '{secret_hex}' "
        f"{fake_abs_path}"
    )
    redacted, counts = redact_text(text)
    assert "sk-testtoken" not in redacted
    assert "github_pat_" not in redacted
    assert fake_aws_key not in redacted
    assert secret_hex not in redacted
    assert fake_abs_root not in redacted
    assert "[REDACTED_TOKEN]" in redacted
    assert "[REDACTED_AWS_KEY]" in redacted
    assert "[REDACTED_SECRET]" in redacted
    assert "[REDACTED_PATH]/contracts/Token.sol" in redacted
    assert counts["env_secret"] == 1
    assert counts["github_token"] == 1
    assert counts["aws_access_key"] == 1
    assert counts["json_secret"] == 1
    assert counts["absolute_path"] == 1


def test_cli_ai_triage_payload_includes_only_redacted_snippet_when_requested() -> None:
    secret_hex = "0x" + "c" * 64
    proc = run_cli(
        "ai-triage-payload",
        "--check",
        "reentrancy-eth",
        "--file",
        "/Users/example/private/contracts/Vault.sol",
        "--start-line",
        "42",
        "--severity",
        "high",
        "--confidence",
        "medium",
        "--description",
        "Vault withdraw sends before state update.",
        "--snippet",
        f"PRIVATE_KEY={secret_hex}\n// /Users/example/private/contracts/Vault.sol\ncall.value(amount)();",
        "--include-redacted-snippet",
        "--format",
        "json",
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    encoded = json.dumps(payload)
    assert payload["status"] == "redacted_advisory_payload"
    assert payload["external_ai_call_made"] is False
    assert payload["send_private_snippets"] is False
    assert payload["snippet"]["included"] is True
    assert secret_hex not in encoded
    assert "/Users/example/private" not in encoded
    assert "call.value(amount)();" in payload["snippet"]["redacted_text"]
    assert "[REDACTED_SECRET]" in payload["snippet"]["redacted_text"]
    assert payload["redaction_summary"]["env_secret"] == 1
    assert payload["redaction_summary"]["absolute_path"] >= 1


def test_ai_triage_markdown_keeps_advisory_boundary() -> None:
    payload = ai_triage_payload(
        check="unchecked-transfer",
        file="contracts/Token.sol",
        start_line=7,
        severity="medium",
        confidence="high",
        description="Unchecked transfer return value.",
    )
    markdown = render_ai_triage_markdown(payload)
    assert "# Contract Guard CI Optional AI Triage Payload" in markdown
    assert "No external AI call was made" in markdown
    assert "Private snippets are not sent" in markdown
    assert "Deterministic evidence stays separate" in markdown
    assert "Send private snippets: `false`" in markdown


def test_ai_triage_explanation_is_local_advisory_and_separate() -> None:
    payload = ai_triage_payload(
        check="reentrancy-eth",
        file="contracts/Vault.sol",
        start_line=42,
        severity="high",
        confidence="medium",
        description="Vault withdraw sends ETH before state update.",
    )
    explanation = ai_triage_explanation(payload)
    encoded = json.dumps(explanation).lower()
    assert explanation["schema"] == "contract_guard_ai_triage_explanation/v1"
    assert explanation["status"] == "local_advisory_explanation"
    assert explanation["external_ai_call_made"] is False
    assert explanation["provider"] == "none"
    assert explanation["send_private_snippets"] is False
    assert explanation["advisory_only"] is True
    assert set(explanation) >= {"deterministic_evidence", "advisory_explanation"}
    assert explanation["deterministic_evidence"]["check"] == "reentrancy-eth"
    assert "review immediately before merge" in explanation["advisory_explanation"]["review_priority"]
    assert "complete audit" not in encoded
    assert "proved safe" not in encoded
    assert "guarantee of safety" not in encoded


def test_cli_ai_triage_explain_markdown_keeps_boundaries() -> None:
    secret_hex = "0x" + "d" * 64
    proc = run_cli(
        "ai-triage-explain",
        "--check",
        "unchecked-transfer",
        "--file",
        "/Users/example/private/contracts/Token.sol",
        "--start-line",
        "7",
        "--severity",
        "medium",
        "--confidence",
        "high",
        "--description",
        "Unchecked transfer return value.",
        "--snippet",
        f"TOKEN={secret_hex} at /Users/example/private/contracts/Token.sol",
        "--include-redacted-snippet",
        "--format",
        "markdown",
    )
    assert proc.returncode == 0, proc.stderr
    assert "# Contract Guard CI Advisory Triage Explanation" in proc.stdout
    assert "No external AI call was made" in proc.stdout
    assert "## Deterministic evidence" in proc.stdout
    assert "## Advisory explanation" in proc.stdout
    assert "## Non-claims" in proc.stdout
    assert "Send private snippets: `false`" in proc.stdout
    assert secret_hex not in proc.stdout
    assert "/Users/example/private" not in proc.stdout


def test_ai_triage_explanation_markdown_has_non_claims() -> None:
    explanation = ai_triage_explanation(
        ai_triage_payload(
            check="unchecked-transfer",
            file="contracts/Token.sol",
            start_line=7,
            severity="medium",
            confidence="high",
            description="Unchecked transfer return value.",
        )
    )
    markdown = render_ai_triage_explanation_markdown(explanation)
    assert "This advisory text is separate from deterministic evidence" in markdown
    assert "This explanation does not prove the contract is safe." in markdown
    assert "This explanation is not an audit finding by itself." in markdown
    assert "This explanation must not suppress deterministic tool evidence." in markdown


def test_ai_triage_config_default_keeps_local_runner_boundary() -> None:
    config = ai_triage_config()
    assert config["schema"] == "contract_guard_ai_triage_config/v1"
    assert config["status"] == "local_only_default"
    assert config["external_ai_call_made"] is False
    assert config["external_provider_enabled"] is False
    assert config["provider_payload_allowed"] is False
    assert config["private_code_leaves_local_runner"] is False
    assert config["send_private_snippets"] is False
    assert config["hosted_uploads_enabled"] is False
    assert config["diagnostics"] == []


def test_ai_triage_config_blocks_provider_without_required_opt_ins() -> None:
    config = ai_triage_config(provider="openai", enable_external_provider=False, include_redacted_snippets=False)
    assert config["ok"] is False
    assert config["status"] == "needs_attention"
    assert config["provider_payload_allowed"] is False
    assert "external_provider_requires_explicit_opt_in" in config["diagnostics"]
    config = ai_triage_config(provider="openai", enable_external_provider=True, include_redacted_snippets=False)
    assert config["ok"] is False
    assert config["provider_payload_allowed"] is False
    assert "external_provider_requires_redacted_snippet_opt_in" in config["diagnostics"]


def test_cli_ai_triage_config_ready_still_sends_no_private_code() -> None:
    proc = run_cli(
        "ai-triage-config",
        "--provider",
        "openai",
        "--enable-external-provider",
        "--include-redacted-snippets",
        "--format",
        "json",
    )
    assert proc.returncode == 0, proc.stderr
    config = json.loads(proc.stdout)
    assert config["status"] == "external_provider_opt_in_ready"
    assert config["provider_payload_allowed"] is True
    assert config["external_ai_call_made"] is False
    assert config["private_code_leaves_local_runner"] is False
    assert config["send_private_snippets"] is False
    assert config["hosted_uploads_enabled"] is False
    assert config["requires_explicit_external_provider_opt_in"] is True
    assert config["requires_redacted_snippet_opt_in"] is True


def test_ai_triage_config_blocks_private_snippets_and_hosted_uploads() -> None:
    config = ai_triage_config(
        provider="openai",
        enable_external_provider=True,
        include_redacted_snippets=True,
        allow_private_snippets=True,
        allow_hosted_uploads=True,
    )
    assert config["ok"] is False
    assert config["provider_payload_allowed"] is False
    assert config["send_private_snippets"] is False
    assert config["hosted_uploads_enabled"] is False
    assert "private_snippets_not_allowed" in config["diagnostics"]
    assert "hosted_uploads_not_allowed" in config["diagnostics"]


def test_ai_triage_config_markdown_states_no_private_code_leaves() -> None:
    markdown = render_ai_triage_config_markdown(ai_triage_config())
    assert "# Contract Guard CI AI Triage Configuration Boundary" in markdown
    assert "Private code leaves local runner: `false`" in markdown
    assert "Send private snippets: `false`" in markdown
    assert "Hosted uploads enabled: `false`" in markdown
    assert "future provider payload is allowed only after explicit provider opt-in" in markdown


def test_combined_ai_triage_report_keeps_sections_separate() -> None:
    explanation = ai_triage_explanation(
        ai_triage_payload(
            check="reentrancy-eth",
            file="contracts/Vault.sol",
            start_line=42,
            severity="high",
            confidence="medium",
            description="Vault withdraw sends before state update.",
        )
    )
    report = combined_ai_triage_report(explanation)
    assert report["schema"] == "contract_guard_ai_triage_combined_report/v1"
    assert report["status"] == "separate_deterministic_and_advisory_sections"
    assert report["section_order"] == ["deterministic_evidence", "advisory_ai_text"]
    assert report["deterministic_evidence_source_of_truth"] is True
    assert report["advisory_ai_text_is_non_gating"] is True
    assert report["ai_text_can_suppress_findings"] is False
    assert report["deterministic_evidence"]["check"] == "reentrancy-eth"
    assert "non_claims" in report["advisory_ai_text"]
    assert report["privacy_boundary"] == {
        "send_private_snippets": False,
        "private_code_leaves_local_runner": False,
        "hosted_uploads_enabled": False,
    }


def test_combined_ai_triage_markdown_orders_evidence_before_ai_text() -> None:
    report = combined_ai_triage_report(
        ai_triage_explanation(
            ai_triage_payload(
                check="unchecked-transfer",
                file="contracts/Token.sol",
                start_line=7,
                severity="medium",
                confidence="high",
                description="Unchecked transfer return value.",
            )
        )
    )
    markdown = render_combined_ai_triage_markdown(report)
    evidence_index = markdown.index("## Deterministic evidence (source of truth)")
    advisory_index = markdown.index("## Advisory AI text (separate, non-gating)")
    assert evidence_index < advisory_index
    assert "Deterministic analyzer evidence is the source of truth" in markdown
    assert "AI text is separate, non-gating, and cannot suppress findings" in markdown
    assert "This explanation does not prove the contract is safe." in markdown
    assert "Send private snippets: `false`" in markdown


def test_cli_ai_triage_combined_redacts_and_separates_sections() -> None:
    secret_hex = "0x" + "e" * 64
    proc = run_cli(
        "ai-triage-combined",
        "--check",
        "reentrancy-eth",
        "--file",
        "/Users/example/private/contracts/Vault.sol",
        "--start-line",
        "42",
        "--severity",
        "high",
        "--confidence",
        "medium",
        "--description",
        "Vault withdraw sends before state update.",
        "--snippet",
        f"PRIVATE_KEY={secret_hex} at /Users/example/private/contracts/Vault.sol",
        "--include-redacted-snippet",
        "--format",
        "markdown",
    )
    assert proc.returncode == 0, proc.stderr
    assert "## Deterministic evidence (source of truth)" in proc.stdout
    assert "## Advisory AI text (separate, non-gating)" in proc.stdout
    assert proc.stdout.index("## Deterministic evidence (source of truth)") < proc.stdout.index("## Advisory AI text (separate, non-gating)")
    assert "Private code leaves local runner: `false`" in proc.stdout
    assert secret_hex not in proc.stdout
    assert "/Users/example/private" not in proc.stdout


def test_github_action_preserves_reports_and_uploads_sarif() -> None:
    workflow = (ROOT / ".github" / "workflows" / "contract-guard-ci.yml").read_text(encoding="utf-8")
    assert "fetch-depth: 0" in workflow
    assert "contract-guard scan \"${scan_args[@]}\" --format json > contract-guard-reports/scan.json" in workflow
    assert "contract-guard scan \"${scan_args[@]}\" --fail-on-severity none --format markdown > contract-guard-reports/scan.md" in workflow
    assert "contract-guard scan \"${scan_args[@]}\" --fail-on-severity none --format sarif > contract-guard-reports/scan.sarif" in workflow
    assert "github/codeql-action/upload-sarif@v3" in workflow
    assert "sarif_file: contract-guard-reports/scan.sarif" in workflow
    assert "actions/upload-artifact@v4" in workflow
    assert ".contract-guard-baseline.json" in workflow


def test_dogfood_readiness_verifier_runs_local_fixture_bundle() -> None:
    with TemporaryDirectory() as tmp:
        output_dir = Path(tmp) / "dogfood"
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        proc = subprocess.run(
            [
                sys.executable,
                "scripts/contract_guard_dogfood_readiness.py",
                "--output-dir",
                str(output_dir),
                "--format",
                "json",
            ],
            cwd=str(ROOT),
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)

    assert payload["schema"] == "contract_guard_dogfood_readiness/v1"
    assert payload["schema_version"] == "1"
    assert payload["status"] == "passed"
    assert payload["ok"] is True
    assert {command["name"] for command in payload["commands"]} == {
        "plan",
        "policy",
        "scan-json",
        "scan-markdown",
        "scan-sarif",
    }
    assert all(command["ok"] for command in payload["commands"])
    assert all(check["ok"] for check in payload["checks"])
    check_names = {check["name"] for check in payload["checks"]}
    assert {
        "output_files_stay_under_output_dir",
        "no_stderr_artifacts",
        "sarif_marks_deterministic_no_ai",
        "markdown_keeps_deterministic_evidence_separate",
        "markdown_omits_raw_stdout_stderr_sections",
    } <= check_names
    assert payload["safety"] == {
        "external_services_used": False,
        "hosted_uploads_enabled": False,
        "private_snippets_sent": False,
        "live_ai_provider_called": False,
        "payment_or_custody_scope": False,
        "audit_completeness_claimed": False,
    }


def test_cli_dogfood_readiness_matches_local_safety_boundary() -> None:
    with TemporaryDirectory() as tmp:
        proc = run_cli("dogfood-readiness", "--output-dir", str(Path(tmp) / "dogfood"), "--format", "json")
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)

    assert payload["schema"] == "contract_guard_dogfood_readiness/v1"
    assert payload["status"] == "passed"
    assert all(command["ok"] for command in payload["commands"])
    assert all(check["ok"] for check in payload["checks"])
    assert payload["safety"]["external_services_used"] is False
    assert payload["safety"]["hosted_uploads_enabled"] is False
    assert payload["safety"]["private_snippets_sent"] is False
    assert payload["safety"]["live_ai_provider_called"] is False


def test_cli_dogfood_readiness_runs_defi_vault_fixture() -> None:
    with TemporaryDirectory() as tmp:
        output_dir = Path(tmp) / "dogfood-vault"
        proc = run_cli(
            "dogfood-readiness",
            "--fixture-repo",
            "examples/foundry-defi-vault",
            "--output-dir",
            str(output_dir),
            "--format",
            "json",
        )
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        plan = json.loads((output_dir / "plan.json").read_text(encoding="utf-8"))

    assert payload["fixture_repo"] == "examples/foundry-defi-vault"
    assert payload["status"] == "passed"
    assert all(command["ok"] for command in payload["commands"])
    assert all(check["ok"] for check in payload["checks"])
    assert plan["summary"]["foundry_project"] is True
    assert plan["summary"]["solidity_files"] == 2


if __name__ == "__main__":
    test_plan_json_for_empty_repo()
    test_scan_can_skip_external_tools()
    test_scan_result_command_schema_is_stable()
    test_plan_detects_solidity_fixture()
    test_diff_scope_filters_changed_solidity_files()
    test_cli_changed_only_reports_diff_scope()
    test_diff_filter_keeps_only_changed_slither_findings()
    test_baseline_suppresses_non_high_but_never_high()
    test_load_baseline_keeps_report_path_relative()
    test_cli_baseline_file_reports_loaded_suppressions()
    test_failure_policy_fails_on_active_high_finding()
    test_failure_policy_respects_severity_and_confidence_thresholds()
    test_failure_policy_runs_after_baseline_suppression()
    test_cli_failure_policy_defaults_do_not_fail_empty_scan()
    test_foundry_normalizes_passing_output()
    test_foundry_normalizes_failing_output()
    test_foundry_normalizes_timeout()
    test_slither_normalizes_detector_json()
    test_slither_avoids_absolute_path_when_only_absolute_filename_exists()
    test_slither_invalid_json_is_diagnostic_not_exception()
    test_aderyn_normalizes_json_findings_without_snippets_or_absolute_paths()
    test_aderyn_invalid_payload_is_diagnostic_not_exception()
    test_scan_does_not_include_aderyn_without_explicit_opt_in()
    test_cli_include_aderyn_runs_fake_tool_without_raw_banner_paths()
    test_aderyn_can_participate_in_sarif_when_explicitly_included()
    test_markdown_report_renders_stable_deterministic_evidence()
    test_cli_markdown_includes_deterministic_boundary()
    test_sarif_report_renders_slither_findings_for_code_scanning()
    test_cli_sarif_empty_scan_is_valid_json()
    test_invariant_payload_all_profiles_is_advisory()
    test_cli_invariants_json_uses_contract_name_without_repo_arg()
    test_invariant_markdown_keeps_templates_advisory()
    test_fuzz_hooks_payload_all_tools_is_scaffold_only()
    test_cli_fuzz_hooks_json_generates_echidna_command()
    test_fuzz_hooks_markdown_keeps_execution_boundary()
    test_false_positive_review_blocks_high_severity_suppression()
    test_cli_false_positive_json_generates_non_high_baseline_candidate()
    test_false_positive_markdown_keeps_audit_trail_boundary()
    test_policy_loads_defaults_when_no_policy_file_exists()
    test_cli_policy_validates_example_policy_file()
    test_policy_rejects_ai_private_upload_and_raw_output_defaults()
    test_policy_markdown_states_local_deterministic_boundary()
    test_ai_triage_payload_drops_snippet_by_default()
    test_redact_text_removes_common_secret_patterns_and_paths()
    test_cli_ai_triage_payload_includes_only_redacted_snippet_when_requested()
    test_ai_triage_markdown_keeps_advisory_boundary()
    test_ai_triage_explanation_is_local_advisory_and_separate()
    test_cli_ai_triage_explain_markdown_keeps_boundaries()
    test_ai_triage_explanation_markdown_has_non_claims()
    test_ai_triage_config_default_keeps_local_runner_boundary()
    test_ai_triage_config_blocks_provider_without_required_opt_ins()
    test_cli_ai_triage_config_ready_still_sends_no_private_code()
    test_ai_triage_config_blocks_private_snippets_and_hosted_uploads()
    test_ai_triage_config_markdown_states_no_private_code_leaves()
    test_combined_ai_triage_report_keeps_sections_separate()
    test_combined_ai_triage_markdown_orders_evidence_before_ai_text()
    test_cli_ai_triage_combined_redacts_and_separates_sections()
    test_github_action_preserves_reports_and_uploads_sarif()
    test_dogfood_readiness_verifier_runs_local_fixture_bundle()
    test_cli_dogfood_readiness_matches_local_safety_boundary()
    test_cli_dogfood_readiness_runs_defi_vault_fixture()
