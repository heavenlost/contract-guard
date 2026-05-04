from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

SCHEMA = "contract_guard_dogfood_readiness/v1"
SCHEMA_VERSION = "1"
DEFAULT_OUTPUT_DIR = Path("/tmp/contract-guard-dogfood-readiness")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def cli_env(root: Path) -> dict[str, str]:
    env = os.environ.copy()
    src = str(root / "src")
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = src if not existing else f"{src}{os.pathsep}{existing}"
    return env


def run_cli(root: Path, output_dir: Path, name: str, output_file: str, args: list[str]) -> dict[str, Any]:
    command = [sys.executable, "-m", "contract_guard_ci.cli", *args]
    proc = subprocess.run(
        command,
        cwd=str(root),
        env=cli_env(root),
        text=True,
        capture_output=True,
        check=False,
    )
    stdout_path = output_dir / output_file
    stdout_path.write_text(proc.stdout, encoding="utf-8")
    stderr_path: Path | None = None
    if proc.stderr:
        stderr_path = output_dir / f"{output_file}.stderr"
        stderr_path.write_text(proc.stderr, encoding="utf-8")
    return {
        "name": name,
        "command": command[1:],
        "exit_code": proc.returncode,
        "ok": proc.returncode == 0,
        "stdout_file": str(stdout_path),
        "stderr_file": str(stderr_path) if stderr_path else None,
    }


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def build_checks(output_dir: Path, commands: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    resolved_output_dir = output_dir.resolve()

    checks.append({
        "name": "output_files_stay_under_output_dir",
        "ok": all(Path(command["stdout_file"]).resolve().is_relative_to(resolved_output_dir) for command in commands),
    })
    checks.append({
        "name": "no_stderr_artifacts",
        "ok": all(command["stderr_file"] is None for command in commands),
    })

    plan = load_json(output_dir / "plan.json")
    checks.append({
        "name": "plan_schema",
        "ok": plan.get("schema") == "contract_guard_plan/v1" and plan.get("schema_version") == "1",
    })
    checks.append({
        "name": "fixture_foundry_layout_detected",
        "ok": plan.get("summary", {}).get("foundry_project") is True and plan.get("summary", {}).get("solidity_files", 0) >= 1,
    })

    scan = load_json(output_dir / "scan.json")
    checks.append({
        "name": "scan_schema_and_status",
        "ok": scan.get("schema") == "contract_guard_scan/v1" and scan.get("schema_version") == "1" and scan.get("status") == "passed",
    })
    checks.append({
        "name": "scan_explicitly_skipped_external_tools",
        "ok": scan.get("summary") == {"checks": 2, "passed": 0, "failed": 0, "skipped": 2},
    })

    sarif = load_json(output_dir / "scan.sarif")
    checks.append({
        "name": "sarif_version",
        "ok": sarif.get("version") == "2.1.0" and bool(sarif.get("runs")),
    })
    sarif_properties = sarif.get("runs", [{}])[0].get("properties", {})
    checks.append({
        "name": "sarif_marks_deterministic_no_ai",
        "ok": sarif_properties.get("deterministic_evidence_only") is True and sarif_properties.get("ai_triage_included") is False,
    })

    policy_md = (output_dir / "policy.md").read_text(encoding="utf-8")
    checks.append({
        "name": "policy_safety_defaults_rendered",
        "ok": all(
            marker in policy_md
            for marker in [
                "AI triage enabled: `false`",
                "Send private snippets: `false`",
                "Hosted uploads enabled: `false`",
                "Include raw stdout/stderr: `false`",
            ]
        ),
    })

    scan_md = (output_dir / "scan.md").read_text(encoding="utf-8")
    checks.append({
        "name": "markdown_keeps_deterministic_evidence_separate",
        "ok": "Deterministic tool evidence" in scan_md and "Optional AI triage is not included" in scan_md,
    })
    checks.append({
        "name": "markdown_omits_raw_stdout_stderr_sections",
        "ok": "## Raw stdout" not in scan_md and "## Raw stderr" not in scan_md,
    })

    return checks


def render_dogfood_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Contract Guard dogfood readiness",
        "",
        f"Status: `{'passed' if payload['ok'] else 'failed'}`",
        f"Fixture repo: `{payload['fixture_repo']}`",
        f"Output dir: `{payload['output_dir']}`",
        "",
        "## Safety boundaries",
        "",
    ]
    for key, value in payload["safety"].items():
        lines.append(f"- {key}: `{str(value).lower()}`")
    lines.extend(["", "## Commands", ""])
    for command in payload["commands"]:
        lines.append(f"- `{command['name']}`: {'PASS' if command['ok'] else 'FAIL'} -> `{command['stdout_file']}`")
    lines.extend(["", "## Checks", ""])
    for check in payload["checks"]:
        lines.append(f"- `{check['name']}`: {'PASS' if check['ok'] else 'FAIL'}")
    return "\n".join(lines) + "\n"


def build_payload(fixture_repo: str, output_dir: Path, project_root: Path | None = None) -> dict[str, Any]:
    root = (project_root or repo_root()).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    commands = [
        run_cli(root, output_dir, "plan", "plan.json", ["plan", "--repo", fixture_repo, "--json"]),
        run_cli(root, output_dir, "policy", "policy.md", ["policy", "--repo", fixture_repo, "--policy-file", ".contract-guard-policy.json", "--format", "markdown"]),
        run_cli(root, output_dir, "scan-json", "scan.json", ["scan", "--repo", fixture_repo, "--skip-foundry", "--skip-slither", "--baseline-file", ".contract-guard-baseline.json", "--format", "json"]),
        run_cli(root, output_dir, "scan-markdown", "scan.md", ["scan", "--repo", fixture_repo, "--skip-foundry", "--skip-slither", "--baseline-file", ".contract-guard-baseline.json", "--format", "markdown"]),
        run_cli(root, output_dir, "scan-sarif", "scan.sarif", ["scan", "--repo", fixture_repo, "--skip-foundry", "--skip-slither", "--baseline-file", ".contract-guard-baseline.json", "--format", "sarif"]),
    ]
    command_ok = all(command["ok"] for command in commands)
    checks = build_checks(output_dir, commands) if command_ok else []
    ok = command_ok and all(check["ok"] for check in checks)
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "ok": ok,
        "status": "passed" if ok else "failed",
        "repo_root": str(root),
        "fixture_repo": fixture_repo,
        "output_dir": str(output_dir),
        "commands": commands,
        "checks": checks,
        "safety": {
            "external_services_used": False,
            "hosted_uploads_enabled": False,
            "private_snippets_sent": False,
            "live_ai_provider_called": False,
            "payment_or_custody_scope": False,
            "audit_completeness_claimed": False,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the local Contract Guard CI dogfood readiness fixture bundle")
    parser.add_argument("--project-root", default=None, help="Contract Guard CI checkout root; defaults to the installed source checkout")
    parser.add_argument("--fixture-repo", default="examples/foundry-basic", help="Repo path to exercise, relative to this checkout by default")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Directory for local JSON/Markdown/SARIF outputs")
    parser.add_argument("--format", choices=["json", "markdown"], default="json")
    args = parser.parse_args(argv)

    payload = build_payload(args.fixture_repo, Path(args.output_dir), Path(args.project_root) if args.project_root else None)
    if args.format == "markdown":
        print(render_dogfood_markdown(payload), end="")
    else:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
