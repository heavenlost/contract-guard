from __future__ import annotations

import json
import shlex
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from typing import Any


FUZZ_HOOK_SCHEMA = "contract_guard_fuzz_hooks/v1"
FUZZ_HOOK_SCHEMA_VERSION = "1"
FUZZ_HOOK_DISCLAIMER = (
    "Deterministic fuzzing hooks are local-runner scaffolds only. "
    "They do not execute external fuzzers by default and are not proofs, audits, or guarantees of smart-contract safety."
)


@dataclass(frozen=True)
class FuzzHook:
    id: str
    tool: str
    title: str
    command: list[str]
    config_path: str
    executes_by_default: bool
    required_setup: list[str]
    artifacts: list[str]
    notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def fuzz_hooks_payload(
    tool: str = "all",
    target: str = "test/invariants/InvariantTest.sol",
    contract_name: str = "InvariantTest",
    echidna_config: str = "echidna.yaml",
    medusa_config: str = "medusa.json",
) -> dict[str, Any]:
    normalized_tool = _normalize_tool(tool)
    safe_target = _safe_report_path(target)
    safe_contract = _safe_identifier(contract_name, fallback="InvariantTest")
    hooks = fuzz_hooks(
        tool=normalized_tool,
        target=safe_target,
        contract_name=safe_contract,
        echidna_config=_safe_report_path(echidna_config),
        medusa_config=_safe_report_path(medusa_config),
    )
    return {
        "schema": FUZZ_HOOK_SCHEMA,
        "schema_version": FUZZ_HOOK_SCHEMA_VERSION,
        "ok": True,
        "status": "scaffold_only",
        "tool": normalized_tool,
        "target": safe_target,
        "contract": safe_contract,
        "disclaimer": FUZZ_HOOK_DISCLAIMER,
        "hooks": [hook.to_dict() for hook in hooks],
    }


def fuzz_hooks(
    tool: str = "all",
    target: str = "test/invariants/InvariantTest.sol",
    contract_name: str = "InvariantTest",
    echidna_config: str = "echidna.yaml",
    medusa_config: str = "medusa.json",
) -> list[FuzzHook]:
    catalog = {
        "echidna": _echidna_hook(target=target, contract_name=contract_name, config_path=echidna_config),
        "medusa": _medusa_hook(target=target, contract_name=contract_name, config_path=medusa_config),
    }
    if tool == "all":
        return [catalog["echidna"], catalog["medusa"]]
    return [catalog[tool]]


def render_fuzz_hooks_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Contract Guard CI Fuzzing Hooks",
        "",
        f"Tool: `{payload['tool']}`",
        f"Target: `{payload['target']}`",
        f"Contract: `{payload['contract']}`",
        "",
        f"> {payload['disclaimer']}",
        "",
    ]
    for hook in payload["hooks"]:
        lines.extend(
            [
                f"## {hook['title']}",
                "",
                f"- ID: `{hook['id']}`",
                f"- Tool: `{hook['tool']}`",
                f"- Config: `{hook['config_path']}`",
                f"- Executes by default: `{str(hook['executes_by_default']).lower()}`",
                "",
                "```bash",
                shlex.join(hook["command"]),
                "```",
                "",
                "Required setup:",
            ]
        )
        lines.extend(f"- {item}" for item in hook["required_setup"])
        lines.extend(["", "Expected local artifacts:"])
        lines.extend(f"- `{item}`" for item in hook["artifacts"])
        lines.extend(["", "Notes:"])
        lines.extend(f"- {item}" for item in hook["notes"])
        lines.append("")
    return "\n".join(lines)


def dumps_fuzz_hooks_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


def _echidna_hook(target: str, contract_name: str, config_path: str) -> FuzzHook:
    return FuzzHook(
        id="echidna-foundry-invariant-scaffold",
        tool="echidna",
        title="Echidna Foundry invariant hook scaffold",
        command=["echidna", target, "--contract", contract_name, "--config", config_path],
        config_path=config_path,
        executes_by_default=False,
        required_setup=[
            "Install Echidna on the local or self-hosted CI runner before enabling live execution.",
            "Keep the target invariant contract deterministic and avoid network, fork, or secret-dependent setup by default.",
            "Review the generated command against the pinned Echidna version before making it policy-gating.",
        ],
        artifacts=[
            "contract-guard-reports/echidna.json",
            "contract-guard-reports/echidna.log",
            "corpus/echidna/",
        ],
        notes=[
            "This scaffold only records the intended command shape; Contract Guard does not run Echidna from this generator.",
            "Treat future Echidna failures as deterministic fuzzer evidence, separate from optional AI explanation.",
        ],
    )


def _medusa_hook(target: str, contract_name: str, config_path: str) -> FuzzHook:
    return FuzzHook(
        id="medusa-foundry-invariant-scaffold",
        tool="medusa",
        title="Medusa Foundry fuzz hook scaffold",
        command=["medusa", "fuzz", "--config", config_path],
        config_path=config_path,
        executes_by_default=False,
        required_setup=[
            "Install Medusa on the local or self-hosted CI runner before enabling live execution.",
            f"Configure `{config_path}` to point at `{target}` and target contract `{contract_name}`.",
            "Review the generated command against the pinned Medusa version before making it policy-gating.",
        ],
        artifacts=[
            "contract-guard-reports/medusa.json",
            "contract-guard-reports/medusa.log",
            "corpus/medusa/",
        ],
        notes=[
            "This scaffold only records the intended command shape; Contract Guard does not run Medusa from this generator.",
            "Treat future Medusa failures as deterministic fuzzer evidence, separate from optional AI explanation.",
        ],
    )


def _normalize_tool(tool: str) -> str:
    normalized = str(tool or "all").strip().lower().replace("_", "-")
    if normalized not in {"all", "echidna", "medusa"}:
        raise ValueError(f"unsupported fuzzing tool: {tool}")
    return normalized


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
        for anchor in ("test", "src", "contracts", "script"):
            if anchor in parts:
                return "/".join(parts[parts.index(anchor) :])
        return PurePosixPath(normalized).name
    return normalized
