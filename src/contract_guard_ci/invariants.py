from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any


INVARIANT_SCHEMA = "contract_guard_invariant_templates/v1"
INVARIANT_SCHEMA_VERSION = "1"
INVARIANT_DISCLAIMER = (
    "Deterministic invariant templates are advisory starting points for Foundry tests. "
    "They are not proofs, audits, or guarantees of smart-contract safety."
)


@dataclass(frozen=True)
class InvariantTemplate:
    id: str
    profile: str
    title: str
    rationale: str
    foundry_snippet: str
    required_customization: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def invariant_payload(profile: str = "all", contract_name: str = "Protocol", test_contract_name: str | None = None) -> dict[str, Any]:
    selected = invariant_templates(profile=profile, contract_name=contract_name, test_contract_name=test_contract_name)
    return {
        "schema": INVARIANT_SCHEMA,
        "schema_version": INVARIANT_SCHEMA_VERSION,
        "ok": True,
        "status": "advisory_templates",
        "profile": profile,
        "contract": contract_name,
        "disclaimer": INVARIANT_DISCLAIMER,
        "templates": [template.to_dict() for template in selected],
    }


def invariant_templates(profile: str = "all", contract_name: str = "Protocol", test_contract_name: str | None = None) -> list[InvariantTemplate]:
    normalized = profile.strip().lower().replace("_", "-")
    test_name = test_contract_name or f"{contract_name}InvariantTest"
    catalog = {
        "erc20": _erc20_templates(contract_name, test_name),
        "vault": _vault_templates(contract_name, test_name),
        "access-control": _access_control_templates(contract_name, test_name),
    }
    if normalized == "all":
        return [template for templates in catalog.values() for template in templates]
    return catalog.get(normalized, [])


def render_invariant_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Contract Guard CI Invariant Templates",
        "",
        f"Profile: `{payload['profile']}`",
        f"Target contract: `{payload['contract']}`",
        "",
        f"> {payload['disclaimer']}",
        "",
    ]
    for template in payload["templates"]:
        lines.extend(
            [
                f"## {template['title']}",
                "",
                f"- ID: `{template['id']}`",
                f"- Profile: `{template['profile']}`",
                f"- Rationale: {template['rationale']}",
                "- Required customization:",
            ]
        )
        lines.extend(f"  - {item}" for item in template["required_customization"])
        lines.extend(["", "```solidity", template["foundry_snippet"].rstrip(), "```", ""])
    return "\n".join(lines)


def dumps_invariant_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


def _erc20_templates(contract_name: str, test_name: str) -> list[InvariantTemplate]:
    return [
        InvariantTemplate(
            id="erc20-total-supply-accounting",
            profile="erc20",
            title="ERC20 total supply equals tracked balances",
            rationale="Token supply drift is a common accounting bug; track a bounded holder set and compare it against totalSupply.",
            foundry_snippet=f"""contract {test_name} is Test {{
    {contract_name} internal token;
    address[] internal holders;

    function invariant_totalSupplyEqualsTrackedBalances() public view {{
        uint256 tracked;
        for (uint256 i = 0; i < holders.length; i++) {{
            tracked += token.balanceOf(holders[i]);
        }}
        assertEq(token.totalSupply(), tracked, "totalSupply must equal tracked balances");
    }}
}}""",
            required_customization=[
                "Initialize token and holder set in setUp().",
                "Ensure the holder set includes every address that can receive minted/transferred tokens during invariant runs.",
                "Use a handler contract when the holder set must be updated after transfers.",
            ],
        ),
        InvariantTemplate(
            id="erc20-no-negative-effective-balance",
            profile="erc20",
            title="ERC20 balances never exceed total supply",
            rationale="No individual account should hold more tokens than the entire supply.",
            foundry_snippet=f"""contract {test_name} is Test {{
    {contract_name} internal token;
    address[] internal holders;

    function invariant_noBalanceExceedsTotalSupply() public view {{
        uint256 supply = token.totalSupply();
        for (uint256 i = 0; i < holders.length; i++) {{
            assertLe(token.balanceOf(holders[i]), supply, "balance exceeds totalSupply");
        }}
    }}
}}""",
            required_customization=[
                "Initialize representative holders in setUp().",
                "Add protocol-specific escrow, vault, and fee-recipient addresses to holders.",
            ],
        ),
    ]


def _vault_templates(contract_name: str, test_name: str) -> list[InvariantTemplate]:
    return [
        InvariantTemplate(
            id="vault-assets-cover-shares",
            profile="vault",
            title="Vault assets cover outstanding shares",
            rationale="Share/accounting drift is a common vault failure mode; assets should cover the redeemable share model.",
            foundry_snippet=f"""contract {test_name} is Test {{
    {contract_name} internal vault;

    function invariant_assetsCoverShares() public view {{
        uint256 shares = vault.totalSupply();
        uint256 assets = vault.totalAssets();
        assertGe(assets, vault.convertToAssets(shares), "assets must cover outstanding shares");
    }}
}}""",
            required_customization=[
                "Confirm the vault implements ERC4626-style totalAssets/convertToAssets semantics.",
                "Adjust the inequality for expected fees, locked profit, or withdrawal penalties.",
                "Use a handler for deposits, withdrawals, donations, and yield updates.",
            ],
        ),
        InvariantTemplate(
            id="vault-preview-redeem-monotonic",
            profile="vault",
            title="Vault preview redeem is monotonic",
            rationale="A larger share amount should not preview fewer assets than a smaller share amount under the same state.",
            foundry_snippet=f"""contract {test_name} is Test {{
    {contract_name} internal vault;

    function invariant_previewRedeemMonotonic(uint128 small, uint128 large) public view {{
        vm.assume(uint256(small) <= uint256(large));
        assertLe(vault.previewRedeem(small), vault.previewRedeem(large), "previewRedeem must be monotonic");
    }}
}}""",
            required_customization=[
                "Bound inputs to realistic share amounts if the vault reverts above totalSupply.",
                "Adjust for vaults with non-standard rounding or fee logic.",
            ],
        ),
    ]


def _access_control_templates(contract_name: str, test_name: str) -> list[InvariantTemplate]:
    return [
        InvariantTemplate(
            id="access-control-owner-not-zero",
            profile="access-control",
            title="Privileged owner is never accidentally zero",
            rationale="Unexpected owner/admin loss can permanently disable emergency operations or upgrades.",
            foundry_snippet=f"""contract {test_name} is Test {{
    {contract_name} internal target;

    function invariant_ownerIsNotZero() public view {{
        assertTrue(target.owner() != address(0), "owner must not be zero");
    }}
}}""",
            required_customization=[
                "Use only for contracts where zero owner is not an intentional renounce state.",
                "Replace owner() with the relevant admin/role getter for AccessControl-style contracts.",
            ],
        ),
        InvariantTemplate(
            id="access-control-paused-blocks-sensitive-actions",
            profile="access-control",
            title="Paused state blocks sensitive actions",
            rationale="Emergency pause controls should reliably block value-moving or state-mutating sensitive paths.",
            foundry_snippet=f"""contract {test_name} is Test {{
    {contract_name} internal target;

    function invariant_pausedBlocksSensitiveActions() public {{
        if (target.paused()) {{
            vm.expectRevert();
            target.sensitiveAction();
        }}
    }}
}}""",
            required_customization=[
                "Replace sensitiveAction() with the protocol's actual value-moving entry points.",
                "Ensure the handler can enter paused and unpaused states.",
                "Remove this template if the protocol intentionally allows the action while paused.",
            ],
        ),
    ]
