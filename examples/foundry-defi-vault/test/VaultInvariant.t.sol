// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DogfoodAsset, TrainingVault} from "../src/TrainingVault.sol";

/// @notice Plain Solidity invariant harness; no forge-std dependency needed for local dogfood.
contract VaultInvariantHarness {
    DogfoodAsset internal asset;
    TrainingVault internal vault;
    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);

    constructor() {
        asset = new DogfoodAsset();
        vault = new TrainingVault(asset);
        asset.mint(alice, 1_000_000 ether);
        asset.mint(bob, 1_000_000 ether);
    }

    function vaultAddress() external view returns (address) {
        return address(vault);
    }

    function invariant_totalAssetsCoverShares() external view {
        assert(vault.totalAssets() >= vault.totalShares());
    }

    function invariant_ownerIsStable() external view {
        assert(vault.owner() == address(this));
    }

    function invariant_noSharesWhenNoAssets() external view {
        if (vault.totalAssets() == 0) {
            assert(vault.totalShares() == 0);
        }
    }
}
