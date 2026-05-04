// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Tiny dependency-free fixture contract for Contract Guard CI beta docs.
/// @dev This is not a production protocol and does not custody funds.
contract GuardedCounter {
    error NotOwner();
    error Paused();

    address public immutable owner;
    bool public paused;
    uint256 public value;

    constructor(address initialOwner) {
        owner = initialOwner;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    function setPaused(bool nextPaused) external onlyOwner {
        paused = nextPaused;
    }

    function increment() external onlyOwner {
        if (paused) revert Paused();
        value += 1;
    }
}
