// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/GuardedCounter.sol";

/// @notice Dependency-free Foundry invariant harness for packaging smoke.
/// @dev Uses Solidity's built-in assert and avoids forge-std downloads.
contract GuardedCounterInvariant {
    GuardedCounter internal counter;

    constructor() {
        counter = new GuardedCounter(address(this));
    }

    function setPaused(bool paused) public {
        counter.setPaused(paused);
    }

    function incrementWhenOpen() public {
        if (!counter.paused()) {
            counter.increment();
        }
    }

    function invariant_ownerRemainsHarness() public view {
        assert(counter.owner() == address(this));
    }
}
