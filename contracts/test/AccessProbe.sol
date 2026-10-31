// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessRegistry} from "../AccessRegistry.sol";

/// @notice TEST ONLY. Records what `hasAccess` returns inside a mined block, together with that
///         block's timestamp. Lets the tests check exact second boundaries without relying on how
///         `eth_call` picks its block timestamp.
contract AccessProbe {
    uint256 public lastTimestamp;
    bool public lastHasAccess;

    function observe(AccessRegistry registry, address user, uint256 planId) external {
        lastTimestamp = block.timestamp;
        lastHasAccess = registry.hasAccess(user, planId);
    }
}
