// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessRegistry} from "../AccessRegistry.sol";

/// @notice TEST ONLY. Never deploy. A contract that tries to misuse the ETH it receives.
/// @dev Used as the buyer (refund path) and as the treasury (withdraw path) in the tests.
contract ReentrantBuyer {
    enum Mode {
        Accept, // take the ETH and do nothing
        Reject, // revert on receive
        ReenterPurchase, // call `purchase` again from `receive`, bubble up a failure
        ReenterPurchaseSwallow // call `purchase` again from `receive`, swallow a failure
    }

    AccessRegistry public immutable registry;
    uint256 public immutable targetPlan;

    Mode public mode;
    uint256 public receiveCalls;
    bool public reenterSucceeded;
    bytes4 public reenterErrorSelector;

    error ReenterFailed(bytes4 selector);
    error Rejected();

    constructor(AccessRegistry registry_, uint256 targetPlan_) {
        registry = registry_;
        targetPlan = targetPlan_;
    }

    function setMode(Mode mode_) external {
        mode = mode_;
    }

    function buy(uint256 planId, uint256 maxPrice) external payable {
        registry.purchase{value: msg.value}(planId, maxPrice);
    }

    receive() external payable {
        receiveCalls += 1;
        Mode current = mode;
        if (current == Mode.Reject) revert Rejected();
        if (current == Mode.Accept || receiveCalls > 1) return;

        // Re-enter with whatever was just received.
        (bool ok, bytes memory data) = address(registry).call{value: msg.value}(
            abi.encodeCall(AccessRegistry.purchase, (targetPlan, msg.value))
        );
        reenterSucceeded = ok;
        if (!ok) {
            bytes4 selector = data.length >= 4 ? bytes4(data) : bytes4(0);
            reenterErrorSelector = selector;
            if (current == Mode.ReenterPurchase) revert ReenterFailed(selector);
        }
    }
}
