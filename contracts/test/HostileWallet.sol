// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice TEST ONLY. A contract that answers ERC-1271 checks the way an attacker would: by using up
///         all the gas it is given, by returning far more data than a `bytes4`, or by reverting.
contract HostileWallet {
    enum Mode {
        BurnGas,
        ReturnLarge,
        Revert
    }

    Mode public immutable mode;

    error Hostile();

    constructor(Mode mode_) {
        mode = mode_;
    }

    /// @dev Declared to return `bytes` so the oversized answer is a well-formed ABI encoding.
    function isValidSignature(bytes32 hash, bytes calldata) external view returns (bytes memory) {
        if (mode == Mode.BurnGas) {
            bytes32 h = hash;
            while (true) {
                h = keccak256(abi.encode(h));
            }
        }
        if (mode == Mode.Revert) revert Hostile();
        return new bytes(4096);
    }
}
