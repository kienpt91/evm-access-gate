// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice TEST ONLY. Minimal ERC-1271 wallet: a signature is valid if the owner signed the hash.
/// @dev Real smart-contract wallets (Safe, account-abstraction wallets) apply their own wrapping
///      or policy. This mock only exists to exercise the ERC-1271 branch of the login check.
///      It accepts 65-byte `r || s || v` signatures and does not reject malleable `s` values.
contract Erc1271Wallet {
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant INVALID_VALUE = 0xffffffff;

    address public immutable owner;

    constructor(address owner_) {
        owner = owner_;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        if (signature.length != 65) return INVALID_VALUE;
        bytes32 r = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);
        uint8 v = uint8(signature[64]);
        address recovered = ecrecover(hash, v, r, s);
        if (recovered != address(0) && recovered == owner) return MAGIC_VALUE;
        return INVALID_VALUE;
    }
}
