// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice A scroll that answers with a huge payload. Copying it into the caller's memory
///         costs quadratically, so this is the shape a griefing upgrade would take if the
///         scroll address were a proxy.
contract ReturnBombDojangScroll {
    uint256 private immutable _size;

    constructor(uint256 size) {
        _size = size;
    }

    fallback(bytes calldata) external returns (bytes memory) {
        return new bytes(_size);
    }
}
