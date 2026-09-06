// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice A scroll that returns an arbitrary payload where a `bool` is declared, standing in
///         for an interface that drifted. Deliberately does not implement IDojangScroll: not
///         conforming is the point.
contract RawWordDojangScroll {
    bytes private _response;

    constructor(bytes memory response) {
        _response = response;
    }

    fallback(bytes calldata) external returns (bytes memory) {
        return _response;
    }
}
