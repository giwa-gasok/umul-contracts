// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IDojangScroll} from "../../src/interfaces/IDojangScroll.sol";

/// @notice A scroll whose lookups always fail. Used to check that an unreadable
///         Dojang does not stop evidence from being recorded.
contract RevertingDojangScroll is IDojangScroll {
    error ScrollUnavailable();

    function isVerified(address, bytes32) external pure returns (bool) {
        revert ScrollUnavailable();
    }
}
