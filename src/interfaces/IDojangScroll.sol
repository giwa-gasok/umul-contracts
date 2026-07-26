// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Minimal DojangScroll interface used by Gasok.
/// @dev The upstream `DojangAttesterId` is a bytes32 user-defined value type, so
///      its external ABI is `bytes32`.
interface IDojangScroll {
    function isVerified(address addr, bytes32 attesterId) external view returns (bool);
}
