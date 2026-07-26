// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IDojangScroll} from "../../src/interfaces/IDojangScroll.sol";

contract MockDojangScroll is IDojangScroll {
    mapping(address participant => mapping(bytes32 attesterId => bool verified)) private _verified;

    function setVerified(address participant, bytes32 dojangAttesterId, bool verified) external {
        _verified[participant][dojangAttesterId] = verified;
    }

    function isVerified(address participant, bytes32 dojangAttesterId) external view returns (bool) {
        return _verified[participant][dojangAttesterId];
    }
}
