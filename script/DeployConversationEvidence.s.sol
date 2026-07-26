// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ConversationEvidenceRegistry} from "../src/ConversationEvidenceRegistry.sol";

interface ScriptVm {
    function broadcast(uint256 privateKey) external;
    function envBytes32(string calldata name) external view returns (bytes32 value);
    function envUint(string calldata name) external view returns (uint256 value);
    function envOr(string calldata name, address defaultValue) external view returns (address value);
}

/// @notice Deploys the evidence registry against the GIWA Sepolia DojangScroll predeploy.
/// @dev The deployer key is read from `DEPLOYER_PRIVATE_KEY` and never appears in this file,
///      in the runbook, or in the broadcast artefacts committed to the repository.
contract DeployConversationEvidence {
    ScriptVm private constant vm = ScriptVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    address private constant DEFAULT_DOJANG_SCROLL = 0xd5077b67dcb56caC8b270C7788FC3E6ee03F17B9;

    function run() external returns (ConversationEvidenceRegistry registry) {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address dojangScroll = vm.envOr("DOJANG_SCROLL_ADDRESS", DEFAULT_DOJANG_SCROLL);
        bytes32 attesterId = vm.envBytes32("DOJANG_ATTESTER_ID");

        vm.broadcast(deployerKey);
        registry = new ConversationEvidenceRegistry(dojangScroll, attesterId);
    }
}
