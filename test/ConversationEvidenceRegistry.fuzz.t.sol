// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ConversationEvidenceRegistry} from "../src/ConversationEvidenceRegistry.sol";
import {MockDojangScroll} from "./mocks/MockDojangScroll.sol";

interface FuzzVm {
    function addr(uint256 privateKey) external returns (address);
    function assume(bool condition) external;
    function expectRevert(bytes4 revertData) external;
    function expectRevert(bytes calldata revertData) external;
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 newTimestamp) external;
}

contract ConversationEvidenceRegistryFuzzTest {
    FuzzVm private constant vm = FuzzVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 private constant ATTESTER_ID = keccak256("TESTNET_FAUCET");
    uint256 private constant FIRST_KEY = 0xA11CE;
    uint256 private constant SECOND_KEY = 0xB0B;
    uint256 private constant THIRD_KEY = 0xCAFE;

    MockDojangScroll private dojang;
    ConversationEvidenceRegistry private registry;
    mapping(address participant => uint256 privateKey) private privateKeys;

    function setUp() public {
        vm.warp(1_000_000);
        dojang = new MockDojangScroll();
        registry = new ConversationEvidenceRegistry(address(dojang), ATTESTER_ID);
        privateKeys[vm.addr(FIRST_KEY)] = FIRST_KEY;
        privateKeys[vm.addr(SECOND_KEY)] = SECOND_KEY;
        privateKeys[vm.addr(THIRD_KEY)] = THIRD_KEY;
    }

    function testFuzz_rejectsParticipantCountsBelowTwo(uint8 seed) public {
        uint256 count = uint256(seed) % 2;
        address[] memory participants = new address[](count);
        bytes[] memory signatures = new bytes[](count);
        if (count == 1) participants[0] = vm.addr(FIRST_KEY);
        ConversationEvidenceRegistry.Evidence memory evidence = _evidence(participants, keccak256(abi.encode(seed)));

        vm.expectRevert(abi.encodeWithSelector(ConversationEvidenceRegistry.TooFewParticipants.selector, count));
        registry.recordEvidence(evidence, participants, signatures);
    }

    function testFuzz_acceptsTwoOrThreeValidParticipants(uint8 seed, bytes32 nonce) public {
        uint256 count = 2 + (uint256(seed) % 2);
        address[] memory participants = _sortedParticipants(count);
        _verifyAll(participants);
        ConversationEvidenceRegistry.Evidence memory evidence = _evidence(participants, nonce);
        bytes[] memory signatures = _signaturesFor(evidence, participants);

        bytes32 evidenceId = registry.recordEvidence(evidence, participants, signatures);

        require(registry.evidenceExists(evidenceId), "evidence not stored");
        require(registry.getEvidence(evidenceId).participants.length == count, "participant boundary mismatch");
    }

    function testFuzz_rejectsDescendingParticipantPair(address first, address second, bytes32 nonce) public {
        vm.assume(first != address(0) && second != address(0) && first != second);
        address[] memory participants = new address[](2);
        if (uint160(first) > uint160(second)) {
            participants[0] = first;
            participants[1] = second;
        } else {
            participants[0] = second;
            participants[1] = first;
        }
        bytes[] memory signatures = new bytes[](2);
        ConversationEvidenceRegistry.Evidence memory evidence = _evidence(participants, nonce);

        vm.expectRevert(
            abi.encodeWithSelector(
                ConversationEvidenceRegistry.ParticipantsNotSorted.selector, participants[0], participants[1]
            )
        );
        registry.recordEvidence(evidence, participants, signatures);
    }

    function testFuzz_rejectsDuplicateParticipant(address participant, bytes32 nonce) public {
        vm.assume(participant != address(0));
        address[] memory participants = new address[](2);
        participants[0] = participant;
        participants[1] = participant;
        bytes[] memory signatures = new bytes[](2);
        ConversationEvidenceRegistry.Evidence memory evidence = _evidence(participants, nonce);

        vm.expectRevert(abi.encodeWithSelector(ConversationEvidenceRegistry.DuplicateParticipant.selector, participant));
        registry.recordEvidence(evidence, participants, signatures);
    }

    function testFuzz_rejectsReusedEvidence(bytes32 nonce) public {
        address[] memory participants = _sortedParticipants(2);
        _verifyAll(participants);
        ConversationEvidenceRegistry.Evidence memory evidence = _evidence(participants, nonce);
        bytes[] memory signatures = _signaturesFor(evidence, participants);
        bytes32 evidenceId = registry.recordEvidence(evidence, participants, signatures);

        vm.expectRevert(
            abi.encodeWithSelector(ConversationEvidenceRegistry.EvidenceAlreadyRecorded.selector, evidenceId)
        );
        registry.recordEvidence(evidence, participants, signatures);
    }

    function _evidence(address[] memory participants, bytes32 nonce)
        private
        view
        returns (ConversationEvidenceRegistry.Evidence memory)
    {
        bytes32 safeNonce = nonce == bytes32(0) ? bytes32(uint256(1)) : nonce;
        return ConversationEvidenceRegistry.Evidence({
            conversationHash: keccak256("conversation"),
            contentHash: keccak256("content"),
            participantsHash: registry.hashParticipants(participants),
            messageCount: 1,
            startedAt: uint64(block.timestamp - 1),
            endedAt: uint64(block.timestamp),
            nonce: safeNonce,
            deadline: uint64(block.timestamp + 1 days)
        });
    }

    function _sortedParticipants(uint256 count) private returns (address[] memory participants) {
        address[] memory candidates = new address[](3);
        candidates[0] = vm.addr(FIRST_KEY);
        candidates[1] = vm.addr(SECOND_KEY);
        candidates[2] = vm.addr(THIRD_KEY);

        for (uint256 i; i < candidates.length; ++i) {
            for (uint256 j = i + 1; j < candidates.length; ++j) {
                if (uint160(candidates[j]) < uint160(candidates[i])) {
                    (candidates[i], candidates[j]) = (candidates[j], candidates[i]);
                }
            }
        }

        participants = new address[](count);
        for (uint256 i; i < count; ++i) {
            participants[i] = candidates[i];
        }
    }

    function _signaturesFor(ConversationEvidenceRegistry.Evidence memory evidence, address[] memory participants)
        private
        returns (bytes[] memory signatures)
    {
        signatures = new bytes[](participants.length);
        bytes32 digest = registry.hashEvidence(evidence);
        for (uint256 i; i < participants.length; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKeys[participants[i]], digest);
            signatures[i] = abi.encodePacked(r, s, v);
        }
    }

    function _verifyAll(address[] memory participants) private {
        for (uint256 i; i < participants.length; ++i) {
            dojang.setVerified(participants[i], ATTESTER_ID, true);
        }
    }
}
