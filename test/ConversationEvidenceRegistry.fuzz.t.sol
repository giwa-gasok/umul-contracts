// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ConversationEvidenceRegistry} from "../src/ConversationEvidenceRegistry.sol";
import {MockDojangScroll} from "./mocks/MockDojangScroll.sol";

interface FuzzVm {
    function addr(uint256 privateKey) external returns (address);
    function expectRevert(bytes calldata revertData) external;
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 newTimestamp) external;
}

contract ConversationEvidenceRegistryFuzzTest {
    FuzzVm private constant vm = FuzzVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 private constant ATTESTER_ID = keccak256("TESTNET_FAUCET");
    uint256 private constant MIN_PARTICIPANTS = 2;
    uint256 private constant TEST_MAX_PARTICIPANTS = 8;
    uint256 private constant SECP256K1_ORDER =
        115792089237316195423570985008687907852837564279074904382605163141518161494337;

    MockDojangScroll private dojang;
    ConversationEvidenceRegistry private registry;

    function setUp() public {
        vm.warp(1_000_000);
        dojang = new MockDojangScroll();
        registry = new ConversationEvidenceRegistry(address(dojang), ATTESTER_ID);
    }

    function testFuzz_rejectsParticipantCountsBelowTwo(uint8 countSeed, bytes32 signerSeed) public {
        uint256 count = uint256(countSeed) % MIN_PARTICIPANTS;
        (address[] memory participants,) = _sortedSigners(signerSeed, count);
        bytes[] memory signatures = new bytes[](count);
        ConversationEvidenceRegistry.Evidence memory evidence = _evidence(participants, signerSeed, signerSeed);

        vm.expectRevert(abi.encodeWithSelector(ConversationEvidenceRegistry.TooFewParticipants.selector, count));
        registry.recordEvidence(evidence, participants, signatures);
    }

    function testFuzz_recordsVariedParticipantCounts(uint8 countSeed, bytes32 signerSeed, bytes32 nonce) public {
        _recordAndAssert(_participantCount(countSeed), signerSeed, nonce);
    }

    function testFuzz_recordsMinimumParticipantBoundary(bytes32 signerSeed, bytes32 nonce) public {
        _recordAndAssert(MIN_PARTICIPANTS, signerSeed, nonce);
    }

    function testFuzz_recordsUpperParticipantBoundary(bytes32 signerSeed, bytes32 nonce) public {
        _recordAndAssert(TEST_MAX_PARTICIPANTS, signerSeed, nonce);
    }

    function testFuzz_rejectsEmptySignatureAtAnyParticipant(
        uint8 countSeed,
        uint8 participantSeed,
        bytes32 signerSeed,
        bytes32 nonce
    ) public {
        uint256 count = _participantCount(countSeed);
        (address[] memory participants, uint256[] memory privateKeys) = _sortedSigners(signerSeed, count);
        _verifyAll(participants);
        ConversationEvidenceRegistry.Evidence memory evidence = _evidence(participants, nonce, signerSeed);
        bytes[] memory signatures = _signaturesFor(evidence, participants, privateKeys);
        uint256 target = uint256(participantSeed) % count;
        signatures[target] = bytes("");

        vm.expectRevert(
            abi.encodeWithSelector(ConversationEvidenceRegistry.InvalidSignature.selector, participants[target])
        );
        registry.recordEvidence(evidence, participants, signatures);
    }

    function testFuzz_rejectsWrongSignerAtAnyParticipant(
        uint8 countSeed,
        uint8 participantSeed,
        bytes32 signerSeed,
        bytes32 nonce
    ) public {
        uint256 count = _participantCount(countSeed);
        (address[] memory participants, uint256[] memory privateKeys) = _sortedSigners(signerSeed, count);
        _verifyAll(participants);
        ConversationEvidenceRegistry.Evidence memory evidence = _evidence(participants, nonce, signerSeed);
        bytes[] memory signatures = _signaturesFor(evidence, participants, privateKeys);
        uint256 target = uint256(participantSeed) % count;
        uint256 wrongKey = privateKeys[target] == SECP256K1_ORDER - 1 ? 1 : privateKeys[target] + 1;
        signatures[target] = _sign(wrongKey, registry.hashEvidence(evidence));

        vm.expectRevert(
            abi.encodeWithSelector(ConversationEvidenceRegistry.InvalidSignature.selector, participants[target])
        );
        registry.recordEvidence(evidence, participants, signatures);
    }

    function testFuzz_rejectsUnverifiedParticipantAtAnyIndex(
        uint8 countSeed,
        uint8 participantSeed,
        bytes32 signerSeed,
        bytes32 nonce
    ) public {
        uint256 count = _participantCount(countSeed);
        (address[] memory participants, uint256[] memory privateKeys) = _sortedSigners(signerSeed, count);
        uint256 target = uint256(participantSeed) % count;
        _verifyAllExcept(participants, target);
        ConversationEvidenceRegistry.Evidence memory evidence = _evidence(participants, nonce, signerSeed);
        bytes[] memory signatures = _signaturesFor(evidence, participants, privateKeys);

        vm.expectRevert(
            abi.encodeWithSelector(ConversationEvidenceRegistry.ParticipantNotVerified.selector, participants[target])
        );
        registry.recordEvidence(evidence, participants, signatures);
    }

    function testFuzz_rejectsAnyAdjacentParticipantSwap(
        uint8 countSeed,
        uint8 pairSeed,
        bytes32 signerSeed,
        bytes32 nonce
    ) public {
        uint256 count = _participantCount(countSeed);
        (address[] memory participants, uint256[] memory privateKeys) = _sortedSigners(signerSeed, count);
        uint256 first = uint256(pairSeed) % (count - 1);
        uint256 second = first + 1;
        (participants[first], participants[second]) = (participants[second], participants[first]);
        (privateKeys[first], privateKeys[second]) = (privateKeys[second], privateKeys[first]);
        _verifyAll(participants);
        ConversationEvidenceRegistry.Evidence memory evidence = _evidence(participants, nonce, signerSeed);
        bytes[] memory signatures = _signaturesFor(evidence, participants, privateKeys);

        vm.expectRevert(
            abi.encodeWithSelector(
                ConversationEvidenceRegistry.ParticipantsNotSorted.selector, participants[first], participants[second]
            )
        );
        registry.recordEvidence(evidence, participants, signatures);
    }

    function testFuzz_rejectsDuplicateParticipantAtAnyAdjacentIndex(
        uint8 countSeed,
        uint8 pairSeed,
        bytes32 signerSeed,
        bytes32 nonce
    ) public {
        uint256 count = _participantCount(countSeed);
        (address[] memory participants, uint256[] memory privateKeys) = _sortedSigners(signerSeed, count);
        uint256 first = uint256(pairSeed) % (count - 1);
        participants[first + 1] = participants[first];
        privateKeys[first + 1] = privateKeys[first];
        ConversationEvidenceRegistry.Evidence memory evidence = _evidence(participants, nonce, signerSeed);
        bytes[] memory signatures = _signaturesFor(evidence, participants, privateKeys);

        vm.expectRevert(
            abi.encodeWithSelector(ConversationEvidenceRegistry.DuplicateParticipant.selector, participants[first])
        );
        registry.recordEvidence(evidence, participants, signatures);
    }

    function testFuzz_rejectsReusedEvidence(uint8 countSeed, bytes32 signerSeed, bytes32 nonce) public {
        uint256 count = _participantCount(countSeed);
        (address[] memory participants, uint256[] memory privateKeys) = _sortedSigners(signerSeed, count);
        _verifyAll(participants);
        ConversationEvidenceRegistry.Evidence memory evidence = _evidence(participants, nonce, signerSeed);
        bytes[] memory signatures = _signaturesFor(evidence, participants, privateKeys);
        bytes32 evidenceId = registry.recordEvidence(evidence, participants, signatures);

        vm.expectRevert(
            abi.encodeWithSelector(ConversationEvidenceRegistry.EvidenceAlreadyRecorded.selector, evidenceId)
        );
        registry.recordEvidence(evidence, participants, signatures);
    }

    function _recordAndAssert(uint256 count, bytes32 signerSeed, bytes32 nonce) private {
        (address[] memory participants, uint256[] memory privateKeys) = _sortedSigners(signerSeed, count);
        _verifyAll(participants);
        ConversationEvidenceRegistry.Evidence memory evidence = _evidence(participants, nonce, signerSeed);
        bytes[] memory signatures = _signaturesFor(evidence, participants, privateKeys);
        bytes32 expectedId = keccak256(abi.encode(registry.hashEvidence(evidence), evidence.nonce));

        bytes32 evidenceId = registry.recordEvidence(evidence, participants, signatures);

        _assertEq(evidenceId, expectedId, "evidence id mismatch");
        require(registry.evidenceExists(evidenceId), "evidence not stored");
        ConversationEvidenceRegistry.EvidenceRecord memory record = registry.getEvidence(evidenceId);
        _assertEq(record.evidenceId, evidenceId, "stored evidence id mismatch");
        _assertEq(record.conversationHash, evidence.conversationHash, "conversation hash mismatch");
        _assertEq(record.contentHash, evidence.contentHash, "content hash mismatch");
        _assertEq(record.participantsHash, evidence.participantsHash, "participants hash mismatch");
        _assertEq(record.participants, participants);
        _assertEq(record.messageCount, evidence.messageCount, "message count mismatch");
        _assertEq(record.startedAt, evidence.startedAt, "startedAt mismatch");
        _assertEq(record.endedAt, evidence.endedAt, "endedAt mismatch");
        _assertEq(record.recordedAt, uint64(block.timestamp), "recordedAt mismatch");
        _assertEq(record.submitter, address(this), "submitter mismatch");
    }

    function _participantCount(uint8 countSeed) private pure returns (uint256) {
        return MIN_PARTICIPANTS + (uint256(countSeed) % (TEST_MAX_PARTICIPANTS - MIN_PARTICIPANTS + 1));
    }

    function _sortedSigners(bytes32 seed, uint256 count)
        private
        returns (address[] memory participants, uint256[] memory privateKeys)
    {
        participants = new address[](count);
        privateKeys = new uint256[](count);
        uint256 firstKey =
            (uint256(keccak256(abi.encode("Gasok evidence fuzz signer", seed)))
                    % (SECP256K1_ORDER - TEST_MAX_PARTICIPANTS)) + 1;

        for (uint256 i; i < count; ++i) {
            privateKeys[i] = firstKey + i;
            participants[i] = vm.addr(privateKeys[i]);
        }

        for (uint256 i; i < count; ++i) {
            for (uint256 j = i + 1; j < count; ++j) {
                if (uint160(participants[j]) < uint160(participants[i])) {
                    (participants[i], participants[j]) = (participants[j], participants[i]);
                    (privateKeys[i], privateKeys[j]) = (privateKeys[j], privateKeys[i]);
                }
            }
        }
    }

    function _evidence(address[] memory participants, bytes32 nonce, bytes32 scenarioSeed)
        private
        view
        returns (ConversationEvidenceRegistry.Evidence memory)
    {
        bytes32 safeNonce = nonce == bytes32(0) ? bytes32(uint256(1)) : nonce;
        bytes32 conversationHash = _nonzeroHash(keccak256(abi.encode("conversation", scenarioSeed)));
        bytes32 contentHash = _nonzeroHash(keccak256(abi.encode("content", scenarioSeed)));
        uint32 messageCount = uint32(uint256(scenarioSeed) % type(uint32).max) + 1;
        return ConversationEvidenceRegistry.Evidence({
            conversationHash: conversationHash,
            contentHash: contentHash,
            participantsHash: registry.hashParticipants(participants),
            messageCount: messageCount,
            startedAt: uint64(block.timestamp - 1),
            endedAt: uint64(block.timestamp),
            nonce: safeNonce,
            deadline: uint64(block.timestamp + 1 days)
        });
    }

    function _signaturesFor(
        ConversationEvidenceRegistry.Evidence memory evidence,
        address[] memory participants,
        uint256[] memory privateKeys
    ) private returns (bytes[] memory signatures) {
        require(participants.length == privateKeys.length, "signer fixture mismatch");
        signatures = new bytes[](participants.length);
        bytes32 digest = registry.hashEvidence(evidence);
        for (uint256 i; i < participants.length; ++i) {
            signatures[i] = _sign(privateKeys[i], digest);
        }
    }

    function _sign(uint256 privateKey, bytes32 digest) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _verifyAll(address[] memory participants) private {
        for (uint256 i; i < participants.length; ++i) {
            dojang.setVerified(participants[i], ATTESTER_ID, true);
        }
    }

    function _verifyAllExcept(address[] memory participants, uint256 excludedIndex) private {
        for (uint256 i; i < participants.length; ++i) {
            if (i != excludedIndex) {
                dojang.setVerified(participants[i], ATTESTER_ID, true);
            }
        }
    }

    function _nonzeroHash(bytes32 value) private pure returns (bytes32) {
        return value == bytes32(0) ? bytes32(uint256(1)) : value;
    }

    function _assertEq(bytes32 actual, bytes32 expected, string memory message) private pure {
        require(actual == expected, message);
    }

    function _assertEq(address actual, address expected, string memory message) private pure {
        require(actual == expected, message);
    }

    function _assertEq(uint256 actual, uint256 expected, string memory message) private pure {
        require(actual == expected, message);
    }

    function _assertEq(address[] memory actual, address[] memory expected) private pure {
        require(actual.length == expected.length, "participant array length mismatch");
        for (uint256 i; i < actual.length; ++i) {
            require(actual[i] == expected[i], "participant array item mismatch");
        }
    }
}
