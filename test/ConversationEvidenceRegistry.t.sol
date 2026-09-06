// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ConversationEvidenceRegistry} from "../src/ConversationEvidenceRegistry.sol";
import {MockDojangScroll} from "./mocks/MockDojangScroll.sol";
import {RawWordDojangScroll} from "./mocks/RawWordDojangScroll.sol";
import {ReturnBombDojangScroll} from "./mocks/ReturnBombDojangScroll.sol";
import {RevertingDojangScroll} from "./mocks/RevertingDojangScroll.sol";

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function expectEmit(bool checkTopic1, bool checkTopic2, bool checkTopic3, bool checkData) external;
    function expectRevert(bytes4 revertData) external;
    function expectRevert(bytes calldata revertData) external;
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 newTimestamp) external;
}

contract ConversationEvidenceRegistryTest {
    event EvidenceRecorded(
        bytes32 indexed evidenceId,
        bytes32 indexed conversationHash,
        bytes32 indexed contentHash,
        bytes32 participantsHash,
        address[] participants,
        bool[] participantsVerified,
        uint32 messageCount,
        uint64 startedAt,
        uint64 endedAt,
        uint64 recordedAt,
        address submitter
    );

    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 private constant ATTESTER_ID = keccak256("TESTNET_FAUCET");
    uint256 private constant FIRST_KEY = 0xA11CE;
    uint256 private constant SECOND_KEY = 0xB0B;
    uint256 private constant THIRD_KEY = 0xCAFE;
    uint256 private constant SECP256K1_HALF_ORDER =
        57896044618658097711785492504343953926418782139537452191302581570759080747168;

    MockDojangScroll private dojang;
    ConversationEvidenceRegistry private registry;
    mapping(address participant => uint256 privateKey) private privateKeys;
    mapping(bytes32 evidenceId => ConversationEvidenceRegistry registry) private registryFor;

    function setUp() public {
        vm.warp(1_000_000);
        dojang = new MockDojangScroll();
        registry = new ConversationEvidenceRegistry(address(dojang), ATTESTER_ID);

        privateKeys[vm.addr(FIRST_KEY)] = FIRST_KEY;
        privateKeys[vm.addr(SECOND_KEY)] = SECOND_KEY;
        privateKeys[vm.addr(THIRD_KEY)] = THIRD_KEY;
    }

    function test_constructor_rejectsZeroDojangScroll() public {
        vm.expectRevert(ConversationEvidenceRegistry.ZeroDojangScroll.selector);
        new ConversationEvidenceRegistry(address(0), ATTESTER_ID);
    }

    function test_constructor_rejectsZeroAttesterId() public {
        vm.expectRevert(ConversationEvidenceRegistry.ZeroAttesterId.selector);
        new ConversationEvidenceRegistry(address(dojang), bytes32(0));
    }

    function test_constructor_setsImmutableDojangConfiguration() public view {
        _assertEq(address(registry.dojangScroll()), address(dojang));
        _assertEq(registry.attesterId(), ATTESTER_ID);
    }

    function test_domainSeparator_usesRequiredEip712Domain() public view {
        bytes32 expected = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("GasokConversationEvidence")),
                keccak256(bytes("1")),
                block.chainid,
                address(registry)
            )
        );

        _assertEq(registry.domainSeparator(), expected);
    }

    function test_hashEvidence_matchesCanonicalTypedDataDigest() public {
        address[] memory participants = _sortedParticipants(2);
        ConversationEvidenceRegistry.Evidence memory evidence =
            _validEvidence(participants, keccak256("nonce-canonical-digest"));
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Evidence(bytes32 conversationHash,bytes32 contentHash,bytes32 participantsHash,uint32 messageCount,uint64 startedAt,uint64 endedAt,bytes32 nonce,uint64 deadline)"
                ),
                evidence.conversationHash,
                evidence.contentHash,
                evidence.participantsHash,
                evidence.messageCount,
                evidence.startedAt,
                evidence.endedAt,
                evidence.nonce,
                evidence.deadline
            )
        );
        bytes32 expected = keccak256(abi.encodePacked("\x19\x01", registry.domainSeparator(), structHash));

        _assertEq(registry.hashEvidence(evidence), expected);
    }

    function test_recordEvidence_recordsWhenEveryVerifiedParticipantSigned() public {
        address[] memory participants = _sortedParticipants(2);
        _verifyAll(participants);
        ConversationEvidenceRegistry.Evidence memory evidence = _validEvidence(participants, keccak256("nonce-success"));
        bytes[] memory signatures = _signaturesFor(evidence, participants);
        bytes32 digest = registry.hashEvidence(evidence);
        bytes32 expectedId = keccak256(abi.encode(digest, evidence.nonce));

        vm.expectEmit(true, true, true, true);
        emit EvidenceRecorded(
            expectedId,
            evidence.conversationHash,
            evidence.contentHash,
            evidence.participantsHash,
            participants,
            _flags(true, true),
            evidence.messageCount,
            evidence.startedAt,
            evidence.endedAt,
            uint64(block.timestamp),
            address(this)
        );

        bytes32 evidenceId = registry.recordEvidence(evidence, participants, signatures);

        _assertEq(evidenceId, expectedId);
        _assertTrue(registry.evidenceExists(evidenceId));
        ConversationEvidenceRegistry.EvidenceRecord memory record = registry.getEvidence(evidenceId);
        _assertEq(record.evidenceId, evidenceId);
        _assertEq(record.conversationHash, evidence.conversationHash);
        _assertEq(record.contentHash, evidence.contentHash);
        _assertEq(record.participantsHash, evidence.participantsHash);
        _assertEq(record.participants, participants);
        _assertEq(record.participantsVerified, _flags(true, true));
        _assertEq(record.messageCount, evidence.messageCount);
        _assertEq(record.startedAt, evidence.startedAt);
        _assertEq(record.endedAt, evidence.endedAt);
        _assertEq(record.recordedAt, uint64(block.timestamp));
        _assertEq(record.submitter, address(this));
    }

    function test_recordEvidence_requiresEveryParticipantSignature() public {
        address[] memory participants = _sortedParticipants(2);
        _verifyAll(participants);
        ConversationEvidenceRegistry.Evidence memory evidence = _validEvidence(participants, keccak256("nonce-missing"));
        bytes[] memory signatures = _signaturesFor(evidence, participants);
        signatures[1] = bytes("");

        vm.expectRevert(abi.encodeWithSelector(ConversationEvidenceRegistry.InvalidSignature.selector, participants[1]));
        registry.recordEvidence(evidence, participants, signatures);
    }

    function test_recordEvidence_rejectsSignatureFromWrongWallet() public {
        address[] memory participants = _sortedParticipants(2);
        _verifyAll(participants);
        ConversationEvidenceRegistry.Evidence memory evidence = _validEvidence(participants, keccak256("nonce-wrong"));
        bytes[] memory signatures = _signaturesFor(evidence, participants);
        signatures[0] = _sign(THIRD_KEY, registry.hashEvidence(evidence));

        vm.expectRevert(abi.encodeWithSelector(ConversationEvidenceRegistry.InvalidSignature.selector, participants[0]));
        registry.recordEvidence(evidence, participants, signatures);
    }

    function test_recordEvidence_rejectsMalleableSignature() public {
        address[] memory participants = _sortedParticipants(2);
        _verifyAll(participants);
        ConversationEvidenceRegistry.Evidence memory evidence =
            _validEvidence(participants, keccak256("nonce-malleable"));
        bytes[] memory signatures = _signaturesFor(evidence, participants);
        signatures[0] = abi.encodePacked(bytes32(uint256(1)), bytes32(SECP256K1_HALF_ORDER + 1), uint8(27));

        vm.expectRevert(abi.encodeWithSelector(ConversationEvidenceRegistry.InvalidSignature.selector, participants[0]));
        registry.recordEvidence(evidence, participants, signatures);
    }

    function test_recordEvidence_rejectsInvalidRecoveryId() public {
        address[] memory participants = _sortedParticipants(2);
        _verifyAll(participants);
        ConversationEvidenceRegistry.Evidence memory evidence = _validEvidence(participants, keccak256("nonce-v"));
        bytes[] memory signatures = _signaturesFor(evidence, participants);
        signatures[0][64] = bytes1(uint8(29));

        vm.expectRevert(abi.encodeWithSelector(ConversationEvidenceRegistry.InvalidSignature.selector, participants[0]));
        registry.recordEvidence(evidence, participants, signatures);
    }

    /// @notice Records even with an unverified participant, flagging the status instead.
    function test_recordEvidence_recordsUnverifiedParticipantAsFalseFlag() public {
        address[] memory participants = _sortedParticipants(2);
        dojang.setVerified(participants[0], ATTESTER_ID, true);
        ConversationEvidenceRegistry.Evidence memory evidence =
            _validEvidence(participants, keccak256("nonce-unverified"));
        bytes[] memory signatures = _signaturesFor(evidence, participants);

        bytes32 evidenceId = registry.recordEvidence(evidence, participants, signatures);

        ConversationEvidenceRegistry.EvidenceRecord memory record = registry.getEvidence(evidenceId);
        _assertEq(record.participants, participants);
        _assertEq(record.participantsVerified, _flags(true, false));
    }

    /// @notice A conversation where nobody is verified is recorded all the same.
    function test_recordEvidence_recordsWhenNoParticipantIsVerified() public {
        address[] memory participants = _sortedParticipants(2);
        ConversationEvidenceRegistry.Evidence memory evidence =
            _validEvidence(participants, keccak256("nonce-none-verified"));
        bytes[] memory signatures = _signaturesFor(evidence, participants);

        bytes32 evidenceId = registry.recordEvidence(evidence, participants, signatures);

        _assertEq(registry.getEvidence(evidenceId).participantsVerified, _flags(false, false));
    }

    /// @notice A non-canonical `true` still reads as verified rather than reverting.
    /// @dev The boolean ABI decoder reverts on a word that is neither 0 nor 1, so decoding
    ///      the answer as `bool` would revert `recordEvidence` itself and undo the whole
    ///      point of reading the scroll through a raw staticcall.
    function test_recordEvidence_readsDirtyBooleanWordAsVerified() public {
        bytes32 evidenceId =
            _recordAgainstScroll(address(new RawWordDojangScroll(abi.encode(uint256(2)))), "nonce-scroll-dirty");

        _assertEq(_registryFor(evidenceId).getEvidence(evidenceId).participantsVerified, _flags(true, true));
    }

    /// @notice A zero word is the only word that means unverified.
    function test_recordEvidence_readsZeroWordAsUnverified() public {
        bytes32 evidenceId =
            _recordAgainstScroll(address(new RawWordDojangScroll(abi.encode(uint256(0)))), "nonce-scroll-zero");

        _assertEq(_registryFor(evidenceId).getEvidence(evidenceId).participantsVerified, _flags(false, false));
    }

    /// @notice A short answer is not an answer. Nothing reverts, nothing is verified.
    function test_recordEvidence_recordsWhenDojangReturnsShortData() public {
        bytes32 evidenceId = _recordAgainstScroll(address(new RawWordDojangScroll(hex"deadbeef")), "nonce-scroll-short");

        _assertEq(_registryFor(evidenceId).getEvidence(evidenceId).participantsVerified, _flags(false, false));
    }

    /// @notice A scroll flooding the return buffer cannot grief the caller's memory.
    /// @dev Taking the answer into a `bytes memory` would copy all of it and pay quadratic
    ///      memory expansion for the privilege. The 32-byte output window never copies more
    ///      than a word, so what is left is the callee's own expansion.
    function test_recordEvidence_recordsWhenDojangFloodsReturnData() public {
        bytes32 evidenceId = _recordAgainstScroll(address(new ReturnBombDojangScroll(3_000_000)), "nonce-scroll-bomb");

        _assertEq(_registryFor(evidenceId).getEvidence(evidenceId).participantsVerified, _flags(false, false));
    }

    /// @notice Evidence survives a failing Dojang lookup; only the signal is lost.
    function test_recordEvidence_recordsWhenDojangLookupReverts() public {
        ConversationEvidenceRegistry unreadable =
            new ConversationEvidenceRegistry(address(new RevertingDojangScroll()), ATTESTER_ID);
        address[] memory participants = _sortedParticipants(2);
        ConversationEvidenceRegistry.Evidence memory evidence = ConversationEvidenceRegistry.Evidence({
            conversationHash: keccak256("conversation"),
            contentHash: keccak256("content"),
            participantsHash: unreadable.hashParticipants(participants),
            messageCount: 3,
            startedAt: uint64(block.timestamp - 100),
            endedAt: uint64(block.timestamp - 1),
            nonce: keccak256("nonce-scroll-down"),
            deadline: uint64(block.timestamp + 1 days)
        });
        bytes32 digest = unreadable.hashEvidence(evidence);
        bytes[] memory signatures = new bytes[](2);
        for (uint256 i; i < participants.length; ++i) {
            signatures[i] = _sign(privateKeys[participants[i]], digest);
        }

        bytes32 evidenceId = unreadable.recordEvidence(evidence, participants, signatures);

        _assertEq(unreadable.getEvidence(evidenceId).participantsVerified, _flags(false, false));
    }

    function test_recordEvidence_rejectsDuplicateParticipant() public {
        address participant = vm.addr(FIRST_KEY);
        address[] memory participants = new address[](2);
        participants[0] = participant;
        participants[1] = participant;
        bytes[] memory signatures = new bytes[](2);
        ConversationEvidenceRegistry.Evidence memory evidence =
            _validEvidence(participants, keccak256("nonce-duplicate"));

        vm.expectRevert(abi.encodeWithSelector(ConversationEvidenceRegistry.DuplicateParticipant.selector, participant));
        registry.recordEvidence(evidence, participants, signatures);
    }

    function test_recordEvidence_rejectsUnsortedParticipants() public {
        address[] memory participants = _sortedParticipants(2);
        (participants[0], participants[1]) = (participants[1], participants[0]);
        bytes[] memory signatures = new bytes[](2);
        ConversationEvidenceRegistry.Evidence memory evidence =
            _validEvidence(participants, keccak256("nonce-unsorted"));

        vm.expectRevert(
            abi.encodeWithSelector(
                ConversationEvidenceRegistry.ParticipantsNotSorted.selector, participants[0], participants[1]
            )
        );
        registry.recordEvidence(evidence, participants, signatures);
    }

    function test_recordEvidence_rejectsZeroParticipant() public {
        address[] memory participants = new address[](2);
        participants[1] = vm.addr(FIRST_KEY);
        bytes[] memory signatures = new bytes[](2);
        ConversationEvidenceRegistry.Evidence memory evidence = _validEvidence(participants, keccak256("nonce-zero"));

        vm.expectRevert(abi.encodeWithSelector(ConversationEvidenceRegistry.ZeroParticipant.selector, uint256(0)));
        registry.recordEvidence(evidence, participants, signatures);
    }

    function test_recordEvidence_rejectsFewerThanTwoParticipants() public {
        address[] memory participants = new address[](1);
        participants[0] = vm.addr(FIRST_KEY);
        bytes[] memory signatures = new bytes[](1);
        ConversationEvidenceRegistry.Evidence memory evidence = _validEvidence(participants, keccak256("nonce-too-few"));

        vm.expectRevert(abi.encodeWithSelector(ConversationEvidenceRegistry.TooFewParticipants.selector, uint256(1)));
        registry.recordEvidence(evidence, participants, signatures);
    }

    function test_recordEvidence_rejectsSignatureLengthMismatch() public {
        address[] memory participants = _sortedParticipants(2);
        bytes[] memory signatures = new bytes[](1);
        ConversationEvidenceRegistry.Evidence memory evidence = _validEvidence(participants, keccak256("nonce-length"));

        vm.expectRevert(
            abi.encodeWithSelector(ConversationEvidenceRegistry.SignatureCountMismatch.selector, uint256(2), uint256(1))
        );
        registry.recordEvidence(evidence, participants, signatures);
    }

    function test_recordEvidence_rejectsParticipantsHashMismatch() public {
        address[] memory participants = _sortedParticipants(2);
        bytes[] memory signatures = new bytes[](2);
        ConversationEvidenceRegistry.Evidence memory evidence =
            _validEvidence(participants, keccak256("nonce-participants-hash"));
        evidence.participantsHash = keccak256("wrong");

        vm.expectRevert(
            abi.encodeWithSelector(
                ConversationEvidenceRegistry.ParticipantsHashMismatch.selector,
                evidence.participantsHash,
                registry.hashParticipants(participants)
            )
        );
        registry.recordEvidence(evidence, participants, signatures);
    }

    function test_recordEvidence_rejectsExpiredDeadline() public {
        address[] memory participants = _sortedParticipants(2);
        ConversationEvidenceRegistry.Evidence memory evidence = _validEvidence(participants, keccak256("nonce-expired"));
        evidence.deadline = uint64(block.timestamp - 1);
        bytes[] memory signatures = new bytes[](2);

        vm.expectRevert(
            abi.encodeWithSelector(
                ConversationEvidenceRegistry.DeadlineExpired.selector, evidence.deadline, block.timestamp
            )
        );
        registry.recordEvidence(evidence, participants, signatures);
    }

    function test_recordEvidence_acceptsDeadlineAtCurrentTimestamp() public {
        address[] memory participants = _sortedParticipants(2);
        _verifyAll(participants);
        ConversationEvidenceRegistry.Evidence memory evidence =
            _validEvidence(participants, keccak256("nonce-deadline-now"));
        evidence.deadline = uint64(block.timestamp);
        bytes[] memory signatures = _signaturesFor(evidence, participants);

        registry.recordEvidence(evidence, participants, signatures);
    }

    function test_recordEvidence_rejectsStartedAtAfterEndedAt() public {
        address[] memory participants = _sortedParticipants(2);
        ConversationEvidenceRegistry.Evidence memory evidence = _validEvidence(participants, keccak256("nonce-time"));
        evidence.startedAt = evidence.endedAt + 1;
        bytes[] memory signatures = new bytes[](2);

        vm.expectRevert(
            abi.encodeWithSelector(
                ConversationEvidenceRegistry.InvalidTimeRange.selector, evidence.startedAt, evidence.endedAt
            )
        );
        registry.recordEvidence(evidence, participants, signatures);
    }

    function test_recordEvidence_rejectsZeroMessageCount() public {
        address[] memory participants = _sortedParticipants(2);
        ConversationEvidenceRegistry.Evidence memory evidence =
            _validEvidence(participants, keccak256("nonce-message-count"));
        evidence.messageCount = 0;
        bytes[] memory signatures = new bytes[](2);

        vm.expectRevert(ConversationEvidenceRegistry.ZeroMessageCount.selector);
        registry.recordEvidence(evidence, participants, signatures);
    }

    function test_recordEvidence_rejectsZeroConversationHash() public {
        address[] memory participants = _sortedParticipants(2);
        ConversationEvidenceRegistry.Evidence memory evidence =
            _validEvidence(participants, keccak256("nonce-conversation-hash"));
        evidence.conversationHash = bytes32(0);
        bytes[] memory signatures = new bytes[](2);

        vm.expectRevert(ConversationEvidenceRegistry.ZeroConversationHash.selector);
        registry.recordEvidence(evidence, participants, signatures);
    }

    function test_recordEvidence_rejectsZeroContentHash() public {
        address[] memory participants = _sortedParticipants(2);
        ConversationEvidenceRegistry.Evidence memory evidence =
            _validEvidence(participants, keccak256("nonce-content-hash"));
        evidence.contentHash = bytes32(0);
        bytes[] memory signatures = new bytes[](2);

        vm.expectRevert(ConversationEvidenceRegistry.ZeroContentHash.selector);
        registry.recordEvidence(evidence, participants, signatures);
    }

    function test_recordEvidence_rejectsZeroNonce() public {
        address[] memory participants = _sortedParticipants(2);
        ConversationEvidenceRegistry.Evidence memory evidence = _validEvidence(participants, bytes32(0));
        bytes[] memory signatures = new bytes[](2);

        vm.expectRevert(ConversationEvidenceRegistry.ZeroNonce.selector);
        registry.recordEvidence(evidence, participants, signatures);
    }

    function test_recordEvidence_rejectsEvidenceReplay() public {
        address[] memory participants = _sortedParticipants(2);
        _verifyAll(participants);
        ConversationEvidenceRegistry.Evidence memory evidence = _validEvidence(participants, keccak256("nonce-replay"));
        bytes[] memory signatures = _signaturesFor(evidence, participants);
        bytes32 evidenceId = registry.recordEvidence(evidence, participants, signatures);

        vm.expectRevert(
            abi.encodeWithSelector(ConversationEvidenceRegistry.EvidenceAlreadyRecorded.selector, evidenceId)
        );
        registry.recordEvidence(evidence, participants, signatures);
    }

    function test_getEvidence_rejectsUnknownId() public {
        bytes32 unknownId = keccak256("unknown");
        vm.expectRevert(abi.encodeWithSelector(ConversationEvidenceRegistry.EvidenceNotFound.selector, unknownId));
        registry.getEvidence(unknownId);
    }

    /// @dev Records one evidence against a registry wired to `scroll`, and remembers that
    ///      registry so the caller can read the record back by id.
    function _recordAgainstScroll(address scroll, bytes32 nonce) private returns (bytes32 evidenceId) {
        ConversationEvidenceRegistry target = new ConversationEvidenceRegistry(scroll, ATTESTER_ID);
        address[] memory participants = _sortedParticipants(2);
        ConversationEvidenceRegistry.Evidence memory evidence = ConversationEvidenceRegistry.Evidence({
            conversationHash: keccak256("conversation"),
            contentHash: keccak256("content"),
            participantsHash: target.hashParticipants(participants),
            messageCount: 3,
            startedAt: uint64(block.timestamp - 100),
            endedAt: uint64(block.timestamp - 1),
            nonce: nonce,
            deadline: uint64(block.timestamp + 1 days)
        });
        bytes32 digest = target.hashEvidence(evidence);
        bytes[] memory signatures = new bytes[](participants.length);
        for (uint256 i; i < participants.length; ++i) {
            signatures[i] = _sign(privateKeys[participants[i]], digest);
        }

        evidenceId = target.recordEvidence(evidence, participants, signatures);
        registryFor[evidenceId] = target;
    }

    function _registryFor(bytes32 evidenceId) private view returns (ConversationEvidenceRegistry) {
        return registryFor[evidenceId];
    }

    function _validEvidence(address[] memory participants, bytes32 nonce)
        private
        view
        returns (ConversationEvidenceRegistry.Evidence memory)
    {
        return ConversationEvidenceRegistry.Evidence({
            conversationHash: keccak256("conversation"),
            contentHash: keccak256("content"),
            participantsHash: registry.hashParticipants(participants),
            messageCount: 3,
            startedAt: uint64(block.timestamp - 100),
            endedAt: uint64(block.timestamp - 1),
            nonce: nonce,
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
            signatures[i] = _sign(privateKeys[participants[i]], digest);
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

    function _flags(bool first, bool second) private pure returns (bool[] memory flags) {
        flags = new bool[](2);
        flags[0] = first;
        flags[1] = second;
    }

    function _assertTrue(bool value) private pure {
        require(value, "assert true failed");
    }

    function _assertEq(bytes32 actual, bytes32 expected) private pure {
        require(actual == expected, "bytes32 mismatch");
    }

    function _assertEq(address actual, address expected) private pure {
        require(actual == expected, "address mismatch");
    }

    function _assertEq(uint256 actual, uint256 expected) private pure {
        require(actual == expected, "uint mismatch");
    }

    function _assertEq(address[] memory actual, address[] memory expected) private pure {
        require(actual.length == expected.length, "address array length mismatch");
        for (uint256 i; i < actual.length; ++i) {
            require(actual[i] == expected[i], "address array item mismatch");
        }
    }

    function _assertEq(bool[] memory actual, bool[] memory expected) private pure {
        require(actual.length == expected.length, "bool array length mismatch");
        for (uint256 i; i < actual.length; ++i) {
            require(actual[i] == expected[i], "bool array item mismatch");
        }
    }
}
