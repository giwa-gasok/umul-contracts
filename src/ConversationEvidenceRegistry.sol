// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IDojangScroll} from "./interfaces/IDojangScroll.sol";

/// @title Gasok Conversation Evidence Registry
/// @notice Records hashes of participant-approved conversations without storing message plaintext.
/// @dev P0 supports EOA signatures only. EIP-1271 smart-account signatures are deferred to P1.
contract ConversationEvidenceRegistry {
    struct Evidence {
        bytes32 conversationHash;
        bytes32 contentHash;
        bytes32 participantsHash;
        uint32 messageCount;
        uint64 startedAt;
        uint64 endedAt;
        bytes32 nonce;
        uint64 deadline;
    }

    struct EvidenceRecord {
        bytes32 evidenceId;
        bytes32 contentHash;
        bytes32 conversationHash;
        bytes32 participantsHash;
        address[] participants;
        uint32 messageCount;
        uint64 startedAt;
        uint64 endedAt;
        uint64 recordedAt;
        address submitter;
    }

    error DeadlineExpired(uint64 deadline, uint256 currentTimestamp);
    error DuplicateParticipant(address participant);
    error EvidenceAlreadyRecorded(bytes32 evidenceId);
    error EvidenceNotFound(bytes32 evidenceId);
    error InvalidSignature(address participant);
    error InvalidTimeRange(uint64 startedAt, uint64 endedAt);
    error ParticipantNotVerified(address participant);
    error ParticipantsHashMismatch(bytes32 expected, bytes32 actual);
    error ParticipantsNotSorted(address previous, address current);
    error SignatureCountMismatch(uint256 participantCount, uint256 signatureCount);
    error TooFewParticipants(uint256 participantCount);
    error ZeroAttesterId();
    error ZeroContentHash();
    error ZeroConversationHash();
    error ZeroDojangScroll();
    error ZeroMessageCount();
    error ZeroNonce();
    error ZeroParticipant(uint256 index);

    event EvidenceRecorded(
        bytes32 indexed evidenceId,
        bytes32 indexed conversationHash,
        bytes32 indexed contentHash,
        bytes32 participantsHash,
        address[] participants,
        uint32 messageCount,
        uint64 startedAt,
        uint64 endedAt,
        uint64 recordedAt,
        address submitter
    );

    string public constant DOMAIN_NAME = "GasokConversationEvidence";
    string public constant DOMAIN_VERSION = "1";

    bytes32 public constant EVIDENCE_TYPEHASH = keccak256(
        "Evidence(bytes32 conversationHash,bytes32 contentHash,bytes32 participantsHash,uint32 messageCount,uint64 startedAt,uint64 endedAt,bytes32 nonce,uint64 deadline)"
    );

    bytes32 private constant _DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _NAME_HASH = keccak256(bytes(DOMAIN_NAME));
    bytes32 private constant _VERSION_HASH = keccak256(bytes(DOMAIN_VERSION));
    uint256 private constant _SECP256K1_HALF_ORDER =
        57896044618658097711785492504343953926418782139537452191302581570759080747168;

    IDojangScroll public immutable dojangScroll;
    bytes32 public immutable attesterId;

    mapping(bytes32 evidenceId => bool exists) public evidenceExists;
    mapping(bytes32 evidenceId => EvidenceRecord record) private _evidenceRecords;

    constructor(address dojangScrollAddress, bytes32 dojangAttesterId) {
        if (dojangScrollAddress == address(0)) revert ZeroDojangScroll();
        if (dojangAttesterId == bytes32(0)) revert ZeroAttesterId();

        dojangScroll = IDojangScroll(dojangScrollAddress);
        attesterId = dojangAttesterId;
    }

    /// @notice Records evidence after every sorted, verified participant has signed it.
    /// @dev `evidenceId = keccak256(abi.encode(typedDataDigest, evidence.nonce))`.
    ///      The digest already commits to the nonce; including it again makes the ID
    ///      derivation and replay boundary explicit.
    function recordEvidence(Evidence calldata evidence, address[] calldata participants, bytes[] calldata signatures)
        external
        returns (bytes32 evidenceId)
    {
        _validateShape(evidence, participants, signatures);

        bytes32 actualParticipantsHash = hashParticipants(participants);
        if (evidence.participantsHash != actualParticipantsHash) {
            revert ParticipantsHashMismatch(evidence.participantsHash, actualParticipantsHash);
        }

        bytes32 digest = hashEvidence(evidence);
        evidenceId = keccak256(abi.encode(digest, evidence.nonce));
        if (evidenceExists[evidenceId]) revert EvidenceAlreadyRecorded(evidenceId);

        for (uint256 i; i < participants.length; ++i) {
            address participant = participants[i];
            if (!dojangScroll.isVerified(participant, attesterId)) {
                revert ParticipantNotVerified(participant);
            }
            if (_recover(digest, signatures[i]) != participant) {
                revert InvalidSignature(participant);
            }
        }

        evidenceExists[evidenceId] = true;
        _storeAndEmit(evidenceId, evidence, participants);
    }

    function _storeAndEmit(bytes32 evidenceId, Evidence calldata evidence, address[] calldata participants) private {
        uint64 recordedAt = uint64(block.timestamp);
        EvidenceRecord storage record = _evidenceRecords[evidenceId];
        record.evidenceId = evidenceId;
        record.contentHash = evidence.contentHash;
        record.conversationHash = evidence.conversationHash;
        record.participantsHash = evidence.participantsHash;
        record.participants = participants;
        record.messageCount = evidence.messageCount;
        record.startedAt = evidence.startedAt;
        record.endedAt = evidence.endedAt;
        record.recordedAt = recordedAt;
        record.submitter = msg.sender;

        emit EvidenceRecorded(
            evidenceId,
            evidence.conversationHash,
            evidence.contentHash,
            evidence.participantsHash,
            participants,
            evidence.messageCount,
            evidence.startedAt,
            evidence.endedAt,
            recordedAt,
            msg.sender
        );
    }

    function getEvidence(bytes32 evidenceId) external view returns (EvidenceRecord memory) {
        if (!evidenceExists[evidenceId]) revert EvidenceNotFound(evidenceId);
        return _evidenceRecords[evidenceId];
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(_DOMAIN_TYPEHASH, _NAME_HASH, _VERSION_HASH, block.chainid, address(this)));
    }

    function hashEvidence(Evidence memory evidence) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                EVIDENCE_TYPEHASH,
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
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    /// @notice Deterministically hashes the ABI-encoded, strictly sorted participant array.
    function hashParticipants(address[] memory participants) public pure returns (bytes32) {
        return keccak256(abi.encode(participants));
    }

    function _validateShape(Evidence calldata evidence, address[] calldata participants, bytes[] calldata signatures)
        private
        view
    {
        if (participants.length < 2) revert TooFewParticipants(participants.length);
        if (participants.length != signatures.length) {
            revert SignatureCountMismatch(participants.length, signatures.length);
        }
        if (evidence.conversationHash == bytes32(0)) revert ZeroConversationHash();
        if (evidence.contentHash == bytes32(0)) revert ZeroContentHash();
        if (evidence.messageCount == 0) revert ZeroMessageCount();
        if (evidence.startedAt > evidence.endedAt) revert InvalidTimeRange(evidence.startedAt, evidence.endedAt);
        if (evidence.nonce == bytes32(0)) revert ZeroNonce();
        if (evidence.deadline < block.timestamp) revert DeadlineExpired(evidence.deadline, block.timestamp);

        address previous;
        for (uint256 i; i < participants.length; ++i) {
            address current = participants[i];
            if (current == address(0)) revert ZeroParticipant(i);
            if (current == previous) revert DuplicateParticipant(current);
            if (uint160(current) < uint160(previous)) revert ParticipantsNotSorted(previous, current);
            previous = current;
        }
    }

    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address) {
        if (signature.length != 65) return address(0);

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 0x20))
            v := byte(0, calldataload(add(signature.offset, 0x40)))
        }

        if (uint256(s) > _SECP256K1_HALF_ORDER || (v != 27 && v != 28)) {
            return address(0);
        }
        return ecrecover(digest, v, r, s);
    }
}
