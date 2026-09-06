// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ConversationEvidenceRegistry} from "../src/ConversationEvidenceRegistry.sol";
import {IDojangScroll} from "../src/interfaces/IDojangScroll.sol";

interface ForkVm {
    function addr(uint256 privateKey) external returns (address);
    function createSelectFork(string calldata urlOrAlias, uint256 blockNumber) external returns (uint256 forkId);
    function envOr(string calldata name, string calldata defaultValue) external returns (string memory value);
    function expectRevert(bytes calldata revertData) external;
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
}

/// @notice Pins the real GIWA Sepolia Dojang state that the P0 completion criteria depend on.
/// @dev BASELINE_BLOCK is the pre-attestation measurement: only wallet A holds a TESTNET_FAUCET
///      attestation. Wallet B is attested later in the plan, so this block preserves the mixed
///      state permanently even after B becomes verified on the live chain.
///      Verification no longer gates recording, so this mixed state pins what ends up
///      in the verification flags rather than who gets rejected.
contract ConversationEvidenceRegistryForkTest {
    ForkVm private constant vm = ForkVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 private constant BASELINE_BLOCK = 31_763_461;
    address private constant DOJANG_SCROLL = 0xd5077b67dcb56caC8b270C7788FC3E6ee03F17B9;
    bytes32 private constant TESTNET_FAUCET_ATTESTER =
        0xaa92f8c143657dde575de430aecaea6ca91f2e6072339b16932d426895d8d678;
    /// @dev Read from the DojangAttesterBook `AttesterRegistered` log at block 19,431,287.
    bytes32 private constant UPBIT_KOREA_ATTESTER = 0xd99b42e778498aa3c9c1f6a012359130252780511687a35982e8e52735453034;

    address private constant WALLET_A = 0xEf792c4973Cc8ef6aF433B3bd9f4461B701301f6;
    address private constant WALLET_B = 0x532dA989489eaB825d484EAd09f117018da47778;
    address private constant WALLET_C = 0x2F9713FB44eE7A15EF393eA694959324Be7a6479;

    IDojangScroll private dojang;
    ConversationEvidenceRegistry private registry;

    function setUp() public {
        string memory rpcUrl = vm.envOr("GIWA_SEPOLIA_RPC_URL", string("https://sepolia-rpc.giwa.io"));
        vm.createSelectFork(rpcUrl, BASELINE_BLOCK);
        dojang = IDojangScroll(DOJANG_SCROLL);
        registry = new ConversationEvidenceRegistry(DOJANG_SCROLL, TESTNET_FAUCET_ATTESTER);
    }

    /// @notice The recorded baseline: A verified, B and C unverified under TESTNET_FAUCET.
    function test_baselineDojangStatus_isWalletAOnly() public view {
        _assertTrue(dojang.isVerified(WALLET_A, TESTNET_FAUCET_ATTESTER), "A must be verified at baseline");
        _assertFalse(dojang.isVerified(WALLET_B, TESTNET_FAUCET_ATTESTER), "B must be unverified at baseline");
        _assertFalse(dojang.isVerified(WALLET_C, TESTNET_FAUCET_ATTESTER), "C must be unverified at baseline");
    }

    /// @notice Under the UPBIT_KOREA attester none of the three test wallets is verified.
    function test_baselineDojangStatus_isEmptyForUpbitKorea() public view {
        _assertFalse(dojang.isVerified(WALLET_A, UPBIT_KOREA_ATTESTER), "A must be unverified for UPBIT_KOREA");
        _assertFalse(dojang.isVerified(WALLET_B, UPBIT_KOREA_ATTESTER), "B must be unverified for UPBIT_KOREA");
        _assertFalse(dojang.isVerified(WALLET_C, UPBIT_KOREA_ATTESTER), "C must be unverified for UPBIT_KOREA");
    }

    /// @notice A conversation containing the unverified wallet B now fails on the
    ///         signature, not on verification.
    /// @dev B's key is unavailable, so an empty signature stands in. This call used to
    ///      revert with `ParticipantNotVerified` before reaching signature recovery.
    function test_recordEvidence_baselineWalletBFailsOnSignatureNotVerification() public {
        address[] memory participants = new address[](2);
        participants[0] = WALLET_B;
        participants[1] = WALLET_A;
        // `_evidenceFor` calls the registry, so it must run before `expectRevert` arms the next call.
        ConversationEvidenceRegistry.Evidence memory evidence = _evidenceFor(participants);

        vm.expectRevert(abi.encodeWithSelector(ConversationEvidenceRegistry.InvalidSignature.selector, WALLET_B));
        registry.recordEvidence(evidence, participants, new bytes[](2));
    }

    /// @notice The same holds for the unverified wallet C in the three-participant group.
    function test_recordEvidence_baselineWalletCFailsOnSignatureNotVerification() public {
        address[] memory participants = new address[](3);
        participants[0] = WALLET_C;
        participants[1] = WALLET_B;
        participants[2] = WALLET_A;
        ConversationEvidenceRegistry.Evidence memory evidence = _evidenceFor(participants);

        vm.expectRevert(abi.encodeWithSelector(ConversationEvidenceRegistry.InvalidSignature.selector, WALLET_C));
        registry.recordEvidence(evidence, participants, new bytes[](3));
    }

    /// @notice Against the real DojangScroll rather than a mock, a pair that is
    ///         unverified on both sides records as long as the signatures match.
    ///         Both flags stay false.
    function test_recordEvidence_recordsLocallySignedUnverifiedPair() public {
        uint256 firstKey = 0xA11CE;
        uint256 secondKey = 0xB0B;
        address firstSigner = vm.addr(firstKey);
        address secondSigner = vm.addr(secondKey);

        address[] memory participants = new address[](2);
        (participants[0], participants[1]) =
            uint160(firstSigner) < uint160(secondSigner) ? (firstSigner, secondSigner) : (secondSigner, firstSigner);
        _assertFalse(dojang.isVerified(participants[0], TESTNET_FAUCET_ATTESTER), "fixture signer must be unverified");
        _assertFalse(dojang.isVerified(participants[1], TESTNET_FAUCET_ATTESTER), "fixture signer must be unverified");

        ConversationEvidenceRegistry.Evidence memory evidence = _evidenceFor(participants);
        bytes32 digest = registry.hashEvidence(evidence);
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _sign(participants[0] == firstSigner ? firstKey : secondKey, digest);
        signatures[1] = _sign(participants[1] == firstSigner ? firstKey : secondKey, digest);

        bytes32 evidenceId = registry.recordEvidence(evidence, participants, signatures);

        _assertTrue(registry.evidenceExists(evidenceId), "unverified pair must be recorded");
        bool[] memory verified = registry.getEvidence(evidenceId).participantsVerified;
        _assertFalse(verified[0], "unverified participant flagged as verified");
        _assertFalse(verified[1], "unverified participant flagged as verified");
    }

    function _evidenceFor(address[] memory participants)
        private
        view
        returns (ConversationEvidenceRegistry.Evidence memory)
    {
        return ConversationEvidenceRegistry.Evidence({
            conversationHash: keccak256("fork-conversation"),
            contentHash: keccak256("fork-content"),
            participantsHash: registry.hashParticipants(participants),
            messageCount: uint32(participants.length),
            startedAt: uint64(block.timestamp - 60),
            endedAt: uint64(block.timestamp),
            nonce: keccak256("fork-nonce"),
            deadline: uint64(block.timestamp + 1 hours)
        });
    }

    function _sign(uint256 privateKey, bytes32 digest) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _assertTrue(bool value, string memory message) private pure {
        require(value, message);
    }

    function _assertFalse(bool value, string memory message) private pure {
        require(!value, message);
    }
}
