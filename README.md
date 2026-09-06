# umul-contracts

Umul(Gasok) 대화 증빙 컨트랙트. 참여자 전원이 EIP-712 로 서명한 대화 해시를
GIWA Sepolia 에 기록한다. 대화 원문은 어디에도 저장하지 않는다.

[giwa-gasok/umul-app](https://github.com/giwa-gasok/umul-app) 의 `contracts/` 를
이력째 분리해 옮긴 저장소다. 앱과 문서는 원 저장소에 있다.

## 배포

| 항목 | 값 |
| --- | --- |
| 네트워크 | GIWA Sepolia (chain ID 91342) |
| 주소 | `0x6ffa0a783C722d1Ce4e16a9bb53162EE44626DAC` |
| DojangScroll | `0xd5077b67dcb56caC8b270C7788FC3E6ee03F17B9` |
| attester | TESTNET_FAUCET |
| 소스 검증 | Blockscout 완료 |

배포 산출물 전문은 `deployments/giwa-sepolia.json` 에 있다.

이전 배포본 `0x675dB91aCEC52DCb44e6d20FB1F1299FFafBb51B` 은 참여자 전원의 Dojang
인증을 강제하던 버전이다. 그 주소에 남은 기록은 전원 인증된 경우만 존재하지만,
새 주소의 기록은 `participantsVerified` 를 봐야 알 수 있다. 두 주소를 함께
조회한다면 이 차이를 드러내야 한다.

EIP-712 도메인에 컨트랙트 주소가 들어가므로 옛 주소로 모은 서명은 새 주소에서
무효다.

## 동작

`recordEvidence(evidence, participants, signatures)` 는 다음을 순서대로
확인한 뒤 기록한다.

1. 참여자 2명 이상, 서명 개수 일치, 필드 형태 검사
2. 참여자 배열이 오름차순이고 `participantsHash` 와 일치
3. EIP-712 digest 계산, `evidenceId` 미사용 확인 (리플레이 차단)
4. 각 서명이 digest 에서 해당 참여자 주소로 복구

## Dojang 인증

인증은 증빙의 **조건이 아니라 속성**이다. 기록 시점에 참여자마다
`DojangScroll.isVerified` 를 읽어 `participants` 와 같은 순서의 `bool[]` 로
`EvidenceRecord.participantsVerified` 와 `EvidenceRecorded` 이벤트에 남긴다.
미인증 지갑만으로 이루어진 대화도 서명이 맞으면 기록되고, 열람하는 쪽이
플래그를 보고 증빙의 무게를 판단한다.

스크롤 조회가 revert 하면 그 참여자는 미인증으로 읽는다. 조회 실패가 증빙
기록을 막으면 인증이 다시 조건이 되어 버리기 때문이다.

원리와 실제 트랜잭션 해부는 원 저장소의
[증빙 컨트랙트 가이드](https://github.com/giwa-gasok/umul-app/blob/main/docs/architecture/evidence-contract-guide.md)에
있다.

## 개발

Foundry 를 쓴다. `lib/` 는 커밋하지 않으며 테스트는 forge-std 없이 최소 `Vm`
인터페이스를 직접 선언한다.

```bash
forge fmt --check
forge test --no-match-contract ForkTest        # 단위와 퍼즈
GIWA_SEPOLIA_RPC_URL=https://sepolia-rpc.giwa.io \
  forge test --match-contract ForkTest          # 실제 체인 fork
```

## 구조

| 경로 | 내용 |
| --- | --- |
| `src/ConversationEvidenceRegistry.sol` | 증빙 레지스트리 본체 |
| `test/` | 단위, 퍼즈, GIWA Sepolia fork 테스트 |
| `script/` | 배포 스크립트 |
| `deployments/` | 네트워크별 배포 기록 |

## 한계

- P0 는 EOA 서명만 지원한다. EIP-1271 스마트 계정은 다음 단계다
- attester 는 생성자에서 고정된다. 바꾸려면 재배포해야 한다
- 인증 플래그는 기록 시점의 스냅샷이다. 이후 attestation 이 철회되거나
  만료돼도 기록된 `true` 는 그대로 남는다 (테스트넷 파우셋은 30일 만료)
