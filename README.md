# umul-contracts

Umul(Gasok) 대화 증빙 컨트랙트. 참여자 전원이 EIP-712 로 서명한 대화 해시를
GIWA Sepolia 에 기록한다. 대화 원문은 어디에도 저장하지 않는다.

[giwa-gasok/gasok](https://github.com/giwa-gasok/gasok) 의 `contracts/` 를
이력째 분리해 옮긴 저장소다. 앱과 문서는 원 저장소에 있다.

## 배포

| 항목 | 값 |
| --- | --- |
| 네트워크 | GIWA Sepolia (chain ID 91342) |
| 주소 | `0x675dB91aCEC52DCb44e6d20FB1F1299FFafBb51B` |
| DojangScroll | `0xd5077b67dcb56caC8b270C7788FC3E6ee03F17B9` |
| attester | TESTNET_FAUCET |
| 소스 검증 | Blockscout 완료 |

배포 산출물 전문은 `deployments/giwa-sepolia.json` 에 있다.

## 동작

`recordEvidence(evidence, participants, signatures)` 는 다음을 순서대로
확인한 뒤 기록한다.

1. 참여자 2명 이상, 서명 개수 일치, 필드 형태 검사
2. 참여자 배열이 오름차순이고 `participantsHash` 와 일치
3. EIP-712 digest 계산, `evidenceId` 미사용 확인 (리플레이 차단)
4. 참여자 전원 `DojangScroll.isVerified` 재확인
5. 각 서명이 digest 에서 해당 참여자 주소로 복구

원리와 실제 트랜잭션 해부는 원 저장소의
[증빙 컨트랙트 가이드](https://github.com/giwa-gasok/gasok/blob/main/docs/architecture/evidence-contract-guide.md)에
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
- 서명 후 Dojang 인증이 철회되거나 만료되면 제출이 거부된다
