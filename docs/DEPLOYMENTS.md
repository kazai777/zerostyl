# Deployments

On-chain deployments of the ZeroStyl Stylus contracts.

## Arbitrum Sepolia (testnet)

| Contract | Purpose | Address |
|----------|---------|---------|
| `tx_privacy_verifier` | Private token transfers | [`0x0c61c2d2f15a2f26c13bbe9882e56d545f393bd3`](https://sepolia.arbiscan.io/address/0x0c61c2d2f15a2f26c13bbe9882e56d545f393bd3) |
| `state_mask_verifier` | Range-proof / state registry | [`0xf88346c0a80690a2f9d359f70d157fa36f1be7e0`](https://sepolia.arbiscan.io/address/0xf88346c0a80690a2f9d359f70d157fa36f1be7e0) |
| `private_vote_verifier` | Anonymous voting + tally | [`0xd21389dffe34235a9f8d6c4e88ac1fec70670edf`](https://sepolia.arbiscan.io/address/0xd21389dffe34235a9f8d6c4e88ac1fec70670edf) |
| `private_lending_pool` | Solvency proofs + liquidation | [`0xaa948bd92dbe5b1de9af384add42fc6859288f36`](https://sepolia.arbiscan.io/address/0xaa948bd92dbe5b1de9af384add42fc6859288f36) |
| `private_swap_verifier` | Multi-circuit private swaps | [`0xd5dfa87f650453dbb5f3da46b6faadf02134bb76`](https://sepolia.arbiscan.io/address/0xd5dfa87f650453dbb5f3da46b6faadf02134bb76) |

## Security status

These testnet deployments accept a `bytes32` proof hash and do **not** yet verify the SNARK
on-chain. Their integrity guarantees are conditional — see the "Honest Assessment" and
"Current Security Model" sections of [`../contracts/CONTRACTS.md`](../contracts/CONTRACTS.md)
before relying on them.

## Mainnet

None. ZeroStyl is not deployed to any mainnet.
