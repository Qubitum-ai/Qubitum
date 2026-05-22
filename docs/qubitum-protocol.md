# Qubitum Protocol

Qubitum is a marketplace for private, verifiable AI inference. Miners run inference and proof generation, validators route requests and verify proofs on CPU, and users receive inference results backed by cryptographic proof records.

## Launch Milestones

1. ZKML prototype: Risc Zero zkVM integration, GPT-2 scale proof-generation benchmarks, and a single-subnet testnet.
2. Chain launch: staking, miner bonding, validator bootstrapping, and data availability integration.
3. Multi-subnet: permissionless subnet creation for specialized domains such as vision, code, and biology.
4. Post-quantum migration: hybrid Dilithium signatures, then full post-quantum account migration.

## Core Constants

- Token: QBT
- Initial supply: 21,000,000 QBT
- Halving interval: 4 years
- Emission split: 50% miners, 30% validators, 20% treasury
- Miner registration burn: 10 QBT
- Miner activation bond: 100-10,000 QBT
- Invalid proof slash: 10-100%
- Bond exit cooldown: 7 days
- Proof size target: 50-200 KB
- Verification target: under 100 ms on commodity CPU

## Privacy Contract

Model weights and inference inputs are private. The chain stores commitments and proof metadata, not raw inputs or model weights. Inference outputs are public or user-visible, and miner identity may be shielded through optional identity commitments.

Validators verify that inference executed correctly, that the committed model version was used, and that latency bounds were met. Validators do not learn model weights, raw inference input, or model internals.
