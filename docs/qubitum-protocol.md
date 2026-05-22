# Qubitum Protocol

Qubitum is a marketplace for private, verifiable AI inference. Miners run inference and proof generation, validators route requests and verify proofs on CPU, and users receive inference results backed by cryptographic proof records.

## Launch Milestones

1. ZKML prototype: Risc Zero zkVM integration, GPT-2 scale proof-generation benchmarks, and a single-subnet testnet.
2. Chain launch: staking, miner bonding, validator bootstrapping, and data availability integration.
3. Multi-subnet: permissionless subnet creation for specialized domains such as vision, code, and biology.
4. Post-quantum migration: hybrid Dilithium signatures, then full post-quantum account migration.

## Local Single-Subnet Flow

The protocol primitives include a runnable single-subnet scenario:

```sh
cargo run -p qubitum-protocol --example single_subnet
```

The example creates a QBT genesis ledger, burns QBT to create a subnet, registers and bonds a miner, registers and stakes a validator, verifies a proof through the mock verifier, records the inference, and settles user payment between miner, validator, and treasury.

## Runtime Wire Format

The core protocol structs and enums derive SCALE `Encode`/`Decode` plus `scale-info` metadata. That keeps the primitives usable for Substrate storage, extrinsics, runtime APIs, RPC metadata, and future migration tooling instead of being test-only Rust structs.

## FRAME Pallet Surface

`pallet-qubitum` provides the first on-chain surface for the protocol. It stores subnets, miners, validators, proof records, and total burned QBT using FRAME-native maps, and exposes dispatchables for subnet creation, miner registration and bonding, validator staking, proof record submission, and root-controlled miner slashing.

Current focused checks:

```sh
cargo test -p pallet-qubitum
cargo clippy -p pallet-qubitum --all-targets -- -D warnings
```

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

## Post-Quantum Signature Policy

The primitives encode three signature modes for migration:

- Classical launch mode: classical signatures are accepted for compatibility.
- Hybrid mode: transactions must carry both a classical signature commitment and a post-quantum signature commitment.
- Full post-quantum mode: post-quantum signature commitments are required without depending on a classical signature.
