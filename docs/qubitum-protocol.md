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

## Node Chain Identity

The development and local chains now identify as Qubitum networks and expose QBT token metadata through the chain spec. A plain node start, `--chain dev`, `--chain qubitum`, and `--chain qubitum-dev` all resolve to the single-authority Qubitum local chain; `--chain qubitum-local` resolves to the multi-authority local chain; and `--chain qubitum-devnet` resolves to the checked-in devnet configuration.

Finney and test-Finney remain explicit legacy imports because those specs are backed by OpenTensor snapshots and bootnodes.

## Runtime Wire Format

The core protocol structs and enums derive SCALE `Encode`/`Decode` plus `scale-info` metadata. That keeps the primitives usable for Substrate storage, extrinsics, runtime APIs, RPC metadata, and future migration tooling instead of being test-only Rust structs.

## FRAME Pallet Surface

`pallet-qubitum` provides the first on-chain surface for the protocol. It stores subnets, miners, validators, inference requests, proof records, and total burned QBT using FRAME-native maps, and exposes dispatchables for subnet creation, miner registration and bonding, miner deactivation and bond withdrawal, validator staking and stake withdrawal, user inference escrow, proof record submission, and root-controlled participant slashing.

The pallet is wired into `node-subtensor-runtime` as `Qubitum`, with runtime-provided weights and a FRAME benchmarking suite for all dispatchables. Placeholder weights are isolated behind `pallet_qubitum::weights::WeightInfo` so generated benchmark output can replace them without changing call logic.

Users open inference requests by escrowing QBT against a request ID, subnet, assigned miner, assigned validator, input commitment, and fee split. The pallet verifies that the assigned miner and validator are active members of the subnet before holding funds. Valid proof submission must match the request assignment, then settles that held payment atomically: miner payment, validator fee, and protocol treasury fee are transferred from escrow, and the request status moves from pending to settled. Invalid verifier outcomes slash both the miner bond and validator stake without settling the user escrow. Pending requests can be cancelled by the request owner after the configured cancellation delay to release escrow.

Miners can exit by moving from active or slashed status into an on-chain cooldown. While exiting, they cannot submit new work, but their remaining held bond is still slashable. After the cooldown expires, the operator can withdraw the residual bond and the miner becomes disabled.

Validators use the same two-step exit pattern: active validators enter a stake cooldown, stop qualifying for proof submissions, and withdraw remaining stake only after the cooldown expires.

Root governance can slash miner bonds and validator stake within the configured invalid-proof slash bounds. Slashed participants are removed from active eligibility, but can still enter the exit cooldown and withdraw any residual held capital after the delay.

Proof submission is constrained to the registered validator operator for the submitted validator ID. The pallet rejects duplicate request IDs, requires an existing pending inference request, requires the submitted model commitment to match the registered miner commitment, validates the proof envelope, and routes every submission through `pallet_qubitum::VerifyProof` before storing a proof record. The current runtime uses a shape-only verifier adapter; a concrete Risc Zero verifier can replace that associated type without changing dispatchable semantics.

The proof envelope commits to the off-chain proof artifact without storing raw proof bytes on-chain:

- `proof_commitment`: receipt, seal, or external proof commitment
- `journal_commitment`: verifier-authenticated public journal commitment
- `image_id`: zkVM image id, verification key, or circuit id
- `verifier_version`: concrete verifier family and version, such as `RiscZeroV1`

This keeps block execution bounded while preserving enough metadata for validators, indexers, and future Risc Zero adapters to audit what was verified. Accepted proof records also retain proof system, proof size, verification latency, and chain-stamped submission block metadata for RPC consumers.

`pallet-qubitum-runtime-api` exposes typed runtime queries for subnet, miner, validator, inference-request, proof-record, registry-count, and total-burned state. `pallet-qubitum-rpc` wires those queries into node JSON-RPC methods under the `qubitum_*` namespace, returning SCALE-encoded bytes for complex structs and a direct balance for total burned state.

Runtime safe mode explicitly allows Qubitum `submit_proof` so already-routed verified work can keep settling, while blocking Qubitum subnet creation, participant registration, miner exits, new inference requests, and request cancellation until safe mode exits.

Current focused checks:

```sh
cargo test -p pallet-qubitum
cargo test -p pallet-qubitum --features runtime-benchmarks
cargo clippy -p pallet-qubitum --all-targets -- -D warnings
cargo check -p node-subtensor-runtime
cargo check -p node-subtensor-runtime --features runtime-benchmarks
cargo clippy -p pallet-qubitum-runtime-api -- -D warnings
cargo clippy -p pallet-qubitum-rpc -- -D warnings
cargo check -p node-subtensor
cargo test -p node-subtensor-runtime --test safe_mode
```

## Core Constants

- Token: QBT
- Initial supply: 21,000,000 QBT
- Halving interval: 4 years
- Emission split: 50% miners, 30% validators, 20% treasury
- Miner registration burn: 10 QBT
- Miner activation bond: 100-10,000 QBT
- Invalid proof slash: 10-100%
- Miner bond exit cooldown: 7 days in the current runtime
- Validator stake exit cooldown: 7 days in the current runtime
- Inference request cancellation delay: 50 blocks in the current runtime
- Proof size target: 50-200 KB
- Verification target: under 100 ms on commodity CPU

## Privacy Contract

Model weights and inference inputs are private. The chain stores commitments, proof-envelope metadata, and verifier version data, not raw inputs, proof bytes, journals, or model weights. Inference outputs are public or user-visible, and miner identity may be shielded through optional identity commitments.

Validators verify that inference executed correctly, that the committed model version was used, and that latency bounds were met. Validators do not learn model weights, raw inference input, or model internals.

## Post-Quantum Signature Policy

The primitives encode three signature modes for migration:

- Classical launch mode: classical signatures are accepted for compatibility.
- Hybrid mode: transactions must carry both a classical signature commitment and a post-quantum signature commitment.
- Full post-quantum mode: post-quantum signature commitments are required without depending on a classical signature.
