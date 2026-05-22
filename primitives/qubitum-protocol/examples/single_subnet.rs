use qubitum_protocol::{
    AccountId, Commitment, InferenceProofSubmission, MIN_MINER_BOND, MINER_REGISTRATION_BURN,
    MockVerifier, ProofSystem, ProtocolError, ProtocolState, SubnetDomain,
    TARGET_PROOF_SIZE_MIN_BYTES,
};

fn account(seed: u8) -> AccountId {
    [seed; 32]
}

fn commitment(seed: u8) -> Commitment {
    [seed; 32]
}

fn main() -> Result<(), ProtocolError> {
    let treasury = account(99);
    let subnet_owner = account(1);
    let miner_operator = account(2);
    let validator_operator = account(3);
    let user = account(4);
    let proof_commitment = commitment(44);

    let mut state = ProtocolState::with_genesis(
        treasury,
        &[
            (subnet_owner, 1_000_000_000_000_000),
            (miner_operator, 1_000_000_000_000_000),
            (validator_operator, 1_000_000_000_000_000),
            (user, 1_000_000_000_000_000),
        ],
    )?;

    let subnet_id =
        state.create_subnet(subnet_owner, SubnetDomain::Code, MINER_REGISTRATION_BURN)?;
    let miner_id = state.register_miner(
        miner_operator,
        subnet_id,
        commitment(10),
        ProofSystem::RiscZeroStark,
    )?;
    state.activate_miner(miner_id, MIN_MINER_BOND)?;
    let validator_id = state.register_validator(validator_operator, subnet_id, MIN_MINER_BOND)?;

    let result = state.process_proof(
        user,
        InferenceProofSubmission {
            request_id: 1,
            subnet_id,
            miner_id,
            validator_id,
            input_commitment: commitment(11),
            output_commitment: commitment(12),
            model_commitment: commitment(10),
            proof_commitment,
            proof_system: ProofSystem::RiscZeroStark,
            proof_size_bytes: TARGET_PROOF_SIZE_MIN_BYTES,
            verification_latency_ms: 17,
            submitted_at: 100,
        },
        1_000,
        250,
        50,
        &MockVerifier::expecting(proof_commitment),
    )?;

    println!("single-subnet proof result: {result:?}");
    println!("records: {}", state.records.len());
    println!("miner ledger: {:?}", state.ledger(&miner_operator));
    println!("validator ledger: {:?}", state.ledger(&validator_operator));
    println!("treasury ledger: {:?}", state.ledger(&treasury));

    Ok(())
}
