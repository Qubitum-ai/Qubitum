use frame_support::traits::Contains;
use node_subtensor_runtime::{RuntimeCall, SafeModeWhitelistedCalls};
use qubitum_protocol::{
    InferenceProofSubmission, ProofEnvelope, ProofSystem, SubnetDomain, TARGET_PROOF_SIZE_MIN_BYTES,
};

fn commitment(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn proof(seed: u8) -> ProofEnvelope {
    ProofEnvelope::risc_zero_v1(commitment(seed), commitment(seed + 1), commitment(seed + 2))
}

fn valid_submission() -> InferenceProofSubmission {
    InferenceProofSubmission {
        request_id: 1,
        subnet_id: 0,
        miner_id: 0,
        validator_id: 0,
        input_commitment: commitment(1),
        output_commitment: commitment(2),
        model_commitment: commitment(3),
        proof: proof(4),
        proof_system: ProofSystem::RiscZeroStark,
        proof_size_bytes: TARGET_PROOF_SIZE_MIN_BYTES,
        verification_latency_ms: 10,
        submitted_at: 1,
    }
}

#[test]
fn qubitum_submit_proof_is_allowed_in_safe_mode() {
    let call = RuntimeCall::Qubitum(pallet_qubitum::Call::submit_proof {
        submission: valid_submission(),
    });

    assert!(SafeModeWhitelistedCalls::contains(&call));
}

#[test]
fn qubitum_registration_is_blocked_in_safe_mode() {
    let call = RuntimeCall::Qubitum(pallet_qubitum::Call::create_subnet {
        domain: SubnetDomain::Code,
        proof_system: ProofSystem::RiscZeroStark,
    });

    assert!(!SafeModeWhitelistedCalls::contains(&call));
}

#[test]
fn qubitum_request_inference_is_blocked_in_safe_mode() {
    let call = RuntimeCall::Qubitum(pallet_qubitum::Call::request_inference {
        request_id: 1,
        params: pallet_qubitum::InferenceRequestParams {
            subnet_id: 0,
            miner_id: 0,
            validator_id: 0,
            input_commitment: commitment(1),
            payment: 1_000u64.into(),
            validator_fee_bps: 250,
            treasury_fee_bps: 50,
        },
    });

    assert!(!SafeModeWhitelistedCalls::contains(&call));
}

#[test]
fn qubitum_cancel_inference_is_blocked_in_safe_mode() {
    let call = RuntimeCall::Qubitum(pallet_qubitum::Call::cancel_inference { request_id: 1 });

    assert!(!SafeModeWhitelistedCalls::contains(&call));
}

#[test]
fn qubitum_expire_inference_is_blocked_in_safe_mode() {
    let call = RuntimeCall::Qubitum(pallet_qubitum::Call::expire_inference { request_id: 1 });

    assert!(!SafeModeWhitelistedCalls::contains(&call));
}

#[test]
fn qubitum_identity_commitments_are_blocked_in_safe_mode() {
    let miner = RuntimeCall::Qubitum(pallet_qubitum::Call::set_miner_identity_commitments {
        miner_id: 1,
        shielded_identity_commitment: Some(commitment(1)),
        endpoint_commitment: Some(commitment(2)),
    });
    let validator =
        RuntimeCall::Qubitum(pallet_qubitum::Call::set_validator_identity_commitments {
            validator_id: 1,
            shielded_identity_commitment: Some(commitment(3)),
            endpoint_commitment: Some(commitment(4)),
        });

    assert!(!SafeModeWhitelistedCalls::contains(&miner));
    assert!(!SafeModeWhitelistedCalls::contains(&validator));
}

#[test]
fn qubitum_miner_exit_is_blocked_in_safe_mode() {
    let deactivate = RuntimeCall::Qubitum(pallet_qubitum::Call::deactivate_miner { miner_id: 1 });
    let withdraw = RuntimeCall::Qubitum(pallet_qubitum::Call::withdraw_miner_bond { miner_id: 1 });

    assert!(!SafeModeWhitelistedCalls::contains(&deactivate));
    assert!(!SafeModeWhitelistedCalls::contains(&withdraw));
}

#[test]
fn qubitum_validator_exit_is_blocked_in_safe_mode() {
    let deactivate =
        RuntimeCall::Qubitum(pallet_qubitum::Call::deactivate_validator { validator_id: 1 });
    let withdraw =
        RuntimeCall::Qubitum(pallet_qubitum::Call::withdraw_validator_stake { validator_id: 1 });
    let slash = RuntimeCall::Qubitum(pallet_qubitum::Call::slash_validator {
        validator_id: 1,
        slash_bps: 1_000,
    });

    assert!(!SafeModeWhitelistedCalls::contains(&deactivate));
    assert!(!SafeModeWhitelistedCalls::contains(&withdraw));
    assert!(!SafeModeWhitelistedCalls::contains(&slash));
}
