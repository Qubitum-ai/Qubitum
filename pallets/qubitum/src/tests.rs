#![allow(clippy::arithmetic_side_effects, clippy::unwrap_used)]

use crate::{
    ActiveMinersBySubnet, ActiveValidatorsBySubnet, AutoRouteInferenceRequestParams,
    CancelledInferenceRequestCount, ChainInferenceRequest, ChainMiner, ChainPublicIdentity,
    ChainPublicInferenceRequest, ChainPublicMiner, ChainPublicProofRecord, ChainPublicSubnet,
    ChainPublicValidator, ChainReadinessBlockers, ChainRequestStatusCounts, ChainRouteAvailability,
    ChainValidator, Error, FailClosedProofVerifier, HoldReason, InferenceRequestCommitmentParams,
    InferenceRequestParams, InferenceRequestStatus, InferenceRequestTerms,
    InferenceRequestTermsWitness, InferenceRequestTimingWitness, InferenceRequests,
    LegacyAccountingMigrationFailures, LegacyCapitalRecordMigrationFailures,
    LegacyRoutingIndexMigrationFailures, MinerCount, MinerIdentityCommitments,
    MinerIdentitySignatureBundles, MinerIdentitySignatureChallenges, MinerLockedBond, Miners,
    PendingInferenceRequestCount, PendingMinerRequests, PendingValidatorRequests, ProofRecords,
    ProofVerificationPolicy, ProofVerifierMode, PublicRegistryStatus,
    RejectedInferenceRequestCount, RequestCount, SettledInferenceRequestCount, SubnetCount,
    Subnets, TotalBurned, TotalInferenceEscrowed, TotalInferenceRefunded, TotalMinerPayouts,
    TotalTreasuryFees, TotalValidatorFees, ValidatorCount, ValidatorIdentityCommitments,
    ValidatorIdentitySignatureBundles, ValidatorIdentitySignatureChallenges, ValidatorLockedStake,
    Validators, VerifyProof,
    mock::{
        Balances, Qubitum, RuntimeEvent, RuntimeOrigin, System, Test, new_test_ext,
        set_verification_outcome,
    },
};
use codec::Encode;
use frame_support::{
    assert_noop, assert_ok,
    traits::{Hooks, StorageVersion, fungible::InspectHold},
};
use qubitum_protocol::{
    InferenceProofSubmission, MAX_INVALID_PROOF_SLASH_BPS, MAX_MINER_BOND,
    MIN_INVALID_PROOF_SLASH_BPS, MIN_MINER_BOND, MINER_REGISTRATION_BURN, ProofEnvelope,
    ProofSystem, ProofVerifierVersion, RegistryStatus, SignatureAlgorithm, SignatureBundle,
    SignatureCommitment, SignatureMode, SubnetDomain, TARGET_PROOF_SIZE_MAX_BYTES,
    TARGET_PROOF_SIZE_MIN_BYTES, TARGET_VERIFICATION_MS, VerificationOutcome,
};

fn commitment(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn subnet_creation_burn() -> u128 {
    <Test as crate::Config>::SubnetCreationBurn::get()
}

fn assignment_blinding() -> [u8; 32] {
    commitment(90)
}

fn timing_blinding() -> [u8; 32] {
    commitment(92)
}

fn terms_blinding() -> [u8; 32] {
    commitment(91)
}

fn proof(seed: u8) -> ProofEnvelope {
    ProofEnvelope::risc_zero_v1(commitment(seed), commitment(seed + 1), commitment(seed + 2))
}

fn signature(algorithm: SignatureAlgorithm, seed: u8) -> SignatureCommitment {
    SignatureCommitment {
        algorithm,
        public_key_commitment: commitment(seed),
        signature_commitment: commitment(seed.saturating_add(1)),
    }
}

fn challenge_bound_signature(
    algorithm: SignatureAlgorithm,
    seed: u8,
    challenge: [u8; 32],
) -> SignatureCommitment {
    let unsigned = SignatureCommitment {
        algorithm,
        public_key_commitment: commitment(seed),
        signature_commitment: [0; 32],
    };
    SignatureCommitment {
        signature_commitment: Qubitum::identity_signature_binding(challenge, unsigned),
        ..unsigned
    }
}

fn classical_signature_bundle() -> SignatureBundle {
    SignatureBundle {
        classical: Some(signature(SignatureAlgorithm::Ecdsa, 30)),
        post_quantum: None,
    }
}

fn post_quantum_signature_bundle() -> SignatureBundle {
    SignatureBundle {
        classical: None,
        post_quantum: Some(signature(SignatureAlgorithm::Dilithium3, 40)),
    }
}

fn post_quantum_signature_bundle_for_challenge(challenge: [u8; 32]) -> SignatureBundle {
    SignatureBundle {
        classical: None,
        post_quantum: Some(challenge_bound_signature(
            SignatureAlgorithm::Dilithium3,
            40,
            challenge,
        )),
    }
}

fn miner_identity_signature_bundle(
    miner_id: u64,
    shielded_identity_commitment: Option<[u8; 32]>,
    endpoint_commitment: Option<[u8; 32]>,
) -> SignatureBundle {
    let miner = Miners::<Test>::get(miner_id).unwrap();
    let challenge = Qubitum::miner_identity_signature_challenge(
        miner_id,
        miner.operator_commitment,
        shielded_identity_commitment,
        endpoint_commitment,
    );
    post_quantum_signature_bundle_for_challenge(challenge)
}

fn validator_identity_signature_bundle(
    validator_id: u64,
    shielded_identity_commitment: Option<[u8; 32]>,
    endpoint_commitment: Option<[u8; 32]>,
) -> SignatureBundle {
    let validator = Validators::<Test>::get(validator_id).unwrap();
    let challenge = Qubitum::validator_identity_signature_challenge(
        validator_id,
        validator.operator_commitment,
        shielded_identity_commitment,
        endpoint_commitment,
    );
    post_quantum_signature_bundle_for_challenge(challenge)
}

fn dual_signature_bundle() -> SignatureBundle {
    SignatureBundle {
        classical: Some(signature(SignatureAlgorithm::Ecdsa, 30)),
        post_quantum: Some(signature(SignatureAlgorithm::Dilithium3, 40)),
    }
}

fn zero_signature_bundle() -> SignatureBundle {
    SignatureBundle {
        classical: Some(SignatureCommitment {
            algorithm: SignatureAlgorithm::Ecdsa,
            public_key_commitment: [0; 32],
            signature_commitment: commitment(31),
        }),
        post_quantum: None,
    }
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[derive(Encode)]
struct LegacyChainProofRecordV4 {
    request_id: u64,
    subnet_id: u16,
    miner_id: u64,
    validator_id: u64,
    input_commitment: [u8; 32],
    output_commitment: [u8; 32],
    model_commitment: [u8; 32],
    proof: ProofEnvelope,
    proof_system: ProofSystem,
    proof_size_bytes: u32,
    verification_latency_ms: u32,
    submitted_at: u64,
}

#[derive(Encode)]
struct LegacyChainProofRecordV11 {
    request_id: u64,
    subnet_id: u16,
    miner_id: u64,
    validator_id: u64,
    input_commitment: [u8; 32],
    output_commitment: [u8; 32],
    model_commitment: [u8; 32],
    proof: ProofEnvelope,
    proof_system: ProofSystem,
    proof_size_bytes: u32,
    verification_latency_ms: u32,
    submitted_at: u64,
    accepted_at: u64,
}

#[derive(Encode)]
struct LegacyChainProofRecordV14 {
    request_id: u64,
    subnet_id: u16,
    assignment_commitment: [u8; 32],
    input_commitment: [u8; 32],
    output_commitment: [u8; 32],
    model_commitment: [u8; 32],
    proof: ProofEnvelope,
    proof_system: ProofSystem,
    proof_size_bytes: u32,
    verification_latency_ms: u32,
    submitted_at: u64,
    accepted_at: u64,
}

#[derive(Encode)]
struct LegacyChainSubnetV15 {
    id: u16,
    owner: u64,
    domain: SubnetDomain,
    proof_system: ProofSystem,
    creation_burn: u128,
    min_miner_bond: u128,
    max_miner_bond: u128,
    min_validator_stake: u128,
    active: bool,
}

#[derive(Encode)]
struct LegacyChainMinerV7 {
    id: u64,
    operator: u64,
    subnet_id: u16,
    model_commitment: [u8; 32],
    proof_system: ProofSystem,
    bond: u128,
    status: RegistryStatus,
}

#[derive(Encode)]
struct LegacyChainValidatorV7 {
    id: u64,
    operator: u64,
    subnet_id: u16,
    stake: u128,
    status: RegistryStatus,
}

#[derive(Encode)]
struct LegacyChainMinerV9 {
    id: u64,
    operator_commitment: [u8; 32],
    subnet_id: u16,
    model_commitment: [u8; 32],
    proof_system: ProofSystem,
    bond: u128,
    status: RegistryStatus,
}

#[derive(Encode)]
struct LegacyChainValidatorV9 {
    id: u64,
    operator_commitment: [u8; 32],
    subnet_id: u16,
    stake: u128,
    status: RegistryStatus,
}

#[derive(Encode)]
struct LegacyChainInferenceRequestV8 {
    request_id: u64,
    user: u64,
    subnet_id: u16,
    miner_id: u64,
    validator_id: u64,
    input_commitment: [u8; 32],
    payment: u128,
    validator_fee_bps: u16,
    treasury_fee_bps: u16,
    created_at: u64,
    status: InferenceRequestStatus,
}

#[derive(Encode)]
struct LegacyChainInferenceRequestV10 {
    request_id: u64,
    user_commitment: [u8; 32],
    subnet_id: u16,
    miner_id: u64,
    validator_id: u64,
    input_commitment: [u8; 32],
    payment: u128,
    validator_fee_bps: u16,
    treasury_fee_bps: u16,
    created_at: u64,
    status: InferenceRequestStatus,
}

#[derive(Encode)]
struct LegacyChainInferenceRequestV12 {
    request_id: u64,
    user_commitment: [u8; 32],
    subnet_id: u16,
    assignment_commitment: [u8; 32],
    input_commitment: [u8; 32],
    payment: u128,
    validator_fee_bps: u16,
    treasury_fee_bps: u16,
    created_at: u64,
    status: InferenceRequestStatus,
}

#[derive(Encode)]
struct LegacyChainInferenceRequestV13 {
    request_id: u64,
    user_commitment: [u8; 32],
    subnet_id: u16,
    assignment_commitment: [u8; 32],
    input_commitment: [u8; 32],
    payment: u128,
    validator_fee_bps: u16,
    treasury_fee_bps: u16,
    timing_commitment: [u8; 32],
    status: InferenceRequestStatus,
}

fn register_active_miner_and_validator() {
    assert_ok!(Qubitum::create_subnet(
        RuntimeOrigin::signed(1),
        SubnetDomain::Code,
        ProofSystem::RiscZeroStark
    ));
    assert_ok!(Qubitum::register_miner(
        RuntimeOrigin::signed(2),
        0,
        commitment(10),
        ProofSystem::RiscZeroStark
    ));
    assert_ok!(Qubitum::activate_miner(
        RuntimeOrigin::signed(2),
        0,
        MIN_MINER_BOND
    ));
    assert_ok!(Qubitum::register_validator(
        RuntimeOrigin::signed(3),
        0,
        MIN_MINER_BOND
    ));
    attest_active_miner_and_validator();
}

fn attest_active_miner_and_validator() {
    assert_ok!(Qubitum::set_miner_identity_commitments(
        RuntimeOrigin::signed(2),
        0,
        Some(commitment(120)),
        Some(commitment(121)),
        miner_identity_signature_bundle(0, Some(commitment(120)), Some(commitment(121))),
    ));
    assert_ok!(Qubitum::set_validator_identity_commitments(
        RuntimeOrigin::signed(3),
        0,
        Some(commitment(122)),
        Some(commitment(123)),
        validator_identity_signature_bundle(0, Some(commitment(122)), Some(commitment(123))),
    ));
}

fn valid_submission(request_id: u64) -> InferenceProofSubmission {
    bind_proof_transcript(InferenceProofSubmission {
        request_id,
        subnet_id: 0,
        miner_id: 0,
        validator_id: 0,
        input_commitment: commitment(1),
        output_commitment: commitment(2),
        model_commitment: commitment(10),
        proof: proof(11),
        proof_system: ProofSystem::RiscZeroStark,
        proof_size_bytes: TARGET_PROOF_SIZE_MIN_BYTES,
        verification_latency_ms: 10,
        submitted_at: System::block_number(),
    })
}

fn bind_proof_transcript(mut submission: InferenceProofSubmission) -> InferenceProofSubmission {
    submission.proof.journal_commitment = Qubitum::proof_transcript_commitment(&submission);
    submission
}

fn request_inference(request_id: u64) {
    RequestCount::<Test>::put(request_id);
    assert_ok!(Qubitum::request_inference(
        RuntimeOrigin::signed(4),
        request_id,
        InferenceRequestParams {
            subnet_id: 0,
            miner_id: 0,
            validator_id: 0,
            input_commitment: commitment(1),
            assignment_blinding: assignment_blinding(),
            timing_blinding: timing_blinding(),
            terms_blinding: terms_blinding(),
            payment: 1_000,
            validator_fee_bps: 250,
            treasury_fee_bps: 50,
        },
    ));
}

fn request_terms() -> InferenceRequestTerms<u128> {
    inference_terms(1_000, 250, 50)
}

fn request_terms_witness() -> InferenceRequestTermsWitness<u128> {
    terms_witness(request_terms(), terms_blinding())
}

fn timing_witness(created_at: u64) -> InferenceRequestTimingWitness {
    InferenceRequestTimingWitness {
        created_at,
        blinding: timing_blinding(),
    }
}

fn legacy_timing_witness(created_at: u64) -> InferenceRequestTimingWitness {
    InferenceRequestTimingWitness {
        created_at,
        blinding: [0; 32],
    }
}

fn inference_terms(
    payment: u128,
    validator_fee_bps: u16,
    treasury_fee_bps: u16,
) -> InferenceRequestTerms<u128> {
    InferenceRequestTerms {
        payment,
        validator_fee_bps,
        treasury_fee_bps,
    }
}

fn terms_witness(
    terms: InferenceRequestTerms<u128>,
    blinding: [u8; 32],
) -> InferenceRequestTermsWitness<u128> {
    InferenceRequestTermsWitness { terms, blinding }
}

fn expected_miner_bond_commitment(
    miner_id: u64,
    operator: u64,
    status: RegistryStatus,
) -> [u8; 32] {
    Qubitum::miner_bond_commitment(miner_id, Qubitum::operator_commitment(&operator), status)
}

fn expected_validator_stake_commitment(
    validator_id: u64,
    operator: u64,
    status: RegistryStatus,
) -> [u8; 32] {
    Qubitum::validator_stake_commitment(
        validator_id,
        Qubitum::operator_commitment(&operator),
        status,
    )
}

fn submit_proof(
    origin: RuntimeOrigin,
    submission: InferenceProofSubmission,
) -> Result<(), sp_runtime::DispatchError> {
    Qubitum::submit_proof(
        origin,
        submission,
        4,
        2,
        assignment_blinding(),
        request_terms_witness(),
    )
}

fn challenge_proof(
    origin: RuntimeOrigin,
    submission: InferenceProofSubmission,
) -> Result<(), sp_runtime::DispatchError> {
    Qubitum::challenge_proof(
        origin,
        submission,
        4,
        2,
        assignment_blinding(),
        request_terms_witness(),
    )
}

#[test]
fn create_subnet_burns_qbt_and_commits_owner_and_policy() {
    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::Code,
            ProofSystem::RiscZeroStark
        ));

        let subnet = Subnets::<Test>::get(0).unwrap();
        assert_eq!(
            subnet.owner_commitment,
            Qubitum::subnet_owner_commitment(&1)
        );
        assert_ne!(subnet.owner_commitment, Qubitum::account_commitment(&1));
        assert_eq!(subnet.domain, SubnetDomain::Code);
        assert_eq!(subnet.proof_system, ProofSystem::RiscZeroStark);
        assert_eq!(
            subnet.policy_commitment,
            Qubitum::subnet_policy_commitment(0, SubnetDomain::Code, ProofSystem::RiscZeroStark)
        );
        assert!(!contains_subsequence(&subnet.encode(), &1_u64.encode()));
        assert!(!contains_subsequence(
            &subnet.encode(),
            &subnet_creation_burn().encode()
        ));
        assert!(!contains_subsequence(
            &subnet.encode(),
            &MIN_MINER_BOND.encode()
        ));
        assert_eq!(SubnetCount::<Test>::get(), 1);
        assert_eq!(TotalBurned::<Test>::get(), subnet_creation_burn());
        assert_eq!(
            Balances::free_balance(1),
            1_000_000_000_000_000 - subnet_creation_burn()
        );
    });
}

#[test]
fn create_subnet_rejects_mock_or_external_proof_systems_without_burn() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Qubitum::create_subnet(
                RuntimeOrigin::signed(1),
                SubnetDomain::Code,
                ProofSystem::Mock
            ),
            Error::<Test>::UnsupportedProofSystem
        );
        assert_noop!(
            Qubitum::create_subnet(
                RuntimeOrigin::signed(1),
                SubnetDomain::Code,
                ProofSystem::External(7)
            ),
            Error::<Test>::UnsupportedProofSystem
        );

        assert_eq!(SubnetCount::<Test>::get(), 0);
        assert_eq!(TotalBurned::<Test>::get(), 0);
        assert_eq!(Balances::free_balance(1), 1_000_000_000_000_000);
    });
}

#[test]
fn public_subnet_view_redacts_owner_and_economic_policy() {
    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(4),
            SubnetDomain::Code,
            ProofSystem::RiscZeroStark
        ));

        let public_subnet = Qubitum::public_subnet(0).unwrap();
        assert_eq!(
            public_subnet,
            ChainPublicSubnet {
                id: 0,
                domain: SubnetDomain::Code,
                proof_system: ProofSystem::RiscZeroStark,
                active: true,
            }
        );

        let encoded_subnet = public_subnet.encode();
        for hidden in [
            4_u64.encode(),
            subnet_creation_burn().encode(),
            MINER_REGISTRATION_BURN.encode(),
            MIN_MINER_BOND.encode(),
            MAX_MINER_BOND.encode(),
        ] {
            assert!(!contains_subsequence(&encoded_subnet, &hidden));
        }
    });
}

#[test]
fn protocol_params_expose_runtime_policy() {
    new_test_ext().execute_with(|| {
        let params = Qubitum::protocol_params();

        assert_eq!(params.subnet_creation_burn, subnet_creation_burn());
        assert_eq!(params.miner_registration_burn, MINER_REGISTRATION_BURN);
        assert_eq!(params.min_miner_bond, MIN_MINER_BOND);
        assert_eq!(params.max_miner_bond, MAX_MINER_BOND);
        assert_eq!(params.max_active_miners_per_subnet, 16);
        assert_eq!(params.max_active_validators_per_subnet, 32);
        assert_eq!(params.min_validator_stake, MIN_MINER_BOND);
        assert_eq!(
            params.min_invalid_proof_slash_bps,
            MIN_INVALID_PROOF_SLASH_BPS
        );
        assert_eq!(
            params.max_invalid_proof_slash_bps,
            MAX_INVALID_PROOF_SLASH_BPS
        );
        assert_eq!(params.min_proof_size_bytes, TARGET_PROOF_SIZE_MIN_BYTES);
        assert_eq!(params.max_proof_size_bytes, TARGET_PROOF_SIZE_MAX_BYTES);
        assert_eq!(params.max_verification_latency_ms, TARGET_VERIFICATION_MS);
        assert_eq!(params.max_proof_submission_age_blocks, 10);
        assert_eq!(params.proof_verifier_mode, ProofVerifierMode::TestOnly);
        assert!(params.proof_settlement_enabled);
        assert!(!params.production_zk_verifier);
        assert_eq!(params.signature_mode, SignatureMode::FullPostQuantum);
        assert!(!params.committed_request_payloads);
        assert!(!params.shielded_call_payloads);
        assert!(!params.shield_submitter_origin_privacy);
        assert!(!params.shield_key_window_privacy);
        assert!(!params.private_route_selection);
        assert!(!params.account_commitment_blinding);
        assert!(!params.private_routing_indexes);
        assert!(!params.private_capital_accounting);
        assert!(!params.private_event_metadata);
        assert!(!params.post_quantum_account_signatures);
        assert!(!params.post_quantum_signature_crypto_verification);
        assert!(!params.privacy_complete);
        assert!(!params.post_quantum_complete);
        assert!(!params.production_ready);
        assert!(params.identity_signature_commitment_policy);
        assert!(params.identity_signature_challenge_binding);
        assert!(!params.identity_signature_verification);
        assert_eq!(
            params.readiness_blockers,
            ChainReadinessBlockers {
                proof_settlement_disabled: false,
                production_zk_verifier_missing: true,
                committed_request_payloads_missing: true,
                shielded_call_payloads_missing: true,
                shield_submitter_origin_privacy_missing: true,
                shield_key_window_privacy_missing: true,
                private_route_selection_missing: true,
                account_commitment_blinding_missing: true,
                private_routing_indexes_missing: true,
                private_capital_accounting_missing: true,
                private_event_metadata_missing: true,
                signature_mode_not_full_post_quantum: false,
                post_quantum_account_signatures_missing: true,
                post_quantum_signature_crypto_verification_missing: true,
                identity_signature_verification_missing: true,
                external_audit_missing: true,
            }
        );
        assert!(params.readiness_blockers.privacy_blocked());
        assert!(params.readiness_blockers.post_quantum_blocked());
        assert!(params.readiness_blockers.production_blocked());
        assert_eq!(
            params.privacy_complete,
            !params.readiness_blockers.privacy_blocked()
        );
        assert_eq!(
            params.post_quantum_complete,
            !params.readiness_blockers.post_quantum_blocked()
        );
        assert_eq!(
            params.production_ready,
            !params.readiness_blockers.production_blocked()
        );
        assert_eq!(params.miner_exit_cooldown_blocks, 20);
        assert_eq!(params.validator_exit_cooldown_blocks, 20);
        assert_eq!(params.request_cancel_delay_blocks, 10);
    });
}

#[test]
fn protocol_params_flag_public_storage_linkability_gaps() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();

        let params = Qubitum::protocol_params();
        assert!(!params.shield_submitter_origin_privacy);
        assert!(!params.shield_key_window_privacy);
        assert!(!params.account_commitment_blinding);
        assert!(!params.private_routing_indexes);
        assert!(!params.private_capital_accounting);
        assert!(!params.private_event_metadata);
        assert!(
            params
                .readiness_blockers
                .shield_submitter_origin_privacy_missing
        );
        assert!(params.readiness_blockers.shield_key_window_privacy_missing);
        assert!(
            params
                .readiness_blockers
                .account_commitment_blinding_missing
        );
        assert!(params.readiness_blockers.private_routing_indexes_missing);
        assert!(params.readiness_blockers.private_capital_accounting_missing);
        assert!(params.readiness_blockers.private_event_metadata_missing);
        assert!(params.readiness_blockers.privacy_blocked());

        assert_eq!(
            Miners::<Test>::get(0).unwrap().operator_commitment,
            Qubitum::operator_commitment(&2)
        );
        assert_eq!(
            Validators::<Test>::get(0).unwrap().operator_commitment,
            Qubitum::operator_commitment(&3)
        );
        assert_eq!(MinerLockedBond::<Test>::get(0), Some(MIN_MINER_BOND));
        assert_eq!(ValidatorLockedStake::<Test>::get(0), Some(MIN_MINER_BOND));
        assert_eq!(ActiveMinersBySubnet::<Test>::get(0).to_vec(), vec![0]);
        assert_eq!(ActiveValidatorsBySubnet::<Test>::get(0).to_vec(), vec![0]);
    });
}

#[test]
fn protocol_params_are_policy_only_across_state_transitions() {
    new_test_ext().execute_with(|| {
        let baseline = Qubitum::protocol_params();

        register_active_miner_and_validator();
        assert_eq!(Qubitum::protocol_params(), baseline);

        request_inference(73);
        assert_eq!(Qubitum::protocol_params(), baseline);

        assert_ok!(submit_proof(RuntimeOrigin::signed(3), valid_submission(73)));
        assert_eq!(Qubitum::protocol_params(), baseline);
    });

    new_test_ext().execute_with(|| {
        let baseline = Qubitum::protocol_params();

        register_active_miner_and_validator();
        request_inference(74);
        set_verification_outcome(VerificationOutcome::Invalid { slash_bps: 1_000 });
        assert_ok!(submit_proof(RuntimeOrigin::signed(3), valid_submission(74)));

        assert_eq!(Qubitum::protocol_params(), baseline);
    });

    new_test_ext().execute_with(|| {
        let baseline = Qubitum::protocol_params();

        register_active_miner_and_validator();
        request_inference(75);
        System::set_block_number(10);
        assert_ok!(Qubitum::cancel_inference(
            RuntimeOrigin::signed(4),
            75,
            0,
            0,
            assignment_blinding(),
            timing_witness(0),
            request_terms_witness()
        ));

        assert_eq!(Qubitum::protocol_params(), baseline);
    });

    new_test_ext().execute_with(|| {
        let baseline = Qubitum::protocol_params();

        register_active_miner_and_validator();
        request_inference(76);
        System::set_block_number(10);
        assert_ok!(Qubitum::expire_inference(
            RuntimeOrigin::signed(5),
            76,
            4,
            0,
            0,
            assignment_blinding(),
            timing_witness(0),
            request_terms_witness()
        ));

        assert_eq!(Qubitum::protocol_params(), baseline);
    });
}

#[test]
fn routing_requires_post_quantum_identity_bundles() {
    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::Code,
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::register_miner(
            RuntimeOrigin::signed(2),
            0,
            commitment(10),
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::activate_miner(
            RuntimeOrigin::signed(2),
            0,
            MIN_MINER_BOND
        ));
        assert_ok!(Qubitum::register_validator(
            RuntimeOrigin::signed(3),
            0,
            MIN_MINER_BOND
        ));

        assert_eq!(
            Qubitum::next_route_availability(0),
            ChainRouteAvailability {
                request_id: 0,
                subnet_id: 0,
                available: false,
            }
        );
        assert_noop!(
            Qubitum::request_inference(
                RuntimeOrigin::signed(4),
                0,
                InferenceRequestParams {
                    subnet_id: 0,
                    miner_id: 0,
                    validator_id: 0,
                    input_commitment: commitment(1),
                    assignment_blinding: assignment_blinding(),
                    timing_blinding: timing_blinding(),
                    terms_blinding: terms_blinding(),
                    payment: 1_000,
                    validator_fee_bps: 250,
                    treasury_fee_bps: 50,
                },
            ),
            Error::<Test>::NoRouteAvailable
        );

        assert_ok!(Qubitum::set_miner_identity_commitments(
            RuntimeOrigin::signed(2),
            0,
            Some(commitment(120)),
            Some(commitment(121)),
            miner_identity_signature_bundle(0, Some(commitment(120)), Some(commitment(121))),
        ));
        assert!(!Qubitum::next_route_availability(0).available);

        assert_ok!(Qubitum::set_validator_identity_commitments(
            RuntimeOrigin::signed(3),
            0,
            Some(commitment(122)),
            Some(commitment(123)),
            validator_identity_signature_bundle(0, Some(commitment(122)), Some(commitment(123))),
        ));
        assert!(Qubitum::next_route_availability(0).available);
        assert_ok!(Qubitum::request_inference(
            RuntimeOrigin::signed(4),
            0,
            InferenceRequestParams {
                subnet_id: 0,
                miner_id: 0,
                validator_id: 0,
                input_commitment: commitment(1),
                assignment_blinding: assignment_blinding(),
                timing_blinding: timing_blinding(),
                terms_blinding: terms_blinding(),
                payment: 1_000,
                validator_fee_bps: 250,
                treasury_fee_bps: 50,
            },
        ));
    });
}

#[test]
fn proof_submission_requires_current_post_quantum_identity_bundles() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(87);
        MinerIdentitySignatureBundles::<Test>::remove(0);

        assert_noop!(
            submit_proof(RuntimeOrigin::signed(3), valid_submission(87)),
            Error::<Test>::MissingSignatureBundle
        );

        assert!(ProofRecords::<Test>::get(87).is_none());
        assert_eq!(
            InferenceRequests::<Test>::get(87).unwrap().status,
            InferenceRequestStatus::Pending
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            1_000
        );
        assert_eq!(PendingMinerRequests::<Test>::get(0), 1);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 1);
    });
}

#[test]
fn register_and_activate_miner_locks_bond() {
    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::General,
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::register_miner(
            RuntimeOrigin::signed(2),
            0,
            commitment(10),
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::activate_miner(
            RuntimeOrigin::signed(2),
            0,
            MIN_MINER_BOND
        ));

        let miner = Miners::<Test>::get(0).unwrap();
        assert_eq!(miner.status, RegistryStatus::Active);
        assert_eq!(
            miner.bond_commitment,
            expected_miner_bond_commitment(0, 2, RegistryStatus::Active)
        );
        assert_eq!(MinerCount::<Test>::get(), 1);
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2),
            MIN_MINER_BOND
        );
        assert_eq!(
            TotalBurned::<Test>::get(),
            subnet_creation_burn() + MINER_REGISTRATION_BURN
        );
    });
}

#[test]
fn participant_capital_commitments_do_not_dictionary_encode_amounts() {
    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::General,
            ProofSystem::RiscZeroStark
        ));
        for model in [10, 11] {
            assert_ok!(Qubitum::register_miner(
                RuntimeOrigin::signed(2),
                0,
                commitment(model),
                ProofSystem::RiscZeroStark
            ));
        }
        assert_ok!(Qubitum::activate_miner(
            RuntimeOrigin::signed(2),
            0,
            MIN_MINER_BOND
        ));
        assert_ok!(Qubitum::activate_miner(
            RuntimeOrigin::signed(2),
            1,
            MIN_MINER_BOND
        ));
        assert_ok!(Qubitum::register_validator(
            RuntimeOrigin::signed(3),
            0,
            MIN_MINER_BOND
        ));
        assert_ok!(Qubitum::register_validator(
            RuntimeOrigin::signed(3),
            0,
            MIN_MINER_BOND
        ));

        let miner_0 = Miners::<Test>::get(0).unwrap();
        let miner_1 = Miners::<Test>::get(1).unwrap();
        let validator_0 = Validators::<Test>::get(0).unwrap();
        let validator_1 = Validators::<Test>::get(1).unwrap();
        let dictionary_amount_hash = Qubitum::balance_commitment(MIN_MINER_BOND);

        assert_ne!(miner_0.bond_commitment, dictionary_amount_hash);
        assert_ne!(miner_1.bond_commitment, dictionary_amount_hash);
        assert_ne!(miner_0.bond_commitment, miner_1.bond_commitment);
        assert_ne!(validator_0.stake_commitment, dictionary_amount_hash);
        assert_ne!(validator_1.stake_commitment, dictionary_amount_hash);
        assert_ne!(validator_0.stake_commitment, validator_1.stake_commitment);
    });
}

#[test]
fn activate_miner_rejects_bad_operator_and_bad_bond() {
    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::General,
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::register_miner(
            RuntimeOrigin::signed(2),
            0,
            commitment(10),
            ProofSystem::RiscZeroStark
        ));

        assert_noop!(
            Qubitum::activate_miner(RuntimeOrigin::signed(3), 0, MIN_MINER_BOND),
            Error::<Test>::NotOperator
        );
        assert_noop!(
            Qubitum::activate_miner(RuntimeOrigin::signed(2), 0, MAX_MINER_BOND + 1),
            Error::<Test>::InvalidBond
        );
    });
}

#[test]
fn activate_miner_rejects_duplicate_activation() {
    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::General,
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::register_miner(
            RuntimeOrigin::signed(2),
            0,
            commitment(10),
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::activate_miner(
            RuntimeOrigin::signed(2),
            0,
            MIN_MINER_BOND
        ));

        assert_noop!(
            Qubitum::activate_miner(RuntimeOrigin::signed(2), 0, MIN_MINER_BOND),
            Error::<Test>::InvalidMinerStatus
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2),
            MIN_MINER_BOND
        );
    });
}

#[test]
fn miner_exit_requires_cooldown_and_releases_bond() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();

        assert_noop!(
            Qubitum::deactivate_miner(RuntimeOrigin::signed(3), 0),
            Error::<Test>::NotOperator
        );
        assert_ok!(Qubitum::deactivate_miner(RuntimeOrigin::signed(2), 0));

        let miner = Miners::<Test>::get(0).unwrap();
        assert_eq!(
            miner.status,
            RegistryStatus::Exiting {
                exit_available_at: 20
            }
        );

        assert_noop!(
            Qubitum::withdraw_miner_bond(RuntimeOrigin::signed(2), 0),
            Error::<Test>::MinerExitUnavailable
        );

        System::set_block_number(20);
        assert_ok!(Qubitum::withdraw_miner_bond(RuntimeOrigin::signed(2), 0));

        let miner = Miners::<Test>::get(0).unwrap();
        assert_eq!(miner.status, RegistryStatus::Disabled);
        assert_eq!(
            miner.bond_commitment,
            expected_miner_bond_commitment(0, 2, RegistryStatus::Disabled)
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2),
            0
        );
        assert_noop!(
            Qubitum::deactivate_miner(RuntimeOrigin::signed(2), 0),
            Error::<Test>::InvalidMinerStatus
        );
    });
}

#[test]
fn slashed_miner_can_exit_with_remaining_bond() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        assert_ok!(Qubitum::slash_miner(RuntimeOrigin::root(), 0, 2, 1_000));

        assert_ok!(Qubitum::deactivate_miner(RuntimeOrigin::signed(2), 0));
        System::set_block_number(20);
        assert_ok!(Qubitum::withdraw_miner_bond(RuntimeOrigin::signed(2), 0));

        let miner = Miners::<Test>::get(0).unwrap();
        assert_eq!(miner.status, RegistryStatus::Disabled);
        assert_eq!(
            miner.bond_commitment,
            expected_miner_bond_commitment(0, 2, RegistryStatus::Disabled)
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2),
            0
        );
    });
}

#[test]
fn root_slash_burns_held_validator_stake() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();

        assert_ok!(Qubitum::slash_validator(RuntimeOrigin::root(), 0, 3, 1_000));

        let validator = Validators::<Test>::get(0).unwrap();
        assert_eq!(
            validator.stake_commitment,
            expected_validator_stake_commitment(0, 3, RegistryStatus::Slashed)
        );
        assert_eq!(validator.status, RegistryStatus::Slashed);
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::ValidatorStake.into(), &3),
            90_000_000_000
        );
    });
}

#[test]
fn slashed_validator_can_exit_with_remaining_stake() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        assert_ok!(Qubitum::slash_validator(RuntimeOrigin::root(), 0, 3, 1_000));

        assert_ok!(Qubitum::deactivate_validator(RuntimeOrigin::signed(3), 0));
        System::set_block_number(20);
        assert_ok!(Qubitum::withdraw_validator_stake(
            RuntimeOrigin::signed(3),
            0
        ));

        let validator = Validators::<Test>::get(0).unwrap();
        assert_eq!(validator.status, RegistryStatus::Disabled);
        assert_eq!(
            validator.stake_commitment,
            expected_validator_stake_commitment(0, 3, RegistryStatus::Disabled)
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::ValidatorStake.into(), &3),
            0
        );
    });
}

#[test]
fn failed_root_slashes_preserve_locked_capital_status_and_routing() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();

        let miner_before = Miners::<Test>::get(0).unwrap();
        let validator_before = Validators::<Test>::get(0).unwrap();
        let total_burned_before = TotalBurned::<Test>::get();
        let miner_hold_before = Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2);
        let validator_hold_before =
            Balances::balance_on_hold(&HoldReason::ValidatorStake.into(), &3);

        assert_noop!(
            Qubitum::slash_miner(RuntimeOrigin::root(), 0, 99, 1_000),
            Error::<Test>::NotOperator
        );
        assert_noop!(
            Qubitum::slash_miner(RuntimeOrigin::root(), 0, 2, MIN_INVALID_PROOF_SLASH_BPS - 1),
            Error::<Test>::InvalidSlashPercent
        );
        assert_noop!(
            Qubitum::slash_validator(RuntimeOrigin::root(), 0, 88, 1_000),
            Error::<Test>::NotOperator
        );
        assert_noop!(
            Qubitum::slash_validator(RuntimeOrigin::root(), 0, 3, MIN_INVALID_PROOF_SLASH_BPS - 1),
            Error::<Test>::InvalidSlashPercent
        );

        assert_eq!(Miners::<Test>::get(0), Some(miner_before));
        assert_eq!(Validators::<Test>::get(0), Some(validator_before));
        assert_eq!(MinerLockedBond::<Test>::get(0), Some(MIN_MINER_BOND));
        assert_eq!(ValidatorLockedStake::<Test>::get(0), Some(MIN_MINER_BOND));
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2),
            miner_hold_before
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::ValidatorStake.into(), &3),
            validator_hold_before
        );
        assert_eq!(TotalBurned::<Test>::get(), total_burned_before);
        assert_eq!(ActiveMinersBySubnet::<Test>::get(0).to_vec(), vec![0]);
        assert_eq!(ActiveValidatorsBySubnet::<Test>::get(0).to_vec(), vec![0]);
    });
}

#[test]
fn participant_capital_lifecycle_uses_per_registry_record_amounts() {
    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::General,
            ProofSystem::RiscZeroStark
        ));
        for model in [10, 11] {
            assert_ok!(Qubitum::register_miner(
                RuntimeOrigin::signed(2),
                0,
                commitment(model),
                ProofSystem::RiscZeroStark
            ));
        }
        assert_ok!(Qubitum::activate_miner(
            RuntimeOrigin::signed(2),
            0,
            MIN_MINER_BOND
        ));
        assert_ok!(Qubitum::activate_miner(
            RuntimeOrigin::signed(2),
            1,
            MIN_MINER_BOND
        ));
        assert_eq!(MinerLockedBond::<Test>::get(0), Some(MIN_MINER_BOND));
        assert_eq!(MinerLockedBond::<Test>::get(1), Some(MIN_MINER_BOND));

        assert_ok!(Qubitum::slash_miner(RuntimeOrigin::root(), 0, 2, 1_000));

        assert_eq!(MinerLockedBond::<Test>::get(0), Some(90_000_000_000));
        assert_eq!(MinerLockedBond::<Test>::get(1), Some(MIN_MINER_BOND));
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2),
            190_000_000_000
        );
        assert_eq!(
            Miners::<Test>::get(0).unwrap().status,
            RegistryStatus::Slashed
        );
        assert_eq!(
            Miners::<Test>::get(1).unwrap().status,
            RegistryStatus::Active
        );

        assert_ok!(Qubitum::deactivate_miner(RuntimeOrigin::signed(2), 0));
        System::set_block_number(20);
        assert_ok!(Qubitum::withdraw_miner_bond(RuntimeOrigin::signed(2), 0));

        assert_eq!(MinerLockedBond::<Test>::get(0), None);
        assert_eq!(MinerLockedBond::<Test>::get(1), Some(MIN_MINER_BOND));
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2),
            MIN_MINER_BOND
        );
        assert_eq!(
            Miners::<Test>::get(0).unwrap().status,
            RegistryStatus::Disabled
        );
        assert_eq!(
            Miners::<Test>::get(1).unwrap().status,
            RegistryStatus::Active
        );
    });

    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::General,
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::register_validator(
            RuntimeOrigin::signed(3),
            0,
            MIN_MINER_BOND
        ));
        assert_ok!(Qubitum::register_validator(
            RuntimeOrigin::signed(3),
            0,
            MIN_MINER_BOND
        ));
        assert_eq!(ValidatorLockedStake::<Test>::get(0), Some(MIN_MINER_BOND));
        assert_eq!(ValidatorLockedStake::<Test>::get(1), Some(MIN_MINER_BOND));

        assert_ok!(Qubitum::slash_validator(RuntimeOrigin::root(), 0, 3, 1_000));

        assert_eq!(ValidatorLockedStake::<Test>::get(0), Some(90_000_000_000));
        assert_eq!(ValidatorLockedStake::<Test>::get(1), Some(MIN_MINER_BOND));
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::ValidatorStake.into(), &3),
            190_000_000_000
        );
        assert_eq!(
            Validators::<Test>::get(0).unwrap().status,
            RegistryStatus::Slashed
        );
        assert_eq!(
            Validators::<Test>::get(1).unwrap().status,
            RegistryStatus::Active
        );

        assert_ok!(Qubitum::deactivate_validator(RuntimeOrigin::signed(3), 0));
        System::set_block_number(20);
        assert_ok!(Qubitum::withdraw_validator_stake(
            RuntimeOrigin::signed(3),
            0
        ));

        assert_eq!(ValidatorLockedStake::<Test>::get(0), None);
        assert_eq!(ValidatorLockedStake::<Test>::get(1), Some(MIN_MINER_BOND));
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::ValidatorStake.into(), &3),
            MIN_MINER_BOND
        );
        assert_eq!(
            Validators::<Test>::get(0).unwrap().status,
            RegistryStatus::Disabled
        );
        assert_eq!(
            Validators::<Test>::get(1).unwrap().status,
            RegistryStatus::Active
        );
    });
}

#[test]
fn legacy_missing_capital_records_fallback_only_when_unambiguous() {
    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::General,
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::register_miner(
            RuntimeOrigin::signed(2),
            0,
            commitment(10),
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::activate_miner(
            RuntimeOrigin::signed(2),
            0,
            MIN_MINER_BOND
        ));
        MinerLockedBond::<Test>::remove(0);

        assert_ok!(Qubitum::slash_miner(RuntimeOrigin::root(), 0, 2, 1_000));

        assert_eq!(MinerLockedBond::<Test>::get(0), Some(90_000_000_000));
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2),
            90_000_000_000
        );
        assert_eq!(
            Miners::<Test>::get(0).unwrap().status,
            RegistryStatus::Slashed
        );
    });

    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::General,
            ProofSystem::RiscZeroStark
        ));
        for model in [10, 11] {
            assert_ok!(Qubitum::register_miner(
                RuntimeOrigin::signed(2),
                0,
                commitment(model),
                ProofSystem::RiscZeroStark
            ));
        }
        assert_ok!(Qubitum::activate_miner(
            RuntimeOrigin::signed(2),
            0,
            MIN_MINER_BOND
        ));
        assert_ok!(Qubitum::activate_miner(
            RuntimeOrigin::signed(2),
            1,
            MIN_MINER_BOND
        ));
        MinerLockedBond::<Test>::remove(0);

        assert_noop!(
            Qubitum::slash_miner(RuntimeOrigin::root(), 0, 2, 1_000),
            Error::<Test>::MissingCapitalRecord
        );

        assert_eq!(
            Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2),
            MIN_MINER_BOND * 2
        );
        assert_eq!(
            Miners::<Test>::get(0).unwrap().status,
            RegistryStatus::Active
        );
        assert_eq!(
            Miners::<Test>::get(1).unwrap().status,
            RegistryStatus::Active
        );
    });

    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::General,
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::register_validator(
            RuntimeOrigin::signed(3),
            0,
            MIN_MINER_BOND
        ));
        assert_ok!(Qubitum::register_validator(
            RuntimeOrigin::signed(3),
            0,
            MIN_MINER_BOND
        ));
        ValidatorLockedStake::<Test>::remove(0);

        assert_noop!(
            Qubitum::slash_validator(RuntimeOrigin::root(), 0, 3, 1_000),
            Error::<Test>::MissingCapitalRecord
        );

        assert_eq!(
            Balances::balance_on_hold(&HoldReason::ValidatorStake.into(), &3),
            MIN_MINER_BOND * 2
        );
        assert_eq!(
            Validators::<Test>::get(0).unwrap().status,
            RegistryStatus::Active
        );
        assert_eq!(
            Validators::<Test>::get(1).unwrap().status,
            RegistryStatus::Active
        );
    });
}

#[test]
fn register_validator_locks_stake() {
    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::Vision,
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::register_validator(
            RuntimeOrigin::signed(3),
            0,
            MIN_MINER_BOND
        ));

        let validator = Validators::<Test>::get(0).unwrap();
        assert_eq!(
            validator.operator_commitment,
            Qubitum::operator_commitment(&3)
        );
        assert_ne!(
            validator.operator_commitment,
            Qubitum::account_commitment(&3)
        );
        assert_eq!(validator.status, RegistryStatus::Active);
        assert_eq!(ValidatorCount::<Test>::get(), 1);
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::ValidatorStake.into(), &3),
            MIN_MINER_BOND
        );
    });
}

#[test]
fn active_set_capacity_failures_rollback_locked_capital_and_ids() {
    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::General,
            ProofSystem::RiscZeroStark
        ));

        let miner_limit = <Test as crate::Config>::MaxActiveMinersPerSubnet::get();
        for index in 0..miner_limit {
            assert_ok!(Qubitum::register_miner(
                RuntimeOrigin::signed(2),
                0,
                commitment(index.saturating_add(10) as u8),
                ProofSystem::RiscZeroStark
            ));
            assert_ok!(Qubitum::activate_miner(
                RuntimeOrigin::signed(2),
                u64::from(index),
                MIN_MINER_BOND
            ));
        }

        assert_ok!(Qubitum::register_miner(
            RuntimeOrigin::signed(2),
            0,
            commitment(250),
            ProofSystem::RiscZeroStark
        ));
        let overflow_miner_id = MinerCount::<Test>::get().saturating_sub(1);
        let held_before = Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2);

        assert_noop!(
            Qubitum::activate_miner(RuntimeOrigin::signed(2), overflow_miner_id, MIN_MINER_BOND),
            Error::<Test>::TooManyActiveMiners
        );

        let miner = Miners::<Test>::get(overflow_miner_id).unwrap();
        assert_eq!(miner.status, RegistryStatus::Pending);
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2),
            held_before
        );
        assert_eq!(
            ActiveMinersBySubnet::<Test>::get(0).len(),
            miner_limit as usize
        );
        assert!(!ActiveMinersBySubnet::<Test>::get(0).contains(&overflow_miner_id));
    });

    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::General,
            ProofSystem::RiscZeroStark
        ));

        let validator_limit = <Test as crate::Config>::MaxActiveValidatorsPerSubnet::get();
        for _ in 0..validator_limit {
            assert_ok!(Qubitum::register_validator(
                RuntimeOrigin::signed(3),
                0,
                MIN_MINER_BOND
            ));
        }
        let validator_count_before = ValidatorCount::<Test>::get();
        let held_before = Balances::balance_on_hold(&HoldReason::ValidatorStake.into(), &3);

        assert_noop!(
            Qubitum::register_validator(RuntimeOrigin::signed(3), 0, MIN_MINER_BOND),
            Error::<Test>::TooManyActiveValidators
        );

        assert_eq!(ValidatorCount::<Test>::get(), validator_count_before);
        assert!(Validators::<Test>::get(validator_count_before).is_none());
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::ValidatorStake.into(), &3),
            held_before
        );
        assert_eq!(
            ActiveValidatorsBySubnet::<Test>::get(0).len(),
            validator_limit as usize
        );
    });
}

#[test]
fn registry_id_overflows_do_not_burn_or_lock_funds() {
    new_test_ext().execute_with(|| {
        SubnetCount::<Test>::put(u16::MAX);
        let burned_before = TotalBurned::<Test>::get();
        assert_noop!(
            Qubitum::create_subnet(
                RuntimeOrigin::signed(1),
                SubnetDomain::Code,
                ProofSystem::RiscZeroStark
            ),
            Error::<Test>::ArithmeticOverflow
        );
        assert_eq!(TotalBurned::<Test>::get(), burned_before);
        assert!(Subnets::<Test>::get(u16::MAX).is_none());
        assert_eq!(SubnetCount::<Test>::get(), u16::MAX);
    });

    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::Code,
            ProofSystem::RiscZeroStark
        ));
        MinerCount::<Test>::put(u64::MAX);
        let burned_before = TotalBurned::<Test>::get();
        assert_noop!(
            Qubitum::register_miner(
                RuntimeOrigin::signed(2),
                0,
                commitment(10),
                ProofSystem::RiscZeroStark
            ),
            Error::<Test>::ArithmeticOverflow
        );
        assert_eq!(TotalBurned::<Test>::get(), burned_before);
        assert!(Miners::<Test>::get(u64::MAX).is_none());
        assert_eq!(MinerCount::<Test>::get(), u64::MAX);
    });

    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::Code,
            ProofSystem::RiscZeroStark
        ));
        ValidatorCount::<Test>::put(u64::MAX);
        assert_noop!(
            Qubitum::register_validator(RuntimeOrigin::signed(3), 0, MIN_MINER_BOND),
            Error::<Test>::ArithmeticOverflow
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::ValidatorStake.into(), &3),
            0
        );
        assert!(Validators::<Test>::get(u64::MAX).is_none());
        assert_eq!(ValidatorCount::<Test>::get(), u64::MAX);
    });
}

#[test]
fn request_id_overflow_does_not_escrow_or_increment_pending() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        RequestCount::<Test>::put(u64::MAX);
        let assignment = Qubitum::route_assignment(0, u64::MAX).unwrap();

        assert_noop!(
            Qubitum::request_inference(
                RuntimeOrigin::signed(4),
                u64::MAX,
                InferenceRequestParams {
                    subnet_id: 0,
                    miner_id: 0,
                    validator_id: 0,
                    input_commitment: commitment(1),
                    assignment_blinding: assignment_blinding(),
                    timing_blinding: timing_blinding(),
                    terms_blinding: terms_blinding(),
                    payment: 1_000,
                    validator_fee_bps: 250,
                    treasury_fee_bps: 50,
                },
            ),
            Error::<Test>::ArithmeticOverflow
        );

        assert!(InferenceRequests::<Test>::get(u64::MAX).is_none());
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            0
        );
        assert_eq!(PendingInferenceRequestCount::<Test>::get(), 0);
        assert_eq!(
            Qubitum::request_status_counts(),
            ChainRequestStatusCounts {
                pending: 0,
                settled: 0,
                cancelled: 0,
                rejected: 0,
                expired: 0,
            }
        );
        assert_eq!(PendingMinerRequests::<Test>::get(assignment.miner_id), 0);
        assert_eq!(
            PendingValidatorRequests::<Test>::get(assignment.validator_id),
            0
        );
        assert_eq!(RequestCount::<Test>::get(), u64::MAX);
    });
}

#[test]
fn accounting_overflows_fail_without_state_changes() {
    new_test_ext().execute_with(|| {
        TotalBurned::<Test>::put(u128::MAX);

        assert_noop!(
            Qubitum::create_subnet(
                RuntimeOrigin::signed(1),
                SubnetDomain::Code,
                ProofSystem::RiscZeroStark,
            ),
            Error::<Test>::ArithmeticOverflow
        );

        assert_eq!(SubnetCount::<Test>::get(), 0);
        assert!(Subnets::<Test>::get(0).is_none());
        assert_eq!(Balances::free_balance(1), 1_000_000_000_000_000);
        assert_eq!(TotalBurned::<Test>::get(), u128::MAX);
    });

    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::Code,
            ProofSystem::RiscZeroStark,
        ));
        TotalBurned::<Test>::put(u128::MAX);

        assert_noop!(
            Qubitum::register_miner(
                RuntimeOrigin::signed(2),
                0,
                commitment(10),
                ProofSystem::RiscZeroStark,
            ),
            Error::<Test>::ArithmeticOverflow
        );

        assert_eq!(MinerCount::<Test>::get(), 0);
        assert!(Miners::<Test>::get(0).is_none());
        assert_eq!(Balances::free_balance(2), 1_000_000_000_000_000);
        assert_eq!(TotalBurned::<Test>::get(), u128::MAX);
    });

    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        TotalInferenceEscrowed::<Test>::put(u128::MAX);

        assert_noop!(
            Qubitum::request_inference(
                RuntimeOrigin::signed(4),
                0,
                InferenceRequestParams {
                    subnet_id: 0,
                    miner_id: 0,
                    validator_id: 0,
                    input_commitment: commitment(1),
                    assignment_blinding: assignment_blinding(),
                    timing_blinding: timing_blinding(),
                    terms_blinding: terms_blinding(),
                    payment: 1_000,
                    validator_fee_bps: 250,
                    treasury_fee_bps: 50,
                },
            ),
            Error::<Test>::ArithmeticOverflow
        );

        assert!(InferenceRequests::<Test>::get(0).is_none());
        assert_eq!(RequestCount::<Test>::get(), 0);
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            0
        );
        assert_eq!(PendingMinerRequests::<Test>::get(0), 0);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 0);
        assert_eq!(TotalInferenceEscrowed::<Test>::get(), u128::MAX);
    });

    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(80);
        let miner_free_before = Balances::free_balance(2);
        let validator_free_before = Balances::free_balance(3);
        let treasury_free_before = Balances::free_balance(99);
        TotalMinerPayouts::<Test>::put(u128::MAX);

        assert_noop!(
            submit_proof(RuntimeOrigin::signed(3), valid_submission(80)),
            Error::<Test>::ArithmeticOverflow
        );

        assert!(ProofRecords::<Test>::get(80).is_none());
        assert_eq!(
            InferenceRequests::<Test>::get(80).unwrap().status,
            InferenceRequestStatus::Pending
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            1_000
        );
        assert_eq!(PendingMinerRequests::<Test>::get(0), 1);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 1);
        assert_eq!(Balances::free_balance(2), miner_free_before);
        assert_eq!(Balances::free_balance(3), validator_free_before);
        assert_eq!(Balances::free_balance(99), treasury_free_before);
        assert_eq!(TotalMinerPayouts::<Test>::get(), u128::MAX);
    });

    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(83);
        let miner_free_before = Balances::free_balance(2);
        let validator_free_before = Balances::free_balance(3);
        let treasury_free_before = Balances::free_balance(99);
        TotalValidatorFees::<Test>::put(u128::MAX);

        assert_noop!(
            submit_proof(RuntimeOrigin::signed(3), valid_submission(83)),
            Error::<Test>::ArithmeticOverflow
        );

        assert!(ProofRecords::<Test>::get(83).is_none());
        assert_eq!(
            InferenceRequests::<Test>::get(83).unwrap().status,
            InferenceRequestStatus::Pending
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            1_000
        );
        assert_eq!(PendingMinerRequests::<Test>::get(0), 1);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 1);
        assert_eq!(Balances::free_balance(2), miner_free_before);
        assert_eq!(Balances::free_balance(3), validator_free_before);
        assert_eq!(Balances::free_balance(99), treasury_free_before);
        assert_eq!(TotalMinerPayouts::<Test>::get(), 0);
        assert_eq!(TotalValidatorFees::<Test>::get(), u128::MAX);
        assert_eq!(TotalTreasuryFees::<Test>::get(), 0);
    });

    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(84);
        let miner_free_before = Balances::free_balance(2);
        let validator_free_before = Balances::free_balance(3);
        let treasury_free_before = Balances::free_balance(99);
        TotalTreasuryFees::<Test>::put(u128::MAX);

        assert_noop!(
            submit_proof(RuntimeOrigin::signed(3), valid_submission(84)),
            Error::<Test>::ArithmeticOverflow
        );

        assert!(ProofRecords::<Test>::get(84).is_none());
        assert_eq!(
            InferenceRequests::<Test>::get(84).unwrap().status,
            InferenceRequestStatus::Pending
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            1_000
        );
        assert_eq!(PendingMinerRequests::<Test>::get(0), 1);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 1);
        assert_eq!(Balances::free_balance(2), miner_free_before);
        assert_eq!(Balances::free_balance(3), validator_free_before);
        assert_eq!(Balances::free_balance(99), treasury_free_before);
        assert_eq!(TotalMinerPayouts::<Test>::get(), 0);
        assert_eq!(TotalValidatorFees::<Test>::get(), 0);
        assert_eq!(TotalTreasuryFees::<Test>::get(), u128::MAX);
    });

    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(81);
        TotalInferenceRefunded::<Test>::put(u128::MAX);
        System::set_block_number(10);

        assert_noop!(
            Qubitum::cancel_inference(
                RuntimeOrigin::signed(4),
                81,
                0,
                0,
                assignment_blinding(),
                timing_witness(0),
                request_terms_witness()
            ),
            Error::<Test>::ArithmeticOverflow
        );

        assert_eq!(
            InferenceRequests::<Test>::get(81).unwrap().status,
            InferenceRequestStatus::Pending
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            1_000
        );
        assert_eq!(PendingMinerRequests::<Test>::get(0), 1);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 1);
        assert_eq!(TotalInferenceRefunded::<Test>::get(), u128::MAX);
    });

    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        TotalBurned::<Test>::put(u128::MAX);

        assert_noop!(
            Qubitum::slash_miner(RuntimeOrigin::root(), 0, 2, 1_000),
            Error::<Test>::ArithmeticOverflow
        );

        assert_eq!(
            Miners::<Test>::get(0).unwrap().status,
            RegistryStatus::Active
        );
        assert_eq!(MinerLockedBond::<Test>::get(0), Some(MIN_MINER_BOND));
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2),
            MIN_MINER_BOND
        );
        assert_eq!(ActiveMinersBySubnet::<Test>::get(0).to_vec(), vec![0]);
        assert_eq!(TotalBurned::<Test>::get(), u128::MAX);
    });

    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        TotalBurned::<Test>::put(u128::MAX);

        assert_noop!(
            Qubitum::slash_validator(RuntimeOrigin::root(), 0, 3, 1_000),
            Error::<Test>::ArithmeticOverflow
        );

        assert_eq!(
            Validators::<Test>::get(0).unwrap().status,
            RegistryStatus::Active
        );
        assert_eq!(ValidatorLockedStake::<Test>::get(0), Some(MIN_MINER_BOND));
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::ValidatorStake.into(), &3),
            MIN_MINER_BOND
        );
        assert_eq!(ActiveValidatorsBySubnet::<Test>::get(0).to_vec(), vec![0]);
        assert_eq!(TotalBurned::<Test>::get(), u128::MAX);
    });

    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(82);
        set_verification_outcome(VerificationOutcome::Invalid { slash_bps: 1_000 });
        TotalBurned::<Test>::put(u128::MAX);

        assert_noop!(
            submit_proof(RuntimeOrigin::signed(3), valid_submission(82)),
            Error::<Test>::ArithmeticOverflow
        );

        assert!(ProofRecords::<Test>::get(82).is_none());
        assert_eq!(
            InferenceRequests::<Test>::get(82).unwrap().status,
            InferenceRequestStatus::Pending
        );
        assert_eq!(PendingMinerRequests::<Test>::get(0), 1);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 1);
        assert_eq!(
            Miners::<Test>::get(0).unwrap().status,
            RegistryStatus::Active
        );
        assert_eq!(
            Validators::<Test>::get(0).unwrap().status,
            RegistryStatus::Active
        );
        assert_eq!(MinerLockedBond::<Test>::get(0), Some(MIN_MINER_BOND));
        assert_eq!(ValidatorLockedStake::<Test>::get(0), Some(MIN_MINER_BOND));
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2),
            MIN_MINER_BOND
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::ValidatorStake.into(), &3),
            MIN_MINER_BOND
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            1_000
        );
        assert_eq!(TotalBurned::<Test>::get(), u128::MAX);
        assert_eq!(TotalInferenceRefunded::<Test>::get(), 0);
    });

    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(85);
        set_verification_outcome(VerificationOutcome::Invalid { slash_bps: 1_000 });
        let burned_before = TotalBurned::<Test>::get();
        TotalInferenceRefunded::<Test>::put(u128::MAX);

        assert_noop!(
            submit_proof(RuntimeOrigin::signed(3), valid_submission(85)),
            Error::<Test>::ArithmeticOverflow
        );

        assert!(ProofRecords::<Test>::get(85).is_none());
        assert_eq!(
            InferenceRequests::<Test>::get(85).unwrap().status,
            InferenceRequestStatus::Pending
        );
        assert_eq!(PendingMinerRequests::<Test>::get(0), 1);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 1);
        assert_eq!(
            Miners::<Test>::get(0).unwrap().status,
            RegistryStatus::Active
        );
        assert_eq!(
            Validators::<Test>::get(0).unwrap().status,
            RegistryStatus::Active
        );
        assert_eq!(MinerLockedBond::<Test>::get(0), Some(MIN_MINER_BOND));
        assert_eq!(ValidatorLockedStake::<Test>::get(0), Some(MIN_MINER_BOND));
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2),
            MIN_MINER_BOND
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::ValidatorStake.into(), &3),
            MIN_MINER_BOND
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            1_000
        );
        assert_eq!(TotalBurned::<Test>::get(), burned_before);
        assert_eq!(TotalInferenceRefunded::<Test>::get(), u128::MAX);
    });

    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(86);
        set_verification_outcome(VerificationOutcome::Invalid { slash_bps: 1_000 });
        let burned_before = TotalBurned::<Test>::get();
        TotalInferenceRefunded::<Test>::put(u128::MAX);

        assert_noop!(
            challenge_proof(RuntimeOrigin::signed(4), valid_submission(86)),
            Error::<Test>::ArithmeticOverflow
        );

        assert!(ProofRecords::<Test>::get(86).is_none());
        assert_eq!(
            InferenceRequests::<Test>::get(86).unwrap().status,
            InferenceRequestStatus::Pending
        );
        assert_eq!(PendingMinerRequests::<Test>::get(0), 1);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 1);
        assert_eq!(
            Miners::<Test>::get(0).unwrap().status,
            RegistryStatus::Active
        );
        assert_eq!(MinerLockedBond::<Test>::get(0), Some(MIN_MINER_BOND));
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2),
            MIN_MINER_BOND
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            1_000
        );
        assert_eq!(TotalBurned::<Test>::get(), burned_before);
        assert_eq!(TotalInferenceRefunded::<Test>::get(), u128::MAX);
    });
}

#[test]
fn role_commitments_are_domain_separated_with_legacy_authorization() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(12);

        let subnet = Subnets::<Test>::get(0).unwrap();
        let miner = Miners::<Test>::get(0).unwrap();
        let validator = Validators::<Test>::get(0).unwrap();
        let request = InferenceRequests::<Test>::get(12).unwrap();

        assert_eq!(
            subnet.owner_commitment,
            Qubitum::subnet_owner_commitment(&1)
        );
        assert_ne!(subnet.owner_commitment, Qubitum::account_commitment(&1));
        assert_eq!(miner.operator_commitment, Qubitum::operator_commitment(&2));
        assert_ne!(miner.operator_commitment, Qubitum::account_commitment(&2));
        assert_eq!(
            validator.operator_commitment,
            Qubitum::operator_commitment(&3)
        );
        assert_ne!(
            validator.operator_commitment,
            Qubitum::account_commitment(&3)
        );
        assert_eq!(
            request.user_commitment,
            Qubitum::request_user_commitment(&4)
        );
        assert_ne!(request.user_commitment, Qubitum::account_commitment(&4));

        Miners::<Test>::mutate(0, |maybe_miner| {
            maybe_miner.as_mut().unwrap().operator_commitment = Qubitum::account_commitment(&2);
        });
        Validators::<Test>::mutate(0, |maybe_validator| {
            maybe_validator.as_mut().unwrap().operator_commitment = Qubitum::account_commitment(&3);
        });
        InferenceRequests::<Test>::mutate(12, |maybe_request| {
            maybe_request.as_mut().unwrap().user_commitment = Qubitum::account_commitment(&4);
        });

        assert_ok!(Qubitum::set_miner_identity_commitments(
            RuntimeOrigin::signed(2),
            0,
            Some(commitment(20)),
            Some(commitment(21)),
            miner_identity_signature_bundle(0, Some(commitment(20)), Some(commitment(21))),
        ));
        assert_ok!(Qubitum::set_validator_identity_commitments(
            RuntimeOrigin::signed(3),
            0,
            Some(commitment(22)),
            Some(commitment(23)),
            validator_identity_signature_bundle(0, Some(commitment(22)), Some(commitment(23))),
        ));
        System::set_block_number(10);
        assert_ok!(Qubitum::cancel_inference(
            RuntimeOrigin::signed(4),
            12,
            0,
            0,
            assignment_blinding(),
            timing_witness(0),
            request_terms_witness()
        ));
    });
}

#[test]
fn identity_commitments_are_operator_gated_and_commitment_only() {
    new_test_ext().execute_with(|| {
        let raw_miner_identity = b"RAW_MINER_IDENTITY_ENDPOINT_AND_OPERATOR_METADATA";
        let raw_validator_identity = b"RAW_VALIDATOR_IDENTITY_ENDPOINT_AND_STAKE_METADATA";

        register_active_miner_and_validator();

        assert_noop!(
            Qubitum::set_miner_identity_commitments(
                RuntimeOrigin::signed(3),
                0,
                Some(commitment(20)),
                Some(commitment(21)),
                classical_signature_bundle(),
            ),
            Error::<Test>::NotOperator
        );
        assert_noop!(
            Qubitum::set_validator_identity_commitments(
                RuntimeOrigin::signed(2),
                0,
                Some(commitment(22)),
                Some(commitment(23)),
                classical_signature_bundle(),
            ),
            Error::<Test>::NotOperator
        );
        assert_noop!(
            Qubitum::set_miner_identity_commitments(
                RuntimeOrigin::signed(2),
                0,
                Some([0; 32]),
                None,
                classical_signature_bundle(),
            ),
            Error::<Test>::MissingCommitment
        );
        assert_noop!(
            Qubitum::set_miner_identity_commitments(
                RuntimeOrigin::signed(2),
                0,
                Some(commitment(20)),
                Some([0; 32]),
                classical_signature_bundle(),
            ),
            Error::<Test>::MissingCommitment
        );
        assert_noop!(
            Qubitum::set_validator_identity_commitments(
                RuntimeOrigin::signed(3),
                0,
                Some(commitment(22)),
                Some([0; 32]),
                classical_signature_bundle(),
            ),
            Error::<Test>::MissingCommitment
        );
        assert_noop!(
            Qubitum::set_miner_identity_commitments(
                RuntimeOrigin::signed(2),
                0,
                Some(commitment(20)),
                Some(commitment(21)),
                classical_signature_bundle(),
            ),
            Error::<Test>::InvalidSignatureBundle
        );
        assert_noop!(
            Qubitum::set_validator_identity_commitments(
                RuntimeOrigin::signed(3),
                0,
                Some(commitment(22)),
                Some(commitment(23)),
                zero_signature_bundle(),
            ),
            Error::<Test>::InvalidSignatureBundle
        );
        assert_noop!(
            Qubitum::set_miner_identity_commitments(
                RuntimeOrigin::signed(2),
                0,
                Some(commitment(20)),
                Some(commitment(21)),
                dual_signature_bundle(),
            ),
            Error::<Test>::InvalidSignatureBundle
        );

        let miner_signature_bundle =
            miner_identity_signature_bundle(0, Some(commitment(20)), Some(commitment(21)));
        let validator_signature_bundle =
            validator_identity_signature_bundle(0, Some(commitment(22)), Some(commitment(23)));

        assert_ok!(Qubitum::set_miner_identity_commitments(
            RuntimeOrigin::signed(2),
            0,
            Some(commitment(20)),
            Some(commitment(21)),
            miner_signature_bundle,
        ));
        assert_ok!(Qubitum::set_validator_identity_commitments(
            RuntimeOrigin::signed(3),
            0,
            Some(commitment(22)),
            Some(commitment(23)),
            validator_signature_bundle,
        ));

        let miner_commitments = MinerIdentityCommitments::<Test>::get(0).unwrap();
        assert_eq!(
            miner_commitments.shielded_identity_commitment,
            Some(commitment(20))
        );
        assert_eq!(miner_commitments.endpoint_commitment, Some(commitment(21)));
        assert_eq!(
            MinerIdentitySignatureBundles::<Test>::get(0),
            Some(miner_signature_bundle)
        );
        let miner_signature_challenge = MinerIdentitySignatureChallenges::<Test>::get(0).unwrap();
        let public_miner_identity = Qubitum::public_miner_identity(0).unwrap();
        assert_eq!(
            public_miner_identity,
            ChainPublicIdentity {
                participant_id: 0,
                has_shielded_identity_commitment: true,
                has_endpoint_commitment: true,
                signature_commitment_recorded: true,
                signature_challenge_bound: true,
                signature_verified: false,
                challenge_available: true,
            }
        );
        let encoded_public_miner_identity = public_miner_identity.encode();
        for hidden in [
            commitment(20).encode(),
            commitment(21).encode(),
            miner_signature_bundle.encode(),
            miner_signature_challenge.encode(),
        ] {
            assert!(!contains_subsequence(
                &encoded_public_miner_identity,
                &hidden
            ));
        }
        let miner = Miners::<Test>::get(0).unwrap();
        assert_eq!(
            miner_signature_challenge,
            Qubitum::miner_identity_signature_challenge(
                0,
                miner.operator_commitment,
                Some(commitment(20)),
                Some(commitment(21)),
            )
        );
        let validator_commitments = ValidatorIdentityCommitments::<Test>::get(0).unwrap();
        assert_eq!(
            validator_commitments.shielded_identity_commitment,
            Some(commitment(22))
        );
        assert_eq!(
            validator_commitments.endpoint_commitment,
            Some(commitment(23))
        );
        assert_eq!(
            ValidatorIdentitySignatureBundles::<Test>::get(0),
            Some(validator_signature_bundle)
        );
        let validator_signature_challenge =
            ValidatorIdentitySignatureChallenges::<Test>::get(0).unwrap();
        let public_validator_identity = Qubitum::public_validator_identity(0).unwrap();
        assert_eq!(
            public_validator_identity,
            ChainPublicIdentity {
                participant_id: 0,
                has_shielded_identity_commitment: true,
                has_endpoint_commitment: true,
                signature_commitment_recorded: true,
                signature_challenge_bound: true,
                signature_verified: false,
                challenge_available: true,
            }
        );
        let encoded_public_validator_identity = public_validator_identity.encode();
        for hidden in [
            commitment(22).encode(),
            commitment(23).encode(),
            validator_signature_bundle.encode(),
            validator_signature_challenge.encode(),
        ] {
            assert!(!contains_subsequence(
                &encoded_public_validator_identity,
                &hidden
            ));
        }
        let validator = Validators::<Test>::get(0).unwrap();
        assert_eq!(
            validator_signature_challenge,
            Qubitum::validator_identity_signature_challenge(
                0,
                validator.operator_commitment,
                Some(commitment(22)),
                Some(commitment(23)),
            )
        );
        assert_ne!(miner_signature_challenge, validator_signature_challenge);

        for encoded in [
            miner_commitments.encode(),
            MinerIdentitySignatureBundles::<Test>::get(0)
                .unwrap()
                .encode(),
            miner_signature_challenge.encode(),
            validator_commitments.encode(),
            ValidatorIdentitySignatureBundles::<Test>::get(0)
                .unwrap()
                .encode(),
            validator_signature_challenge.encode(),
        ] {
            assert!(!contains_subsequence(&encoded, raw_miner_identity));
            assert!(!contains_subsequence(&encoded, raw_validator_identity));
        }

        assert_ok!(Qubitum::set_miner_identity_commitments(
            RuntimeOrigin::signed(2),
            0,
            None,
            None,
            miner_identity_signature_bundle(0, None, None),
        ));
        assert!(MinerIdentityCommitments::<Test>::get(0).is_none());
        assert!(MinerIdentitySignatureBundles::<Test>::get(0).is_none());
        assert!(MinerIdentitySignatureChallenges::<Test>::get(0).is_none());
        assert_eq!(
            Qubitum::public_miner_identity(0),
            Some(ChainPublicIdentity {
                participant_id: 0,
                has_shielded_identity_commitment: false,
                has_endpoint_commitment: false,
                signature_commitment_recorded: false,
                signature_challenge_bound: false,
                signature_verified: false,
                challenge_available: false,
            })
        );
        assert_noop!(
            Qubitum::set_validator_identity_commitments(
                RuntimeOrigin::signed(3),
                0,
                None,
                None,
                zero_signature_bundle(),
            ),
            Error::<Test>::InvalidSignatureBundle
        );
        assert!(ValidatorIdentityCommitments::<Test>::get(0).is_some());
        assert!(ValidatorIdentitySignatureBundles::<Test>::get(0).is_some());
        assert!(ValidatorIdentitySignatureChallenges::<Test>::get(0).is_some());
        assert_ok!(Qubitum::set_validator_identity_commitments(
            RuntimeOrigin::signed(3),
            0,
            None,
            None,
            validator_identity_signature_bundle(0, None, None),
        ));
        assert!(ValidatorIdentityCommitments::<Test>::get(0).is_none());
        assert!(ValidatorIdentitySignatureBundles::<Test>::get(0).is_none());
        assert!(ValidatorIdentitySignatureChallenges::<Test>::get(0).is_none());
        assert_eq!(
            Qubitum::public_validator_identity(0),
            Some(ChainPublicIdentity {
                participant_id: 0,
                has_shielded_identity_commitment: false,
                has_endpoint_commitment: false,
                signature_commitment_recorded: false,
                signature_challenge_bound: false,
                signature_verified: false,
                challenge_available: false,
            })
        );
        assert_eq!(Qubitum::public_miner_identity(999), None);
        assert_eq!(Qubitum::public_validator_identity(999), None);
    });
}

#[test]
fn failed_identity_commitment_updates_do_not_clobber_existing_state() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();

        assert_ok!(Qubitum::set_miner_identity_commitments(
            RuntimeOrigin::signed(2),
            0,
            Some(commitment(20)),
            Some(commitment(21)),
            miner_identity_signature_bundle(0, Some(commitment(20)), Some(commitment(21))),
        ));
        assert_ok!(Qubitum::set_validator_identity_commitments(
            RuntimeOrigin::signed(3),
            0,
            Some(commitment(22)),
            Some(commitment(23)),
            validator_identity_signature_bundle(0, Some(commitment(22)), Some(commitment(23))),
        ));

        let miner_commitments = MinerIdentityCommitments::<Test>::get(0);
        let miner_signature = MinerIdentitySignatureBundles::<Test>::get(0);
        let miner_challenge = MinerIdentitySignatureChallenges::<Test>::get(0);
        let validator_commitments = ValidatorIdentityCommitments::<Test>::get(0);
        let validator_signature = ValidatorIdentitySignatureBundles::<Test>::get(0);
        let validator_challenge = ValidatorIdentitySignatureChallenges::<Test>::get(0);

        assert_noop!(
            Qubitum::set_miner_identity_commitments(
                RuntimeOrigin::signed(2),
                0,
                Some(commitment(24)),
                Some([0; 32]),
                classical_signature_bundle(),
            ),
            Error::<Test>::MissingCommitment
        );
        assert_noop!(
            Qubitum::set_miner_identity_commitments(
                RuntimeOrigin::signed(2),
                0,
                Some(commitment(24)),
                Some(commitment(25)),
                classical_signature_bundle(),
            ),
            Error::<Test>::InvalidSignatureBundle
        );
        assert_noop!(
            Qubitum::set_validator_identity_commitments(
                RuntimeOrigin::signed(3),
                0,
                Some(commitment(26)),
                Some([0; 32]),
                classical_signature_bundle(),
            ),
            Error::<Test>::MissingCommitment
        );
        assert_noop!(
            Qubitum::set_validator_identity_commitments(
                RuntimeOrigin::signed(3),
                0,
                Some(commitment(26)),
                Some(commitment(27)),
                zero_signature_bundle(),
            ),
            Error::<Test>::InvalidSignatureBundle
        );
        assert_noop!(
            Qubitum::set_miner_identity_commitments(
                RuntimeOrigin::signed(2),
                0,
                None,
                None,
                classical_signature_bundle(),
            ),
            Error::<Test>::InvalidSignatureBundle
        );
        assert_noop!(
            Qubitum::set_validator_identity_commitments(
                RuntimeOrigin::signed(3),
                0,
                None,
                None,
                zero_signature_bundle(),
            ),
            Error::<Test>::InvalidSignatureBundle
        );

        assert_eq!(MinerIdentityCommitments::<Test>::get(0), miner_commitments);
        assert_eq!(
            MinerIdentitySignatureBundles::<Test>::get(0),
            miner_signature
        );
        assert_eq!(
            MinerIdentitySignatureChallenges::<Test>::get(0),
            miner_challenge
        );
        assert_eq!(
            ValidatorIdentityCommitments::<Test>::get(0),
            validator_commitments
        );
        assert_eq!(
            ValidatorIdentitySignatureBundles::<Test>::get(0),
            validator_signature
        );
        assert_eq!(
            ValidatorIdentitySignatureChallenges::<Test>::get(0),
            validator_challenge
        );
    });
}

#[test]
fn identity_signature_challenges_are_role_separated_and_mutable() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();

        let shared_operator_commitment = Qubitum::operator_commitment(&2);
        assert_ne!(
            Qubitum::miner_identity_signature_challenge(
                0,
                shared_operator_commitment,
                Some(commitment(50)),
                Some(commitment(51)),
            ),
            Qubitum::validator_identity_signature_challenge(
                0,
                shared_operator_commitment,
                Some(commitment(50)),
                Some(commitment(51)),
            )
        );

        assert_ok!(Qubitum::set_miner_identity_commitments(
            RuntimeOrigin::signed(2),
            0,
            Some(commitment(50)),
            Some(commitment(51)),
            miner_identity_signature_bundle(0, Some(commitment(50)), Some(commitment(51))),
        ));
        let miner = Miners::<Test>::get(0).unwrap();
        let first_challenge = MinerIdentitySignatureChallenges::<Test>::get(0).unwrap();
        assert_eq!(
            first_challenge,
            Qubitum::miner_identity_signature_challenge(
                0,
                miner.operator_commitment,
                Some(commitment(50)),
                Some(commitment(51)),
            )
        );

        assert_ok!(Qubitum::set_miner_identity_commitments(
            RuntimeOrigin::signed(2),
            0,
            Some(commitment(50)),
            Some(commitment(52)),
            miner_identity_signature_bundle(0, Some(commitment(50)), Some(commitment(52))),
        ));
        let updated_challenge = MinerIdentitySignatureChallenges::<Test>::get(0).unwrap();
        assert_ne!(first_challenge, updated_challenge);
        assert_eq!(
            updated_challenge,
            Qubitum::miner_identity_signature_challenge(
                0,
                miner.operator_commitment,
                Some(commitment(50)),
                Some(commitment(52)),
            )
        );
    });
}

#[test]
fn identity_signature_bundle_must_bind_current_challenge() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();

        assert_noop!(
            Qubitum::set_miner_identity_commitments(
                RuntimeOrigin::signed(2),
                0,
                Some(commitment(60)),
                Some(commitment(61)),
                post_quantum_signature_bundle(),
            ),
            Error::<Test>::InvalidSignatureBundle
        );

        let stale_miner_bundle =
            miner_identity_signature_bundle(0, Some(commitment(120)), Some(commitment(121)));
        assert_noop!(
            Qubitum::set_miner_identity_commitments(
                RuntimeOrigin::signed(2),
                0,
                Some(commitment(60)),
                Some(commitment(61)),
                stale_miner_bundle,
            ),
            Error::<Test>::InvalidSignatureBundle
        );

        assert_ok!(Qubitum::set_miner_identity_commitments(
            RuntimeOrigin::signed(2),
            0,
            Some(commitment(60)),
            Some(commitment(61)),
            miner_identity_signature_bundle(0, Some(commitment(60)), Some(commitment(61))),
        ));

        assert_noop!(
            Qubitum::set_validator_identity_commitments(
                RuntimeOrigin::signed(3),
                0,
                Some(commitment(62)),
                Some(commitment(63)),
                post_quantum_signature_bundle(),
            ),
            Error::<Test>::InvalidSignatureBundle
        );

        assert_ok!(Qubitum::set_validator_identity_commitments(
            RuntimeOrigin::signed(3),
            0,
            Some(commitment(62)),
            Some(commitment(63)),
            validator_identity_signature_bundle(0, Some(commitment(62)), Some(commitment(63))),
        ));
    });
}

#[test]
fn identity_signature_commitments_are_not_reported_as_verified() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();

        assert_ok!(Qubitum::set_miner_identity_commitments(
            RuntimeOrigin::signed(2),
            0,
            Some(commitment(64)),
            Some(commitment(65)),
            miner_identity_signature_bundle(0, Some(commitment(64)), Some(commitment(65))),
        ));
        assert_ok!(Qubitum::set_validator_identity_commitments(
            RuntimeOrigin::signed(3),
            0,
            Some(commitment(66)),
            Some(commitment(67)),
            validator_identity_signature_bundle(0, Some(commitment(66)), Some(commitment(67))),
        ));

        let miner_identity = Qubitum::public_miner_identity(0).unwrap();
        let validator_identity = Qubitum::public_validator_identity(0).unwrap();
        let params = Qubitum::protocol_params();

        assert!(miner_identity.signature_commitment_recorded);
        assert!(miner_identity.signature_challenge_bound);
        assert!(!miner_identity.signature_verified);
        assert!(validator_identity.signature_commitment_recorded);
        assert!(validator_identity.signature_challenge_bound);
        assert!(!validator_identity.signature_verified);
        assert!(!params.identity_signature_verification);
        assert!(!params.post_quantum_signature_crypto_verification);
        assert!(
            params
                .readiness_blockers
                .identity_signature_verification_missing
        );
        assert!(
            params
                .readiness_blockers
                .post_quantum_signature_crypto_verification_missing
        );
        assert!(params.readiness_blockers.post_quantum_blocked());
        assert!(!params.post_quantum_complete);
    });
}

#[test]
fn routing_and_proof_reject_unbound_identity_signature_bundles() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(88);

        MinerIdentitySignatureBundles::<Test>::insert(0, post_quantum_signature_bundle());

        let public_identity = Qubitum::public_miner_identity(0).unwrap();
        assert!(public_identity.signature_commitment_recorded);
        assert!(public_identity.challenge_available);
        assert!(!public_identity.signature_challenge_bound);
        assert!(!Qubitum::next_route_availability(0).available);
        assert_noop!(
            submit_proof(RuntimeOrigin::signed(3), valid_submission(88)),
            Error::<Test>::InvalidSignatureBundle
        );
        assert!(ProofRecords::<Test>::get(88).is_none());
        assert_eq!(
            InferenceRequests::<Test>::get(88).unwrap().status,
            InferenceRequestStatus::Pending
        );
    });
}

#[test]
fn validator_exit_requires_cooldown_and_releases_stake() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();

        assert_noop!(
            Qubitum::deactivate_validator(RuntimeOrigin::signed(2), 0),
            Error::<Test>::NotOperator
        );
        assert_ok!(Qubitum::deactivate_validator(RuntimeOrigin::signed(3), 0));

        let validator = Validators::<Test>::get(0).unwrap();
        assert_eq!(
            validator.status,
            RegistryStatus::Exiting {
                exit_available_at: 20
            }
        );

        assert_noop!(
            Qubitum::withdraw_validator_stake(RuntimeOrigin::signed(3), 0),
            Error::<Test>::ValidatorExitUnavailable
        );

        System::set_block_number(20);
        assert_ok!(Qubitum::withdraw_validator_stake(
            RuntimeOrigin::signed(3),
            0
        ));

        let validator = Validators::<Test>::get(0).unwrap();
        assert_eq!(validator.status, RegistryStatus::Disabled);
        assert_eq!(
            validator.stake_commitment,
            expected_validator_stake_commitment(0, 3, RegistryStatus::Disabled)
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::ValidatorStake.into(), &3),
            0
        );
        assert_noop!(
            Qubitum::deactivate_validator(RuntimeOrigin::signed(3), 0),
            Error::<Test>::InvalidValidatorStatus
        );
    });
}

#[test]
fn validator_cannot_exit_with_pending_proof_assignment() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(41);

        assert_noop!(
            Qubitum::deactivate_validator(RuntimeOrigin::signed(3), 0),
            Error::<Test>::PendingAssignedRequests
        );
        assert_ok!(submit_proof(RuntimeOrigin::signed(3), valid_submission(41)));
    });
}

#[test]
fn submit_proof_records_commitments_for_active_participants() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(42);
        System::set_block_number(123);
        let mut submission = valid_submission(42);
        submission.submitted_at = 120;
        submission = bind_proof_transcript(submission);
        let expected_audit_commitment =
            Qubitum::proof_audit_commitment(&submission, 123, assignment_blinding());

        assert_ok!(Qubitum::submit_proof(
            RuntimeOrigin::signed(3),
            submission,
            4,
            2,
            assignment_blinding(),
            request_terms_witness()
        ));

        let record = ProofRecords::<Test>::get(42).unwrap();
        assert_eq!(record.request_id, 42);
        assert_eq!(
            record.assignment_commitment,
            Qubitum::request_assignment_commitment(42, 0, 0, 0, assignment_blinding())
        );
        assert_eq!(record.audit_commitment, expected_audit_commitment);
        assert_eq!(record.proof_system, ProofSystem::RiscZeroStark);
        let encoded_record = record.encode();
        for hidden in [
            commitment(1).encode(),
            commitment(2).encode(),
            commitment(10).encode(),
            proof(11).encode(),
            TARGET_PROOF_SIZE_MIN_BYTES.encode(),
            10_u32.encode(),
            120_u64.encode(),
            123_u64.encode(),
        ] {
            assert!(!contains_subsequence(&encoded_record, &hidden));
        }
        assert_eq!(
            InferenceRequests::<Test>::get(42).unwrap().status,
            InferenceRequestStatus::Settled
        );
        assert_eq!(TotalInferenceEscrowed::<Test>::get(), 1_000);
        assert_eq!(TotalMinerPayouts::<Test>::get(), 970);
        assert_eq!(TotalValidatorFees::<Test>::get(), 25);
        assert_eq!(TotalTreasuryFees::<Test>::get(), 5);
        assert_eq!(TotalInferenceRefunded::<Test>::get(), 0);
        assert_eq!(
            Qubitum::request_status_counts(),
            ChainRequestStatusCounts {
                pending: 0,
                settled: 1,
                cancelled: 0,
                rejected: 0,
                expired: 0,
            }
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            0
        );
        assert_eq!(
            Balances::free_balance(2),
            1_000_000_000_000_000 - MINER_REGISTRATION_BURN - MIN_MINER_BOND + 970
        );
        assert_eq!(
            Balances::free_balance(3),
            1_000_000_000_000_000 - MIN_MINER_BOND + 25
        );
        assert_eq!(Balances::free_balance(99), 5);
    });
}

#[test]
fn stored_runtime_records_do_not_expose_raw_inference_or_model_payloads() {
    new_test_ext().execute_with(|| {
        let raw_input = b"PRIVATE_RAW_USER_PROMPT_transfer_strategy_and_customer_context";
        let raw_output = b"PRIVATE_RAW_MODEL_OUTPUT_ranked_answers_and_reasoning_trace";
        let raw_model = b"PRIVATE_RAW_MODEL_WEIGHTS_transformer_layer_bytes";

        register_active_miner_and_validator();
        request_inference(43);
        System::set_block_number(5);
        assert_ok!(submit_proof(RuntimeOrigin::signed(3), valid_submission(43)));

        for encoded in [
            Miners::<Test>::get(0).unwrap().encode(),
            Validators::<Test>::get(0).unwrap().encode(),
            InferenceRequests::<Test>::get(43).unwrap().encode(),
            ProofRecords::<Test>::get(43).unwrap().encode(),
        ] {
            assert!(!contains_subsequence(&encoded, raw_input));
            assert!(!contains_subsequence(&encoded, raw_output));
            assert!(!contains_subsequence(&encoded, raw_model));
        }

        assert!(!contains_subsequence(
            &Miners::<Test>::get(0).unwrap().encode(),
            &2_u64.encode()
        ));
        assert!(!contains_subsequence(
            &Miners::<Test>::get(0).unwrap().encode(),
            &MIN_MINER_BOND.encode()
        ));
        assert!(!contains_subsequence(
            &Validators::<Test>::get(0).unwrap().encode(),
            &3_u64.encode()
        ));
        assert!(!contains_subsequence(
            &Validators::<Test>::get(0).unwrap().encode(),
            &MIN_MINER_BOND.encode()
        ));
        assert!(!contains_subsequence(
            &InferenceRequests::<Test>::get(43).unwrap().encode(),
            &4_u64.encode()
        ));
    });
}

#[test]
fn public_request_and_proof_views_redact_private_route_payment_and_timing() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        System::set_block_number(99);
        RequestCount::<Test>::put(91);
        assert_ok!(Qubitum::request_inference(
            RuntimeOrigin::signed(4),
            91,
            InferenceRequestParams {
                subnet_id: 0,
                miner_id: 0,
                validator_id: 0,
                input_commitment: commitment(1),
                assignment_blinding: assignment_blinding(),
                timing_blinding: timing_blinding(),
                terms_blinding: terms_blinding(),
                payment: 123_456_789,
                validator_fee_bps: 777,
                treasury_fee_bps: 888,
            },
        ));

        let public_request = Qubitum::public_inference_request(91).unwrap();
        assert_eq!(
            public_request,
            ChainPublicInferenceRequest {
                request_id: 91,
                subnet_id: 0,
                status: InferenceRequestStatus::Pending,
            }
        );
        let encoded_request = public_request.encode();
        for hidden in [
            4_u64.encode(),
            123_456_789_u128.encode(),
            777_u16.encode(),
            888_u16.encode(),
            99_u64.encode(),
            commitment(1).encode(),
        ] {
            assert!(!contains_subsequence(&encoded_request, &hidden));
        }

        System::set_block_number(100);
        let mut submission = valid_submission(91);
        submission.proof_size_bytes = 65_432;
        submission.verification_latency_ms = 77;
        submission.submitted_at = 100;
        submission = bind_proof_transcript(submission);
        assert_ok!(Qubitum::submit_proof(
            RuntimeOrigin::signed(3),
            submission,
            4,
            2,
            assignment_blinding(),
            terms_witness(inference_terms(123_456_789, 777, 888), terms_blinding())
        ));

        let public_proof = Qubitum::public_proof_record(91).unwrap();
        assert_eq!(
            public_proof,
            ChainPublicProofRecord {
                request_id: 91,
                subnet_id: 0,
                proof_system: ProofSystem::RiscZeroStark,
            }
        );
        let encoded_proof = public_proof.encode();
        for hidden in [
            65_432_u32.encode(),
            77_u32.encode(),
            100_u64.encode(),
            commitment(1).encode(),
            commitment(2).encode(),
            commitment(10).encode(),
            proof(11).encode(),
        ] {
            assert!(!contains_subsequence(&encoded_proof, &hidden));
        }
    });
}

#[test]
fn public_registry_views_redact_operator_capital_and_model_commitments() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();

        let public_miner = Qubitum::public_miner(0).unwrap();
        assert_eq!(
            public_miner,
            ChainPublicMiner {
                id: 0,
                subnet_id: 0,
                proof_system: ProofSystem::RiscZeroStark,
                status: PublicRegistryStatus::Active,
            }
        );
        let encoded_miner = public_miner.encode();
        for hidden in [
            2_u64.encode(),
            MIN_MINER_BOND.encode(),
            commitment(10).encode(),
        ] {
            assert!(!contains_subsequence(&encoded_miner, &hidden));
        }

        let public_validator = Qubitum::public_validator(0).unwrap();
        assert_eq!(
            public_validator,
            ChainPublicValidator {
                id: 0,
                subnet_id: 0,
                status: PublicRegistryStatus::Active,
            }
        );
        let encoded_validator = public_validator.encode();
        for hidden in [3_u64.encode(), MIN_MINER_BOND.encode()] {
            assert!(!contains_subsequence(&encoded_validator, &hidden));
        }

        assert_ok!(Qubitum::deactivate_miner(RuntimeOrigin::signed(2), 0));
        let exiting_miner = Qubitum::public_miner(0).unwrap();
        assert_eq!(exiting_miner.status, PublicRegistryStatus::Exiting);
        assert!(!contains_subsequence(
            &exiting_miner.encode(),
            &20_u64.encode()
        ));

        assert_ok!(Qubitum::deactivate_validator(RuntimeOrigin::signed(3), 0));
        let exiting_validator = Qubitum::public_validator(0).unwrap();
        assert_eq!(exiting_validator.status, PublicRegistryStatus::Exiting);
        assert!(!contains_subsequence(
            &exiting_validator.encode(),
            &20_u64.encode()
        ));
    });
}

#[test]
fn public_registry_events_redact_operator_capital_model_and_exit_schedule() {
    new_test_ext().execute_with(|| {
        System::set_block_number(7);
        let miner_bond = MIN_MINER_BOND + 12_345;
        let validator_stake = MIN_MINER_BOND + 54_321;

        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::Code,
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::register_miner(
            RuntimeOrigin::signed(2),
            0,
            commitment(44),
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::activate_miner(
            RuntimeOrigin::signed(2),
            0,
            miner_bond
        ));
        assert_ok!(Qubitum::register_validator(
            RuntimeOrigin::signed(3),
            0,
            validator_stake
        ));
        assert_ok!(Qubitum::deactivate_miner(RuntimeOrigin::signed(2), 0));
        assert_ok!(Qubitum::deactivate_validator(RuntimeOrigin::signed(3), 0));

        System::set_block_number(27);
        assert_ok!(Qubitum::withdraw_miner_bond(RuntimeOrigin::signed(2), 0));
        assert_ok!(Qubitum::withdraw_validator_stake(
            RuntimeOrigin::signed(3),
            0
        ));

        let events: Vec<_> = System::events()
            .into_iter()
            .filter_map(|record| match record.event {
                RuntimeEvent::Qubitum(event) => Some(event),
                _ => None,
            })
            .collect();

        assert!(
            events
                .iter()
                .any(|event| matches!(event, crate::Event::SubnetCreated { subnet_id: 0 }))
        );
        assert!(events.iter().any(|event| matches!(
            event,
            crate::Event::MinerRegistered {
                miner_id: 0,
                subnet_id: 0,
            }
        )));
        assert!(
            events
                .iter()
                .any(|event| matches!(event, crate::Event::MinerActivated { miner_id: 0 }))
        );
        assert!(events.iter().any(|event| matches!(
            event,
            crate::Event::ValidatorRegistered {
                validator_id: 0,
                subnet_id: 0,
            }
        )));
        assert!(
            events
                .iter()
                .any(|event| matches!(event, crate::Event::MinerExitStarted { miner_id: 0 }))
        );
        assert!(events.iter().any(|event| matches!(
            event,
            crate::Event::ValidatorExitStarted { validator_id: 0 }
        )));
        assert!(
            events
                .iter()
                .any(|event| matches!(event, crate::Event::MinerBondWithdrawn { miner_id: 0 }))
        );
        assert!(events.iter().any(|event| matches!(
            event,
            crate::Event::ValidatorStakeWithdrawn { validator_id: 0 }
        )));

        for encoded in events.iter().map(Encode::encode) {
            for hidden in [
                miner_bond.encode(),
                validator_stake.encode(),
                commitment(44).encode(),
                27_u64.encode(),
            ] {
                assert!(!contains_subsequence(&encoded, &hidden));
            }
        }
    });
}

#[test]
fn identity_update_events_redact_commitments_signatures_and_challenges() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        System::set_block_number(1);
        System::reset_events();

        let miner_identity_commitment = commitment(150);
        let miner_endpoint_commitment = commitment(151);
        let miner_bundle = miner_identity_signature_bundle(
            0,
            Some(miner_identity_commitment),
            Some(miner_endpoint_commitment),
        );
        let miner_signature = miner_bundle.post_quantum.unwrap();
        assert_ok!(Qubitum::set_miner_identity_commitments(
            RuntimeOrigin::signed(2),
            0,
            Some(miner_identity_commitment),
            Some(miner_endpoint_commitment),
            miner_bundle,
        ));

        let validator_identity_commitment = commitment(152);
        let validator_endpoint_commitment = commitment(153);
        let validator_bundle = validator_identity_signature_bundle(
            0,
            Some(validator_identity_commitment),
            Some(validator_endpoint_commitment),
        );
        let validator_signature = validator_bundle.post_quantum.unwrap();
        assert_ok!(Qubitum::set_validator_identity_commitments(
            RuntimeOrigin::signed(3),
            0,
            Some(validator_identity_commitment),
            Some(validator_endpoint_commitment),
            validator_bundle,
        ));

        let miner_challenge = MinerIdentitySignatureChallenges::<Test>::get(0).unwrap();
        let validator_challenge = ValidatorIdentitySignatureChallenges::<Test>::get(0).unwrap();
        let events: Vec<_> = System::events()
            .into_iter()
            .filter_map(|record| match record.event {
                RuntimeEvent::Qubitum(event) => Some(event),
                _ => None,
            })
            .collect();

        assert!(
            events
                .iter()
                .any(|event| matches!(event, crate::Event::MinerIdentityCommitmentsUpdated))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, crate::Event::ValidatorIdentityCommitmentsUpdated))
        );

        for encoded in events.iter().map(Encode::encode) {
            for hidden in [
                0_u64.encode(),
                miner_identity_commitment.encode(),
                miner_endpoint_commitment.encode(),
                miner_signature.public_key_commitment.encode(),
                miner_signature.signature_commitment.encode(),
                miner_challenge.encode(),
                validator_identity_commitment.encode(),
                validator_endpoint_commitment.encode(),
                validator_signature.public_key_commitment.encode(),
                validator_signature.signature_commitment.encode(),
                validator_challenge.encode(),
            ] {
                assert!(!contains_subsequence(&encoded, &hidden));
            }
        }
    });
}

#[test]
fn public_lifecycle_events_redact_route_payment_and_proof_metadata() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        System::set_block_number(1);
        System::reset_events();
        RequestCount::<Test>::put(96);

        assert_ok!(Qubitum::request_inference_auto_route(
            RuntimeOrigin::signed(4),
            96,
            AutoRouteInferenceRequestParams {
                subnet_id: 0,
                input_commitment: commitment(31),
                assignment_blinding: assignment_blinding(),
                timing_blinding: timing_blinding(),
                terms_blinding: terms_blinding(),
                payment: 123_456_789,
                validator_fee_bps: 777,
                treasury_fee_bps: 888,
            },
        ));

        System::set_block_number(2);
        let mut submission = valid_submission(96);
        submission.input_commitment = commitment(31);
        submission.output_commitment = commitment(32);
        submission.proof = proof(33);
        submission.proof_size_bytes = 65_432;
        submission.verification_latency_ms = 77;
        submission.submitted_at = 2;
        submission = bind_proof_transcript(submission);
        assert_ok!(Qubitum::submit_proof(
            RuntimeOrigin::signed(3),
            submission,
            4,
            2,
            assignment_blinding(),
            terms_witness(inference_terms(123_456_789, 777, 888), terms_blinding())
        ));

        let events: Vec<_> = System::events()
            .into_iter()
            .filter_map(|record| match record.event {
                RuntimeEvent::Qubitum(event) => Some(event),
                _ => None,
            })
            .collect();

        assert!(events.iter().any(|event| matches!(
            event,
            crate::Event::InferenceRequested {
                request_id: 96,
                subnet_id: 0,
            }
        )));
        assert!(
            events
                .iter()
                .any(|event| matches!(event, crate::Event::ProofAccepted { request_id: 96 }))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, crate::Event::InferenceSettled { request_id: 96 }))
        );

        for encoded in events.iter().map(Encode::encode) {
            for hidden in [
                123_456_789_u128.encode(),
                777_u16.encode(),
                888_u16.encode(),
                65_432_u32.encode(),
                77_u32.encode(),
                commitment(31).encode(),
                commitment(32).encode(),
                commitment(10).encode(),
                proof(33).encode(),
            ] {
                assert!(!contains_subsequence(&encoded, &hidden));
            }
        }
    });
}

#[test]
fn public_failure_events_redact_route_payment_and_proof_metadata() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        System::set_block_number(1);
        System::reset_events();
        RequestCount::<Test>::put(97);

        assert_ok!(Qubitum::request_inference_auto_route(
            RuntimeOrigin::signed(4),
            97,
            AutoRouteInferenceRequestParams {
                subnet_id: 0,
                input_commitment: commitment(41),
                assignment_blinding: assignment_blinding(),
                timing_blinding: timing_blinding(),
                terms_blinding: terms_blinding(),
                payment: 123_456_789,
                validator_fee_bps: 777,
                treasury_fee_bps: 888,
            },
        ));

        System::set_block_number(2);
        let mut submission = valid_submission(97);
        submission.input_commitment = commitment(41);
        submission.output_commitment = commitment(42);
        submission.proof = proof(43);
        submission.proof_size_bytes = 65_432;
        submission.verification_latency_ms = 77;
        submission.submitted_at = 2;
        submission = bind_proof_transcript(submission);
        set_verification_outcome(VerificationOutcome::Invalid { slash_bps: 1_000 });
        assert_ok!(Qubitum::submit_proof(
            RuntimeOrigin::signed(3),
            submission,
            4,
            2,
            assignment_blinding(),
            terms_witness(inference_terms(123_456_789, 777, 888), terms_blinding())
        ));

        let events: Vec<_> = System::events()
            .into_iter()
            .filter_map(|record| match record.event {
                RuntimeEvent::Qubitum(event) => Some(event),
                _ => None,
            })
            .collect();

        assert!(
            events
                .iter()
                .any(|event| matches!(event, crate::Event::MinerSlashed { miner_id: 0 }))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, crate::Event::ValidatorSlashed { validator_id: 0 }))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, crate::Event::ProofRejected { request_id: 97 }))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, crate::Event::InferenceRefunded { request_id: 97 }))
        );

        for encoded in events.iter().map(Encode::encode) {
            for hidden in [
                123_456_789_u128.encode(),
                777_u16.encode(),
                888_u16.encode(),
                65_432_u32.encode(),
                77_u32.encode(),
                commitment(41).encode(),
                commitment(42).encode(),
                commitment(10).encode(),
                proof(43).encode(),
            ] {
                assert!(!contains_subsequence(&encoded, &hidden));
            }
        }
    });

    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        System::set_block_number(1);
        System::reset_events();
        RequestCount::<Test>::put(98);

        assert_ok!(Qubitum::request_inference_auto_route(
            RuntimeOrigin::signed(4),
            98,
            AutoRouteInferenceRequestParams {
                subnet_id: 0,
                input_commitment: commitment(51),
                assignment_blinding: assignment_blinding(),
                timing_blinding: timing_blinding(),
                terms_blinding: terms_blinding(),
                payment: 987_654_321,
                validator_fee_bps: 444,
                treasury_fee_bps: 555,
            },
        ));

        System::set_block_number(2);
        let mut submission = valid_submission(98);
        submission.input_commitment = commitment(51);
        submission.output_commitment = commitment(52);
        submission.proof = proof(53);
        submission.proof_size_bytes = 54_321;
        submission.verification_latency_ms = 88;
        submission.submitted_at = 2;
        submission = bind_proof_transcript(submission);
        set_verification_outcome(VerificationOutcome::Invalid { slash_bps: 1_000 });
        assert_ok!(Qubitum::challenge_proof(
            RuntimeOrigin::signed(4),
            submission,
            4,
            2,
            assignment_blinding(),
            terms_witness(inference_terms(987_654_321, 444, 555), terms_blinding())
        ));

        let events: Vec<_> = System::events()
            .into_iter()
            .filter_map(|record| match record.event {
                RuntimeEvent::Qubitum(event) => Some(event),
                _ => None,
            })
            .collect();

        assert!(
            events
                .iter()
                .any(|event| matches!(event, crate::Event::MinerSlashed { miner_id: 0 }))
        );
        assert!(events.iter().any(|event| matches!(
            event,
            crate::Event::ProofChallengeAccepted { request_id: 98 }
        )));
        assert!(
            events
                .iter()
                .any(|event| matches!(event, crate::Event::InferenceRefunded { request_id: 98 }))
        );

        for encoded in events.iter().map(Encode::encode) {
            for hidden in [
                987_654_321_u128.encode(),
                444_u16.encode(),
                555_u16.encode(),
                54_321_u32.encode(),
                88_u32.encode(),
                commitment(51).encode(),
                commitment(52).encode(),
                commitment(10).encode(),
                proof(53).encode(),
            ] {
                assert!(!contains_subsequence(&encoded, &hidden));
            }
        }
    });
}

#[test]
fn runtime_upgrade_migrates_subnet_owner_and_policy_to_commitments() {
    new_test_ext().execute_with(|| {
        let legacy = LegacyChainSubnetV15 {
            id: 7,
            owner: 44,
            domain: SubnetDomain::Code,
            proof_system: ProofSystem::RiscZeroStark,
            creation_burn: subnet_creation_burn(),
            min_miner_bond: MIN_MINER_BOND,
            max_miner_bond: MAX_MINER_BOND,
            min_validator_stake: MIN_MINER_BOND,
            active: true,
        };
        sp_io::storage::set(&Subnets::<Test>::hashed_key_for(7), &legacy.encode());
        StorageVersion::new(15).put::<crate::Pallet<Test>>();

        <Qubitum as Hooks<u64>>::on_runtime_upgrade();

        let subnet = Subnets::<Test>::get(7).unwrap();
        assert_eq!(subnet.id, 7);
        assert_eq!(
            subnet.owner_commitment,
            Qubitum::subnet_owner_commitment(&44)
        );
        assert_eq!(
            subnet.policy_commitment,
            Qubitum::subnet_policy_commitment(7, SubnetDomain::Code, ProofSystem::RiscZeroStark)
        );
        assert!(subnet.active);
        assert!(!contains_subsequence(&subnet.encode(), &44_u64.encode()));
        assert!(!contains_subsequence(
            &subnet.encode(),
            &MIN_MINER_BOND.encode()
        ));
        assert_eq!(
            StorageVersion::get::<crate::Pallet<Test>>(),
            StorageVersion::new(18)
        );
    });
}

#[test]
fn runtime_upgrade_migrates_identity_signature_challenges() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();

        assert_ok!(Qubitum::set_miner_identity_commitments(
            RuntimeOrigin::signed(2),
            0,
            Some(commitment(70)),
            Some(commitment(71)),
            miner_identity_signature_bundle(0, Some(commitment(70)), Some(commitment(71))),
        ));
        assert_ok!(Qubitum::set_validator_identity_commitments(
            RuntimeOrigin::signed(3),
            0,
            Some(commitment(72)),
            Some(commitment(73)),
            validator_identity_signature_bundle(0, Some(commitment(72)), Some(commitment(73))),
        ));

        MinerIdentitySignatureChallenges::<Test>::remove(0);
        ValidatorIdentitySignatureChallenges::<Test>::remove(0);
        StorageVersion::new(16).put::<crate::Pallet<Test>>();

        <Qubitum as Hooks<u64>>::on_runtime_upgrade();

        let miner = Miners::<Test>::get(0).unwrap();
        assert_eq!(
            MinerIdentitySignatureChallenges::<Test>::get(0),
            Some(Qubitum::miner_identity_signature_challenge(
                0,
                miner.operator_commitment,
                Some(commitment(70)),
                Some(commitment(71)),
            ))
        );
        let validator = Validators::<Test>::get(0).unwrap();
        assert_eq!(
            ValidatorIdentitySignatureChallenges::<Test>::get(0),
            Some(Qubitum::validator_identity_signature_challenge(
                0,
                validator.operator_commitment,
                Some(commitment(72)),
                Some(commitment(73)),
            ))
        );
        assert_eq!(
            StorageVersion::get::<crate::Pallet<Test>>(),
            StorageVersion::new(18)
        );
    });
}

#[test]
fn runtime_upgrade_migrates_proof_record_acceptance_timestamp() {
    new_test_ext().execute_with(|| {
        let legacy = LegacyChainProofRecordV4 {
            request_id: 77,
            subnet_id: 0,
            miner_id: 0,
            validator_id: 0,
            input_commitment: commitment(1),
            output_commitment: commitment(2),
            model_commitment: commitment(10),
            proof: proof(11),
            proof_system: ProofSystem::RiscZeroStark,
            proof_size_bytes: TARGET_PROOF_SIZE_MIN_BYTES,
            verification_latency_ms: 10,
            submitted_at: 55,
        };
        sp_io::storage::set(&ProofRecords::<Test>::hashed_key_for(77), &legacy.encode());
        StorageVersion::new(4).put::<crate::Pallet<Test>>();

        <Qubitum as Hooks<u64>>::on_runtime_upgrade();

        let record = ProofRecords::<Test>::get(77).unwrap();
        let expected_submission = InferenceProofSubmission {
            request_id: 77,
            subnet_id: 0,
            miner_id: 0,
            validator_id: 0,
            input_commitment: commitment(1),
            output_commitment: commitment(2),
            model_commitment: commitment(10),
            proof: proof(11),
            proof_system: ProofSystem::RiscZeroStark,
            proof_size_bytes: TARGET_PROOF_SIZE_MIN_BYTES,
            verification_latency_ms: 10,
            submitted_at: 55,
        };
        assert_eq!(
            record.assignment_commitment,
            Qubitum::legacy_request_assignment_commitment(77, 0, 0, 0)
        );
        assert_eq!(
            record.audit_commitment,
            Qubitum::legacy_proof_audit_commitment(
                expected_submission.request_id,
                expected_submission.subnet_id,
                Qubitum::legacy_request_assignment_commitment(77, 0, 0, 0),
                expected_submission.input_commitment,
                expected_submission.output_commitment,
                expected_submission.model_commitment,
                &expected_submission.proof,
                expected_submission.proof_system,
                expected_submission.proof_size_bytes,
                expected_submission.verification_latency_ms,
                expected_submission.submitted_at,
                55,
            )
        );
        assert!(!contains_subsequence(&record.encode(), &proof(11).encode()));
        assert_eq!(
            StorageVersion::get::<crate::Pallet<Test>>(),
            StorageVersion::new(18)
        );
    });
}

#[test]
fn runtime_upgrade_migrates_proof_record_routes_to_commitments() {
    new_test_ext().execute_with(|| {
        let legacy = LegacyChainProofRecordV11 {
            request_id: 77,
            subnet_id: 3,
            miner_id: 7,
            validator_id: 9,
            input_commitment: commitment(1),
            output_commitment: commitment(2),
            model_commitment: commitment(10),
            proof: proof(11),
            proof_system: ProofSystem::RiscZeroStark,
            proof_size_bytes: TARGET_PROOF_SIZE_MIN_BYTES,
            verification_latency_ms: 10,
            submitted_at: 55,
            accepted_at: 58,
        };
        sp_io::storage::set(&ProofRecords::<Test>::hashed_key_for(77), &legacy.encode());
        StorageVersion::new(11).put::<crate::Pallet<Test>>();

        <Qubitum as Hooks<u64>>::on_runtime_upgrade();

        let record = ProofRecords::<Test>::get(77).unwrap();
        let expected_submission = InferenceProofSubmission {
            request_id: 77,
            subnet_id: 3,
            miner_id: 7,
            validator_id: 9,
            input_commitment: commitment(1),
            output_commitment: commitment(2),
            model_commitment: commitment(10),
            proof: proof(11),
            proof_system: ProofSystem::RiscZeroStark,
            proof_size_bytes: TARGET_PROOF_SIZE_MIN_BYTES,
            verification_latency_ms: 10,
            submitted_at: 55,
        };
        assert_eq!(
            record.assignment_commitment,
            Qubitum::legacy_request_assignment_commitment(77, 3, 7, 9)
        );
        assert_eq!(
            record.audit_commitment,
            Qubitum::legacy_proof_audit_commitment(
                expected_submission.request_id,
                expected_submission.subnet_id,
                Qubitum::legacy_request_assignment_commitment(77, 3, 7, 9),
                expected_submission.input_commitment,
                expected_submission.output_commitment,
                expected_submission.model_commitment,
                &expected_submission.proof,
                expected_submission.proof_system,
                expected_submission.proof_size_bytes,
                expected_submission.verification_latency_ms,
                expected_submission.submitted_at,
                58,
            )
        );
        assert!(!contains_subsequence(&record.encode(), &7_u64.encode()));
        assert!(!contains_subsequence(&record.encode(), &9_u64.encode()));
        assert!(!contains_subsequence(&record.encode(), &proof(11).encode()));
        assert_eq!(
            StorageVersion::get::<crate::Pallet<Test>>(),
            StorageVersion::new(18)
        );
    });
}

#[test]
fn runtime_upgrade_migrates_proof_record_details_to_audit_commitments() {
    new_test_ext().execute_with(|| {
        let legacy = LegacyChainProofRecordV14 {
            request_id: 77,
            subnet_id: 3,
            assignment_commitment: Qubitum::legacy_request_assignment_commitment(77, 3, 7, 9),
            input_commitment: commitment(1),
            output_commitment: commitment(2),
            model_commitment: commitment(10),
            proof: proof(11),
            proof_system: ProofSystem::RiscZeroStark,
            proof_size_bytes: TARGET_PROOF_SIZE_MIN_BYTES,
            verification_latency_ms: 10,
            submitted_at: 55,
            accepted_at: 58,
        };
        sp_io::storage::set(&ProofRecords::<Test>::hashed_key_for(77), &legacy.encode());
        StorageVersion::new(14).put::<crate::Pallet<Test>>();

        <Qubitum as Hooks<u64>>::on_runtime_upgrade();

        let expected_submission = InferenceProofSubmission {
            request_id: 77,
            subnet_id: 3,
            miner_id: 7,
            validator_id: 9,
            input_commitment: commitment(1),
            output_commitment: commitment(2),
            model_commitment: commitment(10),
            proof: proof(11),
            proof_system: ProofSystem::RiscZeroStark,
            proof_size_bytes: TARGET_PROOF_SIZE_MIN_BYTES,
            verification_latency_ms: 10,
            submitted_at: 55,
        };
        let record = ProofRecords::<Test>::get(77).unwrap();
        assert_eq!(
            record.audit_commitment,
            Qubitum::legacy_proof_audit_commitment(
                expected_submission.request_id,
                expected_submission.subnet_id,
                Qubitum::legacy_request_assignment_commitment(77, 3, 7, 9),
                expected_submission.input_commitment,
                expected_submission.output_commitment,
                expected_submission.model_commitment,
                &expected_submission.proof,
                expected_submission.proof_system,
                expected_submission.proof_size_bytes,
                expected_submission.verification_latency_ms,
                expected_submission.submitted_at,
                58,
            )
        );
        for hidden in [
            commitment(1).encode(),
            commitment(2).encode(),
            commitment(10).encode(),
            proof(11).encode(),
            TARGET_PROOF_SIZE_MIN_BYTES.encode(),
            10_u32.encode(),
            55_u64.encode(),
            58_u64.encode(),
        ] {
            assert!(!contains_subsequence(&record.encode(), &hidden));
        }
        assert_eq!(
            StorageVersion::get::<crate::Pallet<Test>>(),
            StorageVersion::new(18)
        );
    });
}

#[test]
fn runtime_upgrade_migrates_registry_operators_to_commitments() {
    new_test_ext().execute_with(|| {
        let legacy_miner = LegacyChainMinerV7 {
            id: 7,
            operator: 22,
            subnet_id: 3,
            model_commitment: commitment(44),
            proof_system: ProofSystem::RiscZeroStark,
            bond: MIN_MINER_BOND,
            status: RegistryStatus::Active,
        };
        let legacy_validator = LegacyChainValidatorV7 {
            id: 9,
            operator: 33,
            subnet_id: 3,
            stake: MIN_MINER_BOND,
            status: RegistryStatus::Active,
        };
        sp_io::storage::set(&Miners::<Test>::hashed_key_for(7), &legacy_miner.encode());
        sp_io::storage::set(
            &Validators::<Test>::hashed_key_for(9),
            &legacy_validator.encode(),
        );
        StorageVersion::new(7).put::<crate::Pallet<Test>>();

        <Qubitum as Hooks<u64>>::on_runtime_upgrade();

        let miner = Miners::<Test>::get(7).unwrap();
        assert_eq!(miner.id, 7);
        assert_eq!(miner.operator_commitment, Qubitum::operator_commitment(&22));
        assert_eq!(miner.model_commitment, commitment(44));
        assert_eq!(
            miner.bond_commitment,
            expected_miner_bond_commitment(7, 22, RegistryStatus::Active)
        );
        assert!(!contains_subsequence(&miner.encode(), &22_u64.encode()));
        assert!(!contains_subsequence(
            &miner.encode(),
            &MIN_MINER_BOND.encode()
        ));

        let validator = Validators::<Test>::get(9).unwrap();
        assert_eq!(validator.id, 9);
        assert_eq!(
            validator.operator_commitment,
            Qubitum::operator_commitment(&33)
        );
        assert_eq!(
            validator.stake_commitment,
            expected_validator_stake_commitment(9, 33, RegistryStatus::Active)
        );
        assert!(!contains_subsequence(&validator.encode(), &33_u64.encode()));
        assert!(!contains_subsequence(
            &validator.encode(),
            &MIN_MINER_BOND.encode()
        ));
        assert_eq!(
            StorageVersion::get::<crate::Pallet<Test>>(),
            StorageVersion::new(18)
        );
    });
}

#[test]
fn runtime_upgrade_migrates_participant_capital_to_commitments() {
    new_test_ext().execute_with(|| {
        let legacy_miner = LegacyChainMinerV9 {
            id: 7,
            operator_commitment: Qubitum::account_commitment(&22),
            subnet_id: 3,
            model_commitment: commitment(44),
            proof_system: ProofSystem::RiscZeroStark,
            bond: MIN_MINER_BOND,
            status: RegistryStatus::Active,
        };
        let legacy_validator = LegacyChainValidatorV9 {
            id: 9,
            operator_commitment: Qubitum::account_commitment(&33),
            subnet_id: 3,
            stake: MIN_MINER_BOND,
            status: RegistryStatus::Active,
        };
        sp_io::storage::set(&Miners::<Test>::hashed_key_for(7), &legacy_miner.encode());
        sp_io::storage::set(
            &Validators::<Test>::hashed_key_for(9),
            &legacy_validator.encode(),
        );
        StorageVersion::new(9).put::<crate::Pallet<Test>>();

        <Qubitum as Hooks<u64>>::on_runtime_upgrade();

        let miner = Miners::<Test>::get(7).unwrap();
        assert_eq!(miner.id, 7);
        assert_eq!(miner.operator_commitment, Qubitum::account_commitment(&22));
        assert_eq!(
            miner.bond_commitment,
            Qubitum::miner_bond_commitment(
                7,
                Qubitum::account_commitment(&22),
                RegistryStatus::Active
            )
        );
        assert!(!contains_subsequence(
            &miner.encode(),
            &MIN_MINER_BOND.encode()
        ));

        let validator = Validators::<Test>::get(9).unwrap();
        assert_eq!(validator.id, 9);
        assert_eq!(
            validator.operator_commitment,
            Qubitum::account_commitment(&33)
        );
        assert_eq!(
            validator.stake_commitment,
            Qubitum::validator_stake_commitment(
                9,
                Qubitum::account_commitment(&33),
                RegistryStatus::Active
            )
        );
        assert!(!contains_subsequence(
            &validator.encode(),
            &MIN_MINER_BOND.encode()
        ));
        assert_eq!(
            StorageVersion::get::<crate::Pallet<Test>>(),
            StorageVersion::new(18)
        );
    });
}

#[test]
fn runtime_upgrade_migrates_request_users_to_commitments() {
    new_test_ext().execute_with(|| {
        let legacy_request = LegacyChainInferenceRequestV8 {
            request_id: 91,
            user: 44,
            subnet_id: 3,
            miner_id: 7,
            validator_id: 9,
            input_commitment: commitment(55),
            payment: 123_456,
            validator_fee_bps: 250,
            treasury_fee_bps: 50,
            created_at: 12,
            status: InferenceRequestStatus::Pending,
        };
        sp_io::storage::set(
            &InferenceRequests::<Test>::hashed_key_for(91),
            &legacy_request.encode(),
        );
        StorageVersion::new(8).put::<crate::Pallet<Test>>();

        <Qubitum as Hooks<u64>>::on_runtime_upgrade();

        let request = InferenceRequests::<Test>::get(91).unwrap();
        assert_eq!(request.request_id, 91);
        assert_eq!(
            request.user_commitment,
            Qubitum::request_user_commitment(&44)
        );
        assert_eq!(
            request.assignment_commitment,
            Qubitum::legacy_request_assignment_commitment(91, 3, 7, 9)
        );
        assert_eq!(
            request.terms_commitment,
            Qubitum::legacy_request_terms_commitment(91, 123_456, 250, 50)
        );
        assert_eq!(
            request.timing_commitment,
            Qubitum::legacy_request_timing_commitment(91, 12)
        );
        assert_eq!(request.status, InferenceRequestStatus::Pending);
        assert!(!contains_subsequence(&request.encode(), &44_u64.encode()));
        assert!(!contains_subsequence(&request.encode(), &7_u64.encode()));
        assert!(!contains_subsequence(&request.encode(), &9_u64.encode()));
        assert_eq!(PendingMinerRequests::<Test>::get(7), 1);
        assert_eq!(PendingValidatorRequests::<Test>::get(9), 1);
        assert_eq!(
            StorageVersion::get::<crate::Pallet<Test>>(),
            StorageVersion::new(18)
        );
    });
}

#[test]
fn runtime_upgrade_migrates_request_timing_to_commitments() {
    new_test_ext().execute_with(|| {
        let legacy_request = LegacyChainInferenceRequestV12 {
            request_id: 91,
            user_commitment: Qubitum::account_commitment(&44),
            subnet_id: 3,
            assignment_commitment: Qubitum::legacy_request_assignment_commitment(91, 3, 7, 9),
            input_commitment: commitment(55),
            payment: 123_456,
            validator_fee_bps: 250,
            treasury_fee_bps: 50,
            created_at: 12,
            status: InferenceRequestStatus::Pending,
        };
        sp_io::storage::set(
            &InferenceRequests::<Test>::hashed_key_for(91),
            &legacy_request.encode(),
        );
        StorageVersion::new(12).put::<crate::Pallet<Test>>();

        <Qubitum as Hooks<u64>>::on_runtime_upgrade();

        let request = InferenceRequests::<Test>::get(91).unwrap();
        assert_eq!(
            request.timing_commitment,
            Qubitum::legacy_request_timing_commitment(91, 12)
        );
        assert_eq!(
            request.terms_commitment,
            Qubitum::legacy_request_terms_commitment(91, 123_456, 250, 50)
        );
        assert_eq!(request.status, InferenceRequestStatus::Pending);
        assert_eq!(
            StorageVersion::get::<crate::Pallet<Test>>(),
            StorageVersion::new(18)
        );
    });
}

#[test]
fn runtime_upgrade_migrates_request_terms_to_commitments() {
    new_test_ext().execute_with(|| {
        let legacy_request = LegacyChainInferenceRequestV13 {
            request_id: 91,
            user_commitment: Qubitum::account_commitment(&44),
            subnet_id: 3,
            assignment_commitment: Qubitum::legacy_request_assignment_commitment(91, 3, 7, 9),
            input_commitment: commitment(55),
            payment: 123_456,
            validator_fee_bps: 250,
            treasury_fee_bps: 50,
            timing_commitment: Qubitum::legacy_request_timing_commitment(91, 12),
            status: InferenceRequestStatus::Settled,
        };
        sp_io::storage::set(
            &InferenceRequests::<Test>::hashed_key_for(91),
            &legacy_request.encode(),
        );
        StorageVersion::new(13).put::<crate::Pallet<Test>>();

        <Qubitum as Hooks<u64>>::on_runtime_upgrade();

        let request = InferenceRequests::<Test>::get(91).unwrap();
        assert_eq!(
            request.terms_commitment,
            Qubitum::legacy_request_terms_commitment(91, 123_456, 250, 50)
        );
        assert_eq!(request.status, InferenceRequestStatus::Settled);
        assert!(!contains_subsequence(
            &request.encode(),
            &123_456_u128.encode()
        ));
        assert_eq!(
            StorageVersion::get::<crate::Pallet<Test>>(),
            StorageVersion::new(18)
        );
        assert_eq!(TotalInferenceEscrowed::<Test>::get(), 123_456);
        assert_eq!(TotalValidatorFees::<Test>::get(), 3_086);
        assert_eq!(TotalTreasuryFees::<Test>::get(), 617);
        assert_eq!(TotalMinerPayouts::<Test>::get(), 119_753);
    });
}

#[test]
fn runtime_upgrade_records_legacy_accounting_failures_without_saturated_totals() {
    new_test_ext().execute_with(|| {
        let max_payment_request = LegacyChainInferenceRequestV13 {
            request_id: 91,
            user_commitment: Qubitum::account_commitment(&44),
            subnet_id: 3,
            assignment_commitment: Qubitum::legacy_request_assignment_commitment(91, 3, 7, 9),
            input_commitment: commitment(55),
            payment: u128::MAX,
            validator_fee_bps: 0,
            treasury_fee_bps: 0,
            timing_commitment: Qubitum::legacy_request_timing_commitment(91, 12),
            status: InferenceRequestStatus::Settled,
        };
        let one_unit_request = LegacyChainInferenceRequestV13 {
            request_id: 92,
            user_commitment: Qubitum::account_commitment(&45),
            subnet_id: 3,
            assignment_commitment: Qubitum::legacy_request_assignment_commitment(92, 3, 7, 9),
            input_commitment: commitment(56),
            payment: 1,
            validator_fee_bps: 0,
            treasury_fee_bps: 0,
            timing_commitment: Qubitum::legacy_request_timing_commitment(92, 13),
            status: InferenceRequestStatus::Settled,
        };
        sp_io::storage::set(
            &InferenceRequests::<Test>::hashed_key_for(91),
            &max_payment_request.encode(),
        );
        sp_io::storage::set(
            &InferenceRequests::<Test>::hashed_key_for(92),
            &one_unit_request.encode(),
        );
        StorageVersion::new(13).put::<crate::Pallet<Test>>();

        <Qubitum as Hooks<u64>>::on_runtime_upgrade();

        assert_eq!(LegacyAccountingMigrationFailures::<Test>::get(), 1);
        assert_eq!(TotalInferenceEscrowed::<Test>::get(), 0);
        assert_eq!(TotalMinerPayouts::<Test>::get(), 0);
        assert_eq!(TotalValidatorFees::<Test>::get(), 0);
        assert_eq!(TotalTreasuryFees::<Test>::get(), 0);
        assert_eq!(TotalInferenceRefunded::<Test>::get(), 0);
        assert_eq!(Qubitum::accounting().legacy_migration_failures, 1);
        assert_eq!(
            InferenceRequests::<Test>::get(91).unwrap().status,
            InferenceRequestStatus::Settled
        );
        assert_eq!(
            InferenceRequests::<Test>::get(92).unwrap().status,
            InferenceRequestStatus::Settled
        );
        assert_eq!(
            StorageVersion::get::<crate::Pallet<Test>>(),
            StorageVersion::new(18)
        );
    });

    new_test_ext().execute_with(|| {
        let invalid_split_request = LegacyChainInferenceRequestV13 {
            request_id: 93,
            user_commitment: Qubitum::account_commitment(&46),
            subnet_id: 3,
            assignment_commitment: Qubitum::legacy_request_assignment_commitment(93, 3, 7, 9),
            input_commitment: commitment(57),
            payment: 100,
            validator_fee_bps: 10_001,
            treasury_fee_bps: 0,
            timing_commitment: Qubitum::legacy_request_timing_commitment(93, 14),
            status: InferenceRequestStatus::Settled,
        };
        sp_io::storage::set(
            &InferenceRequests::<Test>::hashed_key_for(93),
            &invalid_split_request.encode(),
        );
        StorageVersion::new(13).put::<crate::Pallet<Test>>();

        <Qubitum as Hooks<u64>>::on_runtime_upgrade();

        assert_eq!(LegacyAccountingMigrationFailures::<Test>::get(), 1);
        assert_eq!(TotalInferenceEscrowed::<Test>::get(), 0);
        assert_eq!(TotalMinerPayouts::<Test>::get(), 0);
        assert_eq!(TotalValidatorFees::<Test>::get(), 0);
        assert_eq!(TotalTreasuryFees::<Test>::get(), 0);
        assert_eq!(TotalInferenceRefunded::<Test>::get(), 0);
        assert_eq!(Qubitum::accounting().legacy_migration_failures, 1);
        assert_eq!(
            InferenceRequests::<Test>::get(93).unwrap().status,
            InferenceRequestStatus::Settled
        );
    });
}

#[test]
fn request_inference_escrows_payment() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(7);

        let request = InferenceRequests::<Test>::get(7).unwrap();
        assert_eq!(
            request.user_commitment,
            Qubitum::request_user_commitment(&4)
        );
        assert_eq!(
            request.assignment_commitment,
            Qubitum::request_assignment_commitment(7, 0, 0, 0, assignment_blinding())
        );
        assert_eq!(
            request.terms_commitment,
            Qubitum::request_terms_commitment(7, 1_000, 250, 50, terms_blinding())
        );
        assert!(!contains_subsequence(
            &request.encode(),
            &1_000_u128.encode()
        ));
        assert!(!contains_subsequence(&request.encode(), &250_u16.encode()));
        assert!(!contains_subsequence(&request.encode(), &50_u16.encode()));
        assert_eq!(
            request.timing_commitment,
            Qubitum::request_timing_commitment(7, 0, timing_blinding())
        );
        assert_eq!(request.status, InferenceRequestStatus::Pending);
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            1_000
        );
        assert_eq!(RequestCount::<Test>::get(), 8);
        assert_eq!(PendingMinerRequests::<Test>::get(0), 1);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 1);
        assert_eq!(TotalInferenceEscrowed::<Test>::get(), 1_000);
        assert_eq!(TotalInferenceRefunded::<Test>::get(), 0);
        assert_eq!(
            Qubitum::request_status_counts(),
            ChainRequestStatusCounts {
                pending: 1,
                settled: 0,
                cancelled: 0,
                rejected: 0,
                expired: 0,
            }
        );
    });
}

#[test]
fn request_storage_commits_route_assignment_without_raw_participant_ids() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        assert_ok!(Qubitum::register_miner(
            RuntimeOrigin::signed(1),
            0,
            commitment(12),
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::activate_miner(
            RuntimeOrigin::signed(1),
            1,
            MIN_MINER_BOND
        ));
        assert_ok!(Qubitum::set_miner_identity_commitments(
            RuntimeOrigin::signed(1),
            1,
            Some(commitment(124)),
            Some(commitment(125)),
            miner_identity_signature_bundle(1, Some(commitment(124)), Some(commitment(125))),
        ));

        RequestCount::<Test>::put(3);
        let assignment = Qubitum::route_assignment(0, 3).unwrap();
        assert_eq!(assignment.miner_id, 1);
        assert_ok!(Qubitum::request_inference(
            RuntimeOrigin::signed(4),
            3,
            InferenceRequestParams {
                subnet_id: 0,
                miner_id: 0,
                validator_id: 0,
                input_commitment: commitment(1),
                assignment_blinding: assignment_blinding(),
                timing_blinding: timing_blinding(),
                terms_blinding: terms_blinding(),
                payment: 1_000,
                validator_fee_bps: 250,
                treasury_fee_bps: 50,
            },
        ));

        let request = InferenceRequests::<Test>::get(3).unwrap();
        assert_eq!(
            request.assignment_commitment,
            Qubitum::request_assignment_commitment(
                3,
                0,
                assignment.miner_id,
                assignment.validator_id,
                assignment_blinding()
            )
        );
        assert!(!contains_subsequence(
            &request.encode(),
            &assignment.miner_id.encode()
        ));
        assert_eq!(PendingMinerRequests::<Test>::get(assignment.miner_id), 1);
        assert_eq!(
            PendingValidatorRequests::<Test>::get(assignment.validator_id),
            1
        );
    });
}

#[test]
fn request_commitment_call_rejects_unverifiable_committed_payloads_without_state_changes() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        RequestCount::<Test>::put(88);
        let assignment = Qubitum::route_assignment(0, 88).unwrap();
        let assignment_commitment = Qubitum::request_assignment_commitment(
            88,
            0,
            assignment.miner_id,
            assignment.validator_id,
            assignment_blinding(),
        );
        let terms_commitment =
            Qubitum::request_terms_commitment(88, 1_000, 250, 50, terms_blinding());
        let timing_commitment = Qubitum::request_timing_commitment(88, 0, timing_blinding());
        let params = InferenceRequestCommitmentParams {
            subnet_id: 0,
            input_commitment: commitment(1),
            assignment_commitment,
            created_at: 0,
            timing_commitment,
            terms_commitment,
            payment: 1_000,
            validator_fee_bps: 250,
            treasury_fee_bps: 50,
        };
        let encoded_call = crate::Call::<Test>::request_inference_commitments {
            request_id: 88,
            params: params.clone(),
        }
        .encode();

        assert!(!contains_subsequence(
            &encoded_call,
            &assignment_blinding().encode()
        ));
        assert!(!contains_subsequence(
            &encoded_call,
            &terms_blinding().encode()
        ));
        assert!(!contains_subsequence(
            &encoded_call,
            &timing_blinding().encode()
        ));

        assert_noop!(
            Qubitum::request_inference_commitments(RuntimeOrigin::signed(4), 88, params),
            Error::<Test>::UnsupportedCommittedRequestPayload
        );
        assert!(InferenceRequests::<Test>::get(88).is_none());
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            0
        );
        assert_eq!(PendingMinerRequests::<Test>::get(assignment.miner_id), 0);
        assert_eq!(
            PendingValidatorRequests::<Test>::get(assignment.validator_id),
            0
        );
        assert_eq!(RequestCount::<Test>::get(), 88);
    });
}

#[test]
fn request_commitment_call_rejects_before_validating_created_at() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        RequestCount::<Test>::put(89);
        System::set_block_number(5);
        let assignment = Qubitum::route_assignment(0, 89).unwrap();

        assert_noop!(
            Qubitum::request_inference_commitments(
                RuntimeOrigin::signed(4),
                89,
                InferenceRequestCommitmentParams {
                    subnet_id: 0,
                    input_commitment: commitment(1),
                    assignment_commitment: Qubitum::request_assignment_commitment(
                        89,
                        0,
                        assignment.miner_id,
                        assignment.validator_id,
                        assignment_blinding(),
                    ),
                    created_at: 4,
                    timing_commitment: Qubitum::request_timing_commitment(89, 4, timing_blinding()),
                    terms_commitment: Qubitum::request_terms_commitment(
                        89,
                        1_000,
                        250,
                        50,
                        terms_blinding(),
                    ),
                    payment: 1_000,
                    validator_fee_bps: 250,
                    treasury_fee_bps: 50,
                },
            ),
            Error::<Test>::UnsupportedCommittedRequestPayload
        );
        assert!(InferenceRequests::<Test>::get(89).is_none());
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            0
        );
        assert_eq!(PendingMinerRequests::<Test>::get(assignment.miner_id), 0);
        assert_eq!(
            PendingValidatorRequests::<Test>::get(assignment.validator_id),
            0
        );
    });
}

#[test]
fn request_inference_requires_nonzero_assignment_blinding() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        RequestCount::<Test>::put(11);

        assert_noop!(
            Qubitum::request_inference(
                RuntimeOrigin::signed(4),
                11,
                InferenceRequestParams {
                    subnet_id: 0,
                    miner_id: 0,
                    validator_id: 0,
                    input_commitment: commitment(1),
                    assignment_blinding: [0; 32],
                    timing_blinding: timing_blinding(),
                    terms_blinding: terms_blinding(),
                    payment: 1_000,
                    validator_fee_bps: 250,
                    treasury_fee_bps: 50,
                },
            ),
            Error::<Test>::MissingCommitment
        );
    });
}

#[test]
fn request_inference_requires_nonzero_timing_blinding() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        RequestCount::<Test>::put(13);

        assert_noop!(
            Qubitum::request_inference(
                RuntimeOrigin::signed(4),
                13,
                InferenceRequestParams {
                    subnet_id: 0,
                    miner_id: 0,
                    validator_id: 0,
                    input_commitment: commitment(1),
                    assignment_blinding: assignment_blinding(),
                    timing_blinding: [0; 32],
                    terms_blinding: terms_blinding(),
                    payment: 1_000,
                    validator_fee_bps: 250,
                    treasury_fee_bps: 50,
                },
            ),
            Error::<Test>::MissingCommitment
        );
    });
}

#[test]
fn request_inference_requires_nonzero_terms_blinding() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        RequestCount::<Test>::put(12);

        assert_noop!(
            Qubitum::request_inference(
                RuntimeOrigin::signed(4),
                12,
                InferenceRequestParams {
                    subnet_id: 0,
                    miner_id: 0,
                    validator_id: 0,
                    input_commitment: commitment(1),
                    assignment_blinding: assignment_blinding(),
                    timing_blinding: timing_blinding(),
                    terms_blinding: [0; 32],
                    payment: 1_000,
                    validator_fee_bps: 250,
                    treasury_fee_bps: 50,
                },
            ),
            Error::<Test>::MissingCommitment
        );
    });
}

#[test]
fn assignment_blinding_prevents_route_dictionary_witness() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(7);

        let request = InferenceRequests::<Test>::get(7).unwrap();
        assert_eq!(
            request.assignment_commitment,
            Qubitum::request_assignment_commitment(7, 0, 0, 0, assignment_blinding())
        );
        assert_ne!(
            request.assignment_commitment,
            Qubitum::legacy_request_assignment_commitment(7, 0, 0, 0)
        );

        assert_noop!(
            Qubitum::submit_proof(
                RuntimeOrigin::signed(3),
                valid_submission(7),
                4,
                2,
                [0; 32],
                request_terms_witness()
            ),
            Error::<Test>::AssignmentMismatch
        );
        assert_noop!(
            Qubitum::submit_proof(
                RuntimeOrigin::signed(3),
                valid_submission(7),
                4,
                2,
                commitment(91),
                request_terms_witness()
            ),
            Error::<Test>::AssignmentMismatch
        );
        assert_ok!(submit_proof(RuntimeOrigin::signed(3), valid_submission(7)));
    });
}

#[test]
fn terms_blinding_prevents_payment_dictionary_witness() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(7);

        let request = InferenceRequests::<Test>::get(7).unwrap();
        assert_eq!(
            request.terms_commitment,
            Qubitum::request_terms_commitment(7, 1_000, 250, 50, terms_blinding())
        );
        assert_ne!(
            request.terms_commitment,
            Qubitum::legacy_request_terms_commitment(7, 1_000, 250, 50)
        );

        assert_noop!(
            Qubitum::submit_proof(
                RuntimeOrigin::signed(3),
                valid_submission(7),
                4,
                2,
                assignment_blinding(),
                terms_witness(request_terms(), [0; 32])
            ),
            Error::<Test>::RequestMismatch
        );
        assert_noop!(
            Qubitum::submit_proof(
                RuntimeOrigin::signed(3),
                valid_submission(7),
                4,
                2,
                assignment_blinding(),
                terms_witness(inference_terms(999, 250, 50), terms_blinding())
            ),
            Error::<Test>::RequestMismatch
        );
        assert_ok!(submit_proof(RuntimeOrigin::signed(3), valid_submission(7)));
    });
}

#[test]
fn legacy_assignment_witness_preserves_legacy_proof_record_binding() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(7);
        let legacy_assignment = Qubitum::legacy_request_assignment_commitment(7, 0, 0, 0);
        InferenceRequests::<Test>::mutate(7, |maybe_request| {
            maybe_request.as_mut().unwrap().assignment_commitment = legacy_assignment;
        });

        let submission = valid_submission(7);
        let accepted_at = System::block_number();
        let expected_audit = Qubitum::legacy_proof_audit_commitment(
            submission.request_id,
            submission.subnet_id,
            legacy_assignment,
            submission.input_commitment,
            submission.output_commitment,
            submission.model_commitment,
            &submission.proof,
            submission.proof_system,
            submission.proof_size_bytes,
            submission.verification_latency_ms,
            submission.submitted_at,
            accepted_at,
        );

        assert_ok!(Qubitum::submit_proof(
            RuntimeOrigin::signed(3),
            submission,
            4,
            2,
            [0; 32],
            request_terms_witness()
        ));

        let record = ProofRecords::<Test>::get(7).unwrap();
        assert_eq!(record.assignment_commitment, legacy_assignment);
        assert_eq!(record.audit_commitment, expected_audit);
    });
}

#[test]
fn timing_blinding_prevents_created_at_dictionary_witness() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(7);

        let request = InferenceRequests::<Test>::get(7).unwrap();
        assert_eq!(
            request.timing_commitment,
            Qubitum::request_timing_commitment(7, 0, timing_blinding())
        );
        assert_ne!(
            request.timing_commitment,
            Qubitum::legacy_request_timing_commitment(7, 0)
        );

        System::set_block_number(10);
        assert_noop!(
            Qubitum::cancel_inference(
                RuntimeOrigin::signed(4),
                7,
                0,
                0,
                assignment_blinding(),
                legacy_timing_witness(0),
                request_terms_witness()
            ),
            Error::<Test>::RequestMismatch
        );
        assert_noop!(
            Qubitum::cancel_inference(
                RuntimeOrigin::signed(4),
                7,
                0,
                0,
                assignment_blinding(),
                timing_witness(1),
                request_terms_witness()
            ),
            Error::<Test>::RequestMismatch
        );
        assert_ok!(Qubitum::cancel_inference(
            RuntimeOrigin::signed(4),
            7,
            0,
            0,
            assignment_blinding(),
            timing_witness(0),
            request_terms_witness()
        ));
    });
}

#[test]
fn legacy_terms_witness_preserves_migrated_request_settlement() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(7);
        let legacy_terms = Qubitum::legacy_request_terms_commitment(7, 1_000, 250, 50);
        InferenceRequests::<Test>::mutate(7, |maybe_request| {
            maybe_request.as_mut().unwrap().terms_commitment = legacy_terms;
        });

        assert_ok!(Qubitum::submit_proof(
            RuntimeOrigin::signed(3),
            valid_submission(7),
            4,
            2,
            assignment_blinding(),
            terms_witness(request_terms(), [0; 32])
        ));
        assert_eq!(
            InferenceRequests::<Test>::get(7).unwrap().status,
            InferenceRequestStatus::Settled
        );
    });
}

#[test]
fn legacy_timing_witness_preserves_migrated_request_cancellation() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(7);
        let legacy_timing = Qubitum::legacy_request_timing_commitment(7, 0);
        InferenceRequests::<Test>::mutate(7, |maybe_request| {
            maybe_request.as_mut().unwrap().timing_commitment = legacy_timing;
        });

        System::set_block_number(10);
        assert_ok!(Qubitum::cancel_inference(
            RuntimeOrigin::signed(4),
            7,
            0,
            0,
            assignment_blinding(),
            legacy_timing_witness(0),
            request_terms_witness()
        ));
        assert_eq!(
            InferenceRequests::<Test>::get(7).unwrap().status,
            InferenceRequestStatus::Cancelled
        );
    });
}

#[test]
fn pending_assignment_blocks_participant_exit_until_request_closes() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(7);

        assert_noop!(
            Qubitum::deactivate_miner(RuntimeOrigin::signed(2), 0),
            Error::<Test>::PendingAssignedRequests
        );
        assert_noop!(
            Qubitum::deactivate_validator(RuntimeOrigin::signed(3), 0),
            Error::<Test>::PendingAssignedRequests
        );

        assert_ok!(submit_proof(RuntimeOrigin::signed(3), valid_submission(7)));
        assert_eq!(PendingMinerRequests::<Test>::get(0), 0);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 0);

        assert_ok!(Qubitum::deactivate_miner(RuntimeOrigin::signed(2), 0));
        assert_ok!(Qubitum::deactivate_validator(RuntimeOrigin::signed(3), 0));
    });
}

#[test]
fn root_slash_rejects_pending_assigned_participants() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(7);

        assert_noop!(
            Qubitum::slash_miner(RuntimeOrigin::root(), 0, 2, 1_000),
            Error::<Test>::PendingAssignedRequests
        );
        assert_noop!(
            Qubitum::slash_validator(RuntimeOrigin::root(), 0, 3, 1_000),
            Error::<Test>::PendingAssignedRequests
        );

        assert_ok!(submit_proof(RuntimeOrigin::signed(3), valid_submission(7)));
        assert_ok!(Qubitum::slash_miner(RuntimeOrigin::root(), 0, 2, 1_000));
        assert_ok!(Qubitum::slash_validator(RuntimeOrigin::root(), 0, 3, 1_000));
    });
}

#[test]
fn request_inference_rejects_non_next_request_id() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();

        assert_noop!(
            Qubitum::request_inference(
                RuntimeOrigin::signed(4),
                1,
                InferenceRequestParams {
                    subnet_id: 0,
                    miner_id: 0,
                    validator_id: 0,
                    input_commitment: commitment(1),
                    assignment_blinding: assignment_blinding(),
                    timing_blinding: timing_blinding(),
                    terms_blinding: terms_blinding(),
                    payment: 1_000,
                    validator_fee_bps: 250,
                    treasury_fee_bps: 50,
                },
            ),
            Error::<Test>::InvalidRequestId
        );
        assert_eq!(RequestCount::<Test>::get(), 0);
    });
}

#[test]
fn request_inference_requires_active_assigned_participants() {
    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::Code,
            ProofSystem::RiscZeroStark
        ));

        assert_noop!(
            Qubitum::request_inference(
                RuntimeOrigin::signed(4),
                10,
                InferenceRequestParams {
                    subnet_id: 0,
                    miner_id: 0,
                    validator_id: 0,
                    input_commitment: commitment(1),
                    assignment_blinding: assignment_blinding(),
                    timing_blinding: timing_blinding(),
                    terms_blinding: terms_blinding(),
                    payment: 1_000,
                    validator_fee_bps: 250,
                    treasury_fee_bps: 50,
                },
            ),
            Error::<Test>::NoRouteAvailable
        );

        assert_ok!(Qubitum::register_miner(
            RuntimeOrigin::signed(2),
            0,
            commitment(10),
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::register_validator(
            RuntimeOrigin::signed(3),
            0,
            MIN_MINER_BOND
        ));

        assert_noop!(
            Qubitum::request_inference(
                RuntimeOrigin::signed(4),
                10,
                InferenceRequestParams {
                    subnet_id: 0,
                    miner_id: 0,
                    validator_id: 0,
                    input_commitment: commitment(1),
                    assignment_blinding: assignment_blinding(),
                    timing_blinding: timing_blinding(),
                    terms_blinding: terms_blinding(),
                    payment: 1_000,
                    validator_fee_bps: 250,
                    treasury_fee_bps: 50,
                },
            ),
            Error::<Test>::NoRouteAvailable
        );
    });
}

#[test]
fn route_assignment_returns_active_participants_only() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        assert_eq!(
            Qubitum::route_assignment(0, 42).map(|assignment| {
                (
                    assignment.request_id,
                    assignment.subnet_id,
                    assignment.miner_id,
                    assignment.validator_id,
                )
            }),
            Some((42, 0, 0, 0))
        );
        assert_eq!(ActiveMinersBySubnet::<Test>::get(0).to_vec(), vec![0]);
        assert_eq!(ActiveValidatorsBySubnet::<Test>::get(0).to_vec(), vec![0]);

        assert_ok!(Qubitum::deactivate_miner(RuntimeOrigin::signed(2), 0));
        assert!(ActiveMinersBySubnet::<Test>::get(0).is_empty());
        assert_eq!(Qubitum::route_assignment(0, 42), None);
    });
}

#[test]
fn next_route_assignment_uses_chain_next_request_id() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        RequestCount::<Test>::put(42);

        let assignment = Qubitum::next_route_assignment(0).unwrap();
        assert_eq!(assignment.request_id, 42);
        assert_eq!(assignment.subnet_id, 0);
        assert_eq!(assignment.miner_id, 0);
        assert_eq!(assignment.validator_id, 0);

        assert_ok!(Qubitum::request_inference(
            RuntimeOrigin::signed(4),
            assignment.request_id,
            InferenceRequestParams {
                subnet_id: assignment.subnet_id,
                miner_id: 0,
                validator_id: 0,
                input_commitment: commitment(1),
                assignment_blinding: assignment_blinding(),
                timing_blinding: timing_blinding(),
                terms_blinding: terms_blinding(),
                payment: 1_000,
                validator_fee_bps: 250,
                treasury_fee_bps: 50,
            },
        ));

        assert_eq!(RequestCount::<Test>::get(), 43);
        assert_eq!(Qubitum::next_route_assignment(0).unwrap().request_id, 43);
    });
}

#[test]
fn public_next_route_availability_does_not_expose_participant_assignment_or_future_oracle() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        RequestCount::<Test>::put(42);

        assert_eq!(
            Qubitum::next_route_availability(0),
            ChainRouteAvailability {
                request_id: 42,
                subnet_id: 0,
                available: true,
            }
        );

        assert_ok!(Qubitum::deactivate_miner(RuntimeOrigin::signed(2), 0));
        assert_eq!(
            Qubitum::next_route_availability(0),
            ChainRouteAvailability {
                request_id: 42,
                subnet_id: 0,
                available: false,
            }
        );
    });
}

#[test]
fn route_assignment_removes_slashed_participants() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();

        assert_ok!(Qubitum::slash_miner(RuntimeOrigin::root(), 0, 2, 1_000));
        assert!(ActiveMinersBySubnet::<Test>::get(0).is_empty());
        assert_eq!(Qubitum::route_assignment(0, 42), None);

        assert_ok!(Qubitum::slash_validator(RuntimeOrigin::root(), 0, 3, 1_000));
        assert!(ActiveValidatorsBySubnet::<Test>::get(0).is_empty());
    });
}

#[test]
fn route_assignment_rejects_self_validation_operator() {
    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::Code,
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::register_miner(
            RuntimeOrigin::signed(2),
            0,
            commitment(10),
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::activate_miner(
            RuntimeOrigin::signed(2),
            0,
            MIN_MINER_BOND
        ));
        assert_ok!(Qubitum::register_validator(
            RuntimeOrigin::signed(2),
            0,
            MIN_MINER_BOND
        ));

        assert_eq!(Qubitum::route_assignment(0, 42), None);
        assert_noop!(
            Qubitum::request_inference(
                RuntimeOrigin::signed(4),
                42,
                InferenceRequestParams {
                    subnet_id: 0,
                    miner_id: 0,
                    validator_id: 0,
                    input_commitment: commitment(1),
                    assignment_blinding: assignment_blinding(),
                    timing_blinding: timing_blinding(),
                    terms_blinding: terms_blinding(),
                    payment: 1_000,
                    validator_fee_bps: 250,
                    treasury_fee_bps: 50,
                },
            ),
            Error::<Test>::NoRouteAvailable
        );
    });
}

#[test]
fn route_assignment_skips_self_validation_validator_when_alternative_exists() {
    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::Code,
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::register_miner(
            RuntimeOrigin::signed(2),
            0,
            commitment(10),
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::activate_miner(
            RuntimeOrigin::signed(2),
            0,
            MIN_MINER_BOND
        ));
        assert_ok!(Qubitum::set_miner_identity_commitments(
            RuntimeOrigin::signed(2),
            0,
            Some(commitment(120)),
            Some(commitment(121)),
            miner_identity_signature_bundle(0, Some(commitment(120)), Some(commitment(121))),
        ));
        assert_ok!(Qubitum::register_validator(
            RuntimeOrigin::signed(2),
            0,
            MIN_MINER_BOND
        ));
        assert_ok!(Qubitum::set_validator_identity_commitments(
            RuntimeOrigin::signed(2),
            0,
            Some(commitment(122)),
            Some(commitment(123)),
            validator_identity_signature_bundle(0, Some(commitment(122)), Some(commitment(123))),
        ));
        assert_ok!(Qubitum::register_validator(
            RuntimeOrigin::signed(3),
            0,
            MIN_MINER_BOND
        ));
        assert_ok!(Qubitum::set_validator_identity_commitments(
            RuntimeOrigin::signed(3),
            1,
            Some(commitment(124)),
            Some(commitment(125)),
            validator_identity_signature_bundle(1, Some(commitment(124)), Some(commitment(125))),
        ));

        let assignment = Qubitum::route_assignment(0, 42).unwrap();
        assert_eq!(assignment.miner_id, 0);
        assert_eq!(assignment.validator_id, 1);
        RequestCount::<Test>::put(42);
        assert_ok!(Qubitum::request_inference(
            RuntimeOrigin::signed(4),
            42,
            InferenceRequestParams {
                subnet_id: 0,
                miner_id: 0,
                validator_id: 0,
                input_commitment: commitment(1),
                assignment_blinding: assignment_blinding(),
                timing_blinding: timing_blinding(),
                terms_blinding: terms_blinding(),
                payment: 1_000,
                validator_fee_bps: 250,
                treasury_fee_bps: 50,
            },
        ));
    });
}

#[test]
fn route_assignment_scans_past_sixteen_self_validation_conflicts() {
    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::Code,
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::register_miner(
            RuntimeOrigin::signed(2),
            0,
            commitment(10),
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::activate_miner(
            RuntimeOrigin::signed(2),
            0,
            MIN_MINER_BOND
        ));
        assert_ok!(Qubitum::set_miner_identity_commitments(
            RuntimeOrigin::signed(2),
            0,
            Some(commitment(120)),
            Some(commitment(121)),
            miner_identity_signature_bundle(0, Some(commitment(120)), Some(commitment(121))),
        ));

        for validator_id in 0..16 {
            assert_ok!(Qubitum::register_validator(
                RuntimeOrigin::signed(2),
                0,
                MIN_MINER_BOND
            ));
            assert_ok!(Qubitum::set_validator_identity_commitments(
                RuntimeOrigin::signed(2),
                validator_id,
                Some(commitment(122)),
                Some(commitment(123)),
                validator_identity_signature_bundle(
                    validator_id,
                    Some(commitment(122)),
                    Some(commitment(123)),
                ),
            ));
        }
        assert_ok!(Qubitum::register_validator(
            RuntimeOrigin::signed(3),
            0,
            MIN_MINER_BOND
        ));
        assert_ok!(Qubitum::set_validator_identity_commitments(
            RuntimeOrigin::signed(3),
            16,
            Some(commitment(124)),
            Some(commitment(125)),
            validator_identity_signature_bundle(16, Some(commitment(124)), Some(commitment(125))),
        ));
        assert_eq!(ActiveValidatorsBySubnet::<Test>::get(0).len(), 17);

        let assignment = Qubitum::route_assignment(0, 0).unwrap();
        assert_eq!(assignment.miner_id, 0);
        assert_eq!(assignment.validator_id, 16);

        assert_ok!(Qubitum::request_inference(
            RuntimeOrigin::signed(4),
            0,
            InferenceRequestParams {
                subnet_id: 0,
                miner_id: 0,
                validator_id: 0,
                input_commitment: commitment(1),
                assignment_blinding: assignment_blinding(),
                timing_blinding: timing_blinding(),
                terms_blinding: terms_blinding(),
                payment: 1_000,
                validator_fee_bps: 250,
                treasury_fee_bps: 50,
            },
        ));
    });
}

#[test]
fn active_miner_index_stays_sorted_by_id() {
    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::Code,
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::register_miner(
            RuntimeOrigin::signed(2),
            0,
            commitment(10),
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::register_miner(
            RuntimeOrigin::signed(2),
            0,
            commitment(11),
            ProofSystem::RiscZeroStark
        ));

        assert_ok!(Qubitum::activate_miner(
            RuntimeOrigin::signed(2),
            1,
            MIN_MINER_BOND
        ));
        assert_ok!(Qubitum::activate_miner(
            RuntimeOrigin::signed(2),
            0,
            MIN_MINER_BOND
        ));

        assert_eq!(ActiveMinersBySubnet::<Test>::get(0).to_vec(), vec![0, 1]);
    });
}

#[test]
fn submit_proof_rejects_self_validation_assignment() {
    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::Code,
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::register_miner(
            RuntimeOrigin::signed(2),
            0,
            commitment(10),
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::activate_miner(
            RuntimeOrigin::signed(2),
            0,
            MIN_MINER_BOND
        ));
        assert_ok!(Qubitum::register_validator(
            RuntimeOrigin::signed(2),
            0,
            MIN_MINER_BOND
        ));
        InferenceRequests::<Test>::insert(
            88,
            ChainInferenceRequest {
                request_id: 88,
                user_commitment: Qubitum::request_user_commitment(&4),
                subnet_id: 0,
                assignment_commitment: Qubitum::request_assignment_commitment(
                    88,
                    0,
                    0,
                    0,
                    assignment_blinding(),
                ),
                input_commitment: commitment(1),
                terms_commitment: Qubitum::request_terms_commitment(
                    88,
                    1_000,
                    250,
                    50,
                    terms_blinding(),
                ),
                timing_commitment: Qubitum::request_timing_commitment(88, 0, timing_blinding()),
                status: InferenceRequestStatus::Pending,
            },
        );

        assert_noop!(
            submit_proof(RuntimeOrigin::signed(2), valid_submission(88)),
            Error::<Test>::SelfValidation
        );
    });
}

#[test]
fn runtime_upgrade_rebuilds_active_routing_indexes() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(42);
        let legacy_subnet = LegacyChainSubnetV15 {
            id: 0,
            owner: 1,
            domain: SubnetDomain::Code,
            proof_system: ProofSystem::RiscZeroStark,
            creation_burn: subnet_creation_burn(),
            min_miner_bond: MIN_MINER_BOND,
            max_miner_bond: MAX_MINER_BOND,
            min_validator_stake: MIN_MINER_BOND,
            active: true,
        };
        sp_io::storage::set(&Subnets::<Test>::hashed_key_for(0), &legacy_subnet.encode());
        let legacy_request = LegacyChainInferenceRequestV10 {
            request_id: 42,
            user_commitment: Qubitum::account_commitment(&4),
            subnet_id: 0,
            miner_id: 0,
            validator_id: 0,
            input_commitment: commitment(1),
            payment: 1_000,
            validator_fee_bps: 250,
            treasury_fee_bps: 50,
            created_at: 0,
            status: InferenceRequestStatus::Pending,
        };
        sp_io::storage::set(
            &InferenceRequests::<Test>::hashed_key_for(42),
            &legacy_request.encode(),
        );
        ActiveMinersBySubnet::<Test>::remove(0);
        ActiveValidatorsBySubnet::<Test>::remove(0);
        PendingMinerRequests::<Test>::remove(0);
        PendingValidatorRequests::<Test>::remove(0);
        PendingInferenceRequestCount::<Test>::put(0);
        SettledInferenceRequestCount::<Test>::put(0);
        CancelledInferenceRequestCount::<Test>::put(0);
        RejectedInferenceRequestCount::<Test>::put(0);
        StorageVersion::new(10).put::<crate::Pallet<Test>>();

        assert_eq!(Qubitum::route_assignment(0, 42), None);
        assert_eq!(PendingMinerRequests::<Test>::get(0), 0);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 0);

        <Qubitum as Hooks<u64>>::on_runtime_upgrade();

        assert_eq!(ActiveMinersBySubnet::<Test>::get(0).to_vec(), vec![0]);
        assert_eq!(ActiveValidatorsBySubnet::<Test>::get(0).to_vec(), vec![0]);
        assert_eq!(PendingMinerRequests::<Test>::get(0), 1);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 1);
        assert_eq!(
            StorageVersion::get::<crate::Pallet<Test>>(),
            StorageVersion::new(18)
        );
        assert_eq!(TotalInferenceEscrowed::<Test>::get(), 1_000);
        assert_eq!(TotalInferenceRefunded::<Test>::get(), 0);
        assert_eq!(
            Qubitum::request_status_counts(),
            ChainRequestStatusCounts {
                pending: 1,
                settled: 0,
                cancelled: 0,
                rejected: 0,
                expired: 0,
            }
        );
        assert!(Qubitum::route_assignment(0, 42).is_some());
    });
}

#[test]
fn runtime_upgrade_demotes_overflow_routing_index_participants_and_reports_health() {
    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::General,
            ProofSystem::RiscZeroStark
        ));

        let miner_limit = <Test as crate::Config>::MaxActiveMinersPerSubnet::get();
        for index in 0..=miner_limit {
            let miner_id = u64::from(index);
            let operator_commitment = Qubitum::operator_commitment(&2);
            Miners::<Test>::insert(
                miner_id,
                ChainMiner {
                    id: miner_id,
                    operator_commitment,
                    subnet_id: 0,
                    model_commitment: commitment((index.saturating_add(10) % 250) as u8),
                    proof_system: ProofSystem::RiscZeroStark,
                    bond_commitment: Qubitum::miner_bond_commitment(
                        miner_id,
                        operator_commitment,
                        RegistryStatus::Active,
                    ),
                    status: RegistryStatus::Active,
                },
            );
        }

        let validator_limit = <Test as crate::Config>::MaxActiveValidatorsPerSubnet::get();
        for index in 0..=validator_limit {
            let validator_id = u64::from(index);
            let operator_commitment = Qubitum::operator_commitment(&3);
            Validators::<Test>::insert(
                validator_id,
                ChainValidator {
                    id: validator_id,
                    operator_commitment,
                    subnet_id: 0,
                    stake_commitment: Qubitum::validator_stake_commitment(
                        validator_id,
                        operator_commitment,
                        RegistryStatus::Active,
                    ),
                    status: RegistryStatus::Active,
                },
            );
        }
        StorageVersion::new(16).put::<crate::Pallet<Test>>();

        <Qubitum as Hooks<u64>>::on_runtime_upgrade();

        assert_eq!(
            ActiveMinersBySubnet::<Test>::get(0).len(),
            miner_limit as usize
        );
        assert_eq!(
            ActiveValidatorsBySubnet::<Test>::get(0).len(),
            validator_limit as usize
        );
        for miner_id in ActiveMinersBySubnet::<Test>::get(0) {
            assert_eq!(
                Miners::<Test>::get(miner_id).unwrap().status,
                RegistryStatus::Active
            );
        }
        for validator_id in ActiveValidatorsBySubnet::<Test>::get(0) {
            assert_eq!(
                Validators::<Test>::get(validator_id).unwrap().status,
                RegistryStatus::Active
            );
        }

        let exiting_miners: Vec<_> = (0..=miner_limit)
            .map(u64::from)
            .filter(|miner_id| {
                matches!(
                    Miners::<Test>::get(miner_id).unwrap().status,
                    RegistryStatus::Exiting {
                        exit_available_at: 20
                    }
                )
            })
            .collect();
        let exiting_validators: Vec<_> = (0..=validator_limit)
            .map(u64::from)
            .filter(|validator_id| {
                matches!(
                    Validators::<Test>::get(validator_id).unwrap().status,
                    RegistryStatus::Exiting {
                        exit_available_at: 20
                    }
                )
            })
            .collect();

        assert_eq!(exiting_miners.len(), 1);
        assert_eq!(exiting_validators.len(), 1);
        let exiting_miner_id = *exiting_miners.first().unwrap();
        let exiting_validator_id = *exiting_validators.first().unwrap();
        assert_eq!(
            Miners::<Test>::get(exiting_miner_id)
                .unwrap()
                .bond_commitment,
            expected_miner_bond_commitment(
                exiting_miner_id,
                2,
                RegistryStatus::Exiting {
                    exit_available_at: 20
                }
            )
        );
        assert_eq!(
            Validators::<Test>::get(exiting_validator_id)
                .unwrap()
                .stake_commitment,
            expected_validator_stake_commitment(
                exiting_validator_id,
                3,
                RegistryStatus::Exiting {
                    exit_available_at: 20
                }
            )
        );
        assert_eq!(LegacyRoutingIndexMigrationFailures::<Test>::get(), 2);
        assert_eq!(Qubitum::migration_health().legacy_routing_index_failures, 2);
        assert_eq!(Qubitum::migration_health().legacy_accounting_failures, 0);
        assert_eq!(
            Qubitum::public_miner(exiting_miner_id).unwrap().status,
            PublicRegistryStatus::Exiting
        );
        assert_eq!(
            Qubitum::public_validator(exiting_validator_id)
                .unwrap()
                .status,
            PublicRegistryStatus::Exiting
        );
        assert_eq!(
            StorageVersion::get::<crate::Pallet<Test>>(),
            StorageVersion::new(18)
        );
    });
}

#[test]
fn runtime_upgrade_reports_missing_legacy_capital_records() {
    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::General,
            ProofSystem::RiscZeroStark
        ));

        let miner_operator_commitment = Qubitum::operator_commitment(&2);
        Miners::<Test>::insert(
            0,
            ChainMiner {
                id: 0,
                operator_commitment: miner_operator_commitment,
                subnet_id: 0,
                model_commitment: commitment(10),
                proof_system: ProofSystem::RiscZeroStark,
                bond_commitment: Qubitum::miner_bond_commitment(
                    0,
                    miner_operator_commitment,
                    RegistryStatus::Active,
                ),
                status: RegistryStatus::Active,
            },
        );
        Miners::<Test>::insert(
            1,
            ChainMiner {
                id: 1,
                operator_commitment: miner_operator_commitment,
                subnet_id: 0,
                model_commitment: commitment(11),
                proof_system: ProofSystem::RiscZeroStark,
                bond_commitment: Qubitum::miner_bond_commitment(
                    1,
                    miner_operator_commitment,
                    RegistryStatus::Disabled,
                ),
                status: RegistryStatus::Disabled,
            },
        );

        let validator_operator_commitment = Qubitum::operator_commitment(&3);
        Validators::<Test>::insert(
            0,
            ChainValidator {
                id: 0,
                operator_commitment: validator_operator_commitment,
                subnet_id: 0,
                stake_commitment: Qubitum::validator_stake_commitment(
                    0,
                    validator_operator_commitment,
                    RegistryStatus::Active,
                ),
                status: RegistryStatus::Active,
            },
        );
        Validators::<Test>::insert(
            1,
            ChainValidator {
                id: 1,
                operator_commitment: validator_operator_commitment,
                subnet_id: 0,
                stake_commitment: Qubitum::validator_stake_commitment(
                    1,
                    validator_operator_commitment,
                    RegistryStatus::Pending,
                ),
                status: RegistryStatus::Pending,
            },
        );
        StorageVersion::new(17).put::<crate::Pallet<Test>>();

        <Qubitum as Hooks<u64>>::on_runtime_upgrade();

        assert_eq!(LegacyCapitalRecordMigrationFailures::<Test>::get(), 2);
        assert_eq!(
            Qubitum::migration_health().legacy_capital_record_failures,
            2
        );
        assert_eq!(Qubitum::migration_health().legacy_accounting_failures, 0);
        assert_eq!(Qubitum::migration_health().legacy_routing_index_failures, 0);
        assert_eq!(ActiveMinersBySubnet::<Test>::get(0).to_vec(), vec![0]);
        assert_eq!(ActiveValidatorsBySubnet::<Test>::get(0).to_vec(), vec![0]);
        assert_eq!(
            StorageVersion::get::<crate::Pallet<Test>>(),
            StorageVersion::new(18)
        );
    });
}

#[test]
fn request_inference_rejects_public_participant_ids() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        assert_ok!(Qubitum::register_miner(
            RuntimeOrigin::signed(2),
            0,
            commitment(10),
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::activate_miner(
            RuntimeOrigin::signed(2),
            1,
            MIN_MINER_BOND
        ));
        assert_ok!(Qubitum::register_validator(
            RuntimeOrigin::signed(3),
            0,
            MIN_MINER_BOND
        ));

        let assignment = Qubitum::route_assignment(0, 52).unwrap();
        assert_eq!(assignment.miner_id, 0);
        assert_eq!(assignment.validator_id, 0);

        assert_noop!(
            Qubitum::request_inference(
                RuntimeOrigin::signed(4),
                52,
                InferenceRequestParams {
                    subnet_id: 0,
                    miner_id: 1,
                    validator_id: assignment.validator_id,
                    input_commitment: commitment(1),
                    assignment_blinding: assignment_blinding(),
                    timing_blinding: timing_blinding(),
                    terms_blinding: terms_blinding(),
                    payment: 1_000,
                    validator_fee_bps: 250,
                    treasury_fee_bps: 50,
                },
            ),
            Error::<Test>::RouteAssignmentMustBeHidden
        );
    });
}

#[test]
fn auto_route_request_computes_assignment_without_caller_supplied_participants() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        System::set_block_number(1);
        System::reset_events();
        RequestCount::<Test>::put(54);

        assert_ok!(Qubitum::request_inference_auto_route(
            RuntimeOrigin::signed(4),
            54,
            AutoRouteInferenceRequestParams {
                subnet_id: 0,
                input_commitment: commitment(1),
                assignment_blinding: assignment_blinding(),
                timing_blinding: timing_blinding(),
                terms_blinding: terms_blinding(),
                payment: 1_000,
                validator_fee_bps: 250,
                treasury_fee_bps: 50,
            },
        ));

        let request = InferenceRequests::<Test>::get(54).unwrap();
        assert_eq!(
            request.user_commitment,
            Qubitum::request_user_commitment(&4)
        );
        assert_eq!(
            request.assignment_commitment,
            Qubitum::request_assignment_commitment(54, 0, 0, 0, assignment_blinding())
        );
        assert_eq!(request.status, InferenceRequestStatus::Pending);
        assert_eq!(RequestCount::<Test>::get(), 55);
        assert_eq!(PendingMinerRequests::<Test>::get(0), 1);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 1);
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            1_000
        );
        assert!(System::events().iter().any(|record| matches!(
            &record.event,
            RuntimeEvent::Qubitum(crate::Event::InferenceRequested {
                request_id: 54,
                subnet_id: 0,
            })
        )));
    });
}

#[test]
fn cancel_inference_releases_pending_escrow() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(8);

        assert_noop!(
            Qubitum::cancel_inference(
                RuntimeOrigin::signed(4),
                8,
                0,
                0,
                assignment_blinding(),
                timing_witness(0),
                request_terms_witness()
            ),
            Error::<Test>::RequestCancelUnavailable
        );

        System::set_block_number(10);
        assert_noop!(
            Qubitum::cancel_inference(
                RuntimeOrigin::signed(4),
                8,
                1,
                0,
                assignment_blinding(),
                timing_witness(0),
                request_terms_witness()
            ),
            Error::<Test>::AssignmentMismatch
        );
        assert_noop!(
            Qubitum::cancel_inference(
                RuntimeOrigin::signed(4),
                8,
                0,
                0,
                assignment_blinding(),
                timing_witness(1),
                request_terms_witness()
            ),
            Error::<Test>::RequestMismatch
        );
        assert_ok!(Qubitum::cancel_inference(
            RuntimeOrigin::signed(4),
            8,
            0,
            0,
            assignment_blinding(),
            timing_witness(0),
            request_terms_witness()
        ));

        let request = InferenceRequests::<Test>::get(8).unwrap();
        assert_eq!(request.status, InferenceRequestStatus::Cancelled);
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            0
        );
        assert_eq!(PendingMinerRequests::<Test>::get(0), 0);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 0);
        assert_eq!(TotalInferenceRefunded::<Test>::get(), 1_000);
        assert_eq!(
            Qubitum::request_status_counts(),
            ChainRequestStatusCounts {
                pending: 0,
                settled: 0,
                cancelled: 1,
                rejected: 0,
                expired: 0,
            }
        );
    });
}

#[test]
fn expire_inference_releases_stale_request_for_any_signed_caller() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(10);

        assert_noop!(
            Qubitum::expire_inference(
                RuntimeOrigin::signed(5),
                10,
                4,
                0,
                0,
                assignment_blinding(),
                timing_witness(0),
                request_terms_witness()
            ),
            Error::<Test>::RequestCancelUnavailable
        );

        System::set_block_number(10);
        assert_noop!(
            Qubitum::expire_inference(
                RuntimeOrigin::signed(5),
                10,
                4,
                0,
                1,
                assignment_blinding(),
                timing_witness(0),
                request_terms_witness()
            ),
            Error::<Test>::AssignmentMismatch
        );
        assert_noop!(
            Qubitum::expire_inference(
                RuntimeOrigin::signed(5),
                10,
                4,
                0,
                0,
                assignment_blinding(),
                timing_witness(1),
                request_terms_witness()
            ),
            Error::<Test>::RequestMismatch
        );
        assert_ok!(Qubitum::expire_inference(
            RuntimeOrigin::signed(5),
            10,
            4,
            0,
            0,
            assignment_blinding(),
            timing_witness(0),
            request_terms_witness()
        ));

        let request = InferenceRequests::<Test>::get(10).unwrap();
        assert_eq!(request.status, InferenceRequestStatus::Expired);
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            0
        );
        assert_eq!(PendingMinerRequests::<Test>::get(0), 0);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 0);
        assert_eq!(TotalInferenceRefunded::<Test>::get(), 1_000);
        assert_eq!(
            Qubitum::request_status_counts(),
            ChainRequestStatusCounts {
                pending: 0,
                settled: 0,
                cancelled: 0,
                rejected: 0,
                expired: 1,
            }
        );
    });
}

#[test]
fn request_terms_witness_gates_payment_transitions() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();

        request_inference(60);
        assert_noop!(
            Qubitum::submit_proof(
                RuntimeOrigin::signed(3),
                valid_submission(60),
                4,
                2,
                assignment_blinding(),
                terms_witness(inference_terms(999, 250, 50), terms_blinding())
            ),
            Error::<Test>::RequestMismatch
        );
        assert!(!ProofRecords::<Test>::contains_key(60));
        assert_eq!(
            InferenceRequests::<Test>::get(60).unwrap().status,
            InferenceRequestStatus::Pending
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            1_000
        );

        assert_noop!(
            Qubitum::submit_proof(
                RuntimeOrigin::signed(3),
                valid_submission(60),
                4,
                2,
                assignment_blinding(),
                terms_witness(inference_terms(0, 250, 50), terms_blinding())
            ),
            Error::<Test>::InvalidPayment
        );
        assert_ok!(submit_proof(RuntimeOrigin::signed(3), valid_submission(60)));

        request_inference(61);
        System::set_block_number(10);
        assert_noop!(
            Qubitum::cancel_inference(
                RuntimeOrigin::signed(4),
                61,
                0,
                0,
                assignment_blinding(),
                timing_witness(0),
                terms_witness(inference_terms(1_000, 251, 50), terms_blinding())
            ),
            Error::<Test>::RequestMismatch
        );
        assert_noop!(
            Qubitum::cancel_inference(
                RuntimeOrigin::signed(4),
                61,
                0,
                0,
                assignment_blinding(),
                timing_witness(0),
                terms_witness(inference_terms(1_000, 9_000, 2_000), terms_blinding())
            ),
            Error::<Test>::InvalidFeeSplit
        );
        assert_ok!(Qubitum::cancel_inference(
            RuntimeOrigin::signed(4),
            61,
            0,
            0,
            assignment_blinding(),
            timing_witness(0),
            request_terms_witness()
        ));

        request_inference(62);
        System::set_block_number(20);
        assert_noop!(
            Qubitum::expire_inference(
                RuntimeOrigin::signed(5),
                62,
                4,
                0,
                0,
                assignment_blinding(),
                timing_witness(10),
                terms_witness(inference_terms(1_001, 250, 50), terms_blinding())
            ),
            Error::<Test>::RequestMismatch
        );
        assert_ok!(Qubitum::expire_inference(
            RuntimeOrigin::signed(5),
            62,
            4,
            0,
            0,
            assignment_blinding(),
            timing_witness(10),
            request_terms_witness()
        ));
    });
}

#[test]
fn rejected_proof_refund_requires_terms_witness() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(63);
        set_verification_outcome(VerificationOutcome::Invalid { slash_bps: 1_000 });
        let burned_before = TotalBurned::<Test>::get();

        assert_noop!(
            Qubitum::submit_proof(
                RuntimeOrigin::signed(3),
                valid_submission(63),
                4,
                2,
                assignment_blinding(),
                terms_witness(inference_terms(999, 250, 50), terms_blinding())
            ),
            Error::<Test>::RequestMismatch
        );
        assert_eq!(
            InferenceRequests::<Test>::get(63).unwrap().status,
            InferenceRequestStatus::Pending
        );
        assert_eq!(RejectedInferenceRequestCount::<Test>::get(), 0);
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            1_000
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2),
            MIN_MINER_BOND
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::ValidatorStake.into(), &3),
            MIN_MINER_BOND
        );
        assert_eq!(TotalBurned::<Test>::get(), burned_before);
        assert_eq!(
            Miners::<Test>::get(0).unwrap().status,
            RegistryStatus::Active
        );
        assert_eq!(
            Validators::<Test>::get(0).unwrap().status,
            RegistryStatus::Active
        );

        assert_ok!(submit_proof(RuntimeOrigin::signed(3), valid_submission(63)));
        assert_eq!(
            InferenceRequests::<Test>::get(63).unwrap().status,
            InferenceRequestStatus::Rejected
        );
        assert_eq!(TotalInferenceRefunded::<Test>::get(), 1_000);
    });
}

#[test]
fn invalid_proof_challenge_preflight_blocks_slash_side_effects() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(64);
        set_verification_outcome(VerificationOutcome::Invalid { slash_bps: 1_000 });
        let burned_before = TotalBurned::<Test>::get();

        assert_noop!(
            Qubitum::challenge_proof(
                RuntimeOrigin::signed(5),
                valid_submission(64),
                5,
                2,
                assignment_blinding(),
                request_terms_witness()
            ),
            Error::<Test>::NotRequestOwner
        );

        assert_eq!(
            InferenceRequests::<Test>::get(64).unwrap().status,
            InferenceRequestStatus::Pending
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            1_000
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2),
            MIN_MINER_BOND
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::ValidatorStake.into(), &3),
            MIN_MINER_BOND
        );
        assert_eq!(TotalBurned::<Test>::get(), burned_before);
        assert_eq!(PendingMinerRequests::<Test>::get(0), 1);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 1);
        assert_eq!(
            Miners::<Test>::get(0).unwrap().status,
            RegistryStatus::Active
        );
        assert_eq!(
            Validators::<Test>::get(0).unwrap().status,
            RegistryStatus::Active
        );
    });
}

#[test]
fn request_user_witness_gates_settlement_challenge_and_expiry() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();

        request_inference(70);
        assert_noop!(
            Qubitum::submit_proof(
                RuntimeOrigin::signed(3),
                valid_submission(70),
                5,
                2,
                assignment_blinding(),
                request_terms_witness()
            ),
            Error::<Test>::NotRequestOwner
        );
        assert_eq!(
            InferenceRequests::<Test>::get(70).unwrap().status,
            InferenceRequestStatus::Pending
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            1_000
        );
        assert_ok!(submit_proof(RuntimeOrigin::signed(3), valid_submission(70)));

        request_inference(71);
        set_verification_outcome(VerificationOutcome::Invalid { slash_bps: 1_000 });
        assert_noop!(
            Qubitum::challenge_proof(
                RuntimeOrigin::signed(5),
                valid_submission(71),
                5,
                2,
                assignment_blinding(),
                request_terms_witness()
            ),
            Error::<Test>::NotRequestOwner
        );
        assert_eq!(
            InferenceRequests::<Test>::get(71).unwrap().status,
            InferenceRequestStatus::Pending
        );
        assert_eq!(PendingMinerRequests::<Test>::get(0), 1);

        request_inference(72);
        System::set_block_number(10);
        assert_noop!(
            Qubitum::expire_inference(
                RuntimeOrigin::signed(5),
                72,
                5,
                0,
                0,
                assignment_blinding(),
                timing_witness(0),
                request_terms_witness()
            ),
            Error::<Test>::NotRequestOwner
        );
        assert_eq!(
            InferenceRequests::<Test>::get(72).unwrap().status,
            InferenceRequestStatus::Pending
        );
        assert_ok!(Qubitum::expire_inference(
            RuntimeOrigin::signed(5),
            72,
            4,
            0,
            0,
            assignment_blinding(),
            timing_witness(0),
            request_terms_witness()
        ));
        assert_eq!(
            InferenceRequests::<Test>::get(72).unwrap().status,
            InferenceRequestStatus::Expired
        );
    });
}

#[test]
fn cancel_inference_rejects_non_owner_or_settled_request() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(9);

        assert_noop!(
            Qubitum::cancel_inference(
                RuntimeOrigin::signed(3),
                9,
                0,
                0,
                assignment_blinding(),
                timing_witness(0),
                request_terms_witness()
            ),
            Error::<Test>::NotRequestOwner
        );

        assert_ok!(submit_proof(RuntimeOrigin::signed(3), valid_submission(9)));
        assert_noop!(
            Qubitum::cancel_inference(
                RuntimeOrigin::signed(4),
                9,
                0,
                0,
                assignment_blinding(),
                timing_witness(0),
                request_terms_witness()
            ),
            Error::<Test>::RequestAlreadySettled
        );
    });
}

#[test]
fn submit_proof_rejects_latency_or_missing_commitment() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();

        assert_noop!(
            submit_proof(
                RuntimeOrigin::signed(3),
                InferenceProofSubmission {
                    request_id: 43,
                    subnet_id: 0,
                    miner_id: 0,
                    validator_id: 0,
                    input_commitment: [0; 32],
                    output_commitment: commitment(2),
                    model_commitment: commitment(10),
                    proof: proof(11),
                    proof_system: ProofSystem::RiscZeroStark,
                    proof_size_bytes: TARGET_PROOF_SIZE_MIN_BYTES,
                    verification_latency_ms: 10,
                    submitted_at: 77,
                }
            ),
            Error::<Test>::MissingCommitment
        );

        request_inference(44);
        assert_noop!(
            submit_proof(
                RuntimeOrigin::signed(3),
                InferenceProofSubmission {
                    request_id: 44,
                    subnet_id: 0,
                    miner_id: 0,
                    validator_id: 0,
                    input_commitment: commitment(1),
                    output_commitment: commitment(2),
                    model_commitment: commitment(10),
                    proof: proof(11),
                    proof_system: ProofSystem::RiscZeroStark,
                    proof_size_bytes: TARGET_PROOF_SIZE_MIN_BYTES,
                    verification_latency_ms: 101,
                    submitted_at: 77,
                }
            ),
            Error::<Test>::LatencyExceeded
        );

        let mut missing_journal = valid_submission(49);
        missing_journal.proof.journal_commitment = [0; 32];
        assert_noop!(
            submit_proof(RuntimeOrigin::signed(3), missing_journal),
            Error::<Test>::MissingCommitment
        );

        let mut wrong_verifier = valid_submission(50);
        wrong_verifier.proof.verifier_version = ProofVerifierVersion::Mock;
        assert_noop!(
            submit_proof(RuntimeOrigin::signed(3), wrong_verifier),
            Error::<Test>::ProofSystemMismatch
        );
    });
}

#[test]
fn submit_proof_rejects_unbound_transcript_commitment() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(44);

        let mut submission = valid_submission(44);
        submission.proof.journal_commitment = commitment(99);
        assert_noop!(
            submit_proof(RuntimeOrigin::signed(3), submission),
            Error::<Test>::ProofTranscriptMismatch
        );

        let mut tampered_output = valid_submission(44);
        tampered_output.output_commitment = commitment(99);
        assert_noop!(
            submit_proof(RuntimeOrigin::signed(3), tampered_output),
            Error::<Test>::ProofTranscriptMismatch
        );
        assert!(!ProofRecords::<Test>::contains_key(44));
    });
}

#[test]
fn fail_closed_verifier_never_accepts_shape_only_proofs() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(44);
        let submission = valid_submission(44);
        let policy = ProofVerificationPolicy {
            proof_system: ProofSystem::RiscZeroStark,
            model_commitment: commitment(10),
            min_proof_size_bytes: TARGET_PROOF_SIZE_MIN_BYTES,
            max_proof_size_bytes: TARGET_PROOF_SIZE_MAX_BYTES,
            max_verification_latency_ms: TARGET_VERIFICATION_MS,
        };

        assert_eq!(
            FailClosedProofVerifier::verify(&submission, policy),
            Ok(VerificationOutcome::Error)
        );
    });
}

#[test]
fn verifier_error_fails_closed_without_settlement_slash_or_refund_side_effects() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(51);
        let burned_before = TotalBurned::<Test>::get();

        set_verification_outcome(VerificationOutcome::Error);
        assert_noop!(
            submit_proof(RuntimeOrigin::signed(3), valid_submission(51)),
            Error::<Test>::VerifierError
        );

        assert!(ProofRecords::<Test>::get(51).is_none());
        assert_eq!(
            InferenceRequests::<Test>::get(51).unwrap().status,
            InferenceRequestStatus::Pending
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            1_000
        );
        assert_eq!(PendingMinerRequests::<Test>::get(0), 1);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 1);
        assert_eq!(MinerLockedBond::<Test>::get(0), Some(MIN_MINER_BOND));
        assert_eq!(ValidatorLockedStake::<Test>::get(0), Some(MIN_MINER_BOND));
        assert_eq!(
            Miners::<Test>::get(0).unwrap().status,
            RegistryStatus::Active
        );
        assert_eq!(
            Validators::<Test>::get(0).unwrap().status,
            RegistryStatus::Active
        );
        assert_eq!(TotalInferenceEscrowed::<Test>::get(), 1_000);
        assert_eq!(TotalInferenceRefunded::<Test>::get(), 0);
        assert_eq!(TotalMinerPayouts::<Test>::get(), 0);
        assert_eq!(TotalValidatorFees::<Test>::get(), 0);
        assert_eq!(TotalTreasuryFees::<Test>::get(), 0);
        assert_eq!(TotalBurned::<Test>::get(), burned_before);
    });

    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(52);
        let burned_before = TotalBurned::<Test>::get();

        set_verification_outcome(VerificationOutcome::Error);
        assert_noop!(
            challenge_proof(RuntimeOrigin::signed(4), valid_submission(52)),
            Error::<Test>::VerifierError
        );

        assert!(ProofRecords::<Test>::get(52).is_none());
        assert_eq!(
            InferenceRequests::<Test>::get(52).unwrap().status,
            InferenceRequestStatus::Pending
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            1_000
        );
        assert_eq!(PendingMinerRequests::<Test>::get(0), 1);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 1);
        assert_eq!(MinerLockedBond::<Test>::get(0), Some(MIN_MINER_BOND));
        assert_eq!(ValidatorLockedStake::<Test>::get(0), Some(MIN_MINER_BOND));
        assert_eq!(
            Miners::<Test>::get(0).unwrap().status,
            RegistryStatus::Active
        );
        assert_eq!(
            Validators::<Test>::get(0).unwrap().status,
            RegistryStatus::Active
        );
        assert_eq!(TotalInferenceEscrowed::<Test>::get(), 1_000);
        assert_eq!(TotalInferenceRefunded::<Test>::get(), 0);
        assert_eq!(TotalMinerPayouts::<Test>::get(), 0);
        assert_eq!(TotalValidatorFees::<Test>::get(), 0);
        assert_eq!(TotalTreasuryFees::<Test>::get(), 0);
        assert_eq!(TotalBurned::<Test>::get(), burned_before);
    });
}

#[test]
fn submit_proof_rejects_future_or_expired_timestamp() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        System::set_block_number(20);
        request_inference(60);

        let mut future = valid_submission(60);
        future.submitted_at = 21;
        assert_noop!(
            submit_proof(RuntimeOrigin::signed(3), future),
            Error::<Test>::ProofSubmittedFromFuture
        );

        request_inference(61);
        let mut expired = valid_submission(61);
        expired.submitted_at = 9;
        assert_noop!(
            submit_proof(RuntimeOrigin::signed(3), expired),
            Error::<Test>::ProofSubmissionExpired
        );
    });
}

#[test]
fn submit_proof_rejects_duplicate_wrong_validator_or_model() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(45);

        assert_ok!(submit_proof(RuntimeOrigin::signed(3), valid_submission(45)));
        assert_noop!(
            submit_proof(RuntimeOrigin::signed(3), valid_submission(45)),
            Error::<Test>::DuplicateProof
        );

        request_inference(46);
        assert_noop!(
            submit_proof(RuntimeOrigin::signed(4), valid_submission(46)),
            Error::<Test>::NotValidatorOperator
        );

        request_inference(47);
        let mut wrong_model = valid_submission(47);
        wrong_model.model_commitment = commitment(99);
        wrong_model = bind_proof_transcript(wrong_model);
        assert_noop!(
            submit_proof(RuntimeOrigin::signed(3), wrong_model),
            Error::<Test>::ModelCommitmentMismatch
        );
    });
}

#[test]
fn submit_proof_rejects_unassigned_participants() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        assert_ok!(Qubitum::register_miner(
            RuntimeOrigin::signed(2),
            0,
            commitment(10),
            ProofSystem::RiscZeroStark
        ));
        assert_ok!(Qubitum::activate_miner(
            RuntimeOrigin::signed(2),
            1,
            MIN_MINER_BOND
        ));
        assert_ok!(Qubitum::register_validator(
            RuntimeOrigin::signed(3),
            0,
            MIN_MINER_BOND
        ));
        request_inference(52);

        let mut wrong_miner = valid_submission(52);
        wrong_miner.miner_id = 1;
        assert_noop!(
            submit_proof(RuntimeOrigin::signed(3), wrong_miner),
            Error::<Test>::AssignmentMismatch
        );

        let mut wrong_validator = valid_submission(52);
        wrong_validator.validator_id = 1;
        assert_noop!(
            submit_proof(RuntimeOrigin::signed(3), wrong_validator),
            Error::<Test>::AssignmentMismatch
        );
    });
}

#[test]
fn verifier_rejection_slashes_and_refunds_request() {
    new_test_ext().execute_with(|| {
        System::set_block_number(1);
        register_active_miner_and_validator();
        request_inference(48);
        set_verification_outcome(VerificationOutcome::Invalid { slash_bps: 1_000 });

        assert_ok!(submit_proof(RuntimeOrigin::signed(3), valid_submission(48)));

        assert!(ProofRecords::<Test>::get(48).is_none());
        assert_eq!(
            InferenceRequests::<Test>::get(48).unwrap().status,
            InferenceRequestStatus::Rejected
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            0
        );
        assert_eq!(PendingMinerRequests::<Test>::get(0), 0);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 0);
        assert_eq!(TotalInferenceRefunded::<Test>::get(), 1_000);
        assert_eq!(
            Qubitum::request_status_counts(),
            ChainRequestStatusCounts {
                pending: 0,
                settled: 0,
                cancelled: 0,
                rejected: 1,
                expired: 0,
            }
        );
        let miner = Miners::<Test>::get(0).unwrap();
        assert_eq!(
            miner.bond_commitment,
            expected_miner_bond_commitment(0, 2, RegistryStatus::Slashed)
        );
        assert_eq!(miner.status, RegistryStatus::Slashed);
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2),
            90_000_000_000
        );
        System::assert_has_event(RuntimeEvent::Qubitum(crate::Event::MinerSlashed {
            miner_id: 0,
        }));
        let validator = Validators::<Test>::get(0).unwrap();
        assert_eq!(
            validator.stake_commitment,
            expected_validator_stake_commitment(0, 3, RegistryStatus::Slashed)
        );
        assert_eq!(validator.status, RegistryStatus::Slashed);
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::ValidatorStake.into(), &3),
            90_000_000_000
        );
        System::assert_has_event(RuntimeEvent::Qubitum(crate::Event::ValidatorSlashed {
            validator_id: 0,
        }));
    });
}

#[test]
fn invalid_proof_challenge_slashes_miner_without_validator_self_slash() {
    new_test_ext().execute_with(|| {
        System::set_block_number(1);
        register_active_miner_and_validator();
        request_inference(49);
        set_verification_outcome(VerificationOutcome::Invalid { slash_bps: 1_000 });

        assert_ok!(challenge_proof(
            RuntimeOrigin::signed(4),
            valid_submission(49)
        ));

        assert!(ProofRecords::<Test>::get(49).is_none());
        assert_eq!(
            InferenceRequests::<Test>::get(49).unwrap().status,
            InferenceRequestStatus::Rejected
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            0
        );
        assert_eq!(PendingMinerRequests::<Test>::get(0), 0);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 0);
        assert_eq!(TotalInferenceRefunded::<Test>::get(), 1_000);

        let miner = Miners::<Test>::get(0).unwrap();
        assert_eq!(
            miner.bond_commitment,
            expected_miner_bond_commitment(0, 2, RegistryStatus::Slashed)
        );
        assert_eq!(miner.status, RegistryStatus::Slashed);
        System::assert_has_event(RuntimeEvent::Qubitum(crate::Event::MinerSlashed {
            miner_id: 0,
        }));
        let validator = Validators::<Test>::get(0).unwrap();
        assert_eq!(
            validator.stake_commitment,
            expected_validator_stake_commitment(0, 3, RegistryStatus::Active)
        );
        assert_eq!(validator.status, RegistryStatus::Active);
    });
}

#[test]
fn invalid_proof_slashing_removes_participants_from_routing_but_preserves_pending_refunds() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(80);
        request_inference(81);
        set_verification_outcome(VerificationOutcome::Invalid { slash_bps: 1_000 });

        assert_eq!(PendingMinerRequests::<Test>::get(0), 2);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 2);

        assert_ok!(submit_proof(RuntimeOrigin::signed(3), valid_submission(80)));

        assert_eq!(
            Miners::<Test>::get(0).unwrap().status,
            RegistryStatus::Slashed
        );
        assert_eq!(
            Validators::<Test>::get(0).unwrap().status,
            RegistryStatus::Slashed
        );
        assert!(ActiveMinersBySubnet::<Test>::get(0).is_empty());
        assert!(ActiveValidatorsBySubnet::<Test>::get(0).is_empty());
        assert_eq!(Qubitum::route_assignment(0, 82), None);
        assert_eq!(PendingMinerRequests::<Test>::get(0), 1);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 1);
        assert_eq!(
            InferenceRequests::<Test>::get(81).unwrap().status,
            InferenceRequestStatus::Pending
        );

        assert_noop!(
            submit_proof(RuntimeOrigin::signed(3), valid_submission(81)),
            Error::<Test>::NotActive
        );

        System::set_block_number(10);
        assert_ok!(Qubitum::expire_inference(
            RuntimeOrigin::signed(5),
            81,
            4,
            0,
            0,
            assignment_blinding(),
            timing_witness(0),
            request_terms_witness()
        ));
        assert_eq!(PendingMinerRequests::<Test>::get(0), 0);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 0);
        assert_eq!(
            InferenceRequests::<Test>::get(81).unwrap().status,
            InferenceRequestStatus::Expired
        );
        assert_eq!(TotalInferenceRefunded::<Test>::get(), 2_000);
    });
}

#[test]
fn valid_proof_challenge_is_rejected_without_state_changes() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(50);

        assert_noop!(
            challenge_proof(RuntimeOrigin::signed(4), valid_submission(50)),
            Error::<Test>::ChallengeProofValid
        );

        assert!(ProofRecords::<Test>::get(50).is_none());
        assert_eq!(
            InferenceRequests::<Test>::get(50).unwrap().status,
            InferenceRequestStatus::Pending
        );
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
            1_000
        );
        assert_eq!(PendingMinerRequests::<Test>::get(0), 1);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 1);
        assert_eq!(
            Miners::<Test>::get(0).unwrap().status,
            RegistryStatus::Active
        );
        assert_eq!(
            Validators::<Test>::get(0).unwrap().status,
            RegistryStatus::Active
        );
    });
}

#[test]
fn malformed_proof_challenges_are_rejected_without_state_changes() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(53);
        set_verification_outcome(VerificationOutcome::Invalid { slash_bps: 1_000 });

        let assert_unchanged = || {
            assert!(ProofRecords::<Test>::get(53).is_none());
            assert_eq!(
                InferenceRequests::<Test>::get(53).unwrap().status,
                InferenceRequestStatus::Pending
            );
            assert_eq!(
                Balances::balance_on_hold(&HoldReason::InferencePayment.into(), &4),
                1_000
            );
            assert_eq!(PendingMinerRequests::<Test>::get(0), 1);
            assert_eq!(PendingValidatorRequests::<Test>::get(0), 1);
            assert_eq!(TotalInferenceRefunded::<Test>::get(), 0);
            assert_eq!(
                Miners::<Test>::get(0).unwrap().status,
                RegistryStatus::Active
            );
            assert_eq!(
                Validators::<Test>::get(0).unwrap().status,
                RegistryStatus::Active
            );
        };

        let mut zero_proof_commitment = valid_submission(53);
        zero_proof_commitment.proof.proof_commitment = [0; 32];
        assert_noop!(
            challenge_proof(RuntimeOrigin::signed(4), zero_proof_commitment),
            Error::<Test>::MissingCommitment
        );
        assert_unchanged();

        let mut too_small = valid_submission(53);
        too_small.proof_size_bytes = TARGET_PROOF_SIZE_MIN_BYTES - 1;
        assert_noop!(
            challenge_proof(RuntimeOrigin::signed(4), too_small),
            Error::<Test>::InvalidProofSize
        );
        assert_unchanged();

        let mut future = valid_submission(53);
        future.submitted_at = System::block_number() + 1;
        assert_noop!(
            challenge_proof(RuntimeOrigin::signed(4), future),
            Error::<Test>::ProofSubmittedFromFuture
        );
        assert_unchanged();

        System::set_block_number(50);
        let mut stale = valid_submission(53);
        stale.submitted_at = 1;
        assert_noop!(
            challenge_proof(RuntimeOrigin::signed(4), stale),
            Error::<Test>::ProofSubmissionExpired
        );
        assert_unchanged();

        let mut wrong_assignment = valid_submission(53);
        wrong_assignment.input_commitment = commitment(9);
        assert_noop!(
            challenge_proof(RuntimeOrigin::signed(4), wrong_assignment),
            Error::<Test>::RequestMismatch
        );
        assert_unchanged();
    });
}

#[test]
fn root_slash_burns_held_miner_bond() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();

        assert_ok!(Qubitum::slash_miner(RuntimeOrigin::root(), 0, 2, 1_000));

        let miner = Miners::<Test>::get(0).unwrap();
        assert_eq!(
            miner.bond_commitment,
            expected_miner_bond_commitment(0, 2, RegistryStatus::Slashed)
        );
        assert_eq!(miner.status, RegistryStatus::Slashed);
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2),
            90_000_000_000
        );
    });
}
