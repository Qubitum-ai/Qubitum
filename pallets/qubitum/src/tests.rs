#![allow(clippy::arithmetic_side_effects, clippy::unwrap_used)]

use crate::{
    ActiveMinersBySubnet, ActiveValidatorsBySubnet, AutoRouteInferenceRequestParams,
    CancelledInferenceRequestCount, ChainInferenceRequest, ChainPublicInferenceRequest,
    ChainPublicMiner, ChainPublicProofRecord, ChainPublicSubnet, ChainPublicValidator,
    ChainRequestStatusCounts, ChainRouteAvailability, Error, HoldReason, InferenceRequestParams,
    InferenceRequestStatus, InferenceRequests, MinerCount, MinerIdentityCommitments,
    MinerIdentitySignatureBundles, Miners, PendingInferenceRequestCount, PendingMinerRequests,
    PendingValidatorRequests, ProofRecords, PublicRegistryStatus, RejectedInferenceRequestCount,
    RequestCount, SettledInferenceRequestCount, SubnetCount, Subnets, TotalBurned,
    TotalInferenceEscrowed, TotalInferenceRefunded, TotalMinerPayouts, TotalTreasuryFees,
    TotalValidatorFees, ValidatorCount, ValidatorIdentityCommitments,
    ValidatorIdentitySignatureBundles, Validators,
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
}

fn valid_submission(request_id: u64) -> InferenceProofSubmission {
    InferenceProofSubmission {
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
    }
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
            payment: 1_000,
            validator_fee_bps: 250,
            treasury_fee_bps: 50,
        },
    ));
}

fn submit_proof(
    origin: RuntimeOrigin,
    submission: InferenceProofSubmission,
) -> Result<(), sp_runtime::DispatchError> {
    Qubitum::submit_proof(origin, submission, 2)
}

fn challenge_proof(
    origin: RuntimeOrigin,
    submission: InferenceProofSubmission,
) -> Result<(), sp_runtime::DispatchError> {
    Qubitum::challenge_proof(origin, submission, 2)
}

#[test]
fn create_subnet_burns_qbt_and_stores_policy() {
    new_test_ext().execute_with(|| {
        assert_ok!(Qubitum::create_subnet(
            RuntimeOrigin::signed(1),
            SubnetDomain::Code,
            ProofSystem::RiscZeroStark
        ));

        let subnet = Subnets::<Test>::get(0).unwrap();
        assert_eq!(subnet.owner, 1);
        assert_eq!(subnet.domain, SubnetDomain::Code);
        assert_eq!(subnet.proof_system, ProofSystem::RiscZeroStark);
        assert_eq!(SubnetCount::<Test>::get(), 1);
        assert_eq!(TotalBurned::<Test>::get(), MINER_REGISTRATION_BURN);
        assert_eq!(
            Balances::free_balance(1),
            1_000_000_000_000_000 - MINER_REGISTRATION_BURN
        );
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

        assert_eq!(params.subnet_creation_burn, MINER_REGISTRATION_BURN);
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
        assert_eq!(params.signature_mode, SignatureMode::FullPostQuantum);
        assert_eq!(params.miner_exit_cooldown_blocks, 20);
        assert_eq!(params.validator_exit_cooldown_blocks, 20);
        assert_eq!(params.request_cancel_delay_blocks, 10);
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
        assert_eq!(miner.bond, MIN_MINER_BOND);
        assert_eq!(MinerCount::<Test>::get(), 1);
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2),
            MIN_MINER_BOND
        );
        assert_eq!(
            TotalBurned::<Test>::get(),
            MINER_REGISTRATION_BURN + MINER_REGISTRATION_BURN
        );
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
        assert_eq!(miner.bond, 0);
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
        assert_eq!(miner.bond, 0);
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
        assert_eq!(validator.stake, 90_000_000_000);
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
        assert_eq!(validator.stake, 0);
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::ValidatorStake.into(), &3),
            0
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

        assert_ok!(Qubitum::set_miner_identity_commitments(
            RuntimeOrigin::signed(2),
            0,
            Some(commitment(20)),
            Some(commitment(21)),
            post_quantum_signature_bundle(),
        ));
        assert_ok!(Qubitum::set_validator_identity_commitments(
            RuntimeOrigin::signed(3),
            0,
            Some(commitment(22)),
            Some(commitment(23)),
            post_quantum_signature_bundle(),
        ));

        let miner_commitments = MinerIdentityCommitments::<Test>::get(0).unwrap();
        assert_eq!(
            miner_commitments.shielded_identity_commitment,
            Some(commitment(20))
        );
        assert_eq!(miner_commitments.endpoint_commitment, Some(commitment(21)));
        assert_eq!(
            MinerIdentitySignatureBundles::<Test>::get(0),
            Some(post_quantum_signature_bundle())
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
            Some(post_quantum_signature_bundle())
        );

        for encoded in [
            miner_commitments.encode(),
            MinerIdentitySignatureBundles::<Test>::get(0)
                .unwrap()
                .encode(),
            validator_commitments.encode(),
            ValidatorIdentitySignatureBundles::<Test>::get(0)
                .unwrap()
                .encode(),
        ] {
            assert!(!contains_subsequence(&encoded, raw_miner_identity));
            assert!(!contains_subsequence(&encoded, raw_validator_identity));
        }

        assert_ok!(Qubitum::set_miner_identity_commitments(
            RuntimeOrigin::signed(2),
            0,
            None,
            None,
            post_quantum_signature_bundle(),
        ));
        assert!(MinerIdentityCommitments::<Test>::get(0).is_none());
        assert!(MinerIdentitySignatureBundles::<Test>::get(0).is_none());
        assert_ok!(Qubitum::set_validator_identity_commitments(
            RuntimeOrigin::signed(3),
            0,
            None,
            None,
            zero_signature_bundle(),
        ));
        assert!(ValidatorIdentityCommitments::<Test>::get(0).is_none());
        assert!(ValidatorIdentitySignatureBundles::<Test>::get(0).is_none());
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
            post_quantum_signature_bundle(),
        ));
        assert_ok!(Qubitum::set_validator_identity_commitments(
            RuntimeOrigin::signed(3),
            0,
            Some(commitment(22)),
            Some(commitment(23)),
            post_quantum_signature_bundle(),
        ));

        let miner_commitments = MinerIdentityCommitments::<Test>::get(0);
        let miner_signature = MinerIdentitySignatureBundles::<Test>::get(0);
        let validator_commitments = ValidatorIdentityCommitments::<Test>::get(0);
        let validator_signature = ValidatorIdentitySignatureBundles::<Test>::get(0);

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

        assert_eq!(MinerIdentityCommitments::<Test>::get(0), miner_commitments);
        assert_eq!(
            MinerIdentitySignatureBundles::<Test>::get(0),
            miner_signature
        );
        assert_eq!(
            ValidatorIdentityCommitments::<Test>::get(0),
            validator_commitments
        );
        assert_eq!(
            ValidatorIdentitySignatureBundles::<Test>::get(0),
            validator_signature
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
        assert_eq!(validator.stake, 0);
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

        assert_ok!(submit_proof(RuntimeOrigin::signed(3), submission));

        let record = ProofRecords::<Test>::get(42).unwrap();
        assert_eq!(record.request_id, 42);
        assert_eq!(record.input_commitment, commitment(1));
        assert_eq!(record.proof.proof_commitment, commitment(11));
        assert_eq!(record.proof.journal_commitment, commitment(12));
        assert_eq!(record.proof.image_id, commitment(13));
        assert_eq!(record.proof_system, ProofSystem::RiscZeroStark);
        assert_eq!(record.proof_size_bytes, TARGET_PROOF_SIZE_MIN_BYTES);
        assert_eq!(record.verification_latency_ms, 10);
        assert_eq!(record.submitted_at, 120);
        assert_eq!(record.accepted_at, 123);
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
            &Validators::<Test>::get(0).unwrap().encode(),
            &3_u64.encode()
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
        assert_ok!(submit_proof(RuntimeOrigin::signed(3), submission));

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
        assert_ok!(submit_proof(RuntimeOrigin::signed(3), submission));

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
        assert_eq!(record.submitted_at, 55);
        assert_eq!(record.accepted_at, 55);
        assert_eq!(
            StorageVersion::get::<crate::Pallet<Test>>(),
            StorageVersion::new(8)
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
        assert_eq!(miner.operator_commitment, Qubitum::account_commitment(&22));
        assert_eq!(miner.model_commitment, commitment(44));
        assert!(!contains_subsequence(&miner.encode(), &22_u64.encode()));

        let validator = Validators::<Test>::get(9).unwrap();
        assert_eq!(validator.id, 9);
        assert_eq!(
            validator.operator_commitment,
            Qubitum::account_commitment(&33)
        );
        assert_eq!(validator.stake, MIN_MINER_BOND);
        assert!(!contains_subsequence(&validator.encode(), &33_u64.encode()));
        assert_eq!(
            StorageVersion::get::<crate::Pallet<Test>>(),
            StorageVersion::new(8)
        );
    });
}

#[test]
fn request_inference_escrows_payment() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(7);

        let request = InferenceRequests::<Test>::get(7).unwrap();
        assert_eq!(request.user, 4);
        assert_eq!(request.miner_id, 0);
        assert_eq!(request.validator_id, 0);
        assert_eq!(request.payment, 1_000);
        assert_eq!(request.created_at, 0);
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
        let assignment = Qubitum::route_assignment(0, 1).unwrap();

        assert_noop!(
            Qubitum::request_inference(
                RuntimeOrigin::signed(4),
                1,
                InferenceRequestParams {
                    subnet_id: 0,
                    miner_id: assignment.miner_id,
                    validator_id: assignment.validator_id,
                    input_commitment: commitment(1),
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
                miner_id: assignment.miner_id,
                validator_id: assignment.validator_id,
                input_commitment: commitment(1),
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
fn public_route_availability_does_not_expose_participant_assignment() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        RequestCount::<Test>::put(42);

        assert_eq!(
            Qubitum::route_availability(0, 42),
            ChainRouteAvailability {
                request_id: 42,
                subnet_id: 0,
                available: true,
            }
        );
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
            Qubitum::route_availability(0, 42),
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
        assert_ok!(Qubitum::register_validator(
            RuntimeOrigin::signed(2),
            0,
            MIN_MINER_BOND
        ));
        assert_ok!(Qubitum::register_validator(
            RuntimeOrigin::signed(3),
            0,
            MIN_MINER_BOND
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
                miner_id: assignment.miner_id,
                validator_id: assignment.validator_id,
                input_commitment: commitment(1),
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

        for _ in 0..16 {
            assert_ok!(Qubitum::register_validator(
                RuntimeOrigin::signed(2),
                0,
                MIN_MINER_BOND
            ));
        }
        assert_ok!(Qubitum::register_validator(
            RuntimeOrigin::signed(3),
            0,
            MIN_MINER_BOND
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
                miner_id: assignment.miner_id,
                validator_id: assignment.validator_id,
                input_commitment: commitment(1),
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
                user: 4,
                subnet_id: 0,
                miner_id: 0,
                validator_id: 0,
                input_commitment: commitment(1),
                payment: 1_000,
                validator_fee_bps: 250,
                treasury_fee_bps: 50,
                created_at: 0,
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
        ActiveMinersBySubnet::<Test>::remove(0);
        ActiveValidatorsBySubnet::<Test>::remove(0);
        PendingMinerRequests::<Test>::remove(0);
        PendingValidatorRequests::<Test>::remove(0);
        PendingInferenceRequestCount::<Test>::put(0);
        SettledInferenceRequestCount::<Test>::put(0);
        CancelledInferenceRequestCount::<Test>::put(0);
        RejectedInferenceRequestCount::<Test>::put(0);
        StorageVersion::new(1).put::<crate::Pallet<Test>>();

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
            StorageVersion::new(8)
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
fn request_inference_rejects_non_canonical_assignment() {
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
                    payment: 1_000,
                    validator_fee_bps: 250,
                    treasury_fee_bps: 50,
                },
            ),
            Error::<Test>::AssignmentMismatch
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
                payment: 1_000,
                validator_fee_bps: 250,
                treasury_fee_bps: 50,
            },
        ));

        let request = InferenceRequests::<Test>::get(54).unwrap();
        assert_eq!(request.user, 4);
        assert_eq!(request.miner_id, 0);
        assert_eq!(request.validator_id, 0);
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
            Qubitum::cancel_inference(RuntimeOrigin::signed(4), 8),
            Error::<Test>::RequestCancelUnavailable
        );

        System::set_block_number(10);
        assert_ok!(Qubitum::cancel_inference(RuntimeOrigin::signed(4), 8));

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
            Qubitum::expire_inference(RuntimeOrigin::signed(5), 10),
            Error::<Test>::RequestCancelUnavailable
        );

        System::set_block_number(10);
        assert_ok!(Qubitum::expire_inference(RuntimeOrigin::signed(5), 10));

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
fn cancel_inference_rejects_non_owner_or_settled_request() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(9);

        assert_noop!(
            Qubitum::cancel_inference(RuntimeOrigin::signed(3), 9),
            Error::<Test>::NotRequestOwner
        );

        assert_ok!(submit_proof(RuntimeOrigin::signed(3), valid_submission(9)));
        assert_noop!(
            Qubitum::cancel_inference(RuntimeOrigin::signed(4), 9),
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
            Error::<Test>::RequestMismatch
        );

        let mut wrong_validator = valid_submission(52);
        wrong_validator.validator_id = 1;
        assert_noop!(
            submit_proof(RuntimeOrigin::signed(3), wrong_validator),
            Error::<Test>::RequestMismatch
        );
    });
}

#[test]
fn verifier_rejection_slashes_and_refunds_request() {
    new_test_ext().execute_with(|| {
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
        assert_eq!(miner.bond, 90_000_000_000);
        assert_eq!(miner.status, RegistryStatus::Slashed);
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2),
            90_000_000_000
        );
        let validator = Validators::<Test>::get(0).unwrap();
        assert_eq!(validator.stake, 90_000_000_000);
        assert_eq!(validator.status, RegistryStatus::Slashed);
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::ValidatorStake.into(), &3),
            90_000_000_000
        );
    });
}

#[test]
fn invalid_proof_challenge_slashes_miner_without_validator_self_slash() {
    new_test_ext().execute_with(|| {
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
        assert_eq!(miner.bond, 90_000_000_000);
        assert_eq!(miner.status, RegistryStatus::Slashed);
        let validator = Validators::<Test>::get(0).unwrap();
        assert_eq!(validator.stake, MIN_MINER_BOND);
        assert_eq!(validator.status, RegistryStatus::Active);
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
        assert_eq!(miner.bond, 90_000_000_000);
        assert_eq!(miner.status, RegistryStatus::Slashed);
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2),
            90_000_000_000
        );
    });
}
