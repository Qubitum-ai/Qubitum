#![allow(clippy::arithmetic_side_effects, clippy::unwrap_used)]

use crate::{
    Error, HoldReason, MinerCount, Miners, ProofRecords, SubnetCount, Subnets, TotalBurned,
    ValidatorCount, Validators,
    mock::{Balances, Qubitum, RuntimeOrigin, Test, new_test_ext, set_verification_outcome},
};
use frame_support::{assert_noop, assert_ok, traits::fungible::InspectHold};
use qubitum_protocol::{
    InferenceProofSubmission, MAX_MINER_BOND, MIN_MINER_BOND, MINER_REGISTRATION_BURN,
    ProofEnvelope, ProofSystem, ProofVerifierVersion, RegistryStatus, SubnetDomain,
    TARGET_PROOF_SIZE_MIN_BYTES, VerificationOutcome,
};

fn commitment(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn proof(seed: u8) -> ProofEnvelope {
    ProofEnvelope::risc_zero_v1(commitment(seed), commitment(seed + 1), commitment(seed + 2))
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
        submitted_at: 77,
    }
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
        assert_eq!(validator.operator, 3);
        assert_eq!(validator.status, RegistryStatus::Active);
        assert_eq!(ValidatorCount::<Test>::get(), 1);
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::ValidatorStake.into(), &3),
            MIN_MINER_BOND
        );
    });
}

#[test]
fn submit_proof_records_commitments_for_active_participants() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();

        assert_ok!(Qubitum::submit_proof(
            RuntimeOrigin::signed(3),
            valid_submission(42)
        ));

        let record = ProofRecords::<Test>::get(42).unwrap();
        assert_eq!(record.request_id, 42);
        assert_eq!(record.input_commitment, commitment(1));
        assert_eq!(record.proof.proof_commitment, commitment(11));
        assert_eq!(record.proof.journal_commitment, commitment(12));
        assert_eq!(record.proof.image_id, commitment(13));
        assert_eq!(record.proof_system, ProofSystem::RiscZeroStark);
        assert_eq!(record.proof_size_bytes, TARGET_PROOF_SIZE_MIN_BYTES);
        assert_eq!(record.verification_latency_ms, 10);
        assert_eq!(record.submitted_at, 77);
    });
}

#[test]
fn submit_proof_rejects_latency_or_missing_commitment() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();

        assert_noop!(
            Qubitum::submit_proof(
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

        assert_noop!(
            Qubitum::submit_proof(
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
            Qubitum::submit_proof(RuntimeOrigin::signed(3), missing_journal),
            Error::<Test>::MissingCommitment
        );

        let mut wrong_verifier = valid_submission(50);
        wrong_verifier.proof.verifier_version = ProofVerifierVersion::Mock;
        assert_noop!(
            Qubitum::submit_proof(RuntimeOrigin::signed(3), wrong_verifier),
            Error::<Test>::ProofSystemMismatch
        );
    });
}

#[test]
fn submit_proof_rejects_duplicate_wrong_validator_or_model() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();

        assert_ok!(Qubitum::submit_proof(
            RuntimeOrigin::signed(3),
            valid_submission(45)
        ));
        assert_noop!(
            Qubitum::submit_proof(RuntimeOrigin::signed(3), valid_submission(45)),
            Error::<Test>::DuplicateProof
        );

        assert_noop!(
            Qubitum::submit_proof(RuntimeOrigin::signed(4), valid_submission(46)),
            Error::<Test>::NotValidatorOperator
        );

        let mut wrong_model = valid_submission(47);
        wrong_model.model_commitment = commitment(99);
        assert_noop!(
            Qubitum::submit_proof(RuntimeOrigin::signed(3), wrong_model),
            Error::<Test>::ModelCommitmentMismatch
        );
    });
}

#[test]
fn verifier_rejection_slashes_miner_without_recording_proof() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        set_verification_outcome(VerificationOutcome::Invalid { slash_bps: 1_000 });

        assert_ok!(Qubitum::submit_proof(
            RuntimeOrigin::signed(3),
            valid_submission(48)
        ));

        assert!(ProofRecords::<Test>::get(48).is_none());
        let miner = Miners::<Test>::get(0).unwrap();
        assert_eq!(miner.bond, 90_000_000_000);
        assert_eq!(miner.status, RegistryStatus::Slashed);
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2),
            90_000_000_000
        );
    });
}

#[test]
fn root_slash_burns_held_miner_bond() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();

        assert_ok!(Qubitum::slash_miner(RuntimeOrigin::root(), 0, 1_000));

        let miner = Miners::<Test>::get(0).unwrap();
        assert_eq!(miner.bond, 90_000_000_000);
        assert_eq!(miner.status, RegistryStatus::Slashed);
        assert_eq!(
            Balances::balance_on_hold(&HoldReason::MinerBond.into(), &2),
            90_000_000_000
        );
    });
}
