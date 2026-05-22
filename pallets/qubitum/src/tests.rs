#![allow(clippy::arithmetic_side_effects, clippy::unwrap_used)]

use crate::{
    ActiveMinersBySubnet, ActiveValidatorsBySubnet, ChainInferenceRequest, Error, HoldReason,
    InferenceRequestParams, InferenceRequestStatus, InferenceRequests, MinerCount, Miners,
    PendingMinerRequests, PendingValidatorRequests, ProofRecords, RequestCount, SubnetCount,
    Subnets, TotalBurned, ValidatorCount, Validators,
    mock::{
        Balances, Qubitum, RuntimeOrigin, System, Test, new_test_ext, set_verification_outcome,
    },
};
use frame_support::{
    assert_noop, assert_ok,
    traits::{Hooks, StorageVersion, fungible::InspectHold},
};
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
        assert_ok!(Qubitum::slash_miner(RuntimeOrigin::root(), 0, 1_000));

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

        assert_ok!(Qubitum::slash_validator(RuntimeOrigin::root(), 0, 1_000));

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
        assert_ok!(Qubitum::slash_validator(RuntimeOrigin::root(), 0, 1_000));

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
        assert_ok!(Qubitum::submit_proof(
            RuntimeOrigin::signed(3),
            valid_submission(41)
        ));
    });
}

#[test]
fn submit_proof_records_commitments_for_active_participants() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();
        request_inference(42);
        System::set_block_number(123);

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
        assert_eq!(record.submitted_at, 123);
        assert_eq!(
            InferenceRequests::<Test>::get(42).unwrap().status,
            InferenceRequestStatus::Settled
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

        assert_ok!(Qubitum::submit_proof(
            RuntimeOrigin::signed(3),
            valid_submission(7)
        ));
        assert_eq!(PendingMinerRequests::<Test>::get(0), 0);
        assert_eq!(PendingValidatorRequests::<Test>::get(0), 0);

        assert_ok!(Qubitum::deactivate_miner(RuntimeOrigin::signed(2), 0));
        assert_ok!(Qubitum::deactivate_validator(RuntimeOrigin::signed(3), 0));
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
fn route_assignment_removes_slashed_participants() {
    new_test_ext().execute_with(|| {
        register_active_miner_and_validator();

        assert_ok!(Qubitum::slash_miner(RuntimeOrigin::root(), 0, 1_000));
        assert!(ActiveMinersBySubnet::<Test>::get(0).is_empty());
        assert_eq!(Qubitum::route_assignment(0, 42), None);

        assert_ok!(Qubitum::slash_validator(RuntimeOrigin::root(), 0, 1_000));
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
            Qubitum::submit_proof(RuntimeOrigin::signed(2), valid_submission(88)),
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
            StorageVersion::new(2)
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

        assert_ok!(Qubitum::submit_proof(
            RuntimeOrigin::signed(3),
            valid_submission(9)
        ));
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

        request_inference(44);
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
        request_inference(45);

        assert_ok!(Qubitum::submit_proof(
            RuntimeOrigin::signed(3),
            valid_submission(45)
        ));
        assert_noop!(
            Qubitum::submit_proof(RuntimeOrigin::signed(3), valid_submission(45)),
            Error::<Test>::DuplicateProof
        );

        request_inference(46);
        assert_noop!(
            Qubitum::submit_proof(RuntimeOrigin::signed(4), valid_submission(46)),
            Error::<Test>::NotValidatorOperator
        );

        request_inference(47);
        let mut wrong_model = valid_submission(47);
        wrong_model.model_commitment = commitment(99);
        assert_noop!(
            Qubitum::submit_proof(RuntimeOrigin::signed(3), wrong_model),
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
            Qubitum::submit_proof(RuntimeOrigin::signed(3), wrong_miner),
            Error::<Test>::RequestMismatch
        );

        let mut wrong_validator = valid_submission(52);
        wrong_validator.validator_id = 1;
        assert_noop!(
            Qubitum::submit_proof(RuntimeOrigin::signed(3), wrong_validator),
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

        assert_ok!(Qubitum::submit_proof(
            RuntimeOrigin::signed(3),
            valid_submission(48)
        ));

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
