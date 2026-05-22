//! Benchmarks for Qubitum pallet.

#![cfg(feature = "runtime-benchmarks")]
#![allow(clippy::arithmetic_side_effects, clippy::unwrap_used)]

use crate::{
    BalanceOf, Event, InferenceRequestParams, InferenceRequestStatus, InferenceRequests,
    MinerCount, Miners, ProofRecords, SubnetCount, Subnets, TotalBurned, ValidatorCount,
    Validators, pallet::*,
};
use frame_benchmarking::{account, v2::*};
use frame_support::traits::{Get, fungible::Mutate};
use frame_system::RawOrigin;
use qubitum_protocol::{
    Commitment, InferenceProofSubmission, ProofEnvelope, ProofSystem, RegistryStatus, SubnetDomain,
    TARGET_PROOF_SIZE_MIN_BYTES,
};
use sp_runtime::{Saturating, traits::SaturatedConversion};

const SEED: u32 = 0;

fn commitment(seed: u8) -> Commitment {
    [seed; 32]
}

fn proof(seed: u8) -> ProofEnvelope {
    ProofEnvelope::risc_zero_v1(commitment(seed), commitment(seed + 1), commitment(seed + 2))
}

fn assert_last_event<T: Config>(generic_event: <T as frame_system::Config>::RuntimeEvent) {
    frame_system::Pallet::<T>::assert_last_event(generic_event.into());
}

fn fund<T: Config>(who: &T::AccountId, amount: BalanceOf<T>) {
    T::Currency::mint_into(who, amount).unwrap();
}

fn create_bench_subnet<T: Config>() -> T::AccountId {
    let owner: T::AccountId = account("subnet-owner", 0, SEED);
    fund::<T>(&owner, T::SubnetCreationBurn::get());
    Pallet::<T>::create_subnet(
        RawOrigin::Signed(owner.clone()).into(),
        SubnetDomain::Code,
        ProofSystem::RiscZeroStark,
    )
    .unwrap();
    owner
}

fn register_bench_miner<T: Config>() -> T::AccountId {
    let _owner = create_bench_subnet::<T>();
    let miner: T::AccountId = account("miner", 0, SEED);
    let balance = T::MinerRegistrationBurn::get()
        .saturating_add(T::MinMinerBond::get())
        .saturating_add(T::MinMinerBond::get());
    fund::<T>(&miner, balance);
    Pallet::<T>::register_miner(
        RawOrigin::Signed(miner.clone()).into(),
        0,
        commitment(10),
        ProofSystem::RiscZeroStark,
    )
    .unwrap();
    miner
}

fn activate_bench_miner<T: Config>() -> T::AccountId {
    let miner = register_bench_miner::<T>();
    Pallet::<T>::activate_miner(
        RawOrigin::Signed(miner.clone()).into(),
        0,
        T::MinMinerBond::get(),
    )
    .unwrap();
    miner
}

fn register_bench_validator<T: Config>() -> T::AccountId {
    let validator: T::AccountId = account("validator", 0, SEED);
    fund::<T>(
        &validator,
        T::MinValidatorStake::get().saturating_add(T::MinValidatorStake::get()),
    );
    Pallet::<T>::register_validator(
        RawOrigin::Signed(validator.clone()).into(),
        0,
        T::MinValidatorStake::get(),
    )
    .unwrap();
    validator
}

fn proof_submission<T: Config>() -> InferenceProofSubmission {
    InferenceProofSubmission {
        request_id: 42,
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
        submitted_at: frame_system::Pallet::<T>::block_number().saturated_into(),
    }
}

fn request_bench_inference<T: Config>(request_id: u64) -> T::AccountId {
    let user: T::AccountId = account("user", 0, SEED);
    let payment = T::MinMinerBond::get();
    fund::<T>(&user, payment.saturating_add(payment));
    RequestCount::<T>::put(request_id);
    Pallet::<T>::request_inference(
        RawOrigin::Signed(user.clone()).into(),
        request_id,
        InferenceRequestParams {
            subnet_id: 0,
            miner_id: 0,
            validator_id: 0,
            input_commitment: commitment(1),
            payment: T::MinMinerBond::get(),
            validator_fee_bps: 250,
            treasury_fee_bps: 50,
        },
    )
    .unwrap();
    user
}

#[benchmarks]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn create_subnet() {
        let owner: T::AccountId = account("subnet-owner", 0, SEED);
        fund::<T>(&owner, T::SubnetCreationBurn::get());

        #[extrinsic_call]
        _(
            RawOrigin::Signed(owner.clone()),
            SubnetDomain::Code,
            ProofSystem::RiscZeroStark,
        );

        assert_eq!(SubnetCount::<T>::get(), 1);
        assert!(Subnets::<T>::contains_key(0));
        assert_last_event::<T>(Event::<T>::SubnetCreated { subnet_id: 0 }.into());
    }

    #[benchmark]
    fn register_miner() {
        let _owner = create_bench_subnet::<T>();
        let miner: T::AccountId = account("miner", 0, SEED);
        fund::<T>(&miner, T::MinerRegistrationBurn::get());

        #[extrinsic_call]
        _(
            RawOrigin::Signed(miner.clone()),
            0,
            commitment(10),
            ProofSystem::RiscZeroStark,
        );

        assert_eq!(MinerCount::<T>::get(), 1);
        let registered_miner = Miners::<T>::get(0).unwrap();
        assert_eq!(registered_miner.id, 0);
        assert_eq!(
            registered_miner.operator_commitment,
            Pallet::<T>::account_commitment(&miner)
        );
        assert_eq!(registered_miner.subnet_id, 0);
        assert_eq!(registered_miner.model_commitment, commitment(10));
        assert_eq!(registered_miner.proof_system, ProofSystem::RiscZeroStark);
        assert_eq!(
            registered_miner.bond_commitment,
            Pallet::<T>::balance_commitment(BalanceOf::<T>::default())
        );
        assert_eq!(registered_miner.status, RegistryStatus::Pending);
        assert_last_event::<T>(
            Event::<T>::MinerRegistered {
                miner_id: 0,
                subnet_id: 0,
            }
            .into(),
        );
    }

    #[benchmark]
    fn activate_miner() {
        let miner = register_bench_miner::<T>();
        let bond = T::MinMinerBond::get();

        #[extrinsic_call]
        _(RawOrigin::Signed(miner), 0, bond);

        assert_eq!(
            Miners::<T>::get(0).map(|registered| registered.status),
            Some(RegistryStatus::Active)
        );
    }

    #[benchmark]
    fn deactivate_miner() {
        let miner = activate_bench_miner::<T>();

        #[extrinsic_call]
        _(RawOrigin::Signed(miner.clone()), 0);

        let RegistryStatus::Exiting { exit_available_at } = Miners::<T>::get(0).unwrap().status
        else {
            panic!("miner must be exiting");
        };
        assert!(exit_available_at >= T::MinerExitCooldownBlocks::get());
        assert_last_event::<T>(Event::<T>::MinerExitStarted { miner_id: 0 }.into());
    }

    #[benchmark]
    fn withdraw_miner_bond() {
        let miner = activate_bench_miner::<T>();
        Pallet::<T>::deactivate_miner(RawOrigin::Signed(miner.clone()).into(), 0).unwrap();
        let RegistryStatus::Exiting { exit_available_at } = Miners::<T>::get(0).unwrap().status
        else {
            panic!("miner must be exiting");
        };
        frame_system::Pallet::<T>::set_block_number(exit_available_at.saturated_into());

        #[extrinsic_call]
        _(RawOrigin::Signed(miner.clone()), 0);

        let registered_miner = Miners::<T>::get(0).unwrap();
        assert_eq!(registered_miner.status, RegistryStatus::Disabled);
        assert_eq!(
            registered_miner.bond_commitment,
            Pallet::<T>::balance_commitment(BalanceOf::<T>::default())
        );
        assert_last_event::<T>(Event::<T>::MinerBondWithdrawn { miner_id: 0 }.into());
    }

    #[benchmark]
    fn register_validator() {
        let _owner = create_bench_subnet::<T>();
        let validator: T::AccountId = account("validator", 0, SEED);
        fund::<T>(
            &validator,
            T::MinValidatorStake::get().saturating_add(T::MinValidatorStake::get()),
        );
        let stake = T::MinValidatorStake::get();

        #[extrinsic_call]
        _(RawOrigin::Signed(validator.clone()), 0, stake);

        assert_eq!(ValidatorCount::<T>::get(), 1);
        let registered_validator = Validators::<T>::get(0).unwrap();
        assert_eq!(registered_validator.id, 0);
        assert_eq!(
            registered_validator.operator_commitment,
            Pallet::<T>::account_commitment(&validator)
        );
        assert_eq!(registered_validator.subnet_id, 0);
        assert_eq!(
            registered_validator.stake_commitment,
            Pallet::<T>::balance_commitment(stake)
        );
        assert_eq!(registered_validator.status, RegistryStatus::Active);
        assert_last_event::<T>(
            Event::<T>::ValidatorRegistered {
                validator_id: 0,
                subnet_id: 0,
            }
            .into(),
        );
    }

    #[benchmark]
    fn deactivate_validator() {
        let _owner = create_bench_subnet::<T>();
        let validator = register_bench_validator::<T>();

        #[extrinsic_call]
        _(RawOrigin::Signed(validator.clone()), 0);

        let RegistryStatus::Exiting { exit_available_at } = Validators::<T>::get(0).unwrap().status
        else {
            panic!("validator must be exiting");
        };
        assert!(exit_available_at >= T::ValidatorExitCooldownBlocks::get());
        assert_last_event::<T>(Event::<T>::ValidatorExitStarted { validator_id: 0 }.into());
    }

    #[benchmark]
    fn withdraw_validator_stake() {
        let _owner = create_bench_subnet::<T>();
        let validator = register_bench_validator::<T>();
        Pallet::<T>::deactivate_validator(RawOrigin::Signed(validator.clone()).into(), 0).unwrap();
        let RegistryStatus::Exiting { exit_available_at } = Validators::<T>::get(0).unwrap().status
        else {
            panic!("validator must be exiting");
        };
        frame_system::Pallet::<T>::set_block_number(exit_available_at.saturated_into());

        #[extrinsic_call]
        _(RawOrigin::Signed(validator.clone()), 0);

        let registered_validator = Validators::<T>::get(0).unwrap();
        assert_eq!(registered_validator.status, RegistryStatus::Disabled);
        assert_eq!(
            registered_validator.stake_commitment,
            Pallet::<T>::balance_commitment(BalanceOf::<T>::default())
        );
        assert_last_event::<T>(Event::<T>::ValidatorStakeWithdrawn { validator_id: 0 }.into());
    }

    #[benchmark]
    fn submit_proof() {
        let miner = activate_bench_miner::<T>();
        let validator = register_bench_validator::<T>();
        let user = request_bench_inference::<T>(42);
        let submission = proof_submission::<T>();
        let submitted_at = frame_system::Pallet::<T>::block_number().saturated_into();

        #[extrinsic_call]
        _(RawOrigin::Signed(validator), submission, user, miner);

        let record = ProofRecords::<T>::get(42).unwrap();
        assert_eq!(record.request_id, 42);
        assert_eq!(record.subnet_id, 0);
        assert_eq!(record.miner_id, 0);
        assert_eq!(record.validator_id, 0);
        assert_eq!(record.input_commitment, commitment(1));
        assert_eq!(record.output_commitment, commitment(2));
        assert_eq!(record.model_commitment, commitment(10));
        assert_eq!(record.proof, proof(11));
        assert_eq!(record.proof_system, ProofSystem::RiscZeroStark);
        assert_eq!(record.proof_size_bytes, TARGET_PROOF_SIZE_MIN_BYTES);
        assert_eq!(record.verification_latency_ms, 10);
        assert_eq!(record.submitted_at, submitted_at);
        assert!(record.accepted_at >= submitted_at);
    }

    #[benchmark]
    fn slash_miner() {
        let miner = activate_bench_miner::<T>();
        let before = TotalBurned::<T>::get();

        #[extrinsic_call]
        _(RawOrigin::Root, 0, miner, T::MinInvalidProofSlashBps::get());

        assert!(TotalBurned::<T>::get() > before);
    }

    #[benchmark]
    fn slash_validator() {
        let _owner = create_bench_subnet::<T>();
        let validator = register_bench_validator::<T>();
        let before = TotalBurned::<T>::get();

        #[extrinsic_call]
        _(
            RawOrigin::Root,
            0,
            validator,
            T::MinInvalidProofSlashBps::get(),
        );

        assert!(TotalBurned::<T>::get() > before);
    }

    #[benchmark]
    fn request_inference() {
        let _miner = activate_bench_miner::<T>();
        let _validator = register_bench_validator::<T>();
        let user: T::AccountId = account("user", 0, SEED);
        let payment = T::MinMinerBond::get();
        fund::<T>(&user, payment.saturating_add(payment));
        RequestCount::<T>::put(42);

        #[extrinsic_call]
        _(
            RawOrigin::Signed(user.clone()),
            42,
            InferenceRequestParams {
                subnet_id: 0,
                miner_id: 0,
                validator_id: 0,
                input_commitment: commitment(1),
                payment,
                validator_fee_bps: 250,
                treasury_fee_bps: 50,
            },
        );

        let request = InferenceRequests::<T>::get(42).unwrap();
        assert_eq!(
            request.user_commitment,
            Pallet::<T>::account_commitment(&user)
        );
        assert_eq!(request.status, InferenceRequestStatus::Pending);
        assert_last_event::<T>(
            Event::<T>::InferenceRequested {
                request_id: 42,
                subnet_id: 0,
            }
            .into(),
        );
    }

    #[benchmark]
    fn cancel_inference() {
        let _miner = activate_bench_miner::<T>();
        let _validator = register_bench_validator::<T>();
        let user = request_bench_inference::<T>(42);
        frame_system::Pallet::<T>::set_block_number(
            T::RequestCancelDelayBlocks::get().saturated_into(),
        );

        #[extrinsic_call]
        _(RawOrigin::Signed(user.clone()), 42, 0, 0);

        let request = InferenceRequests::<T>::get(42).unwrap();
        assert_eq!(
            request.user_commitment,
            Pallet::<T>::account_commitment(&user)
        );
        assert_eq!(request.status, InferenceRequestStatus::Cancelled);
        assert_last_event::<T>(Event::<T>::InferenceCancelled { request_id: 42 }.into());
    }

    #[benchmark]
    fn expire_inference() {
        let _miner = activate_bench_miner::<T>();
        let _validator = register_bench_validator::<T>();
        let user = request_bench_inference::<T>(42);
        let keeper: T::AccountId = account("keeper", 0, SEED);
        frame_system::Pallet::<T>::set_block_number(
            T::RequestCancelDelayBlocks::get().saturated_into(),
        );

        #[extrinsic_call]
        _(RawOrigin::Signed(keeper), 42, user.clone(), 0, 0);

        let request = InferenceRequests::<T>::get(42).unwrap();
        assert_eq!(
            request.user_commitment,
            Pallet::<T>::account_commitment(&user)
        );
        assert_eq!(request.status, InferenceRequestStatus::Expired);
        assert_last_event::<T>(Event::<T>::InferenceExpired { request_id: 42 }.into());
    }

    impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
}
