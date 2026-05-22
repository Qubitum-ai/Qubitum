//! Benchmarks for Qubitum pallet.

#![cfg(feature = "runtime-benchmarks")]
#![allow(clippy::arithmetic_side_effects, clippy::unwrap_used)]

use crate::{
    BalanceOf, ChainProofRecord, Event, MinerCount, Miners, ProofRecords, SubnetCount, Subnets,
    TotalBurned, ValidatorCount, Validators, pallet::*,
};
use frame_benchmarking::{account, v2::*};
use frame_support::traits::{Get, fungible::Mutate};
use frame_system::RawOrigin;
use qubitum_protocol::{
    Commitment, InferenceProofSubmission, ProofEnvelope, ProofSystem, RegistryStatus, SubnetDomain,
    TARGET_PROOF_SIZE_MIN_BYTES,
};
use sp_runtime::Saturating;

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

fn proof_submission() -> InferenceProofSubmission {
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
        submitted_at: 77,
    }
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
        assert_last_event::<T>(
            Event::<T>::SubnetCreated {
                subnet_id: 0,
                owner,
            }
            .into(),
        );
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
        assert_eq!(registered_miner.operator, miner.clone());
        assert_eq!(registered_miner.subnet_id, 0);
        assert_eq!(registered_miner.model_commitment, commitment(10));
        assert_eq!(registered_miner.proof_system, ProofSystem::RiscZeroStark);
        assert_eq!(registered_miner.bond, BalanceOf::<T>::default());
        assert_eq!(registered_miner.status, RegistryStatus::Pending);
        assert_last_event::<T>(
            Event::<T>::MinerRegistered {
                miner_id: 0,
                subnet_id: 0,
                operator: miner,
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
        assert_eq!(registered_validator.operator, validator.clone());
        assert_eq!(registered_validator.subnet_id, 0);
        assert_eq!(registered_validator.stake, stake);
        assert_eq!(registered_validator.status, RegistryStatus::Active);
        assert_last_event::<T>(
            Event::<T>::ValidatorRegistered {
                validator_id: 0,
                subnet_id: 0,
                operator: validator,
            }
            .into(),
        );
    }

    #[benchmark]
    fn submit_proof() {
        let _miner = activate_bench_miner::<T>();
        let validator = register_bench_validator::<T>();
        let submission = proof_submission();

        #[extrinsic_call]
        _(RawOrigin::Signed(validator), submission);

        assert_eq!(
            ProofRecords::<T>::get(42),
            Some(ChainProofRecord {
                request_id: 42,
                subnet_id: 0,
                miner_id: 0,
                validator_id: 0,
                input_commitment: commitment(1),
                output_commitment: commitment(2),
                model_commitment: commitment(10),
                proof: proof(11),
            })
        );
    }

    #[benchmark]
    fn slash_miner() {
        let _miner = activate_bench_miner::<T>();
        let before = TotalBurned::<T>::get();

        #[extrinsic_call]
        _(RawOrigin::Root, 0, T::MinInvalidProofSlashBps::get());

        assert!(TotalBurned::<T>::get() > before);
    }

    impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
}
