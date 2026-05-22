//! Weight functions for `pallet_qubitum`.

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(missing_docs)]

use core::marker::PhantomData;
use frame_support::{
    traits::Get,
    weights::{constants::RocksDbWeight, Weight},
};

/// Weight functions needed for `pallet_qubitum`.
pub trait WeightInfo {
    fn create_subnet() -> Weight;
    fn register_miner() -> Weight;
    fn activate_miner() -> Weight;
    fn deactivate_miner() -> Weight;
    fn withdraw_miner_bond() -> Weight;
    fn register_validator() -> Weight;
    fn deactivate_validator() -> Weight;
    fn withdraw_validator_stake() -> Weight;
    fn submit_proof() -> Weight;
    fn slash_miner() -> Weight;
    fn slash_validator() -> Weight;
    fn request_inference() -> Weight;
    fn cancel_inference() -> Weight;
}

/// Weights for `pallet_qubitum` using the runtime database weight.
pub struct SubstrateWeight<T>(PhantomData<T>);

impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    fn create_subnet() -> Weight {
        Weight::from_parts(55_000_000, 6_500)
            .saturating_add(T::DbWeight::get().reads(3_u64))
            .saturating_add(T::DbWeight::get().writes(4_u64))
    }

    fn register_miner() -> Weight {
        Weight::from_parts(65_000_000, 7_000)
            .saturating_add(T::DbWeight::get().reads(4_u64))
            .saturating_add(T::DbWeight::get().writes(4_u64))
    }

    fn activate_miner() -> Weight {
        Weight::from_parts(70_000_000, 7_000)
            .saturating_add(T::DbWeight::get().reads(3_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
    }

    fn deactivate_miner() -> Weight {
        Weight::from_parts(45_000_000, 5_000)
            .saturating_add(T::DbWeight::get().reads(2_u64))
            .saturating_add(T::DbWeight::get().writes(1_u64))
    }

    fn withdraw_miner_bond() -> Weight {
        Weight::from_parts(55_000_000, 6_500)
            .saturating_add(T::DbWeight::get().reads(2_u64))
            .saturating_add(T::DbWeight::get().writes(2_u64))
    }

    fn register_validator() -> Weight {
        Weight::from_parts(70_000_000, 7_000)
            .saturating_add(T::DbWeight::get().reads(3_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
    }

    fn deactivate_validator() -> Weight {
        Weight::from_parts(45_000_000, 5_000)
            .saturating_add(T::DbWeight::get().reads(2_u64))
            .saturating_add(T::DbWeight::get().writes(1_u64))
    }

    fn withdraw_validator_stake() -> Weight {
        Weight::from_parts(55_000_000, 6_500)
            .saturating_add(T::DbWeight::get().reads(2_u64))
            .saturating_add(T::DbWeight::get().writes(2_u64))
    }

    fn submit_proof() -> Weight {
        Weight::from_parts(85_000_000, 10_000)
            .saturating_add(T::DbWeight::get().reads(14_u64))
            .saturating_add(T::DbWeight::get().writes(12_u64))
    }

    fn slash_miner() -> Weight {
        Weight::from_parts(75_000_000, 7_000)
            .saturating_add(T::DbWeight::get().reads(3_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
    }

    fn slash_validator() -> Weight {
        Weight::from_parts(75_000_000, 7_000)
            .saturating_add(T::DbWeight::get().reads(3_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
    }

    fn request_inference() -> Weight {
        Weight::from_parts(50_000_000, 7_000)
            .saturating_add(T::DbWeight::get().reads(25_u64))
            .saturating_add(T::DbWeight::get().writes(6_u64))
    }

    fn cancel_inference() -> Weight {
        Weight::from_parts(45_000_000, 6_500)
            .saturating_add(T::DbWeight::get().reads(4_u64))
            .saturating_add(T::DbWeight::get().writes(4_u64))
    }
}

impl WeightInfo for () {
    fn create_subnet() -> Weight {
        Weight::from_parts(55_000_000, 6_500)
            .saturating_add(RocksDbWeight::get().reads(3_u64))
            .saturating_add(RocksDbWeight::get().writes(4_u64))
    }

    fn register_miner() -> Weight {
        Weight::from_parts(65_000_000, 7_000)
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(4_u64))
    }

    fn activate_miner() -> Weight {
        Weight::from_parts(70_000_000, 7_000)
            .saturating_add(RocksDbWeight::get().reads(3_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }

    fn deactivate_miner() -> Weight {
        Weight::from_parts(45_000_000, 5_000)
            .saturating_add(RocksDbWeight::get().reads(2_u64))
            .saturating_add(RocksDbWeight::get().writes(1_u64))
    }

    fn withdraw_miner_bond() -> Weight {
        Weight::from_parts(55_000_000, 6_500)
            .saturating_add(RocksDbWeight::get().reads(2_u64))
            .saturating_add(RocksDbWeight::get().writes(2_u64))
    }

    fn register_validator() -> Weight {
        Weight::from_parts(70_000_000, 7_000)
            .saturating_add(RocksDbWeight::get().reads(3_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }

    fn deactivate_validator() -> Weight {
        Weight::from_parts(45_000_000, 5_000)
            .saturating_add(RocksDbWeight::get().reads(2_u64))
            .saturating_add(RocksDbWeight::get().writes(1_u64))
    }

    fn withdraw_validator_stake() -> Weight {
        Weight::from_parts(55_000_000, 6_500)
            .saturating_add(RocksDbWeight::get().reads(2_u64))
            .saturating_add(RocksDbWeight::get().writes(2_u64))
    }

    fn submit_proof() -> Weight {
        Weight::from_parts(85_000_000, 10_000)
            .saturating_add(RocksDbWeight::get().reads(14_u64))
            .saturating_add(RocksDbWeight::get().writes(12_u64))
    }

    fn slash_miner() -> Weight {
        Weight::from_parts(75_000_000, 7_000)
            .saturating_add(RocksDbWeight::get().reads(3_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }

    fn slash_validator() -> Weight {
        Weight::from_parts(75_000_000, 7_000)
            .saturating_add(RocksDbWeight::get().reads(3_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }

    fn request_inference() -> Weight {
        Weight::from_parts(50_000_000, 7_000)
            .saturating_add(RocksDbWeight::get().reads(25_u64))
            .saturating_add(RocksDbWeight::get().writes(6_u64))
    }

    fn cancel_inference() -> Weight {
        Weight::from_parts(45_000_000, 6_500)
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(4_u64))
    }
}
