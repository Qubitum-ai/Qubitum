#![allow(clippy::arithmetic_side_effects, clippy::unwrap_used)]

use crate as pallet_qubitum;
use frame_support::{derive_impl, parameter_types};
use sp_runtime::{
    BuildStorage,
    traits::{BlakeTwo256, IdentityLookup},
};

pub type AccountId = u64;
pub type Balance = u128;
pub type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system = 0,
        Balances: pallet_balances = 1,
        Qubitum: pallet_qubitum = 2,
    }
);

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const ExistentialDeposit: Balance = 1;
    pub const SubnetCreationBurn: Balance = qubitum_protocol::MINER_REGISTRATION_BURN;
    pub const MinerRegistrationBurn: Balance = qubitum_protocol::MINER_REGISTRATION_BURN;
    pub const MinMinerBond: Balance = qubitum_protocol::MIN_MINER_BOND;
    pub const MaxMinerBond: Balance = qubitum_protocol::MAX_MINER_BOND;
    pub const MinValidatorStake: Balance = qubitum_protocol::MIN_MINER_BOND;
    pub const MinInvalidProofSlashBps: u16 = qubitum_protocol::MIN_INVALID_PROOF_SLASH_BPS;
    pub const MaxInvalidProofSlashBps: u16 = qubitum_protocol::MAX_INVALID_PROOF_SLASH_BPS;
    pub const MinProofSizeBytes: u32 = qubitum_protocol::TARGET_PROOF_SIZE_MIN_BYTES;
    pub const MaxProofSizeBytes: u32 = qubitum_protocol::TARGET_PROOF_SIZE_MAX_BYTES;
    pub const MaxVerificationLatencyMs: u32 = qubitum_protocol::TARGET_VERIFICATION_MS;
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type AccountData = pallet_balances::AccountData<Balance>;
    type Hashing = BlakeTwo256;
}

impl pallet_balances::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
    type Balance = Balance;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type ReserveIdentifier = [u8; 8];
    type RuntimeHoldReason = RuntimeHoldReason;
    type RuntimeFreezeReason = RuntimeFreezeReason;
    type FreezeIdentifier = ();
    type MaxLocks = ();
    type MaxReserves = ();
    type MaxFreezes = ();
    type DoneSlashHandler = ();
}

impl pallet_qubitum::Config for Test {
    type Currency = Balances;
    type SubnetCreationBurn = SubnetCreationBurn;
    type MinerRegistrationBurn = MinerRegistrationBurn;
    type MinMinerBond = MinMinerBond;
    type MaxMinerBond = MaxMinerBond;
    type MinValidatorStake = MinValidatorStake;
    type MinInvalidProofSlashBps = MinInvalidProofSlashBps;
    type MaxInvalidProofSlashBps = MaxInvalidProofSlashBps;
    type MinProofSizeBytes = MinProofSizeBytes;
    type MaxProofSizeBytes = MaxProofSizeBytes;
    type MaxVerificationLatencyMs = MaxVerificationLatencyMs;
    type RuntimeHoldReason = RuntimeHoldReason;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();

    pallet_balances::GenesisConfig::<Test> {
        balances: vec![
            (1, 1_000_000_000_000_000),
            (2, 1_000_000_000_000_000),
            (3, 1_000_000_000_000_000),
            (4, 1_000_000_000_000_000),
        ],
        ..Default::default()
    }
    .assimilate_storage(&mut storage)
    .unwrap();

    storage.into()
}
