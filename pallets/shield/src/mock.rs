use crate as pallet_shield;
use stp_shield::MLKEM768_ENC_KEY_LEN;

use frame_support::pallet_prelude::DispatchError;
use frame_support::traits::{ConstBool, ConstU64, Contains};
use frame_support::{BoundedVec, construct_runtime, derive_impl, parameter_types};
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_core::sr25519;
use sp_runtime::{BuildStorage, generic, testing::TestSignature};
use std::cell::RefCell;
use stp_shield::ShieldEncKey;

pub type Block = frame_system::mocking::MockBlock<Test>;

pub type DecodableExtrinsic = generic::UncheckedExtrinsic<u64, RuntimeCall, TestSignature, ()>;
pub type DecodableBlock =
    generic::Block<generic::Header<u64, sp_runtime::traits::BlakeTwo256>, DecodableExtrinsic>;

construct_runtime!(
    pub enum Test {
        System: frame_system = 0,
        Timestamp: pallet_timestamp = 1,
        Aura: pallet_aura = 2,
        MevShield: pallet_shield = 3,
        Utility: pallet_subtensor_utility = 4,
    }
);

const SLOT_DURATION: u64 = 6000;

parameter_types! {
    pub const SlotDuration: u64 = SLOT_DURATION;
    pub const MaxAuthorities: u32 = 32;
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

impl pallet_timestamp::Config for Test {
    type Moment = u64;
    type OnTimestampSet = ();
    type MinimumPeriod = ConstU64<{ SLOT_DURATION / 2 }>;
    type WeightInfo = ();
}

impl pallet_aura::Config for Test {
    type AuthorityId = AuraId;
    type DisabledValidators = ();
    type MaxAuthorities = MaxAuthorities;
    type AllowMultipleBlocksPerSlot = ConstBool<false>;
    type SlotDuration = SlotDuration;
}

impl pallet_subtensor_utility::Config for Test {
    type RuntimeCall = RuntimeCall;
    type PalletsOrigin = OriginCaller;
    type WeightInfo = ();
}

thread_local! {
    static MOCK_CURRENT: RefCell<Option<AuraId>> = const { RefCell::new(None) };
    static MOCK_NEXT_NEXT: RefCell<Option<Option<AuraId>>> = const { RefCell::new(None) };
}

pub struct MockFindAuthors;

impl pallet_shield::FindAuthors<Test> for MockFindAuthors {
    fn find_current_author() -> Option<AuraId> {
        // Thread-local override (unit tests) → Aura fallback (benchmarks).
        MOCK_CURRENT.with(|c| c.borrow().clone()).or_else(|| {
            let slot = Aura::current_slot_from_digests()?;
            let auths = pallet_aura::Authorities::<Test>::get().into_inner();
            auths.get(*slot as usize % auths.len()).cloned()
        })
    }

    fn find_next_next_author() -> Option<AuraId> {
        if let Some(val) = MOCK_NEXT_NEXT.with(|n| n.borrow().clone()) {
            return val;
        }
        let slot = Aura::current_slot_from_digests()?.checked_add(2)?;
        let auths = pallet_aura::Authorities::<Test>::get().into_inner();
        auths.get(slot as usize % auths.len()).cloned()
    }
}

/// Mock decryptor that just decodes the bytes without decryption.
pub struct MockDecryptor;

impl pallet_shield::ExtrinsicDecryptor<RuntimeCall> for MockDecryptor {
    fn decrypt(data: &[u8]) -> Result<RuntimeCall, DispatchError> {
        pallet_shield::decode_runtime_call_with_depth_limit::<RuntimeCall>(data)
    }
}

pub struct MockQueueCallFilter;

impl Contains<RuntimeCall> for MockQueueCallFilter {
    fn contains(call: &RuntimeCall) -> bool {
        !contains_recursive_shield_call(call, 0)
    }
}

fn contains_recursive_shield_call(call: &RuntimeCall, depth: u8) -> bool {
    if depth >= 8 {
        return true;
    }

    match call {
        RuntimeCall::MevShield(
            pallet_shield::Call::submit_encrypted { .. }
            | pallet_shield::Call::store_encrypted { .. },
        ) => true,
        RuntimeCall::Utility(inner) => match inner {
            pallet_subtensor_utility::Call::batch { calls }
            | pallet_subtensor_utility::Call::batch_all { calls }
            | pallet_subtensor_utility::Call::force_batch { calls } => calls
                .iter()
                .any(|call| contains_recursive_shield_call(call, depth + 1)),
            pallet_subtensor_utility::Call::as_derivative { call, .. }
            | pallet_subtensor_utility::Call::dispatch_as { call, .. }
            | pallet_subtensor_utility::Call::with_weight { call, .. }
            | pallet_subtensor_utility::Call::dispatch_as_fallible { call, .. } => {
                contains_recursive_shield_call(call, depth + 1)
            }
            pallet_subtensor_utility::Call::if_else { main, fallback } => {
                contains_recursive_shield_call(main, depth + 1)
                    || contains_recursive_shield_call(fallback, depth + 1)
            }
            _ => false,
        },
        _ => false,
    }
}

impl pallet_shield::Config for Test {
    type AuthorityId = AuraId;
    type FindAuthors = MockFindAuthors;
    type RuntimeCall = RuntimeCall;
    type QueueCallFilter = MockQueueCallFilter;
    type QueueOrigin = pallet_shield::SignedQueueOrigin;
    type ExtrinsicDecryptor = MockDecryptor;
    type WeightInfo = ();
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut ext: sp_io::TestExternalities = RuntimeGenesisConfig::default()
        .build_storage()
        .expect("valid genesis")
        .into();
    ext.register_extension(sp_keystore::KeystoreExt::new(
        sp_keystore::testing::MemoryKeystore::new(),
    ));
    ext
}

pub fn valid_pk() -> ShieldEncKey {
    BoundedVec::truncate_from(vec![0x42; MLKEM768_ENC_KEY_LEN])
}

pub fn valid_pk_b() -> ShieldEncKey {
    BoundedVec::truncate_from(vec![0x99; MLKEM768_ENC_KEY_LEN])
}

/// Create a deterministic `AuraId` from a simple index for tests.
pub fn author(n: u8) -> AuraId {
    AuraId::from(sr25519::Public::from_raw([n; 32]))
}

pub fn set_authors(current: Option<AuraId>, next_next: Option<AuraId>) {
    MOCK_CURRENT.with(|c| *c.borrow_mut() = current);
    MOCK_NEXT_NEXT.with(|n| *n.borrow_mut() = Some(next_next));
}

pub fn nest_call(call: RuntimeCall, depth: usize) -> RuntimeCall {
    (0..depth).fold(call, |inner, _| {
        RuntimeCall::Utility(pallet_subtensor_utility::Call::batch { calls: vec![inner] })
    })
}

pub fn build_wire_ciphertext(
    key_hash: &[u8; 16],
    kem_ct: &[u8],
    nonce: &[u8; 24],
    aead_ct: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(key_hash);
    buf.extend_from_slice(&(kem_ct.len() as u16).to_le_bytes());
    buf.extend_from_slice(kem_ct);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(aead_ct);
    buf
}
