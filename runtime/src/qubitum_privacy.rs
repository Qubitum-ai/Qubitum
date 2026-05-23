use crate::{RuntimeCall, RuntimeOrigin};
use codec::{Decode, DecodeLimit, DecodeWithMemTracking, Encode};
use frame_support::pallet_prelude::TypeInfo;
use sp_runtime::impl_tx_ext_default;
use sp_runtime::traits::{DispatchInfoOf, Implication, TransactionExtension, ValidateResult};
use sp_runtime::transaction_validity::{TransactionSource, TransactionValidityError};
use subtensor_macros::freeze_struct;
use subtensor_runtime_common::CustomTransactionError;

const MAX_CALL_SCAN_DEPTH: u8 = 8;

#[freeze_struct("6fa88ccc5f626e1a")]
#[derive(Default, Encode, Decode, DecodeWithMemTracking, Clone, Eq, PartialEq, TypeInfo)]
pub struct CheckQubitumShielding;

impl CheckQubitumShielding {
    pub fn new() -> Self {
        Self
    }

    fn privacy_violation(call: &RuntimeCall) -> Option<CustomTransactionError> {
        Self::privacy_violation_at_depth(call, 0)
    }

    fn encoded_bytes_privacy_violation(bytes: &[u8], depth: u8) -> Option<CustomTransactionError> {
        if depth >= MAX_CALL_SCAN_DEPTH {
            return Some(CustomTransactionError::QubitumCallMustBeShielded);
        }

        let remaining_depth = u32::from(MAX_CALL_SCAN_DEPTH - depth);
        match RuntimeCall::decode_all_with_depth_limit(remaining_depth, &mut &bytes[..]) {
            Ok(call) => Self::privacy_violation_at_depth(&call, depth),
            Err(_) => Some(CustomTransactionError::QubitumCallMustBeShielded),
        }
    }

    fn privacy_violation_at_depth(call: &RuntimeCall, depth: u8) -> Option<CustomTransactionError> {
        if depth >= MAX_CALL_SCAN_DEPTH {
            return Some(CustomTransactionError::QubitumCallMustBeShielded);
        }

        match call {
            RuntimeCall::Qubitum(_) => Some(CustomTransactionError::QubitumCallMustBeShielded),
            RuntimeCall::Utility(inner) => match inner {
                pallet_subtensor_utility::Call::batch { calls }
                | pallet_subtensor_utility::Call::batch_all { calls }
                | pallet_subtensor_utility::Call::force_batch { calls } => calls
                    .iter()
                    .find_map(|call| Self::privacy_violation_at_depth(call, depth + 1)),
                pallet_subtensor_utility::Call::as_derivative { call, .. }
                | pallet_subtensor_utility::Call::dispatch_as { call, .. }
                | pallet_subtensor_utility::Call::with_weight { call, .. }
                | pallet_subtensor_utility::Call::dispatch_as_fallible { call, .. } => {
                    Self::privacy_violation_at_depth(call, depth + 1)
                }
                pallet_subtensor_utility::Call::if_else { main, fallback } => {
                    Self::privacy_violation_at_depth(main, depth + 1)
                        .or_else(|| Self::privacy_violation_at_depth(fallback, depth + 1))
                }
                _ => None,
            },
            RuntimeCall::Proxy(
                pallet_subtensor_proxy::Call::proxy { call, .. }
                | pallet_subtensor_proxy::Call::proxy_announced { call, .. },
            ) => Self::privacy_violation_at_depth(call, depth + 1),
            RuntimeCall::Proxy(_) => None,
            RuntimeCall::Sudo(
                pallet_sudo::Call::sudo { call }
                | pallet_sudo::Call::sudo_unchecked_weight { call, .. }
                | pallet_sudo::Call::sudo_as { call, .. },
            ) => Self::privacy_violation_at_depth(call, depth + 1),
            RuntimeCall::Sudo(_) => None,
            RuntimeCall::Multisig(
                pallet_multisig::Call::as_multi_threshold_1 { call, .. }
                | pallet_multisig::Call::as_multi { call, .. },
            ) => Self::privacy_violation_at_depth(call, depth + 1),
            RuntimeCall::Multisig(_) => None,
            RuntimeCall::Scheduler(
                pallet_scheduler::Call::schedule { call, .. }
                | pallet_scheduler::Call::schedule_named { call, .. }
                | pallet_scheduler::Call::schedule_after { call, .. }
                | pallet_scheduler::Call::schedule_named_after { call, .. },
            ) => Self::privacy_violation_at_depth(call, depth + 1),
            RuntimeCall::Scheduler(_) => None,
            RuntimeCall::Preimage(pallet_preimage::Call::note_preimage { bytes }) => {
                Self::encoded_bytes_privacy_violation(bytes, depth + 1)
            }
            RuntimeCall::Preimage(_) => None,
            RuntimeCall::MevShield(pallet_shield::Call::store_encrypted { .. }) => {
                Some(CustomTransactionError::ShieldStoreEncryptedDisabled)
            }
            RuntimeCall::MevShield(_) => None,
            _ => None,
        }
    }
}

impl sp_std::fmt::Debug for CheckQubitumShielding {
    #[cfg(feature = "std")]
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "CheckQubitumShielding")
    }

    #[cfg(not(feature = "std"))]
    fn fmt(&self, _: &mut core::fmt::Formatter) -> core::fmt::Result {
        Ok(())
    }
}

impl TransactionExtension<RuntimeCall> for CheckQubitumShielding {
    const IDENTIFIER: &'static str = "CheckQubitumShielding";

    type Implicit = ();
    type Val = ();
    type Pre = ();

    impl_tx_ext_default!(RuntimeCall; weight);

    fn validate(
        &self,
        origin: RuntimeOrigin,
        call: &RuntimeCall,
        _info: &DispatchInfoOf<RuntimeCall>,
        _len: usize,
        _self_implicit: Self::Implicit,
        _inherited_implication: &impl Implication,
        _source: TransactionSource,
    ) -> ValidateResult<Self::Val, RuntimeCall> {
        if let Some(err) = Self::privacy_violation(call) {
            return Err(err.into());
        }

        Ok((Default::default(), (), origin))
    }

    fn prepare(
        self,
        _val: Self::Val,
        _origin: &RuntimeOrigin,
        call: &RuntimeCall,
        _info: &DispatchInfoOf<RuntimeCall>,
        _len: usize,
    ) -> Result<Self::Pre, TransactionValidityError> {
        if let Some(err) = Self::privacy_violation(call) {
            return Err(err.into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RuntimeCall, System};
    use frame_support::dispatch::GetDispatchInfo;
    use frame_support::pallet_prelude::{BoundedVec, ConstU32};
    use frame_support::weights::Weight;
    use qubitum_protocol::ProofSystem;
    use sp_runtime::AccountId32;
    use sp_runtime::BuildStorage;
    use sp_runtime::traits::TxBaseImplication;
    use sp_runtime::transaction_validity::TransactionValidityError;

    fn new_test_ext() -> sp_io::TestExternalities {
        let mut ext: sp_io::TestExternalities = crate::RuntimeGenesisConfig {
            sudo: pallet_sudo::GenesisConfig { key: None },
            ..Default::default()
        }
        .build_storage()
        .unwrap_or_else(|err| panic!("runtime genesis config should build: {err:?}"))
        .into();
        ext.execute_with(|| System::set_block_number(1));
        ext
    }

    fn account(seed: u8) -> AccountId32 {
        AccountId32::new([seed; 32])
    }

    fn commitment(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn direct_qubitum_call() -> RuntimeCall {
        RuntimeCall::Qubitum(pallet_qubitum::Call::create_subnet {
            domain: qubitum_protocol::SubnetDomain::Code,
            proof_system: ProofSystem::RiscZeroStark,
        })
    }

    fn remark_call(seed: u8) -> RuntimeCall {
        RuntimeCall::System(frame_system::Call::remark {
            remark: commitment(seed).to_vec(),
        })
    }

    fn shield_call() -> RuntimeCall {
        RuntimeCall::MevShield(pallet_shield::Call::submit_encrypted {
            ciphertext: BoundedVec::<u8, ConstU32<8192>>::truncate_from(vec![0xAA; 64]),
        })
    }

    fn store_encrypted_call(seed: u8) -> RuntimeCall {
        RuntimeCall::MevShield(pallet_shield::Call::store_encrypted {
            encrypted_call: BoundedVec::<u8, pallet_shield::MaxEncryptedCallSize>::truncate_from(
                vec![seed; 64],
            ),
        })
    }

    fn nested_batch_call(call: RuntimeCall, depth: u8) -> RuntimeCall {
        (0..depth).fold(call, |inner, _| {
            RuntimeCall::Utility(pallet_subtensor_utility::Call::batch { calls: vec![inner] })
        })
    }

    fn validate_ext(
        call: &RuntimeCall,
        source: TransactionSource,
    ) -> Result<(), TransactionValidityError> {
        validate_ext_with_origin(RuntimeOrigin::signed(account(1)), call, source)
    }

    fn validate_ext_with_origin(
        origin: RuntimeOrigin,
        call: &RuntimeCall,
        source: TransactionSource,
    ) -> Result<(), TransactionValidityError> {
        let ext = CheckQubitumShielding::new();
        let info = call.get_dispatch_info();
        ext.validate(origin, call, &info, 0, (), &TxBaseImplication(call), source)
            .map(|_| ())
    }

    fn prepare_ext(call: &RuntimeCall) -> Result<(), TransactionValidityError> {
        let ext = CheckQubitumShielding::new();
        let info = call.get_dispatch_info();
        ext.prepare((), &RuntimeOrigin::signed(account(1)), call, &info, 0)
    }

    fn assert_qubitum_rejected(call: RuntimeCall) {
        assert_eq!(
            validate_ext(&call, TransactionSource::External),
            Err(CustomTransactionError::QubitumCallMustBeShielded.into())
        );
    }

    fn assert_store_encrypted_disabled(call: RuntimeCall) {
        assert_eq!(
            validate_ext(&call, TransactionSource::External),
            Err(CustomTransactionError::ShieldStoreEncryptedDisabled.into())
        );
    }

    #[test]
    fn direct_external_qubitum_call_must_be_shielded() {
        new_test_ext().execute_with(|| {
            assert_qubitum_rejected(direct_qubitum_call());
        });
    }

    #[test]
    fn unsigned_external_qubitum_call_must_be_shielded() {
        new_test_ext().execute_with(|| {
            assert_eq!(
                validate_ext_with_origin(
                    RuntimeOrigin::none(),
                    &direct_qubitum_call(),
                    TransactionSource::External
                ),
                Err(CustomTransactionError::QubitumCallMustBeShielded.into())
            );
        });
    }

    #[test]
    fn utility_wrapped_external_qubitum_call_must_be_shielded() {
        new_test_ext().execute_with(|| {
            let call = RuntimeCall::Utility(pallet_subtensor_utility::Call::batch {
                calls: vec![direct_qubitum_call()],
            });
            assert_qubitum_rejected(call);
        });
    }

    #[test]
    fn alternate_utility_wrappers_must_be_shielded() {
        new_test_ext().execute_with(|| {
            let signed_origin = Box::new(crate::OriginCaller::system(
                frame_system::RawOrigin::Signed(account(2)),
            ));
            let calls = vec![
                RuntimeCall::Utility(pallet_subtensor_utility::Call::batch_all {
                    calls: vec![direct_qubitum_call()],
                }),
                RuntimeCall::Utility(pallet_subtensor_utility::Call::force_batch {
                    calls: vec![direct_qubitum_call()],
                }),
                RuntimeCall::Utility(pallet_subtensor_utility::Call::as_derivative {
                    index: 1,
                    call: Box::new(direct_qubitum_call()),
                }),
                RuntimeCall::Utility(pallet_subtensor_utility::Call::dispatch_as {
                    as_origin: signed_origin.clone(),
                    call: Box::new(direct_qubitum_call()),
                }),
                RuntimeCall::Utility(pallet_subtensor_utility::Call::with_weight {
                    call: Box::new(direct_qubitum_call()),
                    weight: Weight::zero(),
                }),
                RuntimeCall::Utility(pallet_subtensor_utility::Call::dispatch_as_fallible {
                    as_origin: signed_origin,
                    call: Box::new(direct_qubitum_call()),
                }),
                RuntimeCall::Utility(pallet_subtensor_utility::Call::if_else {
                    main: Box::new(remark_call(3)),
                    fallback: Box::new(direct_qubitum_call()),
                }),
            ];

            for call in calls {
                assert_qubitum_rejected(call);
            }
        });
    }

    #[test]
    fn proxy_wrapped_external_qubitum_call_must_be_shielded() {
        new_test_ext().execute_with(|| {
            let call = RuntimeCall::Proxy(pallet_subtensor_proxy::Call::proxy {
                real: account(2).into(),
                force_proxy_type: None,
                call: Box::new(direct_qubitum_call()),
            });
            assert_qubitum_rejected(call);
        });
    }

    #[test]
    fn proxy_announced_wrapped_external_qubitum_call_must_be_shielded() {
        new_test_ext().execute_with(|| {
            let call = RuntimeCall::Proxy(pallet_subtensor_proxy::Call::proxy_announced {
                delegate: account(2).into(),
                real: account(3).into(),
                force_proxy_type: None,
                call: Box::new(direct_qubitum_call()),
            });
            assert_qubitum_rejected(call);
        });
    }

    #[test]
    fn sudo_wrapped_external_qubitum_call_must_be_shielded() {
        new_test_ext().execute_with(|| {
            let call = RuntimeCall::Sudo(pallet_sudo::Call::sudo {
                call: Box::new(direct_qubitum_call()),
            });
            assert_qubitum_rejected(call);
        });
    }

    #[test]
    fn alternate_sudo_wrappers_must_be_shielded() {
        new_test_ext().execute_with(|| {
            let calls = vec![
                RuntimeCall::Sudo(pallet_sudo::Call::sudo_unchecked_weight {
                    call: Box::new(direct_qubitum_call()),
                    weight: Weight::zero(),
                }),
                RuntimeCall::Sudo(pallet_sudo::Call::sudo_as {
                    who: account(2).into(),
                    call: Box::new(direct_qubitum_call()),
                }),
            ];

            for call in calls {
                assert_qubitum_rejected(call);
            }
        });
    }

    #[test]
    fn multisig_wrapped_external_qubitum_call_must_be_shielded() {
        new_test_ext().execute_with(|| {
            let call = RuntimeCall::Multisig(pallet_multisig::Call::as_multi_threshold_1 {
                other_signatories: vec![account(2)],
                call: Box::new(direct_qubitum_call()),
            });
            assert_qubitum_rejected(call);
        });
    }

    #[test]
    fn multisig_as_multi_wrapped_external_qubitum_call_must_be_shielded() {
        new_test_ext().execute_with(|| {
            let call = RuntimeCall::Multisig(pallet_multisig::Call::as_multi {
                threshold: 2,
                other_signatories: vec![account(2)],
                maybe_timepoint: None,
                call: Box::new(direct_qubitum_call()),
                max_weight: Weight::zero(),
            });
            assert_qubitum_rejected(call);
        });
    }

    #[test]
    fn scheduler_wrapped_external_qubitum_call_must_be_shielded() {
        new_test_ext().execute_with(|| {
            let call = RuntimeCall::Scheduler(pallet_scheduler::Call::schedule {
                when: 2,
                maybe_periodic: None,
                priority: 0,
                call: Box::new(direct_qubitum_call()),
            });
            assert_qubitum_rejected(call);
        });
    }

    #[test]
    fn delayed_scheduler_wrappers_must_be_shielded() {
        new_test_ext().execute_with(|| {
            let calls = vec![
                RuntimeCall::Scheduler(pallet_scheduler::Call::schedule_named {
                    id: [1; 32],
                    when: 2,
                    maybe_periodic: None,
                    priority: 0,
                    call: Box::new(direct_qubitum_call()),
                }),
                RuntimeCall::Scheduler(pallet_scheduler::Call::schedule_after {
                    after: 2,
                    maybe_periodic: None,
                    priority: 0,
                    call: Box::new(direct_qubitum_call()),
                }),
                RuntimeCall::Scheduler(pallet_scheduler::Call::schedule_named_after {
                    id: [2; 32],
                    after: 2,
                    maybe_periodic: None,
                    priority: 0,
                    call: Box::new(direct_qubitum_call()),
                }),
            ];

            for call in calls {
                assert_qubitum_rejected(call);
            }
        });
    }

    #[test]
    fn encoded_preimage_qubitum_call_must_be_shielded() {
        new_test_ext().execute_with(|| {
            let call = RuntimeCall::Preimage(pallet_preimage::Call::note_preimage {
                bytes: direct_qubitum_call().encode(),
            });
            assert_eq!(
                validate_ext(&call, TransactionSource::External),
                Err(CustomTransactionError::QubitumCallMustBeShielded.into())
            );
        });
    }

    #[test]
    fn encoded_preimage_non_qubitum_call_passes() {
        new_test_ext().execute_with(|| {
            let call = RuntimeCall::Preimage(pallet_preimage::Call::note_preimage {
                bytes: remark_call(7).encode(),
            });
            assert!(validate_ext(&call, TransactionSource::External).is_ok());
        });
    }

    #[test]
    fn encoded_preimage_malformed_call_bytes_fail_closed() {
        new_test_ext().execute_with(|| {
            let call = RuntimeCall::Preimage(pallet_preimage::Call::note_preimage {
                bytes: vec![0xFF; 8],
            });
            assert_qubitum_rejected(call);
        });
    }

    #[test]
    fn encoded_preimage_exceeding_decode_depth_fails_closed() {
        new_test_ext().execute_with(|| {
            let call = RuntimeCall::Preimage(pallet_preimage::Call::note_preimage {
                bytes: nested_batch_call(remark_call(8), MAX_CALL_SCAN_DEPTH + 1).encode(),
            });
            assert_qubitum_rejected(call);
        });
    }

    #[test]
    fn store_encrypted_is_disabled_in_public_runtime() {
        new_test_ext().execute_with(|| {
            let call = RuntimeCall::MevShield(pallet_shield::Call::store_encrypted {
                encrypted_call:
                    BoundedVec::<u8, pallet_shield::MaxEncryptedCallSize>::truncate_from(
                        direct_qubitum_call().encode(),
                    ),
            });
            assert_eq!(
                validate_ext(&call, TransactionSource::External),
                Err(CustomTransactionError::ShieldStoreEncryptedDisabled.into())
            );
        });
    }

    #[test]
    fn store_encrypted_ciphertext_bytes_are_disabled_in_public_runtime() {
        new_test_ext().execute_with(|| {
            assert_store_encrypted_disabled(store_encrypted_call(0xAA));
        });
    }

    #[test]
    fn utility_wrapped_store_encrypted_is_disabled_in_public_runtime() {
        new_test_ext().execute_with(|| {
            let call = RuntimeCall::Utility(pallet_subtensor_utility::Call::batch {
                calls: vec![RuntimeCall::MevShield(
                    pallet_shield::Call::store_encrypted {
                        encrypted_call:
                            BoundedVec::<u8, pallet_shield::MaxEncryptedCallSize>::truncate_from(
                                vec![0xAA; 64],
                            ),
                    },
                )],
            });
            assert_eq!(
                validate_ext(&call, TransactionSource::External),
                Err(CustomTransactionError::ShieldStoreEncryptedDisabled.into())
            );
        });
    }

    #[test]
    fn wrapped_store_encrypted_calls_are_disabled_in_public_runtime() {
        new_test_ext().execute_with(|| {
            let calls = vec![
                RuntimeCall::Utility(pallet_subtensor_utility::Call::if_else {
                    main: Box::new(remark_call(12)),
                    fallback: Box::new(store_encrypted_call(0xA1)),
                }),
                RuntimeCall::Proxy(pallet_subtensor_proxy::Call::proxy {
                    real: account(2).into(),
                    force_proxy_type: None,
                    call: Box::new(store_encrypted_call(0xA2)),
                }),
                RuntimeCall::Proxy(pallet_subtensor_proxy::Call::proxy_announced {
                    delegate: account(2).into(),
                    real: account(3).into(),
                    force_proxy_type: None,
                    call: Box::new(store_encrypted_call(0xA3)),
                }),
                RuntimeCall::Sudo(pallet_sudo::Call::sudo_unchecked_weight {
                    call: Box::new(store_encrypted_call(0xA4)),
                    weight: Weight::zero(),
                }),
                RuntimeCall::Sudo(pallet_sudo::Call::sudo_as {
                    who: account(2).into(),
                    call: Box::new(store_encrypted_call(0xA5)),
                }),
                RuntimeCall::Multisig(pallet_multisig::Call::as_multi {
                    threshold: 2,
                    other_signatories: vec![account(2)],
                    maybe_timepoint: None,
                    call: Box::new(store_encrypted_call(0xA6)),
                    max_weight: Weight::zero(),
                }),
                RuntimeCall::Scheduler(pallet_scheduler::Call::schedule_named_after {
                    id: [3; 32],
                    after: 2,
                    maybe_periodic: None,
                    priority: 0,
                    call: Box::new(store_encrypted_call(0xA7)),
                }),
                RuntimeCall::Preimage(pallet_preimage::Call::note_preimage {
                    bytes: store_encrypted_call(0xA8).encode(),
                }),
            ];

            for call in calls {
                assert_store_encrypted_disabled(call);
            }
        });
    }

    #[test]
    fn shield_envelope_and_non_qubitum_calls_pass() {
        new_test_ext().execute_with(|| {
            assert!(validate_ext(&shield_call(), TransactionSource::External).is_ok());
            assert!(validate_ext(&shield_call(), TransactionSource::InBlock).is_ok());
            let call = remark_call(9);
            assert!(validate_ext(&call, TransactionSource::External).is_ok());
        });
    }

    #[test]
    fn inblock_qubitum_call_must_be_shielded() {
        new_test_ext().execute_with(|| {
            assert_eq!(
                validate_ext(&direct_qubitum_call(), TransactionSource::InBlock),
                Err(CustomTransactionError::QubitumCallMustBeShielded.into())
            );
        });
    }

    #[test]
    fn prepare_rejects_unshielded_qubitum_call() {
        new_test_ext().execute_with(|| {
            assert_eq!(
                prepare_ext(&direct_qubitum_call()),
                Err(CustomTransactionError::QubitumCallMustBeShielded.into())
            );

            let wrapped = RuntimeCall::Utility(pallet_subtensor_utility::Call::if_else {
                main: Box::new(remark_call(14)),
                fallback: Box::new(direct_qubitum_call()),
            });
            assert_eq!(
                prepare_ext(&wrapped),
                Err(CustomTransactionError::QubitumCallMustBeShielded.into())
            );
        });
    }

    #[test]
    fn prepare_rejects_disabled_store_encrypted_call() {
        new_test_ext().execute_with(|| {
            assert_eq!(
                prepare_ext(&store_encrypted_call(0xB1)),
                Err(CustomTransactionError::ShieldStoreEncryptedDisabled.into())
            );

            let wrapped = RuntimeCall::Utility(pallet_subtensor_utility::Call::batch_all {
                calls: vec![store_encrypted_call(0xB2)],
            });
            assert_eq!(
                prepare_ext(&wrapped),
                Err(CustomTransactionError::ShieldStoreEncryptedDisabled.into())
            );
        });
    }

    #[test]
    fn prepare_allows_shield_envelope_and_non_qubitum_calls() {
        new_test_ext().execute_with(|| {
            assert!(prepare_ext(&shield_call()).is_ok());
            assert!(prepare_ext(&remark_call(13)).is_ok());
        });
    }

    #[test]
    fn excessively_nested_wrappers_fail_closed() {
        new_test_ext().execute_with(|| {
            assert_qubitum_rejected(nested_batch_call(remark_call(11), MAX_CALL_SCAN_DEPTH));
        });
    }
}
