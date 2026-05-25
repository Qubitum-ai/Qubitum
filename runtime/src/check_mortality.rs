use codec::{Decode, DecodeLimit, DecodeWithMemTracking, Encode};
use core::marker::PhantomData;
use frame_support::pallet_prelude::TypeInfo;
use frame_system::CheckMortality as CheckMortalitySubstrate;
use sp_runtime::{
    generic::Era,
    traits::{DispatchInfoOf, Dispatchable, Implication, TransactionExtension, ValidateResult},
    transaction_validity::{InvalidTransaction, TransactionSource, TransactionValidityError},
};
use subtensor_macros::freeze_struct;

/// Maximum allowed Era period (in blocks) for `submit_encrypted` transactions.
///
/// Substrate's minimum mortal Era is 4 blocks (smallest power-of-two ≥ 4).
/// Limiting encrypted txs to this value ensures stuck transactions evict from
/// the fork-aware tx pool within a handful of blocks.
const MAX_SHIELD_ERA_PERIOD: u64 = 8;
const MAX_SHIELD_CALL_SCAN_DEPTH: u8 = 8;
const MAX_SHIELD_PREIMAGE_DECODE_PROBE_DEPTH: u32 = 32;

pub trait ContainsShieldSubmitEncrypted {
    fn contains_shield_submit_encrypted(&self) -> bool;
}

impl ContainsShieldSubmitEncrypted for crate::RuntimeCall {
    fn contains_shield_submit_encrypted(&self) -> bool {
        shield_submit_encrypted_at_depth(self, 0)
    }
}

fn encoded_runtime_call_contains_shield_submit(bytes: &[u8], depth: u8) -> bool {
    if depth >= MAX_SHIELD_CALL_SCAN_DEPTH {
        return true;
    }

    let remaining_depth = u32::from(MAX_SHIELD_CALL_SCAN_DEPTH - depth);
    match crate::RuntimeCall::decode_all_with_depth_limit(remaining_depth, &mut &bytes[..]) {
        Ok(call) => shield_submit_encrypted_at_depth(&call, depth),
        Err(_) => {
            if let Ok(call) =
                crate::RuntimeCall::decode_with_depth_limit(remaining_depth, &mut &bytes[..])
            {
                return shield_submit_encrypted_at_depth(&call, depth);
            }

            crate::RuntimeCall::decode_all_with_depth_limit(
                MAX_SHIELD_PREIMAGE_DECODE_PROBE_DEPTH,
                &mut &bytes[..],
            )
            .is_ok()
                || crate::RuntimeCall::decode_with_depth_limit(
                    MAX_SHIELD_PREIMAGE_DECODE_PROBE_DEPTH,
                    &mut &bytes[..],
                )
                .is_ok()
        }
    }
}

fn shield_submit_encrypted_at_depth(call: &crate::RuntimeCall, depth: u8) -> bool {
    if depth >= MAX_SHIELD_CALL_SCAN_DEPTH {
        return true;
    }

    match call {
        crate::RuntimeCall::MevShield(pallet_shield::Call::submit_encrypted { .. }) => true,
        crate::RuntimeCall::Utility(inner) => match inner {
            pallet_subtensor_utility::Call::batch { calls }
            | pallet_subtensor_utility::Call::batch_all { calls }
            | pallet_subtensor_utility::Call::force_batch { calls } => calls
                .iter()
                .any(|call| shield_submit_encrypted_at_depth(call, depth + 1)),
            pallet_subtensor_utility::Call::as_derivative { call, .. }
            | pallet_subtensor_utility::Call::dispatch_as { call, .. }
            | pallet_subtensor_utility::Call::with_weight { call, .. }
            | pallet_subtensor_utility::Call::dispatch_as_fallible { call, .. } => {
                shield_submit_encrypted_at_depth(call, depth + 1)
            }
            pallet_subtensor_utility::Call::if_else { main, fallback } => {
                shield_submit_encrypted_at_depth(main, depth + 1)
                    || shield_submit_encrypted_at_depth(fallback, depth + 1)
            }
            _ => false,
        },
        crate::RuntimeCall::Proxy(
            pallet_subtensor_proxy::Call::proxy { call, .. }
            | pallet_subtensor_proxy::Call::proxy_announced { call, .. },
        ) => shield_submit_encrypted_at_depth(call, depth + 1),
        crate::RuntimeCall::Sudo(
            pallet_sudo::Call::sudo { call }
            | pallet_sudo::Call::sudo_unchecked_weight { call, .. }
            | pallet_sudo::Call::sudo_as { call, .. },
        ) => shield_submit_encrypted_at_depth(call, depth + 1),
        crate::RuntimeCall::Multisig(
            pallet_multisig::Call::as_multi_threshold_1 { call, .. }
            | pallet_multisig::Call::as_multi { call, .. },
        ) => shield_submit_encrypted_at_depth(call, depth + 1),
        crate::RuntimeCall::Scheduler(
            pallet_scheduler::Call::schedule { call, .. }
            | pallet_scheduler::Call::schedule_named { call, .. }
            | pallet_scheduler::Call::schedule_after { call, .. }
            | pallet_scheduler::Call::schedule_named_after { call, .. },
        ) => shield_submit_encrypted_at_depth(call, depth + 1),
        crate::RuntimeCall::Preimage(pallet_preimage::Call::note_preimage { bytes }) => {
            encoded_runtime_call_contains_shield_submit(bytes, depth + 1)
        }
        _ => false,
    }
}

fn ensure_shield_submit_mortal_era<Call: ContainsShieldSubmitEncrypted>(
    era: Era,
    call: &Call,
) -> Result<(), TransactionValidityError> {
    if call.contains_shield_submit_encrypted() {
        let era_too_long = match era {
            Era::Immortal => true,
            Era::Mortal(period, _) => period > MAX_SHIELD_ERA_PERIOD,
        };
        if era_too_long {
            return Err(InvalidTransaction::Stale.into());
        }
    }

    Ok(())
}

/// A transparent wrapper around [`frame_system::CheckMortality`] that additionally
/// enforces a short Era period for [`pallet_shield::Call::submit_encrypted`] transactions.
///
/// Drop-in replacement for `frame_system::CheckMortality` in the runtime's
/// transaction extension pipeline. Shares the same `IDENTIFIER = "CheckMortality"`
/// and identical SCALE encoding, so existing clients require no changes.
///
/// Any `submit_encrypted` call signed with an immortal Era or a mortal Era period
/// longer than [`MAX_SHIELD_ERA_PERIOD`] is rejected during both pool validation
/// and block preparation with `InvalidTransaction::Stale`, preventing long-lived
/// encrypted transactions that can never be decrypted from entering or executing.
#[freeze_struct("3cb7a665d55d00e5")]
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, Eq, PartialEq, TypeInfo)]
#[scale_info(skip_type_params(T))]
pub struct CheckMortality<T: frame_system::Config + Send + Sync>(pub Era, PhantomData<T>);

impl<T: frame_system::Config + Send + Sync> CheckMortality<T> {
    pub fn from(era: Era) -> Self {
        Self(era, PhantomData)
    }
}

impl<T: frame_system::Config + Send + Sync> core::fmt::Debug for CheckMortality<T> {
    #[cfg(feature = "std")]
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "CheckMortality({:?})", self.0)
    }

    #[cfg(not(feature = "std"))]
    fn fmt(&self, _: &mut core::fmt::Formatter) -> core::fmt::Result {
        Ok(())
    }
}

impl<T: frame_system::Config + Send + Sync + TypeInfo>
    TransactionExtension<<T as frame_system::Config>::RuntimeCall> for CheckMortality<T>
where
    <T as frame_system::Config>::RuntimeCall: ContainsShieldSubmitEncrypted + Dispatchable,
{
    const IDENTIFIER: &'static str = "CheckMortality";

    type Implicit = <CheckMortalitySubstrate<T> as TransactionExtension<
        <T as frame_system::Config>::RuntimeCall,
    >>::Implicit;
    type Val = <CheckMortalitySubstrate<T> as TransactionExtension<
        <T as frame_system::Config>::RuntimeCall,
    >>::Val;
    type Pre = <CheckMortalitySubstrate<T> as TransactionExtension<
        <T as frame_system::Config>::RuntimeCall,
    >>::Pre;

    fn implicit(&self) -> Result<Self::Implicit, TransactionValidityError> {
        CheckMortalitySubstrate::<T>::from(self.0).implicit()
    }

    fn weight(&self, call: &<T as frame_system::Config>::RuntimeCall) -> sp_weights::Weight {
        CheckMortalitySubstrate::<T>::from(self.0).weight(call)
    }

    fn validate(
        &self,
        origin: T::RuntimeOrigin,
        call: &<T as frame_system::Config>::RuntimeCall,
        info: &DispatchInfoOf<<T as frame_system::Config>::RuntimeCall>,
        len: usize,
        self_implicit: Self::Implicit,
        inherited_implication: &impl Implication,
        source: TransactionSource,
    ) -> ValidateResult<Self::Val, <T as frame_system::Config>::RuntimeCall> {
        ensure_shield_submit_mortal_era(self.0, call)?;

        CheckMortalitySubstrate::<T>::from(self.0).validate(
            origin,
            call,
            info,
            len,
            self_implicit,
            inherited_implication,
            source,
        )
    }

    fn prepare(
        self,
        val: Self::Val,
        origin: &T::RuntimeOrigin,
        call: &<T as frame_system::Config>::RuntimeCall,
        info: &DispatchInfoOf<<T as frame_system::Config>::RuntimeCall>,
        len: usize,
    ) -> Result<Self::Pre, TransactionValidityError> {
        ensure_shield_submit_mortal_era(self.0, call)?;

        CheckMortalitySubstrate::<T>::from(self.0).prepare(val, origin, call, info, len)
    }
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    use frame_support::dispatch::GetDispatchInfo;
    use frame_support::pallet_prelude::{BoundedVec, ConstU32};
    use frame_support::weights::Weight;

    use sp_runtime::AccountId32;
    use sp_runtime::transaction_validity::InvalidTransaction;

    use crate::{Runtime, RuntimeCall, RuntimeOrigin, System};
    use sp_runtime::BuildStorage;

    fn new_test_ext() -> sp_io::TestExternalities {
        let mut ext: sp_io::TestExternalities = crate::RuntimeGenesisConfig {
            sudo: pallet_sudo::GenesisConfig { key: None },
            ..Default::default()
        }
        .build_storage()
        .unwrap()
        .into();
        ext.execute_with(|| System::set_block_number(1));
        ext
    }

    fn submit_encrypted_call() -> RuntimeCall {
        RuntimeCall::MevShield(pallet_shield::Call::submit_encrypted {
            ciphertext: BoundedVec::<u8, ConstU32<8192>>::truncate_from(vec![0xAA; 64]),
        })
    }

    fn account(seed: u8) -> AccountId32 {
        AccountId32::new([seed; 32])
    }

    fn utility_wrapped_submit_encrypted_call() -> RuntimeCall {
        RuntimeCall::Utility(pallet_subtensor_utility::Call::if_else {
            main: Box::new(remark_call()),
            fallback: Box::new(submit_encrypted_call()),
        })
    }

    fn privileged_wrapped_submit_encrypted_calls() -> Vec<RuntimeCall> {
        let proxy_submit = RuntimeCall::Proxy(pallet_subtensor_proxy::Call::proxy {
            real: account(2).into(),
            force_proxy_type: None,
            call: Box::new(submit_encrypted_call()),
        });

        vec![
            proxy_submit.clone(),
            RuntimeCall::Proxy(pallet_subtensor_proxy::Call::proxy_announced {
                delegate: account(3).into(),
                real: account(2).into(),
                force_proxy_type: None,
                call: Box::new(submit_encrypted_call()),
            }),
            RuntimeCall::Sudo(pallet_sudo::Call::sudo {
                call: Box::new(submit_encrypted_call()),
            }),
            RuntimeCall::Sudo(pallet_sudo::Call::sudo_unchecked_weight {
                call: Box::new(submit_encrypted_call()),
                weight: Weight::zero(),
            }),
            RuntimeCall::Sudo(pallet_sudo::Call::sudo_as {
                who: account(4).into(),
                call: Box::new(submit_encrypted_call()),
            }),
            RuntimeCall::Multisig(pallet_multisig::Call::as_multi_threshold_1 {
                other_signatories: vec![account(5)],
                call: Box::new(submit_encrypted_call()),
            }),
            RuntimeCall::Multisig(pallet_multisig::Call::as_multi {
                threshold: 2,
                other_signatories: vec![account(6)],
                maybe_timepoint: None,
                call: Box::new(submit_encrypted_call()),
                max_weight: Weight::zero(),
            }),
            RuntimeCall::Scheduler(pallet_scheduler::Call::schedule {
                when: 2,
                maybe_periodic: None,
                priority: 0,
                call: Box::new(submit_encrypted_call()),
            }),
            RuntimeCall::Scheduler(pallet_scheduler::Call::schedule_named {
                id: [1; 32],
                when: 2,
                maybe_periodic: None,
                priority: 0,
                call: Box::new(submit_encrypted_call()),
            }),
            RuntimeCall::Scheduler(pallet_scheduler::Call::schedule_after {
                after: 2,
                maybe_periodic: None,
                priority: 0,
                call: Box::new(submit_encrypted_call()),
            }),
            RuntimeCall::Scheduler(pallet_scheduler::Call::schedule_named_after {
                id: [2; 32],
                after: 2,
                maybe_periodic: None,
                priority: 0,
                call: Box::new(submit_encrypted_call()),
            }),
            RuntimeCall::Preimage(pallet_preimage::Call::note_preimage {
                bytes: proxy_submit.encode(),
            }),
        ]
    }

    fn nested_utility_call(call: RuntimeCall, depth: u8) -> RuntimeCall {
        (0..depth).fold(call, |inner, _| {
            RuntimeCall::Utility(pallet_subtensor_utility::Call::batch { calls: vec![inner] })
        })
    }

    fn preimage_wrapped_submit_encrypted_call() -> RuntimeCall {
        RuntimeCall::Preimage(pallet_preimage::Call::note_preimage {
            bytes: utility_wrapped_submit_encrypted_call().encode(),
        })
    }

    fn preimage_wrapped_submit_encrypted_call_with_trailing_bytes() -> RuntimeCall {
        let mut bytes = utility_wrapped_submit_encrypted_call().encode();
        bytes.extend_from_slice(&[0xA5, 0x5A, 0xFF]);
        RuntimeCall::Preimage(pallet_preimage::Call::note_preimage { bytes })
    }

    fn deeply_nested_preimage_call(call: RuntimeCall) -> RuntimeCall {
        RuntimeCall::Preimage(pallet_preimage::Call::note_preimage {
            bytes: nested_utility_call(call, MAX_SHIELD_CALL_SCAN_DEPTH + 1).encode(),
        })
    }

    fn deeply_nested_preimage_call_with_trailing_bytes(call: RuntimeCall) -> RuntimeCall {
        let mut bytes = nested_utility_call(call, MAX_SHIELD_CALL_SCAN_DEPTH + 1).encode();
        bytes.extend_from_slice(&[0x01, 0x02]);
        RuntimeCall::Preimage(pallet_preimage::Call::note_preimage { bytes })
    }

    fn remark_call() -> RuntimeCall {
        RuntimeCall::System(frame_system::Call::remark { remark: vec![] })
    }

    /// Only tests the early-return path (era check). Does NOT call into
    /// CheckMortalitySubstrate which needs real block hashes.
    fn validate_era_check(era: Era, call: &RuntimeCall) -> Result<(), TransactionValidityError> {
        ensure_shield_submit_mortal_era(era, call)
    }

    #[test]
    fn shield_tx_with_immortal_era_rejected() {
        new_test_ext().execute_with(|| {
            assert_eq!(
                validate_era_check(Era::Immortal, &submit_encrypted_call()),
                Err(InvalidTransaction::Stale.into())
            );
        });
    }

    #[test]
    fn prepare_rejects_shield_tx_with_immortal_era_before_substrate_mortality() {
        new_test_ext().execute_with(|| {
            let call = submit_encrypted_call();
            let info = call.get_dispatch_info();
            let ext = CheckMortality::<Runtime>::from(Era::Immortal);

            assert_eq!(
                ext.prepare((), &RuntimeOrigin::none(), &call, &info, 0),
                Err(InvalidTransaction::Stale.into())
            );
        });
    }

    #[test]
    fn prepare_rejects_wrapped_shield_tx_with_immortal_era_before_substrate_mortality() {
        new_test_ext().execute_with(|| {
            for call in [
                utility_wrapped_submit_encrypted_call(),
                preimage_wrapped_submit_encrypted_call(),
                deeply_nested_preimage_call(submit_encrypted_call()),
            ] {
                let info = call.get_dispatch_info();
                let ext = CheckMortality::<Runtime>::from(Era::Immortal);

                assert_eq!(
                    ext.prepare((), &RuntimeOrigin::none(), &call, &info, 0),
                    Err(InvalidTransaction::Stale.into())
                );
            }
        });
    }

    #[test]
    fn prepare_rejects_privileged_wrapped_shield_tx_before_substrate_mortality() {
        new_test_ext().execute_with(|| {
            for call in privileged_wrapped_submit_encrypted_calls() {
                let info = call.get_dispatch_info();
                let ext = CheckMortality::<Runtime>::from(Era::Immortal);

                assert_eq!(
                    ext.prepare((), &RuntimeOrigin::none(), &call, &info, 0),
                    Err(InvalidTransaction::Stale.into())
                );
            }
        });
    }

    #[test]
    fn shield_tx_with_era_too_long_rejected() {
        new_test_ext().execute_with(|| {
            // Period 16 > MAX_SHIELD_ERA_PERIOD (8)
            assert_eq!(
                validate_era_check(Era::mortal(16, 1), &submit_encrypted_call()),
                Err(InvalidTransaction::Stale.into())
            );
        });
    }

    #[test]
    fn wrapped_shield_tx_with_immortal_era_rejected() {
        new_test_ext().execute_with(|| {
            assert_eq!(
                validate_era_check(Era::Immortal, &utility_wrapped_submit_encrypted_call()),
                Err(InvalidTransaction::Stale.into())
            );
        });
    }

    #[test]
    fn privileged_wrapped_shield_tx_with_long_era_rejected() {
        new_test_ext().execute_with(|| {
            for call in privileged_wrapped_submit_encrypted_calls() {
                assert_eq!(
                    validate_era_check(Era::mortal(16, 1), &call),
                    Err(InvalidTransaction::Stale.into())
                );
            }
        });
    }

    #[test]
    fn encoded_preimage_shield_tx_with_long_era_rejected() {
        new_test_ext().execute_with(|| {
            assert_eq!(
                validate_era_check(
                    Era::mortal(16, 1),
                    &preimage_wrapped_submit_encrypted_call()
                ),
                Err(InvalidTransaction::Stale.into())
            );
        });
    }

    #[test]
    fn encoded_preimage_shield_tx_prefix_with_trailing_bytes_has_short_era_enforced() {
        new_test_ext().execute_with(|| {
            assert_eq!(
                validate_era_check(
                    Era::mortal(16, 1),
                    &preimage_wrapped_submit_encrypted_call_with_trailing_bytes()
                ),
                Err(InvalidTransaction::Stale.into())
            );
        });
    }

    #[test]
    fn deeply_nested_encoded_preimage_shield_tx_with_long_era_fails_closed() {
        new_test_ext().execute_with(|| {
            assert_eq!(
                validate_era_check(
                    Era::mortal(16, 1),
                    &deeply_nested_preimage_call(submit_encrypted_call())
                ),
                Err(InvalidTransaction::Stale.into())
            );
        });
    }

    #[test]
    fn deeply_nested_encoded_preimage_prefix_with_trailing_bytes_fails_closed() {
        new_test_ext().execute_with(|| {
            assert_eq!(
                validate_era_check(
                    Era::mortal(16, 1),
                    &deeply_nested_preimage_call_with_trailing_bytes(submit_encrypted_call())
                ),
                Err(InvalidTransaction::Stale.into())
            );
        });
    }

    #[test]
    fn deeply_nested_encoded_preimage_non_shield_tx_with_long_era_fails_closed() {
        new_test_ext().execute_with(|| {
            assert_eq!(
                validate_era_check(
                    Era::mortal(16, 1),
                    &deeply_nested_preimage_call(remark_call())
                ),
                Err(InvalidTransaction::Stale.into())
            );
        });
    }

    #[test]
    fn malformed_encoded_preimage_with_long_era_passes_through() {
        new_test_ext().execute_with(|| {
            let call = RuntimeCall::Preimage(pallet_preimage::Call::note_preimage {
                bytes: vec![0xFF; 8],
            });
            assert!(validate_era_check(Era::mortal(256, 1), &call).is_ok());
        });
    }

    #[test]
    fn shield_tx_with_max_allowed_era_accepted() {
        new_test_ext().execute_with(|| {
            assert!(validate_era_check(Era::mortal(8, 1), &submit_encrypted_call()).is_ok());
            assert!(
                validate_era_check(Era::mortal(8, 1), &utility_wrapped_submit_encrypted_call())
                    .is_ok()
            );
        });
    }

    #[test]
    fn shield_tx_with_short_era_accepted() {
        new_test_ext().execute_with(|| {
            assert!(validate_era_check(Era::mortal(4, 1), &submit_encrypted_call()).is_ok());
        });
    }

    #[test]
    fn non_shield_tx_with_immortal_era_passes_through() {
        new_test_ext().execute_with(|| {
            assert!(validate_era_check(Era::Immortal, &remark_call()).is_ok());
        });
    }

    #[test]
    fn non_shield_tx_with_long_era_passes_through() {
        new_test_ext().execute_with(|| {
            assert!(validate_era_check(Era::mortal(256, 1), &remark_call()).is_ok());
        });
    }
}
