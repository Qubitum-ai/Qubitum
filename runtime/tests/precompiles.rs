#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use fp_evm::{Context, ExitError, PrecompileFailure, PrecompileResult};
use frame_support::traits::Contains;
use node_subtensor_runtime::{
    BuildStorage, ContractCallFilter, Runtime, RuntimeCall, RuntimeGenesisConfig, System,
};
use pallet_evm::{BalanceConverter, PrecompileSet};
use precompile_utils::solidity::encode_with_selector;
use precompile_utils::testing::MockHandle;
use qubitum_protocol::{ProofSystem, SubnetDomain};
use sp_core::{H160, H256, U256};
use sp_runtime::codec::Encode;
use sp_runtime::traits::Hash;
use std::collections::BTreeSet;
use subtensor_precompiles::{
    BalanceTransferPrecompile, PrecompileExt, Precompiles, ProxyPrecompile,
};

type AccountId = <Runtime as frame_system::Config>::AccountId;

fn new_test_ext() -> sp_io::TestExternalities {
    let mut ext: sp_io::TestExternalities = RuntimeGenesisConfig::default()
        .build_storage()
        .unwrap()
        .into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}

fn execute_precompile(
    precompiles: &Precompiles<Runtime>,
    precompile_address: H160,
    caller: H160,
    input: Vec<u8>,
    apparent_value: U256,
) -> Option<PrecompileResult> {
    let mut handle = MockHandle::new(
        precompile_address,
        Context {
            address: precompile_address,
            caller,
            apparent_value,
        },
    );
    handle.input = input;
    precompiles.execute(&mut handle)
}

fn evm_apparent_value_from_substrate(amount: u64) -> U256 {
    <Runtime as pallet_evm::Config>::BalanceConverter::into_evm_balance(amount.into())
        .expect("runtime balance conversion should work for test amount")
        .into()
}

fn addr_from_index(index: u64) -> H160 {
    H160::from_low_u64_be(index)
}

fn selector_u32(signature: &str) -> u32 {
    let hash = sp_io::hashing::keccak_256(signature.as_bytes());
    u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
}

fn qubitum_create_subnet_call() -> RuntimeCall {
    RuntimeCall::Qubitum(pallet_qubitum::Call::create_subnet {
        domain: SubnetDomain::Code,
        proof_system: ProofSystem::RiscZeroStark,
    })
}

#[test]
fn precompile_registry_addresses_are_unique() {
    let addresses = Precompiles::<Runtime>::used_addresses();
    let unique: BTreeSet<_> = addresses.into_iter().collect();
    assert_eq!(unique.len(), addresses.len());
}

#[test]
fn generic_runtime_dispatch_precompile_is_not_exposed() {
    new_test_ext().execute_with(|| {
        let precompiles = Precompiles::<Runtime>::new();
        let dispatch_slot = addr_from_index(6);

        assert!(!Precompiles::<Runtime>::used_addresses().contains(&dispatch_slot));
        assert!(
            execute_precompile(
                &precompiles,
                dispatch_slot,
                addr_from_index(1),
                qubitum_create_subnet_call().encode(),
                U256::zero(),
            )
            .is_none()
        );
    });
}

#[test]
fn balance_transfer_precompile_transfers_balance() {
    new_test_ext().execute_with(|| {
        let precompiles = Precompiles::<Runtime>::new();
        let precompile_addr = addr_from_index(BalanceTransferPrecompile::<Runtime>::INDEX);
        let dispatch_account: AccountId = BalanceTransferPrecompile::<Runtime>::account_id();
        let destination_raw = H256::repeat_byte(7);
        let destination_account: AccountId = destination_raw.0.into();

        let amount = 123_456;
        pallet_subtensor::Pallet::<Runtime>::add_balance_to_coldkey_account(
            &dispatch_account,
            (amount * 2).into(),
        );

        let source_balance_before =
            pallet_balances::Pallet::<Runtime>::free_balance(&dispatch_account);
        let destination_balance_before =
            pallet_balances::Pallet::<Runtime>::free_balance(&destination_account);

        let result = execute_precompile(
            &precompiles,
            precompile_addr,
            addr_from_index(1),
            encode_with_selector(selector_u32("transfer(bytes32)"), (destination_raw,)),
            evm_apparent_value_from_substrate(amount),
        );
        let precompile_result =
            result.expect("expected precompile transfer call to be routed to a precompile");
        precompile_result.expect("expected successful precompile transfer dispatch");

        let source_balance_after =
            pallet_balances::Pallet::<Runtime>::free_balance(&dispatch_account);
        let destination_balance_after =
            pallet_balances::Pallet::<Runtime>::free_balance(&destination_account);

        assert_eq!(source_balance_after, source_balance_before - amount.into());
        assert_eq!(
            destination_balance_after,
            destination_balance_before + amount.into()
        );
    });
}

#[test]
fn balance_transfer_precompile_respects_dispatch_guard_policy() {
    new_test_ext().execute_with(|| {
        let precompiles = Precompiles::<Runtime>::new();
        let precompile_addr = addr_from_index(BalanceTransferPrecompile::<Runtime>::INDEX);
        let dispatch_account: AccountId = BalanceTransferPrecompile::<Runtime>::account_id();
        let destination_raw = H256::repeat_byte(8);
        let destination_account: AccountId = destination_raw.0.into();

        let amount = 100;
        pallet_subtensor::Pallet::<Runtime>::add_balance_to_coldkey_account(
            &dispatch_account,
            1_000_000_u64.into(),
        );

        let replacement_coldkey = AccountId::from([9u8; 32]);
        let replacement_hash =
            <Runtime as frame_system::Config>::Hashing::hash_of(&replacement_coldkey);
        pallet_subtensor::ColdkeySwapAnnouncements::<Runtime>::insert(
            &dispatch_account,
            (System::block_number(), replacement_hash),
        );

        let source_balance_before =
            pallet_balances::Pallet::<Runtime>::free_balance(&dispatch_account);
        let destination_balance_before =
            pallet_balances::Pallet::<Runtime>::free_balance(&destination_account);

        let result = execute_precompile(
            &precompiles,
            precompile_addr,
            addr_from_index(1),
            encode_with_selector(selector_u32("transfer(bytes32)"), (destination_raw,)),
            evm_apparent_value_from_substrate(amount),
        );
        let precompile_result =
            result.expect("expected precompile transfer call to be routed to a precompile");
        let failure = precompile_result
            .expect_err("expected transaction extension rejection on precompile dispatch");
        let message = match failure {
            PrecompileFailure::Error {
                exit_status: ExitError::Other(message),
            } => message,
            other => panic!("unexpected precompile failure: {other:?}"),
        };
        assert!(
            message.contains("dispatch execution failed: ColdkeySwapAnnounced"),
            "unexpected precompile failure: {message}"
        );

        let source_balance_after =
            pallet_balances::Pallet::<Runtime>::free_balance(&dispatch_account);
        let destination_balance_after =
            pallet_balances::Pallet::<Runtime>::free_balance(&destination_account);
        assert_eq!(source_balance_after, source_balance_before);
        assert_eq!(destination_balance_after, destination_balance_before);
    });
}

#[test]
fn proxy_precompile_rejects_qubitum_call_bytes() {
    new_test_ext().execute_with(|| {
        let precompiles = Precompiles::<Runtime>::new();
        let precompile_addr = addr_from_index(ProxyPrecompile::<Runtime>::INDEX);
        let result = execute_precompile(
            &precompiles,
            precompile_addr,
            addr_from_index(1),
            encode_with_selector(
                selector_u32("proxyCall(bytes32,uint8[],uint8[])"),
                (
                    H256::repeat_byte(2),
                    Vec::<u8>::new(),
                    qubitum_create_subnet_call().encode(),
                ),
            ),
            U256::zero(),
        )
        .expect("expected proxy call to be routed to the proxy precompile");

        let failure = result.expect_err("expected proxy precompile private-call rejection");
        let message = match failure {
            PrecompileFailure::Error {
                exit_status: ExitError::Other(message),
            } => message,
            other => panic!("unexpected precompile failure: {other:?}"),
        };
        assert!(
            message.contains("Proxy precompile cannot dispatch private runtime call"),
            "unexpected precompile failure: {message}"
        );
    });
}

#[test]
fn proxy_precompile_rejects_runtime_call_prefix_with_trailing_bytes() {
    new_test_ext().execute_with(|| {
        let precompiles = Precompiles::<Runtime>::new();
        let precompile_addr = addr_from_index(ProxyPrecompile::<Runtime>::INDEX);
        let mut call = RuntimeCall::System(frame_system::Call::remark {
            remark: vec![1, 2, 3],
        })
        .encode();
        call.extend_from_slice(&[0xA5, 0x5A]);

        let result = execute_precompile(
            &precompiles,
            precompile_addr,
            addr_from_index(1),
            encode_with_selector(
                selector_u32("proxyCall(bytes32,uint8[],uint8[])"),
                (H256::repeat_byte(2), Vec::<u8>::new(), call),
            ),
            U256::zero(),
        )
        .expect("expected proxy call to be routed to the proxy precompile");

        let failure =
            result.expect_err("expected strict SCALE call decoding to reject trailing bytes");
        let message = match failure {
            PrecompileFailure::Error {
                exit_status: ExitError::Other(message),
            } => message,
            other => panic!("unexpected precompile failure: {other:?}"),
        };
        assert!(
            message.contains("The raw call data not correctly encoded"),
            "unexpected precompile failure: {message}"
        );
    });
}

#[test]
fn proxy_precompile_rejects_qubitum_call_prefix_with_trailing_bytes() {
    new_test_ext().execute_with(|| {
        let precompiles = Precompiles::<Runtime>::new();
        let precompile_addr = addr_from_index(ProxyPrecompile::<Runtime>::INDEX);
        let mut call = qubitum_create_subnet_call().encode();
        call.extend_from_slice(&[0xA5, 0x5A]);

        let result = execute_precompile(
            &precompiles,
            precompile_addr,
            addr_from_index(1),
            encode_with_selector(
                selector_u32("proxyCall(bytes32,uint8[],uint8[])"),
                (H256::repeat_byte(2), Vec::<u8>::new(), call),
            ),
            U256::zero(),
        )
        .expect("expected proxy call to be routed to the proxy precompile");

        let failure =
            result.expect_err("expected strict SCALE call decoding to reject trailing bytes");
        let message = match failure {
            PrecompileFailure::Error {
                exit_status: ExitError::Other(message),
            } => message,
            other => panic!("unexpected precompile failure: {other:?}"),
        };
        assert!(
            message.contains("The raw call data not correctly encoded"),
            "unexpected precompile failure: {message}"
        );
    });
}

#[test]
fn contract_call_filter_rejects_proxy_wrapped_qubitum() {
    let real: AccountId = [2u8; 32].into();
    let private_proxy_call = RuntimeCall::Proxy(pallet_subtensor_proxy::Call::proxy {
        real: real.into(),
        force_proxy_type: None,
        call: Box::new(qubitum_create_subnet_call()),
    });
    assert!(!ContractCallFilter::contains(&private_proxy_call));

    let safe_proxy_call = RuntimeCall::Proxy(pallet_subtensor_proxy::Call::proxy {
        real: AccountId::from([3u8; 32]).into(),
        force_proxy_type: None,
        call: Box::new(RuntimeCall::System(frame_system::Call::remark {
            remark: vec![1],
        })),
    });
    assert!(ContractCallFilter::contains(&safe_proxy_call));
}
