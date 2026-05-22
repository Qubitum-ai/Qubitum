#![cfg_attr(not(feature = "std"), no_std)]

use pallet_qubitum::{
    ChainAccounting, ChainAssignment, ChainIdentityCommitments, ChainMiner, ChainProtocolParams,
    ChainPublicInferenceRequest, ChainPublicProofRecord, ChainRequestStatusCounts, ChainSubnet,
    ChainValidator,
};
use qubitum_protocol::{MinerId, RequestId, SignatureBundle, SubnetId, ValidatorId};
use sp_runtime::AccountId32;
use subtensor_runtime_common::TaoBalance;

sp_api::decl_runtime_apis! {
    pub trait QubitumRuntimeApi {
        fn qubitum_subnet(subnet_id: SubnetId) -> Option<ChainSubnet<AccountId32, TaoBalance>>;
        fn qubitum_miner(miner_id: MinerId) -> Option<ChainMiner<AccountId32, TaoBalance>>;
        fn qubitum_validator(validator_id: ValidatorId) -> Option<ChainValidator<AccountId32, TaoBalance>>;
        fn qubitum_miner_identity_commitments(miner_id: MinerId) -> Option<ChainIdentityCommitments>;
        fn qubitum_miner_identity_signature_bundle(miner_id: MinerId) -> Option<SignatureBundle>;
        fn qubitum_validator_identity_commitments(validator_id: ValidatorId) -> Option<ChainIdentityCommitments>;
        fn qubitum_validator_identity_signature_bundle(validator_id: ValidatorId) -> Option<SignatureBundle>;
        fn qubitum_inference_request(request_id: RequestId) -> Option<ChainPublicInferenceRequest>;
        fn qubitum_proof_record(request_id: RequestId) -> Option<ChainPublicProofRecord>;
        fn qubitum_route_assignment(subnet_id: SubnetId, request_id: RequestId) -> Option<ChainAssignment>;
        fn qubitum_next_route_assignment(subnet_id: SubnetId) -> Option<ChainAssignment>;
        fn qubitum_next_request_id() -> RequestId;
        fn qubitum_pending_miner_requests(miner_id: MinerId) -> RequestId;
        fn qubitum_pending_validator_requests(validator_id: ValidatorId) -> RequestId;
        fn qubitum_counts() -> (SubnetId, MinerId, ValidatorId);
        fn qubitum_total_burned() -> TaoBalance;
        fn qubitum_accounting() -> ChainAccounting<TaoBalance>;
        fn qubitum_protocol_params() -> ChainProtocolParams<TaoBalance>;
        fn qubitum_request_status_counts() -> ChainRequestStatusCounts;
    }
}
