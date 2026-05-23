#![cfg_attr(not(feature = "std"), no_std)]

use pallet_qubitum::{
    ChainAccounting, ChainProtocolParams, ChainPublicIdentity, ChainPublicInferenceRequest,
    ChainPublicMiner, ChainPublicProofRecord, ChainPublicSubnet, ChainPublicValidator,
    ChainRequestStatusCounts, ChainRouteAvailability,
};
use qubitum_protocol::{MinerId, RequestId, SubnetId, ValidatorId};
use subtensor_runtime_common::TaoBalance;

sp_api::decl_runtime_apis! {
    pub trait QubitumRuntimeApi {
        fn qubitum_subnet(subnet_id: SubnetId) -> Option<ChainPublicSubnet>;
        fn qubitum_miner(miner_id: MinerId) -> Option<ChainPublicMiner>;
        fn qubitum_validator(validator_id: ValidatorId) -> Option<ChainPublicValidator>;
        fn qubitum_miner_identity(miner_id: MinerId) -> Option<ChainPublicIdentity>;
        fn qubitum_validator_identity(validator_id: ValidatorId) -> Option<ChainPublicIdentity>;
        fn qubitum_inference_request(request_id: RequestId) -> Option<ChainPublicInferenceRequest>;
        fn qubitum_proof_record(request_id: RequestId) -> Option<ChainPublicProofRecord>;
        fn qubitum_next_route_availability(subnet_id: SubnetId) -> ChainRouteAvailability;
        fn qubitum_next_request_id() -> RequestId;
        fn qubitum_counts() -> (SubnetId, MinerId, ValidatorId);
        fn qubitum_total_burned() -> TaoBalance;
        fn qubitum_accounting() -> ChainAccounting<TaoBalance>;
        fn qubitum_protocol_params() -> ChainProtocolParams<TaoBalance>;
        fn qubitum_request_status_counts() -> ChainRequestStatusCounts;
    }
}
