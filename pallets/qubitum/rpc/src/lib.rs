//! RPC interface for Qubitum protocol state.

use codec::Encode;
use jsonrpsee::{
    core::RpcResult,
    proc_macros::rpc,
    types::{ErrorObjectOwned, error::ErrorObject},
};
use qubitum_protocol::{MinerId, RequestId, SubnetId, ValidatorId};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;
use subtensor_runtime_common::TaoBalance;

pub use pallet_qubitum_runtime_api::QubitumRuntimeApi;

/// Qubitum RPC methods.
#[rpc(client, server)]
pub trait QubitumRpcApi<BlockHash> {
    #[method(name = "qubitum_getSubnet")]
    fn get_subnet(&self, subnet_id: SubnetId, at: Option<BlockHash>) -> RpcResult<Vec<u8>>;

    #[method(name = "qubitum_getMiner")]
    fn get_miner(&self, miner_id: MinerId, at: Option<BlockHash>) -> RpcResult<Vec<u8>>;

    #[method(name = "qubitum_getValidator")]
    fn get_validator(&self, validator_id: ValidatorId, at: Option<BlockHash>)
    -> RpcResult<Vec<u8>>;

    #[method(name = "qubitum_getMinerIdentityCommitments")]
    fn get_miner_identity_commitments(
        &self,
        miner_id: MinerId,
        at: Option<BlockHash>,
    ) -> RpcResult<Vec<u8>>;

    #[method(name = "qubitum_getMinerIdentitySignatureBundle")]
    fn get_miner_identity_signature_bundle(
        &self,
        miner_id: MinerId,
        at: Option<BlockHash>,
    ) -> RpcResult<Vec<u8>>;

    #[method(name = "qubitum_getValidatorIdentityCommitments")]
    fn get_validator_identity_commitments(
        &self,
        validator_id: ValidatorId,
        at: Option<BlockHash>,
    ) -> RpcResult<Vec<u8>>;

    #[method(name = "qubitum_getValidatorIdentitySignatureBundle")]
    fn get_validator_identity_signature_bundle(
        &self,
        validator_id: ValidatorId,
        at: Option<BlockHash>,
    ) -> RpcResult<Vec<u8>>;

    #[method(name = "qubitum_getInferenceRequest")]
    fn get_inference_request(
        &self,
        request_id: RequestId,
        at: Option<BlockHash>,
    ) -> RpcResult<Vec<u8>>;

    #[method(name = "qubitum_getProofRecord")]
    fn get_proof_record(&self, request_id: RequestId, at: Option<BlockHash>) -> RpcResult<Vec<u8>>;

    #[method(name = "qubitum_routeAssignment")]
    fn route_assignment(
        &self,
        subnet_id: SubnetId,
        request_id: RequestId,
        at: Option<BlockHash>,
    ) -> RpcResult<Vec<u8>>;

    #[method(name = "qubitum_nextRouteAssignment")]
    fn next_route_assignment(
        &self,
        subnet_id: SubnetId,
        at: Option<BlockHash>,
    ) -> RpcResult<Vec<u8>>;

    #[method(name = "qubitum_nextRequestId")]
    fn next_request_id(&self, at: Option<BlockHash>) -> RpcResult<RequestId>;

    #[method(name = "qubitum_getCounts")]
    fn get_counts(&self, at: Option<BlockHash>) -> RpcResult<Vec<u8>>;

    #[method(name = "qubitum_getTotalBurned")]
    fn get_total_burned(&self, at: Option<BlockHash>) -> RpcResult<TaoBalance>;

    #[method(name = "qubitum_getAccounting")]
    fn get_accounting(&self, at: Option<BlockHash>) -> RpcResult<Vec<u8>>;

    #[method(name = "qubitum_getProtocolParams")]
    fn get_protocol_params(&self, at: Option<BlockHash>) -> RpcResult<Vec<u8>>;

    #[method(name = "qubitum_getRequestStatusCounts")]
    fn get_request_status_counts(&self, at: Option<BlockHash>) -> RpcResult<Vec<u8>>;
}

/// Error type of this RPC API.
pub enum Error {
    /// The call to runtime failed.
    RuntimeError(String),
}

impl From<Error> for ErrorObjectOwned {
    fn from(e: Error) -> Self {
        match e {
            Error::RuntimeError(e) => ErrorObject::owned(1, e, None::<()>),
        }
    }
}

/// Qubitum RPC implementation.
pub struct Qubitum<C, Block> {
    client: Arc<C>,
    _marker: std::marker::PhantomData<Block>,
}

impl<C, Block> Qubitum<C, Block> {
    /// Create a new Qubitum RPC helper.
    pub fn new(client: Arc<C>) -> Self {
        Self {
            client,
            _marker: Default::default(),
        }
    }
}

impl<C, Block> Qubitum<C, Block>
where
    Block: BlockT,
    C: HeaderBackend<Block>,
{
    fn at_or_best(&self, at: Option<<Block as BlockT>::Hash>) -> <Block as BlockT>::Hash {
        at.unwrap_or_else(|| self.client.info().best_hash)
    }
}

impl<C, Block> QubitumRpcApiServer<<Block as BlockT>::Hash> for Qubitum<C, Block>
where
    Block: BlockT,
    C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
    C::Api: QubitumRuntimeApi<Block>,
{
    fn get_subnet(
        &self,
        subnet_id: SubnetId,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Vec<u8>> {
        let api = self.client.runtime_api();
        let at = self.at_or_best(at);

        api.qubitum_subnet(at, subnet_id)
            .map(|result| result.encode())
            .map_err(|e| Error::RuntimeError(format!("Unable to get Qubitum subnet: {e:?}")).into())
    }

    fn get_miner(
        &self,
        miner_id: MinerId,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Vec<u8>> {
        let api = self.client.runtime_api();
        let at = self.at_or_best(at);

        api.qubitum_miner(at, miner_id)
            .map(|result| result.encode())
            .map_err(|e| Error::RuntimeError(format!("Unable to get Qubitum miner: {e:?}")).into())
    }

    fn get_validator(
        &self,
        validator_id: ValidatorId,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Vec<u8>> {
        let api = self.client.runtime_api();
        let at = self.at_or_best(at);

        api.qubitum_validator(at, validator_id)
            .map(|result| result.encode())
            .map_err(|e| {
                Error::RuntimeError(format!("Unable to get Qubitum validator: {e:?}")).into()
            })
    }

    fn get_miner_identity_commitments(
        &self,
        miner_id: MinerId,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Vec<u8>> {
        let api = self.client.runtime_api();
        let at = self.at_or_best(at);

        api.qubitum_miner_identity_commitments(at, miner_id)
            .map(|result| result.encode())
            .map_err(|e| {
                Error::RuntimeError(format!(
                    "Unable to get Qubitum miner identity commitments: {e:?}"
                ))
                .into()
            })
    }

    fn get_miner_identity_signature_bundle(
        &self,
        miner_id: MinerId,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Vec<u8>> {
        let api = self.client.runtime_api();
        let at = self.at_or_best(at);

        api.qubitum_miner_identity_signature_bundle(at, miner_id)
            .map(|result| result.encode())
            .map_err(|e| {
                Error::RuntimeError(format!(
                    "Unable to get Qubitum miner identity signature bundle: {e:?}"
                ))
                .into()
            })
    }

    fn get_validator_identity_commitments(
        &self,
        validator_id: ValidatorId,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Vec<u8>> {
        let api = self.client.runtime_api();
        let at = self.at_or_best(at);

        api.qubitum_validator_identity_commitments(at, validator_id)
            .map(|result| result.encode())
            .map_err(|e| {
                Error::RuntimeError(format!(
                    "Unable to get Qubitum validator identity commitments: {e:?}"
                ))
                .into()
            })
    }

    fn get_validator_identity_signature_bundle(
        &self,
        validator_id: ValidatorId,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Vec<u8>> {
        let api = self.client.runtime_api();
        let at = self.at_or_best(at);

        api.qubitum_validator_identity_signature_bundle(at, validator_id)
            .map(|result| result.encode())
            .map_err(|e| {
                Error::RuntimeError(format!(
                    "Unable to get Qubitum validator identity signature bundle: {e:?}"
                ))
                .into()
            })
    }

    fn get_proof_record(
        &self,
        request_id: RequestId,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Vec<u8>> {
        let api = self.client.runtime_api();
        let at = self.at_or_best(at);

        api.qubitum_proof_record(at, request_id)
            .map(|result| result.encode())
            .map_err(|e| {
                Error::RuntimeError(format!("Unable to get Qubitum proof record: {e:?}")).into()
            })
    }

    fn get_inference_request(
        &self,
        request_id: RequestId,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Vec<u8>> {
        let api = self.client.runtime_api();
        let at = self.at_or_best(at);

        api.qubitum_inference_request(at, request_id)
            .map(|result| result.encode())
            .map_err(|e| {
                Error::RuntimeError(format!("Unable to get Qubitum inference request: {e:?}"))
                    .into()
            })
    }

    fn route_assignment(
        &self,
        subnet_id: SubnetId,
        request_id: RequestId,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Vec<u8>> {
        let api = self.client.runtime_api();
        let at = self.at_or_best(at);

        api.qubitum_route_assignment(at, subnet_id, request_id)
            .map(|result| result.encode())
            .map_err(|e| {
                Error::RuntimeError(format!("Unable to route Qubitum assignment: {e:?}")).into()
            })
    }

    fn next_route_assignment(
        &self,
        subnet_id: SubnetId,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Vec<u8>> {
        let api = self.client.runtime_api();
        let at = self.at_or_best(at);

        api.qubitum_next_route_assignment(at, subnet_id)
            .map(|result| result.encode())
            .map_err(|e| {
                Error::RuntimeError(format!("Unable to route next Qubitum assignment: {e:?}"))
                    .into()
            })
    }

    fn next_request_id(&self, at: Option<<Block as BlockT>::Hash>) -> RpcResult<RequestId> {
        let api = self.client.runtime_api();
        let at = self.at_or_best(at);

        api.qubitum_next_request_id(at).map_err(|e| {
            Error::RuntimeError(format!("Unable to get Qubitum next request ID: {e:?}")).into()
        })
    }

    fn get_counts(&self, at: Option<<Block as BlockT>::Hash>) -> RpcResult<Vec<u8>> {
        let api = self.client.runtime_api();
        let at = self.at_or_best(at);

        api.qubitum_counts(at)
            .map(|result| result.encode())
            .map_err(|e| Error::RuntimeError(format!("Unable to get Qubitum counts: {e:?}")).into())
    }

    fn get_total_burned(&self, at: Option<<Block as BlockT>::Hash>) -> RpcResult<TaoBalance> {
        let api = self.client.runtime_api();
        let at = self.at_or_best(at);

        api.qubitum_total_burned(at).map_err(|e| {
            Error::RuntimeError(format!("Unable to get Qubitum total burned: {e:?}")).into()
        })
    }

    fn get_accounting(&self, at: Option<<Block as BlockT>::Hash>) -> RpcResult<Vec<u8>> {
        let api = self.client.runtime_api();
        let at = self.at_or_best(at);

        api.qubitum_accounting(at)
            .map(|result| result.encode())
            .map_err(|e| {
                Error::RuntimeError(format!("Unable to get Qubitum accounting: {e:?}")).into()
            })
    }

    fn get_protocol_params(&self, at: Option<<Block as BlockT>::Hash>) -> RpcResult<Vec<u8>> {
        let api = self.client.runtime_api();
        let at = self.at_or_best(at);

        api.qubitum_protocol_params(at)
            .map(|result| result.encode())
            .map_err(|e| {
                Error::RuntimeError(format!("Unable to get Qubitum protocol params: {e:?}")).into()
            })
    }

    fn get_request_status_counts(&self, at: Option<<Block as BlockT>::Hash>) -> RpcResult<Vec<u8>> {
        let api = self.client.runtime_api();
        let at = self.at_or_best(at);

        api.qubitum_request_status_counts(at)
            .map(|result| result.encode())
            .map_err(|e| {
                Error::RuntimeError(format!(
                    "Unable to get Qubitum request status counts: {e:?}"
                ))
                .into()
            })
    }
}
