#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

mod benchmarking;
pub mod weights;

pub use pallet::*;
pub use weights::WeightInfo;

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{
    dispatch::DispatchResult,
    ensure,
    pallet_prelude::{CheckedAdd, CheckedDiv, CheckedMul, CheckedSub},
    traits::{
        EnsureOrigin,
        tokens::{
            Fortitude, Precision, Preservation, Restriction,
            fungible::{self, InspectHold as _, Mutate as _, MutateHold as _},
        },
    },
};
use qubitum_protocol::{
    BlockNumber, Commitment, InferenceProofSubmission, MinerId, ProofEnvelope, ProofSystem,
    RegistryStatus, RequestId, SignatureBundle, SignatureCommitment, SignatureMode,
    SignaturePolicy, SubnetDomain, SubnetId, ValidatorId, VerificationOutcome,
};
use scale_info::TypeInfo;
use sp_io::hashing::blake2_256;
use sp_runtime::{DispatchError, traits::SaturatedConversion};

type BalanceOf<T> =
    <<T as Config>::Currency as fungible::Inspect<<T as frame_system::Config>::AccountId>>::Balance;

/// Minimal policy passed to the runtime proof verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofVerificationPolicy {
    pub proof_system: ProofSystem,
    pub model_commitment: Commitment,
    pub min_proof_size_bytes: u32,
    pub max_proof_size_bytes: u32,
    pub max_verification_latency_ms: u32,
}

/// Runtime adapter for proof verification.
pub trait VerifyProof {
    fn mode() -> ProofVerifierMode;

    fn verify(
        submission: &InferenceProofSubmission,
        policy: ProofVerificationPolicy,
    ) -> Result<VerificationOutcome, DispatchError>;
}

#[derive(
    Encode,
    Decode,
    DecodeWithMemTracking,
    TypeInfo,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Debug,
    MaxEncodedLen,
)]
pub enum ProofVerifierMode {
    FailClosed,
    ShapeOnly,
    ProductionZk,
    TestOnly,
}

impl ProofVerifierMode {
    pub fn proof_settlement_enabled(self) -> bool {
        !matches!(self, Self::FailClosed)
    }

    pub fn production_zk_verifier(self) -> bool {
        matches!(self, Self::ProductionZk)
    }
}

/// Fail-closed verifier for production runtimes until a concrete zkVM verifier is wired in.
pub struct FailClosedProofVerifier;

impl VerifyProof for FailClosedProofVerifier {
    fn mode() -> ProofVerifierMode {
        ProofVerifierMode::FailClosed
    }

    fn verify(
        _submission: &InferenceProofSubmission,
        _policy: ProofVerificationPolicy,
    ) -> Result<VerificationOutcome, DispatchError> {
        Ok(VerificationOutcome::Error)
    }
}

/// Shape-only verifier used until a concrete zkVM verifier is wired in.
pub struct ShapeProofVerifier;

impl VerifyProof for ShapeProofVerifier {
    fn mode() -> ProofVerifierMode {
        ProofVerifierMode::ShapeOnly
    }

    fn verify(
        submission: &InferenceProofSubmission,
        policy: ProofVerificationPolicy,
    ) -> Result<VerificationOutcome, DispatchError> {
        ensure!(
            submission.input_commitment != [0; 32],
            ShapeVerifierError::MissingCommitment
        );
        ensure!(
            submission.output_commitment != [0; 32],
            ShapeVerifierError::MissingCommitment
        );
        ensure!(
            submission.model_commitment != [0; 32],
            ShapeVerifierError::MissingCommitment
        );
        ensure!(
            submission.proof.proof_commitment != [0; 32],
            ShapeVerifierError::MissingCommitment
        );
        ensure!(
            submission.proof.journal_commitment != [0; 32],
            ShapeVerifierError::MissingCommitment
        );
        ensure!(
            submission.proof.image_id != [0; 32],
            ShapeVerifierError::MissingCommitment
        );
        ensure!(
            submission
                .proof
                .verifier_version
                .supports(submission.proof_system),
            ShapeVerifierError::ProofSystemMismatch
        );
        ensure!(
            submission.proof_system == policy.proof_system,
            ShapeVerifierError::ProofSystemMismatch
        );
        ensure!(
            submission.model_commitment == policy.model_commitment,
            ShapeVerifierError::ModelCommitmentMismatch
        );
        ensure!(
            submission.proof_size_bytes >= policy.min_proof_size_bytes
                && submission.proof_size_bytes <= policy.max_proof_size_bytes,
            ShapeVerifierError::InvalidProofSize
        );
        ensure!(
            submission.verification_latency_ms <= policy.max_verification_latency_ms,
            ShapeVerifierError::LatencyExceeded
        );
        Ok(VerificationOutcome::Valid)
    }
}

#[derive(Debug, Eq, PartialEq)]
enum ShapeVerifierError {
    MissingCommitment,
    ProofSystemMismatch,
    ModelCommitmentMismatch,
    InvalidProofSize,
    LatencyExceeded,
}

impl From<ShapeVerifierError> for DispatchError {
    fn from(error: ShapeVerifierError) -> Self {
        match error {
            ShapeVerifierError::MissingCommitment => DispatchError::Other("MissingCommitment"),
            ShapeVerifierError::ProofSystemMismatch => DispatchError::Other("ProofSystemMismatch"),
            ShapeVerifierError::ModelCommitmentMismatch => {
                DispatchError::Other("ModelCommitmentMismatch")
            }
            ShapeVerifierError::InvalidProofSize => DispatchError::Other("InvalidProofSize"),
            ShapeVerifierError::LatencyExceeded => DispatchError::Other("LatencyExceeded"),
        }
    }
}

#[frame_support::pallet]
#[allow(clippy::expect_used, clippy::large_enum_variant)]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    const LEGACY_ASSIGNMENT_BLINDING: Commitment = [0; 32];
    const LEGACY_TIMING_BLINDING: Commitment = [0; 32];
    const LEGACY_TERMS_BLINDING: Commitment = [0; 32];
    const STORAGE_VERSION: StorageVersion = StorageVersion::new(18);
    #[pallet::pallet]
    #[pallet::without_storage_info]
    #[pallet::storage_version(STORAGE_VERSION)]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        /// Native QBT currency implementation.
        type Currency: fungible::Inspect<Self::AccountId>
            + fungible::Mutate<Self::AccountId>
            + fungible::MutateHold<Self::AccountId, Reason = Self::RuntimeHoldReason>;

        /// Amount burned when creating a subnet.
        #[pallet::constant]
        type SubnetCreationBurn: Get<BalanceOf<Self>>;

        /// Amount burned when registering a miner.
        #[pallet::constant]
        type MinerRegistrationBurn: Get<BalanceOf<Self>>;

        /// Minimum miner bond.
        #[pallet::constant]
        type MinMinerBond: Get<BalanceOf<Self>>;

        /// Maximum miner bond.
        #[pallet::constant]
        type MaxMinerBond: Get<BalanceOf<Self>>;

        /// Maximum active miners indexed per subnet for bounded routing.
        #[pallet::constant]
        type MaxActiveMinersPerSubnet: Get<u32>;

        /// Maximum active validators indexed per subnet for bounded routing.
        #[pallet::constant]
        type MaxActiveValidatorsPerSubnet: Get<u32>;

        /// Minimum validator stake.
        #[pallet::constant]
        type MinValidatorStake: Get<BalanceOf<Self>>;

        /// Minimum invalid-proof slash in basis points.
        #[pallet::constant]
        type MinInvalidProofSlashBps: Get<u16>;

        /// Maximum invalid-proof slash in basis points.
        #[pallet::constant]
        type MaxInvalidProofSlashBps: Get<u16>;

        /// Lower accepted proof commitment size metadata bound.
        #[pallet::constant]
        type MinProofSizeBytes: Get<u32>;

        /// Upper accepted proof commitment size metadata bound.
        #[pallet::constant]
        type MaxProofSizeBytes: Get<u32>;

        /// Maximum accepted verification latency.
        #[pallet::constant]
        type MaxVerificationLatencyMs: Get<u32>;

        /// Maximum accepted age of proof submission metadata.
        #[pallet::constant]
        type MaxProofSubmissionAgeBlocks: Get<BlockNumber>;

        /// Active account-signature policy for the Qubitum roadmap phase.
        #[pallet::constant]
        type SignatureMode: Get<SignatureMode>;

        /// Whether this runtime requires Qubitum dispatchables to arrive via shielded payloads.
        #[pallet::constant]
        type ShieldedCallPayloads: Get<bool>;

        /// Whether the runtime can decrypt and dispatch shielded Qubitum payloads.
        #[pallet::constant]
        type ShieldedCallPayloadExecution: Get<bool>;

        /// Origin that proves a Qubitum dispatchable came from a decrypted shield queue payload.
        type ShieldedOrigin: EnsureOrigin<Self::RuntimeOrigin, Success = Self::AccountId>;

        /// Runtime hold reason adapter.
        type RuntimeHoldReason: From<HoldReason>;

        /// Weight information for dispatchables.
        type WeightInfo: WeightInfo;

        /// Runtime proof verifier adapter.
        type ProofVerifier: VerifyProof;

        /// Account receiving protocol treasury fees from inference settlement.
        type ProtocolTreasury: Get<Self::AccountId>;

        /// Delay before an exiting miner can withdraw remaining bond.
        #[pallet::constant]
        type MinerExitCooldownBlocks: Get<BlockNumber>;

        /// Delay before an exiting validator can withdraw remaining stake.
        #[pallet::constant]
        type ValidatorExitCooldownBlocks: Get<BlockNumber>;

        /// Minimum age of a pending inference request before user cancellation.
        #[pallet::constant]
        type RequestCancelDelayBlocks: Get<BlockNumber>;
    }

    #[pallet::composite_enum]
    pub enum HoldReason {
        /// Funds held as miner bond.
        MinerBond,
        /// Funds held as validator stake.
        ValidatorStake,
        /// Funds held from a user until a valid inference proof settles.
        InferencePayment,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        TypeInfo,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Debug,
        MaxEncodedLen,
    )]
    pub enum InferenceRequestStatus {
        Pending,
        Settled,
        Cancelled,
        Rejected,
        Expired,
    }

    #[subtensor_macros::freeze_struct("9f38ff9338c5277b")]
    #[derive(
        Encode, Decode, DecodeWithMemTracking, TypeInfo, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
    )]
    pub struct ChainSubnet {
        pub id: SubnetId,
        pub owner_commitment: Commitment,
        pub domain: SubnetDomain,
        pub proof_system: ProofSystem,
        pub policy_commitment: Commitment,
        pub active: bool,
    }

    #[subtensor_macros::freeze_struct("8d671dfda8ebbb59")]
    #[derive(Decode)]
    struct ChainSubnetV15<AccountId, Balance> {
        pub id: SubnetId,
        pub owner: AccountId,
        pub domain: SubnetDomain,
        pub proof_system: ProofSystem,
        pub creation_burn: Balance,
        pub min_miner_bond: Balance,
        pub max_miner_bond: Balance,
        pub min_validator_stake: Balance,
        pub active: bool,
    }

    #[subtensor_macros::freeze_struct("dbd9c65e1b03c5c")]
    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        TypeInfo,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Debug,
        MaxEncodedLen,
    )]
    pub struct ChainPublicSubnet {
        pub domain: SubnetDomain,
        pub proof_system: ProofSystem,
        pub active: bool,
    }

    #[subtensor_macros::freeze_struct("49f1e4ad5184763c")]
    #[derive(
        Encode, Decode, DecodeWithMemTracking, TypeInfo, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
    )]
    pub struct ChainMiner {
        pub id: MinerId,
        pub operator_commitment: Commitment,
        pub subnet_id: SubnetId,
        pub model_commitment: Commitment,
        pub proof_system: ProofSystem,
        pub bond_commitment: Commitment,
        pub status: RegistryStatus,
    }

    #[subtensor_macros::freeze_struct("9a0b002c063fb365")]
    #[derive(
        Encode, Decode, DecodeWithMemTracking, TypeInfo, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
    )]
    pub struct ChainValidator {
        pub id: ValidatorId,
        pub operator_commitment: Commitment,
        pub subnet_id: SubnetId,
        pub stake_commitment: Commitment,
        pub status: RegistryStatus,
    }

    #[subtensor_macros::freeze_struct("313fbd89999fd1df")]
    #[derive(Decode)]
    struct ChainMinerV7<AccountId, Balance> {
        pub id: MinerId,
        pub operator: AccountId,
        pub subnet_id: SubnetId,
        pub model_commitment: Commitment,
        pub proof_system: ProofSystem,
        #[allow(dead_code)]
        pub bond: Balance,
        pub status: RegistryStatus,
    }

    #[subtensor_macros::freeze_struct("adeecdad1df61c4c")]
    #[derive(Decode)]
    struct ChainValidatorV7<AccountId, Balance> {
        pub id: ValidatorId,
        pub operator: AccountId,
        pub subnet_id: SubnetId,
        #[allow(dead_code)]
        pub stake: Balance,
        pub status: RegistryStatus,
    }

    #[subtensor_macros::freeze_struct("50df9b4015250dd1")]
    #[derive(Decode)]
    struct ChainMinerV9<Balance> {
        pub id: MinerId,
        pub operator_commitment: Commitment,
        pub subnet_id: SubnetId,
        pub model_commitment: Commitment,
        pub proof_system: ProofSystem,
        #[allow(dead_code)]
        pub bond: Balance,
        pub status: RegistryStatus,
    }

    #[subtensor_macros::freeze_struct("25ed5c51a458ec80")]
    #[derive(Decode)]
    struct ChainValidatorV9<Balance> {
        pub id: ValidatorId,
        pub operator_commitment: Commitment,
        pub subnet_id: SubnetId,
        #[allow(dead_code)]
        pub stake: Balance,
        pub status: RegistryStatus,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        TypeInfo,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Debug,
        MaxEncodedLen,
    )]
    pub enum PublicRegistryStatus {
        Pending,
        Active,
        Exiting,
        Slashed,
        Disabled,
    }

    impl From<RegistryStatus> for PublicRegistryStatus {
        fn from(status: RegistryStatus) -> Self {
            match status {
                RegistryStatus::Pending => Self::Pending,
                RegistryStatus::Active => Self::Active,
                RegistryStatus::Exiting { .. } => Self::Exiting,
                RegistryStatus::Slashed => Self::Slashed,
                RegistryStatus::Disabled => Self::Disabled,
            }
        }
    }

    #[subtensor_macros::freeze_struct("28f3739c73469f96")]
    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        TypeInfo,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Debug,
        MaxEncodedLen,
    )]
    pub struct ChainPublicMiner {
        pub proof_system: ProofSystem,
        pub status: PublicRegistryStatus,
    }

    #[subtensor_macros::freeze_struct("8a5ac4035bcbbfb8")]
    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        TypeInfo,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Debug,
        MaxEncodedLen,
    )]
    pub struct ChainPublicValidator {
        pub status: PublicRegistryStatus,
    }

    #[subtensor_macros::freeze_struct("3c08b8dfc39f1bb")]
    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        TypeInfo,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Debug,
        MaxEncodedLen,
    )]
    pub struct ChainIdentityCommitments {
        pub shielded_identity_commitment: Option<Commitment>,
        pub endpoint_commitment: Option<Commitment>,
    }

    #[subtensor_macros::freeze_struct("117398c21baf8580")]
    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        TypeInfo,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Debug,
        MaxEncodedLen,
    )]
    pub struct ChainPublicIdentity {
        pub has_shielded_identity_commitment: bool,
        pub has_endpoint_commitment: bool,
        pub signature_commitment_recorded: bool,
        pub signature_challenge_bound: bool,
        pub signature_verified: bool,
        pub challenge_available: bool,
    }

    #[subtensor_macros::freeze_struct("2bd7236fc3f429db")]
    #[derive(
        Encode, Decode, DecodeWithMemTracking, TypeInfo, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
    )]
    pub struct ChainProofRecord {
        pub request_id: RequestId,
        pub subnet_id: SubnetId,
        pub assignment_commitment: Commitment,
        pub audit_commitment: Commitment,
        pub proof_system: ProofSystem,
    }

    #[subtensor_macros::freeze_struct("d2bcbb022b6e86ed")]
    #[derive(Decode)]
    struct ChainProofRecordV14 {
        pub request_id: RequestId,
        pub subnet_id: SubnetId,
        pub assignment_commitment: Commitment,
        pub input_commitment: Commitment,
        pub output_commitment: Commitment,
        pub model_commitment: Commitment,
        pub proof: ProofEnvelope,
        pub proof_system: ProofSystem,
        pub proof_size_bytes: u32,
        pub verification_latency_ms: u32,
        pub submitted_at: BlockNumber,
        pub accepted_at: BlockNumber,
    }

    #[subtensor_macros::freeze_struct("5708a0cd1ef8a5d3")]
    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        TypeInfo,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Debug,
        MaxEncodedLen,
    )]
    pub struct ChainPublicProofRecord {
        pub proof_system: ProofSystem,
    }

    #[subtensor_macros::freeze_struct("f4b80dadbfe0a525")]
    #[derive(Decode)]
    struct ChainProofRecordV4 {
        pub request_id: RequestId,
        pub subnet_id: SubnetId,
        pub miner_id: MinerId,
        pub validator_id: ValidatorId,
        pub input_commitment: Commitment,
        pub output_commitment: Commitment,
        pub model_commitment: Commitment,
        pub proof: ProofEnvelope,
        pub proof_system: ProofSystem,
        pub proof_size_bytes: u32,
        pub verification_latency_ms: u32,
        pub submitted_at: BlockNumber,
    }

    #[subtensor_macros::freeze_struct("371f671da9eeb79d")]
    #[derive(Decode)]
    struct ChainProofRecordV11 {
        pub request_id: RequestId,
        pub subnet_id: SubnetId,
        pub miner_id: MinerId,
        pub validator_id: ValidatorId,
        pub input_commitment: Commitment,
        pub output_commitment: Commitment,
        pub model_commitment: Commitment,
        pub proof: ProofEnvelope,
        pub proof_system: ProofSystem,
        pub proof_size_bytes: u32,
        pub verification_latency_ms: u32,
        pub submitted_at: BlockNumber,
        pub accepted_at: BlockNumber,
    }

    #[subtensor_macros::freeze_struct("fee59bccb63bff5f")]
    #[derive(
        Encode, Decode, DecodeWithMemTracking, TypeInfo, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
    )]
    pub struct ChainInferenceRequest {
        pub request_id: RequestId,
        pub user_commitment: Commitment,
        pub subnet_id: SubnetId,
        pub assignment_commitment: Commitment,
        pub input_commitment: Commitment,
        pub terms_commitment: Commitment,
        pub timing_commitment: Commitment,
        pub status: InferenceRequestStatus,
    }

    #[subtensor_macros::freeze_struct("20edf071511dd773")]
    #[derive(Decode)]
    struct ChainInferenceRequestV13<Balance> {
        pub request_id: RequestId,
        pub user_commitment: Commitment,
        pub subnet_id: SubnetId,
        pub assignment_commitment: Commitment,
        pub input_commitment: Commitment,
        pub payment: Balance,
        pub validator_fee_bps: u16,
        pub treasury_fee_bps: u16,
        pub timing_commitment: Commitment,
        pub status: InferenceRequestStatus,
    }

    #[subtensor_macros::freeze_struct("15263af0d647d012")]
    #[derive(Decode)]
    struct ChainInferenceRequestV12<Balance> {
        pub request_id: RequestId,
        pub user_commitment: Commitment,
        pub subnet_id: SubnetId,
        pub assignment_commitment: Commitment,
        pub input_commitment: Commitment,
        pub payment: Balance,
        pub validator_fee_bps: u16,
        pub treasury_fee_bps: u16,
        pub created_at: BlockNumber,
        pub status: InferenceRequestStatus,
    }

    #[subtensor_macros::freeze_struct("2344ffffeccde1d9")]
    #[derive(Decode)]
    struct ChainInferenceRequestV10<Balance> {
        pub request_id: RequestId,
        pub user_commitment: Commitment,
        pub subnet_id: SubnetId,
        pub miner_id: MinerId,
        pub validator_id: ValidatorId,
        pub input_commitment: Commitment,
        pub payment: Balance,
        pub validator_fee_bps: u16,
        pub treasury_fee_bps: u16,
        pub created_at: BlockNumber,
        pub status: InferenceRequestStatus,
    }

    #[subtensor_macros::freeze_struct("7f82ec2cbbc92c4")]
    #[derive(Decode)]
    struct ChainInferenceRequestV8<AccountId, Balance> {
        pub request_id: RequestId,
        pub user: AccountId,
        pub subnet_id: SubnetId,
        pub miner_id: MinerId,
        pub validator_id: ValidatorId,
        pub input_commitment: Commitment,
        pub payment: Balance,
        pub validator_fee_bps: u16,
        pub treasury_fee_bps: u16,
        pub created_at: BlockNumber,
        pub status: InferenceRequestStatus,
    }

    #[subtensor_macros::freeze_struct("195937ebd927e555")]
    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        TypeInfo,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Debug,
        MaxEncodedLen,
    )]
    pub struct ChainPublicInferenceRequest {
        pub status: InferenceRequestStatus,
    }

    #[subtensor_macros::freeze_struct("7e8c89f1f353886b")]
    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        TypeInfo,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Debug,
        MaxEncodedLen,
    )]
    pub(crate) struct ChainAssignment {
        pub request_id: RequestId,
        pub subnet_id: SubnetId,
        pub miner_id: MinerId,
        pub validator_id: ValidatorId,
    }

    #[subtensor_macros::freeze_struct("57f1d16b0be8085f")]
    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        TypeInfo,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Debug,
        MaxEncodedLen,
    )]
    pub struct ChainRouteAvailability {
        pub available: bool,
    }

    #[subtensor_macros::freeze_struct("28c6b8a3fc1babd0")]
    #[derive(
        Encode, Decode, DecodeWithMemTracking, TypeInfo, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
    )]
    pub struct ChainAccounting<Balance> {
        pub total_inference_escrowed: Balance,
        pub total_miner_payouts: Balance,
        pub total_validator_fees: Balance,
        pub total_treasury_fees: Balance,
        pub total_inference_refunded: Balance,
        pub legacy_migration_failures: u32,
    }

    #[subtensor_macros::freeze_struct("969bdd87c0c41b4f")]
    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        TypeInfo,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Debug,
        MaxEncodedLen,
    )]
    pub struct ChainMigrationHealth {
        pub legacy_accounting_failures: u32,
        pub legacy_routing_index_failures: u32,
        pub legacy_capital_record_failures: u32,
    }

    #[subtensor_macros::freeze_struct("2026b8cb5063b8e0")]
    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        TypeInfo,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Debug,
        MaxEncodedLen,
    )]
    pub struct ChainReadinessBlockers {
        pub proof_settlement_disabled: bool,
        pub production_zk_verifier_missing: bool,
        pub committed_request_payloads_missing: bool,
        pub shielded_call_payloads_missing: bool,
        pub shield_submitter_origin_privacy_missing: bool,
        pub shield_key_window_privacy_missing: bool,
        pub private_route_selection_missing: bool,
        pub account_commitment_blinding_missing: bool,
        pub private_routing_indexes_missing: bool,
        pub private_storage_keys_missing: bool,
        pub private_capital_accounting_missing: bool,
        pub private_event_metadata_missing: bool,
        pub signature_mode_not_full_post_quantum: bool,
        pub post_quantum_account_signatures_missing: bool,
        pub post_quantum_signature_crypto_verification_missing: bool,
        pub identity_signature_verification_missing: bool,
        pub external_audit_missing: bool,
    }

    impl ChainReadinessBlockers {
        pub fn privacy_blocked(self) -> bool {
            self.committed_request_payloads_missing
                || self.shielded_call_payloads_missing
                || self.shield_submitter_origin_privacy_missing
                || self.shield_key_window_privacy_missing
                || self.private_route_selection_missing
                || self.account_commitment_blinding_missing
                || self.private_routing_indexes_missing
                || self.private_storage_keys_missing
                || self.private_capital_accounting_missing
                || self.private_event_metadata_missing
        }

        pub fn post_quantum_blocked(self) -> bool {
            self.signature_mode_not_full_post_quantum
                || self.post_quantum_account_signatures_missing
                || self.post_quantum_signature_crypto_verification_missing
                || self.identity_signature_verification_missing
        }

        pub fn production_blocked(self) -> bool {
            self.proof_settlement_disabled
                || self.production_zk_verifier_missing
                || self.privacy_blocked()
                || self.post_quantum_blocked()
                || self.external_audit_missing
        }
    }

    #[subtensor_macros::freeze_struct("79ac04d35ba6d82")]
    #[derive(
        Encode, Decode, DecodeWithMemTracking, TypeInfo, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
    )]
    pub struct ChainProtocolParams<Balance> {
        pub subnet_creation_burn: Balance,
        pub miner_registration_burn: Balance,
        pub min_miner_bond: Balance,
        pub max_miner_bond: Balance,
        pub max_active_miners_per_subnet: u32,
        pub max_active_validators_per_subnet: u32,
        pub min_validator_stake: Balance,
        pub min_invalid_proof_slash_bps: u16,
        pub max_invalid_proof_slash_bps: u16,
        pub min_proof_size_bytes: u32,
        pub max_proof_size_bytes: u32,
        pub max_verification_latency_ms: u32,
        pub max_proof_submission_age_blocks: BlockNumber,
        pub proof_verifier_mode: ProofVerifierMode,
        pub proof_settlement_enabled: bool,
        pub production_zk_verifier: bool,
        pub signature_mode: SignatureMode,
        pub committed_request_payloads: bool,
        pub shielded_call_payloads: bool,
        pub shield_submitter_origin_privacy: bool,
        pub shield_key_window_privacy: bool,
        pub private_route_selection: bool,
        pub account_commitment_blinding: bool,
        pub private_routing_indexes: bool,
        pub private_storage_keys: bool,
        pub private_capital_accounting: bool,
        pub private_event_metadata: bool,
        pub public_event_payloads_redacted: bool,
        pub public_query_ids_redacted: bool,
        pub public_subnet_records_redacted: bool,
        pub route_availability_ids_redacted: bool,
        pub public_route_availability_redacted: bool,
        pub public_accounting_totals_redacted: bool,
        pub public_accounting_migration_failures_redacted: bool,
        pub public_migration_health_redacted: bool,
        pub public_request_status_counts_redacted: bool,
        pub public_registry_records_redacted: bool,
        pub public_request_records_redacted: bool,
        pub public_proof_records_redacted: bool,
        pub public_next_request_id_redacted: bool,
        pub public_registry_counts_redacted: bool,
        pub public_total_burned_redacted: bool,
        pub public_identity_metadata_redacted: bool,
        pub post_quantum_account_signatures: bool,
        pub post_quantum_signature_crypto_verification: bool,
        pub privacy_complete: bool,
        pub post_quantum_complete: bool,
        pub production_ready: bool,
        pub identity_signature_commitment_policy: bool,
        pub identity_signature_challenge_binding: bool,
        pub identity_signature_verification: bool,
        pub readiness_blockers: ChainReadinessBlockers,
        pub miner_exit_cooldown_blocks: BlockNumber,
        pub validator_exit_cooldown_blocks: BlockNumber,
        pub request_cancel_delay_blocks: BlockNumber,
    }

    #[subtensor_macros::freeze_struct("6612a0d4ace7e9f2")]
    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        TypeInfo,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Debug,
        MaxEncodedLen,
    )]
    pub struct ChainRequestStatusCounts {
        pub pending: RequestId,
        pub settled: RequestId,
        pub cancelled: RequestId,
        pub rejected: RequestId,
        pub expired: RequestId,
    }

    #[subtensor_macros::freeze_struct("d9891810f17d85a7")]
    #[derive(
        Encode, Decode, DecodeWithMemTracking, TypeInfo, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
    )]
    pub struct InferenceRequestParams<Balance> {
        pub subnet_id: SubnetId,
        pub miner_id: MinerId,
        pub validator_id: ValidatorId,
        pub input_commitment: Commitment,
        pub assignment_blinding: Commitment,
        pub timing_blinding: Commitment,
        pub terms_blinding: Commitment,
        pub payment: Balance,
        pub validator_fee_bps: u16,
        pub treasury_fee_bps: u16,
    }

    #[subtensor_macros::freeze_struct("4b7cdb8148a0443d")]
    #[derive(
        Encode, Decode, DecodeWithMemTracking, TypeInfo, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
    )]
    pub struct AutoRouteInferenceRequestParams<Balance> {
        pub subnet_id: SubnetId,
        pub input_commitment: Commitment,
        pub assignment_blinding: Commitment,
        pub timing_blinding: Commitment,
        pub terms_blinding: Commitment,
        pub payment: Balance,
        pub validator_fee_bps: u16,
        pub treasury_fee_bps: u16,
    }

    #[subtensor_macros::freeze_struct("8b4a3c45e18803d3")]
    #[derive(
        Encode, Decode, DecodeWithMemTracking, TypeInfo, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
    )]
    pub struct InferenceRequestCommitmentParams<Balance> {
        pub subnet_id: SubnetId,
        pub input_commitment: Commitment,
        pub assignment_commitment: Commitment,
        pub created_at: BlockNumber,
        pub timing_commitment: Commitment,
        pub terms_commitment: Commitment,
        pub payment: Balance,
        pub validator_fee_bps: u16,
        pub treasury_fee_bps: u16,
    }

    #[subtensor_macros::freeze_struct("815023debd8cc288")]
    #[derive(
        Encode, Decode, DecodeWithMemTracking, TypeInfo, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
    )]
    pub struct InferenceRequestTerms<Balance> {
        pub payment: Balance,
        pub validator_fee_bps: u16,
        pub treasury_fee_bps: u16,
    }

    #[subtensor_macros::freeze_struct("c2cee8c4c050003a")]
    #[derive(
        Encode, Decode, DecodeWithMemTracking, TypeInfo, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
    )]
    pub struct InferenceRequestTermsWitness<Balance> {
        pub terms: InferenceRequestTerms<Balance>,
        pub blinding: Commitment,
    }

    #[subtensor_macros::freeze_struct("cdc754b0d0e440cf")]
    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        TypeInfo,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Debug,
        MaxEncodedLen,
    )]
    pub struct InferenceRequestTimingWitness {
        pub created_at: BlockNumber,
        pub blinding: Commitment,
    }

    #[pallet::storage]
    pub type SubnetCount<T: Config> = StorageValue<_, SubnetId, ValueQuery>;

    #[pallet::storage]
    pub type MinerCount<T: Config> = StorageValue<_, MinerId, ValueQuery>;

    #[pallet::storage]
    pub type ValidatorCount<T: Config> = StorageValue<_, ValidatorId, ValueQuery>;

    #[pallet::storage]
    pub type Subnets<T: Config> = StorageMap<_, Twox64Concat, SubnetId, ChainSubnet, OptionQuery>;

    #[pallet::storage]
    pub type Miners<T: Config> = StorageMap<_, Twox64Concat, MinerId, ChainMiner, OptionQuery>;

    #[pallet::storage]
    pub type Validators<T: Config> =
        StorageMap<_, Twox64Concat, ValidatorId, ChainValidator, OptionQuery>;

    #[pallet::storage]
    pub type MinerIdentityCommitments<T: Config> =
        StorageMap<_, Twox64Concat, MinerId, ChainIdentityCommitments, OptionQuery>;

    #[pallet::storage]
    pub type MinerIdentitySignatureBundles<T: Config> =
        StorageMap<_, Twox64Concat, MinerId, SignatureBundle, OptionQuery>;

    #[pallet::storage]
    pub type MinerIdentitySignatureChallenges<T: Config> =
        StorageMap<_, Twox64Concat, MinerId, Commitment, OptionQuery>;

    #[pallet::storage]
    pub type ValidatorIdentityCommitments<T: Config> =
        StorageMap<_, Twox64Concat, ValidatorId, ChainIdentityCommitments, OptionQuery>;

    #[pallet::storage]
    pub type ValidatorIdentitySignatureBundles<T: Config> =
        StorageMap<_, Twox64Concat, ValidatorId, SignatureBundle, OptionQuery>;

    #[pallet::storage]
    pub type ValidatorIdentitySignatureChallenges<T: Config> =
        StorageMap<_, Twox64Concat, ValidatorId, Commitment, OptionQuery>;

    #[pallet::storage]
    pub type ProofRecords<T: Config> =
        StorageMap<_, Twox64Concat, RequestId, ChainProofRecord, OptionQuery>;

    #[pallet::storage]
    pub type InferenceRequests<T: Config> =
        StorageMap<_, Twox64Concat, RequestId, ChainInferenceRequest, OptionQuery>;

    #[pallet::storage]
    pub type RequestCount<T: Config> = StorageValue<_, RequestId, ValueQuery>;

    #[pallet::storage]
    pub type ActiveMinersBySubnet<T: Config> = StorageMap<
        _,
        Twox64Concat,
        SubnetId,
        BoundedVec<MinerId, T::MaxActiveMinersPerSubnet>,
        ValueQuery,
    >;

    #[pallet::storage]
    pub type ActiveValidatorsBySubnet<T: Config> = StorageMap<
        _,
        Twox64Concat,
        SubnetId,
        BoundedVec<ValidatorId, T::MaxActiveValidatorsPerSubnet>,
        ValueQuery,
    >;

    #[pallet::storage]
    pub type MinerLockedBond<T: Config> =
        StorageMap<_, Twox64Concat, MinerId, BalanceOf<T>, OptionQuery>;

    #[pallet::storage]
    pub type ValidatorLockedStake<T: Config> =
        StorageMap<_, Twox64Concat, ValidatorId, BalanceOf<T>, OptionQuery>;

    #[pallet::storage]
    pub type PendingMinerRequests<T: Config> =
        StorageMap<_, Twox64Concat, MinerId, RequestId, ValueQuery>;

    #[pallet::storage]
    pub type PendingValidatorRequests<T: Config> =
        StorageMap<_, Twox64Concat, ValidatorId, RequestId, ValueQuery>;

    #[pallet::storage]
    pub type PendingInferenceRequestCount<T: Config> = StorageValue<_, RequestId, ValueQuery>;

    #[pallet::storage]
    pub type SettledInferenceRequestCount<T: Config> = StorageValue<_, RequestId, ValueQuery>;

    #[pallet::storage]
    pub type CancelledInferenceRequestCount<T: Config> = StorageValue<_, RequestId, ValueQuery>;

    #[pallet::storage]
    pub type RejectedInferenceRequestCount<T: Config> = StorageValue<_, RequestId, ValueQuery>;

    #[pallet::storage]
    pub type ExpiredInferenceRequestCount<T: Config> = StorageValue<_, RequestId, ValueQuery>;

    #[pallet::storage]
    pub type TotalBurned<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

    #[pallet::storage]
    pub type TotalInferenceEscrowed<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

    #[pallet::storage]
    pub type TotalMinerPayouts<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

    #[pallet::storage]
    pub type TotalValidatorFees<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

    #[pallet::storage]
    pub type TotalTreasuryFees<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

    #[pallet::storage]
    pub type TotalInferenceRefunded<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

    #[pallet::storage]
    pub type LegacyAccountingMigrationFailures<T: Config> = StorageValue<_, u32, ValueQuery>;

    #[pallet::storage]
    pub type LegacyRoutingIndexMigrationFailures<T: Config> = StorageValue<_, u32, ValueQuery>;

    #[pallet::storage]
    pub type LegacyCapitalRecordMigrationFailures<T: Config> = StorageValue<_, u32, ValueQuery>;

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_runtime_upgrade() -> Weight {
            let on_chain = Pallet::<T>::on_chain_storage_version();
            if on_chain >= STORAGE_VERSION {
                return T::DbWeight::get().reads(1);
            }

            let weight = Self::migrate_operator_commitments(on_chain)
                .saturating_add(Self::migrate_subnet_policy_commitments(on_chain))
                .saturating_add(Self::migrate_participant_capital_commitments(on_chain))
                .saturating_add(Self::migrate_request_assignment_commitments(on_chain))
                .saturating_add(Self::migrate_request_owner_commitments(on_chain))
                .saturating_add(Self::migrate_request_timing_commitments(on_chain))
                .saturating_add(Self::migrate_request_terms_commitments(on_chain))
                .saturating_add(Self::migrate_identity_signature_challenges(on_chain))
                .saturating_add(Self::rebuild_active_routing_indexes())
                .saturating_add(Self::migrate_participant_capital_records(on_chain))
                .saturating_add(Self::rebuild_request_status_counts())
                .saturating_add(Self::migrate_proof_record_timestamps(on_chain))
                .saturating_add(Self::migrate_proof_record_assignment_commitments(on_chain))
                .saturating_add(Self::migrate_proof_record_audit_commitments(on_chain));
            STORAGE_VERSION.put::<Pallet<T>>();
            weight.saturating_add(T::DbWeight::get().reads_writes(1, 1))
        }

        #[cfg(feature = "try-runtime")]
        fn try_state(_n: BlockNumberFor<T>) -> Result<(), sp_runtime::TryRuntimeError> {
            Self::ensure_active_routing_indexes_match()?;
            Ok(())
        }

        #[cfg(feature = "try-runtime")]
        fn post_upgrade(_state: sp_std::vec::Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
            ensure!(
                Pallet::<T>::on_chain_storage_version() == STORAGE_VERSION,
                "Qubitum storage version did not upgrade"
            );
            Self::ensure_active_routing_indexes_match()?;
            Ok(())
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A subnet was created.
        SubnetCreated,
        /// A miner was registered.
        MinerRegistered,
        /// A miner bond was locked and activated.
        MinerActivated,
        /// A miner started the bond exit cooldown.
        MinerExitStarted,
        /// A miner bond was released after cooldown.
        MinerBondWithdrawn,
        /// A validator was registered and staked.
        ValidatorRegistered,
        /// A validator started the stake exit cooldown.
        ValidatorExitStarted,
        /// A validator stake was released after cooldown.
        ValidatorStakeWithdrawn,
        /// A miner published or cleared shielded identity commitments.
        MinerIdentityCommitmentsUpdated,
        /// A validator published or cleared shielded identity commitments.
        ValidatorIdentityCommitmentsUpdated,
        /// An inference request was opened and escrowed.
        InferenceRequested,
        /// A proof record was accepted.
        ProofAccepted,
        /// An invalid proof challenge was accepted and the request was rejected.
        ProofChallengeAccepted,
        /// Escrowed request payment was settled.
        InferenceSettled,
        /// Pending inference request escrow was released back to the user.
        InferenceCancelled,
        /// Rejected proof released escrow back to the user.
        InferenceRefunded,
        /// Stale pending inference escrow was released back to the user.
        InferenceExpired,
        /// A proof was rejected by the verifier and the miner was slashed.
        ProofRejected,
        /// A miner was slashed.
        MinerSlashed,
        /// A validator was slashed.
        ValidatorSlashed,
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Arithmetic overflow.
        ArithmeticOverflow,
        /// The subnet does not exist.
        UnknownSubnet,
        /// The miner does not exist.
        UnknownMiner,
        /// The validator does not exist.
        UnknownValidator,
        /// The requested proof system does not match subnet policy.
        ProofSystemMismatch,
        /// Proof system is not enabled for production Qubitum subnets.
        UnsupportedProofSystem,
        /// Bond amount is outside subnet bounds.
        InvalidBond,
        /// Validator stake is below subnet minimum.
        InvalidStake,
        /// Miner or validator is not active.
        NotActive,
        /// Miner status does not allow this lifecycle transition.
        InvalidMinerStatus,
        /// Miner exit cooldown has not completed.
        MinerExitUnavailable,
        /// Caller is not the registered operator.
        NotOperator,
        /// Validator status does not allow this lifecycle transition.
        InvalidValidatorStatus,
        /// Validator exit cooldown has not completed.
        ValidatorExitUnavailable,
        /// Caller is not the validator assigned to the proof.
        NotValidatorOperator,
        /// Commitment cannot be all zeros.
        MissingCommitment,
        /// Submitted model commitment does not match the registered miner model.
        ModelCommitmentMismatch,
        /// Proof record already exists for the request.
        DuplicateProof,
        /// Inference request already exists.
        DuplicateRequest,
        /// Request ID must match the chain-owned next request ID.
        InvalidRequestId,
        /// Inference request is missing.
        UnknownRequest,
        /// Inference request has already been settled.
        RequestAlreadySettled,
        /// Inference request is still inside the cancellation delay.
        RequestCancelUnavailable,
        /// Caller does not own the inference request.
        NotRequestOwner,
        /// Proof submission does not match the escrowed request.
        RequestMismatch,
        /// Assigned miner or validator does not belong to the request subnet.
        ParticipantMismatch,
        /// Miner and validator cannot be controlled by the same operator.
        SelfValidation,
        /// No active miner and validator route is available for the subnet.
        NoRouteAvailable,
        /// Submitted assignment does not match the deterministic route.
        AssignmentMismatch,
        /// Miner or validator still has pending assigned inference requests.
        PendingAssignedRequests,
        /// Pending assignment accounting was inconsistent.
        PendingAssignmentUnderflow,
        /// Request status accounting was inconsistent.
        RequestStatusCounterUnderflow,
        /// Subnet has reached the active miner routing index bound.
        TooManyActiveMiners,
        /// Subnet has reached the active validator routing index bound.
        TooManyActiveValidators,
        /// Inference payment must be greater than zero.
        InvalidPayment,
        /// Validator and treasury fee split is invalid.
        InvalidFeeSplit,
        /// Public request calldata must not include miner or validator assignment IDs.
        RouteAssignmentMustBeHidden,
        /// Committed request payloads are disabled until their openings can be verified pre-state.
        UnsupportedCommittedRequestPayload,
        /// Proof size metadata is outside accepted bounds.
        InvalidProofSize,
        /// Verification latency exceeds policy.
        LatencyExceeded,
        /// Proof submission timestamp is ahead of the current block.
        ProofSubmittedFromFuture,
        /// Proof submission timestamp is older than the accepted age window.
        ProofSubmissionExpired,
        /// Proof journal commitment does not bind the submitted transcript.
        ProofTranscriptMismatch,
        /// Challenge evidence verified as valid, so it cannot slash the miner.
        ChallengeProofValid,
        /// Slash percentage is outside accepted bounds.
        InvalidSlashPercent,
        /// Signature commitments do not satisfy the active post-quantum migration policy.
        InvalidSignatureBundle,
        /// Participant has not published the signature bundle required for active routing.
        MissingSignatureBundle,
        /// Participant capital accounting is missing for this registry record.
        MissingCapitalRecord,
        /// Proof verifier reported an internal error.
        VerifierError,
        /// Public Qubitum dispatchables are disabled when shielded payload mode is enabled.
        PublicCallPayloadDisallowed,
    }

    #[allow(clippy::large_enum_variant)]
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Create a permissionless Qubitum subnet by burning QBT.
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::create_subnet())]
        #[frame_support::transactional]
        pub fn create_subnet(
            origin: OriginFor<T>,
            domain: SubnetDomain,
            proof_system: ProofSystem,
        ) -> DispatchResult {
            let owner = Self::ensure_payload_signer(origin)?;
            Self::ensure_supported_proof_system(proof_system)?;
            Self::burn_free(&owner, T::SubnetCreationBurn::get())?;

            let subnet_id = Self::next_subnet_id()?;
            let subnet = ChainSubnet {
                id: subnet_id,
                owner_commitment: Self::subnet_owner_commitment(&owner),
                domain,
                proof_system,
                policy_commitment: Self::subnet_policy_commitment(subnet_id, domain, proof_system),
                active: true,
            };

            Subnets::<T>::insert(subnet_id, subnet);
            Self::deposit_event(Event::SubnetCreated);
            Ok(())
        }

        /// Register a miner by burning QBT and committing to a model.
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::register_miner())]
        #[frame_support::transactional]
        pub fn register_miner(
            origin: OriginFor<T>,
            subnet_id: SubnetId,
            model_commitment: Commitment,
            proof_system: ProofSystem,
        ) -> DispatchResult {
            let operator = Self::ensure_payload_signer(origin)?;
            ensure_commitment::<T>(model_commitment)?;
            Self::ensure_supported_proof_system(proof_system)?;
            let subnet = Subnets::<T>::get(subnet_id).ok_or(Error::<T>::UnknownSubnet)?;
            ensure!(
                subnet.proof_system == proof_system,
                Error::<T>::ProofSystemMismatch
            );

            Self::burn_free(&operator, T::MinerRegistrationBurn::get())?;
            let miner_id = Self::next_miner_id()?;
            let operator_commitment = Self::operator_commitment(&operator);
            let status = RegistryStatus::Pending;
            let miner = ChainMiner {
                id: miner_id,
                operator_commitment,
                subnet_id,
                model_commitment,
                proof_system,
                bond_commitment: Self::miner_bond_commitment(miner_id, operator_commitment, status),
                status,
            };

            Miners::<T>::insert(miner_id, miner);
            Self::deposit_event(Event::MinerRegistered);
            Ok(())
        }

        /// Lock a miner bond and activate the miner.
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::activate_miner())]
        #[frame_support::transactional]
        pub fn activate_miner(
            origin: OriginFor<T>,
            miner_id: MinerId,
            bond: BalanceOf<T>,
        ) -> DispatchResult {
            let operator = Self::ensure_payload_signer(origin)?;
            Miners::<T>::try_mutate(miner_id, |maybe_miner| -> DispatchResult {
                let miner = maybe_miner.as_mut().ok_or(Error::<T>::UnknownMiner)?;
                Self::ensure_miner_operator(miner, &operator)?;
                ensure!(
                    miner.status == RegistryStatus::Pending,
                    Error::<T>::InvalidMinerStatus
                );
                ensure!(
                    Subnets::<T>::contains_key(miner.subnet_id),
                    Error::<T>::UnknownSubnet
                );
                ensure!(
                    bond >= T::MinMinerBond::get() && bond <= T::MaxMinerBond::get(),
                    Error::<T>::InvalidBond
                );
                Self::ensure_miner_signature_bundle_bound(miner_id, miner)?;

                T::Currency::hold(&HoldReason::MinerBond.into(), &operator, bond)?;
                Self::insert_active_miner(miner.subnet_id, miner_id)?;
                MinerLockedBond::<T>::insert(miner_id, bond);
                miner.status = RegistryStatus::Active;
                miner.bond_commitment =
                    Self::miner_bond_commitment(miner_id, miner.operator_commitment, miner.status);
                Ok(())
            })?;

            Self::deposit_event(Event::MinerActivated);
            Ok(())
        }

        /// Register and stake a validator for a subnet.
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::register_validator())]
        #[frame_support::transactional]
        pub fn register_validator(
            origin: OriginFor<T>,
            subnet_id: SubnetId,
            stake: BalanceOf<T>,
        ) -> DispatchResult {
            let operator = Self::ensure_payload_signer(origin)?;
            ensure!(
                Subnets::<T>::contains_key(subnet_id),
                Error::<T>::UnknownSubnet
            );
            ensure!(
                stake >= T::MinValidatorStake::get(),
                Error::<T>::InvalidStake
            );
            ensure!(
                (ActiveValidatorsBySubnet::<T>::get(subnet_id).len() as u32)
                    < T::MaxActiveValidatorsPerSubnet::get(),
                Error::<T>::TooManyActiveValidators
            );
            T::Currency::hold(&HoldReason::ValidatorStake.into(), &operator, stake)?;

            let validator_id = Self::next_validator_id()?;
            let operator_commitment = Self::operator_commitment(&operator);
            let status = RegistryStatus::Pending;
            let validator = ChainValidator {
                id: validator_id,
                operator_commitment,
                subnet_id,
                stake_commitment: Self::validator_stake_commitment(
                    validator_id,
                    operator_commitment,
                    status,
                ),
                status,
            };

            Validators::<T>::insert(validator_id, validator);
            ValidatorLockedStake::<T>::insert(validator_id, stake);
            Self::deposit_event(Event::ValidatorRegistered);
            Ok(())
        }

        /// Submit a proof record after validator verification.
        #[pallet::call_index(4)]
        #[pallet::weight(T::WeightInfo::submit_proof())]
        #[frame_support::transactional]
        pub fn submit_proof(
            origin: OriginFor<T>,
            submission: InferenceProofSubmission,
            request_user: T::AccountId,
            miner_operator: T::AccountId,
            assignment_blinding: Commitment,
            terms_witness: InferenceRequestTermsWitness<BalanceOf<T>>,
        ) -> DispatchResult {
            let validator_operator = Self::ensure_payload_signer(origin)?;
            let policy = Self::validate_submission(
                &submission,
                &validator_operator,
                &miner_operator,
                assignment_blinding,
            )?;

            match T::ProofVerifier::verify(&submission, policy)? {
                VerificationOutcome::Valid => {}
                VerificationOutcome::Invalid { slash_bps } => {
                    Self::ensure_rejected_request_refundable(
                        &submission,
                        &request_user,
                        assignment_blinding,
                        &terms_witness,
                    )?;
                    Self::slash_miner_bond(submission.miner_id, &miner_operator, slash_bps)?;
                    Self::deposit_event(Event::MinerSlashed);
                    Self::slash_validator_stake(
                        submission.validator_id,
                        &validator_operator,
                        slash_bps,
                    )?;
                    Self::deposit_event(Event::ValidatorSlashed);
                    Self::refund_rejected_request(
                        &submission,
                        &request_user,
                        assignment_blinding,
                        &terms_witness,
                    )?;
                    Self::deposit_event(Event::ProofRejected);
                    Self::deposit_event(Event::InferenceRefunded);
                    return Ok(());
                }
                VerificationOutcome::Error => return Err(Error::<T>::VerifierError.into()),
            }

            let assignment_commitment =
                Self::submission_assignment_commitment(&submission, assignment_blinding)?;
            let audit_commitment = Self::proof_audit_commitment_for_assignment(
                &submission,
                Self::current_block(),
                assignment_commitment,
            );
            Self::settle_request_payment(
                &submission,
                &request_user,
                &miner_operator,
                &validator_operator,
                assignment_blinding,
                &terms_witness,
            )?;
            ProofRecords::<T>::insert(
                submission.request_id,
                ChainProofRecord {
                    request_id: submission.request_id,
                    subnet_id: submission.subnet_id,
                    assignment_commitment,
                    audit_commitment,
                    proof_system: submission.proof_system,
                },
            );

            Self::deposit_event(Event::ProofAccepted);
            Self::deposit_event(Event::InferenceSettled);
            Ok(())
        }

        /// Challenge an invalid miner proof without relying on validator self-incrimination.
        #[pallet::call_index(16)]
        #[pallet::weight(T::WeightInfo::challenge_proof())]
        #[frame_support::transactional]
        pub fn challenge_proof(
            origin: OriginFor<T>,
            submission: InferenceProofSubmission,
            request_user: T::AccountId,
            miner_operator: T::AccountId,
            assignment_blinding: Commitment,
            terms_witness: InferenceRequestTermsWitness<BalanceOf<T>>,
        ) -> DispatchResult {
            let _challenger = Self::ensure_payload_signer(origin)?;
            let policy = Self::validate_challenge_submission(
                &submission,
                &miner_operator,
                assignment_blinding,
            )?;

            match T::ProofVerifier::verify(&submission, policy)? {
                VerificationOutcome::Invalid { slash_bps } => {
                    Self::ensure_rejected_request_refundable(
                        &submission,
                        &request_user,
                        assignment_blinding,
                        &terms_witness,
                    )?;
                    Self::slash_miner_bond(submission.miner_id, &miner_operator, slash_bps)?;
                    Self::deposit_event(Event::MinerSlashed);
                    Self::refund_rejected_request(
                        &submission,
                        &request_user,
                        assignment_blinding,
                        &terms_witness,
                    )?;
                    Self::deposit_event(Event::ProofRejected);
                    Self::deposit_event(Event::ProofChallengeAccepted);
                    Self::deposit_event(Event::InferenceRefunded);
                    Ok(())
                }
                VerificationOutcome::Valid => Err(Error::<T>::ChallengeProofValid.into()),
                VerificationOutcome::Error => Err(Error::<T>::VerifierError.into()),
            }
        }

        /// Slash a miner bond for invalid proof behavior.
        #[pallet::call_index(5)]
        #[pallet::weight(T::WeightInfo::slash_miner())]
        #[frame_support::transactional]
        pub fn slash_miner(
            origin: OriginFor<T>,
            miner_id: MinerId,
            operator: T::AccountId,
            slash_bps: u16,
        ) -> DispatchResult {
            Self::ensure_public_call_payload_allowed()?;
            ensure_root(origin)?;
            ensure!(
                slash_bps >= T::MinInvalidProofSlashBps::get()
                    && slash_bps <= T::MaxInvalidProofSlashBps::get(),
                Error::<T>::InvalidSlashPercent
            );
            ensure!(
                PendingMinerRequests::<T>::get(miner_id) == 0,
                Error::<T>::PendingAssignedRequests
            );

            Self::slash_miner_bond(miner_id, &operator, slash_bps)?;
            Self::deposit_event(Event::MinerSlashed);
            Ok(())
        }

        /// Open an inference request and escrow QBT until a valid proof settles it.
        #[pallet::call_index(6)]
        #[pallet::weight(T::WeightInfo::request_inference())]
        #[frame_support::transactional]
        pub fn request_inference(
            origin: OriginFor<T>,
            request_id: RequestId,
            params: InferenceRequestParams<BalanceOf<T>>,
        ) -> DispatchResult {
            let user = Self::ensure_payload_signer(origin)?;
            ensure!(
                params.miner_id == 0 && params.validator_id == 0,
                Error::<T>::RouteAssignmentMustBeHidden
            );
            Self::ensure_inference_request_openable(
                request_id,
                params.subnet_id,
                params.input_commitment,
                params.assignment_blinding,
                params.timing_blinding,
                params.terms_blinding,
                params.payment,
                params.validator_fee_bps,
                params.treasury_fee_bps,
            )?;
            Self::ensure_request_id_can_advance(request_id)?;
            let assignment = Self::route_assignment(params.subnet_id, request_id)
                .ok_or(Error::<T>::NoRouteAvailable)?;
            Self::open_inference_request(
                user,
                request_id,
                params.subnet_id,
                assignment.miner_id,
                assignment.validator_id,
                params.input_commitment,
                params.assignment_blinding,
                params.timing_blinding,
                params.terms_blinding,
                params.payment,
                params.validator_fee_bps,
                params.treasury_fee_bps,
            )
        }

        /// Open an inference request with chain-owned miner and validator assignment.
        #[pallet::call_index(17)]
        #[pallet::weight(T::WeightInfo::request_inference())]
        #[frame_support::transactional]
        pub fn request_inference_auto_route(
            origin: OriginFor<T>,
            request_id: RequestId,
            params: AutoRouteInferenceRequestParams<BalanceOf<T>>,
        ) -> DispatchResult {
            let user = Self::ensure_payload_signer(origin)?;
            Self::ensure_inference_request_openable(
                request_id,
                params.subnet_id,
                params.input_commitment,
                params.assignment_blinding,
                params.timing_blinding,
                params.terms_blinding,
                params.payment,
                params.validator_fee_bps,
                params.treasury_fee_bps,
            )?;
            Self::ensure_request_id_can_advance(request_id)?;
            let assignment = Self::route_assignment(params.subnet_id, request_id)
                .ok_or(Error::<T>::NoRouteAvailable)?;
            Self::open_inference_request(
                user,
                request_id,
                params.subnet_id,
                assignment.miner_id,
                assignment.validator_id,
                params.input_commitment,
                params.assignment_blinding,
                params.timing_blinding,
                params.terms_blinding,
                params.payment,
                params.validator_fee_bps,
                params.treasury_fee_bps,
            )
        }

        /// Open an inference request using precommitted private assignment and terms witnesses.
        #[pallet::call_index(18)]
        #[pallet::weight(T::WeightInfo::request_inference())]
        #[frame_support::transactional]
        pub fn request_inference_commitments(
            origin: OriginFor<T>,
            request_id: RequestId,
            params: InferenceRequestCommitmentParams<BalanceOf<T>>,
        ) -> DispatchResult {
            let _user = Self::ensure_payload_signer(origin)?;
            let _ = (request_id, params);
            Err(Error::<T>::UnsupportedCommittedRequestPayload.into())
        }

        /// Cancel a pending inference request and release escrowed QBT.
        #[pallet::call_index(7)]
        #[pallet::weight(T::WeightInfo::cancel_inference())]
        #[frame_support::transactional]
        pub fn cancel_inference(
            origin: OriginFor<T>,
            request_id: RequestId,
            miner_id: MinerId,
            validator_id: ValidatorId,
            assignment_blinding: Commitment,
            timing_witness: InferenceRequestTimingWitness,
            terms_witness: InferenceRequestTermsWitness<BalanceOf<T>>,
        ) -> DispatchResult {
            let user = Self::ensure_payload_signer(origin)?;
            let payment = InferenceRequests::<T>::try_mutate(
                request_id,
                |maybe_request| -> Result<BalanceOf<T>, DispatchError> {
                    let request = maybe_request.as_mut().ok_or(Error::<T>::UnknownRequest)?;
                    Self::ensure_request_user(request, &user)?;
                    Self::ensure_request_assignment_witness(
                        request,
                        miner_id,
                        validator_id,
                        assignment_blinding,
                    )?;
                    Self::ensure_request_timing_witness(request, timing_witness)?;
                    Self::ensure_request_terms_witness(request, &terms_witness)?;
                    ensure!(
                        request.status == InferenceRequestStatus::Pending,
                        Error::<T>::RequestAlreadySettled
                    );
                    let cancel_available_at = timing_witness
                        .created_at
                        .checked_add(T::RequestCancelDelayBlocks::get())
                        .ok_or(Error::<T>::ArithmeticOverflow)?;
                    ensure!(
                        Self::current_block() >= cancel_available_at,
                        Error::<T>::RequestCancelUnavailable
                    );
                    Self::ensure_inference_refund_can_record(terms_witness.terms.payment)?;
                    T::Currency::release(
                        &HoldReason::InferencePayment.into(),
                        &user,
                        terms_witness.terms.payment,
                        Precision::Exact,
                    )?;
                    request.status = InferenceRequestStatus::Cancelled;
                    Ok(terms_witness.terms.payment)
                },
            )?;
            Self::decrement_pending_assignment(miner_id, validator_id)?;
            Self::transition_request_status(
                InferenceRequestStatus::Pending,
                InferenceRequestStatus::Cancelled,
            )?;
            Self::record_inference_refund(payment)?;

            Self::deposit_event(Event::InferenceCancelled);
            Ok(())
        }

        /// Start a miner exit cooldown before remaining bond can be withdrawn.
        #[pallet::call_index(8)]
        #[pallet::weight(T::WeightInfo::deactivate_miner())]
        pub fn deactivate_miner(origin: OriginFor<T>, miner_id: MinerId) -> DispatchResult {
            let operator = Self::ensure_payload_signer(origin)?;
            let exit_available_at = Self::current_block()
                .checked_add(T::MinerExitCooldownBlocks::get())
                .ok_or(Error::<T>::ArithmeticOverflow)?;

            Miners::<T>::try_mutate(miner_id, |maybe_miner| -> DispatchResult {
                let miner = maybe_miner.as_mut().ok_or(Error::<T>::UnknownMiner)?;
                Self::ensure_miner_operator(miner, &operator)?;
                ensure!(
                    matches!(
                        miner.status,
                        RegistryStatus::Active | RegistryStatus::Slashed
                    ),
                    Error::<T>::InvalidMinerStatus
                );
                ensure!(
                    PendingMinerRequests::<T>::get(miner_id) == 0,
                    Error::<T>::PendingAssignedRequests
                );
                Self::remove_active_miner(miner.subnet_id, miner_id);
                miner.status = RegistryStatus::Exiting { exit_available_at };
                miner.bond_commitment =
                    Self::miner_bond_commitment(miner_id, miner.operator_commitment, miner.status);
                Ok(())
            })?;

            Self::deposit_event(Event::MinerExitStarted);
            Ok(())
        }

        /// Withdraw remaining miner bond after the exit cooldown completes.
        #[pallet::call_index(9)]
        #[pallet::weight(T::WeightInfo::withdraw_miner_bond())]
        #[frame_support::transactional]
        pub fn withdraw_miner_bond(origin: OriginFor<T>, miner_id: MinerId) -> DispatchResult {
            let operator = Self::ensure_payload_signer(origin)?;
            Miners::<T>::try_mutate(miner_id, |maybe_miner| -> DispatchResult {
                let miner = maybe_miner.as_mut().ok_or(Error::<T>::UnknownMiner)?;
                Self::ensure_miner_operator(miner, &operator)?;
                let RegistryStatus::Exiting { exit_available_at } = miner.status else {
                    return Err(Error::<T>::InvalidMinerStatus.into());
                };
                ensure!(
                    Self::current_block() >= exit_available_at,
                    Error::<T>::MinerExitUnavailable
                );

                let bond = Self::locked_miner_bond(miner_id, &operator)?;
                if bond != BalanceOf::<T>::default() {
                    T::Currency::release(
                        &HoldReason::MinerBond.into(),
                        &operator,
                        bond,
                        Precision::Exact,
                    )?;
                }
                MinerLockedBond::<T>::remove(miner_id);
                miner.status = RegistryStatus::Disabled;
                miner.bond_commitment =
                    Self::miner_bond_commitment(miner_id, miner.operator_commitment, miner.status);
                Ok(())
            })?;

            Self::deposit_event(Event::MinerBondWithdrawn);
            Ok(())
        }

        /// Start a validator exit cooldown before remaining stake can be withdrawn.
        #[pallet::call_index(10)]
        #[pallet::weight(T::WeightInfo::deactivate_validator())]
        pub fn deactivate_validator(
            origin: OriginFor<T>,
            validator_id: ValidatorId,
        ) -> DispatchResult {
            let operator = Self::ensure_payload_signer(origin)?;
            let exit_available_at = Self::current_block()
                .checked_add(T::ValidatorExitCooldownBlocks::get())
                .ok_or(Error::<T>::ArithmeticOverflow)?;

            Validators::<T>::try_mutate(validator_id, |maybe_validator| -> DispatchResult {
                let validator = maybe_validator
                    .as_mut()
                    .ok_or(Error::<T>::UnknownValidator)?;
                Self::ensure_validator_operator(validator, &operator)?;
                ensure!(
                    matches!(
                        validator.status,
                        RegistryStatus::Pending | RegistryStatus::Active | RegistryStatus::Slashed
                    ),
                    Error::<T>::InvalidValidatorStatus
                );
                ensure!(
                    PendingValidatorRequests::<T>::get(validator_id) == 0,
                    Error::<T>::PendingAssignedRequests
                );
                Self::remove_active_validator(validator.subnet_id, validator_id);
                validator.status = RegistryStatus::Exiting { exit_available_at };
                validator.stake_commitment = Self::validator_stake_commitment(
                    validator_id,
                    validator.operator_commitment,
                    validator.status,
                );
                Ok(())
            })?;

            Self::deposit_event(Event::ValidatorExitStarted);
            Ok(())
        }

        /// Withdraw remaining validator stake after the exit cooldown completes.
        #[pallet::call_index(11)]
        #[pallet::weight(T::WeightInfo::withdraw_validator_stake())]
        #[frame_support::transactional]
        pub fn withdraw_validator_stake(
            origin: OriginFor<T>,
            validator_id: ValidatorId,
        ) -> DispatchResult {
            let operator = Self::ensure_payload_signer(origin)?;
            Validators::<T>::try_mutate(validator_id, |maybe_validator| -> DispatchResult {
                let validator = maybe_validator
                    .as_mut()
                    .ok_or(Error::<T>::UnknownValidator)?;
                Self::ensure_validator_operator(validator, &operator)?;
                let RegistryStatus::Exiting { exit_available_at } = validator.status else {
                    return Err(Error::<T>::InvalidValidatorStatus.into());
                };
                ensure!(
                    Self::current_block() >= exit_available_at,
                    Error::<T>::ValidatorExitUnavailable
                );

                let stake = Self::locked_validator_stake(validator_id, &operator)?;
                if stake != BalanceOf::<T>::default() {
                    T::Currency::release(
                        &HoldReason::ValidatorStake.into(),
                        &operator,
                        stake,
                        Precision::Exact,
                    )?;
                }
                ValidatorLockedStake::<T>::remove(validator_id);
                validator.status = RegistryStatus::Disabled;
                validator.stake_commitment = Self::validator_stake_commitment(
                    validator_id,
                    validator.operator_commitment,
                    validator.status,
                );
                Ok(())
            })?;

            Self::deposit_event(Event::ValidatorStakeWithdrawn);
            Ok(())
        }

        /// Slash a validator stake for invalid verification behavior.
        #[pallet::call_index(12)]
        #[pallet::weight(T::WeightInfo::slash_validator())]
        #[frame_support::transactional]
        pub fn slash_validator(
            origin: OriginFor<T>,
            validator_id: ValidatorId,
            operator: T::AccountId,
            slash_bps: u16,
        ) -> DispatchResult {
            Self::ensure_public_call_payload_allowed()?;
            ensure_root(origin)?;
            ensure!(
                slash_bps >= T::MinInvalidProofSlashBps::get()
                    && slash_bps <= T::MaxInvalidProofSlashBps::get(),
                Error::<T>::InvalidSlashPercent
            );
            ensure!(
                PendingValidatorRequests::<T>::get(validator_id) == 0,
                Error::<T>::PendingAssignedRequests
            );

            Self::slash_validator_stake(validator_id, &operator, slash_bps)?;
            Self::deposit_event(Event::ValidatorSlashed);
            Ok(())
        }

        /// Expire a stale pending inference request and release escrow back to the user.
        #[pallet::call_index(13)]
        #[pallet::weight(T::WeightInfo::expire_inference())]
        #[allow(clippy::too_many_arguments)]
        #[frame_support::transactional]
        pub fn expire_inference(
            origin: OriginFor<T>,
            request_id: RequestId,
            request_user: T::AccountId,
            miner_id: MinerId,
            validator_id: ValidatorId,
            assignment_blinding: Commitment,
            timing_witness: InferenceRequestTimingWitness,
            terms_witness: InferenceRequestTermsWitness<BalanceOf<T>>,
        ) -> DispatchResult {
            let _keeper = Self::ensure_payload_signer(origin)?;
            let payment = InferenceRequests::<T>::try_mutate(
                request_id,
                |maybe_request| -> Result<BalanceOf<T>, DispatchError> {
                    let request = maybe_request.as_mut().ok_or(Error::<T>::UnknownRequest)?;
                    Self::ensure_request_user(request, &request_user)?;
                    Self::ensure_request_assignment_witness(
                        request,
                        miner_id,
                        validator_id,
                        assignment_blinding,
                    )?;
                    Self::ensure_request_timing_witness(request, timing_witness)?;
                    Self::ensure_request_terms_witness(request, &terms_witness)?;
                    ensure!(
                        request.status == InferenceRequestStatus::Pending,
                        Error::<T>::RequestAlreadySettled
                    );
                    let cancel_available_at = timing_witness
                        .created_at
                        .checked_add(T::RequestCancelDelayBlocks::get())
                        .ok_or(Error::<T>::ArithmeticOverflow)?;
                    ensure!(
                        Self::current_block() >= cancel_available_at,
                        Error::<T>::RequestCancelUnavailable
                    );
                    Self::ensure_inference_refund_can_record(terms_witness.terms.payment)?;
                    T::Currency::release(
                        &HoldReason::InferencePayment.into(),
                        &request_user,
                        terms_witness.terms.payment,
                        Precision::Exact,
                    )?;
                    request.status = InferenceRequestStatus::Expired;
                    Ok(terms_witness.terms.payment)
                },
            )?;
            Self::decrement_pending_assignment(miner_id, validator_id)?;
            Self::transition_request_status(
                InferenceRequestStatus::Pending,
                InferenceRequestStatus::Expired,
            )?;
            Self::record_inference_refund(payment)?;

            Self::deposit_event(Event::InferenceExpired);
            Ok(())
        }

        /// Publish or clear commitment-only miner identity metadata.
        #[pallet::call_index(14)]
        #[pallet::weight(T::WeightInfo::set_miner_identity_commitments())]
        #[frame_support::transactional]
        pub fn set_miner_identity_commitments(
            origin: OriginFor<T>,
            miner_id: MinerId,
            shielded_identity_commitment: Option<Commitment>,
            endpoint_commitment: Option<Commitment>,
            signature_bundle: SignatureBundle,
        ) -> DispatchResult {
            let operator = Self::ensure_payload_signer(origin)?;
            let miner = Miners::<T>::get(miner_id).ok_or(Error::<T>::UnknownMiner)?;
            Self::ensure_miner_operator(&miner, &operator)?;
            Self::ensure_optional_commitment(shielded_identity_commitment)?;
            Self::ensure_optional_commitment(endpoint_commitment)?;
            let setting_identity =
                shielded_identity_commitment.is_some() || endpoint_commitment.is_some();
            let indexed_active =
                ActiveMinersBySubnet::<T>::get(miner.subnet_id).contains(&miner_id);
            let should_index =
                setting_identity && miner.status == RegistryStatus::Active && !indexed_active;
            ensure!(
                PendingMinerRequests::<T>::get(miner_id) == 0,
                Error::<T>::PendingAssignedRequests
            );

            if setting_identity {
                let challenge_commitment = Self::miner_identity_signature_challenge(
                    miner_id,
                    miner.operator_commitment,
                    shielded_identity_commitment,
                    endpoint_commitment,
                );
                Self::ensure_signature_bundle_bound_to_challenge(
                    signature_bundle,
                    challenge_commitment,
                )?;
                MinerIdentityCommitments::<T>::insert(
                    miner_id,
                    ChainIdentityCommitments {
                        shielded_identity_commitment,
                        endpoint_commitment,
                    },
                );
                MinerIdentitySignatureBundles::<T>::insert(miner_id, signature_bundle);
                MinerIdentitySignatureChallenges::<T>::insert(miner_id, challenge_commitment);
                if should_index {
                    Self::insert_active_miner(miner.subnet_id, miner_id)?;
                }
            } else {
                if MinerIdentityCommitments::<T>::contains_key(miner_id)
                    || MinerIdentitySignatureBundles::<T>::contains_key(miner_id)
                    || MinerIdentitySignatureChallenges::<T>::contains_key(miner_id)
                {
                    let challenge_commitment = Self::miner_identity_signature_challenge(
                        miner_id,
                        miner.operator_commitment,
                        None,
                        None,
                    );
                    Self::ensure_signature_bundle_bound_to_challenge(
                        signature_bundle,
                        challenge_commitment,
                    )?;
                }
                MinerIdentityCommitments::<T>::remove(miner_id);
                MinerIdentitySignatureBundles::<T>::remove(miner_id);
                MinerIdentitySignatureChallenges::<T>::remove(miner_id);
                if miner.status == RegistryStatus::Active && indexed_active {
                    Self::remove_active_miner(miner.subnet_id, miner_id);
                }
            }

            Self::deposit_event(Event::MinerIdentityCommitmentsUpdated);
            Ok(())
        }

        /// Publish or clear commitment-only validator identity metadata.
        #[pallet::call_index(15)]
        #[pallet::weight(T::WeightInfo::set_validator_identity_commitments())]
        #[frame_support::transactional]
        pub fn set_validator_identity_commitments(
            origin: OriginFor<T>,
            validator_id: ValidatorId,
            shielded_identity_commitment: Option<Commitment>,
            endpoint_commitment: Option<Commitment>,
            signature_bundle: SignatureBundle,
        ) -> DispatchResult {
            let operator = Self::ensure_payload_signer(origin)?;
            let validator =
                Validators::<T>::get(validator_id).ok_or(Error::<T>::UnknownValidator)?;
            Self::ensure_validator_operator(&validator, &operator)?;
            Self::ensure_optional_commitment(shielded_identity_commitment)?;
            Self::ensure_optional_commitment(endpoint_commitment)?;
            let setting_identity =
                shielded_identity_commitment.is_some() || endpoint_commitment.is_some();
            let indexed_active =
                ActiveValidatorsBySubnet::<T>::get(validator.subnet_id).contains(&validator_id);
            ensure!(
                PendingValidatorRequests::<T>::get(validator_id) == 0,
                Error::<T>::PendingAssignedRequests
            );

            if setting_identity {
                let challenge_commitment = Self::validator_identity_signature_challenge(
                    validator_id,
                    validator.operator_commitment,
                    shielded_identity_commitment,
                    endpoint_commitment,
                );
                Self::ensure_signature_bundle_bound_to_challenge(
                    signature_bundle,
                    challenge_commitment,
                )?;
                if validator.status == RegistryStatus::Pending {
                    Self::ensure_validator_locked_stake_record(validator_id)?;
                }
                ValidatorIdentityCommitments::<T>::insert(
                    validator_id,
                    ChainIdentityCommitments {
                        shielded_identity_commitment,
                        endpoint_commitment,
                    },
                );
                ValidatorIdentitySignatureBundles::<T>::insert(validator_id, signature_bundle);
                ValidatorIdentitySignatureChallenges::<T>::insert(
                    validator_id,
                    challenge_commitment,
                );
                Validators::<T>::try_mutate(validator_id, |maybe_validator| -> DispatchResult {
                    let validator = maybe_validator
                        .as_mut()
                        .ok_or(Error::<T>::UnknownValidator)?;
                    ensure!(
                        matches!(
                            validator.status,
                            RegistryStatus::Active | RegistryStatus::Pending
                        ),
                        Error::<T>::InvalidValidatorStatus
                    );
                    if validator.status == RegistryStatus::Pending {
                        validator.status = RegistryStatus::Active;
                    }
                    if !indexed_active {
                        Self::insert_active_validator(validator.subnet_id, validator_id)?;
                    }
                    validator.stake_commitment = Self::validator_stake_commitment(
                        validator_id,
                        validator.operator_commitment,
                        validator.status,
                    );
                    Ok(())
                })?;
            } else {
                if ValidatorIdentityCommitments::<T>::contains_key(validator_id)
                    || ValidatorIdentitySignatureBundles::<T>::contains_key(validator_id)
                    || ValidatorIdentitySignatureChallenges::<T>::contains_key(validator_id)
                {
                    let challenge_commitment = Self::validator_identity_signature_challenge(
                        validator_id,
                        validator.operator_commitment,
                        None,
                        None,
                    );
                    Self::ensure_signature_bundle_bound_to_challenge(
                        signature_bundle,
                        challenge_commitment,
                    )?;
                }
                ValidatorIdentityCommitments::<T>::remove(validator_id);
                ValidatorIdentitySignatureBundles::<T>::remove(validator_id);
                ValidatorIdentitySignatureChallenges::<T>::remove(validator_id);
                if validator.status == RegistryStatus::Active {
                    Validators::<T>::try_mutate(
                        validator_id,
                        |maybe_validator| -> DispatchResult {
                            let validator = maybe_validator
                                .as_mut()
                                .ok_or(Error::<T>::UnknownValidator)?;
                            Self::remove_active_validator(validator.subnet_id, validator_id);
                            validator.status = RegistryStatus::Pending;
                            validator.stake_commitment = Self::validator_stake_commitment(
                                validator_id,
                                validator.operator_commitment,
                                validator.status,
                            );
                            Ok(())
                        },
                    )?;
                }
            }

            Self::deposit_event(Event::ValidatorIdentityCommitmentsUpdated);
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        pub fn accounting() -> ChainAccounting<BalanceOf<T>> {
            ChainAccounting {
                total_inference_escrowed: BalanceOf::<T>::default(),
                total_miner_payouts: BalanceOf::<T>::default(),
                total_validator_fees: BalanceOf::<T>::default(),
                total_treasury_fees: BalanceOf::<T>::default(),
                total_inference_refunded: BalanceOf::<T>::default(),
                legacy_migration_failures: 0,
            }
        }

        #[cfg(any(test, feature = "try-runtime"))]
        pub(crate) fn raw_accounting() -> ChainAccounting<BalanceOf<T>> {
            ChainAccounting {
                total_inference_escrowed: TotalInferenceEscrowed::<T>::get(),
                total_miner_payouts: TotalMinerPayouts::<T>::get(),
                total_validator_fees: TotalValidatorFees::<T>::get(),
                total_treasury_fees: TotalTreasuryFees::<T>::get(),
                total_inference_refunded: TotalInferenceRefunded::<T>::get(),
                legacy_migration_failures: LegacyAccountingMigrationFailures::<T>::get(),
            }
        }

        #[cfg(any(test, feature = "try-runtime"))]
        pub(crate) fn raw_migration_health() -> ChainMigrationHealth {
            ChainMigrationHealth {
                legacy_accounting_failures: LegacyAccountingMigrationFailures::<T>::get(),
                legacy_routing_index_failures: LegacyRoutingIndexMigrationFailures::<T>::get(),
                legacy_capital_record_failures: LegacyCapitalRecordMigrationFailures::<T>::get(),
            }
        }

        pub fn migration_health() -> ChainMigrationHealth {
            ChainMigrationHealth {
                legacy_accounting_failures: 0,
                legacy_routing_index_failures: 0,
                legacy_capital_record_failures: 0,
            }
        }

        pub fn protocol_params() -> ChainProtocolParams<BalanceOf<T>> {
            let proof_verifier_mode = T::ProofVerifier::mode();
            let proof_settlement_enabled = proof_verifier_mode.proof_settlement_enabled();
            let production_zk_verifier = proof_verifier_mode.production_zk_verifier();
            let signature_mode = T::SignatureMode::get();
            let committed_request_payloads = false;
            let shielded_call_payloads = T::ShieldedCallPayloads::get();
            let shielded_call_payload_execution =
                shielded_call_payloads && T::ShieldedCallPayloadExecution::get();
            let shield_submitter_origin_privacy = false;
            let shield_key_window_privacy = false;
            let private_route_selection = false;
            let account_commitment_blinding = false;
            let private_routing_indexes = false;
            let private_storage_keys = false;
            let private_capital_accounting = false;
            let private_event_metadata = false;
            let public_event_payloads_redacted = true;
            let public_query_ids_redacted = true;
            let public_subnet_records_redacted = true;
            let route_availability_ids_redacted = true;
            let public_route_availability_redacted = true;
            let public_accounting_totals_redacted = true;
            let public_accounting_migration_failures_redacted = true;
            let public_migration_health_redacted = true;
            let public_request_status_counts_redacted = true;
            let public_registry_records_redacted = true;
            let public_request_records_redacted = true;
            let public_proof_records_redacted = true;
            let public_next_request_id_redacted = true;
            let public_registry_counts_redacted = true;
            let public_total_burned_redacted = true;
            let public_identity_metadata_redacted = true;
            let post_quantum_account_signatures = false;
            let post_quantum_signature_crypto_verification = false;
            let identity_signature_commitment_policy = true;
            let identity_signature_challenge_binding = true;
            let identity_signature_verification = false;
            let readiness_blockers = ChainReadinessBlockers {
                proof_settlement_disabled: !proof_settlement_enabled,
                production_zk_verifier_missing: !production_zk_verifier,
                committed_request_payloads_missing: !committed_request_payloads,
                shielded_call_payloads_missing: !shielded_call_payload_execution,
                shield_submitter_origin_privacy_missing: !shield_submitter_origin_privacy,
                shield_key_window_privacy_missing: !shield_key_window_privacy,
                private_route_selection_missing: !private_route_selection,
                account_commitment_blinding_missing: !account_commitment_blinding,
                private_routing_indexes_missing: !private_routing_indexes,
                private_storage_keys_missing: !private_storage_keys,
                private_capital_accounting_missing: !private_capital_accounting,
                private_event_metadata_missing: !private_event_metadata,
                signature_mode_not_full_post_quantum: signature_mode
                    != SignatureMode::FullPostQuantum,
                post_quantum_account_signatures_missing: !post_quantum_account_signatures,
                post_quantum_signature_crypto_verification_missing:
                    !post_quantum_signature_crypto_verification,
                identity_signature_verification_missing: !identity_signature_verification,
                external_audit_missing: true,
            };
            let privacy_complete = !readiness_blockers.privacy_blocked();
            let post_quantum_complete = !readiness_blockers.post_quantum_blocked();
            let production_ready = !readiness_blockers.production_blocked();

            ChainProtocolParams {
                subnet_creation_burn: T::SubnetCreationBurn::get(),
                miner_registration_burn: T::MinerRegistrationBurn::get(),
                min_miner_bond: T::MinMinerBond::get(),
                max_miner_bond: T::MaxMinerBond::get(),
                max_active_miners_per_subnet: T::MaxActiveMinersPerSubnet::get(),
                max_active_validators_per_subnet: T::MaxActiveValidatorsPerSubnet::get(),
                min_validator_stake: T::MinValidatorStake::get(),
                min_invalid_proof_slash_bps: T::MinInvalidProofSlashBps::get(),
                max_invalid_proof_slash_bps: T::MaxInvalidProofSlashBps::get(),
                min_proof_size_bytes: T::MinProofSizeBytes::get(),
                max_proof_size_bytes: T::MaxProofSizeBytes::get(),
                max_verification_latency_ms: T::MaxVerificationLatencyMs::get(),
                max_proof_submission_age_blocks: T::MaxProofSubmissionAgeBlocks::get(),
                proof_verifier_mode,
                proof_settlement_enabled,
                production_zk_verifier,
                signature_mode,
                committed_request_payloads,
                shielded_call_payloads,
                shield_submitter_origin_privacy,
                shield_key_window_privacy,
                private_route_selection,
                account_commitment_blinding,
                private_routing_indexes,
                private_storage_keys,
                private_capital_accounting,
                private_event_metadata,
                public_event_payloads_redacted,
                public_query_ids_redacted,
                public_subnet_records_redacted,
                route_availability_ids_redacted,
                public_route_availability_redacted,
                public_accounting_totals_redacted,
                public_accounting_migration_failures_redacted,
                public_migration_health_redacted,
                public_request_status_counts_redacted,
                public_registry_records_redacted,
                public_request_records_redacted,
                public_proof_records_redacted,
                public_next_request_id_redacted,
                public_registry_counts_redacted,
                public_total_burned_redacted,
                public_identity_metadata_redacted,
                post_quantum_account_signatures,
                post_quantum_signature_crypto_verification,
                privacy_complete,
                post_quantum_complete,
                production_ready,
                identity_signature_commitment_policy,
                identity_signature_challenge_binding,
                identity_signature_verification,
                readiness_blockers,
                miner_exit_cooldown_blocks: T::MinerExitCooldownBlocks::get(),
                validator_exit_cooldown_blocks: T::ValidatorExitCooldownBlocks::get(),
                request_cancel_delay_blocks: T::RequestCancelDelayBlocks::get(),
            }
        }

        #[cfg(any(test, feature = "try-runtime"))]
        pub(crate) fn raw_request_status_counts() -> ChainRequestStatusCounts {
            ChainRequestStatusCounts {
                pending: PendingInferenceRequestCount::<T>::get(),
                settled: SettledInferenceRequestCount::<T>::get(),
                cancelled: CancelledInferenceRequestCount::<T>::get(),
                rejected: RejectedInferenceRequestCount::<T>::get(),
                expired: ExpiredInferenceRequestCount::<T>::get(),
            }
        }

        pub fn request_status_counts() -> ChainRequestStatusCounts {
            ChainRequestStatusCounts {
                pending: 0,
                settled: 0,
                cancelled: 0,
                rejected: 0,
                expired: 0,
            }
        }

        pub(crate) fn route_assignment(
            subnet_id: SubnetId,
            request_id: RequestId,
        ) -> Option<ChainAssignment> {
            let subnet = Subnets::<T>::get(subnet_id)?;
            if !subnet.active {
                return None;
            }

            let miner_ids = ActiveMinersBySubnet::<T>::get(subnet_id);
            if miner_ids.is_empty() {
                return None;
            }

            let miner_start = Self::route_index(request_id, miner_ids.len())?;
            let validator_seed = request_id.rotate_left(32) ^ u64::from(subnet_id);

            for offset in 0..miner_ids.len() {
                let target = miner_start
                    .checked_add(offset)?
                    .checked_rem(miner_ids.len())?;
                let Some(miner_id) = miner_ids.get(target).copied() else {
                    continue;
                };
                let Some(miner) = Miners::<T>::get(miner_id) else {
                    continue;
                };
                if miner.subnet_id != subnet_id
                    || miner.status != RegistryStatus::Active
                    || Self::ensure_miner_signature_bundle_bound(miner_id, &miner).is_err()
                {
                    continue;
                }

                let Some(validator_id) = Self::route_active_validator(
                    subnet_id,
                    validator_seed,
                    miner.operator_commitment,
                ) else {
                    continue;
                };
                let Some(validator) = Validators::<T>::get(validator_id) else {
                    continue;
                };
                Self::ensure_distinct_operators(&miner, &validator).ok()?;

                return Some(ChainAssignment {
                    request_id,
                    subnet_id,
                    miner_id,
                    validator_id,
                });
            }

            None
        }

        #[cfg(test)]
        pub(crate) fn next_route_assignment(subnet_id: SubnetId) -> Option<ChainAssignment> {
            Self::route_assignment(subnet_id, RequestCount::<T>::get())
        }

        pub fn next_route_availability(_subnet_id: SubnetId) -> ChainRouteAvailability {
            ChainRouteAvailability { available: false }
        }

        pub fn public_subnet(_subnet_id: SubnetId) -> Option<ChainPublicSubnet> {
            None
        }

        pub fn public_miner(_miner_id: MinerId) -> Option<ChainPublicMiner> {
            None
        }

        pub fn public_validator(_validator_id: ValidatorId) -> Option<ChainPublicValidator> {
            None
        }

        pub fn public_miner_identity(_miner_id: MinerId) -> Option<ChainPublicIdentity> {
            None
        }

        pub fn public_validator_identity(
            _validator_id: ValidatorId,
        ) -> Option<ChainPublicIdentity> {
            None
        }

        pub fn public_inference_request(
            _request_id: RequestId,
        ) -> Option<ChainPublicInferenceRequest> {
            None
        }

        pub fn public_proof_record(_request_id: RequestId) -> Option<ChainPublicProofRecord> {
            None
        }

        #[allow(clippy::too_many_arguments)]
        fn ensure_inference_request_openable(
            request_id: RequestId,
            subnet_id: SubnetId,
            input_commitment: Commitment,
            assignment_blinding: Commitment,
            timing_blinding: Commitment,
            terms_blinding: Commitment,
            payment: BalanceOf<T>,
            validator_fee_bps: u16,
            treasury_fee_bps: u16,
        ) -> DispatchResult {
            ensure_commitment::<T>(input_commitment)?;
            ensure_commitment::<T>(assignment_blinding)?;
            ensure_commitment::<T>(timing_blinding)?;
            ensure_commitment::<T>(terms_blinding)?;
            ensure!(
                !InferenceRequests::<T>::contains_key(request_id),
                Error::<T>::DuplicateRequest
            );
            ensure!(
                payment > BalanceOf::<T>::default(),
                Error::<T>::InvalidPayment
            );
            Self::validate_fee_split(validator_fee_bps, treasury_fee_bps)?;
            let subnet = Subnets::<T>::get(subnet_id).ok_or(Error::<T>::UnknownSubnet)?;
            ensure!(subnet.active, Error::<T>::NotActive);
            Ok(())
        }

        #[allow(clippy::too_many_arguments)]
        fn open_inference_request(
            user: T::AccountId,
            request_id: RequestId,
            subnet_id: SubnetId,
            miner_id: MinerId,
            validator_id: ValidatorId,
            input_commitment: Commitment,
            assignment_blinding: Commitment,
            timing_blinding: Commitment,
            terms_blinding: Commitment,
            payment: BalanceOf<T>,
            validator_fee_bps: u16,
            treasury_fee_bps: u16,
        ) -> DispatchResult {
            let created_at = Self::current_block();
            let assignment_commitment = Self::request_assignment_commitment(
                request_id,
                subnet_id,
                miner_id,
                validator_id,
                assignment_blinding,
            );
            let terms_commitment = Self::request_terms_commitment(
                request_id,
                payment,
                validator_fee_bps,
                treasury_fee_bps,
                terms_blinding,
            );
            let timing_commitment =
                Self::request_timing_commitment(request_id, created_at, timing_blinding);
            Self::open_inference_request_with_commitments(
                user,
                request_id,
                subnet_id,
                miner_id,
                validator_id,
                input_commitment,
                assignment_commitment,
                terms_commitment,
                timing_commitment,
                payment,
                validator_fee_bps,
                treasury_fee_bps,
            )
        }

        #[allow(clippy::too_many_arguments)]
        fn open_inference_request_with_commitments(
            user: T::AccountId,
            request_id: RequestId,
            subnet_id: SubnetId,
            miner_id: MinerId,
            validator_id: ValidatorId,
            input_commitment: Commitment,
            assignment_commitment: Commitment,
            terms_commitment: Commitment,
            timing_commitment: Commitment,
            payment: BalanceOf<T>,
            _validator_fee_bps: u16,
            _treasury_fee_bps: u16,
        ) -> DispatchResult {
            Self::ensure_request_assignment(subnet_id, miner_id, validator_id)?;
            Self::ensure_next_request_id(request_id)?;
            Self::ensure_inference_escrow_can_record(payment)?;

            T::Currency::hold(&HoldReason::InferencePayment.into(), &user, payment)?;
            Self::increment_pending_assignment(miner_id, validator_id)?;
            Self::increment_request_status_count(InferenceRequestStatus::Pending)?;
            Self::record_inference_escrow(payment)?;
            InferenceRequests::<T>::insert(
                request_id,
                ChainInferenceRequest {
                    request_id,
                    user_commitment: Self::request_user_commitment(&user),
                    subnet_id,
                    assignment_commitment,
                    input_commitment,
                    terms_commitment,
                    timing_commitment,
                    status: InferenceRequestStatus::Pending,
                },
            );

            Self::deposit_event(Event::InferenceRequested);
            Ok(())
        }

        fn next_subnet_id() -> Result<SubnetId, DispatchError> {
            let id = SubnetCount::<T>::get();
            let next = id.checked_add(1).ok_or(Error::<T>::ArithmeticOverflow)?;
            SubnetCount::<T>::put(next);
            Ok(id)
        }

        fn next_miner_id() -> Result<MinerId, DispatchError> {
            let id = MinerCount::<T>::get();
            let next = id.checked_add(1).ok_or(Error::<T>::ArithmeticOverflow)?;
            MinerCount::<T>::put(next);
            Ok(id)
        }

        fn next_validator_id() -> Result<ValidatorId, DispatchError> {
            let id = ValidatorCount::<T>::get();
            let next = id.checked_add(1).ok_or(Error::<T>::ArithmeticOverflow)?;
            ValidatorCount::<T>::put(next);
            Ok(id)
        }

        fn ensure_next_request_id(request_id: RequestId) -> DispatchResult {
            let next = Self::ensure_request_id_can_advance(request_id)?;
            RequestCount::<T>::put(next);
            Ok(())
        }

        fn ensure_request_id_can_advance(
            request_id: RequestId,
        ) -> Result<RequestId, DispatchError> {
            Self::ensure_request_id_matches_next(request_id)?;
            request_id
                .checked_add(1)
                .ok_or(Error::<T>::ArithmeticOverflow.into())
        }

        fn ensure_request_id_matches_next(request_id: RequestId) -> DispatchResult {
            let expected = RequestCount::<T>::get();
            ensure!(request_id == expected, Error::<T>::InvalidRequestId);
            Ok(())
        }

        fn increment_pending_assignment(
            miner_id: MinerId,
            validator_id: ValidatorId,
        ) -> DispatchResult {
            PendingMinerRequests::<T>::try_mutate(miner_id, |count| {
                *count = count.checked_add(1).ok_or(Error::<T>::ArithmeticOverflow)?;
                Ok::<(), Error<T>>(())
            })?;
            PendingValidatorRequests::<T>::try_mutate(validator_id, |count| {
                *count = count.checked_add(1).ok_or(Error::<T>::ArithmeticOverflow)?;
                Ok::<(), Error<T>>(())
            })?;
            Ok(())
        }

        fn decrement_pending_assignment(
            miner_id: MinerId,
            validator_id: ValidatorId,
        ) -> DispatchResult {
            PendingMinerRequests::<T>::try_mutate_exists(miner_id, |maybe_count| {
                let count = maybe_count.ok_or(Error::<T>::PendingAssignmentUnderflow)?;
                let next = count
                    .checked_sub(1)
                    .ok_or(Error::<T>::PendingAssignmentUnderflow)?;
                if next == 0 {
                    *maybe_count = None;
                } else {
                    *maybe_count = Some(next);
                }
                Ok::<(), Error<T>>(())
            })?;
            PendingValidatorRequests::<T>::try_mutate_exists(validator_id, |maybe_count| {
                let count = maybe_count.ok_or(Error::<T>::PendingAssignmentUnderflow)?;
                let next = count
                    .checked_sub(1)
                    .ok_or(Error::<T>::PendingAssignmentUnderflow)?;
                if next == 0 {
                    *maybe_count = None;
                } else {
                    *maybe_count = Some(next);
                }
                Ok::<(), Error<T>>(())
            })?;
            Ok(())
        }

        fn record_inference_escrow(payment: BalanceOf<T>) -> DispatchResult {
            TotalInferenceEscrowed::<T>::try_mutate(|total| -> DispatchResult {
                *total = total
                    .checked_add(&payment)
                    .ok_or(Error::<T>::ArithmeticOverflow)?;
                Ok(())
            })
        }

        fn increment_request_status_count(status: InferenceRequestStatus) -> DispatchResult {
            match status {
                InferenceRequestStatus::Pending => {
                    PendingInferenceRequestCount::<T>::try_mutate(Self::increment_request_count)
                }
                InferenceRequestStatus::Settled => {
                    SettledInferenceRequestCount::<T>::try_mutate(Self::increment_request_count)
                }
                InferenceRequestStatus::Cancelled => {
                    CancelledInferenceRequestCount::<T>::try_mutate(Self::increment_request_count)
                }
                InferenceRequestStatus::Rejected => {
                    RejectedInferenceRequestCount::<T>::try_mutate(Self::increment_request_count)
                }
                InferenceRequestStatus::Expired => {
                    ExpiredInferenceRequestCount::<T>::try_mutate(Self::increment_request_count)
                }
            }
        }

        fn decrement_request_status_count(status: InferenceRequestStatus) -> DispatchResult {
            match status {
                InferenceRequestStatus::Pending => {
                    PendingInferenceRequestCount::<T>::try_mutate(Self::decrement_request_count)
                }
                InferenceRequestStatus::Settled => {
                    SettledInferenceRequestCount::<T>::try_mutate(Self::decrement_request_count)
                }
                InferenceRequestStatus::Cancelled => {
                    CancelledInferenceRequestCount::<T>::try_mutate(Self::decrement_request_count)
                }
                InferenceRequestStatus::Rejected => {
                    RejectedInferenceRequestCount::<T>::try_mutate(Self::decrement_request_count)
                }
                InferenceRequestStatus::Expired => {
                    ExpiredInferenceRequestCount::<T>::try_mutate(Self::decrement_request_count)
                }
            }
        }

        fn transition_request_status(
            from: InferenceRequestStatus,
            to: InferenceRequestStatus,
        ) -> DispatchResult {
            if from == to {
                return Ok(());
            }

            Self::decrement_request_status_count(from)?;
            Self::increment_request_status_count(to)
        }

        fn increment_request_count(count: &mut RequestId) -> DispatchResult {
            *count = count.checked_add(1).ok_or(Error::<T>::ArithmeticOverflow)?;
            Ok(())
        }

        fn decrement_request_count(count: &mut RequestId) -> DispatchResult {
            *count = count
                .checked_sub(1)
                .ok_or(Error::<T>::RequestStatusCounterUnderflow)?;
            Ok(())
        }

        fn ensure_accounting_can_add(total: BalanceOf<T>, amount: BalanceOf<T>) -> DispatchResult {
            ensure!(
                total.checked_add(&amount).is_some(),
                Error::<T>::ArithmeticOverflow
            );
            Ok(())
        }

        fn ensure_inference_escrow_can_record(payment: BalanceOf<T>) -> DispatchResult {
            Self::ensure_accounting_can_add(TotalInferenceEscrowed::<T>::get(), payment)
        }

        fn ensure_inference_settlement_can_record(
            miner_payment: BalanceOf<T>,
            validator_fee: BalanceOf<T>,
            treasury_fee: BalanceOf<T>,
        ) -> DispatchResult {
            Self::ensure_accounting_can_add(TotalMinerPayouts::<T>::get(), miner_payment)?;
            Self::ensure_accounting_can_add(TotalValidatorFees::<T>::get(), validator_fee)?;
            Self::ensure_accounting_can_add(TotalTreasuryFees::<T>::get(), treasury_fee)
        }

        fn ensure_inference_refund_can_record(payment: BalanceOf<T>) -> DispatchResult {
            Self::ensure_accounting_can_add(TotalInferenceRefunded::<T>::get(), payment)
        }

        fn record_inference_settlement(
            miner_payment: BalanceOf<T>,
            validator_fee: BalanceOf<T>,
            treasury_fee: BalanceOf<T>,
        ) -> DispatchResult {
            TotalMinerPayouts::<T>::try_mutate(|total| -> DispatchResult {
                *total = total
                    .checked_add(&miner_payment)
                    .ok_or(Error::<T>::ArithmeticOverflow)?;
                Ok(())
            })?;
            TotalValidatorFees::<T>::try_mutate(|total| -> DispatchResult {
                *total = total
                    .checked_add(&validator_fee)
                    .ok_or(Error::<T>::ArithmeticOverflow)?;
                Ok(())
            })?;
            TotalTreasuryFees::<T>::try_mutate(|total| -> DispatchResult {
                *total = total
                    .checked_add(&treasury_fee)
                    .ok_or(Error::<T>::ArithmeticOverflow)?;
                Ok(())
            })
        }

        fn record_inference_refund(payment: BalanceOf<T>) -> DispatchResult {
            TotalInferenceRefunded::<T>::try_mutate(|total| -> DispatchResult {
                *total = total
                    .checked_add(&payment)
                    .ok_or(Error::<T>::ArithmeticOverflow)?;
                Ok(())
            })
        }

        fn current_block() -> BlockNumber {
            frame_system::Pallet::<T>::block_number().saturated_into()
        }

        fn ensure_payload_signer(origin: OriginFor<T>) -> Result<T::AccountId, DispatchError> {
            if T::ShieldedCallPayloads::get() {
                T::ShieldedOrigin::try_origin(origin)
                    .map_err(|_| Error::<T>::PublicCallPayloadDisallowed.into())
            } else {
                Ok(ensure_signed(origin)?)
            }
        }

        fn ensure_public_call_payload_allowed() -> DispatchResult {
            ensure!(
                !T::ShieldedCallPayloads::get(),
                Error::<T>::PublicCallPayloadDisallowed
            );
            Ok(())
        }

        pub(crate) fn account_commitment(who: &T::AccountId) -> Commitment {
            who.using_encoded(blake2_256)
        }

        pub(crate) fn subnet_owner_commitment(who: &T::AccountId) -> Commitment {
            Self::role_account_commitment(b"qubitum.subnet.owner.v1", who)
        }

        pub(crate) fn operator_commitment(who: &T::AccountId) -> Commitment {
            Self::role_account_commitment(b"qubitum.operator.v1", who)
        }

        pub(crate) fn request_user_commitment(who: &T::AccountId) -> Commitment {
            Self::role_account_commitment(b"qubitum.request.user.v1", who)
        }

        fn role_account_commitment(domain: &'static [u8], who: &T::AccountId) -> Commitment {
            (domain, who).using_encoded(blake2_256)
        }

        #[cfg(test)]
        pub(crate) fn balance_commitment(amount: BalanceOf<T>) -> Commitment {
            amount.using_encoded(blake2_256)
        }

        pub(crate) fn miner_bond_commitment(
            miner_id: MinerId,
            operator_commitment: Commitment,
            status: RegistryStatus,
        ) -> Commitment {
            Self::participant_capital_commitment(
                b"qubitum.miner.bond.state.v1",
                miner_id,
                operator_commitment,
                status,
            )
        }

        pub(crate) fn validator_stake_commitment(
            validator_id: ValidatorId,
            operator_commitment: Commitment,
            status: RegistryStatus,
        ) -> Commitment {
            Self::participant_capital_commitment(
                b"qubitum.validator.stake.state.v1",
                validator_id,
                operator_commitment,
                status,
            )
        }

        fn participant_capital_commitment(
            domain: &'static [u8],
            participant_id: u64,
            operator_commitment: Commitment,
            status: RegistryStatus,
        ) -> Commitment {
            (domain, participant_id, operator_commitment, status).using_encoded(blake2_256)
        }

        pub(crate) fn miner_identity_signature_challenge(
            miner_id: MinerId,
            operator_commitment: Commitment,
            shielded_identity_commitment: Option<Commitment>,
            endpoint_commitment: Option<Commitment>,
        ) -> Commitment {
            Self::identity_signature_challenge(
                b"qubitum.identity.miner.v1",
                miner_id,
                operator_commitment,
                shielded_identity_commitment,
                endpoint_commitment,
            )
        }

        pub(crate) fn validator_identity_signature_challenge(
            validator_id: ValidatorId,
            operator_commitment: Commitment,
            shielded_identity_commitment: Option<Commitment>,
            endpoint_commitment: Option<Commitment>,
        ) -> Commitment {
            Self::identity_signature_challenge(
                b"qubitum.identity.validator.v1",
                validator_id,
                operator_commitment,
                shielded_identity_commitment,
                endpoint_commitment,
            )
        }

        fn identity_signature_challenge(
            domain: &'static [u8],
            subject_id: u64,
            operator_commitment: Commitment,
            shielded_identity_commitment: Option<Commitment>,
            endpoint_commitment: Option<Commitment>,
        ) -> Commitment {
            (
                domain,
                subject_id,
                operator_commitment,
                shielded_identity_commitment,
                endpoint_commitment,
                T::SignatureMode::get(),
            )
                .using_encoded(blake2_256)
        }

        pub(crate) fn identity_signature_binding(
            challenge: Commitment,
            signature: SignatureCommitment,
        ) -> Commitment {
            (
                b"qubitum.identity.signature.binding.v1",
                challenge,
                signature.algorithm,
                signature.public_key_commitment,
                T::SignatureMode::get(),
            )
                .using_encoded(blake2_256)
        }

        pub(crate) fn subnet_policy_commitment(
            subnet_id: SubnetId,
            domain: SubnetDomain,
            proof_system: ProofSystem,
        ) -> Commitment {
            (
                subnet_id,
                domain,
                proof_system,
                T::SubnetCreationBurn::get(),
                T::MinerRegistrationBurn::get(),
                T::MinMinerBond::get(),
                T::MaxMinerBond::get(),
                T::MinValidatorStake::get(),
                T::MaxActiveMinersPerSubnet::get(),
                T::MaxActiveValidatorsPerSubnet::get(),
            )
                .using_encoded(blake2_256)
        }

        pub(crate) fn request_assignment_commitment(
            request_id: RequestId,
            subnet_id: SubnetId,
            miner_id: MinerId,
            validator_id: ValidatorId,
            assignment_blinding: Commitment,
        ) -> Commitment {
            (
                b"qubitum.request.assignment.v1",
                request_id,
                subnet_id,
                miner_id,
                validator_id,
                assignment_blinding,
            )
                .using_encoded(blake2_256)
        }

        pub(crate) fn legacy_request_assignment_commitment(
            request_id: RequestId,
            subnet_id: SubnetId,
            miner_id: MinerId,
            validator_id: ValidatorId,
        ) -> Commitment {
            (request_id, subnet_id, miner_id, validator_id).using_encoded(blake2_256)
        }

        pub(crate) fn request_timing_commitment(
            request_id: RequestId,
            created_at: BlockNumber,
            timing_blinding: Commitment,
        ) -> Commitment {
            (
                b"qubitum.request.timing.v1",
                request_id,
                created_at,
                timing_blinding,
            )
                .using_encoded(blake2_256)
        }

        pub(crate) fn legacy_request_timing_commitment(
            request_id: RequestId,
            created_at: BlockNumber,
        ) -> Commitment {
            (request_id, created_at).using_encoded(blake2_256)
        }

        pub(crate) fn request_terms_commitment(
            request_id: RequestId,
            payment: BalanceOf<T>,
            validator_fee_bps: u16,
            treasury_fee_bps: u16,
            terms_blinding: Commitment,
        ) -> Commitment {
            (
                b"qubitum.request.terms.v1",
                request_id,
                payment,
                validator_fee_bps,
                treasury_fee_bps,
                terms_blinding,
            )
                .using_encoded(blake2_256)
        }

        pub(crate) fn legacy_request_terms_commitment(
            request_id: RequestId,
            payment: BalanceOf<T>,
            validator_fee_bps: u16,
            treasury_fee_bps: u16,
        ) -> Commitment {
            (request_id, payment, validator_fee_bps, treasury_fee_bps).using_encoded(blake2_256)
        }

        #[cfg(any(test, feature = "runtime-benchmarks"))]
        pub(crate) fn proof_audit_commitment(
            submission: &InferenceProofSubmission,
            accepted_at: BlockNumber,
            assignment_blinding: Commitment,
        ) -> Commitment {
            Self::proof_audit_commitment_for_assignment(
                submission,
                accepted_at,
                Self::request_assignment_commitment(
                    submission.request_id,
                    submission.subnet_id,
                    submission.miner_id,
                    submission.validator_id,
                    assignment_blinding,
                ),
            )
        }

        pub(crate) fn proof_audit_commitment_for_assignment(
            submission: &InferenceProofSubmission,
            accepted_at: BlockNumber,
            assignment_commitment: Commitment,
        ) -> Commitment {
            (
                submission.request_id,
                submission.subnet_id,
                assignment_commitment,
                submission.input_commitment,
                submission.output_commitment,
                submission.model_commitment,
                &submission.proof,
                submission.proof_system,
                submission.proof_size_bytes,
                submission.verification_latency_ms,
                submission.submitted_at,
                accepted_at,
            )
                .using_encoded(blake2_256)
        }

        pub(crate) fn proof_transcript_commitment(
            submission: &InferenceProofSubmission,
        ) -> Commitment {
            (
                submission.request_id,
                submission.subnet_id,
                submission.miner_id,
                submission.validator_id,
                submission.input_commitment,
                submission.output_commitment,
                submission.model_commitment,
                submission.proof_system,
                submission.proof.proof_commitment,
                submission.proof.image_id,
                submission.proof.verifier_version,
                submission.proof_size_bytes,
                submission.verification_latency_ms,
                submission.submitted_at,
            )
                .using_encoded(blake2_256)
        }

        #[allow(clippy::too_many_arguments)]
        pub(crate) fn legacy_proof_audit_commitment(
            request_id: RequestId,
            subnet_id: SubnetId,
            assignment_commitment: Commitment,
            input_commitment: Commitment,
            output_commitment: Commitment,
            model_commitment: Commitment,
            proof: &ProofEnvelope,
            proof_system: ProofSystem,
            proof_size_bytes: u32,
            verification_latency_ms: u32,
            submitted_at: BlockNumber,
            accepted_at: BlockNumber,
        ) -> Commitment {
            (
                request_id,
                subnet_id,
                assignment_commitment,
                input_commitment,
                output_commitment,
                model_commitment,
                proof,
                proof_system,
                proof_size_bytes,
                verification_latency_ms,
                submitted_at,
                accepted_at,
            )
                .using_encoded(blake2_256)
        }

        fn held_miner_bond(operator: &T::AccountId) -> BalanceOf<T> {
            T::Currency::balance_on_hold(&HoldReason::MinerBond.into(), operator)
        }

        fn held_validator_stake(operator: &T::AccountId) -> BalanceOf<T> {
            T::Currency::balance_on_hold(&HoldReason::ValidatorStake.into(), operator)
        }

        fn miner_capital_bearing_status(status: RegistryStatus) -> bool {
            matches!(
                status,
                RegistryStatus::Active | RegistryStatus::Slashed | RegistryStatus::Exiting { .. }
            )
        }

        fn validator_capital_bearing_status(status: RegistryStatus) -> bool {
            matches!(
                status,
                RegistryStatus::Pending
                    | RegistryStatus::Active
                    | RegistryStatus::Slashed
                    | RegistryStatus::Exiting { .. }
            )
        }

        fn miner_capital_record_count(operator_commitment: Commitment) -> u32 {
            Miners::<T>::iter()
                .filter(|(_, miner)| {
                    miner.operator_commitment == operator_commitment
                        && Self::miner_capital_bearing_status(miner.status)
                })
                .fold(0_u32, |count, _| count.saturating_add(1))
        }

        fn validator_capital_record_count(operator_commitment: Commitment) -> u32 {
            Validators::<T>::iter()
                .filter(|(_, validator)| {
                    validator.operator_commitment == operator_commitment
                        && Self::validator_capital_bearing_status(validator.status)
                })
                .fold(0_u32, |count, _| count.saturating_add(1))
        }

        fn locked_miner_bond(
            miner_id: MinerId,
            operator: &T::AccountId,
        ) -> Result<BalanceOf<T>, DispatchError> {
            if let Some(bond) = MinerLockedBond::<T>::get(miner_id) {
                return Ok(bond);
            }

            let miner = Miners::<T>::get(miner_id).ok_or(Error::<T>::UnknownMiner)?;
            Self::ensure_miner_operator(&miner, operator)?;
            ensure!(
                Self::miner_capital_bearing_status(miner.status)
                    && Self::miner_capital_record_count(miner.operator_commitment) == 1,
                Error::<T>::MissingCapitalRecord
            );
            Ok(Self::held_miner_bond(operator))
        }

        fn locked_validator_stake(
            validator_id: ValidatorId,
            operator: &T::AccountId,
        ) -> Result<BalanceOf<T>, DispatchError> {
            if let Some(stake) = ValidatorLockedStake::<T>::get(validator_id) {
                return Ok(stake);
            }

            let validator =
                Validators::<T>::get(validator_id).ok_or(Error::<T>::UnknownValidator)?;
            Self::ensure_validator_operator(&validator, operator)?;
            ensure!(
                Self::validator_capital_bearing_status(validator.status)
                    && Self::validator_capital_record_count(validator.operator_commitment) == 1,
                Error::<T>::MissingCapitalRecord
            );
            Ok(Self::held_validator_stake(operator))
        }

        fn validator_has_active_locked_stake_record(validator_id: ValidatorId) -> bool {
            match ValidatorLockedStake::<T>::get(validator_id) {
                Some(stake) => stake >= T::MinValidatorStake::get(),
                None => false,
            }
        }

        fn ensure_validator_locked_stake_record(validator_id: ValidatorId) -> DispatchResult {
            ensure!(
                Self::validator_has_active_locked_stake_record(validator_id),
                Error::<T>::MissingCapitalRecord
            );
            Ok(())
        }

        fn ensure_miner_operator(miner: &ChainMiner, operator: &T::AccountId) -> DispatchResult {
            ensure!(
                Self::operator_commitment_matches(miner.operator_commitment, operator),
                Error::<T>::NotOperator
            );
            Ok(())
        }

        fn ensure_validator_operator(
            validator: &ChainValidator,
            operator: &T::AccountId,
        ) -> DispatchResult {
            ensure!(
                Self::operator_commitment_matches(validator.operator_commitment, operator),
                Error::<T>::NotOperator
            );
            Ok(())
        }

        fn ensure_validator_submission_operator(
            validator: &ChainValidator,
            operator: &T::AccountId,
        ) -> DispatchResult {
            ensure!(
                Self::operator_commitment_matches(validator.operator_commitment, operator),
                Error::<T>::NotValidatorOperator
            );
            Ok(())
        }

        pub(crate) fn operator_commitment_matches(
            stored: Commitment,
            operator: &T::AccountId,
        ) -> bool {
            stored == Self::operator_commitment(operator)
                || stored == Self::account_commitment(operator)
        }

        fn ensure_request_user(
            request: &ChainInferenceRequest,
            user: &T::AccountId,
        ) -> DispatchResult {
            ensure!(
                Self::request_user_commitment_matches(request.user_commitment, user),
                Error::<T>::NotRequestOwner
            );
            Ok(())
        }

        pub(crate) fn request_user_commitment_matches(
            stored: Commitment,
            user: &T::AccountId,
        ) -> bool {
            stored == Self::request_user_commitment(user)
                || stored == Self::account_commitment(user)
        }

        fn ensure_request_assignment_witness(
            request: &ChainInferenceRequest,
            miner_id: MinerId,
            validator_id: ValidatorId,
            assignment_blinding: Commitment,
        ) -> DispatchResult {
            Self::resolve_request_assignment_commitment(
                request,
                miner_id,
                validator_id,
                assignment_blinding,
            )?;
            Ok(())
        }

        fn resolve_request_assignment_commitment(
            request: &ChainInferenceRequest,
            miner_id: MinerId,
            validator_id: ValidatorId,
            assignment_blinding: Commitment,
        ) -> Result<Commitment, DispatchError> {
            let blinded = Self::request_assignment_commitment(
                request.request_id,
                request.subnet_id,
                miner_id,
                validator_id,
                assignment_blinding,
            );
            let legacy = Self::legacy_request_assignment_commitment(
                request.request_id,
                request.subnet_id,
                miner_id,
                validator_id,
            );
            let assignment_matches = request.assignment_commitment == blinded
                || (assignment_blinding == LEGACY_ASSIGNMENT_BLINDING
                    && request.assignment_commitment == legacy);
            ensure!(assignment_matches, Error::<T>::AssignmentMismatch);
            ensure!(
                assignment_blinding != LEGACY_ASSIGNMENT_BLINDING
                    || request.assignment_commitment == legacy,
                Error::<T>::MissingCommitment
            );
            Ok(request.assignment_commitment)
        }

        fn submission_assignment_commitment(
            submission: &InferenceProofSubmission,
            assignment_blinding: Commitment,
        ) -> Result<Commitment, DispatchError> {
            let request = InferenceRequests::<T>::get(submission.request_id)
                .ok_or(Error::<T>::UnknownRequest)?;
            Self::resolve_request_assignment_commitment(
                &request,
                submission.miner_id,
                submission.validator_id,
                assignment_blinding,
            )
        }

        fn ensure_request_timing_witness(
            request: &ChainInferenceRequest,
            timing_witness: InferenceRequestTimingWitness,
        ) -> DispatchResult {
            let blinded = Self::request_timing_commitment(
                request.request_id,
                timing_witness.created_at,
                timing_witness.blinding,
            );
            let legacy = Self::legacy_request_timing_commitment(
                request.request_id,
                timing_witness.created_at,
            );
            let timing_matches = request.timing_commitment == blinded
                || (timing_witness.blinding == LEGACY_TIMING_BLINDING
                    && request.timing_commitment == legacy);
            ensure!(timing_matches, Error::<T>::RequestMismatch);
            ensure!(
                timing_witness.blinding != LEGACY_TIMING_BLINDING
                    || request.timing_commitment == legacy,
                Error::<T>::MissingCommitment
            );
            Ok(())
        }

        fn ensure_request_terms_witness(
            request: &ChainInferenceRequest,
            terms_witness: &InferenceRequestTermsWitness<BalanceOf<T>>,
        ) -> DispatchResult {
            let terms = &terms_witness.terms;
            ensure!(
                terms.payment > BalanceOf::<T>::default(),
                Error::<T>::InvalidPayment
            );
            Self::validate_fee_split(terms.validator_fee_bps, terms.treasury_fee_bps)?;
            let blinded = Self::request_terms_commitment(
                request.request_id,
                terms.payment,
                terms.validator_fee_bps,
                terms.treasury_fee_bps,
                terms_witness.blinding,
            );
            let legacy = Self::legacy_request_terms_commitment(
                request.request_id,
                terms.payment,
                terms.validator_fee_bps,
                terms.treasury_fee_bps,
            );
            let terms_match = request.terms_commitment == blinded
                || (terms_witness.blinding == LEGACY_TERMS_BLINDING
                    && request.terms_commitment == legacy);
            ensure!(terms_match, Error::<T>::RequestMismatch);
            ensure!(
                terms_witness.blinding != LEGACY_TERMS_BLINDING
                    || request.terms_commitment == legacy,
                Error::<T>::MissingCommitment
            );
            Ok(())
        }

        fn ensure_proof_transcript_witness(
            submission: &InferenceProofSubmission,
        ) -> DispatchResult {
            ensure!(
                submission.proof.journal_commitment
                    == Self::proof_transcript_commitment(submission),
                Error::<T>::ProofTranscriptMismatch
            );
            Ok(())
        }

        fn ensure_optional_commitment(commitment: Option<Commitment>) -> DispatchResult {
            if let Some(commitment) = commitment {
                ensure_commitment::<T>(commitment)?;
            }
            Ok(())
        }

        fn ensure_supported_proof_system(proof_system: ProofSystem) -> DispatchResult {
            ensure!(
                matches!(
                    proof_system,
                    ProofSystem::RiscZeroStark | ProofSystem::Stark
                ),
                Error::<T>::UnsupportedProofSystem
            );
            Ok(())
        }

        fn ensure_signature_bundle(signature_bundle: SignatureBundle) -> DispatchResult {
            SignaturePolicy::new(T::SignatureMode::get())
                .validate(signature_bundle)
                .map(|_| ())
                .map_err(|_| Error::<T>::InvalidSignatureBundle.into())
        }

        fn ensure_signature_bundle_bound_to_challenge(
            signature_bundle: SignatureBundle,
            challenge: Commitment,
        ) -> DispatchResult {
            Self::ensure_signature_bundle(signature_bundle)?;
            if let Some(signature) = signature_bundle.classical {
                Self::ensure_signature_commitment_bound_to_challenge(signature, challenge)?;
            }
            if let Some(signature) = signature_bundle.post_quantum {
                Self::ensure_signature_commitment_bound_to_challenge(signature, challenge)?;
            }
            Ok(())
        }

        fn ensure_signature_commitment_bound_to_challenge(
            signature: SignatureCommitment,
            challenge: Commitment,
        ) -> DispatchResult {
            ensure!(
                signature.signature_commitment
                    == Self::identity_signature_binding(challenge, signature),
                Error::<T>::InvalidSignatureBundle
            );
            Ok(())
        }

        fn ensure_participant_signature_bundles(
            miner_id: MinerId,
            validator_id: ValidatorId,
        ) -> DispatchResult {
            let miner = Miners::<T>::get(miner_id).ok_or(Error::<T>::UnknownMiner)?;
            let validator =
                Validators::<T>::get(validator_id).ok_or(Error::<T>::UnknownValidator)?;
            Self::ensure_miner_signature_bundle_bound(miner_id, &miner)?;
            Self::ensure_validator_signature_bundle_bound(validator_id, &validator)?;
            Ok(())
        }

        fn ensure_miner_signature_bundle_bound(
            miner_id: MinerId,
            miner: &ChainMiner,
        ) -> DispatchResult {
            let commitments = MinerIdentityCommitments::<T>::get(miner_id)
                .ok_or(Error::<T>::MissingSignatureBundle)?;
            let stored_challenge = MinerIdentitySignatureChallenges::<T>::get(miner_id)
                .ok_or(Error::<T>::MissingSignatureBundle)?;
            let expected_challenge = Self::miner_identity_signature_challenge(
                miner_id,
                miner.operator_commitment,
                commitments.shielded_identity_commitment,
                commitments.endpoint_commitment,
            );
            ensure!(
                stored_challenge == expected_challenge,
                Error::<T>::InvalidSignatureBundle
            );
            let signature_bundle = MinerIdentitySignatureBundles::<T>::get(miner_id)
                .ok_or(Error::<T>::MissingSignatureBundle)?;
            Self::ensure_signature_bundle_bound_to_challenge(signature_bundle, expected_challenge)
        }

        fn ensure_validator_signature_bundle_bound(
            validator_id: ValidatorId,
            validator: &ChainValidator,
        ) -> DispatchResult {
            let commitments = ValidatorIdentityCommitments::<T>::get(validator_id)
                .ok_or(Error::<T>::MissingSignatureBundle)?;
            let stored_challenge = ValidatorIdentitySignatureChallenges::<T>::get(validator_id)
                .ok_or(Error::<T>::MissingSignatureBundle)?;
            let expected_challenge = Self::validator_identity_signature_challenge(
                validator_id,
                validator.operator_commitment,
                commitments.shielded_identity_commitment,
                commitments.endpoint_commitment,
            );
            ensure!(
                stored_challenge == expected_challenge,
                Error::<T>::InvalidSignatureBundle
            );
            let signature_bundle = ValidatorIdentitySignatureBundles::<T>::get(validator_id)
                .ok_or(Error::<T>::MissingSignatureBundle)?;
            Self::ensure_signature_bundle_bound_to_challenge(signature_bundle, expected_challenge)
        }

        fn route_active_validator(
            subnet_id: SubnetId,
            seed: u64,
            miner_operator_commitment: Commitment,
        ) -> Option<ValidatorId> {
            let ids = ActiveValidatorsBySubnet::<T>::get(subnet_id);
            if ids.is_empty() {
                return None;
            }

            let start = Self::route_index(seed, ids.len())?;
            for offset in 0..ids.len() {
                let target = start.checked_add(offset)?.checked_rem(ids.len())?;
                let Some(validator_id) = ids.get(target).copied() else {
                    continue;
                };
                let Some(validator) = Validators::<T>::get(validator_id) else {
                    continue;
                };
                if validator.subnet_id == subnet_id
                    && validator.status == RegistryStatus::Active
                    && Self::validator_has_active_locked_stake_record(validator_id)
                    && validator.operator_commitment != miner_operator_commitment
                    && Self::ensure_validator_signature_bundle_bound(validator_id, &validator)
                        .is_ok()
                {
                    return Some(validator_id);
                }
            }

            None
        }

        fn route_index(seed: u64, len: usize) -> Option<usize> {
            let count: u64 = len.try_into().ok()?;
            seed.checked_rem(count)?.try_into().ok()
        }

        fn insert_sorted_miner_id(
            ids: &mut BoundedVec<MinerId, T::MaxActiveMinersPerSubnet>,
            miner_id: MinerId,
        ) -> Result<bool, Error<T>> {
            if ids.contains(&miner_id) {
                return Ok(false);
            }

            let mut sorted = ids.to_vec();
            sorted.push(miner_id);
            sorted.sort_unstable();
            *ids = sorted
                .try_into()
                .map_err(|_| Error::<T>::TooManyActiveMiners)?;
            Ok(true)
        }

        fn insert_sorted_validator_id(
            ids: &mut BoundedVec<ValidatorId, T::MaxActiveValidatorsPerSubnet>,
            validator_id: ValidatorId,
        ) -> Result<bool, Error<T>> {
            if ids.contains(&validator_id) {
                return Ok(false);
            }

            let mut sorted = ids.to_vec();
            sorted.push(validator_id);
            sorted.sort_unstable();
            *ids = sorted
                .try_into()
                .map_err(|_| Error::<T>::TooManyActiveValidators)?;
            Ok(true)
        }

        fn insert_active_miner(subnet_id: SubnetId, miner_id: MinerId) -> DispatchResult {
            ActiveMinersBySubnet::<T>::try_mutate(subnet_id, |ids| {
                Self::insert_sorted_miner_id(ids, miner_id)?;
                Ok(())
            })
        }

        fn remove_active_miner(subnet_id: SubnetId, miner_id: MinerId) {
            ActiveMinersBySubnet::<T>::mutate(subnet_id, |ids| {
                ids.retain(|indexed| *indexed != miner_id);
            });
        }

        fn insert_active_validator(
            subnet_id: SubnetId,
            validator_id: ValidatorId,
        ) -> DispatchResult {
            ActiveValidatorsBySubnet::<T>::try_mutate(subnet_id, |ids| {
                Self::insert_sorted_validator_id(ids, validator_id)?;
                Ok(())
            })
        }

        fn remove_active_validator(subnet_id: SubnetId, validator_id: ValidatorId) {
            ActiveValidatorsBySubnet::<T>::mutate(subnet_id, |ids| {
                ids.retain(|indexed| *indexed != validator_id);
            });
        }

        fn rebuild_active_routing_indexes() -> Weight {
            let mut miner_reads = 0_u64;
            let mut miner_writes = 0_u64;
            let mut validator_reads = 0_u64;
            let mut validator_writes = 0_u64;
            let mut overflow_miners = sp_std::vec::Vec::new();
            let mut overflow_validators = sp_std::vec::Vec::new();
            let mut migration_failures = 0_u32;

            for (subnet_id, _) in ActiveMinersBySubnet::<T>::iter() {
                ActiveMinersBySubnet::<T>::remove(subnet_id);
                miner_reads = miner_reads.saturating_add(1);
                miner_writes = miner_writes.saturating_add(1);
            }
            for (subnet_id, _) in ActiveValidatorsBySubnet::<T>::iter() {
                ActiveValidatorsBySubnet::<T>::remove(subnet_id);
                validator_reads = validator_reads.saturating_add(1);
                validator_writes = validator_writes.saturating_add(1);
            }

            let mut pending_miners = sp_std::vec::Vec::new();
            let mut routable_miners = sp_std::vec::Vec::new();
            for (miner_id, miner) in Miners::<T>::iter() {
                miner_reads = miner_reads.saturating_add(1);
                if miner.status == RegistryStatus::Active
                    && Self::ensure_miner_signature_bundle_bound(miner_id, &miner).is_ok()
                {
                    miner_reads = miner_reads.saturating_add(1);
                    if PendingMinerRequests::<T>::get(miner_id) > 0 {
                        pending_miners.push((miner_id, miner.subnet_id));
                    } else {
                        routable_miners.push((miner_id, miner.subnet_id));
                    }
                }
            }
            for (miner_id, subnet_id) in pending_miners.into_iter().chain(routable_miners) {
                match ActiveMinersBySubnet::<T>::try_mutate(subnet_id, |ids| {
                    Self::insert_sorted_miner_id(ids, miner_id)
                }) {
                    Ok(inserted) => {
                        if inserted {
                            miner_writes = miner_writes.saturating_add(1);
                        }
                    }
                    Err(_) => {
                        overflow_miners.push(miner_id);
                        migration_failures = migration_failures.saturating_add(1);
                    }
                }
            }

            let mut pending_validators = sp_std::vec::Vec::new();
            let mut routable_validators = sp_std::vec::Vec::new();
            for (validator_id, validator) in Validators::<T>::iter() {
                validator_reads = validator_reads.saturating_add(1);
                if validator.status == RegistryStatus::Active
                    && Self::validator_has_active_locked_stake_record(validator_id)
                    && Self::ensure_validator_signature_bundle_bound(validator_id, &validator)
                        .is_ok()
                {
                    validator_reads = validator_reads.saturating_add(1);
                    if PendingValidatorRequests::<T>::get(validator_id) > 0 {
                        pending_validators.push((validator_id, validator.subnet_id));
                    } else {
                        routable_validators.push((validator_id, validator.subnet_id));
                    }
                }
            }
            for (validator_id, subnet_id) in
                pending_validators.into_iter().chain(routable_validators)
            {
                match ActiveValidatorsBySubnet::<T>::try_mutate(subnet_id, |ids| {
                    Self::insert_sorted_validator_id(ids, validator_id)
                }) {
                    Ok(inserted) => {
                        if inserted {
                            validator_writes = validator_writes.saturating_add(1);
                        }
                    }
                    Err(_) => {
                        overflow_validators.push(validator_id);
                        migration_failures = migration_failures.saturating_add(1);
                    }
                }
            }

            let miner_exit_available_at =
                Self::current_block().saturating_add(T::MinerExitCooldownBlocks::get());
            for miner_id in overflow_miners {
                Miners::<T>::mutate(miner_id, |maybe_miner| {
                    if let Some(miner) = maybe_miner
                        && miner.status == RegistryStatus::Active
                        && PendingMinerRequests::<T>::get(miner_id) == 0
                    {
                        miner.status = RegistryStatus::Exiting {
                            exit_available_at: miner_exit_available_at,
                        };
                        miner.bond_commitment = Self::miner_bond_commitment(
                            miner_id,
                            miner.operator_commitment,
                            miner.status,
                        );
                    }
                });
                miner_reads = miner_reads.saturating_add(1);
                miner_writes = miner_writes.saturating_add(1);
            }

            let validator_exit_available_at =
                Self::current_block().saturating_add(T::ValidatorExitCooldownBlocks::get());
            for validator_id in overflow_validators {
                Validators::<T>::mutate(validator_id, |maybe_validator| {
                    if let Some(validator) = maybe_validator
                        && validator.status == RegistryStatus::Active
                        && PendingValidatorRequests::<T>::get(validator_id) == 0
                    {
                        validator.status = RegistryStatus::Exiting {
                            exit_available_at: validator_exit_available_at,
                        };
                        validator.stake_commitment = Self::validator_stake_commitment(
                            validator_id,
                            validator.operator_commitment,
                            validator.status,
                        );
                    }
                });
                validator_reads = validator_reads.saturating_add(1);
                validator_writes = validator_writes.saturating_add(1);
            }
            LegacyRoutingIndexMigrationFailures::<T>::put(migration_failures);

            T::DbWeight::get().reads_writes(
                miner_reads.saturating_add(validator_reads),
                miner_writes
                    .saturating_add(validator_writes)
                    .saturating_add(1),
            )
        }

        fn migrate_participant_capital_records(on_chain: StorageVersion) -> Weight {
            if on_chain >= StorageVersion::new(18) {
                return Weight::zero();
            }

            let mut miner_reads = 0_u64;
            let mut validator_reads = 0_u64;
            let mut missing = 0_u32;

            for (miner_id, miner) in Miners::<T>::iter() {
                miner_reads = miner_reads.saturating_add(1);
                if Self::miner_capital_bearing_status(miner.status) {
                    miner_reads = miner_reads.saturating_add(1);
                    if !MinerLockedBond::<T>::contains_key(miner_id) {
                        missing = missing.saturating_add(1);
                    }
                }
            }

            for (validator_id, validator) in Validators::<T>::iter() {
                validator_reads = validator_reads.saturating_add(1);
                if Self::validator_capital_bearing_status(validator.status) {
                    validator_reads = validator_reads.saturating_add(1);
                    if !ValidatorLockedStake::<T>::contains_key(validator_id) {
                        missing = missing.saturating_add(1);
                    }
                }
            }

            LegacyCapitalRecordMigrationFailures::<T>::put(missing);
            T::DbWeight::get().reads_writes(miner_reads.saturating_add(validator_reads), 1)
        }

        fn clear_pending_assignment_counters() -> Weight {
            let mut miner_reads = 0_u64;
            let mut miner_writes = 0_u64;
            let mut validator_reads = 0_u64;
            let mut validator_writes = 0_u64;

            for (miner_id, _) in PendingMinerRequests::<T>::iter() {
                PendingMinerRequests::<T>::remove(miner_id);
                miner_reads = miner_reads.saturating_add(1);
                miner_writes = miner_writes.saturating_add(1);
            }
            for (validator_id, _) in PendingValidatorRequests::<T>::iter() {
                PendingValidatorRequests::<T>::remove(validator_id);
                validator_reads = validator_reads.saturating_add(1);
                validator_writes = validator_writes.saturating_add(1);
            }

            T::DbWeight::get().reads_writes(
                miner_reads.saturating_add(validator_reads),
                miner_writes.saturating_add(validator_writes),
            )
        }

        fn zero_accounting() -> ChainAccounting<BalanceOf<T>> {
            ChainAccounting {
                total_inference_escrowed: BalanceOf::<T>::default(),
                total_miner_payouts: BalanceOf::<T>::default(),
                total_validator_fees: BalanceOf::<T>::default(),
                total_treasury_fees: BalanceOf::<T>::default(),
                total_inference_refunded: BalanceOf::<T>::default(),
                legacy_migration_failures: 0,
            }
        }

        fn record_legacy_request_accounting(
            accounting: &mut ChainAccounting<BalanceOf<T>>,
            payment: BalanceOf<T>,
            validator_fee_bps: u16,
            treasury_fee_bps: u16,
            status: InferenceRequestStatus,
        ) -> DispatchResult {
            let mut next = accounting.clone();
            Self::checked_accounting_add(&mut next.total_inference_escrowed, payment)?;
            match status {
                InferenceRequestStatus::Settled => {
                    let (miner_payment, validator_fee, treasury_fee) =
                        Self::payment_split(payment, validator_fee_bps, treasury_fee_bps)?;
                    Self::checked_accounting_add(&mut next.total_miner_payouts, miner_payment)?;
                    Self::checked_accounting_add(&mut next.total_validator_fees, validator_fee)?;
                    Self::checked_accounting_add(&mut next.total_treasury_fees, treasury_fee)?;
                }
                InferenceRequestStatus::Cancelled
                | InferenceRequestStatus::Rejected
                | InferenceRequestStatus::Expired => {
                    Self::checked_accounting_add(&mut next.total_inference_refunded, payment)?;
                }
                InferenceRequestStatus::Pending => {}
            }
            *accounting = next;
            Ok(())
        }

        fn checked_accounting_add(
            total: &mut BalanceOf<T>,
            amount: BalanceOf<T>,
        ) -> DispatchResult {
            *total = total
                .checked_add(&amount)
                .ok_or(Error::<T>::ArithmeticOverflow)?;
            Ok(())
        }

        fn note_legacy_accounting_failure(failures: &mut u32) {
            *failures = failures.saturating_add(1);
        }

        fn put_inference_accounting(accounting: ChainAccounting<BalanceOf<T>>, failures: u32) {
            let mut accounting = if failures == 0 {
                accounting
            } else {
                Self::zero_accounting()
            };
            accounting.legacy_migration_failures = failures;
            TotalInferenceEscrowed::<T>::put(accounting.total_inference_escrowed);
            TotalMinerPayouts::<T>::put(accounting.total_miner_payouts);
            TotalValidatorFees::<T>::put(accounting.total_validator_fees);
            TotalTreasuryFees::<T>::put(accounting.total_treasury_fees);
            TotalInferenceRefunded::<T>::put(accounting.total_inference_refunded);
            LegacyAccountingMigrationFailures::<T>::put(failures);
        }

        fn rebuild_request_status_counts() -> Weight {
            let mut request_reads = 0_u64;
            let mut counts = ChainRequestStatusCounts {
                pending: 0,
                settled: 0,
                cancelled: 0,
                rejected: 0,
                expired: 0,
            };

            for (_, request) in InferenceRequests::<T>::iter() {
                request_reads = request_reads.saturating_add(1);
                match request.status {
                    InferenceRequestStatus::Pending => {
                        counts.pending = counts.pending.saturating_add(1);
                    }
                    InferenceRequestStatus::Settled => {
                        counts.settled = counts.settled.saturating_add(1);
                    }
                    InferenceRequestStatus::Cancelled => {
                        counts.cancelled = counts.cancelled.saturating_add(1);
                    }
                    InferenceRequestStatus::Rejected => {
                        counts.rejected = counts.rejected.saturating_add(1);
                    }
                    InferenceRequestStatus::Expired => {
                        counts.expired = counts.expired.saturating_add(1);
                    }
                }
            }

            PendingInferenceRequestCount::<T>::put(counts.pending);
            SettledInferenceRequestCount::<T>::put(counts.settled);
            CancelledInferenceRequestCount::<T>::put(counts.cancelled);
            RejectedInferenceRequestCount::<T>::put(counts.rejected);
            ExpiredInferenceRequestCount::<T>::put(counts.expired);

            T::DbWeight::get().reads_writes(request_reads, 5)
        }

        fn migrate_proof_record_timestamps(on_chain: StorageVersion) -> Weight {
            if on_chain >= StorageVersion::new(5) {
                return Weight::zero();
            }

            let mut migrated = 0_u64;
            ProofRecords::<T>::translate::<ChainProofRecordV4, _>(|_, old| {
                migrated = migrated.saturating_add(1);
                let assignment_commitment = Self::legacy_request_assignment_commitment(
                    old.request_id,
                    old.subnet_id,
                    old.miner_id,
                    old.validator_id,
                );
                Some(ChainProofRecord {
                    request_id: old.request_id,
                    subnet_id: old.subnet_id,
                    assignment_commitment,
                    audit_commitment: Self::legacy_proof_audit_commitment(
                        old.request_id,
                        old.subnet_id,
                        assignment_commitment,
                        old.input_commitment,
                        old.output_commitment,
                        old.model_commitment,
                        &old.proof,
                        old.proof_system,
                        old.proof_size_bytes,
                        old.verification_latency_ms,
                        old.submitted_at,
                        old.submitted_at,
                    ),
                    proof_system: old.proof_system,
                })
            });

            T::DbWeight::get().reads_writes(migrated, migrated)
        }

        fn migrate_proof_record_assignment_commitments(on_chain: StorageVersion) -> Weight {
            if on_chain < StorageVersion::new(5) || on_chain >= StorageVersion::new(12) {
                return Weight::zero();
            }

            let mut migrated = 0_u64;
            ProofRecords::<T>::translate::<ChainProofRecordV11, _>(|_, old| {
                migrated = migrated.saturating_add(1);
                let assignment_commitment = Self::legacy_request_assignment_commitment(
                    old.request_id,
                    old.subnet_id,
                    old.miner_id,
                    old.validator_id,
                );
                Some(ChainProofRecord {
                    request_id: old.request_id,
                    subnet_id: old.subnet_id,
                    assignment_commitment,
                    audit_commitment: Self::legacy_proof_audit_commitment(
                        old.request_id,
                        old.subnet_id,
                        assignment_commitment,
                        old.input_commitment,
                        old.output_commitment,
                        old.model_commitment,
                        &old.proof,
                        old.proof_system,
                        old.proof_size_bytes,
                        old.verification_latency_ms,
                        old.submitted_at,
                        old.accepted_at,
                    ),
                    proof_system: old.proof_system,
                })
            });

            T::DbWeight::get().reads_writes(migrated, migrated)
        }

        fn migrate_proof_record_audit_commitments(on_chain: StorageVersion) -> Weight {
            if on_chain < StorageVersion::new(12) || on_chain >= StorageVersion::new(15) {
                return Weight::zero();
            }

            let mut migrated = 0_u64;
            ProofRecords::<T>::translate::<ChainProofRecordV14, _>(|_, old| {
                migrated = migrated.saturating_add(1);
                Some(ChainProofRecord {
                    request_id: old.request_id,
                    subnet_id: old.subnet_id,
                    assignment_commitment: old.assignment_commitment,
                    audit_commitment: Self::legacy_proof_audit_commitment(
                        old.request_id,
                        old.subnet_id,
                        old.assignment_commitment,
                        old.input_commitment,
                        old.output_commitment,
                        old.model_commitment,
                        &old.proof,
                        old.proof_system,
                        old.proof_size_bytes,
                        old.verification_latency_ms,
                        old.submitted_at,
                        old.accepted_at,
                    ),
                    proof_system: old.proof_system,
                })
            });

            T::DbWeight::get().reads_writes(migrated, migrated)
        }

        fn migrate_identity_signature_challenges(on_chain: StorageVersion) -> Weight {
            if on_chain >= StorageVersion::new(17) {
                return Weight::zero();
            }

            let mut scanned = 0_u64;
            let mut migrated = 0_u64;

            for (miner_id, _) in MinerIdentitySignatureBundles::<T>::iter() {
                scanned = scanned.saturating_add(1);
                if let (Some(commitments), Some(miner)) = (
                    MinerIdentityCommitments::<T>::get(miner_id),
                    Miners::<T>::get(miner_id),
                ) {
                    MinerIdentitySignatureChallenges::<T>::insert(
                        miner_id,
                        Self::miner_identity_signature_challenge(
                            miner_id,
                            miner.operator_commitment,
                            commitments.shielded_identity_commitment,
                            commitments.endpoint_commitment,
                        ),
                    );
                    migrated = migrated.saturating_add(1);
                }
            }

            for (validator_id, _) in ValidatorIdentitySignatureBundles::<T>::iter() {
                scanned = scanned.saturating_add(1);
                if let (Some(commitments), Some(validator)) = (
                    ValidatorIdentityCommitments::<T>::get(validator_id),
                    Validators::<T>::get(validator_id),
                ) {
                    ValidatorIdentitySignatureChallenges::<T>::insert(
                        validator_id,
                        Self::validator_identity_signature_challenge(
                            validator_id,
                            validator.operator_commitment,
                            commitments.shielded_identity_commitment,
                            commitments.endpoint_commitment,
                        ),
                    );
                    migrated = migrated.saturating_add(1);
                }
            }

            T::DbWeight::get().reads_writes(scanned.saturating_mul(3), migrated)
        }

        fn migrate_operator_commitments(on_chain: StorageVersion) -> Weight {
            if on_chain != StorageVersion::new(7) {
                return Weight::zero();
            }

            let mut migrated_miners = 0_u64;
            Miners::<T>::translate::<ChainMinerV7<T::AccountId, BalanceOf<T>>, _>(|_, old| {
                migrated_miners = migrated_miners.saturating_add(1);
                let operator_commitment = Self::operator_commitment(&old.operator);
                Some(ChainMiner {
                    id: old.id,
                    operator_commitment,
                    subnet_id: old.subnet_id,
                    model_commitment: old.model_commitment,
                    proof_system: old.proof_system,
                    bond_commitment: Self::miner_bond_commitment(
                        old.id,
                        operator_commitment,
                        old.status,
                    ),
                    status: old.status,
                })
            });

            let mut migrated_validators = 0_u64;
            Validators::<T>::translate::<ChainValidatorV7<T::AccountId, BalanceOf<T>>, _>(
                |_, old| {
                    migrated_validators = migrated_validators.saturating_add(1);
                    let operator_commitment = Self::operator_commitment(&old.operator);
                    Some(ChainValidator {
                        id: old.id,
                        operator_commitment,
                        subnet_id: old.subnet_id,
                        stake_commitment: Self::validator_stake_commitment(
                            old.id,
                            operator_commitment,
                            old.status,
                        ),
                        status: old.status,
                    })
                },
            );

            let migrated = migrated_miners.saturating_add(migrated_validators);
            T::DbWeight::get().reads_writes(migrated, migrated)
        }

        fn migrate_subnet_policy_commitments(on_chain: StorageVersion) -> Weight {
            if on_chain >= StorageVersion::new(16) {
                return Weight::zero();
            }

            let mut migrated = 0_u64;
            Subnets::<T>::translate::<ChainSubnetV15<T::AccountId, BalanceOf<T>>, _>(|_, old| {
                migrated = migrated.saturating_add(1);
                Some(ChainSubnet {
                    id: old.id,
                    owner_commitment: Self::subnet_owner_commitment(&old.owner),
                    domain: old.domain,
                    proof_system: old.proof_system,
                    policy_commitment: (
                        old.id,
                        old.domain,
                        old.proof_system,
                        old.creation_burn,
                        T::MinerRegistrationBurn::get(),
                        old.min_miner_bond,
                        old.max_miner_bond,
                        old.min_validator_stake,
                        T::MaxActiveMinersPerSubnet::get(),
                        T::MaxActiveValidatorsPerSubnet::get(),
                    )
                        .using_encoded(blake2_256),
                    active: old.active,
                })
            });

            T::DbWeight::get().reads_writes(migrated, migrated)
        }

        fn migrate_participant_capital_commitments(on_chain: StorageVersion) -> Weight {
            if on_chain < StorageVersion::new(8) || on_chain >= StorageVersion::new(10) {
                return Weight::zero();
            }

            let mut migrated_miners = 0_u64;
            Miners::<T>::translate::<ChainMinerV9<BalanceOf<T>>, _>(|_, old| {
                migrated_miners = migrated_miners.saturating_add(1);
                Some(ChainMiner {
                    id: old.id,
                    operator_commitment: old.operator_commitment,
                    subnet_id: old.subnet_id,
                    model_commitment: old.model_commitment,
                    proof_system: old.proof_system,
                    bond_commitment: Self::miner_bond_commitment(
                        old.id,
                        old.operator_commitment,
                        old.status,
                    ),
                    status: old.status,
                })
            });

            let mut migrated_validators = 0_u64;
            Validators::<T>::translate::<ChainValidatorV9<BalanceOf<T>>, _>(|_, old| {
                migrated_validators = migrated_validators.saturating_add(1);
                Some(ChainValidator {
                    id: old.id,
                    operator_commitment: old.operator_commitment,
                    subnet_id: old.subnet_id,
                    stake_commitment: Self::validator_stake_commitment(
                        old.id,
                        old.operator_commitment,
                        old.status,
                    ),
                    status: old.status,
                })
            });

            let migrated = migrated_miners.saturating_add(migrated_validators);
            T::DbWeight::get().reads_writes(migrated, migrated)
        }

        fn migrate_request_owner_commitments(on_chain: StorageVersion) -> Weight {
            if on_chain < StorageVersion::new(7) || on_chain >= StorageVersion::new(9) {
                return Weight::zero();
            }

            let clear_weight = Self::clear_pending_assignment_counters();
            let mut accounting = Self::zero_accounting();
            let mut accounting_failures = 0_u32;
            let mut migrated = 0_u64;
            InferenceRequests::<T>::translate::<
                ChainInferenceRequestV8<T::AccountId, BalanceOf<T>>,
                _,
            >(|_, old| {
                migrated = migrated.saturating_add(1);
                if Self::record_legacy_request_accounting(
                    &mut accounting,
                    old.payment,
                    old.validator_fee_bps,
                    old.treasury_fee_bps,
                    old.status,
                )
                .is_err()
                {
                    Self::note_legacy_accounting_failure(&mut accounting_failures);
                }
                if old.status == InferenceRequestStatus::Pending {
                    let _ = Self::increment_pending_assignment(old.miner_id, old.validator_id);
                }
                Some(ChainInferenceRequest {
                    request_id: old.request_id,
                    user_commitment: Self::request_user_commitment(&old.user),
                    subnet_id: old.subnet_id,
                    assignment_commitment: Self::legacy_request_assignment_commitment(
                        old.request_id,
                        old.subnet_id,
                        old.miner_id,
                        old.validator_id,
                    ),
                    input_commitment: old.input_commitment,
                    terms_commitment: Self::legacy_request_terms_commitment(
                        old.request_id,
                        old.payment,
                        old.validator_fee_bps,
                        old.treasury_fee_bps,
                    ),
                    timing_commitment: Self::legacy_request_timing_commitment(
                        old.request_id,
                        old.created_at,
                    ),
                    status: old.status,
                })
            });
            Self::put_inference_accounting(accounting, accounting_failures);

            clear_weight.saturating_add(
                T::DbWeight::get().reads_writes(migrated, migrated.saturating_add(6)),
            )
        }

        fn migrate_request_assignment_commitments(on_chain: StorageVersion) -> Weight {
            if on_chain < StorageVersion::new(9) || on_chain >= StorageVersion::new(11) {
                return Weight::zero();
            }

            let clear_weight = Self::clear_pending_assignment_counters();
            let mut accounting = Self::zero_accounting();
            let mut accounting_failures = 0_u32;
            let mut migrated = 0_u64;
            InferenceRequests::<T>::translate::<ChainInferenceRequestV10<BalanceOf<T>>, _>(
                |_, old| {
                    migrated = migrated.saturating_add(1);
                    if Self::record_legacy_request_accounting(
                        &mut accounting,
                        old.payment,
                        old.validator_fee_bps,
                        old.treasury_fee_bps,
                        old.status,
                    )
                    .is_err()
                    {
                        Self::note_legacy_accounting_failure(&mut accounting_failures);
                    }
                    if old.status == InferenceRequestStatus::Pending {
                        let _ = Self::increment_pending_assignment(old.miner_id, old.validator_id);
                    }
                    Some(ChainInferenceRequest {
                        request_id: old.request_id,
                        user_commitment: old.user_commitment,
                        subnet_id: old.subnet_id,
                        assignment_commitment: Self::legacy_request_assignment_commitment(
                            old.request_id,
                            old.subnet_id,
                            old.miner_id,
                            old.validator_id,
                        ),
                        input_commitment: old.input_commitment,
                        terms_commitment: Self::legacy_request_terms_commitment(
                            old.request_id,
                            old.payment,
                            old.validator_fee_bps,
                            old.treasury_fee_bps,
                        ),
                        timing_commitment: Self::legacy_request_timing_commitment(
                            old.request_id,
                            old.created_at,
                        ),
                        status: old.status,
                    })
                },
            );
            Self::put_inference_accounting(accounting, accounting_failures);

            clear_weight.saturating_add(
                T::DbWeight::get().reads_writes(migrated, migrated.saturating_add(6)),
            )
        }

        fn migrate_request_timing_commitments(on_chain: StorageVersion) -> Weight {
            if on_chain < StorageVersion::new(11) || on_chain >= StorageVersion::new(13) {
                return Weight::zero();
            }

            let mut accounting = Self::zero_accounting();
            let mut accounting_failures = 0_u32;
            let mut migrated = 0_u64;
            InferenceRequests::<T>::translate::<ChainInferenceRequestV12<BalanceOf<T>>, _>(
                |_, old| {
                    migrated = migrated.saturating_add(1);
                    if Self::record_legacy_request_accounting(
                        &mut accounting,
                        old.payment,
                        old.validator_fee_bps,
                        old.treasury_fee_bps,
                        old.status,
                    )
                    .is_err()
                    {
                        Self::note_legacy_accounting_failure(&mut accounting_failures);
                    }
                    Some(ChainInferenceRequest {
                        request_id: old.request_id,
                        user_commitment: old.user_commitment,
                        subnet_id: old.subnet_id,
                        assignment_commitment: old.assignment_commitment,
                        input_commitment: old.input_commitment,
                        terms_commitment: Self::legacy_request_terms_commitment(
                            old.request_id,
                            old.payment,
                            old.validator_fee_bps,
                            old.treasury_fee_bps,
                        ),
                        timing_commitment: Self::legacy_request_timing_commitment(
                            old.request_id,
                            old.created_at,
                        ),
                        status: old.status,
                    })
                },
            );
            Self::put_inference_accounting(accounting, accounting_failures);

            T::DbWeight::get().reads_writes(migrated, migrated.saturating_add(6))
        }

        fn migrate_request_terms_commitments(on_chain: StorageVersion) -> Weight {
            if on_chain < StorageVersion::new(13) || on_chain >= StorageVersion::new(14) {
                return Weight::zero();
            }

            let mut accounting = Self::zero_accounting();
            let mut accounting_failures = 0_u32;
            let mut migrated = 0_u64;
            InferenceRequests::<T>::translate::<ChainInferenceRequestV13<BalanceOf<T>>, _>(
                |_, old| {
                    migrated = migrated.saturating_add(1);
                    if Self::record_legacy_request_accounting(
                        &mut accounting,
                        old.payment,
                        old.validator_fee_bps,
                        old.treasury_fee_bps,
                        old.status,
                    )
                    .is_err()
                    {
                        Self::note_legacy_accounting_failure(&mut accounting_failures);
                    }
                    Some(ChainInferenceRequest {
                        request_id: old.request_id,
                        user_commitment: old.user_commitment,
                        subnet_id: old.subnet_id,
                        assignment_commitment: old.assignment_commitment,
                        input_commitment: old.input_commitment,
                        terms_commitment: Self::legacy_request_terms_commitment(
                            old.request_id,
                            old.payment,
                            old.validator_fee_bps,
                            old.treasury_fee_bps,
                        ),
                        timing_commitment: old.timing_commitment,
                        status: old.status,
                    })
                },
            );
            Self::put_inference_accounting(accounting, accounting_failures);

            T::DbWeight::get().reads_writes(migrated, migrated.saturating_add(6))
        }

        #[cfg(feature = "try-runtime")]
        fn ensure_active_routing_indexes_match() -> Result<(), sp_runtime::TryRuntimeError> {
            for (subnet_id, miner_ids) in ActiveMinersBySubnet::<T>::iter() {
                for miner_id in miner_ids {
                    let miner = Miners::<T>::get(miner_id)
                        .ok_or("Qubitum active miner index references missing miner")?;
                    ensure!(
                        miner.subnet_id == subnet_id && miner.status == RegistryStatus::Active,
                        "Qubitum active miner index references inactive or wrong-subnet miner"
                    );
                    ensure!(
                        Self::ensure_miner_signature_bundle_bound(miner_id, &miner).is_ok(),
                        "Qubitum active miner index references identity-ineligible miner"
                    );
                }
            }

            for (miner_id, miner) in Miners::<T>::iter() {
                if miner.status == RegistryStatus::Active
                    && Self::ensure_miner_signature_bundle_bound(miner_id, &miner).is_ok()
                {
                    let active_miners = ActiveMinersBySubnet::<T>::get(miner.subnet_id);
                    ensure!(
                        active_miners.contains(&miner_id)
                            || active_miners.len() as u32 >= T::MaxActiveMinersPerSubnet::get(),
                        "Qubitum active identity-eligible miner missing from non-full route index"
                    );
                }
            }

            for (subnet_id, validator_ids) in ActiveValidatorsBySubnet::<T>::iter() {
                for validator_id in validator_ids {
                    let validator = Validators::<T>::get(validator_id)
                        .ok_or("Qubitum active validator index references missing validator")?;
                    ensure!(
                        validator.subnet_id == subnet_id
                            && validator.status == RegistryStatus::Active,
                        "Qubitum active validator index references inactive or wrong-subnet validator"
                    );
                    ensure!(
                        Self::validator_has_active_locked_stake_record(validator_id),
                        "Qubitum active validator index references undercapitalized validator"
                    );
                    ensure!(
                        Self::ensure_validator_signature_bundle_bound(validator_id, &validator)
                            .is_ok(),
                        "Qubitum active validator index references identity-ineligible validator"
                    );
                }
            }

            for (validator_id, validator) in Validators::<T>::iter() {
                if validator.status == RegistryStatus::Active
                    && Self::validator_has_active_locked_stake_record(validator_id)
                    && Self::ensure_validator_signature_bundle_bound(validator_id, &validator)
                        .is_ok()
                {
                    let active_validators = ActiveValidatorsBySubnet::<T>::get(validator.subnet_id);
                    ensure!(
                        active_validators.contains(&validator_id)
                            || active_validators.len() as u32
                                >= T::MaxActiveValidatorsPerSubnet::get(),
                        "Qubitum active identity-eligible validator missing from non-full route index"
                    );
                }
            }

            for (miner_id, count) in PendingMinerRequests::<T>::iter() {
                ensure!(count > 0, "Qubitum pending miner counter is zero");
                let miner = Miners::<T>::get(miner_id)
                    .ok_or("Qubitum pending miner counter references missing miner")?;
                ensure!(
                    matches!(
                        miner.status,
                        RegistryStatus::Active
                            | RegistryStatus::Slashed
                            | RegistryStatus::Exiting { .. }
                    ),
                    "Qubitum pending miner counter references invalid miner status"
                );
            }

            for (validator_id, count) in PendingValidatorRequests::<T>::iter() {
                ensure!(count > 0, "Qubitum pending validator counter is zero");
                let validator = Validators::<T>::get(validator_id)
                    .ok_or("Qubitum pending validator counter references missing validator")?;
                ensure!(
                    matches!(
                        validator.status,
                        RegistryStatus::Active
                            | RegistryStatus::Slashed
                            | RegistryStatus::Exiting { .. }
                    ),
                    "Qubitum pending validator counter references invalid validator status"
                );
            }

            let mut expected_status_counts = ChainRequestStatusCounts {
                pending: 0,
                settled: 0,
                cancelled: 0,
                rejected: 0,
                expired: 0,
            };
            for (_, request) in InferenceRequests::<T>::iter() {
                match request.status {
                    InferenceRequestStatus::Pending => {
                        expected_status_counts.pending =
                            expected_status_counts.pending.saturating_add(1);
                    }
                    InferenceRequestStatus::Settled => {
                        expected_status_counts.settled =
                            expected_status_counts.settled.saturating_add(1);
                    }
                    InferenceRequestStatus::Cancelled => {
                        expected_status_counts.cancelled =
                            expected_status_counts.cancelled.saturating_add(1);
                    }
                    InferenceRequestStatus::Rejected => {
                        expected_status_counts.rejected =
                            expected_status_counts.rejected.saturating_add(1);
                    }
                    InferenceRequestStatus::Expired => {
                        expected_status_counts.expired =
                            expected_status_counts.expired.saturating_add(1);
                    }
                }
            }
            ensure!(
                Self::raw_request_status_counts() == expected_status_counts,
                "Qubitum request status counter mismatch"
            );

            Ok(())
        }

        fn burn_free(who: &T::AccountId, amount: BalanceOf<T>) -> DispatchResult {
            Self::ensure_burned_can_record(amount)?;
            let burned = T::Currency::burn_from(
                who,
                amount,
                Preservation::Expendable,
                Precision::Exact,
                Fortitude::Polite,
            )?;
            Self::record_burned(burned)
        }

        fn ensure_request_assignment(
            subnet_id: SubnetId,
            miner_id: MinerId,
            validator_id: ValidatorId,
        ) -> DispatchResult {
            let miner = Miners::<T>::get(miner_id).ok_or(Error::<T>::UnknownMiner)?;
            let validator =
                Validators::<T>::get(validator_id).ok_or(Error::<T>::UnknownValidator)?;
            ensure!(
                miner.subnet_id == subnet_id && validator.subnet_id == subnet_id,
                Error::<T>::ParticipantMismatch
            );
            ensure!(
                miner.status == RegistryStatus::Active
                    && validator.status == RegistryStatus::Active,
                Error::<T>::NotActive
            );
            Self::ensure_distinct_operators(&miner, &validator)?;
            Self::ensure_participant_signature_bundles(miner_id, validator_id)?;
            Ok(())
        }

        fn ensure_distinct_operators(
            miner: &ChainMiner,
            validator: &ChainValidator,
        ) -> DispatchResult {
            ensure!(
                miner.operator_commitment != validator.operator_commitment,
                Error::<T>::SelfValidation
            );
            Ok(())
        }

        fn validate_submission(
            submission: &InferenceProofSubmission,
            validator_operator: &T::AccountId,
            miner_operator: &T::AccountId,
            assignment_blinding: Commitment,
        ) -> Result<ProofVerificationPolicy, DispatchError> {
            let (policy, miner, validator) =
                Self::validate_submission_for_request(submission, assignment_blinding)?;
            Self::ensure_miner_operator(&miner, miner_operator)?;
            Self::ensure_validator_submission_operator(&validator, validator_operator)?;
            Ok(policy)
        }

        fn validate_challenge_submission(
            submission: &InferenceProofSubmission,
            miner_operator: &T::AccountId,
            assignment_blinding: Commitment,
        ) -> Result<ProofVerificationPolicy, DispatchError> {
            let (policy, miner, _) =
                Self::validate_submission_for_request(submission, assignment_blinding)?;
            Self::ensure_miner_operator(&miner, miner_operator)?;
            Ok(policy)
        }

        fn validate_submission_for_request(
            submission: &InferenceProofSubmission,
            assignment_blinding: Commitment,
        ) -> Result<(ProofVerificationPolicy, ChainMiner, ChainValidator), DispatchError> {
            ensure_commitment::<T>(submission.input_commitment)?;
            ensure_commitment::<T>(submission.output_commitment)?;
            ensure_commitment::<T>(submission.model_commitment)?;
            ensure_proof_envelope::<T>(&submission.proof, submission.proof_system)?;
            ensure!(
                !ProofRecords::<T>::contains_key(submission.request_id),
                Error::<T>::DuplicateProof
            );
            let request = InferenceRequests::<T>::get(submission.request_id)
                .ok_or(Error::<T>::UnknownRequest)?;
            ensure!(
                request.status == InferenceRequestStatus::Pending,
                Error::<T>::RequestAlreadySettled
            );
            ensure!(
                request.subnet_id == submission.subnet_id
                    && request.input_commitment == submission.input_commitment,
                Error::<T>::RequestMismatch
            );
            Self::ensure_request_assignment_witness(
                &request,
                submission.miner_id,
                submission.validator_id,
                assignment_blinding,
            )?;

            let subnet =
                Subnets::<T>::get(submission.subnet_id).ok_or(Error::<T>::UnknownSubnet)?;
            ensure!(
                subnet.proof_system == submission.proof_system,
                Error::<T>::ProofSystemMismatch
            );
            ensure!(
                submission.proof_size_bytes >= T::MinProofSizeBytes::get()
                    && submission.proof_size_bytes <= T::MaxProofSizeBytes::get(),
                Error::<T>::InvalidProofSize
            );
            ensure!(
                submission.verification_latency_ms <= T::MaxVerificationLatencyMs::get(),
                Error::<T>::LatencyExceeded
            );
            Self::ensure_submission_fresh(submission.submitted_at)?;
            Self::ensure_proof_transcript_witness(submission)?;

            let miner = Miners::<T>::get(submission.miner_id).ok_or(Error::<T>::UnknownMiner)?;
            ensure!(
                miner.subnet_id == submission.subnet_id && miner.status == RegistryStatus::Active,
                Error::<T>::NotActive
            );
            ensure!(
                miner.model_commitment == submission.model_commitment,
                Error::<T>::ModelCommitmentMismatch
            );
            let validator = Validators::<T>::get(submission.validator_id)
                .ok_or(Error::<T>::UnknownValidator)?;
            ensure!(
                validator.subnet_id == submission.subnet_id
                    && validator.status == RegistryStatus::Active,
                Error::<T>::NotActive
            );
            Self::ensure_distinct_operators(&miner, &validator)?;
            Self::ensure_participant_signature_bundles(
                submission.miner_id,
                submission.validator_id,
            )?;

            Ok((
                ProofVerificationPolicy {
                    proof_system: subnet.proof_system,
                    model_commitment: miner.model_commitment,
                    min_proof_size_bytes: T::MinProofSizeBytes::get(),
                    max_proof_size_bytes: T::MaxProofSizeBytes::get(),
                    max_verification_latency_ms: T::MaxVerificationLatencyMs::get(),
                },
                miner,
                validator,
            ))
        }

        fn ensure_submission_fresh(submitted_at: BlockNumber) -> DispatchResult {
            let current = Self::current_block();
            ensure!(
                submitted_at <= current,
                Error::<T>::ProofSubmittedFromFuture
            );
            ensure!(
                submitted_at >= current.saturating_sub(T::MaxProofSubmissionAgeBlocks::get()),
                Error::<T>::ProofSubmissionExpired
            );
            Ok(())
        }

        fn settle_request_payment(
            submission: &InferenceProofSubmission,
            request_user: &T::AccountId,
            miner_operator: &T::AccountId,
            validator_operator: &T::AccountId,
            assignment_blinding: Commitment,
            terms_witness: &InferenceRequestTermsWitness<BalanceOf<T>>,
        ) -> Result<(BalanceOf<T>, BalanceOf<T>, BalanceOf<T>), DispatchError> {
            InferenceRequests::<T>::try_mutate(
                submission.request_id,
                |maybe_request| -> Result<(BalanceOf<T>, BalanceOf<T>, BalanceOf<T>), DispatchError> {
                    let request = maybe_request.as_mut().ok_or(Error::<T>::UnknownRequest)?;
                    ensure!(
                        request.status == InferenceRequestStatus::Pending,
                        Error::<T>::RequestAlreadySettled
                    );
                    ensure!(
                        request.subnet_id == submission.subnet_id
                            && request.input_commitment == submission.input_commitment,
                        Error::<T>::RequestMismatch
                    );
                    Self::ensure_request_assignment_witness(
                        request,
                        submission.miner_id,
                        submission.validator_id,
                        assignment_blinding,
                    )?;
                    Self::ensure_request_user(request, request_user)?;
                    Self::ensure_request_terms_witness(request, terms_witness)?;
                    let terms = &terms_witness.terms;

                    let miner =
                        Miners::<T>::get(submission.miner_id).ok_or(Error::<T>::UnknownMiner)?;
                    let validator = Validators::<T>::get(submission.validator_id)
                        .ok_or(Error::<T>::UnknownValidator)?;
                    Self::ensure_miner_operator(&miner, miner_operator)?;
                    Self::ensure_validator_operator(&validator, validator_operator)?;
                    let (miner_payment, validator_fee, treasury_fee) = Self::payment_split(
                        terms.payment,
                        terms.validator_fee_bps,
                        terms.treasury_fee_bps,
                    )?;
                    Self::ensure_inference_settlement_can_record(
                        miner_payment,
                        validator_fee,
                        treasury_fee,
                    )?;

                    Self::transfer_held_payment(request_user, miner_operator, miner_payment)?;
                    Self::transfer_held_payment(request_user, validator_operator, validator_fee)?;
                    Self::transfer_held_payment(
                        request_user,
                        &T::ProtocolTreasury::get(),
                        treasury_fee,
                    )?;
                    request.status = InferenceRequestStatus::Settled;
                    Self::decrement_pending_assignment(submission.miner_id, submission.validator_id)?;
                    Self::transition_request_status(
                        InferenceRequestStatus::Pending,
                        InferenceRequestStatus::Settled,
                    )?;
                    Self::record_inference_settlement(
                        miner_payment,
                        validator_fee,
                        treasury_fee,
                    )?;

                    Ok((miner_payment, validator_fee, treasury_fee))
                },
            )
        }

        fn refund_rejected_request(
            submission: &InferenceProofSubmission,
            request_user: &T::AccountId,
            assignment_blinding: Commitment,
            terms_witness: &InferenceRequestTermsWitness<BalanceOf<T>>,
        ) -> Result<BalanceOf<T>, DispatchError> {
            InferenceRequests::<T>::try_mutate(
                submission.request_id,
                |maybe_request| -> Result<BalanceOf<T>, DispatchError> {
                    let request = maybe_request.as_mut().ok_or(Error::<T>::UnknownRequest)?;
                    Self::ensure_rejected_request_witnesses(
                        request,
                        submission,
                        request_user,
                        assignment_blinding,
                        terms_witness,
                    )?;
                    let terms = &terms_witness.terms;
                    Self::ensure_inference_refund_can_record(terms.payment)?;

                    T::Currency::release(
                        &HoldReason::InferencePayment.into(),
                        request_user,
                        terms.payment,
                        Precision::Exact,
                    )?;
                    request.status = InferenceRequestStatus::Rejected;
                    Self::decrement_pending_assignment(
                        submission.miner_id,
                        submission.validator_id,
                    )?;
                    Self::transition_request_status(
                        InferenceRequestStatus::Pending,
                        InferenceRequestStatus::Rejected,
                    )?;
                    Self::record_inference_refund(terms.payment)?;

                    Ok(terms.payment)
                },
            )
        }

        fn ensure_rejected_request_refundable(
            submission: &InferenceProofSubmission,
            request_user: &T::AccountId,
            assignment_blinding: Commitment,
            terms_witness: &InferenceRequestTermsWitness<BalanceOf<T>>,
        ) -> DispatchResult {
            let request = InferenceRequests::<T>::get(submission.request_id)
                .ok_or(Error::<T>::UnknownRequest)?;
            Self::ensure_rejected_request_witnesses(
                &request,
                submission,
                request_user,
                assignment_blinding,
                terms_witness,
            )?;
            Self::ensure_inference_refund_can_record(terms_witness.terms.payment)
        }

        fn ensure_rejected_request_witnesses(
            request: &ChainInferenceRequest,
            submission: &InferenceProofSubmission,
            request_user: &T::AccountId,
            assignment_blinding: Commitment,
            terms_witness: &InferenceRequestTermsWitness<BalanceOf<T>>,
        ) -> DispatchResult {
            ensure!(
                request.status == InferenceRequestStatus::Pending,
                Error::<T>::RequestAlreadySettled
            );
            ensure!(
                request.subnet_id == submission.subnet_id
                    && request.input_commitment == submission.input_commitment,
                Error::<T>::RequestMismatch
            );
            Self::ensure_request_assignment_witness(
                request,
                submission.miner_id,
                submission.validator_id,
                assignment_blinding,
            )?;
            Self::ensure_request_user(request, request_user)?;
            Self::ensure_request_terms_witness(request, terms_witness)
        }

        fn validate_fee_split(validator_fee_bps: u16, treasury_fee_bps: u16) -> DispatchResult {
            let combined = validator_fee_bps
                .checked_add(treasury_fee_bps)
                .ok_or(Error::<T>::ArithmeticOverflow)?;
            ensure!(
                combined <= qubitum_protocol::BPS_DENOMINATOR,
                Error::<T>::InvalidFeeSplit
            );
            Ok(())
        }

        fn payment_split(
            payment: BalanceOf<T>,
            validator_fee_bps: u16,
            treasury_fee_bps: u16,
        ) -> Result<(BalanceOf<T>, BalanceOf<T>, BalanceOf<T>), DispatchError> {
            Self::validate_fee_split(validator_fee_bps, treasury_fee_bps)?;
            let validator_fee = pro_rata::<T>(payment, validator_fee_bps)?;
            let treasury_fee = pro_rata::<T>(payment, treasury_fee_bps)?;
            let assigned = validator_fee
                .checked_add(&treasury_fee)
                .ok_or(Error::<T>::ArithmeticOverflow)?;
            let miner_payment = payment
                .checked_sub(&assigned)
                .ok_or(Error::<T>::ArithmeticOverflow)?;
            Ok((miner_payment, validator_fee, treasury_fee))
        }

        fn transfer_held_payment(
            source: &T::AccountId,
            dest: &T::AccountId,
            amount: BalanceOf<T>,
        ) -> DispatchResult {
            if amount == BalanceOf::<T>::default() {
                return Ok(());
            }

            T::Currency::transfer_on_hold(
                &HoldReason::InferencePayment.into(),
                source,
                dest,
                amount,
                Precision::Exact,
                Restriction::Free,
                Fortitude::Polite,
            )?;
            Ok(())
        }

        fn slash_miner_bond(
            miner_id: MinerId,
            operator: &T::AccountId,
            slash_bps: u16,
        ) -> Result<BalanceOf<T>, DispatchError> {
            ensure!(
                slash_bps >= T::MinInvalidProofSlashBps::get()
                    && slash_bps <= T::MaxInvalidProofSlashBps::get(),
                Error::<T>::InvalidSlashPercent
            );

            let amount = Miners::<T>::try_mutate(miner_id, |maybe_miner| {
                let miner = maybe_miner.as_mut().ok_or(Error::<T>::UnknownMiner)?;
                Self::ensure_miner_operator(miner, operator)?;
                let current_bond = Self::locked_miner_bond(miner_id, operator)?;
                let slash_amount = pro_rata::<T>(current_bond, slash_bps)?;
                Self::ensure_burned_can_record(slash_amount)?;
                let burned = T::Currency::burn_held(
                    &HoldReason::MinerBond.into(),
                    operator,
                    slash_amount,
                    Precision::Exact,
                    Fortitude::Force,
                )?;
                let remaining_bond = current_bond
                    .checked_sub(&burned)
                    .ok_or(Error::<T>::ArithmeticOverflow)?;
                MinerLockedBond::<T>::insert(miner_id, remaining_bond);
                if remaining_bond < T::MinMinerBond::get()
                    && !matches!(miner.status, RegistryStatus::Exiting { .. })
                {
                    Self::remove_active_miner(miner.subnet_id, miner_id);
                    miner.status = RegistryStatus::Slashed;
                }
                miner.bond_commitment =
                    Self::miner_bond_commitment(miner_id, miner.operator_commitment, miner.status);
                Ok::<BalanceOf<T>, DispatchError>(burned)
            })?;

            Self::record_burned(amount)?;
            Ok(amount)
        }

        fn slash_validator_stake(
            validator_id: ValidatorId,
            operator: &T::AccountId,
            slash_bps: u16,
        ) -> Result<BalanceOf<T>, DispatchError> {
            ensure!(
                slash_bps >= T::MinInvalidProofSlashBps::get()
                    && slash_bps <= T::MaxInvalidProofSlashBps::get(),
                Error::<T>::InvalidSlashPercent
            );

            let amount = Validators::<T>::try_mutate(validator_id, |maybe_validator| {
                let validator = maybe_validator
                    .as_mut()
                    .ok_or(Error::<T>::UnknownValidator)?;
                Self::ensure_validator_operator(validator, operator)?;
                let current_stake = Self::locked_validator_stake(validator_id, operator)?;
                let slash_amount = pro_rata::<T>(current_stake, slash_bps)?;
                Self::ensure_burned_can_record(slash_amount)?;
                let burned = T::Currency::burn_held(
                    &HoldReason::ValidatorStake.into(),
                    operator,
                    slash_amount,
                    Precision::Exact,
                    Fortitude::Force,
                )?;
                let remaining_stake = current_stake
                    .checked_sub(&burned)
                    .ok_or(Error::<T>::ArithmeticOverflow)?;
                ValidatorLockedStake::<T>::insert(validator_id, remaining_stake);
                if remaining_stake < T::MinValidatorStake::get()
                    && !matches!(validator.status, RegistryStatus::Exiting { .. })
                {
                    Self::remove_active_validator(validator.subnet_id, validator_id);
                    validator.status = RegistryStatus::Slashed;
                }
                validator.stake_commitment = Self::validator_stake_commitment(
                    validator_id,
                    validator.operator_commitment,
                    validator.status,
                );
                Ok::<BalanceOf<T>, DispatchError>(burned)
            })?;

            Self::record_burned(amount)?;
            Ok(amount)
        }

        fn ensure_burned_can_record(amount: BalanceOf<T>) -> DispatchResult {
            TotalBurned::<T>::get()
                .checked_add(&amount)
                .ok_or(Error::<T>::ArithmeticOverflow)?;
            Ok(())
        }

        fn record_burned(amount: BalanceOf<T>) -> DispatchResult {
            TotalBurned::<T>::try_mutate(|total| -> DispatchResult {
                *total = total
                    .checked_add(&amount)
                    .ok_or(Error::<T>::ArithmeticOverflow)?;
                Ok(())
            })
        }
    }
}

fn ensure_commitment<T: Config>(commitment: Commitment) -> DispatchResult {
    ensure!(commitment != [0; 32], pallet::Error::<T>::MissingCommitment);
    Ok(())
}

fn ensure_proof_envelope<T: Config>(
    proof: &ProofEnvelope,
    proof_system: ProofSystem,
) -> DispatchResult {
    ensure_commitment::<T>(proof.proof_commitment)?;
    ensure_commitment::<T>(proof.journal_commitment)?;
    ensure_commitment::<T>(proof.image_id)?;
    ensure!(
        proof.verifier_version.supports(proof_system),
        pallet::Error::<T>::ProofSystemMismatch
    );
    Ok(())
}

fn pro_rata<T: Config>(amount: BalanceOf<T>, bps: u16) -> Result<BalanceOf<T>, DispatchError> {
    let bps: BalanceOf<T> = u64::from(bps).saturated_into();
    let denominator: BalanceOf<T> = u64::from(qubitum_protocol::BPS_DENOMINATOR).saturated_into();
    amount
        .checked_mul(&bps)
        .and_then(|value| value.checked_div(&denominator))
        .ok_or_else(|| pallet::Error::<T>::ArithmeticOverflow.into())
}
