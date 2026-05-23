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
    traits::tokens::{
        Fortitude, Precision, Preservation, Restriction,
        fungible::{self, InspectHold as _, Mutate as _, MutateHold as _},
    },
};
use qubitum_protocol::{
    BlockNumber, Commitment, InferenceProofSubmission, MinerId, ProofEnvelope, ProofSystem,
    RegistryStatus, RequestId, SignatureBundle, SignatureMode, SignaturePolicy, SubnetDomain,
    SubnetId, ValidatorId, VerificationOutcome,
};
use scale_info::TypeInfo;
use sp_io::hashing::blake2_256;
use sp_runtime::{DispatchError, Saturating, traits::SaturatedConversion};

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
    fn verify(
        submission: &InferenceProofSubmission,
        policy: ProofVerificationPolicy,
    ) -> Result<VerificationOutcome, DispatchError>;
}

/// Shape-only verifier used until a concrete zkVM verifier is wired in.
pub struct ShapeProofVerifier;

impl VerifyProof for ShapeProofVerifier {
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

    const STORAGE_VERSION: StorageVersion = StorageVersion::new(15);
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

    #[derive(
        Encode, Decode, DecodeWithMemTracking, TypeInfo, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
    )]
    pub struct ChainSubnet<AccountId, Balance> {
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
        pub id: SubnetId,
        pub domain: SubnetDomain,
        pub proof_system: ProofSystem,
        pub active: bool,
    }

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

    #[derive(Decode)]
    struct ChainMinerV7<AccountId, Balance> {
        pub id: MinerId,
        pub operator: AccountId,
        pub subnet_id: SubnetId,
        pub model_commitment: Commitment,
        pub proof_system: ProofSystem,
        pub bond: Balance,
        pub status: RegistryStatus,
    }

    #[derive(Decode)]
    struct ChainValidatorV7<AccountId, Balance> {
        pub id: ValidatorId,
        pub operator: AccountId,
        pub subnet_id: SubnetId,
        pub stake: Balance,
        pub status: RegistryStatus,
    }

    #[derive(Decode)]
    struct ChainMinerV9<Balance> {
        pub id: MinerId,
        pub operator_commitment: Commitment,
        pub subnet_id: SubnetId,
        pub model_commitment: Commitment,
        pub proof_system: ProofSystem,
        pub bond: Balance,
        pub status: RegistryStatus,
    }

    #[derive(Decode)]
    struct ChainValidatorV9<Balance> {
        pub id: ValidatorId,
        pub operator_commitment: Commitment,
        pub subnet_id: SubnetId,
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
        pub id: MinerId,
        pub subnet_id: SubnetId,
        pub proof_system: ProofSystem,
        pub status: PublicRegistryStatus,
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
    pub struct ChainPublicValidator {
        pub id: ValidatorId,
        pub subnet_id: SubnetId,
        pub status: PublicRegistryStatus,
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
    pub struct ChainIdentityCommitments {
        pub shielded_identity_commitment: Option<Commitment>,
        pub endpoint_commitment: Option<Commitment>,
    }

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
        pub request_id: RequestId,
        pub subnet_id: SubnetId,
        pub proof_system: ProofSystem,
    }

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
        pub request_id: RequestId,
        pub subnet_id: SubnetId,
        pub status: InferenceRequestStatus,
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
    pub(crate) struct ChainAssignment {
        pub request_id: RequestId,
        pub subnet_id: SubnetId,
        pub miner_id: MinerId,
        pub validator_id: ValidatorId,
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
    pub struct ChainRouteAvailability {
        pub request_id: RequestId,
        pub subnet_id: SubnetId,
        pub available: bool,
    }

    #[derive(
        Encode, Decode, DecodeWithMemTracking, TypeInfo, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
    )]
    pub struct ChainAccounting<Balance> {
        pub total_inference_escrowed: Balance,
        pub total_miner_payouts: Balance,
        pub total_validator_fees: Balance,
        pub total_treasury_fees: Balance,
        pub total_inference_refunded: Balance,
    }

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
        pub signature_mode: SignatureMode,
        pub miner_exit_cooldown_blocks: BlockNumber,
        pub validator_exit_cooldown_blocks: BlockNumber,
        pub request_cancel_delay_blocks: BlockNumber,
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
    pub struct ChainRequestStatusCounts {
        pub pending: RequestId,
        pub settled: RequestId,
        pub cancelled: RequestId,
        pub rejected: RequestId,
        pub expired: RequestId,
    }

    #[derive(
        Encode, Decode, DecodeWithMemTracking, TypeInfo, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
    )]
    pub struct InferenceRequestParams<Balance> {
        pub subnet_id: SubnetId,
        pub miner_id: MinerId,
        pub validator_id: ValidatorId,
        pub input_commitment: Commitment,
        pub payment: Balance,
        pub validator_fee_bps: u16,
        pub treasury_fee_bps: u16,
    }

    #[derive(
        Encode, Decode, DecodeWithMemTracking, TypeInfo, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
    )]
    pub struct AutoRouteInferenceRequestParams<Balance> {
        pub subnet_id: SubnetId,
        pub input_commitment: Commitment,
        pub payment: Balance,
        pub validator_fee_bps: u16,
        pub treasury_fee_bps: u16,
    }

    #[derive(
        Encode, Decode, DecodeWithMemTracking, TypeInfo, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
    )]
    pub struct InferenceRequestTerms<Balance> {
        pub payment: Balance,
        pub validator_fee_bps: u16,
        pub treasury_fee_bps: u16,
    }

    #[pallet::storage]
    pub type SubnetCount<T: Config> = StorageValue<_, SubnetId, ValueQuery>;

    #[pallet::storage]
    pub type MinerCount<T: Config> = StorageValue<_, MinerId, ValueQuery>;

    #[pallet::storage]
    pub type ValidatorCount<T: Config> = StorageValue<_, ValidatorId, ValueQuery>;

    #[pallet::storage]
    pub type Subnets<T: Config> =
        StorageMap<_, Twox64Concat, SubnetId, ChainSubnet<T::AccountId, BalanceOf<T>>, OptionQuery>;

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
    pub type ValidatorIdentityCommitments<T: Config> =
        StorageMap<_, Twox64Concat, ValidatorId, ChainIdentityCommitments, OptionQuery>;

    #[pallet::storage]
    pub type ValidatorIdentitySignatureBundles<T: Config> =
        StorageMap<_, Twox64Concat, ValidatorId, SignatureBundle, OptionQuery>;

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

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_runtime_upgrade() -> Weight {
            let on_chain = Pallet::<T>::on_chain_storage_version();
            if on_chain >= STORAGE_VERSION {
                return T::DbWeight::get().reads(1);
            }

            let weight = Self::migrate_operator_commitments(on_chain)
                .saturating_add(Self::migrate_participant_capital_commitments(on_chain))
                .saturating_add(Self::migrate_request_assignment_commitments(on_chain))
                .saturating_add(Self::migrate_request_owner_commitments(on_chain))
                .saturating_add(Self::migrate_request_timing_commitments(on_chain))
                .saturating_add(Self::migrate_request_terms_commitments(on_chain))
                .saturating_add(Self::rebuild_active_routing_indexes())
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
        SubnetCreated { subnet_id: SubnetId },
        /// A miner was registered.
        MinerRegistered {
            miner_id: MinerId,
            subnet_id: SubnetId,
        },
        /// A miner bond was locked and activated.
        MinerActivated { miner_id: MinerId },
        /// A miner started the bond exit cooldown.
        MinerExitStarted { miner_id: MinerId },
        /// A miner bond was released after cooldown.
        MinerBondWithdrawn { miner_id: MinerId },
        /// A validator was registered and staked.
        ValidatorRegistered {
            validator_id: ValidatorId,
            subnet_id: SubnetId,
        },
        /// A validator started the stake exit cooldown.
        ValidatorExitStarted { validator_id: ValidatorId },
        /// A validator stake was released after cooldown.
        ValidatorStakeWithdrawn { validator_id: ValidatorId },
        /// A miner published or cleared shielded identity commitments.
        MinerIdentityCommitmentsUpdated { miner_id: MinerId },
        /// A validator published or cleared shielded identity commitments.
        ValidatorIdentityCommitmentsUpdated { validator_id: ValidatorId },
        /// An inference request was opened and escrowed.
        InferenceRequested {
            request_id: RequestId,
            subnet_id: SubnetId,
        },
        /// A proof record was accepted.
        ProofAccepted { request_id: RequestId },
        /// An invalid proof challenge was accepted and the request was rejected.
        ProofChallengeAccepted { request_id: RequestId },
        /// Escrowed request payment was settled.
        InferenceSettled { request_id: RequestId },
        /// Pending inference request escrow was released back to the user.
        InferenceCancelled { request_id: RequestId },
        /// Rejected proof released escrow back to the user.
        InferenceRefunded { request_id: RequestId },
        /// Stale pending inference escrow was released back to the user.
        InferenceExpired { request_id: RequestId },
        /// A proof was rejected by the verifier and the miner was slashed.
        ProofRejected { request_id: RequestId },
        /// A miner was slashed.
        MinerSlashed { miner_id: MinerId },
        /// A validator was slashed.
        ValidatorSlashed { validator_id: ValidatorId },
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
        /// Proof verifier reported an internal error.
        VerifierError,
    }

    #[allow(clippy::large_enum_variant)]
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Create a permissionless Qubitum subnet by burning QBT.
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::create_subnet())]
        pub fn create_subnet(
            origin: OriginFor<T>,
            domain: SubnetDomain,
            proof_system: ProofSystem,
        ) -> DispatchResult {
            let owner = ensure_signed(origin)?;
            Self::ensure_supported_proof_system(proof_system)?;
            Self::burn_free(&owner, T::SubnetCreationBurn::get())?;

            let subnet_id = Self::next_subnet_id()?;
            let subnet = ChainSubnet {
                id: subnet_id,
                owner: owner.clone(),
                domain,
                proof_system,
                creation_burn: T::SubnetCreationBurn::get(),
                min_miner_bond: T::MinMinerBond::get(),
                max_miner_bond: T::MaxMinerBond::get(),
                min_validator_stake: T::MinValidatorStake::get(),
                active: true,
            };

            Subnets::<T>::insert(subnet_id, subnet);
            Self::deposit_event(Event::SubnetCreated { subnet_id });
            Ok(())
        }

        /// Register a miner by burning QBT and committing to a model.
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::register_miner())]
        pub fn register_miner(
            origin: OriginFor<T>,
            subnet_id: SubnetId,
            model_commitment: Commitment,
            proof_system: ProofSystem,
        ) -> DispatchResult {
            let operator = ensure_signed(origin)?;
            ensure_commitment::<T>(model_commitment)?;
            Self::ensure_supported_proof_system(proof_system)?;
            let subnet = Subnets::<T>::get(subnet_id).ok_or(Error::<T>::UnknownSubnet)?;
            ensure!(
                subnet.proof_system == proof_system,
                Error::<T>::ProofSystemMismatch
            );

            Self::burn_free(&operator, T::MinerRegistrationBurn::get())?;
            let miner_id = Self::next_miner_id()?;
            let miner = ChainMiner {
                id: miner_id,
                operator_commitment: Self::account_commitment(&operator),
                subnet_id,
                model_commitment,
                proof_system,
                bond_commitment: Self::balance_commitment(BalanceOf::<T>::default()),
                status: RegistryStatus::Pending,
            };

            Miners::<T>::insert(miner_id, miner);
            Self::deposit_event(Event::MinerRegistered {
                miner_id,
                subnet_id,
            });
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
            let operator = ensure_signed(origin)?;
            Miners::<T>::try_mutate(miner_id, |maybe_miner| -> DispatchResult {
                let miner = maybe_miner.as_mut().ok_or(Error::<T>::UnknownMiner)?;
                Self::ensure_miner_operator(miner, &operator)?;
                ensure!(
                    miner.status == RegistryStatus::Pending,
                    Error::<T>::InvalidMinerStatus
                );
                let subnet = Subnets::<T>::get(miner.subnet_id).ok_or(Error::<T>::UnknownSubnet)?;
                ensure!(
                    bond >= subnet.min_miner_bond && bond <= subnet.max_miner_bond,
                    Error::<T>::InvalidBond
                );

                T::Currency::hold(&HoldReason::MinerBond.into(), &operator, bond)?;
                Self::insert_active_miner(miner.subnet_id, miner_id)?;
                miner.bond_commitment = Self::balance_commitment(bond);
                miner.status = RegistryStatus::Active;
                Ok(())
            })?;

            Self::deposit_event(Event::MinerActivated { miner_id });
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
            let operator = ensure_signed(origin)?;
            let subnet = Subnets::<T>::get(subnet_id).ok_or(Error::<T>::UnknownSubnet)?;
            ensure!(
                stake >= subnet.min_validator_stake,
                Error::<T>::InvalidStake
            );
            T::Currency::hold(&HoldReason::ValidatorStake.into(), &operator, stake)?;

            let validator_id = Self::next_validator_id()?;
            let validator = ChainValidator {
                id: validator_id,
                operator_commitment: Self::account_commitment(&operator),
                subnet_id,
                stake_commitment: Self::balance_commitment(stake),
                status: RegistryStatus::Active,
            };

            Self::insert_active_validator(subnet_id, validator_id)?;
            Validators::<T>::insert(validator_id, validator);
            Self::deposit_event(Event::ValidatorRegistered {
                validator_id,
                subnet_id,
            });
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
            terms: InferenceRequestTerms<BalanceOf<T>>,
        ) -> DispatchResult {
            let validator_operator = ensure_signed(origin)?;
            let policy =
                Self::validate_submission(&submission, &validator_operator, &miner_operator)?;

            match T::ProofVerifier::verify(&submission, policy)? {
                VerificationOutcome::Valid => {}
                VerificationOutcome::Invalid { slash_bps } => {
                    Self::slash_miner_bond(submission.miner_id, &miner_operator, slash_bps)?;
                    Self::slash_validator_stake(
                        submission.validator_id,
                        &validator_operator,
                        slash_bps,
                    )?;
                    Self::refund_rejected_request(&submission, &request_user, &terms)?;
                    Self::deposit_event(Event::ProofRejected {
                        request_id: submission.request_id,
                    });
                    Self::deposit_event(Event::InferenceRefunded {
                        request_id: submission.request_id,
                    });
                    return Ok(());
                }
                VerificationOutcome::Error => return Err(Error::<T>::VerifierError.into()),
            }

            ProofRecords::<T>::insert(
                submission.request_id,
                ChainProofRecord {
                    request_id: submission.request_id,
                    subnet_id: submission.subnet_id,
                    assignment_commitment: Self::request_assignment_commitment(
                        submission.request_id,
                        submission.subnet_id,
                        submission.miner_id,
                        submission.validator_id,
                    ),
                    audit_commitment: Self::proof_audit_commitment(
                        &submission,
                        Self::current_block(),
                    ),
                    proof_system: submission.proof_system,
                },
            );
            Self::settle_request_payment(
                &submission,
                &request_user,
                &miner_operator,
                &validator_operator,
                &terms,
            )?;

            Self::deposit_event(Event::ProofAccepted {
                request_id: submission.request_id,
            });
            Self::deposit_event(Event::InferenceSettled {
                request_id: submission.request_id,
            });
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
            terms: InferenceRequestTerms<BalanceOf<T>>,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            let policy = Self::validate_challenge_submission(&submission, &miner_operator)?;

            match T::ProofVerifier::verify(&submission, policy)? {
                VerificationOutcome::Invalid { slash_bps } => {
                    Self::slash_miner_bond(submission.miner_id, &miner_operator, slash_bps)?;
                    Self::refund_rejected_request(&submission, &request_user, &terms)?;
                    Self::deposit_event(Event::ProofRejected {
                        request_id: submission.request_id,
                    });
                    Self::deposit_event(Event::ProofChallengeAccepted {
                        request_id: submission.request_id,
                    });
                    Self::deposit_event(Event::InferenceRefunded {
                        request_id: submission.request_id,
                    });
                    Ok(())
                }
                VerificationOutcome::Valid => Err(Error::<T>::ChallengeProofValid.into()),
                VerificationOutcome::Error => Err(Error::<T>::VerifierError.into()),
            }
        }

        /// Slash a miner bond for invalid proof behavior.
        #[pallet::call_index(5)]
        #[pallet::weight(T::WeightInfo::slash_miner())]
        pub fn slash_miner(
            origin: OriginFor<T>,
            miner_id: MinerId,
            operator: T::AccountId,
            slash_bps: u16,
        ) -> DispatchResult {
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
            Self::deposit_event(Event::MinerSlashed { miner_id });
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
            let user = ensure_signed(origin)?;
            Self::ensure_inference_request_openable(
                request_id,
                params.subnet_id,
                params.input_commitment,
                params.payment,
                params.validator_fee_bps,
                params.treasury_fee_bps,
            )?;
            let assignment = Self::route_assignment(params.subnet_id, request_id)
                .ok_or(Error::<T>::NoRouteAvailable)?;
            ensure!(
                assignment.miner_id == params.miner_id
                    && assignment.validator_id == params.validator_id,
                Error::<T>::AssignmentMismatch
            );
            Self::open_inference_request(
                user,
                request_id,
                params.subnet_id,
                params.miner_id,
                params.validator_id,
                params.input_commitment,
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
            let user = ensure_signed(origin)?;
            Self::ensure_inference_request_openable(
                request_id,
                params.subnet_id,
                params.input_commitment,
                params.payment,
                params.validator_fee_bps,
                params.treasury_fee_bps,
            )?;
            let assignment = Self::route_assignment(params.subnet_id, request_id)
                .ok_or(Error::<T>::NoRouteAvailable)?;
            Self::open_inference_request(
                user,
                request_id,
                params.subnet_id,
                assignment.miner_id,
                assignment.validator_id,
                params.input_commitment,
                params.payment,
                params.validator_fee_bps,
                params.treasury_fee_bps,
            )
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
            created_at: BlockNumber,
            terms: InferenceRequestTerms<BalanceOf<T>>,
        ) -> DispatchResult {
            let user = ensure_signed(origin)?;
            let payment = InferenceRequests::<T>::try_mutate(
                request_id,
                |maybe_request| -> Result<BalanceOf<T>, DispatchError> {
                    let request = maybe_request.as_mut().ok_or(Error::<T>::UnknownRequest)?;
                    Self::ensure_request_user(request, &user)?;
                    Self::ensure_request_assignment_witness(request, miner_id, validator_id)?;
                    Self::ensure_request_timing_witness(request, created_at)?;
                    Self::ensure_request_terms_witness(request, &terms)?;
                    ensure!(
                        request.status == InferenceRequestStatus::Pending,
                        Error::<T>::RequestAlreadySettled
                    );
                    let cancel_available_at = created_at
                        .checked_add(T::RequestCancelDelayBlocks::get())
                        .ok_or(Error::<T>::ArithmeticOverflow)?;
                    ensure!(
                        Self::current_block() >= cancel_available_at,
                        Error::<T>::RequestCancelUnavailable
                    );
                    T::Currency::release(
                        &HoldReason::InferencePayment.into(),
                        &user,
                        terms.payment,
                        Precision::Exact,
                    )?;
                    request.status = InferenceRequestStatus::Cancelled;
                    Ok(terms.payment)
                },
            )?;
            Self::decrement_pending_assignment(miner_id, validator_id)?;
            Self::transition_request_status(
                InferenceRequestStatus::Pending,
                InferenceRequestStatus::Cancelled,
            )?;
            Self::record_inference_refund(payment);

            Self::deposit_event(Event::InferenceCancelled { request_id });
            Ok(())
        }

        /// Start a miner exit cooldown before remaining bond can be withdrawn.
        #[pallet::call_index(8)]
        #[pallet::weight(T::WeightInfo::deactivate_miner())]
        pub fn deactivate_miner(origin: OriginFor<T>, miner_id: MinerId) -> DispatchResult {
            let operator = ensure_signed(origin)?;
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
                Ok(())
            })?;

            Self::deposit_event(Event::MinerExitStarted { miner_id });
            Ok(())
        }

        /// Withdraw remaining miner bond after the exit cooldown completes.
        #[pallet::call_index(9)]
        #[pallet::weight(T::WeightInfo::withdraw_miner_bond())]
        #[frame_support::transactional]
        pub fn withdraw_miner_bond(origin: OriginFor<T>, miner_id: MinerId) -> DispatchResult {
            let operator = ensure_signed(origin)?;
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

                let bond = Self::held_miner_bond(&operator);
                if bond != BalanceOf::<T>::default() {
                    T::Currency::release(
                        &HoldReason::MinerBond.into(),
                        &operator,
                        bond,
                        Precision::Exact,
                    )?;
                }
                miner.bond_commitment = Self::balance_commitment(BalanceOf::<T>::default());
                miner.status = RegistryStatus::Disabled;
                Ok(())
            })?;

            Self::deposit_event(Event::MinerBondWithdrawn { miner_id });
            Ok(())
        }

        /// Start a validator exit cooldown before remaining stake can be withdrawn.
        #[pallet::call_index(10)]
        #[pallet::weight(T::WeightInfo::deactivate_validator())]
        pub fn deactivate_validator(
            origin: OriginFor<T>,
            validator_id: ValidatorId,
        ) -> DispatchResult {
            let operator = ensure_signed(origin)?;
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
                        RegistryStatus::Active | RegistryStatus::Slashed
                    ),
                    Error::<T>::InvalidValidatorStatus
                );
                ensure!(
                    PendingValidatorRequests::<T>::get(validator_id) == 0,
                    Error::<T>::PendingAssignedRequests
                );
                Self::remove_active_validator(validator.subnet_id, validator_id);
                validator.status = RegistryStatus::Exiting { exit_available_at };
                Ok(())
            })?;

            Self::deposit_event(Event::ValidatorExitStarted { validator_id });
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
            let operator = ensure_signed(origin)?;
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

                let stake = Self::held_validator_stake(&operator);
                if stake != BalanceOf::<T>::default() {
                    T::Currency::release(
                        &HoldReason::ValidatorStake.into(),
                        &operator,
                        stake,
                        Precision::Exact,
                    )?;
                }
                validator.stake_commitment = Self::balance_commitment(BalanceOf::<T>::default());
                validator.status = RegistryStatus::Disabled;
                Ok(())
            })?;

            Self::deposit_event(Event::ValidatorStakeWithdrawn { validator_id });
            Ok(())
        }

        /// Slash a validator stake for invalid verification behavior.
        #[pallet::call_index(12)]
        #[pallet::weight(T::WeightInfo::slash_validator())]
        pub fn slash_validator(
            origin: OriginFor<T>,
            validator_id: ValidatorId,
            operator: T::AccountId,
            slash_bps: u16,
        ) -> DispatchResult {
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
            Self::deposit_event(Event::ValidatorSlashed { validator_id });
            Ok(())
        }

        /// Expire a stale pending inference request and release escrow back to the user.
        #[pallet::call_index(13)]
        #[pallet::weight(T::WeightInfo::expire_inference())]
        #[frame_support::transactional]
        pub fn expire_inference(
            origin: OriginFor<T>,
            request_id: RequestId,
            request_user: T::AccountId,
            miner_id: MinerId,
            validator_id: ValidatorId,
            created_at: BlockNumber,
            terms: InferenceRequestTerms<BalanceOf<T>>,
        ) -> DispatchResult {
            let _keeper = ensure_signed(origin)?;
            let payment = InferenceRequests::<T>::try_mutate(
                request_id,
                |maybe_request| -> Result<BalanceOf<T>, DispatchError> {
                    let request = maybe_request.as_mut().ok_or(Error::<T>::UnknownRequest)?;
                    Self::ensure_request_user(request, &request_user)?;
                    Self::ensure_request_assignment_witness(request, miner_id, validator_id)?;
                    Self::ensure_request_timing_witness(request, created_at)?;
                    Self::ensure_request_terms_witness(request, &terms)?;
                    ensure!(
                        request.status == InferenceRequestStatus::Pending,
                        Error::<T>::RequestAlreadySettled
                    );
                    let cancel_available_at = created_at
                        .checked_add(T::RequestCancelDelayBlocks::get())
                        .ok_or(Error::<T>::ArithmeticOverflow)?;
                    ensure!(
                        Self::current_block() >= cancel_available_at,
                        Error::<T>::RequestCancelUnavailable
                    );
                    T::Currency::release(
                        &HoldReason::InferencePayment.into(),
                        &request_user,
                        terms.payment,
                        Precision::Exact,
                    )?;
                    request.status = InferenceRequestStatus::Expired;
                    Ok(terms.payment)
                },
            )?;
            Self::decrement_pending_assignment(miner_id, validator_id)?;
            Self::transition_request_status(
                InferenceRequestStatus::Pending,
                InferenceRequestStatus::Expired,
            )?;
            Self::record_inference_refund(payment);

            Self::deposit_event(Event::InferenceExpired { request_id });
            Ok(())
        }

        /// Publish or clear commitment-only miner identity metadata.
        #[pallet::call_index(14)]
        #[pallet::weight(T::WeightInfo::set_miner_identity_commitments())]
        pub fn set_miner_identity_commitments(
            origin: OriginFor<T>,
            miner_id: MinerId,
            shielded_identity_commitment: Option<Commitment>,
            endpoint_commitment: Option<Commitment>,
            signature_bundle: SignatureBundle,
        ) -> DispatchResult {
            let operator = ensure_signed(origin)?;
            let miner = Miners::<T>::get(miner_id).ok_or(Error::<T>::UnknownMiner)?;
            Self::ensure_miner_operator(&miner, &operator)?;
            Self::ensure_optional_commitment(shielded_identity_commitment)?;
            Self::ensure_optional_commitment(endpoint_commitment)?;

            if shielded_identity_commitment.is_some() || endpoint_commitment.is_some() {
                Self::ensure_signature_bundle(signature_bundle)?;
                MinerIdentityCommitments::<T>::insert(
                    miner_id,
                    ChainIdentityCommitments {
                        shielded_identity_commitment,
                        endpoint_commitment,
                    },
                );
                MinerIdentitySignatureBundles::<T>::insert(miner_id, signature_bundle);
            } else {
                MinerIdentityCommitments::<T>::remove(miner_id);
                MinerIdentitySignatureBundles::<T>::remove(miner_id);
            }

            Self::deposit_event(Event::MinerIdentityCommitmentsUpdated { miner_id });
            Ok(())
        }

        /// Publish or clear commitment-only validator identity metadata.
        #[pallet::call_index(15)]
        #[pallet::weight(T::WeightInfo::set_validator_identity_commitments())]
        pub fn set_validator_identity_commitments(
            origin: OriginFor<T>,
            validator_id: ValidatorId,
            shielded_identity_commitment: Option<Commitment>,
            endpoint_commitment: Option<Commitment>,
            signature_bundle: SignatureBundle,
        ) -> DispatchResult {
            let operator = ensure_signed(origin)?;
            let validator =
                Validators::<T>::get(validator_id).ok_or(Error::<T>::UnknownValidator)?;
            Self::ensure_validator_operator(&validator, &operator)?;
            Self::ensure_optional_commitment(shielded_identity_commitment)?;
            Self::ensure_optional_commitment(endpoint_commitment)?;

            if shielded_identity_commitment.is_some() || endpoint_commitment.is_some() {
                Self::ensure_signature_bundle(signature_bundle)?;
                ValidatorIdentityCommitments::<T>::insert(
                    validator_id,
                    ChainIdentityCommitments {
                        shielded_identity_commitment,
                        endpoint_commitment,
                    },
                );
                ValidatorIdentitySignatureBundles::<T>::insert(validator_id, signature_bundle);
            } else {
                ValidatorIdentityCommitments::<T>::remove(validator_id);
                ValidatorIdentitySignatureBundles::<T>::remove(validator_id);
            }

            Self::deposit_event(Event::ValidatorIdentityCommitmentsUpdated { validator_id });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        pub fn accounting() -> ChainAccounting<BalanceOf<T>> {
            ChainAccounting {
                total_inference_escrowed: TotalInferenceEscrowed::<T>::get(),
                total_miner_payouts: TotalMinerPayouts::<T>::get(),
                total_validator_fees: TotalValidatorFees::<T>::get(),
                total_treasury_fees: TotalTreasuryFees::<T>::get(),
                total_inference_refunded: TotalInferenceRefunded::<T>::get(),
            }
        }

        pub fn protocol_params() -> ChainProtocolParams<BalanceOf<T>> {
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
                signature_mode: T::SignatureMode::get(),
                miner_exit_cooldown_blocks: T::MinerExitCooldownBlocks::get(),
                validator_exit_cooldown_blocks: T::ValidatorExitCooldownBlocks::get(),
                request_cancel_delay_blocks: T::RequestCancelDelayBlocks::get(),
            }
        }

        pub fn request_status_counts() -> ChainRequestStatusCounts {
            ChainRequestStatusCounts {
                pending: PendingInferenceRequestCount::<T>::get(),
                settled: SettledInferenceRequestCount::<T>::get(),
                cancelled: CancelledInferenceRequestCount::<T>::get(),
                rejected: RejectedInferenceRequestCount::<T>::get(),
                expired: ExpiredInferenceRequestCount::<T>::get(),
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

            let miner_id = Self::route_active_miner(subnet_id, request_id)?;
            let miner = Miners::<T>::get(miner_id)?;
            let validator_seed = request_id.rotate_left(32) ^ u64::from(subnet_id);
            let validator_id =
                Self::route_active_validator(subnet_id, validator_seed, miner.operator_commitment)?;
            let validator = Validators::<T>::get(validator_id)?;
            Self::ensure_distinct_operators(&miner, &validator).ok()?;

            Some(ChainAssignment {
                request_id,
                subnet_id,
                miner_id,
                validator_id,
            })
        }

        #[cfg(test)]
        pub(crate) fn next_route_assignment(subnet_id: SubnetId) -> Option<ChainAssignment> {
            Self::route_assignment(subnet_id, RequestCount::<T>::get())
        }

        pub fn route_availability(
            subnet_id: SubnetId,
            request_id: RequestId,
        ) -> ChainRouteAvailability {
            ChainRouteAvailability {
                request_id,
                subnet_id,
                available: Self::route_assignment(subnet_id, request_id).is_some(),
            }
        }

        pub fn next_route_availability(subnet_id: SubnetId) -> ChainRouteAvailability {
            Self::route_availability(subnet_id, RequestCount::<T>::get())
        }

        pub fn public_subnet(subnet_id: SubnetId) -> Option<ChainPublicSubnet> {
            Subnets::<T>::get(subnet_id).map(|subnet| ChainPublicSubnet {
                id: subnet.id,
                domain: subnet.domain,
                proof_system: subnet.proof_system,
                active: subnet.active,
            })
        }

        pub fn public_miner(miner_id: MinerId) -> Option<ChainPublicMiner> {
            Miners::<T>::get(miner_id).map(|miner| ChainPublicMiner {
                id: miner.id,
                subnet_id: miner.subnet_id,
                proof_system: miner.proof_system,
                status: PublicRegistryStatus::from(miner.status),
            })
        }

        pub fn public_validator(validator_id: ValidatorId) -> Option<ChainPublicValidator> {
            Validators::<T>::get(validator_id).map(|validator| ChainPublicValidator {
                id: validator.id,
                subnet_id: validator.subnet_id,
                status: PublicRegistryStatus::from(validator.status),
            })
        }

        pub fn public_inference_request(
            request_id: RequestId,
        ) -> Option<ChainPublicInferenceRequest> {
            InferenceRequests::<T>::get(request_id).map(|request| ChainPublicInferenceRequest {
                request_id: request.request_id,
                subnet_id: request.subnet_id,
                status: request.status,
            })
        }

        pub fn public_proof_record(request_id: RequestId) -> Option<ChainPublicProofRecord> {
            ProofRecords::<T>::get(request_id).map(|record| ChainPublicProofRecord {
                request_id: record.request_id,
                subnet_id: record.subnet_id,
                proof_system: record.proof_system,
            })
        }

        fn ensure_inference_request_openable(
            request_id: RequestId,
            subnet_id: SubnetId,
            input_commitment: Commitment,
            payment: BalanceOf<T>,
            validator_fee_bps: u16,
            treasury_fee_bps: u16,
        ) -> DispatchResult {
            ensure_commitment::<T>(input_commitment)?;
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
            payment: BalanceOf<T>,
            validator_fee_bps: u16,
            treasury_fee_bps: u16,
        ) -> DispatchResult {
            Self::ensure_request_assignment(subnet_id, miner_id, validator_id)?;
            Self::ensure_next_request_id(request_id)?;

            T::Currency::hold(&HoldReason::InferencePayment.into(), &user, payment)?;
            Self::increment_pending_assignment(miner_id, validator_id)?;
            Self::increment_request_status_count(InferenceRequestStatus::Pending)?;
            Self::record_inference_escrow(payment);
            let created_at = Self::current_block();
            InferenceRequests::<T>::insert(
                request_id,
                ChainInferenceRequest {
                    request_id,
                    user_commitment: Self::account_commitment(&user),
                    subnet_id,
                    assignment_commitment: Self::request_assignment_commitment(
                        request_id,
                        subnet_id,
                        miner_id,
                        validator_id,
                    ),
                    input_commitment,
                    terms_commitment: Self::request_terms_commitment(
                        request_id,
                        payment,
                        validator_fee_bps,
                        treasury_fee_bps,
                    ),
                    timing_commitment: Self::request_timing_commitment(request_id, created_at),
                    status: InferenceRequestStatus::Pending,
                },
            );

            Self::deposit_event(Event::InferenceRequested {
                request_id,
                subnet_id,
            });
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
            let expected = RequestCount::<T>::get();
            ensure!(request_id == expected, Error::<T>::InvalidRequestId);
            let next = request_id
                .checked_add(1)
                .ok_or(Error::<T>::ArithmeticOverflow)?;
            RequestCount::<T>::put(next);
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

        fn record_inference_escrow(payment: BalanceOf<T>) {
            TotalInferenceEscrowed::<T>::mutate(|total| {
                *total = total.saturating_add(payment);
            });
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

        fn record_inference_settlement(
            miner_payment: BalanceOf<T>,
            validator_fee: BalanceOf<T>,
            treasury_fee: BalanceOf<T>,
        ) {
            TotalMinerPayouts::<T>::mutate(|total| {
                *total = total.saturating_add(miner_payment);
            });
            TotalValidatorFees::<T>::mutate(|total| {
                *total = total.saturating_add(validator_fee);
            });
            TotalTreasuryFees::<T>::mutate(|total| {
                *total = total.saturating_add(treasury_fee);
            });
        }

        fn record_inference_refund(payment: BalanceOf<T>) {
            TotalInferenceRefunded::<T>::mutate(|total| {
                *total = total.saturating_add(payment);
            });
        }

        fn current_block() -> BlockNumber {
            frame_system::Pallet::<T>::block_number().saturated_into()
        }

        pub(crate) fn account_commitment(who: &T::AccountId) -> Commitment {
            who.using_encoded(blake2_256)
        }

        pub(crate) fn balance_commitment(amount: BalanceOf<T>) -> Commitment {
            amount.using_encoded(blake2_256)
        }

        pub(crate) fn request_assignment_commitment(
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
        ) -> Commitment {
            (request_id, created_at).using_encoded(blake2_256)
        }

        pub(crate) fn request_terms_commitment(
            request_id: RequestId,
            payment: BalanceOf<T>,
            validator_fee_bps: u16,
            treasury_fee_bps: u16,
        ) -> Commitment {
            (request_id, payment, validator_fee_bps, treasury_fee_bps).using_encoded(blake2_256)
        }

        pub(crate) fn proof_audit_commitment(
            submission: &InferenceProofSubmission,
            accepted_at: BlockNumber,
        ) -> Commitment {
            (
                submission.request_id,
                submission.subnet_id,
                Self::request_assignment_commitment(
                    submission.request_id,
                    submission.subnet_id,
                    submission.miner_id,
                    submission.validator_id,
                ),
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
        fn legacy_proof_audit_commitment(
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

        fn ensure_miner_operator(miner: &ChainMiner, operator: &T::AccountId) -> DispatchResult {
            ensure!(
                miner.operator_commitment == Self::account_commitment(operator),
                Error::<T>::NotOperator
            );
            Ok(())
        }

        fn ensure_validator_operator(
            validator: &ChainValidator,
            operator: &T::AccountId,
        ) -> DispatchResult {
            ensure!(
                validator.operator_commitment == Self::account_commitment(operator),
                Error::<T>::NotOperator
            );
            Ok(())
        }

        fn ensure_validator_submission_operator(
            validator: &ChainValidator,
            operator: &T::AccountId,
        ) -> DispatchResult {
            ensure!(
                validator.operator_commitment == Self::account_commitment(operator),
                Error::<T>::NotValidatorOperator
            );
            Ok(())
        }

        fn ensure_request_user(
            request: &ChainInferenceRequest,
            user: &T::AccountId,
        ) -> DispatchResult {
            ensure!(
                request.user_commitment == Self::account_commitment(user),
                Error::<T>::NotRequestOwner
            );
            Ok(())
        }

        fn ensure_request_assignment_witness(
            request: &ChainInferenceRequest,
            miner_id: MinerId,
            validator_id: ValidatorId,
        ) -> DispatchResult {
            ensure!(
                request.assignment_commitment
                    == Self::request_assignment_commitment(
                        request.request_id,
                        request.subnet_id,
                        miner_id,
                        validator_id,
                    ),
                Error::<T>::AssignmentMismatch
            );
            Ok(())
        }

        fn ensure_request_timing_witness(
            request: &ChainInferenceRequest,
            created_at: BlockNumber,
        ) -> DispatchResult {
            ensure!(
                request.timing_commitment
                    == Self::request_timing_commitment(request.request_id, created_at),
                Error::<T>::RequestMismatch
            );
            Ok(())
        }

        fn ensure_request_terms_witness(
            request: &ChainInferenceRequest,
            terms: &InferenceRequestTerms<BalanceOf<T>>,
        ) -> DispatchResult {
            ensure!(
                terms.payment > BalanceOf::<T>::default(),
                Error::<T>::InvalidPayment
            );
            Self::validate_fee_split(terms.validator_fee_bps, terms.treasury_fee_bps)?;
            ensure!(
                request.terms_commitment
                    == Self::request_terms_commitment(
                        request.request_id,
                        terms.payment,
                        terms.validator_fee_bps,
                        terms.treasury_fee_bps,
                    ),
                Error::<T>::RequestMismatch
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

        fn route_active_miner(subnet_id: SubnetId, seed: u64) -> Option<MinerId> {
            let ids = ActiveMinersBySubnet::<T>::get(subnet_id);
            if ids.is_empty() {
                return None;
            }

            let target = Self::route_index(seed, ids.len())?;
            ids.get(target).copied()
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
                    && validator.operator_commitment != miner_operator_commitment
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

            for (miner_id, miner) in Miners::<T>::iter() {
                miner_reads = miner_reads.saturating_add(1);
                if miner.status == RegistryStatus::Active {
                    let inserted = ActiveMinersBySubnet::<T>::try_mutate(miner.subnet_id, |ids| {
                        Self::insert_sorted_miner_id(ids, miner_id)
                    })
                    .unwrap_or(false);
                    if inserted {
                        miner_writes = miner_writes.saturating_add(1);
                    }
                }
            }

            for (validator_id, validator) in Validators::<T>::iter() {
                validator_reads = validator_reads.saturating_add(1);
                if validator.status == RegistryStatus::Active {
                    let inserted =
                        ActiveValidatorsBySubnet::<T>::try_mutate(validator.subnet_id, |ids| {
                            Self::insert_sorted_validator_id(ids, validator_id)
                        })
                        .unwrap_or(false);
                    if inserted {
                        validator_writes = validator_writes.saturating_add(1);
                    }
                }
            }

            T::DbWeight::get().reads_writes(
                miner_reads.saturating_add(validator_reads),
                miner_writes.saturating_add(validator_writes),
            )
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
            }
        }

        fn record_legacy_request_accounting(
            accounting: &mut ChainAccounting<BalanceOf<T>>,
            payment: BalanceOf<T>,
            validator_fee_bps: u16,
            treasury_fee_bps: u16,
            status: InferenceRequestStatus,
        ) {
            accounting.total_inference_escrowed =
                accounting.total_inference_escrowed.saturating_add(payment);
            match status {
                InferenceRequestStatus::Settled => {
                    if let Ok((miner_payment, validator_fee, treasury_fee)) =
                        Self::payment_split(payment, validator_fee_bps, treasury_fee_bps)
                    {
                        accounting.total_miner_payouts =
                            accounting.total_miner_payouts.saturating_add(miner_payment);
                        accounting.total_validator_fees = accounting
                            .total_validator_fees
                            .saturating_add(validator_fee);
                        accounting.total_treasury_fees =
                            accounting.total_treasury_fees.saturating_add(treasury_fee);
                    }
                }
                InferenceRequestStatus::Cancelled
                | InferenceRequestStatus::Rejected
                | InferenceRequestStatus::Expired => {
                    accounting.total_inference_refunded =
                        accounting.total_inference_refunded.saturating_add(payment);
                }
                InferenceRequestStatus::Pending => {}
            }
        }

        fn put_inference_accounting(accounting: ChainAccounting<BalanceOf<T>>) {
            TotalInferenceEscrowed::<T>::put(accounting.total_inference_escrowed);
            TotalMinerPayouts::<T>::put(accounting.total_miner_payouts);
            TotalValidatorFees::<T>::put(accounting.total_validator_fees);
            TotalTreasuryFees::<T>::put(accounting.total_treasury_fees);
            TotalInferenceRefunded::<T>::put(accounting.total_inference_refunded);
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
                let assignment_commitment = Self::request_assignment_commitment(
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
                let assignment_commitment = Self::request_assignment_commitment(
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

        fn migrate_operator_commitments(on_chain: StorageVersion) -> Weight {
            if on_chain != StorageVersion::new(7) {
                return Weight::zero();
            }

            let mut migrated_miners = 0_u64;
            Miners::<T>::translate::<ChainMinerV7<T::AccountId, BalanceOf<T>>, _>(|_, old| {
                migrated_miners = migrated_miners.saturating_add(1);
                Some(ChainMiner {
                    id: old.id,
                    operator_commitment: Self::account_commitment(&old.operator),
                    subnet_id: old.subnet_id,
                    model_commitment: old.model_commitment,
                    proof_system: old.proof_system,
                    bond_commitment: Self::balance_commitment(old.bond),
                    status: old.status,
                })
            });

            let mut migrated_validators = 0_u64;
            Validators::<T>::translate::<ChainValidatorV7<T::AccountId, BalanceOf<T>>, _>(
                |_, old| {
                    migrated_validators = migrated_validators.saturating_add(1);
                    Some(ChainValidator {
                        id: old.id,
                        operator_commitment: Self::account_commitment(&old.operator),
                        subnet_id: old.subnet_id,
                        stake_commitment: Self::balance_commitment(old.stake),
                        status: old.status,
                    })
                },
            );

            let migrated = migrated_miners.saturating_add(migrated_validators);
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
                    bond_commitment: Self::balance_commitment(old.bond),
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
                    stake_commitment: Self::balance_commitment(old.stake),
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
            let mut migrated = 0_u64;
            InferenceRequests::<T>::translate::<
                ChainInferenceRequestV8<T::AccountId, BalanceOf<T>>,
                _,
            >(|_, old| {
                migrated = migrated.saturating_add(1);
                Self::record_legacy_request_accounting(
                    &mut accounting,
                    old.payment,
                    old.validator_fee_bps,
                    old.treasury_fee_bps,
                    old.status,
                );
                if old.status == InferenceRequestStatus::Pending {
                    let _ = Self::increment_pending_assignment(old.miner_id, old.validator_id);
                }
                Some(ChainInferenceRequest {
                    request_id: old.request_id,
                    user_commitment: Self::account_commitment(&old.user),
                    subnet_id: old.subnet_id,
                    assignment_commitment: Self::request_assignment_commitment(
                        old.request_id,
                        old.subnet_id,
                        old.miner_id,
                        old.validator_id,
                    ),
                    input_commitment: old.input_commitment,
                    terms_commitment: Self::request_terms_commitment(
                        old.request_id,
                        old.payment,
                        old.validator_fee_bps,
                        old.treasury_fee_bps,
                    ),
                    timing_commitment: Self::request_timing_commitment(
                        old.request_id,
                        old.created_at,
                    ),
                    status: old.status,
                })
            });
            Self::put_inference_accounting(accounting);

            clear_weight.saturating_add(
                T::DbWeight::get().reads_writes(migrated, migrated.saturating_add(5)),
            )
        }

        fn migrate_request_assignment_commitments(on_chain: StorageVersion) -> Weight {
            if on_chain < StorageVersion::new(9) || on_chain >= StorageVersion::new(11) {
                return Weight::zero();
            }

            let clear_weight = Self::clear_pending_assignment_counters();
            let mut accounting = Self::zero_accounting();
            let mut migrated = 0_u64;
            InferenceRequests::<T>::translate::<ChainInferenceRequestV10<BalanceOf<T>>, _>(
                |_, old| {
                    migrated = migrated.saturating_add(1);
                    Self::record_legacy_request_accounting(
                        &mut accounting,
                        old.payment,
                        old.validator_fee_bps,
                        old.treasury_fee_bps,
                        old.status,
                    );
                    if old.status == InferenceRequestStatus::Pending {
                        let _ = Self::increment_pending_assignment(old.miner_id, old.validator_id);
                    }
                    Some(ChainInferenceRequest {
                        request_id: old.request_id,
                        user_commitment: old.user_commitment,
                        subnet_id: old.subnet_id,
                        assignment_commitment: Self::request_assignment_commitment(
                            old.request_id,
                            old.subnet_id,
                            old.miner_id,
                            old.validator_id,
                        ),
                        input_commitment: old.input_commitment,
                        terms_commitment: Self::request_terms_commitment(
                            old.request_id,
                            old.payment,
                            old.validator_fee_bps,
                            old.treasury_fee_bps,
                        ),
                        timing_commitment: Self::request_timing_commitment(
                            old.request_id,
                            old.created_at,
                        ),
                        status: old.status,
                    })
                },
            );
            Self::put_inference_accounting(accounting);

            clear_weight.saturating_add(
                T::DbWeight::get().reads_writes(migrated, migrated.saturating_add(5)),
            )
        }

        fn migrate_request_timing_commitments(on_chain: StorageVersion) -> Weight {
            if on_chain < StorageVersion::new(11) || on_chain >= StorageVersion::new(13) {
                return Weight::zero();
            }

            let mut accounting = Self::zero_accounting();
            let mut migrated = 0_u64;
            InferenceRequests::<T>::translate::<ChainInferenceRequestV12<BalanceOf<T>>, _>(
                |_, old| {
                    migrated = migrated.saturating_add(1);
                    Self::record_legacy_request_accounting(
                        &mut accounting,
                        old.payment,
                        old.validator_fee_bps,
                        old.treasury_fee_bps,
                        old.status,
                    );
                    Some(ChainInferenceRequest {
                        request_id: old.request_id,
                        user_commitment: old.user_commitment,
                        subnet_id: old.subnet_id,
                        assignment_commitment: old.assignment_commitment,
                        input_commitment: old.input_commitment,
                        terms_commitment: Self::request_terms_commitment(
                            old.request_id,
                            old.payment,
                            old.validator_fee_bps,
                            old.treasury_fee_bps,
                        ),
                        timing_commitment: Self::request_timing_commitment(
                            old.request_id,
                            old.created_at,
                        ),
                        status: old.status,
                    })
                },
            );
            Self::put_inference_accounting(accounting);

            T::DbWeight::get().reads_writes(migrated, migrated.saturating_add(5))
        }

        fn migrate_request_terms_commitments(on_chain: StorageVersion) -> Weight {
            if on_chain < StorageVersion::new(13) || on_chain >= StorageVersion::new(14) {
                return Weight::zero();
            }

            let mut accounting = Self::zero_accounting();
            let mut migrated = 0_u64;
            InferenceRequests::<T>::translate::<ChainInferenceRequestV13<BalanceOf<T>>, _>(
                |_, old| {
                    migrated = migrated.saturating_add(1);
                    Self::record_legacy_request_accounting(
                        &mut accounting,
                        old.payment,
                        old.validator_fee_bps,
                        old.treasury_fee_bps,
                        old.status,
                    );
                    Some(ChainInferenceRequest {
                        request_id: old.request_id,
                        user_commitment: old.user_commitment,
                        subnet_id: old.subnet_id,
                        assignment_commitment: old.assignment_commitment,
                        input_commitment: old.input_commitment,
                        terms_commitment: Self::request_terms_commitment(
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
            Self::put_inference_accounting(accounting);

            T::DbWeight::get().reads_writes(migrated, migrated.saturating_add(5))
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
                }
            }

            for (miner_id, miner) in Miners::<T>::iter() {
                if miner.status == RegistryStatus::Active {
                    ensure!(
                        ActiveMinersBySubnet::<T>::get(miner.subnet_id).contains(&miner_id),
                        "Qubitum active miner missing from route index"
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
                }
            }

            for (validator_id, validator) in Validators::<T>::iter() {
                if validator.status == RegistryStatus::Active {
                    ensure!(
                        ActiveValidatorsBySubnet::<T>::get(validator.subnet_id)
                            .contains(&validator_id),
                        "Qubitum active validator missing from route index"
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
                Self::request_status_counts() == expected_status_counts,
                "Qubitum request status counter mismatch"
            );

            Ok(())
        }

        fn burn_free(who: &T::AccountId, amount: BalanceOf<T>) -> DispatchResult {
            let burned = T::Currency::burn_from(
                who,
                amount,
                Preservation::Expendable,
                Precision::Exact,
                Fortitude::Polite,
            )?;
            TotalBurned::<T>::mutate(|total| {
                *total = total.saturating_add(burned);
            });
            Ok(())
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
        ) -> Result<ProofVerificationPolicy, DispatchError> {
            let (policy, miner, validator) = Self::validate_submission_for_request(submission)?;
            Self::ensure_miner_operator(&miner, miner_operator)?;
            Self::ensure_validator_submission_operator(&validator, validator_operator)?;
            Ok(policy)
        }

        fn validate_challenge_submission(
            submission: &InferenceProofSubmission,
            miner_operator: &T::AccountId,
        ) -> Result<ProofVerificationPolicy, DispatchError> {
            let (policy, miner, _) = Self::validate_submission_for_request(submission)?;
            Self::ensure_miner_operator(&miner, miner_operator)?;
            Ok(policy)
        }

        fn validate_submission_for_request(
            submission: &InferenceProofSubmission,
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
            terms: &InferenceRequestTerms<BalanceOf<T>>,
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
                    )?;
                    Self::ensure_request_user(request, request_user)?;
                    Self::ensure_request_terms_witness(request, terms)?;

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
                    );

                    Ok((miner_payment, validator_fee, treasury_fee))
                },
            )
        }

        fn refund_rejected_request(
            submission: &InferenceProofSubmission,
            request_user: &T::AccountId,
            terms: &InferenceRequestTerms<BalanceOf<T>>,
        ) -> Result<BalanceOf<T>, DispatchError> {
            InferenceRequests::<T>::try_mutate(
                submission.request_id,
                |maybe_request| -> Result<BalanceOf<T>, DispatchError> {
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
                    )?;
                    Self::ensure_request_user(request, request_user)?;
                    Self::ensure_request_terms_witness(request, terms)?;

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
                    Self::record_inference_refund(terms.payment);

                    Ok(terms.payment)
                },
            )
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
                let current_bond = Self::held_miner_bond(operator);
                let slash_amount = pro_rata::<T>(current_bond, slash_bps)?;
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
                miner.bond_commitment = Self::balance_commitment(remaining_bond);
                if remaining_bond < T::MinMinerBond::get()
                    && !matches!(miner.status, RegistryStatus::Exiting { .. })
                {
                    Self::remove_active_miner(miner.subnet_id, miner_id);
                    miner.status = RegistryStatus::Slashed;
                }
                Ok::<BalanceOf<T>, DispatchError>(burned)
            })?;

            TotalBurned::<T>::mutate(|total| {
                *total = total.saturating_add(amount);
            });
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
                let current_stake = Self::held_validator_stake(operator);
                let slash_amount = pro_rata::<T>(current_stake, slash_bps)?;
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
                validator.stake_commitment = Self::balance_commitment(remaining_stake);
                if remaining_stake < T::MinValidatorStake::get()
                    && !matches!(validator.status, RegistryStatus::Exiting { .. })
                {
                    Self::remove_active_validator(validator.subnet_id, validator_id);
                    validator.status = RegistryStatus::Slashed;
                }
                Ok::<BalanceOf<T>, DispatchError>(burned)
            })?;

            TotalBurned::<T>::mutate(|total| {
                *total = total.saturating_add(amount);
            });
            Ok(amount)
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
