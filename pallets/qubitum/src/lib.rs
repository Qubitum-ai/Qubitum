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
        fungible::{self, Mutate as _, MutateHold as _},
    },
};
use qubitum_protocol::{
    BlockNumber, Commitment, InferenceProofSubmission, MinerId, ProofEnvelope, ProofSystem,
    RegistryStatus, RequestId, SubnetDomain, SubnetId, ValidatorId, VerificationOutcome,
};
use scale_info::TypeInfo;
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

    #[pallet::pallet]
    #[pallet::without_storage_info]
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
        Encode, Decode, DecodeWithMemTracking, TypeInfo, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
    )]
    pub struct ChainMiner<AccountId, Balance> {
        pub id: MinerId,
        pub operator: AccountId,
        pub subnet_id: SubnetId,
        pub model_commitment: Commitment,
        pub proof_system: ProofSystem,
        pub bond: Balance,
        pub status: RegistryStatus,
    }

    #[derive(
        Encode, Decode, DecodeWithMemTracking, TypeInfo, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
    )]
    pub struct ChainValidator<AccountId, Balance> {
        pub id: ValidatorId,
        pub operator: AccountId,
        pub subnet_id: SubnetId,
        pub stake: Balance,
        pub status: RegistryStatus,
    }

    #[derive(
        Encode, Decode, DecodeWithMemTracking, TypeInfo, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
    )]
    pub struct ChainProofRecord {
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

    #[derive(
        Encode, Decode, DecodeWithMemTracking, TypeInfo, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
    )]
    pub struct ChainInferenceRequest<AccountId, Balance> {
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
    pub type Miners<T: Config> =
        StorageMap<_, Twox64Concat, MinerId, ChainMiner<T::AccountId, BalanceOf<T>>, OptionQuery>;

    #[pallet::storage]
    pub type Validators<T: Config> = StorageMap<
        _,
        Twox64Concat,
        ValidatorId,
        ChainValidator<T::AccountId, BalanceOf<T>>,
        OptionQuery,
    >;

    #[pallet::storage]
    pub type ProofRecords<T: Config> =
        StorageMap<_, Twox64Concat, RequestId, ChainProofRecord, OptionQuery>;

    #[pallet::storage]
    pub type InferenceRequests<T: Config> = StorageMap<
        _,
        Twox64Concat,
        RequestId,
        ChainInferenceRequest<T::AccountId, BalanceOf<T>>,
        OptionQuery,
    >;

    #[pallet::storage]
    pub type TotalBurned<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A subnet was created.
        SubnetCreated {
            subnet_id: SubnetId,
            owner: T::AccountId,
        },
        /// A miner was registered.
        MinerRegistered {
            miner_id: MinerId,
            subnet_id: SubnetId,
            operator: T::AccountId,
        },
        /// A miner bond was locked and activated.
        MinerActivated {
            miner_id: MinerId,
            bond: BalanceOf<T>,
        },
        /// A miner started the bond exit cooldown.
        MinerExitStarted {
            miner_id: MinerId,
            exit_available_at: BlockNumber,
        },
        /// A miner bond was released after cooldown.
        MinerBondWithdrawn {
            miner_id: MinerId,
            amount: BalanceOf<T>,
        },
        /// A validator was registered and staked.
        ValidatorRegistered {
            validator_id: ValidatorId,
            subnet_id: SubnetId,
            operator: T::AccountId,
        },
        /// A validator started the stake exit cooldown.
        ValidatorExitStarted {
            validator_id: ValidatorId,
            exit_available_at: BlockNumber,
        },
        /// A validator stake was released after cooldown.
        ValidatorStakeWithdrawn {
            validator_id: ValidatorId,
            amount: BalanceOf<T>,
        },
        /// A user opened an inference request and escrowed QBT.
        InferenceRequested {
            request_id: RequestId,
            user: T::AccountId,
            subnet_id: SubnetId,
            miner_id: MinerId,
            validator_id: ValidatorId,
            payment: BalanceOf<T>,
        },
        /// A proof record was accepted.
        ProofAccepted {
            request_id: RequestId,
            miner_id: MinerId,
            validator_id: ValidatorId,
        },
        /// Escrowed request payment was settled.
        InferenceSettled {
            request_id: RequestId,
            miner_payment: BalanceOf<T>,
            validator_fee: BalanceOf<T>,
            treasury_fee: BalanceOf<T>,
        },
        /// Pending inference request escrow was released back to the user.
        InferenceCancelled {
            request_id: RequestId,
            user: T::AccountId,
            payment: BalanceOf<T>,
        },
        /// A proof was rejected by the verifier and the miner was slashed.
        ProofRejected {
            request_id: RequestId,
            miner_id: MinerId,
            slash_bps: u16,
            amount: BalanceOf<T>,
        },
        /// A miner was slashed.
        MinerSlashed {
            miner_id: MinerId,
            amount: BalanceOf<T>,
        },
        /// A validator was slashed.
        ValidatorSlashed {
            validator_id: ValidatorId,
            amount: BalanceOf<T>,
        },
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
        /// Inference payment must be greater than zero.
        InvalidPayment,
        /// Validator and treasury fee split is invalid.
        InvalidFeeSplit,
        /// Proof size metadata is outside accepted bounds.
        InvalidProofSize,
        /// Verification latency exceeds policy.
        LatencyExceeded,
        /// Slash percentage is outside accepted bounds.
        InvalidSlashPercent,
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
            Self::deposit_event(Event::SubnetCreated { subnet_id, owner });
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
            let subnet = Subnets::<T>::get(subnet_id).ok_or(Error::<T>::UnknownSubnet)?;
            ensure!(
                subnet.proof_system == proof_system,
                Error::<T>::ProofSystemMismatch
            );

            Self::burn_free(&operator, T::MinerRegistrationBurn::get())?;
            let miner_id = Self::next_miner_id()?;
            let miner = ChainMiner {
                id: miner_id,
                operator: operator.clone(),
                subnet_id,
                model_commitment,
                proof_system,
                bond: BalanceOf::<T>::default(),
                status: RegistryStatus::Pending,
            };

            Miners::<T>::insert(miner_id, miner);
            Self::deposit_event(Event::MinerRegistered {
                miner_id,
                subnet_id,
                operator,
            });
            Ok(())
        }

        /// Lock a miner bond and activate the miner.
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::activate_miner())]
        pub fn activate_miner(
            origin: OriginFor<T>,
            miner_id: MinerId,
            bond: BalanceOf<T>,
        ) -> DispatchResult {
            let operator = ensure_signed(origin)?;
            Miners::<T>::try_mutate(miner_id, |maybe_miner| -> DispatchResult {
                let miner = maybe_miner.as_mut().ok_or(Error::<T>::UnknownMiner)?;
                ensure!(miner.operator == operator, Error::<T>::NotOperator);
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
                miner.bond = bond;
                miner.status = RegistryStatus::Active;
                Ok(())
            })?;

            Self::deposit_event(Event::MinerActivated { miner_id, bond });
            Ok(())
        }

        /// Register and stake a validator for a subnet.
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::register_validator())]
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
                operator: operator.clone(),
                subnet_id,
                stake,
                status: RegistryStatus::Active,
            };

            Validators::<T>::insert(validator_id, validator);
            Self::deposit_event(Event::ValidatorRegistered {
                validator_id,
                subnet_id,
                operator,
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
        ) -> DispatchResult {
            let validator_operator = ensure_signed(origin)?;
            let policy = Self::validate_submission(&submission, &validator_operator)?;

            match T::ProofVerifier::verify(&submission, policy)? {
                VerificationOutcome::Valid => {}
                VerificationOutcome::Invalid { slash_bps } => {
                    let amount = Self::slash_miner_bond(submission.miner_id, slash_bps)?;
                    Self::deposit_event(Event::ProofRejected {
                        request_id: submission.request_id,
                        miner_id: submission.miner_id,
                        slash_bps,
                        amount,
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
                    miner_id: submission.miner_id,
                    validator_id: submission.validator_id,
                    input_commitment: submission.input_commitment,
                    output_commitment: submission.output_commitment,
                    model_commitment: submission.model_commitment,
                    proof: submission.proof,
                    proof_system: submission.proof_system,
                    proof_size_bytes: submission.proof_size_bytes,
                    verification_latency_ms: submission.verification_latency_ms,
                    submitted_at: submission.submitted_at,
                },
            );
            let (miner_payment, validator_fee, treasury_fee) =
                Self::settle_request_payment(&submission)?;

            Self::deposit_event(Event::ProofAccepted {
                request_id: submission.request_id,
                miner_id: submission.miner_id,
                validator_id: submission.validator_id,
            });
            Self::deposit_event(Event::InferenceSettled {
                request_id: submission.request_id,
                miner_payment,
                validator_fee,
                treasury_fee,
            });
            Ok(())
        }

        /// Slash a miner bond for invalid proof behavior.
        #[pallet::call_index(5)]
        #[pallet::weight(T::WeightInfo::slash_miner())]
        pub fn slash_miner(
            origin: OriginFor<T>,
            miner_id: MinerId,
            slash_bps: u16,
        ) -> DispatchResult {
            ensure_root(origin)?;
            ensure!(
                slash_bps >= T::MinInvalidProofSlashBps::get()
                    && slash_bps <= T::MaxInvalidProofSlashBps::get(),
                Error::<T>::InvalidSlashPercent
            );

            let amount = Self::slash_miner_bond(miner_id, slash_bps)?;
            Self::deposit_event(Event::MinerSlashed { miner_id, amount });
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
            ensure_commitment::<T>(params.input_commitment)?;
            ensure!(
                !InferenceRequests::<T>::contains_key(request_id),
                Error::<T>::DuplicateRequest
            );
            ensure!(
                params.payment > BalanceOf::<T>::default(),
                Error::<T>::InvalidPayment
            );
            Self::validate_fee_split(params.validator_fee_bps, params.treasury_fee_bps)?;
            let subnet = Subnets::<T>::get(params.subnet_id).ok_or(Error::<T>::UnknownSubnet)?;
            ensure!(subnet.active, Error::<T>::NotActive);
            Self::ensure_request_assignment(
                params.subnet_id,
                params.miner_id,
                params.validator_id,
            )?;

            T::Currency::hold(&HoldReason::InferencePayment.into(), &user, params.payment)?;
            InferenceRequests::<T>::insert(
                request_id,
                ChainInferenceRequest {
                    request_id,
                    user: user.clone(),
                    subnet_id: params.subnet_id,
                    miner_id: params.miner_id,
                    validator_id: params.validator_id,
                    input_commitment: params.input_commitment,
                    payment: params.payment,
                    validator_fee_bps: params.validator_fee_bps,
                    treasury_fee_bps: params.treasury_fee_bps,
                    created_at: Self::current_block(),
                    status: InferenceRequestStatus::Pending,
                },
            );

            Self::deposit_event(Event::InferenceRequested {
                request_id,
                user,
                subnet_id: params.subnet_id,
                miner_id: params.miner_id,
                validator_id: params.validator_id,
                payment: params.payment,
            });
            Ok(())
        }

        /// Cancel a pending inference request and release escrowed QBT.
        #[pallet::call_index(7)]
        #[pallet::weight(T::WeightInfo::cancel_inference())]
        #[frame_support::transactional]
        pub fn cancel_inference(origin: OriginFor<T>, request_id: RequestId) -> DispatchResult {
            let user = ensure_signed(origin)?;
            let payment = InferenceRequests::<T>::try_mutate(
                request_id,
                |maybe_request| -> Result<BalanceOf<T>, DispatchError> {
                    let request = maybe_request.as_mut().ok_or(Error::<T>::UnknownRequest)?;
                    ensure!(request.user == user, Error::<T>::NotRequestOwner);
                    ensure!(
                        request.status == InferenceRequestStatus::Pending,
                        Error::<T>::RequestAlreadySettled
                    );
                    let cancel_available_at = request
                        .created_at
                        .checked_add(T::RequestCancelDelayBlocks::get())
                        .ok_or(Error::<T>::ArithmeticOverflow)?;
                    ensure!(
                        Self::current_block() >= cancel_available_at,
                        Error::<T>::RequestCancelUnavailable
                    );
                    T::Currency::release(
                        &HoldReason::InferencePayment.into(),
                        &request.user,
                        request.payment,
                        Precision::Exact,
                    )?;
                    request.status = InferenceRequestStatus::Cancelled;
                    Ok(request.payment)
                },
            )?;

            Self::deposit_event(Event::InferenceCancelled {
                request_id,
                user,
                payment,
            });
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
                ensure!(miner.operator == operator, Error::<T>::NotOperator);
                ensure!(
                    matches!(
                        miner.status,
                        RegistryStatus::Active | RegistryStatus::Slashed
                    ),
                    Error::<T>::InvalidMinerStatus
                );
                miner.status = RegistryStatus::Exiting { exit_available_at };
                Ok(())
            })?;

            Self::deposit_event(Event::MinerExitStarted {
                miner_id,
                exit_available_at,
            });
            Ok(())
        }

        /// Withdraw remaining miner bond after the exit cooldown completes.
        #[pallet::call_index(9)]
        #[pallet::weight(T::WeightInfo::withdraw_miner_bond())]
        #[frame_support::transactional]
        pub fn withdraw_miner_bond(origin: OriginFor<T>, miner_id: MinerId) -> DispatchResult {
            let operator = ensure_signed(origin)?;
            let amount = Miners::<T>::try_mutate(
                miner_id,
                |maybe_miner| -> Result<BalanceOf<T>, DispatchError> {
                    let miner = maybe_miner.as_mut().ok_or(Error::<T>::UnknownMiner)?;
                    ensure!(miner.operator == operator, Error::<T>::NotOperator);
                    let RegistryStatus::Exiting { exit_available_at } = miner.status else {
                        return Err(Error::<T>::InvalidMinerStatus.into());
                    };
                    ensure!(
                        Self::current_block() >= exit_available_at,
                        Error::<T>::MinerExitUnavailable
                    );

                    let amount = miner.bond;
                    let released = if amount == BalanceOf::<T>::default() {
                        amount
                    } else {
                        T::Currency::release(
                            &HoldReason::MinerBond.into(),
                            &miner.operator,
                            amount,
                            Precision::Exact,
                        )?
                    };
                    miner.bond = BalanceOf::<T>::default();
                    miner.status = RegistryStatus::Disabled;
                    Ok(released)
                },
            )?;

            Self::deposit_event(Event::MinerBondWithdrawn { miner_id, amount });
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
                ensure!(validator.operator == operator, Error::<T>::NotOperator);
                ensure!(
                    matches!(
                        validator.status,
                        RegistryStatus::Active | RegistryStatus::Slashed
                    ),
                    Error::<T>::InvalidValidatorStatus
                );
                validator.status = RegistryStatus::Exiting { exit_available_at };
                Ok(())
            })?;

            Self::deposit_event(Event::ValidatorExitStarted {
                validator_id,
                exit_available_at,
            });
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
            let amount = Validators::<T>::try_mutate(
                validator_id,
                |maybe_validator| -> Result<BalanceOf<T>, DispatchError> {
                    let validator = maybe_validator
                        .as_mut()
                        .ok_or(Error::<T>::UnknownValidator)?;
                    ensure!(validator.operator == operator, Error::<T>::NotOperator);
                    let RegistryStatus::Exiting { exit_available_at } = validator.status else {
                        return Err(Error::<T>::InvalidValidatorStatus.into());
                    };
                    ensure!(
                        Self::current_block() >= exit_available_at,
                        Error::<T>::ValidatorExitUnavailable
                    );

                    let amount = validator.stake;
                    let released = if amount == BalanceOf::<T>::default() {
                        amount
                    } else {
                        T::Currency::release(
                            &HoldReason::ValidatorStake.into(),
                            &validator.operator,
                            amount,
                            Precision::Exact,
                        )?
                    };
                    validator.stake = BalanceOf::<T>::default();
                    validator.status = RegistryStatus::Disabled;
                    Ok(released)
                },
            )?;

            Self::deposit_event(Event::ValidatorStakeWithdrawn {
                validator_id,
                amount,
            });
            Ok(())
        }

        /// Slash a validator stake for invalid verification behavior.
        #[pallet::call_index(12)]
        #[pallet::weight(T::WeightInfo::slash_validator())]
        pub fn slash_validator(
            origin: OriginFor<T>,
            validator_id: ValidatorId,
            slash_bps: u16,
        ) -> DispatchResult {
            ensure_root(origin)?;
            ensure!(
                slash_bps >= T::MinInvalidProofSlashBps::get()
                    && slash_bps <= T::MaxInvalidProofSlashBps::get(),
                Error::<T>::InvalidSlashPercent
            );

            let amount = Self::slash_validator_stake(validator_id, slash_bps)?;
            Self::deposit_event(Event::ValidatorSlashed {
                validator_id,
                amount,
            });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
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

        fn current_block() -> BlockNumber {
            frame_system::Pallet::<T>::block_number().saturated_into()
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
            Ok(())
        }

        fn validate_submission(
            submission: &InferenceProofSubmission,
            validator_operator: &T::AccountId,
        ) -> Result<ProofVerificationPolicy, DispatchError> {
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
                    && request.miner_id == submission.miner_id
                    && request.validator_id == submission.validator_id
                    && request.input_commitment == submission.input_commitment,
                Error::<T>::RequestMismatch
            );

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
            ensure!(
                validator.operator == *validator_operator,
                Error::<T>::NotValidatorOperator
            );

            Ok(ProofVerificationPolicy {
                proof_system: subnet.proof_system,
                model_commitment: miner.model_commitment,
                min_proof_size_bytes: T::MinProofSizeBytes::get(),
                max_proof_size_bytes: T::MaxProofSizeBytes::get(),
                max_verification_latency_ms: T::MaxVerificationLatencyMs::get(),
            })
        }

        fn settle_request_payment(
            submission: &InferenceProofSubmission,
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
                            && request.miner_id == submission.miner_id
                            && request.validator_id == submission.validator_id
                            && request.input_commitment == submission.input_commitment,
                        Error::<T>::RequestMismatch
                    );

                    let miner =
                        Miners::<T>::get(submission.miner_id).ok_or(Error::<T>::UnknownMiner)?;
                    let validator = Validators::<T>::get(submission.validator_id)
                        .ok_or(Error::<T>::UnknownValidator)?;
                    let (miner_payment, validator_fee, treasury_fee) = Self::payment_split(
                        request.payment,
                        request.validator_fee_bps,
                        request.treasury_fee_bps,
                    )?;

                    Self::transfer_held_payment(&request.user, &miner.operator, miner_payment)?;
                    Self::transfer_held_payment(&request.user, &validator.operator, validator_fee)?;
                    Self::transfer_held_payment(
                        &request.user,
                        &T::ProtocolTreasury::get(),
                        treasury_fee,
                    )?;
                    request.status = InferenceRequestStatus::Settled;

                    Ok((miner_payment, validator_fee, treasury_fee))
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
            slash_bps: u16,
        ) -> Result<BalanceOf<T>, DispatchError> {
            ensure!(
                slash_bps >= T::MinInvalidProofSlashBps::get()
                    && slash_bps <= T::MaxInvalidProofSlashBps::get(),
                Error::<T>::InvalidSlashPercent
            );

            let amount = Miners::<T>::try_mutate(miner_id, |maybe_miner| {
                let miner = maybe_miner.as_mut().ok_or(Error::<T>::UnknownMiner)?;
                let slash_amount = pro_rata::<T>(miner.bond, slash_bps)?;
                let burned = T::Currency::burn_held(
                    &HoldReason::MinerBond.into(),
                    &miner.operator,
                    slash_amount,
                    Precision::Exact,
                    Fortitude::Force,
                )?;
                miner.bond = miner
                    .bond
                    .checked_sub(&burned)
                    .ok_or(Error::<T>::ArithmeticOverflow)?;
                if miner.bond < T::MinMinerBond::get()
                    && !matches!(miner.status, RegistryStatus::Exiting { .. })
                {
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
                let slash_amount = pro_rata::<T>(validator.stake, slash_bps)?;
                let burned = T::Currency::burn_held(
                    &HoldReason::ValidatorStake.into(),
                    &validator.operator,
                    slash_amount,
                    Precision::Exact,
                    Fortitude::Force,
                )?;
                validator.stake = validator
                    .stake
                    .checked_sub(&burned)
                    .ok_or(Error::<T>::ArithmeticOverflow)?;
                if validator.stake < T::MinValidatorStake::get()
                    && !matches!(validator.status, RegistryStatus::Exiting { .. })
                {
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
