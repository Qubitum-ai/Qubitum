#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, allow(clippy::arithmetic_side_effects, clippy::unwrap_used))]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

use alloc::vec::Vec;

/// Smallest accounting unit for QBT.
pub type Balance = u128;
/// Chain block number.
pub type BlockNumber = u64;
/// Subnet identifier.
pub type SubnetId = u16;
/// Miner identifier inside a subnet.
pub type MinerId = u64;
/// Validator identifier inside a subnet.
pub type ValidatorId = u64;
/// Inference request identifier.
pub type RequestId = u64;
/// Account identifier placeholder used by runtime integrations.
pub type AccountId = [u8; 32];
/// Commitment/hash placeholder used for private data.
pub type Commitment = [u8; 32];

/// Basis points denominator.
pub const BPS_DENOMINATOR: u16 = 10_000;
/// Number of plancks in one QBT.
pub const PLANCKS_PER_QBT: Balance = 1_000_000_000;
/// Initial QBT supply, expressed in whole QBT.
pub const INITIAL_SUPPLY_QBT: Balance = 21_000_000;
/// Initial QBT supply, expressed in plancks.
pub const INITIAL_SUPPLY: Balance = 21_000_000_000_000_000;
/// Four-year halving interval at a nominal twelve-second block time.
pub const HALVING_INTERVAL_BLOCKS: BlockNumber = 10_512_000;
/// Miner emission share.
pub const MINER_EMISSION_BPS: u16 = 5_000;
/// Validator emission share.
pub const VALIDATOR_REWARD_BPS: u16 = 3_000;
/// Protocol treasury emission share.
pub const TREASURY_REWARD_BPS: u16 = 2_000;
/// Required burn for miner registration.
pub const MINER_REGISTRATION_BURN: Balance = 10_000_000_000;
/// Minimum miner bond.
pub const MIN_MINER_BOND: Balance = 100_000_000_000;
/// Maximum miner bond.
pub const MAX_MINER_BOND: Balance = 10_000_000_000_000;
/// Miner exit cooldown at a nominal twelve-second block time.
pub const BOND_EXIT_COOLDOWN_BLOCKS: BlockNumber = 50_400;
/// Minimum invalid-proof slash.
pub const MIN_INVALID_PROOF_SLASH_BPS: u16 = 1_000;
/// Maximum invalid-proof slash.
pub const MAX_INVALID_PROOF_SLASH_BPS: u16 = 10_000;
/// Target proof size lower bound.
pub const TARGET_PROOF_SIZE_MIN_BYTES: u32 = 50 * 1024;
/// Target proof size upper bound.
pub const TARGET_PROOF_SIZE_MAX_BYTES: u32 = 200 * 1024;
/// Target validator verification latency.
pub const TARGET_VERIFICATION_MS: u32 = 100;

/// Protocol-level error shared by runtime and off-chain clients.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    ArithmeticOverflow,
    CooldownNotComplete,
    InvalidBond,
    InvalidCreationBurn,
    InvalidProofSize,
    InvalidRewardSplit,
    InvalidSlashPercent,
    InvalidStake,
    LatencyExceeded,
    MissingCommitment,
    ProofSystemMismatch,
}

/// Execution proof system used by a subnet or proof submission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofSystem {
    Mock,
    RiscZeroStark,
    Stark,
    External(u16),
}

/// Planned account-signature mode for post-quantum migration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureMode {
    ClassicalEcdsa,
    HybridDilithium,
    FullPostQuantum,
}

/// Specialized AI domain for a subnet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubnetDomain {
    General,
    Vision,
    Code,
    Biology,
    Custom(Commitment),
}

/// Entity lifecycle in Qubitum registries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryStatus {
    Pending,
    Active,
    Exiting { exit_available_at: BlockNumber },
    Slashed,
    Disabled,
}

/// Visibility contract for data handled by a proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Visibility {
    Private,
    Public,
    Optional,
}

/// Expected visibility of a protocol element.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivacyElement {
    pub element: PrivacyElementKind,
    pub visibility: Visibility,
}

/// Data element covered by Qubitum privacy guarantees.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyElementKind {
    ModelWeights,
    InferenceInput,
    InferenceOutput,
    MinerIdentity,
}

/// Protocol emission split.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RewardSplit {
    pub miner_bps: u16,
    pub validator_bps: u16,
    pub treasury_bps: u16,
}

impl RewardSplit {
    pub const fn qubitum() -> Self {
        Self {
            miner_bps: MINER_EMISSION_BPS,
            validator_bps: VALIDATOR_REWARD_BPS,
            treasury_bps: TREASURY_REWARD_BPS,
        }
    }

    pub fn validate(self) -> Result<Self, ProtocolError> {
        let sum = self
            .miner_bps
            .checked_add(self.validator_bps)
            .and_then(|value| value.checked_add(self.treasury_bps))
            .ok_or(ProtocolError::ArithmeticOverflow)?;

        if sum == BPS_DENOMINATOR {
            Ok(self)
        } else {
            Err(ProtocolError::InvalidRewardSplit)
        }
    }

    pub fn allocate(self, amount: Balance) -> Result<EmissionAllocation, ProtocolError> {
        self.validate()?;

        let miner = pro_rata(amount, self.miner_bps)?;
        let validator = pro_rata(amount, self.validator_bps)?;
        let assigned = miner
            .checked_add(validator)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        let treasury = amount
            .checked_sub(assigned)
            .ok_or(ProtocolError::ArithmeticOverflow)?;

        Ok(EmissionAllocation {
            miner,
            validator,
            treasury,
        })
    }
}

/// Amounts emitted to each protocol recipient class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmissionAllocation {
    pub miner: Balance,
    pub validator: Balance,
    pub treasury: Balance,
}

/// Miner bond and slash policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MinerBondPolicy {
    pub registration_burn: Balance,
    pub min_bond: Balance,
    pub max_bond: Balance,
    pub exit_cooldown_blocks: BlockNumber,
    pub min_invalid_proof_slash_bps: u16,
    pub max_invalid_proof_slash_bps: u16,
}

impl MinerBondPolicy {
    pub const fn qubitum() -> Self {
        Self {
            registration_burn: MINER_REGISTRATION_BURN,
            min_bond: MIN_MINER_BOND,
            max_bond: MAX_MINER_BOND,
            exit_cooldown_blocks: BOND_EXIT_COOLDOWN_BLOCKS,
            min_invalid_proof_slash_bps: MIN_INVALID_PROOF_SLASH_BPS,
            max_invalid_proof_slash_bps: MAX_INVALID_PROOF_SLASH_BPS,
        }
    }

    pub fn validate_bond(self, bond: Balance) -> Result<Balance, ProtocolError> {
        if bond < self.min_bond || bond > self.max_bond {
            return Err(ProtocolError::InvalidBond);
        }

        Ok(bond)
    }

    pub fn exit_available_at(
        self,
        current_block: BlockNumber,
    ) -> Result<BlockNumber, ProtocolError> {
        current_block
            .checked_add(self.exit_cooldown_blocks)
            .ok_or(ProtocolError::ArithmeticOverflow)
    }

    pub fn slash_amount(self, bond: Balance, slash_bps: u16) -> Result<Balance, ProtocolError> {
        if slash_bps < self.min_invalid_proof_slash_bps
            || slash_bps > self.max_invalid_proof_slash_bps
        {
            return Err(ProtocolError::InvalidSlashPercent);
        }

        pro_rata(bond, slash_bps)
    }
}

/// Runtime policy for a Qubitum subnet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubnetPolicy {
    pub creation_burn: Balance,
    pub miner_bond: MinerBondPolicy,
    pub min_validator_stake: Balance,
    pub proof_system: ProofSystem,
    pub min_proof_size_bytes: u32,
    pub max_proof_size_bytes: u32,
    pub max_verification_latency_ms: u32,
}

impl SubnetPolicy {
    pub const fn qubitum() -> Self {
        Self {
            creation_burn: MINER_REGISTRATION_BURN,
            miner_bond: MinerBondPolicy::qubitum(),
            min_validator_stake: MIN_MINER_BOND,
            proof_system: ProofSystem::RiscZeroStark,
            min_proof_size_bytes: TARGET_PROOF_SIZE_MIN_BYTES,
            max_proof_size_bytes: TARGET_PROOF_SIZE_MAX_BYTES,
            max_verification_latency_ms: TARGET_VERIFICATION_MS,
        }
    }

    pub fn validate_creation_burn(self, amount: Balance) -> Result<Balance, ProtocolError> {
        if amount < self.creation_burn {
            return Err(ProtocolError::InvalidCreationBurn);
        }

        Ok(amount)
    }

    pub fn validate_validator_stake(self, stake: Balance) -> Result<Balance, ProtocolError> {
        if stake < self.min_validator_stake {
            return Err(ProtocolError::InvalidStake);
        }

        Ok(stake)
    }
}

/// Registered Qubitum subnet metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubnetConfig {
    pub id: SubnetId,
    pub owner: AccountId,
    pub domain: SubnetDomain,
    pub policy: SubnetPolicy,
    pub active: bool,
}

/// Registered miner metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MinerRegistration {
    pub id: MinerId,
    pub operator: AccountId,
    pub subnet_id: SubnetId,
    pub model_commitment: Commitment,
    pub proof_system: ProofSystem,
    pub bond: Balance,
    pub status: RegistryStatus,
    pub shielded_identity_commitment: Option<Commitment>,
    pub endpoint_commitment: Option<Commitment>,
}

impl MinerRegistration {
    pub fn activate(mut self, policy: MinerBondPolicy) -> Result<Self, ProtocolError> {
        policy.validate_bond(self.bond)?;
        ensure_commitment(self.model_commitment)?;
        self.status = RegistryStatus::Active;
        Ok(self)
    }

    pub fn begin_exit(
        mut self,
        policy: MinerBondPolicy,
        current_block: BlockNumber,
    ) -> Result<Self, ProtocolError> {
        self.status = RegistryStatus::Exiting {
            exit_available_at: policy.exit_available_at(current_block)?,
        };
        Ok(self)
    }
}

/// Registered validator metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorRegistration {
    pub id: ValidatorId,
    pub operator: AccountId,
    pub staked: Balance,
    pub routing_subnets: Vec<SubnetId>,
    pub status: RegistryStatus,
}

impl ValidatorRegistration {
    pub fn activate(mut self, policy: SubnetPolicy) -> Result<Self, ProtocolError> {
        policy.validate_validator_stake(self.staked)?;
        self.status = RegistryStatus::Active;
        Ok(self)
    }
}

/// Proof submission routed from a miner through a validator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InferenceProofSubmission {
    pub request_id: RequestId,
    pub subnet_id: SubnetId,
    pub miner_id: MinerId,
    pub validator_id: ValidatorId,
    pub input_commitment: Commitment,
    pub output_commitment: Commitment,
    pub model_commitment: Commitment,
    pub proof_system: ProofSystem,
    pub proof_size_bytes: u32,
    pub verification_latency_ms: u32,
    pub submitted_at: BlockNumber,
}

impl InferenceProofSubmission {
    pub fn validate_shape(self, policy: SubnetPolicy) -> Result<Self, ProtocolError> {
        ensure_commitment(self.input_commitment)?;
        ensure_commitment(self.output_commitment)?;
        ensure_commitment(self.model_commitment)?;

        if self.proof_system != policy.proof_system {
            return Err(ProtocolError::ProofSystemMismatch);
        }

        if self.proof_size_bytes < policy.min_proof_size_bytes
            || self.proof_size_bytes > policy.max_proof_size_bytes
        {
            return Err(ProtocolError::InvalidProofSize);
        }

        if self.verification_latency_ms > policy.max_verification_latency_ms {
            return Err(ProtocolError::LatencyExceeded);
        }

        Ok(self)
    }
}

/// Verifier result before settlement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationOutcome {
    Valid,
    Invalid { slash_bps: u16 },
    Error,
}

/// Recorded successful inference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InferenceRecord {
    pub request_id: RequestId,
    pub subnet_id: SubnetId,
    pub miner_id: MinerId,
    pub validator_id: ValidatorId,
    pub input_commitment: Commitment,
    pub output_commitment: Commitment,
    pub model_commitment: Commitment,
    pub recorded_at: BlockNumber,
}

impl InferenceRecord {
    pub fn from_valid_submission(submission: InferenceProofSubmission) -> Self {
        Self {
            request_id: submission.request_id,
            subnet_id: submission.subnet_id,
            miner_id: submission.miner_id,
            validator_id: submission.validator_id,
            input_commitment: submission.input_commitment,
            output_commitment: submission.output_commitment,
            model_commitment: submission.model_commitment,
            recorded_at: submission.submitted_at,
        }
    }
}

/// Payment settlement for a valid inference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InferenceSettlement {
    pub miner_payment: Balance,
    pub validator_fee: Balance,
    pub treasury_fee: Balance,
}

pub fn settle_inference_payment(
    payment: Balance,
    validator_fee_bps: u16,
    treasury_fee_bps: u16,
) -> Result<InferenceSettlement, ProtocolError> {
    let combined_bps = validator_fee_bps
        .checked_add(treasury_fee_bps)
        .ok_or(ProtocolError::ArithmeticOverflow)?;

    if combined_bps > BPS_DENOMINATOR {
        return Err(ProtocolError::InvalidRewardSplit);
    }

    let validator_fee = pro_rata(payment, validator_fee_bps)?;
    let treasury_fee = pro_rata(payment, treasury_fee_bps)?;
    let assigned = validator_fee
        .checked_add(treasury_fee)
        .ok_or(ProtocolError::ArithmeticOverflow)?;
    let miner_payment = payment
        .checked_sub(assigned)
        .ok_or(ProtocolError::ArithmeticOverflow)?;

    Ok(InferenceSettlement {
        miner_payment,
        validator_fee,
        treasury_fee,
    })
}

/// Privacy table from the protocol specification.
pub const PRIVACY_TABLE: [PrivacyElement; 4] = [
    PrivacyElement {
        element: PrivacyElementKind::ModelWeights,
        visibility: Visibility::Private,
    },
    PrivacyElement {
        element: PrivacyElementKind::InferenceInput,
        visibility: Visibility::Private,
    },
    PrivacyElement {
        element: PrivacyElementKind::InferenceOutput,
        visibility: Visibility::Public,
    },
    PrivacyElement {
        element: PrivacyElementKind::MinerIdentity,
        visibility: Visibility::Optional,
    },
];

/// Returns the signature mode expected for a roadmap phase.
pub fn signature_mode_for_year(year: u16) -> SignatureMode {
    if year <= 1 {
        SignatureMode::ClassicalEcdsa
    } else if year == 2 {
        SignatureMode::HybridDilithium
    } else {
        SignatureMode::FullPostQuantum
    }
}

/// Returns the halving epoch for a block number.
pub fn halving_epoch(block: BlockNumber) -> u32 {
    let epoch = block
        .checked_div(HALVING_INTERVAL_BLOCKS)
        .unwrap_or_default();

    u32::try_from(epoch).unwrap_or(u32::MAX)
}

/// Applies Qubitum's four-year halving schedule to an emission amount.
pub fn emission_after_halvings(
    initial_emission: Balance,
    block: BlockNumber,
) -> Result<Balance, ProtocolError> {
    let halvings = halving_epoch(block);
    let shift = core::cmp::min(halvings, 127);
    initial_emission
        .checked_shr(shift)
        .ok_or(ProtocolError::ArithmeticOverflow)
}

fn pro_rata(amount: Balance, bps: u16) -> Result<Balance, ProtocolError> {
    amount
        .checked_mul(Balance::from(bps))
        .and_then(|value| value.checked_div(Balance::from(BPS_DENOMINATOR)))
        .ok_or(ProtocolError::ArithmeticOverflow)
}

fn ensure_commitment(commitment: Commitment) -> Result<(), ProtocolError> {
    if commitment == [0; 32] {
        return Err(ProtocolError::MissingCommitment);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commitment(seed: u8) -> Commitment {
        [seed; 32]
    }

    fn account(seed: u8) -> AccountId {
        [seed; 32]
    }

    #[test]
    fn qubitum_reward_split_allocates_remainder_to_treasury() {
        let split = RewardSplit::qubitum();

        assert_eq!(
            split.allocate(101).unwrap(),
            EmissionAllocation {
                miner: 50,
                validator: 30,
                treasury: 21,
            }
        );
    }

    #[test]
    fn reward_split_rejects_non_100_percent_total() {
        let split = RewardSplit {
            miner_bps: 5_000,
            validator_bps: 3_000,
            treasury_bps: 1_999,
        };

        assert_eq!(split.validate(), Err(ProtocolError::InvalidRewardSplit));
    }

    #[test]
    fn miner_bond_policy_enforces_registration_bounds() {
        let policy = MinerBondPolicy::qubitum();

        assert_eq!(
            policy.validate_bond(MIN_MINER_BOND - 1),
            Err(ProtocolError::InvalidBond)
        );
        assert_eq!(policy.validate_bond(MIN_MINER_BOND), Ok(MIN_MINER_BOND));
        assert_eq!(policy.validate_bond(MAX_MINER_BOND), Ok(MAX_MINER_BOND));
        assert_eq!(
            policy.validate_bond(MAX_MINER_BOND + 1),
            Err(ProtocolError::InvalidBond)
        );
    }

    #[test]
    fn miner_slashing_respects_invalid_proof_bounds() {
        let policy = MinerBondPolicy::qubitum();

        assert_eq!(
            policy.slash_amount(MIN_MINER_BOND, MIN_INVALID_PROOF_SLASH_BPS - 1),
            Err(ProtocolError::InvalidSlashPercent)
        );
        assert_eq!(
            policy
                .slash_amount(MIN_MINER_BOND, MIN_INVALID_PROOF_SLASH_BPS)
                .unwrap(),
            10_000_000_000
        );
    }

    #[test]
    fn proof_submission_validates_commitments_size_latency_and_backend() {
        let policy = SubnetPolicy::qubitum();
        let submission = InferenceProofSubmission {
            request_id: 7,
            subnet_id: 1,
            miner_id: 2,
            validator_id: 3,
            input_commitment: commitment(1),
            output_commitment: commitment(2),
            model_commitment: commitment(3),
            proof_system: ProofSystem::RiscZeroStark,
            proof_size_bytes: TARGET_PROOF_SIZE_MIN_BYTES,
            verification_latency_ms: TARGET_VERIFICATION_MS,
            submitted_at: 42,
        };

        assert!(submission.clone().validate_shape(policy).is_ok());

        let mut too_slow = submission.clone();
        too_slow.verification_latency_ms = TARGET_VERIFICATION_MS + 1;
        assert_eq!(
            too_slow.validate_shape(policy),
            Err(ProtocolError::LatencyExceeded)
        );

        let mut wrong_backend = submission;
        wrong_backend.proof_system = ProofSystem::Mock;
        assert_eq!(
            wrong_backend.validate_shape(policy),
            Err(ProtocolError::ProofSystemMismatch)
        );
    }

    #[test]
    fn miner_and_validator_activation_set_active_status() {
        let miner = MinerRegistration {
            id: 1,
            operator: account(1),
            subnet_id: 0,
            model_commitment: commitment(2),
            proof_system: ProofSystem::RiscZeroStark,
            bond: MIN_MINER_BOND,
            status: RegistryStatus::Pending,
            shielded_identity_commitment: None,
            endpoint_commitment: Some(commitment(3)),
        };

        assert_eq!(
            miner.activate(MinerBondPolicy::qubitum()).unwrap().status,
            RegistryStatus::Active
        );

        let validator = ValidatorRegistration {
            id: 1,
            operator: account(4),
            staked: MIN_MINER_BOND,
            routing_subnets: alloc::vec![0],
            status: RegistryStatus::Pending,
        };

        assert_eq!(
            validator.activate(SubnetPolicy::qubitum()).unwrap().status,
            RegistryStatus::Active
        );
    }

    #[test]
    fn valid_submission_can_be_recorded_without_raw_inputs_or_weights() {
        let submission = InferenceProofSubmission {
            request_id: 9,
            subnet_id: 4,
            miner_id: 5,
            validator_id: 6,
            input_commitment: commitment(7),
            output_commitment: commitment(8),
            model_commitment: commitment(9),
            proof_system: ProofSystem::RiscZeroStark,
            proof_size_bytes: TARGET_PROOF_SIZE_MAX_BYTES,
            verification_latency_ms: 1,
            submitted_at: 100,
        }
        .validate_shape(SubnetPolicy::qubitum())
        .unwrap();

        let record = InferenceRecord::from_valid_submission(submission);

        assert_eq!(record.input_commitment, commitment(7));
        assert_eq!(record.model_commitment, commitment(9));
        assert_eq!(record.recorded_at, 100);
    }

    #[test]
    fn payment_settlement_preserves_total_payment() {
        let settlement = settle_inference_payment(1_000, 250, 50).unwrap();

        assert_eq!(
            settlement,
            InferenceSettlement {
                miner_payment: 970,
                validator_fee: 25,
                treasury_fee: 5,
            }
        );
    }

    #[test]
    fn halving_schedule_reduces_emission_every_four_years() {
        assert_eq!(halving_epoch(0), 0);
        assert_eq!(halving_epoch(HALVING_INTERVAL_BLOCKS), 1);
        assert_eq!(emission_after_halvings(1_000, 0).unwrap(), 1_000);
        assert_eq!(
            emission_after_halvings(1_000, HALVING_INTERVAL_BLOCKS).unwrap(),
            500
        );
        assert_eq!(
            emission_after_halvings(1_000, HALVING_INTERVAL_BLOCKS * 2).unwrap(),
            250
        );
    }

    #[test]
    fn post_quantum_signature_roadmap_is_encoded() {
        assert_eq!(signature_mode_for_year(1), SignatureMode::ClassicalEcdsa);
        assert_eq!(signature_mode_for_year(2), SignatureMode::HybridDilithium);
        assert_eq!(signature_mode_for_year(3), SignatureMode::FullPostQuantum);
    }

    #[test]
    fn privacy_table_matches_specification() {
        assert_eq!(
            PRIVACY_TABLE,
            [
                PrivacyElement {
                    element: PrivacyElementKind::ModelWeights,
                    visibility: Visibility::Private,
                },
                PrivacyElement {
                    element: PrivacyElementKind::InferenceInput,
                    visibility: Visibility::Private,
                },
                PrivacyElement {
                    element: PrivacyElementKind::InferenceOutput,
                    visibility: Visibility::Public,
                },
                PrivacyElement {
                    element: PrivacyElementKind::MinerIdentity,
                    visibility: Visibility::Optional,
                },
            ]
        );
    }
}
