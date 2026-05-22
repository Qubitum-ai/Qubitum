use super::{
    AccountId, Balance, BlockNumber, Commitment, InferenceProofSubmission, InferenceRecord,
    MinerId, MinerRegistration, ProofProcessing, ProofVerifier, ProtocolError, RegistryStatus,
    RequestId, SubnetConfig, SubnetDomain, SubnetId, SubnetPolicy, ValidatorId,
    ValidatorRegistration, VerificationOutcome, settle_inference_payment,
};
use alloc::collections::BTreeMap;
use alloc::vec;

/// Balance accounting tracked by the protocol state machine.
#[derive(
    codec::Decode, codec::Encode, scale_info::TypeInfo, Clone, Copy, Debug, Default, Eq, PartialEq,
)]
pub struct AccountLedger {
    pub free: Balance,
    pub locked: Balance,
}

impl AccountLedger {
    pub fn total(self) -> Result<Balance, ProtocolError> {
        self.free
            .checked_add(self.locked)
            .ok_or(ProtocolError::ArithmeticOverflow)
    }
}

/// Minimal state machine for Qubitum protocol transitions.
#[derive(codec::Decode, codec::Encode, scale_info::TypeInfo, Clone, Debug, Eq, PartialEq)]
pub struct ProtocolState {
    pub treasury_account: AccountId,
    pub accounts: BTreeMap<AccountId, AccountLedger>,
    pub subnets: BTreeMap<SubnetId, SubnetConfig>,
    pub miners: BTreeMap<MinerId, MinerRegistration>,
    pub validators: BTreeMap<ValidatorId, ValidatorRegistration>,
    pub records: BTreeMap<RequestId, InferenceRecord>,
    pub total_burned: Balance,
    next_subnet_id: SubnetId,
    next_miner_id: MinerId,
    next_validator_id: ValidatorId,
}

impl ProtocolState {
    pub fn new(treasury_account: AccountId) -> Self {
        Self {
            treasury_account,
            accounts: BTreeMap::new(),
            subnets: BTreeMap::new(),
            miners: BTreeMap::new(),
            validators: BTreeMap::new(),
            records: BTreeMap::new(),
            total_burned: 0,
            next_subnet_id: 0,
            next_miner_id: 0,
            next_validator_id: 0,
        }
    }

    pub fn with_genesis(
        treasury_account: AccountId,
        endowed: &[(AccountId, Balance)],
    ) -> Result<Self, ProtocolError> {
        let mut state = Self::new(treasury_account);
        let mut issued: Balance = 0;

        for (account, amount) in endowed.iter().copied() {
            issued = issued
                .checked_add(amount)
                .ok_or(ProtocolError::ArithmeticOverflow)?;
            state.credit(account, amount)?;
        }

        if issued > super::INITIAL_SUPPLY {
            return Err(ProtocolError::ArithmeticOverflow);
        }

        let treasury_remainder = super::INITIAL_SUPPLY
            .checked_sub(issued)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        state.credit(treasury_account, treasury_remainder)?;
        Ok(state)
    }

    pub fn ledger(&self, account: &AccountId) -> AccountLedger {
        self.accounts.get(account).copied().unwrap_or_default()
    }

    pub fn create_subnet(
        &mut self,
        owner: AccountId,
        domain: SubnetDomain,
        creation_burn: Balance,
    ) -> Result<SubnetId, ProtocolError> {
        let policy = SubnetPolicy::qubitum();
        policy.validate_creation_burn(creation_burn)?;
        self.burn(owner, creation_burn)?;

        let id = self.next_subnet_id;
        self.next_subnet_id = self
            .next_subnet_id
            .checked_add(1)
            .ok_or(ProtocolError::ArithmeticOverflow)?;

        let inserted = self
            .subnets
            .insert(
                id,
                SubnetConfig {
                    id,
                    owner,
                    domain,
                    policy,
                    active: true,
                },
            )
            .is_none();

        if inserted {
            Ok(id)
        } else {
            Err(ProtocolError::DuplicateSubnet)
        }
    }

    pub fn register_miner(
        &mut self,
        operator: AccountId,
        subnet_id: SubnetId,
        model_commitment: Commitment,
        proof_system: super::ProofSystem,
    ) -> Result<MinerId, ProtocolError> {
        let policy = self
            .subnets
            .get(&subnet_id)
            .ok_or(ProtocolError::UnknownSubnet)?
            .policy;

        if policy.proof_system != proof_system {
            return Err(ProtocolError::ProofSystemMismatch);
        }

        super::ensure_commitment(model_commitment)?;
        self.burn(operator, policy.miner_bond.registration_burn)?;

        let id = self.next_miner_id;
        self.next_miner_id = self
            .next_miner_id
            .checked_add(1)
            .ok_or(ProtocolError::ArithmeticOverflow)?;

        self.miners.insert(
            id,
            MinerRegistration {
                id,
                operator,
                subnet_id,
                model_commitment,
                proof_system,
                bond: 0,
                status: RegistryStatus::Pending,
                shielded_identity_commitment: None,
                endpoint_commitment: None,
            },
        );

        Ok(id)
    }

    pub fn activate_miner(
        &mut self,
        miner_id: MinerId,
        bond: Balance,
    ) -> Result<(), ProtocolError> {
        let miner = self
            .miners
            .get(&miner_id)
            .ok_or(ProtocolError::UnknownMiner)?;
        let policy = self
            .subnets
            .get(&miner.subnet_id)
            .ok_or(ProtocolError::UnknownSubnet)?
            .policy
            .miner_bond;

        policy.validate_bond(bond)?;
        let operator = miner.operator;
        self.lock(operator, bond)?;

        let miner = self
            .miners
            .get_mut(&miner_id)
            .ok_or(ProtocolError::UnknownMiner)?;
        miner.bond = bond;
        miner.status = RegistryStatus::Active;
        Ok(())
    }

    pub fn begin_miner_exit(
        &mut self,
        miner_id: MinerId,
        current_block: BlockNumber,
    ) -> Result<(), ProtocolError> {
        let miner = self
            .miners
            .get(&miner_id)
            .ok_or(ProtocolError::UnknownMiner)?;
        let policy = self
            .subnets
            .get(&miner.subnet_id)
            .ok_or(ProtocolError::UnknownSubnet)?
            .policy
            .miner_bond;
        let exit_available_at = policy.exit_available_at(current_block)?;

        let miner = self
            .miners
            .get_mut(&miner_id)
            .ok_or(ProtocolError::UnknownMiner)?;
        miner.status = RegistryStatus::Exiting { exit_available_at };
        Ok(())
    }

    pub fn complete_miner_exit(
        &mut self,
        miner_id: MinerId,
        current_block: BlockNumber,
    ) -> Result<(), ProtocolError> {
        let miner = self
            .miners
            .get(&miner_id)
            .ok_or(ProtocolError::UnknownMiner)?;
        let RegistryStatus::Exiting { exit_available_at } = miner.status else {
            return Err(ProtocolError::NotActive);
        };

        if current_block < exit_available_at {
            return Err(ProtocolError::CooldownNotComplete);
        }

        let operator = miner.operator;
        let bond = miner.bond;
        self.unlock(operator, bond)?;

        let miner = self
            .miners
            .get_mut(&miner_id)
            .ok_or(ProtocolError::UnknownMiner)?;
        miner.bond = 0;
        miner.status = RegistryStatus::Disabled;
        Ok(())
    }

    pub fn register_validator(
        &mut self,
        operator: AccountId,
        subnet_id: SubnetId,
        stake: Balance,
    ) -> Result<ValidatorId, ProtocolError> {
        let policy = self
            .subnets
            .get(&subnet_id)
            .ok_or(ProtocolError::UnknownSubnet)?
            .policy;
        policy.validate_validator_stake(stake)?;
        self.lock(operator, stake)?;

        let id = self.next_validator_id;
        self.next_validator_id = self
            .next_validator_id
            .checked_add(1)
            .ok_or(ProtocolError::ArithmeticOverflow)?;

        self.validators.insert(
            id,
            ValidatorRegistration {
                id,
                operator,
                staked: stake,
                routing_subnets: vec![subnet_id],
                status: RegistryStatus::Active,
            },
        );

        Ok(id)
    }

    pub fn submit_valid_proof(
        &mut self,
        payer: AccountId,
        submission: InferenceProofSubmission,
        payment: Balance,
        validator_fee_bps: u16,
        treasury_fee_bps: u16,
    ) -> Result<InferenceRecord, ProtocolError> {
        let policy = self
            .subnets
            .get(&submission.subnet_id)
            .ok_or(ProtocolError::UnknownSubnet)?
            .policy;
        let submission = submission.validate_shape(policy)?;

        let miner_operator = {
            let miner = self
                .miners
                .get(&submission.miner_id)
                .ok_or(ProtocolError::UnknownMiner)?;
            if miner.subnet_id != submission.subnet_id || miner.status != RegistryStatus::Active {
                return Err(ProtocolError::NotActive);
            }
            miner.operator
        };

        let validator_operator = {
            let validator = self
                .validators
                .get(&submission.validator_id)
                .ok_or(ProtocolError::UnknownValidator)?;
            let validator_routes_subnet = validator.routing_subnets.contains(&submission.subnet_id);
            if !validator_routes_subnet || validator.status != RegistryStatus::Active {
                return Err(ProtocolError::NotActive);
            }
            validator.operator
        };

        let settlement = settle_inference_payment(payment, validator_fee_bps, treasury_fee_bps)?;
        self.transfer(payer, miner_operator, settlement.miner_payment)?;
        self.transfer(payer, validator_operator, settlement.validator_fee)?;
        self.transfer(payer, self.treasury_account, settlement.treasury_fee)?;

        let record = InferenceRecord::from_valid_submission(submission);
        self.records.insert(record.request_id, record.clone());
        Ok(record)
    }

    pub fn process_proof<V: ProofVerifier>(
        &mut self,
        payer: AccountId,
        submission: InferenceProofSubmission,
        payment: Balance,
        validator_fee_bps: u16,
        treasury_fee_bps: u16,
        verifier: &V,
    ) -> Result<ProofProcessing, ProtocolError> {
        let policy = self
            .subnets
            .get(&submission.subnet_id)
            .ok_or(ProtocolError::UnknownSubnet)?
            .policy;

        match verifier.verify(&submission, policy)? {
            VerificationOutcome::Valid => {
                let record = self.submit_valid_proof(
                    payer,
                    submission,
                    payment,
                    validator_fee_bps,
                    treasury_fee_bps,
                )?;
                Ok(ProofProcessing::Accepted(record))
            }
            VerificationOutcome::Invalid { slash_bps } => {
                let miner_slashed = self.slash_miner(submission.miner_id, slash_bps)?;
                Ok(ProofProcessing::Rejected { miner_slashed })
            }
            VerificationOutcome::Error => Err(ProtocolError::VerifierError),
        }
    }

    pub fn slash_miner(
        &mut self,
        miner_id: MinerId,
        slash_bps: u16,
    ) -> Result<Balance, ProtocolError> {
        let miner = self
            .miners
            .get(&miner_id)
            .ok_or(ProtocolError::UnknownMiner)?;
        let policy = self
            .subnets
            .get(&miner.subnet_id)
            .ok_or(ProtocolError::UnknownSubnet)?
            .policy
            .miner_bond;
        let slash_amount = policy.slash_amount(miner.bond, slash_bps)?;
        let operator = miner.operator;
        let remaining_bond = miner
            .bond
            .checked_sub(slash_amount)
            .ok_or(ProtocolError::ArithmeticOverflow)?;

        self.burn_locked(operator, slash_amount)?;

        let miner = self
            .miners
            .get_mut(&miner_id)
            .ok_or(ProtocolError::UnknownMiner)?;
        miner.bond = remaining_bond;
        if remaining_bond < policy.min_bond {
            miner.status = RegistryStatus::Slashed;
        }

        Ok(slash_amount)
    }

    fn credit(&mut self, account: AccountId, amount: Balance) -> Result<(), ProtocolError> {
        let ledger = self.accounts.entry(account).or_default();
        ledger.free = ledger
            .free
            .checked_add(amount)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        Ok(())
    }

    fn burn(&mut self, account: AccountId, amount: Balance) -> Result<(), ProtocolError> {
        self.debit_free(account, amount)?;
        self.total_burned = self
            .total_burned
            .checked_add(amount)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        Ok(())
    }

    fn burn_locked(&mut self, account: AccountId, amount: Balance) -> Result<(), ProtocolError> {
        let ledger = self.accounts.entry(account).or_default();
        if ledger.locked < amount {
            return Err(ProtocolError::InsufficientBalance);
        }

        ledger.locked = ledger
            .locked
            .checked_sub(amount)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        self.total_burned = self
            .total_burned
            .checked_add(amount)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        Ok(())
    }

    fn transfer(
        &mut self,
        from: AccountId,
        to: AccountId,
        amount: Balance,
    ) -> Result<(), ProtocolError> {
        self.debit_free(from, amount)?;
        self.credit(to, amount)
    }

    fn lock(&mut self, account: AccountId, amount: Balance) -> Result<(), ProtocolError> {
        self.debit_free(account, amount)?;
        let ledger = self.accounts.entry(account).or_default();
        ledger.locked = ledger
            .locked
            .checked_add(amount)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        Ok(())
    }

    fn unlock(&mut self, account: AccountId, amount: Balance) -> Result<(), ProtocolError> {
        let ledger = self.accounts.entry(account).or_default();
        if ledger.locked < amount {
            return Err(ProtocolError::InsufficientBalance);
        }

        ledger.locked = ledger
            .locked
            .checked_sub(amount)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        ledger.free = ledger
            .free
            .checked_add(amount)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        Ok(())
    }

    fn debit_free(&mut self, account: AccountId, amount: Balance) -> Result<(), ProtocolError> {
        let ledger = self.accounts.entry(account).or_default();
        if ledger.free < amount {
            return Err(ProtocolError::InsufficientBalance);
        }

        ledger.free = ledger
            .free
            .checked_sub(amount)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BOND_EXIT_COOLDOWN_BLOCKS, INITIAL_SUPPLY, MAX_MINER_BOND, MIN_INVALID_PROOF_SLASH_BPS,
        MIN_MINER_BOND, MINER_REGISTRATION_BURN, MockVerifier, ProofEnvelope, ProofSystem,
        TARGET_PROOF_SIZE_MIN_BYTES,
    };

    fn account(seed: u8) -> AccountId {
        [seed; 32]
    }

    fn commitment(seed: u8) -> Commitment {
        [seed; 32]
    }

    fn proof(seed: u8) -> ProofEnvelope {
        ProofEnvelope::risc_zero_v1(commitment(seed), commitment(seed + 1), commitment(seed + 2))
    }

    fn seeded_state() -> ProtocolState {
        ProtocolState::with_genesis(
            account(99),
            &[
                (account(1), 1_000_000_000_000_000),
                (account(2), 1_000_000_000_000_000),
                (account(3), 1_000_000_000_000_000),
                (account(4), 1_000_000_000_000_000),
            ],
        )
        .unwrap()
    }

    #[test]
    fn genesis_credits_treasury_with_remaining_supply() {
        let state = ProtocolState::with_genesis(account(99), &[(account(1), 100)]).unwrap();

        assert_eq!(state.ledger(&account(1)).free, 100);
        assert_eq!(state.ledger(&account(99)).free, INITIAL_SUPPLY - 100);
    }

    #[test]
    fn subnet_creation_burns_qbt_and_records_policy() {
        let mut state = seeded_state();

        let subnet_id = state
            .create_subnet(account(1), SubnetDomain::Code, MINER_REGISTRATION_BURN)
            .unwrap();

        assert_eq!(subnet_id, 0);
        assert_eq!(state.total_burned, MINER_REGISTRATION_BURN);
        assert_eq!(
            state.subnets.get(&subnet_id).unwrap().policy.proof_system,
            ProofSystem::RiscZeroStark
        );
    }

    #[test]
    fn miner_registration_burns_and_activation_locks_bond() {
        let mut state = seeded_state();
        let subnet_id = state
            .create_subnet(account(1), SubnetDomain::General, MINER_REGISTRATION_BURN)
            .unwrap();

        let miner_id = state
            .register_miner(
                account(2),
                subnet_id,
                commitment(10),
                ProofSystem::RiscZeroStark,
            )
            .unwrap();
        state.activate_miner(miner_id, MIN_MINER_BOND).unwrap();

        assert_eq!(
            state.miners.get(&miner_id).unwrap().status,
            RegistryStatus::Active
        );
        assert_eq!(state.ledger(&account(2)).locked, MIN_MINER_BOND);
        assert_eq!(
            state.total_burned,
            MINER_REGISTRATION_BURN + MINER_REGISTRATION_BURN
        );
    }

    #[test]
    fn activation_rejects_bond_outside_policy() {
        let mut state = seeded_state();
        let subnet_id = state
            .create_subnet(account(1), SubnetDomain::General, MINER_REGISTRATION_BURN)
            .unwrap();
        let miner_id = state
            .register_miner(
                account(2),
                subnet_id,
                commitment(10),
                ProofSystem::RiscZeroStark,
            )
            .unwrap();

        assert_eq!(
            state.activate_miner(miner_id, MAX_MINER_BOND + 1),
            Err(ProtocolError::InvalidBond)
        );
    }

    #[test]
    fn validator_registration_locks_stake() {
        let mut state = seeded_state();
        let subnet_id = state
            .create_subnet(account(1), SubnetDomain::Vision, MINER_REGISTRATION_BURN)
            .unwrap();

        let validator_id = state
            .register_validator(account(3), subnet_id, MIN_MINER_BOND)
            .unwrap();

        assert_eq!(
            state.validators.get(&validator_id).unwrap().routing_subnets,
            vec![subnet_id]
        );
        assert_eq!(state.ledger(&account(3)).locked, MIN_MINER_BOND);
    }

    #[test]
    fn valid_proof_settles_payment_and_records_commitments() {
        let mut state = seeded_state();
        let subnet_id = state
            .create_subnet(account(1), SubnetDomain::General, MINER_REGISTRATION_BURN)
            .unwrap();
        let miner_id = state
            .register_miner(
                account(2),
                subnet_id,
                commitment(10),
                ProofSystem::RiscZeroStark,
            )
            .unwrap();
        state.activate_miner(miner_id, MIN_MINER_BOND).unwrap();
        let validator_id = state
            .register_validator(account(3), subnet_id, MIN_MINER_BOND)
            .unwrap();

        let payer_before = state.ledger(&account(4)).free;
        let record = state
            .submit_valid_proof(
                account(4),
                InferenceProofSubmission {
                    request_id: 42,
                    subnet_id,
                    miner_id,
                    validator_id,
                    input_commitment: commitment(1),
                    output_commitment: commitment(2),
                    model_commitment: commitment(10),
                    proof: proof(11),
                    proof_system: ProofSystem::RiscZeroStark,
                    proof_size_bytes: TARGET_PROOF_SIZE_MIN_BYTES,
                    verification_latency_ms: 10,
                    submitted_at: 77,
                },
                1_000,
                250,
                50,
            )
            .unwrap();

        assert_eq!(record.request_id, 42);
        assert_eq!(state.records.get(&42), Some(&record));
        assert_eq!(state.ledger(&account(4)).free, payer_before - 1_000);
        assert_eq!(
            state.ledger(&account(2)).free,
            1_000_000_000_000_000 - MINER_REGISTRATION_BURN - MIN_MINER_BOND + 970
        );
        assert_eq!(
            state.ledger(&account(3)).free,
            1_000_000_000_000_000 - MIN_MINER_BOND + 25
        );
        assert_eq!(
            state.ledger(&account(99)).free,
            INITIAL_SUPPLY - 4_000_000_000_000_000 + 5
        );
    }

    #[test]
    fn process_proof_uses_verifier_and_slashes_invalid_submission() {
        let mut state = seeded_state();
        let subnet_id = state
            .create_subnet(account(1), SubnetDomain::General, MINER_REGISTRATION_BURN)
            .unwrap();
        let miner_id = state
            .register_miner(
                account(2),
                subnet_id,
                commitment(10),
                ProofSystem::RiscZeroStark,
            )
            .unwrap();
        state.activate_miner(miner_id, MIN_MINER_BOND).unwrap();
        let validator_id = state
            .register_validator(account(3), subnet_id, MIN_MINER_BOND)
            .unwrap();

        let result = state
            .process_proof(
                account(4),
                InferenceProofSubmission {
                    request_id: 43,
                    subnet_id,
                    miner_id,
                    validator_id,
                    input_commitment: commitment(1),
                    output_commitment: commitment(2),
                    model_commitment: commitment(10),
                    proof: proof(11),
                    proof_system: ProofSystem::RiscZeroStark,
                    proof_size_bytes: TARGET_PROOF_SIZE_MIN_BYTES,
                    verification_latency_ms: 10,
                    submitted_at: 77,
                },
                1_000,
                250,
                50,
                &MockVerifier::rejecting(MIN_INVALID_PROOF_SLASH_BPS),
            )
            .unwrap();

        assert_eq!(
            result,
            ProofProcessing::Rejected {
                miner_slashed: 10_000_000_000
            }
        );
        assert_eq!(state.records.get(&43), None);
        assert_eq!(state.ledger(&account(2)).locked, 90_000_000_000);
        assert_eq!(
            state.miners.get(&miner_id).unwrap().status,
            RegistryStatus::Slashed
        );
    }

    #[test]
    fn miner_exit_enforces_cooldown_and_unlocks_bond() {
        let mut state = seeded_state();
        let subnet_id = state
            .create_subnet(account(1), SubnetDomain::General, MINER_REGISTRATION_BURN)
            .unwrap();
        let miner_id = state
            .register_miner(
                account(2),
                subnet_id,
                commitment(10),
                ProofSystem::RiscZeroStark,
            )
            .unwrap();
        state.activate_miner(miner_id, MIN_MINER_BOND).unwrap();
        state.begin_miner_exit(miner_id, 10).unwrap();

        assert_eq!(
            state.complete_miner_exit(miner_id, 10 + BOND_EXIT_COOLDOWN_BLOCKS - 1),
            Err(ProtocolError::CooldownNotComplete)
        );

        state
            .complete_miner_exit(miner_id, 10 + BOND_EXIT_COOLDOWN_BLOCKS)
            .unwrap();

        assert_eq!(state.ledger(&account(2)).locked, 0);
        assert_eq!(state.miners.get(&miner_id).unwrap().bond, 0);
        assert_eq!(
            state.miners.get(&miner_id).unwrap().status,
            RegistryStatus::Disabled
        );
    }
}
