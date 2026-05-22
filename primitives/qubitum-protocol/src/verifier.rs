use super::{
    Commitment, InferenceProofSubmission, InferenceRecord, ProtocolError, SubnetPolicy,
    VerificationOutcome,
};

/// Abstract proof verifier used by runtime adapters and tests.
pub trait ProofVerifier {
    fn verify(
        &self,
        submission: &InferenceProofSubmission,
        policy: SubnetPolicy,
    ) -> Result<VerificationOutcome, ProtocolError>;
}

/// Verifier that accepts any submission matching policy shape constraints.
#[derive(
    codec::Decode, codec::Encode, scale_info::TypeInfo, Clone, Copy, Debug, Default, Eq, PartialEq,
)]
pub struct ShapeVerifier;

impl ProofVerifier for ShapeVerifier {
    fn verify(
        &self,
        submission: &InferenceProofSubmission,
        policy: SubnetPolicy,
    ) -> Result<VerificationOutcome, ProtocolError> {
        submission.clone().validate_shape(policy)?;
        Ok(VerificationOutcome::Valid)
    }
}

/// Deterministic verifier for local protocol tests.
#[derive(codec::Decode, codec::Encode, scale_info::TypeInfo, Clone, Copy, Debug, Eq, PartialEq)]
pub struct MockVerifier {
    pub expected_proof_commitment: Option<Commitment>,
    pub forced_invalid_slash_bps: Option<u16>,
}

impl MockVerifier {
    pub const fn accepting() -> Self {
        Self {
            expected_proof_commitment: None,
            forced_invalid_slash_bps: None,
        }
    }

    pub const fn expecting(proof_commitment: Commitment) -> Self {
        Self {
            expected_proof_commitment: Some(proof_commitment),
            forced_invalid_slash_bps: None,
        }
    }

    pub const fn rejecting(slash_bps: u16) -> Self {
        Self {
            expected_proof_commitment: None,
            forced_invalid_slash_bps: Some(slash_bps),
        }
    }
}

impl ProofVerifier for MockVerifier {
    fn verify(
        &self,
        submission: &InferenceProofSubmission,
        policy: SubnetPolicy,
    ) -> Result<VerificationOutcome, ProtocolError> {
        submission.clone().validate_shape(policy)?;

        if let Some(slash_bps) = self.forced_invalid_slash_bps {
            return Ok(VerificationOutcome::Invalid { slash_bps });
        }

        if let Some(expected) = self.expected_proof_commitment
            && expected != submission.proof_commitment
        {
            return Ok(VerificationOutcome::Invalid {
                slash_bps: policy.miner_bond.min_invalid_proof_slash_bps,
            });
        }

        Ok(VerificationOutcome::Valid)
    }
}

/// Result of processing a proof against a verifier.
#[derive(codec::Decode, codec::Encode, scale_info::TypeInfo, Clone, Debug, Eq, PartialEq)]
pub enum ProofProcessing {
    Accepted(InferenceRecord),
    Rejected { miner_slashed: super::Balance },
}
