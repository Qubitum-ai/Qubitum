use super::{Commitment, ProtocolError, SignatureMode};

/// Signature algorithm family used by an account or transaction envelope.
#[derive(codec::Decode, codec::Encode, scale_info::TypeInfo, Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureAlgorithm {
    Ecdsa,
    Sr25519,
    Ed25519,
    Dilithium3,
    Dilithium5,
    Falcon512,
    SphincsPlus,
}

impl SignatureAlgorithm {
    pub const fn is_classical(self) -> bool {
        matches!(self, Self::Ecdsa | Self::Sr25519 | Self::Ed25519)
    }

    pub const fn is_post_quantum(self) -> bool {
        matches!(
            self,
            Self::Dilithium3 | Self::Dilithium5 | Self::Falcon512 | Self::SphincsPlus
        )
    }
}

/// Commitment to a public key and signature payload.
#[derive(codec::Decode, codec::Encode, scale_info::TypeInfo, Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureCommitment {
    pub algorithm: SignatureAlgorithm,
    pub public_key_commitment: Commitment,
    pub signature_commitment: Commitment,
}

/// Transaction signature bundle used during migration.
#[derive(codec::Decode, codec::Encode, scale_info::TypeInfo, Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureBundle {
    pub classical: Option<SignatureCommitment>,
    pub post_quantum: Option<SignatureCommitment>,
}

/// Enforces the roadmap phase for accepted account signatures.
#[derive(codec::Decode, codec::Encode, scale_info::TypeInfo, Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignaturePolicy {
    pub mode: SignatureMode,
}

impl SignaturePolicy {
    pub const fn new(mode: SignatureMode) -> Self {
        Self { mode }
    }

    pub fn validate(self, bundle: SignatureBundle) -> Result<SignatureBundle, ProtocolError> {
        match self.mode {
            SignatureMode::ClassicalEcdsa => {
                validate_classical(bundle.classical)?;
            }
            SignatureMode::HybridDilithium => {
                validate_classical(bundle.classical)?;
                validate_post_quantum(bundle.post_quantum)?;
            }
            SignatureMode::FullPostQuantum => {
                validate_post_quantum(bundle.post_quantum)?;
            }
        }

        Ok(bundle)
    }
}

fn validate_classical(signature: Option<SignatureCommitment>) -> Result<(), ProtocolError> {
    let signature = signature.ok_or(ProtocolError::MissingClassicalSignature)?;
    if signature.algorithm.is_classical() {
        Ok(())
    } else {
        Err(ProtocolError::UnsupportedSignatureAlgorithm)
    }
}

fn validate_post_quantum(signature: Option<SignatureCommitment>) -> Result<(), ProtocolError> {
    let signature = signature.ok_or(ProtocolError::MissingPostQuantumSignature)?;
    if signature.algorithm.is_post_quantum() {
        Ok(())
    } else {
        Err(ProtocolError::UnsupportedSignatureAlgorithm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commitment(seed: u8) -> Commitment {
        [seed; 32]
    }

    fn sig(algorithm: SignatureAlgorithm, seed: u8) -> SignatureCommitment {
        SignatureCommitment {
            algorithm,
            public_key_commitment: commitment(seed),
            signature_commitment: commitment(seed.saturating_add(1)),
        }
    }

    #[test]
    fn classical_phase_accepts_classical_signature() {
        let bundle = SignatureBundle {
            classical: Some(sig(SignatureAlgorithm::Ecdsa, 1)),
            post_quantum: None,
        };

        assert_eq!(
            SignaturePolicy::new(SignatureMode::ClassicalEcdsa).validate(bundle),
            Ok(bundle)
        );
    }

    #[test]
    fn hybrid_phase_requires_dual_signatures() {
        let missing_pq = SignatureBundle {
            classical: Some(sig(SignatureAlgorithm::Ecdsa, 1)),
            post_quantum: None,
        };
        assert_eq!(
            SignaturePolicy::new(SignatureMode::HybridDilithium).validate(missing_pq),
            Err(ProtocolError::MissingPostQuantumSignature)
        );

        let dual = SignatureBundle {
            classical: Some(sig(SignatureAlgorithm::Ecdsa, 1)),
            post_quantum: Some(sig(SignatureAlgorithm::Dilithium3, 3)),
        };
        assert_eq!(
            SignaturePolicy::new(SignatureMode::HybridDilithium).validate(dual),
            Ok(dual)
        );
    }

    #[test]
    fn full_post_quantum_phase_accepts_pq_without_classical() {
        let bundle = SignatureBundle {
            classical: None,
            post_quantum: Some(sig(SignatureAlgorithm::Dilithium5, 2)),
        };

        assert_eq!(
            SignaturePolicy::new(SignatureMode::FullPostQuantum).validate(bundle),
            Ok(bundle)
        );
    }

    #[test]
    fn full_post_quantum_phase_rejects_classical_only() {
        let bundle = SignatureBundle {
            classical: Some(sig(SignatureAlgorithm::Ecdsa, 1)),
            post_quantum: None,
        };

        assert_eq!(
            SignaturePolicy::new(SignatureMode::FullPostQuantum).validate(bundle),
            Err(ProtocolError::MissingPostQuantumSignature)
        );
    }
}
