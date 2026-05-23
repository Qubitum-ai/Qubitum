use super::{Commitment, ProtocolError, SignatureMode};

/// Signature algorithm family used by an account or transaction envelope.
#[derive(
    codec::Decode,
    codec::DecodeWithMemTracking,
    codec::Encode,
    codec::MaxEncodedLen,
    scale_info::TypeInfo,
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
)]
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

    pub const fn is_dilithium(self) -> bool {
        matches!(self, Self::Dilithium3 | Self::Dilithium5)
    }
}

/// Commitment to a public key and signature payload.
#[derive(
    codec::Decode,
    codec::DecodeWithMemTracking,
    codec::Encode,
    codec::MaxEncodedLen,
    scale_info::TypeInfo,
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
)]
pub struct SignatureCommitment {
    pub algorithm: SignatureAlgorithm,
    pub public_key_commitment: Commitment,
    pub signature_commitment: Commitment,
}

/// Transaction signature bundle used during migration.
#[derive(
    codec::Decode,
    codec::DecodeWithMemTracking,
    codec::Encode,
    codec::MaxEncodedLen,
    scale_info::TypeInfo,
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
)]
pub struct SignatureBundle {
    pub classical: Option<SignatureCommitment>,
    pub post_quantum: Option<SignatureCommitment>,
}

/// Enforces the roadmap phase for accepted account signatures.
#[derive(
    codec::Decode,
    codec::DecodeWithMemTracking,
    codec::Encode,
    codec::MaxEncodedLen,
    scale_info::TypeInfo,
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
)]
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
                require_classical(bundle.classical)?;
                validate_optional_post_quantum(bundle.post_quantum)?;
            }
            SignatureMode::HybridDilithium => {
                require_classical(bundle.classical)?;
                require_dilithium(bundle.post_quantum)?;
            }
            SignatureMode::FullPostQuantum => {
                reject_classical(bundle.classical)?;
                require_post_quantum(bundle.post_quantum)?;
            }
        }

        Ok(bundle)
    }
}

fn require_classical(signature: Option<SignatureCommitment>) -> Result<(), ProtocolError> {
    let signature = signature.ok_or(ProtocolError::MissingClassicalSignature)?;
    validate_classical(signature)
}

fn require_post_quantum(signature: Option<SignatureCommitment>) -> Result<(), ProtocolError> {
    let signature = signature.ok_or(ProtocolError::MissingPostQuantumSignature)?;
    validate_post_quantum(signature)
}

fn require_dilithium(signature: Option<SignatureCommitment>) -> Result<(), ProtocolError> {
    let signature = signature.ok_or(ProtocolError::MissingPostQuantumSignature)?;
    ensure_nonzero_commitments(signature)?;
    if signature.algorithm.is_dilithium() {
        Ok(())
    } else {
        Err(ProtocolError::UnsupportedSignatureAlgorithm)
    }
}

fn reject_classical(signature: Option<SignatureCommitment>) -> Result<(), ProtocolError> {
    if signature.is_some() {
        Err(ProtocolError::ClassicalSignatureDisallowed)
    } else {
        Ok(())
    }
}

fn validate_optional_post_quantum(
    signature: Option<SignatureCommitment>,
) -> Result<(), ProtocolError> {
    if let Some(signature) = signature {
        validate_post_quantum(signature)?;
    }
    Ok(())
}

fn validate_classical(signature: SignatureCommitment) -> Result<(), ProtocolError> {
    ensure_nonzero_commitments(signature)?;
    if signature.algorithm.is_classical() {
        Ok(())
    } else {
        Err(ProtocolError::UnsupportedSignatureAlgorithm)
    }
}

fn validate_post_quantum(signature: SignatureCommitment) -> Result<(), ProtocolError> {
    ensure_nonzero_commitments(signature)?;
    if signature.algorithm.is_post_quantum() {
        Ok(())
    } else {
        Err(ProtocolError::UnsupportedSignatureAlgorithm)
    }
}

fn ensure_nonzero_commitments(signature: SignatureCommitment) -> Result<(), ProtocolError> {
    if signature.public_key_commitment == [0; 32] || signature.signature_commitment == [0; 32] {
        Err(ProtocolError::MissingCommitment)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLASSICAL_ALGORITHMS: [SignatureAlgorithm; 3] = [
        SignatureAlgorithm::Ecdsa,
        SignatureAlgorithm::Sr25519,
        SignatureAlgorithm::Ed25519,
    ];
    const POST_QUANTUM_ALGORITHMS: [SignatureAlgorithm; 4] = [
        SignatureAlgorithm::Dilithium3,
        SignatureAlgorithm::Dilithium5,
        SignatureAlgorithm::Falcon512,
        SignatureAlgorithm::SphincsPlus,
    ];
    const ALL_ALGORITHMS: [SignatureAlgorithm; 7] = [
        SignatureAlgorithm::Ecdsa,
        SignatureAlgorithm::Sr25519,
        SignatureAlgorithm::Ed25519,
        SignatureAlgorithm::Dilithium3,
        SignatureAlgorithm::Dilithium5,
        SignatureAlgorithm::Falcon512,
        SignatureAlgorithm::SphincsPlus,
    ];

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
    fn hybrid_phase_rejects_non_dilithium_post_quantum_signatures() {
        for algorithm in [
            SignatureAlgorithm::Falcon512,
            SignatureAlgorithm::SphincsPlus,
        ] {
            let bundle = SignatureBundle {
                classical: Some(sig(SignatureAlgorithm::Ecdsa, 1)),
                post_quantum: Some(sig(algorithm, 3)),
            };
            assert_eq!(
                SignaturePolicy::new(SignatureMode::HybridDilithium).validate(bundle),
                Err(ProtocolError::UnsupportedSignatureAlgorithm)
            );
        }
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
            Err(ProtocolError::ClassicalSignatureDisallowed)
        );
    }

    #[test]
    fn full_post_quantum_phase_rejects_dual_signature_after_classical_sunset() {
        let bundle = SignatureBundle {
            classical: Some(sig(SignatureAlgorithm::Ecdsa, 1)),
            post_quantum: Some(sig(SignatureAlgorithm::Dilithium3, 3)),
        };

        assert_eq!(
            SignaturePolicy::new(SignatureMode::FullPostQuantum).validate(bundle),
            Err(ProtocolError::ClassicalSignatureDisallowed)
        );
    }

    #[test]
    fn signature_policy_rejects_zero_commitments() {
        let zero_public_key = SignatureBundle {
            classical: Some(SignatureCommitment {
                algorithm: SignatureAlgorithm::Ecdsa,
                public_key_commitment: [0; 32],
                signature_commitment: commitment(2),
            }),
            post_quantum: None,
        };
        assert_eq!(
            SignaturePolicy::new(SignatureMode::ClassicalEcdsa).validate(zero_public_key),
            Err(ProtocolError::MissingCommitment)
        );

        let zero_signature = SignatureBundle {
            classical: None,
            post_quantum: Some(SignatureCommitment {
                algorithm: SignatureAlgorithm::Dilithium3,
                public_key_commitment: commitment(3),
                signature_commitment: [0; 32],
            }),
        };
        assert_eq!(
            SignaturePolicy::new(SignatureMode::FullPostQuantum).validate(zero_signature),
            Err(ProtocolError::MissingCommitment)
        );
    }

    #[test]
    fn signature_policy_validates_optional_slots_when_present() {
        let wrong_extra_slot = SignatureBundle {
            classical: Some(sig(SignatureAlgorithm::Ecdsa, 1)),
            post_quantum: Some(sig(SignatureAlgorithm::Ed25519, 3)),
        };
        assert_eq!(
            SignaturePolicy::new(SignatureMode::ClassicalEcdsa).validate(wrong_extra_slot),
            Err(ProtocolError::UnsupportedSignatureAlgorithm)
        );

        let malformed_extra_slot = SignatureBundle {
            classical: Some(SignatureCommitment {
                algorithm: SignatureAlgorithm::Ecdsa,
                public_key_commitment: [0; 32],
                signature_commitment: commitment(2),
            }),
            post_quantum: Some(sig(SignatureAlgorithm::Dilithium3, 3)),
        };
        assert_eq!(
            SignaturePolicy::new(SignatureMode::FullPostQuantum).validate(malformed_extra_slot),
            Err(ProtocolError::ClassicalSignatureDisallowed)
        );
    }

    #[test]
    fn signature_policy_accepts_every_algorithm_in_its_own_slot() {
        for (index, algorithm) in CLASSICAL_ALGORITHMS.iter().copied().enumerate() {
            let bundle = SignatureBundle {
                classical: Some(sig(algorithm, index as u8 + 10)),
                post_quantum: None,
            };
            assert_eq!(
                SignaturePolicy::new(SignatureMode::ClassicalEcdsa).validate(bundle),
                Ok(bundle)
            );
        }

        for (index, algorithm) in POST_QUANTUM_ALGORITHMS.iter().copied().enumerate() {
            let bundle = SignatureBundle {
                classical: None,
                post_quantum: Some(sig(algorithm, index as u8 + 20)),
            };
            assert_eq!(
                SignaturePolicy::new(SignatureMode::FullPostQuantum).validate(bundle),
                Ok(bundle)
            );
        }
    }

    #[test]
    fn signature_policy_rejects_every_algorithm_in_the_wrong_slot() {
        for (index, algorithm) in POST_QUANTUM_ALGORITHMS.iter().copied().enumerate() {
            let bundle = SignatureBundle {
                classical: Some(sig(algorithm, index as u8 + 30)),
                post_quantum: None,
            };
            assert_eq!(
                SignaturePolicy::new(SignatureMode::ClassicalEcdsa).validate(bundle),
                Err(ProtocolError::UnsupportedSignatureAlgorithm)
            );
        }

        for (index, algorithm) in CLASSICAL_ALGORITHMS.iter().copied().enumerate() {
            let bundle = SignatureBundle {
                classical: None,
                post_quantum: Some(sig(algorithm, index as u8 + 40)),
            };
            assert_eq!(
                SignaturePolicy::new(SignatureMode::FullPostQuantum).validate(bundle),
                Err(ProtocolError::UnsupportedSignatureAlgorithm)
            );
        }
    }

    #[test]
    fn hybrid_policy_matrix_requires_one_valid_signature_per_family() {
        for classical in ALL_ALGORITHMS {
            for post_quantum in ALL_ALGORITHMS {
                let bundle = SignatureBundle {
                    classical: Some(sig(classical, 50)),
                    post_quantum: Some(sig(post_quantum, 60)),
                };
                let expected = if classical.is_classical() && post_quantum.is_dilithium() {
                    Ok(bundle)
                } else {
                    Err(ProtocolError::UnsupportedSignatureAlgorithm)
                };

                assert_eq!(
                    SignaturePolicy::new(SignatureMode::HybridDilithium).validate(bundle),
                    expected
                );
            }
        }
    }
}
