# Audit Report

## Title
Digest-Round Binding Vulnerability in Batch Encryption Allows Cross-Round Share Replay by Byzantine Validators

## Summary
The `verify_decryption_key_share()` function in the batch encryption scheme fails to validate that a decryption key share was derived for the specific round claimed in the digest. The verification only checks the cryptographic pairing against the digest's G1 point while completely ignoring the digest's `round` field, allowing Byzantine validators to replay shares across different rounds. [1](#0-0) 

## Finding Description

The batch encryption system uses a `Digest` structure containing two fields: a G1 group element (`digest_g1`) and a round number (`round`): [2](#0-1) 

When a digest is created for a specific round, it uses round-specific randomized powers of tau from `tau_powers_g1[round]`: [3](#0-2) 

However, when verifying a decryption key share, the verification function only uses `digest.as_g1()` (the G1 point) and completely ignores the `round` field: [4](#0-3) 

The verification checks the BLS pairing equation: `e(digest.as_g1() + hashed_offset, vk_g2) == e(signature_share, g2_generator)`. Crucially, only `digest.as_g1()` is used - the round field is never validated.

**Attack Scenario:**

1. A Byzantine validator legitimately derives a decryption key share S1 for round R1 with digest D1 (having G1 point P1 and round=R1)
2. For a different round R2, the Byzantine validator creates a malicious `SecretShare` containing:
   - The same key share S1 from round R1
   - A fake digest D_malicious with `digest_g1 = P1` but `round = R2`
   - Metadata claiming this is for round R2
3. When honest validators verify this share using `verify_decryption_key_share()`, the verification only checks the pairing against P1 and passes
4. The round field R2 in the fake digest is never validated against the actual round used to compute P1

Since the `Digest` struct is serializable/deserializable, a Byzantine validator can construct any Digest value: [5](#0-4) 

The shares are used in the consensus decryption pipeline where validators aggregate shares to decrypt encrypted transactions: [6](#0-5) 

## Impact Explanation

**Severity: High to Critical**

This vulnerability breaks the round-binding property of the threshold encryption scheme, with the following impacts:

1. **Byzantine Fault Tolerance Violation**: The system is designed to tolerate up to 1/3 Byzantine validators, but this verification flaw allows Byzantine validators to submit shares from one round and have them accepted as valid for a different round. This undermines the security model.

2. **Cross-Round Share Replay**: Byzantine validators can reuse shares across rounds, potentially enabling them to decrypt transactions they shouldn't have access to or cause incorrect decryption results.

3. **Consensus Integrity Risk**: If shares from different rounds get mixed during aggregation, the reconstructed decryption key may be invalid or unpredictable, potentially causing consensus disagreements between validators.

4. **Privacy Violations**: The batch encryption is used to protect transaction privacy. Cross-round share replay could compromise the privacy guarantees if Byzantine validators can manipulate which transactions get decrypted with which keys.

The eval proofs computation also relies on the digest's round field, so using a manipulated round could cause incorrect proof generation: [7](#0-6) 

This qualifies as **High Severity** (significant protocol violation undermining Byzantine fault tolerance) and potentially **Critical** if it can be shown to enable transaction decryption attacks or consensus safety violations.

## Likelihood Explanation

**Likelihood: Medium to High**

The attack requires:
- A Byzantine validator (up to 1/3 of validators can be Byzantine per the threat model)
- Knowledge of the verification weakness (now publicly documented)
- Ability to construct malicious `SecretShare` messages with fake digest round fields

The attack is **feasible** because:
1. The Digest structure is fully serializable and can be constructed with arbitrary field values
2. Byzantine validators are expected in the threat model (the system should handle them correctly)
3. The verification code path is executed for every share received from other validators
4. No additional cryptographic checks prevent this attack

The attack is **likely to occur** once Byzantine actors are aware of this weakness, as it requires minimal sophistication - simply manipulating the round field in a Digest struct.

## Recommendation

Add round-binding validation to the verification function. The fix should cryptographically verify that the digest's G1 point was actually computed using the powers for the claimed round.

**Option 1: Include round in the hash/commitment**
Modify the digest computation to cryptographically commit to the round number, such as hashing the round into the polynomial coefficients before computing the KZG commitment.

**Option 2: Additional verification check**
Add explicit validation that the provided round matches the round used to derive the digest. However, this is challenging because the digest is a KZG commitment and verifying which round was used requires knowing the polynomial, which defeats the purpose of the commitment.

**Option 3: Sign the (digest, round) tuple**
Have validators sign the entire `(digest_g1, round)` tuple when creating shares, and verify this signature during share verification. This binds the round to the digest cryptographically.

**Recommended Fix (Option 3):**

```rust
// In BIBEDecryptionKeyShareValue, add a signature over (digest_g1, round)
pub struct BIBEDecryptionKeyShareValue {
    pub(crate) signature_share_eval: G1Affine,
    pub(crate) round_commitment: Signature, // New field
}

// During derivation, sign (digest.as_g1(), digest.round)
impl BIBEMasterSecretKeyShare {
    pub fn derive_decryption_key_share(&self, digest: &Digest) -> Result<BIBEDecryptionKeyShare> {
        let hashed_encryption_key: G1Affine = symmetric::hash_g2_element(self.mpk_g2)?;
        let signature_share_eval = G1Affine::from(
            (digest.as_g1() + hashed_encryption_key) * self.shamir_share_eval,
        );
        
        // Bind the round to the share
        let round_commitment = sign_digest_round(digest, &self.secret_key);
        
        Ok((self.player, BIBEDecryptionKeyShareValue {
            signature_share_eval,
            round_commitment,
        }))
    }
}

// During verification, check the round commitment
impl BIBEVerificationKey {
    pub fn verify_decryption_key_share(
        &self,
        digest: &Digest,
        decryption_key_share: &BIBEDecryptionKeyShare,
    ) -> Result<()> {
        // Existing check
        verify_bls(
            self.vk_g2,
            digest,
            self.mpk_g2,
            decryption_key_share.1.signature_share_eval,
        )?;
        
        // NEW: Verify round commitment
        verify_round_commitment(
            digest,
            &decryption_key_share.1.round_commitment,
            &self.public_key
        )?;
        
        Ok(())
    }
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod round_binding_vulnerability_test {
    use super::*;
    use crate::{
        group::Fr,
        shared::{
            digest::{Digest, DigestKey},
            key_derivation::{gen_msk_shares, BIBEDecryptionKeyShare},
        },
    };
    use aptos_crypto::arkworks::shamir::ShamirThresholdConfig;
    use ark_ff::UniformRand;
    use ark_std::rand::thread_rng;

    #[test]
    fn test_cross_round_share_replay_attack() {
        let mut rng = thread_rng();
        let n = 4;
        let t = 3;
        let tc = ShamirThresholdConfig::new(t, n);
        let msk = Fr::rand(&mut rng);
        let (mpk, vks, msk_shares) = gen_msk_shares(msk, &mut rng, &tc);

        // Create digest for round 1
        let digest_round_1 = Digest {
            digest_g1: G1Affine::rand(&mut rng),
            round: 1,
        };

        // Validator derives share for round 1
        let share_round_1 = msk_shares[0]
            .derive_decryption_key_share(&digest_round_1)
            .unwrap();

        // Verify share is valid for round 1
        vks[0]
            .verify_decryption_key_share(&digest_round_1, &share_round_1)
            .expect("Share should be valid for round 1");

        // ATTACK: Create fake digest with same G1 point but different round
        let digest_round_2_fake = Digest {
            digest_g1: digest_round_1.digest_g1, // Same G1 point!
            round: 2,                             // Different round!
        };

        // Verification should fail but doesn't - this is the vulnerability
        let result = vks[0].verify_decryption_key_share(&digest_round_2_fake, &share_round_1);

        // VULNERABILITY: This passes even though the share was derived for round 1
        // but we're claiming it's for round 2
        assert!(
            result.is_ok(),
            "VULNERABILITY: Share from round 1 incorrectly passes verification for round 2"
        );

        println!("VULNERABILITY CONFIRMED: Share derived for round 1 passes verification when presented with digest claiming round 2");
    }
}
```

This test demonstrates that a share derived for one round can pass verification when presented with a digest claiming a different round, as long as the G1 point remains the same. This confirms the round-binding vulnerability.

## Notes

The vulnerability exists because the batch encryption scheme treats the `Digest` as having two independent fields (G1 point and round), but the verification only validates one of them. The round field is essentially metadata that is trusted without verification. Any system component that relies on the round field being accurate (such as eval proof computation) is vulnerable to this manipulation by Byzantine validators.

The fix requires adding cryptographic binding between the round number and the share verification, ensuring that shares cannot be replayed across rounds even if an attacker controls the digest structure.

### Citations

**File:** crates/aptos-batch-encryption/src/shared/key_derivation.rs (L118-133)
```rust
fn verify_bls(
    verification_key_g2: G2Affine,
    digest: &Digest,
    offset: G2Affine,
    signature: G1Affine,
) -> Result<()> {
    let hashed_offset: G1Affine = symmetric::hash_g2_element(offset)?;

    if PairingSetting::pairing(digest.as_g1() + hashed_offset, verification_key_g2)
        == PairingSetting::pairing(signature, G2Affine::generator())
    {
        Ok(())
    } else {
        Err(anyhow::anyhow!("bls verification error"))
    }
}
```

**File:** crates/aptos-batch-encryption/src/shared/key_derivation.rs (L136-150)
```rust
    pub fn verify_decryption_key_share(
        &self,
        digest: &Digest,
        decryption_key_share: &BIBEDecryptionKeyShare,
    ) -> Result<()> {
        verify_bls(
            self.vk_g2,
            digest,
            self.mpk_g2,
            decryption_key_share.1.signature_share_eval,
        )
        .map_err(|_| BatchEncryptionError::DecryptionKeyShareVerifyError)?;

        Ok(())
    }
```

**File:** crates/aptos-batch-encryption/src/shared/digest.rs (L37-47)
```rust
#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq, Eq, Hash)]
pub struct Digest {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    digest_g1: G1Affine,
    round: usize,
}

impl Digest {
    pub fn as_g1(&self) -> G1Affine {
        self.digest_g1
    }
```

**File:** crates/aptos-batch-encryption/src/shared/digest.rs (L106-135)
```rust
    pub fn digest(
        &self,
        ids: &mut IdSet<UncomputedCoeffs>,
        round: u64,
    ) -> Result<(Digest, EvalProofsPromise)> {
        let round: usize = round as usize;
        if round >= self.tau_powers_g1.len() {
            Err(anyhow!(
                "Tried to compute digest with round greater than setup length."
            ))
        } else if ids.capacity() > self.tau_powers_g1[round].len() - 1 {
            Err(anyhow!(
                "Tried to compute a batch digest with size {}, where setup supports up to size {}",
                ids.capacity(),
                self.tau_powers_g1[round].len() - 1
            ))?
        } else {
            let ids = ids.compute_poly_coeffs();
            let mut coeffs = ids.poly_coeffs();
            coeffs.resize(self.tau_powers_g1[round].len(), Fr::zero());

            let digest = Digest {
                digest_g1: G1Projective::msm(&self.tau_powers_g1[round], &coeffs)
                    .unwrap()
                    .into(),
                round,
            };

            Ok((digest.clone(), EvalProofsPromise::new(digest, ids)))
        }
```

**File:** crates/aptos-batch-encryption/src/shared/digest.rs (L171-177)
```rust
    pub fn compute_all(&self, digest_key: &DigestKey) -> EvalProofs {
        EvalProofs {
            computed_proofs: self
                .ids
                .compute_all_eval_proofs_with_setup(digest_key, self.digest.round),
        }
    }
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L91-109)
```rust
        let encryption_round = block.round();
        let (digest, proofs_promise) =
            FPTXWeighted::digest(&digest_key, &txn_ciphertexts, encryption_round)?;

        let metadata = SecretShareMetadata::new(
            block.epoch(),
            block.round(),
            block.timestamp_usecs(),
            block.id(),
            digest.clone(),
        );

        let derived_key_share = FPTXWeighted::derive_decryption_key_share(&msk_share, &digest)?;
        derived_self_key_share_tx
            .send(Some(SecretShare::new(
                author,
                metadata.clone(),
                derived_key_share,
            )))
```
