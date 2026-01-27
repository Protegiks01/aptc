# Audit Report

## Title
Threshold=1 Secret Sharing Configuration Allows Single Share Key Reconstruction Without Security Validation

## Summary
The `SecretShare::aggregate()` function in `types/src/secret_sharing.rs` accepts and processes threshold=1 configurations without validation, allowing a single share to directly reconstruct the decryption key. While not the default configuration, this represents a critical security weakness in the secret sharing protocol used for consensus randomness generation, as it completely defeats the purpose of threshold cryptography.

## Finding Description

The secret sharing implementation used in Aptos consensus for randomness generation contains no validation to prevent threshold=1 configurations, which fundamentally break the security model of threshold cryptography.

**Code Flow Analysis:**

In `SecretShare::aggregate()`: [1](#0-0) 

The function retrieves the threshold value and takes exactly that many shares for reconstruction. With threshold=1, only a single share is used.

The reconstruction then calls into the cryptographic library: [2](#0-1) 

Which delegates to the Shamir reconstruction algorithm: [3](#0-2) 

The generic reconstruction implementation performs Lagrange interpolation: [4](#0-3) 

**Critical Issue:** When threshold=1, the Lagrange coefficient for a single point is always 1, meaning:
```
reconstructed_key = coefficient * share = 1 * share = share
```

A single share becomes the complete decryption key, providing zero security.

**Validation Gap:**

The WeightedConfig only validates threshold > 0: [5](#0-4) 

Test code explicitly uses threshold=1: [6](#0-5) 

**Security Invariant Violation:**

This breaks the **Cryptographic Correctness** invariant: "BLS signatures, VRF, and hash operations must be secure." Threshold cryptography with threshold=1 provides no security - any single validator can independently decrypt all randomness, eliminating Byzantine fault tolerance for the randomness protocol.

## Impact Explanation

**Severity: Medium**

While the default configuration uses proper thresholds (2/3 reconstruction threshold), the lack of validation creates risk: [7](#0-6) 

**Potential Impact Scenarios:**

1. **Governance Attack**: Malicious governance proposal modifies `randomness_config` to set reconstruction_threshold extremely low, resulting in threshold=1 after rounding
2. **Rounding Algorithm Bug**: Future changes to DKGRounding could inadvertently produce threshold=1 for edge cases
3. **State Inconsistency**: If threshold=1 is used, any single compromised validator can manipulate randomness, breaking consensus safety under the assumption of <1/3 Byzantine validators

**Impact Classification per Bug Bounty:**
- **Medium Severity** ($10,000): "State inconsistencies requiring intervention"
- If exploited, would require network intervention to restore proper randomness generation
- Does not directly cause fund loss, but breaks randomness security guarantees

## Likelihood Explanation

**Likelihood: Low-Medium**

**Factors Decreasing Likelihood:**
- Default configuration uses 2/3 reconstruction threshold, which produces threshold >= 2 for any realistic validator set
- Requires governance approval to modify randomness configuration
- No currently known bug in DKGRounding algorithm

**Factors Increasing Likelihood:**
- No defensive validation anywhere in the stack
- Test code normalizes threshold=1 usage, suggesting developers may not recognize the security issue
- Future code changes could introduce edge cases
- Malicious governance actors could intentionally misconfigure

**Attack Prerequisites:**
- Requires ability to influence on-chain `randomness_config` parameters OR
- Requires undiscovered bug in weight rounding algorithm that produces threshold=1

## Recommendation

Add explicit validation rejecting threshold=1 in multiple layers:

**1. In WeightedConfig::new():**
```rust
pub fn new(threshold_weight: usize, weights: Vec<usize>) -> anyhow::Result<Self> {
    if threshold_weight == 0 {
        return Err(anyhow!(
            "expected the minimum reconstruction weight to be > 0"
        ));
    }
    
    // ADD THIS VALIDATION
    if threshold_weight == 1 {
        return Err(anyhow!(
            "threshold=1 is cryptographically insecure for secret sharing; minimum threshold must be 2"
        ));
    }
    // ... rest of function
}
```

**2. In SecretShare::aggregate():**
```rust
pub fn aggregate<'a>(
    dec_shares: impl Iterator<Item = &'a SecretShare>,
    config: &SecretShareConfig,
) -> anyhow::Result<DecryptionKey> {
    let threshold = config.threshold();
    
    // ADD THIS VALIDATION
    if threshold < 2 {
        return Err(anyhow::anyhow!(
            "Invalid threshold {}: threshold secret sharing requires threshold >= 2",
            threshold
        ));
    }
    
    // ... rest of function
}
```

**3. In on-chain randomness_config validation:** Add invariant checks in Move code when randomness configuration is updated to ensure resulting thresholds will be >= 2.

## Proof of Concept

```rust
#[test]
fn test_threshold_one_security_violation() {
    use aptos_crypto::arkworks::shamir::ShamirThresholdConfig;
    use aptos_batch_encryption::{
        schemes::fptx_weighted::FPTXWeighted,
        traits::BatchThresholdEncryption,
    };
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use rand::thread_rng;
    
    let mut rng = thread_rng();
    
    // Create threshold=1 configuration (INSECURE)
    let t = 1; // threshold
    let n = 3; // number of validators
    let threshold_config = ShamirThresholdConfig::new(t, n);
    
    // Setup encryption system
    let (ek, digest_key, vks, msk_shares) = 
        FPTXWeighted::setup_for_testing(42, 10, 5, &threshold_config).unwrap();
    
    // Generate a digest (randomness challenge)
    let digest = digest_key.hash_to_digest(&[1, 2, 3], 0).unwrap();
    
    // Each validator derives their share
    let dk_shares: Vec<_> = msk_shares
        .iter()
        .map(|msk| FPTXWeighted::derive_decryption_key_share(msk, &digest).unwrap())
        .collect();
    
    // VULNERABILITY: With threshold=1, ANY SINGLE share can reconstruct the key
    let single_share = vec![dk_shares[0].clone()];
    let key_from_one = FPTXWeighted::reconstruct_decryption_key(
        &single_share,
        &threshold_config,
    ).unwrap();
    
    // Verify this single share produces a valid decryption key
    // (In production, this means a single validator can decrypt all randomness)
    let all_shares = vec![dk_shares[0].clone(), dk_shares[1].clone()];
    let key_from_two = FPTXWeighted::reconstruct_decryption_key(
        &all_shares,
        &threshold_config,
    ).unwrap();
    
    // Both keys should be identical, proving threshold=1 provides no security
    assert_eq!(key_from_one, key_from_two);
    
    println!("SECURITY VIOLATION: Single validator (ID={}) can reconstruct key independently", 
             dk_shares[0].player().get_id());
}
```

This PoC demonstrates that with threshold=1, a single share fully reconstructs the decryption key, eliminating the security properties of threshold cryptography and allowing any single validator to decrypt consensus randomness without collaboration.

### Citations

**File:** types/src/secret_sharing.rs (L84-99)
```rust
    pub fn aggregate<'a>(
        dec_shares: impl Iterator<Item = &'a SecretShare>,
        config: &SecretShareConfig,
    ) -> anyhow::Result<DecryptionKey> {
        let threshold = config.threshold();
        let shares: Vec<SecretKeyShare> = dec_shares
            .map(|dec_share| dec_share.share.clone())
            .take(threshold as usize)
            .collect();
        let decryption_key =
            <FPTXWeighted as BatchThresholdEncryption>::reconstruct_decryption_key(
                &shares,
                &config.config,
            )?;
        Ok(decryption_key)
    }
```

**File:** crates/aptos-batch-encryption/src/schemes/fptx_weighted.rs (L371-376)
```rust
    fn reconstruct_decryption_key(
        shares: &[Self::DecryptionKeyShare],
        config: &Self::ThresholdConfig,
    ) -> anyhow::Result<Self::DecryptionKey> {
        BIBEDecryptionKey::reconstruct(config, shares)
    }
```

**File:** crates/aptos-batch-encryption/src/shared/key_derivation.rs (L169-184)
```rust
    fn reconstruct(
        threshold_config: &ShamirThresholdConfig<Fr>,
        shares: &[BIBEDecryptionKeyShare],
    ) -> Result<Self> {
        let signature_g1 = G1Affine::reconstruct(
            threshold_config,
            &shares
                .iter()
                .map(|share| (share.0, share.1.signature_share_eval))
                .collect::<Vec<ShamirGroupShare<G1Affine>>>(),
        )?;

        // sanity check
        Ok(Self { signature_g1 })
    }
}
```

**File:** crates/aptos-crypto/src/arkworks/shamir.rs (L305-331)
```rust
impl<T: WeightedSum> Reconstructable<ShamirThresholdConfig<T::Scalar>> for T {
    type ShareValue = T;

    // Can receive more than `sc.t` shares, but will only use the first `sc.t` shares for efficiency
    fn reconstruct(
        sc: &ShamirThresholdConfig<T::Scalar>,
        shares: &[ShamirShare<Self::ShareValue>],
    ) -> Result<Self> {
        if shares.len() < sc.t {
            Err(anyhow!(
                "Incorrect number of shares provided, received {} but expected at least {}",
                shares.len(),
                sc.t
            ))
        } else {
            let (roots_of_unity_indices, bases): (Vec<usize>, Vec<Self::ShareValue>) = shares
                [..sc.t]
                .iter()
                .map(|(p, g_y)| (p.get_id(), g_y))
                .collect();

            let lagrange_coeffs = sc.lagrange_for_subset(&roots_of_unity_indices);

            Ok(T::weighted_sum(&bases, &lagrange_coeffs))
        }
    }
}
```

**File:** crates/aptos-crypto/src/weighted_config.rs (L68-72)
```rust
        if threshold_weight == 0 {
            return Err(anyhow!(
                "expected the minimum reconstruction weight to be > 0"
            ));
        }
```

**File:** crates/aptos-crypto/src/weighted_config.rs (L459-463)
```rust
        // 1-out-of-1 weighted
        let wc = WeightedConfigBlstrs::new(1, vec![1]).unwrap();
        assert_eq!(wc.starting_index.len(), 1);
        assert_eq!(wc.starting_index[0], 0);
        assert_eq!(wc.get_virtual_player(&wc.get_player(0), 0).id, 0);
```

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L366-373)
```rust
pub static DEFAULT_SECRECY_THRESHOLD: Lazy<U64F64> =
    Lazy::new(|| U64F64::from_num(1) / U64F64::from_num(2));

pub static DEFAULT_RECONSTRUCT_THRESHOLD: Lazy<U64F64> =
    Lazy::new(|| U64F64::from_num(2) / U64F64::from_num(3));

pub static DEFAULT_FAST_PATH_SECRECY_THRESHOLD: Lazy<U64F64> =
    Lazy::new(|| U64F64::from_num(2) / U64F64::from_num(3));
```
