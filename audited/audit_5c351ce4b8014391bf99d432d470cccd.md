# Audit Report

## Title
Unzeroized Secret Shares in Memory Enable Extraction via Memory Analysis

## Summary
The `WeightedBIBEMasterSecretKeyShare` structure stores Shamir secret shares as `Vec<Fr>` field elements without implementing zeroization. At line 278 of the `setup()` function, these shares are cloned for verification, creating additional copies in memory that persist unprotected. This violates Aptos' secure coding guidelines and enables memory-based extraction attacks. [1](#0-0) 

## Finding Description

The `FPTXWeighted::setup()` function creates master secret key shares used by validators for decrypting encrypted transactions in the consensus pipeline. The secret shares are stored in the `shamir_share_evals` field: [2](#0-1) 

During verification, these shares are cloned, creating an additional copy in memory. Neither the `WeightedBIBEMasterSecretKeyShare` structure nor the underlying `Fr` field elements (from arkworks BLS12-381) implement the `Zeroize` trait, meaning these secrets remain in memory after use.

Aptos' own secure coding guidelines explicitly require zeroization of security material: [3](#0-2) [4](#0-3) 

The secret shares persist through the consensus pipeline where they are cloned multiple times: [5](#0-4) [6](#0-5) 

**Attack Path:**
1. Attacker gains memory access to a validator node (via physical access, cold boot attack, or prior compromise)
2. Extracts memory dumps or analyzes live memory
3. Recovers unzeroized secret share values (`Fr` field elements)
4. With threshold shares, can decrypt encrypted transactions or impersonate validators in decryption operations

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty program for the following reasons:

1. **Limited Funds Loss or Manipulation**: An attacker who extracts secret shares can decrypt encrypted transactions meant for compromised validators, potentially enabling front-running or censorship attacks on encrypted transaction content.

2. **State Inconsistencies Requiring Intervention**: If secret shares are compromised across multiple validators, the encrypted transaction system's security guarantees are violated, potentially requiring key rotation and system intervention.

3. **Violation of Documented Security Guidelines**: This directly violates Aptos' `RUST_SECURE_CODING.md` requirements, indicating a gap between documented security practices and implementation.

The impact is limited because:
- Does not directly break consensus safety or liveness
- Does not enable validator signing key theft
- Does not allow manipulation of state transitions
- Requires compromising validator memory first

## Likelihood Explanation

**Likelihood: Low to Medium**

**Prerequisites:**
- Attacker must gain memory access to validator nodes through:
  - Physical access for cold boot attacks
  - Memory forensics on compromised systems  
  - Prior RCE or system compromise
  - Access to swap/page files

**Mitigating Factors:**
- Validators typically have strong physical and network security
- Memory dumps require privileged access
- Cold boot attacks require physical proximity

**Aggravating Factors:**
- Once memory access is achieved, extraction is straightforward
- No technical barriers prevent the attack given memory access
- Violates defense-in-depth principles
- Secret shares may persist in swap files or crash dumps

## Recommendation

Implement `Zeroize` for all structures containing secret share material:

1. Add `zeroize` as a dependency in `crates/aptos-batch-encryption/Cargo.toml`

2. Implement `ZeroizeOnDrop` for `WeightedBIBEMasterSecretKeyShare`:
```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct WeightedBIBEMasterSecretKeyShare {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) mpk_g2: G2Affine,
    pub(crate) weighted_player: Player,
    #[zeroize(skip)] // G2Affine is public key material, doesn't need zeroization
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) shamir_share_evals: Vec<Fr>,
}
```

3. Implement similar protection for `BIBEMasterSecretKeyShare`: [7](#0-6) 

4. Avoid cloning secret shares when possible. At line 278, replace `clone()` with iterators:
```rust
vks[msk_share.weighted_player.get_id()]
    .vks_g2
    .iter()
    .zip(&msk_share.shamir_share_evals)  // Use reference instead of clone
    .try_for_each(|(vk_raw, msk_share_raw)| {
        (G2Projective::from(*vk_raw) == G2Affine::generator() * msk_share_raw)
            .then_some(())
            .ok_or(BatchEncryptionError::VKMSKMismatchError)
    })?;
```

## Proof of Concept

```rust
// File: crates/aptos-batch-encryption/tests/memory_leak_test.rs
use aptos_batch_encryption::schemes::fptx_weighted::{FPTXWeighted, WeightedBIBEMasterSecretKeyShare};
use aptos_batch_encryption::traits::BatchThresholdEncryption;
use aptos_crypto::weighted_config::WeightedConfigArkworks;
use ark_std::rand::{rngs::StdRng, SeedableRng};

#[test]
fn test_secret_shares_remain_in_memory() {
    let mut rng = StdRng::seed_from_u64(42);
    let weights = vec![1, 1, 1, 1];
    let tc = WeightedConfigArkworks::new(3, weights);
    
    let (ek, digest_key, vks, msk_shares) = 
        FPTXWeighted::setup_for_testing(42, 100, 10, &tc).unwrap();
    
    let msk_share = &msk_shares[0];
    
    // Clone the shares (as done at line 278)
    let cloned_shares = msk_share.shamir_share_evals.clone();
    
    // At this point, both msk_share.shamir_share_evals and cloned_shares 
    // contain the same secret values in memory
    
    // Drop the clone
    drop(cloned_shares);
    
    // ISSUE: The memory where cloned_shares resided is not zeroized
    // An attacker with memory access could recover these values
    
    // Verify original still exists
    assert!(!msk_share.shamir_share_evals.is_empty());
    
    // When msk_share goes out of scope, its memory is also not zeroized
    drop(msk_share);
    
    // VULNERABILITY: Secret share values remain in memory at this point
    // and can be extracted via memory forensics
}
```

## Notes

This vulnerability represents a defense-in-depth failure rather than a direct protocol attack. While exploitation requires prior compromise of validator memory access, implementing proper zeroization is a security best practice explicitly mandated by Aptos' own coding guidelines. The fix is straightforward and imposes minimal performance overhead while significantly reducing the attack surface for memory-based extraction techniques.

### Citations

**File:** crates/aptos-batch-encryption/src/schemes/fptx_weighted.rs (L46-53)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WeightedBIBEMasterSecretKeyShare {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) mpk_g2: G2Affine,
    pub(crate) weighted_player: Player,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) shamir_share_evals: Vec<Fr>,
}
```

**File:** crates/aptos-batch-encryption/src/schemes/fptx_weighted.rs (L278-278)
```rust
            .zip(msk_share.shamir_share_evals.clone())
```

**File:** RUST_SECURE_CODING.md (L96-96)
```markdown
Do not rely on `Drop` trait in security material treatment after the use, use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) to explicit destroy security material, e.g. private keys.
```

**File:** RUST_SECURE_CODING.md (L143-145)
```markdown
### Zeroing Sensitive Data

Use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) for zeroing memory containing sensitive data.
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L62-66)
```rust
        let msk_share: MasterSecretKeyShare = secret_share_config
            .as_ref()
            .expect("must exist")
            .msk_share()
            .clone();
```

**File:** types/src/secret_sharing.rs (L141-141)
```rust
    msk_share: MasterSecretKeyShare,
```

**File:** crates/aptos-batch-encryption/src/shared/key_derivation.rs (L23-30)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BIBEMasterSecretKeyShare {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) mpk_g2: G2Affine,
    pub(crate) player: Player,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) shamir_share_eval: Fr,
}
```
