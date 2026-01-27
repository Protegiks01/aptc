# Audit Report

## Title
Sensitive Cryptographic Secrets Exposure via Debug Trait Implementation in WeightedBIBEMasterSecretKeyShare

## Summary
The `WeightedBIBEMasterSecretKeyShare` struct derives the `Debug` trait, which automatically exposes sensitive Shamir secret shares (`shamir_share_evals`) when the struct is printed using debug formatting. Combined with `pub(crate)` field visibility, this creates a latent vulnerability where in-crate code could accidentally log these cryptographic secrets, potentially allowing an attacker with log access to reconstruct the master secret key.

## Finding Description
The `WeightedBIBEMasterSecretKeyShare` struct contains highly sensitive cryptographic material - Shamir secret shares of the master secret key used in the batch encryption scheme. [1](#0-0) 

The struct derives `Debug`, which means any code using standard Rust debugging practices will expose these secrets:
- `println!("{:?}", msk_share)` - Direct debug printing
- `dbg!(msk_share)` - Debug macro
- `assert_eq!(expected, actual)` - Test failures automatically print both values using Debug
- Error messages that include the struct via `{:?}` formatting
- Logging statements like `debug!("Share: {:?}", msk_share)`

The fields are `pub(crate)`, meaning any code within the `aptos-batch-encryption` crate can directly access and potentially log them. Furthermore, the struct is exported as a public type alias [2](#0-1) , and used in consensus secret sharing [3](#0-2) .

If a developer adds debug logging during troubleshooting, or if a test uses `assert_eq!` to compare these structs and fails, the sensitive `shamir_share_evals` field would be printed to logs. An attacker who gains access to these logs (through compromised log aggregation systems, monitoring dashboards, or leaked log files) could extract the secret shares. With threshold shares, they could reconstruct the master secret key and decrypt all batch-encrypted consensus data.

This violates the **Cryptographic Correctness** invariant: proper key management requires that secret key material never be exposed through normal operations.

## Impact Explanation
This qualifies as **Medium Severity** under the Aptos bug bounty program criteria for the following reasons:

1. **Conditional Impact**: The vulnerability only materializes if secrets are accidentally logged AND an attacker gains log access
2. **Scope**: If exploited, it could lead to decryption of sensitive consensus data, qualifying as "Limited funds loss or manipulation" or "State inconsistencies requiring intervention"
3. **Threshold Nature**: An attacker would need access to logs from threshold number of validators to reconstruct the master secret key
4. **Real-World Risk**: Log leakage is a known attack vector in production systems (compromised monitoring, misconfigured log aggregation, insider threats)

The impact is less than Critical because:
- It requires both developer error (logging) AND attacker capability (log access)
- It doesn't directly compromise consensus safety or cause network partition
- It's defensive programming weakness rather than direct exploitation

## Likelihood Explanation
The likelihood is **Medium to Low** because:

**Factors Increasing Likelihood:**
- Rust developers commonly use `{:?}` debug formatting during development
- Test failures with `assert_eq!` would automatically trigger exposure
- The struct is used in production consensus code, increasing chances of troubleshooting scenarios
- Log aggregation systems are common targets for attackers

**Factors Decreasing Likelihood:**
- No current code paths in the codebase log these structs (verified via grep)
- The fields being `pub(crate)` limits direct access to in-crate code only
- Production builds typically disable verbose debug logging
- Requires attacker to first compromise log access infrastructure

However, the **consequence severity** (master secret key compromise) is high enough that even low-probability exposure events warrant prevention.

## Recommendation
Implement a custom `Debug` trait that redacts sensitive fields:

```rust
impl fmt::Debug for WeightedBIBEMasterSecretKeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WeightedBIBEMasterSecretKeyShare")
            .field("mpk_g2", &self.mpk_g2)
            .field("weighted_player", &self.weighted_player)
            .field("shamir_share_evals", &"<REDACTED>")
            .finish()
    }
}
```

Similarly, implement custom Debug for the base struct: [4](#0-3) 

This follows the principle of defense-in-depth: even if code accidentally logs these structs, the sensitive material remains protected.

## Proof of Concept

```rust
use aptos_batch_encryption::{
    schemes::fptx_weighted::FPTXWeighted,
    traits::BatchThresholdEncryption,
};
use aptos_crypto::{weighted_config::WeightedConfigArkworks, SecretSharingConfig};

#[test]
fn test_secret_exposure_via_debug() {
    let mut rng = rand::thread_rng();
    let tc = WeightedConfigArkworks::new(3, vec![1, 2, 5]).unwrap();
    
    let (_, _, _, msk_shares) = 
        FPTXWeighted::setup_for_testing(12345, 8, 1, &tc).unwrap();
    
    // This would expose the sensitive shamir_share_evals in logs:
    // In a real scenario, this could happen via:
    // - debug!("MSK Share: {:?}", msk_shares[0]);
    // - assert_eq!(expected_share, msk_shares[0]);  // on test failure
    // - eprintln!("Error with share: {:?}", msk_shares[0]);
    
    let debug_output = format!("{:?}", msk_shares[0]);
    
    // Verify that sensitive data is present in debug output
    assert!(debug_output.contains("shamir_share_evals"));
    assert!(debug_output.len() > 100); // Contains actual field element data
    
    println!("SECURITY ISSUE: Debug output exposes secrets:");
    println!("{}", debug_output);
    
    // An attacker with access to logs containing this output
    // could extract the shamir_share_evals and potentially
    // reconstruct the master secret key with threshold shares
}
```

**Notes**

This vulnerability represents a **defense-in-depth failure** rather than a directly exploitable attack path. The severity is appropriate at Medium because:

1. It requires accidental developer action (logging with Debug) to trigger
2. It requires subsequent attacker access to logs to exploit
3. The impact if exploited (master secret key compromise) is significant
4. The fix is straightforward (custom Debug implementation)
5. Similar issues have been recognized in security-critical Rust codebases as warranting remediation

The `pub(crate)` visibility provides some protection by limiting field access to in-crate code, but the Debug trait implementation undermines this by allowing any code (in or out of crate) that receives the struct to print its contents. This is particularly concerning for cryptographic secrets that should never appear in logs under any circumstances.

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

**File:** types/src/secret_sharing.rs (L25-25)
```rust
pub type MasterSecretKeyShare = <FPTXWeighted as BatchThresholdEncryption>::MasterSecretKeyShare;
```

**File:** types/src/secret_sharing.rs (L136-146)
```rust
pub struct SecretShareConfig {
    _author: Author,
    _epoch: u64,
    validator: Arc<ValidatorVerifier>,
    digest_key: DigestKey,
    msk_share: MasterSecretKeyShare,
    verification_keys: Vec<VerificationKey>,
    config: <FPTXWeighted as BatchThresholdEncryption>::ThresholdConfig,
    encryption_key: EncryptionKey,
    weights: HashMap<Author, u64>,
}
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
