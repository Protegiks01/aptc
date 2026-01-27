# Audit Report

## Title
Uncoordinated DigestKey Generation Causes EncryptionKey Inconsistency Across Validators

## Summary
The batch encryption system's EncryptionKey depends on a DigestKey that is randomly generated locally by each validator without on-chain coordination or deterministic derivation from DKG state. This creates inconsistent encryption parameters across validators, breaking consensus when the secret sharing feature is enabled.

## Finding Description

The `EncryptionKey` struct is constructed from two components in the FPTXWeighted batch threshold encryption scheme: [1](#0-0) 

The EncryptionKey is created in the FPTXWeighted setup function: [2](#0-1) 

The critical issue is that `digest_key.tau_g2` comes from a `DigestKey` that is randomly generated using fresh randomness: [3](#0-2) 

Each call to `DigestKey::new()` with different RNG state produces a completely different `tau` value (line 60), resulting in different `tau_g2` public parameters (line 91). 

**The vulnerability:** There is no mechanism in the codebase to:
1. Store the DigestKey on-chain (no Move resource found)
2. Derive it deterministically from the DKG transcript
3. Coordinate it across validators before secret sharing begins

When validators independently generate their DigestKey, they produce different `tau_g2` values, leading to different `EncryptionKey` instances. This breaks the fundamental assumption that all validators share the same encryption parameters for threshold decryption to work.

The test code reveals this requirement explicitly: [4](#0-3) 

The same DigestKey (`dk`) must be used for all validators (lines 150, 157) to produce consistent encryption keys.

## Impact Explanation

**Current Status:** The feature is currently disabled. ExecutionProxy is initialized with `None` for secret_share_config: [5](#0-4) 

**If Enabled:** This would constitute a **Critical Severity** consensus violation:
- Validators with different EncryptionKeys cannot verify each other's decryption key shares
- Secret share aggregation fails as shares are derived using inconsistent digest parameters
- Encrypted transaction decryption becomes non-deterministic across validators
- This breaks the "Deterministic Execution" invariant requiring all validators to produce identical state roots

## Likelihood Explanation

**Current:** Not exploitable (feature disabled, no production initialization of SecretShareConfig found).

**Future Risk:** If developers enable this feature without implementing proper DigestKey coordination, the system will immediately fail when validators attempt secret sharing. This is a design flaw awaiting activation rather than a current attack vector.

## Recommendation

Implement one of the following coordination mechanisms:

1. **On-chain Storage:** Create a Move resource to store the DigestKey public parameters during DKG completion:
   - Add `digest_key_params: vector<u8>` to the DKGSessionState in dkg.move
   - Validators deserialize and use the same DigestKey for all secret sharing operations

2. **Deterministic Derivation:** Derive the DigestKey deterministically from the DKG transcript using a shared seed
   - Use a hash of the DKG transcript as the RNG seed for DigestKey::new()
   - All validators produce identical DigestKey from the same transcript

3. **Trusted Setup Ceremony:** Perform a one-time trusted setup to generate the DigestKey parameters and distribute them as part of genesis or via on-chain governance proposal

## Proof of Concept

```rust
// Demonstrates that different DigestKey instances produce different EncryptionKeys
use aptos_batch_encryption::shared::digest::DigestKey;
use aptos_batch_encryption::schemes::fptx_weighted::FPTXWeighted;
use aptos_batch_encryption::traits::BatchThresholdEncryption;
use rand::thread_rng;

#[test]
fn test_inconsistent_encryption_keys() {
    let mut rng1 = thread_rng();
    let mut rng2 = thread_rng();
    
    // Validator 1 generates their DigestKey
    let dk1 = DigestKey::new(&mut rng1, 8, 1).unwrap();
    
    // Validator 2 independently generates their DigestKey
    let dk2 = DigestKey::new(&mut rng2, 8, 1).unwrap();
    
    // The tau_g2 values will be different
    assert_ne!(dk1.tau_g2, dk2.tau_g2);
    
    // When used with the same DKG transcript, this produces different EncryptionKeys
    // causing secret sharing to fail across validators
}
```

## Notes

While this represents a critical design flaw, the feature is currently disabled in production (ExecutionProxy.secret_share_config = None). The vulnerability would manifest only upon feature activation without proper DigestKey coordination. This is a HIGH severity implementation gap that must be addressed before enabling encrypted transaction support.

### Citations

**File:** crates/aptos-batch-encryption/src/shared/encryption_key.rs (L14-25)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptionKey {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) sig_mpk_g2: G2Affine,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) tau_g2: G2Affine,
}

impl EncryptionKey {
    pub fn new(sig_mpk_g2: G2Affine, tau_g2: G2Affine) -> Self {
        Self { sig_mpk_g2, tau_g2 }
    }
```

**File:** crates/aptos-batch-encryption/src/schemes/fptx_weighted.rs (L241-243)
```rust
        let mpk_g2: G2Affine = subtranscript.get_dealt_public_key().as_g2();

        let ek = EncryptionKey::new(mpk_g2, digest_key.tau_g2);
```

**File:** crates/aptos-batch-encryption/src/shared/digest.rs (L59-100)
```rust
    pub fn new(rng: &mut impl RngCore, batch_size: usize, num_rounds: usize) -> Option<Self> {
        let tau = Fr::rand(rng);

        let mut tau_powers_fr = vec![Fr::one()];
        let mut cur = tau;
        for _ in 0..batch_size {
            tau_powers_fr.push(cur);
            cur *= &tau;
        }

        let rs: Vec<Fr> = (0..num_rounds).map(|_| Fr::rand(rng)).collect();

        let tau_powers_randomized_fr = rs
            .into_iter()
            .map(|r| {
                tau_powers_fr
                    .iter()
                    .map(|tau_power| r * tau_power)
                    .collect::<Vec<Fr>>()
            })
            .collect::<Vec<Vec<Fr>>>();

        let tau_powers_g1: Vec<Vec<G1Affine>> = tau_powers_randomized_fr
            .into_iter()
            .map(|powers_for_r| G1Projective::from(G1Affine::generator()).batch_mul(&powers_for_r))
            .collect();

        let tau_powers_g1_projective: Vec<Vec<G1Projective>> = tau_powers_g1
            .iter()
            .map(|gs| gs.iter().map(|g| G1Projective::from(*g)).collect())
            .collect();

        let tau_g2: G2Affine = (G2Affine::generator() * tau).into();

        let fk_domain = FKDomain::new(batch_size, batch_size, tau_powers_g1_projective)?;

        Some(DigestKey {
            tau_g2,
            tau_powers_g1,
            fk_domain,
        })
    }
```

**File:** crates/aptos-batch-encryption/src/tests/fptx_weighted_smoke.rs (L147-162)
```rust
    let dk = DigestKey::new(&mut rng, 8, 1).unwrap();

    let (ek, vks, _) =
        FPTXWeighted::setup(&dk, &pp, &subtranscript, &tc, tc.get_player(0), &dks[0]).unwrap();

    let msk_shares: Vec<<FPTXWeighted as BatchThresholdEncryption>::MasterSecretKeyShare> = tc
        .get_players()
        .into_iter()
        .map(|p| {
            let (_, _, msk_share) =
                FPTXWeighted::setup(&dk, &pp, &subtranscript, &tc, p, &dks[p.get_id()]).unwrap();
            msk_share
        })
        .collect();

    weighted_smoke_with_setup(&mut rng, tc, ek, dk, vks, msk_shares);
```

**File:** consensus/src/consensus_provider.rs (L65-72)
```rust
    let execution_proxy = ExecutionProxy::new(
        Arc::new(BlockExecutor::<AptosVMBlockExecutor>::new(aptos_db)),
        txn_notifier,
        state_sync_notifier,
        node_config.transaction_filters.execution_filter.clone(),
        node_config.consensus.enable_pre_commit,
        None,
    );
```
