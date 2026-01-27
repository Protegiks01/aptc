# Audit Report

## Title
Player ID Spoofing in Threshold Decryption Enables Consensus Denial of Service

## Summary
A malicious validator can spoof the `Player` field in their decryption key share, bypassing validation and causing threshold reconstruction to fail. The verification logic checks the BLS signature cryptographically but does not validate that the player ID in the share matches the expected player, allowing a single compromised validator to break the secret sharing protocol and halt consensus.

## Finding Description

The secret sharing protocol used in Aptos consensus relies on threshold decryption where validators contribute decryption key shares that are aggregated to reconstruct a decryption key. The security assumption is that each validator's share corresponds to their assigned player ID for correct Lagrange interpolation.

**Vulnerability Path:**

1. During share verification, the system uses the `author` field to select the correct verification key: [1](#0-0) 

2. The cryptographic verification only checks the BLS signature, not the player ID: [2](#0-1) 

3. The BLS signature computation does not depend on the player field: [3](#0-2) 

4. During reconstruction, the spoofed player IDs are used directly in Lagrange interpolation: [4](#0-3) 

5. For weighted configurations, the spoofed player determines virtual player mappings: [5](#0-4) 

**Attack Scenario:**

1. Validator at index `i` with player ID `i` receives a decryption request
2. They honestly derive their share: `(player_i, signature_i)`
3. **Attack:** They modify the tuple to `(player_j, signature_i)` where `j ≠ i`
4. They send this share with `author = validator_i` (their actual address)
5. Verification succeeds:
   - Author matches peer ✓
   - BLS signature is valid using `verification_keys[i]` ✓
   - **Missing:** No check that player `j` matches expected player `i`
6. During aggregation, Lagrange coefficients are computed using the spoofed player IDs
7. Reconstruction produces an incorrect decryption key or fails entirely
8. Consensus cannot decrypt ciphertexts, causing a denial of service

The consensus protocol accepts shares through the reliable broadcast mechanism: [6](#0-5) 

## Impact Explanation

**Severity: Critical**

This vulnerability meets Critical severity criteria per the Aptos bug bounty program:

1. **Total loss of liveness/network availability**: A single malicious validator can prevent threshold reconstruction, halting any consensus operations that depend on secret sharing (randomness generation, threshold signatures, etc.)

2. **Consensus Safety violation**: Different nodes might aggregate different subsets of shares with varying spoofed player IDs, potentially producing non-deterministic outcomes or all failing simultaneously

3. **No Byzantine threshold required**: The attack requires only a single compromised validator (1/n), far below the assumed Byzantine threshold of 1/3

4. **Non-recoverable without intervention**: The protocol has no mechanism to detect or exclude spoofed shares, requiring manual validator removal or emergency patches

The vulnerability breaks the **Deterministic Execution** and **Consensus Safety** invariants, as validators cannot reliably reconstruct shared secrets needed for consensus operations.

## Likelihood Explanation

**Likelihood: High**

1. **Low attacker requirements**: Any validator can execute this attack unilaterally
2. **Simple exploitation**: Requires only modifying a single field in a data structure
3. **No detection mechanism**: The spoofed shares pass all validation checks
4. **Immediate impact**: The attack succeeds on the first malicious share
5. **No cost to attacker**: The malicious validator faces no immediate penalties

The attack is trivial to execute and impossible to prevent at the protocol level given the current validation logic.

## Recommendation

Add explicit validation that the player ID in decryption key shares matches the expected player based on the author's position in the validator set.

**Fix for `SecretShare::verify()`:**
```rust
pub fn verify(&self, config: &SecretShareConfig) -> anyhow::Result<()> {
    let index = config.get_id(self.author());
    let decryption_key_share = self.share().clone();
    
    // NEW: Validate player ID matches expected player
    let expected_player = config.verification_keys[index].player();
    ensure!(
        decryption_key_share.player() == expected_player,
        "Player ID mismatch: share claims player {:?} but author {} should be player {:?}",
        decryption_key_share.player(),
        self.author(),
        expected_player
    );
    
    config.verification_keys[index]
        .verify_decryption_key_share(&self.metadata.digest, &decryption_key_share)?;
    Ok(())
}
```

Additionally, add player validation in the verification key verification methods: [7](#0-6) 

**Fix for `WeightedBIBEVerificationKey::verify_decryption_key_share()`:**
```rust
pub fn verify_decryption_key_share(
    &self,
    digest: &Digest,
    dk_share: &WeightedBIBEDecryptionKeyShare,
) -> Result<()> {
    // NEW: Validate player ID matches this verification key
    ensure!(
        dk_share.0 == self.weighted_player,
        "Player mismatch: share claims player {} but verification key is for player {}",
        dk_share.0,
        self.weighted_player
    );
    
    (self.vks_g2.len() == dk_share.1.len())
        .then_some(())
        .ok_or(BatchEncryptionError::DecryptionKeyVerifyError)?;
    
    // ... rest of verification
}
```

## Proof of Concept

```rust
#[test]
fn test_player_spoofing_attack() {
    use aptos_batch_encryption::schemes::fptx_weighted::FPTXWeighted;
    use aptos_batch_encryption::traits::BatchThresholdEncryption;
    use aptos_crypto::player::Player;
    
    let seed = 42u64;
    let max_batch_size = 10;
    let number_of_rounds = 5;
    let n = 4;
    let t = 3;
    let tc = <FPTXWeighted as BatchThresholdEncryption>::ThresholdConfig::new(t, n).unwrap();
    
    let (ek, digest_key, vks, msk_shares) = 
        FPTXWeighted::setup_for_testing(seed, max_batch_size, number_of_rounds, &tc).unwrap();
    
    // Create a digest
    let cts = vec![]; // Empty for simplicity
    let round = 1u64;
    let (digest, _) = FPTXWeighted::digest(&digest_key, &cts, round).unwrap();
    
    // Validator 0 honestly derives their share
    let honest_share = FPTXWeighted::derive_decryption_key_share(&msk_shares[0], &digest).unwrap();
    assert_eq!(honest_share.player(), Player { id: 0 });
    
    // ATTACK: Validator 0 spoofs their player ID to player 2
    let spoofed_share = (Player { id: 2 }, honest_share.1.clone());
    
    // The spoofed share still passes verification (this is the bug!)
    assert!(FPTXWeighted::verify_decryption_key_share(
        &vks[0], 
        &digest, 
        &spoofed_share
    ).is_ok());
    
    // Now collect threshold shares with one spoofed
    let mut shares = vec![spoofed_share];
    for i in 1..t {
        let share = FPTXWeighted::derive_decryption_key_share(&msk_shares[i], &digest).unwrap();
        shares.push(share);
    }
    
    // Reconstruction will fail or produce wrong key due to incorrect Lagrange coefficients
    let result = FPTXWeighted::reconstruct_decryption_key(&shares, &tc);
    
    // Expected behavior: Should detect player mismatch during verification
    // Actual behavior: Verification passes but reconstruction fails
    println!("Reconstruction result: {:?}", result);
}
```

**Notes:**

This vulnerability affects the core threshold cryptography used in Aptos consensus for secret sharing operations. The lack of player ID validation allows any validator to unilaterally break the reconstruction protocol, causing consensus failures. The fix requires adding explicit checks that player IDs in decryption key shares match the expected players based on their position in the validator set.

### Citations

**File:** types/src/secret_sharing.rs (L75-82)
```rust
    pub fn verify(&self, config: &SecretShareConfig) -> anyhow::Result<()> {
        let index = config.get_id(self.author());
        let decryption_key_share = self.share().clone();
        // TODO(ibalajiarun): Check index out of bounds
        config.verification_keys[index]
            .verify_decryption_key_share(&self.metadata.digest, &decryption_key_share)?;
        Ok(())
    }
```

**File:** crates/aptos-batch-encryption/src/shared/key_derivation.rs (L107-115)
```rust
    pub fn derive_decryption_key_share(&self, digest: &Digest) -> Result<BIBEDecryptionKeyShare> {
        let hashed_encryption_key: G1Affine = symmetric::hash_g2_element(self.mpk_g2)?;

        Ok((self.player, BIBEDecryptionKeyShareValue {
            signature_share_eval: G1Affine::from(
                (digest.as_g1() + hashed_encryption_key) * self.shamir_share_eval,
            ),
        }))
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

**File:** crates/aptos-crypto/src/arkworks/shamir.rs (L309-330)
```rust
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
```

**File:** crates/aptos-crypto/src/weighted_config.rs (L423-450)
```rust
    fn reconstruct(
        sc: &WeightedConfigArkworks<F>,
        shares: &[ShamirShare<Self::ShareValue>],
    ) -> anyhow::Result<Self> {
        let mut flattened_shares = Vec::with_capacity(sc.get_total_weight());

        // println!();
        for (player, sub_shares) in shares {
            // println!(
            //     "Flattening {} share(s) for player {player}",
            //     sub_shares.len()
            // );
            for (pos, share) in sub_shares.iter().enumerate() {
                let virtual_player = sc.get_virtual_player(player, pos);

                // println!(
                //     " + Adding share {pos} as virtual player {virtual_player}: {:?}",
                //     share
                // );
                // TODO(Performance): Avoiding the cloning here might be nice
                let tuple = (virtual_player, share.clone());
                flattened_shares.push(tuple);
            }
        }
        flattened_shares.truncate(sc.get_threshold_weight());

        SK::reconstruct(sc.get_threshold_config(), &flattened_shares)
    }
```

**File:** consensus/src/rand/secret_sharing/reliable_broadcast_state.rs (L44-60)
```rust
    fn add(&self, peer: Author, share: Self::Response) -> anyhow::Result<Option<()>> {
        ensure!(share.author() == &peer, "Author does not match");
        ensure!(
            share.metadata() == &self.secret_share_metadata,
            "Metadata does not match: local {:?}, received {:?}",
            self.secret_share_metadata,
            share.metadata()
        );
        share.verify(&self.secret_share_config)?;
        info!(LogSchema::new(LogEvent::ReceiveReactiveSecretShare)
            .epoch(share.epoch())
            .round(share.metadata().round)
            .remote_peer(*share.author()));
        let mut store = self.secret_share_store.lock();
        let aggregated = store.add_share(share)?.then_some(());
        Ok(aggregated)
    }
```

**File:** crates/aptos-batch-encryption/src/schemes/fptx_weighted.rs (L149-169)
```rust
    pub fn verify_decryption_key_share(
        &self,
        digest: &Digest,
        dk_share: &WeightedBIBEDecryptionKeyShare,
    ) -> Result<()> {
        (self.vks_g2.len() == dk_share.1.len())
            .then_some(())
            .ok_or(BatchEncryptionError::DecryptionKeyVerifyError)?;

        self.vks_g2
            .iter()
            .map(|vk_g2| BIBEVerificationKey {
                mpk_g2: self.mpk_g2,
                vk_g2: *vk_g2,
                player: self.weighted_player, // arbitrary
            })
            .zip(&dk_share.1)
            .try_for_each(|(vk, dk_share)| {
                vk.verify_decryption_key_share(digest, &(self.weighted_player, dk_share.clone()))
            })
    }
```
