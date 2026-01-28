# Audit Report

## Title
Missing Player ID Validation in Secret Share Aggregation Enables Denial of Service via Duplicate Virtual Player IDs

## Summary
A malicious validator can forge the `Player` ID field in their decryption key share to match another validator's ID, bypassing verification and causing duplicate virtual player indices during Lagrange interpolation reconstruction. This triggers a panic in `batch_inversion` when computing Lagrange coefficients for duplicate evaluation points, resulting in denial of service for encrypted transaction processing in the consensus pipeline.

## Finding Description

The secret sharing implementation in Aptos Core fails to validate that the `Player` ID embedded in a decryption key share matches the expected player index for the share's `Author`. This breaks the critical invariant that each validator's shares must correspond to their unique position in the weighted threshold scheme.

**Vulnerability Chain:**

1. **Missing Validation**: The `verify()` function maps the share's `Author` to an expected validator index but never validates that the `Player` ID embedded in the share matches this index. [1](#0-0) 

The verification retrieves the index from the Author (line 76) and uses the corresponding verification key (line 79), but the `Player` ID field within `decryption_key_share.0` is never examined or validated against this expected index.

2. **Verification Bypass**: The cryptographic verification constructs validation using the verification key's player field, not the claimed Player ID from the share itself. A malicious validator can provide a cryptographically valid share (signed with their own key) but with an arbitrary Player ID field. [2](#0-1) 

At line 163 and 167, `self.weighted_player` (from the verification key structure indexed by Author) is used for BLS verification, not `dk_share.0` (the Player ID claimed in the share). The Player ID field in the share is completely ignored during verification.

3. **Duplicate Virtual Players**: During weighted reconstruction, shares are flattened into virtual players based on their **claimed** Player ID from the share tuple. [3](#0-2) 

At line 430, the function iterates over shares extracting the `player` field from each tuple. Line 436 uses this claimed player to compute virtual players via `sc.get_virtual_player(player, pos)`. If two shares claim the same Player ID (one legitimate, one forged), both generate virtual players for the same base player index, creating duplicates in `flattened_shares`.

4. **Panic in Lagrange Interpolation**: The duplicate virtual player indices are passed to Lagrange coefficient computation, which creates a vanishing polynomial with duplicate roots. The derivative of this polynomial evaluates to zero at duplicate points. [4](#0-3) 

At line 262, `xs_vec` is constructed from indices (containing duplicates). Line 265 creates a vanishing polynomial with duplicate roots (e.g., `(X - ω^i)²`). Line 277 differentiates this polynomial, which evaluates to zero at the duplicate point. Line 281-282 calls `batch_inversion` on these derivative evaluations, which panics when encountering zero values.

**Attack Execution:**

1. Malicious validator V₁ (Author A₁, expected Player P₁) legitimately derives their key share
2. V₁ modifies the share tuple from `(P₁, value₁)` to `(P₂, value₁)` where P₂ is another validator's player ID
3. V₁ creates `SecretShare` with Author A₁ and forged share `(P₂, value₁)` and broadcasts it
4. Other validators receive and verify the share using `verify()`, which checks against A₁'s verification key (passes cryptographically)
5. Legitimate validator V₂ broadcasts their share `(P₂, value₂)`
6. Both shares pass verification and are stored (keyed by distinct Authors A₁ and A₂)
7. When threshold is met, aggregation begins in `SecretShareStore::try_aggregate()` [5](#0-4) 

8. The blocking task at line 55-70 calls `SecretShare::aggregate()`, which reconstructs with weighted config
9. Both shares' virtual players overlap due to identical claimed Player IDs
10. Lagrange interpolation encounters duplicate indices → zero derivative → `batch_inversion` panic
11. The spawned task crashes, `decision_tx` never receives the decryption key, blocks cannot proceed

## Impact Explanation

**Severity: HIGH** (per Aptos bug bounty criteria)

This vulnerability enables a single Byzantine validator to cause:

- **Denial of service for encrypted transactions**: The panic in the aggregation task prevents reconstruction of decryption keys, blocking all encrypted transaction processing for affected blocks
- **Consensus pipeline disruption**: Blocks requiring secret share aggregation cannot progress, stalling the consensus pipeline
- **Protocol violation**: Violates Byzantine fault tolerance assumptions that the system should tolerate up to ⅓ malicious validators without service disruption

The attack affects consensus availability rather than safety. It prevents progress on encrypted transactions but doesn't cause state divergence or fund loss. However, if encrypted transactions become critical for system operation, this could escalate to "Total Loss of Liveness/Network Availability" (CRITICAL severity).

The vulnerability aligns with **HIGH SEVERITY** per Aptos bug bounty: "Validator Node Slowdowns (High): Significant performance degradation affecting consensus, DoS through resource exhaustion." The panic occurs in the consensus pipeline's decryption phase, making this a direct attack vector against validator availability.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is trivial to execute for any malicious validator:

- **No technical barriers**: Simple modification of a single field in the share tuple
- **No timing dependencies**: Attack succeeds whenever encrypted transactions are processed
- **No validator collusion**: Single Byzantine validator sufficient
- **Deterministic outcome**: Guaranteed panic on duplicate virtual player indices
- **No detection**: The forged share passes all verification checks

The attack succeeds whenever:
1. The malicious validator is in the validator set (weight > 0)
2. At least one other validator exists to target
3. Encrypted transactions are being processed (triggering secret share reconstruction)

Given that Aptos explicitly supports encrypted transactions via the FPTX threshold encryption scheme, this vulnerability is highly exploitable in any production environment using encrypted transactions.

## Recommendation

Add explicit validation in the `SecretShare::verify()` function to ensure the Player ID embedded in the share matches the expected player index for the Author:

```rust
pub fn verify(&self, config: &SecretShareConfig) -> anyhow::Result<()> {
    let expected_index = config.get_id(self.author());
    let claimed_player = self.share().player(); // Extract player from share
    
    // Validate player ID matches expected index
    ensure!(
        claimed_player.get_id() == expected_index,
        "Player ID mismatch: share claims player {} but Author {} maps to index {}",
        claimed_player.get_id(),
        self.author(),
        expected_index
    );
    
    let decryption_key_share = self.share().clone();
    config.verification_keys[expected_index]
        .verify_decryption_key_share(&self.metadata.digest, &decryption_key_share)?;
    Ok(())
}
```

This ensures the invariant that `Author → expected_index → expected_player` is maintained and prevents forged Player IDs from creating duplicate virtual players during reconstruction.

## Proof of Concept

A complete PoC would require:
1. Setting up a test validator set with multiple validators
2. Creating legitimate shares from multiple validators
3. Forging a share with a duplicated Player ID
4. Triggering aggregation with the forged share included
5. Observing the panic in `batch_inversion`

The attack mechanism is straightforward to implement by directly constructing a `SecretShare` with a modified Player ID in the share tuple, as the Player struct's `id` field is publicly accessible.

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

**File:** crates/aptos-crypto/src/arkworks/shamir.rs (L253-290)
```rust
    pub fn lagrange_for_subset(&self, indices: &[usize]) -> Vec<F> {
        // Step 0: check that subset is large enough
        assert!(
            indices.len() >= self.t,
            "subset size {} is smaller than threshold t={}",
            indices.len(),
            self.t
        );

        let xs_vec: Vec<F> = indices.iter().map(|i| self.domain.element(*i)).collect();

        // Step 1: compute poly w/ roots at all x in xs, compute eval at 0
        let vanishing_poly = vanishing_poly::from_roots(&xs_vec);
        let vanishing_poly_at_0 = vanishing_poly.coeffs[0]; // vanishing_poly(0) = const term

        // Step 2 (numerators): for each x in xs, divide poly eval from step 1 by (-x) using batch inversion
        let mut neg_xs: Vec<F> = xs_vec.iter().map(|&x| -x).collect();
        batch_inversion(&mut neg_xs);
        let numerators: Vec<F> = neg_xs
            .iter()
            .map(|&inv_neg_x| vanishing_poly_at_0 * inv_neg_x)
            .collect();

        // Step 3a (denominators): Compute derivative of poly from step 1, and its evaluations
        let derivative = vanishing_poly.differentiate();
        let derivative_evals = derivative.evaluate_over_domain(self.domain).evals; // TODO: with a filter perhaps we don't have to store all evals, but then batch inversion becomes a bit more tedious

        // Step 3b: Only keep the relevant evaluations, then perform a batch inversion
        let mut denominators: Vec<F> = indices.iter().map(|i| derivative_evals[*i]).collect();
        batch_inversion(&mut denominators);

        // Step 4: compute Lagrange coefficients
        numerators
            .into_iter()
            .zip(denominators)
            .map(|(numerator, denom_inv)| numerator * denom_inv)
            .collect()
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L38-72)
```rust
    pub fn try_aggregate(
        self,
        secret_share_config: &SecretShareConfig,
        metadata: SecretShareMetadata,
        decision_tx: Sender<SecretSharedKey>,
    ) -> Either<Self, SecretShare> {
        if self.total_weight < secret_share_config.threshold() {
            return Either::Left(self);
        }
        observe_block(
            metadata.timestamp,
            BlockStage::SECRET_SHARING_ADD_ENOUGH_SHARE,
        );
        let dec_config = secret_share_config.clone();
        let self_share = self
            .get_self_share()
            .expect("Aggregated item should have self share");
        tokio::task::spawn_blocking(move || {
            let maybe_key = SecretShare::aggregate(self.shares.values(), &dec_config);
            match maybe_key {
                Ok(key) => {
                    let dec_key = SecretSharedKey::new(metadata, key);
                    let _ = decision_tx.unbounded_send(dec_key);
                },
                Err(e) => {
                    warn!(
                        epoch = metadata.epoch,
                        round = metadata.round,
                        "Aggregation error: {e}"
                    );
                },
            }
        });
        Either::Right(self_share)
    }
```
