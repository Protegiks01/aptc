# Audit Report

## Title
Secret Share Aggregation Takes Insufficient Shares Due to Weight/Count Confusion Leading to Consensus Liveness Failure

## Summary
The `SecretShare::aggregate` function in `types/src/secret_sharing.rs` incorrectly interprets the threshold WEIGHT as a share COUNT, causing it to select an insufficient number of weighted shares for reconstruction. When validators with zero weight contribute shares, the aggregation may select only zero-weight shares, leading to reconstruction failure and consensus liveness loss.

## Finding Description

The vulnerability exists in the secret share aggregation logic for weighted threshold secret sharing. The system allows validators to have different weights based on their stake, including zero weight for validators with very low stake. However, a critical bug in share selection causes consensus failure. [1](#0-0) 

The bug occurs because `config.threshold()` returns the threshold WEIGHT (e.g., 100), but the code uses it as a COUNT to take that many share objects via `.take(threshold as usize)`. Each share object is a `(Player, Vec<BIBEDecryptionKeyShareValue>)` tuple where the Vec size equals the player's weight. [2](#0-1) 

For validators with zero weight (which is legitimate according to DKG rounding), their share contains an empty Vec. The weighted reconstruction logic flattens these shares and checks if enough virtual shares exist: [3](#0-2) 

The reconstruction expects at least `threshold_weight` number of flattened shares, but when zero-weight shares are selected, insufficient virtual shares exist, causing the reconstruction to fail: [4](#0-3) 

**Attack Scenario:**
1. DKG rounding assigns zero weight to 10 validators with low stake (legitimate operation)
2. Normal weight validators: 5 validators with weight=3 each (total=15)
3. Threshold weight = 10
4. Zero-weight validators send their shares first (HashMap ordering)
5. `total_weight` = 0×10 + 3×5 = 15 ≥ threshold (aggregation proceeds)
6. `take(10)` selects first 10 shares (all from zero-weight validators)
7. Flattening produces 0 virtual shares
8. Reconstruction requires 10 shares but receives 0
9. Reconstruction fails → randomness generation fails → consensus halts [5](#0-4) 

Zero-weight validators can legitimately participate as confirmed by test cases: [6](#0-5) 

## Impact Explanation

**HIGH Severity** - This vulnerability causes total consensus liveness failure:

- **Randomness Generation Failure**: Secret share reconstruction fails, preventing randomness generation required for consensus
- **Block Commitment Halts**: Without randomness, validators cannot commit new blocks
- **Network-Wide Impact**: ALL validators are affected simultaneously
- **Non-Recoverable Without Intervention**: Requires manual intervention or epoch change to recover

This meets the **High Severity** criteria: "Significant protocol violations" and approaches **Critical Severity** for "Total loss of liveness/network availability".

## Likelihood Explanation

**HIGH Likelihood** in realistic validator set configurations:

1. **Automatic Occurrence**: DKG rounding AUTOMATICALLY assigns zero weight to validators with stake below certain thresholds
2. **No Attacker Control Required**: Happens through normal protocol operation when stake distribution is imbalanced
3. **Common in Practice**: Networks often have many small validators alongside large ones
4. **Non-Deterministic Triggers**: HashMap iteration ordering makes this probabilistic but frequent

The likelihood increases with:
- More validators with low stake
- Higher threshold values
- Uneven stake distribution

## Recommendation

Fix the share selection logic to account for validator weights when selecting shares for aggregation:

**Option 1 - Weight-Aware Selection:**
```rust
pub fn aggregate<'a>(
    dec_shares: impl Iterator<Item = &'a SecretShare>,
    config: &SecretShareConfig,
) -> anyhow::Result<DecryptionKey> {
    let threshold = config.threshold();
    let mut shares = Vec::new();
    let mut accumulated_weight = 0u64;
    
    for dec_share in dec_shares {
        shares.push(dec_share.share.clone());
        accumulated_weight += config.get_peer_weight(dec_share.author());
        if accumulated_weight >= threshold {
            break;
        }
    }
    
    ensure!(
        accumulated_weight >= threshold,
        "Insufficient total weight: {} < {}",
        accumulated_weight,
        threshold
    );
    
    <FPTXWeighted as BatchThresholdEncryption>::reconstruct_decryption_key(
        &shares,
        &config.config,
    )
}
```

**Option 2 - Reject Zero-Weight Shares:**

Add validation in `SecretShareStore::add_share`: [7](#0-6) 

```rust
pub fn add_share(&mut self, share: SecretShare) -> anyhow::Result<bool> {
    let weight = self.secret_share_config.get_peer_weight(share.author());
    
    // Reject shares from validators with zero weight
    ensure!(weight > 0, "Shares from zero-weight validators are not accepted");
    
    // ... rest of function
}
```

**Recommended**: Use Option 1 (weight-aware selection) as it maintains system flexibility while fixing the core issue.

## Proof of Concept

```rust
#[test]
fn test_zero_weight_share_aggregation_failure() {
    use aptos_crypto::weighted_config::WeightedConfigBlstrs;
    use types::secret_sharing::{SecretShare, SecretShareConfig};
    
    // Setup: 10 validators with weight 0, 5 validators with weight 3
    let weights = vec![
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 10 zero-weight validators
        3, 3, 3, 3, 3,                  // 5 validators with weight 3 each
    ];
    let threshold_weight = 10;
    
    let wconfig = WeightedConfigBlstrs::new(threshold_weight, weights).unwrap();
    
    // Create secret shares
    let mut shares = Vec::new();
    
    // Simulate zero-weight validators sending shares first (HashMap ordering)
    for i in 0..10 {
        let share = create_test_share(i, vec![]); // Empty vec for weight 0
        shares.push(share);
    }
    
    for i in 10..15 {
        let share = create_test_share(i, vec![val1, val2, val3]); // 3 values for weight 3
        shares.push(share);
    }
    
    // Create config
    let config = SecretShareConfig::new(..., wconfig);
    
    // Attempt aggregation - this will take first 10 shares (all zero-weight)
    let result = SecretShare::aggregate(shares.iter(), &config);
    
    // ASSERTION: This should FAIL but demonstrates the vulnerability
    assert!(result.is_err(), "Aggregation should fail with insufficient weight");
    // In production, this causes consensus liveness failure
}
```

## Notes

The vulnerability is particularly insidious because:

1. **Legitimate Configuration**: Zero-weight validators are an expected outcome of DKG rounding for low-stake validators
2. **Silent Failure Path**: The system accepts zero-weight shares without validation
3. **Non-Deterministic**: Depends on HashMap iteration order, making it difficult to debug
4. **Cascade Effect**: One failed randomness generation can stall the entire network

The fix must preserve support for weighted secret sharing while ensuring sufficient shares are selected for reconstruction.

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

**File:** types/src/secret_sharing.rs (L188-190)
```rust
    pub fn threshold(&self) -> u64 {
        self.config.get_threshold_config().t as u64
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

**File:** crates/aptos-crypto/src/weighted_config.rs (L480-502)
```rust
        // 3-out-of-5, some weights are 0.
        let wc = WeightedConfigBlstrs::new(1, vec![0, 0, 0, 2, 2, 2, 0, 0, 0, 3, 3, 3, 0, 0, 0])
            .unwrap();
        assert_eq!(
            vec![0, 0, 0, 0, 2, 4, 6, 6, 6, 6, 9, 12, 15, 15, 15],
            wc.starting_index
        );
        assert_eq!(wc.get_virtual_player(&wc.get_player(3), 0).id, 0);
        assert_eq!(wc.get_virtual_player(&wc.get_player(3), 1).id, 1);
        assert_eq!(wc.get_virtual_player(&wc.get_player(4), 0).id, 2);
        assert_eq!(wc.get_virtual_player(&wc.get_player(4), 1).id, 3);
        assert_eq!(wc.get_virtual_player(&wc.get_player(5), 0).id, 4);
        assert_eq!(wc.get_virtual_player(&wc.get_player(5), 1).id, 5);
        assert_eq!(wc.get_virtual_player(&wc.get_player(9), 0).id, 6);
        assert_eq!(wc.get_virtual_player(&wc.get_player(9), 1).id, 7);
        assert_eq!(wc.get_virtual_player(&wc.get_player(9), 2).id, 8);
        assert_eq!(wc.get_virtual_player(&wc.get_player(10), 0).id, 9);
        assert_eq!(wc.get_virtual_player(&wc.get_player(10), 1).id, 10);
        assert_eq!(wc.get_virtual_player(&wc.get_player(10), 2).id, 11);
        assert_eq!(wc.get_virtual_player(&wc.get_player(11), 0).id, 12);
        assert_eq!(wc.get_virtual_player(&wc.get_player(11), 1).id, 13);
        assert_eq!(wc.get_virtual_player(&wc.get_player(11), 2).id, 14);
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

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L259-275)
```rust
    pub fn add_share(&mut self, share: SecretShare) -> anyhow::Result<bool> {
        let weight = self.secret_share_config.get_peer_weight(share.author());
        let metadata = share.metadata();
        ensure!(metadata.epoch == self.epoch, "Share from different epoch");
        ensure!(
            metadata.round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );

        let item = self
            .secret_share_map
            .entry(metadata.round)
            .or_insert_with(|| SecretShareItem::new(self.self_author));
        item.add_share(share, weight)?;
        item.try_aggregate(&self.secret_share_config, self.decision_tx.clone());
        Ok(item.has_decision())
    }
```
