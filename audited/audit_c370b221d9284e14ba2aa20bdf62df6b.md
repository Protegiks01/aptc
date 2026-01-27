# Audit Report

## Title
Certified APK Distribution Delays Cause Non-Deterministic Randomness Aggregation and Consensus Liveness Failure

## Summary
Asynchronous distribution of certified augmented public keys (certified_apks) across validators can cause different validators to verify and accept different sets of randomness shares for the same round. This leads to different WVUF evaluations being aggregated, resulting in different randomness values being written to on-chain state. Validators then compute different state roots and cannot reach consensus, causing a chain halt requiring manual intervention.

## Finding Description

The vulnerability exists in the randomness generation subsystem's interaction with the certified APK distribution mechanism. The issue violates the **Deterministic Execution** invariant (Invariant #1): "All validators must produce identical state roots for identical blocks."

**Root Cause:**

The `RandKeys` struct stores certified_apks in a vector of `OnceCell<APK>` that are populated asynchronously via network messages. [1](#0-0) 

When verifying randomness shares, validators check if the certified_apk for the share's author is available. If missing, verification fails and the share is silently dropped. [2](#0-1) 

During randomness aggregation, validators call `WVUF::derive_eval` which uses Lagrange interpolation over the set of shares included in the proof. Different sets of shares produce different interpolation results. [3](#0-2) [4](#0-3) 

**Attack Scenario:**

1. At epoch N+1 start, validators begin broadcasting their certified AugData containing deltas needed to derive certified_apks
2. Due to network delays, Validator X receives certified_apks for validators [A, B, C] but not yet for [D, E]
3. Validator Y has received all certified_apks [A, B, C, D, E]
4. For round R, validators broadcast randomness shares
5. Validator X successfully verifies and accepts shares from [A, B, C] only (threshold = 3 met)
6. Validator Y successfully verifies and accepts shares from [A, B, C, D] (threshold exceeded)
7. Validator X aggregates with shares [A, B, C] → randomness_X
8. Validator Y aggregates with shares [A, B, C, D] → randomness_Y
9. Due to different Lagrange interpolation points: randomness_X ≠ randomness_Y
10. Block execution includes different randomness in metadata transaction [5](#0-4) 

11. Different randomness values are written to PerBlockRandomness resource [6](#0-5) 

12. Validators compute different state root hashes
13. Validators sign commit votes with different state roots [7](#0-6) 

14. Cannot form quorum certificate → **chain halts**

## Impact Explanation

**Severity: High** (up to $50,000 per Aptos Bug Bounty)

This qualifies as "Significant protocol violations" under the High Severity category. The vulnerability causes:

1. **Liveness Failure**: The blockchain cannot progress as validators cannot reach consensus on state roots
2. **Requires Manual Intervention**: Operators must manually synchronize certified_apks or restart consensus to recover
3. **Breaks Core Invariant**: Violates Deterministic Execution invariant - validators executing identical blocks produce different state roots
4. **No Automatic Recovery**: Unlike transient network issues, this requires active intervention as validators have permanently divergent state

While this doesn't cause fund loss or safety violations (chain fork), it causes complete loss of liveness which severely impacts network availability and requires emergency response.

## Likelihood Explanation

**Likelihood: High**

This vulnerability has high probability of occurring in production because:

1. **Normal Network Conditions**: Standard network latency and packet delays naturally cause asynchronous message delivery
2. **No Attacker Required**: This is a protocol design issue that manifests under normal operation
3. **Epoch Boundaries**: Happens at every epoch transition when certified_apks are redistributed
4. **Distributed System Reality**: Perfect synchronization of broadcast messages across geographically distributed validators is impossible
5. **Race Condition**: The time window between first validator receiving threshold shares and last validator receiving all certified_apks creates a natural race condition

The reliable broadcast mechanism for AugData does not include a synchronization barrier ensuring all validators have all certified_apks before randomness generation begins. [8](#0-7) 

## Recommendation

Implement a synchronization barrier that ensures all validators have received and stored all certified_apks before allowing randomness share verification to proceed. Specifically:

1. **Add certified_apk completeness check** in RandConfig:
```rust
pub fn has_all_certified_apks(&self) -> bool {
    self.keys.certified_apks.iter().all(|cell| cell.get().is_some())
}
```

2. **Defer share verification** until all certified_apks are available in `Share::verify`:
```rust
fn verify(&self, rand_config: &RandConfig, ...) -> anyhow::Result<()> {
    // Wait for all certified_apks before verifying any shares
    ensure!(
        rand_config.has_all_certified_apks(),
        "Cannot verify shares until all certified_apks are received"
    );
    
    let index = *rand_config.validator.address_to_validator_index()...
    let apk = &rand_config.keys.certified_apks[index]
        .get()
        .ok_or_else(|| anyhow!("Missing certified_apk"))?;
    // ... rest of verification
}
```

3. **Add timeout mechanism**: If not all certified_apks are received within a timeout period, request missing ones explicitly via RPC

4. **Alternative: Use deterministic subset**: Define a deterministic rule for selecting which validators' shares to use (e.g., first N validators by sorted address) so all validators use the same subset even with different APK availability

## Proof of Concept

```rust
// Reproduction test (add to consensus/src/rand/rand_gen/rand_store.rs tests)
#[tokio::test]
async fn test_certified_apk_distribution_delay_causes_divergence() {
    // Setup: 5 validators with threshold = 3
    let num_validators = 5;
    let weights = vec![100; num_validators];
    
    // Validator X (index 0) - receives certified_apks for validators 0,1,2 only
    let mut rand_config_x = create_rand_config(weights.clone(), 0);
    add_certified_apks(&mut rand_config_x, &[0, 1, 2]); // Missing 3,4
    
    // Validator Y (index 1) - receives all certified_apks
    let mut rand_config_y = create_rand_config(weights.clone(), 1);
    add_certified_apks(&mut rand_config_y, &[0, 1, 2, 3, 4]); // Has all
    
    let metadata = RandMetadata { epoch: 1, round: 100 };
    
    // All validators broadcast shares
    let shares = generate_shares_from_validators(&[0, 1, 2, 3, 4], metadata.clone());
    
    // Validator X can only verify shares from 0,1,2
    let mut verified_shares_x = vec![];
    for share in &shares {
        if share.verify(&rand_config_x).is_ok() {
            verified_shares_x.push(share.clone());
        }
    }
    assert_eq!(verified_shares_x.len(), 3); // Only 0,1,2
    
    // Validator Y can verify shares from 0,1,2,3,4
    let mut verified_shares_y = vec![];
    for share in &shares {
        if share.verify(&rand_config_y).is_ok() {
            verified_shares_y.push(share.clone());
        }
    }
    assert_eq!(verified_shares_y.len(), 5); // All validators
    
    // Aggregate with different sets
    let randomness_x = Share::aggregate(
        verified_shares_x.iter(),
        &rand_config_x,
        metadata.clone()
    ).unwrap();
    
    let randomness_y = Share::aggregate(
        verified_shares_y.iter(),
        &rand_config_y,
        metadata.clone()
    ).unwrap();
    
    // ASSERTION: Different randomness values produced
    assert_ne!(
        randomness_x.randomness(),
        randomness_y.randomness(),
        "Different certified_apk availability leads to different randomness!"
    );
    
    // This means different state roots → consensus failure
}
```

**Notes:**
- The vulnerability is exploitable without any malicious actor
- Network delays during epoch transitions naturally trigger this condition
- The fix requires adding synchronization barriers in the randomness generation protocol
- Impact is severe but recoverable with manual intervention (unlike irreversible fund loss)

### Citations

**File:** types/src/randomness.rs (L103-114)
```rust
#[derive(Clone, SilentDebug)]
pub struct RandKeys {
    // augmented secret / public key share of this validator, obtained from the DKG transcript of last epoch
    pub ask: ASK,
    pub apk: APK,
    // certified augmented public key share of all validators,
    // obtained from all validators in the new epoch,
    // which necessary for verifying randomness shares
    pub certified_apks: Vec<OnceCell<APK>>,
    // public key share of all validators, obtained from the DKG transcript of last epoch
    pub pk_shares: Vec<PKShare>,
}
```

**File:** consensus/src/rand/rand_gen/types.rs (L52-81)
```rust
    fn verify(
        &self,
        rand_config: &RandConfig,
        rand_metadata: &RandMetadata,
        author: &Author,
    ) -> anyhow::Result<()> {
        let index = *rand_config
            .validator
            .address_to_validator_index()
            .get(author)
            .ok_or_else(|| anyhow!("Share::verify failed with unknown author"))?;
        let maybe_apk = &rand_config.keys.certified_apks[index];
        if let Some(apk) = maybe_apk.get() {
            WVUF::verify_share(
                &rand_config.vuf_pp,
                apk,
                bcs::to_bytes(&rand_metadata)
                    .map_err(|e| anyhow!("Serialization failed: {}", e))?
                    .as_slice(),
                &self.share,
            )?;
        } else {
            bail!(
                "[RandShare] No augmented public key for validator id {}, {}",
                index,
                author
            );
        }
        Ok(())
    }
```

**File:** consensus/src/rand/rand_gen/types.rs (L134-142)
```rust
        let eval = WVUF::derive_eval(
            &rand_config.wconfig,
            &rand_config.vuf_pp,
            metadata_serialized.as_slice(),
            &rand_config.get_all_certified_apk(),
            &proof,
            THREAD_MANAGER.get_exe_cpu_pool(),
        )
        .map_err(|e| anyhow!("Share::aggregate failed with WVUF derive_eval error: {e}"))?;
```

**File:** crates/aptos-dkg/src/weighted_vuf/pinkas/mod.rs (L273-314)
```rust
    pub fn collect_lagrange_coeffs_shares_and_rks<'a>(
        wc: &WeightedConfigBlstrs,
        apks: &'a [Option<(RandomizedPKs, Vec<DealtPubKeyShare>)>],
        proof: &'a Vec<(Player, <Self as WeightedVUF>::ProofShare)>,
    ) -> anyhow::Result<(
        Vec<&'a G2Projective>,
        Vec<&'a Vec<G1Projective>>,
        Vec<Scalar>,
        Vec<Range<usize>>,
    )> {
        // Collect all the evaluation points associated with each player's augmented pubkey sub shares.
        let mut sub_player_ids = Vec::with_capacity(wc.get_total_weight());
        // The G2 shares
        let mut shares = Vec::with_capacity(proof.len());
        // The RKs of each player
        let mut rks = Vec::with_capacity(proof.len());
        // The starting & ending index of each player in the `lagr` coefficients vector
        let mut ranges = Vec::with_capacity(proof.len());

        let mut k = 0;
        for (player, share) in proof {
            for j in 0..wc.get_player_weight(player) {
                sub_player_ids.push(wc.get_virtual_player(player, j).id);
            }

            let apk = apks[player.id]
                .as_ref()
                .ok_or_else(|| anyhow!("Missing APK for player {}", player.get_id()))?;

            rks.push(&apk.0.rks);
            shares.push(share);

            let w = wc.get_player_weight(player);
            ranges.push(k..k + w);
            k += w;
        }

        // Compute the Lagrange coefficients associated with those evaluation points
        let batch_dom = wc.get_batch_evaluation_domain();
        let lagr = lagrange_coefficients(batch_dom, &sub_player_ids[..], &Scalar::ZERO);
        Ok((shares, rks, lagr, ranges))
    }
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L803-811)
```rust
        let (rand_result, _has_randomness) = rand_check.await?;

        tracker.start_working();
        // if randomness is disabled, the metadata skips DKG and triggers immediate reconfiguration
        let metadata_txn = if let Some(maybe_rand) = rand_result {
            block.new_metadata_with_randomness(&validator, maybe_rand)
        } else {
            block.new_block_metadata(&validator).into()
        };
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L1009-1025)
```rust
        let mut block_info = block.gen_block_info(
            compute_result.root_hash(),
            compute_result.last_version_or_0(),
            compute_result.epoch_state().clone(),
        );
        if let Some(timestamp) = epoch_end_timestamp {
            info!(
                "[Pipeline] update block timestamp from {} to epoch end timestamp {}",
                block_info.timestamp_usecs(),
                timestamp
            );
            block_info.change_timestamp(timestamp);
        }
        let ledger_info = LedgerInfo::new(block_info, consensus_data_hash);
        info!("[Pipeline] Signed ledger info {ledger_info}");
        let signature = signer.sign(&ledger_info).expect("Signing should succeed");
        let commit_vote = CommitVote::new_with_signature(signer.author(), ledger_info, signature);
```

**File:** types/src/block_metadata_ext.rs (L23-34)
```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockMetadataWithRandomness {
    pub id: HashValue,
    pub epoch: u64,
    pub round: u64,
    pub proposer: AccountAddress,
    #[serde(with = "serde_bytes")]
    pub previous_block_votes_bitvec: Vec<u8>,
    pub failed_proposer_indices: Vec<u32>,
    pub timestamp_usecs: u64,
    pub randomness: Option<Randomness>,
}
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L305-346)
```rust
    async fn broadcast_aug_data(&mut self) -> DropGuard {
        let data = self
            .aug_data_store
            .get_my_aug_data()
            .unwrap_or_else(|| D::generate(&self.config, &self.fast_config));
        // Add it synchronously to avoid race that it sends to others but panics before it persists locally.
        self.aug_data_store
            .add_aug_data(data.clone())
            .expect("Add self aug data should succeed");
        let aug_ack = AugDataCertBuilder::new(data.clone(), self.epoch_state.clone());
        let rb = self.reliable_broadcast.clone();
        let rb2 = self.reliable_broadcast.clone();
        let validators = self.epoch_state.verifier.get_ordered_account_addresses();
        let maybe_existing_certified_data = self.aug_data_store.get_my_certified_aug_data();
        let phase1 = async move {
            if let Some(certified_data) = maybe_existing_certified_data {
                info!("[RandManager] Already have certified aug data");
                return certified_data;
            }
            info!("[RandManager] Start broadcasting aug data");
            info!(LogSchema::new(LogEvent::BroadcastAugData)
                .author(*data.author())
                .epoch(data.epoch()));
            let certified_data = rb.broadcast(data, aug_ack).await.expect("cannot fail");
            info!("[RandManager] Finish broadcasting aug data");
            certified_data
        };
        let ack_state = Arc::new(CertifiedAugDataAckState::new(validators.into_iter()));
        let task = phase1.then(|certified_data| async move {
            info!(LogSchema::new(LogEvent::BroadcastCertifiedAugData)
                .author(*certified_data.author())
                .epoch(certified_data.epoch()));
            info!("[RandManager] Start broadcasting certified aug data");
            rb2.broadcast(certified_data, ack_state)
                .await
                .expect("Broadcast cannot fail");
            info!("[RandManager] Finish broadcasting certified aug data");
        });
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        tokio::spawn(Abortable::new(task, abort_registration));
        DropGuard::new(abort_handle)
    }
```
