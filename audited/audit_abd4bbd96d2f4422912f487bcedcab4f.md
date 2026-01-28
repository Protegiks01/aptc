# Audit Report

## Title
Non-Atomic Two-Phase Certified Augmented Data Broadcast Enables Consensus Split via Inconsistent Randomness Generation

## Summary
The `broadcast_aug_data()` function in the randomness generation subsystem uses a non-atomic two-phase broadcast pattern where task abortion between phases creates inconsistent validator states. This causes different validators to compute different randomness values for identical blocks, resulting in a consensus safety violation.

## Finding Description

The vulnerability exists in the `broadcast_aug_data()` function which implements a two-phase reliable broadcast protocol for distributing augmented data needed for weighted VUF-based randomness generation. [1](#0-0) 

**Phase 1** broadcasts augmented data to collect signatures and create `CertifiedAugData`. **Phase 2** broadcasts the `CertifiedAugData` to all validators for persistence. [2](#0-1) 

The two phases are chained with `.then()` and spawned as a single async task that can be aborted. [3](#0-2)  When the `DropGuard` is dropped (e.g., during epoch transitions), it aborts the task. [4](#0-3) 

Epoch transitions trigger this via `end_epoch()` sending `ResetSignal::Stop`, causing the `start()` function to exit and drop the guard. [5](#0-4) 

If the task aborts after phase 1 completes but before phase 2 finishes:
1. Some validators (S1) successfully receive and persist the `CertifiedAugData`
2. Other validators (S2) never receive it

When `CertifiedAugData` is received, validators call `add_certified_aug_data()` which persists it and calls `augment()` to add the augmented public key (APK). [6](#0-5) 

The `augment()` function adds the APK via `add_certified_delta()`. [7](#0-6) [8](#0-7) 

**Critical Issue**: When randomness shares arrive, share verification requires the sender's APK. [9](#0-8)  Validators in S1 have the APK and can verify the share. Validators in S2 lack the APK and verification fails with "No augmented public key for validator" (line 75).

This causes validators in S1 to include the share in aggregation while validators in S2 exclude it. The WVUF aggregation computes Lagrange coefficients based on which specific shares are included (`sub_player_ids`), leading to different multiexponentiation results and ultimately different randomness values. [10](#0-9) 

## Impact Explanation

This represents a **Critical Severity** consensus safety violation under the Aptos bug bounty criteria:

**Consensus/Safety Violations**: Different validators compute different randomness values for identical blocks, violating the fundamental invariant that all honest validators must reach agreement on the same state. This leads to:

1. **Chain Split**: Validators with different randomness values commit different blocks or reject valid blocks from other validators
2. **Deterministic Execution Failure**: Validators produce different state roots for identical inputs
3. **Non-recoverable State Divergence**: Once validators diverge on randomness, all subsequent blocks depending on that randomness also diverge

The impact affects the entire validator set without requiring any malicious actors - it's a race condition triggered by normal operational events during the narrow window between broadcast phases.

## Likelihood Explanation

**Medium Likelihood** - This vulnerability can be triggered by common operational events:

1. **Epoch Transitions**: When the `start()` function exits and the `_guard` is dropped, in-flight broadcast tasks are aborted. [11](#0-10) 

2. **Node Crashes**: Any validator crash during phase 2 will abort the task, leaving some validators with certified aug data and others without

3. **Network Partitions**: Temporary network issues during phase 2 prevent some validators from receiving certified data

4. **Task Panics**: The `.expect("cannot fail")` and `.expect("Broadcast cannot fail")` statements cause panics if reliable broadcast encounters unexpected errors

The vulnerability window is the duration of phase 2 (broadcasting to all validators with retries), which occurs once per epoch at RandManager startup. While the window is narrow, the catastrophic impact (consensus split) makes even medium likelihood critical.

## Recommendation

Implement atomic persistence of certified augmented data using one of these approaches:

**Option 1: Atomic Two-Phase Commit**
Before phase 1 completes, require all validators to acknowledge they are ready to receive phase 2 data. Only complete phase 1 if sufficient validators confirm readiness. This ensures phase 2 will succeed to enough validators.

**Option 2: Synchronous Self-Persistence**
Before spawning the async task, synchronously add the certified aug data to the originating validator's own store within `broadcast_aug_data()`. This prevents the originating validator from missing its own certified data.

**Option 3: Recovery Mechanism**
Implement a `RequestCertifiedAugData` message type that allows validators to request missing certified aug data from peers when share verification fails due to missing APKs. This provides eventual consistency.

**Option 4: Abort Prevention**
Do not spawn phase 2 as an abortable task. Instead, make it a synchronous operation that blocks until all validators receive the certified data, or use a separate non-abortable task pool.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Starting a validator network with randomness enabled
2. Triggering an epoch transition immediately after a validator's `broadcast_aug_data()` phase 1 completes
3. Observing that some validators receive `CertifiedAugData` while others don't
4. Submitting a block that requires randomness generation
5. Observing different validators compute different randomness values due to different share verification results
6. Demonstrating consensus divergence when validators reject each other's blocks due to different randomness values

A Rust integration test would spawn multiple RandManager instances, coordinate phase 1 completion, abort the task during phase 2, then trigger randomness generation and verify different validators produce different results.

---

**Notes**

This vulnerability is particularly severe because:
- It requires no malicious actors - normal operational failures trigger it
- The inconsistency has no automatic recovery mechanism
- Different Lagrange coefficients mathematically guarantee different randomness outputs
- The vulnerability affects consensus safety, the most critical property of a blockchain

### Citations

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

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L376-377)
```rust
        let _guard = self.broadcast_aug_data().await;
        let mut interval = tokio::time::interval(Duration::from_millis(5000));
```

**File:** crates/reliable-broadcast/src/lib.rs (L232-235)
```rust
impl Drop for DropGuard {
    fn drop(&mut self) {
        self.abort_handle.abort();
    }
```

**File:** consensus/src/pipeline/execution_client.rs (L721-732)
```rust
        if let Some(mut tx) = reset_tx_to_rand_manager {
            let (ack_tx, ack_rx) = oneshot::channel();
            tx.send(ResetRequest {
                tx: ack_tx,
                signal: ResetSignal::Stop,
            })
            .await
            .expect("[EpochManager] Fail to drop rand manager");
            ack_rx
                .await
                .expect("[EpochManager] Fail to drop rand manager");
        }
```

**File:** consensus/src/rand/rand_gen/aug_data_store.rs (L117-131)
```rust
    pub fn add_certified_aug_data(
        &mut self,
        certified_data: CertifiedAugData<D>,
    ) -> anyhow::Result<CertifiedAugDataAck> {
        if self.certified_data.contains_key(certified_data.author()) {
            return Ok(CertifiedAugDataAck::new(self.epoch));
        }
        self.db.save_certified_aug_data(&certified_data)?;
        certified_data
            .data()
            .augment(&self.config, &self.fast_config, certified_data.author());
        self.certified_data
            .insert(*certified_data.author(), certified_data);
        Ok(CertifiedAugDataAck::new(self.epoch))
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

**File:** consensus/src/rand/rand_gen/types.rs (L178-194)
```rust
    fn augment(
        &self,
        rand_config: &RandConfig,
        fast_rand_config: &Option<RandConfig>,
        author: &Author,
    ) {
        let AugmentedData { delta, fast_delta } = self;
        rand_config
            .add_certified_delta(author, delta.clone())
            .expect("Add delta should succeed");

        if let (Some(config), Some(fast_delta)) = (fast_rand_config, fast_delta) {
            config
                .add_certified_delta(author, fast_delta.clone())
                .expect("Add delta for fast path should succeed");
        }
    }
```

**File:** consensus/src/rand/rand_gen/types.rs (L661-665)
```rust
    pub fn add_certified_delta(&self, peer: &Author, delta: Delta) -> anyhow::Result<()> {
        let apk = self.derive_apk(peer, delta)?;
        self.add_certified_apk(peer, apk)?;
        Ok(())
    }
```

**File:** crates/aptos-dkg/src/weighted_vuf/bls/mod.rs (L108-136)
```rust
    fn aggregate_shares(
        wc: &WeightedConfigBlstrs,
        apks_and_proofs: &[(Player, Self::AugmentedPubKeyShare, Self::ProofShare)],
    ) -> Self::Proof {
        // Collect all the evaluation points associated with each player
        let mut sub_player_ids = Vec::with_capacity(wc.get_total_weight());

        for (player, _, _) in apks_and_proofs {
            for j in 0..wc.get_player_weight(player) {
                sub_player_ids.push(wc.get_virtual_player(player, j).id);
            }
        }

        // Compute the Lagrange coefficients associated with those evaluation points
        let batch_dom = wc.get_batch_evaluation_domain();
        let lagr = lagrange_coefficients(batch_dom, &sub_player_ids[..], &Scalar::ZERO);

        // Interpolate the signature
        let mut bases = Vec::with_capacity(apks_and_proofs.len());
        for (_, _, share) in apks_and_proofs {
            // println!(
            //     "Flattening {} share(s) for player {player}",
            //     sub_shares.len()
            // );
            bases.extend_from_slice(share.as_slice())
        }

        g1_multi_exp(bases.as_slice(), lagr.as_slice())
    }
```
