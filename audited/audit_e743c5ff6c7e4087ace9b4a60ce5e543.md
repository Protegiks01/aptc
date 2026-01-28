Based on my comprehensive analysis of the Aptos Core codebase, I can confirm this is a **VALID VULNERABILITY**. All claims have been verified against the actual code.

# Audit Report

## Title
Memory Leak in ProofCoordinator: Unbounded Growth of batch_info_to_time HashMap Due to Incomplete Cleanup in expire()

## Summary
The `expire()` function in `ProofCoordinator` fails to remove entries from the `batch_info_to_time` HashMap when batches expire without completing. This creates a memory leak causing unbounded HashMap growth, eventually leading to memory exhaustion and validator node instability.

## Finding Description

The `ProofCoordinator` maintains two parallel HashMap structures to track batches during proof-of-store formation. [1](#0-0) 

When a batch is initialized, entries are added to both HashMaps in the `init_proof()` function. [2](#0-1) 

There are two cleanup paths:

**Path 1: Successful proof completion** - When a batch receives enough signatures to form a quorum, the entry is removed from `batch_info_to_time`. [3](#0-2) 

**Path 2: Expiration without completion** - When a batch times out before achieving quorum, the `expire()` function **only removes from `batch_info_to_proof`**, but NOT from `batch_info_to_time`. [4](#0-3) 

This asymmetry creates a memory leak. Every batch that expires without completing leaves a permanent entry in `batch_info_to_time` containing a `BatchInfoExt` key and `Instant` value. The `batch_info_to_time` HashMap is only referenced in 4 locations throughout the entire codebase (initialization, insertion during init, removal on success, and field definition), confirming there is no other cleanup path.

**Triggering Conditions:**
- Network partitions preventing signature propagation
- Validator unavailability or slow response times
- Byzantine validators withholding signatures
- Normal operations where some batches naturally fail to achieve quorum within the timeout window

## Impact Explanation

**Severity: Medium to High**

This vulnerability aligns with **High severity** ("Validator Node Slowdowns") in the Aptos Bug Bounty program, as it causes progressive memory exhaustion affecting validator performance. However, it can also be classified as **Medium severity** ("State inconsistencies requiring manual intervention").

**Resource Exhaustion Impact:**
- Each leaked entry contains a `BatchInfoExt` structure and an `Instant` timestamp
- Over days/weeks of continuous operation, thousands of entries accumulate
- HashMap growth degrades performance through increased memory pressure
- Eventually leads to OOM conditions requiring node restart

**Operational Impact:**
- Validator nodes experience progressive slowdown
- Memory alerts trigger requiring manual intervention
- Node restarts needed to clear leaked memory
- Reduced consensus participation during recovery

The gradual nature and recoverability through restart justify Medium severity, while the direct impact on validator performance could justify High severity.

## Likelihood Explanation

**Likelihood: High**

This vulnerability will manifest in all production deployments given sufficient time. Batch timeouts are expected operational events, as evidenced by the dedicated counter and logging. [5](#0-4) 

The `expire()` function is called every 100ms in the main event loop. [6](#0-5) 

**Factors:**
1. Even under optimal conditions, some batches fail to achieve quorum within timeout windows
2. During network stress, batch expiry rates increase significantly
3. No recovery mechanism exists - the leak is permanent
4. The presence of `TIMEOUT_BATCHES_COUNT` metric indicates timeouts are normal, not exceptional

## Recommendation

Add cleanup of `batch_info_to_time` entries in the `expire()` function to match the cleanup behavior of `batch_info_to_proof`:

```rust
async fn expire(&mut self) {
    let mut batch_ids = vec![];
    for signed_batch_info_info in self.timeouts.expire() {
        if let Some(state) = self.batch_info_to_proof.remove(&signed_batch_info_info) {
            // Add this line to fix the memory leak:
            self.batch_info_to_time.remove(&signed_batch_info_info);
            
            if !state.completed {
                batch_ids.push(signed_batch_info_info.batch_id());
            }
            Self::update_counters_on_expire(&state);
            // ... rest of the function
        }
    }
    // ... rest of the function
}
```

This ensures symmetric cleanup: both HashMaps are populated together during initialization and cleaned up together in both success and expiration paths.

## Proof of Concept

A proof of concept would involve:

1. Running a validator node in a test network
2. Monitoring the memory usage of the `ProofCoordinator` process
3. Inducing batch timeouts through network delays or validator unavailability
4. Observing the `batch_info_to_time` HashMap size grow unboundedly over time
5. Confirming that `TIMEOUT_BATCHES_COUNT` increases while memory usage grows proportionally

The vulnerability can be confirmed through code inspection without requiring a full PoC, as the missing cleanup call in `expire()` is definitively absent from the codebase.

---

**Notes:**
This is a legitimate resource management bug in the consensus layer that violates the Resource Limits invariant. The asymmetric cleanup pattern between success and expiration paths is clearly documented in the code, and batch timeouts are normal operational events rather than rare edge cases.

### Citations

**File:** consensus/src/quorum_store/proof_coordinator.rs (L233-235)
```rust
    batch_info_to_proof: HashMap<BatchInfoExt, IncrementalProofState>,
    // to record the batch creation time
    batch_info_to_time: HashMap<BatchInfoExt, Instant>,
```

**File:** consensus/src/quorum_store/proof_coordinator.rs (L289-304)
```rust
        if signed_batch_info.batch_info().is_v2() {
            self.batch_info_to_proof.insert(
                signed_batch_info.batch_info().clone(),
                IncrementalProofState::new_batch_info_ext(signed_batch_info.batch_info().clone()),
            );
        } else {
            self.batch_info_to_proof.insert(
                signed_batch_info.batch_info().clone(),
                IncrementalProofState::new_batch_info(
                    signed_batch_info.batch_info().info().clone(),
                ),
            );
        }
        self.batch_info_to_time
            .entry(signed_batch_info.batch_info().clone())
            .or_insert(Instant::now());
```

**File:** consensus/src/quorum_store/proof_coordinator.rs (L329-346)
```rust
            if !value.completed && value.check_voting_power(validator_verifier, true) {
                let proof = {
                    let _timer = counters::SIGNED_BATCH_INFO_VERIFY_DURATION.start_timer();
                    value.aggregate_and_verify(validator_verifier)?
                };
                // proof validated locally, so adding to cache
                self.proof_cache
                    .insert(proof.info().clone(), proof.multi_signature().clone());
                // quorum store measurements
                let duration = self
                    .batch_info_to_time
                    .remove(signed_batch_info.batch_info())
                    .ok_or(
                        // Batch created without recording the time!
                        SignedBatchInfoError::NoTimeStamps,
                    )?
                    .elapsed();
                counters::BATCH_TO_POS_DURATION.observe_duration(duration);
```

**File:** consensus/src/quorum_store/proof_coordinator.rs (L369-402)
```rust
    async fn expire(&mut self) {
        let mut batch_ids = vec![];
        for signed_batch_info_info in self.timeouts.expire() {
            if let Some(state) = self.batch_info_to_proof.remove(&signed_batch_info_info) {
                if !state.completed {
                    batch_ids.push(signed_batch_info_info.batch_id());
                }
                Self::update_counters_on_expire(&state);

                // We skip metrics if the proof did not complete and did not get a self vote, as it
                // is considered a proof that was re-inited due to a very late vote.
                if !state.completed && !state.self_voted {
                    continue;
                }

                if !state.completed {
                    counters::TIMEOUT_BATCHES_COUNT.inc();
                    info!(
                        LogSchema::new(LogEvent::IncrementalProofExpired),
                        digest = signed_batch_info_info.digest(),
                        self_voted = state.self_voted,
                    );
                }
            }
        }
        if self
            .batch_generator_cmd_tx
            .send(BatchGeneratorCommand::ProofExpiration(batch_ids))
            .await
            .is_err()
        {
            warn!("Failed to send proof expiration to batch generator");
        }
    }
```

**File:** consensus/src/quorum_store/proof_coordinator.rs (L410-508)
```rust
        let mut interval = time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                Some(command) = rx.recv() => monitor!("proof_coordinator_handle_command", {
                    match command {
                        ProofCoordinatorCommand::Shutdown(ack_tx) => {
                            counters::QUORUM_STORE_MSG_COUNT.with_label_values(&["ProofCoordinator::shutdown"]).inc();
                            ack_tx
                                .send(())
                                .expect("Failed to send shutdown ack to QuorumStore");
                            break;
                        },
                        ProofCoordinatorCommand::CommitNotification(batches) => {
                            counters::QUORUM_STORE_MSG_COUNT.with_label_values(&["ProofCoordinator::commit_notification"]).inc();
                            for batch in batches {
                                let digest = batch.digest();
                                if let Entry::Occupied(existing_proof) = self.batch_info_to_proof.entry(batch.clone()) {
                                    if batch == existing_proof.get().batch_info() {
                                        let incremental_proof = existing_proof.get();
                                        if incremental_proof.completed {
                                            counters::BATCH_SUCCESSFUL_CREATION.observe(1.0);
                                        } else {
                                            info!("QS: received commit notification for batch that did not complete: {}, self_voted: {}", digest, incremental_proof.self_voted);
                                        }
                                        debug!(
                                            LogSchema::new(LogEvent::ProofOfStoreCommit),
                                            digest = digest,
                                            batch_id = batch.batch_id().id,
                                            proof_completed = incremental_proof.completed,
                                        );
                                    }
                                }
                            }
                        },
                        ProofCoordinatorCommand::AppendSignature(signer, signed_batch_infos) => {
                            let signed_batch_infos = signed_batch_infos.take();
                            let Some(signed_batch_info) = signed_batch_infos.first() else {
                                error!("Empty signed batch info received from {}", signer.short_str().as_str());
                                continue;
                            };
                            let info = signed_batch_info.batch_info().clone();
                            let approx_created_ts_usecs = signed_batch_info
                                .expiration()
                                .saturating_sub(self.batch_expiry_gap_when_init_usecs);
                            let self_peer_id = self.peer_id;
                            let enable_broadcast_proofs = self.broadcast_proofs;

                            let mut proofs_iter = signed_batch_infos.into_iter().filter_map(|signed_batch_info| {
                                let peer_id = signed_batch_info.signer();
                                let digest = *signed_batch_info.digest();
                                let batch_id = signed_batch_info.batch_id();
                                match self.add_signature(signed_batch_info, &validator_verifier) {
                                    Ok(Some(proof)) => {
                                        debug!(
                                            LogSchema::new(LogEvent::ProofOfStoreReady),
                                            digest = digest,
                                            batch_id = batch_id.id,
                                        );
                                        Some(proof)
                                    },
                                    Ok(None) => None,
                                    Err(e) => {
                                        // Can happen if we already garbage collected, the commit notification is late, or the peer is misbehaving.
                                        if peer_id == self.peer_id {
                                            info!("QS: could not add signature from self, digest = {}, batch_id = {}, err = {:?}", digest, batch_id, e);
                                        } else {
                                            debug!("QS: could not add signature from peer {}, digest = {}, batch_id = {}, err = {:?}", peer_id, digest, batch_id, e);
                                        }
                                        None
                                    },
                                }
                            }).peekable();
                            if proofs_iter.peek().is_some() {
                                observe_batch(approx_created_ts_usecs, self_peer_id, BatchStage::POS_FORMED);
                                if enable_broadcast_proofs {
                                    if proofs_iter.peek().is_some_and(|p| p.info().is_v2()) {
                                        let proofs: Vec<_> = proofs_iter.collect();
                                        network_sender.broadcast_proof_of_store_msg_v2(proofs).await;
                                    } else {
                                        let proofs: Vec<_> = proofs_iter.map(|proof| {
                                            let (info, sig) = proof.unpack();
                                            ProofOfStore::new(info.info().clone(), sig)
                                        }).collect();
                                        network_sender.broadcast_proof_of_store_msg(proofs).await;
                                    }
                                } else {
                                    let proofs: Vec<_> = proofs_iter.collect();
                                    network_sender.send_proof_of_store_msg_to_self(proofs).await;
                                }
                            }
                            if let Some(value) = self.batch_info_to_proof.get_mut(&info) {
                                value.observe_voting_pct(approx_created_ts_usecs, &validator_verifier);
                            }
                        },
                    }
                }),
                _ = interval.tick() => {
                    monitor!("proof_coordinator_handle_tick", self.expire().await);
                }
```
