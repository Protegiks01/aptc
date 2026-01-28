# Audit Report

## Title
Memory Leak in ProofCoordinator: Unbounded Growth of batch_info_to_time HashMap Due to Incomplete Cleanup in expire()

## Summary
The `expire()` function in `ProofCoordinator` fails to remove entries from the `batch_info_to_time` HashMap when batches expire without completing. This creates a memory leak that causes unbounded HashMap growth, eventually leading to memory exhaustion and validator node instability requiring manual intervention.

## Finding Description

The `ProofCoordinator` maintains two parallel HashMap structures to track batches during proof-of-store formation:
- `batch_info_to_proof`: Tracks signature aggregation state
- `batch_info_to_time`: Records batch creation timestamps for metrics [1](#0-0) 

When a batch is initialized via `init_proof()`, entries are added to both HashMaps. The `batch_info_to_proof` HashMap receives the signature aggregation state [2](#0-1) , while `batch_info_to_time` records the batch creation timestamp [3](#0-2) .

There are two cleanup paths:

**Path 1: Successful proof completion** - When a batch receives enough signatures to form a quorum, the `add_signature()` function removes the entry from `batch_info_to_time` to calculate the batch-to-proof duration metric [4](#0-3) .

**Path 2: Expiration without completion** - When a batch times out before achieving quorum, the `expire()` function removes entries from `batch_info_to_proof` [5](#0-4) , but there is NO corresponding removal from `batch_info_to_time`.

This asymmetry creates a memory leak. Every batch that expires without completing leaves a permanent entry in `batch_info_to_time` containing a `BatchInfoExt` key and `Instant` value.

**Triggering Conditions:**
- Network partitions preventing signature propagation
- Validator unavailability or slow response times
- Byzantine validators withholding signatures
- Normal operations where some batches naturally fail to achieve quorum within the timeout window

The codebase shows that batch timeouts are expected operational events, with dedicated counters and logging [6](#0-5) , and the `expire()` function is called every 100ms [7](#0-6) .

## Impact Explanation

**Severity: Medium** (aligns with "State inconsistencies requiring manual intervention")

**Resource Exhaustion:**
- Each leaked entry contains a `BatchInfoExt` (metadata including digest, epoch, batch_id) and an `Instant` timestamp
- Over days/weeks of continuous operation with even modest failure rates, thousands of entries accumulate
- HashMap growth degrades performance due to increased lookup times and memory pressure
- Eventually leads to OOM conditions requiring node restart

**Operational Impact:**
- Validator nodes experience progressive slowdown
- Memory alerts trigger requiring manual intervention
- Node restarts needed to clear leaked memory
- Reduced consensus participation during recovery

**Why Medium and not High/Critical:**
- Does not directly compromise consensus safety or cause fund loss
- Gradual degradation rather than immediate failure
- Recoverable through node restart (though requires intervention)
- Does not affect blockchain state correctness, only node availability

This aligns with the Medium severity definition from the Aptos bug bounty program: "State inconsistencies requiring manual intervention" - the node's internal state becomes inconsistent with unbounded memory usage, requiring operator intervention to resolve.

## Likelihood Explanation

**Likelihood: High**

This vulnerability will manifest in all production deployments given sufficient time:

1. **Natural Occurrence Rate:** Even under optimal conditions, some percentage of batches fail to achieve quorum within timeout windows due to network latency variance, temporary validator unavailability, and load-based delays.

2. **Network Stress Amplification:** During network issues or degraded conditions, batch expiry rates increase significantly, accelerating the memory leak proportionally.

3. **No Recovery Mechanism:** The leak is permanent - there is no code path that cleans up old `batch_info_to_time` entries other than successful proof completion. The `expire()` function only removes from `batch_info_to_proof`, not from `batch_info_to_time`.

4. **Expected Operational Event:** The codebase confirms that batch timeouts are expected operational events through dedicated metrics counters and logging, not rare edge cases.

Given that batch expiry is a normal operational occurrence and there is no cleanup mechanism for failed batches, this leak will eventually affect all running validators.

## Recommendation

Add cleanup of `batch_info_to_time` entries in the `expire()` function to match the cleanup behavior of `batch_info_to_proof`:

```rust
async fn expire(&mut self) {
    let mut batch_ids = vec![];
    for signed_batch_info_info in self.timeouts.expire() {
        if let Some(state) = self.batch_info_to_proof.remove(&signed_batch_info_info) {
            // Add this line to clean up batch_info_to_time
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

This ensures both HashMaps maintain consistent cleanup behavior regardless of whether a batch completes successfully or expires.

## Proof of Concept

The memory leak can be observed by monitoring the `batch_info_to_time` HashMap size over time in a running validator node:

1. Deploy a validator node with instrumentation to track HashMap sizes
2. Monitor the node during normal operations
3. Observe that `batch_info_to_time.len()` continuously grows while `batch_info_to_proof.len()` remains bounded
4. After days of operation with batch timeouts occurring, the leaked HashMap will contain thousands of entries

The vulnerability is evident from code inspection: there is only one removal path for `batch_info_to_time` (successful completion in `add_signature()`), but no removal path in `expire()` for failed batches.

### Citations

**File:** consensus/src/quorum_store/proof_coordinator.rs (L233-235)
```rust
    batch_info_to_proof: HashMap<BatchInfoExt, IncrementalProofState>,
    // to record the batch creation time
    batch_info_to_time: HashMap<BatchInfoExt, Instant>,
```

**File:** consensus/src/quorum_store/proof_coordinator.rs (L290-301)
```rust
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
```

**File:** consensus/src/quorum_store/proof_coordinator.rs (L302-304)
```rust
        self.batch_info_to_time
            .entry(signed_batch_info.batch_info().clone())
            .or_insert(Instant::now());
```

**File:** consensus/src/quorum_store/proof_coordinator.rs (L338-346)
```rust
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

**File:** consensus/src/quorum_store/proof_coordinator.rs (L506-507)
```rust
                _ = interval.tick() => {
                    monitor!("proof_coordinator_handle_tick", self.expire().await);
```
