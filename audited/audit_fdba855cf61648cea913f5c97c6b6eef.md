# Audit Report

## Title
Back Pressure Race Condition Due to Sampled State Updates in ProofManager

## Summary
The ProofManager's back pressure detection mechanism uses a 200ms sampling window to update queue state metrics, creating a race condition where rapid proof/batch arrivals can bypass back pressure throttling. This allows the proof queue to grow significantly beyond intended thresholds before corrective action is taken, potentially causing memory exhaustion and validator performance degradation.

## Finding Description

The vulnerability exists in the interaction between state sampling and back pressure detection in `ProofManager::start()`. [1](#0-0) 

The `update_remaining_txns_and_proofs()` function uses a 200ms sampling window, meaning the actual queue counts (`remaining_total_txn_num` and `remaining_total_proof_num`) are only updated at most once per 200ms, regardless of how many events occur. [2](#0-1) [3](#0-2) 

Both code paths check if back pressure changed by calling `qs_back_pressure()`, which compares the potentially stale counts against configured thresholds: [4](#0-3) 

**Attack Scenario:**
1. Network with 100 validators, `back_pressure_total_proof_limit = 2,000` (20 * 100) [5](#0-4) 

2. Current state: queue has 1,800 proofs, counts were updated at T=0ms showing 1,800
3. At T=10ms: Multiple validators send ProofOfStoreMsg messages (up to 20 proofs each) [6](#0-5) 

4. At T=50ms through T=190ms: Continuous proof arrivals push queue to 4,000+ proofs
5. Throughout this period, `update_remaining_txns_and_proofs()` is called but the sample doesn't fire (too soon after T=0ms)
6. `qs_back_pressure()` still reads stale value of 1,800 < 2,000, returns `proof_count: false`
7. No back pressure update sent to BatchGenerator
8. BatchGenerator continues pulling transactions at full rate, creating more batches
9. At T=200ms: Sample finally fires, counts updated to 4,000+
10. Back pressure triggered, but queue has already grown 2x beyond threshold

## Impact Explanation

This qualifies as **Medium Severity** per Aptos Bug Bounty criteria:

**State Inconsistency:** The proof queue state can deviate significantly from the intended back pressure thresholds for up to 200ms, with the BatchGenerator operating on incorrect assumptions about system capacity.

**Resource Exhaustion:** Each batch/proof consumes memory for:
- BatchInfoExt structures
- Transaction summaries 
- Proof signatures
- Expiration tracking data structures [7](#0-6) 

With 100 validators each sending 20 proofs containing 50 transactions each within 200ms, an additional ~100,000 transaction summaries could be queued beyond the threshold before back pressure activates.

**Validator Slowdown:** Processing and tracking thousands of extra proofs impacts CPU and memory, degrading consensus performance. If multiple validators are affected simultaneously, consensus rounds could slow significantly.

## Likelihood Explanation

**High Likelihood** under normal high-traffic conditions:
- No malicious intent required - legitimate network activity during high TPS periods naturally creates burst traffic
- 200ms windows are common in network messaging
- Multiple validators submitting proofs simultaneously is expected behavior
- The expensive computation in `remaining_txns_without_duplicates()` justifies sampling, but creates the vulnerability window [8](#0-7) 

## Recommendation

**Solution:** Maintain incremental counters updated on every event, eliminating the sampling delay for back pressure decisions while still rate-limiting the expensive full computation.

```rust
fn update_remaining_txns_and_proofs(&mut self) {
    // Always update the counts immediately for back pressure decisions
    (self.remaining_total_txn_num, self.remaining_total_proof_num) =
        (self.batch_proof_queue.get_cached_remaining_counts());
    
    // Sample the expensive full recalculation for metrics/verification
    sample!(
        SampleRate::Duration(Duration::from_millis(200)),
        {
            let (verified_txns, verified_proofs) = 
                self.batch_proof_queue.remaining_txns_and_proofs();
            // Log any discrepancies for monitoring
            if verified_txns != self.remaining_total_txn_num {
                warn!("Count mismatch detected");
            }
        }
    );
}
```

Modify BatchProofQueue to maintain running counters that are updated immediately in `insert_proof()`, `insert_batches()`, and `mark_committed()` rather than recalculated from scratch.

## Proof of Concept

```rust
#[cfg(test)]
mod back_pressure_race_test {
    use super::*;
    use tokio::time::{sleep, Duration};
    
    #[tokio::test]
    async fn test_back_pressure_sampling_race() {
        // Setup ProofManager with low thresholds
        let config = QuorumStoreConfig {
            back_pressure: QuorumStoreBackPressureConfig {
                backlog_txn_limit_count: 1000,
                backlog_per_validator_batch_limit_count: 10,
                ..Default::default()
            },
            ..Default::default()
        };
        
        let (back_pressure_tx, mut back_pressure_rx) = 
            tokio::sync::mpsc::channel(1000);
        
        // Send rapid bursts of proofs within 200ms window
        for i in 0..20 {
            // Each iteration adds proofs
            let proofs = create_test_proofs(100); // 100 proofs per batch
            proof_manager_tx.send(
                ProofManagerCommand::ReceiveProofs(proofs)
            ).await.unwrap();
            
            sleep(Duration::from_millis(5)).await; // 5ms between bursts
        }
        
        // Total: 2000 proofs sent in 100ms
        // Expected: back_pressure should trigger at proof 10
        // Actual: back_pressure won't trigger until 200ms sample fires
        
        sleep(Duration::from_millis(150)).await;
        
        // Check if back pressure was sent (it shouldn't have been yet)
        assert!(
            back_pressure_rx.try_recv().is_err(),
            "Back pressure triggered early due to stale counts"
        );
        
        sleep(Duration::from_millis(100)).await; // Wait for sample
        
        // Now it should trigger
        let bp = back_pressure_rx.recv().await.unwrap();
        assert!(bp.proof_count, "Back pressure should be active after sample fires");
        
        // Verify queue grew beyond threshold before back pressure activated
        assert!(proof_queue_size > 1000, "Queue exceeded threshold during sampling window");
    }
}
```

**Notes:**
- The vulnerability is a timing-based race condition inherent to the sampling optimization
- While the 200ms delay seems short, at high transaction volumes this window allows significant queue overgrowth
- The issue affects availability and performance rather than consensus safety
- Mitigation requires balancing computation cost against back pressure responsiveness

### Citations

**File:** consensus/src/quorum_store/proof_manager.rs (L72-78)
```rust
    fn update_remaining_txns_and_proofs(&mut self) {
        sample!(
            SampleRate::Duration(Duration::from_millis(200)),
            (self.remaining_total_txn_num, self.remaining_total_proof_num) =
                self.batch_proof_queue.remaining_txns_and_proofs();
        );
    }
```

**File:** consensus/src/quorum_store/proof_manager.rs (L245-265)
```rust
    pub(crate) fn qs_back_pressure(&self) -> BackPressure {
        if self.remaining_total_txn_num > self.back_pressure_total_txn_limit
            || self.remaining_total_proof_num > self.back_pressure_total_proof_limit
        {
            sample!(
                SampleRate::Duration(Duration::from_millis(200)),
                info!(
                    "Quorum store is back pressured with {} txns, limit: {}, proofs: {}, limit: {}",
                    self.remaining_total_txn_num,
                    self.back_pressure_total_txn_limit,
                    self.remaining_total_proof_num,
                    self.back_pressure_total_proof_limit
                );
            );
        }

        BackPressure {
            txn_count: self.remaining_total_txn_num > self.back_pressure_total_txn_limit,
            proof_count: self.remaining_total_proof_num > self.back_pressure_total_proof_limit,
        }
    }
```

**File:** consensus/src/quorum_store/proof_manager.rs (L285-291)
```rust
                        let updated_back_pressure = self.qs_back_pressure();
                        if updated_back_pressure != back_pressure {
                            back_pressure = updated_back_pressure;
                            if back_pressure_tx.send(back_pressure).await.is_err() {
                                debug!("Failed to send back_pressure for proposal");
                            }
                        }
```

**File:** consensus/src/quorum_store/proof_manager.rs (L319-325)
```rust
                        let updated_back_pressure = self.qs_back_pressure();
                        if updated_back_pressure != back_pressure {
                            back_pressure = updated_back_pressure;
                            if back_pressure_tx.send(back_pressure).await.is_err() {
                                debug!("Failed to send back_pressure for commit notification");
                            }
                        }
```

**File:** config/src/config/quorum_store_config.rs (L29-46)
```rust
impl Default for QuorumStoreBackPressureConfig {
    fn default() -> QuorumStoreBackPressureConfig {
        QuorumStoreBackPressureConfig {
            // QS will be backpressured if the remaining total txns is more than this number
            // Roughly, target TPS * commit latency seconds
            backlog_txn_limit_count: 36_000,
            // QS will create batches at the max rate until this number is reached
            backlog_per_validator_batch_limit_count: 20,
            decrease_duration_ms: 1000,
            increase_duration_ms: 1000,
            decrease_fraction: 0.5,
            dynamic_min_txn_per_s: 160,
            dynamic_max_txn_per_s: 12000,
            // When the QS is no longer backpressured, we increase number of txns to be pulled from mempool
            // by this amount every second until we reach dynamic_max_txn_per_s
            additive_increase_when_no_backpressure: 2000,
        }
    }
```

**File:** config/src/config/quorum_store_config.rs (L122-122)
```rust
            receiver_max_num_batches: 20,
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L56-76)
```rust
pub struct BatchProofQueue {
    my_peer_id: PeerId,
    // Queue per peer to ensure fairness between peers and priority within peer
    author_to_batches: HashMap<PeerId, BTreeMap<BatchSortKey, BatchInfoExt>>,
    // Map of Batch key to QueueItem containing Batch data and proofs
    items: HashMap<BatchKey, QueueItem>,
    // Number of unexpired and uncommitted proofs in which the txn_summary = (sender, replay protector, hash, expiration)
    // has been included. We only count those batches that are in both author_to_batches and items along with proofs.
    txn_summary_num_occurrences: HashMap<TxnSummaryWithExpiration, u64>,
    // Expiration index
    expirations: TimeExpirations<BatchSortKey>,
    batch_store: Arc<BatchStore>,

    latest_block_timestamp: u64,
    remaining_txns_with_duplicates: u64,
    remaining_proofs: u64,
    remaining_local_txns: u64,
    remaining_local_proofs: u64,

    batch_expiry_gap_when_init_usecs: u64,
}
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L143-172)
```rust
    fn remaining_txns_without_duplicates(&self) -> u64 {
        // txn_summary_num_occurrences counts all the unexpired and uncommitted proofs that have txn summaries
        // in batch_summaries.
        let mut remaining_txns = self.txn_summary_num_occurrences.len() as u64;

        // For the unexpired and uncommitted proofs that don't have transaction summaries in batch_summaries,
        // we need to add the proof.num_txns() to the remaining_txns.
        remaining_txns += self
            .author_to_batches
            .values()
            .map(|batches| {
                batches
                    .keys()
                    .map(|batch_sort_key| {
                        if let Some(item) = self.items.get(&batch_sort_key.batch_key) {
                            if item.txn_summaries.is_none() {
                                if let Some(ref proof) = item.proof {
                                    // The batch has a proof but not txn summaries
                                    return proof.num_txns();
                                }
                            }
                        }
                        0
                    })
                    .sum::<u64>()
            })
            .sum::<u64>();

        remaining_txns
    }
```
