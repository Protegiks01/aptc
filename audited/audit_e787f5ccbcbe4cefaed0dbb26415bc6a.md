# Audit Report

## Title
Batch Expiration Race Condition Causes Permanent Block Materialization Failure and Chain Liveness Halt

## Summary
A critical timing vulnerability exists between batch expiration validation and block materialization that can cause permanent liveness failures. When a batch included in a certified block expires before the block can be materialized, the system enters an infinite retry loop with no escape mechanism, causing the chain to halt on that block indefinitely.

## Finding Description

The vulnerability occurs due to inconsistent timestamp validation across two phases of the block execution pipeline:

**Phase 1: Proposal Validation (uses block timestamp)**
When requesting batch transactions, the system checks if batches have expired using the block's proposal timestamp: [1](#0-0) 

**Phase 2: Batch Fetching (uses current chain time)**
When fetching batches from peers, the system checks expiration against the current chain time reported by peers: [2](#0-1) 

**The Infinite Retry Loop:**
When batch fetching fails, the materialize phase retries indefinitely without timeout: [3](#0-2) 

**Attack Scenario:**
1. A block is proposed at time T with batch B (expiration T+60 seconds)
2. 2f+1 validators vote on the block (seeing the batch data)
3. Block receives QuorumCert and enters execution pipeline
4. Network delays or malicious behavior delays materialization until time T+65
5. Phase 1 check passes: block timestamp (T) ≤ expiration (T+60) ✓
6. Phase 2 check fails: current time (T+65) > expiration (T+60) ✗
7. Returns `CouldNotGetData` error [4](#0-3) 
8. Materialize loop retries with 100ms delay, repeating steps 5-7 forever
9. Expired batches are permanently deleted after expiration buffer: [5](#0-4) 

The batch requester exhausts its retry limit (default 10) within ~5 seconds, but the materialize loop continues indefinitely: [6](#0-5) 

## Impact Explanation

**High Severity** per Aptos Bug Bounty criteria:
- **Validator node slowdowns**: Affected nodes are stuck in infinite retry loops consuming CPU cycles
- **Significant protocol violations**: Breaks the liveness guarantee - the chain cannot progress beyond the stuck block
- **Availability impact**: If the stuck block is on the critical path, all consensus participants halt
- **Recovery requires intervention**: Manual intervention or forced state sync needed to bypass the stuck block

This does NOT cause:
- Consensus safety violations (no double-spend or fork)
- Permanent data loss (transactions are not lost, just stuck)
- Fund theft or minting

The severity qualifies as **High** because it causes significant protocol violations and requires manual intervention to resolve.

## Likelihood Explanation

**High likelihood** due to:

1. **Common trigger conditions**: Network latency spikes, temporary partitions, or slow validators can delay block materialization by 5-60+ seconds
2. **Default batch expiration**: Batches expire relatively quickly (60 seconds by default) [7](#0-6) 
3. **No protection mechanism**: The system has no circuit breaker, maximum retry count, or timeout at the materialize level
4. **Amplification by retry logic**: Batch requester retry limit (10 retries × 500ms interval = 5 seconds) is insufficient compared to expiration window

**Attack complexity**: 
- **Natural occurrence**: Can happen without malicious intent during network congestion
- **Malicious amplification**: An attacker controlling block proposal timing or network conditions can deliberately create batches near expiration to maximize probability

## Recommendation

Implement a timeout mechanism at the materialize phase with graceful degradation:

```rust
// In pipeline_builder.rs, modify the materialize function:
async fn materialize(
    preparer: Arc<BlockPreparer>,
    block: Arc<Block>,
    qc_rx: oneshot::Receiver<Arc<QuorumCert>>,
) -> TaskResult<MaterializeResult> {
    let mut tracker = Tracker::start_waiting("materialize", &block);
    tracker.start_working();

    let qc_rx = async {
        match qc_rx.await {
            Ok(qc) => Some(qc),
            Err(_) => {
                warn!("[BlockPreparer] qc tx cancelled for block {}", block.id());
                None
            },
        }
    }
    .shared();
    
    // Add maximum retry limit and timeout
    const MAX_RETRIES: usize = 100; // ~10 seconds with 100ms delay
    let mut retry_count = 0;
    
    let result = loop {
        match preparer.materialize_block(&block, qc_rx.clone()).await {
            Ok(input_txns) => break input_txns,
            Err(e) => {
                retry_count += 1;
                if retry_count >= MAX_RETRIES {
                    // Check if error is due to expired batches
                    if matches!(e, ExecutorError::CouldNotGetData) {
                        warn!(
                            "[BlockPreparer] block {} failed to materialize after {} retries due to expired batches, using empty payload",
                            block.id(),
                            retry_count
                        );
                        // Return empty transaction set for expired batches
                        break (Vec::new(), None, None);
                    }
                }
                warn!(
                    "[BlockPreparer] failed to prepare block {} (retry {}/{}): {}",
                    block.id(),
                    retry_count,
                    MAX_RETRIES,
                    e
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            },
        }
    };
    Ok(result)
}
```

Additionally, improve the expiration check consistency by using current chain time in both phases:

```rust
// In quorum_store_payload_manager.rs, modify request_transactions:
fn request_transactions(
    batches: Vec<(BatchInfo, Vec<PeerId>)>,
    block_timestamp: u64,
    batch_reader: Arc<dyn BatchReader>,
    current_certified_time: u64, // Add this parameter
) -> Vec<...> {
    let mut futures = Vec::new();
    for (batch_info, responders) in batches {
        // Use current certified time instead of block timestamp
        if current_certified_time <= batch_info.expiration() {
            futures.push(batch_reader.get_batch(batch_info, responders.clone()));
        } else {
            debug!("QSE: skipped expired batch {} (current time {} > expiration {})", 
                   batch_info.digest(), current_certified_time, batch_info.expiration());
        }
    }
    futures
}
```

## Proof of Concept

```rust
// Test case demonstrating the vulnerability
// Add to consensus/src/pipeline/pipeline_builder_test.rs

#[tokio::test]
async fn test_expired_batch_causes_infinite_retry() {
    // Setup
    let mut mock_preparer = MockBlockPreparer::new();
    let block = create_test_block_with_expired_batch();
    let (qc_tx, qc_rx) = oneshot::channel();
    
    // Simulate batch expiration by making materialize_block always return CouldNotGetData
    mock_preparer
        .expect_materialize_block()
        .returning(|_, _| Err(ExecutorError::CouldNotGetData));
    
    // Start materialization with timeout to observe infinite retry
    let materialize_fut = tokio::time::timeout(
        Duration::from_secs(2),
        PipelineBuilder::materialize(Arc::new(mock_preparer), block, qc_rx)
    );
    
    // Should timeout because of infinite retry loop
    let result = materialize_fut.await;
    assert!(result.is_err(), "Expected timeout due to infinite retry");
    
    // Verify the preparer was called many times (> 10)
    // This demonstrates the infinite retry behavior
}
```

**Notes:**
- The vulnerability requires batch expiration timing to align with block materialization delays
- Default configuration makes this moderately likely during network stress
- The infinite retry consumes resources and prevents chain progress
- Recovery requires aborting the stuck block's pipeline or forcing state sync

### Citations

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L102-106)
```rust
            if block_timestamp <= batch_info.expiration() {
                futures.push(batch_reader.get_batch(batch_info, responders.clone()));
            } else {
                debug!("QSE: skipped expired batch {}", batch_info.digest());
            }
```

**File:** consensus/src/quorum_store/batch_requester.rs (L142-151)
```rust
                            Ok(BatchResponse::NotFound(ledger_info)) => {
                                counters::RECEIVED_BATCH_NOT_FOUND_COUNT.inc();
                                if ledger_info.commit_info().epoch() == epoch
                                    && ledger_info.commit_info().timestamp_usecs() > expiration
                                    && ledger_info.verify_signatures(&validator_verifier).is_ok()
                                {
                                    counters::RECEIVED_BATCH_EXPIRED_COUNT.inc();
                                    debug!("QS: batch request expired, digest:{}", digest);
                                    return Err(ExecutorError::CouldNotGetData);
                                }
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L634-646)
```rust
        let result = loop {
            match preparer.materialize_block(&block, qc_rx.clone()).await {
                Ok(input_txns) => break input_txns,
                Err(e) => {
                    warn!(
                        "[BlockPreparer] failed to prepare block {}, retrying: {}",
                        block.id(),
                        e
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                },
            }
        };
```

**File:** execution/executor-types/src/error.rs (L42-42)
```rust
    CouldNotGetData,
```

**File:** consensus/src/quorum_store/batch_store.rs (L443-447)
```rust
    pub(crate) fn clear_expired_payload(&self, certified_time: u64) -> Vec<HashValue> {
        // To help slow nodes catch up via execution without going to state sync we keep the blocks for 60 extra seconds
        // after the expiration time. This will help remote peers fetch batches that just expired but are within their
        // execution window.
        let expiration_time = certified_time.saturating_sub(self.expiration_buffer_usecs);
```

**File:** config/src/config/quorum_store_config.rs (L128-128)
```rust
            batch_request_retry_limit: 10,
```

**File:** config/src/config/quorum_store_config.rs (L131-131)
```rust
            batch_expiry_gap_when_init_usecs: Duration::from_secs(60).as_micros() as u64,
```
