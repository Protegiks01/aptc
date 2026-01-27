# Audit Report

## Title
Time-of-Check-Time-of-Use Race Condition in Payload Availability Causes Consensus Execution Failures

## Summary
A race condition exists between `check_payload_availability()` and `get_transactions()` in the OptQuorumStore payload manager. Concurrent batch expiration via `notify_commit()` can remove batches after the availability check passes but before transactions are retrieved, causing execution failures and preventing validators from voting on valid blocks.

## Finding Description

The vulnerability occurs in the consensus block processing pipeline where payload availability is checked before block execution begins, but the actual transaction retrieval happens asynchronously much later in the pipeline.

**Time of Check:** [1](#0-0) 

The `check_payload()` method verifies batch availability using `exists()`: [2](#0-1) 

For OptQuorumStore payloads, this checks local storage: [3](#0-2) 

**Time of Use:**
After passing the availability check, the block proceeds through multiple processing stages before `get_transactions()` is called during materialization: [4](#0-3) 

**Concurrent Modification:**
Between check and use, batch expiration can occur via commit notifications from OTHER blocks: [5](#0-4) 

This triggers batch cleanup: [6](#0-5) 

Which removes expired batches from local storage: [7](#0-6) 

**Failure Path:**
When `get_transactions()` tries to fetch the now-removed batch: [8](#0-7) 

If the batch expired and all peers have also removed it, `request_batch()` fails: [9](#0-8) 

This error propagates through the materialization pipeline, causing the block execution to fail and preventing the validator from voting.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria:

1. **Validator node slowdowns**: Affected validators repeatedly retry failed batch fetches with 100ms delays: [10](#0-9) 

2. **Significant protocol violations**: Validators may fail to vote on valid blocks, potentially causing consensus liveness issues if multiple validators are affected simultaneously during high load or near batch expiration times.

3. **Consensus availability impact**: While not total network liveness loss, this can significantly degrade consensus performance and increase block confirmation times, especially when many blocks contain batches near expiration.

## Likelihood Explanation

**Likelihood: Moderate to High**

The vulnerability is more likely to occur when:

1. **Batch expiration timing**: Blocks are processed when their batches are close to expiration (within 60 seconds of the expiration buffer)
2. **High commit rate**: Frequent block commits trigger more `notify_commit()` calls, increasing cleanup frequency
3. **Processing delays**: Validators under load take longer between check and use, widening the race window
4. **Network conditions**: Slow block processing due to network latency or validator resource constraints

The time window between check and use spans multiple async operations including backpressure checks, vote construction, block insertion, and pipeline spawning - easily hundreds of milliseconds to seconds under load.

## Recommendation

Implement one of the following mitigations:

**Option 1: Pin batches during processing**
Add a reference-counting or pinning mechanism that prevents batch cleanup while a block is being processed:

```rust
// In check_payload_availability, mark batches as in-use
fn check_payload_availability(&self, block: &Block) -> Result<(), BitVec> {
    // Check availability AND pin batches
    let result = self.check_and_pin_batches(block);
    result
}

// In get_transactions, unpin after retrieval
async fn get_transactions(&self, block: &Block, ...) -> ExecutorResult<...> {
    let result = self.retrieve_transactions(block).await;
    self.unpin_batches(block);
    result
}
```

**Option 2: Defer expiration for in-flight blocks**
Track blocks currently being processed and exclude their batches from cleanup:

```rust
// In clear_expired_payload
pub(crate) fn clear_expired_payload(&self, certified_time: u64) -> Vec<HashValue> {
    let expiration_time = certified_time.saturating_sub(self.expiration_buffer_usecs);
    let expired_digests = self.expirations.lock().expire(expiration_time);
    
    // Filter out batches referenced by in-flight blocks
    let in_flight_batches = self.get_in_flight_batch_digests();
    let safe_to_remove: Vec<_> = expired_digests
        .into_iter()
        .filter(|d| !in_flight_batches.contains(d))
        .collect();
    
    // Continue with cleanup...
}
```

**Option 3: Increase expiration buffer and check timing**
Increase the 60-second expiration buffer and add timestamp validation before use:

```rust
// Increase buffer from 60s to 300s
const EXPIRATION_BUFFER_SECS: u64 = 300;

// In get_transactions, verify batch hasn't expired
async fn get_transactions(&self, block: &Block, ...) -> ExecutorResult<...> {
    // Double-check batch availability with current time
    if let Err(missing) = self.check_payload_availability(block) {
        // Batches expired between check and use
        return Err(ExecutorError::CouldNotGetData);
    }
    // Proceed with retrieval...
}
```

## Proof of Concept

```rust
// Integration test demonstrating the race condition
#[tokio::test]
async fn test_payload_availability_race_condition() {
    // Setup: Create a validator with OptQuorumStore
    let (mut runtime, mut nodes) = setup_test_network(4).await;
    let validator = &mut nodes[0];
    
    // Step 1: Create a batch that expires soon
    let expiration = current_timestamp() + Duration::from_secs(70);
    let batch = create_test_batch(expiration);
    validator.batch_store.persist(vec![batch.clone()]);
    
    // Step 2: Create a block containing this batch
    let block = create_block_with_optqs_payload(vec![batch.batch_info()]);
    
    // Step 3: Start processing the block (check passes)
    let check_result = validator.payload_manager.check_payload_availability(&block);
    assert!(check_result.is_ok(), "Availability check should pass");
    
    // Step 4: Simulate concurrent commit advancing time past expiration
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let commit_time = current_timestamp() + Duration::from_secs(80);
        validator.payload_manager.notify_commit(commit_time, vec![]);
    });
    
    // Step 5: Try to get transactions (fails due to expired batch)
    tokio::time::sleep(Duration::from_millis(100)).await;
    let result = validator.payload_manager.get_transactions(&block, None).await;
    
    // Vulnerability: get_transactions fails even though check passed
    assert!(result.is_err(), "Transaction retrieval fails due to race");
    assert_eq!(result.unwrap_err(), ExecutorError::CouldNotGetData);
    
    // Impact: Validator cannot vote on the block
    let vote_result = validator.vote_on_block(&block).await;
    assert!(vote_result.is_err(), "Validator cannot vote on valid block");
}
```

## Notes

The 60-second expiration buffer provides some protection but is insufficient under the following conditions:
- Validators processing old blocks during catch-up
- High network latency delaying block processing
- Validator resource exhaustion causing slow pipeline execution
- Intentional or accidental clock skew between validators

The vulnerability is exacerbated by the infinite retry loop in the materialize phase, which can cause validators to become stuck attempting to fetch unavailable batches rather than failing fast and potentially recovering through state sync.

### Citations

**File:** consensus/src/round_manager.rs (L1262-1262)
```rust
        if block_store.check_payload(&proposal).is_err() {
```

**File:** consensus/src/quorum_store/batch_store.rs (L443-472)
```rust
    pub(crate) fn clear_expired_payload(&self, certified_time: u64) -> Vec<HashValue> {
        // To help slow nodes catch up via execution without going to state sync we keep the blocks for 60 extra seconds
        // after the expiration time. This will help remote peers fetch batches that just expired but are within their
        // execution window.
        let expiration_time = certified_time.saturating_sub(self.expiration_buffer_usecs);
        let expired_digests = self.expirations.lock().expire(expiration_time);
        let mut ret = Vec::new();
        for h in expired_digests {
            let removed_value = match self.db_cache.entry(h) {
                Occupied(entry) => {
                    // We need to check up-to-date expiration again because receiving the same
                    // digest with a higher expiration would update the persisted value and
                    // effectively extend the expiration.
                    if entry.get().expiration() <= expiration_time {
                        self.persist_subscribers.remove(entry.get().digest());
                        Some(entry.remove())
                    } else {
                        None
                    }
                },
                Vacant(_) => unreachable!("Expired entry not in cache"),
            };
            // No longer holding the lock on db_cache entry.
            if let Some(value) = removed_value {
                self.free_quota(value);
                ret.push(h);
            }
        }
        ret
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L530-539)
```rust
    pub fn update_certified_timestamp(&self, certified_time: u64) {
        trace!("QS: batch reader updating time {:?}", certified_time);
        self.last_certified_time
            .fetch_max(certified_time, Ordering::SeqCst);

        let expired_keys = self.clear_expired_payload(certified_time);
        if let Err(e) = self.db.delete_batches(expired_keys) {
            debug!("Error deleting batches: {:?}", e)
        }
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L684-710)
```rust
                let fut = async move {
                    let batch_digest = *batch_info.digest();
                    defer!({
                        inflight_requests_clone.lock().remove(&batch_digest);
                    });
                    // TODO(ibalajiarun): Support V2 batch
                    if let Ok(mut value) = batch_store.get_batch_from_local(&batch_digest) {
                        Ok(value.take_payload().expect("Must have payload"))
                    } else {
                        // Quorum store metrics
                        counters::MISSED_BATCHES_COUNT.inc();
                        let subscriber_rx = batch_store.subscribe(*batch_info.digest());
                        let payload = requester
                            .request_batch(
                                batch_digest,
                                batch_info.expiration(),
                                responders,
                                subscriber_rx,
                            )
                            .await?;
                        batch_store.persist(vec![PersistedValue::new(
                            batch_info.into(),
                            Some(payload.clone()),
                        )]);
                        Ok(payload)
                    }
                }
```

**File:** consensus/src/quorum_store/batch_store.rs (L727-732)
```rust
    fn exists(&self, digest: &HashValue) -> Option<PeerId> {
        self.batch_store
            .get_batch_from_local(digest)
            .map(|v| v.author())
            .ok()
    }
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L409-425)
```rust
            Payload::OptQuorumStore(OptQuorumStorePayload::V1(p)) => {
                let mut missing_authors = BitVec::with_num_bits(self.ordered_authors.len() as u16);
                for batch in p.opt_batches().deref() {
                    if self.batch_reader.exists(batch.digest()).is_none() {
                        let index = *self
                            .address_to_validator_index
                            .get(&batch.author())
                            .expect("Payload author should have been verified");
                        missing_authors.set(index as u16);
                    }
                }
                if missing_authors.all_zeros() {
                    Ok(())
                } else {
                    Err(missing_authors)
                }
            },
```

**File:** consensus/src/block_preparer.rs (L54-63)
```rust
        let (txns, max_txns_from_block_to_execute, block_gas_limit) = tokio::select! {
                // Poll the block qc future until a QC is received. Ignore None outcomes.
                Some(qc) = block_qc_fut => {
                    let block_voters = Some(qc.ledger_info().get_voters_bitvec().clone());
                    self.payload_manager.get_transactions(block, block_voters).await
                },
                result = self.payload_manager.get_transactions(block, None) => {
                   result
                }
        }?;
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

**File:** consensus/src/pipeline/pipeline_builder.rs (L1132-1135)
```rust
        let payload = block.payload().cloned();
        let timestamp = block.timestamp_usecs();
        let payload_vec = payload.into_iter().collect();
        payload_manager.notify_commit(timestamp, payload_vec);
```

**File:** consensus/src/quorum_store/batch_requester.rs (L176-179)
```rust
            counters::RECEIVED_BATCH_REQUEST_TIMEOUT_COUNT.inc();
            debug!("QS: batch request timed out, digest:{}", digest);
            Err(ExecutorError::CouldNotGetData)
        })
```
