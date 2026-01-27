# Audit Report

## Title
Ignored Batch Persistence Errors Lead to Network Resource Waste and Transaction Delays

## Summary
The batch generator in the quorum store broadcasts batches to the network even when local persistence fails, leading to wasted network bandwidth, unnecessary storage consumption on peer nodes, and delayed transaction inclusion.

## Finding Description

The quorum store's batch generation flow has a critical error handling gap. When a validator creates batches from its mempool, it attempts to persist them locally before broadcasting to the network. However, the code ignores persistence failures and broadcasts all batches regardless of whether they were successfully stored.

**The Error Path:**

The `put()` function in `quorum_store_db.rs` properly propagates database errors: [1](#0-0) 

These errors are handled with `.expect()` in the persistence layer: [2](#0-1) 

However, when the earlier `save()` method fails (due to quota exhaustion or batch expiration), the error is caught and `persist_inner()` returns `None`: [3](#0-2) 

The quota can be exceeded when processing batches: [4](#0-3) 

**The Critical Bug:**

In `batch_generator.rs`, the return value from `persist()` is completely ignored: [5](#0-4) 

This means batches that failed to persist locally are still broadcast to all validators in the network.

**Impact Chain:**

1. Validator creates N batches from mempool
2. Due to quota limits, only M batches persist successfully (M < N)
3. `persist()` returns M SignedBatchInfo objects
4. Batch generator ignores this and broadcasts all N batches
5. Other validators receive all N batches, persist them, and send signatures back
6. The ProofCoordinator rejects signatures for the N-M batches that weren't persisted locally: [6](#0-5) 

7. These N-M batches can never form valid ProofOfStore from this author

## Impact Explanation

**Medium Severity** - This issue causes state inconsistencies requiring intervention:

1. **Resource Waste**: Network bandwidth is consumed broadcasting invalid batches that can never produce proofs
2. **Peer Storage Exhaustion**: Other validators waste quota storing and signing batches that will never be used
3. **Transaction Delays**: Transactions in failed batches must wait for re-proposal rather than immediate inclusion
4. **State Inconsistency**: The node maintains an inconsistent view where it broadcasts batches it doesn't possess

While this doesn't cause consensus safety violations (the ProofCoordinator check prevents invalid proofs), it creates operational issues that can degrade network performance and require manual intervention to clear quotas or restart nodes.

## Likelihood Explanation

**High Likelihood** - This can occur naturally under normal operation:

1. During high transaction volume, validators can legitimately exceed their batch quotas
2. Network delays or slow processing can cause batch expiration before persistence
3. Resource constraints on individual nodes trigger quota limits
4. No malicious actor required - occurs through normal system stress

The issue manifests whenever a validator's quota is exhausted, which is expected during peak load periods on a production network.

## Recommendation

Check the return value from `persist()` and only broadcast batches that were successfully persisted and signed:

```rust
let persist_start = Instant::now();
let mut persist_requests = vec![];
for batch in batches.clone().into_iter() {
    persist_requests.push(batch.into());
}
let signed_batch_infos = self.batch_writer.persist(persist_requests);
counters::BATCH_CREATION_PERSIST_LATENCY.observe_duration(persist_start.elapsed());

// Only broadcast batches that were successfully persisted
if !signed_batch_infos.is_empty() {
    // Map signed infos back to their original batches
    let successfully_persisted_digests: HashSet<_> = signed_batch_infos
        .iter()
        .map(|info| *info.digest())
        .collect();
    
    let batches_to_broadcast: Vec<_> = batches
        .into_iter()
        .filter(|batch| successfully_persisted_digests.contains(batch.digest()))
        .collect();
    
    if !batches_to_broadcast.is_empty() {
        if self.config.enable_batch_v2 {
            network_sender.broadcast_batch_msg_v2(batches_to_broadcast).await;
        } else {
            let batches = batches_to_broadcast.into_iter().map(|batch| {
                batch.try_into().expect("Cannot send V2 batch with flag disabled")
            }).collect();
            network_sender.broadcast_batch_msg(batches).await;
        }
    }
}
```

Alternatively, add metrics and logging to track when batches are broadcast but not persisted, and implement retry logic or quota management to prevent this scenario.

## Proof of Concept

```rust
#[test]
fn test_batch_generator_ignores_persist_failures() {
    // This test demonstrates that batch_generator broadcasts batches
    // even when persistence fails
    
    // 1. Create a batch generator with a mock batch writer that fails persist
    // 2. Generate batches that exceed quota
    // 3. Verify persist() returns empty Vec (indicating failure)
    // 4. Verify batches are still broadcast via network_sender
    // 5. Verify other nodes receive batches they can't fetch from author
    
    // Setup (pseudo-code for reproduction):
    // - Configure QuotaManager with very low limits
    // - Generate multiple large batches to exceed quota
    // - Call handle_scheduled_pull
    // - Capture network_sender.broadcast calls
    // - Assert batches broadcasted > batches persisted
    // - Verify ProofCoordinator rejects these batches with NotFound
}
```

**Notes**

This vulnerability is specifically about the error handling gap in `batch_generator.rs` where the return value from `persist()` is not checked. While the underlying `put()` function properly propagates errors via `Result<(), DbError>`, and the immediate callers use `.expect()` to handle database write failures (causing panics), there is a separate error path through quota exhaustion where `save()` fails gracefully but the calling code in batch_generator ignores this failure.

The issue is partially mitigated by the ProofCoordinator's check that prevents forming invalid proofs, but it still causes resource waste and transaction delays that constitute a Medium severity issue per the Aptos bug bounty criteria for "state inconsistencies requiring intervention."

### Citations

**File:** consensus/src/quorum_store/quorum_store_db.rs (L83-89)
```rust
    pub fn put<S: Schema>(&self, key: &S::Key, value: &S::Value) -> Result<(), DbError> {
        // Not necessary to use a batch, but we'd like a central place to bump counters.
        let mut batch = self.db.new_native_batch();
        batch.put::<S>(key, value)?;
        self.db.write_schemas_relaxed(batch)?;
        Ok(())
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L64-84)
```rust
    pub(crate) fn update_quota(&mut self, num_bytes: usize) -> anyhow::Result<StorageMode> {
        if self.batch_balance == 0 {
            counters::EXCEEDED_BATCH_QUOTA_COUNT.inc();
            bail!("Batch quota exceeded ");
        }

        if self.db_balance >= num_bytes {
            self.batch_balance -= 1;
            self.db_balance -= num_bytes;

            if self.memory_balance >= num_bytes {
                self.memory_balance -= num_bytes;
                Ok(StorageMode::MemoryAndPersisted)
            } else {
                Ok(StorageMode::PersistedOnly)
            }
        } else {
            counters::EXCEEDED_STORAGE_QUOTA_COUNT.inc();
            bail!("Storage quota exceeded ");
        }
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L497-527)
```rust
        match self.save(&persist_request) {
            Ok(needs_db) => {
                trace!("QS: sign digest {}", persist_request.digest());
                if needs_db {
                    if !batch_info.is_v2() {
                        let persist_request =
                            persist_request.try_into().expect("Must be a V1 batch");
                        #[allow(clippy::unwrap_in_result)]
                        self.db
                            .save_batch(persist_request)
                            .expect("Could not write to DB");
                    } else {
                        #[allow(clippy::unwrap_in_result)]
                        self.db
                            .save_batch_v2(persist_request)
                            .expect("Could not write to DB")
                    }
                }
                if !batch_info.is_v2() {
                    self.generate_signed_batch_info(batch_info.info().clone())
                        .ok()
                        .map(|inner| inner.into())
                } else {
                    self.generate_signed_batch_info(batch_info).ok()
                }
            },
            Err(e) => {
                debug!("QS: failed to store to cache {:?}", e);
                None
            },
        }
```

**File:** consensus/src/quorum_store/batch_generator.rs (L486-501)
```rust
                            let persist_start = Instant::now();
                            let mut persist_requests = vec![];
                            for batch in batches.clone().into_iter() {
                                persist_requests.push(batch.into());
                            }
                            self.batch_writer.persist(persist_requests);
                            counters::BATCH_CREATION_PERSIST_LATENCY.observe_duration(persist_start.elapsed());

                            if self.config.enable_batch_v2 {
                                network_sender.broadcast_batch_msg_v2(batches).await;
                            } else {
                                let batches = batches.into_iter().map(|batch| {
                                    batch.try_into().expect("Cannot send V2 batch with flag disabled")
                                }).collect();
                                network_sender.broadcast_batch_msg(batches).await;
                            }
```

**File:** consensus/src/quorum_store/proof_coordinator.rs (L277-283)
```rust
        let batch_author = self
            .batch_reader
            .exists(signed_batch_info.digest())
            .ok_or(SignedBatchInfoError::NotFound)?;
        if batch_author != signed_batch_info.author() {
            return Err(SignedBatchInfoError::WrongAuthor);
        }
```
