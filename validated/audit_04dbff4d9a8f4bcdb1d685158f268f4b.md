# Audit Report

## Title
Storage Quota Bypass Allowing Network-Wide Resource Exhaustion via Unchecked Batch Propagation

## Summary
The quorum store's storage quota enforcement mechanism is fundamentally broken. While quota checks are performed and `EXCEEDED_STORAGE_QUOTA_COUNT` increments when limits are exceeded, the quota violations are not enforced in the batch propagation flow. This allows malicious validators to bypass storage quotas and cause network-wide resource exhaustion by flooding all validators with over-quota batch summaries that get stored in memory without proper validation.

## Finding Description

The quorum store implements a per-peer storage quota system to limit resources consumed by each validator. When a validator exceeds their quota, the system correctly detects this and increments a counter, but critically fails to prevent the over-quota batches from propagating through the network.

**Quota Check Implementation:**

The quota validation logic correctly detects violations and returns an error: [1](#0-0) 

**Critical Flaw #1 - Local Batch Creation:**

When a validator generates batches locally, the `persist()` call result is completely ignored: [2](#0-1) 

The `persist()` method is called at line 491, but its return value (which would be empty if quota is exceeded) is discarded. The batches are then unconditionally broadcast to all validators at lines 494-500, regardless of whether persist succeeded.

**Critical Flaw #2 - Remote Batch Reception:**

When validators receive batches from the network, the `persist_and_send_digests()` function constructs batch summaries BEFORE calling `persist()`, then sends them to ProofManager regardless of the persist result: [3](#0-2) 

The `batches` variable is constructed from `persist_requests` at lines 92-100. Even though `persist()` is called at lines 103/113, the batch summaries are unconditionally sent to ProofManager at lines 131-133, completely bypassing quota enforcement.

**Critical Flaw #3 - ProofManager Lacks Quota Validation:**

The ProofManager accepts batch summaries without any quota validation: [4](#0-3) [5](#0-4) 

The `insert_batches()` method blindly inserts all batch summaries into memory data structures (`author_to_batches`, `items`, `expirations`) without checking if the originating validator has exceeded their quota.

**Default Configuration Enables Attack:**

The system is configured by default to allow batches without proof-of-store in proposals: [6](#0-5) 

**Attack Execution Path:**

1. Malicious validator creates batches exceeding their storage quota (e.g., 300MB db_quota)
2. Local quota check fails, `EXCEEDED_STORAGE_QUOTA_COUNT` increments, `persist()` returns empty vector
3. Batches are broadcast to network anyway (bug in batch_generator.rs line 491)
4. All validators receive these batches via `handle_batches_msg()`
5. Each validator constructs batch summaries BEFORE calling `persist()` (bug in batch_coordinator.rs lines 92-100)
6. Each validator's `persist()` fails due to quota exceeded for that peer
7. Batch summaries are sent to ProofManager anyway (lines 131-133)
8. ProofManager inserts summaries into memory without quota validation (bug in batch_proof_queue.rs)
9. Memory resources are consumed across all validators for invalid batches
10. Attacker can repeat indefinitely with no penalty

This breaks the fundamental security invariant that resource limits must be enforced. The quota system becomes purely observational (counting violations) rather than protective (preventing violations).

## Impact Explanation

This vulnerability qualifies as **HIGH Severity** per Aptos bug bounty criteria under "Validator Node Slowdowns":

**Primary Impacts:**
- **Network-wide resource exhaustion**: A single malicious validator can force ALL validators to consume memory tracking invalid batch summaries
- **Protocol violation**: The quota enforcement mechanism is fundamentally broken - checks exist but are not enforced
- **Amplified attack surface**: Each over-quota batch from one validator causes resource consumption on every validator in the network
- **Validator performance degradation**: Memory and CPU resources wasted on tracking batches that should have been rejected

**Mitigating Factors (why not CRITICAL):**
- Batches expire after 60 seconds, providing natural cleanup
- Only batch summaries (metadata) are stored, not full transaction payloads
- Garbage collection exists for expired batches
- Does not directly cause consensus safety violations or fund loss

However, this remains HIGH severity because:
- It allows sustained resource exhaustion attacks
- The quota system provides zero actual protection
- It affects all validators simultaneously
- The attack can be repeated continuously to maintain resource pressure

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **Trivial to execute**: Any validator in the active set can trigger this by creating large batches. No sophisticated attack required.

2. **Zero cost to attacker**: The malicious validator faces no slashing, reputation penalties, or economic disincentives. The quota counter increments but has no enforcement effect.

3. **Amplified impact**: Each malicious batch affects ALL validators in the network, not just the attacker.

4. **Default configuration vulnerable**: Both `allow_batches_without_pos_in_proposal: true` and `enable_opt_quorum_store: true` are default settings that enable the attack path.

5. **No authentication barriers**: Any validator can perform this attack during normal network operation.

6. **Persistent effect**: Batch summaries remain in memory for 60 seconds, allowing cumulative resource exhaustion if the attack is sustained.

The only requirement is validator set membership, which is achievable through normal staking mechanisms.

## Recommendation

**Fix #1 - Enforce Persist Result in Batch Generator:**

Modify `batch_generator.rs` to respect the `persist()` return value and only broadcast successfully persisted batches:

```rust
let signed_batch_infos = self.batch_writer.persist(persist_requests);
if !signed_batch_infos.is_empty() {
    // Only broadcast batches that were successfully persisted
    let successful_batches: Vec<_> = signed_batch_infos
        .iter()
        .map(|signed_info| /* reconstruct batch from signed_info */)
        .collect();
    if self.config.enable_batch_v2 {
        network_sender.broadcast_batch_msg_v2(successful_batches).await;
    } else {
        network_sender.broadcast_batch_msg(successful_batches).await;
    }
}
```

**Fix #2 - Conditionally Send to ProofManager Based on Persist Result:**

Modify `batch_coordinator.rs` to only send batch summaries to ProofManager if persist succeeded:

```rust
let signed_batch_infos = batch_store.persist(persist_requests.clone());
if !signed_batch_infos.is_empty() {
    // Only send summaries for successfully persisted batches
    let successful_batches = signed_batch_infos
        .iter()
        .map(|signed_info| {
            let batch_info = signed_info.info();
            // Find corresponding persist_request to get summary
            let persist_request = persist_requests.iter()
                .find(|pr| pr.batch_info().digest() == batch_info.digest())
                .expect("must exist");
            (batch_info.clone(), persist_request.summary())
        })
        .collect();
    
    let _ = sender_to_proof_manager
        .send(ProofManagerCommand::ReceiveBatches(successful_batches))
        .await;
}
```

**Fix #3 - Add Quota Validation to ProofManager:**

Add quota checks in `batch_proof_queue.rs` `insert_batches()` to validate against per-author limits before insertion.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Configure a validator with low storage quota (e.g., 1MB db_quota)
2. Generate batches totaling 10MB
3. Observe EXCEEDED_STORAGE_QUOTA_COUNT incrementing
4. Observe batches still broadcast to network
5. Check ProofManager memory on remote validators - batch summaries are present despite quota violation
6. Monitor memory growth across all validators as attack continues

The core issue is evident from code inspection: the quota check executes and returns an error, but the error is ignored in two critical code paths, allowing over-quota batches to propagate network-wide.

## Notes

This is a logic vulnerability where security checks exist but are not properly enforced. The quota system provides observability (counting violations) but no actual protection (preventing propagation). This represents a fundamental breakdown in the resource limit enforcement mechanism that is supposed to protect validators from resource exhaustion attacks.

The vulnerability is distinct from network-layer DoS attacks - it exploits a protocol-level bug in quota enforcement logic rather than attacking network infrastructure. It should be classified as a protocol violation causing validator performance degradation, not a network DoS attack.

### Citations

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

**File:** consensus/src/quorum_store/batch_coordinator.rs (L78-135)
```rust
    fn persist_and_send_digests(
        &self,
        persist_requests: Vec<PersistedValue<BatchInfoExt>>,
        approx_created_ts_usecs: u64,
    ) {
        if persist_requests.is_empty() {
            return;
        }

        let batch_store = self.batch_store.clone();
        let network_sender = self.network_sender.clone();
        let sender_to_proof_manager = self.sender_to_proof_manager.clone();
        tokio::spawn(async move {
            let peer_id = persist_requests[0].author();
            let batches = persist_requests
                .iter()
                .map(|persisted_value| {
                    (
                        persisted_value.batch_info().clone(),
                        persisted_value.summary(),
                    )
                })
                .collect();

            if persist_requests[0].batch_info().is_v2() {
                let signed_batch_infos = batch_store.persist(persist_requests);
                if !signed_batch_infos.is_empty() {
                    if approx_created_ts_usecs > 0 {
                        observe_batch(approx_created_ts_usecs, peer_id, BatchStage::SIGNED);
                    }
                    network_sender
                        .send_signed_batch_info_msg_v2(signed_batch_infos, vec![peer_id])
                        .await;
                }
            } else {
                let signed_batch_infos = batch_store.persist(persist_requests);
                if !signed_batch_infos.is_empty() {
                    assert!(!signed_batch_infos
                        .first()
                        .expect("must not be empty")
                        .is_v2());
                    if approx_created_ts_usecs > 0 {
                        observe_batch(approx_created_ts_usecs, peer_id, BatchStage::SIGNED);
                    }
                    let signed_batch_infos = signed_batch_infos
                        .into_iter()
                        .map(|sbi| sbi.try_into().expect("Batch must be V1 batch"))
                        .collect();
                    network_sender
                        .send_signed_batch_info_msg(signed_batch_infos, vec![peer_id])
                        .await;
                }
            }
            let _ = sender_to_proof_manager
                .send(ProofManagerCommand::ReceiveBatches(batches))
                .await;
        });
    }
```

**File:** consensus/src/quorum_store/proof_manager.rs (L80-86)
```rust
    pub(crate) fn receive_batches(
        &mut self,
        batch_summaries: Vec<(BatchInfoExt, Vec<TxnSummaryWithExpiration>)>,
    ) {
        self.batch_proof_queue.insert_batches(batch_summaries);
        self.update_remaining_txns_and_proofs();
    }
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L258-320)
```rust
    pub fn insert_batches(
        &mut self,
        batches_with_txn_summaries: Vec<(BatchInfoExt, Vec<TxnSummaryWithExpiration>)>,
    ) {
        let start = Instant::now();

        for (batch_info, txn_summaries) in batches_with_txn_summaries.into_iter() {
            let batch_sort_key = BatchSortKey::from_info(&batch_info);
            let batch_key = BatchKey::from_info(&batch_info);

            // If the batch is either committed or the txn summary already exists, skip
            // inserting this batch.
            if self
                .items
                .get(&batch_key)
                .is_some_and(|item| item.is_committed() || item.txn_summaries.is_some())
            {
                continue;
            }

            self.author_to_batches
                .entry(batch_info.author())
                .or_default()
                .insert(batch_sort_key.clone(), batch_info.clone());
            self.expirations
                .add_item(batch_sort_key, batch_info.expiration());

            // We only count txn summaries first time it is added to the queue
            // and only if the proof already exists.
            if self
                .items
                .get(&batch_key)
                .is_some_and(|item| item.proof.is_some())
            {
                for txn_summary in &txn_summaries {
                    *self
                        .txn_summary_num_occurrences
                        .entry(*txn_summary)
                        .or_insert(0) += 1;
                }
            }

            match self.items.entry(batch_key) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().txn_summaries = Some(txn_summaries);
                },
                Entry::Vacant(entry) => {
                    entry.insert(QueueItem {
                        info: batch_info,
                        proof: None,
                        proof_insertion_time: None,
                        txn_summaries: Some(txn_summaries),
                    });
                },
            }
        }

        sample!(
            SampleRate::Duration(Duration::from_millis(500)),
            self.gc_expired_batch_summaries_without_proofs()
        );
        counters::PROOF_QUEUE_ADD_BATCH_SUMMARIES_DURATION.observe_duration(start.elapsed());
    }
```

**File:** config/src/config/quorum_store_config.rs (L140-141)
```rust
            allow_batches_without_pos_in_proposal: true,
            enable_opt_quorum_store: true,
```
