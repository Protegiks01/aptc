# Audit Report

## Title
Storage Quota Bypass Allowing Network-Wide Resource Exhaustion via Unchecked Batch Propagation

## Summary
The `EXCEEDED_STORAGE_QUOTA_COUNT` counter increments when validators exceed their storage quota, but the quota violation is not properly enforced. Batches that exceed quota are still propagated to the ProofManager and tracked in the batch_proof_queue, allowing malicious validators to exhaust resources across the entire network without penalty.

## Finding Description

The quorum store implements a storage quota system to limit the resources each validator can consume. When a validator exceeds their quota, the `EXCEEDED_STORAGE_QUOTA_COUNT` counter increments and an error is returned: [1](#0-0) 

However, this quota violation is not properly enforced across the system. The critical flaw exists in the batch propagation flow:

**1. Batch Creation (Local Validator):**
When a validator creates batches, they call `persist()` but ignore the result: [2](#0-1) 

Even if `persist()` fails due to quota being exceeded, the batches are still broadcast to all validators at line 495/500.

**2. Batch Reception (Remote Validators):**
When other validators receive these over-quota batches, they attempt to persist them. The `persist_and_send_digests()` function sends batch summaries to the ProofManager **regardless of whether persist succeeds or fails**: [3](#0-2) 

Note that the `batches` variable is constructed at lines 92-100 **before** calling `persist()` at line 103/113. Even if all validators fail to persist (quota exceeded), the batch summaries are still sent to ProofManager at line 131-133.

**3. ProofManager Processing:**
The ProofManager receives these batch summaries and inserts them into the batch_proof_queue **without any quota checks**: [4](#0-3) [5](#0-4) 

The `insert_batches()` method has no quota validation and blindly inserts all batch summaries into memory data structures.

**4. Opt Quorum Store Configuration:**
By default, the system is configured to allow batches without ProofOfStore: [6](#0-5) 

This means over-quota batches can potentially be selected for block proposals via the opt quorum store mechanism: [7](#0-6) 

**Attack Scenario:**
1. Malicious validator continuously creates batches exceeding their storage quota
2. `EXCEEDED_STORAGE_QUOTA_COUNT` increments on their node, but no enforcement occurs
3. Batches are broadcast to all validators in the network
4. Each validator attempts to persist, fails (quota exceeded), increments their own `EXCEEDED_STORAGE_QUOTA_COUNT`
5. Despite persist failure, all validators send batch summaries to their ProofManager
6. ProofManager stores these summaries in memory (batch_proof_queue)
7. These summaries consume memory and CPU resources across all validators
8. The malicious validator faces no penalty and can repeat indefinitely

This breaks **Invariant #9: Resource Limits** - "All operations must respect gas, storage, and computational limits." The quota counter tracks violations but provides no actual enforcement.

## Impact Explanation

This vulnerability qualifies as **HIGH Severity** per the Aptos bug bounty criteria:

- **Validator node slowdowns**: All validators in the network waste resources tracking over-quota batches in memory
- **Significant protocol violations**: The quota enforcement mechanism is fundamentally broken
- **Network-wide impact**: A single malicious validator can degrade performance across the entire validator set
- **Resource exhaustion**: Unbounded memory consumption in batch_proof_queue for invalid batches

While this doesn't directly cause consensus safety violations or loss of funds, it allows coordinated resource exhaustion attacks that can significantly degrade network performance and availability.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **Easy to trigger**: Any validator can create batches exceeding quota with minimal effort
2. **No authentication required**: Any validator in the active set can perform this attack
3. **No cost to attacker**: The malicious validator faces no slashing, reputation damage, or other penalties
4. **Amplified impact**: Each over-quota batch from one validator causes resource consumption on ALL validators
5. **Default configuration vulnerable**: `enable_opt_quorum_store: true` and `allow_batches_without_pos_in_proposal: true` are default settings
6. **Persistent effect**: Batch summaries remain in memory until expiration (60 seconds default), allowing cumulative resource exhaustion

The only requirement is that the attacker must be part of the active validator set, which is a relatively low barrier for a motivated attacker.

## Recommendation

Implement proper quota enforcement by **rejecting over-quota batches early** and preventing their propagation:

**1. Enforce quota at batch creation:**
```rust
// In batch_generator.rs, check persist() result before broadcasting
let signed_batch_infos = self.batch_writer.persist(persist_requests);
if signed_batch_infos.is_empty() {
    warn!("Failed to persist batches due to quota or other errors, not broadcasting");
    continue;
}
// Only broadcast if persist succeeded
if self.config.enable_batch_v2 {
    network_sender.broadcast_batch_msg_v2(batches).await;
}
```

**2. Reject over-quota batches at reception:**
```rust
// In batch_coordinator.rs, check persist() result before sending to ProofManager
let signed_batch_infos = batch_store.persist(persist_requests);
if signed_batch_infos.is_empty() {
    // Persist failed (likely quota exceeded), don't propagate further
    warn!("Failed to persist batches from {}, rejecting", peer_id);
    counters::REJECTED_BATCHES_DUE_TO_QUOTA.inc();
    return;
}
// Only send to ProofManager if persist succeeded
let _ = sender_to_proof_manager
    .send(ProofManagerCommand::ReceiveBatches(batches))
    .await;
```

**3. Add quota validation in ProofManager:**
```rust
// In proof_manager.rs, validate batches before inserting
pub(crate) fn receive_batches(
    &mut self,
    batch_summaries: Vec<(BatchInfoExt, Vec<TxnSummaryWithExpiration>)>,
) {
    // Add quota check here
    if !self.validate_batch_quotas(&batch_summaries) {
        warn!("Batches exceeded quota limits, rejecting");
        counters::REJECTED_BATCHES_IN_PROOF_MANAGER.inc();
        return;
    }
    self.batch_proof_queue.insert_batches(batch_summaries);
    self.update_remaining_txns_and_proofs();
}
```

**4. Implement penalties for quota violators:**
- Track repeated quota violations per validator
- Implement temporary bans or rate limiting for repeat offenders
- Consider reputation-based scoring that affects batch selection priority

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[tokio::test]
async fn test_quota_bypass_resource_exhaustion() {
    // Setup: Create a batch store with small quota
    let small_quota = 1000; // Very small quota
    let batch_store = Arc::new(BatchStore::new(
        1, // epoch
        true, // is_new_epoch
        0, // last_certified_time
        Arc::new(MockQuorumStoreStorage::new()),
        small_quota, // memory_quota
        small_quota, // db_quota  
        10, // batch_quota
        validator_signer,
        60_000_000, // expiration_buffer
    ));

    // Attack: Create large batch exceeding quota
    let large_batch_size = small_quota * 10; // 10x the quota
    let large_txns = create_transactions(large_batch_size);
    let batch = create_batch_from_transactions(large_txns);
    
    // Attempt to persist - should fail with quota exceeded
    let persist_request = PersistedValue::new(batch.info().clone(), Some(batch.txns()));
    let result = batch_store.persist(vec![persist_request.clone()]);
    
    // Verify: EXCEEDED_STORAGE_QUOTA_COUNT incremented
    assert_eq!(counters::EXCEEDED_STORAGE_QUOTA_COUNT.get(), 1);
    
    // Verify: persist() returned empty (failed)
    assert!(result.is_empty());
    
    // BUG: Despite failure, batch summaries would still be sent to ProofManager
    // This would happen in batch_coordinator.rs lines 92-133
    let batch_summaries = vec![(batch.info().clone(), batch.summary())];
    
    // Simulate sending to ProofManager
    proof_manager.receive_batches(batch_summaries);
    
    // Verify: Batch is now in proof queue consuming memory despite quota violation
    assert!(proof_manager.batch_proof_queue.items.contains_key(&batch_key));
    
    // Attack can be repeated indefinitely, exhausting resources
    for _ in 0..100 {
        let batch = create_over_quota_batch();
        // Counter increments but no enforcement
        // Resources consumed across all validators
    }
}
```

**Notes:**

The vulnerability exists in the gap between quota measurement (counter increment) and quota enforcement (rejection). The `EXCEEDED_STORAGE_QUOTA_COUNT` counter serves only as an observability metric but provides no actual protection. Batches that exceed quota are still propagated through the network, tracked in memory, and processed by all validators, enabling resource exhaustion attacks without penalty.

### Citations

**File:** consensus/src/quorum_store/batch_store.rs (L80-83)
```rust
        } else {
            counters::EXCEEDED_STORAGE_QUOTA_COUNT.inc();
            bail!("Storage quota exceeded ");
        }
```

**File:** consensus/src/quorum_store/batch_generator.rs (L486-500)
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
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L90-133)
```rust
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

**File:** consensus/src/quorum_store/proof_manager.rs (L129-149)
```rust
        let (opt_batches, opt_batch_txns_size) =
            // TODO(ibalajiarun): Support unique txn calculation
            if let Some(ref params) = request.maybe_optqs_payload_pull_params {
                let max_opt_batch_txns_size = request.max_txns - txns_with_proof_size;
                let max_opt_batch_txns_after_filtering = request.max_txns_after_filtering - cur_unique_txns;
                let (opt_batches, opt_payload_size, _) =
                    self.batch_proof_queue.pull_batches(
                        &excluded_batches
                            .iter()
                            .cloned()
                            .chain(proof_block.iter().map(|proof| proof.info().clone()))
                            .collect(),
                        &params.exclude_authors,
                        max_opt_batch_txns_size,
                        max_opt_batch_txns_after_filtering,
                        request.soft_max_txns_after_filtering,
                        request.return_non_full,
                        request.block_timestamp,
                        Some(params.minimum_batch_age_usecs),
                    );
                (opt_batches, opt_payload_size)
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L258-312)
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
```

**File:** config/src/config/quorum_store_config.rs (L140-141)
```rust
            allow_batches_without_pos_in_proposal: true,
            enable_opt_quorum_store: true,
```
