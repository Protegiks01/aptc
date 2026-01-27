# Audit Report

## Title
Local Batch Transaction Summary Bypass Allows Duplicate Detection Evasion in Block Proposals

## Summary
A vulnerability exists where validators can bypass duplicate transaction detection when proposing blocks. When validators create their own batches, transaction summaries are never inserted into the local ProofManager, causing `txn_summaries` to remain `None`. During block proposal via `pull_internal()`, this leads to using `batch.num_txns()` as an estimate without checking for duplicates, allowing the same transactions to be counted multiple times across different batches.

## Finding Description

The vulnerability stems from an asymmetry in how transaction summaries are handled for local versus remote batches:

**For Remote Batches:**
When a validator receives a batch from the network, the `BatchCoordinator` processes it and sends transaction summaries to the `ProofManager` via the `ReceiveBatches` command. [1](#0-0) 

**For Local Batches:**
When a validator creates its own batch, the `BatchGenerator` only persists the batch via `batch_writer.persist()` without sending summaries to the `ProofManager`. [2](#0-1) 

This creates a situation where the local validator's `ProofManager` has proofs for their own batches but without corresponding transaction summaries (`txn_summaries: None`).

**Exploitation in pull_internal():**
When the validator later becomes a block proposer and pulls proofs via `pull_internal()`, batches without summaries bypass duplicate detection: [3](#0-2) 

When `txn_summaries` is `None`, the code falls back to `batch.num_txns()` without checking the `filtered_txns` set for duplicates.

**Critical Missing Update:**
More importantly, when `txn_summaries` is `None`, the transactions are never added to the `filtered_txns` set: [4](#0-3) 

The `map_or` returns `batch.num_txns()` and never calls `filtered_txns.insert()`, leaving duplicates undetected.

**Attack Scenario:**
1. Malicious Validator A creates multiple batches containing identical transactions
2. Each batch is broadcast to the network and certified by a quorum, producing valid ProofOfStore objects
3. Validator A becomes the block proposer
4. When pulling proofs from their local `ProofManager`, their own batches have `txn_summaries: None`
5. Duplicate detection is bypassed, allowing multiple batches with the same transactions to be included
6. The `unique_txns` counter is artificially inflated by summing `batch.num_txns()` across duplicate batches
7. Block space is consumed by duplicate transactions, crowding out legitimate unique transactions

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program for the following reasons:

**Protocol Violation:** The duplicate detection mechanism is fundamentally bypassed for validator-created batches, violating the resource limits invariant that requires fair transaction inclusion.

**Block Space Manipulation:** A malicious validator can fill blocks with duplicate transactions, wasting bandwidth, storage, and computational resources across all nodes in the network.

**Transaction Quota Gaming:** By inflating the `unique_txns` counter without providing unique transactions, the attacker can reach `max_txns_after_filtering` limits with duplicates, preventing legitimate unique transactions from being included.

**Validator Node Resource Consumption:** While this doesn't cause permanent network unavailability, it creates significant slowdowns by forcing nodes to process and validate duplicate transactions repeatedly, aligning with "Validator node slowdowns" under High Severity criteria.

## Likelihood Explanation

**High Likelihood** - The vulnerability will occur whenever:
1. A validator creates their own batches (normal operation)
2. That validator later becomes the block proposer (occurs regularly in rotation)
3. The validator's own batches are pulled for block inclusion

The attack requires no special conditions or timing - it's a systematic gap in the implementation that affects all validators when proposing blocks containing their own batches. A malicious validator can deliberately exploit this by:
- Creating multiple batches with overlapping transactions
- Timing batch creation to ensure their proofs are available when they become proposer
- Repeatedly exploiting the vulnerability across multiple proposal rounds

## Recommendation

**Fix:** Ensure local batches also send transaction summaries to the `ProofManager`. Modify `BatchGenerator::start()` to extract and send summaries after persisting local batches:

```rust
// In batch_generator.rs, after line 492
if !batches.is_empty() {
    let batches_with_summaries: Vec<(BatchInfoExt, Vec<TxnSummaryWithExpiration>)> = 
        persist_requests
            .iter()
            .map(|req| (req.batch_info().clone(), req.summary()))
            .collect();
    
    let _ = sender_to_proof_manager
        .send(ProofManagerCommand::ReceiveBatches(batches_with_summaries))
        .await;
}
```

This requires adding a `sender_to_proof_manager` channel to `BatchGenerator` similar to how `BatchCoordinator` has one.

**Alternative Fix:** Modify `pull_internal()` to treat missing summaries as an error condition rather than falling back to `batch.num_txns()`, forcing summaries to always be present before pulling batches.

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[tokio::test]
async fn test_local_batch_missing_summaries_bypass() {
    // Setup: Create a BatchProofQueue and insert a proof without summaries
    let my_peer_id = PeerId::random();
    let batch_store = Arc::new(/* initialize batch store */);
    let mut queue = BatchProofQueue::new(my_peer_id, batch_store, 100000);
    
    // Simulate a proof for a local batch (no summaries sent)
    let batch_info = create_batch_info_with_3_transactions();
    let proof = create_proof_of_store(batch_info.clone());
    queue.insert_proof(proof);
    
    // Verify: No summaries were inserted
    assert_eq!(queue.batch_summaries_len(), 0);
    
    // Attack: Pull the proof for block proposal
    let excluded = HashSet::new();
    let max_txns = PayloadTxnsSize::new(1000, 10000);
    let (proofs, _, unique_txns, _) = queue.pull_proofs(
        &excluded,
        max_txns,
        1000,
        1000,
        true,
        Duration::from_secs(100),
    );
    
    // Vulnerability: unique_txns counts all 3 transactions as unique
    // even though summaries are missing and duplicates cannot be detected
    assert_eq!(unique_txns, 3);
    assert_eq!(proofs.len(), 1);
    
    // Now insert a second proof with the SAME transactions
    let batch_info_2 = create_batch_info_with_same_3_transactions();
    let proof_2 = create_proof_of_store(batch_info_2);
    queue.insert_proof(proof_2);
    
    // Pull again
    let (proofs, _, unique_txns, _) = queue.pull_proofs(
        &excluded,
        max_txns,
        1000,
        1000,
        true,
        Duration::from_secs(100),
    );
    
    // BUG: unique_txns should be 3 (same transactions), but it's 6!
    assert_eq!(unique_txns, 6); // Duplicate detection bypassed
    assert_eq!(proofs.len(), 2);
}
```

## Notes

This vulnerability is particularly insidious because:

1. **It's systematic, not a race condition**: Local batches never receive summary insertion by design
2. **It affects all validators**: Every validator experiences this when proposing blocks with their own batches
3. **It's difficult to detect**: The duplicate transactions will eventually be rejected during execution, but block space is already wasted
4. **It enables griefing attacks**: A malicious validator can deliberately create duplicate batches to waste network resources

The root cause is the architectural asymmetry between how `BatchCoordinator` (for remote batches) and `BatchGenerator` (for local batches) interact with `ProofManager`. Only the former sends the `ReceiveBatches` command needed for duplicate detection.

### Citations

**File:** consensus/src/quorum_store/batch_coordinator.rs (L131-133)
```rust
            let _ = sender_to_proof_manager
                .send(ProofManagerCommand::ReceiveBatches(batches))
                .await;
```

**File:** consensus/src/quorum_store/batch_generator.rs (L486-492)
```rust
                            let persist_start = Instant::now();
                            let mut persist_requests = vec![];
                            for batch in batches.clone().into_iter() {
                                persist_requests.push(batch.into());
                            }
                            self.batch_writer.persist(persist_requests);
                            counters::BATCH_CREATION_PERSIST_LATENCY.observe_duration(persist_start.elapsed());
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L638-650)
```rust
                        let unique_txns = if let Some(ref txn_summaries) = item.txn_summaries {
                            cur_unique_txns
                                + txn_summaries
                                    .iter()
                                    .filter(|txn_summary| {
                                        !filtered_txns.contains(txn_summary)
                                            && block_timestamp.as_secs()
                                                < txn_summary.expiration_timestamp_secs
                                    })
                                    .count() as u64
                        } else {
                            cur_unique_txns + batch.num_txns()
                        };
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L661-673)
```rust
                        cur_unique_txns +=
                            item.txn_summaries
                                .as_ref()
                                .map_or(batch.num_txns(), |summaries| {
                                    summaries
                                        .iter()
                                        .filter(|summary| {
                                            filtered_txns.insert(**summary)
                                                && block_timestamp.as_secs()
                                                    < summary.expiration_timestamp_secs
                                        })
                                        .count() as u64
                                });
```
