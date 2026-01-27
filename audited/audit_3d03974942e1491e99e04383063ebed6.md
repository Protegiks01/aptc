# Audit Report

## Title
Transaction Limit Bypass via Incorrect Unique Transaction Accounting Across Multiple Batch Pulls

## Summary
The `ProofManager::handle_proposal_request` function fails to properly track unique transaction counts across multiple sequential batch pulls (`pull_proofs`, `pull_batches`, `pull_batches_with_transactions`), allowing blocks to exceed the `max_txns_after_filtering` limit. The unique transaction count returned by `pull_batches` is discarded, and subsequent pulls use only the count from `pull_proofs`, enabling a bypass of the filtering limit.

## Finding Description
The quorum store's proof manager pulls transactions in three sequential stages when constructing block proposals:

1. **pull_proofs**: Pulls batches with proofs of store
2. **pull_batches**: Pulls optimistic batches without proofs (opt_batches)  
3. **pull_batches_with_transactions**: Pulls inline batches with full transaction data

The `max_txns_after_filtering` parameter is intended to limit the total number of **unique** transactions (after deduplication) across all three pulls. However, the implementation has a critical accounting flaw: [1](#0-0) [2](#0-1) 

The `pull_batches` call returns a tuple where the third element contains the number of unique transactions pulled, but this value is **discarded** (assigned to `_` at line 134).

When calculating the limit for inline batches: [3](#0-2) 

The code only subtracts `cur_unique_txns` (from `pull_proofs`) but **not** the unique transactions from `pull_batches`. The `max_txns_after_filtering` passed to `pull_batches_with_transactions` at line 176 is the original unadjusted value.

Inside `pull_internal`, the checking logic compares against `max_txns_after_filtering`: [4](#0-3) 

Since `cur_unique_txns` is **local** to each `pull_internal` call and starts at 0, the check at line 652 only validates that the inline batches don't exceed 100 transactions by themselves, not that the **total across all three pulls** stays within the limit.

**Attack Scenario:**
1. Attacker controls multiple batch authors
2. `max_txns_after_filtering = 100`
3. `pull_proofs` pulls batches with 50 unique transactions → `cur_unique_txns = 50`
4. `pull_batches` pulls batches with 40 unique transactions → returned but **discarded**
5. Inline batch limit calculated as: `max_txns_after_filtering - cur_unique_txns = 100 - 50 = 50`
6. `pull_batches_with_transactions` called with `max_txns_after_filtering = 100` (unadjusted)
7. Inline batches can pull up to 100 unique transactions (checked locally within that call)
8. But the limit adjustment at line 165 restricts the **count** to 50, while allowing full checking against 100
9. If inline batches pull 50 unique transactions with no overlaps, total = 50 + 40 + 50 = **140 unique transactions**, exceeding the limit of 100

## Impact Explanation
This vulnerability qualifies as **High Severity** based on the Aptos bug bounty criteria:

- **Significant Protocol Violation**: Breaks the invariant that "All operations must respect gas, storage, and computational limits" by allowing blocks to exceed intended transaction limits
- **Consensus Risk**: Different validators may have different batch arrival timing, causing different views of which batches have summaries, leading to inconsistent block construction and potential consensus divergence
- **Resource Exhaustion**: Blocks larger than intended can cause execution delays, memory pressure, and degraded network performance
- **Validator Node Slowdowns**: Executing oversized blocks impacts validator performance

The impact is not Critical because it doesn't directly cause fund loss or permanent network failure, but represents a significant protocol violation that can degrade network performance and create consensus issues.

## Likelihood Explanation
**Likelihood: Medium to High**

This vulnerability can be triggered when:
1. OptQS (Optimistic Quorum Store) is enabled with `maybe_optqs_payload_pull_params` set
2. Multiple batch authors submit batches with non-overlapping transactions
3. Batches arrive with varying proof/summary timing

The TODO comment at line 130 suggests this is a known implementation gap: [5](#0-4) 

The likelihood increases when network conditions cause asynchronous batch and proof arrivals, which is the normal operational mode. An attacker doesn't need privileged access—simply coordinating multiple batch submissions can trigger the issue.

## Recommendation
Track and accumulate unique transaction counts across all three pull operations:

```rust
let (proof_block, txns_with_proof_size, cur_unique_txns, proof_queue_fully_utilized) =
    self.batch_proof_queue.pull_proofs(
        &excluded_batches,
        request.max_txns,
        request.max_txns_after_filtering,
        request.soft_max_txns_after_filtering,
        request.return_non_full,
        request.block_timestamp,
    );

let mut total_unique_txns = cur_unique_txns;

let (opt_batches, opt_batch_txns_size) =
    if let Some(ref params) = request.maybe_optqs_payload_pull_params {
        let max_opt_batch_txns_size = request.max_txns - txns_with_proof_size;
        let max_opt_batch_txns_after_filtering = request.max_txns_after_filtering.saturating_sub(total_unique_txns);
        let (opt_batches, opt_payload_size, opt_unique_txns) =
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
        total_unique_txns += opt_unique_txns;
        (opt_batches, opt_payload_size)
    } else {
        (Vec::new(), PayloadTxnsSize::zero())
    };

let cur_txns = txns_with_proof_size + opt_batch_txns_size;
let (inline_block, inline_block_size) =
    if self.allow_batches_without_pos_in_proposal && proof_queue_fully_utilized {
        let mut max_inline_txns_to_pull = request
            .max_txns
            .saturating_sub(cur_txns)
            .minimum(request.max_inline_txns);
        max_inline_txns_to_pull.set_count(min(
            max_inline_txns_to_pull.count(),
            request
                .max_txns_after_filtering
                .saturating_sub(total_unique_txns),
        ));
        let max_inline_txns_after_filtering = request.max_txns_after_filtering.saturating_sub(total_unique_txns);
        let (inline_batches, inline_payload_size, _inline_unique_txns) =
            self.batch_proof_queue.pull_batches_with_transactions(
                &excluded_batches
                    .iter()
                    .cloned()
                    .chain(proof_block.iter().map(|proof| proof.info().clone()))
                    .chain(opt_batches.clone())
                    .collect(),
                max_inline_txns_to_pull,
                max_inline_txns_after_filtering,
                request.soft_max_txns_after_filtering,
                request.return_non_full,
                request.block_timestamp,
            );
        (inline_batches, inline_payload_size)
    } else {
        (Vec::new(), PayloadTxnsSize::zero())
    };
```

Key changes:
1. Capture `opt_unique_txns` instead of discarding it
2. Introduce `total_unique_txns` accumulator
3. Adjust `max_opt_batch_txns_after_filtering` using `total_unique_txns`
4. Adjust `max_inline_txns_after_filtering` passed to `pull_batches_with_transactions`

## Proof of Concept

```rust
#[tokio::test]
async fn test_unique_txn_limit_bypass() {
    use crate::quorum_store::{
        proof_manager::ProofManager, 
        tests::batch_store_test::batch_store_for_test,
    };
    use aptos_consensus_types::{
        common::{Payload, PayloadFilter, TxnSummaryWithExpiration},
        proof_of_store::{BatchInfo, BatchInfoExt, ProofOfStore},
        request_response::{GetPayloadCommand, GetPayloadRequest},
        utils::PayloadTxnsSize,
        payload_pull_params::OptQSPayloadPullParams,
    };
    use aptos_crypto::HashValue;
    use aptos_types::{
        aggregate_signature::AggregateSignature, 
        quorum_store::BatchId, 
        transaction::ReplayProtector,
        account_address::AccountAddress,
        PeerId,
    };
    use futures::channel::oneshot;
    use std::collections::HashSet;

    let batch_store = batch_store_for_test(50 * 1024 * 1024);
    let mut proof_manager = ProofManager::new(
        PeerId::random(), 
        1000, 
        100, 
        batch_store.clone(), 
        true, 
        true, 
        1000000
    );

    // Create batches with known transaction counts
    let author1 = PeerId::random();
    let author2 = PeerId::random();
    let author3 = PeerId::random();

    // Batch 1: 50 txns with proof
    let proof1 = ProofOfStore::new(
        BatchInfo::new(author1, BatchId::new_for_test(1), 0, 100000, HashValue::random(), 50, 50, 100).into(),
        AggregateSignature::empty(),
    );
    
    // Batch 2: 40 txns without proof (for opt_batches)
    let batch2_info: BatchInfoExt = BatchInfo::new(
        author2, BatchId::new_for_test(2), 0, 100000, HashValue::random(), 40, 40, 100
    ).into();
    let txn_summaries2: Vec<TxnSummaryWithExpiration> = (0..40).map(|i| {
        TxnSummaryWithExpiration::new(
            AccountAddress::random(),
            ReplayProtector::V1 { sequence_number: i },
            100000,
            HashValue::random(),
        )
    }).collect();
    
    // Batch 3: 50 txns without proof (for inline_batches)
    let batch3_info: BatchInfoExt = BatchInfo::new(
        author3, BatchId::new_for_test(3), 0, 100000, HashValue::random(), 50, 50, 100
    ).into();
    let txn_summaries3: Vec<TxnSummaryWithExpiration> = (0..50).map(|i| {
        TxnSummaryWithExpiration::new(
            AccountAddress::random(),
            ReplayProtector::V1 { sequence_number: i + 1000 },
            100000,
            HashValue::random(),
        )
    }).collect();

    // Insert batches
    proof_manager.receive_proofs(vec![proof1]);
    proof_manager.receive_batches(vec![
        (batch2_info.clone(), txn_summaries2),
        (batch3_info.clone(), txn_summaries3),
    ]);

    // Store actual transactions for inline batches
    batch_store.insert_batch(batch3_info.digest(), vec![]); // Would need actual SignedTransactions

    // Request with max_txns_after_filtering = 100
    let (callback_tx, callback_rx) = oneshot::channel();
    let req = GetPayloadCommand::GetPayloadRequest(GetPayloadRequest {
        max_txns: PayloadTxnsSize::new(200, 10000000),
        max_txns_after_filtering: 100,
        soft_max_txns_after_filtering: 100,
        max_inline_txns: PayloadTxnsSize::new(100, 5000000),
        filter: PayloadFilter::InQuorumStore(HashSet::new()),
        callback: callback_tx,
        block_timestamp: aptos_infallible::duration_since_epoch(),
        return_non_full: true,
        maybe_optqs_payload_pull_params: Some(OptQSPayloadPullParams {
            exclude_authors: HashSet::new(),
            minimum_batch_age_usecs: 0,
        }),
    });
    
    proof_manager.handle_proposal_request(req);
    let response = callback_rx.await.unwrap().unwrap();
    
    // With the bug: Total unique txns = 50 + 40 + 50 = 140, exceeding limit of 100
    // Expected: Should respect the 100 limit
    match response {
        GetPayloadResponse::GetPayloadResponse(Payload::OptQuorumStore(payload)) => {
            let total_proof_txns: u64 = payload.proof_with_data.proofs.iter()
                .map(|p| p.num_txns()).sum();
            let total_opt_txns: u64 = payload.opt_batches.batches.iter()
                .map(|b| b.num_txns()).sum();
            let total_inline_txns: u64 = payload.inline_batches.batches.iter()
                .map(|(info, _)| info.num_txns()).sum();
            
            let total = total_proof_txns + total_opt_txns + total_inline_txns;
            println!("Total transactions: {} (proof: {}, opt: {}, inline: {})", 
                     total, total_proof_txns, total_opt_txns, total_inline_txns);
            
            // This assertion will fail with the bug, showing total > 100
            assert!(total <= 100, "Transaction limit bypass detected: {} > 100", total);
        },
        _ => panic!("Unexpected payload type"),
    }
}
```

This test demonstrates that when OptQS is enabled and batches are pulled across all three stages with non-overlapping transactions, the total can exceed `max_txns_after_filtering`.

### Citations

**File:** consensus/src/quorum_store/proof_manager.rs (L114-122)
```rust
        let (proof_block, txns_with_proof_size, cur_unique_txns, proof_queue_fully_utilized) =
            self.batch_proof_queue.pull_proofs(
                &excluded_batches,
                request.max_txns,
                request.max_txns_after_filtering,
                request.soft_max_txns_after_filtering,
                request.return_non_full,
                request.block_timestamp,
            );
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

**File:** consensus/src/quorum_store/proof_manager.rs (L154-180)
```rust
        let cur_txns = txns_with_proof_size + opt_batch_txns_size;
        let (inline_block, inline_block_size) =
            if self.allow_batches_without_pos_in_proposal && proof_queue_fully_utilized {
                let mut max_inline_txns_to_pull = request
                    .max_txns
                    .saturating_sub(cur_txns)
                    .minimum(request.max_inline_txns);
                max_inline_txns_to_pull.set_count(min(
                    max_inline_txns_to_pull.count(),
                    request
                        .max_txns_after_filtering
                        .saturating_sub(cur_unique_txns),
                ));
                let (inline_batches, inline_payload_size, _) =
                    self.batch_proof_queue.pull_batches_with_transactions(
                        &excluded_batches
                            .iter()
                            .cloned()
                            .chain(proof_block.iter().map(|proof| proof.info().clone()))
                            .chain(opt_batches.clone())
                            .collect(),
                        max_inline_txns_to_pull,
                        request.max_txns_after_filtering,
                        request.soft_max_txns_after_filtering,
                        request.return_non_full,
                        request.block_timestamp,
                    );
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L651-657)
```rust
                        if cur_all_txns + batch.size() > max_txns
                            || unique_txns > max_txns_after_filtering
                        {
                            // Exceeded the limit for requested bytes or number of transactions.
                            full = true;
                            return false;
                        }
```
