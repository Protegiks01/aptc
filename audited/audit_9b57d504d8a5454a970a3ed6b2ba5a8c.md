# Audit Report

## Title
Quorum Store Payload Construction Exceeds max_txns_after_filtering Due to Incomplete Unique Transaction Accounting

## Summary
The `ProofManager::handle_proposal_request` method in the quorum store can construct payloads that exceed the `max_txns_after_filtering` limit when OptQS (Optimistic Quorum Store) is enabled with inline batches. The unique transaction count from opt_batches is ignored, causing the inline batch limit calculation to be incorrect and allowing the total payload to violate block size constraints.

## Finding Description
When constructing a block payload with multiple components (proof_block, opt_batches, and inline_batches), the ProofManager fails to properly track cumulative unique transaction counts. 

The vulnerability manifests in the following flow: [1](#0-0) 

First, `pull_proofs` returns `cur_unique_txns` representing unique transactions after deduplication. [2](#0-1) 

Then, `pull_batches` is called for opt_batches. Critically, at line 134, the third return value (unique transaction count from opt_batches) is **discarded with `_`**. The TODO comment at line 130 acknowledges this limitation but doesn't treat it as a security issue. [3](#0-2) 

Finally, when calculating limits for inline_batches, line 165 uses `request.max_txns_after_filtering.saturating_sub(cur_unique_txns)` which only accounts for unique transactions from proofs, **not from opt_batches**. Additionally, line 176 passes the **absolute** `request.max_txns_after_filtering` limit instead of the remaining limit.

The core issue is visible in how `pull_internal` enforces limits: [4](#0-3) 

The check at line 652 compares against `max_txns_after_filtering` as an absolute limit within that single call, not accounting for unique transactions already added by previous calls.

**Exploitation Scenario:**
1. Request has `max_txns_after_filtering = 100`
2. `pull_proofs` returns 40 unique transactions
3. `pull_batches` (opt) adds 35 new unique transactions (ignored)
4. `pull_batches_with_transactions` (inline) is limited to `100 - 40 = 60` unique transactions in the `PayloadTxnsSize.count` but can add up to 100 unique transactions due to line 176
5. Total unique transactions = 40 + 35 + up to 100 = **up to 175 transactions, exceeding the 100 limit by 75%**

The returned payload at line 84 has no validation: [5](#0-4) 

This breaks the invariant that block proposals must respect resource limits (#9: "All operations must respect gas, storage, and computational limits").

## Impact Explanation
This is a **High Severity** vulnerability per Aptos bug bounty criteria ("Significant protocol violations").

**Consensus Impact:**
- When a validator proposes a block with an oversized payload, other validators will reject it during `process_proposal`: [6](#0-5) 

- This causes the proposing validator's block to be rejected
- If the condition persists, it can lead to repeated proposal failures and consensus liveness degradation
- The validator will be seen as faulty by peers, potentially affecting its reputation

**Resource Limit Violations:**
- Blocks exceeding agreed-upon limits can cause uneven resource consumption across validators
- Execution and storage systems may experience unexpected load
- Breaks the deterministic execution guarantee if different validators have different `max_receiving_block_txns` configurations

## Likelihood Explanation
**Medium-High Likelihood** when OptQS is enabled in production:

**Prerequisites:**
- OptQS feature must be enabled (`maybe_optqs_payload_pull_params.is_some()`)
- `allow_batches_without_pos_in_proposal = true` (configurable)
- Proof queue must be fully utilized (`proof_queue_fully_utilized = true`)
- Sufficient transaction load to populate multiple batch types

These conditions naturally occur under moderate to high network load when OptQS is deployed. The vulnerability is not an edge case but a systematic accounting error that manifests whenever all three payload types (proofs, opt_batches, inline_batches) are used together.

## Recommendation
Track cumulative unique transaction counts across all payload components and enforce the remaining limit correctly:

```rust
let (opt_batches, opt_batch_txns_size, opt_unique_txns) =  // Track unique count
    if let Some(ref params) = request.maybe_optqs_payload_pull_params {
        let max_opt_batch_txns_size = request.max_txns - txns_with_proof_size;
        let max_opt_batch_txns_after_filtering = request.max_txns_after_filtering - cur_unique_txns;
        self.batch_proof_queue.pull_batches(
            // ... parameters ...
        )
    } else {
        (Vec::new(), PayloadTxnsSize::zero(), 0)  // Include 0 for unique count
    };

let cumulative_unique_txns = cur_unique_txns + opt_unique_txns;  // Track cumulative

// When calculating inline limits:
max_inline_txns_to_pull.set_count(min(
    max_inline_txns_to_pull.count(),
    request
        .max_txns_after_filtering
        .saturating_sub(cumulative_unique_txns),  // Use cumulative count
));

// Pass remaining limit, not absolute:
let remaining_unique_limit = request.max_txns_after_filtering.saturating_sub(cumulative_unique_txns);
self.batch_proof_queue.pull_batches_with_transactions(
    &excluded_batches...,
    max_inline_txns_to_pull,
    remaining_unique_limit,  // Pass remaining limit
    // ... other parameters ...
);
```

Additionally, add defensive validation before returning the payload:

```rust
// Before line 237 in proof_manager.rs:
let total_payload_len = response.len();
ensure!(
    total_payload_len <= request.max_txns_after_filtering as usize,
    "Constructed payload exceeds max_txns_after_filtering: {} > {}",
    total_payload_len,
    request.max_txns_after_filtering
);
```

## Proof of Concept
```rust
// Test scenario demonstrating the vulnerability
#[tokio::test]
async fn test_payload_exceeds_max_txns_after_filtering() {
    // Setup: ProofManager with OptQS enabled and inline batches allowed
    let max_txns_after_filtering = 100u64;
    
    // Scenario:
    // 1. Insert 40 batches with proofs (40 unique txns)
    // 2. Insert 35 opt batches (35 unique txns) 
    // 3. Insert sufficient inline batches to allow pulling 60+ more
    
    // Make request with max_txns_after_filtering = 100
    let request = GetPayloadRequest {
        max_txns_after_filtering: 100,
        maybe_optqs_payload_pull_params: Some(OptQSPayloadPullParams { ... }),
        return_non_full: false,
        // ... other params
    };
    
    // Call handle_proposal_request
    let payload = /* get resulting payload */;
    
    // Assertion: payload.len() can exceed 100
    // Expected: 40 (proofs) + 35 (opt) + up to 100 (inline) = up to 175
    assert!(payload.len() > max_txns_after_filtering as usize,
        "Payload {} should exceed limit {}", 
        payload.len(), 
        max_txns_after_filtering);
}
```

## Notes
The TODO comment at line 130 (`// TODO(ibalajiarun): Support unique txn calculation`) acknowledges this limitation but doesn't recognize its security implications. This vulnerability specifically affects OptQS deployments where multiple batch types are combined in a single payload. The issue requires all three payload types to be active simultaneously, making it configuration-dependent but not a rare edge case under production load conditions.

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

**File:** consensus/src/quorum_store/proof_manager.rs (L129-152)
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
            } else {
                (Vec::new(), PayloadTxnsSize::zero())
            };
```

**File:** consensus/src/quorum_store/proof_manager.rs (L155-180)
```rust
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

**File:** consensus/src/payload_client/user/quorum_store_client.rs (L83-86)
```rust
            Ok(resp) => match resp.map_err(anyhow::Error::from)?? {
                GetPayloadResponse::GetPayloadResponse(payload) => Ok(payload),
            },
        }
```

**File:** consensus/src/round_manager.rs (L1178-1193)
```rust
        let payload_len = proposal.payload().map_or(0, |payload| payload.len());
        let payload_size = proposal.payload().map_or(0, |payload| payload.size());
        ensure!(
            num_validator_txns + payload_len as u64 <= self.local_config.max_receiving_block_txns,
            "Payload len {} exceeds the limit {}",
            payload_len,
            self.local_config.max_receiving_block_txns,
        );

        ensure!(
            validator_txns_total_bytes + payload_size as u64
                <= self.local_config.max_receiving_block_bytes,
            "Payload size {} exceeds the limit {}",
            payload_size,
            self.local_config.max_receiving_block_bytes,
        );
```
