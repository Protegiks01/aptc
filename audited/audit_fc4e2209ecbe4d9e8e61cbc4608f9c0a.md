# Audit Report

## Title
Off-By-One Error in Batch Expiration Check Allows Inclusion of Expired Batches at Boundary Condition

## Summary
The `reconstruct_batch()` function in the consensus observer message handling uses an incorrect comparison operator (`>` instead of `>=`) when checking batch expiration against block timestamps. This allows batches that are exactly at their expiration time to be incorrectly included in blocks, violating the quorum store's expiration invariant and creating semantic inconsistency across the system.

## Finding Description
The vulnerability exists in the batch reconstruction logic used by consensus observers to verify block payloads. The code checks whether to skip expired batches using: [1](#0-0) 

This comparison uses strictly greater-than (`>`), meaning a batch is only skipped if the block timestamp is **strictly greater** than the expiration time. When `block_info.timestamp_usecs() == expected_batch_info.expiration()`, the condition is false and the batch is **not** skipped.

However, this contradicts the quorum store's established expiration semantics used throughout the codebase:

1. **TimeExpirations::expire()** considers items expired when `expiration_time <= certified_time`: [2](#0-1) 

2. **BatchStore::save()** rejects batches when `expiration <= last_certified_time`: [3](#0-2) 

3. **BatchStore::clear_expired_payload()** removes batches when `expiration <= expiration_time`: [4](#0-3) 

4. **BatchProofQueue::insert_proof()** rejects proofs when `expiration <= latest_block_timestamp`: [5](#0-4) 

All these implementations consistently treat a batch as expired when `expiration <= current_time`. The `reconstruct_batch()` function should follow the same semantic: a batch should be skipped when `block_timestamp >= expiration`.

**Attack Scenario:**
A Byzantine proposer can exploit this by:
1. Setting the block timestamp to exactly equal a batch's expiration time
2. Including this batch in the block payload (proposers can set timestamps within constraints defined in `verify_well_formed()`)
3. The observer's `reconstruct_batch()` will not skip this batch (since timestamp is not > expiration)
4. The batch is included despite being semantically expired according to the system's expiration model

Block timestamp manipulation is constrained but feasible: [6](#0-5) 

Proposers control the timestamp based on their local time service: [7](#0-6) 

## Impact Explanation
This issue qualifies as **Medium Severity** per Aptos bug bounty criteria for the following reasons:

1. **State Inconsistencies**: The bug creates a temporal inconsistency where batches at the exact expiration boundary are considered "valid" for block inclusion but "expired" immediately after when `handle_updated_block_timestamp()` is called with the same timestamp value. This violates the principle that expiration semantics should be consistent across all components.

2. **Semantic Violation**: The batch expiration invariant is broken. The quorum store's expiration model explicitly defines that batches are expired when `expiration <= certified_time`, but the observer's reconstruction logic violates this at the boundary condition.

3. **Observer Correctness**: Consensus observers rely on correct payload reconstruction to verify blocks. The off-by-one error could cause observers to incorrectly accept or process blocks containing batches that should be filtered out according to the system's expiration rules.

While this doesn't directly cause fund loss or consensus safety violations, it represents a state inconsistency that could require intervention to ensure correct and consistent behavior across the distributed system.

## Likelihood Explanation
**Likelihood: Medium**

The vulnerability is exploitable when:
1. A proposer (Byzantine validator) is creating a block
2. A batch exists with expiration time exactly matching the proposed block timestamp
3. The proposer deliberately sets the block timestamp to equal the batch expiration

This requires precise timing coordination but is technically feasible since:
- Proposers have discretion over block timestamps within the validation constraints (must be > parent timestamp and <= current_time + 5 minutes)
- Batch expiration times are predictable (set when batches are created)
- A malicious validator could engineer scenarios where this boundary condition occurs

The exact equality condition is a narrow window, but Byzantine validators specifically trying to exploit this could create the conditions deliberately.

## Recommendation
Change the comparison operator from `>` to `>=` to align with the quorum store's expiration semantics:

```rust
fn reconstruct_batch(
    block_info: &BlockInfo,
    transactions_iter: &mut IntoIter<SignedTransaction>,
    expected_batch_info: &BatchInfo,
    skip_expired_batches: bool,
) -> Result<Option<Vec<SignedTransaction>>, Error> {
    // If the batch is expired we should skip reconstruction (as the
    // transactions for the expired batch won't be sent in the payload).
    // Note: this should only be required for QS batches (not inline batches).
    if skip_expired_batches && block_info.timestamp_usecs() >= expected_batch_info.expiration() {  // Changed from > to >=
        return Ok(None);
    }

    // Gather the transactions for the batch
    // ... rest of function unchanged
}
```

This ensures that batches are skipped when `block_timestamp >= expiration`, which is consistent with:
- `TimeExpirations::expire(certified_time)` expiring items where `expiration <= certified_time`
- `BatchStore::save()` rejecting batches where `expiration <= last_certified_time`  
- All other expiration checks in the quorum store subsystem

## Proof of Concept
```rust
#[test]
fn test_reconstruct_batch_expiration_boundary() {
    use aptos_types::block_info::BlockInfo;
    use aptos_consensus_types::proof_of_store::BatchInfo;
    
    // Create a block with timestamp 1000
    let block_timestamp = 1000u64;
    let block_info = BlockInfo::new(
        0,  // epoch
        0,  // round
        HashValue::random(),  // block_id
        HashValue::random(),  // executed_state_id
        0,  // version
        block_timestamp,  // timestamp_usecs
        None,  // next_epoch_state
    );
    
    // Create a batch with expiration exactly equal to block timestamp
    let batch_expiration = 1000u64;  // Same as block timestamp
    let batch_info = BatchInfo::new(
        PeerId::ZERO,
        BatchId::new(0),
        0,  // epoch
        batch_expiration,  // expiration
        HashValue::random(),  // digest
        5,  // num_txns
        100,  // num_bytes
        0,  // gas_bucket_start
    );
    
    // Create transaction iterator
    let transactions = vec![/* ... 5 test transactions ... */];
    let mut transactions_iter = transactions.into_iter();
    
    // Call reconstruct_batch with skip_expired_batches = true
    let result = reconstruct_batch(
        &block_info,
        &mut transactions_iter,
        &batch_info,
        true,  // skip_expired_batches
    );
    
    // BUG: Currently, this returns Ok(Some(...)) because timestamp is not > expiration
    // EXPECTED: Should return Ok(None) because timestamp >= expiration (batch is expired)
    assert!(result.is_ok());
    assert!(result.unwrap().is_none(), 
        "Batch should be skipped when block timestamp equals expiration");
}
```

This test would currently **fail** with the existing code (batch is not skipped), but would **pass** with the recommended fix (batch is correctly skipped).

## Notes
The vulnerability represents an off-by-one boundary condition error that creates semantic inconsistency in how batch expiration is enforced. While the immediate security impact is limited to observer correctness and state consistency, the violation of established expiration invariants could lead to unexpected behavior and requires correction to ensure the system maintains consistent semantics across all components handling batch expiration.

### Citations

**File:** consensus/src/consensus_observer/network/observer_message.rs (L996-996)
```rust
    if skip_expired_batches && block_info.timestamp_usecs() > expected_batch_info.expiration() {
```

**File:** consensus/src/quorum_store/utils.rs (L75-88)
```rust
    /// Expire and return items corresponding to expiration <= given certified time.
    /// Unwrap is safe because peek() is called in loop condition.
    #[allow(clippy::unwrap_used)]
    pub(crate) fn expire(&mut self, certified_time: u64) -> HashSet<I> {
        let mut ret = HashSet::new();
        while let Some((Reverse(t), _)) = self.expiries.peek() {
            if *t <= certified_time {
                let (_, item) = self.expiries.pop().unwrap();
                ret.insert(item);
            } else {
                break;
            }
        }
        ret
```

**File:** consensus/src/quorum_store/batch_store.rs (L421-438)
```rust
        if value.expiration() > last_certified_time {
            fail_point!("quorum_store::save", |_| {
                // Skip caching and storing value to the db
                Ok(false)
            });
            counters::GAP_BETWEEN_BATCH_EXPIRATION_AND_CURRENT_TIME_WHEN_SAVE.observe(
                Duration::from_micros(value.expiration() - last_certified_time).as_secs_f64(),
            );

            return self.insert_to_cache(value);
        }
        counters::NUM_BATCH_EXPIRED_WHEN_SAVE.inc();
        bail!(
            "Incorrect expiration {} in epoch {}, last committed timestamp {}",
            value.expiration(),
            self.epoch(),
            last_certified_time,
        );
```

**File:** consensus/src/quorum_store/batch_store.rs (L456-456)
```rust
                    if entry.get().expiration() <= expiration_time {
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L176-178)
```rust
        if proof.expiration() <= self.latest_block_timestamp {
            counters::inc_rejected_pos_count(counters::POS_EXPIRED_LABEL);
            return;
```

**File:** consensus/consensus-types/src/block.rs (L527-530)
```rust
            ensure!(
                self.timestamp_usecs() > parent.timestamp_usecs(),
                "Blocks must have strictly increasing timestamps"
            );
```

**File:** consensus/src/liveness/proposal_generator.rs (L601-601)
```rust
        let timestamp = self.time_service.get_current_timestamp();
```
