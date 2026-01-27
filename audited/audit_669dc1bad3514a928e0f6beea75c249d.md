# Audit Report

## Title
Mempool Returns Empty Batches When Transactions Are Available, Causing Consensus Throughput Degradation

## Summary
When consensus requests transaction batches from mempool with `return_non_full = false` (requesting full batches only), and mempool contains fewer transactions than `max_txns`, mempool incorrectly clears the batch and returns an empty vector. This causes consensus to repeatedly poll with delays and eventually propose empty blocks while transactions remain stuck in mempool, degrading throughput under moderate load conditions.

## Finding Description

The vulnerability exists in the mempool batch retrieval logic. When consensus requests transactions via `GetBatchRequest`, the request includes a `return_non_full` parameter that indicates whether mempool should return partial batches or only full batches. [1](#0-0) 

The mempool collects available transactions by iterating through its priority queue, respecting sequence numbers and excluding already-pulled transactions. After building the batch, mempool applies this check: [2](#0-1) 

**The bug**: When `return_non_full = false` and the batch has fewer transactions than `max_txns` (typically 1800-5000) and hasn't reached the byte limit, mempool clears the entire batch and returns an empty vector, even when transactions are available.

**How consensus handles this**: On the consensus side, the `QuorumStoreClient` determines `return_non_full` based on pending blocks and recent fill ratios: [3](#0-2) 

When `return_non_full = false` and mempool returns empty, consensus enters a polling loop: [4](#0-3) 

**Exploitation scenario**:
1. System configured with aggressive "wait for full blocks" settings (e.g., `wait_for_full_blocks_above_pending_blocks: 2`)
2. Pending uncommitted blocks ≥ 2, causing `return_non_full = false`
3. Mempool has 100 ready transactions
4. Consensus requests batch with `max_txns = 1800`
5. Mempool collects 100 transactions but clears them because `100 < 1800`
6. Returns empty vector
7. Consensus polls again with 30ms delay - same result
8. After `quorum_store_poll_time` (300ms), consensus gives up
9. Consensus proposes block with 0 transactions
10. The 100 transactions remain in mempool, delayed by an additional round [5](#0-4) 

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria:
- **Throughput degradation**: Available transactions are not processed, reducing network capacity
- **Transaction delays**: Legitimate transactions experience unnecessary delays (minimum one additional consensus round + polling timeout)
- **Validator node inefficiency**: Nodes waste CPU cycles polling empty mempool and proposing empty blocks
- **State inconsistency**: System state shows transactions in mempool but excluded from blocks without valid reason

This does NOT cause:
- Complete consensus stalling (consensus continues with empty blocks)
- Fund loss or theft
- Safety violations or chain forks

The issue manifests most severely under moderate transaction load (100-1000 pending transactions), where there are enough transactions to matter but not enough to fill blocks. Under high load, blocks naturally fill up and the issue doesn't trigger. Under very low load, the impact is minimal.

## Likelihood Explanation

**Likelihood: Low to Medium** depending on configuration:

**Default Configuration (Low likelihood)**:
The "wait for full blocks" feature is intentionally disabled by default: [6](#0-5) 

With these defaults, `return_non_full` is almost always `true`, preventing the vulnerability.

**Custom Configuration (Medium to High likelihood)**:
If validators enable the feature with aggressive settings:
- `wait_for_full_blocks_above_pending_blocks: 1-5`
- `wait_for_full_blocks_above_recent_fill_threshold: 0.5-0.8`

The vulnerability manifests naturally when:
- Pending blocks accumulate during normal operation
- Transaction load is moderate (not filling entire blocks)
- Each consensus round delays transactions by `quorum_store_poll_time` + block time

## Recommendation

**Fix Option 1: Remove the non-full batch rejection logic**

Since the comment in the code indicates "Should always be true for Quorum Store", and the feature is disabled by default as "not fully tested", the safest fix is to remove the problematic check:

```rust
// Remove lines 575-577 entirely
// Always return available transactions regardless of batch fullness
```

**Fix Option 2: Only clear batch if truly empty**

If the "wait for full blocks" feature is desired, modify the logic to only reject batches when mempool is truly empty:

```rust
// Only clear if we found NO transactions at all
if !return_non_full && !full_bytes && block.is_empty() {
    block.clear();  // This is a no-op but keeps the intent clear
}
// If we have ANY transactions, return them even if not full
```

**Fix Option 3: Better handling in consensus client**

Modify `QuorumStoreClient` to be more lenient when receiving partial batches:

```rust
// Accept partial batches after first attempt
let return_non_full = return_non_full || start_time.elapsed() > Duration::from_millis(50);
```

**Recommended approach**: Fix Option 1 (remove the check) combined with re-evaluation of the "wait for full blocks" feature design before re-enabling it in production.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_types::{
        account_address::AccountAddress,
        chain_id::ChainId,
        transaction::{RawTransaction, Script, SignedTransaction, TransactionPayload},
    };
    use aptos_crypto::{ed25519::Ed25519PrivateKey, PrivateKey, SigningKey, Uniform};
    use std::collections::BTreeMap;

    #[test]
    fn test_mempool_clears_partial_batch_with_return_non_full_false() {
        let mut config = NodeConfig::default();
        config.mempool.system_transaction_timeout_secs = 100;
        let mut mempool = Mempool::new(&config);
        
        // Add 10 transactions to mempool
        for i in 0..10 {
            let sender = AccountAddress::random();
            let private_key = Ed25519PrivateKey::generate_for_testing();
            let raw_txn = RawTransaction::new(
                sender,
                0,
                TransactionPayload::Script(Script::new(vec![], vec![], vec![])),
                1000,
                1,
                100000,
                ChainId::new(1),
            );
            let signature = private_key.sign(&raw_txn).unwrap();
            let txn = SignedTransaction::new(
                raw_txn,
                private_key.public_key(),
                signature,
            );
            
            let status = mempool.add_txn(
                txn,
                100,
                Some(0),
                TimelineState::NotReady,
                true,
                None,
                None,
            );
            assert_eq!(status.code, MempoolStatusCode::Accepted);
        }
        
        // Request batch with return_non_full = false and max_txns = 100
        let batch = mempool.get_batch(
            100,  // max_txns
            10_000_000,  // max_bytes
            false,  // return_non_full = FALSE
            BTreeMap::new(),  // exclude_transactions
        );
        
        // BUG: Mempool returns EMPTY even though 10 transactions are available
        // because 10 < 100 and return_non_full = false
        assert_eq!(batch.len(), 0, "Expected empty batch due to bug");
        
        // Verify transactions are still in mempool
        // (they weren't removed, just excluded from the batch)
        let batch_full = mempool.get_batch(
            100,
            10_000_000,
            true,  // return_non_full = TRUE
            BTreeMap::new(),
        );
        
        // With return_non_full = true, we get the transactions
        assert_eq!(batch_full.len(), 10, "Transactions still available in mempool");
    }
}
```

This test demonstrates that when `return_non_full = false`, mempool returns an empty batch even when 10 transactions are available and ready for inclusion, simply because the batch size (10) is less than `max_txns` (100). The transactions remain in mempool and can be retrieved when `return_non_full = true`.

## Notes

While this vulnerability requires non-default configuration to manifest, it represents a fundamental logic flaw in the mempool batch retrieval mechanism that contradicts the expected behavior of the "wait for full blocks" feature. The feature was intended to optimize throughput by waiting for full batches, but instead it degrades throughput by excluding available transactions. The comment in the code suggesting this should "always be true for Quorum Store" indicates the developers were aware of potential issues with `return_non_full = false` behavior.

### Citations

**File:** mempool/src/core_mempool/mempool.rs (L425-431)
```rust
    pub(crate) fn get_batch(
        &self,
        max_txns: u64,
        max_bytes: u64,
        return_non_full: bool,
        exclude_transactions: BTreeMap<TransactionSummary, TransactionInProgress>,
    ) -> Vec<SignedTransaction> {
```

**File:** mempool/src/core_mempool/mempool.rs (L575-577)
```rust
        if !return_non_full && !full_bytes && (block.len() as u64) < max_txns {
            block.clear();
        }
```

**File:** consensus/src/payload_client/user/quorum_store_client.rs (L96-99)
```rust
        let return_non_full = params.recent_max_fill_fraction
            < self.wait_for_full_blocks_above_recent_fill_threshold
            && params.pending_uncommitted_blocks < self.wait_for_full_blocks_above_pending_blocks;
        let return_empty = params.pending_ordering && return_non_full;
```

**File:** consensus/src/payload_client/user/quorum_store_client.rs (L109-129)
```rust
        let payload = loop {
            // Make sure we don't wait more than expected, due to thread scheduling delays/processing time consumed
            let done = start_time.elapsed() >= params.max_poll_time;
            let payload = self
                .pull_internal(
                    params.max_txns,
                    params.max_txns_after_filtering,
                    params.soft_max_txns_after_filtering,
                    params.max_inline_txns,
                    params.maybe_optqs_payload_pull_params.clone(),
                    return_non_full || return_empty || done,
                    params.user_txn_filter.clone(),
                    params.block_timestamp,
                )
                .await?;
            if payload.is_empty() && !return_empty && !done {
                sleep(Duration::from_millis(NO_TXN_DELAY)).await;
                continue;
            }
            break payload;
        };
```

**File:** consensus/src/liveness/proposal_generator.rs (L652-672)
```rust
        let (validator_txns, mut payload) = self
            .payload_client
            .pull_payload(
                PayloadPullParameters {
                    max_poll_time: self.quorum_store_poll_time.saturating_sub(proposal_delay),
                    max_txns: max_block_txns,
                    max_txns_after_filtering: max_block_txns_after_filtering,
                    soft_max_txns_after_filtering: max_txns_from_block_to_execute
                        .unwrap_or(max_block_txns_after_filtering),
                    max_inline_txns: self.max_inline_txns,
                    maybe_optqs_payload_pull_params,
                    user_txn_filter: payload_filter,
                    pending_ordering,
                    pending_uncommitted_blocks: pending_blocks.len(),
                    recent_max_fill_fraction: max_fill_fraction,
                    block_timestamp: timestamp,
                },
                validator_txn_filter,
            )
            .await
            .context("Fail to retrieve payload")?;
```

**File:** config/src/config/consensus_config.rs (L245-249)
```rust
            // disable wait_for_full until fully tested
            // We never go above 20-30 pending blocks, so this disables it
            wait_for_full_blocks_above_pending_blocks: 100,
            // Max is 1, so 1.1 disables it.
            wait_for_full_blocks_above_recent_fill_threshold: 1.1,
```
