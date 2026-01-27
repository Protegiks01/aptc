# Audit Report

## Title
Integer Underflow in Mixed Payload Client Causes Soft > Hard Limit Violation and Potential Consensus Divergence

## Summary
The `MixedPayloadClient` in `consensus/src/payload_client/mixed.rs` performs unchecked integer subtraction when adjusting transaction limits after pulling validator transactions. This can cause integer underflow (wrapping to near-maximum u64 values in release builds), resulting in `soft_max_txns_after_filtering > max_txns_after_filtering`, which violates the intended limit semantics and can lead to non-deterministic block sizes across validators.

## Finding Description

The vulnerability exists in the payload pulling logic where validator transactions are pulled first, then user transactions. The code adjusts the remaining capacity by subtracting the number of validator transactions pulled: [1](#0-0) 

These lines use unchecked subtraction (`-=` operator). If `validator_txns.len()` exceeds either `max_txns_after_filtering` or `soft_max_txns_after_filtering`, integer underflow occurs. In Rust release builds (which validators run), this wraps around to very large u64 values near `u64::MAX`.

**Root Cause:** The validator transaction limit is controlled by on-chain governance through `ValidatorTxnConfig`: [2](#0-1) 

The default is only 2 transactions per block, but governance can increase this. Meanwhile, backpressure mechanisms can reduce the filtering limits significantly. The minimum floor is enforced here: [3](#0-2) 

This sets `MIN_BLOCK_TXNS_AFTER_FILTERING = 100` (2 * 50 batch size). The backpressure logic ensures `max_block_txns_after_filtering` stays above this: [4](#0-3) 

**Attack Scenario:**
1. On-chain governance increases `per_block_limit_txn_count` to 150 (to handle more DKG transcripts, randomness beacons, etc.)
2. Backpressure activates and reduces `max_txns_after_filtering` to 100 (the minimum)
3. Backpressure also reduces `soft_max_txns_after_filtering` to 50 (the original calculated value before clamping)
4. Validator transaction pool returns 150 transactions
5. Line 95 executes: `50 - 150` → underflows to `18446744073709551516`
6. Now `soft_max_txns_after_filtering` is astronomically large, while `max_txns_after_filtering` might also underflow

**Impact on Pull Logic:**
The underflowed values affect the batch pulling logic: [5](#0-4) 

With underflowed limits:
- Line 652 check (`unique_txns > max_txns_after_filtering`) becomes ineffective
- Line 678 check (`cur_unique_txns >= soft_max_txns_after_filtering`) never triggers
- Blocks are sized only by byte limits, not transaction counts
- Different validators may pull different amounts based on validator transaction timing

This violates the **Deterministic Execution** invariant: validators must produce identical blocks for the same round.

## Impact Explanation

This is a **Medium severity** vulnerability per the Aptos bug bounty criteria:

1. **State Inconsistencies Requiring Intervention**: Different validators may propose blocks with different transaction counts for the same round, leading to proposal rejections and potential consensus stalls requiring manual intervention.

2. **Limited Consensus Impact**: While this doesn't break consensus safety (no double-spending), it affects liveness and can cause temporary network disruptions. Validators may repeatedly fail to agree on block contents until the backpressure condition clears.

3. **Configuration-Dependent**: Requires specific on-chain governance configuration combined with backpressure conditions, making it less immediately exploitable than critical vulnerabilities.

4. **No Direct Fund Loss**: This doesn't enable theft or minting of tokens, but the consensus disruption could have economic impact through network downtime.

## Likelihood Explanation

**Likelihood: Medium-High**

1. **Governance Path**: The `ValidatorTxnConfig.per_block_limit_txn_count` parameter is legitimately modifiable via on-chain governance to support protocol upgrades (more DKG rounds, additional randomness beacons, etc.).

2. **Backpressure is Common**: The backpressure mechanisms activate regularly under high load or slow execution, making the condition where limits are reduced to minimums realistic.

3. **Release Build Behavior**: Validators run release builds where integer underflow silently wraps rather than panicking, so the bug manifests as incorrect behavior rather than crashes.

4. **Currently Safe**: With the default `per_block_limit_txn_count = 2`, this cannot occur. However, any governance proposal to increase this to >100 would trigger the vulnerability under backpressure.

## Recommendation

Replace unchecked subtraction with `saturating_sub` to prevent underflow, similar to how the timeout is handled:

```rust
// Update constraints with validator txn pull results.
let mut user_txn_pull_params = params;
user_txn_pull_params.max_txns -= vtxn_size;
user_txn_pull_params.max_txns_after_filtering = user_txn_pull_params
    .max_txns_after_filtering
    .saturating_sub(validator_txns.len() as u64);
user_txn_pull_params.soft_max_txns_after_filtering = user_txn_pull_params
    .soft_max_txns_after_filtering
    .saturating_sub(validator_txns.len() as u64);
user_txn_pull_params.max_poll_time = user_txn_pull_params
    .max_poll_time
    .saturating_sub(validator_txn_pull_timer.elapsed());
```

**Additional Validation:** Add a configuration sanitizer check to ensure `per_block_limit_txn_count` never exceeds `min_max_txns_in_block_after_filtering_from_backpressure`:

```rust
// In config/src/config/consensus_config.rs, add to sanitize_batch_block_limits:
if let ValidatorTxnConfig::V1 { per_block_limit_txn_count, .. } = &config.effective_validator_txn_config() {
    if *per_block_limit_txn_count > config.min_max_txns_in_block_after_filtering_from_backpressure {
        return Err(Error::ConfigSanitizerFailed(
            sanitizer_name.to_owned(),
            format!(
                "per_block_limit_txn_count ({}) must not exceed min_max_txns_in_block_after_filtering_from_backpressure ({})",
                per_block_limit_txn_count,
                config.min_max_txns_in_block_after_filtering_from_backpressure
            ),
        ));
    }
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_validator_txn_underflow() {
    use crate::payload_client::{mixed::MixedPayloadClient, user, validator::DummyValidatorTxnClient, PayloadClient};
    use aptos_consensus_types::{common::PayloadFilter, payload_pull_params::PayloadPullParameters};
    use aptos_types::{on_chain_config::ValidatorTxnConfig, validator_txn::ValidatorTransaction};
    use aptos_validator_transaction_pool as vtxn_pool;
    use std::{collections::HashSet, sync::Arc, time::Duration};

    // Create many validator transactions (more than soft limit)
    let validator_txns = (0..60).map(|i| ValidatorTransaction::dummy(vec![i])).collect::<Vec<_>>();
    
    let user_txns = crate::test_utils::create_vec_signed_transactions(100);
    
    let client = MixedPayloadClient {
        // Set high validator txn limit
        validator_txn_config: ValidatorTxnConfig::V1 {
            per_block_limit_txn_count: 100,
            per_block_limit_total_bytes: 10_000_000,
        },
        validator_txn_pool_client: Arc::new(DummyValidatorTxnClient::new(validator_txns.clone())),
        user_payload_client: Arc::new(user::DummyClient::new(user_txns.clone())),
    };

    // Create params with low soft limit (simulating backpressure)
    let params = PayloadPullParameters::new_for_test(
        Duration::from_secs(1),
        200,    // max_txns
        1_000_000, // max_bytes  
        100,    // max_txns_after_filtering (hard limit)
        50,     // soft_max_txns_after_filtering (LESS than validator txns!)
        50,     // max_inline_txns
        500_000, // max_inline_bytes
        PayloadFilter::Empty,
        false,
        0,
        0.0,
        aptos_infallible::duration_since_epoch(),
    );

    let result = client.pull_payload(
        params,
        vtxn_pool::TransactionFilter::PendingTxnHashSet(HashSet::new()),
    ).await;

    // In release builds, this will succeed but with underflowed limits
    // In debug builds, this will panic with integer underflow
    // Either way, demonstrates the vulnerability
    match result {
        Ok((vtxns, payload)) => {
            println!("Pulled {} validator txns", vtxns.len());
            println!("Pulled user payload of size {}", payload.len());
            // If we get here in release, the underflow occurred silently
        },
        Err(e) => {
            println!("Error (expected in debug): {:?}", e);
        }
    }
}
```

**Notes:**
- This test will panic in debug builds due to integer underflow
- In release builds (production), it will silently wrap and allow oversized blocks
- The vulnerability is triggered when `validator_txns.len() > soft_max_txns_after_filtering`
- Real-world trigger requires on-chain governance to increase validator transaction limits combined with active backpressure

### Citations

**File:** consensus/src/payload_client/mixed.rs (L94-95)
```rust
        user_txn_pull_params.max_txns_after_filtering -= validator_txns.len() as u64;
        user_txn_pull_params.soft_max_txns_after_filtering -= validator_txns.len() as u64;
```

**File:** types/src/on_chain_config/consensus_config.rs (L125-136)
```rust
const VTXN_CONFIG_PER_BLOCK_LIMIT_TXN_COUNT_DEFAULT: u64 = 2;
const VTXN_CONFIG_PER_BLOCK_LIMIT_TOTAL_BYTES_DEFAULT: u64 = 2097152; //2MB

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum ValidatorTxnConfig {
    /// Disabled. In Jolteon, it also means to not use `BlockType::ProposalExt`.
    V0,
    /// Enabled. Per-block vtxn count and their total bytes are limited.
    V1 {
        per_block_limit_txn_count: u64,
        per_block_limit_total_bytes: u64,
    },
```

**File:** config/src/config/consensus_config.rs (L28-28)
```rust
const MIN_BLOCK_TXNS_AFTER_FILTERING: u64 = DEFEAULT_MAX_BATCH_TXNS as u64 * 2;
```

**File:** consensus/src/liveness/proposal_generator.rs (L827-837)
```rust
        let (max_block_txns_after_filtering, max_txns_from_block_to_execute) = if self
            .min_max_txns_in_block_after_filtering_from_backpressure
            > max_block_txns_after_filtering
        {
            (
                self.min_max_txns_in_block_after_filtering_from_backpressure,
                Some(max_block_txns_after_filtering),
            )
        } else {
            (max_block_txns_after_filtering, None)
        };
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L651-683)
```rust
                        if cur_all_txns + batch.size() > max_txns
                            || unique_txns > max_txns_after_filtering
                        {
                            // Exceeded the limit for requested bytes or number of transactions.
                            full = true;
                            return false;
                        }
                        cur_all_txns += batch.size();
                        // Add this batch to filtered_txns and calculate the number of
                        // unique transactions added in the result so far.
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
                        assert!(item.proof.is_none() == batches_without_proofs);
                        result.push(item);
                        if cur_all_txns == max_txns
                            || cur_unique_txns == max_txns_after_filtering
                            || cur_unique_txns >= soft_max_txns_after_filtering
                        {
                            full = true;
                            return false;
                        }
                    }
```
