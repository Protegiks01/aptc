# Audit Report

## Title
Integer Underflow in Mixed Payload Client Causes Soft > Hard Limit Violation and Potential Consensus Divergence

## Summary
The `MixedPayloadClient` performs unchecked integer subtraction when adjusting transaction limits after pulling validator transactions. When on-chain governance increases the validator transaction limit beyond the backpressure-clamped filtering limits, integer underflow occurs, corrupting the limit values and enabling non-deterministic block sizes that can cause consensus stalls.

## Finding Description

The vulnerability exists in the payload pulling logic where validator transactions are pulled first, then user transactions are pulled with adjusted limits.

The core issue is an architectural mismatch: validator transaction pulling uses `params.max_txns.count()` (the unfiltered base limit of 5000 transactions) [1](#0-0) , while the subsequent subtraction operates on `max_txns_after_filtering` (the backpressure-clamped filtered limit, minimum 100 transactions) [2](#0-1) .

When backpressure activates, the clamping logic ensures `max_block_txns_after_filtering` doesn't fall below `MIN_BLOCK_TXNS_AFTER_FILTERING = 100` [3](#0-2)  and [4](#0-3) . However, `soft_max_txns_after_filtering` can be set to the original backpressure target (e.g., 50 transactions) [5](#0-4) .

The validator transaction limit is governance-controlled through `ValidatorTxnConfig`, with a default of 2 but modifiable via on-chain governance [6](#0-5) . When governance increases this limit beyond 100 (e.g., to 150), the validator transaction pool can provide that many transactions [7](#0-6) .

The pull operation fetches `min(5000, 150) = 150` validator transactions. The subsequent unchecked subtraction using the `SubAssign` trait implementation [8](#0-7)  performs `100 - 150` and `50 - 150`, causing integer underflow. In release builds, this wraps to values near `u64::MAX`, corrupting the limits used for batch selection [9](#0-8)  and [10](#0-9) .

With corrupted limits approaching `u64::MAX`, the transaction count checks never trigger, causing block sizes to be determined solely by byte limits and timing, leading to non-deterministic block contents across different proposers.

## Impact Explanation

This is a **Medium severity** vulnerability per Aptos bug bounty criteria:

1. **State Inconsistencies Requiring Intervention**: Different validators proposing in different rounds may create blocks with vastly different transaction counts under the same backpressure conditions. While the blocks themselves pass validation [11](#0-10)  and [12](#0-11) , the unpredictable block sizes violate the backpressure system's intended behavior, potentially causing consensus stalls or requiring manual intervention.

2. **Limited Consensus Impact**: This affects liveness rather than safety. It doesn't enable double-spending or fund theft, but disrupts the backpressure mechanism designed to maintain network stability during high load conditions.

3. **Configuration-Dependent**: Requires on-chain governance to increase the validator transaction limit beyond 100, combined with active backpressure conditions. This makes it realistic for protocol evolution but not immediately exploitable.

4. **No Direct Fund Loss**: Does not enable theft, minting, or permanent freezing of tokens. The economic impact is indirect through potential network unavailability.

## Likelihood Explanation

**Likelihood: Medium**

1. **Governance Path**: The `ValidatorTxnConfig.per_block_limit_txn_count` parameter is legitimately modifiable via on-chain governance for protocol upgrades (additional DKG rounds, randomness beacons, validator set updates).

2. **Backpressure is Common**: The backpressure mechanisms activate regularly under high load or slow execution [13](#0-12) , making scenarios where limits are reduced to minimums realistic.

3. **Currently Safe**: With the default `per_block_limit_txn_count = 2` [14](#0-13) , this vulnerability cannot manifest. However, the first governance proposal to increase this above 100 would expose the bug when backpressure activates.

4. **Release Build Behavior**: Validators run release builds where integer underflow wraps silently rather than panicking, so the bug manifests as incorrect behavior rather than crashes.

## Recommendation

Replace the unchecked subtraction with saturating subtraction in `MixedPayloadClient::pull_payload`. Change lines 93-95 in `consensus/src/payload_client/mixed.rs` from:

```rust
user_txn_pull_params.max_txns -= vtxn_size;
user_txn_pull_params.max_txns_after_filtering -= validator_txns.len() as u64;
user_txn_pull_params.soft_max_txns_after_filtering -= validator_txns.len() as u64;
```

to:

```rust
user_txn_pull_params.max_txns = user_txn_pull_params.max_txns.saturating_sub(vtxn_size);
user_txn_pull_params.max_txns_after_filtering = user_txn_pull_params.max_txns_after_filtering.saturating_sub(validator_txns.len() as u64);
user_txn_pull_params.soft_max_txns_after_filtering = user_txn_pull_params.soft_max_txns_after_filtering.saturating_sub(validator_txns.len() as u64);
```

Alternatively, enforce that validator transaction pulling respects the filtered limits by using `min(params.max_txns_after_filtering, self.validator_txn_config.per_block_limit_txn_count())` instead of `min(params.max_txns.count(), self.validator_txn_config.per_block_limit_txn_count())`.

## Proof of Concept

While no executable PoC is provided, the vulnerability can be triggered with the following scenario:

1. Governance increases `ValidatorTxnConfig.per_block_limit_txn_count` to 150 via on-chain proposal
2. Network experiences high load, activating backpressure that reduces `max_block_txns_after_filtering` to 50
3. Clamping logic sets `max_block_txns_after_filtering = 100`, `soft_max_txns_after_filtering = 50`
4. Proposer pulls 150 validator transactions (min(5000, 150))
5. Subtraction `100 - 150` wraps to ~18,446,744,073,709,551,566 in release builds
6. Batch selection checks never trigger, block size determined only by byte limits
7. Different proposers create blocks with inconsistent transaction counts, violating backpressure policy

**Notes**

The vulnerability is well-founded with clear technical evidence. The root cause is the mismatch between using the unfiltered transaction count limit (5000) for validator transaction pulling while using the filtered limit (100) for subtraction. The PayloadTxnsSize's SubAssign implementation uses unchecked arithmetic that wraps in release builds, enabling the underflow. While currently safe with the default configuration, any governance action to increase validator transaction limits beyond 100 would expose this bug during backpressure conditions, potentially causing consensus disruption.

### Citations

**File:** consensus/src/payload_client/mixed.rs (L69-72)
```rust
                min(
                    params.max_txns.count(),
                    self.validator_txn_config.per_block_limit_txn_count(),
                ),
```

**File:** consensus/src/payload_client/mixed.rs (L94-95)
```rust
        user_txn_pull_params.max_txns_after_filtering -= validator_txns.len() as u64;
        user_txn_pull_params.soft_max_txns_after_filtering -= validator_txns.len() as u64;
```

**File:** config/src/config/consensus_config.rs (L28-28)
```rust
const MIN_BLOCK_TXNS_AFTER_FILTERING: u64 = DEFEAULT_MAX_BATCH_TXNS as u64 * 2;
```

**File:** config/src/config/consensus_config.rs (L263-318)
```rust
            pipeline_backpressure: vec![
                PipelineBackpressureValues {
                    // pipeline_latency looks how long has the oldest block still in pipeline
                    // been in the pipeline.
                    // Block enters the pipeline after consensus orders it, and leaves the
                    // pipeline once quorum on execution result among validators has been reached
                    // (so-(badly)-called "commit certificate"), meaning 2f+1 validators have finished execution.
                    back_pressure_pipeline_latency_limit_ms: 1200,
                    max_sending_block_txns_after_filtering_override:
                        MAX_SENDING_BLOCK_TXNS_AFTER_FILTERING,
                    max_sending_block_bytes_override: 5 * 1024 * 1024,
                    backpressure_proposal_delay_ms: 50,
                },
                PipelineBackpressureValues {
                    back_pressure_pipeline_latency_limit_ms: 1500,
                    max_sending_block_txns_after_filtering_override:
                        MAX_SENDING_BLOCK_TXNS_AFTER_FILTERING,
                    max_sending_block_bytes_override: 5 * 1024 * 1024,
                    backpressure_proposal_delay_ms: 100,
                },
                PipelineBackpressureValues {
                    back_pressure_pipeline_latency_limit_ms: 1900,
                    max_sending_block_txns_after_filtering_override:
                        MAX_SENDING_BLOCK_TXNS_AFTER_FILTERING,
                    max_sending_block_bytes_override: 5 * 1024 * 1024,
                    backpressure_proposal_delay_ms: 200,
                },
                // with execution backpressure, only later start reducing block size
                PipelineBackpressureValues {
                    back_pressure_pipeline_latency_limit_ms: 2500,
                    max_sending_block_txns_after_filtering_override: 1000,
                    max_sending_block_bytes_override: MIN_BLOCK_BYTES_OVERRIDE,
                    backpressure_proposal_delay_ms: 300,
                },
                PipelineBackpressureValues {
                    back_pressure_pipeline_latency_limit_ms: 3500,
                    max_sending_block_txns_after_filtering_override: 200,
                    max_sending_block_bytes_override: MIN_BLOCK_BYTES_OVERRIDE,
                    backpressure_proposal_delay_ms: 300,
                },
                PipelineBackpressureValues {
                    back_pressure_pipeline_latency_limit_ms: 4500,
                    max_sending_block_txns_after_filtering_override: 30,
                    max_sending_block_bytes_override: MIN_BLOCK_BYTES_OVERRIDE,
                    backpressure_proposal_delay_ms: 300,
                },
                PipelineBackpressureValues {
                    back_pressure_pipeline_latency_limit_ms: 6000,
                    // in practice, latencies and delay make it such that ~2 blocks/s is max,
                    // meaning that most aggressively we limit to ~10 TPS
                    // For transactions that are more expensive than that, we should
                    // instead rely on max gas per block to limit latency.
                    max_sending_block_txns_after_filtering_override: 5,
                    max_sending_block_bytes_override: MIN_BLOCK_BYTES_OVERRIDE,
                    backpressure_proposal_delay_ms: 300,
                },
```

**File:** consensus/src/liveness/proposal_generator.rs (L659-660)
```rust
                    soft_max_txns_after_filtering: max_txns_from_block_to_execute
                        .unwrap_or(max_block_txns_after_filtering),
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

**File:** types/src/on_chain_config/consensus_config.rs (L125-126)
```rust
const VTXN_CONFIG_PER_BLOCK_LIMIT_TXN_COUNT_DEFAULT: u64 = 2;
const VTXN_CONFIG_PER_BLOCK_LIMIT_TOTAL_BYTES_DEFAULT: u64 = 2097152; //2MB
```

**File:** crates/validator-transaction-pool/src/lib.rs (L152-199)
```rust
    pub fn pull(
        &mut self,
        deadline: Instant,
        mut max_items: u64,
        mut max_bytes: u64,
        filter: TransactionFilter,
    ) -> Vec<ValidatorTransaction> {
        let mut ret = vec![];
        let mut seq_num_lower_bound = 0;

        // Check deadline at the end of every iteration to ensure validator txns get a chance no matter what current proposal delay is.
        while max_items >= 1 && max_bytes >= 1 {
            // Find the seq_num of the first txn that satisfies the quota.
            if let Some(seq_num) = self
                .txn_queue
                .range(seq_num_lower_bound..)
                .filter(|(_, item)| {
                    item.txn.size_in_bytes() as u64 <= max_bytes
                        && !filter.should_exclude(&item.txn)
                })
                .map(|(seq_num, _)| *seq_num)
                .next()
            {
                // Update the quota usage.
                // Send the pull notification if requested.
                let PoolItem {
                    txn,
                    pull_notification_tx,
                    ..
                } = self.txn_queue.get(&seq_num).unwrap();
                if let Some(tx) = pull_notification_tx {
                    let _ = tx.push((), txn.clone());
                }
                max_items -= 1;
                max_bytes -= txn.size_in_bytes() as u64;
                seq_num_lower_bound = seq_num + 1;
                ret.push(txn.as_ref().clone());

                if Instant::now() >= deadline {
                    break;
                }
            } else {
                break;
            }
        }

        ret
    }
```

**File:** consensus/consensus-types/src/utils.rs (L141-144)
```rust
impl std::ops::SubAssign for PayloadTxnsSize {
    fn sub_assign(&mut self, rhs: Self) {
        *self = Self::new_normalized(self.count - rhs.count, self.bytes - rhs.bytes);
    }
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L652-652)
```rust
                            || unique_txns > max_txns_after_filtering
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L678-678)
```rust
                            || cur_unique_txns >= soft_max_txns_after_filtering
```

**File:** consensus/src/round_manager.rs (L1166-1177)
```rust
        ensure!(
            num_validator_txns <= vtxn_count_limit,
            "process_proposal failed with per-block vtxn count limit exceeded: limit={}, actual={}",
            self.vtxn_config.per_block_limit_txn_count(),
            num_validator_txns
        );
        ensure!(
            validator_txns_total_bytes <= vtxn_bytes_limit,
            "process_proposal failed with per-block vtxn bytes limit exceeded: limit={}, actual={}",
            self.vtxn_config.per_block_limit_total_bytes(),
            validator_txns_total_bytes
        );
```

**File:** consensus/src/round_manager.rs (L1180-1185)
```rust
        ensure!(
            num_validator_txns + payload_len as u64 <= self.local_config.max_receiving_block_txns,
            "Payload len {} exceeds the limit {}",
            payload_len,
            self.local_config.max_receiving_block_txns,
        );
```
