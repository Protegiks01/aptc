# Audit Report

## Title
Incomplete Batch Size Validation in Chain Health Backoff Allows Throughput Collapse During Network Stress

## Summary
The `sanitize_batch_block_limits()` function fails to validate that `receiver_max_batch_txns` is compatible with `max_sending_block_txns_after_filtering_override` values in chain health backoff and pipeline backpressure configurations. This validation gap allows configurations—including the default configuration—where individual quorum store batches exceed the block transaction limits imposed during network stress, causing severe throughput degradation precisely when the network needs stability most.

## Finding Description

The configuration sanitizer in `sanitize_batch_block_limits()` validates that quorum store batch limits are compatible with consensus block limits. However, it contains a critical validation gap for backpressure override scenarios. [1](#0-0) 

The loop over `chain_health_backoff` only validates that `receiver_max_batch_bytes` does not exceed `max_sending_block_bytes_override`, but completely omits validation of transaction counts. The same issue exists for `pipeline_backpressure`: [2](#0-1) 

This contrasts with the initial validation pairs that do check transaction counts against base limits: [3](#0-2) 

**The Default Configuration Violates This Invariant:**

The default quorum store configuration sets: [4](#0-3) 

The default chain health backoff configuration includes aggressive backoff levels: [5](#0-4) 

And: [6](#0-5) 

Similarly, pipeline backpressure has aggressive levels: [7](#0-6) 

And: [8](#0-7) 

**Attack Flow:**

1. Validators exchange quorum store batches containing up to 100 transactions (default `receiver_max_batch_txns`)
2. Network experiences stress: voting power drops below 72% OR pipeline latency exceeds 4500ms
3. Chain health backoff or pipeline backpressure activates, setting `max_txns_after_filtering` to 25, 5, or 30
4. The proposal generator attempts to assemble blocks with these reduced limits: [9](#0-8) 

5. The batch assembly logic checks if adding each batch would exceed the limit: [10](#0-9) 

6. Since individual batches (100 txns) exceed the backoff limit (5-30 txns), no batches can be included in blocks
7. Blocks become empty or contain only inline transactions, causing throughput collapse

**Invariant Violated:** Resource Limits invariant - the system allows batch configurations that violate backpressure resource limits, causing consensus liveness degradation during network stress when stability is most critical.

## Impact Explanation

**High Severity** - Significant protocol violation affecting consensus liveness:

- **Throughput Collapse During Network Stress**: When the backoff mechanism activates (designed to stabilize the network), throughput drops dramatically because batches cannot fit within reduced block limits
- **Counterproductive Backoff**: The safety mechanism becomes counterproductive, amplifying network problems instead of mitigating them
- **Transaction Confirmation Delays**: Users experience severe delays during critical network stress periods
- **Prolonged Degradation**: If voting power remains low or pipeline latency high, the network operates in degraded state indefinitely
- **Default Configuration Affected**: This affects ALL networks running default configuration, not just misconfigured deployments

This meets the "Significant protocol violations" criterion for High Severity ($50,000 bounty tier). While not reaching Critical severity (which requires total loss of liveness), it represents a severe consensus liveness degradation that affects network availability during stress conditions.

## Likelihood Explanation

**High Likelihood**:

- **Default Configuration**: The vulnerability exists in the default configuration shipped with Aptos Core
- **Natural Triggering**: Network stress naturally triggers backoff (voting power drops, execution latency increases)
- **No Attacker Action Required**: The issue manifests during normal adverse network conditions
- **Weaponizable**: An attacker could deliberately cause network stress to trigger backoff and amplify the impact
- **Already Deployed**: This configuration is likely running on production networks

The issue will manifest whenever:
- Voting power participation drops below 72% (chain health backoff level 4 with 25 txn limit)
- Voting power participation drops below 70% (chain health backoff level 5 with 5 txn limit)  
- Pipeline execution latency exceeds 4500ms (pipeline backpressure level 5 with 30 txn limit)
- Pipeline execution latency exceeds 6000ms (pipeline backpressure level 6 with 5 txn limit)

## Recommendation

Add transaction count validation for all backoff override scenarios in `sanitize_batch_block_limits()`:

```rust
// After line 479, add:
for backpressure_values in &config.pipeline_backpressure {
    recv_batch_send_block_pairs.push((
        config.quorum_store.receiver_max_batch_txns as u64,
        backpressure_values.max_sending_block_txns_after_filtering_override,
        format!(
            "backpressure {} ms: QS recv batch txns < max_sending_block_txns_after_filtering_override",
            backpressure_values.back_pressure_pipeline_latency_limit_ms,
        ),
    ));
}

// After line 489, add:
for backoff_values in &config.chain_health_backoff {
    recv_batch_send_block_pairs.push((
        config.quorum_store.receiver_max_batch_txns as u64,
        backoff_values.max_sending_block_txns_after_filtering_override,
        format!(
            "backoff {} %: txns: QS recv batch txns < max_sending_block_txns_after_filtering_override",
            backoff_values.backoff_if_below_participating_voting_power_percentage,
        ),
    ));
}
```

Additionally, the default configuration should be updated to ensure `receiver_max_batch_txns` is compatible with the most aggressive backoff levels, or the backoff levels should be adjusted to remain above `receiver_max_batch_txns`.

## Proof of Concept

```rust
#[test]
fn test_default_config_violates_chain_health_backoff_txn_limits() {
    // Test that the default configuration has incompatible limits
    let default_config = ConsensusConfig::default();
    let receiver_max_batch_txns = default_config.quorum_store.receiver_max_batch_txns as u64;
    
    // Find the most aggressive backoff levels
    let mut violates = false;
    for backoff_values in &default_config.chain_health_backoff {
        if receiver_max_batch_txns > backoff_values.max_sending_block_txns_after_filtering_override {
            println!(
                "VIOLATION: receiver_max_batch_txns ({}) > backoff override ({}) at {}% voting power",
                receiver_max_batch_txns,
                backoff_values.max_sending_block_txns_after_filtering_override,
                backoff_values.backoff_if_below_participating_voting_power_percentage
            );
            violates = true;
        }
    }
    
    assert!(violates, "Default config should violate the invariant");
    // Expected violations at 72% (25 txns) and 70% (5 txns) voting power
}

#[test]
fn test_missing_validation_allows_incompatible_config() {
    // Create a config that violates the invariant but passes sanitization
    let node_config = NodeConfig {
        consensus: ConsensusConfig {
            chain_health_backoff: vec![ChainHealthBackoffValues {
                backoff_if_below_participating_voting_power_percentage: 70,
                max_sending_block_txns_after_filtering_override: 5,
                max_sending_block_bytes_override: 1024 * 1024,
                backoff_proposal_delay_ms: 300,
            }],
            quorum_store: QuorumStoreConfig {
                receiver_max_batch_txns: 100, // 100 > 5, should fail but doesn't
                receiver_max_batch_bytes: 1024 * 1024,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };
    
    // This SHOULD fail but currently passes sanitization
    let result = ConsensusConfig::sanitize(
        &node_config,
        NodeType::Validator,
        Some(ChainId::testnet()),
    );
    
    // Currently this passes when it should fail
    assert!(result.is_ok(), "Current sanitizer incorrectly allows this configuration");
    
    // After fix, this should fail with Error::ConfigSanitizerFailed
}
```

## Notes

This vulnerability represents a critical configuration validation gap that affects the default deployment. The backoff mechanism, designed to help the network recover during stress, becomes counterproductive due to incompatible batch and block limits. The issue is particularly severe because it manifests precisely when the network is already under stress, amplifying rather than mitigating the problem.

### Citations

**File:** config/src/config/consensus_config.rs (L303-308)
```rust
                PipelineBackpressureValues {
                    back_pressure_pipeline_latency_limit_ms: 4500,
                    max_sending_block_txns_after_filtering_override: 30,
                    max_sending_block_bytes_override: MIN_BLOCK_BYTES_OVERRIDE,
                    backpressure_proposal_delay_ms: 300,
                },
```

**File:** config/src/config/consensus_config.rs (L309-318)
```rust
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

**File:** config/src/config/consensus_config.rs (L347-352)
```rust
                ChainHealthBackoffValues {
                    backoff_if_below_participating_voting_power_percentage: 72,
                    max_sending_block_txns_after_filtering_override: 25,
                    max_sending_block_bytes_override: MIN_BLOCK_BYTES_OVERRIDE,
                    backoff_proposal_delay_ms: 300,
                },
```

**File:** config/src/config/consensus_config.rs (L353-362)
```rust
                ChainHealthBackoffValues {
                    backoff_if_below_participating_voting_power_percentage: 70,
                    // in practice, latencies and delay make it such that ~2 blocks/s is max,
                    // meaning that most aggressively we limit to ~10 TPS
                    // For transactions that are more expensive than that, we should
                    // instead rely on max gas per block to limit latency.
                    max_sending_block_txns_after_filtering_override: 5,
                    max_sending_block_bytes_override: MIN_BLOCK_BYTES_OVERRIDE,
                    backoff_proposal_delay_ms: 300,
                },
```

**File:** config/src/config/consensus_config.rs (L447-463)
```rust
        let mut recv_batch_send_block_pairs = vec![
            (
                config.quorum_store.receiver_max_batch_txns as u64,
                config.max_sending_block_txns,
                "QS recv batch txns < max_sending_block_txns".to_string(),
            ),
            (
                config.quorum_store.receiver_max_batch_txns as u64,
                config.max_sending_block_txns_after_filtering,
                "QS recv batch txns < max_sending_block_txns_after_filtering ".to_string(),
            ),
            (
                config.quorum_store.receiver_max_batch_txns as u64,
                config.min_max_txns_in_block_after_filtering_from_backpressure,
                "QS recv batch txns < min_max_txns_in_block_after_filtering_from_backpressure"
                    .to_string(),
            ),
```

**File:** config/src/config/consensus_config.rs (L470-479)
```rust
        for backpressure_values in &config.pipeline_backpressure {
            recv_batch_send_block_pairs.push((
                config.quorum_store.receiver_max_batch_bytes as u64,
                backpressure_values.max_sending_block_bytes_override,
                format!(
                    "backpressure {} ms: QS recv batch bytes < max_sending_block_bytes_override",
                    backpressure_values.back_pressure_pipeline_latency_limit_ms,
                ),
            ));
        }
```

**File:** config/src/config/consensus_config.rs (L480-489)
```rust
        for backoff_values in &config.chain_health_backoff {
            recv_batch_send_block_pairs.push((
                config.quorum_store.receiver_max_batch_bytes as u64,
                backoff_values.max_sending_block_bytes_override,
                format!(
                    "backoff {} %: bytes: QS recv batch bytes < max_sending_block_bytes_override",
                    backoff_values.backoff_if_below_participating_voting_power_percentage,
                ),
            ));
        }
```

**File:** config/src/config/quorum_store_config.rs (L120-120)
```rust
            receiver_max_batch_txns: 100,
```

**File:** consensus/src/liveness/proposal_generator.rs (L813-816)
```rust
        let max_block_txns_after_filtering = values_max_block_txns_after_filtering
            .into_iter()
            .min()
            .expect("always initialized to at least one value");
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L651-656)
```rust
                        if cur_all_txns + batch.size() > max_txns
                            || unique_txns > max_txns_after_filtering
                        {
                            // Exceeded the limit for requested bytes or number of transactions.
                            full = true;
                            return false;
```
