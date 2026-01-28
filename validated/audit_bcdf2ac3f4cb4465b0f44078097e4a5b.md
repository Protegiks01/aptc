# Audit Report

## Title
Missing Configuration Validation for DAG Consensus Quorum Store Batch Limits Can Cause Network Liveness Failure

## Summary
The DAG consensus configuration sanitizer fails to validate that quorum store batch size limits are compatible with DAG payload limits. This allows configurations where individual batches exceed per-node transaction limits, causing empty block generation and zero transaction throughput.

## Finding Description

The Aptos configuration sanitization system has a critical validation gap specific to DAG consensus. While traditional consensus properly validates that quorum store batch limits do not exceed block limits, DAG consensus lacks equivalent validation.

**Traditional Consensus Validation Chain:**

Traditional consensus validates that receiver batch limits are less than or equal to block transaction limits through `sanitize_batch_block_limits()`. [1](#0-0) 

This ensures the transitive constraint: `sender_max_batch_txns` ≤ `receiver_max_batch_txns` ≤ `max_sending_block_txns`.

**DAG Consensus Validation Gap:**

DAG consensus maintains a separate `quorum_store` configuration field, [2](#0-1)  but the sanitizer only validates internal DAG payload consistency without cross-checking quorum store batch limits. [3](#0-2) 

The `DagPayloadConfig` sanitizer only validates that sending limits do not exceed receiving limits. [4](#0-3) 

**Missing Validation:** There is no check that `quorum_store.receiver_max_batch_txns` ≤ `dag_payload_config.max_sending_txns_per_round` or that `quorum_store.receiver_max_batch_bytes` ≤ `dag_payload_config.max_sending_size_per_round_bytes`.

**Runtime Enforcement Mechanism:**

At runtime, DAG uses its separate quorum store configuration. [5](#0-4) 

When DAG creates a new node, it calculates per-validator payload limits by dividing the round limit by the number of validators. [6](#0-5) 

These limits are passed to the payload client when pulling transactions. [7](#0-6) 

The batch proof queue enforces these limits during batch pulling. When `cur_all_txns + batch.size() > max_txns`, the code immediately sets `full = true` and returns without adding the batch. [8](#0-7) 

If the first batch exceeds the limit before any batches are added, the result is an empty payload. [9](#0-8) 

## Impact Explanation

**Severity: High** (with argument for Critical)

If DAG consensus validators are misconfigured with:
- `quorum_store.sender_max_batch_txns = 15,000`
- `quorum_store.receiver_max_batch_txns = 15,000`  
- `dag_payload_config.max_sending_txns_per_round = 1,000`
- `dag_payload_config.max_receiving_txns_per_round = 20,000`

The sanitizers pass all checks (15,000 ≤ 15,000 ✓, 1,000 ≤ 20,000 ✓), but at runtime:
1. Batches are created with 15,000 transactions
2. Per-node limit = 1,000 / 100 validators = 10 transactions
3. Every batch exceeds the limit (15,000 > 10)
4. All payload pulls return empty results
5. No transactions are processed, resulting in zero network throughput

While the DAG can still finalize empty blocks and maintain consensus progress, the complete inability to process user transactions represents a total loss of network availability for its core function. This aligns with "Validator Node Slowdowns" or "Total Loss of Liveness/Network Availability" categories in the Aptos bug bounty, justifying High to Critical severity.

## Likelihood Explanation

**Likelihood: Medium**

Default DAG configurations are safe [10](#0-9) [11](#0-10)  (300 txns/batch, 10,000 txns/round).

However, the vulnerability can manifest through:

1. **Operator Misconfiguration**: Administrators tuning performance parameters for higher throughput without understanding the constraint dependencies between batch sizes and per-validator limits
2. **Configuration Template Errors**: Incorrect configuration templates distributed across validators
3. **Infrastructure-as-Code Deployments**: Automated deployment systems with invalid parameter combinations

The missing validation means there is no safety net preventing these scenarios. For a decentralized network with multiple independent operators, configuration drift and errors are realistic operational risks that should be caught at the validation layer.

## Recommendation

Add validation in `DagConsensusConfig::sanitize()` to ensure quorum store batch limits are compatible with DAG payload limits:

```rust
impl ConfigSanitizer for DagConsensusConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        
        // Existing validation
        DagPayloadConfig::sanitize(node_config, node_type, chain_id)?;
        
        // NEW: Validate quorum store batch limits against DAG payload limits
        let dag_config = &node_config.dag_consensus;
        let quorum_store = &dag_config.quorum_store;
        let payload_config = &dag_config.node_payload_config;
        
        // Assume minimum validator count for conservative validation
        let min_validators = 4;
        let per_validator_txn_limit = payload_config.max_sending_txns_per_round / min_validators;
        let per_validator_byte_limit = payload_config.max_sending_size_per_round_bytes / min_validators;
        
        if quorum_store.receiver_max_batch_txns as u64 > per_validator_txn_limit {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                format!(
                    "Quorum store receiver_max_batch_txns ({}) exceeds DAG per-validator limit ({})",
                    quorum_store.receiver_max_batch_txns,
                    per_validator_txn_limit
                ),
            ));
        }
        
        if quorum_store.receiver_max_batch_bytes as u64 > per_validator_byte_limit {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                format!(
                    "Quorum store receiver_max_batch_bytes ({}) exceeds DAG per-validator limit ({})",
                    quorum_store.receiver_max_batch_bytes,
                    per_validator_byte_limit
                ),
            ));
        }
        
        Ok(())
    }
}
```

## Proof of Concept

While a full PoC requires a multi-validator testnet setup, the vulnerability can be demonstrated through configuration:

1. Create a `NodeConfig` with DAG consensus enabled
2. Set `dag_consensus.quorum_store.receiver_max_batch_txns = 15000`
3. Set `dag_consensus.node_payload_config.max_sending_txns_per_round = 1000`
4. Run `DagConsensusConfig::sanitize()` - it will PASS
5. At runtime with 100 validators, per-validator limit = 1000/100 = 10
6. Batch pulling will fail as 15000 > 10, resulting in empty payloads

The configuration validation gap is demonstrable through unit testing the sanitizer with these values.

## Notes

- This vulnerability requires operator misconfiguration and does not involve malicious actors
- Default configurations are safe and properly sized
- The issue is specific to DAG consensus; traditional consensus has proper validation
- The missing validation creates a configuration footgun that should be prevented at the sanitizer layer
- Impact severity is debatable between High and Critical depending on whether "zero transaction throughput with continued block finalization" qualifies as "total loss of liveness"

### Citations

**File:** config/src/config/consensus_config.rs (L442-500)
```rust
    fn sanitize_batch_block_limits(
        sanitizer_name: &str,
        config: &ConsensusConfig,
    ) -> Result<(), Error> {
        // Note, we are strict here: receiver batch limits <= sender block limits
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
            (
                config.quorum_store.receiver_max_batch_bytes as u64,
                config.max_sending_block_bytes,
                "QS recv batch bytes < max_sending_block_bytes".to_string(),
            ),
        ];
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

        for (batch, block, label) in &recv_batch_send_block_pairs {
            if *batch > *block {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name.to_owned(),
                    format!("Failed {}: {} > {}", label, *batch, *block),
                ));
            }
        }
        Ok(())
    }
```

**File:** config/src/config/dag_consensus_config.rs (L22-32)
```rust
impl Default for DagPayloadConfig {
    fn default() -> Self {
        Self {
            max_sending_txns_per_round: 10000,
            max_sending_size_per_round_bytes: 10 * 1024 * 1024,
            max_receiving_txns_per_round: 11000,
            max_receiving_size_per_round_bytes: 20 * 1024 * 1024,

            payload_pull_max_poll_time_ms: 1000,
        }
    }
```

**File:** config/src/config/dag_consensus_config.rs (L52-77)
```rust
    fn sanitize_payload_size_limits(
        sanitizer_name: &str,
        config: &DagPayloadConfig,
    ) -> Result<(), Error> {
        let send_recv_pairs = [
            (
                config.max_sending_txns_per_round,
                config.max_receiving_txns_per_round,
                "txns",
            ),
            (
                config.max_sending_size_per_round_bytes,
                config.max_receiving_size_per_round_bytes,
                "bytes",
            ),
        ];
        for (send, recv, label) in &send_recv_pairs {
            if *send > *recv {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name.to_owned(),
                    format!("Failed {}: {} > {}", label, *send, *recv),
                ));
            }
        }
        Ok(())
    }
```

**File:** config/src/config/dag_consensus_config.rs (L166-167)
```rust
    pub quorum_store: QuorumStoreConfig,
}
```

**File:** config/src/config/dag_consensus_config.rs (L169-178)
```rust
impl ConfigSanitizer for DagConsensusConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        DagPayloadConfig::sanitize(node_config, node_type, chain_id)?;

        Ok(())
    }
```

**File:** consensus/src/epoch_manager.rs (L731-735)
```rust
        let quorum_store_config = if consensus_config.is_dag_enabled() {
            self.dag_config.quorum_store.clone()
        } else {
            self.config.quorum_store.clone()
        };
```

**File:** consensus/src/dag/health/backoff.rs (L64-66)
```rust
        let max_txns = max_txns_per_round.saturating_div(
            (self.epoch_state.verifier.len() as f64 * voting_power_ratio).ceil() as u64,
        );
```

**File:** consensus/src/dag/dag_driver.rs (L255-266)
```rust
        let (max_txns, max_size_bytes) = self
            .health_backoff
            .calculate_payload_limits(new_round, &self.payload_config);

        let (validator_txns, payload) = match self
            .payload_client
            .pull_payload(
                PayloadPullParameters {
                    max_poll_time: Duration::from_millis(
                        self.payload_config.payload_pull_max_poll_time_ms,
                    ),
                    max_txns: PayloadTxnsSize::new(max_txns, max_size_bytes),
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L652-657)
```rust
                            || unique_txns > max_txns_after_filtering
                        {
                            // Exceeded the limit for requested bytes or number of transactions.
                            full = true;
                            return false;
                        }
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L708-713)
```rust
            // Stable sort, so the order of proofs within an author will not change.
            result.sort_by_key(|item| Reverse(item.info.gas_bucket_start()));
            (result, cur_all_txns, cur_unique_txns, full)
        } else {
            (Vec::new(), PayloadTxnsSize::zero(), 0, full)
        }
```

**File:** config/src/config/quorum_store_config.rs (L155-176)
```rust
    pub fn default_for_dag() -> Self {
        Self {
            sender_max_batch_txns: 300,
            sender_max_batch_bytes: 4 * 1024 * 1024,
            sender_max_num_batches: 5,
            sender_max_total_txns: 500,
            sender_max_total_bytes: 8 * 1024 * 1024,
            receiver_max_batch_txns: 300,
            receiver_max_batch_bytes: 4 * 1024 * 1024,
            receiver_max_num_batches: 5,
            receiver_max_total_txns: 500,
            receiver_max_total_bytes: 8 * 1024 * 1024,
            back_pressure: QuorumStoreBackPressureConfig {
                backlog_txn_limit_count: 100000,
                backlog_per_validator_batch_limit_count: 20,
                dynamic_min_txn_per_s: 100,
                dynamic_max_txn_per_s: 200,
                ..Default::default()
            },
            ..Default::default()
        }
    }
```
