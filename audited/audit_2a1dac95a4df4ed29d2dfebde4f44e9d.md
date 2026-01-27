# Audit Report

## Title
Missing Validation for Zero Values in Quorum Store Batch Coordinator Configuration Causes Total Batch Rejection and Consensus Liveness Failure

## Summary
The `BatchCoordinator` configuration parameters `receiver_max_batch_txns`, `receiver_max_batch_bytes`, `receiver_max_total_txns`, and `receiver_max_total_bytes` can be set to zero without any validation errors. When set to zero, the coordinator rejects ALL incoming non-empty batches from peer validators, causing consensus liveness failures and preventing the affected validator from participating in the quorum store protocol.

## Finding Description
The vulnerability exists in the configuration validation and batch processing logic of the Aptos consensus quorum store system.

**Configuration Path:**
The `QuorumStoreConfig` defines four critical receiver limit parameters without minimum value validation. [1](#0-0) 

The default values are set to reasonable non-zero values, [2](#0-1)  but there is no enforcement preventing operators from overriding these to zero.

**Validation Gaps:**
The configuration sanitization only validates relative constraints (sender ≤ receiver, batch ≤ total) but does NOT validate that values must be greater than zero. [3](#0-2) [4](#0-3) 

**Exploitation Path:**
When `spawn_quorum_store()` creates `BatchCoordinator` instances, these unvalidated zero values are passed directly: [5](#0-4) 

The `BatchCoordinator` stores these values and uses them in `ensure_max_limits()` to validate incoming batches: [6](#0-5) 

**Critical Bug:**
If `max_batch_txns` or `max_batch_bytes` is zero, the validation checks will reject ANY non-empty batch because the comparisons use `<=`:
- Any batch with `num_txns() > 0` fails when `max_batch_txns == 0`
- Any batch with `num_bytes() > 0` fails when `max_batch_bytes == 0`

When validation fails, the batch is immediately rejected and the function returns without processing: [7](#0-6) 

Empty batches are never created by the batch generator, [8](#0-7)  so ALL legitimate batches from peers will be rejected when these limits are set to zero.

## Impact Explanation
This qualifies as **High Severity** under the Aptos Bug Bounty program for the following reasons:

1. **Validator Node Slowdowns**: The affected validator cannot receive and process batches from peers, degrading consensus performance and increasing latency.

2. **Significant Protocol Violations**: The validator violates the quorum store protocol by rejecting all valid batches, breaking the assumption that honest validators will process legitimate batches.

3. **Consensus Liveness Issues**: If multiple validators are misconfigured with zero limits, the network could experience severe liveness degradation as validators cannot exchange batches needed for consensus progress.

4. **Byzantine Fault Tolerance Reduction**: Each misconfigured validator effectively reduces the network's Byzantine fault tolerance capacity, as it cannot properly participate in consensus despite being online.

This does NOT reach Critical severity because:
- It requires configuration file access (not remotely exploitable without such access)
- It does not cause permanent state corruption or fund loss
- Recovery is possible by correcting the configuration and restarting the node

## Likelihood Explanation
**Likelihood: Medium to High**

**Realistic Attack Scenarios:**

1. **Operator Configuration Error (High Probability)**: An operator might mistakenly set these values to 0 thinking:
   - "0 means unlimited/no limit"
   - "0 means use default value"
   - During testing with intention to disable limits temporarily

2. **Configuration Template Misuse (Medium Probability)**: A test configuration with zero values could be accidentally deployed to production.

3. **Config Injection Attack (Low Probability but High Impact)**: An attacker who gains write access to validator configuration files (via compromised deployment pipeline, stolen credentials, or insider threat) could intentionally set these to zero to DoS specific validators.

**Contributing Factors:**
- No compile-time or runtime validation prevents this
- No warning messages or alerts when zero values are used
- Configuration changes may not be immediately noticed until batches start being rejected
- Error messages logged are generic and may not clearly indicate the root cause

## Recommendation
Add mandatory minimum value validation to prevent zero or negative values for all batch limit parameters.

**Implementation in `config/src/config/quorum_store_config.rs`:**

Add a new validation function after `sanitize_batch_total_limits`:

```rust
fn sanitize_positive_limits(
    sanitizer_name: &str,
    config: &QuorumStoreConfig,
) -> Result<(), Error> {
    let limits = [
        (config.sender_max_batch_txns, "sender_max_batch_txns"),
        (config.sender_max_batch_bytes, "sender_max_batch_bytes"),
        (config.sender_max_total_txns, "sender_max_total_txns"),
        (config.sender_max_total_bytes, "sender_max_total_bytes"),
        (config.receiver_max_batch_txns, "receiver_max_batch_txns"),
        (config.receiver_max_batch_bytes, "receiver_max_batch_bytes"),
        (config.receiver_max_total_txns, "receiver_max_total_txns"),
        (config.receiver_max_total_bytes, "receiver_max_total_bytes"),
    ];
    
    for (value, name) in &limits {
        if *value == 0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name.to_owned(),
                format!("{} must be greater than 0, got: {}", name, value),
            ));
        }
    }
    Ok(())
}
```

Then call this validation in the `ConfigSanitizer::sanitize` implementation:

```rust
impl ConfigSanitizer for QuorumStoreConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();

        // NEW: Validate all limits are positive
        Self::sanitize_positive_limits(
            &sanitizer_name,
            &node_config.consensus.quorum_store,
        )?;

        // Sanitize the send/recv batch limits
        Self::sanitize_send_recv_batch_limits(
            &sanitizer_name,
            &node_config.consensus.quorum_store,
        )?;

        // Sanitize the batch total limits
        Self::sanitize_batch_total_limits(&sanitizer_name, &node_config.consensus.quorum_store)?;

        Ok(())
    }
}
```

## Proof of Concept

**Rust Unit Test** (add to `config/src/config/quorum_store_config.rs`):

```rust
#[test]
fn test_receiver_max_batch_txns_zero_rejected() {
    let node_config = NodeConfig {
        consensus: ConsensusConfig {
            quorum_store: QuorumStoreConfig {
                receiver_max_batch_txns: 0,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let error = QuorumStoreConfig::sanitize(
        &node_config,
        NodeType::Validator,
        Some(ChainId::mainnet()),
    )
    .unwrap_err();
    
    assert!(matches!(error, Error::ConfigSanitizerFailed(_, msg) if msg.contains("receiver_max_batch_txns")));
}

#[test]
fn test_receiver_max_batch_bytes_zero_rejected() {
    let node_config = NodeConfig {
        consensus: ConsensusConfig {
            quorum_store: QuorumStoreConfig {
                receiver_max_batch_bytes: 0,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let error = QuorumStoreConfig::sanitize(
        &node_config,
        NodeType::Validator,
        Some(ChainId::mainnet()),
    )
    .unwrap_err();
    
    assert!(matches!(error, Error::ConfigSanitizerFailed(_, _)));
}

#[test]
fn test_all_receiver_limits_zero_rejected() {
    let node_config = NodeConfig {
        consensus: ConsensusConfig {
            quorum_store: QuorumStoreConfig {
                receiver_max_batch_txns: 0,
                receiver_max_batch_bytes: 0,
                receiver_max_total_txns: 0,
                receiver_max_total_bytes: 0,
                sender_max_batch_txns: 0,
                sender_max_batch_bytes: 0,
                sender_max_total_txns: 0,
                sender_max_total_bytes: 0,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let error = QuorumStoreConfig::sanitize(
        &node_config,
        NodeType::Validator,
        Some(ChainId::mainnet()),
    )
    .unwrap_err();
    
    assert!(matches!(error, Error::ConfigSanitizerFailed(_, _)));
}
```

**Behavioral Test** (demonstrates batch rejection):

Create a test in `consensus/src/quorum_store/batch_coordinator.rs` that shows zero limits cause batch rejection:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_zero_limits_reject_all_batches() {
        // Create a BatchCoordinator with zero limits
        let coordinator = BatchCoordinator::new(
            PeerId::random(),
            NetworkSender::new(/* ... */),
            tokio::sync::mpsc::channel(10).0,
            tokio::sync::mpsc::channel(10).0,
            Arc::new(/* BatchStore */),
            0, // receiver_max_batch_txns set to 0
            1024, // receiver_max_batch_bytes
            0, // receiver_max_total_txns set to 0
            1024, // receiver_max_total_bytes
            Duration::from_secs(60).as_micros() as u64,
            BatchTransactionFilterConfig::default(),
        );
        
        // Create a batch with 1 transaction
        let batch = create_test_batch_with_txns(1);
        let batches = vec![batch];
        
        // This should fail because max_batch_txns is 0
        let result = coordinator.ensure_max_limits(&batches);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Exceeds batch txn limit"));
    }
}
```

## Notes

**Additional Security Considerations:**

1. The same vulnerability exists for `sender_max_*` parameters, which could prevent a validator from creating its own batches, but this is less severe as it only affects the local node.

2. The `receiver_max_num_batches` parameter is also vulnerable to being set to zero, which would limit each `BatchMsg` to 0 batches, effectively rejecting all batch messages.

3. Consider adding monitoring/alerting when batch rejection rates exceed normal thresholds, as this could indicate misconfiguration or attack.

4. The validation should be added at both the config deserialization level and at runtime initialization of `BatchCoordinator` as defense-in-depth.

### Citations

**File:** config/src/config/quorum_store_config.rs (L72-83)
```rust
    /// The maximum number of transactions a single batch received from peers could contain.
    pub receiver_max_batch_txns: usize,
    /// The maximum number of bytes a single batch received from peers could contain.
    pub receiver_max_batch_bytes: usize,
    /// The maximum number of batches a BatchMsg received from peers can contain.
    pub receiver_max_num_batches: usize,
    /// The maximum number of transactions a BatchMsg received from peers can contain. Each BatchMsg can contain
    /// multiple batches.
    pub receiver_max_total_txns: usize,
    /// The maximum number of bytes a BatchMsg received from peers can contain. Each BatchMsg can contain
    /// multiple batches.
    pub receiver_max_total_bytes: usize,
```

**File:** config/src/config/quorum_store_config.rs (L120-126)
```rust
            receiver_max_batch_txns: 100,
            receiver_max_batch_bytes: 1024 * 1024 + BATCH_PADDING_BYTES,
            receiver_max_num_batches: 20,
            receiver_max_total_txns: 2000,
            receiver_max_total_bytes: 4 * 1024 * 1024
                + DEFAULT_MAX_NUM_BATCHES
                + BATCH_PADDING_BYTES,
```

**File:** config/src/config/quorum_store_config.rs (L178-213)
```rust
    fn sanitize_send_recv_batch_limits(
        sanitizer_name: &str,
        config: &QuorumStoreConfig,
    ) -> Result<(), Error> {
        let send_recv_pairs = [
            (
                config.sender_max_batch_txns,
                config.receiver_max_batch_txns,
                "txns",
            ),
            (
                config.sender_max_batch_bytes,
                config.receiver_max_batch_bytes,
                "bytes",
            ),
            (
                config.sender_max_total_txns,
                config.receiver_max_total_txns,
                "total_txns",
            ),
            (
                config.sender_max_total_bytes,
                config.receiver_max_total_bytes,
                "total_bytes",
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

**File:** config/src/config/quorum_store_config.rs (L215-250)
```rust
    fn sanitize_batch_total_limits(
        sanitizer_name: &str,
        config: &QuorumStoreConfig,
    ) -> Result<(), Error> {
        let batch_total_pairs = [
            (
                config.sender_max_batch_txns,
                config.sender_max_total_txns,
                "send_txns",
            ),
            (
                config.sender_max_batch_bytes,
                config.sender_max_total_bytes,
                "send_bytes",
            ),
            (
                config.receiver_max_batch_txns,
                config.receiver_max_total_txns,
                "recv_txns",
            ),
            (
                config.receiver_max_batch_bytes,
                config.receiver_max_total_bytes,
                "recv_bytes",
            ),
        ];
        for (batch, total, label) in &batch_total_pairs {
            if *batch > *total {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name.to_owned(),
                    format!("Failed {}: {} > {}", label, *batch, *total),
                ));
            }
        }
        Ok(())
    }
```

**File:** consensus/src/quorum_store/quorum_store_builder.rs (L324-336)
```rust
            let batch_coordinator = BatchCoordinator::new(
                self.author,
                self.network_sender.clone(),
                self.proof_manager_cmd_tx.clone(),
                self.batch_generator_cmd_tx.clone(),
                self.batch_store.clone().unwrap(),
                self.config.receiver_max_batch_txns as u64,
                self.config.receiver_max_batch_bytes as u64,
                self.config.receiver_max_total_txns as u64,
                self.config.receiver_max_total_bytes as u64,
                self.config.batch_expiry_gap_when_init_usecs,
                self.transaction_filter_config.clone(),
            );
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L137-171)
```rust
    fn ensure_max_limits(&self, batches: &[Batch<BatchInfoExt>]) -> anyhow::Result<()> {
        let mut total_txns = 0;
        let mut total_bytes = 0;
        for batch in batches.iter() {
            ensure!(
                batch.num_txns() <= self.max_batch_txns,
                "Exceeds batch txn limit {} > {}",
                batch.num_txns(),
                self.max_batch_txns,
            );
            ensure!(
                batch.num_bytes() <= self.max_batch_bytes,
                "Exceeds batch bytes limit {} > {}",
                batch.num_bytes(),
                self.max_batch_bytes,
            );

            total_txns += batch.num_txns();
            total_bytes += batch.num_bytes();
        }
        ensure!(
            total_txns <= self.max_total_txns,
            "Exceeds total txn limit {} > {}",
            total_txns,
            self.max_total_txns,
        );
        ensure!(
            total_bytes <= self.max_total_bytes,
            "Exceeds total bytes limit: {} > {}",
            total_bytes,
            self.max_total_bytes,
        );

        Ok(())
    }
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L178-182)
```rust
        if let Err(e) = self.ensure_max_limits(&batches) {
            error!("Batch from {}: {}", author, e);
            counters::RECEIVED_BATCH_MAX_LIMIT_FAILED.inc();
            return;
        }
```

**File:** consensus/src/quorum_store/batch_generator.rs (L364-372)
```rust
        if pulled_txns.is_empty() {
            counters::PULLED_EMPTY_TXNS_COUNT.inc();
            // Quorum store metrics
            counters::CREATED_EMPTY_BATCHES_COUNT.inc();

            counters::EMPTY_BATCH_CREATION_DURATION
                .observe_duration(self.last_end_batch_time.elapsed());
            self.last_end_batch_time = Instant::now();
            return vec![];
```
