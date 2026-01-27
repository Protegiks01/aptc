# Audit Report

## Title
Quorum Store Backpressure Mechanism Inverted by Infinity/NaN Values in decrease_fraction Config Parameter

## Summary
The `decrease_fraction` configuration parameter in `QuorumStoreBackPressureConfig` accepts IEEE 754 special floating-point values (NaN, Infinity, -Infinity) through YAML deserialization without validation, causing the backpressure mechanism to invert its behavior. When set to Infinity, the system increases transaction pull rate to maximum during stress conditions instead of decreasing it, potentially causing validator node crashes or severe consensus slowdowns.

## Finding Description
The Quorum Store backpressure system is designed to protect consensus validators from being overwhelmed by transactions. When transaction backlog exceeds thresholds, the system should multiplicatively decrease the rate at which it pulls transactions from mempool. [1](#0-0) 

The `decrease_fraction` field is defined as an f64 with a default value of 0.5, intended to halve the transaction pull rate during backpressure. However, this field has no validation during config sanitization: [2](#0-1) 

The sanitize function only validates send/recv batch limits and batch/total limits, but completely ignores the `QuorumStoreBackPressureConfig` fields.

YAML configs are deserialized using serde_yaml, which supports IEEE 754 special values: [3](#0-2) 

A malicious config file with `.inf` (YAML 1.2 syntax for infinity) would successfully deserialize into `f64::INFINITY`.

The vulnerable calculation occurs in the batch generator's main loop: [4](#0-3) 

**Attack Scenario with Infinity:**

1. Attacker provides config: `decrease_fraction: .inf`
2. Initial `dynamic_pull_txn_per_s = 6000` (midpoint between min/max)
3. When backpressure activates (system under stress):
   - Calculation: `6000.0 * f64::INFINITY = f64::INFINITY`
   - Cast to u64: `f64::INFINITY as u64 = u64::MAX` (Rust's saturating conversion)
   - `max(u64::MAX, 160) = u64::MAX`
4. The transaction pull rate becomes u64::MAX instead of decreasing
5. This inverts the backpressure logic: the system pulls maximum transactions when it should reduce load

The rate is then used to calculate transaction pulls: [5](#0-4) 

While the final pull is clamped to `sender_max_total_txns` (1500), the backpressure mechanism is completely broken - it continuously pulls at maximum rate even under stress, defeating the purpose of backpressure protection.

## Impact Explanation
**High Severity** - This vulnerability causes:

1. **Backpressure Mechanism Failure**: The critical safety mechanism that protects validators from overload is inverted, causing maximum load during stress conditions
2. **Validator Node Slowdowns**: Continuous max-rate transaction pulling can exhaust memory and CPU resources
3. **Consensus Impact**: Affected validators may fall behind, miss voting deadlines, or crash, impacting consensus liveness
4. **Metrics Corruption**: Backpressure metrics report u64::MAX values, making monitoring useless

This qualifies as High Severity per Aptos bug bounty criteria: "Validator node slowdowns" and "Significant protocol violations."

## Likelihood Explanation
**Low-Medium Likelihood** - Exploitation requires:

1. **Filesystem Access**: Attacker must modify the validator node's config file, requiring:
   - Validator operator with malicious intent (insider threat)
   - Compromised validator node with filesystem access
   - Supply chain attack on config deployment
   
2. **Config Reload**: The node must load the malicious config (startup or reload)

While the attack complexity is low once access is obtained, the requirement for filesystem access significantly limits the attack surface. However, misconfigurations or insider threats are realistic scenarios in blockchain operations.

## Recommendation
Add validation for the `QuorumStoreBackPressureConfig` fields in the sanitize function. The fix should:

1. Check that `decrease_fraction` is a normal finite value between 0 and 1
2. Validate other f64 fields in the config
3. Reject configs with NaN, Infinity, or out-of-range values

Add to `config/src/config/quorum_store_config.rs`:

```rust
impl ConfigSanitizer for QuorumStoreConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        
        // Validate QuorumStoreBackPressureConfig fields
        let bp = &node_config.consensus.quorum_store.back_pressure;
        
        if !bp.decrease_fraction.is_finite() || bp.decrease_fraction <= 0.0 || bp.decrease_fraction > 1.0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name.clone(),
                format!("decrease_fraction must be finite and in range (0, 1], got: {}", bp.decrease_fraction),
            ));
        }

        // Existing validations...
        Self::sanitize_send_recv_batch_limits(&sanitizer_name, &node_config.consensus.quorum_store)?;
        Self::sanitize_batch_total_limits(&sanitizer_name, &node_config.consensus.quorum_store)?;

        Ok(())
    }
}
```

## Proof of Concept

Create a malicious config file `malicious_config.yaml`:

```yaml
consensus:
  quorum_store:
    back_pressure:
      decrease_fraction: .inf
```

Rust test to demonstrate the vulnerability:

```rust
#[test]
fn test_infinity_decrease_fraction_breaks_backpressure() {
    use crate::config::{NodeConfig, PersistableConfig};
    use std::fs::write;
    use tempfile::tempdir;
    
    // Create malicious config
    let malicious_yaml = r#"
consensus:
  quorum_store:
    back_pressure:
      decrease_fraction: .inf
"#;
    
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");
    write(&config_path, malicious_yaml).unwrap();
    
    // Load config - no error because validation is missing
    let config = NodeConfig::load_config(&config_path).unwrap();
    
    // Verify infinity was deserialized
    assert!(config.consensus.quorum_store.back_pressure.decrease_fraction.is_infinite());
    
    // Simulate backpressure calculation
    let mut dynamic_pull_txn_per_s = 6000_u64;
    let decrease_fraction = config.consensus.quorum_store.back_pressure.decrease_fraction;
    let dynamic_min = config.consensus.quorum_store.back_pressure.dynamic_min_txn_per_s;
    
    // This is what happens in batch_generator.rs line 438-441
    dynamic_pull_txn_per_s = std::cmp::max(
        (dynamic_pull_txn_per_s as f64 * decrease_fraction) as u64,
        dynamic_min,
    );
    
    // Instead of decreasing to ~3000, it becomes u64::MAX
    assert_eq!(dynamic_pull_txn_per_s, u64::MAX);
    println!("Backpressure inverted: rate = {} (should be ~3000)", dynamic_pull_txn_per_s);
}
```

**Notes:**
- This vulnerability requires insider access or compromised node to exploit
- The question explicitly mentions "malicious config files", indicating insider threat scenarios are in scope
- While external attackers cannot directly exploit this, it represents a significant configuration security gap
- Defense-in-depth principles suggest all config inputs should be validated regardless of access requirements

### Citations

**File:** config/src/config/quorum_store_config.rs (L16-27)
```rust
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct QuorumStoreBackPressureConfig {
    pub backlog_txn_limit_count: u64,
    pub backlog_per_validator_batch_limit_count: u64,
    pub decrease_duration_ms: u64,
    pub increase_duration_ms: u64,
    pub decrease_fraction: f64,
    pub dynamic_min_txn_per_s: u64,
    pub dynamic_max_txn_per_s: u64,
    pub additive_increase_when_no_backpressure: u64,
}
```

**File:** config/src/config/quorum_store_config.rs (L253-272)
```rust
impl ConfigSanitizer for QuorumStoreConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();

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

**File:** config/src/config/persistable_config.rs (L52-55)
```rust
    /// Parse the config from the serialized string
    fn parse_serialized_config(serialized_config: &str) -> Result<Self, Error> {
        serde_yaml::from_str(serialized_config).map_err(|e| Error::Yaml("config".to_string(), e))
    }
```

**File:** consensus/src/quorum_store/batch_generator.rs (L434-446)
```rust
                    if self.back_pressure.txn_count {
                        // multiplicative decrease, every second
                        if back_pressure_decrease_latest.elapsed() >= back_pressure_decrease_duration {
                            back_pressure_decrease_latest = tick_start;
                            dynamic_pull_txn_per_s = std::cmp::max(
                                (dynamic_pull_txn_per_s as f64 * self.config.back_pressure.decrease_fraction) as u64,
                                self.config.back_pressure.dynamic_min_txn_per_s,
                            );
                            trace!("QS: dynamic_max_pull_txn_per_s: {}", dynamic_pull_txn_per_s);
                        }
                        counters::QS_BACKPRESSURE_TXN_COUNT.observe(1.0);
                        counters::QS_BACKPRESSURE_MAKE_STRICTER_TXN_COUNT.observe(1.0);
                        counters::QS_BACKPRESSURE_DYNAMIC_MAX.observe(dynamic_pull_txn_per_s as f64);
```

**File:** consensus/src/quorum_store/batch_generator.rs (L476-482)
```rust
                        let dynamic_pull_max_txn = std::cmp::max(
                            (since_last_non_empty_pull_ms as f64 / 1000.0 * dynamic_pull_txn_per_s as f64) as u64, 1);
                        let pull_max_txn = std::cmp::min(
                            dynamic_pull_max_txn,
                            self.config.sender_max_total_txns as u64,
                        );
                        let batches = self.handle_scheduled_pull(pull_max_txn).await;
```
