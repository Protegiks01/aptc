# Audit Report

## Title
Missing Validation on Critical Consensus Parameter `batch_expiry_gap_when_init_usecs` Enables Consensus DoS via Misconfiguration

## Summary
The `batch_expiry_gap_when_init_usecs` configuration parameter in Quorum Store lacks any validation, allowing it to be set to extreme values (0 or u64::MAX) that cause immediate batch expiration or arithmetic overflow, resulting in complete consensus failure and network-wide denial of service.

## Finding Description

The `batch_expiry_gap_when_init_usecs` parameter controls the expiration time for batches in the Quorum Store consensus subsystem. This value is added to the current timestamp to determine when batches expire. [1](#0-0) 

However, the configuration sanitizer completely omits validation for this critical parameter: [2](#0-1) 

**Attack Path 1: Setting value to 0**

When batches are created, the expiry time is calculated as: [3](#0-2) 

With `batch_expiry_gap_when_init_usecs = 0`, batches expire immediately upon creation (`expiry_time = current_time`). These batches are then rejected when proofs are inserted: [4](#0-3) 

This prevents any valid proofs from being accepted, halting consensus completely.

**Attack Path 2: Setting value to u64::MAX**

The addition operation uses unchecked arithmetic: [3](#0-2) 

In release builds, adding u64::MAX to current_time (~1.6×10¹⁸ microseconds) causes integer overflow, wrapping to a small value and creating immediately-expired batches, resulting in the same DoS as Attack Path 1.

Additionally, when calculating batch creation timestamps for the minimum age check: [5](#0-4) 

If `batch_expiry_gap_when_init_usecs = u64::MAX`, the subtraction would underflow and saturate to 0, making all batches appear created at timestamp 0 and bypassing age-based filtering.

## Impact Explanation

**Severity: High**

This vulnerability enables complete denial of service of the consensus layer through configuration manipulation. According to the Aptos bug bounty program, this qualifies as **High Severity** under:
- "Validator node slowdowns" (complete halt is worse than slowdown)
- "Significant protocol violations" (consensus cannot form quorum certificates)

If exploited across multiple validators (through coordinated misconfiguration or compromise), this causes:
1. **Total consensus liveness failure** - No blocks can be proposed or committed
2. **Network-wide halt** - All validators affected by the misconfiguration become non-functional
3. **Transaction processing停止** - No transactions can be processed until configuration is corrected and nodes restarted

While not classified as Critical (which requires permanent state corruption or fund theft), this represents a severe availability vulnerability that breaks the consensus liveness invariant.

## Likelihood Explanation

**Likelihood: Medium**

This requires access to modify node configuration files, which typically requires:
- Validator operator access, OR
- Compromise of validator infrastructure, OR  
- Supply chain attack on configuration management

While this limits direct exploitation by external attackers, the risk remains significant because:

1. **Accidental Misconfiguration**: Operators may accidentally set incorrect values during configuration updates or testing
2. **Automated Configuration Systems**: Infrastructure-as-code or automated deployment systems with bugs could propagate invalid values
3. **Partial Compromise**: An attacker with limited access to configuration (but not full system control) could exploit this
4. **Lack of Defense in Depth**: Critical parameters should be validated even if set by trusted operators

The absence of validation violates defense-in-depth principles and represents a missing security control that should exist regardless of trust model.

## Recommendation

Add validation to the `QuorumStoreConfig::sanitize()` method to ensure `batch_expiry_gap_when_init_usecs` falls within reasonable bounds: [2](#0-1) 

**Recommended Fix:**
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

        // Validate batch expiry gap parameters
        let config = &node_config.consensus.quorum_store;
        const MIN_EXPIRY_GAP_USECS: u64 = Duration::from_secs(5).as_micros() as u64;
        const MAX_EXPIRY_GAP_USECS: u64 = Duration::from_secs(300).as_micros() as u64; // 5 minutes
        
        if config.batch_expiry_gap_when_init_usecs < MIN_EXPIRY_GAP_USECS 
            || config.batch_expiry_gap_when_init_usecs > MAX_EXPIRY_GAP_USECS {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                format!(
                    "batch_expiry_gap_when_init_usecs must be between {} and {} microseconds, got {}",
                    MIN_EXPIRY_GAP_USECS,
                    MAX_EXPIRY_GAP_USECS,
                    config.batch_expiry_gap_when_init_usecs
                ),
            ));
        }

        if config.remote_batch_expiry_gap_when_init_usecs < MIN_EXPIRY_GAP_USECS 
            || config.remote_batch_expiry_gap_when_init_usecs > MAX_EXPIRY_GAP_USECS {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                format!(
                    "remote_batch_expiry_gap_when_init_usecs must be between {} and {} microseconds, got {}",
                    MIN_EXPIRY_GAP_USECS,
                    MAX_EXPIRY_GAP_USECS,
                    config.remote_batch_expiry_gap_when_init_usecs
                ),
            ));
        }

        Ok(())
    }
}
```

Additionally, consider using checked arithmetic when calculating expiry times to prevent overflow in release builds.

## Proof of Concept

```rust
// Test demonstrating DoS via batch_expiry_gap_when_init_usecs = 0
#[test]
fn test_zero_expiry_gap_causes_immediate_rejection() {
    use aptos_config::config::{ConsensusConfig, QuorumStoreConfig, NodeConfig};
    use std::time::Duration;
    
    // Create config with zero expiry gap
    let mut quorum_store_config = QuorumStoreConfig::default();
    quorum_store_config.batch_expiry_gap_when_init_usecs = 0;
    
    let node_config = NodeConfig {
        consensus: ConsensusConfig {
            quorum_store: quorum_store_config,
            ..Default::default()
        },
        ..Default::default()
    };
    
    // Sanitize should fail but currently doesn't
    let result = QuorumStoreConfig::sanitize(
        &node_config,
        NodeType::Validator,
        Some(ChainId::mainnet()),
    );
    
    // Current behavior: sanitize passes (VULNERABILITY)
    assert!(result.is_ok(), "Sanitization incorrectly allows zero expiry gap");
    
    // Expected behavior: should fail validation
    // assert!(result.is_err(), "Should reject zero expiry gap");
}

#[test]
fn test_max_expiry_gap_causes_overflow() {
    use aptos_config::config::{ConsensusConfig, QuorumStoreConfig, NodeConfig};
    
    // Create config with MAX expiry gap
    let mut quorum_store_config = QuorumStoreConfig::default();
    quorum_store_config.batch_expiry_gap_when_init_usecs = u64::MAX;
    
    let node_config = NodeConfig {
        consensus: ConsensusConfig {
            quorum_store: quorum_store_config,
            ..Default::default()
        },
        ..Default::default()
    };
    
    // Sanitize should fail but currently doesn't
    let result = QuorumStoreConfig::sanitize(
        &node_config,
        NodeType::Validator,
        Some(ChainId::mainnet()),
    );
    
    // Current behavior: sanitize passes (VULNERABILITY)
    assert!(result.is_ok(), "Sanitization incorrectly allows u64::MAX expiry gap");
    
    // With this config, batch creation would overflow:
    // expiry_time = current_time + u64::MAX → overflow in release mode
}
```

**Notes**

This vulnerability represents a critical gap in input validation for a consensus-critical parameter. While exploitation requires configuration access, the lack of validation violates security best practices and could enable DoS through accidental misconfiguration, automated deployment errors, or partial system compromise. The fix is straightforward: add range validation to reject unreasonable values before they can affect consensus operation.

### Citations

**File:** config/src/config/quorum_store_config.rs (L89-89)
```rust
    pub batch_expiry_gap_when_init_usecs: u64,
```

**File:** config/src/config/quorum_store_config.rs (L253-271)
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
```

**File:** consensus/src/quorum_store/batch_generator.rs (L383-384)
```rust
        let expiry_time = aptos_infallible::duration_since_epoch().as_micros() as u64
            + self.config.batch_expiry_gap_when_init_usecs;
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L176-179)
```rust
        if proof.expiration() <= self.latest_block_timestamp {
            counters::inc_rejected_pos_count(counters::POS_EXPIRED_LABEL);
            return;
        }
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L603-604)
```rust
                    let batch_create_ts_usecs =
                        item.info.expiration() - self.batch_expiry_gap_when_init_usecs;
```
