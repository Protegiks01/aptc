# Audit Report

## Title
Metric-State Divergence in Indexer GRPC Manager Due to Semantic Mismatch Between Atomic Update and Metric Set

## Summary
The `update_known_latest_version()` function in the indexer-grpc-manager uses a conditional atomic operation (`fetch_max`) but an unconditional metric update (`set`), causing the Prometheus metric to diverge from actual state when out-of-order version updates arrive.

## Finding Description

The vulnerability exists in the `update_known_latest_version()` function where there is a semantic mismatch between the atomic state update and the metric update. [1](#0-0) 

The issue arises because:

1. **`fetch_max()` is conditional**: It only updates `known_latest_version` if the new value is greater than the current value (line 406-407)
2. **`set()` is unconditional**: It always sets the `KNOWN_LATEST_VERSION` metric to the provided value (line 408)

In a distributed indexer system with multiple fullnodes reporting versions concurrently, messages can arrive out of order. When this happens:

**Attack Scenario:**
1. Initial state: atomic = 0, metric = 0
2. Fullnode A reports version 200 → atomic = 200, metric = 200 ✓
3. Delayed message from Fullnode B arrives with version 150 (network delay/reordering)
4. `fetch_max(150)` sees 150 < 200, does NOT update atomic (stays at 200)
5. `set(150)` unconditionally sets metric to 150
6. **Final state: atomic = 200, metric = 150 ✗ DIVERGENCE**

The function is called when processing fullnode heartbeats: [2](#0-1) 

The atomic value remains correct (monotonically increasing), but the Prometheus metric regresses, breaking monitoring invariants.

## Impact Explanation

This issue is classified as **Low Severity** per the Aptos bug bounty program for the following reasons:

- **No Consensus Impact**: The indexer-grpc-manager is not part of the consensus layer
- **No Funds at Risk**: This is a monitoring/observability issue only
- **No State Corruption**: The actual application state (`known_latest_version` atomic) remains correct
- **Monitoring Impact Only**: Only affects Prometheus metrics exported for operational dashboards

The impact is limited to:
- Incorrect metrics displayed in monitoring dashboards
- Potential operational confusion when metrics show lower values than reality
- Misleading alerts based on the incorrect metric

Per the bug bounty categories, this falls under "Low Severity (up to $1,000): Non-critical implementation bugs."

## Likelihood Explanation

This issue has **HIGH likelihood** of occurring in production environments because:

1. **Natural in Distributed Systems**: Out-of-order message arrival is common with multiple fullnodes reporting concurrently
2. **No Attacker Required**: This happens naturally due to network delays, retries, and concurrent processing
3. **Continuous Operation**: The metadata manager runs in a continuous loop, constantly processing updates from multiple sources
4. **Already Demonstrated**: The fact that the code uses `fetch_max()` suggests the developers were aware of out-of-order updates but didn't apply the same logic to metrics

The divergence will occur whenever:
- Network latency causes message reordering between fullnodes
- A fullnode reconnects and sends slightly stale data
- Multiple fullnodes report in quick succession with varying staleness

## Recommendation

The fix is to make the metric update conditional, matching the atomic update logic. Replace the unconditional `set()` with a conditional update that only sets the metric if the new value is actually greater:

```rust
fn update_known_latest_version(&self, version: u64) {
    let old_version = self.known_latest_version.fetch_max(version, Ordering::SeqCst);
    // Only update metric if we actually increased the known version
    if version > old_version {
        KNOWN_LATEST_VERSION.set(version as i64);
    }
}
```

Alternatively, update the metric based on the actual current value after the atomic operation:

```rust
fn update_known_latest_version(&self, version: u64) {
    self.known_latest_version.fetch_max(version, Ordering::SeqCst);
    // Always set metric to the current actual value
    let current = self.known_latest_version.load(Ordering::SeqCst);
    KNOWN_LATEST_VERSION.set(current as i64);
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    
    #[test]
    fn test_metric_divergence_on_out_of_order_updates() {
        // Setup: Create metadata manager
        let manager = Arc::new(MetadataManager::new(
            1, // chain_id
            "test:50051".to_string(),
            vec![],
            vec![],
            None,
        ));
        
        // Step 1: Update with version 200
        manager.update_known_latest_version(200);
        assert_eq!(manager.get_known_latest_version(), 200);
        assert_eq!(KNOWN_LATEST_VERSION.get(), 200);
        
        // Step 2: Simulate out-of-order message with version 150
        manager.update_known_latest_version(150);
        
        // BUG: Atomic state is correct (still 200)
        assert_eq!(manager.get_known_latest_version(), 200);
        
        // BUG: But metric has regressed to 150 (DIVERGENCE!)
        assert_eq!(KNOWN_LATEST_VERSION.get(), 150);
        
        // This demonstrates that metrics no longer reflect actual state
        assert_ne!(
            manager.get_known_latest_version() as i64,
            KNOWN_LATEST_VERSION.get()
        );
    }
}
```

## Notes

While this is a genuine implementation bug that causes observable incorrect behavior, it meets the **Low Severity** classification because:

1. It affects only monitoring/observability, not core blockchain functionality
2. The actual application state remains correct and monotonic
3. No security-critical operations depend on the metric value
4. The indexer-grpc-manager is infrastructure code, not consensus or execution layer

The question's framing about "`set()` failing" is somewhat misleading—`IntGauge::set()` doesn't return a `Result` and cannot fail in the conventional sense. The actual bug is the **semantic mismatch** between conditional atomic update and unconditional metric update, which causes divergence through normal distributed system behavior rather than any failure condition.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L405-409)
```rust
    fn update_known_latest_version(&self, version: u64) {
        self.known_latest_version
            .fetch_max(version, Ordering::SeqCst);
        KNOWN_LATEST_VERSION.set(version as i64);
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L533-544)
```rust
    fn handle_fullnode_info(&self, address: GrpcAddress, info: FullnodeInfo) -> Result<()> {
        let mut entry = self
            .fullnodes
            .entry(address.clone())
            .or_insert(Fullnode::new(address.clone()));
        entry.value_mut().recent_states.push_back(info);
        if let Some(known_latest_version) = info.known_latest_version {
            trace!(
                "Received known_latest_version ({known_latest_version}) from fullnode {address}."
            );
            self.update_known_latest_version(known_latest_version);
        }
```
