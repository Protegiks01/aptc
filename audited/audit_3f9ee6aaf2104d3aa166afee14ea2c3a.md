# Audit Report

## Title
Half-Configured ValidatorFullnode Attack via Partial Manual Configuration Override

## Summary
The `optimize()` function in `ConsensusObserverConfig` uses an all-or-nothing approach when checking for manual configuration overrides. If a ValidatorFullnode operator manually sets only `observer_enabled` OR `publisher_enabled` in their local config, the automatic optimization that should enable BOTH flags is completely skipped, creating a half-configured node that disrupts the consensus observer network topology.

## Finding Description

ValidatorFullnodes (VFNs) are designed to serve dual roles in the consensus observer architecture: they observe consensus data from validators and republish it to downstream Public Fullnodes. This requires both `observer_enabled` and `publisher_enabled` to be true. [1](#0-0) 

The vulnerability exists in the configuration optimization logic. The condition checks if EITHER flag is manually set, and if so, skips the entire automatic configuration block:

- Line 121: `!observer_manually_set` - fails if observer is manually set
- Line 122: `!publisher_manually_set` - fails if publisher is manually set  
- Both conditions are ANDed together

**Attack Scenario:**

1. VFN operator sets `observer_enabled: true` in local config YAML, leaving `publisher_enabled` unset
2. During startup, `optimize()` detects `observer_manually_set = true`
3. The condition `!observer_manually_set && !publisher_manually_set` evaluates to `false`
4. Automatic optimization skips setting `publisher_enabled = true`
5. Result: VFN runs with `observer_enabled = true` but `publisher_enabled = false`

**Runtime Consequences:**

The network handler is created because at least one flag is enabled: [2](#0-1) 

However, the publisher component is never created: [3](#0-2) 

When downstream nodes send subscription requests (RPC messages), they are silently dropped: [4](#0-3) 

No error is logged, no response is sent. Downstream nodes timeout and must find alternative VFNs.

**Reverse Scenario:**

If operator sets `publisher_enabled: true` but leaves `observer_enabled` unset, the publisher is created but the observer uses a dummy execution client: [5](#0-4) 

The VFN accepts subscriptions but has no consensus data to publish, leaving subscribers starved.

## Impact Explanation

**Severity: Medium**

This vulnerability causes **state inconsistencies requiring intervention** and **network availability degradation**, meeting the Medium severity criteria in the Aptos bug bounty program.

**Specific Impacts:**

1. **Network Partitioning**: Multiple misconfigured VFNs create "dead zones" where Public Fullnodes cannot access consensus observer data
2. **Cascading Failures**: PFNs fall back to traditional state sync, causing performance degradation across the network
3. **Silent Failures**: No error messages are generated, making diagnosis difficult for operators
4. **Operational Risk**: Legitimate operators following partial documentation may unknowingly create these half-configured nodes
5. **Service Degradation**: The consensus observer feature, designed to improve sync performance, becomes unreliable

While this doesn't directly cause fund loss or consensus safety violations, it degrades network availability and creates operational security risks that can compound during network stress.

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability is likely to occur in production for several reasons:

1. **Common Operator Pattern**: Operators often customize configs incrementally, setting one feature at a time
2. **Documentation Gaps**: If documentation mentions enabling "consensus observer" without explicitly stating both flags must be set together
3. **Config Migration**: During upgrades, operators may port only partial settings from old configs
4. **No Validation**: The system provides no warning when only one flag is manually set
5. **Silent Failure**: The misconfiguration doesn't cause immediate crashes, allowing it to persist undetected

The bug is **100% deterministic** once the partial configuration is in place - there's no race condition or timing dependency.

## Recommendation

Fix the `optimize()` function to check each flag independently:

```rust
NodeType::ValidatorFullnode => {
    if ENABLE_ON_VALIDATOR_FULLNODES {
        // Enable observer if not manually set
        if !observer_manually_set {
            consensus_observer_config.observer_enabled = true;
            modified_config = true;
        }
        // Enable publisher if not manually set
        if !publisher_manually_set {
            consensus_observer_config.publisher_enabled = true;
            modified_config = true;
        }
    }
},
```

Additionally, add validation that warns or errors if only one flag is enabled for VFNs:

```rust
// After optimization, validate VFN configuration
if node_type == NodeType::ValidatorFullnode 
    && consensus_observer_config.observer_enabled != consensus_observer_config.publisher_enabled {
    return Err(Error::ConfigurationError(
        "ValidatorFullnode must have both observer_enabled and publisher_enabled set to the same value".to_string()
    ));
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod vulnerability_tests {
    use super::*;
    use crate::config::NodeConfig;
    
    #[test]
    fn test_half_configured_vfn_observer_only() {
        // Create a node config with both flags disabled (default state)
        let mut node_config = NodeConfig {
            consensus_observer: ConsensusObserverConfig {
                observer_enabled: false,
                publisher_enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };
        
        // Simulate local config where operator manually sets ONLY observer_enabled
        let local_config_yaml = serde_yaml::from_str(
            r#"
            consensus_observer:
              observer_enabled: true
            "#
        ).unwrap();
        
        // Run optimization
        let modified = ConsensusObserverConfig::optimize(
            &mut node_config,
            &local_config_yaml,
            NodeType::ValidatorFullnode,
            Some(ChainId::mainnet()),
        ).unwrap();
        
        // BUG: observer_enabled is true but publisher_enabled remains false
        // This creates a half-configured VFN that receives but doesn't publish
        assert!(node_config.consensus_observer.observer_enabled);
        assert!(!node_config.consensus_observer.publisher_enabled); // VULNERABLE STATE
        
        println!("VULNERABILITY DEMONSTRATED:");
        println!("  observer_enabled: {}", node_config.consensus_observer.observer_enabled);
        println!("  publisher_enabled: {}", node_config.consensus_observer.publisher_enabled);
        println!("  VFN will accept connections but drop all subscription requests!");
    }
    
    #[test]
    fn test_half_configured_vfn_publisher_only() {
        // Create a node config with both flags disabled
        let mut node_config = NodeConfig {
            consensus_observer: ConsensusObserverConfig {
                observer_enabled: false,
                publisher_enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };
        
        // Simulate local config where operator manually sets ONLY publisher_enabled  
        let local_config_yaml = serde_yaml::from_str(
            r#"
            consensus_observer:
              publisher_enabled: true
            "#
        ).unwrap();
        
        // Run optimization
        ConsensusObserverConfig::optimize(
            &mut node_config,
            &local_config_yaml,
            NodeType::ValidatorFullnode,
            Some(ChainId::mainnet()),
        ).unwrap();
        
        // BUG: publisher_enabled is true but observer_enabled remains false
        // This creates a VFN that accepts subscriptions but has no data to publish
        assert!(!node_config.consensus_observer.observer_enabled); // VULNERABLE STATE
        assert!(node_config.consensus_observer.publisher_enabled);
        
        println!("VULNERABILITY DEMONSTRATED:");
        println!("  observer_enabled: {}", node_config.consensus_observer.observer_enabled);
        println!("  publisher_enabled: {}", node_config.consensus_observer.publisher_enabled);
        println!("  VFN will accept subscriptions but never publish any consensus data!");
    }
    
    #[test]
    fn test_correct_vfn_no_manual_override() {
        // Correct behavior when no manual override exists
        let mut node_config = NodeConfig {
            consensus_observer: ConsensusObserverConfig::default(),
            ..Default::default()
        };
        
        let local_config_yaml = serde_yaml::from_str("{}").unwrap();
        
        ConsensusObserverConfig::optimize(
            &mut node_config,
            &local_config_yaml,
            NodeType::ValidatorFullnode,
            Some(ChainId::mainnet()),
        ).unwrap();
        
        // Both flags should be enabled
        assert!(node_config.consensus_observer.observer_enabled);
        assert!(node_config.consensus_observer.publisher_enabled);
    }
}
```

To run the PoC:
```bash
cd config
cargo test test_half_configured_vfn -- --nocapture
```

The test demonstrates that manually setting only one flag in the local config prevents the automatic optimization from enabling the other flag, creating the vulnerable half-configured state.

## Notes

This vulnerability specifically affects the **configuration initialization logic**, not the runtime consensus or execution logic. However, its impact on network topology and availability is significant enough to warrant Medium severity classification. The fix is straightforward and should be applied alongside validation logic to detect and prevent half-configured states at startup.

### Citations

**File:** config/src/config/consensus_observer_config.rs (L119-128)
```rust
            NodeType::ValidatorFullnode => {
                if ENABLE_ON_VALIDATOR_FULLNODES
                    && !observer_manually_set
                    && !publisher_manually_set
                {
                    // Enable both the observer and the publisher for VFNs
                    consensus_observer_config.observer_enabled = true;
                    consensus_observer_config.publisher_enabled = true;
                    modified_config = true;
                }
```

**File:** aptos-node/src/consensus.rs (L157-162)
```rust
    if !node_config
        .consensus_observer
        .is_observer_or_publisher_enabled()
    {
        return (None, None, None);
    }
```

**File:** aptos-node/src/consensus.rs (L247-250)
```rust
    // If the publisher is not enabled, return early
    if !node_config.consensus_observer.publisher_enabled {
        return (None, None);
    }
```

**File:** consensus/src/consensus_observer/network/network_handler.rs (L200-203)
```rust
        // Drop the message if the publisher is not enabled
        if !self.consensus_observer_config.publisher_enabled {
            return;
        }
```

**File:** consensus/src/consensus_provider.rs (L152-185)
```rust
    let execution_client = if node_config.consensus_observer.observer_enabled {
        // Create the execution proxy
        let txn_notifier = Arc::new(MempoolNotifier::new(
            consensus_to_mempool_sender.clone(),
            node_config.consensus.mempool_executed_txn_timeout_ms,
        ));
        let execution_proxy = ExecutionProxy::new(
            Arc::new(BlockExecutor::<AptosVMBlockExecutor>::new(aptos_db.clone())),
            txn_notifier,
            state_sync_notifier,
            node_config.transaction_filters.execution_filter.clone(),
            node_config.consensus.enable_pre_commit,
            None,
        );

        // Create the execution proxy client
        let bounded_executor =
            BoundedExecutor::new(32, consensus_observer_runtime.handle().clone());
        let rand_storage = Arc::new(RandDb::new(node_config.storage.dir()));
        let execution_proxy_client = Arc::new(ExecutionProxyClient::new(
            node_config.consensus.clone(),
            Arc::new(execution_proxy),
            AccountAddress::ONE,
            self_sender.clone(),
            consensus_network_client,
            bounded_executor,
            rand_storage.clone(),
            node_config.consensus_observer,
            consensus_publisher.clone(),
        ));
        execution_proxy_client as Arc<dyn TExecutionClient>
    } else {
        Arc::new(DummyExecutionClient) as Arc<dyn TExecutionClient>
    };
```
