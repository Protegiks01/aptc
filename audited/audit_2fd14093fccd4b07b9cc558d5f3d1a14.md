# Audit Report

## Title
Auto-Bootstrapping Network Partition Vulnerability in Multi-Validator Deployments

## Summary
The `check_auto_bootstrapping()` function in the state sync driver allows validators with genesis waypoints to bypass state synchronization and mark themselves as bootstrapped after a connection deadline expires. When multiple validators in a multi-validator network are identically misconfigured with auto-bootstrapping enabled, they can independently bootstrap at genesis without syncing state, creating irreconcilable network partitions that violate consensus safety guarantees.

## Finding Description

The auto-bootstrapping feature is designed for single-node test deployments but contains no runtime enforcement preventing its use in multi-validator production networks. The vulnerability exists in the interaction between configuration validation and runtime behavior. [1](#0-0) 

The function checks only four conditions before auto-bootstrapping:
1. Node is not already bootstrapped
2. Consensus or observer is enabled (validator role)
3. `enable_auto_bootstrapping` config is true
4. Waypoint version equals 0 (genesis)

When the connection deadline passes without peer connectivity, the node marks itself as bootstrapped without any state synchronization. [2](#0-1) 

The trigger condition is an empty global data summary (no active peers). In a network partition scenario, this condition is met legitimately, causing the auto-bootstrap to activate. [3](#0-2) 

When `bootstrapping_complete()` is called, the node is marked as ready for consensus participation. Once bootstrapped, consensus can execute: [4](#0-3) 

**Attack Scenario:**

1. **Misconfiguration**: Multiple validators (2f+1 or more) in a production network are configured with:
   - `enable_auto_bootstrapping = true` 
   - Genesis waypoint (`version = 0`) [5](#0-4) 

2. **Network Partition**: Validators are partitioned into separate groups unable to communicate (network isolation, firewall issues, or deliberate attack).

3. **Independent Bootstrapping**: After 10 seconds (default `max_connection_deadline_secs`), each partition independently auto-bootstraps at genesis. [6](#0-5) 

4. **Fork Creation**: Each partition starts consensus from epoch 0, version 0, building separate chains with different transaction histories and state roots.

5. **Irreconcilable States**: When partitions reconnect, they cannot reconcile because:
   - Different blocks committed at same heights
   - Different state roots for same versions
   - No common checkpoint beyond genesis
   - Epoch states diverged independently

**Why Safety Rules Don't Prevent This:**

The consensus safety rules verify epoch change proofs against waypoints, but when all validators start from genesis with identical genesis state, they satisfy these checks locally within each partition. [7](#0-6) 

Each partition forms a valid consensus group with >2f+1 validators (if configured), satisfying BFT quorum requirements **within the partition**, but violating global consensus safety across the network.

## Impact Explanation

**Severity: Critical** (up to $1,000,000 per Aptos Bug Bounty)

This vulnerability causes:

1. **Non-Recoverable Network Partition**: Multiple incompatible chains emerge from the same genesis, with no automatic reconciliation path. This requires a hard fork to resolve.

2. **Consensus Safety Violation**: The fundamental BFT guarantee that honest validators agree on committed blocks is violated. Different validators commit different blocks at the same height.

3. **State Inconsistency**: Validators compute different state roots for identical version numbers, breaking the Merkle tree verification guarantees.

4. **Total Loss of Network Integrity**: The blockchain forks permanently, destroying trust in the network's canonical state.

The impact meets the Critical category: "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation

**Likelihood: Low to Medium** (requires specific conditions)

**Required Conditions:**
1. Multiple validators misconfigured with `enable_auto_bootstrapping = true` (default is false)
2. Validators using genesis waypoint (version 0) in production
3. Network partition lasting >10 seconds
4. Sufficient validators in each partition to form quorum (>2f+1)

**Mitigating Factors:**
- Feature is disabled by default [8](#0-7) 

- Sanitizer prevents use with fast sync mode [9](#0-8) 

- Production validators should never use genesis waypoints
- Requires operator error or malicious insider

**Aggravating Factors:**
- No runtime enforcement preventing multi-validator use
- Comment suggests single-node use but no code enforcement
- Configuration is easily replicable across validators
- Network partitions can occur due to infrastructure failures

The vulnerability is exploitable in disaster recovery scenarios, infrastructure failures, or during coordinated validator deployments with template configurations.

## Recommendation

**Immediate Fix**: Add runtime validation to prevent auto-bootstrapping in multi-validator networks.

```rust
async fn check_auto_bootstrapping(&mut self) {
    if !self.bootstrapper.is_bootstrapped()
        && self.is_consensus_or_observer_enabled()
        && self.driver_configuration.config.enable_auto_bootstrapping
        && self.driver_configuration.waypoint.version() == 0
    {
        // NEW: Verify this is truly a single-node deployment
        if self.is_multi_validator_network() {
            error!(LogSchema::new(LogEntry::AutoBootstrapping).message(
                "Auto-bootstrapping is disabled in multi-validator networks! \
                This feature is only for single-node test deployments. \
                Please configure a proper waypoint for production use."
            ));
            return;
        }
        
        // Existing deadline check...
    }
}

fn is_multi_validator_network(&self) -> bool {
    // Check if multiple validators are configured in genesis
    // or if the network expects >1 validator
    if let Ok(epoch_state) = utils::fetch_latest_epoch_state(self.storage.clone()) {
        return epoch_state.verifier.len() > 1;
    }
    false
}
```

**Additional Recommendations:**

1. **Configuration Validation**: Enhance the sanitizer to reject genesis waypoints when node role is Validator and network is not a local test environment.

2. **Warning Logs**: Add prominent warnings when auto-bootstrapping is enabled on validator nodes.

3. **Documentation**: Update deployment guides to explicitly warn against using auto-bootstrapping in production.

4. **Metrics**: Add metrics to track auto-bootstrap triggers for monitoring and alerting.

## Proof of Concept

```rust
// Test demonstrating network partition via auto-bootstrapping
#[tokio::test]
async fn test_auto_bootstrap_network_partition() {
    // Setup: Create 4 validators with auto-bootstrapping enabled
    let mut validators = Vec::new();
    for i in 0..4 {
        let mut config = NodeConfig::default();
        config.base.role = RoleType::Validator;
        
        // MISCONFIGURATION: Enable auto-bootstrapping
        config.state_sync.state_sync_driver.enable_auto_bootstrapping = true;
        config.state_sync.state_sync_driver.max_connection_deadline_secs = 1;
        
        // MISCONFIGURATION: Genesis waypoint
        let waypoint = Waypoint::new_any(&create_genesis_ledger_info());
        assert_eq!(waypoint.version(), 0); // Genesis waypoint
        
        validators.push(create_validator_with_config(config, waypoint));
    }
    
    // Partition: Split into two groups [0,1] and [2,3]
    // Each group has no connectivity to the other
    partition_network(&mut validators, vec![vec![0, 1], vec![2, 3]]);
    
    // Wait for auto-bootstrap deadline
    tokio::time::sleep(Duration::from_secs(2)).await;
    
    // Verify: Both partitions are bootstrapped independently
    for validator in &validators {
        assert!(validator.is_bootstrapped());
    }
    
    // Attack: Each partition starts consensus and proposes blocks
    let block_v0_partition1 = validators[0].propose_block(1).await;
    let block_v0_partition2 = validators[2].propose_block(1).await;
    
    // VULNERABILITY: Different blocks at same version
    assert_ne!(
        block_v0_partition1.id(),
        block_v0_partition2.id(),
        "Network partition created divergent chains!"
    );
    
    // Each partition commits different blocks
    validators[0].commit_block(block_v0_partition1.clone()).await;
    validators[1].commit_block(block_v0_partition1).await;
    
    validators[2].commit_block(block_v0_partition2.clone()).await;
    validators[3].commit_block(block_v0_partition2).await;
    
    // IMPACT: When network heals, irreconcilable fork exists
    restore_network(&mut validators);
    
    // Validators cannot sync - different state roots at version 1
    assert_ne!(
        validators[0].get_state_root(1),
        validators[2].get_state_root(1)
    );
    
    // Network partition is permanent without hard fork
}
```

## Notes

The vulnerability exploits the gap between the feature's intended use ("single node deployments") and the actual code enforcement. While disabled by default and documented as test-only, no runtime checks prevent production misuse in multi-validator scenarios. The combination of configuration flexibility and network partition resilience creates a critical consensus safety vulnerability when validators are identically misconfigured.

### Citations

**File:** state-sync/state-sync-driver/src/driver.rs (L625-630)
```rust
    /// Returns true iff consensus or consensus observer is currently executing
    fn check_if_consensus_or_observer_executing(&self) -> bool {
        self.is_consensus_or_observer_enabled()
            && self.bootstrapper.is_bootstrapped()
            && !self.active_sync_request()
    }
```

**File:** state-sync/state-sync-driver/src/driver.rs (L636-664)
```rust
    async fn check_auto_bootstrapping(&mut self) {
        if !self.bootstrapper.is_bootstrapped()
            && self.is_consensus_or_observer_enabled()
            && self.driver_configuration.config.enable_auto_bootstrapping
            && self.driver_configuration.waypoint.version() == 0
        {
            if let Some(start_time) = self.start_time {
                if let Some(connection_deadline) = start_time.checked_add(Duration::from_secs(
                    self.driver_configuration
                        .config
                        .max_connection_deadline_secs,
                )) {
                    if self.time_service.now() >= connection_deadline {
                        info!(LogSchema::new(LogEntry::AutoBootstrapping).message(
                            "Passed the connection deadline! Auto-bootstrapping the validator!"
                        ));
                        if let Err(error) = self.bootstrapper.bootstrapping_complete().await {
                            warn!(LogSchema::new(LogEntry::AutoBootstrapping)
                                .error(&error)
                                .message("Failed to mark bootstrapping as complete!"));
                        }
                    }
                } else {
                    warn!(LogSchema::new(LogEntry::AutoBootstrapping)
                        .message("The connection deadline overflowed! Unable to auto-bootstrap!"));
                }
            }
        }
    }
```

**File:** state-sync/state-sync-driver/src/driver.rs (L672-678)
```rust
        let global_data_summary = self.aptos_data_client.get_global_data_summary();
        if global_data_summary.is_empty() {
            trace!(LogSchema::new(LogEntry::Driver).message(
                "The global data summary is empty! It's likely that we have no active peers."
            ));
            return self.check_auto_bootstrapping().await;
        }
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L373-378)
```rust
    pub async fn bootstrapping_complete(&mut self) -> Result<(), Error> {
        info!(LogSchema::new(LogEntry::Bootstrapper)
            .message("The node has successfully bootstrapped!"));
        self.bootstrapped = true;
        self.notify_listeners_if_bootstrapped().await
    }
```

**File:** config/src/config/state_sync_config.rs (L110-111)
```rust
    /// Enable auto-bootstrapping if no peers are found after `max_connection_deadline_secs`
    pub enable_auto_bootstrapping: bool,
```

**File:** config/src/config/state_sync_config.rs (L116-117)
```rust
    /// The maximum time (secs) to wait for connections from peers before auto-bootstrapping
    pub max_connection_deadline_secs: u64,
```

**File:** config/src/config/state_sync_config.rs (L140-140)
```rust
            enable_auto_bootstrapping: false,
```

**File:** config/src/config/state_sync_config.rs (L509-516)
```rust
        let fast_sync_enabled = state_sync_driver_config.bootstrapping_mode.is_fast_sync();
        if state_sync_driver_config.enable_auto_bootstrapping && fast_sync_enabled {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Auto-bootstrapping should not be enabled for nodes that are fast syncing!"
                    .to_string(),
            ));
        }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L265-269)
```rust
    fn guarded_initialize(&mut self, proof: &EpochChangeProof) -> Result<(), Error> {
        let waypoint = self.persistent_storage.waypoint()?;
        let last_li = proof
            .verify(&waypoint)
            .map_err(|e| Error::InvalidEpochChangeProof(format!("{}", e)))?;
```
