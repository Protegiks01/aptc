# Audit Report

## Title
Validator Network Isolation Due to Empty Seeds Configuration and Circular Dependency in Peer Discovery

## Summary
Validators configured with an empty seeds PeerSet become permanently isolated from the network when starting fresh or with stale state. The circular dependency between state synchronization (which requires peers) and onchain peer discovery (which requires synchronized state) creates a deadlock condition that prevents validators from ever discovering peers or participating in consensus.

## Finding Description

The vulnerability exists in the ConnectivityManager initialization and its interaction with state synchronization. When a validator is configured with an empty seeds PeerSet, the following sequence occurs: [1](#0-0) 

The seeds are processed as config-based peer discovery, but if empty, no initial peers are available. Validators typically rely on onchain discovery for peer information: [2](#0-1) 

However, onchain discovery depends on ReconfigNotificationListener, which requires the node to have synchronized blockchain state. For a fresh validator or one with significantly stale state, state synchronization requires active peers to fetch blockchain data: [3](#0-2) 

When the global data summary is empty (no active peers), the bootstrapper attempts to verify the waypoint but fails: [4](#0-3) 

The circular dependency creates a permanent deadlock:
1. Empty seeds → No initial peers
2. No peers → Cannot sync blockchain state  
3. Cannot sync state → Cannot receive validator set updates
4. Cannot receive validator set updates → Cannot discover peers via onchain discovery
5. No peer discovery → Validator remains isolated permanently

Critically, production validators have `enable_auto_bootstrapping` disabled by default: [5](#0-4) 

This means the validator will NOT automatically bypass the peer requirement and will remain stuck indefinitely.

## Impact Explanation

This vulnerability meets **High severity** criteria per the Aptos bug bounty program for the following reasons:

1. **Validator Node Isolation**: The affected validator becomes completely isolated from the network and cannot participate in consensus operations, directly impacting network security and decentralization.

2. **Significant Protocol Violation**: The validator violates the fundamental network connectivity invariant - validators must maintain connections with other validators to participate in AptosBFT consensus.

3. **Non-recoverable Without Manual Intervention**: Unlike temporary network issues, this condition is permanent unless the operator manually adds seed peers and restarts the node. There is no automatic recovery mechanism in production configurations.

4. **Affects Fresh Validators**: New validators joining the network with misconfigured or empty seeds cannot bootstrap, preventing network expansion.

5. **Affects Validators After Downtime**: Existing validators that experience extended downtime and restart with stale state face the same isolation if their seeds configuration is empty or contains unreachable peers.

## Likelihood Explanation

The likelihood of this vulnerability occurring is **MEDIUM to HIGH**:

1. **Configuration Errors**: Production validator configurations often use onchain discovery exclusively (as shown in the example validator.yaml), with operators potentially leaving seeds empty or removing them entirely, assuming onchain discovery is sufficient.

2. **Fresh Validator Deployment**: Every new validator joining the network with empty seeds will encounter this issue if they don't have alternative peer discovery methods configured.

3. **Network Maintenance**: During network upgrades or maintenance windows, validators may restart with stale state and empty seeds, triggering the deadlock.

4. **Default Configuration Behavior**: The default production configuration has `enable_auto_bootstrapping: false`, making the issue inevitable rather than edge-case behavior.

## Recommendation

Implement a multi-layered fix to break the circular dependency:

1. **Validation at Configuration Level**: Add configuration validation to prevent empty seeds when onchain discovery is the only method:

```rust
// In network/builder/src/builder.rs or config validation
pub fn validate_peer_discovery_config(
    seeds: &PeerSet,
    discovery_methods: &[DiscoveryMethod],
) -> Result<(), ConfigError> {
    if seeds.is_empty() && discovery_methods.iter().all(|m| matches!(m, DiscoveryMethod::Onchain)) {
        return Err(ConfigError::InvalidConfig(
            "Cannot have empty seeds with only onchain discovery. \
             At least one seed peer or alternative discovery method (File/Rest) is required."
        ));
    }
    Ok(())
}
```

2. **Require Bootstrap Seed Peers**: Enforce that validator networks must have at least one reachable seed peer configured for initial bootstrap, even if they primarily use onchain discovery afterward.

3. **Enable Fallback Auto-bootstrapping for Genesis**: For validators starting from genesis (waypoint version 0), consider enabling auto-bootstrapping after a reasonable timeout, or require explicit configuration acknowledgment.

4. **Enhanced Logging and Monitoring**: Add clear warnings when a validator starts with empty seeds to alert operators before the deadlock occurs.

## Proof of Concept

To reproduce this vulnerability:

1. Configure a validator node with the following settings:
   - Empty seeds: `seeds = {}`
   - Discovery method: `onchain` only
   - Fresh database (genesis state) or significantly stale state
   - `enable_auto_bootstrapping = false` (production default)

2. Start the validator node

3. Observe the behavior:
   - ConnectivityManager initializes with empty discovered_peers
   - State sync attempts to bootstrap but finds no active peers
   - `verify_waypoint_is_satisfiable()` fails with `Error::UnsatisfiableWaypoint`
   - Node logs show repeated failures: "No highest advertised ledger info found in the network!"
   - Validator remains isolated indefinitely

Expected logs:
```
[state-sync] ERROR: Unable to check waypoint satisfiability! No highest advertised ledger info found in the network!
[connectivity_manager] INFO: The global data summary is empty! It's likely that we have no active peers.
```

The validator never progresses past bootstrapping and cannot join consensus.

## Notes

This vulnerability highlights a critical architectural assumption: that validators always have at least one mechanism to discover initial peers. The reliance on onchain discovery alone creates a bootstrap problem for nodes without synchronized state. While this may be partially mitigated in practice by network operators following best practices (maintaining seed configurations), the codebase lacks protective validation to prevent this configuration error, and the default behavior enables rather than prevents the deadlock condition.

### Citations

**File:** network/framework/src/connectivity_manager/mod.rs (L11-21)
```rust
//! Different discovery sources notify the ConnectivityManager of updates to
//! peers' addresses. Currently, there are 2 discovery sources (ordered by
//! decreasing dial priority, i.e., first is highest priority):
//!
//! 1. Onchain discovery protocol
//! 2. Seed peers from config
//!
//! In other words, if a we have some addresses discovered via onchain discovery
//! and some seed addresses from our local config, we will try the onchain
//! discovery addresses first and the local seed addresses after.
//!
```

**File:** network/framework/src/connectivity_manager/mod.rs (L400-402)
```rust
        // Set the initial seed config addresses and public keys
        connmgr.handle_update_discovered_peers(DiscoverySource::Config, seeds);
        connmgr
```

**File:** state-sync/state-sync-driver/src/driver.rs (L671-678)
```rust
        // Fetch the global data summary and verify we have active peers
        let global_data_summary = self.aptos_data_client.get_global_data_summary();
        if global_data_summary.is_empty() {
            trace!(LogSchema::new(LogEntry::Driver).message(
                "The global data summary is empty! It's likely that we have no active peers."
            ));
            return self.check_auto_bootstrapping().await;
        }
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L893-901)
```rust
        // Get the highest advertised synced ledger info version
        let highest_advertised_ledger_info = global_data_summary
            .advertised_data
            .highest_synced_ledger_info()
            .ok_or_else(|| {
                Error::UnsatisfiableWaypoint(
                    "Unable to check waypoint satisfiability! No highest advertised ledger info found in the network!".into(),
                )
            })?;
```

**File:** config/src/config/state_sync_config.rs (L140-140)
```rust
            enable_auto_bootstrapping: false,
```
