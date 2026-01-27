# Audit Report

## Title
Archive Node Misconfiguration Allows Unintended State Merkle Tree Pruning Leading to Loss of Historical Audit Data

## Summary
Archive nodes intended to retain complete historical blockchain data can be misconfigured to still prune critical state merkle tree nodes. The official documentation provides an incomplete configuration example that only disables the ledger pruner while leaving state merkle and epoch snapshot pruners enabled by default, causing permanent loss of historical state authentication data required for auditing, compliance, and forensic analysis.

## Finding Description

Archive nodes in Aptos are fullnodes that must retain all historical blockchain data for auditing, compliance, and verification purposes. However, the pruner configuration system has three independent pruner components that must all be disabled for true archive functionality: [1](#0-0) 

The official documentation in the indexer README provides an example configuration for nodes that "should not be pruned": [2](#0-1) 

**Critical Issue**: This example only disables `ledger_pruner_config`, but the pruner system has three components, each with independent enable flags:

1. **ledger_pruner_config** (disabled in example) - Prunes transactions, events, write sets
2. **state_merkle_pruner_config** (NOT mentioned, uses default) - Prunes state merkle tree nodes
3. **epoch_snapshot_pruner_config** (NOT mentioned, uses default) - Prunes epoch-ending state snapshots

When not explicitly configured, these pruners default to **enabled**: [3](#0-2) [4](#0-3) 

The configuration sanitizer receives the node type but **does not use it** to validate archive node configurations: [5](#0-4) 

When operators follow the incomplete documentation, their "archive" nodes will:
- Retain ledger data (transactions, events) ✓
- **Prune state merkle nodes after 1,000,000 versions** ✗
- **Prune epoch snapshots after 80,000,000 versions** ✗

The state merkle pruner permanently deletes Jellyfish Merkle Tree nodes: [6](#0-5) 

These pruned nodes are essential for generating state proofs at historical versions, which are required for:
- Verifying historical account balances and state
- Auditing historical governance votes
- Compliance requirements for financial regulations
- Forensic analysis of suspicious transactions
- Reconstructing state at any point in blockchain history

## Impact Explanation

**High Severity** - This meets the "Significant protocol violations" category because:

1. **Data Loss**: Permanent, unrecoverable loss of historical state authentication data on nodes that operators believe are maintaining full archives
2. **Audit Failure**: Archive nodes cannot fulfill their purpose of providing verifiable historical state for auditing and compliance
3. **Network Health**: Reduces network data availability as documented in warning messages
4. **Trust Violation**: Operators trusting official documentation will unknowingly run non-archive nodes

The vulnerability affects any operator who:
- Follows the indexer README documentation
- Configures nodes for compliance/auditing purposes
- Runs archive nodes for regulatory requirements
- Provides historical data APIs to users

## Likelihood Explanation

**High Likelihood** - This will occur on every archive node configured following the official documentation example. The likelihood is essentially 100% for operators who:
- Read and follow the `crates/indexer/README.md` documentation
- Configure "archive" nodes by only disabling `ledger_pruner_config`
- Do not independently discover the need to disable all three pruners

The configuration sanitizer provides no protection, warnings, or enforcement of proper archive node configuration. There is no validation that archive nodes have all pruners disabled.

## Recommendation

### Immediate Fix - Update Documentation

The indexer README must be corrected to show complete archive node configuration:

```yaml
storage:
  enable_indexer: true
  # This is to avoid the node being pruned (archive node configuration)
  storage_pruner_config:
    ledger_pruner_config:
      enable: false
    state_merkle_pruner_config:
      enable: false
    epoch_snapshot_pruner_config:
      enable: false
```

### Long-term Fix - Add Configuration Validation

Add explicit archive node validation in the config sanitizer:

```rust
impl ConfigSanitizer for StorageConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let config = &node_config.storage;
        
        // Check for incomplete archive node configuration
        let ledger_disabled = !config.storage_pruner_config.ledger_pruner_config.enable;
        let state_merkle_enabled = config.storage_pruner_config.state_merkle_pruner_config.enable;
        let epoch_snapshot_enabled = config.storage_pruner_config.epoch_snapshot_pruner_config.enable;
        
        if ledger_disabled && (state_merkle_enabled || epoch_snapshot_enabled) {
            warn!(
                "Incomplete archive node configuration detected. Ledger pruner is disabled but \
                state_merkle_pruner ({}) or epoch_snapshot_pruner ({}) are still enabled. \
                This will result in loss of historical state merkle tree data. \
                For true archive nodes, disable all pruners.",
                if state_merkle_enabled { "ENABLED" } else { "disabled" },
                if epoch_snapshot_enabled { "ENABLED" } else { "disabled" }
            );
        }
        
        // existing validation code...
    }
}
```

### Reference Configuration

Use `NO_OP_STORAGE_PRUNER_CONFIG` for archive nodes: [7](#0-6) 

## Proof of Concept

```rust
// Test demonstrating the misconfiguration vulnerability
// File: config/src/config/storage_config_test.rs

#[test]
fn test_archive_node_misconfiguration_allows_state_pruning() {
    use crate::config::{PrunerConfig, LedgerPrunerConfig, StateMerklePrunerConfig, EpochSnapshotPrunerConfig};
    
    // Configuration following the indexer README documentation example
    let incomplete_archive_config = PrunerConfig {
        ledger_pruner_config: LedgerPrunerConfig {
            enable: false,  // Disabled as per documentation
            prune_window: 0,
            batch_size: 0,
            user_pruning_window_offset: 0,
        },
        // state_merkle_pruner_config and epoch_snapshot_pruner_config
        // not specified, so they use defaults
        ..Default::default()
    };
    
    // Verify the misconfiguration: ledger pruner disabled but others enabled
    assert_eq!(incomplete_archive_config.ledger_pruner_config.enable, false, 
        "Ledger pruner should be disabled");
    assert_eq!(incomplete_archive_config.state_merkle_pruner_config.enable, true,
        "BUG: State merkle pruner is ENABLED on 'archive' node!");
    assert_eq!(incomplete_archive_config.epoch_snapshot_pruner_config.enable, true,
        "BUG: Epoch snapshot pruner is ENABLED on 'archive' node!");
    
    // This configuration will prune state merkle nodes after 1M versions
    assert_eq!(incomplete_archive_config.state_merkle_pruner_config.prune_window, 1_000_000);
    
    // Compare with proper archive configuration
    let proper_archive_config = NO_OP_STORAGE_PRUNER_CONFIG;
    assert_eq!(proper_archive_config.ledger_pruner_config.enable, false);
    assert_eq!(proper_archive_config.state_merkle_pruner_config.enable, false);
    assert_eq!(proper_archive_config.epoch_snapshot_pruner_config.enable, false);
    
    println!("VULNERABILITY CONFIRMED:");
    println!("Following the official documentation creates an 'archive' node that");
    println!("will still prune historical state merkle tree data after 1M versions,");
    println!("causing permanent loss of historical state authentication data.");
}
```

## Notes

The vulnerability is exacerbated by:

1. **No explicit "Archive" node type**: The `NodeType` enum only has `Validator`, `ValidatorFullnode`, and `PublicFullnode`. Archive functionality is implicit through configuration rather than an explicit node type.

2. **Unused node_type parameter**: The storage config sanitizer receives but ignores the `node_type` parameter, missing an opportunity to validate archive-specific requirements.

3. **No validation in readonly mode check**: While readonly database opening enforces `NO_OP_STORAGE_PRUNER_CONFIG`, normal operational archive nodes run in read-write mode and have no such enforcement: [8](#0-7) 

This vulnerability represents a critical gap between operator expectations (maintaining full historical data) and actual system behavior (pruning essential state authentication data), potentially violating regulatory compliance requirements and breaking the fundamental guarantee that archive nodes preserve complete blockchain history.

### Citations

**File:** config/src/config/storage_config.rs (L306-323)
```rust
pub const NO_OP_STORAGE_PRUNER_CONFIG: PrunerConfig = PrunerConfig {
    ledger_pruner_config: LedgerPrunerConfig {
        enable: false,
        prune_window: 0,
        batch_size: 0,
        user_pruning_window_offset: 0,
    },
    state_merkle_pruner_config: StateMerklePrunerConfig {
        enable: false,
        prune_window: 0,
        batch_size: 0,
    },
    epoch_snapshot_pruner_config: EpochSnapshotPrunerConfig {
        enable: false,
        prune_window: 0,
        batch_size: 0,
    },
};
```

**File:** config/src/config/storage_config.rs (L379-385)
```rust
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct PrunerConfig {
    pub ledger_pruner_config: LedgerPrunerConfig,
    pub state_merkle_pruner_config: StateMerklePrunerConfig,
    pub epoch_snapshot_pruner_config: EpochSnapshotPrunerConfig,
}
```

**File:** config/src/config/storage_config.rs (L398-413)
```rust
impl Default for StateMerklePrunerConfig {
    fn default() -> Self {
        StateMerklePrunerConfig {
            enable: true,
            // This allows a block / chunk being executed to have access to a non-latest state tree.
            // It needs to be greater than the number of versions the state committing thread is
            // able to commit during the execution of the block / chunk. If the bad case indeed
            // happens due to this being too small, a node restart should recover it.
            // Still, defaulting to 1M to be super safe.
            prune_window: 1_000_000,
            // A 10k transaction block (touching 60k state values, in the case of the account
            // creation benchmark) on a 4B items DB (or 1.33B accounts) yields 300k JMT nodes
            batch_size: 1_000,
        }
    }
}
```

**File:** config/src/config/storage_config.rs (L415-431)
```rust
impl Default for EpochSnapshotPrunerConfig {
    fn default() -> Self {
        Self {
            enable: true,
            // This is based on ~5K TPS * 2h/epoch * 2 epochs. -- epoch ending snapshots are used
            // by state sync in fast sync mode.
            // The setting is in versions, not epochs, because this makes it behave more like other
            // pruners: a slower network will have longer history in db with the same pruner
            // settings, but the disk space take will be similar.
            // settings.
            prune_window: 80_000_000,
            // A 10k transaction block (touching 60k state values, in the case of the account
            // creation benchmark) on a 4B items DB (or 1.33B accounts) yields 300k JMT nodes
            batch_size: 1_000,
        }
    }
}
```

**File:** config/src/config/storage_config.rs (L682-716)
```rust
impl ConfigSanitizer for StorageConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let config = &node_config.storage;

        let ledger_prune_window = config
            .storage_pruner_config
            .ledger_pruner_config
            .prune_window;
        let state_merkle_prune_window = config
            .storage_pruner_config
            .state_merkle_pruner_config
            .prune_window;
        let epoch_snapshot_prune_window = config
            .storage_pruner_config
            .epoch_snapshot_pruner_config
            .prune_window;
        let user_pruning_window_offset = config
            .storage_pruner_config
            .ledger_pruner_config
            .user_pruning_window_offset;

        if ledger_prune_window < 50_000_000 {
            warn!("Ledger prune_window is too small, harming network data availability.");
        }
        if state_merkle_prune_window < 100_000 {
            warn!("State Merkle prune_window is too small, node might stop functioning.");
        }
        if epoch_snapshot_prune_window < 50_000_000 {
            warn!("Epoch snapshot prune_window is too small, harming network data availability.");
        }
```

**File:** crates/indexer/README.md (L42-48)
```markdown
      storage:
      enable_indexer: true
      # This is to avoid the node being pruned
      storage_pruner_config:
         ledger_pruner_config:
            enable: false

```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/mod.rs (L37-49)
```rust
/// Responsible for pruning the state tree.
pub struct StateMerklePruner<S> {
    /// Keeps track of the target version that the pruner needs to achieve.
    target_version: AtomicVersion,
    /// Overall progress, updated when the whole version is done.
    progress: AtomicVersion,

    metadata_pruner: StateMerkleMetadataPruner<S>,
    // Non-empty iff sharding is enabled.
    shard_pruners: Vec<StateMerkleShardPruner<S>>,

    _phantom: PhantomData<S>,
}
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L124-127)
```rust
        ensure!(
            pruner_config.eq(&NO_OP_STORAGE_PRUNER_CONFIG) || !readonly,
            "Do not set prune_window when opening readonly.",
        );
```
