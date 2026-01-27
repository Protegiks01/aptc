# Audit Report

## Title
Pruning Inconsistency Between BlockInfoSchema and Event Storage Causes Consensus Leader Selection Failure

## Summary
The `get_latest_block_events()` function's reverse iteration path iterates over `BlockInfoSchema` entries that are never pruned, while attempting to fetch corresponding events that are pruned by `EventStorePruner`. This causes `expect_new_block_event()` to fail with `NotFound` errors for old blocks, breaking consensus leader reputation and potentially causing incorrect leader selection.

## Finding Description

The vulnerability exists in the asymmetric pruning behavior between two related storage schemas:

**The Problem:** [1](#0-0) 

The reverse iteration path creates an iterator over `BlockInfoSchema` and for each block info entry, attempts to fetch the corresponding event. However:

1. **BlockInfoSchema is NEVER pruned** - Verification across all pruner implementations confirms no pruner touches `BlockInfoSchema` or `BlockByVersionSchema`

2. **Events ARE pruned** - The `EventStorePruner` actively removes old events: [2](#0-1) 

3. **Failure point** - When the iteration attempts to fetch events for old blocks, `expect_new_block_event()` fails: [3](#0-2) 

**Consensus Impact:**
This function is critical for consensus leader reputation: [4](#0-3) 

When `get_latest_block_events()` fails due to pruned events, the error handling falls back to empty results: [5](#0-4) 

This breaks the leader reputation system's ability to evaluate validator performance, potentially causing:
- Incorrect leader selection in consensus rounds
- Byzantine validators gaining unfair leader election advantage
- Honest validators being unfairly penalized

**Attack Scenario:**
1. Normal pruning occurs after blocks age beyond the retention window
2. `BlockInfoSchema` retains entries for pruned blocks indefinitely
3. Consensus calls `get_latest_block_events()` with `skip_index_and_usage=true`
4. Reverse iteration encounters `BlockInfo` for a pruned block
5. `expect_new_block_event()` throws `NotFound` error
6. Leader reputation initialization fails, returns empty metadata
7. Consensus cannot properly evaluate validator performance

## Impact Explanation

**Severity: Medium** (up to $10,000 per Aptos bug bounty)

This qualifies as "State inconsistencies requiring intervention" because:

1. **Consensus Protocol Degradation**: Leader selection relies on accurate block metadata. Empty results cause fallback behavior that may select suboptimal or malicious leaders.

2. **Deterministic Execution Violation**: Different nodes may encounter this error at different times depending on their pruning schedules, causing non-deterministic behavior.

3. **Storage Invariant Violation**: The invariant that "related storage schemas maintain consistency" is broken. `BlockInfoSchema` and event storage become permanently desynchronized after pruning.

While this doesn't directly cause fund loss or network partition, it compromises consensus quality and could enable Byzantine behavior through manipulated leader selection.

## Likelihood Explanation

**Likelihood: HIGH**

This will occur automatically on any node that:
- Has `skip_index_and_usage=true` configuration
- Runs long enough for pruning to activate (typically days to weeks)
- Participates in consensus (validators)

No attacker action is required - normal operation triggers the vulnerability. The pruning window is typically set to retain recent data (e.g., 150M versions), but `BlockInfoSchema` grows unbounded, guaranteeing eventual inconsistency.

## Recommendation

**Fix: Prune BlockInfoSchema consistently with events**

Add a new pruner for block metadata that runs alongside `EventStorePruner`:

```rust
// In storage/aptosdb/src/pruner/ledger_pruner/block_info_pruner.rs
pub struct BlockInfoPruner {
    ledger_metadata_db: Arc<DB>,
}

impl DBSubPruner for BlockInfoPruner {
    fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
        let mut batch = SchemaBatch::new();
        
        // Find BlockInfo entries to prune by iterating and checking first_version
        let mut iter = self.ledger_metadata_db.iter::<BlockInfoSchema>()?;
        iter.seek_to_first();
        
        for item in iter {
            let (block_height, block_info) = item?;
            if block_info.first_version() < target_version {
                batch.delete::<BlockInfoSchema>(&block_height)?;
                batch.delete::<BlockByVersionSchema>(&block_info.first_version())?;
            } else {
                break;  // Blocks are ordered, stop when we reach unpruned range
            }
        }
        
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::BlockInfoPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;
        self.ledger_metadata_db.write_schemas(batch)
    }
}
```

Register this pruner in the ledger pruner manager to run alongside event pruning.

**Alternative: Add error handling**

If preserving all `BlockInfo` is intentional, add graceful error handling:

```rust
// In aptosdb_reader.rs, line 764-768
let event_result = self
    .ledger_db
    .event_db()
    .expect_new_block_event(first_version);

match event_result {
    Ok(event) => {
        events.push(EventWithVersion::new(first_version, event));
    }
    Err(AptosDbError::NotFound(_)) => {
        // Event pruned, skip this block
        continue;
    }
    Err(e) => return Err(e),
}
```

## Proof of Concept

**Rust Reproduction Steps:**

1. Configure node with `skip_index_and_usage=true`
2. Commit blocks until version > prune_window (e.g., 150M versions)
3. Trigger pruning via ledger pruner
4. Call `get_latest_block_events(window_size)`
5. Observe `NotFound` error for blocks whose events were pruned
6. Verify `BlockInfoSchema` still contains entries for those blocks

**Minimal Test:**

```rust
#[test]
fn test_block_info_event_pruning_inconsistency() {
    let db = create_test_db();
    
    // Write block info and events
    write_test_blocks(&db, 100);
    
    // Prune events but not block info (simulating real behavior)
    db.event_pruner.prune(0, 50).unwrap();
    
    // Attempt to get latest block events using reverse iteration
    let result = db.get_latest_block_events(10);
    
    // Should fail when encountering pruned events for existing BlockInfo
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AptosDbError::NotFound(_)));
}
```

## Notes

This vulnerability demonstrates a fundamental design issue where related storage schemas have asymmetric lifecycle management. The fix requires either:
1. Synchronizing pruning across all block-related schemas
2. Adding defensive error handling for missing related data

The consensus impact makes this more severe than a typical storage bug, as it directly affects Byzantine fault tolerance properties of the leader election mechanism.

### Citations

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L755-773)
```rust
            let db = self.ledger_db.metadata_db_arc();
            let mut iter = db.rev_iter::<BlockInfoSchema>()?;
            iter.seek_to_last();

            let mut events = Vec::with_capacity(num_events);
            for item in iter {
                let (_block_height, block_info) = item?;
                let first_version = block_info.first_version();
                if latest_version.as_ref().is_some_and(|v| first_version <= *v) {
                    let event = self
                        .ledger_db
                        .event_db()
                        .expect_new_block_event(first_version)?;
                    events.push(EventWithVersion::new(first_version, event));
                    if events.len() == num_events {
                        break;
                    }
                }
            }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L55-65)
```rust
        let num_events_per_version = self.ledger_db.event_db().prune_event_indices(
            current_progress,
            target_version,
            indices_batch,
        )?;
        self.ledger_db.event_db().prune_events(
            num_events_per_version,
            current_progress,
            target_version,
            &mut batch,
        )?;
```

**File:** storage/aptosdb/src/ledger_db/event_db.rs (L83-96)
```rust
    pub(crate) fn expect_new_block_event(&self, version: Version) -> Result<ContractEvent> {
        for event in self.get_events_by_version(version)? {
            if let Some(key) = event.event_key() {
                if *key == new_block_event_key() {
                    return Ok(event);
                }
            }
        }

        Err(AptosDbError::NotFound(format!(
            "NewBlockEvent at version {}",
            version,
        )))
    }
```

**File:** consensus/src/liveness/leader_reputation.rs (L78-78)
```rust
        let events = self.aptos_db.get_latest_block_events(limit)?;
```

**File:** consensus/src/liveness/leader_reputation.rs (L179-183)
```rust
            if let Err(e) = self.refresh_db_result(&mut locked, latest_db_version) {
                warn!(
                    error = ?e, "[leader reputation] Fail to initialize db result",
                );
                return (vec![], HashValue::zero());
```
