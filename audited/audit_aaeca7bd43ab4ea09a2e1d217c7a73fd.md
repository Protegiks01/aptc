# Audit Report

## Title
Missing Parent-Child Round Invariant Validation During Recovery Leads to Premature Block Pruning and Node DoS

## Summary
The consensus recovery logic in `persistent_liveness_storage.rs` fails to validate that blocks loaded from ConsensusDB satisfy the fundamental parent-child round invariant (`parent.round() < child.round()`). If ConsensusDB contains corrupted blocks with invalid parent links, the window root calculation can produce a window_root_block with a higher round than commit_root_block, leading to incorrect pruning of committed blocks and node failure to restart.

## Finding Description

The vulnerability exists in the recovery code path when a consensus node restarts and loads blocks from persistent storage:

**Step 1: Blocks Loaded Without Validation**

In `RecoveryData::new`, blocks are retrieved from ConsensusDB without validation: [1](#0-0) 

These blocks are passed to `find_root_with_window`, which walks backwards following parent links: [2](#0-1) 

**The Critical Issue**: The algorithm assumes parent_id points to a block with `parent.round() < current_block.round()`, but this invariant is **never validated** during recovery. While `Block::verify_well_formed()` exists and checks this invariant: [3](#0-2) 

This validation is **not called** anywhere in `persistent_liveness_storage.rs` during recovery.

**Step 2: Corrupted Parent Links Lead to Invalid Window Root**

If ConsensusDB contains blocks with corrupted parent_id fields (e.g., due to disk corruption or malicious local modification), where `parent_id` points to a block with a **higher** round:

```
Example Corruption:
- Block B100: round=100, parent_id=B110 (INVALID: parent should have lower round)
- Block B110: round=110, parent_id=B90
- commit_block = B100 (from storage ledger)
```

The walking-backwards algorithm would:
1. Start at B100 (round 100)
2. Follow parent_id to B110 (round 110) - **now at higher round!**
3. Set window_start_block = B110

This violates the invariant: `window_start_block.round() (110) > commit_block.round() (100)`

**Step 3: Premature Pruning Before Safety Assertion**

The pruning logic executes **before** the safety assertion: [4](#0-3) 

If `window_root_block` has round > `commit_root_block`, then `root_id` points to the higher-round block. The pruning algorithm: [5](#0-4) 

This keeps only blocks that are **descendants** of window_root_block. Since commit_root_block (round 100) cannot be a descendant of window_root_block (round 110), blocks in the commit chain get incorrectly pruned.

**Step 4: Node Failure**

Later, when `BlockTree::new` is called, the assertion fires: [6](#0-5) 

The node panics and cannot restart. Even if this assertion didn't exist, the pruned blocks would cause `get_ordered_block_window` to fail with "Parent block not found" errors.

## Impact Explanation

**Severity: Medium** (State inconsistencies requiring intervention)

While the vulnerability requires local filesystem access to corrupt ConsensusDB (making it non-exploitable remotely), the impact is significant:

1. **Node Denial of Service**: The affected validator cannot restart until the database is manually repaired
2. **Network Liveness Impact**: If multiple validators are affected, network liveness could degrade
3. **Defensive Programming Failure**: The code lacks defensive validation, making it fragile against data corruption

This does not reach High/Critical severity because:
- It's not remotely exploitable by an unprivileged attacker
- It doesn't directly cause fund loss or consensus safety violations
- The safety assertion prevents silent corruption from propagating

However, it represents a **defensive programming vulnerability** where validation happens too late—after irreversible pruning has occurred.

## Likelihood Explanation

**Likelihood: Low-Medium**

The vulnerability can be triggered by:

1. **Disk Corruption**: Hardware failures causing database corruption (rare but possible)
2. **Malicious Local Access**: Node operator or attacker with local access modifies database
3. **Implementation Bugs**: Future bugs in consensus code could write invalid blocks to storage

While remote exploitation is not possible, validators are high-value targets and the defensive gap creates unnecessary risk.

## Recommendation

Add validation before the pruning step to fail fast with a clear error:

```rust
// In RecoveryData::new, after line 383, add validation:
if let Some(window_root_block) = &root.window_root_block {
    ensure!(
        window_root_block.round() <= root.commit_root_block.round(),
        "Invalid recovery data: window_root round {} > commit_root round {}",
        window_root_block.round(),
        root.commit_root_block.round()
    );
}

// Additionally, validate all loaded blocks satisfy parent-child invariant:
for block in &blocks {
    if !block.is_genesis_block() {
        let parent = block.quorum_cert().certified_block();
        ensure!(
            parent.round() < block.round(),
            "Block {} has invalid parent round: parent {} >= child {}",
            block.id(),
            parent.round(),
            block.round()
        );
    }
}
```

This ensures:
1. Early detection of corrupted data before any state modification
2. Clear error messages for debugging
3. Prevention of incorrect pruning
4. Fail-safe behavior instead of panic during initialization

## Proof of Concept

```rust
// Proof of concept demonstrating the issue
// (Would require test harness to corrupt database)

#[test]
fn test_corrupted_parent_links_cause_invalid_window_root() {
    // 1. Create valid blocks B90, B100
    let b90 = create_test_block(90, genesis_id);
    let b100 = create_test_block(100, b90.id());
    
    // 2. Create corrupted block B110 that claims B90 as parent
    let b110 = create_test_block(110, b90.id());
    
    // 3. Corrupt B100's parent_id to point to B110 (higher round)
    let corrupted_b100 = create_block_with_corrupted_parent(100, b110.id());
    
    // 4. Set commit_root to B100 in storage
    storage.set_latest_ledger_info(create_ledger_info(corrupted_b100.id()));
    
    // 5. Attempt recovery
    let blocks = vec![b90, corrupted_b100, b110];
    let result = RecoveryData::new(
        None,
        ledger_recovery_data,
        blocks,
        root_metadata,
        quorum_certs,
        None,
        true,
        Some(10),
    );
    
    // 6. Current behavior: Panics later during BlockTree::new
    // Expected behavior: Should fail immediately with validation error
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Invalid recovery data"));
}
```

**Notes**

The vulnerability is a **defensive programming issue** rather than a remotely exploitable attack. It represents a gap in the defense-in-depth strategy where corrupted persistent state can cause node failures. While the safety assertion prevents silent corruption, the validation should occur earlier to:

1. Provide better error diagnostics
2. Prevent wasted computation on invalid data  
3. Avoid irreversible pruning before validation
4. Follow fail-fast principles

The fix is straightforward and adds minimal overhead while significantly improving robustness against data corruption scenarios.

### Citations

**File:** consensus/src/persistent_liveness_storage.rs (L171-181)
```rust
        let mut current_block = &commit_block;
        while !current_block.is_genesis_block()
            && current_block.quorum_cert().certified_block().round() >= window_start_round
        {
            if let Some(parent_block) = id_to_blocks.get(&current_block.parent_id()) {
                current_block = *parent_block;
            } else {
                bail!("Parent block not found for block {}", current_block.id());
            }
        }
        let window_start_id = current_block.id();
```

**File:** consensus/src/persistent_liveness_storage.rs (L358-383)
```rust
        let root = ledger_recovery_data
            .find_root(
                &mut blocks,
                &mut quorum_certs,
                order_vote_enabled,
                window_size,
            )
            .with_context(|| {
                // for better readability
                blocks.sort_by_key(|block| block.round());
                quorum_certs.sort_by_key(|qc| qc.certified_block().round());
                format!(
                    "\nRoot: {}\nBlocks in db: {}\nQuorum Certs in db: {}\n",
                    ledger_recovery_data.storage_ledger.ledger_info(),
                    blocks
                        .iter()
                        .map(|b| format!("\n{}", b))
                        .collect::<Vec<String>>()
                        .concat(),
                    quorum_certs
                        .iter()
                        .map(|qc| format!("\n{}", qc))
                        .collect::<Vec<String>>()
                        .concat(),
                )
            })?;
```

**File:** consensus/src/persistent_liveness_storage.rs (L386-402)
```rust
        let (root_id, epoch) = match &root.window_root_block {
            None => {
                let commit_root_id = root.commit_root_block.id();
                let epoch = root.commit_root_block.epoch();
                (commit_root_id, epoch)
            },
            Some(window_root_block) => {
                let window_start_id = window_root_block.id();
                let epoch = window_root_block.epoch();
                (window_start_id, epoch)
            },
        };
        let blocks_to_prune = Some(Self::find_blocks_to_prune(
            root_id,
            &mut blocks,
            &mut quorum_certs,
        ));
```

**File:** consensus/src/persistent_liveness_storage.rs (L448-476)
```rust
    fn find_blocks_to_prune(
        root_id: HashValue,
        blocks: &mut Vec<Block>,
        quorum_certs: &mut Vec<QuorumCert>,
    ) -> Vec<HashValue> {
        // prune all the blocks that don't have root as ancestor
        let mut tree = HashSet::new();
        let mut to_remove = HashSet::new();
        tree.insert(root_id);
        // assume blocks are sorted by round already
        blocks.retain(|block| {
            if tree.contains(&block.parent_id()) {
                tree.insert(block.id());
                true
            } else {
                to_remove.insert(block.id());
                false
            }
        });
        quorum_certs.retain(|qc| {
            if tree.contains(&qc.certified_block().id()) {
                true
            } else {
                to_remove.insert(qc.certified_block().id());
                false
            }
        });
        to_remove.into_iter().collect()
    }
```

**File:** consensus/consensus-types/src/block.rs (L475-478)
```rust
        ensure!(
            parent.round() < self.round(),
            "Block must have a greater round than parent's block"
        );
```

**File:** consensus/src/block_storage/block_tree.rs (L113-114)
```rust
        assert_eq!(window_root.epoch(), root_ordered_cert.commit_info().epoch());
        assert!(window_root.round() <= root_ordered_cert.commit_info().round());
```
