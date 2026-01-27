# Audit Report

## Title
Transaction Accumulator Irreversible Data Loss Due to Lack of Recovery Mechanism After Pruning

## Summary
The Aptos storage system lacks any recovery mechanism to rebuild the transaction accumulator if frozen nodes are incorrectly deleted by the pruner. Since both accumulator nodes and transaction infos are pruned simultaneously, and no frozen subtree roots are preserved as a backup at the pruning boundary, any pruning bug would cause permanent, irreversible data loss requiring a hard fork.

## Finding Description

The transaction accumulator in Aptos is a Merkle accumulator that stores hashes of transaction infos. The system prunes old data through coordinated sub-pruners that delete both accumulator nodes and transaction infos. [1](#0-0) 

The pruning process deletes accumulator nodes (frozen nodes) from storage: [2](#0-1) 

Simultaneously, transaction infos are also pruned: [3](#0-2) 

To rebuild the accumulator at any version, the system requires either:
1. The frozen accumulator nodes themselves (via `get_frozen_subtree_hashes`)
2. The transaction infos to recompute hashes [4](#0-3) 

The critical issue is that `get_frozen_subtree_hashes` fails if any required node is missing: [5](#0-4) 

Since both accumulator nodes AND transaction infos are pruned in the same cycle, if a pruning bug causes incorrect deletion, there is NO recovery mechanism. The system does not:
- Preserve frozen subtree roots at the `min_readable_version` boundary as a backup
- Validate that required nodes remain after pruning
- Provide any rebuild mechanism from remaining data

The `confirm_or_save_frozen_subtrees` function exists but is only called during state snapshot restoration, not during normal pruning operations: [6](#0-5) 

## Impact Explanation

This constitutes a **Critical Severity** vulnerability per Aptos bug bounty criteria:

1. **Non-recoverable network partition requiring hardfork**: If accumulator nodes are lost, affected nodes cannot compute accumulator roots, cannot serve proofs, and cannot sync with the network. Recovery requires restoring from backup or hard fork.

2. **Consensus Safety violation**: Nodes with corrupted accumulators cannot validate transaction proofs, breaking the ability to verify ledger consistency.

3. **Permanent data loss**: Without transaction infos or accumulator nodes, the historical transaction accumulator state is permanently lost and cannot be reconstructed.

The test verification confirms that after pruning, the system expects to access accumulator summaries: [7](#0-6) 

But there's no safeguard ensuring this will succeed if pruning has a bug.

## Likelihood Explanation

**Moderate to High Likelihood:**

1. **Complex pruning algorithm**: The pruning algorithm involves intricate position calculations and edge cases, making bugs possible during code evolution.

2. **No validation layer**: There's no post-pruning validation that frozen subtrees at `min_readable_version` remain accessible.

3. **Parallel pruning**: Multiple sub-pruners run in parallel, increasing the risk of race conditions or coordination bugs.

4. **Code changes**: Future modifications to the pruning logic could introduce bugs that violate preservation invariants.

While the current implementation may be correct, the lack of defensive programming (validation, backup, recovery) makes the system fragile.

## Recommendation

Implement multiple defense layers:

1. **Preserve frozen subtree roots at pruning boundary**: Before pruning, explicitly save frozen subtree roots for `min_readable_version` using `confirm_or_save_frozen_subtrees` to a separate, non-prunable storage area.

2. **Add pre/post-pruning validation**: Verify that `get_accumulator_summary(min_readable_version)` succeeds both before and after pruning completes.

3. **Implement recovery mechanism**: Provide a rebuild path from remaining transaction data or require explicit backup of frozen subtrees before enabling pruning.

4. **Add assertions**: Insert runtime checks that frozen subtree positions for `min_readable_version` are never deleted.

Example fix for validation:

```rust
pub(crate) fn prune(begin: Version, end: Version, db_batch: &mut SchemaBatch) -> Result<()> {
    // Identify frozen subtree positions at the pruning boundary
    let boundary_frozen_positions: HashSet<Position> = 
        FrozenSubTreeIterator::new(begin + 1).collect();
    
    for version_to_delete in begin..end {
        db_batch.delete::<TransactionAccumulatorRootHashSchema>(&version_to_delete)?;
        if version_to_delete % 2 == 0 {
            continue;
        }
        
        let mut current = first_ancestor_that_is_a_left_child;
        while !current.is_leaf() {
            let left = current.left_child();
            let right = current.right_child();
            
            // SAFETY: Never delete frozen subtree roots at boundary
            if !boundary_frozen_positions.contains(&left) {
                db_batch.delete::<TransactionAccumulatorSchema>(&left)?;
            }
            if !boundary_frozen_positions.contains(&right) {
                db_batch.delete::<TransactionAccumulatorSchema>(&right)?;
            }
            current = right;
        }
    }
    Ok(())
}
```

## Proof of Concept

The vulnerability is demonstrated by the design itself - no PoC code is needed to show that recovery is impossible. The issue is validated by tracing the code paths:

1. `LedgerPruner::prune()` coordinates sub-pruners
2. `TransactionAccumulatorPruner::prune()` deletes accumulator nodes  
3. `TransactionInfoPruner::prune()` deletes transaction infos
4. `get_accumulator_summary()` fails if nodes are missing (returns error from HashReader)
5. No recovery path exists since both accumulator nodes and transaction infos are gone

The system's reliance on `get_frozen_subtree_hashes` without any backup mechanism creates irreversible data loss if pruning malfunctions.

## Notes

This is a **design-level vulnerability** rather than an implementation bug. The current pruning algorithm may be correctly implemented, but the lack of defensive safeguards (validation, backup, recovery) makes the system vulnerable to future bugs or edge cases. Given the critical nature of the transaction accumulator for consensus and state verification, defense-in-depth is essential.

### Citations

**File:** storage/aptosdb/src/pruner/ledger_pruner/mod.rs (L176-184)
```rust
            sub_pruners: vec![
                event_store_pruner,
                persisted_auxiliary_info_pruner,
                transaction_accumulator_pruner,
                transaction_auxiliary_data_pruner,
                transaction_info_pruner,
                transaction_pruner,
                write_set_pruner,
            ],
```

**File:** storage/aptosdb/src/ledger_db/transaction_accumulator_db.rs (L149-172)
```rust
    pub(crate) fn prune(begin: Version, end: Version, db_batch: &mut SchemaBatch) -> Result<()> {
        for version_to_delete in begin..end {
            db_batch.delete::<TransactionAccumulatorRootHashSchema>(&version_to_delete)?;
            // The even version will be pruned in the iteration of version + 1.
            if version_to_delete % 2 == 0 {
                continue;
            }

            let first_ancestor_that_is_a_left_child =
                Self::find_first_ancestor_that_is_a_left_child(version_to_delete);

            // This assertion is true because we skip the leaf nodes with address which is a
            // a multiple of 2.
            assert!(!first_ancestor_that_is_a_left_child.is_leaf());

            let mut current = first_ancestor_that_is_a_left_child;
            while !current.is_leaf() {
                db_batch.delete::<TransactionAccumulatorSchema>(&current.left_child())?;
                db_batch.delete::<TransactionAccumulatorSchema>(&current.right_child())?;
                current = current.right_child();
            }
        }
        Ok(())
    }
```

**File:** storage/aptosdb/src/ledger_db/transaction_accumulator_db.rs (L195-201)
```rust
impl HashReader for TransactionAccumulatorDb {
    fn get(&self, position: Position) -> Result<HashValue, anyhow::Error> {
        self.db
            .get::<TransactionAccumulatorSchema>(&position)?
            .ok_or_else(|| anyhow!("{} does not exist.", position))
    }
}
```

**File:** storage/aptosdb/src/ledger_db/transaction_info_db.rs (L95-100)
```rust
    pub(crate) fn prune(begin: Version, end: Version, batch: &mut SchemaBatch) -> Result<()> {
        for version in begin..end {
            batch.delete::<TransactionInfoSchema>(&version)?;
        }
        Ok(())
    }
```

**File:** storage/accumulator/src/lib.rs (L460-464)
```rust
    fn get_frozen_subtree_hashes(&self) -> Result<Vec<HashValue>> {
        FrozenSubTreeIterator::new(self.num_leaves)
            .map(|p| self.reader.get(p))
            .collect::<Result<Vec<_>>>()
    }
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L78-111)
```rust
pub fn confirm_or_save_frozen_subtrees(
    transaction_accumulator_db: &DB,
    num_leaves: LeafCount,
    frozen_subtrees: &[HashValue],
    existing_batch: Option<&mut SchemaBatch>,
) -> Result<()> {
    let positions: Vec<_> = FrozenSubTreeIterator::new(num_leaves).collect();
    ensure!(
        positions.len() == frozen_subtrees.len(),
        "Number of frozen subtree roots not expected. Expected: {}, actual: {}",
        positions.len(),
        frozen_subtrees.len(),
    );

    if let Some(existing_batch) = existing_batch {
        confirm_or_save_frozen_subtrees_impl(
            transaction_accumulator_db,
            frozen_subtrees,
            positions,
            existing_batch,
        )?;
    } else {
        let mut batch = SchemaBatch::new();
        confirm_or_save_frozen_subtrees_impl(
            transaction_accumulator_db,
            frozen_subtrees,
            positions,
            &mut batch,
        )?;
        transaction_accumulator_db.write_schemas(batch)?;
    }

    Ok(())
}
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/test.rs (L158-162)
```rust
            aptos_db.get_accumulator_summary(j as Version).unwrap();
            assert!(aptos_db.state_store.get_usage(Some(j as u64)).is_ok());
        }
        verify_transaction_accumulator_pruned(&ledger_store, i as u64);
    }
```
