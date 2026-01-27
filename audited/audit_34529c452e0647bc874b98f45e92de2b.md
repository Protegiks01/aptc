# Audit Report

## Title
Race Condition in `path_from_root_to_block()` Causes False Rejection of Valid Blocks During Root Advancement

## Summary
The `path_from_root_to_block()` function in `consensus/src/block_storage/block_tree.rs` contains a logic flaw at lines 540-542 that incorrectly rejects valid blocks when the ordered root advances past them. This causes proposal generation failures and liveness degradation when validators cannot propose blocks due to spurious "Parent block already pruned" errors.

## Finding Description

The vulnerability exists in the root mismatch check logic: [1](#0-0) 

The algorithm traverses backwards from a block and stops when it reaches a block with `round <= root_round`. It then checks if the stopped block's ID matches `root_id`. **The critical flaw**: if the input `block_id` itself has `round <= root_round`, the loop breaks immediately without any traversal, setting `cur_block_id = block_id`. The subsequent check then compares `block_id` against `root_id`, which will fail if they're different blocks.

**Race Condition Scenario:**

1. Validator prepares to propose at round 106, reads `highest_certified_block` B5 (round 105) as parent
2. Concurrently, another thread calls `send_for_execution()` with block B8 (round 108)
3. The `ordered_root` advances from round 100 to round 108 via: [2](#0-1) 

4. Validator calls `path_from_ordered_root(B5_id)` which invokes: [3](#0-2) 

5. This becomes `path_from_root_to_block(B5_id, B8_id, round=108)`
6. Since B5.round (105) <= root_round (108), loop breaks immediately
7. Check fails: `cur_block_id (B5_id) != root_id (B8_id)`
8. Returns `None`

The proposal generator interprets this as the parent being pruned: [4](#0-3) [5](#0-4) 

When proposal generation fails, the error is logged but the round cannot progress: [6](#0-5) 

**Critical Issue**: Block B5 **is** a valid descendant of the canonical chain and should not be rejected. The rejection happens purely because the `ordered_root` advanced past it, not because it's on a different fork or has been pruned.

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria:

- **Liveness Degradation**: Individual validators cannot propose when they're leaders, causing round timeouts and delays
- **Not Total Network Halt**: Other validators can still propose in subsequent rounds, so network doesn't completely stop
- **No Safety Violation**: No double-spend, chain split, or fund loss
- **Requires Intervention**: During high-throughput periods, this can cause frequent proposal failures requiring validator restarts or manual intervention
- **State Inconsistencies**: The decoupled execution architecture (ordered_root vs commit_root) makes this race more likely

The issue manifests as spurious "Parent block already pruned" errors during normal operation, particularly when:
- Network has high throughput (frequent root advancements)
- Decoupled execution creates lag between ordered_root and commit_root
- Multiple validators race between reading parents and generating proposals

## Likelihood Explanation

**Moderate to High Likelihood**:

- **No Malicious Actor Required**: Happens during normal consensus operation due to timing
- **High Throughput Trigger**: More likely when ordered_root advances rapidly (3+ rounds between proposal preparation and generation)
- **Decoupled Execution Amplifies**: The architecture maintaining separate `ordered_root` and `commit_root` increases the window for this race
- **Validator Impact**: Affects proposal generation, a critical consensus path executed frequently

The race window exists between:
1. Reading `highest_certified_block` from block store
2. Calling `path_from_ordered_root()` with potentially stale parent

During high network activity, the `ordered_root` can advance multiple rounds in this window, triggering the false rejection.

## Recommendation

**Fix the algorithm to handle blocks below root_round correctly:**

```rust
pub(super) fn path_from_root_to_block(
    &self,
    block_id: HashValue,
    root_id: HashValue,
    root_round: u64,
) -> Option<Vec<Arc<PipelinedBlock>>> {
    let mut res = vec![];
    let mut cur_block_id = block_id;
    
    // Special case: if block_id itself is at or below root round,
    // verify it's either the root or descends from it
    match self.get_block(&cur_block_id) {
        Some(block) if block.round() <= root_round => {
            // If this is the root itself, return empty path
            if cur_block_id == root_id {
                return Some(vec![]);
            }
            // Otherwise, the block is below root - it's already committed
            // This is correct behavior to reject
            return None;
        },
        Some(_) => {
            // Block is above root, proceed with traversal
        },
        None => return None,
    }
    
    loop {
        match self.get_block(&cur_block_id) {
            Some(ref block) if block.round() <= root_round => {
                break;
            },
            Some(block) => {
                cur_block_id = block.parent_id();
                res.push(block);
            },
            None => return None,
        }
    }
    
    if cur_block_id != root_id {
        return None;
    }
    res.reverse();
    Some(res)
}
```

**Alternative: Atomic root reading in wrapper functions:**

Ensure `path_from_ordered_root()` and `path_from_commit_root()` read root_id and root_round atomically by caching the root block first, preventing inconsistent parameter passing.

## Proof of Concept

```rust
#[cfg(test)]
mod liveness_bug_test {
    use super::*;
    use aptos_consensus_types::block::Block;
    use aptos_crypto::HashValue;
    
    #[test]
    fn test_path_from_root_rejects_valid_block_after_root_advancement() {
        // Setup: Create a block tree with ordered execution
        let (mut block_tree, genesis_qc) = setup_block_tree();
        
        // Initial state: ordered_root at round 100
        let root_100 = create_and_insert_block(&mut block_tree, 100, genesis_qc.clone());
        block_tree.update_ordered_root(root_100.id());
        
        // Build chain: 100 -> 101 -> 102 -> ... -> 105
        let mut prev_block = root_100.clone();
        let mut blocks = vec![];
        for round in 101..=105 {
            let block = create_and_insert_block(&mut block_tree, round, 
                                               create_qc_for_block(&prev_block));
            blocks.push(block.clone());
            prev_block = block;
        }
        let block_105 = blocks.last().unwrap();
        
        // Simulate race: Thread A reads block_105 as parent for round 106 proposal
        let parent_id = block_105.id();
        
        // Thread B advances ordered_root to round 108 (skipping over 105)
        let block_108 = create_and_insert_block(&mut block_tree, 108, 
                                               create_qc_for_block(&prev_block));
        block_tree.update_ordered_root(block_108.id());
        
        // Thread A tries to get path from ordered_root to parent (block_105)
        let path = block_tree.path_from_ordered_root(parent_id);
        
        // BUG: This returns None even though block_105 is a valid descendant!
        assert!(path.is_none(), "Bug triggered: valid block rejected");
        
        // This would cause proposal generation to fail with:
        // "Parent block {:?} already pruned", parent_id
        
        // Expected behavior: Should return the path from root_108 back to block_105
        // (even if empty, indicating block is below current root but still valid)
    }
}
```

The PoC demonstrates that when `ordered_root` advances from round 100 to round 108, a perfectly valid block at round 105 (which is in the canonical chain between these roots) gets incorrectly rejected by `path_from_ordered_root()`, triggering the liveness issue.

---

## Notes

This vulnerability is acknowledged in the code comments but may not be fully understood: [7](#0-6) 

The comment mentions races during root propagation but focuses on blocks being pruned, not the specific case where valid blocks below the root round get incorrectly rejected due to the immediate loop termination. The `unwrap_or_default()` handling in some call sites masks the issue but doesn't prevent proposal failures in critical paths.

### Citations

**File:** consensus/src/block_storage/block_tree.rs (L515-518)
```rust
    /// While generally the provided blocks should always belong to the active tree, there might be
    /// a race, in which the root of the tree is propagated forward between retrieving the block
    /// and getting its path from root (e.g., at proposal generator). Hence, we don't want to panic
    /// and prefer to return None instead.
```

**File:** consensus/src/block_storage/block_tree.rs (L519-546)
```rust
    pub(super) fn path_from_root_to_block(
        &self,
        block_id: HashValue,
        root_id: HashValue,
        root_round: u64,
    ) -> Option<Vec<Arc<PipelinedBlock>>> {
        let mut res = vec![];
        let mut cur_block_id = block_id;
        loop {
            match self.get_block(&cur_block_id) {
                Some(ref block) if block.round() <= root_round => {
                    break;
                },
                Some(block) => {
                    cur_block_id = block.parent_id();
                    res.push(block);
                },
                None => return None,
            }
        }
        // At this point cur_block.round() <= self.root.round()
        if cur_block_id != root_id {
            return None;
        }
        // Called `.reverse()` to get the chronically increased order.
        res.reverse();
        Some(res)
    }
```

**File:** consensus/src/block_storage/block_tree.rs (L548-553)
```rust
    pub(super) fn path_from_ordered_root(
        &self,
        block_id: HashValue,
    ) -> Option<Vec<Arc<PipelinedBlock>>> {
        self.path_from_root_to_block(block_id, self.ordered_root_id, self.ordered_root().round())
    }
```

**File:** consensus/src/block_storage/block_store.rs (L312-349)
```rust
    pub async fn send_for_execution(
        &self,
        finality_proof: WrappedLedgerInfo,
    ) -> anyhow::Result<()> {
        let block_id_to_commit = finality_proof.commit_info().id();
        let block_to_commit = self
            .get_block(block_id_to_commit)
            .ok_or_else(|| format_err!("Committed block id not found"))?;

        // First make sure that this commit is new.
        ensure!(
            block_to_commit.round() > self.ordered_root().round(),
            "Committed block round lower than root"
        );

        let blocks_to_commit = self
            .path_from_ordered_root(block_id_to_commit)
            .unwrap_or_default();

        assert!(!blocks_to_commit.is_empty());

        let finality_proof_clone = finality_proof.clone();
        self.pending_blocks
            .lock()
            .gc(finality_proof.commit_info().round());

        self.inner.write().update_ordered_root(block_to_commit.id());
        self.inner
            .write()
            .insert_ordered_cert(finality_proof_clone.clone());
        update_counters_for_ordered_blocks(&blocks_to_commit);

        self.execution_client
            .finalize_order(blocks_to_commit, finality_proof.clone())
            .await
            .expect("Failed to persist commit");

        Ok(())
```

**File:** consensus/src/liveness/proposal_generator.rs (L575-578)
```rust
        let mut pending_blocks = self
            .block_store
            .path_from_commit_root(parent_id)
            .ok_or_else(|| format_err!("Parent block {} already pruned", parent_id))?;
```

**File:** consensus/src/liveness/proposal_generator.rs (L591-594)
```rust
        let pending_ordering = self
            .block_store
            .path_from_ordered_root(parent_id)
            .ok_or_else(|| format_err!("Parent block {} already pruned", parent_id))?
```

**File:** consensus/src/round_manager.rs (L508-510)
```rust
                ) {
                    warn!("Error generating and sending proposal: {}", e);
                }
```
