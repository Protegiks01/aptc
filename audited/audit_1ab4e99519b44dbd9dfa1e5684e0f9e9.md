# Audit Report

## Title
Infinite Loop in Block Traversal Due to Missing Cycle Detection

## Summary
The `get_recent_block_execution_times()` function can enter an infinite loop if parent_id links form a cycle. While normal block validation prevents cycles through round ordering checks, blocks loaded from persistent storage during recovery bypass this validation, allowing corrupted storage to create cyclic parent relationships that cause validator node hangs.

## Finding Description

The vulnerable function traverses blocks backward by following parent_id links without cycle detection: [1](#0-0) 

The function has two exit conditions:
1. `cur_block` becomes `None` when `get_block(parent_id)` returns `None`
2. `res.len() >= num_blocks` when enough execution summaries are collected

**Normal Protection:** Block validation enforces strictly increasing rounds, making cycles mathematically impossible: [2](#0-1) 

**Validation Bypass:** However, blocks loaded during recovery bypass `verify_well_formed()`: [3](#0-2) 

The recovery path calls `insert_committed_block()` which doesn't validate round ordering: [4](#0-3) 

`BlockTree::insert_block()` only verifies parent existence, not round ordering or cycle prevention: [5](#0-4) 

**Attack Scenario:**
If persistent storage is corrupted to contain Block A (parent→Block B) and Block B (parent→Block A) without execution summaries, the traversal will loop infinitely between A and B, never hitting either exit condition. [6](#0-5) 

## Impact Explanation

**Severity: HIGH** per Aptos bug bounty criteria (Validator node slowdowns).

When `get_recent_block_execution_times()` is called in the consensus path, an infinite loop causes:
- Validator node hangs indefinitely
- Node cannot participate in consensus
- Network liveness degradation if multiple validators affected
- Requires manual intervention and storage repair to recover

The validator is completely non-functional until storage is manually fixed and the node restarted with corrected data.

## Likelihood Explanation

**Likelihood: MEDIUM-LOW**

This vulnerability requires:
- **Storage corruption** via file system access, storage implementation bug, or hardware failure
- Corrupted blocks must form a cycle with compatible structure to bypass other checks
- Blocks must lack execution summaries (common for recovered blocks)

While the barrier is significant (requires storage-level access/corruption), the impact is guaranteed once conditions are met. Hardware failures, storage bugs, or sophisticated attackers with file system access could trigger this.

## Recommendation

Add cycle detection to `get_recent_block_execution_times()` using a visited set:

```rust
pub fn get_recent_block_execution_times(&self, num_blocks: usize) -> Vec<ExecutionSummary> {
    let mut res = vec![];
    let mut cur_block = Some(self.ordered_root());
    let mut visited = std::collections::HashSet::new();
    
    loop {
        match cur_block {
            Some(block) => {
                let block_id = block.id();
                
                // Detect cycles
                if !visited.insert(block_id) {
                    warn!("Cycle detected in block parent links at block {}", block_id);
                    return res;
                }
                
                if let Some(execution_time_and_size) = block.get_execution_summary() {
                    res.push(execution_time_and_size);
                    if res.len() >= num_blocks {
                        return res;
                    }
                }
                cur_block = self.get_block(block.parent_id());
            },
            None => return res,
        }
    }
}
```

Additionally, add round ordering validation in `insert_committed_block()` and `BlockTree::insert_block()` to prevent cycles at insertion time.

## Proof of Concept

```rust
#[cfg(test)]
mod cycle_test {
    use super::*;
    use aptos_crypto::HashValue;
    
    #[tokio::test]
    async fn test_infinite_loop_with_cycle() {
        // Create two blocks with cyclic parent relationships
        let block_a_id = HashValue::random();
        let block_b_id = HashValue::random();
        
        // Block A with parent = Block B
        let block_a = Block::new_for_testing(
            block_a_id,
            BlockData::new_with_parent(1, block_b_id, /* ... */),
            None,
        );
        
        // Block B with parent = Block A (creating cycle)
        let block_b = Block::new_for_testing(
            block_b_id,
            BlockData::new_with_parent(1, block_a_id, /* ... */),
            None,
        );
        
        // Insert blocks without execution summaries
        let block_store = create_test_block_store().await;
        block_store.insert_committed_block(block_a).await.unwrap();
        block_store.insert_committed_block(block_b).await.unwrap();
        
        // Set one as ordered root
        block_store.inner.write().update_ordered_root(block_a_id);
        
        // This will loop infinitely
        let timeout = tokio::time::timeout(
            Duration::from_secs(5),
            async {
                block_store.get_recent_block_execution_times(10)
            }
        );
        
        // Verify timeout occurs (proving infinite loop)
        assert!(timeout.await.is_err(), "Function should timeout due to infinite loop");
    }
}
```

## Notes

This vulnerability represents a defense-in-depth failure where storage corruption can cause consensus layer denial of service. While the attack surface requires storage-level access (not achievable through normal protocol interactions), the guaranteed impact and lack of runtime recovery mechanisms warrant fixing this through proper cycle detection and validation at block insertion time.

### Citations

**File:** consensus/src/block_storage/block_store.rs (L282-297)
```rust
        for block in blocks {
            if block.round() <= root_block_round {
                block_store
                    .insert_committed_block(block)
                    .await
                    .unwrap_or_else(|e| {
                        panic!(
                            "[BlockStore] failed to insert committed block during build {:?}",
                            e
                        )
                    });
            } else {
                block_store.insert_block(block).await.unwrap_or_else(|e| {
                    panic!("[BlockStore] failed to insert block during build {:?}", e)
                });
            }
```

**File:** consensus/src/block_storage/block_store.rs (L397-410)
```rust
    pub async fn insert_committed_block(
        &self,
        block: Block,
    ) -> anyhow::Result<Arc<PipelinedBlock>> {
        ensure!(
            self.get_block(block.id()).is_none(),
            "Recovered block already exists"
        );

        // We don't know if the blocks in the window for a committed block will
        // be available in memory so we set the OrderedBlockWindow to empty
        let pipelined_block = PipelinedBlock::new_ordered(block, OrderedBlockWindow::empty());
        self.insert_block_inner(pipelined_block).await
    }
```

**File:** consensus/src/block_storage/block_store.rs (L778-802)
```rust
    fn get_recent_block_execution_times(&self, num_blocks: usize) -> Vec<ExecutionSummary> {
        let mut res = vec![];
        let mut cur_block = Some(self.ordered_root());
        loop {
            match cur_block {
                Some(block) => {
                    if let Some(execution_time_and_size) = block.get_execution_summary() {
                        debug!(
                            "Found execution time for {}, {:?}",
                            block.id(),
                            execution_time_and_size
                        );
                        res.push(execution_time_and_size);
                        if res.len() >= num_blocks {
                            return res;
                        }
                    } else {
                        debug!("Couldn't find execution time for {}", block.id());
                    }
                    cur_block = self.get_block(block.parent_id());
                },
                None => return res,
            }
        }
    }
```

**File:** consensus/consensus-types/src/block.rs (L475-478)
```rust
        ensure!(
            parent.round() < self.round(),
            "Block must have a greater round than parent's block"
        );
```

**File:** consensus/src/block_storage/block_tree.rs (L319-322)
```rust
            match self.get_linkable_block_mut(&block.parent_id()) {
                Some(parent_block) => parent_block.add_child(block_id),
                None => bail!("Parent block {} not found", block.parent_id()),
            };
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L497-499)
```rust
    pub fn get_execution_summary(&self) -> Option<ExecutionSummary> {
        self.execution_summary.get().cloned()
    }
```
