# Audit Report

## Title
Race Condition in OrderedBlockWindow Weak Pointer Access Causes Validator Node Panic

## Summary
A Time-of-Check-Time-of-Use (TOCTOU) race condition exists in the consensus layer between block insertion and block pruning. The `insert_block()` function releases its read lock after obtaining an `OrderedBlockWindow` containing weak pointers, then calls `blocks()` without holding any lock. Concurrently, `commit_callback()` can prune and remove blocks from memory, causing weak pointer upgrades to fail and triggering an explicit panic that crashes the validator node.

## Finding Description

The vulnerability stems from the design of `OrderedBlockWindow`, which stores `Weak<PipelinedBlock>` pointers rather than strong `Arc` references to avoid reference cycles. [1](#0-0)  This design creates a critical window where blocks can be dropped between obtaining the window and accessing its contents.

**Vulnerable Code Path:**

In `BlockStore::insert_block()`, the following race condition exists:

1. A read lock is acquired on `self.inner` (BlockTree) and `get_ordered_block_window()` is called, returning an `OrderedBlockWindow` with weak pointers to ancestor blocks [2](#0-1) 

2. The read lock is **immediately released** when the guard goes out of scope at the end of line 424

3. `block_window.blocks()` is called **without holding any lock** [3](#0-2) 

The `OrderedBlockWindow::new()` constructor downgrades all `Arc<PipelinedBlock>` references to `Weak` pointers, leaving the BlockTree's `id_to_block` HashMap as the only source of strong references. [4](#0-3) 

**Panic-Inducing Methods:**

Both `blocks()` and `pipelined_blocks()` methods contain explicit panic statements when weak pointer upgrade fails:

- The `blocks()` method panics with a descriptive error message [5](#0-4) 

- The `pipelined_blocks()` method also panics if upgrade fails [6](#0-5) 

**Concurrent Block Removal:**

During the vulnerable window (after lock release, before `blocks()` call), another thread can execute `commit_callback()` which:

1. Calls `process_pruned_blocks()` to manage memory of pruned blocks [7](#0-6) 

2. When `pruned_block_ids` exceeds `max_pruned_blocks_in_mem` (default 100), removes oldest blocks from memory [8](#0-7) 

3. Removes blocks via `remove_block()`, which deletes them from the `id_to_block` HashMap [9](#0-8) 

When `remove_block()` removes the entry from the HashMap, it drops the `Arc<PipelinedBlock>`. If this was the last strong reference, the block is deallocated, invalidating all weak pointers to it.

**Additional Vulnerable Path:**

The same panic can occur in `find_window_root()`, which calls `pipelined_blocks()` on an `OrderedBlockWindow` during `commit_callback()` execution. [10](#0-9) 

**Test Evidence:**

The codebase contains a test `test_execution_pool_block_window_with_pruning_failure` that explicitly expects a panic when pruned blocks are accessed, confirming the panic behavior is known but occurs under specific conditions. [11](#0-10)  The default production value for `max_pruned_blocks_in_mem` is 100. [12](#0-11) 

## Impact Explanation

**Severity: High** (Validator Node Crash)

This vulnerability causes validator node panics, leading to:

1. **Immediate Node Crash**: When the panic occurs, the validator process terminates, requiring manual restart
2. **Consensus Disruption**: If multiple validators experience this race condition simultaneously during network stress or rapid commits, it degrades consensus performance
3. **Liveness Impact**: Repeated crashes reduce validator availability and network liveness
4. **No Data Corruption**: The panic occurs before state changes, preventing permanent corruption, but requiring node restart for recovery

This meets the **High Severity** criteria per the Aptos bug bounty program for "Validator node slowdowns" and "API crashes." While not causing permanent damage, it creates operational instability that can affect network reliability.

## Likelihood Explanation

**Likelihood: Medium**

The race condition can occur during normal consensus operation when:

1. **Concurrent Operations**: One thread inserts a new block while another commits blocks
2. **Memory Pressure**: When `pruned_block_ids` exceeds 100 blocks, oldest pruned blocks are removed from memory
3. **High Throughput**: Faster block production increases timing overlap probability

The vulnerability is more likely during:
- Network synchronization when nodes catch up on blocks
- High transaction throughput periods with rapid commits
- Validator restarts when replaying historical blocks
- Fork resolution scenarios with multiple concurrent branches

The race window is small (microseconds to milliseconds), but the high frequency of block operations in production blockchains creates a non-negligible cumulative probability over time.

## Recommendation

**Fix 1: Hold Lock During blocks() Call**

Extend the read lock scope to cover the `blocks()` call:

```rust
let blocks = {
    let guard = self.inner.read();
    let block_window = guard.get_ordered_block_window(&block, self.window_size)?;
    block_window.blocks()
};
```

**Fix 2: Return Strong References**

Modify `OrderedBlockWindow` to return `Arc<PipelinedBlock>` instead of weak pointers, or clone the blocks while holding the lock to ensure strong references exist during the vulnerable window.

**Fix 3: Graceful Error Handling**

Replace panic with error return in `blocks()` and `pipelined_blocks()` methods, allowing callers to handle missing blocks gracefully (e.g., by retrying or requesting the block again).

## Proof of Concept

The existing test demonstrates the panic behavior:

```rust
// From consensus/src/block_storage/execution_pool/block_window_test.rs:104-126
#[should_panic]
#[tokio::test]
async fn test_execution_pool_block_window_with_pruning_failure() {
    const NUM_BLOCKS: usize = 5;
    let window_size = Some(3u64);
    let max_pruned_blocks_in_mem: usize = 0; // Force immediate removal
    
    let (_, block_store, pipelined_blocks) = create_block_tree_no_forks_inner::<{ NUM_BLOCKS }>(
        NUM_BLOCKS as u64,
        window_size,
        max_pruned_blocks_in_mem,
    ).await;
    let [_, _, a2, a3, _] = pipelined_blocks;
    
    block_store.prune_tree(a3.id());
    
    // a2 was pruned and removed, accessing it will panic
    get_blocks_from_block_store_and_window(block_store.clone(), a2.block(), window_size);
}
```

To reproduce with production settings, run validators under high load with many commits exceeding the 100-block pruned memory threshold, then observe intermittent panics during concurrent block insertion and commit operations.

## Notes

This vulnerability exists due to an intentional design choice to use weak pointers to break reference cycles (as noted in the code comment at `consensus/src/block_storage/block_store.rs:469`). However, this design creates a race condition that was not fully mitigated. The test suite demonstrates awareness of the panic behavior but only tests it under artificial conditions (`max_pruned_blocks_in_mem = 0`), not the production default of 100 where the issue can still manifest under high load.

### Citations

**File:** consensus/consensus-types/src/pipelined_block.rs (L136-140)
```rust
pub struct OrderedBlockWindow {
    /// `block_id` (HashValue) helps with logging in the unlikely case there are issues upgrading
    /// the `Weak` pointer (we can use `block_id`)
    blocks: Vec<(HashValue, Weak<PipelinedBlock>)>,
}
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L143-149)
```rust
    pub fn new(blocks: Vec<Arc<PipelinedBlock>>) -> Self {
        Self {
            blocks: blocks
                .iter()
                .map(|x| (x.id(), Arc::downgrade(x)))
                .collect::<Vec<(HashValue, Weak<PipelinedBlock>)>>(),
        }
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L161-175)
```rust
    pub fn blocks(&self) -> Vec<Block> {
        let mut blocks: Vec<Block> = vec![];
        for (block_id, block) in self.blocks.iter() {
            let upgraded_block = block.upgrade();
            if let Some(block) = upgraded_block {
                blocks.push(block.block().clone())
            } else {
                panic!(
                    "Block with id: {} not found during upgrade in OrderedBlockWindow::blocks()",
                    block_id
                )
            }
        }
        blocks
    }
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L177-190)
```rust
    pub fn pipelined_blocks(&self) -> Vec<Arc<PipelinedBlock>> {
        let mut blocks: Vec<Arc<PipelinedBlock>> = Vec::new();
        for (block_id, block) in self.blocks.iter() {
            if let Some(block) = block.upgrade() {
                blocks.push(block);
            } else {
                panic!(
                    "Block with id: {} not found during upgrade in OrderedBlockWindow::pipelined_blocks()",
                    block_id
                )
            }
        }
        blocks
    }
```

**File:** consensus/src/block_storage/block_store.rs (L421-424)
```rust
        let block_window = self
            .inner
            .read()
            .get_ordered_block_window(&block, self.window_size)?;
```

**File:** consensus/src/block_storage/block_store.rs (L425-425)
```rust
        let blocks = block_window.blocks();
```

**File:** consensus/src/block_storage/block_tree.rs (L174-181)
```rust
    fn remove_block(&mut self, block_id: HashValue) {
        // Remove the block from the store
        if let Some(block) = self.id_to_block.remove(&block_id) {
            let round = block.executed_block().round();
            self.round_to_ids.remove(&round);
        };
        self.id_to_quorum_cert.remove(&block_id);
    }
```

**File:** consensus/src/block_storage/block_tree.rs (L467-489)
```rust
    pub(super) fn find_window_root(
        &self,
        block_to_commit_id: HashValue,
        window_size: Option<u64>,
    ) -> HashValue {
        // Window Size is None only if execution pool is off
        if let Some(window_size) = window_size {
            assert_ne!(window_size, 0, "Window size must be greater than 0");
        }

        // Try to get the block, then the ordered window, then the first block's parent ID
        let block = self
            .get_block(&block_to_commit_id)
            .expect("Block not found");
        let ordered_block_window = self
            .get_ordered_block_window(block.block(), window_size)
            .expect("Ordered block window not found");
        let pipelined_blocks = ordered_block_window.pipelined_blocks();

        // If the first block is None, it falls back on the current block as the window root
        let window_root_block = pipelined_blocks.first().unwrap_or(&block);
        window_root_block.id()
    }
```

**File:** consensus/src/block_storage/block_tree.rs (L496-510)
```rust
    pub(super) fn process_pruned_blocks(&mut self, mut newly_pruned_blocks: VecDeque<HashValue>) {
        counters::NUM_BLOCKS_IN_TREE.sub(newly_pruned_blocks.len() as i64);
        // The newly pruned blocks are pushed back to the deque pruned_block_ids.
        // In case the overall number of the elements is greater than the predefined threshold,
        // the oldest elements (in the front of the deque) are removed from the tree.
        self.pruned_block_ids.append(&mut newly_pruned_blocks);
        if self.pruned_block_ids.len() > self.max_pruned_blocks_in_mem {
            let num_blocks_to_remove = self.pruned_block_ids.len() - self.max_pruned_blocks_in_mem;
            for _ in 0..num_blocks_to_remove {
                if let Some(id) = self.pruned_block_ids.pop_front() {
                    self.remove_block(id);
                }
            }
        }
    }
```

**File:** consensus/src/block_storage/block_tree.rs (L567-600)
```rust
    pub fn commit_callback(
        &mut self,
        storage: Arc<dyn PersistentLivenessStorage>,
        block_id: HashValue,
        block_round: Round,
        finality_proof: WrappedLedgerInfo,
        commit_decision: LedgerInfoWithSignatures,
        window_size: Option<u64>,
    ) {
        let current_round = self.commit_root().round();
        let committed_round = block_round;
        let commit_proof = finality_proof
            .create_merged_with_executed_state(commit_decision)
            .expect("Inconsistent commit proof and evaluation decision, cannot commit block");

        debug!(
            LogSchema::new(LogEvent::CommitViaBlock).round(current_round),
            committed_round = committed_round,
            block_id = block_id,
        );

        let window_root_id = self.find_window_root(block_id, window_size);
        let ids_to_remove = self.find_blocks_to_prune(window_root_id);

        if let Err(e) = storage.prune_tree(ids_to_remove.clone().into_iter().collect()) {
            // it's fine to fail here, as long as the commit succeeds, the next restart will clean
            // up dangling blocks, and we need to prune the tree to keep the root consistent with
            // executor.
            warn!(error = ?e, "fail to delete block");
        }
        self.process_pruned_blocks(ids_to_remove);
        self.update_window_root(window_root_id);
        self.update_highest_commit_cert(commit_proof);
    }
```

**File:** consensus/src/block_storage/execution_pool/block_window_test.rs (L104-126)
```rust
/// `get_block_window` on a block that has been pruned. Should panic if the
/// `max_pruned_blocks_in_mem` is 0.
#[should_panic]
#[tokio::test]
async fn test_execution_pool_block_window_with_pruning_failure() {
    const NUM_BLOCKS: usize = 5;
    let window_size = Some(3u64);

    // No pruned blocks are not kept in the block store if this is set to 0
    let max_pruned_blocks_in_mem: usize = 0;
    let (_, block_store, pipelined_blocks) = create_block_tree_no_forks_inner::<{ NUM_BLOCKS }>(
        NUM_BLOCKS as u64,
        window_size,
        max_pruned_blocks_in_mem,
    )
    .await;
    let [_, _, a2, a3, _] = pipelined_blocks;

    block_store.prune_tree(a3.id());

    // a2 was pruned, no longer exists in the block_store
    get_blocks_from_block_store_and_window(block_store.clone(), a2.block(), window_size);
}
```

**File:** config/src/config/consensus_config.rs (L232-232)
```rust
            max_pruned_blocks_in_mem: 100,
```
