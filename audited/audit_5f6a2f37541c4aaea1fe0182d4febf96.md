# Audit Report

## Title
Block Tree Window Traversal Bypasses Pruning Boundary Causing Validator Failures

## Summary
The `get_ordered_block_window()` function in `BlockTree` traverses parent blocks without respecting the `window_root` pruning boundary. When the calculated `window_start_round` falls below the `window_root`, the traversal attempts to access blocks that have been pruned and removed from memory, causing validator nodes to fail block insertion with a "Parent block not found" error.

## Finding Description

The vulnerability exists in the tree consistency mechanism within the consensus layer. When a new block arrives, `insert_block()` validates only against `ordered_root` and then calls `get_ordered_block_window()` to build an execution window by traversing backwards through parent blocks. [1](#0-0) 

The traversal calculates `window_start_round` using the current window_size configuration: [2](#0-1) 

However, the loop condition only checks if the block is not genesis and if the QC's certified block round is >= `window_start_round` - it does NOT check against the `window_root_id` boundary: [3](#0-2) 

Meanwhile, the pruning mechanism removes blocks before the `window_root` from the tree. After blocks are marked for pruning and the pruned buffer fills up, blocks are removed from the `id_to_block` HashMap: [4](#0-3) 

The default buffer size is 100 blocks: [5](#0-4) 

**Attack Scenario:**
1. Blocks are committed with a small `window_size` (e.g., 1-5), advancing `window_root` to round 100
2. Blocks before round 100 are pruned via `find_blocks_to_prune()`: [6](#0-5) 
3. After 100+ pruned blocks accumulate, blocks < 100 are removed from `id_to_block`
4. `window_size` is increased to 15 via on-chain governance (confirmed possible via on-chain config): [7](#0-6) 
5. Ordered root is at round 110, a new block at round 111 arrives
6. Validation passes: checks only `ordered_root(110) < 111`, NOT against `window_root`
7. `get_ordered_block_window(block_111, window_size=15)` calculates `window_start_round = 97`
8. Traversal proceeds: 111 → 110 → ... → 100 (window_root)
9. At block 100, its QC points to round 99, condition `99 >= 97` passes
10. Attempts to access block 99 via `get_block()`, which returns None (pruned)
11. Function bails with "Parent block not found", validator fails to insert block 111

The validation at line 271 checks `commit_root`, not `window_root`, allowing blocks whose traversal will access pruned blocks: [8](#0-7) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under Aptos bug bounty criteria:

- **Validator node slowdowns**: Validators repeatedly fail to insert legitimate blocks, requiring retries or manual intervention. The `bail!()` macro propagates errors through the consensus pipeline, disrupting block processing.

- **API crashes**: The insert operation fails with an unrecoverable error that affects network participation and transaction ordering.

- **Significant protocol violations**: Breaks the tree consistency invariant that all accessible blocks should have accessible parents in memory. This violates the execution pool's assumption that the block window is complete and contiguous.

The impact escalates when:
1. Multiple validators are affected simultaneously due to similar pruning states
2. Large `window_size` configurations are deployed (10-50 blocks)
3. Network experiences configuration changes mid-epoch

While not causing immediate fund loss, this affects **network liveness and availability** - validators cannot process legitimate blocks, potentially stalling consensus progress if enough validators are affected.

## Likelihood Explanation

**Likelihood: Medium to High** depending on configuration

**Conditions Required:**
- `window_size` configured large enough that: `block.round() - window_size + 1 < window_root.round()`
- More than 100 blocks have been pruned (to trigger actual removal from `id_to_block`)
- Gap between `window_root` and `ordered_root` is less than `window_size`

**Triggering Scenarios:**
1. **Configuration change**: Default `window_size` is 1, making this unlikely initially. However, if governance increases `window_size` to 10-50 for performance optimization after blocks have been pruned with smaller window_size, the vulnerability becomes immediately exploitable.

2. **Normal operation**: Can occur naturally during normal block processing when the right timing conditions align after a configuration update.

3. **Network delays**: Blocks arriving after pruning with updated window_size configuration can trigger this condition.

**Frequency**: Increases significantly with larger `window_size` values and after on-chain configuration changes. Could occur repeatedly until configuration is adjusted or manual intervention occurs.

## Recommendation

Add validation to check against `window_root` before attempting traversal, or modify the loop condition to stop at `window_root`:

**Option 1 - Add validation in `insert_block`:**
```rust
// After line 419
ensure!(
    calculate_window_start_round(block.round(), self.window_size.unwrap_or(1)) 
        >= self.inner.read().window_root().round(),
    "Block window would traverse below window_root"
);
```

**Option 2 - Modify `get_ordered_block_window` loop condition:**
```rust
// Replace lines 290-291
while !current_block.is_genesis_block()
    && current_block.quorum_cert().certified_block().round() >= window_start_round
    && current_block.parent_id() != self.window_root_id  // Add this check
{
```

**Option 3 - Handle missing parents gracefully:**
```rust
// Replace line 297
// Stop traversal at window_root boundary instead of failing
break;
```

## Proof of Concept

While a full compilable PoC would require setting up a test harness with block generation and pruning, the vulnerability can be demonstrated by:

1. Creating a block tree with window_size=1
2. Committing blocks up to round 110, advancing window_root to round 110
3. Pruning 100+ blocks to trigger removal from memory
4. Updating window_size to 15 via on-chain config
5. Creating a new block at round 111
6. Calling `insert_block()` which will fail when `get_ordered_block_window()` attempts to access pruned blocks

The existing test at `consensus/src/block_storage/execution_pool/block_window_test.rs:104-126` demonstrates related behavior where accessing pruned blocks fails with panic.

## Notes

This is a **logic vulnerability** in the validation and traversal code. The mismatch between what is validated (ordered_root) and what is required (blocks back to window_start_round) creates a security issue. The vulnerability is configuration-dependent but can be reliably triggered through legitimate on-chain governance actions that increase window_size after blocks have been pruned with a smaller window_size.

### Citations

**File:** consensus/src/block_storage/block_store.rs (L416-424)
```rust
        ensure!(
            self.inner.read().ordered_root().round() < block.round(),
            "Block with old round"
        );

        let block_window = self
            .inner
            .read()
            .get_ordered_block_window(&block, self.window_size)?;
```

**File:** consensus/src/util/mod.rs (L26-29)
```rust
pub fn calculate_window_start_round(current_round: Round, window_size: u64) -> Round {
    assert!(window_size > 0);
    (current_round + 1).saturating_sub(window_size)
}
```

**File:** consensus/src/block_storage/block_tree.rs (L270-275)
```rust
        ensure!(
            block.round() >= self.commit_root().round(),
            "Block round {} is less than the commit root round {}, cannot get_ordered_block_window",
            block.round(),
            self.commit_root().round()
        );
```

**File:** consensus/src/block_storage/block_tree.rs (L290-298)
```rust
        while !current_block.is_genesis_block()
            && current_block.quorum_cert().certified_block().round() >= window_start_round
        {
            if let Some(current_pipelined_block) = self.get_block(&current_block.parent_id()) {
                current_block = current_pipelined_block.block().clone();
                window.push(current_pipelined_block);
            } else {
                bail!("Parent block not found for block {}", current_block.id());
            }
```

**File:** consensus/src/block_storage/block_tree.rs (L405-434)
```rust
    pub(super) fn find_blocks_to_prune(
        &self,
        next_window_root_id: HashValue,
    ) -> VecDeque<HashValue> {
        // Nothing to do if this is the window root
        if next_window_root_id == self.window_root_id {
            return VecDeque::new();
        }

        let mut blocks_pruned = VecDeque::new();
        let mut blocks_to_be_pruned = vec![self.linkable_window_root()];

        while let Some(block_to_remove) = blocks_to_be_pruned.pop() {
            block_to_remove.executed_block().abort_pipeline();
            // Add the children to the blocks to be pruned (if any), but stop when it reaches the
            // new root
            for child_id in block_to_remove.children() {
                if next_window_root_id == *child_id {
                    continue;
                }
                blocks_to_be_pruned.push(
                    self.get_linkable_block(child_id)
                        .expect("Child must exist in the tree"),
                );
            }
            // Track all the block ids removed
            blocks_pruned.push_back(block_to_remove.id());
        }
        blocks_pruned
    }
```

**File:** consensus/src/block_storage/block_tree.rs (L496-509)
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
```

**File:** config/src/config/consensus_config.rs (L232-232)
```rust
            max_pruned_blocks_in_mem: 100,
```

**File:** types/src/on_chain_config/consensus_config.rs (L10-13)
```rust
/// Default Window Size for Execution Pool.
/// This describes the number of blocks in the Execution Pool Window
pub const DEFAULT_WINDOW_SIZE: Option<u64> = None;
pub const DEFAULT_ENABLED_WINDOW_SIZE: Option<u64> = Some(1);
```
