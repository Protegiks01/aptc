# Audit Report

## Title
Time-of-Check-Time-of-Use Race Condition in Block Ordering Causes Validator Node Crash

## Summary
The `send_for_execution` method in `BlockStore` contains a TOCTOU race condition where `ordered_root` can advance between validation checks and path retrieval, causing an assertion failure that crashes validator nodes during concurrent block ordering operations.

## Finding Description

The `BlockStore::send_for_execution` method performs non-atomic read operations across multiple separate lock acquisitions, creating a race condition window. [1](#0-0) 

The vulnerability occurs through this sequence:

1. Thread A calls `send_for_execution(block_B10)` when `ordered_root = B5`
2. Thread A acquires a read lock, retrieves block B10, releases lock
3. Thread A acquires another read lock, validates `B10.round() > ordered_root().round()` (10 > 5), releases lock  
4. Thread B concurrently calls `send_for_execution(block_B12)` and completes execution, updating `ordered_root` to B12
5. Thread A acquires a read lock and calls `path_from_ordered_root(B10)`
6. The path traversal algorithm walks backward from B10 and checks if the block's round ≤ root_round [2](#0-1) 
7. Since B10.round (10) ≤ ordered_root().round (12), it breaks immediately
8. The algorithm then validates `cur_block_id == root_id` [3](#0-2) 
9. Since B10 ≠ B12, `path_from_ordered_root` returns `None`
10. `unwrap_or_default()` converts `None` to an empty vector
11. The assertion `assert!(!blocks_to_commit.is_empty())` fails, crashing the validator node

This directly relates to the security question because:
- `get_block()` successfully returns block B10 even though it may be marked for pruning or about to become stale
- The non-atomic reads allow `ordered_root` to advance, making the previously-retrieved block inconsistent with current state
- The use of this "stale" block reference (B10) in subsequent operations causes the crash

## Impact Explanation

**Severity: High** (up to $50,000 per Aptos Bug Bounty)

This vulnerability causes validator node crashes, which falls under High Severity "API crashes" and impacts network liveness. Multiple concurrent commits during normal consensus operation can trigger this race condition, causing affected validators to crash and temporarily reducing network capacity. While not causing loss of funds or permanent network partition, repeated crashes could significantly degrade network performance and validator reliability.

## Likelihood Explanation

**Likelihood: Medium to High**

This race condition can occur during normal network operation without requiring attacker intervention:
- Consensus naturally processes multiple blocks concurrently via async execution
- The probability increases during periods of high block production rate
- No special timing or coordination is required - concurrent `send_for_execution` calls from processing different QCs naturally create the race window
- The vulnerability is deterministic once the race condition window is entered

## Recommendation

Acquire and hold a single write lock for the entire duration of validation and state updates in `send_for_execution`:

```rust
pub async fn send_for_execution(&self, finality_proof: WrappedLedgerInfo) -> anyhow::Result<()> {
    let block_id_to_commit = finality_proof.commit_info().id();
    
    // Acquire write lock once for atomic operation
    let mut tree_guard = self.inner.write();
    
    let block_to_commit = tree_guard.get_block(&block_id_to_commit)
        .ok_or_else(|| format_err!("Committed block id not found"))?;
    
    ensure!(
        block_to_commit.round() > tree_guard.ordered_root().round(),
        "Committed block round lower than root"
    );
    
    let blocks_to_commit = tree_guard.path_from_ordered_root(block_id_to_commit)
        .ok_or_else(|| format_err!("Failed to get path from ordered root"))?;
    
    ensure!(!blocks_to_commit.is_empty(), "Blocks to commit cannot be empty");
    
    // Perform state updates under same lock
    tree_guard.update_ordered_root(block_to_commit.id());
    tree_guard.insert_ordered_cert(finality_proof.clone());
    
    drop(tree_guard); // Explicitly release before async call
    
    // Rest of execution...
}
```

Alternatively, replace the `assert!` with proper error handling:
```rust
let blocks_to_commit = self
    .path_from_ordered_root(block_id_to_commit)
    .ok_or_else(|| format_err!("Block {} is no longer descendant of ordered root", block_id_to_commit))?;
```

## Proof of Concept

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_send_for_execution_race() {
    // Setup: Create BlockStore with initial state
    let block_store = setup_block_store_with_chain(/* B1 -> B2 -> ... -> B10 */);
    
    // Prepare two finality proofs for blocks at different rounds
    let proof_b10 = create_finality_proof(block_b10_id, round_10);
    let proof_b12 = create_finality_proof(block_b12_id, round_12);
    
    // Launch concurrent send_for_execution calls
    let handle1 = tokio::spawn({
        let store = block_store.clone();
        async move {
            store.send_for_execution(proof_b10).await
        }
    });
    
    let handle2 = tokio::spawn({
        let store = block_store.clone();
        async move {
            // Add small delay to increase race probability
            tokio::time::sleep(Duration::from_micros(100)).await;
            store.send_for_execution(proof_b12).await
        }
    });
    
    // One of these should panic at the assertion
    let results = tokio::join!(handle1, handle2);
    
    // Test passes if panic occurred (demonstrating vulnerability)
    assert!(results.0.is_err() || results.1.is_err(), 
            "Expected panic from TOCTOU race condition");
}
```

## Notes

This vulnerability demonstrates that while `get_block()` can indeed return blocks marked for pruning (as they remain in the `id_to_block` HashMap within the `max_pruned_blocks_in_mem` limit), the more critical issue is the non-atomic access pattern that allows stale block references to be used inconsistently when `ordered_root` advances concurrently. The pruned block tracking in `pruned_block_ids` [4](#0-3)  is separate from the TOCTOU race, but both stem from the fundamental issue of non-atomic multi-step operations on shared state.

### Citations

**File:** consensus/src/block_storage/block_store.rs (L317-331)
```rust
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

**File:** consensus/src/block_storage/block_tree.rs (L528-530)
```rust
            match self.get_block(&cur_block_id) {
                Some(ref block) if block.round() <= root_round => {
                    break;
```

**File:** consensus/src/block_storage/block_tree.rs (L540-541)
```rust
        if cur_block_id != root_id {
            return None;
```
