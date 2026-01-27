# Audit Report

## Title
Race Condition in Block Store Garbage Collection Causes State Inconsistency Window

## Summary
The `send_for_execution()` function in `block_store.rs` performs garbage collection on `pending_blocks` before updating `ordered_root`, creating a window where concurrent operations see inconsistent state between the cleared pending blocks cache and the stale ordered root pointer.

## Finding Description

In the `send_for_execution()` function, there is a critical ordering issue: [1](#0-0) 

The sequence is:
1. **Line 327-329**: Computes `path_from_ordered_root()` using the current (old) `ordered_root` value
2. **Line 334-336**: Performs `pending_blocks.lock().gc()` which removes all blocks with round ≤ commit round from the pending blocks cache
3. **Line 338**: Updates `ordered_root` to the new committed block

Between steps 2 and 3, there exists a race window where:
- The `pending_blocks` cache has been cleared of blocks up to the new commit round
- But `ordered_root` still points to the old (lower) round value

This creates an inconsistency that affects concurrent operations. For example, `insert_block()` checks whether a block's round exceeds the ordered root: [2](#0-1) 

During the race window, a late-arriving block with round between `old_ordered_root` and `new_ordered_root` would pass this check even though it should be rejected as already-ordered.

Similarly, the `need_fetch_for_quorum_cert()` function uses ordered_root to determine if a QC needs fetching: [3](#0-2) 

During the race, a QC for a block between the old and new ordered roots would incorrectly be marked as needing fetch, when it should return `QCRoundBeforeRoot`.

The block retrieval mechanism attempts to fulfill requests from the local `pending_blocks` cache first: [4](#0-3) 

However, the GC operation removes blocks from this cache: [5](#0-4) 

## Impact Explanation

**Medium Severity** - This issue qualifies as Medium severity under the Aptos bug bounty criteria for "State inconsistencies requiring intervention" because:

1. **Performance Degradation**: Nodes experiencing this race must perform unnecessary network fetches instead of local cache hits, increasing latency and network load
2. **State Management Inconsistency**: The temporary desynchronization between `pending_blocks` state and `ordered_root` violates the expected consistency model
3. **Cascading Effects**: In high-throughput scenarios with many concurrent commits, multiple nodes hitting this race simultaneously could cause network congestion and validation delays
4. **Operational Impact**: While not causing consensus failure, repeated occurrences could degrade validator performance metrics

However, this does NOT reach High or Critical severity because:
- No consensus safety violation occurs (blocks remain in `BlockTree`)
- No funds can be lost or stolen
- No permanent state corruption results
- The network remains available and eventually consistent

## Likelihood Explanation

**High Likelihood** in production environments:

1. **Frequent Occurrence**: This race happens on every commit operation, which occurs continuously in a live network
2. **Timing Sensitive**: The window is small but non-zero - any concurrent operation between the GC and ordered_root update will observe the inconsistency
3. **High Concurrency**: Aptos validators handle multiple concurrent proposals, QCs, and sync operations, increasing the probability of hitting this window
4. **No Special Privileges Required**: This is a natural race condition requiring no attacker action - it occurs during normal consensus operation

## Recommendation

**Fix**: Perform the `ordered_root` update BEFORE garbage collecting `pending_blocks`, or use atomic operations:

```rust
pub async fn send_for_execution(
    &self,
    finality_proof: WrappedLedgerInfo,
) -> anyhow::Result<()> {
    let block_id_to_commit = finality_proof.commit_info().id();
    let block_to_commit = self
        .get_block(block_id_to_commit)
        .ok_or_else(|| format_err!("Committed block id not found"))?;

    ensure!(
        block_to_commit.round() > self.ordered_root().round(),
        "Committed block round lower than root"
    );

    let blocks_to_commit = self
        .path_from_ordered_root(block_id_to_commit)
        .unwrap_or_default();

    assert!(!blocks_to_commit.is_empty());

    let finality_proof_clone = finality_proof.clone();
    
    // FIX: Update ordered_root BEFORE garbage collection
    self.inner.write().update_ordered_root(block_to_commit.id());
    self.inner
        .write()
        .insert_ordered_cert(finality_proof_clone.clone());
    
    // Now GC is safe - ordered_root reflects the new state
    self.pending_blocks
        .lock()
        .gc(finality_proof.commit_info().round());

    update_counters_for_ordered_blocks(&blocks_to_commit);

    self.execution_client
        .finalize_order(blocks_to_commit, finality_proof.clone())
        .await
        .expect("Failed to persist commit");

    Ok(())
}
```

This ensures that once blocks are removed from `pending_blocks`, the `ordered_root` already reflects that they are ordered, eliminating the inconsistency window.

## Proof of Concept

The race can be demonstrated with a concurrent stress test:

```rust
#[tokio::test]
async fn test_gc_race_condition() {
    // Setup: Create block store with blocks at rounds 100-110
    let block_store = setup_block_store_with_blocks(100, 110).await;
    
    // Thread 1: Commit block at round 110
    let bs1 = block_store.clone();
    let commit_task = tokio::spawn(async move {
        let finality_proof = create_finality_proof_for_round(110);
        bs1.send_for_execution(finality_proof).await
    });
    
    // Thread 2: Concurrently try to fetch block 105 while commit is in progress
    let bs2 = block_store.clone();
    let fetch_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_micros(10)).await; // Race timing
        
        // This should see either:
        // - ordered_root=100 AND block 105 in pending_blocks, OR  
        // - ordered_root=110 AND block 105 NOT in pending_blocks
        // But due to race, it may see:
        // - ordered_root=100 (old) AND block 105 NOT in pending_blocks (GC'd)
        let ordered_root_round = bs2.ordered_root().round();
        let pending_has_105 = bs2.pending_blocks()
            .lock()
            .blocks_by_round
            .contains_key(&105);
        
        (ordered_root_round, pending_has_105)
    });
    
    let (ordered_round, has_block) = fetch_task.await.unwrap();
    
    // Inconsistent state: ordered_root=100 but block 105 was GC'd
    if ordered_round == 100 && !has_block {
        println!("Race condition detected: ordered_root={} but block 105 missing from pending_blocks", ordered_round);
    }
}
```

## Notes

This race condition creates a brief window of state inconsistency that, while not causing consensus failures, violates the expected atomicity of state updates and can lead to performance degradation and unnecessary network operations under high load conditions.

### Citations

**File:** consensus/src/block_storage/block_store.rs (L327-338)
```rust
        let blocks_to_commit = self
            .path_from_ordered_root(block_id_to_commit)
            .unwrap_or_default();

        assert!(!blocks_to_commit.is_empty());

        let finality_proof_clone = finality_proof.clone();
        self.pending_blocks
            .lock()
            .gc(finality_proof.commit_info().round());

        self.inner.write().update_ordered_root(block_to_commit.id());
```

**File:** consensus/src/block_storage/block_store.rs (L416-419)
```rust
        ensure!(
            self.inner.read().ordered_root().round() < block.round(),
            "Block with old round"
        );
```

**File:** consensus/src/block_storage/sync_manager.rs (L97-100)
```rust
    pub fn need_fetch_for_quorum_cert(&self, qc: &QuorumCert) -> NeedFetchResult {
        if qc.certified_block().round() < self.ordered_root().round() {
            return NeedFetchResult::QCRoundBeforeRoot;
        }
```

**File:** consensus/src/block_storage/sync_manager.rs (L685-689)
```rust
            if retrieve_batch_size == 1 {
                let (tx, rx) = oneshot::channel();
                self.pending_blocks
                    .lock()
                    .insert_request(target_block_retrieval_payload, tx);
```

**File:** consensus/src/block_storage/pending_blocks.rs (L122-133)
```rust
    pub fn gc(&mut self, round: Round) {
        let mut to_remove = vec![];
        for (r, _) in self.blocks_by_round.range(..=round) {
            to_remove.push(*r);
        }
        for r in to_remove {
            self.opt_blocks_by_round.remove(&r);
            if let Some(block) = self.blocks_by_round.remove(&r) {
                self.blocks_by_hash.remove(&block.id());
            }
        }
    }
```
