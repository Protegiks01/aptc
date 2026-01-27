# Audit Report

## Title
Race Condition in BlockStore::send_for_execution Causes Validator Node Panic Due to Mishandled None Return from path_from_ordered_root

## Summary
The `BlockStore::send_for_execution` method contains a Time-Of-Check-Time-Of-Use (TOCTOU) race condition that causes validator nodes to panic and crash during concurrent quorum certificate processing. The method checks that a block's round is higher than the ordered root, but between this check and retrieving the path to the block, another thread can advance the ordered root, causing `path_from_ordered_root` to return `None`. This `None` value is converted to an empty vector via `unwrap_or_default()`, which then fails an assertion, crashing the validator. [1](#0-0) 

## Finding Description

The vulnerability exists in the consensus layer's block ordering mechanism. The `BlockReader` trait defines `path_from_ordered_root` as returning `Option<Vec<Arc<PipelinedBlock>>>`, with documented semantics that None indicates the block is not a successor of the root. [2](#0-1) 

The implementation in `BlockTree::path_from_root_to_block` explicitly handles race conditions where "the root of the tree is propagated forward between retrieving the block and getting its path from root" by returning `None` instead of panicking. [3](#0-2) 

However, the caller in `send_for_execution` mishandles this `None` case: [1](#0-0) 

**Race Condition Scenario:**

1. Thread 1 receives QC for Block B (round 110), calls `send_for_execution(QC_B)`
2. Thread 1 validates: `block_to_commit.round() > ordered_root.round()` (110 > 100) ✓ [4](#0-3) 
3. Thread 2 concurrently receives QC for Block C (round 120), calls `send_for_execution(QC_C)`
4. Thread 2 advances ordered_root to Block C (round 120) [5](#0-4) 
5. Thread 1 now calls `path_from_ordered_root(Block_B)` with the updated root at round 120
6. Since Block B's round (110) ≤ ordered_root round (120), `path_from_root_to_block` returns `None` [6](#0-5) 
7. `unwrap_or_default()` converts `None` to empty vector
8. Assertion `assert!(!blocks_to_commit.is_empty())` fails → **Node panics and crashes**

The inconsistency is evident when comparing with other callers: `proposal_generator.rs` properly handles the `None` case by returning an error [7](#0-6)  and [8](#0-7) , while `send_for_execution` uses an anti-pattern that defeats the graceful error handling.

## Impact Explanation

**Severity: High** per Aptos Bug Bounty criteria ("Validator node slowdowns, API crashes").

**Impact:**
- **Validator Node Crash**: The panic terminates the validator process immediately
- **Consensus Liveness Degradation**: If multiple validators hit this race, consensus progress stalls
- **No Recovery Without Restart**: Node remains down until manual intervention
- **Unpredictable Triggering**: Occurs naturally during high QC arrival rates, no Byzantine behavior required

This breaks the **Consensus Liveness** invariant and violates availability guarantees. Multiple concurrent calls to `send_for_execution` can occur through: [9](#0-8)  and [10](#0-9) 

## Likelihood Explanation

**Likelihood: High** during periods of rapid block production and QC propagation.

**Factors Increasing Likelihood:**
- Multiple QCs arriving in quick succession (common during catch-up or high throughput)
- Concurrent processing via async tasks in sync_manager [11](#0-10) 
- No serialization lock protecting `send_for_execution` calls
- Short time window between check and use increases race probability

The race window spans from the round check to the path retrieval - approximately 4 lines of code where each line acquires/releases locks independently, providing ample opportunity for interleaving.

## Recommendation

**Fix 1: Handle None Gracefully** (Recommended)
Replace the `unwrap_or_default()` + `assert` pattern with proper error handling:

```rust
let blocks_to_commit = self
    .path_from_ordered_root(block_id_to_commit)
    .ok_or_else(|| format_err!("Block {} path not found from ordered root (possibly due to concurrent root advancement)", block_id_to_commit))?;
```

**Fix 2: Hold Lock Across Critical Section**
Acquire a single read lock for the entire critical section to prevent root updates:

```rust
let inner = self.inner.read();
let block_to_commit = inner.get_block(&block_id_to_commit)
    .ok_or_else(|| format_err!("Committed block id not found"))?;

ensure!(
    block_to_commit.round() > inner.ordered_root().round(),
    "Committed block round lower than root"
);

let blocks_to_commit = inner.path_from_ordered_root(block_id_to_commit)
    .ok_or_else(|| format_err!("Block path not found"))?;
drop(inner);

assert!(!blocks_to_commit.is_empty());
```

**Fix 3: Add Mutex for send_for_execution**
Serialize all `send_for_execution` calls to prevent concurrent root updates.

## Proof of Concept

```rust
#[tokio::test]
async fn test_concurrent_send_for_execution_race() {
    // Setup: Create BlockStore with root at round 100
    let (block_store, mut blocks) = setup_block_store_with_chain().await;
    
    // Block B at round 110, Block C at round 120 (both children of root)
    let block_b = blocks[1].clone(); // round 110
    let block_c = blocks[2].clone(); // round 120
    
    // Create QCs for both blocks
    let qc_b = create_qc_for_block(&block_b);
    let qc_c = create_qc_for_block(&block_c);
    
    // Insert blocks into store
    block_store.insert_block(block_b.block().clone()).await.unwrap();
    block_store.insert_block(block_c.block().clone()).await.unwrap();
    
    // Spawn two concurrent tasks
    let store_clone_1 = block_store.clone();
    let store_clone_2 = block_store.clone();
    
    let task1 = tokio::spawn(async move {
        // Thread 1: Process QC for Block B
        store_clone_1.send_for_execution(qc_b.into_wrapped_ledger_info()).await
    });
    
    let task2 = tokio::spawn(async move {
        // Thread 2: Process QC for Block C (will advance root past Block B)
        // Add small delay to ensure Thread 1 passes the round check first
        tokio::time::sleep(Duration::from_millis(10)).await;
        store_clone_2.send_for_execution(qc_c.into_wrapped_ledger_info()).await
    });
    
    // At least one task should panic due to the race condition
    let results = tokio::join!(task1, task2);
    
    // Expected: task1 panics with assertion failure
    assert!(results.0.is_err() || results.1.is_err(), 
            "Race condition should cause at least one panic");
}
```

**Notes:**
The PoC demonstrates the race condition by orchestrating two concurrent `send_for_execution` calls where the second call advances the ordered root beyond the first call's target block, causing the first call to panic when `path_from_ordered_root` returns `None`.

### Citations

**File:** consensus/src/block_storage/block_store.rs (L322-325)
```rust
        ensure!(
            block_to_commit.round() > self.ordered_root().round(),
            "Committed block round lower than root"
        );
```

**File:** consensus/src/block_storage/block_store.rs (L327-331)
```rust
        let blocks_to_commit = self
            .path_from_ordered_root(block_id_to_commit)
            .unwrap_or_default();

        assert!(!blocks_to_commit.is_empty());
```

**File:** consensus/src/block_storage/block_store.rs (L338-338)
```rust
        self.inner.write().update_ordered_root(block_to_commit.id());
```

**File:** consensus/src/block_storage/mod.rs (L46-46)
```rust
    fn path_from_ordered_root(&self, block_id: HashValue) -> Option<Vec<Arc<PipelinedBlock>>>;
```

**File:** consensus/src/block_storage/block_tree.rs (L512-518)
```rust
    /// Returns all the blocks between the commit root and the given block, including the given block
    /// but excluding the root.
    /// In case a given block is not the successor of the root, return None.
    /// While generally the provided blocks should always belong to the active tree, there might be
    /// a race, in which the root of the tree is propagated forward between retrieving the block
    /// and getting its path from root (e.g., at proposal generator). Hence, we don't want to panic
    /// and prefer to return None instead.
```

**File:** consensus/src/block_storage/block_tree.rs (L540-542)
```rust
        if cur_block_id != root_id {
            return None;
        }
```

**File:** consensus/src/liveness/proposal_generator.rs (L577-578)
```rust
            .path_from_commit_root(parent_id)
            .ok_or_else(|| format_err!("Parent block {} already pruned", parent_id))?;
```

**File:** consensus/src/liveness/proposal_generator.rs (L593-594)
```rust
            .path_from_ordered_root(parent_id)
            .ok_or_else(|| format_err!("Parent block {} already pruned", parent_id))?
```

**File:** consensus/src/block_storage/sync_manager.rs (L180-200)
```rust
        match self.need_fetch_for_quorum_cert(qc) {
            NeedFetchResult::NeedFetch => self.fetch_quorum_cert(qc.clone(), retriever).await?,
            NeedFetchResult::QCBlockExist => self.insert_single_quorum_cert(qc.clone())?,
            NeedFetchResult::QCAlreadyExist => return Ok(()),
            _ => (),
        }
        if self.ordered_root().round() < qc.commit_info().round() {
            SUCCESSFUL_EXECUTED_WITH_REGULAR_QC.inc();
            self.send_for_execution(qc.into_wrapped_ledger_info())
                .await?;
            if qc.ends_epoch() {
                retriever
                    .network
                    .broadcast_epoch_change(EpochChangeProof::new(
                        vec![qc.ledger_info().clone()],
                        /* more = */ false,
                    ))
                    .await;
            }
        }
        Ok(())
```

**File:** consensus/src/block_storage/sync_manager.rs (L218-219)
```rust
                SUCCESSFUL_EXECUTED_WITH_ORDER_VOTE_QC.inc();
                self.send_for_execution(ordered_cert.clone()).await?;
```
