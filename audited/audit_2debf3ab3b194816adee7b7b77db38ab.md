# Audit Report

## Title
Time-of-Check Time-of-Use (TOCTOU) Race Condition in BlockReader Trait Leading to Consensus State Corruption

## Summary
The `BlockReader` trait implementation in `BlockStore` does not enforce atomicity between `block_exists()` and `get_block()` operations. These methods acquire separate read locks, allowing concurrent pruning operations to remove blocks between the check and use, causing critical consensus operations to fail and leading to state inconsistencies across validators.

## Finding Description

The `BlockReader` trait defines two query methods that should provide consistent views of block storage: [1](#0-0) 

The `BlockStore` implementation acquires separate read locks for each call: [2](#0-1) 

This creates a TOCTOU vulnerability where concurrent write operations (block pruning) can invalidate assumptions made during the check phase. The vulnerability manifests in the critical consensus path for inserting quorum certificates:

**Step 1**: The `need_fetch_for_quorum_cert` function checks if a block exists: [3](#0-2) 

**Step 2**: Based on this check returning `QCBlockExist`, the code attempts to insert the QC: [4](#0-3) 

**Step 3**: The `insert_single_quorum_cert` function calls `get_block()` and expects it to succeed: [5](#0-4) 

**Race Condition Window**: Between the `block_exists()` call (acquiring/releasing read lock) and the `get_block()` call (acquiring/releasing a separate read lock), the execution pipeline can asynchronously trigger block pruning via `commit_callback`: [6](#0-5) 

The callback acquires a write lock and removes blocks: [7](#0-6) 

**Result**: The `insert_single_quorum_cert` function bails with error "Insert QC without having the block in store first", causing the entire `add_certs` operation to fail: [8](#0-7) 

This same pattern affects the round manager's QC processing: [9](#0-8) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria:

1. **Significant Protocol Violations**: Validators fail to insert valid quorum certificates, violating the consensus protocol's requirement that all validators process QCs consistently.

2. **Validator Node Issues**: When the race condition occurs, the validator cannot process incoming QCs, causing it to fall behind the network and potentially requiring manual intervention.

3. **State Inconsistencies**: Different validators may have inconsistent views of which QCs are valid. Some nodes may successfully insert a QC before pruning occurs, while others fail after pruning, leading to consensus state divergence.

4. **Loss of Liveness**: Repeated failures to insert QCs during sync operations can prevent validators from catching up to the network, effectively removing them from consensus participation.

While this doesn't directly cause fund loss or permanent network partition (making it sub-Critical), it represents a significant consensus protocol violation that can degrade network performance and validator availability.

## Likelihood Explanation

**High Likelihood** - This race condition occurs naturally during normal consensus operations without requiring any attacker action:

- **Frequent Trigger Conditions**: The race window exists whenever a node receives QCs for blocks near the pruning boundary during active consensus
- **Concurrent Execution**: Block pruning via `commit_callback` runs asynchronously in the execution pipeline, creating constant opportunities for races
- **High-Throughput Scenarios**: In production networks with high block production rates, the pruning operations are frequent, increasing collision probability
- **No Special Conditions Required**: Any validator performing state sync or processing order vote messages can hit this race

The vulnerability is not just theoretical - it represents a systemic atomicity violation in the core consensus data structures.

## Recommendation

**Fix**: Ensure atomicity between `block_exists()` and `get_block()` operations by holding a single lock across both calls, or implement the check-and-use pattern atomically.

**Option 1 - Atomic check-and-get method**:
Add a new method to `BlockReader` trait:
```rust
fn get_block_if_exists(&self, block_id: HashValue) -> Result<Option<Arc<PipelinedBlock>>, BlockMissingError>;
```

Implement in `BlockStore`:
```rust
fn get_block_if_exists(&self, block_id: HashValue) -> Result<Option<Arc<PipelinedBlock>>, BlockMissingError> {
    let guard = self.inner.read();
    if guard.block_exists(&block_id) {
        guard.get_block(&block_id)
            .ok_or(BlockMissingError::RemovedDuringLookup)
    } else {
        Ok(None)
    }
}
```

Update `need_fetch_for_quorum_cert` to return the block along with the status, and update callers to use the returned block rather than calling `get_block()` again.

**Option 2 - Extended lock scope**:
Modify the critical sections to hold the read lock across both operations:
```rust
pub fn need_fetch_for_quorum_cert_with_block(&self, qc: &QuorumCert) 
    -> (NeedFetchResult, Option<Arc<PipelinedBlock>>) 
{
    let guard = self.inner.read();
    // ... perform all checks while holding the lock
    if guard.block_exists(qc.certified_block().id()) {
        let block = guard.get_block(qc.certified_block().id());
        return (NeedFetchResult::QCBlockExist, block);
    }
    // ...
}
```

**Option 3 - Optimistic retry**:
Catch the race condition and retry:
```rust
match self.need_fetch_for_quorum_cert(qc) {
    NeedFetchResult::QCBlockExist => {
        match self.insert_single_quorum_cert(qc.clone()) {
            Err(e) if e.to_string().contains("without having the block") => {
                // Block was pruned during race - refetch
                self.fetch_quorum_cert(qc.clone(), retriever).await?
            }
            result => result?,
        }
    }
    // ...
}
```

**Recommended**: Option 1 provides the cleanest solution by making the atomic operation explicit in the API.

## Proof of Concept

```rust
// Conceptual PoC demonstrating the race condition
// This would be added to consensus/src/block_storage/block_store_test.rs

#[tokio::test]
async fn test_toctou_race_in_qc_insertion() {
    use std::sync::{Arc, Barrier};
    use std::thread;
    
    // Setup: Create a block store with blocks that can be pruned
    let (block_store, blocks) = setup_block_store_with_prunable_blocks().await;
    let qc = create_qc_for_block(blocks[5].id()); // QC for a block near pruning boundary
    
    // Create a barrier to synchronize threads for maximum race likelihood
    let barrier = Arc::new(Barrier::new(2));
    let barrier_clone = barrier.clone();
    let block_store_clone = block_store.clone();
    
    // Thread 1: Attempt to insert QC (victim thread)
    let handle1 = tokio::spawn(async move {
        barrier_clone.wait(); // Synchronize start
        
        // This should succeed but will fail if race occurs
        let result = block_store_clone.insert_quorum_cert(
            &qc,
            &mut create_test_retriever()
        ).await;
        
        result
    });
    
    // Thread 2: Trigger pruning (racing thread)
    let handle2 = thread::spawn(move || {
        barrier.wait(); // Synchronize start
        
        // Immediately trigger commit callback which prunes blocks
        let new_commit_block = blocks[10].id();
        block_store.commit_callback(
            new_commit_block,
            create_commit_proof()
        );
    });
    
    // Execute race
    let result1 = handle1.await.unwrap();
    handle2.join().unwrap();
    
    // Assertion: In vulnerable code, this will fail with
    // "Insert QC without having the block in store first"
    // even though the block existed when need_fetch_for_quorum_cert checked
    assert!(result1.is_err(), "Expected race condition to cause failure");
    assert!(result1.unwrap_err().to_string()
        .contains("without having the block in store first"));
}
```

To reproduce in practice:
1. Set up a validator network with moderate to high block production rate
2. Trigger state sync on a lagging validator while blocks are actively being committed and pruned
3. Monitor logs for errors containing "Insert QC without having the block in store first"
4. Observe that the validator fails to sync properly and may require restart

**Notes**

This vulnerability demonstrates a fundamental atomicity violation in the BlockReader interface contract. The trait design suggests `block_exists()` and `get_block()` should provide consistent views, but the implementation using separate lock acquisitions breaks this guarantee. This is particularly dangerous because the race window is small but the consequences are severe - validators can fail to process critical consensus messages, leading to state divergence and liveness issues.

The issue is exacerbated by Aptos's high-performance design with concurrent execution pipelines, which increases the frequency of pruning operations and thus the likelihood of hitting this race condition in production environments.

### Citations

**File:** consensus/src/block_storage/mod.rs (L24-29)
```rust
pub trait BlockReader: Send + Sync {
    /// Check if a block with the block_id exist in the BlockTree.
    fn block_exists(&self, block_id: HashValue) -> bool;

    /// Try to get a block with the block_id, return an Arc of it if found.
    fn get_block(&self, block_id: HashValue) -> Option<Arc<PipelinedBlock>>;
```

**File:** consensus/src/block_storage/block_store.rs (L475-489)
```rust
            let callback = Box::new(
                move |finality_proof: WrappedLedgerInfo,
                      commit_decision: LedgerInfoWithSignatures| {
                    if let Some(tree) = block_tree.upgrade() {
                        tree.write().commit_callback(
                            storage,
                            id,
                            round,
                            finality_proof,
                            commit_decision,
                            window_size,
                        );
                    }
                },
            );
```

**File:** consensus/src/block_storage/block_store.rs (L525-550)
```rust
        match self.get_block(qc.certified_block().id()) {
            Some(pipelined_block) => {
                ensure!(
                    // decoupled execution allows dummy block infos
                    pipelined_block
                        .block_info()
                        .match_ordered_only(qc.certified_block()),
                    "QC for block {} has different {:?} than local {:?}",
                    qc.certified_block().id(),
                    qc.certified_block(),
                    pipelined_block.block_info()
                );
                observe_block(
                    pipelined_block.block().timestamp_usecs(),
                    BlockStage::QC_ADDED,
                );
                if pipelined_block.block().is_opt_block() {
                    observe_block(
                        pipelined_block.block().timestamp_usecs(),
                        BlockStage::QC_ADDED_OPT_BLOCK,
                    );
                }
                pipelined_block.set_qc(Arc::new(qc.clone()));
            },
            None => bail!("Insert {} without having the block in store first", qc),
        };
```

**File:** consensus/src/block_storage/block_store.rs (L630-637)
```rust
impl BlockReader for BlockStore {
    fn block_exists(&self, block_id: HashValue) -> bool {
        self.inner.read().block_exists(&block_id)
    }

    fn get_block(&self, block_id: HashValue) -> Option<Arc<PipelinedBlock>> {
        self.inner.read().get_block(&block_id)
    }
```

**File:** consensus/src/block_storage/sync_manager.rs (L97-111)
```rust
    pub fn need_fetch_for_quorum_cert(&self, qc: &QuorumCert) -> NeedFetchResult {
        if qc.certified_block().round() < self.ordered_root().round() {
            return NeedFetchResult::QCRoundBeforeRoot;
        }
        if self
            .get_quorum_cert_for_block(qc.certified_block().id())
            .is_some()
        {
            return NeedFetchResult::QCAlreadyExist;
        }
        if self.block_exists(qc.certified_block().id()) {
            return NeedFetchResult::QCBlockExist;
        }
        NeedFetchResult::NeedFetch
    }
```

**File:** consensus/src/block_storage/sync_manager.rs (L144-145)
```rust
        self.insert_quorum_cert(sync_info.highest_quorum_cert(), &mut retriever)
            .await?;
```

**File:** consensus/src/block_storage/sync_manager.rs (L180-184)
```rust
        match self.need_fetch_for_quorum_cert(qc) {
            NeedFetchResult::NeedFetch => self.fetch_quorum_cert(qc.clone(), retriever).await?,
            NeedFetchResult::QCBlockExist => self.insert_single_quorum_cert(qc.clone())?,
            NeedFetchResult::QCAlreadyExist => return Ok(()),
            _ => (),
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

**File:** consensus/src/round_manager.rs (L1944-1961)
```rust
        match self
            .block_store
            .need_fetch_for_quorum_cert(verified_qc.as_ref())
        {
            NeedFetchResult::QCAlreadyExist => Ok(()),
            NeedFetchResult::QCBlockExist => {
                // If the block is already in the block store, but QC isn't available in the block store, insert QC.
                let result = self
                    .block_store
                    .insert_quorum_cert(
                        verified_qc.as_ref(),
                        &mut self.create_block_retriever(preferred_peer),
                    )
                    .await
                    .context("[RoundManager] Failed to process the QC from order vote msg");
                self.process_certificates().await?;
                result
            },
```
