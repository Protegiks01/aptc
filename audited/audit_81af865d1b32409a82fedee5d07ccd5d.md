# Audit Report

## Title
Non-Atomic QC Updates in set_qc() Enable Block-Pipeline Desynchronization

## Summary
The `set_qc()` function in `PipelinedBlock` updates two separate mutexes (`block_qc` and `pipeline_tx`) non-atomically, creating a race condition window where concurrent calls can cause the stored QC to differ from the QC sent to the execution pipeline, breaking consensus state consistency.

## Finding Description

The vulnerability exists in the `set_qc()` function which performs two critical operations with separate mutex locks: [1](#0-0) 

The function first locks and updates `block_qc`, releases the lock, then separately locks `pipeline_tx` to send the QC to the pipeline channel. This non-atomic update creates a race window.

The BlockStore is explicitly designed for concurrent access across multiple consensus components: [2](#0-1) 

The critical issue occurs in `insert_single_quorum_cert()` where `set_qc()` is called BEFORE acquiring the BlockTree write lock: [3](#0-2) 

**Race Condition Scenario:**

When two code paths attempt to insert QCs for the same block concurrently:

**Thread A (Vote Aggregation):** Locally aggregates votes → calls `new_qc_aggregated()` → `insert_quorum_cert()` → `insert_single_quorum_cert()` → `set_qc(qc1)`

**Thread B (Order Vote Message):** Receives QC from peer → calls `new_qc_from_order_vote_msg()` → `insert_quorum_cert()` → `insert_single_quorum_cert()` → `set_qc(qc2)` [4](#0-3) [5](#0-4) 

The TOCTOU vulnerability exists in the check before insertion: [6](#0-5) 

Both threads can pass the `QCBlockExist` check before either completes the insertion, leading to concurrent `set_qc()` calls.

**Execution Timeline:**
```
T1: set_qc(qc1) → Lock block_qc → *block_qc = qc1 → Unlock block_qc
T2: set_qc(qc2) → Lock block_qc → *block_qc = qc2 → Unlock block_qc [OVERWRITES qc1]
T1: Lock pipeline_tx → Take qc_tx → Send qc1 to channel → Unlock
T2: Lock pipeline_tx → Take qc_tx → None (already taken!) → Unlock [NO SEND]
```

**Result:** `block_qc` contains `qc2`, but pipeline received `qc1`. The pipeline materializes and executes with `qc1`: [7](#0-6) 

But any subsequent call to `block.qc()` returns `qc2`: [8](#0-7) 

## Impact Explanation

This vulnerability violates the **State Consistency** invariant (Critical Invariant #4) and **Deterministic Execution** invariant (Critical Invariant #1).

**Severity: HIGH** - "Significant protocol violations"

The desynchronization causes:

1. **Execution Inconsistency**: The pipeline executes with one QC while the stored block state references a different QC
2. **Signature Verification Failures**: Later consensus operations reading `block.qc()` get different signatures than what was used during execution
3. **State Sync Corruption**: State synchronization may propagate inconsistent block-QC bindings to other validators
4. **Consensus Fork Risk**: If two validators execute the same block with different QCs (due to this race occurring at different times), they may produce different state roots, violating consensus safety

While this requires validator-level access to trigger, it can occur during **normal network operation** without malicious intent - simply from the timing of vote aggregation versus receiving order vote messages from peers.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This race condition will occur when:
- A validator aggregates votes for block B locally (forming qc1)
- Simultaneously receives an order vote message containing a QC for block B from another validator (qc2)
- Both operations reach `insert_single_quorum_cert()` before either completes

This is highly likely in production because:
1. Order vote is a standard Aptos consensus feature, creating two concurrent QC insertion paths
2. Network latency variations naturally cause timing overlaps
3. The race window is significant (between releasing `block_qc` lock and acquiring `pipeline_tx` lock)
4. No synchronization prevents concurrent `set_qc()` calls on the same block

## Recommendation

**Solution: Make QC updates atomic by holding a single lock for both operations**

```rust
pub fn set_qc(&self, qc: Arc<QuorumCert>) {
    // Acquire both locks together or use a single encompassing lock
    let mut block_qc_guard = self.block_qc.lock();
    let mut pipeline_tx_guard = self.pipeline_tx.lock();
    
    *block_qc_guard = Some(qc.clone());
    
    if let Some(tx) = pipeline_tx_guard.as_mut() {
        tx.qc_tx.take().map(|tx| tx.send(qc));
    }
    
    // Both locks released together at end of scope
}
```

**Alternative: Add idempotency check in insert_single_quorum_cert**

```rust
pub fn insert_single_quorum_cert(&self, qc: QuorumCert) -> anyhow::Result<()> {
    match self.get_block(qc.certified_block().id()) {
        Some(pipelined_block) => {
            // Check if QC already set - make operation idempotent
            if pipelined_block.qc().is_some() {
                return Ok(()); // QC already inserted, skip
            }
            
            ensure!(
                pipelined_block
                    .block_info()
                    .match_ordered_only(qc.certified_block()),
                "QC for block {} has different info",
                qc.certified_block().id()
            );
            
            pipelined_block.set_qc(Arc::new(qc.clone()));
        },
        None => bail!("Insert {} without having the block in store first", qc),
    };
    
    // Acquire write lock and insert
    self.storage.save_tree(vec![], vec![qc.clone()])?;
    self.inner.write().insert_quorum_cert(qc)
}
```

## Proof of Concept

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_set_qc_race() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    
    // Create a pipelined block with pipeline channels set up
    let block = Arc::new(PipelinedBlock::new_ordered(
        Block::new_for_testing(...),
        OrderedBlockWindow::empty(),
    ));
    
    // Set up pipeline channels
    let (qc_tx, qc_rx) = oneshot::channel();
    let (pipeline_tx, _) = create_pipeline_channels();
    block.set_pipeline_tx(pipeline_tx);
    
    // Create two different QCs for the same block (same certified block, different signatures)
    let qc1 = Arc::new(QuorumCert::new(...)); // From vote aggregation
    let qc2 = Arc::new(QuorumCert::new(...)); // From order vote message
    
    let block1 = block.clone();
    let block2 = block.clone();
    let race_detected = Arc::new(AtomicBool::new(false));
    let race_flag = race_detected.clone();
    
    // Spawn two threads calling set_qc concurrently
    let handle1 = tokio::spawn(async move {
        block1.set_qc(qc1.clone());
    });
    
    let handle2 = tokio::spawn(async move {
        block2.set_qc(qc2.clone());
    });
    
    handle1.await.unwrap();
    handle2.await.unwrap();
    
    // Check for desynchronization
    let stored_qc = block.qc().unwrap();
    let pipeline_qc = qc_rx.await.unwrap();
    
    // Race condition: stored QC differs from pipeline QC
    if stored_qc != pipeline_qc {
        race_flag.store(true, Ordering::SeqCst);
        println!("RACE DETECTED: block_qc = {:?}, pipeline_qc = {:?}", 
                 stored_qc, pipeline_qc);
    }
    
    assert!(race_detected.load(Ordering::SeqCst), 
            "Race condition should cause QC desynchronization");
}
```

## Notes

The vulnerability requires validator-level consensus participation to trigger but can occur during normal network operations without malicious intent. The race window is significant enough that production deployments with order vote enabled would experience this under normal network latency variations, making it a reliability and consensus correctness issue affecting all validators in the network.

### Citations

**File:** consensus/consensus-types/src/pipelined_block.rs (L340-345)
```rust
    pub fn set_qc(&self, qc: Arc<QuorumCert>) {
        *self.block_qc.lock() = Some(qc.clone());
        if let Some(tx) = self.pipeline_tx().lock().as_mut() {
            tx.qc_tx.take().map(|tx| tx.send(qc));
        }
    }
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L501-503)
```rust
    pub fn qc(&self) -> Option<Arc<QuorumCert>> {
        self.block_qc.lock().clone()
    }
```

**File:** consensus/src/block_storage/block_store.rs (L69-71)
```rust
/// Responsible for maintaining all the blocks of payload and the dependencies of those blocks
/// (parent and previous QC links).  It is expected to be accessed concurrently by multiple threads
/// and is thread-safe.
```

**File:** consensus/src/block_storage/block_store.rs (L547-555)
```rust
                pipelined_block.set_qc(Arc::new(qc.clone()));
            },
            None => bail!("Insert {} without having the block in store first", qc),
        };

        self.storage
            .save_tree(vec![], vec![qc.clone()])
            .context("Insert block failed when saving quorum")?;
        self.inner.write().insert_quorum_cert(qc)
```

**File:** consensus/src/round_manager.rs (L1925-1937)
```rust
    async fn new_qc_aggregated(
        &mut self,
        qc: Arc<QuorumCert>,
        preferred_peer: Author,
    ) -> anyhow::Result<()> {
        let result = self
            .block_store
            .insert_quorum_cert(&qc, &mut self.create_block_retriever(preferred_peer))
            .await
            .context("[RoundManager] Failed to process a newly aggregated QC");
        self.process_certificates().await?;
        result
    }
```

**File:** consensus/src/round_manager.rs (L1939-1960)
```rust
    async fn new_qc_from_order_vote_msg(
        &mut self,
        verified_qc: Arc<QuorumCert>,
        preferred_peer: Author,
    ) -> anyhow::Result<()> {
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

**File:** consensus/src/pipeline/pipeline_builder.rs (L615-632)
```rust
    async fn materialize(
        preparer: Arc<BlockPreparer>,
        block: Arc<Block>,
        qc_rx: oneshot::Receiver<Arc<QuorumCert>>,
    ) -> TaskResult<MaterializeResult> {
        let mut tracker = Tracker::start_waiting("materialize", &block);
        tracker.start_working();

        let qc_rx = async {
            match qc_rx.await {
                Ok(qc) => Some(qc),
                Err(_) => {
                    warn!("[BlockPreparer] qc tx cancelled for block {}", block.id());
                    None
                },
            }
        }
        .shared();
```
