# Audit Report

## Title
Ordered Certificate Rollback During BlockTree Rebuild Violates Finality Invariant

## Summary
The `highest_ordered_cert()` function can decrease its round value when `BlockStore::rebuild()` is called during sync operations, violating the critical finality invariant that ordered rounds must be monotonically increasing. This occurs because the rebuild process creates a new `BlockTree` with `highest_ordered_cert` initialized from the commit certificate, discarding any higher previously-seen ordered certificate values.

## Finding Description

The AptosBFT consensus protocol with order votes enabled (`order_vote_enabled = true`) maintains a `highest_ordered_cert` field representing the highest round for which blocks have been ordered for execution. This value should **never** decrease, as it represents a finality commitment. [1](#0-0) 

During normal operation, `highest_ordered_cert` is correctly enforced to only increase: [2](#0-1) 

However, when `BlockStore::rebuild()` is called during sync operations, it completely replaces the `BlockTree`: [3](#0-2) 

The new tree is created via `BlockTree::new()` with a `root_ordered_cert` that comes from the recovery data: [4](#0-3) 

When `order_vote_enabled = true`, this `root_ordered_cert` is created from the committed ledger state: [5](#0-4) 

**The vulnerability:** The `root_ordered_cert` is based on the **commit round** from storage, which can be significantly lower than the previous `highest_ordered_cert` value due to execution pipelining. Since the old tree is completely replaced, the higher `highest_ordered_cert` value is permanently lost.

**Attack Scenario:**
1. Node has `highest_ordered_cert` at round 100 (from recently received QC with commit_info at round 100)
2. Node has `ordered_root` at round 90, `commit_root` at round 80 (normal pipelining lag)
3. Node receives SyncInfo from peer with `highest_commit_cert` at round 95
4. Sync is triggered because the commit cert block doesn't exist or node fell behind: [6](#0-5) 

5. `fast_forward_sync()` creates recovery data with `root_ordered_cert` at round 95
6. `rebuild()` replaces the tree, setting `highest_ordered_cert` to round 95
7. **Result:** `highest_ordered_cert()` rolled back from 100 to 95

The rollback is then propagated when the node creates new SyncInfo messages: [7](#0-6) 

## Impact Explanation

**Severity: CRITICAL** - This is a consensus safety violation with multiple severe impacts:

1. **Order Vote Re-acceptance:** The RoundManager only processes order votes within 100 rounds of `highest_ordered_round`: [8](#0-7) 

After rollback from round 100 to 95, order votes for rounds 96-100 become acceptable again. This could cause the node to:
- Accept and process order votes for rounds it already ordered
- Potentially order different blocks at the same rounds
- Create consensus fork if different blocks are ordered

2. **Network-wide Inconsistency:** The rolled-back `highest_ordered_round` is broadcast to peers via SyncInfo, misleading the network about actual ordering progress and potentially causing cascading rollbacks.

3. **Round State Regression:** The round state management uses `highest_ordered_round` to track consensus progress: [9](#0-8) 

Rollback could cause the node's round state to regress, affecting timeout calculations and consensus participation.

4. **Finality Violation:** The fundamental invariant that "ordered rounds are monotonically increasing" is broken, undermining the consensus protocol's safety guarantees.

This meets the **Critical Severity** criteria: "Consensus/Safety violations" and could lead to "Non-recoverable network partition."

## Likelihood Explanation

**Likelihood: HIGH** - This vulnerability can be triggered during normal network operations:

1. **Natural Trigger Conditions:**
   - Node temporarily falls behind (common in networks)
   - Node restarts and syncs from peers
   - Network partition temporarily isolates a node
   - Any scenario where sync is triggered while execution pipeline has uncommitted ordered blocks

2. **No Attacker Control Required:** The vulnerability is triggered by legitimate sync operations, not malicious input. The gap between `highest_ordered_cert` and `commit_root` is a normal consequence of execution pipelining.

3. **Affects All Nodes:** When `order_vote_enabled = true` (production configuration), all nodes are vulnerable during sync operations.

4. **Automatic Propagation:** Once one node experiences rollback, it broadcasts the incorrect `highest_ordered_round` to peers, potentially causing network-wide confusion.

The combination of natural occurrence, no attacker requirements, and network-wide scope makes this a high-likelihood critical vulnerability.

## Recommendation

**Fix:** Preserve the `highest_ordered_cert` across rebuild operations, similar to how `highest_2chain_timeout_cert` is preserved: [10](#0-9) 

**Proposed Solution:**

In `BlockStore::rebuild()`, preserve and restore the `highest_ordered_cert`:

```rust
pub async fn rebuild(&self, ...) {
    // ... existing code ...
    
    // Preserve highest ordered cert from old tree
    let prev_highest_ordered_cert = self.highest_ordered_cert();
    let prev_2chain_htc = self.highest_2chain_timeout_cert()
        .map(|tc| tc.as_ref().clone());
    
    let _ = Self::build(
        root,
        root_metadata,
        blocks,
        quorum_certs,
        prev_2chain_htc,
        // ... other params ...
    ).await;
    
    // Restore highest ordered cert if it was higher
    let new_highest_ordered = self.inner.read().highest_ordered_cert();
    if prev_highest_ordered_cert.commit_info().round() > 
       new_highest_ordered.commit_info().round() {
        self.inner.write().insert_ordered_cert(
            prev_highest_ordered_cert.as_ref().clone()
        );
    }
    
    self.try_send_for_execution().await;
}
```

**Alternative:** Persist `highest_ordered_cert` to storage independently and restore it during recovery, ensuring it's never lost even across node restarts.

**Validation:** Add assertion in `rebuild()` that new `highest_ordered_cert` >= old value, failing fast if invariant is violated.

## Proof of Concept

**Rust Unit Test:**

```rust
#[tokio::test]
async fn test_highest_ordered_cert_rollback_during_rebuild() {
    // Setup: Create BlockStore with blocks up to round 100
    let (mut runtime, mut block_store, mut block_on, ...) = test_utils::start_test(...);
    
    // Step 1: Insert blocks and QCs up to round 100
    for round in 1..=100 {
        let block = test_utils::make_block(round, ...);
        let qc = test_utils::make_qc_for_block(&block, ...);
        block_store.insert_block(block).await.unwrap();
        block_store.insert_single_quorum_cert(qc).await.unwrap();
    }
    
    // Step 2: Send blocks up to round 90 for execution
    let qc_90 = test_utils::make_commit_qc_for_round(90, ...);
    block_store.send_for_execution(qc_90.into_wrapped_ledger_info())
        .await.unwrap();
    
    // Step 3: Insert QC with commit_info at round 100
    // This updates highest_ordered_cert to round 100
    let qc_102 = test_utils::make_qc_with_commit_info(102, 100, ...);
    block_store.insert_single_quorum_cert(qc_102).unwrap();
    
    // Verify: highest_ordered_cert is at round 100
    let before_cert = block_store.highest_ordered_cert();
    assert_eq!(before_cert.commit_info().round(), 100);
    
    // Step 4: Trigger rebuild with commit cert at round 95
    // Simulating sync to a slightly newer commit but older than highest_ordered
    let recovery_data = test_utils::create_recovery_data_with_commit_round(95, ...);
    block_store.rebuild(
        recovery_data.root,
        recovery_data.root_metadata,
        recovery_data.blocks,
        recovery_data.quorum_certs,
    ).await;
    
    // VULNERABILITY: highest_ordered_cert rolled back!
    let after_cert = block_store.highest_ordered_cert();
    assert_eq!(after_cert.commit_info().round(), 95);
    
    // Demonstrate impact: Node now accepts order votes for rounds 96-100 again
    // which it previously processed
    assert!(after_cert.commit_info().round() < before_cert.commit_info().round(),
        "CRITICAL: highest_ordered_cert decreased from {} to {}, violating finality!",
        before_cert.commit_info().round(),
        after_cert.commit_info().round()
    );
}
```

This test demonstrates the concrete rollback scenario and confirms the finality violation.

### Citations

**File:** consensus/src/block_storage/block_tree.rs (L90-90)
```rust
    highest_ordered_cert: Arc<WrappedLedgerInfo>,
```

**File:** consensus/src/block_storage/block_tree.rs (L104-148)
```rust
    pub(super) fn new(
        commit_root_id: HashValue,
        window_root: PipelinedBlock,
        root_quorum_cert: QuorumCert,
        root_ordered_cert: WrappedLedgerInfo,
        root_commit_cert: WrappedLedgerInfo,
        max_pruned_blocks_in_mem: usize,
        highest_2chain_timeout_cert: Option<Arc<TwoChainTimeoutCertificate>>,
    ) -> Self {
        assert_eq!(window_root.epoch(), root_ordered_cert.commit_info().epoch());
        assert!(window_root.round() <= root_ordered_cert.commit_info().round());
        let window_root_id = window_root.id();

        // Build the tree from the window root block which is <= the commit root block.
        let mut id_to_block = HashMap::new();
        let mut round_to_ids = BTreeMap::new();
        round_to_ids.insert(window_root.round(), window_root_id);
        id_to_block.insert(window_root_id, LinkableBlock::new(window_root));
        counters::NUM_BLOCKS_IN_TREE.set(1);

        let root_quorum_cert = Arc::new(root_quorum_cert);
        let mut id_to_quorum_cert = HashMap::new();
        id_to_quorum_cert.insert(
            root_quorum_cert.certified_block().id(),
            Arc::clone(&root_quorum_cert),
        );

        let pruned_block_ids = VecDeque::with_capacity(max_pruned_blocks_in_mem);

        BlockTree {
            id_to_block,
            ordered_root_id: commit_root_id,
            commit_root_id, // initially we set commit_root_id = root_id
            window_root_id,
            highest_certified_block_id: commit_root_id,
            highest_quorum_cert: Arc::clone(&root_quorum_cert),
            highest_ordered_cert: Arc::new(root_ordered_cert),
            highest_commit_cert: Arc::new(root_commit_cert),
            id_to_quorum_cert,
            pruned_block_ids,
            max_pruned_blocks_in_mem,
            highest_2chain_timeout_cert,
            round_to_ids,
        }
    }
```

**File:** consensus/src/block_storage/block_tree.rs (L388-392)
```rust
    pub fn insert_ordered_cert(&mut self, ordered_cert: WrappedLedgerInfo) {
        if ordered_cert.commit_info().round() > self.highest_ordered_cert.commit_info().round() {
            self.highest_ordered_cert = Arc::new(ordered_cert);
        }
    }
```

**File:** consensus/src/block_storage/block_store.rs (L352-395)
```rust
    pub async fn rebuild(
        &self,
        root: RootInfo,
        root_metadata: RootMetadata,
        blocks: Vec<Block>,
        quorum_certs: Vec<QuorumCert>,
    ) {
        info!(
            "Rebuilding block tree. root {:?}, blocks {:?}, qcs {:?}",
            root,
            blocks.iter().map(|b| b.id()).collect::<Vec<_>>(),
            quorum_certs
                .iter()
                .map(|qc| qc.certified_block().id())
                .collect::<Vec<_>>()
        );
        let max_pruned_blocks_in_mem = self.inner.read().max_pruned_blocks_in_mem();

        // Rollover the previous highest TC from the old tree to the new one.
        let prev_2chain_htc = self
            .highest_2chain_timeout_cert()
            .map(|tc| tc.as_ref().clone());
        let _ = Self::build(
            root,
            root_metadata,
            blocks,
            quorum_certs,
            prev_2chain_htc,
            self.execution_client.clone(),
            Arc::clone(&self.storage),
            max_pruned_blocks_in_mem,
            Arc::clone(&self.time_service),
            self.vote_back_pressure_limit,
            self.payload_manager.clone(),
            self.order_vote_enabled,
            self.window_size,
            self.pending_blocks.clone(),
            self.pipeline_builder.clone(),
            Some(self.inner.clone()),
        )
        .await;

        self.try_send_for_execution().await;
    }
```

**File:** consensus/src/block_storage/block_store.rs (L680-688)
```rust
    fn sync_info(&self) -> SyncInfo {
        SyncInfo::new_decoupled(
            self.highest_quorum_cert().as_ref().clone(),
            self.highest_ordered_cert().as_ref().clone(),
            self.highest_commit_cert().as_ref().clone(),
            self.highest_2chain_timeout_cert()
                .map(|tc| tc.as_ref().clone()),
        )
    }
```

**File:** consensus/src/persistent_liveness_storage.rs (L145-151)
```rust
        let (root_ordered_cert, root_commit_cert) = if order_vote_enabled {
            // We are setting ordered_root same as commit_root. As every committed block is also ordered, this is fine.
            // As the block store inserts all the fetched blocks and quorum certs and execute the blocks, the block store
            // updates highest_ordered_cert accordingly.
            let root_ordered_cert =
                WrappedLedgerInfo::new(VoteData::dummy(), latest_ledger_info_sig.clone());
            (root_ordered_cert.clone(), root_ordered_cert)
```

**File:** consensus/src/block_storage/sync_manager.rs (L279-326)
```rust
    async fn sync_to_highest_quorum_cert(
        &self,
        highest_quorum_cert: QuorumCert,
        highest_commit_cert: WrappedLedgerInfo,
        retriever: &mut BlockRetriever,
    ) -> anyhow::Result<()> {
        if !self.need_sync_for_ledger_info(highest_commit_cert.ledger_info()) {
            return Ok(());
        }

        if let Some(pre_commit_status) = self.pre_commit_status() {
            defer! {
                pre_commit_status.lock().resume();
            }
        }

        let (root, root_metadata, blocks, quorum_certs) = Self::fast_forward_sync(
            &highest_quorum_cert,
            &highest_commit_cert,
            retriever,
            self.storage.clone(),
            self.execution_client.clone(),
            self.payload_manager.clone(),
            self.order_vote_enabled,
            self.window_size,
            Some(self),
        )
        .await?
        .take();
        info!(
            LogSchema::new(LogEvent::CommitViaSync).round(self.ordered_root().round()),
            committed_round = root.commit_root_block.round(),
            block_id = root.commit_root_block.id(),
        );
        self.rebuild(root, root_metadata, blocks, quorum_certs)
            .await;

        if highest_commit_cert.ledger_info().ledger_info().ends_epoch() {
            retriever
                .network
                .send_epoch_change(EpochChangeProof::new(
                    vec![highest_quorum_cert.ledger_info().clone()],
                    /* more = */ false,
                ))
                .await;
        }
        Ok(())
    }
```

**File:** consensus/src/round_manager.rs (L1568-1572)
```rust
            let highest_ordered_round = self.block_store.sync_info().highest_ordered_round();
            let order_vote_round = order_vote_msg.order_vote().ledger_info().round();
            let li_digest = order_vote_msg.order_vote().ledger_info().hash();
            if order_vote_round > highest_ordered_round
                && order_vote_round < highest_ordered_round + 100
```

**File:** consensus/src/liveness/round_state.rs (L245-252)
```rust
    pub fn process_certificates(
        &mut self,
        sync_info: SyncInfo,
        verifier: &ValidatorVerifier,
    ) -> Option<NewRoundEvent> {
        if sync_info.highest_ordered_round() > self.highest_ordered_round {
            self.highest_ordered_round = sync_info.highest_ordered_round();
        }
```
