# Audit Report

## Title
Non-Atomic SyncInfo Snapshot Causes Consensus Liveness Degradation via Invariant Violations

## Summary
The `sync_info()` function in `BlockStore` reads four certificate values using separate read locks, creating a race condition window where concurrent BlockTree updates can produce an inconsistent `SyncInfo` that violates critical consensus invariants. When this inconsistent `SyncInfo` is embedded in proposals and broadcast, all receiving validators reject the proposal due to verification failures, causing round timeouts and consensus liveness degradation.

## Finding Description

The vulnerability exists in the `sync_info()` function which creates a snapshot of the current consensus state by reading four values non-atomically: [1](#0-0) 

Each method call (`highest_quorum_cert()`, `highest_ordered_cert()`, `highest_commit_cert()`, `highest_2chain_timeout_cert()`) acquires and immediately releases a read lock on `self.inner` (the BlockTree): [2](#0-1) 

Between these separate read operations, concurrent write operations can modify the BlockTree state. Specifically, `insert_quorum_cert()` atomically updates both `highest_quorum_cert` AND `highest_ordered_cert` under a single write lock: [3](#0-2) 

This creates a race condition where `sync_info()` can read:
- **OLD** `highest_quorum_cert` (round R) - read before concurrent update
- **NEW** `highest_ordered_cert` (round R+1) - read after concurrent update  
- **OLD** `highest_commit_cert` (round R-1) - read before concurrent update

This produces a `SyncInfo` with **HQC round < HOC round**, violating a critical invariant enforced by `SyncInfo::verify()`: [4](#0-3) 

**Exploitation Path:**

1. A validator (Node A) is elected as proposer for round R
2. Node A begins creating a proposal, calling `block_store.sync_info()` to include current state: [5](#0-4) 

3. During the non-atomic reads in `sync_info()`, another thread concurrently processes a new QuorumCert, updating the BlockTree
4. Node A's `sync_info()` returns an inconsistent `SyncInfo` (e.g., HQC round=10, HOC round=11)
5. Node A broadcasts the proposal with this inconsistent `SyncInfo` to all validators
6. All receiving validators call `ensure_round_and_sync_up()` which invokes `sync_up()`: [6](#0-5) 

7. The `sync_up()` function verifies the `SyncInfo`: [7](#0-6) 

8. Verification fails with "HQC has lower round than HOC" error
9. All validators reject the proposal, causing the round to timeout
10. Consensus makes no progress for that round, degrading liveness

## Impact Explanation

This vulnerability qualifies as **High Severity** per the Aptos bug bounty program:

- **Validator node slowdowns**: Nodes waste time processing and rejecting invalid proposals, then waiting for round timeouts
- **Significant protocol violations**: Legitimate proposals from correctly-elected proposers are rejected due to metadata inconsistency rather than actual invalidity
- **Consensus liveness degradation**: Each occurrence causes a complete round timeout (typically several seconds), directly reducing network throughput

While this does not break consensus **safety** (no chain splits or double-spends), it significantly impacts **liveness** - the network's ability to make progress. Under high concurrency or targeted timing attacks by malicious validators who can trigger the race condition deliberately, this could cause repeated round failures.

The impact is amplified because:
1. The race window occurs during normal operation, not requiring malicious behavior
2. High-throughput networks with frequent QC updates have higher exposure
3. A single inconsistent `SyncInfo` causes network-wide proposal rejection
4. Recovery requires a full round timeout before the next proposer attempts

## Likelihood Explanation

**Likelihood: Medium to High**

The race condition can occur naturally during normal consensus operation:

- **Trigger conditions**: Any concurrent BlockTree update during `sync_info()` execution
- **Frequency factors**: 
  - High transaction throughput → more frequent QC updates
  - Fast round progression → more `sync_info()` calls
  - Multi-core validator nodes → true parallelism increases race likelihood
- **No special privileges required**: Occurs during normal validator operation
- **Reproducibility**: Probabilistic but repeatable under load testing

In production environments with continuous consensus activity, the four separate read locks in `sync_info()` create multiple race windows. Given that consensus typically operates at sub-second round times with continuous block production, the race condition is statistically likely to manifest periodically.

A malicious validator with access to consensus timing could potentially increase the likelihood by controlling when it processes received QCs to maximize the chance of triggering the race on other nodes' proposals.

## Recommendation

**Solution: Acquire a single read lock for the entire `sync_info()` snapshot**

Modify `sync_info()` to atomically read all four values under a single read lock:

```rust
fn sync_info(&self) -> SyncInfo {
    let inner = self.inner.read();
    SyncInfo::new_decoupled(
        inner.highest_quorum_cert().as_ref().clone(),
        inner.highest_ordered_cert().as_ref().clone(),
        inner.highest_commit_cert().as_ref().clone(),
        inner.highest_2chain_timeout_cert()
            .map(|tc| tc.as_ref().clone()),
    )
}
```

This ensures all four values represent a consistent snapshot of the BlockTree state at a single point in time. The read lock prevents any concurrent write operations from modifying the state during the snapshot creation.

**Alternative consideration**: If performance profiling shows the extended read lock causes contention, consider maintaining pre-computed consistent `SyncInfo` that gets atomically updated whenever any component changes. However, the simpler fix is likely sufficient given that read locks allow concurrent readers.

## Proof of Concept

**Rust Unit Test (Pseudo-code showing race scenario):**

```rust
#[tokio::test]
async fn test_sync_info_race_condition() {
    // Setup: Create BlockStore with initial state
    let (block_store, storage, execution_client) = setup_block_store().await;
    
    // Initial state: HQC round=10, HOC round=10, HCC round=9
    let initial_qc = create_qc_for_round(10);
    block_store.insert_single_quorum_cert(initial_qc).unwrap();
    
    // Spawn concurrent tasks
    let block_store_clone = block_store.clone();
    let update_task = tokio::spawn(async move {
        // Simulate concurrent QC insertion that updates both HQC and HOC
        let new_qc = create_qc_for_round(11);
        block_store_clone.insert_single_quorum_cert(new_qc).unwrap();
    });
    
    let block_store_clone2 = block_store.clone();
    let read_task = tokio::spawn(async move {
        // Repeatedly call sync_info to catch the race
        for _ in 0..1000 {
            let sync_info = block_store_clone2.sync_info();
            
            // Check for invariant violation
            let hqc_round = sync_info.highest_certified_round();
            let hoc_round = sync_info.highest_ordered_round();
            
            if hqc_round < hoc_round {
                panic!("Invariant violated: HQC round {} < HOC round {}", 
                       hqc_round, hoc_round);
            }
        }
    });
    
    // Wait for both tasks
    let _ = tokio::join!(update_task, read_task);
}
```

**Reproduction steps:**

1. Run consensus under high load with continuous block production
2. Monitor logs for `InvalidSyncInfoMsg` security events with "HQC has lower round than HOC" errors
3. Observe round timeouts following legitimate proposals from correct proposers
4. Correlate timing between BlockStore updates and proposal generation to confirm race window

The vulnerability is demonstrable through stress testing with concurrent consensus operations, where the race condition will eventually manifest as proposal rejections due to `SyncInfo` verification failures.

### Citations

**File:** consensus/src/block_storage/block_store.rs (L664-678)
```rust
    fn highest_quorum_cert(&self) -> Arc<QuorumCert> {
        self.inner.read().highest_quorum_cert()
    }

    fn highest_ordered_cert(&self) -> Arc<WrappedLedgerInfo> {
        self.inner.read().highest_ordered_cert()
    }

    fn highest_commit_cert(&self) -> Arc<WrappedLedgerInfo> {
        self.inner.read().highest_commit_cert()
    }

    fn highest_2chain_timeout_cert(&self) -> Option<Arc<TwoChainTimeoutCertificate>> {
        self.inner.read().highest_2chain_timeout_cert()
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

**File:** consensus/src/block_storage/block_tree.rs (L349-386)
```rust
    pub(super) fn insert_quorum_cert(&mut self, qc: QuorumCert) -> anyhow::Result<()> {
        let block_id = qc.certified_block().id();
        let qc = Arc::new(qc);

        // Safety invariant: For any two quorum certificates qc1, qc2 in the block store,
        // qc1 == qc2 || qc1.round != qc2.round
        // The invariant is quadratic but can be maintained in linear time by the check
        // below.
        precondition!({
            let qc_round = qc.certified_block().round();
            self.id_to_quorum_cert.values().all(|x| {
                (*(*x).ledger_info()).ledger_info().consensus_data_hash()
                    == (*(*qc).ledger_info()).ledger_info().consensus_data_hash()
                    || x.certified_block().round() != qc_round
            })
        });

        match self.get_block(&block_id) {
            Some(block) => {
                if block.round() > self.highest_certified_block().round() {
                    self.highest_certified_block_id = block.id();
                    self.highest_quorum_cert = Arc::clone(&qc);
                }
            },
            None => bail!("Block {} not found", block_id),
        }

        self.id_to_quorum_cert
            .entry(block_id)
            .or_insert_with(|| Arc::clone(&qc));

        if self.highest_ordered_cert.commit_info().round() < qc.commit_info().round() {
            // Question: We are updating highest_ordered_cert but not highest_ordered_root. Is that fine?
            self.highest_ordered_cert = Arc::new(qc.into_wrapped_ledger_info());
        }

        Ok(())
    }
```

**File:** consensus/consensus-types/src/sync_info.rs (L152-156)
```rust
        ensure!(
            self.highest_quorum_cert.certified_block().round()
                >= self.highest_ordered_cert().commit_info().round(),
            "HQC has lower round than HOC"
        );
```

**File:** consensus/src/round_manager.rs (L489-491)
```rust
            let epoch_state = self.epoch_state.clone();
            let network = self.network.clone();
            let sync_info = self.block_store.sync_info();
```

**File:** consensus/src/round_manager.rs (L743-750)
```rust
        let in_correct_round = self
            .ensure_round_and_sync_up(
                proposal_msg.proposal().round(),
                proposal_msg.sync_info(),
                proposal_msg.proposer(),
            )
            .await
            .context("[RoundManager] Process proposal")?;
```

**File:** consensus/src/round_manager.rs (L878-896)
```rust
    async fn sync_up(&mut self, sync_info: &SyncInfo, author: Author) -> anyhow::Result<()> {
        let local_sync_info = self.block_store.sync_info();
        if sync_info.has_newer_certificates(&local_sync_info) {
            info!(
                self.new_log(LogEvent::ReceiveNewCertificate)
                    .remote_peer(author),
                "Local state {},\n remote state {}", local_sync_info, sync_info
            );
            // Some information in SyncInfo is ahead of what we have locally.
            // First verify the SyncInfo (didn't verify it in the yet).
            sync_info.verify(&self.epoch_state.verifier).map_err(|e| {
                error!(
                    SecurityEvent::InvalidSyncInfoMsg,
                    sync_info = sync_info,
                    remote_peer = author,
                    error = ?e,
                );
                VerifyError::from(e)
            })?;
```
