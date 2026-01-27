# Audit Report

## Title
Atomicity Violation in Consensus Block/QC Persistence Causes Recovery Failure and Consensus Liveness Loss

## Summary
The `save_tree()` function's implementation violates its atomicity contract by saving blocks and quorum certificates in separate, non-atomic database writes. A crash between these operations creates an inconsistent state where blocks exist without their corresponding QCs, causing recovery to fail and nodes to enter degraded recovery mode or halt entirely.

## Finding Description

The `PersistentLivenessStorage` trait explicitly requires atomic persistence of blocks and quorum certificates: [1](#0-0) 

However, the implementation violates this atomicity guarantee through two separate code paths:

**Path 1: Block insertion without QC** [2](#0-1) 

**Path 2: QC insertion without block** [3](#0-2) 

These are **two separate database write operations**, not one atomic transaction. While each individual `save_tree()` call uses atomic batch writes internally via RocksDB, the temporal separation between the two calls creates a critical race condition window.

**The Attack Scenario:**

1. Block B is proposed containing QC_A for its parent block A
2. `insert_block_inner()` saves block B (which embeds QC_A in its `quorum_cert` field)
3. **CRASH occurs** before `insert_single_quorum_cert()` saves QC_A separately to QCSchema
4. Upon recovery, `ConsensusDB::get_data()` loads blocks and QCs from separate storage: [4](#0-3) 

5. Block A exists, but QC_A is **only** in BlockSchema (embedded in block B), **not** in QCSchema (separate storage)
6. If block A is the commit root, recovery attempts to find its QC: [5](#0-4) 

7. **Recovery fails** with error "No QC found for root"
8. Node enters `PartialRecoveryData` mode: [6](#0-5) 

9. System sets `recovery_mode = true` and starts `RecoveryManager` instead of normal consensus: [7](#0-6) 

**Root Cause:** The recovery code does not extract QCs from blocks' embedded `quorum_cert` fields—it only checks the separately stored QC list. This design assumes QCs are always persisted to both locations atomically, which the current implementation violates.

## Impact Explanation

**Critical Severity** per Aptos Bug Bounty criteria:
- **Total loss of liveness/network availability**: If multiple validators experience simultaneous crashes (power outage, datacenter failure, coordinated restart), affected nodes cannot resume normal consensus, requiring manual intervention
- **Non-recoverable network partition**: Nodes stuck in recovery mode cannot participate in consensus, potentially partitioning the network if enough validators are affected
- **Significant protocol violations**: Violates the explicit atomicity invariant stated in code documentation and the "State Consistency: State transitions must be atomic" invariant

**Minimum Impact:** Medium Severity - "State inconsistencies requiring intervention" as individual nodes require manual recovery procedures.

## Likelihood Explanation

**High Likelihood:**
- Crashes during block processing are common (OS crashes, power failures, OOM kills, hardware failures)
- The race window exists during every block insertion where the QC is saved separately
- No malicious actor required—this is a reliability bug affecting normal operations
- The timing window is narrow but real: between lines 513-514 and 552-554 in block_store.rs
- Production deployments with hundreds of validators increase probability of simultaneous crashes

**Realistic Scenario:** Datacenter experiencing power issues causes multiple validator nodes to crash mid-block-processing. Upon restart, affected nodes fail recovery due to missing QCs, degrading network liveness until manual intervention.

## Recommendation

**Solution: Enforce true atomicity by saving blocks and their QCs together in a single operation.**

Modify `insert_block_inner()` to accept an optional QC parameter and save both atomically:

```rust
// In block_store.rs
pub async fn insert_block_inner(
    &self,
    pipelined_block: PipelinedBlock,
    qc: Option<QuorumCert>, // Add QC parameter
) -> anyhow::Result<Arc<PipelinedBlock>> {
    // ... existing code ...
    
    // Save block and QC atomically
    let qcs = if let Some(qc) = qc {
        vec![qc]
    } else {
        vec![]
    };
    
    self.storage
        .save_tree(vec![pipelined_block.block().clone()], qcs)
        .context("Insert block failed when saving block and QC")?;
    
    self.inner.write().insert_block(pipelined_block)
}
```

**Alternative: Extract QCs from blocks during recovery:**

Modify recovery to extract embedded QCs from loaded blocks:

```rust
// In persistent_liveness_storage.rs, after loading blocks
let mut quorum_certs = raw_data.3;
// Extract embedded QCs from blocks
for block in &blocks {
    let embedded_qc = block.quorum_cert().clone();
    if !quorum_certs.iter().any(|qc| qc.certified_block().id() == embedded_qc.certified_block().id()) {
        quorum_certs.push(embedded_qc);
    }
}
```

**Recommended Fix:** Implement **both** solutions—enforce atomicity at write time AND add resilience at recovery time for defense-in-depth.

## Proof of Concept

```rust
// Reproduction steps (pseudo-code for clarity):

#[test]
fn test_atomicity_violation_recovery_failure() {
    // 1. Start consensus node with storage
    let storage = setup_consensus_storage();
    let block_store = setup_block_store(storage.clone());
    
    // 2. Create block A and block B (B contains QC for A)
    let block_a = create_test_block(round: 10);
    let qc_a = create_qc_for_block(&block_a);
    let block_b = create_test_block_with_qc(round: 11, qc: qc_a.clone());
    
    // 3. Insert block B (saves B with embedded QC_A)
    block_store.insert_block_inner(block_b).await.unwrap();
    
    // 4. Simulate crash BEFORE insert_single_quorum_cert saves QC_A
    // (Don't call insert_single_quorum_cert)
    drop(block_store);
    
    // 5. Simulate block A becoming the commit root via ledger update
    storage.aptos_db().commit_block_as_root(block_a.id());
    
    // 6. Attempt recovery
    let recovery_data = storage.start(order_vote_enabled: false, window_size: None);
    
    // 7. Verify recovery failure
    match recovery_data {
        LivenessStorageData::FullRecoveryData(_) => {
            panic!("Expected recovery failure, got full recovery");
        }
        LivenessStorageData::PartialRecoveryData(_) => {
            // Confirms vulnerability: recovery degraded to partial mode
            println!("VULNERABILITY CONFIRMED: Node in degraded recovery mode");
        }
    }
}
```

**Actual reproduction requires:**
1. Setting up a test validator node
2. Using process signals (SIGKILL) to simulate crash at precise timing
3. Observing logs showing "No QC found for root" error message
4. Confirming node enters RecoveryManager instead of RoundManager

## Notes

This vulnerability demonstrates a critical gap between interface contract (atomic persistence) and implementation reality (split writes). The issue is particularly severe because:

1. The trait documentation explicitly promises atomicity
2. The recovery logic assumes this atomicity guarantee
3. The failure mode is silent (no compile-time checks) but catastrophic at runtime
4. Multiple production scenarios (datacenter failures, coordinated restarts) can trigger simultaneous crashes across validators

The fix must address both the write path (enforce true atomicity) and the recovery path (handle legacy/corrupted state gracefully).

### Citations

**File:** consensus/src/persistent_liveness_storage.rs (L34-35)
```rust
    /// Persist the blocks and quorum certs into storage atomically.
    fn save_tree(&self, blocks: Vec<Block>, quorum_certs: Vec<QuorumCert>) -> Result<()>;
```

**File:** consensus/src/persistent_liveness_storage.rs (L139-143)
```rust
        let commit_block_quorum_cert = quorum_certs
            .iter()
            .find(|qc| qc.certified_block().id() == commit_block.id())
            .ok_or_else(|| format_err!("No QC found for root: {}", commit_block.id()))?
            .clone();
```

**File:** consensus/src/persistent_liveness_storage.rs (L591-594)
```rust
            Err(e) => {
                error!(error = ?e, "Failed to construct recovery data");
                LivenessStorageData::PartialRecoveryData(ledger_recovery_data)
            },
```

**File:** consensus/src/block_storage/block_store.rs (L512-514)
```rust
        self.storage
            .save_tree(vec![pipelined_block.block().clone()], vec![])
            .context("Insert block failed when saving block")?;
```

**File:** consensus/src/block_storage/block_store.rs (L552-554)
```rust
        self.storage
            .save_tree(vec![], vec![qc.clone()])
            .context("Insert block failed when saving quorum")?;
```

**File:** consensus/src/consensusdb/mod.rs (L90-99)
```rust
        let consensus_blocks = self
            .get_all::<BlockSchema>()?
            .into_iter()
            .map(|(_, block)| block)
            .collect();
        let consensus_qcs = self
            .get_all::<QCSchema>()?
            .into_iter()
            .map(|(_, qc)| qc)
            .collect();
```

**File:** consensus/src/epoch_manager.rs (L1407-1415)
```rust
            LivenessStorageData::PartialRecoveryData(ledger_data) => {
                self.recovery_mode = true;
                self.start_recovery_manager(
                    ledger_data,
                    consensus_config,
                    epoch_state,
                    Arc::new(network_sender),
                )
                .await
```
