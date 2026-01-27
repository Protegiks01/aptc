# Audit Report

## Title
Race Condition in sync_info() Leading to Invalid SyncInfo and Proposal Rejection

## Summary
The `sync_info()` function in `BlockStore` acquires read locks separately for each certificate field, creating a TOCTOU race condition where concurrent BlockTree updates can produce a SyncInfo with violated invariants. This causes validators' proposals and votes to be rejected by peers, potentially causing temporary liveness issues.

## Finding Description

The `sync_info()` function constructs a `SyncInfo` object by making four separate read lock acquisitions on the internal `BlockTree`: [1](#0-0) 

Each call to `highest_quorum_cert()`, `highest_ordered_cert()`, `highest_commit_cert()`, and `highest_2chain_timeout_cert()` independently acquires and releases the read lock: [2](#0-1) 

Between these lock acquisitions, another thread can acquire the write lock and modify the `BlockTree` state (e.g., via `insert_quorum_cert`, `insert_ordered_cert`, or `update_highest_commit_cert`): [3](#0-2) [4](#0-3) 

This race condition can violate critical SyncInfo invariants enforced by `SyncInfo::verify()`: [5](#0-4) 

**Attack Scenario:**
1. Thread A (creating proposal): Calls `sync_info()`, acquires read lock, reads HQC (round 100), releases lock
2. Thread B (processing blocks): Acquires write lock, inserts new QCs, updates HOC to round 105, HCC to round 100, releases lock
3. Thread A: Acquires read lock, reads HOC (round 105), releases lock, reads HCC (round 100)
4. Thread A: Creates `SyncInfo` with HQC(100), HOC(105), HCC(100) — violating invariant HQC.round ≥ HOC.round

When this invalid SyncInfo is sent to peers in proposals or votes: [6](#0-5) 

The receiving validators verify the SyncInfo before use: [7](#0-6) 

The verification **fails** and logs a security event, causing the entire proposal to be rejected: [8](#0-7) 

## Impact Explanation

**Severity: Medium** per Aptos bug bounty criteria.

While this bug does **not** cause validators to request wrong blocks (the verification prevents that), it does cause:
- **Temporary liveness degradation**: When the leader generates invalid SyncInfo, its proposals are rejected by all validators, requiring a round timeout
- **Reduced validator effectiveness**: Affected validators' votes and proposals are ignored
- **Network slowdown**: Under high load when the race is more likely, multiple validators may generate invalid messages

However, this is **not** a critical issue because:
- Consensus safety is maintained (verification prevents use of invalid SyncInfo)
- Network does not permanently stall (other validators can still propose)
- Self-limiting (affects only the validator with the race, not the network)

## Likelihood Explanation

**Likelihood: Low to Medium** depending on network conditions.

The race requires:
- Concurrent BlockStore modifications during `sync_info()` execution
- Specific timing window (between read lock acquisitions, typically microseconds)
- Active block processing and QC insertion

More likely during:
- Heavy network load with many concurrent block insertions
- Fast forward sync operations
- Epoch transitions with rapid certificate updates

Less likely during:
- Steady state with infrequent block updates
- Low transaction volume

## Recommendation

Acquire the read lock **once** and hold it for the entire `sync_info()` operation to ensure atomic snapshot:

```rust
fn sync_info(&self) -> SyncInfo {
    let inner = self.inner.read();  // Single lock acquisition
    SyncInfo::new_decoupled(
        inner.highest_quorum_cert().as_ref().clone(),
        inner.highest_ordered_cert().as_ref().clone(),
        inner.highest_commit_cert().as_ref().clone(),
        inner.highest_2chain_timeout_cert()
            .map(|tc| tc.as_ref().clone()),
    )
    // Lock released here
}
```

This ensures all four certificate fields are read from a consistent BlockTree state.

## Proof of Concept

```rust
// Conceptual test demonstrating the race condition
// (Actual reproduction requires multi-threaded timing control)

use std::sync::Arc;
use std::thread;

#[test]
fn test_sync_info_race_condition() {
    let block_store = create_test_block_store();
    
    // Thread 1: Generate sync_info (simulates proposal creation)
    let bs1 = block_store.clone();
    let handle1 = thread::spawn(move || {
        // This can read HQC before the update
        bs1.sync_info()
    });
    
    // Thread 2: Insert new QCs (simulates block processing)
    let bs2 = block_store.clone();
    let handle2 = thread::spawn(move || {
        // Insert QC that updates HOC to higher round
        let new_qc = create_qc_with_higher_round();
        bs2.insert_single_quorum_cert(new_qc).unwrap();
    });
    
    let sync_info = handle1.join().unwrap();
    handle2.join().unwrap();
    
    // If race occurred, verify() will fail
    let result = sync_info.verify(&validator_verifier);
    
    // Under race conditions, this assertion can fail
    assert!(result.is_ok(), "SyncInfo invariants violated: {:?}", result.err());
}
```

**Notes:**
- The actual exploitability is limited because verification prevents use of invalid SyncInfo
- The bug causes self-inflicted message rejection rather than enabling external attacks
- Network recovery is not truly stalled, only temporarily delayed for that validator's round

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

**File:** consensus/src/block_storage/block_tree.rs (L388-392)
```rust
    pub fn insert_ordered_cert(&mut self, ordered_cert: WrappedLedgerInfo) {
        if ordered_cert.commit_info().round() > self.highest_ordered_cert.commit_info().round() {
            self.highest_ordered_cert = Arc::new(ordered_cert);
        }
    }
```

**File:** consensus/consensus-types/src/sync_info.rs (L152-165)
```rust
        ensure!(
            self.highest_quorum_cert.certified_block().round()
                >= self.highest_ordered_cert().commit_info().round(),
            "HQC has lower round than HOC"
        );

        ensure!(
            self.highest_ordered_round() >= self.highest_commit_round(),
            format!(
                "HOC {} has lower round than HLI {}",
                self.highest_ordered_cert(),
                self.highest_commit_cert()
            )
        );
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

**File:** consensus/src/round_manager.rs (L888-896)
```rust
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

**File:** consensus/src/round_manager.rs (L1401-1401)
```rust
        let vote_msg = VoteMsg::new(vote.clone(), self.block_store.sync_info());
```
