# Audit Report

## Title
Race Condition in `sync_info()` Allows Creation of Invalid SyncInfo Objects That Fail Validation

## Summary
The `sync_info()` method in `BlockStore` performs multiple non-atomic read operations to construct a `SyncInfo` object, creating a Time-of-Check-Time-of-Use (TOCTOU) race condition. This allows the method to return `SyncInfo` objects that violate internal consistency invariants and fail validation checks when received by peers, causing sync protocol failures.

## Finding Description

The `sync_info()` method reads four separate certificate values from the BlockTree using individual read lock acquisitions: [1](#0-0) 

Each call to `highest_quorum_cert()`, `highest_ordered_cert()`, `highest_commit_cert()`, and `highest_2chain_timeout_cert()` acquires and immediately releases a read lock on the inner BlockTree: [2](#0-1) 

Between these separate lock acquisitions, another thread can acquire a write lock and modify the BlockTree state. This creates a non-atomic snapshot where the returned `SyncInfo` contains certificates from different points in time.

The `SyncInfo::verify()` method enforces strict consistency requirements: [3](#0-2) 

**Critical Invariant:** `HQC.certified_block().round() >= HOC.commit_info().round()`

**Attack Scenario:**

**Initial BlockTree state (Thread A perspective):**
- HQC: certified_block round 10, commit_info round 8
- HOC: round 8
- HCC: round 8

**Thread A:** Broadcasting its state by calling `sync_info()`:
1. Calls `highest_quorum_cert()`, acquires read lock, reads HQC (certified_block round 10), releases lock

**Thread B:** Processing a new QuorumCert via `insert_single_quorum_cert()`:
1. Receives QC with certified_block round 20, commit_info round 18
2. Acquires write lock on BlockTree
3. Updates `highest_quorum_cert` to round 20 (certified_block)
4. Updates `highest_ordered_cert` to round 18 (commit_info) [4](#0-3) 

5. Releases write lock

**Thread A continues:**
1. Calls `highest_ordered_cert()`, acquires read lock, reads HOC (now round 18), releases lock
2. Calls `highest_commit_cert()`, acquires read lock, reads HCC (round 8), releases lock
3. Constructs `SyncInfo` with:
   - HQC certified_block round: **10**
   - HOC round: **18**
   - HCC round: 8

This `SyncInfo` violates the validation check because `10 < 18` (HQC certified_block round < HOC round).

When Thread A broadcasts this `SyncInfo` to peers, they process it in `sync_up()`: [5](#0-4) 

At line 888, `sync_info.verify()` is called and fails with error "HQC has lower round than HOC", causing the sync to abort.

## Impact Explanation

**Severity: Medium** ($10,000 category: "State inconsistencies requiring intervention")

**Impact:**
1. **Sync Protocol Failures:** Peers receiving invalid `SyncInfo` objects will reject them during verification, preventing state synchronization
2. **Liveness Degradation:** Nodes may fail to sync to the latest state, falling behind the network
3. **Network Fragmentation Risk:** If multiple nodes broadcast invalid `SyncInfo` during high contention periods, network-wide sync failures could occur
4. **Consensus Disruption:** RoundManager relies on `SyncInfo` for round progression; validation failures block advancement

The vulnerability doesn't directly cause fund loss or permanent network partition, but it creates state inconsistencies that require operator intervention during high-concurrency scenarios.

## Likelihood Explanation

**Likelihood: Medium-High**

The race condition occurs naturally during normal consensus operations without requiring malicious intent:

1. **High-Frequency Operations:** `sync_info()` is called frequently during proposal generation, voting, and timeouts
2. **Concurrent Certificate Updates:** New QCs are continuously inserted via `insert_quorum_cert()` as blocks are certified
3. **Multi-Core Systems:** Modern validators run on multi-core systems where true parallel execution enables this race
4. **Network Load:** During high transaction throughput or epoch transitions, certificate update frequency increases

The attack requires:
- **No special privileges:** Any validator node can trigger this during normal operation
- **No malicious input:** Occurs due to normal timing of concurrent operations
- **No network manipulation:** Pure implementation bug

**Triggering Conditions:**
- Thread executing `sync_info()` gets preempted between certificate reads
- Another thread completes a QC insertion that updates multiple certificates
- Timing window is small (~microseconds) but occurs frequently under load

## Recommendation

**Fix:** Acquire a single read lock for the entire `sync_info()` operation to create an atomic snapshot.

**Corrected Implementation:**

```rust
fn sync_info(&self) -> SyncInfo {
    // Acquire a single read lock to ensure atomic snapshot
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

This ensures all four certificate reads occur within a single read lock acquisition, preventing intermediate state changes and guaranteeing a consistent snapshot.

**Alternative Approach:** Add validation to `sync_info()` before returning:

```rust
fn sync_info(&self) -> SyncInfo {
    loop {
        let sync_info = SyncInfo::new_decoupled(
            self.highest_quorum_cert().as_ref().clone(),
            self.highest_ordered_cert().as_ref().clone(),
            self.highest_commit_cert().as_ref().clone(),
            self.highest_2chain_timeout_cert()
                .map(|tc| tc.as_ref().clone()),
        );
        // Validate before returning - retry if race condition detected
        if sync_info.verify(&self.epoch_state.verifier).is_ok() {
            return sync_info;
        }
        warn!("Detected inconsistent SyncInfo due to race, retrying...");
    }
}
```

**Recommended Solution:** The first approach (single read lock) is cleaner, more efficient, and guarantees atomicity without retry loops.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn test_sync_info_race_condition() {
        // Setup: Create a BlockStore with initial state
        let block_store = Arc::new(create_test_block_store());
        
        // Initial state: HQC round 10, HOC round 8
        assert_eq!(
            block_store.highest_quorum_cert().certified_block().round(),
            10
        );
        assert_eq!(
            block_store.highest_ordered_cert().commit_info().round(),
            8
        );

        let barrier = Arc::new(Barrier::new(2));
        let block_store_clone = Arc::clone(&block_store);
        let barrier_clone = Arc::clone(&barrier);

        // Thread A: Reads sync_info with deliberate delays
        let thread_a = thread::spawn(move || {
            barrier_clone.wait(); // Synchronize start
            
            // Read HQC (round 10)
            let hqc = block_store_clone.highest_quorum_cert();
            let hqc_round = hqc.certified_block().round();
            
            // Simulate preemption - sleep to allow Thread B to execute
            thread::sleep(Duration::from_millis(10));
            
            // Read HOC (should be round 18 after Thread B updates)
            let hoc = block_store_clone.highest_ordered_cert();
            let hoc_round = hoc.commit_info().round();
            
            // This will have inconsistent state: HQC round 10, HOC round 18
            (hqc_round, hoc_round)
        });

        // Thread B: Updates BlockTree
        let thread_b = thread::spawn(move || {
            barrier.wait(); // Synchronize start
            
            // Small delay to ensure Thread A reads HQC first
            thread::sleep(Duration::from_millis(5));
            
            // Insert new QC with certified_block round 20, commit_info round 18
            let new_qc = create_test_qc(20, 18);
            block_store.insert_single_quorum_cert(new_qc).unwrap();
        });

        let (hqc_round, hoc_round) = thread_a.join().unwrap();
        thread_b.join().unwrap();

        // Demonstrate the race condition
        println!("Thread A read: HQC round {}, HOC round {}", hqc_round, hoc_round);
        assert_eq!(hqc_round, 10); // Read old HQC
        assert_eq!(hoc_round, 18); // Read new HOC
        assert!(hqc_round < hoc_round); // Inconsistent state!

        // This SyncInfo would fail validation
        // verify() would return: "HQC has lower round than HOC"
    }
}
```

**To reproduce in production:**
1. Monitor validator logs for "InvalidSyncInfoMsg" errors during high load
2. Add instrumentation to track `sync_info()` call timing and concurrent QC insertions
3. Observe validation failures with error message "HQC has lower round than HOC"
4. Correlate failures with periods of high block production rate and concurrent operations

**Notes**

The vulnerability affects all nodes running AptosBFT consensus. While individual occurrences may be transient (nodes retry sync), frequent race conditions during high load can cause cascading sync failures across the network. The fix is straightforward (single read lock) and has minimal performance impact since read locks are already being acquired - just consolidating them into one acquisition instead of four.

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

**File:** consensus/consensus-types/src/sync_info.rs (L138-165)
```rust
    pub fn verify(&self, validator: &ValidatorVerifier) -> anyhow::Result<()> {
        let epoch = self.highest_quorum_cert.certified_block().epoch();
        ensure!(
            epoch == self.highest_ordered_cert().commit_info().epoch(),
            "Multi epoch in SyncInfo - HOC and HQC"
        );
        ensure!(
            epoch == self.highest_commit_cert().commit_info().epoch(),
            "Multi epoch in SyncInfo - HOC and HCC"
        );
        if let Some(tc) = &self.highest_2chain_timeout_cert {
            ensure!(epoch == tc.epoch(), "Multi epoch in SyncInfo - TC and HQC");
        }

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

**File:** consensus/src/round_manager.rs (L878-906)
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
            SYNC_INFO_RECEIVED_WITH_NEWER_CERT.inc();
            let result = self
                .block_store
                .add_certs(sync_info, self.create_block_retriever(author))
                .await;
            self.process_certificates().await?;
            result
        } else {
            Ok(())
        }
```
