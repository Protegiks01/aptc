# Audit Report

## Title
Race Condition in `sync_info()` Allows Creation of Invalid SyncInfo Objects That Fail Validation

## Summary
The `sync_info()` method in `BlockStore` performs multiple non-atomic read operations to construct a `SyncInfo` object, creating a Time-of-Check-Time-of-Use (TOCTOU) race condition. When concurrent certificate updates occur between these reads, the method can return `SyncInfo` objects that violate internal consistency invariants, causing validation failures when processed by peers.

## Finding Description

The `sync_info()` method constructs a SyncInfo object by making four separate getter calls, each acquiring and immediately releasing a read lock: [1](#0-0) 

Each getter method independently acquires a read lock on the inner BlockTree: [2](#0-1) 

The BlockStore uses an `Arc<RwLock<BlockTree>>` for concurrent access: [3](#0-2) 

Between these separate lock acquisitions, another thread can acquire a write lock and modify the BlockTree state. The `insert_single_quorum_cert()` method acquires a write lock and calls `insert_quorum_cert()`: [4](#0-3) 

This method updates both `highest_quorum_cert` and `highest_ordered_cert`: [5](#0-4) 

The `SyncInfo::verify()` method enforces a critical invariant that HQC's certified block round must be greater than or equal to HOC's commit info round: [6](#0-5) 

**Race Scenario:**

Thread A executes `sync_info()`:
1. Acquires read lock, reads HQC (certified_block round 10), releases lock

Thread B executes `insert_single_quorum_cert()` with a new QC:
1. Acquires write lock
2. Updates `highest_quorum_cert` to round 20
3. Updates `highest_ordered_cert` to round 18
4. Releases write lock

Thread A continues:
1. Acquires read lock, reads HOC (now round 18), releases lock
2. Constructs SyncInfo with HQC round 10, HOC round 18

This violates the invariant: 10 < 18.

When this SyncInfo is processed by peers in `sync_up()`, the verification fails: [7](#0-6) 

## Impact Explanation

**Severity: Medium** - This vulnerability causes temporary liveness issues as defined in the Aptos bug bounty program.

**Impact:**
1. **Sync Protocol Failures**: Peers receiving invalid SyncInfo objects will reject them during verification, causing sync attempts to fail
2. **Temporary Liveness Degradation**: Nodes may experience transient sync failures, though they can retry successfully once consistent state is read
3. **Network Performance Degradation**: Under high load with frequent concurrent operations, multiple nodes may broadcast invalid SyncInfo, temporarily affecting network-wide synchronization efficiency

The vulnerability does not cause:
- Permanent state corruption (error is handled gracefully)
- Fund loss or theft
- Consensus safety violations
- Permanent network partition

The error is logged as `SecurityEvent::InvalidSyncInfoMsg` and handled through automatic retry mechanisms, meaning manual operator intervention is typically not required despite temporary sync disruptions.

## Likelihood Explanation

**Likelihood: Low to Medium**

The race condition can occur during normal consensus operations:
- `sync_info()` is called frequently during proposal generation, voting, and state synchronization
- QCs are continuously inserted as blocks are certified
- Multi-core validator nodes enable true parallel execution

However, the race window is extremely small (microseconds between lock releases), making the exact timing required for this race condition relatively rare even under high load. The probability increases during:
- High transaction throughput periods
- Epoch transitions with rapid certificate updates
- Network catch-up scenarios with multiple concurrent QC insertions

## Recommendation

Acquire a single read lock for the entire `sync_info()` operation to ensure an atomic snapshot of all certificates:

```rust
fn sync_info(&self) -> SyncInfo {
    let inner = self.inner.read();
    SyncInfo::new_decoupled(
        inner.highest_quorum_cert().as_ref().clone(),
        inner.highest_ordered_cert().as_ref().clone(),
        inner.highest_commit_cert().as_ref().clone(),
        inner.highest_2chain_timeout_cert().map(|tc| tc.as_ref().clone()),
    )
}
```

This ensures all certificate reads occur within a single consistent snapshot of the BlockTree state.

## Proof of Concept

This race condition occurs naturally during concurrent operations and cannot be easily demonstrated with a deterministic test due to its timing-dependent nature. However, the following pseudo-test illustrates the vulnerable pattern:

```rust
// Thread 1: Reading sync_info
let hqc = block_store.highest_quorum_cert(); // Round 10
// <-- Race window: Thread 2 inserts QC updating both HQC and HOC
let hoc = block_store.highest_ordered_cert(); // Round 18 (updated)
let sync_info = SyncInfo::new_decoupled(hqc, hoc, hcc, tc);
// sync_info.verify() would fail: HQC round 10 < HOC round 18
```

The vulnerability can be triggered under high load by spawning multiple threads that concurrently call `sync_info()` while others call `insert_single_quorum_cert()` with QCs that update multiple certificates.

## Notes

This is a **valid race condition** that violates consistency invariants in the consensus synchronization protocol. The severity assessment of Medium is appropriate given that it causes temporary liveness issues as defined in the bug bounty program. However, it's important to note that:

1. The error is caught by validation and logged appropriately
2. No permanent damage occurs - the node can retry with a consistent snapshot
3. The probability of occurrence is relatively low due to the microsecond race window
4. This represents a code quality/correctness issue in concurrent programming rather than a critical security vulnerability

The fix is straightforward and should be implemented to ensure atomic consistency guarantees in the sync protocol.

### Citations

**File:** consensus/src/block_storage/block_store.rs (L85-86)
```rust
pub struct BlockStore {
    inner: Arc<RwLock<BlockTree>>,
```

**File:** consensus/src/block_storage/block_store.rs (L555-555)
```rust
        self.inner.write().insert_quorum_cert(qc)
```

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

**File:** consensus/src/block_storage/block_tree.rs (L368-383)
```rust
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
```

**File:** consensus/consensus-types/src/sync_info.rs (L152-156)
```rust
        ensure!(
            self.highest_quorum_cert.certified_block().round()
                >= self.highest_ordered_cert().commit_info().round(),
            "HQC has lower round than HOC"
        );
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
