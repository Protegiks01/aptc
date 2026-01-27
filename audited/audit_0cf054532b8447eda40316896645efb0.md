# Audit Report

## Title
Storage Persistence Race Condition in 2-Chain Timeout Certificate Insertion Allows Inconsistent State Reads

## Summary
The `insert_2chain_timeout_certificate()` function in `BlockStore` contains a critical race condition where storage persistence (`save_highest_2chain_timeout_cert()`) completes before in-memory state update (`replace_2chain_timeout_cert()`), creating a window where concurrent threads can read stale timeout certificate state from memory while storage contains fresh data. This violates the state consistency invariant and can cause consensus liveness issues and post-crash state mismatches.

## Finding Description
The vulnerability exists in the two-phase update pattern without atomic guarantees: [1](#0-0) 

**Race Window Analysis:**

1. **Thread 1** (inserting TC_new with round R):
   - Line 564-568: Checks current TC round from in-memory state via `highest_2chain_timeout_cert()` - reads OLD TC (round R-1)
   - Line 570-572: Calls `save_highest_2chain_timeout_cert()` - persists NEW TC to storage successfully
   - **RACE WINDOW BEGINS** - Storage has TC_new (round R), Memory still has TC_old (round R-1)
   - Line 573: Attempts `self.inner.write().replace_2chain_timeout_cert()` - must acquire write lock on `self.inner`

2. **Thread 2** (during race window, reading state):
   - Calls `sync_info()` which invokes `highest_2chain_timeout_cert()`: [2](#0-1) 
   - This reads from in-memory `BlockTree` state: [3](#0-2) 
   - Returns TC_old (round R-1) even though storage has TC_new (round R)

3. **Thread 3** (using stale TC for safety rules):
   - Calls `sign_timeout_with_qc()` passing the stale TC: [4](#0-3) 
   - SafetyRules performs safety checks with OLD TC: [5](#0-4) 
   - The `safe_to_timeout()` check uses `tc_round = maybe_tc.map_or(0, |tc| tc.round())` with stale round value

**Broken Invariant:**
This violates the "State Consistency" invariant that requires state transitions to be atomic. After `save_highest_2chain_timeout_cert()` succeeds, the system is in an inconsistent state where:
- Persistent storage has TC with round R
- In-memory cache has TC with round R-1
- Concurrent readers get different values depending on whether they read from storage (during recovery) or memory (during normal operation)

**Attack Scenarios:**

1. **Concurrent TC Insertion Race:**
   - TC_A (round 10) arrives on Thread 1
   - TC_B (round 11) arrives on Thread 2
   - Thread 1: persists TC_A, waits for write lock
   - Thread 2: reads OLD TC (round 9), persists TC_B, updates memory to TC_B
   - Thread 1: acquires lock, updates memory to TC_A (round 10)
   - Final state: Memory has TC_A (round 10), Storage has TC_B (round 11)
   - After crash recovery: Node recovers TC_B but had been operating with TC_A

2. **Post-Crash State Mismatch:**
   - Node broadcasts `SyncInfo` with OLD TC to peers
   - Node crashes before memory update completes
   - Node recovers with NEW TC from storage
   - Peers believe node is in different state than actual recovered state

3. **Safety Rules Decision on Stale Data:**
   - SafetyRules signs timeout based on OLD TC
   - Should have used NEW TC for safety check
   - May incorrectly accept/reject timeout signing

## Impact Explanation
This is **High Severity** based on Aptos Bug Bounty criteria:

1. **State Inconsistency Requiring Intervention**: The storage-memory divergence violates consistency guarantees and requires careful recovery procedures

2. **Consensus Liveness Impact**: Nodes operating with stale TC information may:
   - Broadcast incorrect sync info to peers
   - Make suboptimal timeout decisions  
   - Cause unnecessary synchronization overhead
   - Delay consensus progress during timeout scenarios

3. **Protocol Violation**: The 2-chain timeout protocol relies on all validators having consistent view of highest timeout certificate. This race allows validators to have inconsistent views even after successful persistence

While this doesn't directly cause consensus safety violations (Byzantine fault tolerance remains intact), it degrades liveness and can cause nodes to make decisions based on stale state, affecting network health during timeout scenarios which are critical for liveness recovery.

## Likelihood Explanation
**High Likelihood** - This race condition can trigger under normal network operation:

1. **Natural Occurrence**: During network timeouts, multiple nodes broadcast timeout certificates simultaneously. A validator receiving concurrent TC messages will have multiple threads calling `insert_2chain_timeout_certificate()` concurrently

2. **Lock Contention**: The write lock on `self.inner` is held during many consensus operations (block insertion, QC insertion, etc.). Heavy consensus activity increases the window where Thread 1 waits for the lock after storage persistence

3. **No Explicit Synchronization**: There's no mutex or atomic operation protecting the two-phase update (storage → memory), making the race window inevitable under concurrent load

4. **Crash Amplification**: If a crash occurs during the race window, the inconsistency becomes permanent in the sense that recovery will use storage state but the node had been broadcasting different state to peers

## Recommendation
Implement atomic storage-memory updates using one of these approaches:

**Option 1: Hold lock during storage operation (Recommended)**
```rust
pub fn insert_2chain_timeout_certificate(
    &self,
    tc: Arc<TwoChainTimeoutCertificate>,
) -> anyhow::Result<()> {
    // Acquire write lock BEFORE checking and persisting
    let mut inner = self.inner.write();
    
    let cur_tc_round = inner
        .highest_2chain_timeout_cert()
        .map_or(0, |tc| tc.round());
    
    if tc.round() <= cur_tc_round {
        return Ok(());
    }
    
    // Persist to storage while holding lock
    self.storage
        .save_highest_2chain_timeout_cert(tc.as_ref())
        .context("Timeout certificate insert failed when persisting to DB")?;
    
    // Update memory while still holding lock
    inner.replace_2chain_timeout_cert(tc);
    
    // Lock released here - storage and memory updated atomically
    Ok(())
}
```

**Option 2: Compare-and-swap pattern**
```rust
pub fn insert_2chain_timeout_certificate(
    &self,
    tc: Arc<TwoChainTimeoutCertificate>,
) -> anyhow::Result<()> {
    loop {
        let cur_tc_round = self
            .highest_2chain_timeout_cert()
            .map_or(0, |tc| tc.round());
        
        if tc.round() <= cur_tc_round {
            return Ok(());
        }
        
        // Persist to storage first
        self.storage
            .save_highest_2chain_timeout_cert(tc.as_ref())
            .context("Timeout certificate insert failed when persisting to DB")?;
        
        // CAS: only update if current value matches what we checked
        let mut inner = self.inner.write();
        let current_round = inner
            .highest_2chain_timeout_cert()
            .map_or(0, |tc| tc.round());
        
        if current_round == cur_tc_round {
            inner.replace_2chain_timeout_cert(tc);
            return Ok(());
        }
        // CAS failed, retry
    }
}
```

**Option 1 is recommended** as it's simpler and ensures atomicity at the cost of holding the lock slightly longer during storage I/O. Given that TC insertion is relatively rare (only during timeout scenarios), this performance trade-off is acceptable for correctness.

## Proof of Concept

```rust
#[cfg(test)]
mod race_condition_test {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    
    #[test]
    fn test_concurrent_tc_insertion_race() {
        // Setup: Create a BlockStore with initial TC at round 5
        let (block_store, _) = create_test_block_store();
        let initial_tc = create_timeout_cert(5);
        block_store.insert_2chain_timeout_certificate(Arc::new(initial_tc)).unwrap();
        
        // Attack: Insert two TCs concurrently
        let tc_round_10 = Arc::new(create_timeout_cert(10));
        let tc_round_11 = Arc::new(create_timeout_cert(11));
        
        let store1 = Arc::new(block_store);
        let store2 = Arc::clone(&store1);
        
        let tc_10_clone = Arc::clone(&tc_round_10);
        let tc_11_clone = Arc::clone(&tc_round_11);
        
        // Thread 1: Insert TC with round 10
        let handle1 = thread::spawn(move || {
            // Add small delay to increase race likelihood
            thread::sleep(Duration::from_millis(5));
            store1.insert_2chain_timeout_certificate(tc_10_clone)
        });
        
        // Thread 2: Insert TC with round 11 (should win)
        let handle2 = thread::spawn(move || {
            store2.insert_2chain_timeout_certificate(tc_11_clone)
        });
        
        handle1.join().unwrap().unwrap();
        handle2.join().unwrap().unwrap();
        
        // Verify inconsistency: memory might have round 10, storage has round 11
        let memory_tc_round = block_store
            .highest_2chain_timeout_cert()
            .map(|tc| tc.round())
            .unwrap_or(0);
        
        // Simulate crash and recovery
        let storage_tc_round = recover_tc_from_storage(&block_store.storage)
            .map(|tc| tc.round())
            .unwrap_or(0);
        
        // ASSERTION: This can fail, demonstrating the race condition
        assert_eq!(
            memory_tc_round, 
            storage_tc_round,
            "Race condition detected: memory has round {}, storage has round {}",
            memory_tc_round,
            storage_tc_round
        );
        
        // Additional check: verify highest round is in memory
        assert_eq!(
            memory_tc_round, 
            11,
            "Expected highest TC (round 11) in memory, got round {}",
            memory_tc_round
        );
    }
}
```

**Notes:**
- The race window exists between storage persistence and memory update
- During high consensus load, this window widens due to lock contention
- The inconsistency becomes observable when reading state concurrently or after crash recovery
- Fix requires holding the write lock during both storage and memory updates to ensure atomicity

### Citations

**File:** consensus/src/block_storage/block_store.rs (L560-575)
```rust
    pub fn insert_2chain_timeout_certificate(
        &self,
        tc: Arc<TwoChainTimeoutCertificate>,
    ) -> anyhow::Result<()> {
        let cur_tc_round = self
            .highest_2chain_timeout_cert()
            .map_or(0, |tc| tc.round());
        if tc.round() <= cur_tc_round {
            return Ok(());
        }
        self.storage
            .save_highest_2chain_timeout_cert(tc.as_ref())
            .context("Timeout certificate insert failed when persisting to DB")?;
        self.inner.write().replace_2chain_timeout_cert(tc);
        Ok(())
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

**File:** consensus/src/block_storage/block_tree.rs (L217-219)
```rust
    pub(super) fn highest_2chain_timeout_cert(&self) -> Option<Arc<TwoChainTimeoutCertificate>> {
        self.highest_2chain_timeout_cert.clone()
    }
```

**File:** consensus/src/round_manager.rs (L1014-1021)
```rust
                let signature = self
                    .safety_rules
                    .lock()
                    .sign_timeout_with_qc(
                        &timeout,
                        self.block_store.highest_2chain_timeout_cert().as_deref(),
                    )
                    .context("[RoundManager] SafetyRules signs 2-chain timeout")?;
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L124-145)
```rust
    fn safe_to_timeout(
        &self,
        timeout: &TwoChainTimeout,
        maybe_tc: Option<&TwoChainTimeoutCertificate>,
        safety_data: &SafetyData,
    ) -> Result<(), Error> {
        let round = timeout.round();
        let qc_round = timeout.hqc_round();
        let tc_round = maybe_tc.map_or(0, |tc| tc.round());
        if (round == next_round(qc_round)? || round == next_round(tc_round)?)
            && qc_round >= safety_data.one_chain_round
        {
            Ok(())
        } else {
            Err(Error::NotSafeToTimeout(
                round,
                qc_round,
                tc_round,
                safety_data.one_chain_round,
            ))
        }
    }
```
