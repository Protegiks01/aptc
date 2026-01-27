# Audit Report

## Title
Denial of Service via Panic During Concurrent Consensus and State Sync Operations

## Summary
The storage layer uses `try_lock().expect()` to prevent concurrent commits, which causes validator node crashes (panic) when consensus and state sync operations race. This violates the documented invariant that "consensus and state sync must hand over to each other after all pending execution and committing complete" and creates a Critical severity DoS vulnerability.

## Finding Description

The security question asks whether multiple threads can commit `ChunkToCommit` instances concurrently for overlapping version ranges. The answer is: **they cannot**, but the prevention mechanism causes validator node crashes. [1](#0-0) 

The `pre_commit_ledger` function uses `try_lock().expect("Concurrent committing detected.")` which will panic if two threads attempt to pre-commit simultaneously. While this prevents non-deterministic transaction ordering, it crashes the validator node instead.

The vulnerability arises during state synchronization when:

1. **Consensus triggers state sync**: When `ExecutionProxy::sync_for_duration` is called, it acquires a write_mutex and calls `executor.finish()`: [2](#0-1) 

2. **Executor is marked as finished**: The `finish()` method sets the BlockExecutor's internal state to None: [3](#0-2) 

3. **State sync runs while BufferManager is still active**: The state sync proceeds via ChunkExecutor, but the BufferManager is NOT notified to reset until AFTER state sync completes: [4](#0-3) 

4. **Race condition window**: Between when `executor.finish()` is called and when the BufferManager receives its reset request, the BufferManager continues processing blocks through its pipeline. When these blocks reach the PersistingPhase and attempt to call `pre_commit_block`, they encounter the finished executor: [5](#0-4) 

This causes a panic with "BlockExecutor is not reset". Alternatively, if timing allows a block to call `pre_commit_ledger` while ChunkExecutor is also calling it, the second caller will panic with "Concurrent committing detected."

The code comments explicitly acknowledge this design requirement: [6](#0-5) 

However, this handover is NOT enforced in the implementation. The BufferManager continues running until it receives a reset request, which happens AFTER state sync completes.

## Impact Explanation

This is a **Critical Severity** vulnerability under the Aptos Bug Bounty criteria:

- **Total loss of liveness/network availability**: When the panic occurs, the validator node crashes and becomes unavailable
- **Requires node restart**: The validator must be manually restarted to recover
- **Consensus impact**: If multiple validators experience this race condition simultaneously (e.g., during network partition recovery), it could impact consensus participation
- **Production occurrence**: This can happen naturally during legitimate state sync operations, not just malicious attacks

The vulnerability meets the "$1,000,000" Critical tier because it causes complete node unavailability, requiring manual intervention to restore service.

## Likelihood Explanation

**Medium to High likelihood** in production environments:

1. **Natural occurrence**: This race condition can trigger during:
   - Network partition recovery when nodes fall behind
   - Consensus observer fallback scenarios
   - Any situation triggering `sync_for_duration` while consensus is processing blocks

2. **Timing requirements**: The vulnerability requires:
   - State sync to be triggered while consensus has blocks in the execution pipeline
   - Blocks to reach PersistingPhase during the window between `executor.finish()` and BufferManager reset
   - This timing window exists for the entire duration of state sync (potentially seconds to minutes)

3. **Attack amplification**: While the race can occur naturally, an attacker with network influence could potentially increase the likelihood by:
   - Causing validators to fall behind through network manipulation
   - Triggering repeated sync attempts
   - Exploiting consensus observer fallback conditions

## Recommendation

**Fix 1: Drain BufferManager before state sync**

Modify `ExecutionProxy::sync_for_duration` to send the reset request to BufferManager BEFORE calling `executor.finish()`:

```rust
async fn sync_for_duration(
    &self,
    duration: Duration,
) -> Result<LedgerInfoWithSignatures, StateSyncError> {
    let mut latest_logical_time = self.write_mutex.lock().await;
    
    // NEW: Send reset to BufferManager FIRST
    // (requires passing BufferManager handle to ExecutionProxy)
    self.buffer_manager_handle.send_reset_and_wait().await?;
    
    // NOW safe to finish executor and run state sync
    self.executor.finish();
    
    let result = monitor!(
        "sync_for_duration",
        self.state_sync_notifier.sync_for_duration(duration).await
    );
    
    // ... rest of method
}
```

**Fix 2: Replace panic with error handling**

Replace `try_lock().expect()` with proper error handling in the storage layer:

```rust
fn pre_commit_ledger(&self, chunk: ChunkToCommit, sync_commit: bool) -> Result<()> {
    gauged_api("pre_commit_ledger", || {
        let _lock = self.pre_commit_lock.try_lock()
            .map_err(|_| AptosDbError::Other(
                "Another commit operation is in progress. This indicates a synchronization issue between consensus and state sync.".to_string()
            ))?;
        // ... rest of method
    })
}
```

This allows callers to handle the error gracefully rather than crashing the node.

**Fix 3: Add explicit synchronization barrier**

Add a shared atomic flag that prevents consensus from submitting new blocks during state sync.

## Proof of Concept

While a full reproduction requires the complete Aptos node setup, the vulnerability can be demonstrated with the following logical sequence:

1. Start a validator node with active consensus
2. Trigger state sync (e.g., via `sync_for_duration`) while consensus is processing blocks
3. Monitor for either:
   - Panic: "BlockExecutor is not reset" from BufferManager attempting pre_commit
   - Panic: "Concurrent committing detected" from simultaneous pre_commit attempts

**Triggering conditions:**
- Network partition causing validator to fall behind
- Consensus observer fallback scenario
- Manual state sync trigger during active consensus

**Expected result:** Validator node crashes with panic, requiring restart.

**Mitigation verification:** After applying Fix 1 or Fix 2, the same scenario should either:
- Gracefully drain pending operations before state sync (Fix 1)
- Return an error instead of panicking (Fix 2)

---

**Notes:**

The original security question asked about non-deterministic transaction ordering from concurrent commits. The actual finding is that the system prevents this through panic-induced crashes rather than proper synchronization. This is arguably worse from an availability perspective, as it creates a Critical DoS vulnerability. The documented design invariant explicitly states that handover should be clean, but the implementation does not enforce this requirement.

### Citations

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L44-53)
```rust
    fn pre_commit_ledger(&self, chunk: ChunkToCommit, sync_commit: bool) -> Result<()> {
        gauged_api("pre_commit_ledger", || {
            // Pre-committing and committing in concurrency is allowed but not pre-committing at the
            // same time from multiple threads, the same for committing.
            // Consensus and state sync must hand over to each other after all pending execution and
            // committing complete.
            let _lock = self
                .pre_commit_lock
                .try_lock()
                .expect("Concurrent committing detected.");
```

**File:** consensus/src/state_computer.rs (L132-141)
```rust
    async fn sync_for_duration(
        &self,
        duration: Duration,
    ) -> Result<LedgerInfoWithSignatures, StateSyncError> {
        // Grab the logical time lock
        let mut latest_logical_time = self.write_mutex.lock().await;

        // Before state synchronization, we have to call finish() to free the
        // in-memory SMT held by the BlockExecutor to prevent a memory leak.
        self.executor.finish();
```

**File:** execution/executor/src/block_executor/mod.rs (L131-138)
```rust
    fn pre_commit_block(&self, block_id: HashValue) -> ExecutorResult<()> {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "pre_commit_block"]);

        self.inner
            .read()
            .as_ref()
            .expect("BlockExecutor is not reset")
            .pre_commit_block(block_id)
```

**File:** execution/executor/src/block_executor/mod.rs (L151-155)
```rust
    fn finish(&self) {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "finish"]);

        *self.inner.write() = None;
    }
```

**File:** consensus/src/pipeline/execution_client.rs (L642-659)
```rust
    async fn sync_for_duration(
        &self,
        duration: Duration,
    ) -> Result<LedgerInfoWithSignatures, StateSyncError> {
        fail_point!("consensus::sync_for_duration", |_| {
            Err(anyhow::anyhow!("Injected error in sync_for_duration").into())
        });

        // Sync for the specified duration
        let result = self.execution_proxy.sync_for_duration(duration).await;

        // Reset the rand and buffer managers to the new synced round
        if let Ok(latest_synced_ledger_info) = &result {
            self.reset(latest_synced_ledger_info).await?;
        }

        result
    }
```
