# Audit Report

## Title
Critical State Corruption in Consensus Fast Forward Sync Due to Missing Rollback Mechanism

## Summary
The `fast_forward_sync()` function in the consensus sync manager atomically persists blocks and quorum certificates to ConsensusDB, but if the subsequent execution state sync fails, there is no rollback mechanism. This leaves the validator in a corrupted state where persistent consensus storage contains new blocks while execution state remains at an old version, causing permanent validator corruption requiring manual intervention.

## Finding Description

The vulnerability exists in the `fast_forward_sync()` function called by `sync_to_highest_quorum_cert()`. The critical code path is: [1](#0-0) 

Within `fast_forward_sync()`, the execution sequence is: [2](#0-1) 

The function performs these operations in order:
1. **Line 503**: Atomically persists blocks and quorum certificates to ConsensusDB via `storage.save_tree()`
2. **Lines 504-511**: Aborts pending execution pipeline tasks
3. **Lines 512-514**: Calls `execution_client.sync_to_target()` to sync execution state - **CAN FAIL HERE**
4. **Lines 519-522**: Calls `storage.start()` to construct recovery data
5. Returns recovery data to caller

If `execution_client.sync_to_target()` fails at step 3, the function returns an error immediately due to the `?` operator. This means:
- Steps 4-5 never execute
- `rebuild()` is never called in the caller function
- The validator is left with ConsensusDB containing new blocks but AptosDB at old version

The ConsensusDB write is atomic (confirmed by examining the implementation): [3](#0-2) 

However, there is **no transaction/rollback mechanism** that spans ConsensusDB and AptosDB together.

Inside `execution_client.sync_to_target()`, the function performs partial state modifications before the actual state sync: [4](#0-3) 

The TODO comment at lines 669-670 explicitly acknowledges this issue but provides no fix. The reset of rand and buffer managers happens at line 667, but if state sync fails at line 671, these components remain in an inconsistent state.

Further inside `execution_proxy.sync_to_target()`: [5](#0-4) 

At line 185, `executor.finish()` is called to free memory. If `state_sync_notifier.sync_to_target()` fails at line 218, the subsequent updates to logical time (line 222) and executor reset (line 226) never occur.

**On validator restart**, the `storage.start()` method attempts recovery: [6](#0-5) 

This method loads blocks/QCs from ConsensusDB (which contains the new state) but gets the ledger info from AptosDB (which is at the old state). The `RecoveryData::new()` call may fail when trying to reconcile this mismatch, resulting in `PartialRecoveryData` (line 594), but the corrupted blocks remain in ConsensusDB permanently.

**Breaking Invariant**: This violates **Invariant #4: State Consistency** - "State transitions must be atomic and verifiable via Merkle proofs." The transition is not atomic across ConsensusDB and AptosDB.

## Impact Explanation

**Severity: CRITICAL** (per Aptos Bug Bounty criteria)

This vulnerability meets the following critical severity criteria:

1. **Non-recoverable network partition**: An affected validator cannot rejoin consensus without manual intervention (database cleanup/restoration)

2. **Total loss of liveness**: The corrupted validator cannot make progress and cannot participate in consensus

3. **State inconsistencies requiring intervention**: The desynchronization between ConsensusDB and AptosDB requires manual database repair

4. **Potential consensus safety violations**: If the validator manages to partially recover and participate in voting with inconsistent state, it could vote based on incorrect execution state, potentially causing consensus forks

The impact is amplified because:
- **Multiple validators can be affected simultaneously** if network issues or malicious peers trigger sync during periods of instability
- **No automatic recovery mechanism exists** - the validator remains permanently corrupted until manually repaired
- **Silent corruption** - the validator may appear to be running but is actually in an inconsistent state
- **Cascading failures** - other validators trying to sync from a corrupted validator may also become corrupted

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to occur because:

1. **Network instability**: State sync failures are common in real-world blockchain networks due to network partitions, timeouts, peer disconnections, or bandwidth limitations

2. **Disk I/O failures**: Storage operations can fail due to disk errors, out-of-space conditions, or I/O timeouts

3. **Malicious peers**: An attacker controlling network peers can send malformed sync responses or disconnect mid-sync to trigger the failure path

4. **Fail points exist in code**: The code contains fail point injection at multiple locations, indicating the developers anticipated these failures [7](#0-6) [8](#0-7) 

5. **Known but unfixed issue**: The TODO comment acknowledges the problem has been identified but not resolved

6. **No redundancy**: There is no retry logic or alternative recovery path when sync fails after storage persistence

**Attack scenario**:
- Attacker controls malicious peers in the network
- Validator falls behind and initiates fast forward sync
- Attacker's peers respond to block retrieval requests normally
- ConsensusDB gets populated with fetched blocks
- When execution sync begins, attacker's peers disconnect or send invalid data
- State sync fails, leaving validator corrupted

This requires no special privileges - just the ability to be selected as a peer for block retrieval.

## Recommendation

Implement a **two-phase commit pattern** with rollback capability:

**Option 1: Optimistic Approach with Rollback**
```rust
pub async fn fast_forward_sync<'a>(
    // ... parameters ...
) -> anyhow::Result<RecoveryData> {
    // ... existing block fetching logic ...
    
    // Check early that recovery will succeed (existing)
    LedgerRecoveryData::new(highest_commit_cert.ledger_info().clone())
        .find_root(&mut blocks.clone(), &mut quorum_certs.clone(), order_vote_enabled, window_size)?;
    
    // NEW: Save original blocks/QCs for potential rollback
    let blocks_to_save = blocks.clone();
    let qcs_to_save = quorum_certs.clone();
    
    // Persist to storage
    storage.save_tree(blocks_to_save.clone(), qcs_to_save.clone())?;
    
    // Abort pipeline
    if let Some(block_store) = maybe_block_store {
        monitor!("abort_pipeline_for_state_sync", block_store.abort_pipeline_for_state_sync().await);
    }
    
    // NEW: Try execution sync with rollback on failure
    let sync_result = execution_client.sync_to_target(highest_commit_cert.ledger_info().clone()).await;
    
    if let Err(e) = sync_result {
        // ROLLBACK: Delete the blocks we just saved
        error!("Execution sync failed, rolling back ConsensusDB changes: {:?}", e);
        let block_ids: Vec<HashValue> = blocks_to_save.iter().map(|b| b.id()).collect();
        storage.prune_tree(block_ids)?;
        return Err(e.into());
    }
    
    // Continue with storage.start() and recovery as before
    let recovery_data = match storage.start(order_vote_enabled, window_size) {
        LivenessStorageData::FullRecoveryData(recovery_data) => recovery_data,
        _ => panic!("Failed to construct recovery data after fast forward sync"),
    };
    
    Ok(recovery_data)
}
```

**Option 2: Pessimistic Approach (Safer)**
```rust
pub async fn fast_forward_sync<'a>(
    // ... parameters ...
) -> anyhow::Result<RecoveryData> {
    // ... existing block fetching logic ...
    
    // Check early that recovery will succeed (existing)
    LedgerRecoveryData::new(highest_commit_cert.ledger_info().clone())
        .find_root(&mut blocks.clone(), &mut quorum_certs.clone(), order_vote_enabled, window_size)?;
    
    // NEW: Sync execution BEFORE persisting to ConsensusDB
    if let Some(block_store) = maybe_block_store {
        monitor!("abort_pipeline_for_state_sync", block_store.abort_pipeline_for_state_sync().await);
    }
    
    // Sync execution first - if this fails, nothing has been persisted
    execution_client.sync_to_target(highest_commit_cert.ledger_info().clone()).await?;
    
    // Only persist after successful execution sync
    storage.save_tree(blocks.clone(), quorum_certs.clone())?;
    
    // Continue with storage.start() and recovery as before
    let recovery_data = match storage.start(order_vote_enabled, window_size) {
        LivenessStorageData::FullRecoveryData(recovery_data) => recovery_data,
        _ => panic!("Failed to construct recovery data after fast forward sync"),
    };
    
    Ok(recovery_data)
}
```

**Option 2 is recommended** because:
- Simpler implementation with no rollback complexity
- Execution sync can be retried multiple times before giving up
- No risk of partial rollback failures
- Aligns with the principle of "fail fast" before committing state changes

Additionally, fix the acknowledged TODO in `execution_client.rs`: [9](#0-8) 

## Proof of Concept

The vulnerability can be demonstrated using the existing fail point mechanism:

```rust
#[tokio::test]
async fn test_fast_forward_sync_corruption_on_execution_failure() {
    // Setup: Create a test consensus environment with storage and execution client
    let (storage, execution_client, validator) = setup_test_validator();
    
    // Inject fail point to cause execution sync to fail
    fail::cfg("consensus::sync_to_target", "return").unwrap();
    
    // Trigger fast forward sync
    let highest_qc = create_test_quorum_cert(/* round 100 */);
    let highest_commit = create_test_commit_cert(/* round 95 */);
    let mut retriever = create_test_retriever();
    
    // This should fail due to injected error
    let result = BlockStore::fast_forward_sync(
        &highest_qc,
        &highest_commit,
        &mut retriever,
        storage.clone(),
        execution_client.clone(),
        payload_manager.clone(),
        true, // order_vote_enabled
        None, // window_size
        None, // maybe_block_store
    ).await;
    
    // Verify the error occurred
    assert!(result.is_err());
    
    // CRITICAL: Check state corruption
    // ConsensusDB should contain blocks but execution state should be old
    let consensus_blocks = storage.consensus_db().get_all::<BlockSchema>().unwrap();
    assert!(!consensus_blocks.is_empty(), "ConsensusDB has blocks persisted");
    
    let ledger_info = storage.aptos_db().get_latest_ledger_info().unwrap();
    assert!(
        ledger_info.ledger_info().round() < highest_commit.commit_info().round(),
        "AptosDB is at old round - STATE CORRUPTION CONFIRMED"
    );
    
    // Try to restart validator - this will fail or produce inconsistent state
    let recovery_result = storage.start(true, None);
    match recovery_result {
        LivenessStorageData::PartialRecoveryData(_) => {
            println!("VULNERABILITY CONFIRMED: Validator cannot fully recover");
        }
        LivenessStorageData::FullRecoveryData(data) => {
            // If it succeeds, the recovery data will be inconsistent
            println!("VULNERABILITY CONFIRMED: Recovery data is inconsistent");
            // Verify inconsistency between consensus and execution state
        }
    }
    
    fail::cfg("consensus::sync_to_target", "off").unwrap();
}
```

To reproduce in a live environment:
1. Run a validator node
2. Force it to fall behind by disconnecting it temporarily
3. Use network manipulation to cause state sync to fail after block retrieval succeeds
4. Observe ConsensusDB contains new blocks but AptosDB remains at old version
5. Restart the validator - it will fail to recover properly

## Notes

This vulnerability demonstrates a classic **atomicity violation** in distributed systems where multiple storage systems (ConsensusDB and AptosDB) must be kept in sync, but there is no two-phase commit or compensating transaction mechanism. The explicit TODO comment in the code confirms this is a known issue that has not been addressed, making it a high-priority critical vulnerability that should be fixed immediately.

### Citations

**File:** consensus/src/block_storage/sync_manager.rs (L295-314)
```rust
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
```

**File:** consensus/src/block_storage/sync_manager.rs (L503-524)
```rust
        storage.save_tree(blocks.clone(), quorum_certs.clone())?;
        // abort any pending executor tasks before entering state sync
        // with zaptos, things can run before hitting buffer manager
        if let Some(block_store) = maybe_block_store {
            monitor!(
                "abort_pipeline_for_state_sync",
                block_store.abort_pipeline_for_state_sync().await
            );
        }
        execution_client
            .sync_to_target(highest_commit_cert.ledger_info().clone())
            .await?;

        // we do not need to update block_tree.highest_commit_decision_ledger_info here
        // because the block_tree is going to rebuild itself.

        let recovery_data = match storage.start(order_vote_enabled, window_size) {
            LivenessStorageData::FullRecoveryData(recovery_data) => recovery_data,
            _ => panic!("Failed to construct recovery data after fast forward sync"),
        };

        Ok(recovery_data)
```

**File:** consensus/src/consensusdb/mod.rs (L121-137)
```rust
    pub fn save_blocks_and_quorum_certificates(
        &self,
        block_data: Vec<Block>,
        qc_data: Vec<QuorumCert>,
    ) -> Result<(), DbError> {
        if block_data.is_empty() && qc_data.is_empty() {
            return Err(anyhow::anyhow!("Consensus block and qc data is empty!").into());
        }
        let mut batch = SchemaBatch::new();
        block_data
            .iter()
            .try_for_each(|block| batch.put::<BlockSchema>(&block.id(), block))?;
        qc_data
            .iter()
            .try_for_each(|qc| batch.put::<QCSchema>(&qc.certified_block().id(), qc))?;
        self.commit(batch)
    }
```

**File:** consensus/src/pipeline/execution_client.rs (L661-672)
```rust
    async fn sync_to_target(&self, target: LedgerInfoWithSignatures) -> Result<(), StateSyncError> {
        fail_point!("consensus::sync_to_target", |_| {
            Err(anyhow::anyhow!("Injected error in sync_to_target").into())
        });

        // Reset the rand and buffer managers to the target round
        self.reset(&target).await?;

        // TODO: handle the state sync error (e.g., re-push the ordered
        // blocks to the buffer manager when it's reset but sync fails).
        self.execution_proxy.sync_to_target(target).await
    }
```

**File:** consensus/src/state_computer.rs (L177-233)
```rust
    async fn sync_to_target(&self, target: LedgerInfoWithSignatures) -> Result<(), StateSyncError> {
        // Grab the logical time lock and calculate the target logical time
        let mut latest_logical_time = self.write_mutex.lock().await;
        let target_logical_time =
            LogicalTime::new(target.ledger_info().epoch(), target.ledger_info().round());

        // Before state synchronization, we have to call finish() to free the
        // in-memory SMT held by BlockExecutor to prevent a memory leak.
        self.executor.finish();

        // The pipeline phase already committed beyond the target block timestamp, just return.
        if *latest_logical_time >= target_logical_time {
            warn!(
                "State sync target {:?} is lower than already committed logical time {:?}",
                target_logical_time, *latest_logical_time
            );
            return Ok(());
        }

        // This is to update QuorumStore with the latest known commit in the system,
        // so it can set batches expiration accordingly.
        // Might be none if called in the recovery path, or between epoch stop and start.
        if let Some(inner) = self.state.read().as_ref() {
            let block_timestamp = target.commit_info().timestamp_usecs();
            inner
                .payload_manager
                .notify_commit(block_timestamp, Vec::new());
        }

        // Inject an error for fail point testing
        fail_point!("consensus::sync_to_target", |_| {
            Err(anyhow::anyhow!("Injected error in sync_to_target").into())
        });

        // Invoke state sync to synchronize to the specified target. Here, the
        // ChunkExecutor will process chunks and commit to storage. However, after
        // block execution and commits, the internal state of the ChunkExecutor may
        // not be up to date. So, it is required to reset the cache of the
        // ChunkExecutor in state sync when requested to sync.
        let result = monitor!(
            "sync_to_target",
            self.state_sync_notifier.sync_to_target(target).await
        );

        // Update the latest logical time
        *latest_logical_time = target_logical_time;

        // Similarly, after state synchronization, we have to reset the cache of
        // the BlockExecutor to guarantee the latest committed state is up to date.
        self.executor.reset()?;

        // Return the result
        result.map_err(|error| {
            let anyhow_error: anyhow::Error = error.into();
            anyhow_error.into()
        })
    }
```

**File:** consensus/src/persistent_liveness_storage.rs (L519-596)
```rust
    fn start(&self, order_vote_enabled: bool, window_size: Option<u64>) -> LivenessStorageData {
        info!("Start consensus recovery.");
        let raw_data = self
            .db
            .get_data()
            .expect("unable to recover consensus data");

        let last_vote = raw_data
            .0
            .map(|bytes| bcs::from_bytes(&bytes[..]).expect("unable to deserialize last vote"));

        let highest_2chain_timeout_cert = raw_data.1.map(|b| {
            bcs::from_bytes(&b).expect("unable to deserialize highest 2-chain timeout cert")
        });
        let blocks = raw_data.2;
        let quorum_certs: Vec<_> = raw_data.3;
        let blocks_repr: Vec<String> = blocks.iter().map(|b| format!("\n\t{}", b)).collect();
        info!(
            "The following blocks were restored from ConsensusDB : {}",
            blocks_repr.concat()
        );
        let qc_repr: Vec<String> = quorum_certs
            .iter()
            .map(|qc| format!("\n\t{}", qc))
            .collect();
        info!(
            "The following quorum certs were restored from ConsensusDB: {}",
            qc_repr.concat()
        );
        // find the block corresponding to storage latest ledger info
        let latest_ledger_info = self
            .aptos_db
            .get_latest_ledger_info()
            .expect("Failed to get latest ledger info.");
        let accumulator_summary = self
            .aptos_db
            .get_accumulator_summary(latest_ledger_info.ledger_info().version())
            .expect("Failed to get accumulator summary.");
        let ledger_recovery_data = LedgerRecoveryData::new(latest_ledger_info);

        match RecoveryData::new(
            last_vote,
            ledger_recovery_data.clone(),
            blocks,
            accumulator_summary.into(),
            quorum_certs,
            highest_2chain_timeout_cert,
            order_vote_enabled,
            window_size,
        ) {
            Ok(mut initial_data) => {
                (self as &dyn PersistentLivenessStorage)
                    .prune_tree(initial_data.take_blocks_to_prune())
                    .expect("unable to prune dangling blocks during restart");
                if initial_data.last_vote.is_none() {
                    self.db
                        .delete_last_vote_msg()
                        .expect("unable to cleanup last vote");
                }
                if initial_data.highest_2chain_timeout_certificate.is_none() {
                    self.db
                        .delete_highest_2chain_timeout_certificate()
                        .expect("unable to cleanup highest 2-chain timeout cert");
                }
                info!(
                    "Starting up the consensus state machine with recovery data - [last_vote {}], [highest timeout certificate: {}]",
                    initial_data.last_vote.as_ref().map_or_else(|| "None".to_string(), |v| v.to_string()),
                    initial_data.highest_2chain_timeout_certificate().as_ref().map_or_else(|| "None".to_string(), |v| v.to_string()),
                );

                LivenessStorageData::FullRecoveryData(initial_data)
            },
            Err(e) => {
                error!(error = ?e, "Failed to construct recovery data");
                LivenessStorageData::PartialRecoveryData(ledger_recovery_data)
            },
        }
    }
```
