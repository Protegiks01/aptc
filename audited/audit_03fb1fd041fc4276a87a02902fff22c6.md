# Audit Report

## Title
Silent Disk Full Error Leads to Consensus/Storage Divergence and Data Loss in Persisting Phase

## Summary
The consensus persisting phase silently discards storage errors when disk is full, causing the node to believe blocks are committed when they are not actually persisted. This creates a dangerous consensus/storage divergence that leads to data loss on node restart and potential network-wide inconsistencies.

## Finding Description

The vulnerability exists in a critical error handling path during block persistence. When consensus reaches agreement on blocks and attempts to persist them to storage, disk full errors are completely silenced through multiple layers of error suppression:

**Layer 1: Error Discarding in `wait_for_commit_ledger()`**

The `wait_for_commit_ledger()` method explicitly discards the result of the commit operation. [1](#0-0)  This TaskResult contains any errors from the actual disk write, including disk full errors, but they are completely ignored.

**Layer 2: Unconditional Success Response**

The persisting phase ALWAYS returns `Ok(round)`, regardless of whether the commit succeeded or failed. [2](#0-1)  Even though it calls `wait_for_commit_ledger()` at line 71, it never checks if the commit actually succeeded and unconditionally returns success at line 74.

**Layer 3: Error Path from Storage Layer**

The actual disk write occurs in the storage layer where RocksDB write failures propagate as errors. When disk is full, RocksDB's `write_opt()` returns an IOError which is converted to `AptosDbError`. [3](#0-2)  The error propagates through the executor's commit path. [4](#0-3)  Note that there is NO error logging - only an info log at the start (lines 366-369).

The RocksDB error conversion maps IOError to `AptosDbError::OtherRocksDbError`. [5](#0-4) 

The commit ledger function in the storage writer propagates these errors. [6](#0-5) 

The pipeline builder's commit_ledger function converts these to TaskError but also has no error logging. [7](#0-6) 

**Layer 4: Buffer Manager Ignores Errors**

The buffer manager only matches `Some(Ok(round))` pattern. [8](#0-7)  Even if an error was somehow propagated (which it isn't due to Layer 2), it would be silently ignored as there's no `Some(Err(...))` branch.

**Attack Scenario:**

1. A validator node's disk approaches capacity (can occur naturally through state growth or as a resource exhaustion attack)
2. Consensus achieves quorum on new blocks
3. The persisting phase attempts to commit blocks via `wait_for_commit_ledger()`
4. RocksDB write fails with "No space left on device" error (ENOSPC)
5. Error propagates up as `TaskError::InternalError` in the commit_ledger_fut
6. **Error is silently discarded** at `wait_for_commit_ledger()`
7. Persisting phase returns `Ok(round)` indicating success
8. Buffer manager updates `highest_committed_round` believing blocks are persisted
9. Node continues operating, believing it has committed blocks that are NOT on disk
10. If node crashes or restarts, it loses the "committed" blocks
11. Other validators have these blocks persisted, creating state divergence

This breaks the critical invariant: **"State Consistency: State transitions must be atomic and verifiable"**

## Impact Explanation

**Severity: HIGH** (per Aptos Bug Bounty criteria - "State inconsistencies requiring manual intervention")

The impact is severe:

1. **Data Loss**: Blocks that consensus believes are committed are lost on node restart
2. **State Divergence**: The node's in-memory consensus state diverges from its on-disk storage state
3. **Network Inconsistency**: The affected node has different ledger state than other validators
4. **Silent Failure**: No error logging or alerting occurs, making diagnosis extremely difficult
5. **Validator Penalties**: Node may vote on incorrect state, leading to slashing or removal
6. **Recovery Complexity**: Requires state sync to recover, but the node may not even detect it's out of sync

This doesn't reach "Critical" severity because:
- It doesn't directly cause funds loss across the network
- It doesn't break consensus safety for the entire network (only affects the single node with disk full)
- It's recoverable through state sync

However, it's definitely "High" severity because:
- It causes data loss and state inconsistencies
- It requires manual intervention to detect and fix
- It can degrade validator operations significantly
- Multiple validators could be affected simultaneously if disk management is poor

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This is likely to occur because:

1. **Natural Occurrence**: Disk full is a common operational issue that happens naturally as blockchain state grows
2. **No Prevention**: There's no backpressure mechanism to stop consensus when disk space is low
3. **Monitoring Gaps**: While there are disk space alerts in the monitoring configuration [9](#0-8) , they may not be acted upon quickly enough
4. **Silent Failure**: The lack of error logging means operators won't immediately know there's a problem
5. **Resource Exhaustion Attacks**: An attacker could accelerate disk consumption through state-heavy transactions

The alerts trigger at warning (<200 GB, 1h duration) and critical (<50 GB, 5m duration) levels. However, these alerts may trigger too late, after some blocks have already failed to persist. The 50GB threshold for critical alerts may not provide enough buffer when blocks are large or the commit rate is high.

## Recommendation

Implement proper error handling and logging at multiple layers:

1. **Make `wait_for_commit_ledger()` propagate errors**: Change the return type from `()` to `Result<(), TaskError>` and propagate the commit result.

2. **Check commit results in persisting phase**: Modify the persisting phase to check the result of `wait_for_commit_ledger()` and return errors appropriately.

3. **Add error logging**: Add error-level logging in the executor's `commit_ledger()` method when storage writes fail.

4. **Handle errors in buffer manager**: Add a `Some(Err(e))` branch in the buffer manager to handle persisting phase failures, potentially triggering node panic or emergency state sync.

5. **Implement backpressure**: Add disk space checks before attempting to commit blocks, pausing consensus when disk space is critically low.

6. **Enhanced monitoring**: Lower the critical alert threshold and add metrics tracking failed commit attempts.

## Proof of Concept

A PoC would require:
1. Setting up a validator node with limited disk space
2. Running consensus until disk fills up
3. Observing that blocks are "committed" in memory but not on disk
4. Restarting the node and observing data loss
5. Comparing state with other validators to confirm divergence

This can be simulated using disk quota limits or fail-points in the storage layer to inject ENOSPC errors during the `write_opt()` call.

## Notes

This vulnerability represents a critical gap in error handling that violates the fundamental blockchain invariant of state consistency. The silent failure mode makes it particularly dangerous as operators may not detect the issue until significant divergence has occurred. While monitoring alerts exist, they are insufficient to prevent this scenario as they may trigger too late. The vulnerability affects the core consensus persistence path and requires immediate remediation to prevent potential validator penalties and network inconsistencies.

### Citations

**File:** consensus/consensus-types/src/pipelined_block.rs (L562-568)
```rust
    pub async fn wait_for_commit_ledger(&self) {
        // may be aborted (e.g. by reset)
        if let Some(fut) = self.pipeline_futs() {
            // this may be cancelled
            let _ = fut.commit_ledger_fut.await;
        }
    }
```

**File:** consensus/src/pipeline/persisting_phase.rs (L59-81)
```rust
    async fn process(&self, req: PersistingRequest) -> PersistingResponse {
        let PersistingRequest {
            blocks,
            commit_ledger_info,
        } = req;

        for b in &blocks {
            if let Some(tx) = b.pipeline_tx().lock().as_mut() {
                tx.commit_proof_tx
                    .take()
                    .map(|tx| tx.send(commit_ledger_info.clone()));
            }
            b.wait_for_commit_ledger().await;
        }

        let response = Ok(blocks.last().expect("Blocks can't be empty").round());
        if commit_ledger_info.ledger_info().ends_epoch() {
            self.commit_msg_tx
                .send_epoch_change(EpochChangeProof::new(vec![commit_ledger_info], false))
                .await;
        }
        response
    }
```

**File:** storage/schemadb/src/lib.rs (L289-303)
```rust
    fn write_schemas_inner(&self, batch: impl IntoRawBatch, option: &WriteOptions) -> DbResult<()> {
        let labels = [self.name.as_str()];
        let _timer = APTOS_SCHEMADB_BATCH_COMMIT_LATENCY_SECONDS.timer_with(&labels);

        let raw_batch = batch.into_raw_batch(self)?;

        let serialized_size = raw_batch.inner.size_in_bytes();
        self.inner
            .write_opt(raw_batch.inner, option)
            .into_db_res()?;

        raw_batch.stats.commit();
        APTOS_SCHEMADB_BATCH_COMMIT_BYTES.observe_with(&[&self.name], serialized_size as f64);

        Ok(())
```

**File:** storage/schemadb/src/lib.rs (L389-407)
```rust
fn to_db_err(rocksdb_err: rocksdb::Error) -> AptosDbError {
    match rocksdb_err.kind() {
        ErrorKind::Incomplete => AptosDbError::RocksDbIncompleteResult(rocksdb_err.to_string()),
        ErrorKind::NotFound
        | ErrorKind::Corruption
        | ErrorKind::NotSupported
        | ErrorKind::InvalidArgument
        | ErrorKind::IOError
        | ErrorKind::MergeInProgress
        | ErrorKind::ShutdownInProgress
        | ErrorKind::TimedOut
        | ErrorKind::Aborted
        | ErrorKind::Busy
        | ErrorKind::Expired
        | ErrorKind::TryAgain
        | ErrorKind::CompactionTooLarge
        | ErrorKind::ColumnFamilyDropped
        | ErrorKind::Unknown => AptosDbError::OtherRocksDbError(rocksdb_err.to_string()),
    }
```

**File:** execution/executor/src/block_executor/mod.rs (L362-395)
```rust
    fn commit_ledger(&self, ledger_info_with_sigs: LedgerInfoWithSignatures) -> ExecutorResult<()> {
        let _timer = OTHER_TIMERS.timer_with(&["commit_ledger"]);

        let block_id = ledger_info_with_sigs.ledger_info().consensus_block_id();
        info!(
            LogSchema::new(LogEntry::BlockExecutor).block_id(block_id),
            "commit_ledger"
        );

        // Check for any potential retries
        // TODO: do we still have such retries?
        let committed_block = self.block_tree.root_block();
        if committed_block.num_persisted_transactions()?
            == ledger_info_with_sigs.ledger_info().version() + 1
        {
            return Ok(());
        }

        // Confirm the block to be committed is tracked in the tree.
        self.block_tree.get_block(block_id)?;

        fail_point!("executor::commit_blocks", |_| {
            Err(anyhow::anyhow!("Injected error in commit_blocks.").into())
        });

        let target_version = ledger_info_with_sigs.ledger_info().version();
        self.db
            .writer
            .commit_ledger(target_version, Some(&ledger_info_with_sigs), None)?;

        self.block_tree.prune(ledger_info_with_sigs.ledger_info())?;

        Ok(())
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L78-112)
```rust
    fn commit_ledger(
        &self,
        version: Version,
        ledger_info_with_sigs: Option<&LedgerInfoWithSignatures>,
        chunk_opt: Option<ChunkToCommit>,
    ) -> Result<()> {
        gauged_api("commit_ledger", || {
            // Pre-committing and committing in concurrency is allowed but not pre-committing at the
            // same time from multiple threads, the same for committing.
            // Consensus and state sync must hand over to each other after all pending execution and
            // committing complete.
            let _lock = self
                .commit_lock
                .try_lock()
                .expect("Concurrent committing detected.");
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["commit_ledger"]);

            let old_committed_ver = self.get_and_check_commit_range(version)?;

            let mut ledger_batch = SchemaBatch::new();
            // Write down LedgerInfo if provided.
            if let Some(li) = ledger_info_with_sigs {
                self.check_and_put_ledger_info(version, li, &mut ledger_batch)?;
            }
            // Write down commit progress
            ledger_batch.put::<DbMetadataSchema>(
                &DbMetadataKey::OverallCommitProgress,
                &DbMetadataValue::Version(version),
            )?;
            self.ledger_db.metadata_db().write_schemas(ledger_batch)?;

            // Notify the pruners, invoke the indexer, and update in-memory ledger info.
            self.post_commit(old_committed_ver, version, ledger_info_with_sigs, chunk_opt)
        })
    }
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L1079-1106)
```rust
    async fn commit_ledger(
        pre_commit_fut: TaskFuture<PreCommitResult>,
        commit_proof_fut: TaskFuture<LedgerInfoWithSignatures>,
        parent_block_commit_fut: TaskFuture<CommitLedgerResult>,
        executor: Arc<dyn BlockExecutorTrait>,
        block: Arc<Block>,
    ) -> TaskResult<CommitLedgerResult> {
        let mut tracker = Tracker::start_waiting("commit_ledger", &block);
        parent_block_commit_fut.await?;
        pre_commit_fut.await?;
        let ledger_info_with_sigs = commit_proof_fut.await?;

        // it's committed as prefix
        if ledger_info_with_sigs.commit_info().id() != block.id() {
            return Ok(None);
        }

        tracker.start_working();
        let ledger_info_with_sigs_clone = ledger_info_with_sigs.clone();
        tokio::task::spawn_blocking(move || {
            executor
                .commit_ledger(ledger_info_with_sigs_clone)
                .map_err(anyhow::Error::from)
        })
        .await
        .expect("spawn blocking failed")?;
        Ok(Some(ledger_info_with_sigs))
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L968-973)
```rust
                Some(Ok(round)) = self.persisting_phase_rx.next() => {
                    // see where `need_backpressure()` is called.
                    self.pending_commit_votes = self.pending_commit_votes.split_off(&(round + 1));
                    self.highest_committed_round = round;
                    self.pending_commit_blocks = self.pending_commit_blocks.split_off(&(round + 1));
                },
```

**File:** terraform/helm/monitoring/files/rules/alerts.yml (L91-125)
```yaml
  - alert: Validator Low Disk Space (warning)
    expr: (kubelet_volume_stats_capacity_bytes{persistentvolumeclaim=~".*(validator|fullnode)-e.*"} - kubelet_volume_stats_used_bytes) / 1024 / 1024 / 1024 < 200
    for: 1h
    labels:
      severity: warning
      summary: "Less than 200 GB of free space on Aptos Node."
    annotations:
      description: "(This is a warning, deal with it in working hours.) A validator or fullnode pod has less than 200 GB of disk space. Take these steps:
        1. If only a few nodes have this issue, it might be that they are not typically spec'd or customized differently, \
          it's most likely a expansion of the volume is needed soon. Talk to the PE team. Otherwise, it's a bigger issue.
        2. Pass this issue on to the storage team. If you are the storage team, read on.
        3. Go to the dashboard and look for the stacked up column family sizes. \
          If the total size on that chart can't justify low free disk space, we need to log in to a node to see if something other than the AptosDB is eating up disk. \
          Start from things under /opt/aptos/data.
        3 Otherwise, if the total size on that chart is the majority of the disk consumption, zoom out and look for anomalies -- sudden increases overall or on a few \
          specific Column Families, etc. Also check average size of each type of data. Reason about the anomaly with changes in recent releases in mind.
        4 If everything made sense, it's a bigger issue, somehow our gas schedule didn't stop state explosion before an alert is triggered. Our recommended disk \
          spec and/or default pruning configuration, as well as storage gas schedule need updates. Discuss with the ecosystem team and send out a PR on the docs site, \
          form a plan to inform the node operator community and prepare for a on-chain proposal to update the gas schedule."
  - alert: Validator Very Low Disk Space (critical)
    expr: (kubelet_volume_stats_capacity_bytes{persistentvolumeclaim=~".*(validator|fullnode)-e.*"} - kubelet_volume_stats_used_bytes) / 1024 / 1024 / 1024 < 50
    for: 5m
    labels:
      severity: critical
      summary: "Less than 50 GB of free space on Aptos Node."
    annotations:
      description: "A validator or fullnode pod has less than 50 GB of disk space -- that's dangerously low. \
        1. A warning level alert of disk space less than 200GB should've fired a few days ago at least, search on slack and understand why it's not dealt with.
        2. Search in the code for the runbook of the warning alert, quickly go through that too determine if it's a bug. Involve the storage team and other team accordingly.
      If no useful information is found, evaluate the trend of disk usage increasing, how long can we run further? If it can't last the night, you have these options to mitigate this:
        1. Expand the disk if it's a cloud volume.
        2. Shorten the pruner windows. Before that, find the latest version of these https://github.com/aptos-labs/aptos-core/blob/48cc64df8a64f2d13012c10d8bd5bf25d94f19dc/config/src/config/storage_config.rs#L166-L218 \
          and read carefully the comments on the prune window config entries -- set safe values.
        3. If you believe this is happening on nodes that are not run by us, involve the PE / Community / Ecosystem teams to coordinate efforts needed on those nodes.
      "
```
