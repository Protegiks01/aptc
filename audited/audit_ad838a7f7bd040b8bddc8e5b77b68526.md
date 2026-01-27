Audit Report

## Title
Silent Final Version Mismatch in replay_kv Allows Incomplete Transaction Restores Without Error

## Summary
The `replay_kv()` function in Aptos Core's backup restore process fails to enforce consistency of the final version after transactional KV replay. If any transaction chunk silently fails to stream (e.g., due to premature stream completion or chunk loss), the system may report successful completion while actually omitting required transactions. This results in a DB state inconsistent with the expected target, violating key state and consensus invariants.

## Finding Description
In the function `replay_kv()` (`storage/backup/backup-cli/src/backup_types/transaction/restore.rs`), a `try_fold` collects the "total_replayed" version by simply accepting the most recent version processed from the stream. However, if the transaction stream (`db_commit_stream`) is prematurely truncated or omits chunks due to not being present or unexpected failure in the stream pipeline, `try_fold` will succeed, returning the last processed version. The function never validates that this version reaches the expected final one (e.g., the global `target_version`). This can lead to an incomplete database restore, which is neither reported as an error nor detected by the final control-flow. Logs and metrics would misleadingly show replay "success".

This is different from the `replay_transactions` pathway, which performs explicit assertion checks and commits, reducing this risk.

If chunk loss or stream truncation occurs due to network, backup, or deserialization errors not surfaced as Result errors, this bug can silently leave the node incomplete and unsynced relative to the canonical ledger. Such divergence can remain undetected until subsequent node operation, at which point consensus or state verification may fail—with potential for network split or necessity of full re-restore.

## Impact Explanation
This is a **High Severity** protocol violation under the Aptos bug bounty program:
- Any node restored with missing transactions will have a divergent state inconsistent with the canonical blockchain, violating the **Deterministic Execution** and **State Consistency** invariants.
- While it does not directly permit fund theft or arbitrary state injection, it presents a critical risk to network safety if multiple nodes are restored from the same incomplete backup set.
- Malicious manipulation of backup sets or induced backup errors could lead to targeted node isolation or permanent unsync.

## Likelihood Explanation
The bug could be triggered by attackers who supply manipulated backup transaction data (e.g., as part of a public backup sharing scheme), by failures in distributed backup systems, or by accidental network/infra issues during node restore operations. Detection is nontrivial, as no error or warning is surfaced—the restoration tool will return Ok(()) and misleading metrics.

## Recommendation
- Enforce a post-condition at the end of `replay_kv()` that the final replayed version equals the configured `target_version`.
- If the processed stream ends early, explicitly raise an error.
- Add an integrity validation after all chunks are processed to require that no chunks were missed, and that state transitions match expected ledger proofs.

Suggested code addition after line 629:
```rust
ensure!(
    total_replayed == self.global_opt.target_version,
    "KV Replay did not reach the expected target_version: got {}, expected {}",
    total_replayed,
    self.global_opt.target_version
);
```

## Proof of Concept

1. Create a backup manifest missing the last transaction chunk, but whose earlier chunks cover a valid range.
2. Restore a node using the current restore tool in KV mode, aiming for `target_version = N`.
3. Observe that `replay_kv()` completes successfully, logging a lower "total_replayed" than target, no error.
4. Start the node: it will be out-of-sync and reject further state syncs or consensus participation until manually fixed.

This can be demonstrated by tampering with a backup set or by simulating a faulty manifest in integration testing.

---

Citations: [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L251-340)
```rust
/// Takes a series of transaction backup manifests, preheat in parallel, then execute in order.
pub struct TransactionRestoreBatchController {
    global_opt: GlobalRestoreOptions,
    storage: Arc<dyn BackupStorage>,
    manifest_handles: Vec<FileHandle>,
    replay_from_version: Option<(Version, bool)>,
    epoch_history: Option<Arc<EpochHistory>>,
    verify_execution_mode: VerifyExecutionMode,
    output_transaction_analysis: Option<PathBuf>,
    first_version: Option<Version>,
}

impl TransactionRestoreBatchController {
    pub fn new(
        global_opt: GlobalRestoreOptions,
        storage: Arc<dyn BackupStorage>,
        manifest_handles: Vec<FileHandle>,
        first_version: Option<Version>,
        replay_from_version: Option<(Version, bool)>, // bool indicates if this is a KV only replay
        epoch_history: Option<Arc<EpochHistory>>,
        verify_execution_mode: VerifyExecutionMode,
        output_transaction_analysis: Option<PathBuf>,
    ) -> Self {
        Self {
            global_opt,
            storage,
            manifest_handles,
            replay_from_version,
            epoch_history,
            verify_execution_mode,
            output_transaction_analysis,
            first_version,
        }
    }

    pub async fn run(self) -> Result<()> {
        let name = self.name();
        info!("{} started.", name);
        self.run_impl()
            .await
            .map_err(|e| anyhow!("{} failed: {}", name, e))?;
        info!("{} succeeded.", name);
        Ok(())
    }

    fn name(&self) -> String {
        format!("transaction {}", self.global_opt.run_mode.name())
    }

    async fn run_impl(self) -> Result<()> {
        if self.manifest_handles.is_empty() {
            return Ok(());
        }

        let mut loaded_chunk_stream = self.loaded_chunk_stream();
        // If first_version is None, we confirm and save frozen substrees to create a baseline
        // When first version is not None, it only happens when we already finish first phase of db restore and
        // we don't need to confirm and save frozen subtrees again.
        let first_version = self.first_version.unwrap_or(
            self.confirm_or_save_frozen_subtrees(&mut loaded_chunk_stream)
                .await?,
        );
        if let RestoreRunMode::Restore { restore_handler } = self.global_opt.run_mode.as_ref() {
            ensure!(
                self.output_transaction_analysis.is_none(),
                "Bug: requested to output transaction output sizing info in restore mode.",
            );
            AptosVM::set_concurrency_level_once(self.global_opt.replay_concurrency_level);

            let kv_only = self.replay_from_version.is_some_and(|(_, k)| k);
            let txns_to_execute_stream = self
                .save_before_replay_version(first_version, loaded_chunk_stream, restore_handler)
                .await?;

            if let Some(txns_to_execute_stream) = txns_to_execute_stream {
                if kv_only {
                    self.replay_kv(restore_handler, txns_to_execute_stream)
                        .await?;
                } else {
                    self.replay_transactions(restore_handler, txns_to_execute_stream)
                        .await?;
                }
            }
        } else {
            self.go_through_verified_chunks(loaded_chunk_stream, first_version)
                .await?;
        }
        Ok(())
    }

```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L341-401)
```rust
    fn loaded_chunk_stream(&self) -> Peekable<impl Stream<Item = Result<LoadedChunk>> + use<>> {
        let con = self.global_opt.concurrent_downloads;

        let manifest_handle_stream = stream::iter(self.manifest_handles.clone());

        let storage = self.storage.clone();
        let manifest_stream = manifest_handle_stream
            .map(move |hdl| {
                let storage = storage.clone();
                async move { storage.load_json_file(&hdl).await.err_notes(&hdl) }
            })
            .buffered_x(con * 3, con)
            .and_then(|m: TransactionBackup| future::ready(m.verify().map(|_| m)));

        let target_version = self.global_opt.target_version;
        let first_version = self.first_version.unwrap_or(0);
        let chunk_manifest_stream = manifest_stream
            .map_ok(|m| stream::iter(m.chunks.into_iter().map(Result::<_>::Ok)))
            .try_flatten()
            .try_filter(move |c| {
                future::ready(c.first_version <= target_version && c.last_version >= first_version)
            })
            .scan(0, |last_chunk_last_version, chunk_res| {
                let res = match &chunk_res {
                    Ok(chunk) => {
                        if *last_chunk_last_version != 0
                            && chunk.first_version != *last_chunk_last_version + 1
                        {
                            Some(Err(anyhow!(
                                "Chunk range not consecutive. expecting {}, got {}",
                                *last_chunk_last_version + 1,
                                chunk.first_version
                            )))
                        } else {
                            *last_chunk_last_version = chunk.last_version;
                            Some(chunk_res)
                        }
                    },
                    Err(_) => Some(chunk_res),
                };
                future::ready(res)
            });

        let storage = self.storage.clone();
        let epoch_history = self.epoch_history.clone();
        chunk_manifest_stream
            .and_then(move |chunk| {
                let storage = storage.clone();
                let epoch_history = epoch_history.clone();
                future::ok(async move {
                    tokio::task::spawn(async move {
                        LoadedChunk::load(chunk, &storage, epoch_history.as_ref()).await
                    })
                    .err_into::<anyhow::Error>()
                    .await
                })
            })
            .try_buffered_x(con * 2, con)
            .and_then(future::ready)
            .peekable()
    }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L553-637)
```rust
    // only apply KV to the DB
    async fn replay_kv(
        &self,
        restore_handler: &RestoreHandler,
        txns_to_execute_stream: impl Stream<
            Item = Result<(
                Transaction,
                PersistedAuxiliaryInfo,
                TransactionInfo,
                WriteSet,
                Vec<ContractEvent>,
            )>,
        >,
    ) -> Result<()> {
        let (first_version, _) = self.replay_from_version.unwrap();
        restore_handler.force_state_version_for_kv_restore(first_version.checked_sub(1))?;

        let mut base_version = first_version;
        let mut offset = 0u64;
        let replay_start = Instant::now();
        let arc_restore_handler = Arc::new(restore_handler.clone());

        let db_commit_stream = txns_to_execute_stream
            .try_chunks(BATCH_SIZE)
            .err_into::<anyhow::Error>()
            .map_ok(|chunk| {
                let (txns, persisted_aux_info, txn_infos, write_sets, events): (
                    Vec<_>,
                    Vec<_>,
                    Vec<_>,
                    Vec<_>,
                    Vec<_>,
                ) = chunk.into_iter().multiunzip();
                let handler = arc_restore_handler.clone();
                base_version += offset;
                offset = txns.len() as u64;
                async move {
                    let _timer = OTHER_TIMERS_SECONDS.timer_with(&["replay_txn_chunk_kv_only"]);
                    tokio::task::spawn_blocking(move || {
                        // we directly save transaction and kvs to DB without involving chunk executor
                        handler.save_transactions_and_replay_kv(
                            base_version,
                            &txns,
                            &persisted_aux_info,
                            &txn_infos,
                            &events,
                            write_sets,
                        )?;
                        // return the last version after the replaying
                        Ok(base_version + offset - 1)
                    })
                    .err_into::<anyhow::Error>()
                    .await
                }
            })
            .try_buffered_x(self.global_opt.concurrent_downloads, 1)
            .and_then(future::ready);

        let total_replayed = db_commit_stream
            .and_then(|version| async move {
                let _timer = OTHER_TIMERS_SECONDS.timer_with(&["commit_txn_chunk_kv_only"]);
                tokio::task::spawn_blocking(move || {
                    // version is the latest version finishing the KV replaying
                    let total_replayed = version - first_version;
                    TRANSACTION_REPLAY_VERSION.set(version as i64);
                    info!(
                        version = version,
                        accumulative_tps =
                            (total_replayed as f64 / replay_start.elapsed().as_secs_f64()) as u64,
                        "KV replayed."
                    );
                    Ok(version)
                })
                .await?
            })
            .try_fold(0, |_total, total| future::ok(total))
            .await?;
        info!(
            total_replayed = total_replayed,
            accumulative_tps =
                (total_replayed as f64 / replay_start.elapsed().as_secs_f64()) as u64,
            "KV Replay finished."
        );
        Ok(())
    }
```
