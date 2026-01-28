# Audit Report

## Title
Race Condition Between Bootstrap Completion and Continuous Syncer Initialization Causes Validator Node Panic

## Summary
A race condition exists between the bootstrap completion process and the continuous syncer initialization that can cause validator nodes to panic. When bootstrap completes, it sets the `bootstrapped` flag to `true` before cleaning up the chunk executor. During this window, the continuous syncer can start and reset the chunk executor, which is then finished by the bootstrapper, leaving the continuous syncer with a `None` chunk executor that causes a panic when accessed.

## Finding Description
The vulnerability lies in the asynchronous bootstrap completion flow in the state-sync driver. When bootstrapping completes, the bootstrapper sets `self.bootstrapped = true` and then calls `notify_listeners_if_bootstrapped().await`. [1](#0-0) 

Inside `notify_listeners_if_bootstrapped()`, the method performs cleanup operations including calling `self.reset_active_stream(None).await?` followed by `self.storage_synchronizer.finish_chunk_executor()`. [2](#0-1) 

The critical issue occurs at the `await` point within `reset_active_stream()`, which calls `terminate_stream_with_feedback(...).await?`. This async operation yields control back to the async runtime, allowing other tasks to execute. [3](#0-2) 

During this yield, the driver's event loop can process its progress check interval. The driver runs in a single async task with a `futures::select!` loop that polls multiple notification sources including a `progress_check_interval`. [4](#0-3) 

The `drive_progress()` method checks `if self.bootstrapper.is_bootstrapped()`. Since `bootstrapped` was already set to `true`, this check passes and the continuous syncer is started. [5](#0-4) 

The continuous syncer initialization calls `self.storage_synchronizer.reset_chunk_executor()`, which creates a new `ChunkExecutorInner` by setting `*self.inner.write() = Some(ChunkExecutorInner::new(...))`. [6](#0-5) [7](#0-6) 

However, when control returns to the bootstrapper after the await completes, it calls `self.storage_synchronizer.finish_chunk_executor()`, which sets the chunk executor's inner to `None` by executing `*self.inner.write() = None`. [8](#0-7) [9](#0-8) 

When the continuous syncer subsequently tries to use the chunk executor via `enqueue_chunk_by_execution` or `enqueue_chunk_by_transaction_outputs`, these methods call `with_inner()`. The `with_inner()` method attempts to access the inner executor with `let inner = locked.as_ref().expect("not reset")`. This panics because `inner` is `None`, crashing the validator node. [10](#0-9) [11](#0-10) [12](#0-11) 

## Impact Explanation
This vulnerability causes validator node crashes, which falls under **HIGH severity** according to the Aptos bug bounty program categories for "Validator node slowdowns" and "API crashes". A crashed validator node:

1. **Affects network liveness**: Reduces the number of active validators, potentially impacting consensus if enough validators crash simultaneously
2. **Requires manual intervention**: Validator operators must restart nodes to restore functionality
3. **Can occur repeatedly**: If timing conditions persist during restart, nodes may crash on every bootstrap attempt
4. **Disrupts validator operations**: Affects validator rewards, uptime metrics, and network participation

While this doesn't directly violate consensus safety (the panic prevents potentially incorrect execution), it violates the availability invariant and can cause significant operational disruptions to the network.

## Likelihood Explanation
**Likelihood: MEDIUM**

The race condition requires specific timing where the progress check interval fires during the narrow window between setting `bootstrapped = true` and calling `finish_chunk_executor()`. This window occurs during the `reset_active_stream().await` call, which involves network I/O operations that can take from milliseconds to seconds depending on stream cleanup complexity.

The default `progress_check_interval_ms` is 100ms, which creates frequent opportunities for this race to occur. [13](#0-12) 

The likelihood increases under these conditions:
- High-frequency progress check intervals (configurable via `progress_check_interval_ms`)
- Slow stream cleanup operations due to network delays or large pending data
- Busy validator nodes with high async task contention
- Repeated bootstrap attempts after restarts or state sync failures

The race can occur naturally during normal validator operations without any attacker intervention. It's more likely on production validators under load or during network issues that slow stream termination.

## Recommendation
The fix requires ensuring that the `bootstrapped` flag is only set to `true` after all cleanup operations are complete, or introducing synchronization to prevent the continuous syncer from starting while bootstrap cleanup is in progress. The recommended approach is to move the `self.bootstrapped = true` assignment to after the cleanup completes:

```rust
pub async fn bootstrapping_complete(&mut self) -> Result<(), Error> {
    info!(LogSchema::new(LogEntry::Bootstrapper)
        .message("The node has successfully bootstrapped!"));
    // First perform all cleanup operations
    self.notify_listeners_if_bootstrapped_internal().await?;
    // Only then mark as bootstrapped
    self.bootstrapped = true;
    Ok(())
}

async fn notify_listeners_if_bootstrapped_internal(&mut self) -> Result<(), Error> {
    if let Some(notifier_channel) = self.bootstrap_notifier_channel.take() {
        if let Err(error) = notifier_channel.send(Ok(())) {
            return Err(Error::CallbackSendFailed(format!(
                "Bootstrap notification error: {:?}",
                error
            )));
        }
    }
    self.reset_active_stream(None).await?;
    self.storage_synchronizer.finish_chunk_executor();
    Ok(())
}
```

Alternatively, add a flag to track cleanup completion and check it in the continuous syncer initialization.

## Proof of Concept
The race condition can be reproduced by:
1. Starting a validator node that requires bootstrapping
2. Configuring a short `progress_check_interval_ms` (e.g., 50ms)
3. Simulating slow network conditions during stream termination
4. Observing the panic with message "not reset" when the continuous syncer attempts to use the chunk executor

A deterministic test would require mocking the async runtime to control task scheduling, forcing the progress check to fire during the bootstrap cleanup window.

**Notes**
This is a genuine race condition in the state sync driver's bootstrap completion flow that can cause validator crashes in production. The vulnerability stems from the asynchronous nature of the cleanup operations and the lack of synchronization between the bootstrap completion flag and the actual completion of cleanup tasks. The issue is particularly problematic because it can cause repeated crashes during validator startup, making it difficult for affected validators to join the network.

### Citations

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L373-378)
```rust
    pub async fn bootstrapping_complete(&mut self) -> Result<(), Error> {
        info!(LogSchema::new(LogEntry::Bootstrapper)
            .message("The node has successfully bootstrapped!"));
        self.bootstrapped = true;
        self.notify_listeners_if_bootstrapped().await
    }
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L396-411)
```rust
    async fn notify_listeners_if_bootstrapped(&mut self) -> Result<(), Error> {
        if self.is_bootstrapped() {
            if let Some(notifier_channel) = self.bootstrap_notifier_channel.take() {
                if let Err(error) = notifier_channel.send(Ok(())) {
                    return Err(Error::CallbackSendFailed(format!(
                        "Bootstrap notification error: {:?}",
                        error
                    )));
                }
            }
            self.reset_active_stream(None).await?;
            self.storage_synchronizer.finish_chunk_executor(); // The bootstrapper is now complete
        }

        Ok(())
    }
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L1539-1556)
```rust
    pub async fn reset_active_stream(
        &mut self,
        notification_and_feedback: Option<NotificationAndFeedback>,
    ) -> Result<(), Error> {
        if let Some(active_data_stream) = &self.active_data_stream {
            let data_stream_id = active_data_stream.data_stream_id;
            utils::terminate_stream_with_feedback(
                &mut self.streaming_client,
                data_stream_id,
                notification_and_feedback,
            )
            .await?;
        }

        self.active_data_stream = None;
        self.speculative_stream_state = None;
        Ok(())
    }
```

**File:** state-sync/state-sync-driver/src/driver.rs (L212-240)
```rust
    pub async fn start_driver(mut self) {
        let mut progress_check_interval = IntervalStream::new(interval(Duration::from_millis(
            self.driver_configuration.config.progress_check_interval_ms,
        )))
        .fuse();

        // Start the driver
        info!(LogSchema::new(LogEntry::Driver).message("Started the state sync v2 driver!"));
        self.start_time = Some(self.time_service.now());
        loop {
            ::futures::select! {
                notification = self.client_notification_listener.select_next_some() => {
                    self.handle_client_notification(notification).await;
                },
                notification = self.commit_notification_listener.select_next_some() => {
                    self.handle_snapshot_commit_notification(notification).await;
                }
                notification = self.consensus_notification_handler.select_next_some() => {
                    self.handle_consensus_or_observer_notification(notification).await;
                }
                notification = self.error_notification_listener.select_next_some() => {
                    self.handle_error_notification(notification).await;
                }
                _ = progress_check_interval.select_next_some() => {
                    self.drive_progress().await;
                }
            }
        }
    }
```

**File:** state-sync/state-sync-driver/src/driver.rs (L667-720)
```rust
    async fn drive_progress(&mut self) {
        // Update the executing component metrics
        self.update_executing_component_metrics();

        // Fetch the global data summary and verify we have active peers
        let global_data_summary = self.aptos_data_client.get_global_data_summary();
        if global_data_summary.is_empty() {
            trace!(LogSchema::new(LogEntry::Driver).message(
                "The global data summary is empty! It's likely that we have no active peers."
            ));
            return self.check_auto_bootstrapping().await;
        }

        // Check the progress of any sync requests
        if let Err(error) = self.check_sync_request_progress().await {
            warn!(LogSchema::new(LogEntry::Driver)
                .error(&error)
                .message("Error found when checking the sync request progress!"));
        }

        // If consensus or consensus observer is executing, there's nothing to do
        if self.check_if_consensus_or_observer_executing() {
            return;
        }

        // Drive progress depending on if we're bootstrapping or continuously syncing
        if self.bootstrapper.is_bootstrapped() {
            // Fetch any consensus sync requests
            let consensus_sync_request = self.consensus_notification_handler.get_sync_request();

            // Attempt to continuously sync
            if let Err(error) = self
                .continuous_syncer
                .drive_progress(consensus_sync_request)
                .await
            {
                sample!(
                    SampleRate::Duration(Duration::from_secs(DRIVER_ERROR_LOG_FREQ_SECS)),
                    warn!(LogSchema::new(LogEntry::Driver)
                        .error(&error)
                        .message("Error found when driving progress of the continuous syncer!"));
                );
                metrics::increment_counter(&metrics::CONTINUOUS_SYNCER_ERRORS, error.get_label());
            }
        } else if let Err(error) = self.bootstrapper.drive_progress(&global_data_summary).await {
            sample!(
                    SampleRate::Duration(Duration::from_secs(DRIVER_ERROR_LOG_FREQ_SECS)),
                    warn!(LogSchema::new(LogEntry::Driver)
                        .error(&error)
                        .message("Error found when checking the bootstrapper progress!"));
            );
            metrics::increment_counter(&metrics::BOOTSTRAPPER_ERRORS, error.get_label());
        };
    }
```

**File:** state-sync/state-sync-driver/src/continuous_syncer.rs (L100-180)
```rust
    async fn initialize_active_data_stream(
        &mut self,
        consensus_sync_request: Arc<Mutex<Option<ConsensusSyncRequest>>>,
    ) -> Result<(), Error> {
        // Reset the chunk executor to flush any invalid state currently held in-memory
        self.storage_synchronizer.reset_chunk_executor()?;

        // Fetch the highest synced version and epoch (in storage)
        let (highest_synced_version, highest_synced_epoch) =
            self.get_highest_synced_version_and_epoch()?;

        // Fetch the highest epoch state (in storage)
        let highest_epoch_state = utils::fetch_latest_epoch_state(self.storage.clone())?;

        // Fetch the consensus sync request target (if there is one)
        let sync_request_target = consensus_sync_request
            .lock()
            .as_ref()
            .and_then(|sync_request| sync_request.get_sync_target());

        // Initialize a new active data stream
        let active_data_stream = match self.get_continuous_syncing_mode() {
            ContinuousSyncingMode::ApplyTransactionOutputs => {
                self.streaming_client
                    .continuously_stream_transaction_outputs(
                        highest_synced_version,
                        highest_synced_epoch,
                        sync_request_target,
                    )
                    .await?
            },
            ContinuousSyncingMode::ExecuteTransactions => {
                self.streaming_client
                    .continuously_stream_transactions(
                        highest_synced_version,
                        highest_synced_epoch,
                        false,
                        sync_request_target,
                    )
                    .await?
            },
            ContinuousSyncingMode::ExecuteTransactionsOrApplyOutputs => {
                if self.output_fallback_handler.in_fallback_mode() {
                    metrics::set_gauge(
                        &metrics::DRIVER_FALLBACK_MODE,
                        ExecutingComponent::ContinuousSyncer.get_label(),
                        1,
                    );
                    self.streaming_client
                        .continuously_stream_transaction_outputs(
                            highest_synced_version,
                            highest_synced_epoch,
                            sync_request_target,
                        )
                        .await?
                } else {
                    metrics::set_gauge(
                        &metrics::DRIVER_FALLBACK_MODE,
                        ExecutingComponent::ContinuousSyncer.get_label(),
                        0,
                    );
                    self.streaming_client
                        .continuously_stream_transactions_or_outputs(
                            highest_synced_version,
                            highest_synced_epoch,
                            false,
                            sync_request_target,
                        )
                        .await?
                }
            },
        };
        self.speculative_stream_state = Some(SpeculativeStreamState::new(
            highest_epoch_state,
            None,
            highest_synced_version,
        ));
        self.active_data_stream = Some(active_data_stream);

        Ok(())
    }
```

**File:** execution/executor/src/chunk_executor/mod.rs (L89-106)
```rust
    fn with_inner<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&ChunkExecutorInner<V>) -> Result<T>,
    {
        let locked = self.inner.read();
        let inner = locked.as_ref().expect("not reset");

        let has_pending_pre_commit = inner.has_pending_pre_commit.load(Ordering::Acquire);
        f(inner).map_err(|error| {
            if has_pending_pre_commit {
                panic!(
                    "Hit error with pending pre-committed ledger, panicking. {:?}",
                    error,
                );
            }
            error
        })
    }
```

**File:** execution/executor/src/chunk_executor/mod.rs (L114-156)
```rust
    fn enqueue_chunk_by_execution(
        &self,
        txn_list_with_proof: TransactionListWithProofV2,
        verified_target_li: &LedgerInfoWithSignatures,
        epoch_change_li: Option<&LedgerInfoWithSignatures>,
    ) -> Result<()> {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["chunk", "enqueue_by_execution"]);
        let _timer = EXECUTE_CHUNK.start_timer();

        self.maybe_initialize()?;

        // Verify input data.
        // In consensus-only mode, txn_list_with_proof is fake.
        if !cfg!(feature = "consensus-only-perf-test") {
            txn_list_with_proof.verify(
                verified_target_li.ledger_info(),
                txn_list_with_proof.get_first_transaction_version(),
            )?;
        }

        let (txn_list_with_proof, persisted_aux_info) = txn_list_with_proof.into_parts();
        // Compose enqueue_chunk parameters.
        let TransactionListWithProof {
            transactions,
            events: _,
            first_transaction_version: v,
            proof: txn_infos_with_proof,
        } = txn_list_with_proof;

        let chunk = ChunkToExecute {
            transactions,
            persisted_aux_info,
            first_version: v.ok_or_else(|| anyhow!("first version is None"))?,
        };
        let chunk_verifier = Arc::new(StateSyncChunkVerifier {
            txn_infos_with_proof,
            verified_target_li: verified_target_li.clone(),
            epoch_change_li: epoch_change_li.cloned(),
        });

        // Call the shared implementation.
        self.with_inner(|inner| inner.enqueue_chunk(chunk, chunk_verifier, "execute"))
    }
```

**File:** execution/executor/src/chunk_executor/mod.rs (L158-200)
```rust
    fn enqueue_chunk_by_transaction_outputs(
        &self,
        txn_output_list_with_proof: TransactionOutputListWithProofV2,
        verified_target_li: &LedgerInfoWithSignatures,
        epoch_change_li: Option<&LedgerInfoWithSignatures>,
    ) -> Result<()> {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["chunk", "enqueue_by_outputs"]);
        let _timer = APPLY_CHUNK.start_timer();

        // Verify input data.
        THREAD_MANAGER.get_exe_cpu_pool().install(|| {
            let _timer = CHUNK_OTHER_TIMERS.timer_with(&["apply_chunk__verify"]);
            txn_output_list_with_proof.verify(
                verified_target_li.ledger_info(),
                txn_output_list_with_proof.get_first_output_version(),
            )
        })?;

        let (txn_output_list_with_proof, persisted_aux_info) =
            txn_output_list_with_proof.into_parts();
        // Compose enqueue_chunk parameters.
        let TransactionOutputListWithProof {
            transactions_and_outputs,
            first_transaction_output_version: v,
            proof: txn_infos_with_proof,
        } = txn_output_list_with_proof;
        let (transactions, transaction_outputs): (Vec<_>, Vec<_>) =
            transactions_and_outputs.into_iter().unzip();
        let chunk = ChunkToApply {
            transactions,
            transaction_outputs,
            persisted_aux_info,
            first_version: v.ok_or_else(|| anyhow!("first version is None"))?,
        };
        let chunk_verifier = Arc::new(StateSyncChunkVerifier {
            txn_infos_with_proof,
            verified_target_li: verified_target_li.clone(),
            epoch_change_li: epoch_change_li.cloned(),
        });

        // Call the shared implementation.
        self.with_inner(|inner| inner.enqueue_chunk(chunk, chunk_verifier, "apply"))
    }
```

**File:** execution/executor/src/chunk_executor/mod.rs (L214-219)
```rust
    fn reset(&self) -> Result<()> {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["chunk", "reset"]);

        *self.inner.write() = Some(ChunkExecutorInner::new(self.db.clone())?);
        Ok(())
    }
```

**File:** execution/executor/src/chunk_executor/mod.rs (L221-225)
```rust
    fn finish(&self) {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["chunk", "finish"]);

        *self.inner.write() = None;
    }
```

**File:** state-sync/state-sync-driver/src/storage_synchronizer.rs (L451-453)
```rust
    fn finish_chunk_executor(&self) {
        self.chunk_executor.finish()
    }
```

**File:** config/src/config/state_sync_config.rs (L134-150)
```rust
impl Default for StateSyncDriverConfig {
    fn default() -> Self {
        Self {
            bootstrapping_mode: BootstrappingMode::ExecuteOrApplyFromGenesis,
            commit_notification_timeout_ms: 5000,
            continuous_syncing_mode: ContinuousSyncingMode::ExecuteTransactionsOrApplyOutputs,
            enable_auto_bootstrapping: false,
            fallback_to_output_syncing_secs: 180, // 3 minutes
            progress_check_interval_ms: 100,
            max_connection_deadline_secs: 10,
            max_consecutive_stream_notifications: 10,
            max_num_stream_timeouts: 12,
            max_pending_data_chunks: 50,
            max_pending_mempool_notifications: 100,
            max_stream_wait_time_ms: 5000,
            num_versions_to_skip_snapshot_sync: 400_000_000, // At 5k TPS, this allows a node to fail for about 24 hours.
        }
```
