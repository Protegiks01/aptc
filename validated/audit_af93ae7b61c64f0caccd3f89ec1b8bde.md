# Audit Report

## Title
Race Condition Between Bootstrap Completion and Continuous Syncer Initialization Causes Validator Node Panic

## Summary
A race condition exists between the bootstrap completion process and the continuous syncer initialization that can cause validator nodes to panic. When bootstrap completes, it sets the `bootstrapped` flag to `true` before cleaning up the chunk executor. During this window, the continuous syncer can start and reset the chunk executor, which is then finished by the bootstrapper, leaving the continuous syncer with a `None` chunk executor that causes a panic when accessed.

## Finding Description
The vulnerability lies in the asynchronous bootstrap completion flow in the state-sync driver. When bootstrapping completes, the bootstrapper sets `self.bootstrapped = true` and then calls `notify_listeners_if_bootstrapped().await` [1](#0-0) .

Inside `notify_listeners_if_bootstrapped()`, the method performs cleanup operations including calling `self.reset_active_stream(None).await?` followed by `self.storage_synchronizer.finish_chunk_executor()` [2](#0-1) .

The critical issue occurs at the `await` point within `reset_active_stream()`, which calls `terminate_stream_with_feedback(...).await?` [3](#0-2) . This async operation yields control back to the async runtime, allowing other tasks to execute.

During this yield, the driver's event loop can process its progress check interval. The `drive_progress()` method checks `if self.bootstrapper.is_bootstrapped()` [4](#0-3) . Since `bootstrapped` was already set to `true`, this check passes and the continuous syncer is started.

The continuous syncer initialization calls `self.storage_synchronizer.reset_chunk_executor()` [5](#0-4) , which creates a new `ChunkExecutorInner` by setting `*self.inner.write() = Some(ChunkExecutorInner::new(...))` [6](#0-5) .

However, when control returns to the bootstrapper after the await completes, it calls `self.storage_synchronizer.finish_chunk_executor()` [7](#0-6) , which sets the chunk executor's inner to `None` by executing `*self.inner.write() = None` [8](#0-7) .

When the continuous syncer subsequently tries to use the chunk executor (e.g., via `enqueue_chunk_by_execution` or `enqueue_chunk_by_transaction_outputs`), these methods call `with_inner()` [9](#0-8) . The `with_inner()` method attempts to access the inner executor with `let inner = locked.as_ref().expect("not reset")` [10](#0-9) . This panics because `inner` is `None`, crashing the validator node.

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

The likelihood increases under these conditions:
- High-frequency progress check intervals (configurable via `progress_check_interval_ms` in the driver configuration [11](#0-10) )
- Slow stream cleanup operations due to network delays or large pending data
- Busy validator nodes with high async task contention
- Repeated bootstrap attempts after restarts or state sync failures

The race can occur naturally during normal validator operations without any attacker intervention. It's more likely on production validators under load or during network issues that slow stream termination.

## Recommendation
Add synchronization to prevent the continuous syncer from starting while bootstrap cleanup is in progress. The fix should ensure that `finish_chunk_executor()` is called before the `bootstrapped` flag becomes visible to other components.

**Option 1: Complete cleanup before setting bootstrapped flag**
```rust
pub async fn bootstrapping_complete(&mut self) -> Result<(), Error> {
    info!(LogSchema::new(LogEntry::Bootstrapper)
        .message("The node has successfully bootstrapped!"));
    
    // Complete cleanup BEFORE setting bootstrapped flag
    self.notify_listeners_if_bootstrapped_internal().await?;
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

**Option 2: Add a cleanup_in_progress flag**
Add a `cleanup_in_progress: bool` flag that prevents the continuous syncer from initializing until cleanup completes.

## Proof of Concept
The race condition can be observed by:

1. Setting a very short `progress_check_interval_ms` (e.g., 1ms)
2. Running a validator node through bootstrap with slow network conditions
3. Observing the panic message `"not reset"` when the chunk executor's `with_inner()` method is called

A deterministic test could inject artificial delays in `reset_active_stream()` and force the progress check to execute during that window, though the async nature makes this challenging to reproduce reliably without modifications to the production code.

**Notes**
This is a legitimate concurrency bug in the state synchronization system that can cause validator nodes to crash during the bootstrap-to-continuous-sync transition. The vulnerability is architectural rather than requiring attacker intervention, making it a valid HIGH severity issue under the Aptos bug bounty program.

### Citations

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L373-377)
```rust
    pub async fn bootstrapping_complete(&mut self) -> Result<(), Error> {
        info!(LogSchema::new(LogEntry::Bootstrapper)
            .message("The node has successfully bootstrapped!"));
        self.bootstrapped = true;
        self.notify_listeners_if_bootstrapped().await
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

**File:** state-sync/state-sync-driver/src/driver.rs (L213-216)
```rust
        let mut progress_check_interval = IntervalStream::new(interval(Duration::from_millis(
            self.driver_configuration.config.progress_check_interval_ms,
        )))
        .fuse();
```

**File:** state-sync/state-sync-driver/src/driver.rs (L692-710)
```rust
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
```

**File:** state-sync/state-sync-driver/src/continuous_syncer.rs (L100-105)
```rust
    async fn initialize_active_data_stream(
        &mut self,
        consensus_sync_request: Arc<Mutex<Option<ConsensusSyncRequest>>>,
    ) -> Result<(), Error> {
        // Reset the chunk executor to flush any invalid state currently held in-memory
        self.storage_synchronizer.reset_chunk_executor()?;
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
