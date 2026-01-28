# Audit Report

## Title
Bootstrap-to-Continuous-Sync Transition Race Condition Causes Validator Node Crash

## Summary
A race condition exists in the auto-bootstrap code path where `bootstrapping_complete()` is called without checking for pending storage data chunks. This causes `finish_chunk_executor()` to destroy the chunk executor's internal state while background threads are still processing chunks, resulting in a panic and validator node crash.

## Finding Description

The vulnerability occurs specifically in the **auto-bootstrap path** of the state sync driver. When auto-bootstrapping triggers, it calls `bootstrapping_complete()` directly without checking if storage data is still being processed.

**Vulnerable Code Path:**

The auto-bootstrap logic checks if the connection deadline has passed and directly calls `bootstrapping_complete()`: [1](#0-0) 

This calls `bootstrapping_complete()` which then invokes `notify_listeners_if_bootstrapped()`: [2](#0-1) 

Inside `notify_listeners_if_bootstrapped()`, the code calls `finish_chunk_executor()` WITHOUT checking for pending storage data: [3](#0-2) 

The `finish_chunk_executor()` method destroys the chunk executor's internal state: [4](#0-3) 

Meanwhile, spawned storage synchronizer threads (executor, ledger_updater, committer) continue processing pending chunks. These threads call methods like `update_ledger()` and `commit_chunk()` which invoke `with_inner()`: [5](#0-4) 

The panic occurs at line 94 with `.expect("not reset")` when `inner` is `None`.

**Contrast with Normal Bootstrap Path:**

The normal bootstrap completion path correctly checks for pending data before proceeding: [6](#0-5) 

This check is MISSING in the auto-bootstrap path, creating the race condition.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program:

- **Validator Node Crashes**: The panic causes immediate process termination, requiring manual operator intervention to restart
- **Network Availability Impact**: Affects new validators or validators restarting from genesis during network upgrades or onboarding
- **No Automatic Recovery**: The crash requires manual restart; there is no graceful degradation or error recovery

The impact is limited to validators with genesis waypoints (version 0) and auto-bootstrapping enabled, which primarily affects new validator deployments and single-node test configurations.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability can be triggered when all of the following conditions are met:
1. Auto-bootstrapping is enabled (configuration-dependent)
2. Validator has a genesis waypoint (version 0)
3. Data chunks are queued from peers
4. All peers disconnect (causing `global_data_summary.is_empty()` to be true)
5. Connection deadline expires while chunks are still processing in background threads

**Natural Occurrence:** Can happen during network instability when peers disconnect during initial sync, especially with slow storage or large data batches.

**Timing Requirements:** The window requires chunks to be in-flight when peers disappear and the deadline expires. While narrow, this is achievable through:
- Network partitions during validator onboarding
- Coordinated peer disconnections
- Natural network instability during bootstrap

**Note on Attack Scenario:** The original report's claim that "an attacker provides slow data to trigger auto-bootstrap" is inaccurate. Auto-bootstrapping only triggers when there are NO peers (`global_data_summary.is_empty()`). The actual scenario requires peers to provide data, then disconnect before processing completes.

## Recommendation

Add a check for pending storage data before calling `finish_chunk_executor()` in the auto-bootstrap path. Modify `check_auto_bootstrapping()` to verify no pending chunks exist:

```rust
async fn check_auto_bootstrapping(&mut self) {
    if !self.bootstrapper.is_bootstrapped()
        && self.is_consensus_or_observer_enabled()
        && self.driver_configuration.config.enable_auto_bootstrapping
        && self.driver_configuration.waypoint.version() == 0
    {
        if let Some(start_time) = self.start_time {
            if let Some(connection_deadline) = start_time.checked_add(Duration::from_secs(
                self.driver_configuration
                    .config
                    .max_connection_deadline_secs,
            )) {
                if self.time_service.now() >= connection_deadline {
                    // ADD THIS CHECK:
                    if self.bootstrapper.pending_storage_data() {
                        return; // Wait for pending data to complete
                    }
                    
                    info!(LogSchema::new(LogEntry::AutoBootstrapping).message(
                        "Passed the connection deadline! Auto-bootstrapping the validator!"
                    ));
                    if let Err(error) = self.bootstrapper.bootstrapping_complete().await {
                        warn!(LogSchema::new(LogEntry::AutoBootstrapping)
                            .error(&error)
                            .message("Failed to mark bootstrapping as complete!"));
                    }
                }
            }
        }
    }
}
```

Alternatively, add the check inside `notify_listeners_if_bootstrapped()` before calling `finish_chunk_executor()`.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Starting a validator with auto-bootstrap enabled and genesis waypoint
2. Having a peer connect and provide bootstrap data to queue chunks in storage synchronizer
3. Disconnecting all peers to make `global_data_summary.is_empty()` return true
4. Waiting for `max_connection_deadline_secs` to expire
5. Observing the panic when auto-bootstrap calls `finish_chunk_executor()` while background threads are still processing the queued chunks

The panic will occur with the message `"not reset"` at the `.expect()` call when `with_inner()` is invoked by background processing threads.

## Notes

- The vulnerability is specific to the auto-bootstrap code path; normal bootstrap completion correctly checks for pending data
- Impact is limited to validators with genesis waypoints and auto-bootstrap enabled
- The timing window is narrow but achievable through network conditions
- The background processing threads (executor, ledger_updater, committer, commit_post_processor) are spawned asynchronously and continue executing even after `finish_chunk_executor()` is called

### Citations

**File:** state-sync/state-sync-driver/src/driver.rs (L636-664)
```rust
    async fn check_auto_bootstrapping(&mut self) {
        if !self.bootstrapper.is_bootstrapped()
            && self.is_consensus_or_observer_enabled()
            && self.driver_configuration.config.enable_auto_bootstrapping
            && self.driver_configuration.waypoint.version() == 0
        {
            if let Some(start_time) = self.start_time {
                if let Some(connection_deadline) = start_time.checked_add(Duration::from_secs(
                    self.driver_configuration
                        .config
                        .max_connection_deadline_secs,
                )) {
                    if self.time_service.now() >= connection_deadline {
                        info!(LogSchema::new(LogEntry::AutoBootstrapping).message(
                            "Passed the connection deadline! Auto-bootstrapping the validator!"
                        ));
                        if let Err(error) = self.bootstrapper.bootstrapping_complete().await {
                            warn!(LogSchema::new(LogEntry::AutoBootstrapping)
                                .error(&error)
                                .message("Failed to mark bootstrapping as complete!"));
                        }
                    }
                } else {
                    warn!(LogSchema::new(LogEntry::AutoBootstrapping)
                        .message("The connection deadline overflowed! Unable to auto-bootstrap!"));
                }
            }
        }
    }
```

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

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L424-437)
```rust
        if self.active_data_stream.is_some() {
            // We have an active data stream. Process any notifications!
            self.process_active_stream_notifications().await?;
        } else if self.storage_synchronizer.pending_storage_data() {
            // Wait for any pending data to be processed
            sample!(
                SampleRate::Duration(Duration::from_secs(PENDING_DATA_LOG_FREQ_SECS)),
                info!("Waiting for the storage synchronizer to handle pending data!")
            );
        } else {
            // Fetch a new data stream to start streaming data
            self.initialize_active_data_stream(global_data_summary)
                .await?;
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

**File:** execution/executor/src/chunk_executor/mod.rs (L221-225)
```rust
    fn finish(&self) {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["chunk", "finish"]);

        *self.inner.write() = None;
    }
```
