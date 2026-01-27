# Audit Report

## Title
Race Condition in State Sync Event Notification Exposes Uncertified State to Subscribers

## Summary
The `handle_committed_transactions` function in state-sync-driver exhibits a race condition where `fetch_pre_committed_version()` can return a higher version than the committed ledger info version due to pipelined consensus execution. This causes the event subscription service to expose uncertified pre-committed state to reconfig subscribers, violating consensus safety guarantees.

## Finding Description

**Root Cause:**

The vulnerability exists in how commit notifications are processed: [1](#0-0) 

The function fetches both the pre-committed version and the latest synced ledger info separately from storage, creating a race window where:

1. Block N+1 completes pre-commit → state store version advances to V(N+1)
2. Block N+2 completes pre-commit → state store version advances to V(N+2)  
3. Block N+1 completes commit-ledger → ledger info version advances to V(N+1)
4. Consensus notifies state sync about block N+1's commit
5. `fetch_pre_committed_version()` reads V(N+2) from state store
6. `fetch_latest_synced_ledger_info()` reads ledger info at V(N+1)

This is possible because pre-commit and commit operations use separate locks: [2](#0-1) [3](#0-2) 

The comment explicitly states "Pre-committing and committing in concurrency is allowed", enabling the race.

**Exploitation Path:**

The inconsistent versions are then passed to the event notification handler: [4](#0-3) 

When a reconfiguration event occurs, the event service reads on-chain configuration from the HIGHER pre-committed version instead of the certified ledger info version: [5](#0-4) [6](#0-5) 

This creates a `DbBackedOnChainConfig` at the uncertified pre-committed version, which is then distributed to all reconfig subscribers (including mempool, consensus, and other critical components).

**Security Invariant Violated:**

This breaks the fundamental consensus safety principle that **only quorum-certified state should be observable to system components**. Pre-committed state lacks a quorum certificate and could theoretically be rolled back in fork scenarios or crashes, yet subscribers are making decisions based on this uncertified state.

## Impact Explanation

**Severity: High**

This qualifies as a **significant protocol violation** per Aptos bug bounty criteria because:

1. **Consensus Safety Risk**: Subscribers receive configuration from state version V(N+2) that has not yet been certified by a quorum certificate, only pre-committed by local execution
2. **State Inconsistency**: Event notifications claim to be at version V(N+2) but contain events from version V(N+1), creating temporal inconsistency
3. **Reconfiguration Hazard**: Critical reconfigurations (validator set changes, gas schedule updates, feature flags) are propagated using uncertified state
4. **Component Desynchronization**: Different components may observe different versions of on-chain configuration depending on timing

In a Byzantine scenario where malicious validators attempt to create forks, this could cause honest validators to make decisions based on state that never achieves finality.

## Likelihood Explanation

**Likelihood: Medium-High**

This race condition occurs naturally during normal operation whenever:
- Consensus is actively pipelining multiple blocks (the common case for high throughput)
- A reconfiguration event occurs at epoch boundaries or governance proposals
- The timing window between pre-commit(N+2) and commit(N+1) is hit

No attacker action is required to trigger this—it's an inherent race in the pipelined architecture. However, exploitation requires:
1. Natural occurrence of the race (frequent in production)
2. A reconfiguration event during the race window (less frequent but regular)
3. Fork or rollback of pre-committed state (rare but possible in adversarial conditions)

## Recommendation

**Immediate Fix:**

Use the committed ledger info version instead of the pre-committed version when notifying event subscribers:

```rust
pub async fn handle_committed_transactions<
    M: MempoolNotificationSender,
    S: StorageServiceNotificationSender,
>(
    committed_transactions: CommittedTransactions,
    storage: Arc<dyn DbReader>,
    mempool_notification_handler: MempoolNotificationHandler<M>,
    event_subscription_service: Arc<Mutex<EventSubscriptionService>>,
    storage_service_notification_handler: StorageServiceNotificationHandler<S>,
) {
    // Fetch ONLY the latest synced ledger info (certified state)
    let latest_synced_ledger_info = match fetch_latest_synced_ledger_info(storage.clone()) {
        Ok(ledger_info) => ledger_info,
        Err(error) => {
            error!(LogSchema::new(LogEntry::SynchronizerNotification)
                .error(&error)
                .message("Failed to fetch latest synced ledger info!"));
            return;
        },
    };
    
    // Use the CERTIFIED version from the ledger info
    let latest_synced_version = latest_synced_ledger_info.ledger_info().version();

    // Handle the commit notification with certified version
    if let Err(error) = CommitNotification::handle_transaction_notification(
        committed_transactions.events,
        committed_transactions.transactions,
        latest_synced_version,  // Now guaranteed to be certified
        latest_synced_ledger_info,
        mempool_notification_handler,
        event_subscription_service,
        storage_service_notification_handler,
    )
    .await
    {
        error!(LogSchema::new(LogEntry::SynchronizerNotification)
            .error(&error)
            .message("Failed to handle a transaction commit notification!"));
    }
}
```

This ensures event subscribers only receive configuration from quorum-certified state, maintaining consensus safety.

## Proof of Concept

The vulnerability can be demonstrated through the following sequence:

```rust
// Reproduction steps (conceptual, requires consensus test harness):

// 1. Setup: Node with pipelined consensus enabled
// 2. Execute block N+1 → pre_commit_ledger(N+1) → state version = V(N+1)
// 3. Execute block N+2 → pre_commit_ledger(N+2) → state version = V(N+2)
// 4. Before commit_ledger(N+2), finalize block N+1:
//    commit_ledger(N+1, ledger_info_V(N+1)) → ledger info version = V(N+1)
// 5. Consensus sends notification for block N+1
// 6. State sync calls handle_committed_transactions:
//    - fetch_pre_committed_version() → V(N+2) ✓
//    - fetch_latest_synced_ledger_info() → V(N+1) ✓
//    - Mismatch detected!
// 7. If block N+1 contains NewEpochEvent:
//    - Event service reads config from V(N+2) (uncertified)
//    - Subscribers receive uncertified validator set/gas schedule
// 8. If consensus forks before V(N+2) is committed:
//    - Subscribers acted on invalid state
//    - Consensus safety violated
```

**Validation:**
- Add logging to `handle_committed_transactions` to capture version mismatch occurrences
- Monitor for cases where `latest_synced_version > latest_synced_ledger_info.version()`
- Verify reconfig subscribers receive `DbBackedOnChainConfig` with version > certified version

## Notes

This vulnerability is particularly concerning during epoch transitions when validator set changes occur. If validators receive an uncertified validator set and begin signing with it before the set is finalized, consensus safety could be compromised. The fix is straightforward and maintains the existing notification flow while ensuring only certified state is exposed to critical system components.

### Citations

**File:** state-sync/state-sync-driver/src/utils.rs (L336-353)
```rust
    let (latest_synced_version, latest_synced_ledger_info) =
        match fetch_pre_committed_version(storage.clone()) {
            Ok(latest_synced_version) => match fetch_latest_synced_ledger_info(storage.clone()) {
                Ok(latest_synced_ledger_info) => (latest_synced_version, latest_synced_ledger_info),
                Err(error) => {
                    error!(LogSchema::new(LogEntry::SynchronizerNotification)
                        .error(&error)
                        .message("Failed to fetch latest synced ledger info!"));
                    return;
                },
            },
            Err(error) => {
                error!(LogSchema::new(LogEntry::SynchronizerNotification)
                    .error(&error)
                    .message("Failed to fetch latest synced version!"));
                return;
            },
        };
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L44-76)
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
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["pre_commit_ledger"]);

            chunk
                .state_summary
                .latest()
                .global_state_summary
                .log_generation("db_save");

            self.pre_commit_validation(&chunk)?;
            let _new_root_hash =
                self.calculate_and_commit_ledger_and_state_kv(&chunk, self.skip_index_and_usage)?;

            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["save_transactions__others"]);

            self.state_store.buffered_state().lock().update(
                chunk.result_ledger_state_with_summary(),
                chunk.estimated_total_state_updates(),
                sync_commit || chunk.is_reconfig,
            )?;

            Ok(())
        })
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

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L75-112)
```rust
    pub async fn handle_transaction_notification<
        M: MempoolNotificationSender,
        S: StorageServiceNotificationSender,
    >(
        events: Vec<ContractEvent>,
        transactions: Vec<Transaction>,
        latest_synced_version: Version,
        latest_synced_ledger_info: LedgerInfoWithSignatures,
        mut mempool_notification_handler: MempoolNotificationHandler<M>,
        event_subscription_service: Arc<Mutex<EventSubscriptionService>>,
        mut storage_service_notification_handler: StorageServiceNotificationHandler<S>,
    ) -> Result<(), Error> {
        // Log the highest synced version and timestamp
        let blockchain_timestamp_usecs = latest_synced_ledger_info.ledger_info().timestamp_usecs();
        debug!(
            LogSchema::new(LogEntry::NotificationHandler).message(&format!(
                "Notifying the storage service, mempool and the event subscription service of version: {:?} and timestamp: {:?}.",
                latest_synced_version, blockchain_timestamp_usecs
            ))
        );

        // Notify the storage service of the committed transactions
        storage_service_notification_handler
            .notify_storage_service_of_committed_transactions(latest_synced_version)
            .await?;

        // Notify mempool of the committed transactions
        mempool_notification_handler
            .notify_mempool_of_committed_transactions(transactions, blockchain_timestamp_usecs)
            .await?;

        // Notify the event subscription service of the events
        event_subscription_service
            .lock()
            .notify_events(latest_synced_version, events)?;

        Ok(())
    }
```

**File:** state-sync/inter-component/event-notifications/src/lib.rs (L281-307)
```rust
    fn read_on_chain_configs(
        &self,
        version: Version,
    ) -> Result<OnChainConfigPayload<DbBackedOnChainConfig>, Error> {
        let db_state_view = &self
            .storage
            .read()
            .reader
            .state_view_at_version(Some(version))
            .map_err(|error| {
                Error::UnexpectedErrorEncountered(format!(
                    "Failed to create account state view {:?}",
                    error
                ))
            })?;
        let epoch = ConfigurationResource::fetch_config(&db_state_view)
            .ok_or_else(|| {
                Error::UnexpectedErrorEncountered("Configuration resource does not exist!".into())
            })?
            .epoch();

        // Return the new on-chain config payload (containing all found configs at this version).
        Ok(OnChainConfigPayload::new(
            epoch,
            DbBackedOnChainConfig::new(self.storage.read().reader.clone(), version),
        ))
    }
```

**File:** state-sync/inter-component/event-notifications/src/lib.rs (L310-326)
```rust
impl EventNotificationSender for EventSubscriptionService {
    fn notify_events(&mut self, version: Version, events: Vec<ContractEvent>) -> Result<(), Error> {
        if events.is_empty() {
            return Ok(()); // No events!
        }

        // Notify event subscribers and check if a reconfiguration event was processed
        let reconfig_event_processed = self.notify_event_subscribers(version, events)?;

        // If a reconfiguration event was found, also notify the reconfig subscribers
        // of the new configuration values.
        if reconfig_event_processed {
            self.notify_reconfiguration_subscribers(version)
        } else {
            Ok(())
        }
    }
```
