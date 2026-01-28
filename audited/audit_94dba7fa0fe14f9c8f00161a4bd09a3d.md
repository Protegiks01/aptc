# Audit Report

## Title
Race Condition in Reconfiguration Notification Processing Causes Validators to Use Wrong On-Chain Configs for Epochs

## Summary
A race condition exists where state sync fetches the latest pre-committed storage version instead of the version corresponding to reconfiguration events being processed. This allows validators to receive on-chain configuration data from an incorrect epoch, potentially causing consensus safety violations.

## Finding Description

The vulnerability stems from a critical design flaw in the notification flow between consensus and state sync:

**Missing Version Information in Notifications:**

The `ConsensusCommitNotification` struct contains only transactions and subscribable events, with no version field. [1](#0-0) 

**Independent Version Query by State Sync:**

When processing commit notifications, state sync independently queries storage for the latest pre-committed version: [2](#0-1) [3](#0-2) 

**Pre-Committed Version Returns Latest State Store Version:**

The `fetch_pre_committed_version()` function returns the current version from the state store: [4](#0-3) 

**Wrong Version Used for Config Reads:**

When a reconfiguration event is detected, this version is used to read on-chain configs: [5](#0-4) [6](#0-5) 

The `read_on_chain_configs` function reads `ConfigurationResource` at the specified version to extract the epoch and configs: [7](#0-6) 

**Race Condition Mechanism:**

The pipeline architecture allows this race:

Block B2's `pre_commit_fut` only waits for Block B1's `pre_commit_fut`, NOT for B1's `notify_state_sync_fut`: [8](#0-7) 

This means Block B2 can pre-commit (updating the state store to version 105) while Block B1's notification (for version 100) is still queued or being processed. When state sync processes B1's notification, it fetches version 105 and reads epoch 3 configs instead of epoch 2 configs.

**Execution Flow:**

1. Block B1 (version 100) with reconfiguration event R1 (epoch 2) pre-commits and commits
2. B1's `notify_state_sync` sends notification N1 asynchronously
3. Block B2 (version 105) with reconfiguration event R2 (epoch 3) pre-commits, updating state store version to 105
4. State sync processes N1:
   - Fetches pre-committed version → gets 105
   - Detects R1 (epoch 2 event)
   - Reads `ConfigurationResource` at version 105 → gets epoch 3
   - Reads `ValidatorSet` at version 105 → gets epoch 3 validator set
   - Sends epoch 3 configs to validators when they should receive epoch 2 configs

This violates the invariant that reconfiguration notifications must contain configs from the version where the reconfiguration event occurred.

## Impact Explanation

**Critical Severity** - This constitutes a consensus safety violation per Aptos bug bounty criteria:

1. **Validator Set Mismatch**: Validators receive the wrong validator set for an epoch, breaking quorum formation requirements
2. **Epoch Confusion**: Validators may skip epochs entirely (e.g., jumping from epoch 2 to epoch 3)
3. **Block Signature Verification Failures**: Blocks signed with epoch 2 validator set would fail verification by validators using epoch 3 validator set
4. **Consensus Liveness Loss**: Validators operating with mismatched epoch configurations cannot reach consensus on blocks
5. **Potential Chain Split**: Different validators processing notifications at different timing could end up on different epoch states

The vulnerability affects all validators network-wide and requires no attacker action - it can occur naturally during rapid epoch transitions or back-to-back governance proposals.

## Likelihood Explanation

**Medium to High Likelihood:**

1. **No Synchronization**: The pipeline architecture explicitly allows B2's pre-commit to proceed while B1's notification is in flight, with no synchronization mechanism
2. **Natural Trigger**: Rapid epoch changes from governance proposals or validator set updates can trigger this without malicious intent
3. **Async Channel Buffering**: Notifications are sent via unbounded async channels, creating a timing window where commits can outpace notification processing
4. **Production Scenarios**: High-load periods or state sync processing delays widen the race window

The timing window is small but non-zero, and the consequences are severe.

## Recommendation

Include the committed version in `ConsensusCommitNotification`:

```rust
pub struct ConsensusCommitNotification {
    transactions: Vec<Transaction>,
    subscribable_events: Vec<ContractEvent>,
    committed_version: Version,  // Add this field
    callback: oneshot::Sender<ConsensusNotificationResponse>,
}
```

Modify `notify_state_sync` in the pipeline to pass the committed version:

```rust
let committed_version = compute_result.last_version_or_0();
state_sync_notifier.notify_new_commit(txns, subscribable_events, committed_version)
```

Update `handle_committed_transactions` to use the provided version instead of querying storage:

```rust
pub async fn handle_committed_transactions(
    committed_transactions: CommittedTransactions,
    committed_version: Version,  // Use this instead of fetching from storage
    // ... rest of parameters
) {
    // Remove fetch_pre_committed_version call
    // Use committed_version directly
    CommitNotification::handle_transaction_notification(
        committed_transactions.events,
        committed_transactions.transactions,
        committed_version,  // Use the version from notification
        // ...
    )
}
```

## Proof of Concept

The race condition can be reproduced by:

1. Creating two consecutive blocks with reconfiguration events in rapid succession
2. Observing that state sync processes the first block's notification after the second block has pre-committed
3. Verifying that the on-chain configs sent to subscribers are from the second block's version, not the first

This requires timing-sensitive test infrastructure that can delay notification processing while allowing the next block to pre-commit, demonstrating the absence of proper synchronization between the notification path and the pre-commit path.

**Notes**

The vulnerability exists because the consensus pipeline's parallelism optimization (allowing subsequent blocks to pre-commit while previous blocks' notifications are in flight) was not coordinated with state sync's assumption that it can query the "latest" version when processing notifications. This architectural mismatch creates a critical race window during epoch transitions.

### Citations

**File:** state-sync/inter-component/consensus-notifications/src/lib.rs (L294-298)
```rust
pub struct ConsensusCommitNotification {
    transactions: Vec<Transaction>,
    subscribable_events: Vec<ContractEvent>,
    callback: oneshot::Sender<ConsensusNotificationResponse>,
}
```

**File:** state-sync/state-sync-driver/src/utils.rs (L336-337)
```rust
    let (latest_synced_version, latest_synced_ledger_info) =
        match fetch_pre_committed_version(storage.clone()) {
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L107-109)
```rust
        event_subscription_service
            .lock()
            .notify_events(latest_synced_version, events)?;
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L137-141)
```rust
    fn get_pre_committed_version(&self) -> Result<Option<Version>> {
        gauged_api("get_pre_committed_version", || {
            Ok(self.state_store.current_state_locked().version())
        })
    }
```

**File:** state-sync/inter-component/event-notifications/src/lib.rs (L264-269)
```rust
    fn notify_reconfiguration_subscribers(&mut self, version: Version) -> Result<(), Error> {
        if self.reconfig_subscriptions.is_empty() {
            return Ok(()); // No reconfiguration subscribers!
        }

        let new_configs = self.read_on_chain_configs(version)?;
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

**File:** state-sync/inter-component/event-notifications/src/lib.rs (L311-322)
```rust
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
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L535-544)
```rust
        let pre_commit_fut = spawn_shared_fut(
            Self::pre_commit(
                ledger_update_fut.clone(),
                parent.pre_commit_fut.clone(),
                order_proof_fut.clone(),
                commit_proof_fut.clone(),
                self.executor.clone(),
                block.clone(),
                self.pre_commit_status(),
            ),
```
