# Audit Report

## Title
Missing Timestamp Monotonicity Validation in sync_to_target() Enables Time-Traveling State Sync Attacks

## Summary
The `sync_to_target()` function in `ExecutionProxy` validates only epoch and round progression but fails to verify that the target's timestamp is monotonically increasing. This breaks the blockchain's fundamental timestamp monotonicity invariant and could enable time-traveling attacks where a node syncs to a valid chain state with a backwards-moving timestamp.

## Finding Description

The `ExecutionProxy::sync_to_target()` function is responsible for synchronizing a node's state to a target `LedgerInfoWithSignatures` provided during fast-forward sync operations. The function performs validation to ensure the target represents forward progress, but critically omits timestamp validation. [1](#0-0) 

The `LogicalTime` structure used for validation contains only epoch and round, excluding timestamp entirely. [2](#0-1) 

At line 188, the code checks `*latest_logical_time >= target_logical_time`, but this comparison is based solely on (epoch, round) tuple via the derived `PartialOrd` implementation. The timestamp from the target is extracted at line 200 but is only used to notify the payload manager—no validation occurs.

The misleading comment at line 187 states "committed beyond the target block **timestamp**" but the actual check ignores timestamp completely. This creates a dangerous mismatch between documented intent and actual behavior.

In contrast, during normal consensus operation, timestamp monotonicity IS enforced: [3](#0-2) 

The `VoteData::verify()` function ensures `parent.timestamp_usecs() <= proposed.timestamp_usecs()` at line 69, but this validation is bypassed during state sync.

The on-chain timestamp module enforces monotonicity during block execution: [4](#0-3) 

However, if a node syncs to a state with backwards timestamp via `sync_to_target()`, the on-chain time resource would reflect this backwards value, violating the invariant that blockchain time strictly increases.

**Attack Scenario:**

1. Node N has committed state at (epoch=1, round=100, version=1000, timestamp=5000000 μs)
2. Attacker provides a sync target with valid signatures at (epoch=1, round=150, version=1500, timestamp=4000000 μs)
3. The validation at line 188 passes: `LogicalTime(1, 100) >= LogicalTime(1, 150)` is FALSE, so sync proceeds
4. No timestamp check occurs—the backwards timestamp is accepted
5. Node syncs to state with timestamp=4000000, moving backwards by 1 second

## Impact Explanation

This vulnerability constitutes a **High Severity** protocol violation for several reasons:

**Invariant Violation:** Breaks the fundamental blockchain property that timestamps must be monotonically increasing, which is documented as a consensus guarantee.

**Smart Contract Impact:** Time-dependent Move contracts relying on `timestamp::now_seconds()` or `timestamp::now_microseconds()` would observe time moving backwards, potentially causing:
- Transaction expiration validation failures
- Time-locked operations to execute prematurely  
- Auction/voting deadlines to be violated
- Staking reward calculations based on time periods to become incorrect

**Consensus Disruption:** After syncing to backwards timestamp, when the node attempts to produce or vote on new blocks with current timestamps, this could cause state divergence or validation failures.

While the attack requires obtaining a valid `LedgerInfoWithSignatures` with 2f+1 validator signatures and backwards timestamp (which typically requires Byzantine behavior or clock synchronization failures), the missing validation represents a clear protocol violation that should be defended against.

## Likelihood Explanation

**Moderate-to-Low likelihood** in well-functioning networks, but **possible** in adversarial scenarios:

**Requires:** A valid `LedgerInfoWithSignatures` with backwards timestamp, which could occur through:
1. Network partition with clock skew affecting >2/3 of validators
2. Systematic clock failure on majority of validator nodes
3. Fork scenario with competing chains having different timestamps
4. Compromised validators (>1/3) deliberately creating backwards-timestamp blocks

While normal operations with <1/3 Byzantine validators and proper clock synchronization should prevent this, the code should defend against edge cases and clock synchronization failures that could affect validator subsets.

## Recommendation

Add timestamp monotonicity validation to `sync_to_target()`:

```rust
async fn sync_to_target(&self, target: LedgerInfoWithSignatures) -> Result<(), StateSyncError> {
    let mut latest_logical_time = self.write_mutex.lock().await;
    let target_logical_time =
        LogicalTime::new(target.ledger_info().epoch(), target.ledger_info().round());
    
    self.executor.finish();
    
    // Check logical time (epoch, round)
    if *latest_logical_time >= target_logical_time {
        warn!(
            "State sync target {:?} is lower than already committed logical time {:?}",
            target_logical_time, *latest_logical_time
        );
        return Ok(());
    }
    
    // NEW: Validate timestamp monotonicity
    let current_timestamp = self.executor
        .get_latest_ledger_info()
        .map(|li| li.ledger_info().timestamp_usecs())
        .unwrap_or(0);
    let target_timestamp = target.ledger_info().timestamp_usecs();
    
    if target_timestamp < current_timestamp {
        return Err(StateSyncError::from(anyhow::anyhow!(
            "Sync target timestamp {} is less than current timestamp {}",
            target_timestamp,
            current_timestamp
        )));
    }
    
    // ... rest of function
}
```

Additionally, update `LogicalTime` to include timestamp for comprehensive ordering:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LogicalTime {
    epoch: u64,
    round: Round,
    timestamp_usecs: u64,
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_sync_to_target_rejects_backwards_timestamp() {
    use aptos_types::{
        block_info::BlockInfo,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
        aggregate_signature::AggregateSignature,
    };
    
    // Setup: Node at timestamp T1
    let current_ledger_info = LedgerInfo::new(
        BlockInfo::new(
            1,  // epoch
            100,  // round
            HashValue::random(),
            HashValue::random(),
            1000,  // version
            5_000_000,  // timestamp_usecs = 5 seconds
            None,
        ),
        HashValue::zero(),
    );
    
    // Attack: Target with higher round but LOWER timestamp
    let target_ledger_info = LedgerInfo::new(
        BlockInfo::new(
            1,  // same epoch
            150,  // higher round
            HashValue::random(),
            HashValue::random(),
            1500,  // higher version
            4_000_000,  // BACKWARDS timestamp = 4 seconds
            None,
        ),
        HashValue::zero(),
    );
    
    let target = LedgerInfoWithSignatures::new(
        target_ledger_info,
        AggregateSignature::empty(),
    );
    
    // Current implementation would ACCEPT this (BUG)
    // Fixed implementation should REJECT this
    let result = execution_proxy.sync_to_target(target).await;
    
    // Should fail with timestamp validation error
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("timestamp"));
}
```

## Notes

The vulnerability is confirmed by examining multiple code paths:

- Storage layer validation [5](#0-4)  checks version, root hash, and epoch continuity but NOT timestamp monotonicity

- State sync driver validation [6](#0-5)  only validates version numbers, not timestamps

The missing validation represents a defense-in-depth failure where multiple layers fail to enforce a critical blockchain invariant.

### Citations

**File:** consensus/src/state_computer.rs (L27-31)
```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
struct LogicalTime {
    epoch: u64,
    round: Round,
}
```

**File:** consensus/src/state_computer.rs (L177-194)
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
```

**File:** consensus/consensus-types/src/vote_data.rs (L59-80)
```rust
    pub fn verify(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.parent.epoch() == self.proposed.epoch(),
            "Parent and proposed epochs do not match",
        );
        anyhow::ensure!(
            self.parent.round() < self.proposed.round(),
            "Proposed round is less than parent round",
        );
        anyhow::ensure!(
            self.parent.timestamp_usecs() <= self.proposed.timestamp_usecs(),
            "Proposed happened before parent",
        );
        anyhow::ensure!(
            // if decoupled execution is turned on, the versions are dummy values (0),
            // but the genesis block per epoch uses the ground truth version number,
            // so we bypass the version check here.
            self.proposed.version() == 0 || self.parent.version() <= self.proposed.version(),
            "Proposed version is less than parent version",
        );
        Ok(())
    }
```

**File:** aptos-move/framework/aptos-framework/sources/timestamp.move (L32-50)
```text
    public fun update_global_time(
        account: &signer,
        proposer: address,
        timestamp: u64
    ) acquires CurrentTimeMicroseconds {
        // Can only be invoked by AptosVM signer.
        system_addresses::assert_vm(account);

        let global_timer = borrow_global_mut<CurrentTimeMicroseconds>(@aptos_framework);
        let now = global_timer.microseconds;
        if (proposer == @vm_reserved) {
            // NIL block with null address as proposer. Timestamp must be equal.
            assert!(now == timestamp, error::invalid_argument(EINVALID_TIMESTAMP));
        } else {
            // Normal block. Time must advance
            assert!(now < timestamp, error::invalid_argument(EINVALID_TIMESTAMP));
            global_timer.microseconds = timestamp;
        };
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L540-601)
```rust
    fn check_and_put_ledger_info(
        &self,
        version: Version,
        ledger_info_with_sig: &LedgerInfoWithSignatures,
        ledger_batch: &mut SchemaBatch,
    ) -> Result<(), AptosDbError> {
        let ledger_info = ledger_info_with_sig.ledger_info();

        // Verify the version.
        ensure!(
            ledger_info.version() == version,
            "Version in LedgerInfo doesn't match last version. {:?} vs {:?}",
            ledger_info.version(),
            version,
        );

        // Verify the root hash.
        let db_root_hash = self
            .ledger_db
            .transaction_accumulator_db()
            .get_root_hash(version)?;
        let li_root_hash = ledger_info_with_sig
            .ledger_info()
            .transaction_accumulator_hash();
        ensure!(
            db_root_hash == li_root_hash,
            "Root hash pre-committed doesn't match LedgerInfo. pre-commited: {:?} vs in LedgerInfo: {:?}",
            db_root_hash,
            li_root_hash,
        );

        // Verify epoch continuity.
        let current_epoch = self
            .ledger_db
            .metadata_db()
            .get_latest_ledger_info_option()
            .map_or(0, |li| li.ledger_info().next_block_epoch());
        ensure!(
            ledger_info_with_sig.ledger_info().epoch() == current_epoch,
            "Gap in epoch history. Trying to put in LedgerInfo in epoch: {}, current epoch: {}",
            ledger_info_with_sig.ledger_info().epoch(),
            current_epoch,
        );

        // Ensure that state tree at the end of the epoch is persisted.
        if ledger_info_with_sig.ledger_info().ends_epoch() {
            let state_snapshot = self.state_store.get_state_snapshot_before(version + 1)?;
            ensure!(
                state_snapshot.is_some() && state_snapshot.as_ref().unwrap().0 == version,
                "State checkpoint not persisted at the end of the epoch, version {}, next_epoch {}, snapshot in db: {:?}",
                version,
                ledger_info_with_sig.ledger_info().next_block_epoch(),
                state_snapshot,
            );
        }

        // Put write to batch.
        self.ledger_db
            .metadata_db()
            .put_ledger_info(ledger_info_with_sig, ledger_batch)?;
        Ok(())
    }
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L262-318)
```rust
    pub async fn initialize_sync_target_request(
        &mut self,
        sync_target_notification: ConsensusSyncTargetNotification,
        latest_pre_committed_version: Version,
        latest_synced_ledger_info: LedgerInfoWithSignatures,
    ) -> Result<(), Error> {
        // Get the target sync version and latest committed version
        let sync_target_version = sync_target_notification
            .get_target()
            .ledger_info()
            .version();
        let latest_committed_version = latest_synced_ledger_info.ledger_info().version();

        // If the target version is old, return an error to consensus (something is wrong!)
        if sync_target_version < latest_committed_version
            || sync_target_version < latest_pre_committed_version
        {
            let error = Err(Error::OldSyncRequest(
                sync_target_version,
                latest_pre_committed_version,
                latest_committed_version,
            ));
            self.respond_to_sync_target_notification(sync_target_notification, error.clone())?;
            return error;
        }

        // If the committed version is at the target, return successfully
        if sync_target_version == latest_committed_version {
            info!(
                LogSchema::new(LogEntry::NotificationHandler).message(&format!(
                    "We're already at the requested sync target version: {} \
                (pre-committed version: {}, committed version: {})!",
                    sync_target_version, latest_pre_committed_version, latest_committed_version
                ))
            );
            let result = Ok(());
            self.respond_to_sync_target_notification(sync_target_notification, result.clone())?;
            return result;
        }

        // If the pre-committed version is already at the target, something has else gone wrong
        if sync_target_version == latest_pre_committed_version {
            let error = Err(Error::InvalidSyncRequest(
                sync_target_version,
                latest_pre_committed_version,
            ));
            self.respond_to_sync_target_notification(sync_target_notification, error.clone())?;
            return error;
        }

        // Save the request so we can notify consensus once we've hit the target
        let consensus_sync_request =
            ConsensusSyncRequest::new_with_target(sync_target_notification);
        self.consensus_sync_request = Arc::new(Mutex::new(Some(consensus_sync_request)));

        Ok(())
    }
```
