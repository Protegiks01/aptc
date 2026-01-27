# Audit Report

## Title
Silent State Storage Usage Calculation Bypass During KV Replay Restore

## Summary
The `save_transactions_impl()` function in `storage/aptosdb/src/backup/restore_utils.rs` contains a defensive check at line 269 that silently skips state storage usage calculation when prerequisite data is missing, rather than propagating an error. This results in incomplete usage tracking post-restore, breaking state consistency invariants.

## Finding Description

The vulnerability exists in the KV replay restore logic: [1](#0-0) 

The code checks if `state_store.get_usage(Some(first_version - 1)).is_ok()` before calculating state. When this check returns `false` (indicating missing usage data), the entire state calculation block is silently skipped without raising an error. The function continues execution and returns `Ok(())` at line 293, making the operation appear successful.

**State Storage Usage Criticality:**

State storage usage tracking is essential for the Aptos protocol: [2](#0-1) 

Storage usage data is used to calculate gas costs dynamically based on utilization and enforce storage limits. Without proper usage tracking, gas calculations become incorrect and storage limits cannot be enforced.

**How the Error Propagates:**

During KV replay restoration: [3](#0-2) 

The restore initializes state at line 568, then processes transactions in batches. If batch N fails to calculate state (due to the silent skip), batch N+1 will also fail when it checks for batch N's usage data, creating a cascading failure where **all subsequent batches skip state calculation**.

**The Core Issue:**

The `get_state_storage_usage` method has error handling that returns untracked usage when `skip_usage` is enabled: [4](#0-3) 

However, the restore code doesn't propagate this error—it just checks `.is_ok()` and skips calculation entirely if false.

## Impact Explanation

**Severity: Medium**

This qualifies as "State inconsistencies requiring intervention" per Aptos bug bounty criteria:

1. **Broken Invariant**: Violates the state consistency invariant that all committed versions must have associated usage data for gas calculation and storage limit enforcement

2. **Gas Calculation Errors**: Post-restore nodes will have incorrect or missing usage data, leading to wrong gas cost calculations for storage operations

3. **Storage Limit Bypass**: Without accurate usage tracking, storage limits cannot be properly enforced, potentially enabling storage bombing attacks

4. **Cascading Effect**: Once one batch skips state calculation, all subsequent batches in the restore will also skip, amplifying the inconsistency

5. **Silent Failure**: No error is raised, making the issue difficult to detect until gas calculation anomalies emerge

## Likelihood Explanation

**Likelihood: Medium-Low**

The vulnerability requires specific conditions to trigger:

1. **Requires Node Operator Access**: Exploitation requires ability to initiate database restore operations, which is limited to node operators/administrators

2. **Defensive Initialization**: The restore flow calls `force_state_version_for_kv_restore()` before processing batches, which would typically catch missing usage data: [5](#0-4) 

3. **Scenarios Where It Can Occur**:
   - Corrupted backup data provided to restore operation
   - Database corruption occurring during multi-batch restore
   - Race conditions in batch processing (though code appears sequential)
   - Manual database manipulation between batches

4. **Not Exploitable by Unprivileged Attackers**: Regular transaction senders or network peers cannot trigger this vulnerability

## Recommendation

**Fix: Propagate errors instead of silent skip**

Replace the conditional check with explicit error handling:

```rust
// Current problematic code at line 269
if kv_replay && first_version > 0 && state_store.get_usage(Some(first_version - 1)).is_ok() {
    // calculate state...
}

// Recommended fix
if kv_replay && first_version > 0 {
    // Explicitly require usage data - fail if missing
    let _previous_usage = state_store.get_usage(Some(first_version - 1))
        .map_err(|e| AptosDbError::Other(format!(
            "Missing usage data for version {} during KV replay: {}",
            first_version - 1, e
        )))?;
    
    let (ledger_state, _hot_state_updates) = state_store.calculate_state_and_put_updates(
        &StateUpdateRefs::index_write_sets(first_version, write_sets, write_sets.len(), vec![]),
        &mut ledger_db_batch.ledger_metadata_db_batches,
        state_kv_batches,
    )?;
    state_store.set_state_ignoring_summary(ledger_state);
}
```

This ensures that:
- Missing usage data causes the restore to fail explicitly with a clear error message
- The database is not left in an inconsistent state
- Node operators are immediately alerted to the problem

## Proof of Concept

Since this requires node operator access and database manipulation, a full PoC would involve:

1. Set up an AptosDB instance with valid data through version V
2. Initiate KV replay restore starting from version V+1
3. Between batch 1 and batch 2 completion, delete or corrupt usage data for intermediate versions
4. Observe that batch 2 silently skips state calculation without error
5. Verify post-restore that `get_usage()` returns errors or untracked usage for affected versions
6. Demonstrate that gas calculations for storage operations use incorrect values

**Verification steps** (conceptual Rust test):

```rust
#[test]
fn test_missing_usage_data_during_kv_replay() {
    // 1. Initialize DB with data through version 10000
    // 2. Start KV replay from version 10001
    // 3. Simulate missing usage data for version 10000
    // 4. Call save_transactions with kv_replay=true
    // 5. Assert that function returns Ok despite missing usage
    // 6. Verify that usage data was NOT stored for the batch
    // 7. Show cascading failure for subsequent batches
}
```

---

**Note:** While this is a legitimate bug that violates state consistency invariants, it does **not** meet the highest bar for "exploitable by unprivileged attacker" as it requires node operator access. This should be classified as a **Medium severity** defensive programming issue requiring code hardening rather than a Critical or High severity exploit.

### Citations

**File:** storage/aptosdb/src/backup/restore_utils.rs (L269-277)
```rust
    if kv_replay && first_version > 0 && state_store.get_usage(Some(first_version - 1)).is_ok() {
        let (ledger_state, _hot_state_updates) = state_store.calculate_state_and_put_updates(
            &StateUpdateRefs::index_write_sets(first_version, write_sets, write_sets.len(), vec![]),
            &mut ledger_db_batch.ledger_metadata_db_batches, // used for storing the storage usage
            state_kv_batches,
        )?;
        // n.b. ideally this is set after the batches are committed
        state_store.set_state_ignoring_summary(ledger_state);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/storage_gas.move (L1-50)
```text
/// Gas parameters for global storage.
///
/// # General overview sections
///
/// [Definitions](#definitions)
///
/// * [Utilization dimensions](#utilization-dimensions)
/// * [Utilization ratios](#utilization-ratios)
/// * [Gas curve lookup](#gas-curve-lookup)
/// * [Item-wise operations](#item-wise-operations)
/// * [Byte-wise operations](#byte-wise-operations)
///
/// [Function dependencies](#function-dependencies)
///
/// * [Initialization](#initialization)
/// * [Reconfiguration](#reconfiguration)
/// * [Setting configurations](#setting-configurations)
///
/// # Definitions
///
/// ## Utilization dimensions
///
/// Global storage gas fluctuates each epoch based on total utilization,
/// which is defined across two dimensions:
///
/// 1. The number of "items" in global storage.
/// 2. The number of bytes in global storage.
///
/// "Items" include:
///
/// 1. Resources having the `key` attribute, which have been moved into
///    global storage via a `move_to()` operation.
/// 2.  Table entries.
///
/// ## Utilization ratios
///
/// `initialize()` sets an arbitrary "target" utilization for both
/// item-wise and byte-wise storage, then each epoch, gas parameters are
/// reconfigured based on the "utilization ratio" for each of the two
/// utilization dimensions. The utilization ratio for a given dimension,
/// either item-wise or byte-wise, is taken as the quotient of actual
/// utilization and target utilization. For example, given a 500 GB
/// target and 250 GB actual utilization, the byte-wise utilization
/// ratio is 50%.
///
/// See `base_8192_exponential_curve()` for mathematical definitions.
///
/// ## Gas curve lookup
///
/// The utilization ratio in a given epoch is used as a lookup value in
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L554-637)
```rust
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

**File:** storage/aptosdb/src/state_store/mod.rs (L238-248)
```rust
    fn get_state_storage_usage(&self, version: Option<Version>) -> Result<StateStorageUsage> {
        version.map_or(Ok(StateStorageUsage::zero()), |version| {
            Ok(match self.ledger_db.metadata_db().get_usage(version) {
                Ok(data) => data,
                _ => {
                    ensure!(self.skip_usage, "VersionData at {version} is missing.");
                    StateStorageUsage::new_untracked()
                },
            })
        })
    }
```

**File:** storage/aptosdb/src/backup/restore_handler.rs (L101-103)
```rust
    pub fn force_state_version_for_kv_restore(&self, version: Option<Version>) -> Result<()> {
        self.state_store.init_state_ignoring_summary(version)
    }
```
