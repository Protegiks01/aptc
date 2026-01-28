# Audit Report

## Title
Critical Version Mismatch in KV-Only Transaction Replay Causes Data Corruption and State Inconsistency

## Summary
The `save_before_replay_version()` function correctly partitions transactions into save-only and replay sets based on `first_to_replay = max(replay_from_version, next_expected_version)`, but the `replay_kv()` function incorrectly uses the raw CLI argument `replay_from_version` as the starting version for replay. When `replay_from_version < next_expected_version`, transactions from the replay stream are saved at incorrect version numbers, overwriting previously saved transactions and causing permanent data corruption and state inconsistency.

## Finding Description

The vulnerability exists in the interaction between two functions in the transaction restore process:

The `save_before_replay_version()` function correctly calculates `first_to_replay` as the maximum of the CLI-provided `replay_from_version` and the database's `next_expected_version`. [1](#0-0)  This ensures transactions already in the database are not replayed. Transactions with versions less than `first_to_replay` are saved without KV state updates [2](#0-1) , while transactions at or above `first_to_replay` are returned in a stream for replay.

However, when `replay_kv()` processes the transaction stream, it uses the original CLI argument. [3](#0-2)  The `base_version` is set to `first_version` (from `replay_from_version`), not to `first_to_replay`. When transactions are saved, they use this incorrect base version. [4](#0-3) 

The actual database writes use `first_version + idx` as the version key. [5](#0-4) 

**Attack Scenario:**

1. A node has transactions 0-119 in its database (`next_expected_version = 120`)
2. Operator runs restore with `--replay-transactions-from-version=100 --kv-only-replay=true`
3. Backup contains transactions 100-199

**What happens:**
- `first_to_replay = max(100, 120) = 120`
- `save_before_replay_version()` saves transactions 100-119 (without KV)
- Stream contains transactions 120-199 (80 transactions)
- `replay_kv()` sets `base_version = 100` (not 120!)
- Transactions from stream (originally 120-199) are saved as versions 100-179
- **Result:** Transactions 100-119 are OVERWRITTEN with wrong data (transactions that should be at 120-139), and transactions 180-199 are MISSING

This violates the **Deterministic Execution** and **State Consistency** invariants, as different nodes would produce different state roots for the same block sequence.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty program:

1. **State Corruption**: Transaction data is permanently corrupted in the database, with transactions stored at incorrect versions and some transactions missing entirely.

2. **Consensus/Safety Violations**: Nodes that undergo restore with this bug would have different transaction data than other nodes at the same version numbers, causing state root mismatches. When such a node attempts to participate in consensus, it will compute incorrect state roots and fail validation checks.

3. **Non-recoverable**: Once the corruption occurs, it requires manual intervention to recover, as the database contains fundamentally incorrect data. The affected node must wipe its database and perform a correct restore.

4. **State Inconsistency**: The blockchain state would be calculated from incorrect transactions, leading to wrong account balances and incorrect smart contract states.

While this affects restore operations rather than runtime consensus, a validator node that undergoes this corrupted restore would be unable to participate in consensus due to state root mismatches, effectively removing it from the validator set until manually corrected.

## Likelihood Explanation

**Likelihood: MEDIUM**

This vulnerability triggers under specific operational scenarios:

1. **Restore Operations**: Node operators perform database restores during node failures, data corruption recovery, or setting up new nodes.

2. **Trigger Conditions**: The bug activates when an operator specifies `--replay-transactions-from-version` less than the current database version. This can occur during:
   - Interrupted restore operations being retried
   - Following outdated documentation or reusing old commands
   - Mismatched state snapshot and transaction backup versions

3. **Silent Failure**: The corruption is not immediately detected as no error is thrown during the restore process. The node appears to function normally until consensus checks fail.

4. **Operational Error**: While not the typical restore flow, the scenario is plausible when operators are recovering from partial failures or have mismatched backup components.

## Recommendation

The fix is to pass the correct starting version to `replay_kv()`. The function should use the actual first version from the transaction stream, not the CLI argument.

**Option 1**: Modify `replay_kv()` to accept `first_to_replay` as a parameter:
- Pass `first_to_replay` calculated in `save_before_replay_version()` to `replay_kv()`
- Initialize `base_version = first_to_replay` instead of `first_version`

**Option 2**: Determine the starting version from the transaction stream context:
- Track the actual first version of transactions in the stream
- Use that version to initialize `base_version`

The core issue is the disconnect between what `save_before_replay_version()` returns (transactions >= `first_to_replay`) and what `replay_kv()` assumes (transactions >= `first_version`).

## Proof of Concept

The vulnerability can be demonstrated through the following scenario:

1. Create a test database with transactions 0-119
2. Run restore with `--replay-transactions-from-version=100 --kv-only-replay=true` 
3. Provide a backup containing transactions 100-199
4. Observe that:
   - `save_before_replay_version()` correctly saves transactions 100-119
   - The stream contains transactions 120-199
   - `replay_kv()` saves the first transaction from the stream (120) at version 100
   - This overwrites the previously saved transaction 100
5. Verify database corruption by checking transaction versions 100-119 contain wrong data

The code paths confirmed in the analysis clearly show the version mismatch logic error that leads to data corruption.

## Notes

This is a logic vulnerability in the backup/restore system that causes data corruption when specific CLI arguments are used. While it requires operator action to trigger, the impact on affected nodes is severe as they will have corrupted databases requiring manual intervention to fix. The vulnerability is particularly concerning because it fails silently and may not be detected until consensus failures occur.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L453-457)
```rust
        let first_to_replay = max(
            self.replay_from_version
                .map_or(Version::MAX, |(version, _)| version),
            next_expected_version,
        );
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L498-527)
```rust
                    if first_version < first_to_replay {
                        let num_to_save =
                            (min(first_to_replay, last_version + 1) - first_version) as usize;
                        let txns_to_save: Vec<_> = txns.drain(..num_to_save).collect();
                        let persisted_aux_info_to_save: Vec<_> =
                            persisted_aux_info.drain(..num_to_save).collect();
                        let txn_infos_to_save: Vec<_> = txn_infos.drain(..num_to_save).collect();
                        let event_vecs_to_save: Vec<_> = event_vecs.drain(..num_to_save).collect();
                        let write_sets_to_save = write_sets.drain(..num_to_save).collect();
                        tokio::task::spawn_blocking(move || {
                            restore_handler.save_transactions(
                                first_version,
                                &txns_to_save,
                                &persisted_aux_info_to_save,
                                &txn_infos_to_save,
                                &event_vecs_to_save,
                                write_sets_to_save,
                            )
                        })
                        .await??;
                        let last_saved = first_version + num_to_save as u64 - 1;
                        TRANSACTION_SAVE_VERSION.set(last_saved as i64);
                        info!(
                            version = last_saved,
                            accumulative_tps = ((last_saved - global_first_version + 1) as f64
                                / start.elapsed().as_secs_f64())
                                as u64,
                            "Transactions saved."
                        );
                    }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L567-570)
```rust
        let (first_version, _) = self.replay_from_version.unwrap();
        restore_handler.force_state_version_for_kv_restore(first_version.checked_sub(1))?;

        let mut base_version = first_version;
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L587-594)
```rust
                base_version += offset;
                offset = txns.len() as u64;
                async move {
                    let _timer = OTHER_TIMERS_SECONDS.timer_with(&["replay_txn_chunk_kv_only"]);
                    tokio::task::spawn_blocking(move || {
                        // we directly save transaction and kvs to DB without involving chunk executor
                        handler.save_transactions_and_replay_kv(
                            base_version,
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L206-228)
```rust
    for (idx, txn) in txns.iter().enumerate() {
        ledger_db.transaction_db().put_transaction(
            first_version + idx as Version,
            txn,
            /*skip_index=*/ false,
            &mut ledger_db_batch.transaction_db_batches,
        )?;
    }

    for (idx, aux_info) in persisted_aux_info.iter().enumerate() {
        PersistedAuxiliaryInfoDb::put_persisted_auxiliary_info(
            first_version + idx as Version,
            aux_info,
            &mut ledger_db_batch.persisted_auxiliary_info_db_batches,
        )?;
    }

    for (idx, txn_info) in txn_infos.iter().enumerate() {
        TransactionInfoDb::put_transaction_info(
            first_version + idx as Version,
            txn_info,
            &mut ledger_db_batch.transaction_info_db_batches,
        )?;
```
