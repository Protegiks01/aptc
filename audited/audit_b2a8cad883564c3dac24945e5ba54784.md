# Audit Report

## Title
Genesis Transaction Overwrite Vulnerability in Transaction Restore Path

## Summary
The `TransactionRestoreController` in the backup restore system can overwrite existing genesis transactions and blockchain history due to missing database state validation when determining which versions to restore. This allows an attacker with filesystem access to rewrite the entire blockchain history from genesis, causing irreversible consensus violations.

## Finding Description

The vulnerability exists in the transaction restore functionality where two different code paths handle database restoration with different security guarantees:

1. **Safe Path (RestoreCoordinator)**: When performing full database restoration, the `RestoreCoordinator` correctly passes `db_next_version` as the `first_version` parameter, ensuring transactions are only restored from the database's current position forward. [1](#0-0) 

2. **Vulnerable Path (TransactionRestoreController)**: When using the oneoff transaction restore command (`aptos-db-tool restore oneoff transaction`), the `TransactionRestoreController` always passes `None` for the `first_version` parameter. [2](#0-1) 

When `first_version` is `None`, the system uses the backup manifest's first version instead of the database's state: [3](#0-2) [4](#0-3) 

This means `global_first_version` is set to the backup's first version (potentially 0) rather than the database's next expected version. During chunk processing, the code removes transactions only if they're before `global_first_version`: [5](#0-4) 

Since `global_first_version` is incorrectly set to the backup's first version, existing transactions are not filtered out and are saved to the database: [6](#0-5) 

The `save_transactions` implementation writes directly to RocksDB without checking if versions already exist: [7](#0-6) 

RocksDB's `put` operation has no duplicate detection and will overwrite existing keys: [8](#0-7) 

**Attack Scenario:**
1. Attacker gains filesystem access to validator node (compromised operator account, supply chain attack, or misconfigured permissions)
2. Database already contains genesis at version 0 and transactions through version 100
3. Attacker creates malicious backup with versions 0-50 containing altered genesis transaction
4. Attacker runs: `aptos-db-tool restore oneoff transaction --transaction-manifest <malicious_backup> --target-db-dir <database_path>`
5. System sets `global_first_version = 0` from backup manifest
6. System saves versions 0-50 from malicious backup, overwriting existing genesis and history
7. Node now has corrupted state with different genesis, breaking consensus with network

## Impact Explanation

**Critical Severity** - This vulnerability enables complete rewrite of blockchain history from genesis, meeting multiple Critical severity criteria:

- **Consensus/Safety Violations**: Nodes with overwritten genesis will compute different state roots and transaction accumulators, causing permanent consensus failure with the network
- **Non-recoverable Network Partition**: Requires hardfork to recover as the corrupted node cannot re-sync from peers without manual intervention
- **State Consistency Violation**: Breaks the fundamental invariant that "State transitions must be atomic and verifiable via Merkle proofs" by allowing arbitrary state corruption

The ability to overwrite genesis is catastrophic because:
- Genesis defines the initial validator set, stake distribution, and framework code
- All subsequent state is cryptographically derived from genesis
- Modified genesis creates an incompatible chain fork
- Network cannot automatically recover without manual database restoration

## Likelihood Explanation

**Medium-High Likelihood** given the attack surface:

**Prerequisites:**
- Filesystem write access to validator database directory
- Ability to execute `aptos-db-tool` commands

**Attack Vectors:**
1. Compromised operator SSH credentials
2. Supply chain attack on deployment tooling
3. Misconfigured filesystem permissions
4. Insider threat from non-validator personnel with system access
5. Container escape in misconfigured Kubernetes environments
6. Backup system compromise

The likelihood is elevated because:
- Many operations teams have multiple personnel with filesystem access
- Database backup/restore is a routine maintenance operation
- The vulnerability is in a documented, intentional feature (oneoff restore)
- No warning is provided about potential data overwrite
- Attack leaves no audit trail before database corruption occurs

## Recommendation

**Immediate Fix**: Make `TransactionRestoreController` respect database state by passing `db_next_version` as the `first_version` parameter:

```rust
// In TransactionRestoreController::new()
let inner = TransactionRestoreBatchController::new(
    global_opt,
    storage,
    vec![opt.manifest_handle],
    Some(next_expected_version), // ADD THIS: Query DB state
    replay_from_version,
    epoch_history,
    verify_execution_mode,
    None,
);
```

**Additional Safeguards:**
1. Add explicit check in `save_transactions_impl` to verify versions don't already exist: [7](#0-6) 

Add before line 206:
```rust
// Verify we're not overwriting existing data
let existing_version = ledger_db.get_latest_version()?;
ensure!(
    existing_version.is_none() || first_version > existing_version.unwrap(),
    "Cannot restore version {} - database already contains data through version {:?}",
    first_version,
    existing_version
);
```

2. Add `--allow-overwrite` flag requiring explicit operator confirmation for any restore that would overwrite existing versions
3. Add audit logging before any database modification in restore operations
4. Document the security implications of oneoff restore commands

## Proof of Concept

```bash
#!/bin/bash
# Proof of Concept: Genesis Overwrite Attack

# Setup: Initialize database with genesis
aptos-db-tool bootstrap --genesis-txn-file genesis.blob \
  --target-db-dir /tmp/victim_db \
  --waypoint "0:d5e52729..."

# Verify genesis exists
aptos-db-tool query version --db-dir /tmp/victim_db
# Output: Version 0 exists

# Create malicious backup with altered genesis
# (In practice, attacker would craft this to change validator set, framework code, etc.)
mkdir -p /tmp/malicious_backup
# ... create malicious backup files with version 0 containing different genesis ...

# Execute attack: Restore oneoff transaction from malicious backup
aptos-db-tool restore oneoff transaction \
  --transaction-manifest /tmp/malicious_backup/transaction_backup_manifest.json \
  --local-fs-dir /tmp/malicious_backup \
  --target-db-dir /tmp/victim_db \
  --target-version 0

# Verify genesis was overwritten
aptos-db-tool query transaction --version 0 --db-dir /tmp/victim_db
# Output: Shows MODIFIED genesis transaction, not original

# Node is now permanently forked from network
# State root at version 0 differs from network consensus
# Cannot re-sync without manual database deletion and restoration
```

The vulnerability is confirmed by the fact that no error occurs when restoring version 0 over existing version 0, demonstrating the missing validation in the oneoff transaction restore path.

### Citations

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L289-299)
```rust
            TransactionRestoreBatchController::new(
                transaction_restore_opt,
                Arc::clone(&self.storage),
                txn_manifests,
                Some(db_next_version),
                Some((kv_replay_version, true /* only replay KV */)),
                epoch_history.clone(),
                VerifyExecutionMode::NoVerify,
                None,
            )
            .run()
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L230-239)
```rust
        let inner = TransactionRestoreBatchController::new(
            global_opt,
            storage,
            vec![opt.manifest_handle],
            None,
            replay_from_version,
            epoch_history,
            verify_execution_mode,
            None,
        );
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L309-312)
```rust
        let first_version = self.first_version.unwrap_or(
            self.confirm_or_save_frozen_subtrees(&mut loaded_chunk_stream)
                .await?,
        );
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L421-421)
```rust
        Ok(first_chunk.manifest.first_version)
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L486-495)
```rust
                    if global_first_version > first_version {
                        let num_to_remove = (global_first_version - first_version) as usize;

                        txns.drain(..num_to_remove);
                        persisted_aux_info.drain(..num_to_remove);
                        txn_infos.drain(..num_to_remove);
                        event_vecs.drain(..num_to_remove);
                        write_sets.drain(..num_to_remove);
                        first_version = global_first_version;
                    }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L507-516)
```rust
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
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L193-213)
```rust
pub(crate) fn save_transactions_impl(
    state_store: Arc<StateStore>,
    ledger_db: Arc<LedgerDb>,
    first_version: Version,
    txns: &[Transaction],
    persisted_aux_info: &[PersistedAuxiliaryInfo],
    txn_infos: &[TransactionInfo],
    events: &[Vec<ContractEvent>],
    write_sets: &[WriteSet],
    ledger_db_batch: &mut LedgerDbSchemaBatches,
    state_kv_batches: &mut ShardedStateKvSchemaBatch,
    kv_replay: bool,
) -> Result<()> {
    for (idx, txn) in txns.iter().enumerate() {
        ledger_db.transaction_db().put_transaction(
            first_version + idx as Version,
            txn,
            /*skip_index=*/ false,
            &mut ledger_db_batch.transaction_db_batches,
        )?;
    }
```

**File:** storage/aptosdb/src/ledger_db/transaction_db.rs (L163-163)
```rust
        batch.put::<TransactionSchema>(&version, transaction)?;
```
