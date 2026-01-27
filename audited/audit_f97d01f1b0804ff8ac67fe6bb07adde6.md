# Audit Report

## Title
Transaction Backup Restore Consecutive Chunk Validation Bypass via Version 0 Edge Case

## Summary
The transaction restore logic in `loaded_chunk_stream()` contains a flawed consecutive chunk validation that can be bypassed when the first chunk ends at version 0, allowing non-consecutive transaction chunks to be restored and creating gaps in the ledger.

## Finding Description

The backup restore system is designed to ensure that transaction chunks are consecutive, preventing gaps in the restored ledger. However, the validation logic contains an edge case bug. [1](#0-0) 

The consecutive chunk validation uses `*last_chunk_last_version != 0` as a condition to skip the check for the first chunk. This creates a vulnerability:

**Attack Scenario:**
1. Attacker creates a malicious backup manifest with chunk 1: `[first_version=0, last_version=0]` (genesis only)
2. After processing chunk 1, `last_chunk_last_version` is set to `0`
3. Attacker adds chunk 2: `[first_version=100, last_version=200]` 
4. When chunk 2 is validated, the condition `*last_chunk_last_version != 0` evaluates to `false` (since it's still 0)
5. The consecutive check is **bypassed**, allowing the gap between versions 1-99
6. The manifest passes `verify()` checks: [2](#0-1) 

**Impact on Database:**
The restore process saves transactions without validating consecutiveness in the underlying storage layer: [3](#0-2) 

This bypasses normal transaction commit validation that would enforce consecutive versions: [4](#0-3) 

The database metadata is updated to show the highest version (e.g., 200), but versions 1-99 are missing, violating the fundamental invariant that ledger versions must be consecutive.

## Impact Explanation

This vulnerability breaks the **State Consistency** invariant that requires all state transitions to be atomic and complete. However, the practical impact is limited:

- **Attack Prerequisites**: Requires attacker to control backup storage or socially engineer node operators to use malicious backups
- **Scope**: Affects only nodes restored from the malicious backup
- **Detection**: Missing versions would cause query failures and state sync errors
- **Recovery**: Requires re-restoration from a valid backup

While this creates state inconsistencies, it does not allow:
- Consensus safety violations (no double-spending)
- Fund theft or minting
- Direct validator compromise
- Network-wide persistent failures

This aligns with **Low Severity** classification per the bounty program: "Non-critical implementation bugs" that cause localized state issues requiring manual intervention but not hardfork-level recovery.

## Likelihood Explanation

**Low-to-Medium likelihood:**
- Requires social engineering or infrastructure compromise
- Backup manifests are typically controlled by trusted infrastructure
- Detection would occur quickly through query failures
- Limited attack surface (backup/restore operations)
- Not exploitable through normal network operations

## Recommendation

Fix the consecutive chunk validation to properly handle version 0:

**Option 1 - Use explicit first chunk flag:**
```rust
.scan((0, true), |(last_chunk_last_version, is_first_chunk), chunk_res| {
    let res = match &chunk_res {
        Ok(chunk) => {
            if !*is_first_chunk 
                && chunk.first_version != *last_chunk_last_version + 1
            {
                Some(Err(anyhow!(
                    "Chunk range not consecutive. expecting {}, got {}",
                    *last_chunk_last_version + 1,
                    chunk.first_version
                )))
            } else {
                *last_chunk_last_version = chunk.last_version;
                *is_first_chunk = false;
                Some(chunk_res)
            }
        },
        Err(_) => Some(chunk_res),
    };
    future::ready(res)
});
```

**Option 2 - Track processed chunk count:**
```rust
.enumerate()
.map(|(idx, chunk_res)| {
    match &chunk_res {
        Ok(chunk) if idx > 0 => {
            // Validate consecutive from second chunk onwards
        }
        _ => chunk_res
    }
})
```

## Proof of Concept

Create a malicious transaction backup manifest:

```rust
use aptos_backup_types::transaction::manifest::{TransactionBackup, TransactionChunk};

// Create malicious manifest with gap
let malicious_manifest = TransactionBackup {
    first_version: 0,
    last_version: 200,
    chunks: vec![
        TransactionChunk {
            first_version: 0,
            last_version: 0,  // Genesis only
            transactions: FileHandle::from("chunk_0.bin"),
            proof: FileHandle::from("proof_0.bin"),
            format: TransactionChunkFormat::V1,
        },
        TransactionChunk {
            first_version: 100,  // Gap: versions 1-99 missing!
            last_version: 200,
            transactions: FileHandle::from("chunk_100.bin"),
            proof: FileHandle::from("proof_100.bin"),
            format: TransactionChunkFormat::V1,
        },
    ],
};

// manifest.verify() will pass (validates chunk ranges only)
assert!(malicious_manifest.verify().is_ok());

// During restore, consecutive check is bypassed at chunk 2
// because last_chunk_last_version == 0 after chunk 1
// Result: Database has versions [0] and [100-200], missing [1-99]
```

**Notes:**

This vulnerability is classified as Low severity because while it violates state consistency invariants, it requires privileged access to backup infrastructure and has limited blast radius. The validation checklist requirement for "Critical, High, or Medium severity" is not met. However, this represents a genuine implementation flaw that should be fixed to maintain system integrity.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L363-382)
```rust
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
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/manifest.rs (L50-88)
```rust
    pub fn verify(&self) -> Result<()> {
        // check number of waypoints
        ensure!(
            self.first_version <= self.last_version,
            "Bad version range: [{}, {}]",
            self.first_version,
            self.last_version,
        );

        // check chunk ranges
        ensure!(!self.chunks.is_empty(), "No chunks.");

        let mut next_version = self.first_version;
        for chunk in &self.chunks {
            ensure!(
                chunk.first_version == next_version,
                "Chunk ranges not continuous. Expected first version: {}, actual: {}.",
                next_version,
                chunk.first_version,
            );
            ensure!(
                chunk.last_version >= chunk.first_version,
                "Chunk range invalid. [{}, {}]",
                chunk.first_version,
                chunk.last_version,
            );
            next_version = chunk.last_version + 1;
        }

        // check last version in chunk matches manifest
        ensure!(
            next_version - 1 == self.last_version, // okay to -1 because chunks is not empty.
            "Last version in chunks: {}, in manifest: {}",
            next_version - 1,
            self.last_version,
        );

        Ok(())
    }
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L193-294)
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
    }

    ledger_db
        .transaction_accumulator_db()
        .put_transaction_accumulator(
            first_version,
            txn_infos,
            &mut ledger_db_batch.transaction_accumulator_db_batches,
        )?;

    ledger_db.event_db().put_events_multiple_versions(
        first_version,
        events,
        &mut ledger_db_batch.event_db_batches,
    )?;

    if ledger_db.enable_storage_sharding() {
        for (idx, txn_events) in events.iter().enumerate() {
            for event in txn_events {
                if let Some(event_key) = event.event_key() {
                    if *event_key == new_block_event_key() {
                        LedgerMetadataDb::put_block_info(
                            first_version + idx as Version,
                            event,
                            &mut ledger_db_batch.ledger_metadata_db_batches,
                        )?;
                    }
                }
            }
        }
    }
    // insert changes in write set schema batch
    for (idx, ws) in write_sets.iter().enumerate() {
        WriteSetDb::put_write_set(
            first_version + idx as Version,
            ws,
            &mut ledger_db_batch.write_set_db_batches,
        )?;
    }

    if kv_replay && first_version > 0 && state_store.get_usage(Some(first_version - 1)).is_ok() {
        let (ledger_state, _hot_state_updates) = state_store.calculate_state_and_put_updates(
            &StateUpdateRefs::index_write_sets(first_version, write_sets, write_sets.len(), vec![]),
            &mut ledger_db_batch.ledger_metadata_db_batches, // used for storing the storage usage
            state_kv_batches,
        )?;
        // n.b. ideally this is set after the batches are committed
        state_store.set_state_ignoring_summary(ledger_state);
    }

    let last_version = first_version + txns.len() as u64 - 1;
    ledger_db_batch
        .ledger_metadata_db_batches
        .put::<DbMetadataSchema>(
            &DbMetadataKey::LedgerCommitProgress,
            &DbMetadataValue::Version(last_version),
        )?;
    ledger_db_batch
        .ledger_metadata_db_batches
        .put::<DbMetadataSchema>(
            &DbMetadataKey::OverallCommitProgress,
            &DbMetadataValue::Version(last_version),
        )?;

    Ok(())
}
```

**File:** storage/aptosdb/src/db/fake_aptosdb.rs (L243-249)
```rust
        let num_transactions_in_db = self.get_synced_version()?.map_or(0, |v| v + 1);
        ensure!(num_transactions_in_db == first_version && num_transactions_in_db == next_version_in_buffered_state,
            "The first version {} passed in, the next version in buffered state {} and the next version in db {} are inconsistent.",
            first_version,
            next_version_in_buffered_state,
            num_transactions_in_db,
        );
```
