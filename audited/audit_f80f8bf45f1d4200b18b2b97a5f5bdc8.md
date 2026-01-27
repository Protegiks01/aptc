# Audit Report

## Title
Missing Write Set Size Bounds Checks in Backup Restore Leading to Memory Exhaustion and Database Corruption

## Summary
The `LoadedChunk::load()` function in the transaction backup restore process does not validate write set sizes before deserialization and storage. This allows an attacker to craft malicious backup files with extremely large write sets that can cause memory exhaustion (DoS) and commit invalid state to the database, violating the system's resource limits invariant.

## Finding Description

During normal transaction execution, Aptos enforces strict limits on write set sizes through `ChangeSetConfigs::check_change_set()`: [1](#0-0) 

These limits are:
- `max_bytes_per_write_op`: 1 MB per write operation
- `max_bytes_all_write_ops_per_transaction`: 10 MB total per transaction  
- `max_write_ops_per_transaction`: 8,192 operations per transaction

However, the backup restore process completely bypasses these validations. In `LoadedChunk::load()`, write sets are deserialized from backup files without any size checking: [2](#0-1) 

The code uses `bcs::from_bytes()` which has no size limit and will allocate whatever memory is specified in the serialized data. The deserialized write sets are then pushed to a vector without validation.

These unchecked write sets are subsequently saved to the database via `save_transactions()`: [3](#0-2) 

The `save_transactions_impl()` function stores write sets directly to the database without size validation: [4](#0-3) 

And `WriteSetDb::put_write_set()` performs no validation: [5](#0-4) 

**Attack Path:**

1. Attacker crafts a malicious backup file containing write sets that violate size limits (e.g., 100 MB write sets, or 100,000 write operations per transaction)
2. Victim runs restore command: `aptos-db-tool restore --target-db-dir /path/to/db --transaction-manifest malicious_backup.json`
3. During `LoadedChunk::load()`, BCS deserialization allocates massive amounts of memory for oversized write sets
4. If the system survives deserialization, invalid write sets are committed to the database via `save_transactions()`
5. Result: Either memory exhaustion crash (DoS) or database corruption with invalid state that violates resource limits

The verification mechanism through `replay_transactions()` is optional and controlled by CLI parameters: [6](#0-5) 

Verification only occurs if `replay_from_version` is specified AND `verify_execution_mode` is not `NoVerify`, meaning write sets can be committed without ever being validated against the established size limits.

## Impact Explanation

**Severity: Medium** per Aptos bug bounty criteria:

1. **Denial of Service (DoS)**: Memory exhaustion during deserialization can crash validator nodes, causing temporary unavailability. This qualifies as "validator node slowdowns" (High) or "state inconsistencies requiring intervention" (Medium).

2. **Database Corruption**: Invalid write sets that violate size constraints can be permanently committed to the database, creating state inconsistencies that violate the Resource Limits invariant (#9). This requires manual intervention to detect and fix.

3. **State Consistency Violation**: If multiple nodes restore from the same malicious backup, they will have inconsistent state compared to nodes that didn't restore, potentially affecting consensus participation.

The impact does not reach Critical severity because:
- It does not directly cause loss of funds or consensus safety violations
- It requires victim action (running restore from untrusted backup)
- It does not enable permanent network partition without manual recovery

However, it qualifies as Medium severity due to the state inconsistencies and potential DoS impact requiring intervention.

## Likelihood Explanation

**Likelihood: Medium**

**Requirements for exploitation:**
- Attacker must convince victim to restore from malicious backup
- Victim must have access to backup restore functionality (typically node operators)
- No authentication or authorization bypass required

**Factors increasing likelihood:**
- Backup restore is a common operational procedure during node recovery, migration, or state sync
- Backup sources may not always be fully trusted (third-party backup services, shared storage)
- The attack is straightforward to execute (just craft oversized write sets in backup format)
- No cryptographic bypasses or complex timing required

**Factors decreasing likelihood:**
- Requires social engineering or compromised backup infrastructure
- Most operators likely restore from their own trusted backups
- Detection is possible through monitoring memory usage during restore

The combination of common operational exposure and straightforward exploitation, balanced against the need for victim cooperation, results in Medium likelihood.

## Recommendation

Add bounds checking in `LoadedChunk::load()` before deserializing and storing write sets. The validation should enforce the same limits used during transaction execution:

**Recommended fix for `storage/backup/backup-cli/src/backup_types/transaction/restore.rs`:**

```rust
use aptos_move::aptos_vm_types::storage::change_set_configs::ChangeSetConfigs;
use aptos_gas_schedule::AptosGasParameters;

impl LoadedChunk {
    async fn load(
        manifest: TransactionChunk,
        storage: &Arc<dyn BackupStorage>,
        epoch_history: Option<&Arc<EpochHistory>>,
    ) -> Result<Self> {
        // ... existing code ...
        
        // Add validation constants
        const MAX_BYTES_PER_WRITE_OP: u64 = 1 << 20; // 1 MB
        const MAX_BYTES_ALL_WRITE_OPS: u64 = 10 << 20; // 10 MB  
        const MAX_WRITE_OPS: usize = 8192;
        
        while let Some(record_bytes) = file.read_record_bytes().await? {
            // Validate record size before deserialization
            ensure!(
                record_bytes.len() <= MAX_BYTES_ALL_WRITE_OPS as usize,
                "Record size {} exceeds maximum allowed size {}",
                record_bytes.len(),
                MAX_BYTES_ALL_WRITE_OPS
            );
            
            let (txn, aux_info, txn_info, events, write_set): (/* ... */) = 
                match manifest.format {
                    TransactionChunkFormat::V0 => {
                        let (txn, txn_info, events, write_set) = 
                            bcs::from_bytes(&record_bytes)?;
                        // ... existing code ...
                    },
                    TransactionChunkFormat::V1 => bcs::from_bytes(&record_bytes)?,
                };
            
            // Validate write_set size after deserialization
            let num_write_ops = write_set.expect_write_op_iter().count();
            ensure!(
                num_write_ops <= MAX_WRITE_OPS,
                "Write set has {} operations, exceeds maximum of {}",
                num_write_ops,
                MAX_WRITE_OPS
            );
            
            let mut total_write_set_size = 0u64;
            for (key, op) in write_set.expect_write_op_iter() {
                if let Some(bytes) = op.bytes() {
                    let op_size = bytes.len() as u64 + key.size() as u64;
                    ensure!(
                        op_size <= MAX_BYTES_PER_WRITE_OP,
                        "Write operation size {} exceeds maximum of {}",
                        op_size,
                        MAX_BYTES_PER_WRITE_OP
                    );
                    total_write_set_size += op_size;
                }
            }
            
            ensure!(
                total_write_set_size <= MAX_BYTES_ALL_WRITE_OPS,
                "Total write set size {} exceeds maximum of {}",
                total_write_set_size,
                MAX_BYTES_ALL_WRITE_OPS
            );
            
            // ... continue with existing code ...
        }
        
        // ... rest of function ...
    }
}
```

Alternatively, use `bcs::from_bytes_with_limit()` for initial size checking before full deserialization.

## Proof of Concept

**Reproduction Steps:**

1. Create a malicious backup manifest with oversized write sets:

```rust
// Create a WriteSet that violates size limits
let mut write_ops = BTreeMap::new();
for i in 0..10000 {  // Exceeds MAX_WRITE_OPS of 8192
    let key = StateKey::raw(format!("key_{}", i).into_bytes());
    let large_value = vec![0u8; 2 * 1024 * 1024]; // 2 MB, exceeds 1 MB limit
    write_ops.insert(key, WriteOp::legacy_modification(large_value.into()));
}
let malicious_write_set = WriteSet::new(write_ops).unwrap();

// Serialize transaction with malicious write set
let txn = Transaction::GenesisTransaction(/* ... */);
let txn_info = TransactionInfo::new(/* ... */);
let events = vec![];
let record = (txn, PersistedAuxiliaryInfo::None, txn_info, events, malicious_write_set);
let record_bytes = bcs::to_bytes(&record).unwrap();

// Write to backup file
// Total size will be ~20 GB for 10,000 write ops * 2 MB each
```

2. Run restore command:
```bash
aptos-db-tool restore \
  --target-db-dir /tmp/test-db \
  --transaction-manifest malicious_backup.json
```

3. Observe:
   - Memory usage spikes during `LoadedChunk::load()`
   - If memory is available, invalid write sets are committed to database
   - No validation errors are raised despite violating all size limits

**Expected outcome:** Node crashes with OOM or commits invalid state to database.

**After fix:** Restore fails with clear error message indicating write set size limit violations.

## Notes

This vulnerability demonstrates a critical gap between transaction execution validation and backup restore validation. The restore path assumes all backup data is valid and trusted, but does not enforce the same invariants that protect the system during normal operation. This breaks the Resource Limits invariant (#9) which states "All operations must respect gas, storage, and computational limits."

The fix should ideally reuse the existing `ChangeSetConfigs::check_change_set()` validation logic rather than duplicating constants, ensuring consistency between execution and restore validation.

### Citations

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L154-177)
```rust
            max_bytes_per_write_op: NumBytes,
            { 5.. => "max_bytes_per_write_op" },
            1 << 20, // a single state item is 1MB max
        ],
        [
            max_bytes_all_write_ops_per_transaction: NumBytes,
            { 5.. => "max_bytes_all_write_ops_per_transaction" },
            10 << 20, // all write ops from a single transaction are 10MB max
        ],
        [
            max_bytes_per_event: NumBytes,
            { 5.. => "max_bytes_per_event" },
            1 << 20, // a single event is 1MB max
        ],
        [
            max_bytes_all_events_per_transaction: NumBytes,
            { 5.. => "max_bytes_all_events_per_transaction"},
            10 << 20, // all events from a single transaction are 10MB max
        ],
        [
            max_write_ops_per_transaction: NumSlots,
            { 11.. => "max_write_ops_per_transaction" },
            8192,
        ],
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L112-137)
```rust
        while let Some(record_bytes) = file.read_record_bytes().await? {
            let (txn, aux_info, txn_info, events, write_set): (
                _,
                PersistedAuxiliaryInfo,
                _,
                _,
                WriteSet,
            ) = match manifest.format {
                TransactionChunkFormat::V0 => {
                    let (txn, txn_info, events, write_set) = bcs::from_bytes(&record_bytes)?;
                    (
                        txn,
                        PersistedAuxiliaryInfo::None,
                        txn_info,
                        events,
                        write_set,
                    )
                },
                TransactionChunkFormat::V1 => bcs::from_bytes(&record_bytes)?,
            };
            txns.push(txn);
            persisted_aux_info.push(aux_info);
            txn_infos.push(txn_info);
            event_vecs.push(events);
            write_sets.push(write_set);
        }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L313-333)
```rust
        if let RestoreRunMode::Restore { restore_handler } = self.global_opt.run_mode.as_ref() {
            ensure!(
                self.output_transaction_analysis.is_none(),
                "Bug: requested to output transaction output sizing info in restore mode.",
            );
            AptosVM::set_concurrency_level_once(self.global_opt.replay_concurrency_level);

            let kv_only = self.replay_from_version.is_some_and(|(_, k)| k);
            let txns_to_execute_stream = self
                .save_before_replay_version(first_version, loaded_chunk_stream, restore_handler)
                .await?;

            if let Some(txns_to_execute_stream) = txns_to_execute_stream {
                if kv_only {
                    self.replay_kv(restore_handler, txns_to_execute_stream)
                        .await?;
                } else {
                    self.replay_transactions(restore_handler, txns_to_execute_stream)
                        .await?;
                }
            }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L507-517)
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
                        .await??;
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L261-267)
```rust
    for (idx, ws) in write_sets.iter().enumerate() {
        WriteSetDb::put_write_set(
            first_version + idx as Version,
            ws,
            &mut ledger_db_batch.write_set_db_batches,
        )?;
    }
```

**File:** storage/aptosdb/src/ledger_db/write_set_db.rs (L149-155)
```rust
    pub(crate) fn put_write_set(
        version: Version,
        write_set: &WriteSet,
        batch: &mut impl WriteBatch,
    ) -> Result<()> {
        batch.put::<WriteSetSchema>(&version, write_set)
    }
```
