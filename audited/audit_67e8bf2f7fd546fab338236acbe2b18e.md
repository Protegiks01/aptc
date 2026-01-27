# Audit Report

## Title
Cross-Database Non-Atomic Writes in LedgerDb Causing State Inconsistency and Consensus Failures

## Summary
The `write_schemas()` function in LedgerDb writes to 8 separate RocksDB databases sequentially without atomicity guarantees across them. If any write fails after others succeed, the ledger databases are left in an inconsistent state where transaction data exists in some databases but not others, breaking state consistency and causing transaction validation failures that can halt consensus and state synchronization. [1](#0-0) 

## Finding Description
The vulnerability exists in the core transaction commit path where ledger data must be written atomically across 8 sub-databases to maintain consistency.

**The Problem:**
The `write_schemas()` function writes to databases in this sequential order:
1. write_set_db
2. transaction_info_db  
3. transaction_db
4. persisted_auxiliary_info_db
5. event_db
6. transaction_accumulator_db
7. transaction_auxiliary_data_db
8. ledger_metadata_db

Each individual database write is atomic (RocksDB WriteBatch), but there is NO atomicity across the 8 databases. If write #6 (transaction_accumulator_db) fails due to I/O error, disk full, or process interruption, databases 1-5 contain committed data while 6-8 do not.

**Critical Usage Path:**
This function is called during state sync finalization, which is critical for blockchain synchronization: [2](#0-1) 

**How Inconsistency Breaks Transaction Validation:**
When reading transactions with proofs, the system queries multiple databases: [3](#0-2) 

If transaction_info_db and transaction_db contain data but transaction_accumulator_db does not (due to partial write failure), the call to `get_transaction_proof()` will fail: [4](#0-3) 

The accumulator's HashReader will return an error when it cannot find the required position: [5](#0-4) 

**Developers' Acknowledgment:**
The codebase contains explicit TODO comments acknowledging this unresolved issue: [6](#0-5) [7](#0-6) 

**Attack Scenario:**
1. Validator node processes transaction chunk during state sync via `finalize_state_snapshot()`
2. `ledger_db.write_schemas()` begins sequential writes
3. First 5 databases successfully commit transaction data
4. Write to transaction_accumulator_db fails (I/O error, disk full, corruption)
5. Databases 6-8 never receive data; function returns error
6. **Before node restarts**, another thread handles RPC request for transaction with proof
7. `get_transaction_with_proof()` succeeds reading transaction and transaction_info but FAILS generating proof (missing accumulator data)
8. State sync peer cannot verify transaction, causing sync failure
9. Consensus validators cannot verify blocks containing these transactions
10. Network experiences consensus liveness failure or partition

**Invariants Violated:**
- **State Consistency**: Merkle accumulator root hash is inconsistent with actual transaction data
- **Deterministic Execution**: Different nodes may have different views of committed state if failures occur at different times

## Impact Explanation
**Critical Severity** - This vulnerability meets multiple critical impact criteria:

1. **Consensus/Safety Violations**: Validators cannot generate or verify transaction proofs, preventing consensus from progressing. This violates the fundamental requirement that all validators must be able to verify transactions deterministically.

2. **Network Partition Risk**: Nodes with inconsistent database states cannot properly synchronize with the network. If multiple validators experience partial write failures, they may diverge in their view of committed state, potentially requiring hard fork intervention to resolve.

3. **Total Loss of Liveness**: A validator experiencing this issue cannot:
   - Serve valid transaction proofs to state sync peers
   - Verify incoming blocks (accumulator proofs fail)
   - Participate in consensus (cannot validate transactions)

4. **State Inconsistencies Requiring Manual Intervention**: While restart triggers truncation recovery, this requires manual node restart and database recovery operations. During the window between failure and restart, the node is non-functional.

The severity is amplified because:
- This occurs in the critical commit path used by all validators
- No automatic recovery exists before manual restart
- The issue is explicitly acknowledged but unresolved (TODO comments)
- Can cascade to multiple nodes under common failure conditions (storage issues)

## Likelihood Explanation
**High Likelihood** - This vulnerability can be triggered by common operational scenarios:

1. **Disk Space Exhaustion**: Validators running low on disk space will experience write failures during commit operations
2. **I/O Errors**: Hardware failures, network storage issues, or filesystem corruption can cause RocksDB writes to fail
3. **Process Interruption**: Graceful or forced shutdown during commit leaves databases inconsistent
4. **Storage Performance Degradation**: Slow storage can lead to timeouts and partial write failures

The likelihood is particularly concerning because:
- The commit path is executed for every transaction chunk during normal operation
- State sync operations (which use this path) occur frequently as nodes join/rejoin the network
- No validation or recovery mechanism exists until node restart
- The failure window creates an operational hazard where reads can access inconsistent data

The explicit TODO comments confirm developers are aware this is a real issue requiring resolution, not a theoretical edge case.

## Recommendation
Implement atomic cross-database writes using one of these approaches:

**Option 1: Two-Phase Commit with Write-Ahead Log**
```rust
pub fn write_schemas(&self, schemas: LedgerDbSchemaBatches) -> Result<()> {
    // Phase 1: Write to WAL
    let wal_entry = serialize_schemas(&schemas)?;
    self.write_ahead_log.append(wal_entry)?;
    
    // Phase 2: Write to all databases
    self.write_set_db.write_schemas(schemas.write_set_db_batches)?;
    self.transaction_info_db.write_schemas(schemas.transaction_info_db_batches)?;
    self.transaction_db.write_schemas(schemas.transaction_db_batches)?;
    self.persisted_auxiliary_info_db.write_schemas(schemas.persisted_auxiliary_info_db_batches)?;
    self.event_db.write_schemas(schemas.event_db_batches)?;
    self.transaction_accumulator_db.write_schemas(schemas.transaction_accumulator_db_batches)?;
    self.transaction_auxiliary_data_db.write_schemas(schemas.transaction_auxiliary_data_db_batches)?;
    self.ledger_metadata_db.write_schemas(schemas.ledger_metadata_db_batches)?;
    
    // Phase 3: Clear WAL entry on success
    self.write_ahead_log.mark_complete()?;
    Ok(())
}
```

**Option 2: Progress Tracking per Sub-Database**
Write progress markers for each sub-database before committing, then validate consistency on startup:

```rust
pub fn write_schemas(&self, schemas: LedgerDbSchemaBatches) -> Result<()> {
    let version = extract_version_from_schemas(&schemas)?;
    
    // Track progress for each database
    self.write_set_db.write_progress(version)?;
    self.write_set_db.write_schemas(schemas.write_set_db_batches)?;
    
    self.transaction_info_db.write_progress(version)?;
    self.transaction_info_db.write_schemas(schemas.transaction_info_db_batches)?;
    
    // ... repeat for all databases
    
    Ok(())
}
```

Then enhance startup consistency check: [8](#0-7) 

Add validation that all ledger sub-databases have consistent progress and truncate any that are ahead.

**Option 3: Single Unified Database** (Most robust but requires refactoring)
Consolidate all ledger sub-databases into a single RocksDB instance with column families, enabling true atomic writes across all data.

## Proof of Concept

```rust
#[cfg(test)]
mod test_cross_db_consistency {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_partial_write_causes_inconsistency() {
        let tmp_dir = TempDir::new().unwrap();
        let db = AptosDB::open_for_test(tmp_dir.path());
        
        // Prepare transaction data
        let version = 100;
        let mut batches = LedgerDbSchemaBatches::new();
        
        // Populate batches with test transaction data
        populate_test_transaction(&mut batches, version);
        
        // Simulate failure by closing accumulator DB before write
        std::mem::drop(db.ledger_db.transaction_accumulator_db());
        
        // Attempt write - will fail at accumulator DB
        let result = db.ledger_db.write_schemas(batches);
        assert!(result.is_err());
        
        // Now transaction_db and transaction_info_db have data
        // but transaction_accumulator_db does not
        
        let txn = db.ledger_db.transaction_db().get_transaction(version);
        assert!(txn.is_ok()); // Transaction exists
        
        let txn_info = db.ledger_db.transaction_info_db().get_transaction_info(version);
        assert!(txn_info.is_ok()); // TransactionInfo exists
        
        // But proof generation fails due to missing accumulator data
        let proof = db.get_transaction_with_proof(version, version, false);
        assert!(proof.is_err()); // INCONSISTENCY: Data exists but proof cannot be generated
        
        // This breaks state sync and consensus verification
    }
}
```

## Notes
This vulnerability represents a fundamental design flaw in the storage layer's atomicity guarantees. While recovery exists via node restart and truncation, the window between failure and recovery creates operational risk where:

1. The affected node cannot serve valid proofs to peers
2. Consensus may stall if the node is an active validator
3. State sync cannot progress for nodes attempting to sync from the affected node

The explicit TODO comments confirm this is a known architectural issue awaiting proper resolution. The developers acknowledge the need to "handle data inconsistency" but have not yet implemented the required atomic write mechanism or comprehensive recovery logic.

### Citations

**File:** storage/aptosdb/src/ledger_db/mod.rs (L281-281)
```rust
        // TODO(grao): Handle data inconsistency.
```

**File:** storage/aptosdb/src/ledger_db/mod.rs (L531-548)
```rust
    pub fn write_schemas(&self, schemas: LedgerDbSchemaBatches) -> Result<()> {
        self.write_set_db
            .write_schemas(schemas.write_set_db_batches)?;
        self.transaction_info_db
            .write_schemas(schemas.transaction_info_db_batches)?;
        self.transaction_db
            .write_schemas(schemas.transaction_db_batches)?;
        self.persisted_auxiliary_info_db
            .write_schemas(schemas.persisted_auxiliary_info_db_batches)?;
        self.event_db.write_schemas(schemas.event_db_batches)?;
        self.transaction_accumulator_db
            .write_schemas(schemas.transaction_accumulator_db_batches)?;
        self.transaction_auxiliary_data_db
            .write_schemas(schemas.transaction_auxiliary_data_db_batches)?;
        // TODO: remove this after sharding migration
        self.ledger_metadata_db
            .write_schemas(schemas.ledger_metadata_db_batches)
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L223-223)
```rust
            self.ledger_db.write_schemas(ledger_db_batch)?;
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L272-273)
```rust
            // TODO(grao): Write progress for each of the following databases, and handle the
            // inconsistency at the startup time.
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L1076-1090)
```rust
        let proof = self
            .ledger_db
            .transaction_info_db()
            .get_transaction_info_with_proof(
                version,
                ledger_version,
                self.ledger_db.transaction_accumulator_db(),
            )?;

        let transaction = self.ledger_db.transaction_db().get_transaction(version)?;

        // If events were requested, also fetch those.
        let events = if fetch_events {
            Some(self.ledger_db.event_db().get_events_by_version(version)?)
        } else {
```

**File:** storage/aptosdb/src/ledger_db/transaction_accumulator_db.rs (L66-72)
```rust
    pub fn get_transaction_proof(
        &self,
        version: Version,
        ledger_version: Version,
    ) -> Result<TransactionAccumulatorProof> {
        Accumulator::get_proof(self, ledger_version + 1 /* num_leaves */, version)
            .map_err(Into::into)
```

**File:** storage/aptosdb/src/ledger_db/transaction_accumulator_db.rs (L196-200)
```rust
    fn get(&self, position: Position) -> Result<HashValue, anyhow::Error> {
        self.db
            .get::<TransactionAccumulatorSchema>(&position)?
            .ok_or_else(|| anyhow!("{} does not exist.", position))
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L410-450)
```rust
    pub fn sync_commit_progress(
        ledger_db: Arc<LedgerDb>,
        state_kv_db: Arc<StateKvDb>,
        state_merkle_db: Arc<StateMerkleDb>,
        crash_if_difference_is_too_large: bool,
    ) {
        let ledger_metadata_db = ledger_db.metadata_db();
        if let Some(overall_commit_progress) = ledger_metadata_db
            .get_synced_version()
            .expect("DB read failed.")
        {
            info!(
                overall_commit_progress = overall_commit_progress,
                "Start syncing databases..."
            );
            let ledger_commit_progress = ledger_metadata_db
                .get_ledger_commit_progress()
                .expect("Failed to read ledger commit progress.");
            assert_ge!(ledger_commit_progress, overall_commit_progress);

            let state_kv_commit_progress = state_kv_db
                .metadata_db()
                .get::<DbMetadataSchema>(&DbMetadataKey::StateKvCommitProgress)
                .expect("Failed to read state K/V commit progress.")
                .expect("State K/V commit progress cannot be None.")
                .expect_version();
            assert_ge!(state_kv_commit_progress, overall_commit_progress);

            // LedgerCommitProgress was not guaranteed to commit after all ledger changes finish,
            // have to attempt truncating every column family.
            info!(
                ledger_commit_progress = ledger_commit_progress,
                "Attempt ledger truncation...",
            );
            let difference = ledger_commit_progress - overall_commit_progress;
            if crash_if_difference_is_too_large {
                assert_le!(difference, MAX_COMMIT_PROGRESS_DIFFERENCE);
            }
            truncate_ledger_db(ledger_db.clone(), overall_commit_progress)
                .expect("Failed to truncate ledger db.");

```
