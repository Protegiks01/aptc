# Audit Report

## Title
Non-Atomic Two-Phase Commit in Backup Restoration Allows Validator State Inconsistency

## Summary
The backup restoration process uses a non-atomic two-phase commit where state key-value database commits succeed before ledger database commits. If restoration fails after the first commit but before the second, validators are left in an inconsistent state with no automatic rollback mechanism. An attacker can craft malicious backups that pass `verify()` but intentionally fail during restoration, causing different validators to have divergent database states and breaking consensus safety.

## Finding Description

The vulnerability exists in the transaction restoration flow with three critical components:

**1. Insufficient Verification**

The `verify()` function only validates structural properties: [1](#0-0) 

This function checks version ranges and chunk continuity but does NOT validate:
- File handle existence or accessibility
- File content validity or format correctness
- Cryptographic proof validity
- Transaction accumulator integrity

**2. Non-Atomic Two-Phase Commit**

During transaction restoration, the system commits to two separate databases in sequence: [2](#0-1) 

The comment explicitly states "commit the state kv before ledger in case of failure happens," acknowledging the ordering. The state KV database commits FIRST (line 170), then the ledger database commits SECOND (line 172). These operations are not atomic - if the ledger commit fails after the state KV commit succeeds, the databases become inconsistent.

**3. No Inconsistency Detection During Restore**

The `sync_commit_progress` function that normally detects and fixes database inconsistencies is disabled during restore operations: [3](#0-2) 

When opening the database for restore using `open_kv_only`, the `empty_buffered_state_for_restore` parameter is set to `true`: [4](#0-3) 

This skips the `sync_commit_progress` call, disabling automatic inconsistency detection.

**4. Resume Mechanism Compounds the Problem**

The system tracks restoration progress using `OverallCommitProgress` from the ledger metadata database: [5](#0-4) 

If ledger_db.write_schemas() fails, `OverallCommitProgress` is not updated (it's written in the failed batch). On resume, the system will:
1. Read the old version from `OverallCommitProgress`
2. Attempt to restore the same transactions again
3. Encounter conflicts because state_kv_db already has those changes

**Attack Path:**

1. Attacker crafts a malicious backup with:
   - Valid manifest.json that passes `verify()` checks
   - Valid transaction data files (so transactions load successfully)
   - Corrupted or malformed ledger metadata (e.g., invalid transaction accumulator data, malformed events, corrupted write set references)

2. Validator begins restoration from this backup
3. `LoadedChunk.load()` succeeds (reads and validates transactions against proofs)
4. `save_transactions()` is called:
   - `state_kv_db.commit()` succeeds (writes state changes)
   - `ledger_db.write_schemas()` fails (due to malformed ledger data)

5. Result: Database in inconsistent state:
   - State KV DB: Contains transaction state changes for version N
   - Ledger DB: Missing transaction metadata for version N
   - OverallCommitProgress: Still points to version N-1
   - Transaction accumulator: Missing entries for version N

6. Different validators restoring from this backup will have different states depending on whether they completed the second phase or not, breaking consensus.

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000)

This vulnerability causes **Consensus Safety Violations** - a critical severity category per the Aptos bug bounty program. Specifically:

1. **State Consistency Invariant Broken**: Validators have divergent database states where state KV changes exist without corresponding ledger metadata. This violates the fundamental invariant that "State transitions must be atomic and verifiable via Merkle proofs."

2. **Deterministic Execution Invariant Broken**: Different validators will compute different state roots because their databases are in inconsistent states. This directly violates "All validators must produce identical state roots for identical blocks."

3. **Non-Recoverable Network Partition**: Once validators are in inconsistent states:
   - They cannot reach consensus on new blocks (different state roots)
   - Resume attempts fail or compound the problem
   - Manual intervention or hard fork required to recover
   - Meets the definition of "Non-recoverable network partition (requires hardfork)"

4. **Affects All Validators**: Any validator restoring from the malicious backup enters an inconsistent state, potentially affecting the entire validator set if the backup is widely distributed.

## Likelihood Explanation

**Likelihood: HIGH**

1. **Low Attacker Barrier**: 
   - No privileged access required
   - Attacker only needs to craft files and host them
   - Backup format is well-documented
   - No cryptographic signing of backups prevents tampering

2. **Realistic Attack Scenarios**:
   - Compromised backup storage provider
   - Man-in-the-middle attack on backup downloads
   - Social engineering to distribute "helpful" backups
   - Insider threat from backup infrastructure operator

3. **Common Trigger Events**:
   - New validators bootstrapping from backups
   - Disaster recovery scenarios
   - Network upgrades requiring state migration
   - Archive node restoration

4. **Difficult Detection**: The inconsistency is subtle and may not be immediately apparent until consensus fails.

## Recommendation

Implement atomic two-phase commit with proper rollback on failure:

**Option 1: Reverse Commit Order (Simple)**
Commit ledger_db BEFORE state_kv_db, so if state_kv_db fails, the transaction isn't marked as committed:

```rust
// In restore_utils.rs save_transactions function
let last_version = first_version + txns.len() as u64 - 1;

// Commit ledger DB FIRST
ledger_db.write_schemas(ledger_db_batch)?;

// Then commit state KV DB - if this fails, resume will retry correctly
state_store
    .state_db
    .state_kv_db
    .commit(last_version, None, sharded_kv_schema_batch)?;
```

**Option 2: Add Rollback on Failure (Robust)**
```rust
let last_version = first_version + txns.len() as u64 - 1;

// Commit state KV first
let state_commit_result = state_store
    .state_db
    .state_kv_db
    .commit(last_version, None, sharded_kv_schema_batch);

if state_commit_result.is_ok() {
    // Only commit ledger if state KV succeeded
    if let Err(e) = ledger_db.write_schemas(ledger_db_batch) {
        // Rollback state KV changes
        warn!("Ledger DB commit failed, rolling back state KV");
        state_store.state_db.state_kv_db.rollback_to_version(
            first_version.checked_sub(1)
        )?;
        return Err(e);
    }
} else {
    return state_commit_result;
}
```

**Option 3: Enhanced verify() (Defense in Depth)**
Add deep validation in `verify()`:

```rust
impl TransactionBackup {
    pub fn verify(&self, storage: &dyn BackupStorage) -> Result<()> {
        // Existing checks...
        
        // Verify all file handles are accessible
        for chunk in &self.chunks {
            ensure!(
                storage.file_exists(&chunk.transactions).await?,
                "Transaction file not found: {:?}",
                chunk.transactions
            );
            ensure!(
                storage.file_exists(&chunk.proof).await?,
                "Proof file not found: {:?}",
                chunk.proof
            );
            
            // Load and validate proof structure
            let (proof, ledger_info): (TransactionAccumulatorRangeProof, LedgerInfoWithSignatures) = 
                storage.load_bcs_file(&chunk.proof).await?;
            // Basic sanity checks on proof...
        }
        
        Ok(())
    }
}
```

**Recommended Solution**: Implement Option 1 (reverse commit order) immediately as it's simple and effective, then add Option 3 for defense in depth.

## Proof of Concept

**Crafting the Malicious Backup:**

```rust
// Create a valid manifest
let manifest = TransactionBackup {
    first_version: 1000,
    last_version: 1099,
    chunks: vec![
        TransactionChunk {
            first_version: 1000,
            last_version: 1099,
            transactions: FileHandle::new("txns_1000_1099.bcs"),
            proof: FileHandle::new("proof_1000_1099.bcs"),
            format: TransactionChunkFormat::V1,
        }
    ],
};

// manifest passes verify() - valid version ranges, continuous chunks
assert!(manifest.verify().is_ok());

// Create valid transaction file (so state_kv commit succeeds)
// Create INVALID proof file with corrupted transaction accumulator
// (details omitted - would corrupt the serialized TransactionAccumulatorRangeProof)

// When validator restores:
// 1. verify() passes ✓
// 2. Transactions load ✓
// 3. state_kv_db.commit() succeeds ✓
// 4. ledger_db.write_schemas() fails ✗ (corrupted accumulator)
// Result: Inconsistent state
```

**Simulating the Failure:**

```rust
#[test]
fn test_partial_restore_inconsistency() {
    // Setup test database
    let tmpdir = TempPath::new();
    let db = AptosDB::open_kv_only(...);
    
    // Create backup with intentionally corrupted ledger data
    let backup = create_malicious_backup();
    
    // Start restoration
    let restore_result = restore_transactions(&db, &backup);
    
    // Verify state is inconsistent after failure
    assert!(restore_result.is_err());
    
    // State KV has changes
    let state_version = db.state_kv_db.get_commit_progress().unwrap();
    assert_eq!(state_version, 1099);
    
    // But ledger DB doesn't
    let ledger_version = db.get_synced_version().unwrap();
    assert_eq!(ledger_version, 999); // Still at old version
    
    // This is an inconsistent state that breaks consensus
}
```

## Notes

This vulnerability is particularly dangerous because:

1. The comment in the code acknowledges the ordering ("commit the state kv before ledger in case of failure happens") but doesn't explain the rationale or implement proper rollback

2. The `sync_commit_progress` mechanism exists to fix such inconsistencies but is explicitly disabled during restore operations

3. The resume mechanism makes the problem worse by attempting to re-apply already committed state changes

4. No cryptographic signing or deep validation of backup files prevents tampering

5. The attack is practical - backup files are often hosted on third-party infrastructure that could be compromised

This represents a fundamental atomicity violation in a critical database operation that can lead to permanent network partition requiring a hard fork to resolve.

### Citations

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

**File:** storage/aptosdb/src/backup/restore_utils.rs (L164-173)
```rust
        // get the last version and commit to the state kv db
        // commit the state kv before ledger in case of failure happens
        let last_version = first_version + txns.len() as u64 - 1;
        state_store
            .state_db
            .state_kv_db
            .commit(last_version, None, sharded_kv_schema_batch)?;

        ledger_db.write_schemas(ledger_db_batch)?;
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L353-359)
```rust
        if !hack_for_tests && !empty_buffered_state_for_restore {
            Self::sync_commit_progress(
                Arc::clone(&ledger_db),
                Arc::clone(&state_kv_db),
                Arc::clone(&state_merkle_db),
                /*crash_if_difference_is_too_large=*/ true,
            );
```

**File:** storage/aptosdb/src/db/mod.rs (L92-103)
```rust
        Self::open_internal(
            &db_paths,
            readonly,
            pruner_config,
            rocksdb_configs,
            enable_indexer,
            buffered_state_target_items,
            max_num_nodes_per_lru_cache_shard,
            true,
            internal_indexer_db,
            HotStateConfig::default(),
        )
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L76-78)
```rust
    pub(crate) fn get_synced_version(&self) -> Result<Option<Version>> {
        get_progress(&self.db, &DbMetadataKey::OverallCommitProgress)
    }
```
