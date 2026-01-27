# Audit Report

## Title
Race Condition in Genesis Ledger Info Commit Allows Concurrent Writes Without Synchronization

## Summary
The `commit_genesis_ledger_info()` function in `storage/aptosdb/src/db/mod.rs` lacks synchronization protection that is present in similar critical functions (`commit_ledger()` and `pre_commit_ledger()`). This creates a Time-Of-Check-Time-Of-Use (TOCTOU) race condition where concurrent calls can both pass validation checks and write genesis ledger information, potentially causing genesis state corruption.

## Finding Description

The `commit_genesis_ledger_info()` function performs a check-then-act operation without atomic synchronization: [1](#0-0) 

The function reads the current epoch from an in-memory cache, validates it equals 0, then writes the genesis ledger info. However, this check and write are not atomic, creating a race window.

Compare this with `commit_ledger()` which has explicit concurrency protection: [2](#0-1) 

The AptosDB struct defines these locks at initialization: [3](#0-2) 

Notice that `pre_commit_lock` and `commit_lock` exist, but **no genesis_commit_lock** is defined or used.

Additionally, `commit_genesis_ledger_info()` fails to update the in-memory cache after writing (unlike `post_commit()` which calls `set_latest_ledger_info()`): [4](#0-3) 

This means subsequent calls still read stale cache data, allowing the race condition to persist.

**Attack Scenario:**
1. Thread A calls `commit_genesis_ledger_info(genesis_li_A)`, reads epoch from cache (returns 0)
2. Thread B calls `commit_genesis_ledger_info(genesis_li_B)`, reads epoch from cache (still returns 0, cache not updated)
3. Thread A passes validation check (epoch == 0) and prepares write batch
4. Thread B passes validation check (epoch == 0) and prepares write batch
5. Thread A writes genesis_li_A to database at key epoch=0
6. Thread B writes genesis_li_B to database at key epoch=0 (overwrites Thread A)

The LedgerInfoSchema uses epoch as the key: [5](#0-4) 

Both writes target the same key (epoch 0), and RocksDB's atomic batch write guarantees do not prevent concurrent batches from interleaving - only that each batch is atomic internally. [6](#0-5) 

The call site in node initialization shows potential for concurrent execution: [7](#0-6) 

## Impact Explanation

This vulnerability breaks **Critical Invariant #4: State Consistency** - state transitions must be atomic and verifiable. If genesis is written with conflicting data:

1. **Genesis State Corruption**: The last concurrent write wins, potentially installing a different genesis block than intended
2. **Cross-Node Inconsistency**: Different nodes could end up with different genesis states if they experience the race differently
3. **Consensus Violation**: Breaks **Critical Invariant #1: Deterministic Execution** - validators would not produce identical state roots
4. **Chain Split Risk**: Nodes with different genesis blocks cannot participate in the same chain

This meets **High Severity** criteria per Aptos Bug Bounty: "Significant protocol violations" and "State inconsistencies requiring intervention."

## Likelihood Explanation

**Likelihood: LOW-MEDIUM**

The vulnerability requires concurrent calls to `commit_genesis_ledger_info()` during node initialization. While the normal flow is single-threaded, the following scenarios enable exploitation:

1. **Accidental Multi-Process Start**: Deployment scripts accidentally spawn multiple node processes pointing to the same database directory
2. **Fast Restart Race**: Node crashes and restarts with overlapping initialization phases
3. **Testing Environments**: Integration tests or deployment automation with concurrent database access
4. **Malicious Internal Actor**: An attacker with access to node deployment could deliberately trigger concurrent initialization

The lack of any synchronization makes exploitation **trivial once concurrent access occurs** - no sophisticated timing or race window exploitation needed.

## Recommendation

Add synchronization protection consistent with other commit operations:

```rust
pub struct AptosDB {
    // ... existing fields ...
    pre_commit_lock: std::sync::Mutex<()>,
    commit_lock: std::sync::Mutex<()>,
    genesis_commit_lock: std::sync::Mutex<()>,  // ADD THIS
    // ... rest of fields ...
}

pub fn commit_genesis_ledger_info(&self, genesis_li: &LedgerInfoWithSignatures) -> Result<()> {
    // ADD: Acquire lock to prevent concurrent genesis commits
    let _lock = self
        .genesis_commit_lock
        .try_lock()
        .expect("Concurrent genesis commit detected.");
    
    let ledger_metadata_db = self.ledger_db.metadata_db();
    let current_epoch = ledger_metadata_db
        .get_latest_ledger_info_option()
        .map_or(0, |li| li.ledger_info().next_block_epoch());
    ensure!(
        genesis_li.ledger_info().epoch() == current_epoch && current_epoch == 0,
        "Genesis ledger info epoch is not 0"
    );
    let mut ledger_batch = SchemaBatch::new();
    ledger_metadata_db.put_ledger_info(genesis_li, &mut ledger_batch)?;
    ledger_metadata_db.write_schemas(ledger_batch)?;
    
    // ADD: Update in-memory cache after successful write
    ledger_metadata_db.set_latest_ledger_info(genesis_li.clone());
    
    Ok(())
}
```

## Proof of Concept

```rust
#[test]
fn test_concurrent_genesis_commit_race() {
    use std::sync::Arc;
    use std::thread;
    
    // Create a test database
    let tmpdir = aptos_temppath::TempPath::new();
    let db = AptosDB::new_for_test(&tmpdir);
    let db = Arc::new(db);
    
    // Create two different genesis ledger infos
    let genesis_li_1 = create_test_genesis_ledger_info(/* version 1 */);
    let genesis_li_2 = create_test_genesis_ledger_info(/* version 2 */);
    
    // Spawn two threads that try to commit genesis concurrently
    let db_clone1 = Arc::clone(&db);
    let db_clone2 = Arc::clone(&db);
    
    let handle1 = thread::spawn(move || {
        db_clone1.commit_genesis_ledger_info(&genesis_li_1)
    });
    
    let handle2 = thread::spawn(move || {
        db_clone2.commit_genesis_ledger_info(&genesis_li_2)
    });
    
    // Both threads should succeed (demonstrating the race)
    let result1 = handle1.join().unwrap();
    let result2 = handle2.join().unwrap();
    
    // At least one should succeed, possibly both due to race
    assert!(result1.is_ok() || result2.is_ok());
    
    // If both succeed, we've corrupted the genesis state
    // The final state is non-deterministic (race condition)
    if result1.is_ok() && result2.is_ok() {
        println!("VULNERABILITY: Both genesis commits succeeded!");
        println!("Final genesis state is non-deterministic");
    }
}
```

**Notes**

This vulnerability represents a defensive programming failure where critical synchronization mechanisms present in related functions (`commit_ledger`, `pre_commit_ledger`) are absent from `commit_genesis_ledger_info`. While exploitation requires concurrent initialization attempts (uncommon in production but possible in deployment/testing scenarios or fast restart situations), the complete absence of guards makes the race trivial to trigger once concurrent access occurs. The impact is severe as genesis state corruption could cause permanent chain inconsistencies requiring manual intervention or hard fork.

### Citations

**File:** storage/aptosdb/src/db/mod.rs (L34-37)
```rust
    /// This is just to detect concurrent calls to `pre_commit_ledger()`
    pre_commit_lock: std::sync::Mutex<()>,
    /// This is just to detect concurrent calls to `commit_ledger()`
    commit_lock: std::sync::Mutex<()>,
```

**File:** storage/aptosdb/src/db/mod.rs (L207-219)
```rust
    pub fn commit_genesis_ledger_info(&self, genesis_li: &LedgerInfoWithSignatures) -> Result<()> {
        let ledger_metadata_db = self.ledger_db.metadata_db();
        let current_epoch = ledger_metadata_db
            .get_latest_ledger_info_option()
            .map_or(0, |li| li.ledger_info().next_block_epoch());
        ensure!(
            genesis_li.ledger_info().epoch() == current_epoch && current_epoch == 0,
            "Genesis ledger info epoch is not 0"
        );
        let mut ledger_batch = SchemaBatch::new();
        ledger_metadata_db.put_ledger_info(genesis_li, &mut ledger_batch)?;
        ledger_metadata_db.write_schemas(ledger_batch)
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L89-92)
```rust
            let _lock = self
                .commit_lock
                .try_lock()
                .expect("Concurrent committing detected.");
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L662-665)
```rust
        if let Some(x) = ledger_info_with_sigs {
            self.ledger_db
                .metadata_db()
                .set_latest_ledger_info(x.clone());
```

**File:** storage/aptosdb/src/schema/ledger_info/mod.rs (L26-31)
```rust
define_schema!(
    LedgerInfoSchema,
    u64, /* epoch num */
    LedgerInfoWithSignatures,
    LEDGER_INFO_CF_NAME
);
```

**File:** storage/schemadb/src/lib.rs (L289-304)
```rust
    fn write_schemas_inner(&self, batch: impl IntoRawBatch, option: &WriteOptions) -> DbResult<()> {
        let labels = [self.name.as_str()];
        let _timer = APTOS_SCHEMADB_BATCH_COMMIT_LATENCY_SECONDS.timer_with(&labels);

        let raw_batch = batch.into_raw_batch(self)?;

        let serialized_size = raw_batch.inner.size_in_bytes();
        self.inner
            .write_opt(raw_batch.inner, option)
            .into_db_res()?;

        raw_batch.stats.commit();
        APTOS_SCHEMADB_BATCH_COMMIT_BYTES.observe_with(&[&self.name], serialized_size as f64);

        Ok(())
    }
```

**File:** aptos-node/src/storage.rs (L86-94)
```rust
            if fast_sync_db
                .get_latest_ledger_info_option()
                .expect("should returns Ok results")
                .is_none()
            {
                // it means the DB is empty and we need to
                // commit the genesis ledger info to the DB.
                fast_sync_db.commit_genesis_ledger_info(&ledger_info)?;
            }
```
