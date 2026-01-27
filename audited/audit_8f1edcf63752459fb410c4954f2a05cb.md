# Audit Report

## Title
`commit_genesis_ledger_info()` Cache Inconsistency Enables Genesis Replacement

## Summary
The `commit_genesis_ledger_info()` function fails to update the in-memory cache after writing genesis to the database, creating a state inconsistency that bypasses the intended idempotency check. This allows the function to be called multiple times, potentially overwriting the genesis ledger info with malicious data.

## Finding Description

The `commit_genesis_ledger_info()` function in `storage/aptosdb/src/db/mod.rs` writes genesis ledger info to the database but fails to update the in-memory cache that tracks the latest ledger info. [1](#0-0) 

The function includes a safety check intended to prevent multiple writes: [2](#0-1) 

This check reads `current_epoch` from the in-memory cache via `get_latest_ledger_info_option()`. [3](#0-2) 

The cache is initialized from the database when `LedgerMetadataDb` is created. [4](#0-3) 

However, after `commit_genesis_ledger_info()` writes genesis to the database via `put_ledger_info()` and `write_schemas()`, it **does not** call `set_latest_ledger_info()` to update the cache. [5](#0-4) 

In contrast, the normal commit path properly updates the cache after persisting data. [6](#0-5) 

For genesis blocks, `next_block_epoch()` returns 1 (not 0) because genesis includes the `next_epoch_state`. [7](#0-6) [8](#0-7) 

**Attack Scenario:**
1. First call to `commit_genesis_ledger_info()`: Genesis is written to DB, cache remains `None`
2. Check still returns `current_epoch = 0` (reads stale cache)
3. Second call with different genesis data passes the check
4. Malicious genesis overwrites legitimate genesis at database key `epoch=0`

The function is called during fast-sync bootstrap. [9](#0-8) 

## Impact Explanation

This is a **Medium Severity** vulnerability (state inconsistency requiring intervention):

- **State Consistency Violation**: Creates a discrepancy between in-memory cache and persisted database state, violating the "State Consistency" invariant
- **Potential Genesis Corruption**: If exploited, allows replacement of genesis with different validator sets or state roots, which could cause chain splits
- **Limited Scope**: The function is not publicly exposed and is only called during internal bootstrap operations

## Likelihood Explanation

**Likelihood: Low**

The vulnerability has limited exploitability:
- The function is not part of any public API or storage interface trait
- Only called once during node bootstrap in controlled circumstances
- Requires either a bootstrap bug causing multiple calls, or insider access to node internals
- The bootstrap code has a guard check (though that check also relies on the stale cache)

However, if triggered (through a bug, race condition, or restart scenario), the impact would be severe.

## Recommendation

Update `commit_genesis_ledger_info()` to call `set_latest_ledger_info()` after successfully writing to the database, similar to the normal commit path: [1](#0-0) 

The fixed implementation should be:

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
    ledger_metadata_db.write_schemas(ledger_batch)?;
    
    // Update the in-memory cache to maintain consistency
    ledger_metadata_db.set_latest_ledger_info(genesis_li.clone());
    
    Ok(())
}
```

## Proof of Concept

```rust
// Test demonstrating the cache inconsistency bug
#[test]
fn test_commit_genesis_cache_bug() {
    use aptos_temppath::TempPath;
    use aptos_types::validator_verifier::ValidatorSet;
    
    let tmpdir = TempPath::new();
    let db = AptosDB::new_for_test(&tmpdir);
    
    // Create a genesis ledger info
    let genesis_li = LedgerInfoWithSignatures::genesis(
        HashValue::random(),
        ValidatorSet::empty()
    );
    
    // First commit - should succeed
    db.commit_genesis_ledger_info(&genesis_li).unwrap();
    
    // Verify genesis is in database by reading directly from DB
    let ledger_db = &db.ledger_db;
    let db_ledger_info = ledger_db.metadata_db()
        .db()
        .get::<LedgerInfoSchema>(&0)
        .unwrap()
        .unwrap();
    assert_eq!(db_ledger_info.ledger_info().version(), 0);
    
    // BUT: Cache is still None!
    let cached_info = ledger_db.metadata_db().get_latest_ledger_info_option();
    assert!(cached_info.is_none(), "BUG: Cache was not updated!");
    
    // This means a second call would pass the check and could overwrite genesis
    // with different data (if we had a way to trigger it)
}
```

## Notes

This vulnerability demonstrates a cache synchronization bug that compromises the idempotency guarantee of `commit_genesis_ledger_info()`. While the current codebase only calls this function once during bootstrap with appropriate guards, the missing cache update creates a state inconsistency that violates storage invariants and could enable genesis replacement if exploited through unexpected code paths, restart scenarios, or future refactoring.

### Citations

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

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L43-50)
```rust
    pub(super) fn new(db: Arc<DB>) -> Self {
        let latest_ledger_info = get_latest_ledger_info_in_db_impl(&db).expect("DB read failed.");
        let latest_ledger_info = ArcSwap::from(Arc::new(latest_ledger_info));

        Self {
            db,
            latest_ledger_info,
        }
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L94-98)
```rust
    pub(crate) fn get_latest_ledger_info_option(&self) -> Option<LedgerInfoWithSignatures> {
        let ledger_info_ptr = self.latest_ledger_info.load();
        let ledger_info: &Option<_> = ledger_info_ptr.deref();
        ledger_info.clone()
    }
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L186-198)
```rust
    pub(crate) fn put_ledger_info(
        &self,
        ledger_info_with_sigs: &LedgerInfoWithSignatures,
        batch: &mut SchemaBatch,
    ) -> Result<()> {
        let ledger_info = ledger_info_with_sigs.ledger_info();

        if ledger_info.ends_epoch() {
            // This is the last version of the current epoch, update the epoch by version index.
            batch.put::<EpochByVersionSchema>(&ledger_info.version(), &ledger_info.epoch())?;
        }
        batch.put::<LedgerInfoSchema>(&ledger_info.epoch(), ledger_info_with_sigs)
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L661-669)
```rust
        // Once everything is successfully persisted, update the latest in-memory ledger info.
        if let Some(x) = ledger_info_with_sigs {
            self.ledger_db
                .metadata_db()
                .set_latest_ledger_info(x.clone());

            LEDGER_VERSION.set(x.ledger_info().version() as i64);
            NEXT_BLOCK_EPOCH.set(x.ledger_info().next_block_epoch() as i64);
        }
```

**File:** types/src/block_info.rs (L119-133)
```rust
    pub fn genesis(genesis_state_root_hash: HashValue, validator_set: ValidatorSet) -> Self {
        let verifier: ValidatorVerifier = (&validator_set).into();
        Self {
            epoch: GENESIS_EPOCH,
            round: GENESIS_ROUND,
            id: HashValue::zero(),
            executed_state_id: genesis_state_root_hash,
            version: GENESIS_VERSION,
            timestamp_usecs: GENESIS_TIMESTAMP_USECS,
            next_epoch_state: Some(EpochState {
                epoch: 1,
                verifier: verifier.into(),
            }),
        }
    }
```

**File:** types/src/block_info.rs (L144-146)
```rust
    pub fn next_block_epoch(&self) -> u64 {
        self.next_epoch_state().map_or(self.epoch, |e| e.epoch)
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
