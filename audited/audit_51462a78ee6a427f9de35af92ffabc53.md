# Audit Report

## Title
Database Debugging Tool Prints Corrupted Data Without Integrity Verification

## Summary
The `print_raw_data_by_version` debugging tool retrieves and displays raw database entries without performing cryptographic integrity verification, allowing corrupted or tampered data to be displayed without any warnings to operators.

## Finding Description

The debugging tool at [1](#0-0)  directly retrieves data from various database components without verifying cryptographic hashes or integrity proofs.

The tool retrieves:
- Transaction data [2](#0-1) 
- TransactionInfo metadata [3](#0-2) 
- WriteSet data [4](#0-3) 
- Events [5](#0-4) 

However, the Aptos blockchain maintains cryptographic integrity through TransactionInfo which stores hashes that link these components. The proper verification method [6](#0-5)  demonstrates that verification should:
1. Compare `transaction.hash()` against `TransactionInfo.transaction_hash()`
2. Verify event root hash matches computed hash from events
3. Validate Merkle proofs through the accumulator

The underlying database getters perform no verification - they simply read from RocksDB [7](#0-6) [8](#0-7) [9](#0-8) 

In contrast, a separate tool specifically performs integrity checks [10](#0-9)  showing that verification is feasible and necessary for integrity assurance.

## Impact Explanation

This represents a **Medium severity** operational security issue under the "State inconsistencies requiring intervention" category. While not directly exploitable for fund theft or consensus violations, it creates a vulnerability in operational workflows:

1. **Database corruption scenarios** (hardware failures, cosmic ray bit flips, software bugs) are realistic for production blockchain nodes
2. **Operators debugging issues** would rely on this tool's output to diagnose problems
3. **Incorrect diagnostic information** could lead to wrong operational decisions, delayed incident response, or misidentification of the root cause
4. **Silent failures** are particularly dangerous in blockchain systems where data integrity is paramount

However, this does NOT reach Critical/High severity because it's not in the consensus path and requires pre-existing database corruption.

## Likelihood Explanation

**Medium likelihood**. Hardware-induced database corruption is a known operational concern for distributed systems running on commodity hardware. The tool would be invoked specifically during debugging scenarios when anomalies are suspected, making the impact window relevant during critical operational incidents.

## Recommendation

Add integrity verification to the debugging tool by validating cryptographic consistency:

```rust
// After retrieving data, add verification
let transaction = ledger_db.transaction_db().get_transaction(self.version)?;
let transaction_info = ledger_db.transaction_info_db().get_transaction_info(self.version)?;

// Verify transaction hash matches
let computed_hash = transaction.hash();
if computed_hash != transaction_info.transaction_hash() {
    println!("⚠️  WARNING: Transaction hash mismatch!");
    println!("   Computed: {:?}", computed_hash);
    println!("   Expected: {:?}", transaction_info.transaction_hash());
}

// Verify events hash to event_root_hash
let events = ledger_db.event_db().get_events_by_version(self.version)?;
if !events.is_empty() {
    let event_hashes: Vec<_> = events.iter().map(CryptoHash::hash).collect();
    let computed_event_root = InMemoryEventAccumulator::from_leaves(&event_hashes).root_hash();
    if computed_event_root != transaction_info.event_root_hash() {
        println!("⚠️  WARNING: Event root hash mismatch!");
    }
}

// Verify against transaction accumulator
let accumulator_hash = ledger_db
    .transaction_accumulator_db_raw()
    .get::<TransactionAccumulatorSchema>(&Position::from_leaf_index(self.version))?;
if accumulator_hash.as_ref() != Some(&transaction_info.hash()) {
    println!("⚠️  WARNING: TransactionInfo not in accumulator!");
}
```

## Proof of Concept

```rust
// Reproduction steps:
// 1. Create a test database with valid transactions
// 2. Manually corrupt a transaction in the database using direct RocksDB access
// 3. Run print_raw_data_by_version on the corrupted version
// 4. Observe: Tool prints corrupted data without warning
// 5. Run check_txn_info_hashes tool on same data
// 6. Observe: Verification tool detects the corruption

#[test]
fn test_debug_tool_prints_corrupted_data() {
    // Setup: Create database and commit valid transaction
    let tmpdir = TempPath::new();
    let db = AptosDB::new_for_test(&tmpdir);
    
    // Commit a valid transaction at version 0
    let txn = create_test_transaction();
    let txn_info = TransactionInfo::new(
        txn.hash(),
        HashValue::zero(), // state_change_hash
        HashValue::zero(), // event_root_hash  
        None, 100, ExecutionStatus::Success, None
    );
    db.save_transactions(&[...], 0, None).unwrap();
    
    // Corrupt the transaction in database (simulating disk corruption)
    let corrupted_txn = create_different_transaction();
    db.transaction_db().db().put::<TransactionSchema>(&0, &corrupted_txn).unwrap();
    
    // Use print_raw_data_by_version tool
    // Expected: Should print corrupted transaction without warning
    // Actual: Prints corrupted data silently
    
    // Contrast with proper verification which would fail:
    let retrieved_txn = db.get_transaction(0).unwrap();
    let retrieved_info = db.get_transaction_info(0).unwrap();
    assert_ne!(retrieved_txn.hash(), retrieved_info.transaction_hash());
    // This mismatch indicates corruption but the debug tool doesn't check it
}
```

**Notes:**

This issue specifically affects the operational security posture of validator nodes. While the debugging tool is not in the critical consensus path, defense-in-depth principles suggest that all tools operating on security-critical blockchain data should perform integrity verification, especially given that the necessary cryptographic proofs are already stored in the database and readily available for verification.

### Citations

**File:** storage/aptosdb/src/db_debugger/examine/print_raw_data_by_version.rs (L24-79)
```rust
    pub fn run(self) -> Result<()> {
        let rocksdb_config = RocksdbConfigs {
            enable_storage_sharding: self.sharding_config.enable_storage_sharding,
            ..Default::default()
        };
        let env = None;
        let block_cache = None;

        let (ledger_db, _, _, _) = AptosDB::open_dbs(
            &StorageDirPaths::from_path(&self.db_dir),
            rocksdb_config,
            env,
            block_cache,
            /*readonly=*/ true,
            /*max_num_nodes_per_lru_cache_shard=*/ 0,
            /*reset_hot_state=*/ false,
        )?;

        println!(
            "Transaction: {:?}",
            ledger_db.transaction_db().get_transaction(self.version)?
        );

        println!(
            "PersistedAuxiliaryInfo: {:?}",
            ledger_db
                .persisted_auxiliary_info_db()
                .get_persisted_auxiliary_info(self.version)?
        );

        println!(
            "WriteSet: {:?}",
            ledger_db.write_set_db().get_write_set(self.version)?
        );

        println!(
            "Events: {:?}",
            ledger_db.event_db().get_events_by_version(self.version)?
        );

        println!(
            "TransactionInfo: {:?}",
            ledger_db
                .transaction_info_db()
                .get_transaction_info(self.version)?
        );

        println!(
            "TransactionAccumulatorHash: {:?}",
            ledger_db
                .transaction_accumulator_db()
                .get_root_hash(self.version)?
        );

        Ok(())
    }
```

**File:** types/src/transaction/mod.rs (L1417-1439)
```rust
    pub fn verify(&self, ledger_info: &LedgerInfo) -> Result<()> {
        let txn_hash = self.transaction.hash();
        ensure!(
            txn_hash == self.proof.transaction_info().transaction_hash(),
            "Transaction hash ({}) not expected ({}).",
            txn_hash,
            self.proof.transaction_info().transaction_hash(),
        );

        if let Some(events) = &self.events {
            let event_hashes: Vec<_> = events.iter().map(CryptoHash::hash).collect();
            let event_root_hash =
                InMemoryEventAccumulator::from_leaves(&event_hashes[..]).root_hash();
            ensure!(
                event_root_hash == self.proof.transaction_info().event_root_hash(),
                "Event root hash ({}) not expected ({}).",
                event_root_hash,
                self.proof.transaction_info().event_root_hash(),
            );
        }

        self.proof.verify(ledger_info, self.version)
    }
```

**File:** storage/aptosdb/src/ledger_db/transaction_db.rs (L56-60)
```rust
    pub(crate) fn get_transaction(&self, version: Version) -> Result<Transaction> {
        self.db
            .get::<TransactionSchema>(&version)?
            .ok_or_else(|| AptosDbError::NotFound(format!("Txn {version}")))
    }
```

**File:** storage/aptosdb/src/ledger_db/write_set_db.rs (L57-61)
```rust
    pub(crate) fn get_write_set(&self, version: Version) -> Result<WriteSet> {
        self.db
            .get::<WriteSetSchema>(&version)?
            .ok_or_else(|| AptosDbError::NotFound(format!("WriteSet at version {}", version)))
    }
```

**File:** storage/aptosdb/src/ledger_db/event_db.rs (L67-81)
```rust
    pub(crate) fn get_events_by_version(&self, version: Version) -> Result<Vec<ContractEvent>> {
        let mut events = vec![];

        let mut iter = self.db.iter::<EventSchema>()?;
        // Grab the first event and then iterate until we get all events for this version.
        iter.seek(&version)?;
        while let Some(((ver, _index), event)) = iter.next().transpose()? {
            if ver != version {
                break;
            }
            events.push(event);
        }

        Ok(events)
    }
```

**File:** storage/aptosdb/src/db_debugger/ledger/check_txn_info_hashes.rs (L32-58)
```rust
        println!("Checking that TransactionInfo hashes matches accumulator leaf hashes...");
        let txn_info_iter = ledger_db
            .transaction_info_db()
            .get_transaction_info_iter(self.start_version, self.num_versions)?;
        let mut version = self.start_version;
        for res in txn_info_iter {
            let txn_info = res?;
            let leaf_hash =
                ledger_db
                    .transaction_accumulator_db_raw()
                    .get::<TransactionAccumulatorSchema>(&Position::from_leaf_index(version))?;
            let txn_info_hash = txn_info.hash();

            ensure!(
                leaf_hash.as_ref() == Some(&txn_info_hash),
                "Found mismatch: version: {}, txn_info_hash: {:?}, leaf_hash: {:?}",
                version,
                txn_info_hash,
                leaf_hash,
            );

            if version % 10_000 == 0 {
                println!("Good until version {}.", version);
            }

            version += 1;
        }
```
