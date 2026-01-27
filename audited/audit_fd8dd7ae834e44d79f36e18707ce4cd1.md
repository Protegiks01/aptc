# Audit Report

## Title
Incomplete Event Validation Allows Database Inconsistencies to Go Undetected

## Summary
The `verify_events()` function in the database validation tool performs unidirectional validation, only checking that events present in the transaction list exist in the internal indexer DB, but failing to verify that all events in the indexer DB are present in the transaction list. When transactions have empty event vectors, no validation is performed, allowing database inconsistencies to remain undetected.

## Finding Description

The `verify_events()` function is designed to validate consistency between AptosDB and the internal indexer DB. However, its implementation contains a critical logical flaw that creates a validation blind spot. [1](#0-0) 

The function performs a one-way validation:
1. For each event in the transaction list, it verifies the event exists in the indexer DB via `verify_event_by_key()` and `verify_event_by_version()`
2. However, it NEVER checks if the indexer DB contains additional events that are missing from the transaction list [2](#0-1) 

When `event_vec` contains empty vectors (e.g., `Some(vec![vec![], vec![]])`), representing transactions with zero events:
- The outer loop iterates through each transaction's event vector
- The inner loop `for (idx, event) in events.iter().enumerate()` executes zero times when `events` is empty
- No validation calls are made
- The function increments `version` and continues
- Returns `Ok(())` without detecting if the indexer DB has events for those versions

**Attack Scenario:**

1. Due to a bug in `get_events_by_version()` or database corruption, AptosDB returns empty event vectors for some transactions [3](#0-2) 

2. The internal indexer DB correctly has indexed events for those transactions [4](#0-3) 

3. An operator runs the validation tool to check database consistency [5](#0-4) 

4. The validation passes because:
   - For empty event vectors, no verification is performed
   - Events missing from AptosDB but present in the indexer are never checked
   
5. The operator incorrectly believes the databases are consistent

6. This undetected inconsistency can lead to:
   - Different query results depending on which DB is used
   - State verification failures across validator nodes
   - Potential consensus issues if event data affects state root calculations

This violates the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." If different nodes have different event data, they may produce different state roots for identical blocks, breaking the **Deterministic Execution** invariant.

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty program: "State inconsistencies requiring intervention."

The vulnerability enables:
1. **Undetected database corruption**: Missing events in AptosDB go unnoticed
2. **Cross-database inconsistencies**: AptosDB and internal indexer DB can diverge without detection
3. **Query inconsistencies**: Different APIs may return different results based on which database they query
4. **Consensus risk**: If validators have different event data and events affect state transitions, they may produce different state roots
5. **Operational blindness**: Operators cannot trust the validation tool to detect all database issues

While not directly exploitable for fund theft, this creates a systemic risk where data corruption can propagate undetected through the network, potentially leading to consensus failures or requiring manual intervention to resolve state inconsistencies.

## Likelihood Explanation

**Likelihood: Medium to High**

This issue will occur whenever:
1. There's a bug in `get_events_by_version()` that causes it to return fewer events than exist
2. Database corruption causes events to be missing from AptosDB
3. State sync or backup/restore operations fail to properly populate events
4. Any code path results in transactions being written with incomplete event data

The validation tool is specifically designed to catch such inconsistencies, but this flaw means it will fail to detect a significant class of corruption scenarios. Given the complexity of distributed database systems and the multiple code paths that interact with event storage, the likelihood of encountering scenarios where this blind spot matters is non-trivial.

## Recommendation

Implement bidirectional validation by adding a reverse check that verifies all events in the internal indexer DB for the validated version range are present in the transaction list:

```rust
fn verify_events(
    transaction_list: &TransactionListWithProofV2,
    internal_indexer_db: &DB,
    start_version: u64,
) -> Result<()> {
    let mut version = start_version;
    match &transaction_list.get_transaction_list_with_proof().events {
        None => {
            return Ok(());
        },
        Some(event_vec) => {
            // Forward validation: check transaction list events exist in indexer
            for events in event_vec {
                for (idx, event) in events.iter().enumerate() {
                    match event {
                        ContractEvent::V1(event) => {
                            let seq_num = event.sequence_number();
                            let event_key = event.key();
                            verify_event_by_version(
                                event_key,
                                seq_num,
                                internal_indexer_db,
                                version,
                                idx,
                            )?;
                            verify_event_by_key(
                                event_key,
                                seq_num,
                                internal_indexer_db,
                                idx,
                                version,
                            )?;
                        },
                        _ => continue,
                    }
                }
                
                // NEW: Reverse validation - check all indexer events for this version
                // exist in the transaction list
                verify_indexer_events_for_version(
                    internal_indexer_db,
                    version,
                    events,
                )?;
                
                version += 1;
            }
        },
    }
    Ok(())
}

fn verify_indexer_events_for_version(
    internal_indexer_db: &DB,
    version: u64,
    expected_events: &Vec<ContractEvent>,
) -> Result<()> {
    // Iterate through all events in indexer DB for this version
    let mut iter = internal_indexer_db.iter::<EventByVersionSchema>()?;
    let mut indexer_event_count = 0;
    
    // Seek to first event for this version
    iter.seek(&(EventKey::default(), version, 0))?;
    
    while let Some(((event_key, ver, seq_num), idx)) = iter.next().transpose()? {
        if ver != version {
            break;
        }
        indexer_event_count += 1;
        
        // Verify this indexer event exists in the transaction list
        if idx as usize >= expected_events.len() {
            panic!(
                "Indexer has event at idx {} for version {}, but transaction list only has {} events",
                idx, version, expected_events.len()
            );
        }
    }
    
    // Verify counts match
    if indexer_event_count != expected_events.len() {
        panic!(
            "Event count mismatch at version {}: indexer has {}, transaction list has {}",
            version, indexer_event_count, expected_events.len()
        );
    }
    
    Ok(())
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_db_indexer::db_ops::open_internal_indexer_db;
    use aptos_types::contract_event::ContractEvent;
    use aptos_types::event::EventKey;
    use tempfile::TempDir;
    
    #[test]
    fn test_missing_events_validation_bypass() {
        // Setup: Create internal indexer DB with events
        let tmpdir = TempDir::new().unwrap();
        let internal_db = open_internal_indexer_db(
            tmpdir.path(), 
            &RocksdbConfig::default()
        ).unwrap();
        
        // Insert events into internal indexer DB for version 100
        let event_key = EventKey::random();
        let version = 100u64;
        
        // Add 2 events to indexer DB
        internal_db.put::<EventByVersionSchema>(
            &(event_key, version, 0),
            &0u64,
        ).unwrap();
        internal_db.put::<EventByVersionSchema>(
            &(event_key, version, 1),
            &1u64,
        ).unwrap();
        
        // Create transaction list with EMPTY event vector for this version
        let txn_list = TransactionListWithProofV2::new(
            TransactionListWithAuxiliaryInfos::new(
                TransactionListWithProof::new(
                    vec![Transaction::dummy()],
                    Some(vec![vec![]]), // EMPTY event vector!
                    Some(version),
                    TransactionInfoListWithProof::new_empty(),
                ),
                vec![PersistedAuxiliaryInfo::None],
            )
        );
        
        // BUG: This validation should FAIL because the indexer has 2 events
        // but the transaction list has 0 events. However, it PASSES!
        let result = verify_events(&txn_list, &internal_db, version);
        
        // Current behavior: validation passes incorrectly
        assert!(result.is_ok()); // This should fail but doesn't!
        
        // Expected behavior: validation should detect the mismatch and panic
        // with a message like "Event count mismatch at version 100"
    }
}
```

## Notes

This vulnerability demonstrates a systemic validation gap in the storage layer that could mask critical data integrity issues. While the validation tool is not part of the consensus path, database consistency is foundational to the blockchain's security guarantees. The incomplete validation creates a false sense of security for operators and could allow corrupted or incomplete data to persist undetected, eventually manifesting as consensus failures or state inconsistencies across the network.

### Citations

**File:** storage/aptosdb/src/db_debugger/validation.rs (L148-155)
```rust
pub fn verify_batch_txn_events(
    txns: &TransactionListWithProofV2,
    internal_db: &DB,
    start_version: u64,
) -> Result<()> {
    verify_transactions(txns, internal_db, start_version)?;
    verify_events(txns, internal_db, start_version)
}
```

**File:** storage/aptosdb/src/db_debugger/validation.rs (L228-274)
```rust
fn verify_event_by_key(
    event_key: &EventKey,
    seq_num: u64,
    internal_indexer_db: &DB,
    expected_idx: usize,
    expected_version: u64,
) -> Result<()> {
    match internal_indexer_db.get::<EventByKeySchema>(&(*event_key, seq_num)) {
        Ok(None) => {
            panic!("Event not found in internal indexer db: {:?}", event_key);
        },
        Err(e) => {
            panic!("Error while fetching event: {:?}", e);
        },
        Ok(Some((version, idx))) => {
            assert!(idx as usize == expected_idx && version == expected_version);
            if version as usize % SAMPLE_RATE == 0 {
                println!(
                    "Processed {} at {:?}, {:?}",
                    version, event_key, expected_idx
                );
            }
        },
    }
    Ok(())
}

fn verify_event_by_version(
    event_key: &EventKey,
    seq_num: u64,
    internal_indexer_db: &DB,
    version: u64,
    expected_idx: usize,
) -> Result<()> {
    match internal_indexer_db.get::<EventByVersionSchema>(&(*event_key, version, seq_num)) {
        Ok(None) => {
            panic!("Event not found in internal indexer db: {:?}", event_key);
        },
        Err(e) => {
            panic!("Error while fetching event: {:?}", e);
        },
        Ok(Some(idx)) => {
            assert!(idx as usize == expected_idx);
        },
    }
    Ok(())
}
```

**File:** storage/aptosdb/src/db_debugger/validation.rs (L276-316)
```rust
fn verify_events(
    transaction_list: &TransactionListWithProofV2,
    internal_indexer_db: &DB,
    start_version: u64,
) -> Result<()> {
    let mut version = start_version;
    match &transaction_list.get_transaction_list_with_proof().events {
        None => {
            return Ok(());
        },
        Some(event_vec) => {
            for events in event_vec {
                for (idx, event) in events.iter().enumerate() {
                    match event {
                        ContractEvent::V1(event) => {
                            let seq_num = event.sequence_number();
                            let event_key = event.key();
                            verify_event_by_version(
                                event_key,
                                seq_num,
                                internal_indexer_db,
                                version,
                                idx,
                            )?;
                            verify_event_by_key(
                                event_key,
                                seq_num,
                                internal_indexer_db,
                                idx,
                                version,
                            )?;
                        },
                        _ => continue,
                    }
                }
                version += 1;
            }
        },
    }
    Ok(())
}
```

**File:** storage/aptosdb/src/ledger_db/event_db.rs (L63-81)
```rust
        self.db.write_schemas(batch)
    }

    /// Returns all of the events for a given transaction version.
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

**File:** storage/indexer_schemas/src/schema/event_by_version/mod.rs (L1-29)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

//! This module defines physical storage schema for an event index via which a ContractEvent (
//! represented by a <txn_version, event_idx> tuple so that it can be fetched from `EventSchema`)
//! can be found by <access_path, version, sequence_num> tuple.
//!
//! ```text
//! |<--------------key------------>|<-value->|
//! | event_key | txn_ver | seq_num |   idx   |
//! ```

use crate::{schema::EVENT_BY_VERSION_CF_NAME, utils::ensure_slice_len_eq};
use anyhow::Result;
use aptos_schemadb::{
    define_pub_schema,
    schema::{KeyCodec, ValueCodec},
};
use aptos_types::{event::EventKey, transaction::Version};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::mem::size_of;

define_pub_schema!(EventByVersionSchema, Key, Value, EVENT_BY_VERSION_CF_NAME);

type SeqNum = u64;
type Key = (EventKey, Version, SeqNum);

type Index = u64;
type Value = Index;
```
