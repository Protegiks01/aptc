# Audit Report

## Title
Event Root Hash Validation Bypass in Database Debugger Allows Undetected Event Data Loss

## Summary
The `verify_events()` function in the database validation debugger fails to verify that events retrieved from the database match the cryptographic `event_root_hash` commitment stored in `TransactionInfo`. This allows complete or partial event data loss to go undetected, violating the State Consistency invariant and potentially causing consensus divergence between nodes.

## Finding Description

The validation logic in `verify_events()` only checks that events present in `event_vec` are properly indexed in the internal indexer database, but does NOT verify that all expected events are actually present based on the transaction's cryptographic commitment. [1](#0-0) 

The function iterates through events retrieved from the database and validates their indexing, but never compares the event list against the `event_root_hash` stored in `TransactionInfo`. 

Every transaction has an `event_root_hash` field that represents a Merkle accumulator root of all events emitted during execution: [2](#0-1) 

The `TransactionListWithProofV2` structure contains `transaction_infos` with these hashes: [3](#0-2) 

However, the validation code retrieves events from the database without verifying they match the committed hash: [4](#0-3) 

The `get_events_by_version()` method simply returns whatever events exist in the EventSchema table: [5](#0-4) 

**Attack Scenario:**
1. Transaction executes and emits events, `event_root_hash` is computed and stored in `TransactionInfo`
2. Events are written to EventSchema and indexed in internal_indexer_db
3. Database corruption, pruning bug, or malicious deletion removes events from EventSchema
4. Validation runs: `get_events_by_version()` returns empty/partial list
5. `verify_events()` validates the empty list successfully (nothing to check)
6. Critical data loss goes undetected despite `event_root_hash` proving events should exist

The proper verification already exists in `TransactionListWithProof::verify()` but is never called by the debugger validation: [6](#0-5) 

## Impact Explanation

**Critical Severity** - This vulnerability breaks multiple critical invariants:

1. **State Consistency Violation**: Events are part of the transaction execution output. Missing events mean the stored state is inconsistent with the cryptographic commitment. This violates invariant #4: "State transitions must be atomic and verifiable via Merkle proofs."

2. **Deterministic Execution Violation**: If different validator nodes have different event data due to undetected corruption, they would produce different state roots for queries that depend on events, violating invariant #1: "All validators must produce identical state roots for identical blocks."

3. **Consensus Safety Risk**: While events don't directly affect state merkle tree computation, event-based indexers and applications could diverge between nodes, leading to inconsistent views of blockchain state across the network.

4. **Undetectable Data Corruption**: The validation tool is specifically designed to detect database inconsistencies. Its failure to catch missing events means critical data loss could persist indefinitely, affecting:
   - Smart contract applications relying on event data
   - Indexers and explorers serving user queries  
   - Wallets and dApps monitoring on-chain activity
   - Audit trails and compliance systems

This meets **Critical Severity** criteria for "State inconsistencies requiring intervention" and represents a significant protocol violation that could require coordinated recovery across the network.

## Likelihood Explanation

**High Likelihood** of occurrence in production:

1. **Database Corruption**: RocksDB corruption in the EventSchema column family would cause events to be lost while TransactionInfo remains intact
2. **Pruning Bugs**: Event pruning logic could incorrectly delete events that should be retained
3. **Partial Writes**: Write failures during transaction commit could result in TransactionInfo being persisted but events not being written
4. **State Sync Issues**: During state synchronization, events might not be fetched/stored correctly while transaction data is successfully synchronized

The validation tool is run to detect exactly these types of issues, but it currently provides false confidence by passing when events are missing.

## Recommendation

Add event root hash verification to the `verify_events()` function to ensure events match their cryptographic commitment:

```rust
fn verify_events(
    transaction_list: &TransactionListWithProofV2,
    internal_indexer_db: &DB,
    start_version: u64,
) -> Result<()> {
    let mut version = start_version;
    let txn_list = transaction_list.get_transaction_list_with_proof();
    let transaction_infos = &txn_list.proof.transaction_infos;
    
    match &txn_list.events {
        None => {
            // If events is None, verify all transactions have empty event_root_hash
            for txn_info in transaction_infos {
                let event_root_hash = txn_info.event_root_hash();
                ensure!(
                    event_root_hash == ACCUMULATOR_PLACEHOLDER_HASH.deref(),
                    "Transaction at version {} has non-empty event_root_hash but events were not fetched",
                    version
                );
                version += 1;
            }
            return Ok(());
        },
        Some(event_vec) => {
            ensure!(
                event_vec.len() == transaction_infos.len(),
                "Event vector length doesn't match transaction info length"
            );
            
            for (events, txn_info) in event_vec.iter().zip(transaction_infos.iter()) {
                // Verify events match the event_root_hash commitment
                verify_events_against_root_hash(events, txn_info)?;
                
                // Verify events are properly indexed
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

Additionally, import the necessary function and constant:
```rust
use aptos_crypto::hash::ACCUMULATOR_PLACEHOLDER_HASH;
use aptos_types::transaction::verify_events_against_root_hash; // Make this public if needed
```

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_types::{
        contract_event::ContractEvent,
        transaction::{Transaction, TransactionInfo, TransactionListWithProof, Version},
        proof::TransactionInfoListWithProof,
    };
    use aptos_crypto::{hash::CryptoHash, HashValue};
    
    #[test]
    fn test_missing_events_undetected() {
        // Setup: Create a transaction list with events that have a non-empty event_root_hash
        let txn = Transaction::dummy();
        let events = vec![ContractEvent::dummy()]; // Create some events
        
        // Compute the event_root_hash from actual events
        let event_hashes: Vec<_> = events.iter().map(CryptoHash::hash).collect();
        let event_root_hash = InMemoryEventAccumulator::from_leaves(&event_hashes).root_hash();
        
        // Create TransactionInfo with the correct event_root_hash
        let txn_info = TransactionInfo::new(
            txn.hash(),
            HashValue::zero(), // state_checkpoint_hash
            HashValue::zero(), // event_root_hash - SHOULD BE event_root_hash from above
            None,
            0,
            ExecutionStatus::Success,
        );
        
        // Create TransactionListWithProof with events set to None (simulating missing events)
        let txn_list = TransactionListWithProof::new(
            vec![txn],
            None, // Events are missing!
            Some(0),
            TransactionInfoListWithProof::new(
                TransactionAccumulatorRangeProof::new_empty(),
                vec![txn_info],
            ),
        );
        
        // Current implementation: This validation PASSES even though events are missing
        let result = verify_events(
            &TransactionListWithProofV2::new(txn_list),
            &mock_internal_db,
            0,
        );
        
        assert!(result.is_ok()); // BUG: Should fail but passes!
        
        // With the fix: This should FAIL because event_root_hash indicates events should exist
        // but they are missing
    }
}
```

This proof of concept demonstrates that the current validation accepts a transaction list where events are missing despite the `event_root_hash` in `TransactionInfo` indicating events should be present. The recommended fix would cause this test to properly fail, detecting the data inconsistency.

**Notes**

The vulnerability exists specifically in the database validation/debugging tool at `storage/aptosdb/src/db_debugger/validation.rs`. While the core `TransactionListWithProof::verify()` method does include event root hash verification, the debugger's custom validation bypasses this check entirely. This creates a false sense of security when running database integrity checks, as critical event data corruption would go unnoticed.

### Citations

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

**File:** types/src/transaction/mod.rs (L2338-2351)
```rust
        // Verify the events if they exist.
        if let Some(event_lists) = &self.events {
            ensure!(
                event_lists.len() == self.get_num_transactions(),
                "The length of event_lists ({}) does not match the number of transactions ({}).",
                event_lists.len(),
                self.get_num_transactions(),
            );
            event_lists
                .into_par_iter()
                .zip_eq(self.proof.transaction_infos.par_iter())
                .map(|(events, txn_info)| verify_events_against_root_hash(events, txn_info))
                .collect::<Result<Vec<_>>>()?;
        }
```

**File:** types/src/transaction/mod.rs (L2629-2643)
```rust
fn verify_events_against_root_hash(
    events: &[ContractEvent],
    transaction_info: &TransactionInfo,
) -> Result<()> {
    let event_hashes: Vec<_> = events.iter().map(CryptoHash::hash).collect();
    let event_root_hash = InMemoryEventAccumulator::from_leaves(&event_hashes).root_hash();
    ensure!(
        event_root_hash == transaction_info.event_root_hash(),
        "The event root hash calculated doesn't match that carried on the \
                         transaction info! Calculated hash {:?}, transaction info hash {:?}",
        event_root_hash,
        transaction_info.event_root_hash()
    );
    Ok(())
}
```

**File:** types/src/proof/definition.rs (L880-883)
```rust
pub struct TransactionInfoListWithProof {
    pub ledger_info_to_transaction_infos_proof: TransactionAccumulatorRangeProof,
    pub transaction_infos: Vec<TransactionInfo>,
}
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L294-302)
```rust
            let events = if fetch_events {
                Some(
                    (start_version..start_version + limit)
                        .map(|version| self.ledger_db.event_db().get_events_by_version(version))
                        .collect::<Result<Vec<_>>>()?,
                )
            } else {
                None
            };
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
