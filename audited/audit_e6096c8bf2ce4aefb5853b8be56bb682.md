# Audit Report

## Title
Missing Cryptographic Verification of Events Against event_root_hash During Indexer Retrieval

## Summary
Mint events and all other contract events are cryptographically committed to via `event_root_hash` in `TransactionInfo` during transaction execution, but this commitment is **not verified** when events are retrieved through normal API/indexer paths. This allows corrupted or tampered event data in storage to be served to indexers without detection, potentially causing false mint records.

## Finding Description

Events in Aptos have a cryptographic integrity mechanism through the `event_root_hash` field in `TransactionInfo`, but this protection is not enforced during event retrieval.

**During Transaction Commitment:**

When transactions are executed, events are cryptographically committed through a Merkle accumulator: [1](#0-0) 

The computed `event_root_hash` is stored in `TransactionInfo` and committed atomically to storage: [2](#0-1) 

**During Event Retrieval (API/Indexer Path):**

When events are retrieved via the REST API or internal indexer, they are read directly from storage without verification: [3](#0-2) 

The events are fetched directly from EventDB with no verification against `TransactionInfo.event_root_hash`: [4](#0-3) 

**Verification Only Exists in State Sync:**

The `verify_events_against_root_hash` function exists but is only called during state synchronization with proofs: [5](#0-4) 

This verification is invoked only in proof-based contexts like `TransactionListWithProof::verify`: [6](#0-5) 

**Attack Scenarios:**

1. **Storage Corruption**: Hardware failures, bit flips, or storage bugs that corrupt event data would go undetected when serving indexers
2. **Direct Storage Modification**: An attacker with filesystem access to a node could modify RocksDB event data
3. **Software Bugs**: Bugs in the storage layer that write incorrect event data wouldn't be caught during reads
4. **Backup/Restore Issues**: Corrupted backups that maintain block-level integrity but contain wrong data

While RocksDB provides block-level checksums (kXXH3), these protect against storage-level corruption but not against logical data tampering or application-layer bugs.

## Impact Explanation

This issue qualifies as **Medium Severity** under the Aptos bug bounty criteria:

- **"State inconsistencies requiring intervention"**: False mint records served to external indexers represent data integrity inconsistencies
- **"Limited funds loss or manipulation"**: While not directly causing fund loss on-chain, incorrect mint event data could mislead external systems (NFT marketplaces, token analytics platforms, supply tracking)

The impact is limited because:
- Does NOT affect consensus or on-chain state directly
- Does NOT allow unauthorized minting on-chain
- The blockchain state itself remains correct and verifiable

However, it breaks the integrity guarantee that external systems rely on when consuming event data from indexers.

## Likelihood Explanation

**Likelihood: Low to Medium**

The vulnerability requires one of these conditions:
1. **Storage-level access** to directly modify database files (requires compromised node)
2. **Hardware/software failures** causing storage corruption (not malicious but realistic)
3. **Storage layer bugs** that write incorrect data (rare but possible)

The most realistic scenario is undetected storage corruption rather than intentional attacks. However, given that:
- Nodes handle high-value transactions
- External systems depend on event data integrity
- No application-layer verification exists to catch corruption

The risk of serving incorrect data to indexers is non-negligible, especially in a distributed system with many nodes and storage systems.

## Recommendation

Implement optional event verification against `event_root_hash` during retrieval. This could be done through:

**Option 1: Add verification mode to event retrieval APIs**

```rust
pub fn get_events_by_event_key_verified(
    &self,
    event_key: &EventKey,
    start_seq_num: u64,
    order: Order,
    limit: u64,
    ledger_version: Version,
) -> Result<Vec<EventWithVersion>> {
    let events = self.get_events_by_event_key(event_key, start_seq_num, order, limit, ledger_version)?;
    
    // Verify events against TransactionInfo for each transaction
    for event_with_version in &events {
        let txn_info = self.main_db_reader.get_transaction_info(event_with_version.transaction_version)?;
        let events_at_version = self.get_events_by_version(event_with_version.transaction_version)?;
        verify_events_against_root_hash(&events_at_version, &txn_info)?;
    }
    
    Ok(events)
}
```

**Option 2: Add periodic integrity checks**

Implement background verification that periodically samples events and verifies them against their committed `event_root_hash` to detect corruption early.

**Option 3: Add verification flag to API**

Allow clients to request verified events (with verification overhead) vs. unverified events (faster) based on their trust requirements.

## Proof of Concept

```rust
// Proof of concept showing unverified event retrieval
// This would need to be run against a test node with storage access

use aptos_storage_interface::DbReader;
use aptos_types::event::EventKey;
use aptos_types::indexer::indexer_db_reader::Order;

async fn demonstrate_unverified_retrieval() {
    // Setup: Commit a transaction with events
    let event_key = EventKey::new(0, AccountAddress::random());
    
    // Step 1: Retrieve events normally - NO VERIFICATION OCCURS
    let events = db_reader.get_events(
        &event_key,
        0,
        Order::Ascending,
        10,
        ledger_version
    ).unwrap();
    
    // Step 2: At this point, if storage was corrupted/tampered with,
    // the events returned could be different from what was committed,
    // and no error would be raised
    
    // Step 3: Compare against what SHOULD happen with verification
    for event in &events {
        let txn_info = db_reader.get_transaction_info(event.transaction_version).unwrap();
        let all_events_at_version = db_reader.get_events_by_version(event.transaction_version).unwrap();
        
        // This verification is NOT performed in normal API flow
        verify_events_against_root_hash(&all_events_at_version, &txn_info)
            .expect("Event integrity check failed - corruption detected!");
    }
}
```

## Notes

**Important Context:**

1. This is primarily a **data integrity monitoring gap** rather than a remotely exploitable vulnerability
2. The issue requires either storage-level access (privileged) or hardware/software failures to manifest
3. Consensus and on-chain state remain protected through separate verification mechanisms
4. The tradeoff between performance (no verification on reads) and integrity (verification overhead) may be intentional

**Defense in Depth:**

While RocksDB checksums provide some protection, application-layer cryptographic verification would provide defense-in-depth against:
- Storage bugs that write incorrect data
- Backup/restore corruption
- Future vulnerabilities in the storage layer

The cryptographic commitment (`event_root_hash`) already exists—it's just not being verified during the retrieval path that serves external indexers.

### Citations

**File:** execution/executor/src/workflow/do_ledger_update.rs (L69-75)
```rust
                let event_hashes = txn_output
                    .events()
                    .iter()
                    .map(CryptoHash::hash)
                    .collect::<Vec<_>>();
                let event_root_hash =
                    InMemoryEventAccumulator::from_leaves(&event_hashes).root_hash();
```

**File:** execution/executor/src/workflow/do_ledger_update.rs (L77-88)
```rust
                let txn_info = TransactionInfo::new(
                    txn.hash(),
                    write_set_hash,
                    event_root_hash,
                    state_checkpoint_hash,
                    txn_output.gas_used(),
                    txn_output
                        .status()
                        .as_kept_status()
                        .expect("Already sorted."),
                    auxiliary_info_hash,
                );
```

**File:** storage/indexer/src/db_indexer.rs (L692-704)
```rust
        let mut events_with_version = event_indices
            .into_iter()
            .map(|(seq, ver, idx)| {
                let event = match self
                    .main_db_reader
                    .get_event_by_version_and_index(ver, idx)?
                {
                    event @ ContractEvent::V1(_) => event,
                    ContractEvent::V2(_) => ContractEvent::V1(
                        self.indexer_db
                            .get_translated_v1_event_by_version_and_index(ver, idx)?,
                    ),
                };
```

**File:** storage/aptosdb/src/event_store/mod.rs (L42-50)
```rust
    pub fn get_event_by_version_and_index(
        &self,
        version: Version,
        index: u64,
    ) -> Result<ContractEvent> {
        self.event_db
            .get::<EventSchema>(&(version, index))?
            .ok_or_else(|| AptosDbError::NotFound(format!("Event {} of Txn {}", index, version)))
    }
```

**File:** types/src/transaction/mod.rs (L2346-2350)
```rust
            event_lists
                .into_par_iter()
                .zip_eq(self.proof.transaction_infos.par_iter())
                .map(|(events, txn_info)| verify_events_against_root_hash(events, txn_info))
                .collect::<Result<Vec<_>>>()?;
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
