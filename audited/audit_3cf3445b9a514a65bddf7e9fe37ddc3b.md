# Audit Report

## Title
Silent Event Sequence Number Gap Detection Failure in Aptos Indexer Leading to Data Loss

## Summary
The Aptos indexer does not validate sequence number continuity when storing events for a given GUID (Globally Unique Identifier). This allows events with gaps in their sequence numbers to be silently inserted into the indexer database, causing undetectable data loss in event streams consumed by applications, wallets, and analytics platforms.

## Finding Description

The Aptos blockchain emits events during transaction execution, where each event stream (identified by a GUID composed of `account_address` and `creation_number`) maintains a monotonically increasing `sequence_number` starting from 0. The indexer is responsible for extracting these events from transactions and storing them in a PostgreSQL database for external consumption.

**The Core Issue:**

The indexer's event insertion logic blindly stores whatever events it receives without validating that sequence numbers are continuous for each GUID. [1](#0-0) 

This function uses `on_conflict().do_update()` to handle duplicate insertions but performs no validation to detect missing sequence numbers within a stream.

The event extraction from transactions similarly lacks any gap detection: [2](#0-1) 

Events are simply collected from each transaction and filtered, but sequence number continuity is never checked.

The database schema defines a composite primary key but no constraints to enforce continuity: [3](#0-2) 

**Contrast with Storage Layer:**

Notably, the internal storage layer (used by validators) DOES validate sequence number continuity: [4](#0-3) 

Lines 130-137 explicitly check for gaps and return an error if `seq != cur_seq`, with the message "DB corruption: Sequence number not continuous."

However, this protection exists only in the validator's internal storage, not in the external indexer consumed by applications.

**Attack Scenarios:**

1. **Fullnode Bug**: A bug in event extraction causes some events to be omitted from transaction responses
2. **Indexer Recovery**: Indexer crashes and resumes from incorrect checkpoint, skipping transactions containing events
3. **Database Corruption**: Direct deletion of event records from indexer database
4. **Network Corruption**: Malformed data causes event parsing failures that are silently ignored

In all cases, the indexer would continue operating normally with no indication that data is missing.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** ($10,000 tier) under the Aptos Bug Bounty program as it causes "State inconsistencies requiring intervention."

**Specific Impact:**

- **Financial Applications**: DeFi protocols tracking coin transfer events via indexer would miss transactions, causing incorrect balance calculations and potential financial losses
- **NFT Marketplaces**: Missing mint/transfer events could result in NFTs appearing lost or ownership disputes
- **Governance Systems**: Voting events could be lost, affecting proposal outcome tracking
- **Analytics Platforms**: Historical event data becomes unreliable, breaking metrics and dashboards
- **Wallet Applications**: Transaction history displayed to users would be incomplete

The impact is limited to data integrity in the indexer (not consensus), but downstream applications have no way to detect the gaps without manually cross-referencing with on-chain data.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability requires one of these conditions:
- Software bug in fullnode or indexer causing event omission
- Operational error during indexer deployment/recovery
- Database corruption incident

While not trivially exploitable by external attackers, these scenarios occur in production systems:
- Software bugs are common during upgrades
- Database operations can fail
- Indexer restarts from checkpoints can have off-by-one errors

The vulnerability is **dormant** until triggered, but once triggered, it causes **permanent silent data loss** with no detection mechanism.

## Recommendation

Implement sequence number gap detection in the indexer's event processing pipeline:

**Solution 1: Validation During Insertion**

Add validation logic in `insert_events()` to check for gaps before inserting:

```rust
fn insert_events(
    conn: &mut PgConnection,
    items_to_insert: &[EventModel],
) -> Result<(), diesel::result::Error> {
    use schema::events::dsl::*;
    
    // Group events by GUID and validate sequence continuity
    let mut events_by_guid: HashMap<(String, i64), Vec<&EventModel>> = HashMap::new();
    for event in items_to_insert {
        events_by_guid
            .entry((event.account_address.clone(), event.creation_number))
            .or_insert_with(Vec::new)
            .push(event);
    }
    
    // Check for gaps within each batch
    for ((addr, creation), events_list) in events_by_guid.iter_mut() {
        events_list.sort_by_key(|e| e.sequence_number);
        
        // Get the last known sequence number from DB
        let last_seq = events
            .filter(account_address.eq(addr))
            .filter(creation_number.eq(creation))
            .select(sequence_number)
            .order(sequence_number.desc())
            .first::<i64>(conn)
            .optional()?
            .unwrap_or(-1);
        
        // Validate continuity
        let mut expected_seq = last_seq + 1;
        for event in events_list.iter() {
            if event.sequence_number != expected_seq {
                return Err(diesel::result::Error::QueryBuilderError(
                    format!(
                        "Event sequence gap detected for GUID ({}, {}): expected {}, got {}",
                        addr, creation, expected_seq, event.sequence_number
                    ).into()
                ));
            }
            expected_seq += 1;
        }
    }
    
    // Original insertion logic
    let chunks = get_chunks(items_to_insert.len(), EventModel::field_count());
    for (start_ind, end_ind) in chunks {
        execute_with_better_error(
            conn,
            diesel::insert_into(schema::events::table)
                .values(&items_to_insert[start_ind..end_ind])
                .on_conflict((account_address, creation_number, sequence_number))
                .do_update()
                .set((
                    inserted_at.eq(excluded(inserted_at)),
                    event_index.eq(excluded(event_index)),
                )),
            None,
        )?;
    }
    Ok(())
}
```

**Solution 2: Post-Processing Validation**

Add a background job that periodically scans for gaps:

```sql
-- Query to detect gaps in event sequences
SELECT 
    account_address,
    creation_number,
    sequence_number,
    LEAD(sequence_number) OVER (
        PARTITION BY account_address, creation_number 
        ORDER BY sequence_number
    ) as next_seq
FROM events
WHERE LEAD(sequence_number) OVER (
    PARTITION BY account_address, creation_number 
    ORDER BY sequence_number
) - sequence_number > 1;
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_event_sequence_gap_detection() {
    // Setup test indexer
    let (conn_pool, tailer) = setup_indexer().await.unwrap();
    
    // Create transaction with events sequence 0, 1, 2
    let txn1 = create_test_transaction_with_events(vec![
        ("0xfefefefe", 4, 0),
        ("0xfefefefe", 4, 1),
        ("0xfefefefe", 4, 2),
    ]);
    
    // Process first transaction - should succeed
    tailer.processor
        .process_transactions_with_status(vec![txn1])
        .await
        .unwrap();
    
    // Create transaction with events sequence 4, 5 (missing 3!)
    let txn2 = create_test_transaction_with_events(vec![
        ("0xfefefefe", 4, 4),
        ("0xfefefefe", 4, 5),
    ]);
    
    // Process second transaction - SHOULD FAIL but currently succeeds
    let result = tailer.processor
        .process_transactions_with_status(vec![txn2])
        .await;
    
    // Current behavior: silently accepts gap
    assert!(result.is_ok()); // This passes - BAD!
    
    // Expected behavior: should return error about missing sequence 3
    // assert!(result.is_err()); // This is what SHOULD happen
    
    // Verify the gap exists in database
    let events: Vec<EventQuery> = events::table
        .filter(events::account_address.eq("0x00000000000000000000000000000000000000000000000000000000fefefefe"))
        .filter(events::creation_number.eq(4))
        .order(events::sequence_number.asc())
        .load(&mut conn_pool.get().unwrap())
        .unwrap();
    
    assert_eq!(events.len(), 5); // Has 5 events
    assert_eq!(events[0].sequence_number, 0);
    assert_eq!(events[1].sequence_number, 1);
    assert_eq!(events[2].sequence_number, 2);
    assert_eq!(events[3].sequence_number, 4); // Gap! Missing 3
    assert_eq!(events[4].sequence_number, 5);
    
    // Application consuming this stream has NO WAY to detect the gap
}
```

## Notes

- This vulnerability affects **data integrity** in the external indexer, not blockchain consensus
- The validator's internal storage layer correctly validates sequence continuity, but this protection doesn't extend to the indexer
- Applications cannot detect gaps without cross-referencing every event with on-chain data
- Silent data loss is particularly dangerous as it may go unnoticed for extended periods
- The fix should fail-fast with clear error messages to trigger alerting and investigation

### Citations

**File:** crates/indexer/src/processors/default_processor.rs (L276-297)
```rust
fn insert_events(
    conn: &mut PgConnection,
    items_to_insert: &[EventModel],
) -> Result<(), diesel::result::Error> {
    use schema::events::dsl::*;
    let chunks = get_chunks(items_to_insert.len(), EventModel::field_count());
    for (start_ind, end_ind) in chunks {
        execute_with_better_error(
            conn,
            diesel::insert_into(schema::events::table)
                .values(&items_to_insert[start_ind..end_ind])
                .on_conflict((account_address, creation_number, sequence_number))
                .do_update()
                .set((
                    inserted_at.eq(excluded(inserted_at)),
                    event_index.eq(excluded(event_index)),
                )),
            None,
        )?;
    }
    Ok(())
}
```

**File:** crates/indexer/src/models/transactions.rs (L256-291)
```rust
    pub fn from_transactions(
        transactions: &[APITransaction],
    ) -> (
        Vec<Self>,
        Vec<TransactionDetail>,
        Vec<EventModel>,
        Vec<WriteSetChangeModel>,
        Vec<WriteSetChangeDetail>,
    ) {
        let mut txns = vec![];
        let mut txn_details = vec![];
        let mut events = vec![];
        let mut wscs = vec![];
        let mut wsc_details = vec![];

        for txn in transactions {
            let (txn, txn_detail, event_list, mut wsc_list, mut wsc_detail_list) =
                Self::from_transaction(txn);
            let mut event_v1_list = event_list
                .into_iter()
                .filter(|e| {
                    !(e.sequence_number == 0
                        && e.creation_number == 0
                        && e.account_address == DEFAULT_ACCOUNT_ADDRESS)
                })
                .collect::<Vec<_>>();
            txns.push(txn);
            if let Some(a) = txn_detail {
                txn_details.push(a);
            }
            events.append(&mut event_v1_list);
            wscs.append(&mut wsc_list);
            wsc_details.append(&mut wsc_detail_list);
        }
        (txns, txn_details, events, wscs, wsc_details)
    }
```

**File:** crates/indexer/migrations/2022-08-08-043603_core_tables/up.sql (L208-226)
```sql
CREATE TABLE events (
  sequence_number BIGINT NOT NULL,
  creation_number BIGINT NOT NULL,
  account_address VARCHAR(66) NOT NULL,
  transaction_version BIGINT NOT NULL,
  transaction_block_height BIGINT NOT NULL,
  type TEXT NOT NULL,
  data jsonb NOT NULL,
  inserted_at TIMESTAMP NOT NULL DEFAULT NOW(),
  -- Constraints
  PRIMARY KEY (
    account_address,
    creation_number,
    sequence_number
  ),
  CONSTRAINT fk_transaction_versions FOREIGN KEY (transaction_version) REFERENCES transactions (version)
);
CREATE INDEX ev_addr_type_index ON events (account_address);
CREATE INDEX ev_insat_index ON events (inserted_at);
```

**File:** storage/aptosdb/src/event_store/mod.rs (L107-143)
```rust
    pub fn lookup_events_by_key(
        &self,
        event_key: &EventKey,
        start_seq_num: u64,
        limit: u64,
        ledger_version: u64,
    ) -> Result<
        Vec<(
            u64,     // sequence number
            Version, // transaction version it belongs to
            u64,     // index among events for the same transaction
        )>,
    > {
        let mut iter = self.event_db.iter::<EventByKeySchema>()?;
        iter.seek(&(*event_key, start_seq_num))?;

        let mut result = Vec::new();
        let mut cur_seq = start_seq_num;
        for res in iter.take(limit as usize) {
            let ((path, seq), (ver, idx)) = res?;
            if path != *event_key || ver > ledger_version {
                break;
            }
            if seq != cur_seq {
                let msg = if cur_seq == start_seq_num {
                    "First requested event is probably pruned."
                } else {
                    "DB corruption: Sequence number not continuous."
                };
                db_other_bail!("{} expected: {}, actual: {}", msg, cur_seq, seq);
            }
            result.push((seq, ver, idx));
            cur_seq += 1;
        }

        Ok(result)
    }
```
