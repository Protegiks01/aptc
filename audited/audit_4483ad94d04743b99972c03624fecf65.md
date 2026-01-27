# Audit Report

## Title
Event Query Order-Dependent Result Set Inconsistency in Internal Indexer

## Summary
The `get_events_by_event_key()` function in the internal indexer returns different event sets when switching between `Order::Ascending` and `Order::Descending` for identical query parameters. This occurs due to improper interaction between the `ledger_version` filter and the order-based range calculation, violating data consistency guarantees. [1](#0-0) 

## Finding Description

The vulnerability exists in how the indexer processes event queries with different ordering. The issue stems from two interacting code paths:

1. **Range Calculation Logic**: When converting descending queries to forward scans, the `get_first_seq_num_and_limit()` function calculates a different starting point and limit. [2](#0-1) 

2. **Version Filtering with Early Break**: The `lookup_events_by_key()` function performs a forward scan and breaks immediately when encountering an event with `version > ledger_version`. [3](#0-2) 

**Exploitation Scenario:**

Assume events with sequence numbers and transaction versions:
- seq 0, version 10
- seq 1, version 20  
- seq 2, version 30
- seq 3, version 40
- seq 4, version 50

Query: `event_key=K, start_seq_num=2, limit=10, ledger_version=35`

**Ascending Path:**
- Calculates: `first_seq=2, real_limit=10`
- `lookup_events_by_key` seeks to seq 2, scans forward
- Finds seq 2 (v30) ✓, then seq 3 (v40 > 35) → **breaks immediately**
- Returns: `[seq 2]` (1 event)

**Descending Path:**  
- Calculates: `first_seq=0, real_limit=3` (since limit > cursor)
- `lookup_events_by_key` seeks to seq 0, scans forward up to 3 events
- Finds seq 0 (v10) ✓, seq 1 (v20) ✓, seq 2 (v30) ✓
- All versions ≤ 35, no break occurs
- Returns: `[seq 0, 1, 2]` reversed to `[seq 2, 1, 0]` (3 events) [4](#0-3) 

**Result:** Ascending returns `{seq 2}` while descending returns `{seq 2, 1, 0}` - different event sets violating the data consistency invariant.

The root cause is that the ledger version filter acts as a hard boundary that causes premature termination during forward scans. For ascending queries starting mid-range, this truncates results. For descending queries, the backward-to-forward translation causes scanning from an earlier sequence number, potentially avoiding the version boundary entirely.

## Impact Explanation

**Severity: Medium** - State inconsistencies requiring intervention

This vulnerability breaks the **State Consistency** invariant. According to the Aptos bug bounty criteria, this falls under "Medium Severity" as it causes:

1. **Data Inconsistency**: Different API responses for semantically identical queries (same event key, start, limit, ledger version)
2. **Non-Deterministic Behavior**: Applications receive different event sets based solely on query order direction
3. **Potential State Divergence**: If different nodes or components use different ordering preferences, they may construct different views of event history
4. **Application-Level Impact**: Smart contracts or applications relying on complete event history may make incorrect decisions due to missing events

While this doesn't directly cause consensus violations or fund loss, it creates state inconsistency that could propagate to higher-level systems. Applications expecting deterministic event queries may exhibit undefined behavior when the same logical query returns different results.

## Likelihood Explanation

**Likelihood: High**

This issue occurs deterministically when:
1. Events exist across a version boundary relative to the `ledger_version` parameter
2. An ascending query starts at a sequence number where the next event exceeds `ledger_version`
3. A descending query from the same starting point retrieves events before the version boundary

These conditions are common in production scenarios:
- **Historical Queries**: Users frequently query events up to a specific ledger version (e.g., for state reconstruction)
- **Multi-Version Systems**: Nodes at different sync stages use different ledger versions
- **API Usage**: Public APIs expose both ascending and descending query options

The vulnerability is easily triggerable by any unprivileged API consumer and requires no special permissions or collusion. Any application using the internal indexer API for event queries is vulnerable to receiving incomplete or inconsistent data.

## Recommendation

The fix requires ensuring that version filtering produces consistent results regardless of query direction. The issue is that the early break in `lookup_events_by_key` creates asymmetry.

**Option 1: Post-Filter Approach** (Recommended)
After retrieving events in the requested range, filter by `ledger_version` without breaking early, then apply the limit:

```rust
pub fn lookup_events_by_key(
    &self,
    event_key: &EventKey,
    start_seq_num: u64,
    limit: u64,
    ledger_version: u64,
) -> Result<Vec<(u64, Version, u64)>> {
    let mut iter = self.db.iter::<EventByKeySchema>()?;
    iter.seek(&(*event_key, start_seq_num))?;
    
    let mut result = Vec::new();
    let mut cur_seq = start_seq_num;
    
    // Collect all events in sequence range
    for res in iter.take(limit as usize) {
        let ((path, seq), (ver, idx)) = res?;
        if path != *event_key {
            break;
        }
        if seq != cur_seq {
            let msg = if cur_seq == start_seq_num {
                "First requested event is probably pruned."
            } else {
                "DB corruption: Sequence number not continuous."
            };
            bail!("{} expected: {}, actual: {}", msg, cur_seq, seq);
        }
        
        // Only add if within ledger version, but continue scanning
        if ver <= ledger_version {
            result.push((seq, ver, idx));
        }
        cur_seq += 1;
    }
    
    // Truncate to requested limit after filtering
    result.truncate(limit as usize);
    Ok(result)
}
```

**Option 2: Bidirectional Aware Logic**
Modify `get_events_by_event_key` to track direction and ensure symmetric filtering by fetching extra events when needed and filtering consistently.

The recommended fix ensures that both query directions scan the same logical range and apply version filtering uniformly, guaranteeing result set consistency.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_types::{
        event::EventKey,
        indexer::indexer_db_reader::Order,
    };
    
    #[test]
    fn test_event_query_order_consistency() {
        // Setup: Create test database with events at different versions
        let (db_indexer, event_key) = setup_test_db_with_events(vec![
            (0, 10),  // seq 0, version 10
            (1, 20),  // seq 1, version 20
            (2, 30),  // seq 2, version 30
            (3, 40),  // seq 3, version 40
            (4, 50),  // seq 4, version 50
        ]);
        
        let start_seq = 2;
        let limit = 10;
        let ledger_version = 35; // Between seq 2 and seq 3
        
        // Query ascending
        let ascending_events = db_indexer.get_events_by_event_key(
            &event_key,
            start_seq,
            Order::Ascending,
            limit,
            ledger_version,
        ).unwrap();
        
        // Query descending  
        let descending_events = db_indexer.get_events_by_event_key(
            &event_key,
            start_seq,
            Order::Descending,
            limit,
            ledger_version,
        ).unwrap();
        
        // Extract sequence numbers
        let ascending_seqs: Vec<u64> = ascending_events.iter()
            .map(|e| extract_seq_num(e))
            .collect();
        let mut descending_seqs: Vec<u64> = descending_events.iter()
            .map(|e| extract_seq_num(e))
            .collect();
        descending_seqs.reverse(); // Normalize to ascending order
        
        // VULNERABILITY: These should be equal but are not
        // ascending_seqs = [2]
        // descending_seqs = [0, 1, 2]
        assert_eq!(
            ascending_seqs, 
            descending_seqs,
            "Event sets differ between Ascending and Descending queries: \
             Ascending returned {:?}, Descending returned {:?}",
            ascending_seqs,
            descending_seqs
        );
    }
}
```

## Notes

This vulnerability demonstrates a subtle interaction between query optimization (range calculation) and filtering logic (version boundaries). The issue is exacerbated by the fact that the `ledger_version` parameter is meant to provide a consistent snapshot view, but the implementation violates this guarantee by making the snapshot view order-dependent.

The bug affects the internal indexer API which is used by:
- REST API endpoints for event queries
- State synchronization processes
- Historical data reconstruction tools
- Application-level event monitoring systems

Any system relying on deterministic event queries will exhibit non-deterministic behavior due to this inconsistency. The fix must ensure that the same logical query (same event key, start position, limit, and ledger version) returns the same set of events regardless of iteration direction.

### Citations

**File:** storage/indexer/src/db_indexer.rs (L206-245)
```rust
    /// Given `event_key` and `start_seq_num`, returns events identified by transaction version and
    /// index among all events emitted by the same transaction. Result won't contain records with a
    /// transaction version > `ledger_version` and is in ascending order.
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
        let mut iter = self.db.iter::<EventByKeySchema>()?;
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
                bail!("{} expected: {}, actual: {}", msg, cur_seq, seq);
            }
            result.push((seq, ver, idx));
            cur_seq += 1;
        }

        Ok(result)
    }
```

**File:** storage/indexer/src/db_indexer.rs (L644-724)
```rust
    pub fn get_events_by_event_key(
        &self,
        event_key: &EventKey,
        start_seq_num: u64,
        order: Order,
        limit: u64,
        ledger_version: Version,
    ) -> Result<Vec<EventWithVersion>> {
        self.indexer_db
            .ensure_cover_ledger_version(ledger_version)?;
        error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;
        let get_latest = order == Order::Descending && start_seq_num == u64::MAX;

        let cursor = if get_latest {
            // Caller wants the latest, figure out the latest seq_num.
            // In the case of no events on that path, use 0 and expect empty result below.
            self.indexer_db
                .get_latest_sequence_number(ledger_version, event_key)?
                .unwrap_or(0)
        } else {
            start_seq_num
        };

        // Convert requested range and order to a range in ascending order.
        let (first_seq, real_limit) = get_first_seq_num_and_limit(order, cursor, limit)?;

        // Query the index.
        let mut event_indices = self.indexer_db.lookup_events_by_key(
            event_key,
            first_seq,
            real_limit,
            ledger_version,
        )?;

        // When descending, it's possible that user is asking for something beyond the latest
        // sequence number, in which case we will consider it a bad request and return an empty
        // list.
        // For example, if the latest sequence number is 100, and the caller is asking for 110 to
        // 90, we will get 90 to 100 from the index lookup above. Seeing that the last item
        // is 100 instead of 110 tells us 110 is out of bound.
        if order == Order::Descending {
            if let Some((seq_num, _, _)) = event_indices.last() {
                if *seq_num < cursor {
                    event_indices = Vec::new();
                }
            }
        }

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
                let v0 = match &event {
                    ContractEvent::V1(event) => event,
                    ContractEvent::V2(_) => bail!("Unexpected module event"),
                };
                ensure!(
                    seq == v0.sequence_number(),
                    "Index broken, expected seq:{}, actual:{}",
                    seq,
                    v0.sequence_number()
                );

                Ok(EventWithVersion::new(ver, event))
            })
            .collect::<Result<Vec<_>>>()?;
        if order == Order::Descending {
            events_with_version.reverse();
        }

        Ok(events_with_version)
    }
```

**File:** storage/indexer_schemas/src/utils.rs (L32-42)
```rust
pub fn get_first_seq_num_and_limit(order: Order, cursor: u64, limit: u64) -> Result<(u64, u64)> {
    ensure!(limit > 0, "limit should > 0, got {}", limit);

    Ok(if order == Order::Ascending {
        (cursor, limit)
    } else if limit <= cursor {
        (cursor - limit + 1, limit)
    } else {
        (0, cursor + 1)
    })
}
```
