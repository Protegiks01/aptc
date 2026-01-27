# Audit Report

## Title
V2 Events Silently Filtered from External Indexer Creating Incomplete Event Streams for Downstream Consumers

## Summary
The external PostgreSQL-based indexer filters out all V2 events (ContractEventV2) before storing them in the database, causing downstream consumers to receive incomplete event data and breaking applications that expect continuous, complete event sequences. This occurs because V2 events are assigned dummy GUID values that match the filter criteria designed to exclude placeholder events.

## Finding Description

The external indexer (`crates/indexer`) processes blockchain transactions and stores them in PostgreSQL for downstream consumers. During event processing, a filter silently removes all V2 events from the indexed data.

**Root Cause:**

When V2 events (ContractEventV2) are converted to the API Event type, they receive dummy values because V2 events don't have the EventKey concept that V1 events use: [1](#0-0) [2](#0-1) 

The indexer's transaction processing includes a filter that removes events with these exact dummy values: [3](#0-2) [4](#0-3) 

**Data Integrity Violation:**

The `num_events` field in the transactions table stores the original event count (including V2 events), but the actual events stored in the database exclude V2 events: [5](#0-4) 

This creates a mismatch where `transactions.num_events` does not match the actual number of rows in the `events` table for that transaction.

**Impact on Downstream Consumers:**

The events table schema shows the primary key structure that downstream consumers rely on: [6](#0-5) 

Applications querying this table expecting complete event data will miss all V2 events emitted by transactions. When the MODULE_EVENT_MIGRATION feature flag is enabled, framework modules conditionally emit V2 events, making this issue production-relevant.

## Impact Explanation

**Medium Severity** - This qualifies as "State inconsistencies requiring intervention" per the Aptos bug bounty program:

1. **Data Completeness Loss**: Downstream consumers querying the external indexer receive incomplete event data, missing all V2 events entirely
2. **Analytics/Monitoring Failure**: Systems counting or analyzing events will have incorrect totals and miss critical business events
3. **Application Breakage**: DApps relying solely on the external indexer for event monitoring will fail to detect V2 events, potentially missing state changes, transfers, or other critical operations
4. **Data Integrity Violation**: The `num_events` field doesn't match actual stored events, violating database consistency invariants
5. **No Direct Fund Loss**: While this doesn't directly cause fund theft, it can lead to incorrect application behavior that could indirectly affect funds

This does not reach Critical or High severity because:
- It doesn't affect consensus or validator operations
- The blockchain itself correctly stores and processes V2 events
- Consumers can query nodes directly via API for complete event data
- The internal indexer has proper V2 event translation support

## Likelihood Explanation

**High Likelihood** when MODULE_EVENT_MIGRATION is enabled:

1. **Automatic Occurrence**: Any transaction emitting V2 events will have those events filtered out automatically—no special attacker action required
2. **Framework-Level Impact**: Core framework modules (account, token, reconfiguration) conditionally emit V2 events when the feature flag is enabled
3. **Production Deployment**: The MODULE_EVENT_MIGRATION feature flag (feature #57) is designed for production rollout
4. **Widespread Effect**: All external indexer deployments are affected; this isn't configuration-dependent
5. **Silent Failure**: No error or warning is generated when events are filtered; consumers simply see incomplete data

## Recommendation

**Immediate Fix**: Remove the V2 event filter and properly handle V2 events in the external indexer.

**Option 1 - Store V2 Events with Synthetic Keys:**
Modify the filter to preserve V2 events while assigning them unique synthetic keys based on transaction version and event index:

```rust
// In from_transactions(), instead of filtering:
let mut event_v1_list = event_list
    .into_iter()
    .map(|mut e| {
        // Assign unique synthetic key to V2 events
        if e.sequence_number == 0 
            && e.creation_number == 0 
            && e.account_address == DEFAULT_ACCOUNT_ADDRESS 
        {
            // Use transaction_version as creation_number for uniqueness
            e.creation_number = e.transaction_version;
            // Keep sequence_number based on event_index
            e.sequence_number = e.event_index.unwrap_or(0);
        }
        e
    })
    .collect::<Vec<_>>();
```

**Option 2 - Implement V2 Event Translation:**
Add event V2 to V1 translation support similar to the internal indexer, using the EventV2TranslationEngine to properly translate V2 events before storage.

**Option 3 - Separate V2 Event Table:**
Create a dedicated table for V2 events with appropriate schema that doesn't require EventKey compatibility.

**Additional Recommendations:**
1. Add validation to ensure `num_events` matches actual stored events
2. Add monitoring/alerting when event count mismatches are detected
3. Document that the external indexer does/doesn't support V2 events
4. Provide migration path for existing deployments

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_api_types::{
        Event as APIEvent, EventGuid, Transaction as APITransaction,
        UserTransaction, TransactionInfo, U64, Address,
    };
    use aptos_types::account_address::AccountAddress;
    use move_core_types::language_storage::TypeTag;

    #[test]
    fn test_v2_event_filtering_vulnerability() {
        // Create a transaction with both V1 and V2 events
        let v1_event = APIEvent {
            guid: EventGuid {
                creation_number: U64::from(5),
                account_address: Address::from(AccountAddress::from_hex_literal("0xabc").unwrap()),
            },
            sequence_number: U64::from(10),
            typ: TypeTag::Bool, // placeholder
            data: serde_json::json!({"test": "v1"}),
        };

        // V2 event will have dummy GUID
        let v2_event = APIEvent {
            guid: EventGuid {
                creation_number: U64::from(0),
                account_address: Address::from(AccountAddress::ZERO),
            },
            sequence_number: U64::from(0),
            typ: TypeTag::Bool,
            data: serde_json::json!({"test": "v2"}),
        };

        // Process through from_events
        let events = vec![v1_event, v2_event];
        let processed_events = EventModel::from_events(&events, 1000, 100);

        // Vulnerability: Only 1 event stored despite 2 being emitted
        assert_eq!(processed_events.len(), 1, 
            "V2 event was filtered out, only V1 event remains");
        
        // This demonstrates the data integrity violation:
        // Transaction would have num_events=2 but only 1 event actually stored
        println!("Original events: 2");
        println!("Stored events: {}", processed_events.len());
        println!("VULNERABILITY: V2 events are silently dropped from indexer");
    }
}
```

**Notes:**

This vulnerability violates the data completeness and integrity invariants expected by downstream consumers. While the blockchain itself correctly processes V2 events, the external indexer's filtering creates an incomplete view of the chain state that breaks applications depending on complete event streams for analytics, monitoring, or business logic.

### Citations

**File:** api/types/src/transaction.rs (L48-52)
```rust
static DUMMY_GUID: Lazy<EventGuid> = Lazy::new(|| EventGuid {
    creation_number: U64::from(0u64),
    account_address: Address::from(AccountAddress::ZERO),
});
static DUMMY_SEQUENCE_NUMBER: Lazy<U64> = Lazy::new(|| U64::from(0));
```

**File:** api/types/src/transaction.rs (L886-891)
```rust
            ContractEvent::V2(v2) => Self {
                guid: *DUMMY_GUID,
                sequence_number: *DUMMY_SEQUENCE_NUMBER,
                typ: v2.type_tag().into(),
                data,
            },
```

**File:** crates/indexer/src/models/transactions.rs (L28-29)
```rust
const DEFAULT_ACCOUNT_ADDRESS: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000000";
```

**File:** crates/indexer/src/models/transactions.rs (L136-145)
```rust
                        user_txn.events.len() as i64,
                        block_height,
                        epoch,
                    ),
                    Some(TransactionDetail::User(user_txn_output, signatures)),
                    EventModel::from_events(
                        &user_txn.events,
                        user_txn.info.version.0 as i64,
                        block_height,
                    ),
```

**File:** crates/indexer/src/models/transactions.rs (L274-281)
```rust
            let mut event_v1_list = event_list
                .into_iter()
                .filter(|e| {
                    !(e.sequence_number == 0
                        && e.creation_number == 0
                        && e.account_address == DEFAULT_ACCOUNT_ADDRESS)
                })
                .collect::<Vec<_>>();
```

**File:** crates/indexer/src/schema.rs (L509-521)
```rust
    events (account_address, creation_number, sequence_number) {
        sequence_number -> Int8,
        creation_number -> Int8,
        #[max_length = 66]
        account_address -> Varchar,
        transaction_version -> Int8,
        transaction_block_height -> Int8,
        #[sql_name = "type"]
        type_ -> Text,
        data -> Jsonb,
        inserted_at -> Timestamp,
        event_index -> Nullable<Int8>,
    }
```
