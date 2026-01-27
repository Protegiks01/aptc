# Audit Report

## Title
Indexer Denial of Service via Unsafe Event Deserialization with .unwrap()

## Summary
The token processor contains multiple unsafe `.unwrap()` calls when deserializing event data from blockchain transactions. If event data fails to deserialize into expected Rust struct formats, the indexer will panic and crash, causing a complete denial of service for all indexer-dependent infrastructure.

## Finding Description

The vulnerability exists in the token event processing pipeline where event data deserialization uses unsafe `.unwrap()` calls that will panic on any deserialization failure.

**Critical Code Locations:** [1](#0-0) [2](#0-1) [3](#0-2) 

The vulnerability chain works as follows:

1. **Event Storage**: Events are stored in the database with arbitrary JSON data in the `data` field (Jsonb type) [4](#0-3) 

2. **Deserialization Chain**: When processing events, the code calls `BurnEvent::from_event()` or `TransferEvent::from_event()`, which internally call `V2TokenEvent::from_event().unwrap()`

3. **Panic on Failure**: `V2TokenEvent::from_event()` returns `Result<Option<Self>>` and can fail if `serde_json::from_value()` fails: [5](#0-4) 

4. **Crash Propagation**: The `.unwrap()` call causes a panic that crashes the entire indexer process

**Attack Scenarios:**

1. **Module Version Mismatch**: On-chain Move modules are upgraded with new/modified event struct fields, but the indexer runs with old struct definitions. When new events are emitted, deserialization fails.

2. **Database State Corruption**: Any corruption in the `events` table's `data` field will trigger crashes when those events are reprocessed.

3. **Type System Edge Cases**: Move's type system may allow variations in event structure that the rigid Rust deserializer cannot handle (e.g., optional fields becoming required, type changes, field reordering).

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria:

- **API Crashes**: The indexer feeds the REST API. Indexer failure causes API service degradation or complete unavailability.
- **Validator Node Slowdowns**: The indexer is part of validator infrastructure. Repeated crashes require manual intervention and restart cycles.
- **Significant Protocol Violations**: The indexer is expected to process all blockchain events deterministically. Crashing on certain events violates this guarantee.

**Affected Components:**
- Token indexing completely halted
- API queries for token data fail
- NFT explorers and marketplaces lose data
- Analytics dashboards become stale
- All downstream services dependent on indexed token data

The crash is non-recoverable without either:
1. Fixing the code and redeploying
2. Manual database intervention to remove/fix malformed events
3. Skipping problematic transactions (breaks completeness guarantee)

## Likelihood Explanation

**Medium-to-High Likelihood:**

1. **Module Upgrades**: Move modules can be upgraded through governance. If event structures change and indexer code isn't updated synchronously, crashes are inevitable. This is a routine operational scenario.

2. **Database Operations**: Large-scale database operations (backups, migrations, replication) can introduce data integrity issues that manifest as deserialization failures.

3. **Edge Cases in Production**: With hundreds of millions of transactions, rare edge cases in event formatting are statistically likely to occur.

4. **Multiple Vulnerability Sites**: The same unsafe pattern appears in 9+ locations in the token processor alone: [6](#0-5) 

## Recommendation

Replace all `.unwrap()` calls with proper error handling that logs errors and continues processing rather than crashing:

```rust
// BEFORE (vulnerable):
if let Some(burn_event) = BurnEvent::from_event(event, txn_version).unwrap() {
    tokens_burned.insert(burn_event.get_token_address());
}

// AFTER (safe):
match BurnEvent::from_event(event, txn_version) {
    Ok(Some(burn_event)) => {
        tokens_burned.insert(burn_event.get_token_address());
    },
    Ok(None) => {
        // Event type didn't match, continue
    },
    Err(e) => {
        aptos_logger::error!(
            transaction_version = txn_version,
            event_type = event.typ.to_string(),
            error = ?e,
            "Failed to deserialize BurnEvent, skipping"
        );
        // Continue processing, don't crash
    }
}
```

Apply this pattern to all deserialization call sites. Additionally:

1. Add metrics/alerts for deserialization failures
2. Implement graceful degradation (skip problematic events)
3. Add integration tests with malformed event data
4. Document expected event schemas and version compatibility

## Proof of Concept

```rust
// Reproduction test showing the crash
#[test]
#[should_panic(expected = "called `Result::unwrap()` on an `Err` value")]
fn test_burn_event_malformed_data_causes_panic() {
    use aptos_api_types::{Event, EventGuid, MoveType, U64};
    use serde_json::json;
    
    // Create event with malformed data (missing required 'token' field)
    let malformed_event = Event {
        guid: EventGuid {
            creation_number: U64::from(0),
            account_address: "0x1".parse().unwrap(),
        },
        sequence_number: U64::from(0),
        typ: MoveType::from_str("0x4::collection::BurnEvent").unwrap(),
        data: json!({
            "index": "0",
            // Missing 'token' field - will cause deserialization to fail
        }),
    };
    
    // This will panic due to .unwrap() on Err result
    let _ = BurnEvent::from_event(&malformed_event, 1).unwrap();
}
```

**Real-world trigger**: Deploy a governance proposal to upgrade the `0x4::collection` module with a modified `BurnEvent` struct (add/remove fields). After upgrade approval and execution, any transaction emitting the new event format will crash the indexer if it hasn't been updated with matching struct definitions.

---

## Notes

The vulnerability stems from a systemic pattern of unsafe error handling rather than a single code defect. The same `.unwrap()` pattern appears throughout the indexer codebase, suggesting this is a widespread robustness issue. While the Move VM and API layer provide some protection through type validation, the rigid struct-based deserialization in the indexer creates a fragile system that cannot tolerate any schema evolution or unexpected data formats.

### Citations

**File:** crates/indexer/src/models/token_models/v2_token_utils.rs (L355-364)
```rust
    pub fn from_event(event: &Event, txn_version: i64) -> anyhow::Result<Option<Self>> {
        let event_type = event.typ.to_string();
        if let Some(V2TokenEvent::BurnEvent(inner)) =
            V2TokenEvent::from_event(event_type.as_str(), &event.data, txn_version).unwrap()
        {
            Ok(Some(inner))
        } else {
            Ok(None)
        }
    }
```

**File:** crates/indexer/src/models/token_models/v2_token_utils.rs (L379-388)
```rust
    pub fn from_event(event: &Event, txn_version: i64) -> anyhow::Result<Option<Self>> {
        let event_type = event.typ.to_string();
        if let Some(V2TokenEvent::TransferEvent(inner)) =
            V2TokenEvent::from_event(event_type.as_str(), &event.data, txn_version).unwrap()
        {
            Ok(Some(inner))
        } else {
            Ok(None)
        }
    }
```

**File:** crates/indexer/src/models/token_models/v2_token_utils.rs (L514-538)
```rust
impl V2TokenEvent {
    pub fn from_event(
        data_type: &str,
        data: &serde_json::Value,
        txn_version: i64,
    ) -> Result<Option<Self>> {
        match data_type {
            "0x4::collection::MintEvent" => {
                serde_json::from_value(data.clone()).map(|inner| Some(Self::MintEvent(inner)))
            },
            "0x4::token::MutationEvent" => serde_json::from_value(data.clone())
                .map(|inner| Some(Self::TokenMutationEvent(inner))),
            "0x4::collection::BurnEvent" => {
                serde_json::from_value(data.clone()).map(|inner| Some(Self::BurnEvent(inner)))
            },
            "0x1::object::TransferEvent" => {
                serde_json::from_value(data.clone()).map(|inner| Some(Self::TransferEvent(inner)))
            },
            _ => Ok(None),
        }
        .context(format!(
            "version {} failed! failed to parse type {}, data {:?}",
            txn_version, data_type, data
        ))
    }
```

**File:** crates/indexer/src/processors/token_processor.rs (L1135-1210)
```rust
                            aggregated_data.aptos_collection = Some(aptos_collection);
                        }
                        if let Some(property_map) =
                            PropertyMap::from_write_resource(wr, txn_version).unwrap()
                        {
                            aggregated_data.property_map = Some(property_map);
                        }
                        if let Some(token) = TokenV2::from_write_resource(wr, txn_version).unwrap()
                        {
                            aggregated_data.token = Some(token);
                        }
                        if let Some(fungible_asset_metadata) =
                            FungibleAssetMetadata::from_write_resource(wr, txn_version).unwrap()
                        {
                            aggregated_data.fungible_asset_metadata = Some(fungible_asset_metadata);
                        }
                        if let Some(fungible_asset_supply) =
                            FungibleAssetSupply::from_write_resource(wr, txn_version).unwrap()
                        {
                            aggregated_data.fungible_asset_supply = Some(fungible_asset_supply);
                        }
                        if let Some(fungible_asset_store) =
                            FungibleAssetStore::from_write_resource(wr, txn_version).unwrap()
                        {
                            aggregated_data.fungible_asset_store = Some(fungible_asset_store);
                        }
                    }
                }
            }

            // Pass through events to get the burn events and token activities v2
            // This needs to be here because we need the metadata above for token activities
            // and burn / transfer events need to come before the next section
            for (index, event) in user_txn.events.iter().enumerate() {
                if let Some(burn_event) = BurnEvent::from_event(event, txn_version).unwrap() {
                    tokens_burned.insert(burn_event.get_token_address());
                }
                if let Some(transfer_event) = TransferEvent::from_event(event, txn_version).unwrap()
                {
                    if let Some(aggregated_data) =
                        token_v2_metadata_helper.get_mut(&transfer_event.get_object_address())
                    {
                        // we don't want index to be 0 otherwise we might have collision with write set change index
                        let index = if index == 0 {
                            user_txn.events.len()
                        } else {
                            index
                        };
                        aggregated_data.transfer_event = Some((index as i64, transfer_event));
                    }
                }
                // handling all the token v1 events
                if let Some(event) = TokenActivityV2::get_v1_from_parsed_event(
                    event,
                    txn_version,
                    txn_timestamp,
                    index as i64,
                    &entry_function_id_str,
                )
                .unwrap()
                {
                    token_activities_v2.push(event);
                }
                // handling token v2 nft events
                if let Some(event) = TokenActivityV2::get_nft_v2_from_parsed_event(
                    event,
                    txn_version,
                    txn_timestamp,
                    index as i64,
                    &entry_function_id_str,
                    &token_v2_metadata_helper,
                )
                .unwrap()
                {
                    token_activities_v2.push(event);
                }
```

**File:** crates/indexer/src/schema.rs (L509-522)
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
}
```
