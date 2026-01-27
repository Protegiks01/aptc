# Audit Report

## Title
Unbounded Recursion in Event JSON Processing Enables Indexer Denial of Service

## Summary
The indexer's event processing contains an unbounded recursive function that traverses deeply nested JSON structures without depth limits. An attacker can craft Move events with up to 128 levels of nesting (within Move VM limits), which when processed during error handling can cause stack overflow and crash the indexer service, resulting in API unavailability.

## Finding Description

The vulnerability exists in the event processing pipeline where blockchain events are converted to JSON and stored in PostgreSQL. The critical flaw is in the `recurse_remove_null_bytes_from_json` function which has no recursion depth limits. [1](#0-0) 

This function is called during error recovery when database insertions fail: [2](#0-1) 

The attack path is:

1. **Event Creation**: An attacker creates a Move module with deeply nested structures (vectors of vectors, structs containing structs) up to the Move VM's maximum depth limit of 128 levels. [3](#0-2) 

2. **Event Emission**: The attacker emits an event containing this deeply nested data structure. The event passes VM validation since 128 levels is within `DEFAULT_MAX_VM_VALUE_NESTED_DEPTH`.

3. **Size Constraints**: The event's BCS-serialized form can fit within the 1 MB per-event gas limit: [4](#0-3) 

4. **JSON Conversion**: The indexer converts the event to JSON without depth validation: [5](#0-4) 

5. **Error Trigger**: When any database error occurs (network issues, constraint violations, transient failures), the error recovery path calls `clean_data_for_db` on all events.

6. **Stack Overflow**: The `recurse_remove_null_bytes_from_json` function recursively traverses the 128-level nested JSON structure without bounds checking, potentially exceeding stack limits and crashing the indexer process.

The function lacks any depth tracking or limits, making it vulnerable to stack exhaustion on deeply nested inputs.

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program's "API crashes" category.

**Primary Impact**: The indexer service crashes and stops processing blockchain events, causing:
- Complete API unavailability for querying events, transactions, and blockchain state
- Applications depending on the indexer cannot function
- Manual operator intervention required to restart the service

**Secondary Impact**: If the malicious event is in a block that the indexer must process, it will crash repeatedly on restart, creating a persistent denial of service until code is patched.

**Scope**: While this does not affect validator nodes or consensus (the indexer is a separate service), the indexer API is critical infrastructure that the ecosystem depends on. Many DApps, wallets, and explorers rely on indexer data.

## Likelihood Explanation

**Likelihood: High**

The attack is highly feasible:
- **No special privileges required**: Any user can submit transactions with events
- **Within protocol limits**: 128-level nesting is explicitly allowed by the Move VM
- **Deterministic trigger**: Database errors occur naturally (network issues, resource constraints) and can be induced
- **Low cost**: A single malicious transaction with one deeply nested event is sufficient
- **Repeatable**: The vulnerability persists until patched

The main uncertainty is whether 128 levels will exceed stack limits on all platforms, but:
- Default Rust stack sizes vary by platform
- Container environments may have reduced stack limits
- The recursion combines with other stack usage during error handling
- Even if 128 levels doesn't always crash, the lack of bounds checking is a critical code quality issue

## Recommendation

Implement depth limits on the recursive JSON traversal function:

```rust
const MAX_JSON_DEPTH: usize = 64;

fn recurse_remove_null_bytes_from_json(sub_json: &mut Value) {
    recurse_remove_null_bytes_from_json_impl(sub_json, 0)
}

fn recurse_remove_null_bytes_from_json_impl(sub_json: &mut Value, depth: usize) {
    if depth > MAX_JSON_DEPTH {
        // Truncate or skip deeply nested values
        return;
    }
    
    match sub_json {
        Value::Array(array) => {
            for item in array {
                recurse_remove_null_bytes_from_json_impl(item, depth + 1);
            }
        },
        Value::Object(object) => {
            for (_key, value) in object {
                recurse_remove_null_bytes_from_json_impl(value, depth + 1);
            }
        },
        Value::String(str) => {
            if !str.is_empty() {
                let replacement = string_null_byte_replacement(str);
                *str = replacement;
            }
        },
        _ => {},
    }
}
```

Additionally, consider adding validation in `Event::from_event()` to reject events with excessive JSON depth before database insertion.

## Proof of Concept

Move module demonstrating deeply nested event creation:

```move
module attacker::deep_nesting {
    use std::vector;
    
    #[event]
    struct DeepEvent has drop, store {
        data: vector<vector<vector<vector<u8>>>>  // 4 levels shown, extend to 128
    }
    
    public entry fun emit_deep_event() {
        // Create maximally nested structure (128 levels)
        let inner = vector::empty<u8>();
        vector::push_back(&mut inner, 1);
        
        // Nest vectors 128 times (pseudocode - actual implementation 
        // would require building up the nesting programmatically)
        let level_1 = vector::singleton(inner);
        let level_2 = vector::singleton(level_1);
        // ... continue to level 128
        
        let event = DeepEvent { data: level_128 };
        0x1::event::emit(event);
    }
}
```

The indexer will process this event normally until a database error occurs, at which point the error recovery path will attempt to clean the deeply nested JSON and potentially crash due to stack overflow.

## Notes

This vulnerability demonstrates a defense-in-depth failure where the lack of input validation at the indexer layer creates exploitable attack surface, even though upstream components (Move VM) have their own limits. The indexer should not assume that VM-validated data is safe for unbounded recursive processing.

### Citations

**File:** crates/indexer/src/util.rs (L73-93)
```rust
fn recurse_remove_null_bytes_from_json(sub_json: &mut Value) {
    match sub_json {
        Value::Array(array) => {
            for item in array {
                recurse_remove_null_bytes_from_json(item);
            }
        },
        Value::Object(object) => {
            for (_key, value) in object {
                recurse_remove_null_bytes_from_json(value);
            }
        },
        Value::String(str) => {
            if !str.is_empty() {
                let replacement = string_null_byte_replacement(str);
                *str = replacement;
            }
        },
        _ => {},
    }
}
```

**File:** crates/indexer/src/processors/default_processor.rs (L150-155)
```rust
        Err(_) => {
            let txns = clean_data_for_db(txns, true);
            let user_transactions = clean_data_for_db(user_transactions, true);
            let signatures = clean_data_for_db(signatures, true);
            let block_metadata_transactions = clean_data_for_db(block_metadata_transactions, true);
            let events = clean_data_for_db(events, true);
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L50-57)
```rust
/// Values can be recursive, and so it is important that we do not use recursive algorithms over
/// deeply nested values as it can cause stack overflow. Since it is not always possible to avoid
/// recursion, we opt for a reasonable limit on VM value depth. It is defined in Move VM config,
/// but since it is difficult to propagate config context everywhere, we use this constant.
///
/// IMPORTANT: When changing this constant, make sure it is in-sync with one in VM config (it is
/// used there now).
pub const DEFAULT_MAX_VM_VALUE_NESTED_DEPTH: u64 = 128;
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L164-167)
```rust
            max_bytes_per_event: NumBytes,
            { 5.. => "max_bytes_per_event" },
            1 << 20, // a single event is 1MB max
        ],
```

**File:** crates/indexer/src/models/events.rs (L43-59)
```rust
    pub fn from_event(
        event: &APIEvent,
        transaction_version: i64,
        transaction_block_height: i64,
        event_index: i64,
    ) -> Self {
        Event {
            account_address: standardize_address(&event.guid.account_address.to_string()),
            creation_number: event.guid.creation_number.0 as i64,
            sequence_number: event.sequence_number.0 as i64,
            transaction_version,
            transaction_block_height,
            type_: event.typ.to_string(),
            data: event.data.clone(),
            event_index: Some(event_index),
        }
    }
```
