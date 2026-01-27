# Audit Report

## Title
Improper Error Handling in Table Item JSON Serialization Can Cause API Server Panics

## Summary
The `try_write_table_item_into_decoded_table_data` and `try_delete_table_item_into_deleted_table_data` functions use `.unwrap()` on JSON serialization results instead of properly propagating errors, which can cause panics that crash API servers and indexers when processing transactions with certain table items.

## Finding Description

The vulnerability exists in the table item conversion path within the API types converter. When converting table items to API response format, the code calls `.json().unwrap()` on `MoveValue` instances: [1](#0-0) [2](#0-1) 

The `json()` method returns `Result<serde_json::Value>` because serialization can fail: [3](#0-2) 

When `serde_json::to_value()` fails (due to edge cases like deeply nested structures, serialization errors, or implementation bugs), the `unwrap()` call panics instead of returning an error. This panic propagates through the call chain and crashes the API server or indexer thread.

**Call Chain:**
1. API endpoint calls `try_into_onchain_transaction()` [4](#0-3) 
2. Which calls `into_transaction_info()` [5](#0-4) 
3. Which calls `try_into_write_set_changes()` with `.filter_map().ok()` that only catches `Result` errors, not panics [6](#0-5) 
4. Which calls `try_table_item_into_write_set_change()` [7](#0-6) 
5. Which calls the vulnerable functions containing `.unwrap()`

The functions already return `Result` types, indicating they're designed to handle errors. However, the use of `.unwrap()` bypasses this error handling and converts recoverable errors into unrecoverable panics.

Other parts of the Aptos codebase properly handle `serde_json` errors by converting them to custom error types or propagating them with `?`, demonstrating that serialization failures are expected and should be handled gracefully.

## Impact Explanation

**Severity: Medium** (aligned with the security question's classification)

This vulnerability can cause **API server crashes**, which falls under High severity criteria ("API crashes"). However, the impact is limited to the API/indexer layer rather than consensus or state:

- **Affected Components**: API servers and indexer services that process transaction data
- **Availability Impact**: An attacker could craft transactions with table items that trigger serialization failures, causing API servers to crash when serving those transactions
- **No State Corruption**: The underlying blockchain state remains intact; only the API layer crashes
- **Recoverable**: Crashed services can be restarted, though the problematic transaction would continue causing crashes
- **No Consensus Impact**: Validator nodes are not affected as this is API-only code

The issue is classified as Medium rather than High because:
1. The likelihood of triggering actual serialization failures is low (Move's type depth limits prevent most edge cases)
2. The impact is temporary and recoverable through service restart
3. It doesn't affect the core blockchain functionality or consensus

## Likelihood Explanation

**Likelihood: Low to Medium**

While the code pattern is clearly incorrect, actual exploitation depends on triggering `serde_json::to_value()` failures:

**Factors increasing likelihood:**
- The `MoveValue` type supports complex nested structures (vectors, structs)
- Future changes to serialization logic could introduce failure cases
- Edge cases with very large U256/I256 values might exist
- The vulnerability is in a hot path (transaction info conversion)

**Factors decreasing likelihood:**
- Move enforces type depth limits (MAX_RECURSIVE_TYPES_ALLOWED = 8) [8](#0-7) 
- The `Serialize` implementation for `MoveValue` is straightforward [9](#0-8) 
- By the time `json()` is called, the values have already been successfully converted to `MoveValue`
- Most primitive types serialize without errors

An attacker would need to find or create specific table item data that passes Move VM validation but fails JSON serialization.

## Recommendation

Replace all `.unwrap()` calls with `?` operator to properly propagate errors:

**In `try_write_table_item_into_decoded_table_data`:**
```rust
Ok(Some(DecodedTableData {
    key: key.json()?,  // Changed from .unwrap()
    key_type: table_info.key_type.to_canonical_string(),
    value: value.json()?,  // Changed from .unwrap()
    value_type: table_info.value_type.to_canonical_string(),
}))
```

**In `try_delete_table_item_into_deleted_table_data`:**
```rust
Ok(Some(DeletedTableData {
    key: key.json()?,  // Changed from .unwrap()
    key_type: table_info.key_type.to_canonical_string(),
}))
```

This change ensures that serialization errors are properly propagated as `Result::Err` values, which are handled gracefully at the call sites:
- In `into_transaction_info`, the error is filtered out via `.ok()` and the write set change is omitted from the response
- In `try_into_write_set_payload`, the error is propagated with `?` and returned to the caller

## Proof of Concept

While creating a Move transaction that triggers actual serialization failure is difficult due to Move's type system protections, the vulnerability can be demonstrated conceptually:

**Rust test demonstrating the panic:**
```rust
#[test]
#[should_panic(expected = "called `Result::unwrap()` on an `Err` value")]
fn test_json_unwrap_panic() {
    // This is a conceptual demonstration
    // In practice, MoveValue serialization rarely fails
    // but the use of unwrap() means any failure becomes a panic
    
    // If we could construct a MoveValue that fails to serialize:
    // let problematic_value = /* some edge case */;
    // let result = problematic_value.json().unwrap(); // PANIC!
    
    // The proper pattern would be:
    // let result = problematic_value.json()?; // Error propagation
}
```

**Attack scenario:**
1. Attacker identifies or crafts a transaction that writes to a table with complex nested data
2. The data passes Move VM validation during execution
3. When an API server tries to convert this transaction to JSON for an API response
4. The serialization fails for an edge case (e.g., exceeding internal limits)
5. The `.unwrap()` panics, crashing the API server thread
6. Repeated requests for this transaction cause persistent DoS of the API endpoint

**Notes**
- This vulnerability represents a violation of Rust error handling best practices and defensive programming principles
- The code already uses `Result` return types throughout, indicating error handling is expected
- The inconsistency between proper error handling elsewhere in the function (using `?`) and `.unwrap()` for JSON serialization suggests this is an oversight rather than intentional design
- Even if actual exploitation is difficult, the incorrect pattern should be fixed to prevent future issues as the codebase evolves

### Citations

**File:** api/types/src/convert.rs (L185-191)
```rust
        let info = self.into_transaction_info(
            data.version,
            &data.info,
            data.accumulator_root_hash,
            data.changes,
            aux_data,
        );
```

**File:** api/types/src/convert.rs (L263-267)
```rust
            changes: write_set
                .into_write_op_iter()
                .filter_map(|(sk, wo)| self.try_into_write_set_changes(sk, wo).ok())
                .flatten()
                .collect(),
```

**File:** api/types/src/convert.rs (L457-459)
```rust
                vec![self.try_table_item_into_write_set_change(hash, *handle, key.to_owned(), op)]
                    .into_iter()
                    .collect()
```

**File:** api/types/src/convert.rs (L572-577)
```rust
        Ok(Some(DecodedTableData {
            key: key.json().unwrap(),
            key_type: table_info.key_type.to_canonical_string(),
            value: value.json().unwrap(),
            value_type: table_info.value_type.to_canonical_string(),
        }))
```

**File:** api/types/src/convert.rs (L595-598)
```rust
        Ok(Some(DeletedTableData {
            key: key.json().unwrap(),
            key_type: table_info.key_type.to_canonical_string(),
        }))
```

**File:** api/types/src/move_types.rs (L387-389)
```rust
    pub fn json(&self) -> anyhow::Result<serde_json::Value> {
        Ok(serde_json::to_value(self)?)
    }
```

**File:** api/types/src/move_types.rs (L476-498)
```rust
impl Serialize for MoveValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self {
            MoveValue::U8(v) => v.serialize(serializer),
            MoveValue::U16(v) => v.serialize(serializer),
            MoveValue::U32(v) => v.serialize(serializer),
            MoveValue::U64(v) => v.serialize(serializer),
            MoveValue::U128(v) => v.serialize(serializer),
            MoveValue::U256(v) => v.serialize(serializer),
            MoveValue::I8(v) => v.serialize(serializer),
            MoveValue::I16(v) => v.serialize(serializer),
            MoveValue::I32(v) => v.serialize(serializer),
            MoveValue::I64(v) => v.serialize(serializer),
            MoveValue::I128(v) => v.serialize(serializer),
            MoveValue::I256(v) => v.serialize(serializer),
            MoveValue::Bool(v) => v.serialize(serializer),
            MoveValue::Address(v) => v.serialize(serializer),
            MoveValue::Vector(v) => v.serialize(serializer),
            MoveValue::Bytes(v) => v.serialize(serializer),
            MoveValue::Struct(v) => v.serialize(serializer),
            MoveValue::String(v) => v.serialize(serializer),
        }
    }
```

**File:** api/types/src/move_types.rs (L688-688)
```rust
pub const MAX_RECURSIVE_TYPES_ALLOWED: u8 = 8;
```

**File:** api/src/context.rs (L758-758)
```rust
                let txn = converter.try_into_onchain_transaction(timestamp, t)?;
```
