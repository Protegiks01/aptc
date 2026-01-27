# Audit Report

## Title
Indexer Data Corruption via Unchecked u64 to i64 Cast in Event Processing

## Summary
The indexer's `Event::from_event()` function performs unchecked u64 to i64 casts on `creation_number` and `sequence_number` fields. While these casts do **not** panic as claimed in the security question, they **do** cause silent data corruption when values exceed i64::MAX, resulting in negative values being stored in the indexer database.

## Finding Description

The security question incorrectly assumes that u64 to i64 casts panic in debug builds. However, in Rust, the `as` operator for numeric casts **never panics**, even with `overflow-checks = true` enabled in the release profile. [1](#0-0) 

The actual vulnerability is **silent data corruption**. When `event.guid.creation_number.0` or `event.sequence_number.0` contain u64 values ≥ 2^63 (9,223,372,036,854,775,808), the cast wraps these values to negative i64 numbers. For example, 2^63 becomes -9,223,372,036,854,775,808 (i64::MIN).

The `creation_number` and `sequence_number` fields originate from Move's event system: [2](#0-1) [3](#0-2) 

While Move's event emission system increments these counters with overflow checks that abort transactions, there is no validation in the indexer that these values are within i64 range before casting. [4](#0-3) [5](#0-4) 

## Impact Explanation

**Medium Severity** - State inconsistencies requiring intervention.

While the likelihood is extremely low under normal operation (requiring ~9 quintillion events per handle), this represents a **lack of defense-in-depth**. Edge cases that could trigger corruption include:

1. Storage layer corruption or state sync bugs introducing malformed data
2. Future changes to Move VM counter management
3. Genesis/migration scenarios with legacy data
4. Potential Byzantine validator attacks if consensus guarantees are violated

The corrupted data would manifest as negative sequence numbers in the indexer database, causing:
- Query failures or incorrect results
- Analytics and monitoring systems receiving invalid data
- Potential cascading failures in dependent systems
- Loss of event ordering guarantees

This does not directly affect consensus or validator operations, but violates the indexer's data integrity guarantees.

## Likelihood Explanation

**Low to Very Low** under normal circumstances:

- Reaching 2^63 requires ~9 quintillion transactions per event handle
- Move VM has arithmetic overflow checks preventing natural overflow
- Event handles start with counter = 0

However, the lack of validation creates unnecessary risk. The indexer should not assume all inputs are valid - it should validate and handle errors gracefully.

## Recommendation

Use checked conversion with proper error handling:

```rust
impl Event {
    pub fn from_event(
        event: &APIEvent,
        transaction_version: i64,
        transaction_block_height: i64,
        event_index: i64,
    ) -> anyhow::Result<Self> {
        let creation_number = i64::try_from(event.guid.creation_number.0)
            .context("creation_number exceeds i64::MAX")?;
        let sequence_number = i64::try_from(event.sequence_number.0)
            .context("sequence_number exceeds i64::MAX")?;
        
        Ok(Event {
            account_address: standardize_address(&event.guid.account_address.to_string()),
            creation_number,
            sequence_number,
            transaction_version,
            transaction_block_height,
            type_: event.typ.to_string(),
            data: event.data.clone(),
            event_index: Some(event_index),
        })
    }
}
```

The same pattern appears throughout the indexer codebase and should be fixed systematically.

## Proof of Concept

```rust
#[test]
fn test_event_cast_overflow() {
    use aptos_api_types::{Event as APIEvent, EventGuid, U64, Address, MoveType};
    use crate::models::events::Event;
    
    // Create an event with creation_number at exactly i64::MAX + 1
    let mut event = APIEvent {
        guid: EventGuid {
            creation_number: U64(9_223_372_036_854_775_808), // 2^63
            account_address: Address::from([0u8; 32]),
        },
        sequence_number: U64(9_223_372_036_854_775_808), // 2^63
        typ: MoveType::from_str("0x1::test::TestEvent").unwrap(),
        data: serde_json::json!({}),
    };
    
    let indexed_event = Event::from_event(&event, 1, 1, 0);
    
    // Demonstrates silent corruption: positive u64 becomes negative i64
    assert_eq!(indexed_event.creation_number, -9_223_372_036_854_775_808);
    assert_eq!(indexed_event.sequence_number, -9_223_372_036_854_775_808);
    
    // This data corruption would be silently stored in the database
}
```

## Notes

**Important Clarification**: The security question's premise is **incorrect**. The casts do **NOT** panic on overflow in debug builds. Rust's `as` operator for numeric casts uses silent truncation/wrapping behavior regardless of the `overflow-checks` setting. The actual issue is data corruption, not crashes.

### Citations

**File:** crates/indexer/src/models/events.rs (L51-52)
```rust
            creation_number: event.guid.creation_number.0 as i64,
            sequence_number: event.sequence_number.0 as i64,
```

**File:** api/types/src/move_types.rs (L129-129)
```rust
define_integer_type!(U64, u64, "A string encoded U64.");
```

**File:** api/types/src/wrappers.rs (L99-102)
```rust
pub struct EventGuid {
    pub creation_number: U64,
    pub account_address: Address,
}
```

**File:** aptos-move/framework/src/natives/event.rs (L102-144)
```rust
fn native_write_to_event_store(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut arguments: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert!(ty_args.len() == 1);
    debug_assert!(arguments.len() == 3);

    let ty = &ty_args[0];
    let msg = arguments.pop_back().unwrap();
    let seq_num = safely_pop_arg!(arguments, u64);
    let guid = safely_pop_arg!(arguments, Vec<u8>);

    // TODO(Gas): Get rid of abstract memory size
    context.charge(
        EVENT_WRITE_TO_EVENT_STORE_BASE
            + EVENT_WRITE_TO_EVENT_STORE_PER_ABSTRACT_VALUE_UNIT * context.abs_val_size(&msg)?,
    )?;
    let ty_tag = context.type_to_type_tag(ty)?;
    let (layout, contains_delayed_fields) = context
        .type_to_type_layout_with_delayed_fields(ty)?
        .unpack();

    let function_value_extension = context.function_value_extension();
    let max_value_nest_depth = context.max_value_nest_depth();
    let blob = ValueSerDeContext::new(max_value_nest_depth)
        .with_delayed_fields_serde()
        .with_func_args_deserialization(&function_value_extension)
        .serialize(&msg, &layout)?
        .ok_or_else(|| {
            SafeNativeError::InvariantViolation(PartialVMError::new(
                StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
            ))
        })?;
    let key = bcs::from_bytes(guid.as_slice()).map_err(|_| {
        SafeNativeError::InvariantViolation(PartialVMError::new(StatusCode::EVENT_KEY_MISMATCH))
    })?;

    let ctx = context.extensions_mut().get_mut::<NativeEventContext>();
    let event =
        ContractEvent::new_v1(key, seq_num, ty_tag, blob).map_err(|_| SafeNativeError::Abort {
            abort_code: ECANNOT_CREATE_EVENT,
        })?;
```

**File:** Cargo.toml (L921-923)
```text
[profile.release]
debug = true
overflow-checks = true
```
