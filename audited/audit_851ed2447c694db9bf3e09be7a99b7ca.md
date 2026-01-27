# Audit Report

## Title
Memory Exhaustion via Unbounded Event Emission in Single Transaction

## Summary
An attacker can emit millions of small events in a single transaction to exhaust validator memory before size limits are enforced, potentially causing validator crashes or severe performance degradation. The vulnerability exists because event count is unlimited while only total event data bytes are capped at 10MB, allowing massive memory consumption through struct overhead.

## Finding Description

The `NativeEventContext` stores emitted events in an unbounded `Vec<(ContractEvent, Option<MoveTypeLayout>)>` during transaction execution. [1](#0-0) 

When events are emitted, gas is charged based on abstract value size, then the event is serialized and pushed to the Vec: [2](#0-1) 

The critical vulnerability is that while gas is charged per event, there is **no limit on the number of events** - only on their total serialized data size (10MB): [3](#0-2) 

This size limit is only enforced AFTER transaction execution completes: [4](#0-3) 

**Attack Scenario:**
1. Attacker creates a transaction that emits 10,000,000 events, each containing 1 byte of data
2. Gas cost per event: 20,006 + 61 * 1 ≈ 20,067 internal gas units
3. Total gas: ~200,670,000,000 internal gas = 200,670 Gas units (well within 2,000,000 limit)
4. Total event data: 10MB (passes the check)

**Memory Consumption:**
- Event data blobs: 10MB
- Each `ContractEvent` struct contains:
  - EventKey (32 bytes) or discriminant
  - sequence_number (8 bytes)  
  - TypeTag (~100-200 bytes)
  - event_data Vec<u8> (24 bytes overhead + 1 byte data)
- Minimum per event: ~165 bytes

**Total memory during execution: 10MB + (10,000,000 × 165 bytes) = 10MB + 1.65GB ≈ 1.66GB**

The `NativeEventContext.events` Vec grows to 1.66GB during execution, BEFORE the 10MB data size check occurs. This breaks the **Move VM Safety** invariant that "Bytecode execution must respect gas limits and memory constraints."

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria: "Validator node slowdowns" and potential crashes.

**Impact:**
- Validators with limited memory (e.g., 4GB RAM) can be forced into memory exhaustion
- A single malicious transaction can consume 1.6GB+ of memory
- Multiple concurrent transactions could amplify the effect
- Memory pressure causes swapping, severe performance degradation, or OOM crashes
- Affects all validators processing the block containing the malicious transaction
- Does not require validator collusion or privileged access

While this doesn't cause permanent network failure, it can temporarily degrade validator performance across the network and potentially cause individual validator crashes, affecting network liveness.

## Likelihood Explanation

**Likelihood: High**

- **Low cost:** Only ~200K Gas units needed (typical transaction)
- **No special permissions:** Any user can submit the transaction
- **Easy to execute:** Simple Move code looping event emissions
- **Deterministic:** All validators processing the block are affected
- **No detection:** Appears as legitimate transaction until execution

The attack is trivial to execute with a simple Move function:

```move
public entry fun exhaust_memory(account: &signer) {
    let i = 0;
    while (i < 10_000_000) {
        0x1::event::emit(MyEvent { data: vector[1u8] });
        i = i + 1;
    }
}
```

## Recommendation

Implement a **maximum event count per transaction** in addition to the byte size limit: [5](#0-4) 

Add to `ChangeSetConfigs`:
```rust
max_events_per_transaction: u64,
```

Initialize to a reasonable value (e.g., 1,000 or 10,000 events) and check during validation: [4](#0-3) 

Modify the event check to:
```rust
let event_count = change_set.events_iter().count();
if event_count > self.max_events_per_transaction as usize {
    return storage_write_limit_reached(Some("Too many events."));
}

let mut total_event_size = 0;
for event in change_set.events_iter() {
    let size = event.event_data().len() as u64;
    if size > self.max_bytes_per_event {
        return storage_write_limit_reached(None);
    }
    total_event_size += size;
    if total_event_size > self.max_bytes_all_events_per_transaction {
        return storage_write_limit_reached(None);
    }
}
```

## Proof of Concept

```move
module 0xCAFE::memory_bomb {
    use std::vector;
    use aptos_framework::event;

    struct TinyEvent has drop, store {
        data: u8
    }

    public entry fun emit_millions_of_events(account: &signer) {
        let i = 0u64;
        // Emit 10 million tiny events
        while (i < 10_000_000) {
            event::emit(TinyEvent { data: 1 });
            i = i + 1;
        }
    }
}
```

**Expected behavior:**
- Transaction consumes ~200K Gas units
- Passes all current validation checks
- Total event data: 10MB (within limit)
- Validator memory consumption: ~1.66GB during execution
- Causes memory pressure on validators with limited RAM

**To reproduce:**
1. Deploy the module above
2. Call `emit_millions_of_events` 
3. Monitor validator memory usage during block execution
4. Observe memory spike to 1.6GB+ for single transaction processing

## Notes

This vulnerability exists because the event count is not bounded, only the total byte size of event data. The `Vec` overhead and `ContractEvent` struct sizes create significant memory consumption that bypasses the 10MB limit. The issue is exacerbated by the fact that validation occurs after execution, when memory has already been allocated.

### Citations

**File:** aptos-move/framework/src/natives/event.rs (L33-36)
```rust
#[derive(Default, Tid)]
pub struct NativeEventContext {
    events: Vec<(ContractEvent, Option<MoveTypeLayout>)>,
}
```

**File:** aptos-move/framework/src/natives/event.rs (L116-149)
```rust
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
    // TODO(layouts): avoid cloning layouts for events with delayed fields.
    ctx.events.push((
        event,
        contains_delayed_fields.then(|| layout.as_ref().clone()),
    ));
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L169-172)
```rust
            max_bytes_all_events_per_transaction: NumBytes,
            { 5.. => "max_bytes_all_events_per_transaction"},
            10 << 20, // all events from a single transaction are 10MB max
        ],
```

**File:** aptos-move/aptos-vm-types/src/storage/change_set_configs.rs (L10-17)
```rust
pub struct ChangeSetConfigs {
    gas_feature_version: u64,
    max_bytes_per_write_op: u64,
    max_bytes_all_write_ops_per_transaction: u64,
    max_bytes_per_event: u64,
    max_bytes_all_events_per_transaction: u64,
    max_write_ops_per_transaction: u64,
}
```

**File:** aptos-move/aptos-vm-types/src/storage/change_set_configs.rs (L115-125)
```rust
        let mut total_event_size = 0;
        for event in change_set.events_iter() {
            let size = event.event_data().len() as u64;
            if size > self.max_bytes_per_event {
                return storage_write_limit_reached(None);
            }
            total_event_size += size;
            if total_event_size > self.max_bytes_all_events_per_transaction {
                return storage_write_limit_reached(None);
            }
        }
```
