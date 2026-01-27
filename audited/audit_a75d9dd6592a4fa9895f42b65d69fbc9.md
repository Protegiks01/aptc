# Audit Report

## Title
Gas Griefing via Type Depth Mismatch in Event Emission

## Summary
A mismatch between the Move bytecode verifier's `max_type_depth` limit (20) and the BCS serialization's `MAX_TYPE_TAG_NESTING` limit (8) allows gas to be consumed before event creation fails, enabling targeted gas griefing attacks.

## Finding Description

The vulnerability stems from inconsistent type depth validation across different layers of the Aptos stack:

**The Mismatch:**
When function values are enabled (production default), the bytecode verifier allows types with nesting depth up to 20: [1](#0-0) 

However, BCS serialization enforces a much stricter limit of 8 levels: [2](#0-1) 

**The Execution Flow:**

In `native_write_to_event_store`, gas is charged BEFORE type tag validation: [3](#0-2) 

The type-to-tag conversion succeeds for deeply nested types (depth 9-20): [4](#0-3) 

But event creation later fails when attempting to compute the event size: [5](#0-4) 

Inside `ContractEventV1::new`, the size calculation calls `bcs::serialized_size` on the TypeTag: [6](#0-5) [7](#0-6) 

The BCS serialization enforces the 8-level nesting limit through `type_tag_recursive_serialize`: [8](#0-7) 

**Attack Scenario:**
An attacker deploys a Move module containing a function that emits events with types nested 9-20 levels deep (e.g., `vector<vector<vector<vector<vector<vector<vector<vector<vector<u8>>>>>>>>>`). When users call this function:
1. The module passes bytecode verification (max_type_depth = 20)
2. Transaction execution begins and gas is charged
3. Event creation fails with `ECANNOT_CREATE_EVENT`
4. Users lose gas without successful event emission

The Move framework explicitly documents this error condition: [9](#0-8) 

## Impact Explanation

This is a **Low Severity** issue per Aptos bug bounty criteria as it only causes gas loss without broader system impact:
- No fund theft or unauthorized minting
- No consensus safety violations
- No state corruption or data loss  
- No network-wide availability issues
- Users only lose gas fees (minor economic harm)

The issue falls under "Non-critical implementation bugs" in the Low Severity category.

## Likelihood Explanation

**Likelihood: Medium-Low**

The vulnerability requires:
- Deploying modules with unusual type structures (9-20 nesting levels)
- Users interacting with these modules
- Types this deeply nested are rare in normal code

However, it can be triggered:
- Accidentally in complex generic libraries
- Maliciously by attackers deploying griefing contracts
- Repeatedly once a vulnerable module is deployed

## Recommendation

**Option 1: Align Limits (Preferred)**
Set `max_type_depth` in the verifier config to match `MAX_TYPE_TAG_NESTING`:

```rust
max_type_depth: Some(8),  // Match BCS serialization limit
```

**Option 2: Early Validation**
In `native_write_to_event_store`, validate type depth BEFORE charging gas by attempting serialization earlier in the flow.

**Option 3: Increase BCS Limit**
Raise `MAX_TYPE_TAG_NESTING` to 20, though this has broader implications for serialization safety.

The recommended fix is Option 1, as it prevents the mismatch at the earliest validation point.

## Proof of Concept

```move
module 0x1::griefing_attack {
    use aptos_framework::event;
    
    // Type with 9 levels of nesting (exceeds MAX_TYPE_TAG_NESTING=8)
    struct DeepEvent has store, drop {
        data: vector<vector<vector<vector<vector<vector<vector<vector<vector<u8>>>>>>>>>
    }
    
    public entry fun emit_deep_event() {
        // This will pass verification but fail at runtime after gas consumption
        event::emit(DeepEvent { 
            data: vector[vector[vector[vector[vector[vector[vector[vector[vector[1]]]]]]]]]
        });
    }
}
```

When a user calls `emit_deep_event()`:
1. Transaction is accepted and begins execution
2. Gas is charged in `native_write_to_event_store`
3. `ContractEvent::new_v1()` fails with `ECANNOT_CREATE_EVENT`
4. Transaction aborts, user loses gas

**Note:** While this is a valid implementation bug causing gas waste, it does not meet the Critical/High/Medium severity thresholds required for significant bounty consideration. The security harm is limited to minor gas griefing without broader protocol implications.

### Citations

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L188-192)
```rust
        max_type_depth: if enable_function_values {
            Some(20)
        } else {
            None
        },
```

**File:** third_party/move/move-core/types/src/safe_serialize.rs (L11-11)
```rust
pub(crate) const MAX_TYPE_TAG_NESTING: u8 = 8;
```

**File:** third_party/move/move-core/types/src/safe_serialize.rs (L24-34)
```rust
    // For testability, we allow to serialize one more level than deserialize.
    const MAX_TYPE_TAG_NESTING_WHEN_SERIALIZING: u8 =
        MAX_TYPE_TAG_NESTING + if cfg!(test) { 1 } else { 0 };

    TYPE_TAG_DEPTH.with(|depth| {
        let mut r = depth.borrow_mut();
        if *r >= MAX_TYPE_TAG_NESTING_WHEN_SERIALIZING {
            return Err(S::Error::custom(
                "type tag nesting exceeded during serialization",
            ));
        }
```

**File:** aptos-move/framework/src/natives/event.rs (L116-119)
```rust
    context.charge(
        EVENT_WRITE_TO_EVENT_STORE_BASE
            + EVENT_WRITE_TO_EVENT_STORE_PER_ABSTRACT_VALUE_UNIT * context.abs_val_size(&msg)?,
    )?;
```

**File:** aptos-move/framework/src/natives/event.rs (L120-120)
```rust
    let ty_tag = context.type_to_type_tag(ty)?;
```

**File:** aptos-move/framework/src/natives/event.rs (L141-144)
```rust
    let event =
        ContractEvent::new_v1(key, seq_num, ty_tag, blob).map_err(|_| SafeNativeError::Abort {
            abort_code: ECANNOT_CREATE_EVENT,
        })?;
```

**File:** types/src/contract_event.rs (L206-208)
```rust
        // Ensure size is "computable".
        event.size()?;
        Ok(event)
```

**File:** types/src/contract_event.rs (L227-230)
```rust
    pub fn size(&self) -> anyhow::Result<usize> {
        let size = self.key.size() + 8 /* u64 */ + bcs::serialized_size(&self.type_tag)? + self.event_data.len();
        Ok(size)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/event.move (L12-14)
```text
    /// An event cannot be created. This error is returned by native implementations when
    ///   - The type tag for event is too deeply nested.
    const ECANNOT_CREATE_EVENT: u64 = 1;
```
