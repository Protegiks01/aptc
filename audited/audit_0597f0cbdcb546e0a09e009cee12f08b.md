# Audit Report

## Title
Event Size Validation Bypass: TypeTag and Metadata Excluded from Storage Limits

## Summary
The `check_change_set()` function in `change_set_configs.rs` only validates `event_data` size against storage limits, but excludes the EventKey, sequence_number, and TypeTag from the size calculation. This allows attackers to bypass event storage limits by creating events with large TypeTags and metadata, causing actual stored event sizes to exceed the enforced limits.

## Finding Description

The vulnerability lies in the event size validation logic within the `check_change_set()` function: [1](#0-0) 

The validation only checks `event.event_data().len()` against `max_bytes_per_event` (1MB) and `max_bytes_all_events_per_transaction` (10MB). However, events are stored using their full BCS-serialized representation which includes additional components:

**For V1 Events (ContractEventV1):** [2](#0-1) 

The actual size includes EventKey (40 bytes), sequence_number (8 bytes), TypeTag (variable), and event_data.

**For V2 Events (ContractEventV2):** [3](#0-2) 

The actual size includes TypeTag (variable) and event_data.

**EventKey Structure (fixed 40 bytes):** [4](#0-3) 

**Storage Implementation:**
Events are stored using their full BCS-serialized size: [5](#0-4) 

**TypeTag Size Bounds:**
TypeTags can be deeply nested up to depth 8 with maximum identifier lengths of 255 bytes each, resulting in TypeTags that can be several kilobytes in size. With depth-8 nesting and maximum-length module/struct identifiers:
- Per StructTag level: ~32 (address) + 255 (module) + 255 (name) + overhead ≈ 550 bytes
- Depth-8 nested structure: ~4-5KB

**Attack Scenario:**
1. Attacker creates events with `event_data` at maximum limit (1MB per event)
2. Uses deeply nested TypeTags (depth 8) with maximum-length identifiers (255 bytes)
3. For V1 events: Additional 48 bytes (EventKey + sequence_number) + ~5KB (TypeTag)
4. Validation passes because only `event_data.len()` is checked
5. Actual stored size: 1MB + 5KB + 48 bytes ≈ 1.005MB per event
6. For a transaction with 10MB of events: actual storage ~10.05MB, bypassing the 10MB limit by ~50KB

## Impact Explanation

This vulnerability allows bypassing storage limits, leading to:

1. **Storage Bloat**: Events consume more storage than enforced limits suggest, affecting all validators
2. **Resource Exhaustion**: Cumulative effect across many transactions leads to gradual storage exhaustion
3. **State Inconsistency**: Actual storage consumption diverges from validated limits

This qualifies as **Medium Severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention" - the storage accounting is incorrect, and over time this could lead to storage exhaustion requiring manual intervention or limit adjustments.

While bounded by TypeTag depth limits (MAX_TYPE_TAG_NESTING = 8) and identifier size limits (255 bytes), the bypass is consistent and exploitable by any transaction sender.

## Likelihood Explanation

**Likelihood: Medium-High**

- **Exploitability**: Any transaction sender can exploit this without special privileges
- **Economic Constraints**: Requires gas payment for transaction execution, providing some economic bound
- **Attack Complexity**: Low - simply emit events with deeply nested TypeTags
- **Detection**: Difficult to detect as events pass validation checks
- **Accumulation**: Multiple attackers or repeated transactions compound the effect

The attack is straightforward to execute and could be automated. While each bypass is relatively small (few KB per event), cumulative effects across the network over time could be significant.

## Recommendation

Modify the event size validation in `check_change_set()` to account for the full serialized event size including all metadata and TypeTag:

```rust
let mut total_event_size = 0;
for event in change_set.events_iter() {
    // Use the full event size, not just event_data
    let size = event.size() as u64;
    if size > self.max_bytes_per_event {
        return storage_write_limit_reached(None);
    }
    total_event_size += size;
    if total_event_size > self.max_bytes_all_events_per_transaction {
        return storage_write_limit_reached(None);
    }
}
```

The `ContractEvent::size()` method already computes the correct full size: [6](#0-5) 

This change ensures that storage limits accurately reflect actual storage consumption, preventing the bypass.

## Proof of Concept

```rust
// In aptos-move/e2e-move-tests/src/tests/
#[test]
fn test_event_size_bypass() {
    use aptos_types::contract_event::ContractEvent;
    use aptos_types::event::EventKey;
    use move_core_types::language_storage::{StructTag, TypeTag};
    use move_core_types::account_address::AccountAddress;
    use move_core_types::identifier::Identifier;
    
    // Create a deeply nested TypeTag (depth 8)
    let mut type_tag = TypeTag::U8;
    for _ in 0..8 {
        type_tag = TypeTag::Struct(Box::new(StructTag {
            address: AccountAddress::ONE,
            module: Identifier::new("a".repeat(255)).unwrap(), // Max length
            name: Identifier::new("b".repeat(255)).unwrap(),   // Max length
            type_args: vec![type_tag],
        }));
    }
    
    // Create event with max event_data (1MB)
    let event_data = vec![0u8; 1024 * 1024]; // 1MB
    
    let event = ContractEvent::new_v1(
        EventKey::new(0, AccountAddress::ONE),
        0,
        type_tag,
        event_data.clone(),
    ).unwrap();
    
    // event_data().len() is 1MB (passes check)
    assert_eq!(event.event_data().len(), 1024 * 1024);
    
    // But actual size is larger (bypasses limit)
    let actual_size = event.size();
    assert!(actual_size > 1024 * 1024);
    
    // The difference is unaccounted for in validation
    println!("Event data size (checked): {} bytes", event.event_data().len());
    println!("Actual event size (stored): {} bytes", actual_size);
    println!("Bypass amount: {} bytes", actual_size - event.event_data().len());
}
```

This PoC demonstrates that while `event_data().len()` returns exactly 1MB (which would pass validation), the actual `size()` is larger due to the TypeTag and metadata, proving the storage limit bypass.

## Notes

The vulnerability affects both V1 and V2 events:
- **V1 events**: Missing EventKey (40 bytes) + sequence_number (8 bytes) + TypeTag (variable)
- **V2 events**: Missing TypeTag (variable)

The TypeTag size is bounded by `MAX_TYPE_TAG_NESTING` (depth limit of 8) and identifier length limits (255 bytes), but within these constraints, attackers can consistently bypass storage limits. The gas parameters defining these limits were introduced in gas feature version 5: [7](#0-6)

### Citations

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

**File:** types/src/contract_event.rs (L108-114)
```rust
    pub fn size(&self) -> usize {
        let result = match self {
            ContractEvent::V1(event) => event.size(),
            ContractEvent::V2(event) => event.size(),
        };
        result.expect("Size of events is computable and is checked at construction time")
    }
```

**File:** types/src/contract_event.rs (L227-230)
```rust
    pub fn size(&self) -> anyhow::Result<usize> {
        let size = self.key.size() + 8 /* u64 */ + bcs::serialized_size(&self.type_tag)? + self.event_data.len();
        Ok(size)
    }
```

**File:** types/src/contract_event.rs (L268-271)
```rust
    pub fn size(&self) -> anyhow::Result<usize> {
        let size = bcs::serialized_size(&self.type_tag)? + self.event_data.len();
        Ok(size)
    }
```

**File:** types/src/event.rs (L49-51)
```rust
    pub fn size(&self) -> usize {
        8 /* u64 */ + 32 /* address */
    }
```

**File:** storage/aptosdb/src/schema/event/mod.rs (L50-52)
```rust
    fn encode_value(&self) -> Result<Vec<u8>> {
        bcs::to_bytes(self).map_err(Into::into)
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L164-172)
```rust
            max_bytes_per_event: NumBytes,
            { 5.. => "max_bytes_per_event" },
            1 << 20, // a single event is 1MB max
        ],
        [
            max_bytes_all_events_per_transaction: NumBytes,
            { 5.. => "max_bytes_all_events_per_transaction"},
            10 << 20, // all events from a single transaction are 10MB max
        ],
```
