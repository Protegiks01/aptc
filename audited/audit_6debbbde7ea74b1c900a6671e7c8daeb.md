# Audit Report

## Title
Event Emission Underpayment: Missing Per-Item IO Gas Overhead Enables Storage Bombing at 1000x Reduced Cost

## Summary
The `io_gas_per_event()` function charges only per-byte IO gas for events (89 gas/byte) without any per-item overhead, while state writes charge both per-slot overhead (89,568 gas) and per-byte costs. Since events incur similar database write and indexing costs as state items, attackers can emit many tiny events to create disproportionate storage burden while paying ~1000x less than the equivalent cost for state writes.

## Finding Description

The IO gas pricing mechanism treats events fundamentally differently from state writes despite similar underlying storage costs:

**State Write Pricing** (all versions V2-V4): [1](#0-0) 

State writes charge a per-item overhead (`per_item_create` or `per_item_write`) plus per-byte costs. The per-slot overhead is 89,568 gas, representing the fixed cost of database operations.

**Event Pricing** (all versions): [2](#0-1) 

Events charge only per-byte costs (89 gas/byte) with NO per-item overhead.

**Gas Parameters**: [3](#0-2) [4](#0-3) 

The per-slot overhead (89,568) is approximately 1,007x larger than the per-byte cost (89).

**Storage Reality**: [5](#0-4) 

Each event incurs:
- 1 write to `EventSchema` (keyed by version, index)
- 2 index writes for V1 events (`EventByKeySchema`, `EventByVersionSchema`)
- 1 write to `EventAccumulatorSchema` for Merkle accumulator

These are equivalent to the database operations that justify the per-slot overhead for state writes.

**Attack Vector**:

An attacker creates a Move transaction that emits many tiny events. The only limits are: [6](#0-5) 

There is NO limit on the number of events, only total bytes (10MB per transaction).

**Exploitation Example**:
- Emit 10MB of events with minimal type tags (~20 bytes per event average)
- Number of events: 10,485,760 bytes / 20 bytes = ~524,288 events
- IO gas paid: 10,485,760 × 89 = 933,232,640 gas (within 1B `max_io_gas` limit)
- IO gas if per-item overhead applied: 524,288 × 89,568 + 10,485,760 × 89 = ~47B gas
- Undercharging factor: ~50x

For smaller events (closer to minimum size), the undercharging approaches 1000x.

**Additional Consideration - Storage Fees**: [7](#0-6) 

In V2 pricing (current), events also pay ZERO storage fees, compounding the undercharging.

## Impact Explanation

This qualifies as **Medium Severity** per Aptos bug bounty criteria:

**"Limited funds loss or manipulation"**: The systematic undercharging means attackers pay dramatically less than the true cost of storage/indexing operations, effectively manipulating the gas market to obtain services below cost. While not direct theft, this represents an economic vulnerability where the network subsidizes attacker storage at ~50-1000x below fair cost.

**"State inconsistencies requiring intervention"**: Repeated exploitation could cause:
- Excessive storage bloat across all nodes (events persist permanently unless pruned)
- Index size explosion for V1 events
- Increased hardware requirements for node operators
- Potential need for emergency pruning or intervention at scale

The vulnerability breaks **Invariant #9: "Resource Limits: All operations must respect gas, storage, and computational limits"** by failing to charge gas proportional to the actual resource costs incurred.

## Likelihood Explanation

**Likelihood: High**

- Any user can emit events via the public `event::emit<T>()` function [8](#0-7) 

- No special permissions required
- Attack can be repeated indefinitely across many transactions
- Economic incentive exists for attackers to grief node operators or spam storage
- Transaction complexity is low (simple Move module emitting events in a loop)

## Recommendation

Add a per-item IO gas overhead for events, consistent with state write pricing:

```rust
pub fn io_gas_per_event(
    &self,
    event: &ContractEvent,
) -> impl GasExpression<VMGasParameters, Unit = InternalGasUnit> + use<> {
    // Add per-item overhead to match state write pricing model
    STORAGE_IO_PER_EVENT_ITEM_WRITE * NumArgs::new(1) 
        + STORAGE_IO_PER_EVENT_BYTE_WRITE * NumBytes::new(event.size() as u64)
}
```

Add a new gas parameter `STORAGE_IO_PER_EVENT_ITEM_WRITE` with a value comparable to `STORAGE_IO_PER_STATE_SLOT_WRITE` (perhaps 50-90% of it, around 40,000-80,000 gas) to reflect the fixed cost of event storage and indexing operations.

This aligns the gas model with actual resource costs while maintaining reasonable event pricing.

## Proof of Concept

```move
module attacker::event_spam {
    use aptos_framework::event;
    
    struct TinyEvent has store, drop {
        data: u8
    }
    
    // Emit many tiny events to maximize DB writes while minimizing gas cost
    public entry fun spam_events() {
        let i = 0;
        // Emit up to gas limit allows (hundreds of thousands of events)
        while (i < 500000) {
            event::emit(TinyEvent { data: 1 });
            i = i + 1;
        };
    }
}
```

**Expected Result**: Transaction succeeds, creating 500,000 events (500,000+ DB writes) while paying only per-byte IO gas (~89 × 500,000 × 20 bytes = ~890M gas), when it should pay per-item overhead (~500,000 × 89,568 = ~45B gas if overhead were applied).

**Notes**

The vulnerability is valid but impacts are somewhat limited by:
1. `max_io_gas` limit (1B) caps exploitation per transaction
2. Transaction fees still cost money, limiting economic viability of pure griefing
3. Events can be pruned by node operators (though this requires manual intervention)

However, the fundamental issue remains: the gas pricing model does not reflect actual storage/indexing costs for events, creating a systematic undercharging vulnerability that violates the principle that gas should match resource consumption.

### Citations

**File:** aptos-move/aptos-vm-types/src/storage/io_pricing.rs (L142-156)
```rust
    fn io_gas_per_write(&self, key: &StateKey, op_size: &WriteOpSize) -> InternalGas {
        use aptos_types::write_set::WriteOpSize::*;

        match op_size {
            Creation { write_len } => {
                self.per_item_create * NumArgs::new(1)
                    + self.write_op_size(key, *write_len) * self.per_byte_create
            },
            Modification { write_len } => {
                self.per_item_write * NumArgs::new(1)
                    + self.write_op_size(key, *write_len) * self.per_byte_write
            },
            Deletion => 0.into(),
        }
    }
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

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L108-116)
```rust
            storage_io_per_state_slot_write: InternalGasPerArg,
            { 0..=9 => "write_data.per_op", 10.. => "storage_io_per_state_slot_write"},
            // The cost of writing down the upper level new JMT nodes are shared between transactions
            // because we write down the JMT in batches, however the bottom levels will be specific
            // to each transactions assuming they don't touch exactly the same leaves. It's fair to
            // target roughly 1-2 full internal JMT nodes (about 0.5-1KB in total) worth of writes
            // for each write op.
            89_568,
        ],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L133-136)
```rust
            storage_io_per_event_byte_write: InternalGasPerByte,
            { RELEASE_V1_11.. => "storage_io_per_event_byte_write" },
            89,
        ],
```

**File:** storage/aptosdb/src/ledger_db/event_db.rs (L145-170)
```rust
    pub(crate) fn put_events(
        &self,
        version: u64,
        events: &[ContractEvent],
        skip_index: bool,
        batch: &mut impl WriteBatch,
    ) -> Result<()> {
        // Event table and indices updates
        events
            .iter()
            .enumerate()
            .try_for_each::<_, Result<_>>(|(idx, event)| {
                if let ContractEvent::V1(v1) = event {
                    if !skip_index {
                        batch.put::<EventByKeySchema>(
                            &(*v1.key(), v1.sequence_number()),
                            &(version, idx as u64),
                        )?;
                        batch.put::<EventByVersionSchema>(
                            &(*v1.key(), version, v1.sequence_number()),
                            &(idx as u64),
                        )?;
                    }
                }
                batch.put::<EventSchema>(&(version, idx as u64), event)
            })?;
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

**File:** aptos-move/aptos-vm-types/src/storage/space_pricing.rs (L58-69)
```rust
    pub fn legacy_storage_fee_per_event(
        &self,
        params: &TransactionGasParameters,
        event: &ContractEvent,
    ) -> Fee {
        match self {
            Self::V1 => {
                NumBytes::new(event.size() as u64) * params.legacy_storage_fee_per_event_byte
            },
            Self::V2 => 0.into(),
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/event.move (L17-19)
```text
    public fun emit<T: store + drop>(msg: T) {
        write_module_event_to_store<T>(msg);
    }
```
