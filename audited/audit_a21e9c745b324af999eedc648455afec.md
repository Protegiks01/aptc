# Audit Report

## Title
Event Data Bomb: Unbounded Memory Amplification During API Event Conversion

## Summary
The `try_into_events()` function in the Aptos API lacks effective memory limits when converting BCS-serialized event data to JSON format. Events limited to 1MB during emission can expand to 30-50MB+ during API processing due to BCS-to-JSON conversion overhead, enabling resource exhaustion attacks against API servers.

## Finding Description

The vulnerability exists in the event conversion pipeline when the API retrieves historical transactions. The attack exploits a mismatch between on-chain event size limits (enforced during transaction execution) and API processing limits (inadequately enforced during retrieval).

**Step 1: Event Emission with Maximum Size**
During transaction execution, events are limited by `max_bytes_per_event` (1MB BCS) and `max_bytes_all_events_per_transaction` (10MB BCS total). [1](#0-0) 

These limits are enforced during transaction execution: [2](#0-1) 

**Step 2: Event Storage**
Events are stored on-chain with their BCS-serialized data, which is compact binary format. [3](#0-2) 

**Step 3: Vulnerable API Conversion**
When retrieving transactions via the API, `try_into_events()` processes each event by:
1. Deserializing BCS to `AnnotatedMoveValue` via `view_value()`
2. Converting to API `MoveValue` 
3. Serializing to JSON [4](#0-3) 

**Step 4: Ineffective Memory Limit**
The `view_value()` function uses a `Limiter` with 100MB default, but it only charges for metadata (field names, type tags), not actual data content: [5](#0-4) [6](#0-5) 

The `annotate_value()` function processes data recursively but never charges the limiter for actual data bytes: [7](#0-6) 

**Step 5: JSON Serialization Amplification**
The final JSON conversion is completely unbounded: [8](#0-7) 

**Attack Scenario:**
1. Attacker creates Move module emitting events with `vector<u64>` containing maximum data (~131,000 u64 values = 1MB BCS)
2. Emits 10 such events per transaction (10MB BCS total, within limits)
3. Each u64 in BCS (8 bytes) becomes a JSON string (up to 20 characters for max value)
4. Memory expansion: 10MB BCS → ~30MB during deserialization → ~40-50MB JSON
5. Attacker makes concurrent API requests (50-100 requests) to retrieve these transactions
6. Total memory consumption: 100 requests × 40MB = 4GB, causing API server memory exhaustion

## Impact Explanation

**Severity: High**

This vulnerability enables Denial-of-Service attacks against Aptos API servers, fitting the High severity category: "API crashes, validator node slowdowns."

**Affected Systems:**
- All Aptos API servers retrieving transactions with large events
- Validator nodes running co-located API services
- Public API endpoints serving blockchain data

**Impact Quantification:**
- Memory amplification factor: 3-5x from BCS to in-memory representation, then to JSON
- Per-transaction impact: 10MB on-chain → 40-50MB API memory usage
- Concurrent attack: 100 requests can consume 4GB+ RAM
- Can cause API crashes, slowdowns, or OOM conditions

The vulnerability breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The API processing does not have proportional resource usage to on-chain data size.

## Likelihood Explanation

**Likelihood: Medium-High**

**Attacker Requirements:**
- Ability to deploy Move modules (requires gas payment)
- Ability to emit large events (costs gas but feasible)
- No validator privileges needed
- Can use standard API endpoints

**Exploitation Complexity:**
- Low - straightforward to create Move module with large vector events
- Events persist on-chain, enabling repeated exploitation
- Any client can query the transaction, triggering memory allocation
- Concurrent requests amplify the attack

**Cost vs Impact:**
- Moderate cost to create transactions with large events (gas fees)
- High impact: can disrupt API availability for all users
- Attack can be repeated indefinitely once events are stored

## Recommendation

Implement effective memory limits during event conversion:

**1. Add data-aware charging to the Limiter:**

```rust
// In move-resource-viewer/src/lib.rs, modify annotate_value():
fn annotate_value(
    &self,
    value: &MoveValue,
    ty: &FatType,
    limit: &mut Limiter,
) -> anyhow::Result<AnnotatedMoveValue> {
    // Charge for the actual data size
    let value_size = self.estimate_value_size(value);
    limit.charge(value_size)?;
    
    Ok(match (value, ty) {
        // ... existing match arms
    })
}

fn estimate_value_size(&self, value: &MoveValue) -> usize {
    match value {
        MoveValue::Vector(v) => v.len() * std::mem::size_of::<MoveValue>(),
        MoveValue::Struct(s) => s.fields().iter().map(|f| self.estimate_value_size(f)).sum(),
        _ => std::mem::size_of_val(value),
    }
}
```

**2. Add JSON size limits in convert.rs:**

```rust
// In api/types/src/convert.rs, modify try_into_events():
pub fn try_into_events(&self, events: &[ContractEvent]) -> Result<Vec<Event>> {
    const MAX_JSON_SIZE_PER_EVENT: usize = 5 << 20; // 5MB per event
    const MAX_JSON_SIZE_TOTAL: usize = 50 << 20; // 50MB total
    
    let mut ret = vec![];
    let mut total_size = 0;
    
    for event in events {
        let data = self.inner.view_value(event.type_tag(), event.event_data())?;
        let move_value = MoveValue::try_from(data)?;
        let json = move_value.json()?;
        
        // Check JSON size
        let json_size = serde_json::to_string(&json)?.len();
        ensure!(json_size <= MAX_JSON_SIZE_PER_EVENT, "Event JSON exceeds size limit");
        
        total_size += json_size;
        ensure!(total_size <= MAX_JSON_SIZE_TOTAL, "Total event JSON exceeds size limit");
        
        ret.push((event, json).into());
    }
    Ok(ret)
}
```

**3. Consider response streaming or pagination for large transactions**

## Proof of Concept

```move
// File: large_event_bomb.move
module attacker::event_bomb {
    use std::vector;
    use aptos_framework::event;

    struct LargeEvent has drop, store {
        data: vector<u64>,
    }

    public entry fun emit_large_events(account: &signer) {
        // Create vector with ~131,000 u64 values (1MB BCS)
        let data = vector::empty<u64>();
        let i = 0;
        while (i < 131000) {
            vector::push_back(&mut data, 18446744073709551615u64); // Max u64
            i = i + 1;
        };

        // Emit 10 events (10MB BCS total)
        let j = 0;
        while (j < 10) {
            event::emit(LargeEvent { data: copy data });
            j = j + 1;
        };
    }
}
```

**Exploitation steps:**
1. Deploy the Move module and execute `emit_large_events()`
2. Note the transaction version
3. Make concurrent API requests: `GET /transactions/by_version/{version}`
4. Monitor API server memory usage - will spike to 4GB+ with 100 concurrent requests
5. API server experiences slowdowns or crashes due to memory exhaustion

**Expected outcome:** API server memory consumption increases dramatically (40-50MB per request) compared to on-chain data size (10MB), demonstrating the memory amplification vulnerability.

## Notes

This vulnerability demonstrates a classic resource amplification attack where compact on-chain data (BCS format) expands significantly during API processing (JSON format). The issue is exacerbated by:

- BCS uses 8 bytes per u64, JSON uses up to 20 characters (2.5x expansion)
- Vector and struct overhead in JSON (brackets, commas, field names)
- Multiple in-memory representations during conversion pipeline
- No effective limits on the expanded representations

The fix requires implementing proper memory accounting throughout the conversion pipeline, not just for metadata but for actual data content.

### Citations

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

**File:** types/src/contract_event.rs (L268-271)
```rust
    pub fn size(&self) -> anyhow::Result<usize> {
        let size = bcs::serialized_size(&self.type_tag)? + self.event_data.len();
        Ok(size)
    }
```

**File:** api/types/src/convert.rs (L601-610)
```rust
    pub fn try_into_events(&self, events: &[ContractEvent]) -> Result<Vec<Event>> {
        let mut ret = vec![];
        for event in events {
            let data = self
                .inner
                .view_value(event.type_tag(), event.event_data())?;
            ret.push((event, MoveValue::try_from(data)?.json()?).into());
        }
        Ok(ret)
    }
```

**File:** third_party/move/tools/move-resource-viewer/src/lib.rs (L685-689)
```rust
    pub fn view_value(&self, ty_tag: &TypeTag, blob: &[u8]) -> anyhow::Result<AnnotatedMoveValue> {
        let mut limit = Limiter::default();
        let ty = self.resolve_type_impl(ty_tag, &mut limit)?;
        self.view_value_by_fat_type(&ty, blob, &mut limit)
    }
```

**File:** third_party/move/tools/move-resource-viewer/src/lib.rs (L880-916)
```rust
    fn annotate_value(
        &self,
        value: &MoveValue,
        ty: &FatType,
        limit: &mut Limiter,
    ) -> anyhow::Result<AnnotatedMoveValue> {
        Ok(match (value, ty) {
            (MoveValue::Bool(b), FatType::Bool) => AnnotatedMoveValue::Bool(*b),
            (MoveValue::U8(i), FatType::U8) => AnnotatedMoveValue::U8(*i),
            (MoveValue::U16(i), FatType::U16) => AnnotatedMoveValue::U16(*i),
            (MoveValue::U32(i), FatType::U32) => AnnotatedMoveValue::U32(*i),
            (MoveValue::U64(i), FatType::U64) => AnnotatedMoveValue::U64(*i),
            (MoveValue::U128(i), FatType::U128) => AnnotatedMoveValue::U128(*i),
            (MoveValue::U256(i), FatType::U256) => AnnotatedMoveValue::U256(*i),
            (MoveValue::I8(i), FatType::I8) => AnnotatedMoveValue::I8(*i),
            (MoveValue::I16(i), FatType::I16) => AnnotatedMoveValue::I16(*i),
            (MoveValue::I32(i), FatType::I32) => AnnotatedMoveValue::I32(*i),
            (MoveValue::I64(i), FatType::I64) => AnnotatedMoveValue::I64(*i),
            (MoveValue::I128(i), FatType::I128) => AnnotatedMoveValue::I128(*i),
            (MoveValue::I256(i), FatType::I256) => AnnotatedMoveValue::I256(*i),
            (MoveValue::Address(a), FatType::Address) => AnnotatedMoveValue::Address(*a),
            (MoveValue::Vector(a), FatType::Vector(ty)) => match ty.as_ref() {
                FatType::U8 => AnnotatedMoveValue::Bytes(
                    a.iter()
                        .map(|v| match v {
                            MoveValue::U8(i) => Ok(*i),
                            _ => Err(anyhow!("unexpected value type")),
                        })
                        .collect::<anyhow::Result<_>>()?,
                ),
                _ => AnnotatedMoveValue::Vector(
                    ty.type_tag(limit).unwrap(),
                    a.iter()
                        .map(|v| self.annotate_value(v, ty.as_ref(), limit))
                        .collect::<anyhow::Result<_>>()?,
                ),
            },
```

**File:** third_party/move/tools/move-resource-viewer/src/limit.rs (L7-20)
```rust
// Default limit set to 100mb per query.
const DEFAULT_LIMIT: usize = 100_000_000;

pub struct Limiter(usize);

impl Limiter {
    pub fn charge(&mut self, cost: usize) -> PartialVMResult<()> {
        if self.0 < cost {
            return Err(PartialVMError::new(StatusCode::ABORTED)
                .with_message("Query exceeds size limit".to_string()));
        }
        self.0 -= cost;
        Ok(())
    }
```

**File:** api/types/src/move_types.rs (L387-389)
```rust
    pub fn json(&self) -> anyhow::Result<serde_json::Value> {
        Ok(serde_json::to_value(self)?)
    }
```
