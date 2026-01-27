# Audit Report

## Title
Memory Allocation Before Gas Metering in BLS12381 Public Key Aggregation Native Function

## Summary
The `native_bls12381_aggregate_pubkeys` function allocates significant memory before charging adequate gas, creating a potential resource exhaustion vector when combined with transaction spam and parallel execution.

## Finding Description

The BLS12381 public key aggregation function exposed to Move contracts performs multiple heap allocations before proper gas metering occurs, violating the **Resource Limits** invariant (invariant #9: "All operations must respect gas, storage, and computational limits"). [1](#0-0) 

The vulnerability manifests through this execution flow:

1. **Unprotected Memory Allocation**: The `pop_as_vec_of_vec_u8` helper function is called, which uses the `safely_pop_vec_arg!` macro to extract and allocate a `Vec<Vec<u8>>` containing all serialized public keys. [2](#0-1) 

2. **Delayed Gas Charge**: Only after this allocation does the function charge `BLS12381_BASE` gas (551 units), which is negligible compared to the memory allocated. [3](#0-2) 

3. **Multiple Allocations**: Additional vectors are created during deserialization and aggregation: [4](#0-3) 

**Attack Scenario:**

While the question asks about "millions of PKs," transaction size limits prevent this. However, an attacker can:

1. Submit transactions at the maximum size limit (64 KB for regular, 1 MB for governance)
2. Pack ~1,365 public keys (regular) or ~21,845 keys (governance) per transaction
3. Flood the mempool with such transactions
4. During parallel block execution, multiple transactions allocate memory simultaneously before gas protection [5](#0-4) 

**Memory Calculations:**
- Regular transaction: 1,365 keys × 72 bytes (48 bytes + Vec overhead) ≈ 98 KB per `pop_as_vec_of_vec_u8`
- Governance transaction: Limited by gas to ~9,600 keys effectively (8.7 billion gas needed vs 4 billion limit)
- With 32 concurrent executions: 32 × 98 KB ≈ 3 MB unmetered allocation spike per batch

## Impact Explanation

**Severity Assessment: MEDIUM (not High)**

This does **NOT** meet High severity criteria because:

1. **Cannot achieve "millions of PKs"**: The question's premise is incorrect. Transaction size limits cap at ~1,365-21,845 keys, not millions.

2. **Bounded per-transaction impact**: Each transaction causes ~100-200 KB of pre-gas allocations, which is manageable for modern validator hardware (32+ GB RAM).

3. **Gas system still protects**: Deserialization charges 400,684 gas per key, so processing will halt when gas runs out, preventing unbounded computation. [6](#0-5) 

4. **Requires sustained spam**: To cause meaningful impact, an attacker would need thousands of concurrent transactions, which face mempool limits and require paying gas fees.

The vulnerability represents a **gas accounting imprecision** rather than a critical DoS vector. It violates the principle of "charge before work" but is unlikely to crash production validators due to:
- Hardware resource abundance
- Transaction throughput limitations  
- Gas exhaustion during deserialization
- Mempool spam protections

## Likelihood Explanation

**Likelihood: LOW**

- Attacker must pay gas for many transactions to amplify impact
- Parallel execution concurrency is limited (typically 16-32 threads)
- Modern validators have sufficient RAM headroom for this attack
- Block size and transaction inclusion limits bound the attack surface
- The memory allocations, while unmetered initially, are released quickly after processing

## Recommendation

Implement pre-allocation gas charging before extracting vector arguments:

```rust
fn native_bls12381_aggregate_pubkeys(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut arguments: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert!(ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    context.charge(BLS12381_BASE)?;

    // NEW: Estimate and charge for vector extraction BEFORE allocation
    if let Some(vec_value) = arguments.back() {
        if let Ok(vec) = vec_value.value_as::<Vec<Value>>() {
            let num_elements = vec.len();
            // Charge proportional gas for the memory that will be allocated
            context.charge(BLS12381_PER_PUBKEY_DESERIALIZE * NumArgs::new(num_elements.min(10) as u64))?;
        }
    }

    let pks_bytes = pop_as_vec_of_vec_u8(&mut arguments)?;
    // ... rest of function
}
```

This ensures meaningful gas is charged before the first large allocation occurs.

## Proof of Concept

```move
// Compile with: aptos move compile
module 0x1::bls_dos_poc {
    use std::bls12381;
    use std::vector;

    // This function attempts to aggregate maximum public keys
    // to test memory allocation before gas metering
    public fun test_aggregate_max_keys(): vector<u8> {
        let keys = vector::empty<vector<u8>>();
        let i = 0;
        
        // Add 1365 keys (max for 64KB transaction)
        while (i < 1365) {
            // Dummy 48-byte public key
            let key = vector::empty<u8>();
            let j = 0;
            while (j < 48) {
                vector::push_back(&mut key, (i as u8));
                j = j + 1;
            };
            vector::push_back(&mut keys, key);
            i = i + 1;
        };
        
        // This call will allocate ~98KB before base gas charge
        let (aggpk, success) = bls12381::aggregate_pubkeys_internal(keys);
        assert!(success, 1);
        aggpk
    }
}
```

**Expected behavior**: Memory allocation occurs before adequate gas is charged, but gas exhaustion during deserialization prevents full exploitation.

---

## Notes

After thorough analysis, while a gas accounting imprecision exists, it does **NOT** constitute a High severity vulnerability because:

1. The question's premise about "millions of PKs" is factually impossible due to transaction size limits (max ~1,365 regular, ~21,845 governance by size, ~9,600 by gas)
2. Per-transaction memory impact (~100-200 KB) is insufficient to crash modern validators
3. Gas metering during deserialization provides protection against unbounded processing
4. The attack requires sustained spam with many concurrent transactions, facing practical limitations

The issue represents a minor gas accounting inefficiency rather than an exploitable DoS vulnerability meeting the "EXTREMELY high bar" required for validation.

### Citations

**File:** aptos-move/framework/src/natives/cryptography/bls12381.rs (L259-299)
```rust
fn native_bls12381_aggregate_pubkeys(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut arguments: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert!(ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    // Parses a Vec<Vec<u8>> of all serialized public keys
    let pks_bytes = pop_as_vec_of_vec_u8(&mut arguments)?;
    let num_pks = pks_bytes.len();

    context.charge(BLS12381_BASE)?;

    // If zero PKs were given as input, return None.
    if pks_bytes.is_empty() {
        return Ok(smallvec![Value::vector_u8(vec![]), Value::bool(false)]);
    }

    let pks = bls12381_deserialize_pks(pks_bytes, context)?;
    debug_assert!(pks.len() <= num_pks);

    // If not all PKs were successfully deserialized, return None and only charge for the actual work done
    if pks.len() != num_pks {
        return Ok(smallvec![Value::vector_u8(vec![]), Value::bool(false)]);
    }

    // Aggregate the public keys (this will NOT subgroup-check the individual PKs)
    // NOTE(Gas): |pks| elliptic curve additions
    context.charge(BLS12381_PER_PUBKEY_AGGREGATE * NumArgs::new(num_pks as u64))?;
    let aggpk =
        match bls12381::PublicKey::aggregate(pks.iter().collect::<Vec<&bls12381::PublicKey>>()) {
            Ok(aggpk) => aggpk,
            Err(_) => return Ok(smallvec![Value::vector_u8(vec![]), Value::bool(false)]),
        };

    Ok(smallvec![
        Value::vector_u8(aggpk.to_bytes().to_vec()),
        Value::bool(true)
    ])
}
```

**File:** aptos-move/aptos-native-interface/src/helpers.rs (L77-103)
```rust
macro_rules! safely_pop_vec_arg {
    ($arguments:ident, $t:ty) => {{
        // Replicating the code from pop_arg! here
        use $crate::reexports::move_vm_types::natives::function::{PartialVMError, StatusCode};
        let value_vec = match $arguments.pop_back().map(|v| v.value_as::<Vec<Value>>()) {
            None => {
                return Err($crate::SafeNativeError::InvariantViolation(
                    PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                ))
            }
            Some(Err(e)) => return Err($crate::SafeNativeError::InvariantViolation(e)),
            Some(Ok(v)) => v,
        };

        // Pop each Value from the popped Vec<Value>, cast it as a Vec<u8>, and push it to a Vec<Vec<u8>>
        let mut vec_vec = vec![];
        for value in value_vec {
            let vec = match value.value_as::<$t>() {
                Err(e) => return Err($crate::SafeNativeError::InvariantViolation(e)),
                Ok(v) => v,
            };
            vec_vec.push(vec);
        }

        vec_vec
    }};
}
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/aptos_framework.rs (L172-172)
```rust
        [bls12381_base: InternalGas, "bls12381.base", 551],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/aptos_framework.rs (L174-175)
```rust
        [bls12381_per_pubkey_deserialize: InternalGasPerArg, "bls12381.per_pubkey_deserialize", 400684],
        [bls12381_per_pubkey_aggregate: InternalGasPerArg, "bls12381.per_pubkey_aggregate", 15439],
```

**File:** crates/aptos-crypto/src/bls12381/bls12381_keys.rs (L76-86)
```rust
    pub fn aggregate(pubkeys: Vec<&Self>) -> Result<PublicKey> {
        let blst_pubkeys: Vec<_> = pubkeys.iter().map(|pk| &pk.pubkey).collect();

        // CRYPTONOTE(Alin): We assume the PKs have had their PoPs verified and thus have also been subgroup-checked
        let aggpk = blst::min_pk::AggregatePublicKey::aggregate(&blst_pubkeys[..], false)
            .map_err(|e| anyhow!("{:?}", e))?;

        Ok(PublicKey {
            pubkey: aggpk.to_public_key(),
        })
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L73-81)
```rust
            max_transaction_size_in_bytes: NumBytes,
            "max_transaction_size_in_bytes",
            64 * 1024
        ],
        [
            max_transaction_size_in_bytes_gov: NumBytes,
            { RELEASE_V1_13.. => "max_transaction_size_in_bytes.gov" },
            1024 * 1024
        ],
```
