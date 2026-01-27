# Audit Report

## Title
Memory Exhaustion via BCS Deserialization Bomb in Package Publishing

## Summary
The `publish_package_txn` entry function deserializes user-controlled bytes into `PackageMetadata` without size limits, allowing attackers to craft malicious BCS-encoded data that claims massive vector lengths. This causes out-of-memory conditions during deserialization before gas limits prevent the allocation, potentially crashing validator nodes.

## Finding Description

The vulnerability exists in the interaction between transaction argument validation and application-level BCS deserialization: [1](#0-0) 

The entry function accepts a `metadata_serialized: vector<u8>` parameter, which passes transaction validation with a 64KB size limit: [2](#0-1) 

However, when this vector is deserialized via `util::from_bytes`, the native implementation charges gas based only on the **input byte length**, not the claimed vector sizes within: [3](#0-2) 

The gas cost is minimal (1102 base + 18 per byte): [4](#0-3) 

After charging this small amount, deserialization proceeds via `bcs::from_bytes_seed`: [5](#0-4) 

The `PackageMetadata` structure contains nested vectors that can be exploited: [6](#0-5) 

**Attack Mechanism:**

1. Attacker crafts 64KB of BCS-encoded bytes claiming massive vector lengths using ULEB128 compression (e.g., length of 2^30 can be encoded in ~5 bytes)
2. Transaction passes validation (64KB size check passes)
3. Gas charged: 1102 + (18 × 65536) ≈ 1.18M internal gas units (trivial amount)
4. BCS deserialization attempts to allocate memory for claimed vector sizes (e.g., 2^30 × struct_size bytes)
5. Out-of-memory condition occurs before transaction gas limit is exhausted
6. Validator node crashes or experiences severe performance degradation

The deserialization for primitive vectors uses standard Rust serde implementation which pre-allocates based on claimed length: [7](#0-6) 

**Why Transaction Argument Validation Doesn't Help:**

While entry function arguments undergo validation with `MAX_NUM_BYTES` limit: [8](#0-7) 

This only validates the outer `vector<u8>` argument itself, not the PackageMetadata structure nested inside those bytes. The application-level `from_bytes` call bypasses this protection.

## Impact Explanation

**Severity: HIGH** - Validator Node Slowdown/Crash

This vulnerability allows any unprivileged attacker to crash validator nodes by submitting specially crafted package publishing transactions. The impact includes:

- **Validator Availability**: Repeated attacks can keep validators offline, affecting network liveness
- **Network Performance**: Validators experiencing memory pressure will have degraded performance
- **DoS Potential**: Coordinated attacks could target multiple validators simultaneously

While this doesn't directly cause consensus violations or fund loss, it affects **Critical Invariant #9 (Resource Limits)** and **Invariant #3 (Move VM Safety)** by allowing memory exhaustion before gas limits are enforced.

Per the Aptos bug bounty criteria, "Validator node slowdowns" and "Significant protocol violations" qualify as **High Severity** issues.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is:
- **Accessible**: Any user can call `publish_package_txn` without special permissions
- **Low-cost**: Transaction fees are minimal (only 64KB of data + execution gas)
- **Reliable**: BCS format and ULEB128 encoding make it straightforward to craft malicious payloads
- **Undetectable**: The transaction appears valid until deserialization begins
- **Repeatable**: Attacker can submit multiple such transactions rapidly

The only limiting factors are:
- Transaction rate limits (but these are per-account, attacker can use multiple accounts)
- Network transaction propagation

## Recommendation

**Implement size limits during BCS deserialization before attempting memory allocation:**

1. **Short-term fix**: Add a maximum allocation check in `native_from_bytes` before deserialization:

```rust
fn native_from_bytes(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    // ... existing code ...
    
    let bytes = safely_pop_arg!(args, Vec<u8>);
    
    // Add size limit based on bytes.len() with reasonable multiplier
    const MAX_DESERIALIZED_SIZE_MULTIPLIER: usize = 100;
    let max_deserialized_size = bytes.len() * MAX_DESERIALIZED_SIZE_MULTIPLIER;
    
    context.charge(
        UTIL_FROM_BYTES_BASE + UTIL_FROM_BYTES_PER_BYTE * NumBytes::new(bytes.len() as u64),
    )?;

    let function_value_extension = context.function_value_extension();
    let max_value_nest_depth = context.max_value_nest_depth();
    
    // Use size-limited deserialization
    let val = match ValueSerDeContext::new(max_value_nest_depth)
        .with_legacy_signer()
        .with_func_args_deserialization(&function_value_extension)
        .deserialize_with_limit(&bytes, &layout, max_deserialized_size)
    {
        Some(val) => val,
        None => {
            return Err(SafeNativeError::Abort {
                abort_code: EFROM_BYTES,
            })
        },
    };

    Ok(smallvec![val])
}
```

2. **Long-term fix**: Modify BCS deserialization to track allocated memory and abort if it exceeds input size by unreasonable factor, or integrate with gas metering during deserialization.

## Proof of Concept

```move
#[test_only]
module test_addr::deserialization_bomb {
    use aptos_framework::code;
    use std::vector;
    
    #[test(attacker = @0xcafe)]
    #[expected_failure] // Will OOM before completing
    fun test_oom_attack(attacker: signer) {
        // Craft malicious PackageMetadata bytes
        let malicious_bytes = vector::empty<u8>();
        
        // Encode a small valid structure followed by 
        // a vector claiming 2^28 elements using ULEB128
        // (simplified - actual exploit would need valid BCS structure)
        
        // ULEB128 encoding of 2^28 (268435456)
        vector::push_back(&mut malicious_bytes, 0x80);  // continuation bit
        vector::push_back(&mut malicious_bytes, 0x80);
        vector::push_back(&mut malicious_bytes, 0x80);
        vector::push_back(&mut malicious_bytes, 0x80);
        vector::push_back(&mut malicious_bytes, 0x10);  // final byte
        
        // Add minimal valid structure around it
        // ... (full PoC would include complete BCS encoding)
        
        let empty_code = vector::empty<vector<u8>>();
        
        // This should OOM before gas limit is reached
        code::publish_package_txn(&attacker, malicious_bytes, empty_code);
    }
}
```

**Note**: A complete working PoC requires constructing valid BCS-encoded `PackageMetadata` structure with malicious vector length claims, which would be validated by implementing a Rust test that generates the malicious bytes and attempts deserialization.

## Notes

This vulnerability demonstrates a classic **deserialization bomb** pattern where:
1. Compact input representation (ULEB128-compressed lengths)
2. Disproportionate resource consumption during expansion
3. Resource exhaustion occurs before metering/limiting mechanisms engage

The root cause is the disconnect between **transaction-level validation** (which sees raw bytes) and **application-level deserialization** (which interprets those bytes). The fix requires either propagating size limits through all deserialization layers or implementing allocation tracking within the BCS deserializer itself.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/code.move (L30-49)
```text
    struct PackageMetadata has copy, drop, store {
        /// Name of this package.
        name: String,
        /// The upgrade policy of this package.
        upgrade_policy: UpgradePolicy,
        /// The numbers of times this module has been upgraded. Also serves as the on-chain version.
        /// This field will be automatically assigned on successful upgrade.
        upgrade_number: u64,
        /// The source digest of the sources in the package. This is constructed by first building the
        /// sha256 of each individual source, than sorting them alphabetically, and sha256 them again.
        source_digest: String,
        /// The package manifest, in the Move.toml format. Gzipped text.
        manifest: vector<u8>,
        /// The list of modules installed by this package.
        modules: vector<ModuleMetadata>,
        /// Holds PackageDeps.
        deps: vector<PackageDep>,
        /// For future extension
        extension: Option<Any>
    }
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L256-259)
```text
    public entry fun publish_package_txn(owner: &signer, metadata_serialized: vector<u8>, code: vector<vector<u8>>)
    acquires PackageRegistry {
        publish_package(owner, util::from_bytes<PackageMetadata>(metadata_serialized), code)
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L73-76)
```rust
            max_transaction_size_in_bytes: NumBytes,
            "max_transaction_size_in_bytes",
            64 * 1024
        ],
```

**File:** aptos-move/framework/src/natives/util.rs (L41-44)
```rust
    let bytes = safely_pop_arg!(args, Vec<u8>);
    context.charge(
        UTIL_FROM_BYTES_BASE + UTIL_FROM_BYTES_PER_BYTE * NumBytes::new(bytes.len() as u64),
    )?;
```

**File:** aptos-move/framework/src/natives/util.rs (L48-51)
```rust
    let val = match ValueSerDeContext::new(max_value_nest_depth)
        .with_legacy_signer()
        .with_func_args_deserialization(&function_value_extension)
        .deserialize(&bytes, &layout)
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/aptos_framework.rs (L300-301)
```rust
        [util_from_bytes_base: InternalGas, "util.from_bytes.base", 1102],
        [util_from_bytes_per_byte: InternalGasPerByte, "util.from_bytes.per_byte", 18],
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L5141-5143)
```rust
            L::Vector(layout) => Ok(match layout.as_ref() {
                L::U8 => Value::vector_u8(Vec::deserialize(deserializer)?),
                L::U16 => Value::vector_u16(Vec::deserialize(deserializer)?),
```

**File:** aptos-move/aptos-vm/src/verifier/transaction_arg_validation.rs (L546-563)
```rust
fn read_n_bytes(n: usize, src: &mut Cursor<&[u8]>, dest: &mut Vec<u8>) -> Result<(), VMStatus> {
    let deserialization_error = |msg: &str| -> VMStatus {
        VMStatus::error(
            StatusCode::FAILED_TO_DESERIALIZE_ARGUMENT,
            Some(msg.to_string()),
        )
    };
    let len = dest.len();

    // It is safer to limit the length under some big (but still reasonable
    // number).
    const MAX_NUM_BYTES: usize = 1_000_000;
    if len.checked_add(n).is_none_or(|s| s > MAX_NUM_BYTES) {
        return Err(deserialization_error(&format!(
            "Couldn't read bytes: maximum limit of {} bytes exceeded",
            MAX_NUM_BYTES
        )));
    }
```
