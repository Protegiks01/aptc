# Audit Report

## Title
Unbounded Type Arguments in StructTag Enable Memory Exhaustion Attack on Validators

## Summary
The `StructTag` structure in `language_storage.rs` contains an unbounded `Vec<TypeTag>` for `type_args`, allowing attackers to craft transactions with millions of type arguments. While nesting depth is limited to 8 levels, there is no limit on the width (number of type arguments at a single level). This enables a memory amplification attack where a 6 MB transaction can force validators to allocate over 90 MB of memory during BCS deserialization, before any gas metering or validation occurs.

## Finding Description

The vulnerability exists in the `StructTag` definition which has an unbounded vector of type arguments: [1](#0-0) 

While there are protections against deep nesting via `MAX_TYPE_TAG_NESTING`: [2](#0-1) 

This only limits the DEPTH of nesting (e.g., `Struct<Struct<Struct<...>>>`), not the WIDTH (number of type arguments at one level).

**Attack Flow:**

1. **Transaction Creation**: Attacker crafts a transaction with an entry function type argument like `0x1::SomeModule::SomeStruct<u8, u8, u8, ..., u8>` containing millions of primitive type arguments.

2. **BCS Encoding Efficiency**: In BCS format, each `TypeTag::U8` is encoded as a single byte (just the enum discriminant). With the 6 MB transaction size limit: [3](#0-2) 

An attacker can fit approximately 6 million type arguments in a single transaction.

3. **Memory Amplification During Deserialization**: When the transaction is deserialized from BCS, the `Vec<TypeTag>` is allocated. Each `TypeTag` in memory occupies 16 bytes: [4](#0-3) 

This creates a memory amplification factor of 16x. A transaction with 6 million type arguments requires approximately **96 MB** of memory allocation (6,000,000 × 16 bytes).

4. **Pre-Validation Allocation**: This memory allocation happens during BCS deserialization of the transaction payload, which occurs BEFORE:
   - Gas metering starts
   - VM type validation begins
   - Any transaction execution

5. **VM Validation Fails Too Late**: When the VM attempts to process the type arguments via `create_ty_impl`: [5](#0-4) 

It iterates over all type arguments without checking the vector length first. The `max_ty_size` limit (128 nodes): [6](#0-5) 

Will cause the validation to fail after ~128 iterations, but by then the memory has already been allocated and the deserialization cost has been paid.

6. **Network-Wide Impact**: This attack affects:
   - All nodes receiving the transaction in mempool
   - All validators processing the transaction
   - Full nodes syncing blocks containing such transactions

**Existing Protections Are Insufficient:**

The `max_generic_instantiation_length` limit only applies to compiled Move modules, not transaction type arguments: [7](#0-6) [8](#0-7) 

## Impact Explanation

**Severity: High** (Validator node slowdowns and resource exhaustion)

This vulnerability enables a resource exhaustion attack with the following impacts:

1. **Memory Exhaustion**: Each malicious transaction can force 90+ MB allocations on every validator and full node that processes it. Multiple such transactions can quickly exhaust available memory.

2. **CPU Exhaustion**: Deserializing millions of type tags and iterating through them (even if failing early) consumes significant CPU cycles.

3. **Consensus Degradation**: If validators experience memory pressure or slowdowns from processing these transactions, it can delay block production and consensus rounds.

4. **Amplification Attack**: Attacker cost is minimal (transaction fees for a 6 MB transaction) but can force much larger resource consumption across all network participants.

5. **Deterministic Execution Violation**: Different nodes may handle memory pressure differently (OOM kills, swapping, etc.), potentially leading to non-deterministic behavior.

Per Aptos bug bounty criteria, this qualifies as **High Severity** due to "Validator node slowdowns" and resource exhaustion that can affect network liveness.

## Likelihood Explanation

**Likelihood: High**

This attack is highly likely to be exploited because:

1. **Low Barrier to Entry**: Any user can submit transactions to the network. No special privileges required.

2. **Low Cost**: Transaction fees are based on gas consumption and size. A 6 MB transaction is within normal limits and would be relatively cheap.

3. **Guaranteed Impact**: The memory allocation is deterministic and happens on all nodes processing the transaction.

4. **Repeatable**: Attack can be repeated in every block, compounding the resource exhaustion.

5. **Hard to Mitigate**: Without code changes, operators cannot prevent these transactions from being processed.

## Recommendation

Implement a limit on the number of type arguments in a `StructTag` during deserialization. This should be enforced at multiple layers:

**1. Add validation during TypeTag deserialization:**

Add a check in the BCS deserialization path before allocating the `type_args` vector. This could be done by implementing a custom deserializer for `StructTag` that validates the vector length before allocating.

**2. Add runtime validation:**

Add an early check in `create_ty_impl` before iterating over type arguments:

```rust
// In runtime_types.rs, create_ty_impl function
T::Struct(struct_tag) => {
    const MAX_TYPE_ARGS: usize = 32; // Match max_generic_instantiation_length
    if struct_tag.type_args.len() > MAX_TYPE_ARGS {
        return Err(
            PartialVMError::new(StatusCode::TOO_MANY_TYPE_PARAMETERS)
                .with_message(format!(
                    "Struct has {} type arguments, maximum is {}",
                    struct_tag.type_args.len(),
                    MAX_TYPE_ARGS
                ))
        );
    }
    // ... rest of processing
}
```

**3. Add a transaction validation check:**

In the transaction validation phase, check all type arguments in entry function calls:

```rust
// In aptos-vm or transaction validation
fn validate_type_args(ty_args: &[TypeTag]) -> Result<(), VMStatus> {
    const MAX_TYPE_ARGS: usize = 32;
    for ty_arg in ty_args {
        if let TypeTag::Struct(struct_tag) = ty_arg {
            if struct_tag.type_args.len() > MAX_TYPE_ARGS {
                return Err(VMStatus::error(
                    StatusCode::TOO_MANY_TYPE_PARAMETERS,
                    Some(format!("Type argument has {} generic parameters, maximum is {}", 
                        struct_tag.type_args.len(), MAX_TYPE_ARGS))
                ));
            }
        }
    }
    Ok(())
}
```

The limit should be consistent with `max_generic_instantiation_length` (currently 32) to maintain consistency across the system.

## Proof of Concept

**Rust Reproduction Steps:**

```rust
// Create a malicious StructTag with millions of type arguments
use move_core_types::language_storage::{StructTag, TypeTag};
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::Identifier;

fn create_malicious_type_arg() -> TypeTag {
    // Create a StructTag with 1 million u8 type arguments
    let type_args: Vec<TypeTag> = vec![TypeTag::U8; 1_000_000];
    
    let struct_tag = StructTag {
        address: AccountAddress::ONE,
        module: Identifier::new("test").unwrap(),
        name: Identifier::new("Test").unwrap(),
        type_args,
    };
    
    TypeTag::Struct(Box::new(struct_tag))
}

// Serialize to BCS
let malicious_type = create_malicious_type_arg();
let serialized = bcs::to_bytes(&malicious_type).unwrap();
println!("Serialized size: {} bytes", serialized.len()); 
// Will be around 1 MB (1 byte per TypeTag::U8)

// Deserialize - this will allocate 1,000,000 * 16 = 16 MB
let deserialized: TypeTag = bcs::from_bytes(&serialized).unwrap();
println!("Deserialized successfully, memory allocated");

// If used in a transaction, this would affect all validators
```

**Transaction Creation:**

```rust
use aptos_types::transaction::{EntryFunction, TransactionPayload};

// Create entry function with malicious type argument
let entry_fn = EntryFunction::new(
    ModuleId::new(AccountAddress::ONE, Identifier::new("module").unwrap()),
    Identifier::new("function").unwrap(),
    vec![create_malicious_type_arg()], // malicious type arg here
    vec![], // no regular args needed
);

let payload = TransactionPayload::EntryFunction(entry_fn);
// This transaction, when broadcast, will force memory allocation on all receiving nodes
```

**Notes**

The vulnerability exists because:
1. BCS deserialization doesn't limit vector lengths by default
2. The safe_serialize module only tracks nesting depth, not width
3. Memory size of TypeTag (16 bytes) is much larger than serialized size (~1 byte for primitives)
4. Validation in the VM happens after deserialization and memory allocation
5. No early bounds checking exists for the number of type arguments in transaction-provided type tags

### Citations

**File:** third_party/move/move-core/types/src/language_storage.rs (L216-223)
```rust
pub struct StructTag {
    pub address: AccountAddress,
    pub module: Identifier,
    pub name: Identifier,
    // alias for compatibility with old json serialized data.
    #[serde(rename = "type_args", alias = "type_params")]
    pub type_args: Vec<TypeTag>,
}
```

**File:** third_party/move/move-core/types/src/language_storage.rs (L660-660)
```rust
        assert_eq!(mem::size_of::<TypeTag>(), 16);
```

**File:** third_party/move/move-core/types/src/safe_serialize.rs (L11-11)
```rust
pub(crate) const MAX_TYPE_TAG_NESTING: u8 = 8;
```

**File:** aptos-move/e2e-testsuite/src/tests/verify_txn.rs (L30-30)
```rust
pub const MAX_TRANSACTION_SIZE_IN_BYTES: u64 = 6 * 1024 * 1024;
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L1478-1481)
```rust
                    for ty_arg in &struct_tag.type_args {
                        let ty_arg = self.create_ty_impl(ty_arg, resolver, count, depth + 1)?;
                        ty_args.push(ty_arg);
                    }
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L123-123)
```rust
        TypeBuilder::with_limits(max_ty_size.into(), max_ty_depth.into())
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L158-158)
```rust
        max_generic_instantiation_length: Some(32),
```

**File:** third_party/move/move-bytecode-verifier/src/limits.rs (L53-63)
```rust
    fn verify_struct_handles(&self, config: &VerifierConfig) -> PartialVMResult<()> {
        if let Some(limit) = config.max_generic_instantiation_length {
            for (idx, struct_handle) in self.resolver.struct_handles().iter().enumerate() {
                if struct_handle.type_parameters.len() > limit {
                    return Err(PartialVMError::new(StatusCode::TOO_MANY_TYPE_PARAMETERS)
                        .at_index(IndexKind::StructHandle, idx as u16));
                }
            }
        }
        Ok(())
    }
```
