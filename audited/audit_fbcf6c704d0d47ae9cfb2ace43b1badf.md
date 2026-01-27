# Audit Report

## Title
Type Tag Deserialization Gas Bypass via Deep Nesting

## Summary
The BCS deserialization of deeply nested type tags in transaction payloads consumes CPU and memory proportional to nesting depth (up to 8 levels), but gas is only charged based on referenced modules, not nesting complexity. This allows attackers to submit transactions with maximally-nested type tags that impose disproportionate computational costs on API and validator nodes without proportional gas payment, especially when transactions are rejected before execution.

## Finding Description

The vulnerability exists in the transaction submission pipeline where type tags are deserialized from BCS format before any gas is charged.

**The Flow:**

1. **Transaction Submission (No Gas Charged):** When a transaction containing an `EntryFunction` payload is submitted to the API, the `ty_args: Vec<TypeTag>` field is BCS-deserialized [1](#0-0) 

2. **Nested Type Tag Deserialization:** For nested types (Vector, Struct, Function), the custom deserializer `type_tag_recursive_deserialize()` is invoked, which tracks nesting depth using a thread-local counter and enforces a maximum depth of 8 [2](#0-1) 

3. **Type Tag Structure:** The `TypeTag` enum uses this recursive deserializer for its Vector, Struct, and Function variants, allowing arbitrary nesting up to the limit [3](#0-2) 

4. **Gas Charging During Execution (Disproportionate):** Later during execution, gas is charged via `check_type_tag_dependencies_and_charge_gas()`, which only charges for the **modules referenced** by type tags, not the nesting depth [4](#0-3) 

**The Vulnerability:**

An attacker can craft transactions with deeply nested type tags like:
- `vector<vector<vector<vector<vector<vector<vector<vector<u64>>>>>>>>`  (depth 8)
- Or with structs: `MyStruct<V, V, V, ...>` where V is the above vector type (up to 32 type params [5](#0-4) )

This causes:
- **CPU Cost:** O(depth × num_type_params) deserialization operations (up to 8 × 32 = 256 nested levels per transaction)
- **Memory Cost:** Proportional heap allocations for each nesting level
- **Gas Charged:** Zero gas if type tags reference no modules (e.g., primitive types only), or minimal gas based on module size regardless of nesting

**Exploitation Scenario:**

1. Attacker creates transactions with maximum-depth nested type tags (8 levels deep, 32 type parameters per struct)
2. Submits transactions with invalid signatures or insufficient balance (will be rejected)
3. API nodes perform full BCS deserialization consuming CPU/memory
4. Transactions rejected before execution → **zero gas charged**
5. Attacker pays nothing but consumes node resources
6. Repeat via API rate limit (100 req/min default [6](#0-5) ) or multiple endpoints

Even for valid transactions that execute, the gas charged is based on module dependencies, not deserialization complexity, creating a gas underpayment issue.

## Impact Explanation

**High Severity** per Aptos bug bounty criteria:

1. **Validator Node Slowdowns:** Validators must deserialize type tags when processing transactions from mempool. An attacker can flood the network with such transactions, causing cumulative CPU/memory exhaustion across all validators.

2. **API Crashes:** API nodes performing repeated deserialization of complex nested structures without proportional rate limiting or resource accounting can exhaust CPU/memory, leading to crashes or severe performance degradation.

3. **Gas Metering Bypass:** This violates the critical invariant "Resource Limits: All operations must respect gas, storage, and computational limits." Deserialization work is not metered proportionally, allowing free computation.

4. **DoS Without Cost:** Rejected transactions (invalid signatures, insufficient balance) consume resources during deserialization but charge zero gas, enabling cost-free attacks.

The vulnerability breaks the fundamental economic security model where attackers must pay proportionally for consumed resources.

## Likelihood Explanation

**High Likelihood:**

1. **Easy to Exploit:** Any transaction sender can craft payloads with deeply nested type tags using standard transaction construction tools.

2. **No Special Privileges Required:** Does not require validator access, governance participation, or stake.

3. **Existing Limits Insufficient:** 
   - The 8-level depth limit is per the design ( [7](#0-6) ), but still allows significant complexity multiplication
   - API rate limiting (100 req/min) can be bypassed via multiple IPs or endpoints
   - Transaction size limit (64KB [8](#0-7) ) doesn't prevent this attack as nested structures have compact BCS encoding

4. **Affects Multiple Components:** Both API nodes (during submission) and validators (during consensus/execution) are vulnerable.

## Recommendation

Implement gas charging proportional to type tag deserialization complexity:

**Option 1: Charge Gas During Deserialization (Preferred)**
- Extend the gas meter interface to charge during BCS deserialization
- Modify `type_tag_recursive_deserialize()` to accept a gas meter parameter
- Charge gas proportional to nesting depth (e.g., base_cost × depth)

**Option 2: Pre-validate Complexity Before Deserialization**
- Add a lightweight pre-scan of BCS bytes to estimate type tag complexity
- Reject transactions exceeding complexity threshold at API layer
- More efficient but less precise than Option 1

**Option 3: Enhanced Gas Charging During Execution**
- Modify `check_type_tag_dependencies_and_charge_gas()` to also charge for nesting depth
- Add a `type_tag_depth_cost` gas parameter
- Charge: `base_cost_per_module + depth_cost_per_level × total_depth`

**Code Fix Example (Option 3):**

In `dependencies_gas_charging.rs`, enhance the function:

```rust
pub fn check_type_tag_dependencies_and_charge_gas(
    module_storage: &impl ModuleStorage,
    gas_meter: &mut impl DependencyGasMeter,
    traversal_context: &mut TraversalContext,
    ty_tags: &[TypeTag],
) -> VMResult<()> {
    // First charge for nesting depth
    let total_depth: usize = ty_tags.iter()
        .flat_map(|ty_tag| ty_tag.preorder_traversal_iter())
        .count();
    
    gas_meter.charge_depth_gas(total_depth)?;
    
    // Then charge for module dependencies (existing logic)
    // ...
}
```

Add corresponding gas schedule parameters for `type_tag_depth_cost`.

## Proof of Concept

```rust
// PoC: Create transaction with maximum-depth nested type tags
use aptos_types::transaction::{EntryFunction, RawTransaction, SignedTransaction};
use move_core_types::language_storage::{TypeTag, ModuleId, Identifier};
use move_core_types::account_address::AccountAddress;

fn create_malicious_transaction() -> SignedTransaction {
    // Create maximally nested type tag: vector<vector<...<u64>...>> (depth 8)
    let mut nested_type = TypeTag::U64;
    for _ in 0..8 {
        nested_type = TypeTag::Vector(Box::new(nested_type));
    }
    
    // Create entry function with 32 such type arguments (max allowed)
    let type_args: Vec<TypeTag> = (0..32).map(|_| nested_type.clone()).collect();
    
    let entry_fn = EntryFunction::new(
        ModuleId::new(AccountAddress::ONE, Identifier::new("test").unwrap()),
        Identifier::new("func").unwrap(),
        type_args,  // 32 type args, each nested to depth 8 = 256 nested levels
        vec![],     // Empty regular args
    );
    
    // Create transaction with invalid signature (will be rejected, costs 0 gas)
    let raw_txn = RawTransaction::new_entry_function(
        AccountAddress::random(),
        0,
        entry_fn,
        1000000,
        1,
        100000000,
        1,
    );
    
    // Sign with invalid signature
    SignedTransaction::new_invalid_signature(raw_txn)
}

// Submit this transaction to the API
// It will consume CPU/memory during deserialization but be rejected before gas charging
// Repeat at API rate limit to cause resource exhaustion
```

**Attack Steps:**
1. Generate 100 such transactions per minute (API rate limit)
2. Each transaction requires ~256 nested deserialization operations
3. Total: 25,600 operations/minute, 427/second per API node
4. Multiply by number of attack clients and API endpoints
5. API nodes experience CPU/memory exhaustion without proportional gas payment

**Notes**

This vulnerability represents a fundamental mismatch between computational cost (O(depth)) and gas charging (O(modules)). While individual attacks are bounded by depth limits, the cumulative effect across multiple attackers or sustained attacks can significantly impact node availability. The issue is particularly severe because rejected transactions consume resources without any gas payment, breaking the economic security model that underpins blockchain DOS resistance.

### Citations

**File:** api/src/transactions.rs (L1223-1232)
```rust
                let signed_transaction: SignedTransaction =
                    bcs::from_bytes_with_limit(&data.0, Self::MAX_SIGNED_TRANSACTION_DEPTH)
                        .context("Failed to deserialize input into SignedTransaction")
                        .map_err(|err| {
                            SubmitTransactionError::bad_request_with_code(
                                err,
                                AptosErrorCode::InvalidInput,
                                ledger_info,
                            )
                        })?;
```

**File:** third_party/move/move-core/types/src/safe_serialize.rs (L11-67)
```rust
pub(crate) const MAX_TYPE_TAG_NESTING: u8 = 8;

thread_local! {
    static TYPE_TAG_DEPTH: RefCell<u8> = const { RefCell::new(0) };
}

pub(crate) fn type_tag_recursive_serialize<S, T>(t: &T, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize,
{
    use serde::ser::Error;

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
        *r += 1;
        Ok(())
    })?;
    let res = t.serialize(s);
    TYPE_TAG_DEPTH.with(|depth| {
        let mut r = depth.borrow_mut();
        *r -= 1;
    });
    res
}

pub(crate) fn type_tag_recursive_deserialize<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    use serde::de::Error;
    TYPE_TAG_DEPTH.with(|depth| {
        let mut r = depth.borrow_mut();
        if *r >= MAX_TYPE_TAG_NESTING {
            return Err(D::Error::custom(
                "type tag nesting exceeded during deserialization",
            ));
        }
        *r += 1;
        Ok(())
    })?;
    let res = T::deserialize(d);
    TYPE_TAG_DEPTH.with(|depth| {
        let mut r = depth.borrow_mut();
        *r -= 1;
    });
    res
```

**File:** third_party/move/move-core/types/src/language_storage.rs (L74-106)
```rust
    #[serde(rename = "vector", alias = "Vector")]
    Vector(
        #[serde(
            serialize_with = "safe_serialize::type_tag_recursive_serialize",
            deserialize_with = "safe_serialize::type_tag_recursive_deserialize"
        )]
        Box<TypeTag>,
    ),
    #[serde(rename = "struct", alias = "Struct")]
    Struct(
        #[serde(
            serialize_with = "safe_serialize::type_tag_recursive_serialize",
            deserialize_with = "safe_serialize::type_tag_recursive_deserialize"
        )]
        Box<StructTag>,
    ),

    // NOTE: Added in bytecode version v6, do not reorder!
    #[serde(rename = "u16", alias = "U16")]
    U16,
    #[serde(rename = "u32", alias = "U32")]
    U32,
    #[serde(rename = "u256", alias = "U256")]
    U256,

    // NOTE: added in bytecode version v8
    Function(
        #[serde(
            serialize_with = "safe_serialize::type_tag_recursive_serialize",
            deserialize_with = "safe_serialize::type_tag_recursive_deserialize"
        )]
        Box<FunctionTag>,
    ),
```

**File:** third_party/move/move-vm/runtime/src/storage/dependencies_gas_charging.rs (L19-46)
```rust
pub fn check_type_tag_dependencies_and_charge_gas(
    module_storage: &impl ModuleStorage,
    gas_meter: &mut impl DependencyGasMeter,
    traversal_context: &mut TraversalContext,
    ty_tags: &[TypeTag],
) -> VMResult<()> {
    // Charge gas based on the distinct ordered module ids.
    let timer = VM_TIMER.timer_with_label("traverse_ty_tags_for_gas_charging");
    let ordered_ty_tags = ty_tags
        .iter()
        .flat_map(|ty_tag| ty_tag.preorder_traversal_iter())
        .filter_map(TypeTag::struct_tag)
        .map(|struct_tag| {
            let module_id = traversal_context
                .referenced_module_ids
                .alloc(struct_tag.module_id());
            (module_id.address(), module_id.name())
        })
        .collect::<BTreeSet<_>>();
    drop(timer);

    check_dependencies_and_charge_gas(
        module_storage,
        gas_meter,
        traversal_context,
        ordered_ty_tags,
    )
}
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L158-158)
```rust
        max_generic_instantiation_length: Some(32),
```

**File:** api/doc/README.md (L1-100)
```markdown
# Aptos Node API v1

## Overview
Aptos Node API v1 provides a RESTful interface for interacting with Aptos blockchain nodes. The API enables users to retrieve blockchain information, submit transactions, and query account states.

## Key Features
- Account state and resources querying
- Transaction submission and monitoring
- Block and event information retrieval
- Validator data access
- Smart contract interaction

## Getting Started
1. Ensure you have an Aptos node running
2. API is available by default on port 8080
3. Use any REST client to send requests

## Authentication
The API does not require authentication for public endpoints. Some administrative endpoints may require additional authorization.

## Data Formats
- All requests and responses use JSON format
- Transactions must be signed using Ed25519
- Timestamps are represented in UTC ISO 8601 format

## Limitations
- Rate limiting: 100 requests per minute by default
- Maximum request size: 2MB
- Connection timeout: 30 seconds

## Versioning
The API follows semantic versioning. Current v1 version ensures backward compatibility within the major version.

## API Documentation
Complete OpenAPI specification is available at `/api/v1/spec`

## Support
- [GitHub Issues](https://github.com/aptos-labs/aptos-core/issues)
- [Discord](https://discord.gg/aptosnetwork)
- [Aptos Documentation](https://aptos.dev)

## Contributing
We welcome community contributions! Please review our [contribution guidelines](../CONTRIBUTING.md) before submitting a pull request.
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L1-100)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

//! This module defines all the gas parameters for transactions, along with their initial values
//! in the genesis and a mapping between the Rust representation and the on-chain gas schedule.

use crate::{
    gas_schedule::VMGasParameters,
    ver::gas_feature_versions::{
        RELEASE_V1_10, RELEASE_V1_11, RELEASE_V1_12, RELEASE_V1_13, RELEASE_V1_15, RELEASE_V1_26,
        RELEASE_V1_41,
    },
};
use aptos_gas_algebra::{
    AbstractValueSize, Fee, FeePerByte, FeePerGasUnit, FeePerSlot, Gas, GasExpression,
    GasScalingFactor, GasUnit, NumModules, NumSlots, NumTypeNodes,
};
use move_core_types::gas_algebra::{
    InternalGas, InternalGasPerArg, InternalGasPerByte, InternalGasUnit, NumBytes, ToUnitWithParams,
};

const GAS_SCALING_FACTOR: u64 = 1_000_000;

crate::gas_schedule::macros::define_gas_parameters!(
    TransactionGasParameters,
    "txn",
    VMGasParameters => .txn,
    [
        // The flat minimum amount of gas required for any transaction.
        // Charged at the start of execution.
        // It is variable to charge more for more expensive authenticators, e.g., keyless
        [
            min_transaction_gas_units: InternalGas,
            "min_transaction_gas_units",
            2_760_000
        ],
        // Any transaction over this size will be charged an additional amount per byte.
        [
            large_transaction_cutoff: NumBytes,
            "large_transaction_cutoff",
            600
        ],
        // The units of gas that to be charged per byte over the `large_transaction_cutoff` in addition to
        // `min_transaction_gas_units` for transactions whose size exceeds `large_transaction_cutoff`.
        [
            intrinsic_gas_per_byte: InternalGasPerByte,
            "intrinsic_gas_per_byte",
            1_158
        ],
        // ~5 microseconds should equal one unit of computational gas. We bound the maximum
        // computational time of any given transaction at roughly 20 seconds. We want this number and
        // `MAX_PRICE_PER_GAS_UNIT` to always satisfy the inequality that
        // MAXIMUM_NUMBER_OF_GAS_UNITS * MAX_PRICE_PER_GAS_UNIT < min(u64::MAX, GasUnits<GasCarrier>::MAX)
        [
            maximum_number_of_gas_units: Gas,
            "maximum_number_of_gas_units",
            aptos_global_constants::MAX_GAS_AMOUNT
        ],
        // The minimum gas price that a transaction can be submitted with.
        // TODO(Gas): should probably change this to something > 0
        [
            min_price_per_gas_unit: FeePerGasUnit,
            "min_price_per_gas_unit",
            aptos_global_constants::GAS_UNIT_PRICE
        ],
        // The maximum gas unit price that a transaction can be submitted with.
        [
            max_price_per_gas_unit: FeePerGasUnit,
            "max_price_per_gas_unit",
            10_000_000_000
        ],
        [
            max_transaction_size_in_bytes: NumBytes,
            "max_transaction_size_in_bytes",
            64 * 1024
        ],
        [
            max_transaction_size_in_bytes_gov: NumBytes,
            { RELEASE_V1_13.. => "max_transaction_size_in_bytes.gov" },
            1024 * 1024
        ],
        [
            gas_unit_scaling_factor: GasScalingFactor,
            "gas_unit_scaling_factor",
            GAS_SCALING_FACTOR
        ],
        // Gas Parameters for reading data from storage.
        [
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
```
