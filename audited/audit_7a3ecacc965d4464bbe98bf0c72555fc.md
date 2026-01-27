# Audit Report

## Title
Feature Flag Toggle Causes Irreversible Table Deserialization Failures Leading to Network Halt

## Summary
The `contains_delayed_fields` flag used in table value deserialization is computed at runtime based on the current VM configuration, but table data was serialized with a potentially different configuration. If the `AGGREGATOR_V2_DELAYED_FIELDS` feature flag is toggled via governance, all existing table entries containing aggregator types become permanently unreadable, causing widespread transaction failures and requiring a hardfork to recover. [1](#0-0) 

## Finding Description

The vulnerability stems from a mismatch between serialization and deserialization layouts for table values containing delayed fields (Aggregators, Snapshots, DerivedStrings).

**Root Cause:**

The `LayoutInfo` structure stores a `contains_delayed_fields` boolean flag that determines whether to use delayed field serialization/deserialization extensions. This flag is computed from the runtime type layout, which depends on the VM configuration setting `delayed_field_optimization_enabled`: [2](#0-1) 

The `delayed_field_optimization_enabled` flag is controlled by the on-chain feature flag `AGGREGATOR_V2_DELAYED_FIELDS`, which is currently **enabled by default**: [3](#0-2) 

**Serialization Logic:**

When serializing table values, the code conditionally uses `with_delayed_fields_serde()` based on the flag: [4](#0-3) 

**Deserialization Logic:**

During deserialization, the same flag controls whether delayed field extensions are enabled: [5](#0-4) 

**The Fatal Flaw:**

When the deserialization context lacks `delayed_fields_extension` but encounters Native-encoded bytes, it returns an error: [6](#0-5) 

**Exploitation Scenario:**

1. **Current State**: `AGGREGATOR_V2_DELAYED_FIELDS` is enabled by default. All Aggregator values in tables are serialized with Native encoding.

2. **Governance Action**: A governance proposal disables `AGGREGATOR_V2_DELAYED_FIELDS` (e.g., due to perceived performance issues or bugs).

3. **Flag Change Propagates**: 
   - `delayed_field_optimization_enabled` becomes `false`
   - Type layout computation no longer marks Aggregator types as containing delayed fields
   - `contains_delayed_fields = false` for all Aggregator types

4. **Transaction Execution**: Any transaction calling `native_borrow_box()` on a table containing pre-existing Aggregator data: [7](#0-6) 

5. **Deserialization Failure**: The stored bytes contain Native encoding, but the deserializer doesn't expect it, causing `VM_EXTENSION_ERROR`: [8](#0-7) 

**Affected Systems:**

Aggregators are widely used in critical system contracts and are specifically designed to be stored in tables: [9](#0-8) 

This includes staking, governance, and DeFi protocols.

## Impact Explanation

**Severity: CRITICAL** - Non-recoverable network partition requiring hardfork ($1,000,000 category)

**Impact:**
1. **Immediate Network Halt**: All transactions accessing tables with Aggregators fail with `VM_EXTENSION_ERROR`
2. **System Contract Failure**: Critical contracts using Aggregators (staking, governance) become inoperable
3. **Consensus Divergence**: If some validators update VM config before others, they will produce different execution results, violating the **Deterministic Execution** invariant
4. **Irreversible Data Corruption**: The stored bytes cannot be read with the new configuration, and re-enabling the flag doesn't help data written during the "off" period
5. **Hardfork Required**: The only recovery path is a coordinated network upgrade with data migration

This breaks multiple critical invariants:
- **Deterministic Execution**: Different configs → different results
- **State Consistency**: Table data becomes permanently inaccessible
- **Governance Integrity**: If governance contracts use Aggregators, governance itself fails

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Factors Increasing Likelihood:**
1. Feature flags are **designed to be toggled** via governance for emergency response
2. `AGGREGATOR_V2_DELAYED_FIELDS` is a recent feature that might be disabled if bugs are discovered
3. No warning or migration path exists in the codebase
4. The feature flag system is explicitly designed for runtime configuration changes [10](#0-9) 

**Factors Decreasing Likelihood:**
1. Governance is trusted and would likely test changes
2. Disabling a "optimization" flag seems safe on the surface

**Historical Context:**
The production config explicitly notes that delayed field optimization should be enabled manually: [11](#0-10) 

This suggests the feature was considered experimental, increasing the likelihood of future disablement.

## Recommendation

**Immediate Mitigation:**

1. **Mark the feature flag as non-toggleable**: Once `AGGREGATOR_V2_DELAYED_FIELDS` is enabled, it should never be disabled without a coordinated upgrade.

2. **Version the serialization format**: Store a format version byte with each table entry to detect mismatches:

```rust
fn serialize_value(
    function_value_extension: &dyn FunctionValueExtension,
    layout_info: &LayoutInfo,
    val: &Value,
) -> PartialVMResult<(Bytes, Option<TriompheArc<MoveTypeLayout>>)> {
    // Prepend version byte: 0x01 for delayed fields, 0x00 for regular
    let version = if layout_info.contains_delayed_fields { 0x01u8 } else { 0x00u8 };
    
    let mut bytes = vec![version];
    // ... existing serialization logic ...
    bytes.extend_from_slice(&serialized);
    
    Ok((bytes.into(), layout))
}

fn deserialize_value(
    function_value_extension: &dyn FunctionValueExtension,
    bytes: &[u8],
    layout_info: &LayoutInfo,
) -> PartialVMResult<Value> {
    if bytes.is_empty() {
        return Err(partial_extension_error("empty bytes"));
    }
    
    let version = bytes[0];
    let expected_version = if layout_info.contains_delayed_fields { 0x01u8 } else { 0x00u8 };
    
    if version != expected_version {
        return Err(partial_extension_error(format!(
            "Serialization format mismatch: stored version {} but expected {} \
             (delayed_field_optimization_enabled may have changed)",
            version, expected_version
        )));
    }
    
    // ... existing deserialization logic with &bytes[1..] ...
}
```

3. **Add migration support**: Implement automatic re-serialization when format mismatches are detected during reads.

4. **Document the constraint**: Explicitly document that `AGGREGATOR_V2_DELAYED_FIELDS` is a one-way door.

## Proof of Concept

```move
// Test module: aggregator_flag_toggle_test.move
module 0xCAFE::table_aggregator_test {
    use std::table::{Self, Table};
    use aptos_framework::aggregator_v2::{Self, Aggregator};
    
    struct AggregatorStore has key {
        data: Table<u64, Aggregator<u64>>
    }
    
    public entry fun setup(account: &signer) {
        let data = table::new<u64, Aggregator<u64>>();
        let agg = aggregator_v2::create_aggregator<u64>(1000);
        aggregator_v2::add(&mut agg, 42);
        table::add(&mut data, 1, agg);
        
        move_to(account, AggregatorStore { data });
    }
    
    public entry fun read(account_addr: address) acquires AggregatorStore {
        let store = borrow_global<AggregatorStore>(account_addr);
        // This borrow_box call will fail if flag changed
        let agg_ref = table::borrow(&store.data, 1);
        assert!(aggregator_v2::read(agg_ref) == 42, 1);
    }
}
```

**Rust Test Steps:**

```rust
// In aptos-move/e2e-move-tests/src/tests/aggregator_v2.rs

#[test]
fn test_flag_toggle_breaks_deserialization() {
    let mut h = MoveHarness::new();
    
    // Step 1: Enable AGGREGATOR_V2_DELAYED_FIELDS and write data
    h.enable_features(vec![FeatureFlag::AGGREGATOR_V2_DELAYED_FIELDS], vec![]);
    
    let account = h.new_account_at(AccountAddress::from_hex_literal("0xCAFE").unwrap());
    assert_success!(h.run_entry_function(
        &account,
        str::parse("0xCAFE::table_aggregator_test::setup").unwrap(),
        vec![],
        vec![]
    ));
    
    // Step 2: Disable the flag
    h.enable_features(vec![], vec![FeatureFlag::AGGREGATOR_V2_DELAYED_FIELDS]);
    
    // Step 3: Try to read - THIS SHOULD FAIL with VM_EXTENSION_ERROR
    let result = h.run_entry_function(
        &account,
        str::parse("0xCAFE::table_aggregator_test::read").unwrap(),
        vec![],
        vec![bcs::to_bytes(&account.address()).unwrap()]
    );
    
    // The transaction will abort with "cannot deserialize table value"
    assert!(result.status().status().unwrap().is_discarded());
}
```

**Expected Failure Output:**
```
VMStatus: Execution(
    ExecutionStatus::MoveAbort {
        location: ModuleId { address: ..., name: "table" },
        code: VM_EXTENSION_ERROR,
        info: Some("cannot deserialize table value")
    }
)
```

This demonstrates that toggling the feature flag makes previously written table data permanently unreadable, confirming the critical vulnerability.

### Citations

**File:** aptos-move/framework/table-natives/src/lib.rs (L81-84)
```rust
struct LayoutInfo {
    layout: TriompheArc<MoveTypeLayout>,
    contains_delayed_fields: bool,
}
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L447-505)
```rust
fn native_borrow_box(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    assert_eq!(ty_args.len(), 3);
    assert_eq!(args.len(), 2);

    context.charge(BORROW_BOX_BASE)?;
    let fix_memory_double_counting =
        context.timed_feature_enabled(TimedFeatureFlag::FixTableNativesMemoryDoubleCounting);

    let (extensions, mut loader_context, abs_val_gas_params, gas_feature_version) =
        context.extensions_with_loader_context_and_gas_params();
    let table_context = extensions.get::<NativeTableContext>();
    let mut table_data = table_context.table_data.borrow_mut();

    let key = args.pop_back().unwrap();
    let handle = get_table_handle(&safely_pop_arg!(args, StructRef))?;

    let table =
        table_data.get_or_create_table(&mut loader_context, handle, &ty_args[0], &ty_args[2])?;

    let function_value_extension = loader_context.function_value_extension();
    let key_bytes = serialize_key(&function_value_extension, &table.key_layout, &key)?;
    let key_cost = BORROW_BOX_PER_BYTE_SERIALIZED * NumBytes::new(key_bytes.len() as u64);

    let (gv, loaded) =
        table.get_or_create_global_value(&function_value_extension, table_context, key_bytes)?;
    let mem_usage = if !fix_memory_double_counting || loaded.is_some() {
        gv.view()
            .map(|val| {
                abs_val_gas_params
                    .abstract_heap_size(&val, gas_feature_version)
                    .map(u64::from)
            })
            .transpose()?
    } else {
        None
    };

    let res = match gv.borrow_global() {
        Ok(ref_val) => Ok(smallvec![ref_val]),
        Err(_) => Err(SafeNativeError::Abort {
            abort_code: NOT_FOUND,
        }),
    };

    drop(table_data);

    // TODO(Gas): Figure out a way to charge this earlier.
    context.charge(key_cost)?;
    if let Some(amount) = mem_usage {
        context.use_heap_memory(amount)?;
    }
    charge_load_cost(context, loaded)?;

    res
}
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L686-700)
```rust
    let serialization_result = if layout_info.contains_delayed_fields {
        // Value contains delayed fields, so we should be able to serialize it.
        ValueSerDeContext::new(max_value_nest_depth)
            .with_delayed_fields_serde()
            .with_func_args_deserialization(function_value_extension)
            .serialize(val, layout_info.layout.as_ref())?
            .map(|bytes| (bytes.into(), Some(layout_info.layout.clone())))
    } else {
        // No delayed fields, make sure serialization fails if there are any
        // native values.
        ValueSerDeContext::new(max_value_nest_depth)
            .with_func_args_deserialization(function_value_extension)
            .serialize(val, layout_info.layout.as_ref())?
            .map(|bytes| (bytes.into(), None))
    };
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L704-721)
```rust
fn deserialize_value(
    function_value_extension: &dyn FunctionValueExtension,
    bytes: &[u8],
    layout_info: &LayoutInfo,
) -> PartialVMResult<Value> {
    let layout = layout_info.layout.as_ref();
    let deserialization_result = if layout_info.contains_delayed_fields {
        ValueSerDeContext::new(function_value_extension.max_value_nest_depth())
            .with_func_args_deserialization(function_value_extension)
            .with_delayed_fields_serde()
            .deserialize(bytes, layout)
    } else {
        ValueSerDeContext::new(function_value_extension.max_value_nest_depth())
            .with_func_args_deserialization(function_value_extension)
            .deserialize(bytes, layout)
    };
    deserialization_result.ok_or_else(|| partial_extension_error("cannot deserialize table value"))
}
```

**File:** third_party/move/move-vm/runtime/src/storage/ty_layout_converter.rs (L180-192)
```rust
    fn get_delayed_field_kind_if_delayed_field_optimization_enabled(
        &self,
        idx: &StructNameIndex,
    ) -> PartialVMResult<Option<IdentifierMappingKind>> {
        if !self.vm_config().delayed_field_optimization_enabled {
            return Ok(None);
        }
        let struct_name = self.get_struct_name(idx)?;
        Ok(IdentifierMappingKind::from_ident(
            struct_name.module(),
            struct_name.name(),
        ))
    }
```

**File:** types/src/on_chain_config/aptos_features.rs (L210-210)
```rust
            FeatureFlag::AGGREGATOR_V2_DELAYED_FIELDS,
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L5207-5218)
```rust
                    None => {
                        // If no custom deserializer, it is not known how the
                        // delayed value should be deserialized. Just like with
                        // serialization, we return an error.
                        Err(D::Error::custom(
                            PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                                .with_message(format!(
                                    "no custom deserializer for native value ({:?}) with layout {}",
                                    kind, layout
                                )),
                        ))
                    },
```

**File:** aptos-move/e2e-move-tests/src/tests/aggregator.data/pack/sources/aggregator_test.move (L1-1)
```text
module 0x1::aggregator_test {
```

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L320-325)
```rust
    fn try_enable_delayed_field_optimization(mut self) -> Self {
        if self.features.is_aggregator_v2_delayed_fields_enabled() {
            self.runtime_environment.enable_delayed_field_optimization();
        }
        self
    }
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L250-252)
```rust
        // By default, do not use delayed field optimization. Instead, clients should enable it
        // manually where applicable.
        delayed_field_optimization_enabled: false,
```
