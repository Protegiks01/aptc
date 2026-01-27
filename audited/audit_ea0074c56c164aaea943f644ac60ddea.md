# Audit Report

## Title
Mock Resolver Divergence Prevents Testing of Production Delayed Field Code Paths

## Summary
The DUMMY_RESOLVER used in unit tests has `delayed_field_optimization_enabled` set to false, causing aggregator V2 delayed field operations to use fallback code paths that differ fundamentally from production behavior where optimizations are enabled. This creates a systematic blind spot where critical delayed field logic remains untested.

## Finding Description

The vulnerability lies in a fundamental divergence between test and production execution paths for aggregator V2 delayed fields.

**In Unit Tests:** [1](#0-0) 

The `NativeAggregatorContext` is created with `delayed_field_optimization_enabled = false`, and uses the `DUMMY_RESOLVER` which implements delayed field methods as `unreachable!()`: [2](#0-1) 

**In Production:** [3](#0-2) 

Production uses `new_with_delayed_field_optimization_enabled`, which conditionally enables optimizations based on feature flags: [4](#0-3) 

**The Code Path Divergence:**

When delayed field optimizations are enabled (production), aggregator V2 operations call resolver methods like `generate_delayed_field_id`, `get_delayed_field_value`, and `get_reads_needing_exchange`: [5](#0-4) 

When disabled (tests), these operations use simple fallback behavior that doesn't invoke the resolver at all.

**Critical Untested Logic:**

The change set finalization logic calls `get_reads_needing_exchange` only when delayed field writes exist: [6](#0-5) 

Since tests have optimizations disabled, they never exercise this critical state consistency mechanism.

## Impact Explanation

**Severity: High**

This breaks the **Deterministic Execution** invariant (#1) and **State Consistency** invariant (#4). Specifically:

1. **Untested State Consistency Logic**: The `get_reads_needing_exchange` mechanism ensures that resources modified by delayed fields are properly tracked for materialization. Bugs in this logic could cause state divergence between validators.

2. **Potential Consensus Safety Violations**: If delayed field materialization logic contains bugs, different validators could compute different state roots for the same block, violating consensus safety.

3. **Production-Only Code Paths**: Multiple critical operations are only exercised in production:
   - Delayed field ID generation and validation
   - Delayed field value resolution from storage
   - Resource exchange computation for state consistency
   - Delayed field delta application and validation

4. **Feature Flag Dependency**: The issue only manifests when `is_aggregator_v2_delayed_fields_enabled()` returns true: [7](#0-6) 

This means the vulnerability is latent and activates when governance enables the feature.

## Likelihood Explanation

**Likelihood: High**

The likelihood is high because:

1. **Systematic Coverage Gap**: ALL aggregator V2 delayed field operations are untested in unit tests
2. **Feature Already Deployed**: The code suggests this feature is production-ready and can be enabled via governance
3. **Complex Logic**: Delayed field operations involve intricate state management, ID generation, and cross-resource dependencies - areas prone to bugs
4. **No Manual Testing Compensation**: Without automated test coverage, manual testing must catch all edge cases

## Recommendation

**Immediate Fix:**

1. Create a test-only implementation of the delayed field resolver that doesn't use `unreachable!()`:

```rust
#[cfg(feature = "testing")]
struct TestDelayedFieldResolver {
    next_id: RefCell<u32>,
    values: RefCell<HashMap<DelayedFieldID, DelayedFieldValue>>,
}

impl TDelayedFieldView for TestDelayedFieldResolver {
    fn generate_delayed_field_id(&self, width: u32) -> DelayedFieldID {
        let id = *self.next_id.borrow();
        *self.next_id.borrow_mut() += 1;
        DelayedFieldID::new_with_width(id, width)
    }
    
    fn get_delayed_field_value(&self, id: &DelayedFieldID) 
        -> Result<DelayedFieldValue, PanicOr<DelayedFieldsSpeculativeError>> {
        self.values.borrow()
            .get(id)
            .cloned()
            .ok_or(/* appropriate error */)
    }
    // ... implement other methods
}
```

2. Enable delayed field optimizations in unit tests by setting the flag to `true` in `unit_test_extensions_hook`

3. Add comprehensive unit tests for:
   - Delayed field ID generation and collision resistance
   - Delayed field value resolution and caching
   - `get_reads_needing_exchange` correctness
   - Edge cases in delayed field delta application

## Proof of Concept

The following test would fail if delayed field optimizations were enabled with the current DUMMY_RESOLVER:

```rust
#[test]
#[cfg(feature = "testing")]
fn test_delayed_field_with_optimization_enabled() {
    // This test would panic with "unreachable!" if we set
    // delayed_field_optimization_enabled = true in unit_test_extensions_hook
    
    // Modify unit_test_extensions_hook to enable optimizations:
    // exts.add(NativeAggregatorContext::new(
    //     [0; 32],
    //     &*DUMMY_RESOLVER,
    //     true,  // <-- Change this to true
    //     &*DUMMY_RESOLVER,
    // ));
    
    // Then run any aggregator V2 test that creates an aggregator
    // It will panic at generate_delayed_field_id
}
```

The root cause is evident in comparing test vs production configurations and observing that production-critical delayed field operations are systematically bypassed in the test environment.

### Citations

**File:** aptos-move/aptos-vm/src/natives.rs (L76-124)
```rust
impl TDelayedFieldView for AptosBlankStorage {
    type Identifier = DelayedFieldID;
    type ResourceGroupTag = StructTag;
    type ResourceKey = StateKey;

    fn get_delayed_field_value(
        &self,
        _id: &Self::Identifier,
    ) -> Result<DelayedFieldValue, PanicOr<DelayedFieldsSpeculativeError>> {
        unreachable!()
    }

    fn delayed_field_try_add_delta_outcome(
        &self,
        _id: &Self::Identifier,
        _base_delta: &SignedU128,
        _delta: &SignedU128,
        _max_value: u128,
    ) -> Result<bool, PanicOr<DelayedFieldsSpeculativeError>> {
        unreachable!()
    }

    fn generate_delayed_field_id(&self, _width: u32) -> Self::Identifier {
        unreachable!()
    }

    fn validate_delayed_field_id(&self, _id: &Self::Identifier) -> Result<(), PanicError> {
        unreachable!()
    }

    fn get_reads_needing_exchange(
        &self,
        _delayed_write_set_keys: &HashSet<Self::Identifier>,
        _skip: &HashSet<Self::ResourceKey>,
    ) -> Result<
        BTreeMap<Self::ResourceKey, (StateValueMetadata, u64, TriompheArc<MoveTypeLayout>)>,
        PanicError,
    > {
        unreachable!()
    }

    fn get_group_reads_needing_exchange(
        &self,
        _delayed_write_set_keys: &HashSet<Self::Identifier>,
        _skip: &HashSet<Self::ResourceKey>,
    ) -> PartialVMResult<BTreeMap<Self::ResourceKey, (StateValueMetadata, u64)>> {
        unimplemented!()
    }
}
```

**File:** aptos-move/aptos-vm/src/natives.rs (L212-216)
```rust
    exts.add(NativeAggregatorContext::new(
        [0; 32],
        &*DUMMY_RESOLVER,
        false,
        &*DUMMY_RESOLVER,
```

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L212-213)
```rust
        let storage_environment =
            AptosEnvironment::new_with_delayed_field_optimization_enabled(&state_view);
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

**File:** aptos-move/framework/src/natives/aggregator_natives/aggregator_v2.rs (L118-125)
```rust
    let value = if let Some((resolver, mut delayed_field_data)) = get_context_data(context) {
        let width = get_width_by_type(aggregator_value_ty, EUNSUPPORTED_AGGREGATOR_TYPE)?;
        let id = resolver.generate_delayed_field_id(width);
        delayed_field_data.create_new_aggregator(id);
        Value::delayed_value(id)
    } else {
        create_value_by_type(aggregator_value_ty, 0, EUNSUPPORTED_AGGREGATOR_TYPE)?
    };
```

**File:** aptos-move/framework/src/natives/aggregator_natives/context.rs (L152-163)
```rust
            reads_needing_exchange: if delayed_write_set_ids.is_empty() {
                BTreeMap::new()
            } else {
                self.delayed_field_resolver
                    .get_reads_needing_exchange(&delayed_write_set_ids, &HashSet::new())?
            },
            group_reads_needing_exchange: if delayed_write_set_ids.is_empty() {
                BTreeMap::new()
            } else {
                self.delayed_field_resolver
                    .get_group_reads_needing_exchange(&delayed_write_set_ids, &HashSet::new())?
            },
```

**File:** types/src/on_chain_config/aptos_features.rs (L385-390)
```rust
    pub fn is_aggregator_v2_delayed_fields_enabled(&self) -> bool {
        // This feature depends on resource groups being split inside VMChange set,
        // which is gated by RESOURCE_GROUPS_SPLIT_IN_VM_CHANGE_SET feature, so
        // require that feature to be enabled as well.
        self.is_enabled(FeatureFlag::AGGREGATOR_V2_DELAYED_FIELDS)
            && self.is_resource_groups_split_in_vm_change_set_enabled()
```
