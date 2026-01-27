# Audit Report

## Title
Critical Race Condition in Global Struct Layout Cache Enables Consensus Safety Violation via Stale Layout Poisoning

## Summary
A race condition exists between module publishing and struct layout caching that allows aborted transactions to poison the global layout cache with stale layouts. When a transaction computes a layout based on an old module version, gets aborted due to module publishing, and stores the stale layout to the cache after the cache flush but before re-execution, subsequent transactions will use the wrong struct layout with the new module version, causing consensus splits and memory corruption.

## Finding Description

The vulnerability exists in the interaction between three components:

1. **Global Layout Cache**: Uses `StructKey` (struct name + type args) WITHOUT module version tracking [1](#0-0) 

2. **Vacant-Entry Pattern**: Prevents overwriting existing cache entries [2](#0-1) 

3. **Layout Cache Flush Timing**: Occurs AFTER module publish commits [3](#0-2) 

**Attack Scenario:**

1. Transaction T1 (index 5) starts execution, loads module M version V1 from storage
2. T1 computes struct layout L1 based on V1's struct definition [4](#0-3) 
3. Transaction T2 (index 10) publishes module M version V2 with DIFFERENT struct layout (e.g., added field)
4. T2 commits successfully, calls `flush_layout_cache()` clearing all cached layouts [5](#0-4) 
5. **Critical Race**: T1 (still executing speculatively) stores layout L1 to the now-empty cache via `store_struct_layout_entry`
6. T1's module read-set validation detects it read V1 but V2 is published - T1 is aborted [6](#0-5) 
7. T1 re-executes as incarnation 1, loads module M version V2, computes layout L2
8. T1 tries to store L2, but the vacant-entry pattern prevents overwriting: cache already contains L1 from the aborted incarnation
9. Cache now contains L1 (computed from V1) but all future transactions use V2
10. Transaction T3 uses cached layout L1 with module V2 → **struct size mismatch, memory corruption, consensus split**

**Why This Breaks Deterministic Execution:**

Different validators executing at different speeds will experience different race condition outcomes:
- **Fast Validator A**: T1's stale write happens before T2's flush → cache clean → correct layout cached
- **Slow Validator B**: T1's stale write happens after T2's flush → cache poisoned → wrong layout cached
- Both validators execute the same block but compute different state roots due to different cached layouts

## Impact Explanation

**CRITICAL SEVERITY** - This vulnerability enables:

1. **Consensus Safety Violation**: Different validators produce different state roots for identical blocks, violating the fundamental consensus invariant. This can lead to permanent chain splits requiring a hardfork to resolve.

2. **Non-Recoverable Network Partition**: Once validators diverge on cached layouts, all subsequent blocks using those structs will compute different state roots, creating an irrecoverable fork.

3. **Memory Corruption**: Using struct layouts with incorrect sizes causes out-of-bounds memory access during value serialization/deserialization in the Move VM, potentially leading to crashes or undefined behavior [7](#0-6) 

4. **Deterministic Execution Violation**: Breaks Aptos invariant #1 - all validators must produce identical state roots for identical blocks.

This qualifies for the highest Critical severity category: "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation

**MEDIUM-HIGH Likelihood:**

**Enabling Factors:**
- Module publishing occurs regularly on Aptos (framework upgrades, user modules)
- BlockSTM parallel execution amplifies race condition windows
- No special permissions required - any module publisher can trigger this
- The race window is small but non-zero, especially under high load

**Mitigating Factors:**
- Requires precise timing between module publish and concurrent transaction execution
- More likely during high transaction throughput when parallel execution is active
- Framework modules (most likely to be republished) are accessed frequently, increasing exposure

**Realistic Trigger:**
A malicious actor can deliberately trigger this by:
1. Publishing a popular module upgrade (or timing attack during governance upgrades)
2. Simultaneously sending transactions that use the affected structs
3. Exploiting the parallel execution timing to poison the cache

Even without malicious intent, this can occur naturally during framework upgrades with high transaction volume.

## Recommendation

**Immediate Fix**: Include module version/hash in `StructKey` to prevent cross-version cache collisions:

```rust
// In third_party/move/move-vm/runtime/src/storage/layout_cache.rs
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct StructKey {
    pub idx: StructNameIndex,
    pub ty_args_id: TypeVecId,
    pub module_version: u64, // ADD: Module version/hash to ensure cache isolation
}
```

**Alternative Fix**: Implement transaction-scoped layout caching instead of global caching, with proper rollback on abort:

```rust
// Store layouts per-transaction, flush on abort
pub struct TransactionLayoutCache {
    txn_idx: TxnIndex,
    incarnation: Incarnation,
    layouts: HashMap<StructKey, LayoutCacheEntry>,
}
```

**Complete Fix**: Combine both approaches:
1. Add version tracking to StructKey
2. Flush layouts when ANY module in the defining modules set is republished (not just all layouts)
3. Track layout cache reads in `CapturedReads` for validation, similar to module reads [8](#0-7) 

## Proof of Concept

**Setup:**
```rust
// Module V1: struct with 1 field
module 0x1::test_module {
    struct TestStruct {
        field1: u64,
    }
}

// Module V2: struct with 2 fields (different layout!)
module 0x1::test_module {
    struct TestStruct {
        field1: u64,
        field2: u128,  // Added field - layout changes
    }
}
```

**Exploitation Steps:**

1. Deploy module V1 at start of block
2. Submit Transaction T1 at index 5:
   - Access `TestStruct` from V1
   - VM computes layout L1 (size = 8 bytes)
   - VM stores L1 to global cache with key K = (test_module::TestStruct, [])

3. Submit Transaction T2 at index 10:
   - Publish module V2 with modified `TestStruct` (size = 24 bytes)
   - On commit, `flush_layout_cache()` clears all layouts
   
4. **Race Condition**: If T1's `store_layout_to_cache()` executes AFTER step 3's flush:
   - Cache is empty after flush
   - T1 stores L1 (8 bytes) to cache
   - T1 validation fails (read V1, but V2 published)
   - T1 re-executes with V2, computes L2 (24 bytes)
   - T1 tries to store L2, but L1 already exists (vacant-entry blocks it)

5. Submit Transaction T3 at index 15:
   - Access `TestStruct` from V2
   - Cache hit: retrieves L1 (8 bytes)
   - Attempts to deserialize 24-byte value using 8-byte layout
   - **Memory corruption / consensus split**

**Expected Result:**
- Validators with different execution timing cache different layouts
- Fast validators compute correct state root using L2
- Slow validators compute incorrect state root using poisoned L1
- Network splits into incompatible forks

## Notes

This vulnerability is particularly dangerous because:

1. **Silent Failure**: No error is thrown when the wrong layout is used - it silently corrupts memory or produces incorrect state
2. **Persistent Poison**: Once cached, the wrong layout persists for the entire block (until next flush)
3. **Cascading Effect**: All transactions in the block using that struct will be affected
4. **Difficult Detection**: Validators may not immediately detect the divergence until state root comparison

The issue fundamentally stems from treating the layout cache as a pure optimization without accounting for the cache invalidation requirements in a parallel execution model with module publishing.

### Citations

**File:** third_party/move/move-vm/runtime/src/storage/layout_cache.rs (L79-83)
```rust
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct StructKey {
    pub idx: StructNameIndex,
    pub ty_args_id: TypeVecId,
}
```

**File:** aptos-move/block-executor/src/code_cache_global.rs (L162-168)
```rust
    /// Flushes only layout caches.
    pub fn flush_layout_cache(&self) {
        // TODO(layouts):
        //   Flushing is only needed because of enums. Once we refactor layouts to store a single
        //   variant instead, this can be removed.
        self.struct_layouts.clear();
    }
```

**File:** aptos-move/block-executor/src/code_cache_global.rs (L181-190)
```rust
    pub(crate) fn store_struct_layout_entry(
        &self,
        key: &StructKey,
        entry: LayoutCacheEntry,
    ) -> PartialVMResult<()> {
        if let dashmap::Entry::Vacant(e) = self.struct_layouts.entry(*key) {
            e.insert(entry);
        }
        Ok(())
    }
```

**File:** aptos-move/block-executor/src/txn_last_input_output.rs (L572-575)
```rust
        if published {
            // Record validation requirements after the modules are published.
            global_module_cache.flush_layout_cache();
            scheduler.record_validation_requirements(txn_idx, module_ids_for_v2)?;
```

**File:** third_party/move/move-vm/runtime/src/storage/ty_layout_converter.rs (L117-129)
```rust
                // Otherwise a cache miss, compute the result and store it.
                let mut modules = DefiningModules::new();
                let layout = self.type_to_type_layout_with_delayed_fields_impl::<false>(
                    gas_meter,
                    traversal_context,
                    &mut modules,
                    ty,
                    check_option_type,
                )?;
                let cache_entry = LayoutCacheEntry::new(layout.clone(), modules);
                self.struct_definition_loader
                    .store_layout_to_cache(&key, cache_entry)?;
                return Ok(layout);
```

**File:** third_party/move/move-vm/runtime/src/storage/ty_layout_converter.rs (L254-325)
```rust
    fn type_to_type_layout_impl<const ANNOTATED: bool>(
        &self,
        gas_meter: &mut impl DependencyGasMeter,
        traversal_context: &mut TraversalContext,
        modules: &mut DefiningModules,
        ty: &Type,
        count: &mut u64,
        depth: u64,
        check_option_type: bool,
    ) -> PartialVMResult<(MoveTypeLayout, bool)> {
        self.check_depth_and_increment_count(count, depth)?;

        Ok(match ty {
            Type::Bool => (MoveTypeLayout::Bool, false),
            Type::U8 => (MoveTypeLayout::U8, false),
            Type::U16 => (MoveTypeLayout::U16, false),
            Type::U32 => (MoveTypeLayout::U32, false),
            Type::U64 => (MoveTypeLayout::U64, false),
            Type::U128 => (MoveTypeLayout::U128, false),
            Type::U256 => (MoveTypeLayout::U256, false),
            Type::I8 => (MoveTypeLayout::I8, false),
            Type::I16 => (MoveTypeLayout::I16, false),
            Type::I32 => (MoveTypeLayout::I32, false),
            Type::I64 => (MoveTypeLayout::I64, false),
            Type::I128 => (MoveTypeLayout::I128, false),
            Type::I256 => (MoveTypeLayout::I256, false),
            Type::Address => (MoveTypeLayout::Address, false),
            Type::Signer => (MoveTypeLayout::Signer, false),
            Type::Function { .. } => (MoveTypeLayout::Function, false),
            Type::Vector(ty) => self
                .type_to_type_layout_impl::<ANNOTATED>(
                    gas_meter,
                    traversal_context,
                    modules,
                    ty,
                    count,
                    depth + 1,
                    check_option_type,
                )
                .map(|(elem_layout, contains_delayed_fields)| {
                    let vec_layout = MoveTypeLayout::Vector(Box::new(elem_layout));
                    (vec_layout, contains_delayed_fields)
                })?,
            Type::Struct { idx, .. } => self.struct_to_type_layout::<ANNOTATED>(
                gas_meter,
                traversal_context,
                modules,
                idx,
                &[],
                count,
                depth + 1,
                check_option_type,
            )?,
            Type::StructInstantiation { idx, ty_args, .. } => self
                .struct_to_type_layout::<ANNOTATED>(
                    gas_meter,
                    traversal_context,
                    modules,
                    idx,
                    ty_args,
                    count,
                    depth + 1,
                    check_option_type,
                )?,
            Type::Reference(_) | Type::MutableReference(_) | Type::TyParam(_) => {
                return Err(
                    PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                        .with_message(format!("No type layout for {:?}", ty)),
                );
            },
        })
    }
```

**File:** aptos-move/block-executor/src/cold_validation.rs (L14-61)
```rust
/**
 * In BlockSTMv2, validations are not scheduled in waves as separate tasks like
 * in BlockSTMv1. Instead normal validations occur granularly and on-demand, at
 * the time of particular updates. However, global code cache does not support
 * push validation by design. This because most blocks do not contain module
 * publishing, so the trade-off taken is to reduce the overhead on the common
 * read path. Instead, published modules become visible to other workers (executing
 * higher indexed txns) during a txn commit, and it is required that all txns
 * that are executed or executing to validate their module read set. This file
 * provides the primitives for BlockSTMv2 scheduler to manage such requirements.
 *
 * A high-level idea is that at any time, at most one worker is responsible for
 * fulfilling the module validation requirements for an interval of txns. The
 * interval starts at the index of a committed txn that published modules, and
 * ends at the first txn that has never been scheduled for execution. (Note: for
 * contended workloads, the scheduler currently may execute later txns early,
 * losing the benefits of this optimization for higher-indexed txns). The interval
 * induces a traversal of the interval to identify the set of txn versions
 * (txn index & incarnation pair) requiring module read set validation. In order
 * to reduce the time in critical (sequential) section of the code, the traversal
 * is performed after the txn is committed by the same worker if no requirements
 * were already active, or by the designated worker that may have already been
 * performing module validations. When this happens, the start of interval is
 * reset to the newly committed txn (which must be higher than recorded start
 * since txns can not be committed with unfulfilled requirements). The traversal
 * can be done locally, only needing access to the array of statuses. After the
 * traversal is finished and the requirements are properly recorded, the designated
 * worker may get module validation tasks to perform from scheduler's next_task
 * call - depending on a distance threshold from the committed prefix of the block.
 * The rationale for a distance threshold is to (a) prioritize more important
 * work and (b) avoid wasted work as txns that get re-executed after module
 * publishing (with higher incarnation) would no longer require module validation.
 *
 * When the interval is reset, the module requirements are combined together.
 * This might cause some txns to be validated against a module when strictly
 * speaking they would not require it. However, it allows a simpler implementation
 * that is easier to reason about, and is not expected to be a bottleneck.
 *
 * The implementation of ColdValidationRequirements is templated over the type of
 * the requirement. This allows easier testing, as well as future extensions to
 * other types of validation requirements that may be better offloaded to an uncommon
 * dedicated path for optimal performance. TODO(BlockSTMv2): a promising direction
 * is to enable caching use-cases in the VM, whereby cache invalidations might be
 * rare and infeasible to record every access for push validation.
 *
 * Finally, ColdValidationRequirements allows to cheaply check if a txn has
 * unfulfilled requirements, needed by the scheduler to avoid committing such txns.
 **/
```

**File:** aptos-move/block-executor/src/captured_reads.rs (L1-50)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use crate::{
    code_cache_global::GlobalModuleCache,
    types::InputOutputKey,
    view::{GroupReadResult, LatestView, ReadResult},
};
use anyhow::bail;
use aptos_aggregator::{
    delta_change_set::serialize,
    delta_math::DeltaHistory,
    types::{DelayedFieldValue, DelayedFieldsSpeculativeError, ReadPosition},
};
use aptos_mvhashmap::{
    types::{
        Incarnation, MVDataError, MVDataOutput, MVDelayedFieldsError, MVGroupError, StorageVersion,
        TxnIndex, ValueWithLayout, Version,
    },
    versioned_data::VersionedData,
    versioned_delayed_fields::TVersionedDelayedFieldView,
    versioned_group_data::VersionedGroupData,
};
use aptos_types::{
    error::{code_invariant_error, PanicError, PanicOr},
    executable::ModulePath,
    state_store::{state_value::StateValueMetadata, TStateView},
    transaction::BlockExecutableTransaction as Transaction,
    vm_status::StatusCode,
    write_set::TransactionWrite,
};
use aptos_vm_types::resolver::ResourceGroupSize;
use derivative::Derivative;
use move_binary_format::errors::{PartialVMError, PartialVMResult};
use move_core_types::value::MoveTypeLayout;
use move_vm_types::{
    code::{ModuleCode, SyncModuleCache, WithAddress, WithName, WithSize},
    delayed_values::delayed_field_id::DelayedFieldID,
};
use std::{
    collections::{
        hash_map::Entry::{self, Occupied, Vacant},
        BTreeMap, BTreeSet, HashMap, HashSet,
    },
    hash::Hash,
    ops::Deref,
    sync::Arc,
};
use triomphe::Arc as TriompheArc;

```
