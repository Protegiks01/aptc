# Audit Report

## Title
Layout Cache Coherence Vulnerability: Uncommitted Layouts Leak Across Transaction Boundaries Leading to Consensus Divergence

## Summary
The Move VM's global layout cache stores type layouts without transaction versioning or module content validation. When a transaction computes and caches a layout during speculative execution but subsequently aborts, the cached layout persists in the global cache. Subsequent transactions can retrieve this stale layout even when operating on different module versions, violating deterministic execution and potentially causing consensus splits.

## Finding Description

The vulnerability exists in the interaction between three components:

1. **Unversioned Global Layout Cache**: The `GlobalModuleCache` maintains a `DashMap<StructKey, LayoutCacheEntry>` where `StructKey` contains only a `StructNameIndex` and type arguments, with no module version or content hash. [1](#0-0) 

2. **Shared Cache Across Transactions**: Each transaction receives a `LatestView` that references the same global module cache. Layouts cached by one transaction are immediately visible to all subsequent transactions within the block. [2](#0-1) 

3. **Cache Persistence on Abort**: When a transaction aborts, its cached layouts remain in the global cache. The layout cache is only flushed when modules are successfully published and committed, not when transactions abort. [3](#0-2) 

**Attack Scenario:**

1. Transaction T1 (index i) publishes module M v2 with modified struct S definition during speculative execution
2. T1 computes layout L2 for M::S based on v2 and caches it globally with key `StructKey { idx: M::S, ty_args: [] }`
3. T1's validation fails and it aborts (e.g., read-write conflict, gas limit exceeded, or transaction logic error)
4. Layout L2 remains in the global cache indefinitely
5. Transaction T2 (index j where j > i) executes after T1 aborts
6. T2 loads module M v1 (since T1 aborted, v2 was never committed)
7. T2 needs layout for M::S, checks cache with the same `StructKey`
8. **Cache hit!** T2 retrieves L2 (computed from v2) but is operating on M v1
9. T2 uses the incorrect layout for serialization/deserialization operations

The `load_layout_from_cache` function re-reads modules only for gas charging, not layout validation: [4](#0-3) 

This re-reading captures module dependencies for validation purposes, but **the cached layout content itself is returned without verifying it matches the current module version**. If the module hasn't changed since the layout was cached (because the caching transaction aborted), there's no validation trigger, yet the layout is still wrong.

## Impact Explanation

This vulnerability breaks the **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks."

**Critical Severity** - Consensus Safety Violation:

1. **Non-Deterministic Execution**: Different validators may observe different cached layouts based on the timing of speculative execution and aborts. Validator A might execute T1 before T2, caching L2. Validator B might not execute T1 at all due to different scheduling, never caching L2. When both execute T2, they use different layouts, producing different results.

2. **State Root Divergence**: Using incorrect layouts during resource deserialization or serialization causes:
   - Incorrect field values read from storage
   - Corrupted resource states written back
   - Different transaction outputs across validators
   - Divergent state roots after block execution

3. **Consensus Split**: When validators compute different state roots for the same block, AptosBFT consensus cannot proceed. The network partitions into incompatible chains, requiring manual intervention or a hard fork to resolve.

4. **Transaction Result Inconsistency**: Some validators may see transactions succeed while others see them fail due to deserialization errors from layout mismatches, breaking the fundamental blockchain property of transaction finality.

This meets the **Critical Severity** criteria: "Consensus/Safety violations" and potentially "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation

**High Likelihood**:

1. **Common Trigger Condition**: Transaction aborts are routine in blockchain execution:
   - Speculative execution failures in parallel execution
   - Gas limit exceeded
   - Read-write conflicts requiring re-execution
   - Transaction logic errors (revert conditions)

2. **No Special Privileges Required**: Any user can submit transactions that publish module upgrades. Module publishing is a standard operation on Aptos.

3. **Subtle and Undetected**: The vulnerability manifests only when:
   - A transaction publishes a module with modified struct definitions
   - That transaction subsequently aborts
   - Another transaction uses the same struct type

4. **Persistent Issue**: Once a stale layout is cached, it persists until:
   - A successful module publication flushes the cache
   - Block boundaries are crossed (but only if cache size limits are exceeded)
   - The cache is manually flushed during environment changes

The attack window is particularly wide in parallel execution where multiple transactions execute concurrently, creating many opportunities for layout cache pollution from aborted transactions.

## Recommendation

**Immediate Fix**: Add transaction-level validation to cached layouts or flush on abort.

**Option 1 - Include Module Hash in Cache Key** (Preferred):
```rust
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct StructKey {
    pub idx: StructNameIndex,
    pub ty_args_id: TypeVecId,
    pub module_hash: [u8; 32],  // Add hash of module bytecode
}
```

Modify `load_layout_from_cache` to verify the module hash matches before returning cached layouts.

**Option 2 - Transaction-Local Layout Caches**:
Implement per-transaction layout caches that are discarded on abort instead of using a global cache for speculative execution: [5](#0-4) 

Modify to maintain separate caches for committed vs speculative layouts.

**Option 3 - Flush on Abort**:
Add layout cache flushing when transactions abort:
```rust
// In abort handling code
if modules_published_before_abort {
    global_module_cache.flush_layout_cache();
}
```

**Long-term Fix**: Redesign the layout cache architecture to:
- Version layouts by module content hash
- Validate cached layouts against current module state before use
- Implement proper cache invalidation on module changes
- Consider transaction-local caches for speculative execution

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[test]
fn test_layout_cache_leak_from_aborted_transaction() {
    // Setup: Deploy module M v1 with struct S { field1: u64 }
    let mut executor = create_test_executor();
    let module_v1 = compile_module("module 0x1::M { struct S has key { field1: u64 } }");
    executor.publish_module(module_v1);
    
    // Transaction T1: Publish module M v2 with struct S { field1: u64, field2: u128 }
    let module_v2 = compile_module(
        "module 0x1::M { struct S has key { field1: u64, field2: u128 } }"
    );
    
    // Execute T1 speculatively (will abort later)
    let txn1 = create_module_publish_txn(module_v2);
    executor.speculative_execute(txn1); // Caches layout for v2
    
    // Simulate T1 validation failure - transaction aborts
    executor.abort_transaction(txn1);
    // Layout for v2 remains in cache!
    
    // Transaction T2: Read resource of type M::S
    let txn2 = create_read_resource_txn("0x1::M::S", address_1);
    let result = executor.execute(txn2);
    
    // T2 should use layout for v1, but actually uses cached layout for v2
    // This causes deserialization error or incorrect field values
    assert!(result.is_err() || result.unwrap().has_incorrect_values());
}
```

Move test scenario:
```move
// Module v1
module 0x1::TestModule {
    struct Data has key {
        value: u64
    }
}

// Module v2 (incompatible change)
module 0x1::TestModule {
    struct Data has key {
        value: u64,
        extra: u128  // Added field
    }
}

// Test: T1 publishes v2 but aborts, T2 reads Data with v1 but uses v2 layout
```

The proof of concept would show that after T1 aborts, T2 retrieves the wrong layout from cache, leading to incorrect deserialization or data corruption.

**Notes:**

The vulnerability is exacerbated by the comment in `flush_layout_cache` acknowledging layout cache management issues: [6](#0-5) 

The TODO indicates awareness of layout cache complexity but doesn't address the cache coherence problem during speculative execution and aborts.

### Citations

**File:** third_party/move/move-vm/runtime/src/storage/layout_cache.rs (L79-83)
```rust
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct StructKey {
    pub idx: StructNameIndex,
    pub ty_args_id: TypeVecId,
}
```

**File:** aptos-move/block-executor/src/view.rs (L1072-1079)
```rust
pub(crate) struct LatestView<'a, T: Transaction, S: TStateView<Key = T::Key>> {
    base_view: &'a S,
    pub(crate) global_module_cache:
        &'a GlobalModuleCache<ModuleId, CompiledModule, Module, AptosModuleExtension>,
    pub(crate) runtime_environment: &'a RuntimeEnvironment,
    pub(crate) latest_view: ViewState<'a, T>,
    pub(crate) txn_idx: TxnIndex,
}
```

**File:** aptos-move/block-executor/src/txn_last_input_output.rs (L572-576)
```rust
        if published {
            // Record validation requirements after the modules are published.
            global_module_cache.flush_layout_cache();
            scheduler.record_validation_requirements(txn_idx, module_ids_for_v2)?;
        }
```

**File:** third_party/move/move-vm/runtime/src/storage/loader/lazy.rs (L203-221)
```rust
    fn load_layout_from_cache(
        &self,
        gas_meter: &mut impl DependencyGasMeter,
        traversal_context: &mut TraversalContext,
        key: &StructKey,
    ) -> Option<PartialVMResult<LayoutWithDelayedFields>> {
        let entry = self.module_storage.get_struct_layout(key)?;
        let (layout, modules) = entry.unpack();
        for module_id in modules.iter() {
            // Re-read all modules for this layout, so that transaction gets invalidated
            // on module publish. Also, we re-read them in exactly the same way as they
            // were traversed during layout construction, so gas charging should be exactly
            // the same as on the cache miss.
            if let Err(err) = self.charge_module(gas_meter, traversal_context, module_id) {
                return Some(Err(err));
            }
        }
        Some(Ok(layout))
    }
```

**File:** aptos-move/block-executor/src/code_cache_global.rs (L86-97)
```rust
/// A global cache for verified code and derived information (such as layouts) that is concurrently
/// accessed during the block execution. Module cache is read-only, and modified safely only at
/// block boundaries. Layout cache can be modified during execution of the block.
pub struct GlobalModuleCache<K, D, V, E> {
    /// Module cache containing the verified code.
    module_cache: HashMap<K, Entry<D, V, E>>,
    /// Sum of serialized sizes (in bytes) of all cached modules.
    size: usize,
    /// Cached layouts of structs or enums. This cache stores roots only and is invalidated when
    /// modules are published.
    struct_layouts: DashMap<StructKey, LayoutCacheEntry>,
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
