# Audit Report

## Title
Layout Cache Race Condition Causes Non-Deterministic Execution During Module Publishing

## Summary
A critical race condition exists in the BlockSTM parallel executor where the layout cache flush occurs after modules are made visible to other executing transactions. This allows transactions to read newly published modules while using stale cached type layouts, resulting in non-deterministic execution and consensus violations across validators.

## Finding Description

The vulnerability occurs in the `publish_module_write_set` function during parallel transaction execution. When a transaction publishes a module with modified struct layouts, a critical ordering issue exists:

**Module Publishing Order:**
The implementation first adds modules to the per-block cache (making them immediately visible to concurrent transactions), then flushes the layout cache afterwards: [1](#0-0) 

**Concurrent Transaction Execution:**
Worker threads execute transactions in parallel while commit hooks run sequentially. During the gap between module publication and layout cache flush, other transactions can read the newly published modules: [2](#0-1) 

**Layout Cache Access:**
All transactions share the same global layout cache with no transaction-local isolation. The cache uses `StructKey` (containing `StructNameIndex`) as the lookup key: [3](#0-2) 

**Key Vulnerability Point:**
The `StructNameIndex` is explicitly designed to be reused across module republishes, even when struct layouts change. The runtime environment documentation states: "Since there is no other information other than index, even for structs with different layouts it is fine to re-use the index": [4](#0-3) 

This design allows a republished module with modified struct layout to have the same `StructKey` as the previous version, enabling stale cached layouts to be retrieved when accessing new module code.

**Module Read Flow:**
When transactions execute, they read modules through a three-tier cache system that checks the per-block cache, allowing concurrent access to newly published modules: [5](#0-4) 

**Layout Retrieval:**
The layout converter checks the cache before constructing new layouts, using the reused `StructNameIndex`: [6](#0-5) 

**Why Validation Doesn't Catch This:**
Module read validation only verifies that the module VERSION (transaction index) is correct, not whether the cached LAYOUT matches the module: [7](#0-6) 

The validation checks `contains_not_overridden` for global cache reads and version equality for per-block cache reads, but never validates layout cache consistency.

## Impact Explanation

**Critical Severity - Consensus/Safety Violation**

This vulnerability breaks the fundamental deterministic execution invariant: "All validators must produce identical state roots for identical blocks."

Different validators executing the same block with different parallel execution timing will produce divergent results:
- **Validator A**: Transaction executes before layout cache flush → uses stale layout → incorrect state computation → wrong state root
- **Validator B**: Transaction executes after layout cache flush → recomputes layout → correct state computation → correct state root

**Consequences:**
1. **Consensus violation**: Validators produce different state roots for the same block sequence
2. **Network partition**: Validators cannot reach consensus on block validity, causing the network to halt
3. **Chain split risk**: Different validator subsets may commit different states
4. **Hard fork requirement**: Recovery requires manual intervention to reconcile divergent states

This directly qualifies as Critical Severity per Aptos bug bounty criteria: "Consensus/Safety violations" resulting in "Non-recoverable network partition (requires hardfork)."

## Likelihood Explanation

**High Likelihood**

This vulnerability triggers during normal blockchain operation:

- **Frequency**: Occurs whenever modules are republished (common during package upgrades) while parallel execution is active (the default execution mode)
- **No special permissions required**: Any account with sufficient gas can publish or upgrade modules
- **Significant timing window**: The gap between adding multiple modules to the cache (loop at lines 559-571) and flushing the layout cache (line 574) provides multiple opportunities for concurrent transactions to observe inconsistent cache state
- **Parallel execution amplifies risk**: BlockSTM's design ensures many transactions execute speculatively and concurrently with commit operations, maximizing the probability of timing-dependent cache access

The concurrent architecture explicitly enables this race condition - worker threads continuously execute transactions while commit hooks run sequentially, creating the exact conditions for non-deterministic layout cache access.

## Recommendation

**Immediate Fix:**
Flush the layout cache BEFORE making modules visible to concurrent transactions:

```rust
pub(crate) fn publish_module_write_set(
    &self,
    txn_idx: TxnIndex,
    global_module_cache: &GlobalModuleCache<...>,
    versioned_cache: &MVHashMap<...>,
    runtime_environment: &RuntimeEnvironment,
    scheduler: &SchedulerWrapper<'_>,
) -> Result<bool, PanicError> {
    // ... existing code ...
    
    let mut published = false;
    let mut module_ids_for_v2 = BTreeSet::new();
    
    // Flush layout cache FIRST, before publishing modules
    if !output_before_guard.module_write_set().is_empty() {
        global_module_cache.flush_layout_cache();
        published = true;
    }
    
    // Then publish modules to per-block cache
    for write in output_before_guard.module_write_set().values() {
        if scheduler.is_v2() {
            module_ids_for_v2.insert(write.module_id().clone());
        }
        add_module_write_to_module_cache::<T>(
            write,
            txn_idx,
            runtime_environment,
            global_module_cache,
            versioned_cache.module_cache(),
        )?;
    }
    
    if published {
        scheduler.record_validation_requirements(txn_idx, module_ids_for_v2)?;
    }
    Ok(published)
}
```

**Long-term Solution:**
As noted in the codebase TODO, refactor layouts to eliminate the need for cache flushing by storing single variants instead of full enum layouts. Additionally, consider adding layout version tracking to the cache key or implementing transaction-local layout cache isolation.

## Proof of Concept

This vulnerability requires multi-threaded execution testing with precise timing control to demonstrate the race condition. A proof of concept would involve:

1. Deploy module A with struct S containing field layout L1
2. Submit transaction T1 to republish module A with struct S having modified layout L2
3. Concurrently submit transaction T2 that reads and uses struct A::S
4. Use thread synchronization to pause T1 between module cache update and layout cache flush
5. Allow T2 to execute during this window
6. Observe that T2 retrieves stale layout L1 but passes validation
7. Compare state roots between execution with different timing

The race condition is timing-dependent and requires instrumentation of the BlockSTM executor to reliably reproduce, making it challenging to demonstrate in a simple test case. However, the code analysis clearly shows the vulnerability exists in the production implementation.

**Notes:**
- This vulnerability affects both BlockSTM v1 and v2 implementations as they share the same `publish_module_write_set` logic
- The issue only manifests when modules are republished with actual struct layout changes, not just code changes
- The comment at `code_cache_global.rs:164-166` indicates developers are aware layout flushing is necessary, but the current ordering creates the race condition
- StructNameIndex reuse is an intentional design decision for memory efficiency, documented at `environment.rs:57-61`, which assumes proper cache invalidation synchronization

### Citations

**File:** aptos-move/block-executor/src/txn_last_input_output.rs (L559-577)
```rust
        for write in output_before_guard.module_write_set().values() {
            published = true;
            if scheduler.is_v2() {
                module_ids_for_v2.insert(write.module_id().clone());
            }
            add_module_write_to_module_cache::<T>(
                write,
                txn_idx,
                runtime_environment,
                global_module_cache,
                versioned_cache.module_cache(),
            )?;
        }
        if published {
            // Record validation requirements after the modules are published.
            global_module_cache.flush_layout_cache();
            scheduler.record_validation_requirements(txn_idx, module_ids_for_v2)?;
        }
        Ok(published)
```

**File:** aptos-move/block-executor/src/executor.rs (L1454-1506)
```rust
        loop {
            while scheduler.commit_hooks_try_lock() {
                // Perform sequential commit hooks.
                while let Some((txn_idx, incarnation)) = scheduler.start_commit()? {
                    self.prepare_and_queue_commit_ready_txn(
                        txn_idx,
                        incarnation,
                        num_txns,
                        executor,
                        block,
                        num_workers as usize,
                        runtime_environment,
                        scheduler_wrapper,
                        shared_sync_params,
                    )?;
                }

                scheduler.commit_hooks_unlock();
            }

            match scheduler.next_task(worker_id)? {
                TaskKind::Execute(txn_idx, incarnation) => {
                    if incarnation > num_workers.pow(2) + num_txns + 30 {
                        // Something is wrong if we observe high incarnations (e.g. a bug
                        // might manifest as an execution-invalidation cycle). Break out
                        // to fallback to sequential execution.
                        error!("Observed incarnation {} of txn {txn_idx}", incarnation);
                        return Err(PanicOr::Or(ParallelBlockExecutionError::IncarnationTooHigh));
                    }

                    Self::execute_v2(
                        worker_id,
                        txn_idx,
                        incarnation,
                        block.get_txn(txn_idx),
                        &block.get_auxiliary_info(txn_idx),
                        last_input_output,
                        versioned_cache,
                        executor,
                        base_view,
                        shared_sync_params.global_module_cache,
                        runtime_environment,
                        ParallelState::new(
                            versioned_cache,
                            scheduler_wrapper,
                            shared_sync_params.start_shared_counter,
                            shared_sync_params.delayed_field_id_counter,
                            incarnation,
                        ),
                        scheduler,
                        &self.config.onchain.block_gas_limit_type,
                    )?;
                },
```

**File:** aptos-move/block-executor/src/code_cache_global.rs (L170-189)
```rust
    /// Returns layout entry if it exists in global cache.
    pub(crate) fn get_struct_layout_entry(&self, key: &StructKey) -> Option<LayoutCacheEntry> {
        match self.struct_layouts.get(key) {
            None => {
                GLOBAL_LAYOUT_CACHE_MISSES.inc();
                None
            },
            Some(e) => Some(e.deref().clone()),
        }
    }

    pub(crate) fn store_struct_layout_entry(
        &self,
        key: &StructKey,
        entry: LayoutCacheEntry,
    ) -> PartialVMResult<()> {
        if let dashmap::Entry::Vacant(e) = self.struct_layouts.entry(*key) {
            e.insert(entry);
        }
        Ok(())
```

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L54-63)
```rust
    /// Map from struct names to indices, to save on unnecessary cloning and reduce memory
    /// consumption. Used by all struct type creations in the VM and in code cache.
    ///
    /// SAFETY:
    ///   By itself, it is fine to index struct names even of non-successful module publishes. If
    ///   we cached some name, which was not published, it will stay in cache and will be used by
    ///   another republish. Since there is no other information other than index, even for structs
    ///   with different layouts it is fine to re-use the index.
    ///   We wrap the index map into an [Arc] so that on republishing these clones are cheap.
    struct_name_index_map: Arc<StructNameIndexMap>,
```

**File:** aptos-move/block-executor/src/code_cache.rs (L148-174)
```rust
        match &self.latest_view {
            ViewState::Sync(state) => {
                // Check the transaction-level cache with already read modules first.
                if let CacheRead::Hit(read) = state.captured_reads.borrow().get_module_read(key) {
                    return Ok(read);
                }

                // Otherwise, it is a miss. Check global cache.
                if let Some(module) = self.global_module_cache.get(key) {
                    state
                        .captured_reads
                        .borrow_mut()
                        .capture_global_cache_read(key.clone(), module.clone());
                    return Ok(Some((module, Self::Version::default())));
                }

                // If not global cache, check per-block cache.
                let _timer = GLOBAL_MODULE_CACHE_MISS_SECONDS.start_timer();
                let read = state
                    .versioned_map
                    .module_cache()
                    .get_module_or_build_with(key, builder)?;
                state
                    .captured_reads
                    .borrow_mut()
                    .capture_per_block_cache_read(key.clone(), read.clone());
                Ok(read)
```

**File:** third_party/move/move-vm/runtime/src/storage/ty_layout_converter.rs (L90-129)
```rust
            let key = match ty {
                Type::Struct { idx, .. } => {
                    let ty_args_id = ty_pool.intern_ty_args(&[]);
                    Some(StructKey {
                        idx: *idx,
                        ty_args_id,
                    })
                },
                Type::StructInstantiation { idx, ty_args, .. } => {
                    let ty_args_id = ty_pool.intern_ty_args(ty_args);
                    Some(StructKey {
                        idx: *idx,
                        ty_args_id,
                    })
                },
                _ => None,
            };

            if let Some(key) = key {
                if let Some(result) = self.struct_definition_loader.load_layout_from_cache(
                    gas_meter,
                    traversal_context,
                    &key,
                ) {
                    return result;
                }

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

**File:** aptos-move/block-executor/src/captured_reads.rs (L1060-1067)
```rust
        let validate = |key: &K, read: &ModuleRead<DC, VC, S>| match read {
            ModuleRead::GlobalCache(_) => global_module_cache.contains_not_overridden(key),
            ModuleRead::PerBlockCache(previous) => {
                let current_version = per_block_module_cache.get_module_version(key);
                let previous_version = previous.as_ref().map(|(_, version)| *version);
                current_version == previous_version
            },
        };
```
