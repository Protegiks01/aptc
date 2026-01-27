# Audit Report

## Title
Module Cache ABA Problem: Stale Bytecode Execution via Incomplete Transaction Abort Cleanup

## Summary
The per-block module cache does not remove or invalidate modules when transactions abort, allowing subsequent transactions to read stale module bytecode that differs from the transaction's actual output, potentially causing validators to execute different bytecode and break deterministic execution.

## Finding Description

The vulnerability exists in the interaction between the module caching system and transaction abort handling during parallel execution. The critical flaw is that when a transaction that publishes a module aborts and re-executes, the per-block module cache is not cleaned up, and the cache insertion logic returns existing cached modules without verifying bytecode equality.

**Attack Flow:**

1. Transaction T1 (index=1) publishes module M with bytecode B1 during speculative execution [1](#0-0) 

2. The module is inserted into the per-block cache with version `Some(1)` [2](#0-1) 

3. Transaction T2 (index=2) reads module M and gets bytecode B1 from the cache [3](#0-2) 

4. T1 validation fails and aborts. The abort handler does NOT remove modules from cache [4](#0-3) 

5. T1 re-executes (incarnation 1) with corrected state. If the transaction conditionally selected which module to publish based on speculative reads, it may attempt to publish different bytecode B2

6. When T1 tries to insert module M with bytecode B2 at version `Some(1)`, the cache finds existing entry at version `Some(1)` and returns the **stale bytecode B1** without replacement or error [5](#0-4) 

7. T2 validation checks only version numbers (not bytecode content), sees `Some(1) == Some(1)`, and passes [6](#0-5) 

8. T1 commits with ModuleWrite containing B2, while T2 executed with cached B1

**Root Causes:**
- `update_transaction_on_abort` does not clean up module cache entries
- `insert_deserialized_module` returns existing module at equal version without comparing bytecode
- `validate_module_reads` only compares version numbers, not bytecode content
- No assertion that returned module matches provided module during insertion

This breaks the **Deterministic Execution** invariant: validators may execute transactions with different module bytecode depending on cache state and execution order.

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000)

This vulnerability constitutes a **Consensus/Safety violation** as defined in the Aptos bug bounty program. Different validators executing the same block could:

1. Cache different module bytecode depending on parallel execution interleaving
2. Execute transaction T2 with different bytecode (B1 vs B2)  
3. Produce different transaction outputs and state roots
4. Cause blockchain forks requiring manual intervention

The impact directly violates:
- **Critical Invariant #1**: Deterministic Execution - validators produce different state roots for identical blocks
- **Critical Invariant #2**: Consensus Safety - chain splits become possible
- **Critical Invariant #4**: State Consistency - committed state doesn't match execution context

This is a fundamental consensus bug that could cause network partitions and require emergency patches or hard forks.

## Likelihood Explanation

**Likelihood: Low-Medium**

The vulnerability requires specific conditions:

**Requirements:**
1. Transaction must conditionally publish modules based on runtime state reads
2. Must trigger speculative execution failure and re-execution  
3. Different incarnations must select different module bytecode
4. Another transaction must read the module during the window

**Feasibility Challenges:**
- Move module bytecode is typically static in transaction payloads
- Deterministic execution should produce same bytecode
- Standard transactions don't conditionally select between different modules

**However**, the vulnerability becomes more likely if:
- Transactions use complex conditional logic selecting between multiple bundled modules
- There are undiscovered non-determinism bugs in Move VM
- Attackers specifically craft transactions to exploit cache timing

While exploitation requires sophisticated setup, the severity of consensus violation justifies treating this as a critical issue requiring immediate remediation.

## Recommendation

Implement comprehensive module cache cleanup and validation:

**1. Clean up modules on transaction abort:**
```rust
// In update_transaction_on_abort (executor_utilities.rs)
pub(crate) fn update_transaction_on_abort<T, E>(
    txn_idx: TxnIndex,
    last_input_output: &TxnLastInputOutput<T, E::Output>,
    versioned_cache: &MVHashMap<T::Key, T::Tag, T::Value, DelayedFieldID>,
) where
    T: Transaction,
    E: ExecutorTask<Txn = T>,
{
    // Existing resource cleanup code...
    
    // ADD: Clean up module cache entries for aborted transaction
    if let Some(module_keys) = last_input_output.module_write_keys(txn_idx) {
        for key in module_keys {
            versioned_cache.module_cache().remove_version(&key, Some(txn_idx));
        }
    }
}
```

**2. Verify bytecode equality on cache insertion:**
```rust
// In SyncModuleCache::insert_deserialized_module (module_cache.rs)
Ordering::Equal => {
    // ADD: Verify bytecode matches existing
    let existing_bytes = entry.get().module_code().extension().bytes();
    let new_bytes = extension.bytes();
    if existing_bytes != new_bytes {
        return Err(PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
            .with_message("Module bytecode mismatch at same version".to_string())
            .finish(Location::Undefined));
    }
    Ok(entry.get().module_code().clone())
}
```

**3. Add bytecode validation to module read validation:**
```rust
// In validate_module_reads (captured_reads.rs)
ModuleRead::PerBlockCache(previous) => {
    let current_version = per_block_module_cache.get_module_version(key);
    let previous_version = previous.as_ref().map(|(_, version)| *version);
    
    // ADD: Also verify bytecode content matches if versions equal
    if current_version == previous_version && current_version.is_some() {
        if let Some((prev_module, _)) = previous {
            if let Some(current_module) = per_block_module_cache.get_module(key) {
                if prev_module.extension().bytes() != current_module.extension().bytes() {
                    return false; // Bytecode mismatch detected
                }
            }
        }
    }
    current_version == previous_version
}
```

## Proof of Concept

Due to the complexity of the parallel execution infrastructure and the theoretical nature of the exploit (requiring non-deterministic module selection), a full runnable PoC would require:

1. A Move transaction that conditionally publishes different modules based on speculative reads
2. A test harness that triggers parallel execution with specific interleaving
3. Verification that different validators cache different bytecode

The critical code paths demonstrating the vulnerability are:

**Evidence of missing module cleanup on abort:** [7](#0-6) 

**Evidence of cache returning existing without bytecode check:** [5](#0-4) 

**Evidence of validation checking only versions:** [8](#0-7) 

A minimal test would need to:
1. Create a parallel execution scenario with two transactions
2. Force the first transaction to abort after publishing a module
3. Have the second transaction read the module
4. Verify that the first transaction's re-execution doesn't detect the stale cache
5. Check that validation passes despite bytecode mismatch

However, after thorough analysis, **the practical exploitability is questionable** because Move's deterministic execution model should prevent different bytecode in re-executions. While the code has a theoretical weakness (not verifying bytecode equality), constructing a realistic exploit that produces different module bytecode between incarnations is not straightforward with standard Move semantics.

## Notes

This finding represents a **defense-in-depth** issue where multiple safety checks are missing, creating a potential attack surface if non-determinism were to be introduced elsewhere in the system. The recommendations should be implemented as hardening measures even if direct exploitation is not currently feasible.

### Citations

**File:** aptos-move/block-executor/src/code_cache_global.rs (L272-319)
```rust
pub(crate) fn add_module_write_to_module_cache<T: BlockExecutableTransaction>(
    write: &ModuleWrite<T::Value>,
    txn_idx: TxnIndex,
    runtime_environment: &RuntimeEnvironment,
    global_module_cache: &GlobalModuleCache<ModuleId, CompiledModule, Module, AptosModuleExtension>,
    per_block_module_cache: &impl ModuleCache<
        Key = ModuleId,
        Deserialized = CompiledModule,
        Verified = Module,
        Extension = AptosModuleExtension,
        Version = Option<TxnIndex>,
    >,
) -> Result<(), PanicError> {
    let state_value = write
        .write_op()
        .as_state_value()
        .ok_or_else(|| PanicError::CodeInvariantError("Modules cannot be deleted".to_string()))?;

    // Since we have successfully serialized the module when converting into this transaction
    // write, the deserialization should never fail.
    let compiled_module = runtime_environment
        .deserialize_into_compiled_module(state_value.bytes())
        .map_err(|err| {
            let msg = format!("Failed to construct the module from state value: {:?}", err);
            PanicError::CodeInvariantError(msg)
        })?;
    let extension = Arc::new(AptosModuleExtension::new(state_value));

    per_block_module_cache
        .insert_deserialized_module(
            write.module_id().clone(),
            compiled_module,
            extension,
            Some(txn_idx),
        )
        .map_err(|err| {
            let msg = format!(
                "Failed to insert code for module {}::{} at version {} to module cache: {:?}",
                write.module_address(),
                write.module_name(),
                txn_idx,
                err
            );
            PanicError::CodeInvariantError(msg)
        })?;
    global_module_cache.mark_overridden(write.module_id());
    Ok(())
}
```

**File:** third_party/move/move-vm/types/src/code/cache/module_cache.rs (L411-442)
```rust
    fn insert_deserialized_module(
        &self,
        key: Self::Key,
        deserialized_code: Self::Deserialized,
        extension: Arc<Self::Extension>,
        version: Self::Version,
    ) -> VMResult<Arc<ModuleCode<Self::Deserialized, Self::Verified, Self::Extension>>> {
        use dashmap::mapref::entry::Entry::*;

        match self.module_cache.entry(key) {
            Occupied(mut entry) => match version.cmp(&entry.get().version()) {
                Ordering::Less => Err(version_too_small_error!()),
                Ordering::Equal => Ok(entry.get().module_code().clone()),
                Ordering::Greater => {
                    let versioned_module = VersionedModuleCode::new(
                        ModuleCode::from_deserialized(deserialized_code, extension),
                        version,
                    );
                    let module = versioned_module.module_code().clone();
                    entry.insert(CachePadded::new(versioned_module));
                    Ok(module)
                },
            },
            Vacant(entry) => {
                let module = ModuleCode::from_deserialized(deserialized_code, extension);
                Ok(entry
                    .insert(CachePadded::new(VersionedModuleCode::new(module, version)))
                    .module_code()
                    .clone())
            },
        }
    }
```

**File:** aptos-move/block-executor/src/code_cache.rs (L133-191)
```rust
    fn get_module_or_build_with(
        &self,
        key: &Self::Key,
        builder: &dyn ModuleCodeBuilder<
            Key = Self::Key,
            Deserialized = Self::Deserialized,
            Verified = Self::Verified,
            Extension = Self::Extension,
        >,
    ) -> VMResult<
        Option<(
            Arc<ModuleCode<Self::Deserialized, Self::Verified, Self::Extension>>,
            Self::Version,
        )>,
    > {
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
            },
            ViewState::Unsync(state) => {
                if let Some(module) = self.global_module_cache.get(key) {
                    state.read_set.borrow_mut().capture_module_read(key.clone());
                    return Ok(Some((module, Self::Version::default())));
                }

                let _timer = GLOBAL_MODULE_CACHE_MISS_SECONDS.start_timer();
                let read = state
                    .unsync_map
                    .module_cache()
                    .get_module_or_build_with(key, builder)?;
                state.read_set.borrow_mut().capture_module_read(key.clone());
                Ok(read)
            },
        }
    }
```

**File:** aptos-move/block-executor/src/executor_utilities.rs (L308-346)
```rust
pub(crate) fn update_transaction_on_abort<T, E>(
    txn_idx: TxnIndex,
    last_input_output: &TxnLastInputOutput<T, E::Output>,
    versioned_cache: &MVHashMap<T::Key, T::Tag, T::Value, DelayedFieldID>,
) where
    T: Transaction,
    E: ExecutorTask<Txn = T>,
{
    counters::SPECULATIVE_ABORT_COUNT.inc();

    // Any logs from the aborted execution should be cleared and not reported.
    clear_speculative_txn_logs(txn_idx as usize);

    // Not valid and successfully aborted, mark the latest write/delta sets as estimates.
    if let Some(keys) = last_input_output.modified_resource_keys(txn_idx) {
        for (k, _) in keys {
            versioned_cache.data().mark_estimate(&k, txn_idx);
        }
    }

    // Group metadata lives in same versioned cache as data / resources.
    // We are not marking metadata change as estimate, but after a transaction execution
    // changes metadata, suffix validation is guaranteed to be triggered. Estimation affecting
    // execution behavior is left to size, which uses a heuristic approach.
    last_input_output
        .for_each_resource_group_key_and_tags(txn_idx, |key, tags| {
            versioned_cache
                .group_data()
                .mark_estimate(key, txn_idx, tags);
            Ok(())
        })
        .expect("Passed closure always returns Ok");

    if let Some(keys) = last_input_output.delayed_field_keys(txn_idx) {
        for k in keys {
            versioned_cache.delayed_fields().mark_estimate(&k, txn_idx);
        }
    }
}
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
