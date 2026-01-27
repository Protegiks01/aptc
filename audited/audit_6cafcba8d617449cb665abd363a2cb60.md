# Audit Report

## Title
Trace Replay Module Version Mismatch Can Cause Type Check Failures and Performance Degradation

## Summary
The `FullTraceRecorder::record_entrypoint()` function clones `LoadedFunction` objects containing references to module versions at execution time. During trace replay for asynchronous type checking, remote function calls load modules from `latest_view`, which may contain upgraded versions. This version mismatch between recorded entrypoints and replayed remote calls can cause spurious type check failures, triggering expensive sequential fallbacks.

## Finding Description

When asynchronous runtime checks are enabled in Aptos, transactions execute **without** type checks and record execution traces. Type checking is deferred to trace replay after transaction materialization. This breaks the critical invariant of **Deterministic Execution** when module upgrades occur within the same block. [1](#0-0) 

The recorded trace contains a cloned `LoadedFunction` with `Arc<Module>` and `Arc<Function>` references pointing to the module version at execution time. However, during replay, remote function calls load fresh module instances from storage: [2](#0-1) 

This creates a version inconsistency where the entrypoint uses module version V1 (from the trace) but remote calls load module version V2 (from `latest_view`), even though the actual execution used V1 for all calls.

**Critical Evidence:**

The codebase explicitly acknowledges this problem for module validation: [3](#0-2) 

The comment states module validation is skipped after commit because later module publishes can be observed. However, trace replay does NOT skip type checking, executing with this same problematic pattern: [4](#0-3) 

When type checks fail due to version mismatches, the system returns a `CodeInvariantError` triggering sequential fallback - a significant performance penalty.

**Execution Flow Demonstrating the Issue:**

1. During parallel execution, transaction T1 calls Module A which makes remote calls to Module B (both at version 1)
2. Type checks are **disabled** during execution when tracing is enabled: [5](#0-4) 

3. Trace records entrypoint with Module A v1
4. Later in the block, transaction T2 commits, upgrading Module B to v2 in the global cache
5. T1's trace is replayed during materialization: [6](#0-5) 

6. Entrypoint uses Module A v1 (from trace), but remote calls to Module B load v2 (from `latest_view`)
7. Type mismatch causes validation failure despite the execution being type-safe with consistent v1 versions

## Impact Explanation

**Severity: HIGH** per Aptos bug bounty criteria ("Validator node slowdowns, Significant protocol violations")

This vulnerability enables a **Denial of Service attack** against parallel execution:

1. **Performance Degradation**: Each spurious type check failure forces expensive sequential re-execution, negating the benefits of parallel execution
2. **Repeated Exploitation**: An attacker can craft transaction patterns that reliably trigger this condition within blocks containing module upgrades
3. **Protocol Violation**: The type checker validates execution against incorrect module versions, undermining the safety guarantees of the type system

While this does not directly cause consensus divergence (all validators see the same state), it violates the **Deterministic Execution** invariant by performing type checks with different module versions than were actually executed.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This is exploitable in production environments where:

1. Module upgrades occur (common in active chains with governance and protocol updates)
2. Asynchronous runtime checks are enabled (line 141-142 in environment.rs confirms this is a configurable production feature)
3. Transactions in the same block interact with upgraded modules

The attack requires:
- No special privileges (any transaction sender can trigger this)
- Precise timing: transactions calling a module + transaction upgrading that module in same block
- Module upgrade capabilities (but these exist for framework modules and user-deployed contracts)

The codebase comment acknowledging this exact issue for module validation indicates the developers are aware of the problem but haven't addressed it for trace replay.

## Recommendation

**Option 1: Snapshot Module Versions in Trace**
Record the exact module versions (not just function references) used during execution in the trace, and use these snapshots during replay instead of loading from `latest_view`.

**Option 2: Skip Type Checking After Module Publishes**
Similar to the existing mitigation for module validation, skip trace replay type checking for transactions that may observe module upgrades:

```rust
// In materialize_txn_commit, before trace replay:
if environment.async_runtime_checks_enabled() && !trace.is_empty() {
    // Check if any module publishes happened in this block before this transaction
    let has_prior_module_publishes = /* check versioned_cache.module_cache() */;
    
    if !has_prior_module_publishes {
        let result = TypeChecker::new(&latest_view).replay(&trace);
        if let Err(err) = result {
            // ... error handling
        }
    }
    // Otherwise skip type check to avoid version mismatch issues
}
```

**Option 3: Versioned Module Cache for Replay**
Create a versioned view of the module cache at the transaction's execution time and use that for trace replay instead of `latest_view`.

## Proof of Concept

```rust
// Reproduction scenario (conceptual, requires Aptos test harness):

// Step 1: Deploy Module A v1 that calls Module B v1
module 0xA::A {
    use 0xB::B;
    
    public entry fun call_b() {
        B::function_v1(); // Type: () -> u64
    }
}

module 0xB::B {
    public fun function_v1(): u64 { 42 }
}

// Step 2: In a single block, submit:
// - Tx1 (index 10): Call 0xA::A::call_b()  [executes with B v1, traces recorded]
// - Tx2 (index 5): Upgrade Module B:

module 0xB::B {
    public fun function_v1(): u128 { 42 }  // Changed return type!
}

// Step 3: Expected behavior during parallel execution:
// - Tx2 commits first (lower index), publishes B v2 to global cache
// - Tx1 validates, materializes
// - Tx1 trace replay:
//   * Entrypoint: A v1 (from trace)
//   * Remote call to B: loads B v2 (from latest_view)
//   * Type mismatch: expected u64, found u128
//   * Type check FAILS despite execution being valid
// - Sequential fallback triggered

// This can be verified by:
// 1. Enabling async_runtime_checks in test configuration
// 2. Observing CodeInvariantError in executor logs
// 3. Measuring performance degradation from sequential fallback
```

**Notes:**

This vulnerability exists at the intersection of three design decisions:
1. Deferring type checks to trace replay when tracing is enabled
2. Cloning module references at record time but loading fresh modules at replay time  
3. Non-versioned global module cache that updates at commit time

The explicit comment in executor.rs acknowledging the module validation issue suggests this is a known limitation, but the mitigation (skipping validation) was not applied to trace replay type checking, leaving this attack vector open.

### Citations

**File:** third_party/move/move-vm/runtime/src/execution_tracing/recorders.rs (L111-113)
```rust
    fn record_entrypoint(&mut self, function: &LoadedFunction) {
        self.calls.push(DynamicCall::Entrypoint(function.clone()));
    }
```

**File:** third_party/move/move-vm/runtime/src/runtime_type_checks_async.rs (L797-806)
```rust
            FunctionHandle::Remote { module, name } => {
                // There is no need to meter gas here: it has been charged during execution.
                let module = self
                    .module_storage
                    .unmetered_get_existing_lazily_verified_module(module)
                    .map_err(|err| err.to_partial())?;
                let function = module.get_function(name).map_err(|err| err.to_partial())?;
                (LoadedFunctionOwner::Module(module), function)
            },
        };
```

**File:** aptos-move/block-executor/src/executor.rs (L1147-1153)
```rust
            // Module cache is not versioned (published at commit), so validation after
            // commit might observe later publishes (higher txn index) and be incorrect.
            // Hence, we skip the paranoid module validation after commit.
            // TODO(BlockSTMv2): Do the additional checking in sequential commit hook,
            // when modules have been published. Update the comment here as skipping
            // in V2 is needed for a different, code cache implementation related reason.
            true,
```

**File:** aptos-move/block-executor/src/executor.rs (L1170-1176)
```rust
        let latest_view = LatestView::new(
            shared_sync_params.base_view,
            shared_sync_params.global_module_cache,
            environment.runtime_environment(),
            ViewState::Sync(parallel_state),
            txn_idx,
        );
```

**File:** aptos-move/block-executor/src/executor.rs (L1234-1257)
```rust
        if environment.async_runtime_checks_enabled() && !trace.is_empty() {
            // Note that the trace may be empty (if block was small and executor decides not to
            // collect the trace and replay, or if the VM decides it is not profitable to do this
            // check for this particular transaction), so we check it in advance.
            let result = {
                counters::update_txn_trace_counters(&trace);
                let _timer = TRACE_REPLAY_SECONDS.start_timer();
                TypeChecker::new(&latest_view).replay(&trace)
            };

            // In case of runtime type check errors, fallback to sequential execution. There errors
            // are supposed to be unlikely so this fallback is fine, and is mostly needed to make
            // sure transaction epilogue runs after failure, etc.
            if let Err(err) = result {
                alert!(
                    "Runtime type check failed during replay of transaction {}: {:?}",
                    txn_idx,
                    err
                );
                return Err(PanicError::CodeInvariantError(format!(
                    "Sequential fallback on type check failure for transaction {}: {:?}",
                    txn_idx, err
                )));
            }
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L241-245)
```rust
        // Tracing and runtime checks (full or partial) are mutually exclusive because if we record
        // the trace, the checks are done after execution via abstract interpretation during trace
        // replay.
        let paranoid_type_checks =
            !trace_recorder.is_enabled() && interpreter.vm_config.paranoid_type_checks;
```
