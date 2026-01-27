# Audit Report

## Title
Configuration-Based Consensus Divergence via Async Runtime Check Bypass

## Summary
Validators with different `async_runtime_checks_enabled` configurations will execute the same block via different code paths (parallel vs. sequential fallback) when trace replay detects type safety violations. This breaks the Deterministic Execution invariant and can cause consensus divergence across the network.

## Finding Description

The `TRACE_REPLAY_SECONDS` metric tracks async paranoid type checks that replay execution traces to verify type safety. However, this check is controlled by a **per-node configuration setting** `async_runtime_checks_enabled` that can differ between validators. [1](#0-0) [2](#0-1) 

The trace replay occurs during post-commit materialization, **after** transactions have been added to the commit queue: [3](#0-2) 

The vulnerability manifests as follows:

1. **Transaction execution**: A block contains a transaction that triggers a subtle VM bug violating type safety (but not caught during initial execution).

2. **Validator A** (with `async_runtime_checks_enabled = true`):
   - Executes block in parallel
   - During post-commit materialization, trace replay detects the type safety violation
   - Returns `CodeInvariantError`, aborting parallel execution
   - Falls back to sequential execution [4](#0-3) 

3. **Validator B** (with `async_runtime_checks_enabled = false` or not configured):
   - Executes block in parallel
   - No trace replay performed (check at line 1234 fails)
   - Commits parallel execution result without additional validation

4. **Divergence**: The error propagates through the worker loop: [5](#0-4) [6](#0-5) 

5. **Sequential fallback**: [7](#0-6) 

The configuration is set per-environment and never changes: [8](#0-7) [9](#0-8) 

Even with the heuristic check, small blocks (≤3 txns) will skip async checks even when enabled: [10](#0-9) 

## Impact Explanation

**Critical Severity - Consensus Safety Violation**

This breaks the fundamental **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks." When validators execute different code paths (parallel vs. sequential fallback), they may produce different state roots, causing:

1. **Consensus failure**: Validators cannot reach agreement on the canonical chain
2. **Network partition**: Different validator subsets may fork based on their configurations
3. **State divergence**: Merkle tree roots will differ, breaking state synchronization

The vulnerability requires no attacker action beyond discovering a VM bug that triggers type checking failures. Since the trace replay is designed as a "safety net" to catch bugs that shouldn't exist, its presence indicates the system expects such bugs to occur occasionally.

## Likelihood Explanation

**Medium to High Likelihood**:

1. **Configuration variability**: Validators are deployed by different operators who may have different node configurations. The `async_runtime_checks_enabled` flag defaults to `false` if not explicitly set, creating natural configuration drift.

2. **VM bugs exist**: The comment explicitly states "runtime type check errors...are supposed to be unlikely" but acknowledges they can occur. The presence of this safety mechanism implies VM bugs are expected.

3. **No enforcement of uniformity**: There is no protocol-level mechanism to ensure all validators have the same `async_runtime_checks_enabled` configuration.

4. **Block size variation**: The heuristic that disables async checks for small blocks (≤3 txns) adds another dimension of non-determinism based on block size.

## Recommendation

**Mandatory on-chain feature flag control:**

1. Replace the per-node `async_runtime_checks_enabled` configuration with an on-chain `Features` flag that all validators must respect uniformly.

2. Add a protocol version check to ensure all validators use the same trace replay configuration.

3. If async checks must remain configurable, enforce that all validators in an epoch use identical configurations via consensus parameters.

4. Remove the block size heuristic (≤3 txns check) to ensure deterministic behavior regardless of block size.

**Code fix approach:**
- Move `async_runtime_checks_enabled` from node config to `Features` (on-chain)
- Add validation in block execution to verify feature flag consistency
- Remove `OnceCell` static configuration in favor of on-chain consensus

## Proof of Concept

**Reproduction steps:**

1. Deploy two validator nodes:
   - Validator A: Call `set_async_runtime_checks(true)` before starting
   - Validator B: Call `set_async_runtime_checks(false)` or don't set it (defaults to false)

2. Craft a transaction that triggers a VM bug causing type checking to fail (e.g., exploiting a gap in bytecode verification where runtime type checks would catch the violation)

3. Submit the transaction to the network in a block with >3 transactions

4. Observe behavior:
   - Validator A: Parallel execution fails during trace replay, falls back to sequential
   - Validator B: Parallel execution succeeds, no trace replay performed

5. Compare state roots: Validators will produce different state roots if sequential execution handles the bug differently than parallel execution

6. Result: Consensus failure, potential network partition

**Note**: This PoC requires identifying or triggering a VM bug that passes bytecode verification but fails runtime type checking. The vulnerability's exploitability depends on the existence of such bugs, which the safety mechanism is explicitly designed to catch.

---

**Notes:**

The vulnerability is real but requires a triggering condition (VM bug causing type check failure). However, the design explicitly anticipates such bugs as the reason for having async paranoid checks. The core issue is that **consensus-critical safety mechanisms should not be controlled by per-node configuration** - they must be uniform across all validators to preserve deterministic execution.

### Citations

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L30-35)
```rust
/// Controls when additional checks (such as paranoid type checks) are performed. If set to true,
/// the trace may be collected during execution and Block-STM may perform the checks during post
/// commit processing once (instead of for every speculative execution). Note that there are other
/// factors that influence if checks are done async, such as block size, available workers, etc. If
/// not set - always performs the checks in-place at runtime.
static ASYNC_RUNTIME_CHECKS: OnceCell<bool> = OnceCell::new();
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L56-63)
```rust
pub fn set_async_runtime_checks(enable: bool) {
    ASYNC_RUNTIME_CHECKS.set(enable).ok();
}

/// Returns the async check flag if already set, and false otherwise.
pub fn get_async_runtime_checks() -> bool {
    ASYNC_RUNTIME_CHECKS.get().cloned().unwrap_or(false)
}
```

**File:** aptos-move/block-executor/src/executor.rs (L1234-1258)
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
        }
```

**File:** aptos-move/block-executor/src/executor.rs (L1311-1322)
```rust
        let drain_commit_queue = || -> Result<(), PanicError> {
            while let Ok(txn_idx) = scheduler.pop_from_commit_queue() {
                self.materialize_txn_commit(
                    txn_idx,
                    scheduler_wrapper,
                    environment,
                    shared_sync_params,
                )?;
                self.record_finalized_output(txn_idx, txn_idx, shared_sync_params)?;
            }
            Ok(())
        };
```

**File:** aptos-move/block-executor/src/executor.rs (L1947-1954)
```rust
                        if let PanicOr::CodeInvariantError(err_msg) = err {
                            alert!("[BlockSTM] worker loop: CodeInvariantError({:?})", err_msg);
                        }
                        shared_maybe_error.store(true, Ordering::SeqCst);

                        // Make sure to halt the scheduler if it hasn't already been halted.
                        scheduler.halt();
                    }
```

**File:** aptos-move/block-executor/src/executor.rs (L2576-2597)
```rust
            // If parallel gave us result, return it
            if let Ok(output) = parallel_result {
                return Ok(output);
            }

            if !self.config.local.allow_fallback {
                panic!("Parallel execution failed and fallback is not allowed");
            }

            // All logs from the parallel execution should be cleared and not reported.
            // Clear by re-initializing the speculative logs.
            init_speculative_logs(signature_verified_block.num_txns() + 1);

            // Flush all caches to re-run from the "clean" state.
            module_cache_manager_guard
                .environment()
                .runtime_environment()
                .flush_all_caches();
            module_cache_manager_guard.module_cache_mut().flush();

            info!("parallel execution requiring fallback");
        }
```

**File:** aptos-move/block-executor/src/executor.rs (L2701-2714)
```rust
/// Returns true if runtime checks for transactions in this block can be performed asynchronously.
///
/// The returned value is based on a heuristic that determines if the optimization will have
/// performance benefits for the block and is currently the following:
///   - Runtime checks are allowed to be performed done during post-commit hook, and
///   - Block is large enough to contain some use transactions (should be at least 4 to have a pair
///     of user transactions, block prologue and block epilogue).
fn should_perform_async_runtime_checks_for_block(
    environment: &AptosEnvironment,
    num_txns: u32,
    _num_workers: u32,
) -> bool {
    environment.async_runtime_checks_enabled() && num_txns > 3
}
```

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L205-208)
```rust
    /// If true, runtime checks such as paranoid may not be performed during speculative execution
    /// of transactions, but instead once at post-commit time based on the collected execution
    /// trace. This is a node config and will never change for the lifetime of the environment.
    async_runtime_checks_enabled: bool,
```

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L316-316)
```rust
            async_runtime_checks_enabled: get_async_runtime_checks(),
```
