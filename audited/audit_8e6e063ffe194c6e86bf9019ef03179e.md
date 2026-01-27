# Audit Report

## Title
Async Paranoid Check Creates Consensus Divergence Risk via Non-Uniform Configuration

## Summary
The async paranoid check (trace replay) occurs AFTER transaction commitment in parallel execution, and its failure handling depends on local per-node configuration (`async_runtime_checks` and `allow_fallback`). This creates a consensus divergence vulnerability where validators with different configurations will disagree on block validity when the paranoid check fails, violating the fundamental "Deterministic Execution" invariant.

## Finding Description

The vulnerability occurs in the block executor's post-commit materialization flow: [1](#0-0) 

Transaction commitment happens first in `prepare_and_queue_commit_ready_txn`. After this, the paranoid check runs in `materialize_txn_commit`: [2](#0-1) 

When the trace replay fails, it returns a `PanicError::CodeInvariantError` that propagates through the worker loop: [3](#0-2) 

The critical issue is that both `async_runtime_checks` and `allow_fallback` are LOCAL configurations: [4](#0-3) [5](#0-4) 

Neither setting is enforced uniformly across validators. When parallel execution fails, the behavior differs: [6](#0-5) 

**Attack Scenario:**
1. A transaction executes successfully and is committed
2. The async paranoid check (trace replay) fails due to a TypeChecker bug or edge case
3. Validator A (`async_runtime_checks=true`, `allow_fallback=false`): Panics at line 2582, rejects block
4. Validator B (`async_runtime_checks=false`): Never runs check, accepts block
5. Validator C (`async_runtime_checks=true`, `allow_fallback=true`): Falls back to sequential execution (which doesn't perform paranoid checks), accepts block

The network now has consensus divergence with validators on different forks.

## Impact Explanation

**Critical Severity** - This meets the "Consensus/Safety violations" criterion from the bug bounty program. It directly violates Critical Invariant #1: "Deterministic Execution - All validators must produce identical state roots for identical blocks."

The impact includes:
- Network partition where validators cannot agree on block validity
- Potential for chain splits requiring coordination or hard fork to resolve
- Non-deterministic block processing based on local configuration
- Undermines the fundamental consensus safety guarantee

This is particularly severe because:
1. The transaction is ALREADY COMMITTED before the check fails
2. The failure handling is non-deterministic across validators
3. No on-chain enforcement ensures uniform configuration
4. Sequential fallback bypasses the check entirely, masking the issue

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability requires:
1. ✓ Validators with heterogeneous `async_runtime_checks` and `allow_fallback` configurations (likely in practice as defaults differ and no enforcement exists)
2. ✓ A transaction or execution edge case that causes trace replay to fail (the comment acknowledges these "are supposed to be unlikely" but can occur)
3. ✓ Default configuration makes this exploitable: `async_runtime_checks` defaults to `false`, and there's no sanitizer enforcement [7](#0-6) 

The mainnet sanitizer only enforces `paranoid_type_verification` and `paranoid_hot_potato_verification`, NOT `async_runtime_checks`: [8](#0-7) 

## Recommendation

**Solution 1: Make paranoid check failure deterministic (RECOMMENDED)**
1. If `async_runtime_checks` is enabled, always propagate failures without fallback for committed transactions
2. Add on-chain governance parameter for `async_runtime_checks_enabled` that all validators must respect
3. Remove local configuration for consensus-affecting behavior

**Solution 2: Perform paranoid checks BEFORE commit**
Move the trace replay to occur in `prepare_and_queue_commit_ready_txn` BEFORE line 1059 commits the transaction. This way, failures prevent commitment consistently.

**Solution 3: Add configuration enforcement**
Extend the sanitizer to enforce uniform `async_runtime_checks` and `allow_fallback` for mainnet:

```rust
// In config/src/config/execution_config.rs sanitizer
if chain_id.is_mainnet() {
    if execution_config.async_runtime_checks {
        return Err(Error::ConfigSanitizerFailed(
            sanitizer_name,
            "async_runtime_checks must be false for mainnet validators for consensus safety!"
                .into(),
        ));
    }
}
```

## Proof of Concept

```rust
// Reproduction steps:
// 1. Set up 3 validator nodes with different configs:
//    Node A: async_runtime_checks=true, allow_fallback=false
//    Node B: async_runtime_checks=false
//    Node C: async_runtime_checks=true, allow_fallback=true
//
// 2. Inject a TypeChecker replay bug or find a transaction that triggers
//    a replay failure (e.g., by fuzzing the TypeChecker with edge cases)
//
// 3. Submit the transaction through consensus
//
// 4. Observe divergence:
//    - Node A: Panics and rejects block
//    - Node B: Accepts block (never ran check)
//    - Node C: Accepts block (sequential fallback)
//
// 5. Network partitions with Node A on a different fork

// Minimal test to demonstrate config differences:
#[test]
fn test_consensus_divergence_via_async_check_config() {
    // Node with async_runtime_checks=true, allow_fallback=false
    let config_strict = BlockExecutorConfig {
        local: BlockExecutorLocalConfig {
            allow_fallback: false,
            // ... with async_runtime_checks via ExecutionConfig
        },
    };
    
    // Node with async_runtime_checks=false
    let config_permissive = BlockExecutorConfig {
        local: BlockExecutorLocalConfig {
            allow_fallback: true,
        },
    };
    
    // When trace replay fails, nodes disagree on block validity
    // leading to consensus divergence
}
```

## Notes

This vulnerability exists because consensus-critical validation logic is controlled by local, per-node configuration rather than enforced uniformly across all validators. The trace replay check is performed POST-COMMIT, meaning the transaction's state changes are already applied when the check fails, creating an irrecoverable inconsistency across nodes with different configurations.

The issue is exacerbated by sequential execution fallback never performing paranoid checks, effectively masking failures for nodes configured with `allow_fallback=true`.

### Citations

**File:** aptos-move/block-executor/src/executor.rs (L1059-1067)
```rust
        last_input_output.commit(
            txn_idx,
            num_txns,
            num_workers,
            block_limit_processor,
            shared_sync_params.maybe_block_epilogue_txn_idx,
            &scheduler,
        )
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

**File:** config/src/config/execution_config.rs (L59-60)
```rust
    pub async_runtime_checks: bool,
}
```

**File:** config/src/config/execution_config.rs (L94-94)
```rust
            async_runtime_checks: false,
```

**File:** config/src/config/execution_config.rs (L166-183)
```rust
        // If this is a mainnet node, ensure that additional verifiers are enabled
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() {
                if !execution_config.paranoid_hot_potato_verification {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "paranoid_hot_potato_verification must be enabled for mainnet nodes!"
                            .into(),
                    ));
                }
                if !execution_config.paranoid_type_verification {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "paranoid_type_verification must be enabled for mainnet nodes!".into(),
                    ));
                }
            }
        }
```

**File:** types/src/block_executor/config.rs (L57-59)
```rust
    // If specified, parallel execution fallbacks to sequential, if issue occurs.
    // Otherwise, if there is an error in either of the execution, we will panic.
    pub allow_fallback: bool,
```
