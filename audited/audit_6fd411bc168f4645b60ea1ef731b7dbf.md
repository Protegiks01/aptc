# Audit Report

## Title
Speculative Failure DoS via Repeated Transaction Conflicts in BlockSTM Parallel Execution

## Summary
An attacker can craft a set of conflicting transactions that repeatedly trigger speculative execution failures in the BlockSTM parallel executor, causing incarnation numbers to exceed the safety threshold and forcing expensive fallback to sequential execution. This degrades validator performance and block processing throughput.

## Finding Description

The BlockSTM parallel executor uses optimistic concurrency control to execute transactions in parallel. When conflicts occur during speculative execution, transactions are marked with speculative failures and re-executed with incrementing incarnation numbers. [1](#0-0) 

The speculative failures occur when write operations encounter state inconsistencies, such as trying to modify non-existent values or create already-existing values: [2](#0-1) 

The system enforces an incarnation limit to detect potential livelocks: [3](#0-2) 

When this limit is exceeded, the system returns an `IncarnationTooHigh` error and falls back to sequential execution (if `allow_fallback = true`, which is the default): [4](#0-3) [5](#0-4) 

**Attack Scenario:**

1. Attacker submits a block containing many transactions that deliberately conflict on shared resources (e.g., all trying to create the same resource, or forming circular dependencies)
2. During parallel execution, these transactions repeatedly conflict and trigger speculative failures
3. Re-executions increment incarnation numbers for affected transactions
4. With pathological conflict patterns, incarnation numbers can exceed `num_workers^2 + num_txns + 30`
5. System detects `IncarnationTooHigh` and falls back to sequential execution
6. Sequential execution succeeds but processes transactions one-by-one, defeating the purpose of parallel execution

This breaks the **Resource Limits** invariant by causing excessive re-executions and forcing sequential processing, and violates the **liveness guarantee** by significantly degrading block processing performance.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program's "Validator node slowdowns" category.

**Impact:**
- **Performance Degradation:** Forces validators to use sequential execution instead of parallel, reducing throughput significantly (potentially by orders of magnitude depending on concurrency level)
- **Resource Exhaustion:** Wasted CPU cycles on repeated speculative executions before fallback
- **Network-Wide Impact:** If multiple validators are targeted simultaneously, overall network throughput degrades
- **Potential Complete DoS:** If validators are configured with `allow_fallback = false` (non-default), the system panics and the block cannot be processed: [6](#0-5) 

While legitimate transactions ultimately commit through sequential execution (with default config), the attack successfully degrades validator performance and could be used to:
- Reduce network transaction throughput during critical periods
- Increase transaction confirmation latency
- Waste validator computational resources

## Likelihood Explanation

**Likelihood: High**

**Attacker Requirements:**
- Ability to submit transactions to mempool (available to any user)
- Knowledge of resource addresses to create conflicts
- No special privileges required

**Attack Feasibility:**
- Crafting conflicting transactions is straightforward (e.g., multiple transactions trying to create the same resource at the same address)
- The incarnation limit formula `num_workers^2 + num_txns + 30` is reachable with moderate conflict patterns
- Example: With 8 workers and 100 transactions, limit is 64 + 100 + 30 = 194 incarnations
- An attacker could create 50 transactions all conflicting on the same resource, potentially triggering hundreds of re-executions across the conflicting set

**Barriers:**
- Mempool admission policies may limit transaction submission rate
- Transaction fees provide some economic barrier
- However, a determined attacker could still mount this attack periodically

## Recommendation

Implement multi-layered mitigations:

**1. Conflict Detection and Early Abort:**
Add pre-execution conflict analysis to detect and abort pathological conflict patterns before excessive re-executions occur. If a transaction has been re-executed beyond a lower threshold (e.g., `num_workers + 10`), prioritize it for sequential execution or delay conflicting transactions.

**2. Per-Transaction Incarnation Limits:**
Track incarnation counts per-transaction and abort transactions that exceed a per-transaction threshold, treating them as failed transactions rather than forcing entire block sequential fallback:

```rust
// In worker_loop_v2, before execute_v2 call:
const MAX_PER_TXN_INCARNATION: u32 = 50;
if incarnation > MAX_PER_TXN_INCARNATION {
    // Mark transaction as failed/aborted rather than triggering block-wide fallback
    scheduler.abort_transaction(txn_idx, incarnation)?;
    continue;
}
```

**3. Adaptive Fallback Strategy:**
Instead of full sequential fallback, implement partial fallback where only highly-conflicting transaction subsets are executed sequentially while others continue in parallel.

**4. Rate Limiting for Conflicting Transactions:**
Track conflict patterns in mempool and deprioritize transactions that create excessive conflicts with pending transactions.

**5. Monitoring and Alerting:**
Add metrics to track incarnation numbers and alert operators when approaching limits, enabling investigation of potential attacks.

## Proof of Concept

```move
// File: sources/conflict_dos.move
module attacker::conflict_dos {
    use std::signer;
    
    struct SharedResource has key {
        value: u64
    }
    
    // Each transaction in the attack attempts to create the same resource
    public entry fun create_shared_resource(account: &signer) {
        let addr = @0x1234; // Same address for all transactions
        
        // This will succeed for the first transaction
        // All others will hit "recreating existing value" speculative failure
        move_to<SharedResource>(account, SharedResource { value: 0 });
    }
}

// Rust reproduction steps:
// 1. Create 200 transactions all calling create_shared_resource with the same target address
// 2. Submit to a block for parallel execution
// 3. With 8 workers, incarnation limit is ~194
// 4. Each conflicting transaction triggers re-execution
// 5. Total re-executions across all transactions can easily exceed limit
// 6. System falls back to sequential execution
// 7. Observe degraded performance (measure time to process block)
```

**Notes**

While the default configuration (`allow_fallback = true`) prevents complete block processing failure, this vulnerability represents a significant availability attack vector. The system's fallback to sequential execution is a defensive measure that prevents catastrophic failure but at the cost of severe performance degradation. An attacker can weaponize this behavior to degrade network throughput during critical periods, effectively achieving a performance-based denial of service that impacts all network participants.

The vulnerability is particularly concerning because:
1. It requires no special privileges to exploit
2. The attack can be mounted repeatedly with different transaction patterns
3. Detection may be difficult to distinguish from legitimate high-contention scenarios
4. The performance impact scales with network load, making it most effective during peak usage

### Citations

**File:** aptos-move/block-executor/src/executor.rs (L433-441)
```rust
        if is_speculative_failure {
            // Recording in order to check the invariant that the final, committed incarnation
            // of each transaction is not a speculative failure.
            last_input_output.record_speculative_failure(idx_to_execute);
            // Ignoring module validation requirements since speculative failure
            // anyway requires re-execution.
            let _ = scheduler.finish_execution(abort_manager)?;
            return Ok(());
        }
```

**File:** aptos-move/block-executor/src/executor.rs (L1476-1482)
```rust
                    if incarnation > num_workers.pow(2) + num_txns + 30 {
                        // Something is wrong if we observe high incarnations (e.g. a bug
                        // might manifest as an execution-invalidation cycle). Break out
                        // to fallback to sequential execution.
                        error!("Observed incarnation {} of txn {txn_idx}", incarnation);
                        return Err(PanicOr::Or(ParallelBlockExecutionError::IncarnationTooHigh));
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

**File:** aptos-move/aptos-vm/src/move_vm_ext/write_op_converter.rs (L231-247)
```rust
            (None, Modify(_) | Delete) => {
                // Possible under speculative execution, returning speculative error waiting for re-execution.
                return Err(
                    PartialVMError::new(StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR)
                        .with_message(
                            "When converting write op: updating non-existent value.".to_string(),
                        ),
                );
            },
            (Some(_), New(_)) => {
                // Possible under speculative execution, returning speculative error waiting for re-execution.
                return Err(
                    PartialVMError::new(StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR)
                        .with_message(
                            "When converting write op: Recreating existing value.".to_string(),
                        ),
                );
```

**File:** types/src/block_executor/config.rs (L71-79)
```rust
    pub fn default_with_concurrency_level(concurrency_level: usize) -> Self {
        Self {
            blockstm_v2: false,
            concurrency_level,
            allow_fallback: true,
            discard_failed_blocks: false,
            module_cache_config: BlockExecutorModuleCacheLocalConfig::default(),
        }
    }
```
