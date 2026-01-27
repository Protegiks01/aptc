# Audit Report

## Title
Unhandled Panic Propagation from Block Execution to Consensus Layer

## Summary
The block execution pipeline lacks panic safety mechanisms. If an unwinding panic occurs during parallel transaction execution in worker threads, it will propagate through Rayon's thread pool scope, bypass error handling via the `?` operator (which only handles `Result::Err`), and crash the validator node, causing liveness issues.

## Finding Description
The vulnerability exists in the call chain from consensus to VM block execution: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

The critical issue: Rayon's `thread_pool.scope()` propagates unwinding panics from spawned worker threads. While the code handles `Result<(), PanicOr<...>>` errors from `worker_loop()`, actual unwinding panics (from `panic!`, `assert!`, `unwrap()`, `expect()`) bypass this error handling and propagate to the calling thread after the scope exits.

**Panic propagation path:**
1. Worker thread executes transaction and encounters panic (e.g., failed assertion)
2. Panic unwinds through worker thread
3. Rayon catches panic and resumes it in calling thread after `scope()` exits
4. Panic bypasses all `?` operators (which only handle `Result` types)
5. Panic propagates through `execute_block()` → `execute_and_update_state()` → consensus
6. Validator node crashes

**Explicit panic locations:** [5](#0-4) [6](#0-5) 

While these explicit panics are guarded by `allow_fallback` (set to `true` in production), they demonstrate the lack of defensive panic handling. [7](#0-6) 

**Code invariant checks that could panic:** [8](#0-7) [9](#0-8) 

## Impact Explanation
This qualifies as **High Severity** under the Aptos bug bounty program:
- **Validator node crashes**: If a panic propagates, the validator process terminates
- **Liveness degradation**: Multiple validator crashes reduce network availability
- **Consensus disruption**: Validator crashes during block execution disrupt consensus progress

While I could not identify a concrete attacker-controlled trigger for these panics, the vulnerability represents a systemic fragility where:
1. Future code changes introducing panics would be catastrophic
2. Undiscovered edge cases triggering assertions would crash validators
3. The system lacks defense-in-depth for panic safety

## Likelihood Explanation
**Likelihood: Low to Medium**

The existing code has defensive checks that convert most errors to `Result` types. However:
- Code invariant violations (`assert!`, `expect!`) exist in execution paths
- Future code additions may introduce panics
- Complex transaction patterns might trigger unexpected edge cases
- The lack of `catch_unwind` means ANY panic becomes a validator crash

## Recommendation
Wrap the Rayon scope invocation in `std::panic::catch_unwind` to convert unwinding panics to `Result` errors:

```rust
use std::panic::{catch_unwind, AssertUnwindSafe};

// In execute_transactions_parallel_v2 and execute_transactions_parallel
let panic_result = catch_unwind(AssertUnwindSafe(|| {
    self.executor_thread_pool.scope(|s| {
        for worker_id in &worker_ids {
            s.spawn(|_| {
                // existing worker logic
            });
        }
    });
}));

if panic_result.is_err() {
    alert!("Caught panic in block execution, falling back");
    shared_maybe_error.store(true, Ordering::SeqCst);
}
```

This ensures panics are caught and converted to execution errors, triggering fallback to sequential execution rather than crashing the validator.

## Proof of Concept
The PoC would require:
1. Identifying a specific transaction pattern that triggers a code invariant violation
2. Crafting transactions to exploit that pattern
3. Demonstrating validator crash when panic propagates

However, without a concrete panic trigger, I cannot provide a working PoC. The vulnerability is the **lack of panic safety mechanism**, not a specific exploitable panic.

**Notes:**
- No `catch_unwind` exists in the VM or block executor code paths
- The system relies on all panics being prevented, not handled
- This creates fragility where any future panic becomes a validator crash vulnerability

### Citations

**File:** execution/executor/src/block_executor/mod.rs (L97-112)
```rust
    fn execute_and_update_state(
        &self,
        block: ExecutableBlock,
        parent_block_id: HashValue,
        onchain_config: BlockExecutorConfigFromOnchain,
    ) -> ExecutorResult<()> {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "execute_and_state_checkpoint"]);

        self.maybe_initialize()?;
        // guarantee only one block being executed at a time
        let _guard = self.execution_lock.lock();
        self.inner
            .read()
            .as_ref()
            .expect("BlockExecutor is not reset")
            .execute_and_update_state(block, parent_block_id, onchain_config)
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L281-294)
```rust
    fn execute_block<V: VMBlockExecutor>(
        executor: &V,
        txn_provider: &DefaultTxnProvider<SignatureVerifiedTransaction, AuxiliaryInfo>,
        state_view: &CachedStateView,
        onchain_config: BlockExecutorConfigFromOnchain,
        transaction_slice_metadata: TransactionSliceMetadata,
    ) -> Result<BlockOutput<SignatureVerifiedTransaction, TransactionOutput>> {
        let _timer = OTHER_TIMERS.timer_with(&["vm_execute_block"]);
        Ok(executor.execute_block(
            txn_provider,
            state_view,
            onchain_config,
            transaction_slice_metadata,
        )?)
```

**File:** aptos-move/aptos-vm/src/block_executor/mod.rs (L515-586)
```rust
    pub fn execute_block_on_thread_pool<
        S: StateView + Sync,
        L: TransactionCommitHook,
        TP: TxnProvider<SignatureVerifiedTransaction, AuxiliaryInfo> + Sync,
    >(
        executor_thread_pool: Arc<rayon::ThreadPool>,
        signature_verified_block: &TP,
        state_view: &S,
        module_cache_manager: &AptosModuleCacheManager,
        config: BlockExecutorConfig,
        transaction_slice_metadata: TransactionSliceMetadata,
        transaction_commit_listener: Option<L>,
    ) -> Result<BlockOutput<SignatureVerifiedTransaction, TransactionOutput>, VMStatus> {
        let _timer = BLOCK_EXECUTOR_EXECUTE_BLOCK_SECONDS.start_timer();

        let num_txns = signature_verified_block.num_txns();
        if state_view.id() != StateViewId::Miscellaneous {
            // Speculation is disabled in Miscellaneous context, which is used by testing and
            // can even lead to concurrent execute_block invocations, leading to errors on flush.
            init_speculative_logs(num_txns);
        }

        BLOCK_EXECUTOR_CONCURRENCY.set(config.local.concurrency_level as i64);

        let mut module_cache_manager_guard = module_cache_manager.try_lock(
            &state_view,
            &config.local.module_cache_config,
            transaction_slice_metadata,
        )?;

        let executor =
            BlockExecutor::<SignatureVerifiedTransaction, E, S, L, TP, AuxiliaryInfo>::new(
                config,
                executor_thread_pool,
                transaction_commit_listener,
            );

        let ret = executor.execute_block(
            signature_verified_block,
            state_view,
            &transaction_slice_metadata,
            &mut module_cache_manager_guard,
        );
        match ret {
            Ok(block_output) => {
                let (transaction_outputs, block_epilogue_txn) = block_output.into_inner();
                let output_vec: Vec<_> = transaction_outputs
                    .into_iter()
                    .map(|output| output.take_output())
                    .collect();

                // Flush the speculative logs of the committed transactions.
                let pos = output_vec.partition_point(|o| !o.status().is_retry());

                if state_view.id() != StateViewId::Miscellaneous {
                    // Speculation is disabled in Miscellaneous context, which is used by testing and
                    // can even lead to concurrent execute_block invocations, leading to errors on flush.
                    flush_speculative_logs(pos);
                }

                Ok(BlockOutput::new(output_vec, block_epilogue_txn))
            },
            Err(BlockExecutionError::FatalBlockExecutorError(PanicError::CodeInvariantError(
                err_msg,
            ))) => Err(VMStatus::Error {
                status_code: StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR,
                sub_status: None,
                message: Some(err_msg),
            }),
            Err(BlockExecutionError::FatalVMError(err)) => Err(err),
        }
    }
```

**File:** aptos-move/block-executor/src/executor.rs (L423-428)
```rust
        let mut read_set = sync_view.take_parallel_reads();
        if read_set.is_incorrect_use() {
            return Err(code_invariant_error(format!(
                "Incorrect use detected in CapturedReads after executing txn = {idx_to_execute} incarnation = {incarnation}"
            )));
        }
```

**File:** aptos-move/block-executor/src/executor.rs (L788-800)
```rust
        let (read_set, is_speculative_failure) = last_input_output
            .read_set(idx_to_validate)
            .expect("[BlockSTM]: Prior read-set must be recorded");

        if is_speculative_failure {
            return false;
        }

        assert!(
            !read_set.is_incorrect_use(),
            "Incorrect use must be handled after execution"
        );

```

**File:** aptos-move/block-executor/src/executor.rs (L1765-1806)
```rust
        self.executor_thread_pool.scope(|s| {
            for worker_id in &worker_ids {
                s.spawn(|_| {
                    let environment = module_cache_manager_guard.environment();
                    let executor = {
                        let _init_timer = VM_INIT_SECONDS.start_timer();
                        E::init(
                            &environment.clone(),
                            shared_sync_params.base_view,
                            async_runtime_checks_enabled,
                        )
                    };

                    if let Err(err) = self.worker_loop_v2(
                        &executor,
                        signature_verified_block,
                        environment,
                        *worker_id,
                        num_workers,
                        &scheduler,
                        &shared_sync_params,
                    ) {
                        // If there are multiple errors, they all get logged: FatalVMError is
                        // logged at construction, below we log CodeInvariantErrors.
                        if let PanicOr::CodeInvariantError(err_msg) = err {
                            alert!(
                                "[BlockSTMv2] worker loop: CodeInvariantError({:?})",
                                err_msg
                            );
                        }
                        shared_maybe_error.store(true, Ordering::SeqCst);

                        // Make sure to halt the scheduler if it hasn't already been halted.
                        scheduler.halt();
                    }

                    if *worker_id == 0 {
                        maybe_executor.acquire().replace(executor);
                    }
                });
            }
        });
```

**File:** aptos-move/block-executor/src/executor.rs (L2580-2583)
```rust

            if !self.config.local.allow_fallback {
                panic!("Parallel execution failed and fallback is not allowed");
            }
```

**File:** aptos-move/block-executor/src/executor.rs (L2613-2616)
```rust
            Err(SequentialBlockExecutionError::ResourceGroupSerializationError) => {
                if !self.config.local.allow_fallback {
                    panic!("Parallel execution failed and fallback is not allowed");
                }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3110-3120)
```rust
        let config = BlockExecutorConfig {
            local: BlockExecutorLocalConfig {
                blockstm_v2: AptosVM::get_blockstm_v2_enabled(),
                concurrency_level: AptosVM::get_concurrency_level(),
                allow_fallback: true,
                discard_failed_blocks: AptosVM::get_discard_failed_blocks(),
                module_cache_config: BlockExecutorModuleCacheLocalConfig::default(),
            },
            onchain: onchain_config,
        };
        self.execute_block_with_config(txn_provider, state_view, config, transaction_slice_metadata)
```
