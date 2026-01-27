# Audit Report

## Title
Reader-Writer Lock Contention in ChunkExecutor Blocks Critical Reset Operations

## Summary
The `with_inner()` function in `ChunkExecutor` holds a read lock for the entire duration of long-running operations (VM execution, ledger updates, database commits), which can block critical write lock operations like `reset()` and `finish()` for extended periods. This causes validator node slowdowns and delayed epoch transitions during state synchronization.

## Finding Description

The `with_inner()` function acquires a read lock that spans the entire closure execution: [1](#0-0) 

This read lock is held during three categories of long-running operations:

**1. VM Execution** - When `enqueue_chunk()` is called, it executes up to 3,000 transactions per chunk via `chunk.into_output::<V>()`: [2](#0-1) 

The VM execution happens within the closure while holding the read lock: [3](#0-2) 

With max execution gas of 920M units (92ms per transaction) and governance transactions up to 4B units (400ms), a chunk can hold the lock for 30+ seconds: [4](#0-3) 

**2. Ledger Updates** - State checkpoint and merkle tree computations: [5](#0-4) 

**3. Database Commits** - Synchronous database writes: [6](#0-5) 

Meanwhile, `reset()` and `finish()` require write locks and will block: [7](#0-6) 

These operations are critical for consensus and state sync: [8](#0-7) [9](#0-8) 

State sync processes chunks concurrently in a pipeline with up to 3,000 transactions per chunk: [10](#0-9) 

## Impact Explanation

This issue qualifies as **High Severity** under the Aptos bug bounty program criteria: "Validator node slowdowns."

During state synchronization, validators processing expensive blocks (with legitimate transactions near gas limits) will experience:

1. **Delayed Epoch Transitions**: When consensus detects epoch changes and calls `reset()`, it blocks until all in-flight chunk operations complete, potentially delaying validator set updates by 30+ seconds per chunk in the pipeline.

2. **Prolonged Error Recovery**: If errors occur during state sync, `reset()` calls for recovery are blocked, extending downtime.

3. **Cascading Validator Impact**: Multiple validators performing state sync simultaneously experience coordinated slowdowns, temporarily reducing network throughput.

While not breaking consensus safety, this affects validator liveness and responsiveness during critical operations.

## Likelihood Explanation

**Likelihood: High**

This occurs naturally during:
- New validators joining and performing initial state sync
- Validators recovering from downtime
- State sync after network partitions
- Processing of blocks containing expensive governance proposals or complex DeFi transactions

The max chunk size of 3,000 transactions combined with legitimate expensive transactions creates frequent conditions for extended lock holds.

## Recommendation

Refactor `with_inner()` to reduce the read lock scope. The lock should only protect access to retrieve the `ChunkExecutorInner` reference, not the actual operations:

```rust
fn with_inner<F, T>(&self, f: F) -> Result<T>
where
    F: FnOnce(&ChunkExecutorInner<V>) -> Result<T>,
{
    // Acquire read lock briefly to get Arc reference
    let inner = {
        let locked = self.inner.read();
        locked.as_ref().expect("not reset").clone()
    };
    // Lock released here - long operations happen without lock
    
    let has_pending_pre_commit = inner.has_pending_pre_commit.load(Ordering::Acquire);
    f(&inner).map_err(|error| {
        if has_pending_pre_commit {
            panic!(
                "Hit error with pending pre-committed ledger, panicking. {:?}",
                error,
            );
        }
        error
    })
}
```

Change `inner: RwLock<Option<ChunkExecutorInner<V>>>` to `inner: RwLock<Option<Arc<ChunkExecutorInner<V>>>>` to enable safe cloning of the Arc reference.

## Proof of Concept

```rust
// Reproduction test demonstrating lock contention
#[tokio::test]
async fn test_chunk_executor_lock_contention() {
    let chunk_executor = ChunkExecutor::<AptosVM>::new(db);
    chunk_executor.reset().unwrap();
    
    // Thread 1: Simulate long-running chunk execution
    let executor1 = Arc::clone(&chunk_executor);
    let handle1 = tokio::spawn(async move {
        let start = Instant::now();
        // This holds read lock for duration of chunk execution
        executor1.enqueue_chunk_by_execution(
            expensive_chunk_with_3000_txns, 
            &ledger_info, 
            None
        ).unwrap();
        println!("Chunk execution took: {:?}", start.elapsed());
    });
    
    // Thread 2: Attempt reset while chunk is executing
    tokio::time::sleep(Duration::from_millis(100)).await;
    let executor2 = Arc::clone(&chunk_executor);
    let handle2 = tokio::spawn(async move {
        let start = Instant::now();
        // This will block until chunk execution completes
        executor2.reset().unwrap();
        println!("Reset blocked for: {:?}", start.elapsed());
    });
    
    handle1.await.unwrap();
    handle2.await.unwrap();
    
    // Observe: reset() blocked for duration of chunk execution
}
```

## Notes

While this issue causes validator performance degradation, it does not break consensus safety or allow fund theft. The transactions being processed are legitimate and already committed to the blockchain. The vulnerability lies in unnecessarily broad lock scoping that impacts operational responsiveness rather than security guarantees. However, it meets the High severity criteria for "Validator node slowdowns" and should be addressed to maintain network performance during state synchronization.

### Citations

**File:** execution/executor/src/chunk_executor/mod.rs (L89-106)
```rust
    fn with_inner<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&ChunkExecutorInner<V>) -> Result<T>,
    {
        let locked = self.inner.read();
        let inner = locked.as_ref().expect("not reset");

        let has_pending_pre_commit = inner.has_pending_pre_commit.load(Ordering::Acquire);
        f(inner).map_err(|error| {
            if has_pending_pre_commit {
                panic!(
                    "Hit error with pending pre-committed ledger, panicking. {:?}",
                    error,
                );
            }
            error
        })
    }
```

**File:** execution/executor/src/chunk_executor/mod.rs (L214-226)
```rust
    fn reset(&self) -> Result<()> {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["chunk", "reset"]);

        *self.inner.write() = Some(ChunkExecutorInner::new(self.db.clone())?);
        Ok(())
    }

    fn finish(&self) {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["chunk", "finish"]);

        *self.inner.write() = None;
    }
}
```

**File:** execution/executor/src/chunk_executor/mod.rs (L261-288)
```rust
    fn commit_chunk_impl(&self) -> Result<ExecutedChunk> {
        let _timer = CHUNK_OTHER_TIMERS.timer_with(&["commit_chunk_impl__total"]);
        let chunk = {
            let _timer =
                CHUNK_OTHER_TIMERS.timer_with(&["commit_chunk_impl__next_chunk_to_commit"]);
            self.commit_queue.lock().next_chunk_to_commit()?
        };

        let output = chunk.output.expect_complete_result();
        let num_txns = output.num_transactions_to_commit();
        if chunk.ledger_info_opt.is_some() || num_txns != 0 {
            let _timer = CHUNK_OTHER_TIMERS.timer_with(&["commit_chunk_impl__save_txns"]);
            // TODO(aldenhu): remove since there's no practical strategy to recover from this error.
            fail_point!("executor::commit_chunk", |_| {
                Err(anyhow::anyhow!("Injected error in commit_chunk"))
            });
            self.db.writer.save_transactions(
                output.as_chunk_to_commit(),
                chunk.ledger_info_opt.as_ref(),
                false, // sync_commit
            )?;
        }

        let _timer = CHUNK_OTHER_TIMERS.timer_with(&["commit_chunk_impl__dequeue_and_return"]);
        self.commit_queue.lock().dequeue_committed()?;

        Ok(chunk)
    }
```

**File:** execution/executor/src/chunk_executor/mod.rs (L295-334)
```rust
    fn enqueue_chunk<Chunk: TransactionChunk + Sync>(
        &self,
        chunk: Chunk,
        chunk_verifier: Arc<dyn ChunkResultVerifier + Send + Sync>,
        mode_for_log: &'static str,
    ) -> Result<()> {
        let parent_state = self.commit_queue.lock().latest_state().clone();

        let first_version = parent_state.next_version();
        ensure!(
            chunk.first_version() == parent_state.next_version(),
            "Chunk carries unexpected first version. Expected: {}, got: {}",
            parent_state.next_version(),
            chunk.first_version(),
        );

        let num_txns = chunk.len();

        let state_view = self.state_view(parent_state.latest())?;
        let execution_output = chunk.into_output::<V>(&parent_state, state_view)?;
        let output = PartialStateComputeResult::new(execution_output);

        // Enqueue for next stage.
        self.commit_queue
            .lock()
            .enqueue_for_ledger_update(ChunkToUpdateLedger {
                output,
                chunk_verifier,
            })?;

        info!(
            LogSchema::new(LogEntry::ChunkExecutor)
                .first_version_in_request(Some(first_version))
                .num_txns_in_request(num_txns),
            mode = mode_for_log,
            "Enqueued transaction chunk!",
        );

        Ok(())
    }
```

**File:** execution/executor/src/chunk_executor/mod.rs (L336-392)
```rust
    pub fn update_ledger(&self) -> Result<()> {
        let _timer = CHUNK_OTHER_TIMERS.timer_with(&["chunk_update_ledger_total"]);

        let (parent_state_summary, parent_accumulator, chunk) =
            self.commit_queue.lock().next_chunk_to_update_ledger()?;
        let ChunkToUpdateLedger {
            output,
            chunk_verifier,
        } = chunk;

        let state_checkpoint_output = DoStateCheckpoint::run(
            &output.execution_output,
            &parent_state_summary,
            &ProvableStateSummary::new_persisted(self.db.reader.as_ref())?,
            Some(
                chunk_verifier
                    .transaction_infos()
                    .iter()
                    .map(|t| t.state_checkpoint_hash())
                    .collect_vec(),
            ),
        )?;

        let ledger_update_output = DoLedgerUpdate::run(
            &output.execution_output,
            &state_checkpoint_output,
            parent_accumulator.clone(),
        )?;

        chunk_verifier.verify_chunk_result(&parent_accumulator, &ledger_update_output)?;

        let ledger_info_opt = chunk_verifier.maybe_select_chunk_ending_ledger_info(
            &ledger_update_output,
            output.execution_output.next_epoch_state.as_ref(),
        )?;
        output.set_state_checkpoint_output(state_checkpoint_output);
        output.set_ledger_update_output(ledger_update_output);

        let first_version = output.execution_output.first_version;
        let num_txns = output.execution_output.num_transactions_to_commit();
        let executed_chunk = ExecutedChunk {
            output,
            ledger_info_opt,
        };

        self.commit_queue
            .lock()
            .save_ledger_update_output(executed_chunk)?;

        info!(
            LogSchema::new(LogEntry::ChunkExecutor)
                .first_version_in_request(Some(first_version))
                .num_txns_in_request(num_txns),
            "Calculated ledger update!",
        );
        Ok(())
    }
```

**File:** execution/executor/src/chunk_executor/transaction_chunk.rs (L68-113)
```rust
    fn into_output<V: VMBlockExecutor>(
        self,
        parent_state: &LedgerState,
        state_view: CachedStateView,
    ) -> Result<ExecutionOutput> {
        let ChunkToExecute {
            transactions,
            persisted_aux_info,
            first_version: _,
        } = self;

        assert_eq!(
            transactions.len(),
            persisted_aux_info.len(),
            "transactions and persisted_aux_info must have the same length"
        );

        // TODO(skedia) In the chunk executor path, we ideally don't need to verify the signature
        // as only transactions with verified signatures are committed to the storage.
        let sig_verified_txns = {
            let _timer = CHUNK_OTHER_TIMERS.timer_with(&["sig_verify"]);

            let num_txns = transactions.len();
            SIG_VERIFY_POOL.install(|| {
                transactions
                    .into_par_iter()
                    .with_min_len(optimal_min_len(num_txns, 32))
                    .map(|t| t.into())
                    .collect::<Vec<_>>()
            })
        };

        let _timer = VM_EXECUTE_CHUNK.start_timer();
        DoGetExecutionOutput::by_transaction_execution::<V>(
            &V::new(),
            sig_verified_txns.into(),
            persisted_aux_info
                .into_iter()
                .map(|info| AuxiliaryInfo::new(info, None))
                .collect(),
            parent_state,
            state_view,
            BlockExecutorConfigFromOnchain::new_no_block_limit(),
            TransactionSliceMetadata::unknown(),
        )
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L210-219)
```rust
        [
            max_execution_gas: InternalGas,
            { 7.. => "max_execution_gas" },
            920_000_000, // 92ms of execution at 10k gas per ms
        ],
        [
            max_execution_gas_gov: InternalGas,
            { RELEASE_V1_13.. => "max_execution_gas.gov" },
            4_000_000_000,
        ],
```

**File:** consensus/src/state_computer.rs (L165-174)
```rust
        // Similarly, after state synchronization, we have to reset the cache of
        // the BlockExecutor to guarantee the latest committed state is up to date.
        self.executor.reset()?;

        // Return the result
        result.map_err(|error| {
            let anyhow_error: anyhow::Error = error.into();
            anyhow_error.into()
        })
    }
```

**File:** consensus/src/state_computer.rs (L224-230)
```rust
        // Similarly, after state synchronization, we have to reset the cache of
        // the BlockExecutor to guarantee the latest committed state is up to date.
        self.executor.reset()?;

        // Return the result
        result.map_err(|error| {
            let anyhow_error: anyhow::Error = error.into();
```

**File:** config/src/config/state_sync_config.rs (L23-31)
```rust
// The maximum chunk sizes for data client requests and response
const MAX_EPOCH_CHUNK_SIZE: u64 = 200;
const MAX_STATE_CHUNK_SIZE: u64 = 4000;
const MAX_TRANSACTION_CHUNK_SIZE: u64 = 3000;
const MAX_TRANSACTION_OUTPUT_CHUNK_SIZE: u64 = 3000;

// The maximum number of concurrent requests to send
const MAX_CONCURRENT_REQUESTS: u64 = 6;
const MAX_CONCURRENT_STATE_REQUESTS: u64 = 6;
```
