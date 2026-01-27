# Audit Report

## Title
Pipeline Join Indefinite Blocking in Executor Benchmark Tool

## Summary
The `pipeline.join()` method in the executor benchmark tool lacks timeout protection and can block indefinitely if any pipeline stage hangs, particularly the IndexerGrpcWaiter which contains an infinite polling loop without timeout safeguards.

## Finding Description
The `Pipeline::join()` method calls the standard library's `JoinHandle::join()` on each pipeline thread without any timeout mechanism. [1](#0-0) 

The pipeline consists of multiple stages running in separate threads, including a preparation thread, execution thread, ledger update thread, commit thread, and optionally an indexer gRPC waiter thread. [2](#0-1) 

The most critical blocking scenario occurs in the `IndexerGrpcWaiter::wait_for_version()` method, which contains an infinite loop that only exits when `stream_version >= target_version`. [3](#0-2)  If the indexer stream stops updating due to a bug, crash, or service failure, this loop will run indefinitely with no timeout protection.

When `run_benchmark()` calls `pipeline.join()`, it will block forever waiting for stuck threads to complete. [4](#0-3) 

Additional blocking scenarios include:
- Threads using `mpsc::sync_channel` with blocking `.send().unwrap()` calls that can deadlock if receivers are stuck
- Database operations (`execute_and_update_state`, `ledger_update`, `commit_ledger`) that could hang on I/O or lock contention

## Impact Explanation
**Assessment: This does NOT meet the Aptos bug bounty severity criteria.**

While this issue causes operational problems, it fails to qualify as a security vulnerability because:

1. **Scope limitation**: This affects the executor-benchmark tool, which is used for performance testing and development, not production validator nodes or consensus operations.

2. **No security impact**: The benchmark tool hanging does not:
   - Affect network consensus or validator operations
   - Cause loss of user funds
   - Enable transaction manipulation
   - Break any critical blockchain invariants
   - Impact production network availability

3. **Severity mismatch**: 
   - Not Critical: No funds loss, consensus break, or network partition
   - Not High: Not a validator node issue (benchmark tool only)
   - Not Medium: No production state inconsistencies or funds at risk

This is an operational reliability and code quality issue in development tooling, not a security vulnerability affecting the blockchain protocol or user assets.

## Likelihood Explanation
The likelihood of this occurring in benchmark/test scenarios is **moderate**, as it requires:
- Indexer gRPC stream failures or bugs
- Database lock contention during heavy load testing
- Thread panics causing channel deadlocks

However, the likelihood of security impact is **zero** because this code path does not execute in production validator nodes or affect blockchain operations.

## Recommendation
While not a security issue, the reliability concern should be addressed:

```rust
pub fn join(self) -> (Option<u64>, Vec<OverallMeasurement>, EventMeasurements) {
    let timeout = Duration::from_secs(300); // 5 minute timeout
    let mut counts = vec![];
    
    for handle in self.join_handles {
        match handle.join_timeout(timeout) {
            Ok(Ok(count)) => {
                if count > 0 {
                    counts.push(count);
                }
            },
            Ok(Err(e)) => panic!("Thread panicked: {:?}", e),
            Err(_) => {
                error!("Pipeline thread timed out after {:?}", timeout);
                panic!("Pipeline stage timed out - possible hang detected");
            }
        }
    }
    // ... rest of method
}
```

Additionally, add timeout to `IndexerGrpcWaiter::wait_for_version()`:
```rust
pub async fn wait_for_version(&self, target_version: Version, abort_on_finish: bool) {
    let timeout = Duration::from_secs(600); // 10 minute timeout
    let start_time = Instant::now();
    
    loop {
        if start_time.elapsed() > timeout {
            error!("Indexer waiter timed out after {:?}", timeout);
            return;
        }
        // ... rest of polling logic
    }
}
```

## Proof of Concept
This is not applicable as this is not a security vulnerability that can be exploited. The issue is an operational reliability concern in development tooling, not a blockchain security flaw.

---

## Notes

**After rigorous validation against the security criteria, I must conclude:**

**This issue does NOT qualify as a security vulnerability** according to the Aptos bug bounty criteria because:

1. It affects development/benchmarking tooling, not production consensus or validator code
2. There is no attacker exploitation path
3. No critical blockchain invariants are violated
4. No security impact to funds, consensus, or network availability
5. Does not meet Critical, High, or Medium severity criteria

While the lack of timeout protection is a legitimate **code quality and operational reliability concern** that should be fixed, it is fundamentally different from the security vulnerabilities the audit scope targets (consensus attacks, Move VM bugs, state manipulation, governance exploits, etc.).

The prompt explicitly states: "False positives harm credibility more than missed findings" and requires "overwhelming evidence" with an "EXTREMELY high" bar for validity. Under these strict criteria, this operational issue in a benchmark tool does not constitute a security vulnerability.

### Citations

**File:** execution/executor-benchmark/src/pipeline.rs (L162-348)
```rust
        let preparation_thread = std::thread::Builder::new()
            .name("block_preparation".to_string())
            .spawn(move || {
                start_pipeline_rx.map(|rx| rx.recv());
                let mut processed = 0;
                while let Ok(txns) = raw_block_receiver.recv() {
                    processed += txns.len() as u64;
                    if print_transactions {
                        println!("Transactions:");
                        for txn in &txns {
                            println!("{:?}", txn);
                        }
                    }
                    let exe_block_msg = preparation_stage.process(txns);
                    executable_block_sender.send(exe_block_msg).unwrap();
                }
                info!("Done preparation");
                start_execution_tx.map(|tx| tx.send(()));
                processed
            })
            .expect("Failed to spawn block partitioner thread.");
        join_handles.push(preparation_thread);

        let exe_thread = std::thread::Builder::new()
            .name("txn_executor".to_string())
            .spawn(move || {
                start_execution_rx.map(|rx| rx.recv());
                let overall_measuring = OverallMeasuring::start();
                let mut executed = 0;

                let mut stage_index = 0;
                let mut stage_overall_measuring = overall_measuring.clone();
                let mut stage_executed = 0;
                let mut stage_txn_occurences: HashMap<String, usize> = HashMap::new();

                while let Ok(msg) = executable_block_receiver.recv() {
                    let ExecuteBlockMessage {
                        current_block_start_time,
                        partition_time,
                        block,
                    } = msg;
                    let block_size = block.transactions.num_transactions() as u64;
                    for txn in block.transactions.txns() {
                        if let Some(txn) = txn.borrow_into_inner().try_as_signed_user_txn() {
                            if let TransactionPayload::EntryFunction(entry) = txn.payload() {
                                *stage_txn_occurences
                                    .entry(format!(
                                        "{}::{}",
                                        entry.module().name(),
                                        entry.function()
                                    ))
                                    .or_insert(0) += 1;
                            }
                        }
                    }

                    NUM_TXNS.inc_with_by(&["execution"], block_size);
                    info!("Received block of size {:?} to execute", block_size);
                    executed += block_size;
                    stage_executed += block_size;
                    exe.execute_block(current_block_start_time, partition_time, block, stage_index);
                    info!("Finished executing block");

                    // Empty blocks indicate the end of a stage.
                    // Print the accumulated stage stats at that point.
                    if block_size == 0 {
                        if stage_executed > 0 {
                            info!("Execution finished stage {}", stage_index);
                            let stage_measurement = stage_overall_measuring.elapsed(
                                format!("Staged execution: stage {}:", stage_index),
                                format!("{:?}", stage_txn_occurences),
                                stage_executed,
                            );

                            stage_measurement.print_end();
                            staged_result_clone.lock().push(stage_measurement);
                        }
                        stage_index += 1;
                        stage_overall_measuring = OverallMeasuring::start();
                        stage_executed = 0;
                        stage_txn_occurences = HashMap::new();
                    }
                }

                if stage_index > 0 && stage_executed > 0 {
                    info!("Execution finished stage {}", stage_index);
                    let stage_measurement = stage_overall_measuring.elapsed(
                        format!("Staged execution: stage {}:", stage_index),
                        format!("{:?}", stage_txn_occurences),
                        stage_executed,
                    );
                    stage_measurement.print_end();
                    staged_result_clone.lock().push(stage_measurement);
                }

                if num_blocks.is_some() {
                    overall_measuring
                        .elapsed(
                            "Overall execution".to_string(),
                            if stage_index == 0 {
                                format!("{:?}", stage_txn_occurences)
                            } else {
                                "across all stages".to_string()
                            },
                            executed,
                        )
                        .print_end();
                }
                start_ledger_update_tx.map(|tx| tx.send(()));
                executed
            })
            .expect("Failed to spawn transaction executor thread.");
        join_handles.push(exe_thread);

        let ledger_update_thread = std::thread::Builder::new()
            .name("ledger_update".to_string())
            .spawn(move || {
                start_ledger_update_rx.map(|rx| rx.recv());

                while let Ok(ledger_update_msg) = ledger_update_receiver.recv() {
                    NUM_TXNS
                        .inc_with_by(&["ledger_update"], ledger_update_msg.num_input_txns as u64);
                    ledger_update_stage.ledger_update(ledger_update_msg);
                }
                start_commit_tx.map(|tx| tx.send(()));

                0
            })
            .expect("Failed to spawn ledger update thread.");
        join_handles.push(ledger_update_thread);

        let target_version = Arc::new(Mutex::new(None));
        let target_version_clone = target_version.clone();

        if !config.skip_commit {
            let commit_thread = std::thread::Builder::new()
                .name("txn_committer".to_string())
                .spawn(move || {
                    start_commit_rx.map(|rx| rx.recv());
                    info!("Starting commit thread");
                    let mut committer =
                        TransactionCommitter::new(executor_3, start_version, commit_receiver);
                    let final_version = committer.run();

                    // Store the final version for indexer_grpc waiter
                    *target_version_clone.lock() = Some(final_version);
                    start_indexer_grpc_wait_tx.map(|tx| tx.send(()));

                    0
                })
                .expect("Failed to spawn transaction committer thread.");
            join_handles.push(commit_thread);
        }

        // Add indexer_grpc waiter stage
        if config.wait_for_indexer_grpc && !config.skip_commit {
            if let Some(indexer_wrapper) = indexer_wrapper {
                let waiter = IndexerGrpcWaiter::new(indexer_wrapper.0, indexer_wrapper.1);
                let target_version_for_waiter = target_version.clone();
                let waiter_thread = std::thread::Builder::new()
                    .name("indexer_grpc_waiter".to_string())
                    .spawn(move || {
                        start_indexer_grpc_wait_rx.map(|rx| rx.recv());
                        info!("Starting indexer_grpc waiter thread");

                        // Wait for target version to be set by commit thread
                        let target_ver = loop {
                            if let Some(ver) = *target_version_for_waiter.lock() {
                                break ver;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        };

                        // Create a tokio runtime for async wait
                        let runtime = tokio::runtime::Runtime::new().unwrap();
                        runtime.block_on(
                            waiter.wait_for_version(target_ver - 1, /*abort_on_finish=*/ true),
                        );
                        indexer_wrapper.2.store(true, Ordering::SeqCst);
                        info!("Indexer_grpc waiter finished");
                        // This is a HACK. Just sleep here to wait the DB lock to drop.
                        std::thread::sleep(std::time::Duration::from_secs(2));
                        0
                    })
                    .expect("Failed to spawn indexer_grpc waiter thread.");
                join_handles.push(waiter_thread);
            }
```

**File:** execution/executor-benchmark/src/pipeline.rs (L367-382)
```rust
    pub fn join(self) -> (Option<u64>, Vec<OverallMeasurement>, EventMeasurements) {
        let mut counts = vec![];
        for handle in self.join_handles {
            let count = handle.join().unwrap();
            if count > 0 {
                counts.push(count);
            }
        }
        (
            counts.into_iter().min(),
            Arc::try_unwrap(self.staged_result).unwrap().into_inner(),
            EventMeasurements {
                staged_events: Arc::try_unwrap(self.staged_events).unwrap().into_inner(),
            },
        )
    }
```

**File:** execution/executor-benchmark/src/indexer_grpc_waiter.rs (L37-75)
```rust
    pub async fn wait_for_version(&self, target_version: Version, abort_on_finish: bool) {
        info!(
            "Waiting for indexer_grpc to reach target version: {}",
            target_version
        );

        let start_time = Instant::now();
        let mut last_log_time = Instant::now();

        loop {
            let table_info_version = self.table_info_service.next_version().saturating_sub(1);
            let stream_version = self.stream_version.load(Ordering::SeqCst);
            if stream_version >= target_version {
                info!(
                    "Indexer stream reached target version. Current: {}, Target: {}, elapsed: {:.2}s",
                    stream_version,
                    target_version,
                    start_time.elapsed().as_secs_f64()
                );
                if abort_on_finish {
                    self.table_info_service.abort();
                }
                break;
            }

            // Log status every 1 second
            if last_log_time.elapsed().as_secs() >= STATUS_LOG_INTERVAL_SECS {
                let versions_behind = target_version.saturating_sub(stream_version);
                let elapsed_secs = start_time.elapsed().as_secs_f64();
                info!(
                    "Indexer_grpc progress: target={}, table_info_current={}, stream_version={}, behind={}, elapsed={:.2}s",
                    target_version, table_info_version, stream_version, versions_behind, elapsed_secs
                );
                last_log_time = Instant::now();
            }

            tokio::time::sleep(Duration::from_millis(INDEXER_GRPC_POLL_INTERVAL_MS)).await;
        }
    }
```

**File:** execution/executor-benchmark/src/lib.rs (L459-461)
```rust
    pipeline.start_pipeline_processing();
    info!("Waiting for pipeline to finish");
    let (num_pipeline_txns, staged_results, staged_events) = pipeline.join();
```
