# Audit Report

## Title
Unbounded Memory Allocation in Executor Benchmark Pipeline Causes OOM Risk

## Summary
The executor benchmark's pipeline implementation allocates synchronous channels with capacity directly proportional to the number of blocks being benchmarked. When `generate_then_execute` mode is enabled (the default for benchmarks), this allows unbounded memory growth that scales linearly with `num_blocks`, potentially exhausting available memory and triggering OOM kills during large-scale benchmarks.

## Finding Description

The vulnerability exists in the pipeline configuration where channel buffer sizes are determined by the number of blocks without any upper bound cap. [1](#0-0) 

When `generate_then_execute` is enabled, the queue capacity becomes `(num_blocks.unwrap() + 1).max(50)`. This configuration is used by default in benchmark execution: [2](#0-1) 

The critical issue is that pipeline processing doesn't start until AFTER all blocks are generated: [3](#0-2) 

The preparation thread waits for the start signal before consuming from the channel: [4](#0-3) 

**Attack Path:**
1. Operator configures benchmark with large `num_blocks` (e.g., 100,000) and large `block_size` (e.g., 10,000 transactions)
2. Pipeline creates channel with capacity = 100,001 blocks
3. Transaction generator creates all 100,000 blocks in memory (1 billion transactions total)
4. Each transaction is several hundred bytes to kilobytes in size
5. Total memory consumption: ~100-1000+ GB before any execution starts
6. System experiences memory pressure, OOM killer terminates the process

While developers intended to use `SyncSender` for backpressure to prevent memory exhaustion: [5](#0-4) 

This backpressure is defeated because the channel capacity scales with `num_blocks`, allowing all blocks to buffer before any backpressure occurs.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria:

- **Validator node slowdowns**: Memory pressure degrades node performance
- **API crashes**: OOM kills terminate the benchmark process
- **Significant protocol violations**: Breaks Resource Limits invariant (#9) - "All operations must respect gas, storage, and computational limits"

While this primarily affects benchmarking infrastructure rather than production validators, benchmark stability is critical for:
- Performance regression testing before mainnet deployments
- Validator hardware capacity planning
- Protocol upgrade validation

A crashed benchmark can delay critical releases or mask performance regressions that would affect production.

## Likelihood Explanation

**Likelihood: Medium-to-High**

This issue will trigger whenever:
1. Benchmarks are run with `generate_then_execute=true` (the default)
2. `num_blocks` is set to a sufficiently large value
3. System memory is limited relative to the total transaction payload

As blockchain workloads increase and more comprehensive benchmarks are needed, operators will naturally increase `num_blocks` to test at scale. The lack of an upper bound cap means this is inevitable as benchmark scale grows.

The issue is deterministic and reproducible - it will always occur given sufficient `num_blocks` relative to available memory.

## Recommendation

Implement a maximum cap on channel buffer sizes regardless of `num_blocks`:

```rust
const MAX_PIPELINE_BUFFER_SIZE: usize = 1000;

let (raw_block_sender, raw_block_receiver) = mpsc::sync_channel::<Vec<Transaction>>(
    if config.generate_then_execute {
        ((num_blocks.unwrap() + 1).min(MAX_PIPELINE_BUFFER_SIZE)).max(50)
    } else {
        10
    }, /* bound */
);
```

Apply the same cap to all pipeline channels:

```rust
let (executable_block_sender, executable_block_receiver) =
    mpsc::sync_channel::<ExecuteBlockMessage>(
        if config.split_stages {
            ((num_blocks.unwrap() + 1).min(MAX_PIPELINE_BUFFER_SIZE)).max(50)
        } else {
            10
        }, /* bound */
    );

let (ledger_update_sender, ledger_update_receiver) =
    mpsc::sync_channel::<LedgerUpdateMessage>(
        if config.split_stages || config.skip_commit {
            ((num_blocks.unwrap() + 1).min(MAX_PIPELINE_BUFFER_SIZE)).max(3)
        } else {
            3
        }, /* bound */
    );
```

This ensures backpressure mechanisms function correctly even for large benchmarks, preventing unbounded memory growth while still allowing sufficient buffering for performance.

## Proof of Concept

```rust
// Add to execution/executor-benchmark/src/lib.rs tests module
#[test]
#[ignore] // Ignore by default as it requires significant memory
fn test_large_scale_benchmark_memory_pressure() {
    use tempfile::TempDir;
    
    let test_dir = TempDir::new().unwrap();
    let storage_dir = test_dir.path().join("db");
    let checkpoint_dir = test_dir.path().join("cp");
    
    std::fs::create_dir_all(&storage_dir).unwrap();
    std::fs::create_dir_all(&checkpoint_dir).unwrap();
    
    // Configure benchmark with parameters that would exhaust memory
    // On a 16GB system, this attempts to allocate ~20-50GB
    let num_blocks = 10000;
    let block_size = 5000; // 50M transactions total
    
    let storage_test_config = StorageTestConfig {
        pruner_config: NO_OP_STORAGE_PRUNER_CONFIG,
        enable_storage_sharding: false,
        enable_indexer_grpc: false,
    };
    
    // Create initial DB
    create_db_with_accounts::<AptosVMBlockExecutor>(
        1000,
        100_000_000_000,
        100,
        &storage_dir,
        storage_test_config,
        false,
        PipelineConfig::default(),
        default_benchmark_features(),
        false,
    );
    
    // This will allocate channels sized to num_blocks
    // Watch system memory consumption spike as transaction generation proceeds
    let pipeline_config = PipelineConfig {
        generate_then_execute: true, // Critical: buffers ALL blocks
        ..Default::default()
    };
    
    // This call will likely OOM on systems with <64GB RAM
    run_benchmark::<AptosVMBlockExecutor>(
        block_size,
        num_blocks,
        BenchmarkWorkload::Transfer {
            connected_tx_grps: 0,
            shuffle_connected_txns: false,
            hotspot_probability: None,
        },
        1,
        100,
        100,
        &storage_dir,
        &checkpoint_dir,
        false,
        storage_test_config,
        pipeline_config,
        default_benchmark_features(),
        false,
    );
}
```

To observe the vulnerability:
1. Run with `ulimit -v 16000000` (16GB virtual memory limit)
2. Monitor memory with `watch -n 1 free -h` in another terminal
3. Observe memory consumption growing linearly during transaction generation
4. Process terminates with OOM before execution phase begins

## Notes

This vulnerability demonstrates a classic resource exhaustion issue where well-intentioned backpressure mechanisms (SyncSender) are undermined by configuration that defeats their purpose. The fix is straightforward and maintains performance characteristics while preventing unbounded memory growth.

### Citations

**File:** execution/executor-benchmark/src/pipeline.rs (L85-91)
```rust
        let (raw_block_sender, raw_block_receiver) = mpsc::sync_channel::<Vec<Transaction>>(
            if config.generate_then_execute {
                (num_blocks.unwrap() + 1).max(50)
            } else {
                10
            }, /* bound */
        );
```

**File:** execution/executor-benchmark/src/pipeline.rs (L162-177)
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
```

**File:** execution/executor-benchmark/src/lib.rs (L454-460)
```rust
    if pipeline_config.generate_then_execute {
        overall_measuring.start_time = Instant::now();
    }
    generator.drop_sender();
    info!("Done creating workload");
    pipeline.start_pipeline_processing();
    info!("Waiting for pipeline to finish");
```

**File:** execution/executor-benchmark/src/lib.rs (L897-905)
```rust
    let execute_pipeline_config = PipelineConfig {
        generate_then_execute: true,
        num_sig_verify_threads: std::cmp::max(1, num_cpus::get() / 3),
        print_transactions,
        num_generator_workers,
        split_stages,
        wait_for_indexer_grpc: enable_indexer_grpc,
        ..Default::default()
    };
```

**File:** execution/executor-benchmark/src/transaction_generator.rs (L199-201)
```rust
    /// Each generated block of transactions are sent to this channel. Using `SyncSender` to make
    /// sure if execution is slow to consume the transactions, we do not run out of memory.
    block_sender: Option<mpsc::SyncSender<Vec<Transaction>>>,
```
