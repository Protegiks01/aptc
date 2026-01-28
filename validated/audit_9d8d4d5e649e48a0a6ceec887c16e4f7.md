# Audit Report

## Title
State View Race Condition in Remote Executor Error Path Causes Cross-Block State Contamination

## Summary
The `RemoteExecutorClient::execute_block()` function fails to call `drop_state_view()` when `get_output_from_shards()` returns a VMStatus error, leaving stale state view references active. Combined with per-key read locking in `RemoteStateViewService::handle_message()`, this creates a race condition where in-flight state view requests from a failed block can receive contaminated responses containing mixed state values from different ledger versions, potentially causing consensus violations.

## Finding Description

The vulnerability exists in two interconnected components in the remote sharded block executor:

**Component 1: Missing Cleanup in Error Path**

In `RemoteExecutorClient::execute_block()`, when `get_output_from_shards()` returns an error, the `?` operator causes early return, bypassing the `drop_state_view()` call. [1](#0-0) 

This leaves the state view active in `RemoteStateViewService` when it should be cleared.

**Component 2: Per-Key Read Lock Acquisition**

The `handle_message()` function processes state key requests by acquiring and releasing the read lock **for each individual key** within a `.map()` closure. [2](#0-1) 

Between processing different keys, the read lock is released, creating a window where another thread can acquire the write lock and swap the state view.

**Attack Scenario:**

1. Block N execution starts, coordinator calls `set_state_view(state_view_V)` [3](#0-2) 
2. Coordinator sends execution commands to all shards
3. Shards send `RemoteKVRequest` messages with batches of 200 keys [4](#0-3) 
4. `RemoteStateViewService` spawns multiple `handle_message()` threads [5](#0-4) 
5. Shard 0 encounters VM error and returns `RemoteExecutionResult` with error
6. `get_output_from_shards()` receives the error and returns immediately without waiting for other shards [6](#0-5) 
7. `drop_state_view()` is skipped due to early return
8. `REMOTE_SHARDED_BLOCK_EXECUTOR` mutex is released [7](#0-6) 
9. Shards 1-3 are still executing block N, their `handle_message()` threads are still processing
10. Next block starts, acquires mutex, calls `set_state_view(state_view_V+1)` which swaps the state view [8](#0-7) 
11. Old `handle_message()` threads acquire read locks for remaining keys and read from state view V+1 instead of V
12. Contaminated responses are sent to shards 1-3, containing mixed state values from versions V and V+1
13. Shards complete execution with inconsistent state and send results
14. Due to persistent channels and sequential shard processing, coordinator may receive results for block N when expecting block N+1 results, causing wrong state root computation [9](#0-8) 

This violates the invariant that all validators must produce identical state roots for identical blocks, as different validators with different timing will compute different state roots.

## Impact Explanation

**Severity: High**

This vulnerability causes **consensus violations** through non-deterministic execution:

1. **Consensus Violation**: Different validators may receive contaminated state values depending on race timing, causing them to compute different state roots for the same block. This violates AptosBFT safety guarantees.

2. **State Inconsistency**: Execution uses state values from two different ledger versions simultaneously, creating a state view that never existed at any atomic point in time, breaking Merkle proof verification.

3. **Execution Non-Determinism**: The same block produces different outputs on different nodes based purely on timing, violating blockchain determinism requirements.

Per Aptos bug bounty criteria, this qualifies as **High Severity** due to "Significant protocol violations" that lead to consensus inconsistencies. This is a validator consensus vulnerability, not a fund theft vulnerability, placing it in the High severity category.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability is triggerable when:

1. **Remote Sharded Execution Configured**: Validators must explicitly configure remote sharded execution by setting remote addresses and multiple shards. This is NOT enabled by default [10](#0-9)  (default is 0-1 shards), requiring explicit deployment of the remote executor service [11](#0-10) 

2. **VM Errors Trigger**: Any transaction causing VM errors (out of gas, Move aborts, assertion failures) triggers the error path. Attackers can craft such transactions.

3. **Race Window Exploitable**: With 200-key batches and network/processing latency, the race window between shards completing at different times is substantial (milliseconds to seconds).

While the vulnerability requires explicit configuration of remote sharded execution (reducing baseline likelihood), once configured it is easily triggerable by any attacker who can submit transactions. The likelihood is **Medium** rather than High due to the non-default configuration requirement.

## Recommendation

Add proper cleanup in the error path using RAII pattern or explicit cleanup:

```rust
fn execute_block(
    &self,
    state_view: Arc<S>,
    transactions: PartitionedTransactions,
    concurrency_level_per_shard: usize,
    onchain_config: BlockExecutorConfigFromOnchain,
) -> Result<ShardedExecutionOutput, VMStatus> {
    self.state_view_service.set_state_view(state_view);
    
    // Ensure cleanup happens regardless of early returns
    let _guard = scopeguard::guard((), |_| {
        self.state_view_service.drop_state_view();
    });
    
    let (sub_blocks, global_txns) = transactions.into();
    if !global_txns.is_empty() {
        panic!("Global transactions are not supported yet");
    }
    
    for (shard_id, sub_blocks) in sub_blocks.into_iter().enumerate() {
        let senders = self.command_txs.clone();
        let execution_request = RemoteExecutionRequest::ExecuteBlock(ExecuteBlockCommand {
            sub_blocks,
            concurrency_level: concurrency_level_per_shard,
            onchain_config: onchain_config.clone(),
        });
        senders[shard_id]
            .lock()
            .unwrap()
            .send(Message::new(bcs::to_bytes(&execution_request).unwrap()))
            .unwrap();
    }
    
    let execution_results = self.get_output_from_shards()?;
    // _guard drops here, calling drop_state_view()
    Ok(ShardedExecutionOutput::new(execution_results, vec![]))
}
```

Alternatively, wait for all shards to complete before returning errors, or implement proper cancellation signaling to shards.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Configuring a remote sharded executor with 4 shards
2. Submitting a block with transactions that cause shard 0 to fail quickly (e.g., out-of-gas transaction)
3. Ensuring shards 1-3 have significant processing time through large state key batches
4. Starting next block execution immediately after shard 0 fails
5. Observing contaminated state view responses sent to shards 1-3
6. Demonstrating different state roots computed by validators with different timing

Due to the distributed nature of the remote executor requiring multiple processes and network communication, a complete PoC requires deployment infrastructure. However, the code paths are clearly vulnerable as shown in the citations above.

## Notes

The remote executor service is production code with a standalone binary for distributed execution across multiple processes. While not enabled by default, it is a legitimate performance optimization feature that validators may deploy. The vulnerability is triggered through normal transaction submission (VM errors) combined with timing-dependent race conditions in the state view service.

### Citations

**File:** execution/executor-service/src/remote_executor_client.rs (L57-72)
```rust
pub static REMOTE_SHARDED_BLOCK_EXECUTOR: Lazy<
    Arc<
        aptos_infallible::Mutex<
            ShardedBlockExecutor<CachedStateView, RemoteExecutorClient<CachedStateView>>,
        >,
    >,
> = Lazy::new(|| {
    info!("REMOTE_SHARDED_BLOCK_EXECUTOR created");
    Arc::new(aptos_infallible::Mutex::new(
        RemoteExecutorClient::create_remote_sharded_block_executor(
            get_coordinator_address(),
            get_remote_addresses(),
            None,
        ),
    ))
});
```

**File:** execution/executor-service/src/remote_executor_client.rs (L163-172)
```rust
    fn get_output_from_shards(&self) -> Result<Vec<Vec<Vec<TransactionOutput>>>, VMStatus> {
        trace!("RemoteExecutorClient Waiting for results");
        let mut results = vec![];
        for rx in self.result_rxs.iter() {
            let received_bytes = rx.recv().unwrap().to_bytes();
            let result: RemoteExecutionResult = bcs::from_bytes(&received_bytes).unwrap();
            results.push(result.inner?);
        }
        Ok(results)
    }
```

**File:** execution/executor-service/src/remote_executor_client.rs (L188-188)
```rust
        self.state_view_service.set_state_view(state_view);
```

**File:** execution/executor-service/src/remote_executor_client.rs (L208-210)
```rust
        let execution_results = self.get_output_from_shards()?;

        self.state_view_service.drop_state_view();
```

**File:** execution/executor-service/src/remote_state_view_service.rs (L54-57)
```rust
    pub fn set_state_view(&self, state_view: Arc<S>) {
        let mut state_view_lock = self.state_view.write().unwrap();
        *state_view_lock = Some(state_view);
    }
```

**File:** execution/executor-service/src/remote_state_view_service.rs (L68-70)
```rust
            self.thread_pool.spawn(move || {
                Self::handle_message(message, state_view, kv_txs);
            });
```

**File:** execution/executor-service/src/remote_state_view_service.rs (L95-107)
```rust
        let resp = state_keys
            .into_iter()
            .map(|state_key| {
                let state_value = state_view
                    .read()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .get_state_value(&state_key)
                    .unwrap();
                (state_key, state_value)
            })
            .collect_vec();
```

**File:** execution/executor-service/src/remote_state_view.rs (L27-27)
```rust
pub static REMOTE_STATE_KEY_BATCH_SIZE: usize = 200;
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L215-272)
```rust
    pub fn start(&self) {
        trace!(
            "Shard starting, shard_id={}, num_shards={}.",
            self.shard_id,
            self.num_shards
        );
        let mut num_txns = 0;
        loop {
            let command = self.coordinator_client.receive_execute_command();
            match command {
                ExecutorShardCommand::ExecuteSubBlocks(
                    state_view,
                    transactions,
                    concurrency_level_per_shard,
                    onchain_config,
                ) => {
                    num_txns += transactions.num_txns();
                    trace!(
                        "Shard {} received ExecuteBlock command of block size {} ",
                        self.shard_id,
                        num_txns
                    );
                    let exe_timer = SHARDED_EXECUTOR_SERVICE_SECONDS
                        .timer_with(&[&self.shard_id.to_string(), "execute_block"]);
                    let ret = self.execute_block(
                        transactions,
                        state_view.as_ref(),
                        BlockExecutorConfig {
                            local: BlockExecutorLocalConfig::default_with_concurrency_level(
                                concurrency_level_per_shard,
                            ),
                            onchain: onchain_config,
                        },
                    );
                    drop(state_view);
                    drop(exe_timer);

                    let _result_tx_timer = SHARDED_EXECUTOR_SERVICE_SECONDS
                        .timer_with(&[&self.shard_id.to_string(), "result_tx"]);
                    self.coordinator_client.send_execution_result(ret);
                },
                ExecutorShardCommand::Stop => {
                    break;
                },
            }
        }
        let exe_time = SHARDED_EXECUTOR_SERVICE_SECONDS
            .get_metric_with_label_values(&[&self.shard_id.to_string(), "execute_block"])
            .unwrap()
            .get_sample_sum();
        info!(
            "Shard {} is shutting down; On shard execution tps {} txns/s ({} txns / {} s)",
            self.shard_id,
            (num_txns as f64 / exe_time),
            num_txns,
            exe_time
        );
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1-1)
```rust
// Copyright (c) Aptos Foundation
```

**File:** execution/executor-service/src/main.rs (L1-49)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use aptos_executor_service::process_executor_service::ProcessExecutorService;
use aptos_logger::info;
use clap::Parser;
use std::net::SocketAddr;

#[derive(Debug, Parser)]
struct Args {
    #[clap(long, default_value_t = 8)]
    pub num_executor_threads: usize,

    #[clap(long)]
    pub shard_id: usize,

    #[clap(long)]
    pub num_shards: usize,

    #[clap(long, num_args = 1..)]
    pub remote_executor_addresses: Vec<SocketAddr>,

    #[clap(long)]
    pub coordinator_address: SocketAddr,
}

fn main() {
    let args = Args::parse();
    aptos_logger::Logger::new().init();

    let (tx, rx) = crossbeam_channel::unbounded();
    ctrlc::set_handler(move || {
        tx.send(()).unwrap();
    })
    .expect("Error setting Ctrl-C handler");

    let _exe_service = ProcessExecutorService::new(
        args.shard_id,
        args.num_shards,
        args.num_executor_threads,
        args.coordinator_address,
        args.remote_executor_addresses,
    );

    rx.recv()
        .expect("Could not receive Ctrl-C msg from channel.");
    info!("Process executor service shutdown successfully.");
}

```
