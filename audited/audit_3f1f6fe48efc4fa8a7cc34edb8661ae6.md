Audit Report

## Title
Untrusted Remote Shard Can Force Block Rejection via Fabricated VMStatus Error in send_execution_result

## Summary
A malicious remote execution shard can arbitrarily return an error (Err(VMStatus)) in the `send_execution_result` interface, causing the coordinator to reject an otherwise successful block. There is no cross-validation or verification of errors at the coordinator, enabling remote denial-of-service by a single compromised executor.

## Finding Description
In the sharded block execution model, the coordinator dispatches sub-blocks to shards for parallel execution. Each shard returns its result via the `CoordinatorClient::send_execution_result` method as a `Result<Vec<Vec<TransactionOutput>>, VMStatus>`. The coordinator (local or remote) simply aggregates these results and will immediately return an error (causing block rejection) if any one shard returns `Err(VMStatus)`. In the remote execution flow, shards are run on different machines and are vulnerable to compromise. A malicious shard can thus return an arbitrary error (for example, `Err(VMStatus::Error { ... })`) even if it executed the sub-block correctly. The coordinator has no way to validate the authenticity of the error and will always reject the entire block upon receiving a single error result from any shard.

If the attacker returns an error variant other than `VMStatus::Executed` (e.g., `Error`, `MoveAbort`, or `ExecutionFailure`), the attack will still cause immediate block rejection. Since `VMStatus::Executed` is the "success" variant (unit type), most fabrications would use the error-carrying variants.

This directly breaks liveness invariants and allows a remote node operator to halt block production or cause persistent denial-of-service for new valid blocks.

## Impact Explanation
This bug enables total denial-of-service for the block execution pipeline in sharded execution mode involving remote shards. An attacker controlling a single shard machine can cause all block executions (and thus block commits) to fail repeatedly, essentially halting chain progress for as long as their access continues. This constitutes a "significant protocol violation" and a "validator node slowdown" per Aptos bug bounty categories, and could escalate to a "total loss of liveness/network availability" if all validators are configured to rely on these remote shards. No funds are lost, but block production is prevented.

## Likelihood Explanation
The attack can be executed by any remote executor node (i.e., anyone running a shard service), which may not be the same as validator operators in a remote sharding deployment. The exploitation is straightforward and does not require privileged access; a malicious update or compromised machine is enough. No cryptographic keys are required. As remote sharded execution is intended to support production scaling, the risk is significant whenever this architecture is deployed.

## Recommendation
Mitigate by introducing one or more of the following:
- Require majority consistency among shard results, or implement a re-execution protocol for error results (e.g., have another shard or the coordinator re-execute the sub-block upon error)
- Authenticate error claims by requiring a proof or logging actual execution trace for coordinator-side validation
- Implement a fallback failover or retry mechanism in the coordinator for rejecting (or reassigning) error-producing shards
- Do not trust remote shards for consensus-critical execution unless they are subject to the same trust assumptions as validators

Example fix sketch for fallback:
```rust
// Pseudocode at coordinator
for each shard_result in results {
    if shard_result.is_err() {
        // Optionally re-dispatch to another (trusted) shard for verification before aborting
        // Or perform coordinator-side execution to corroborate the error
    }
}
```

## Proof of Concept
1. Set up a remote executor coordinator with at least one remote shard (using `set_remote_addresses()`).
2. Modify the remote executor shard to return `Err(VMStatus::Error { ... })` in `send_execution_result` even when execution would succeed.
3. Submit any block of transactions.
4. Observe the coordinator always receives and propagates the fabricated error and never successfully executes any block, regardless of input.

Citations: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

Notes:
- This is NOT a validator collusion vulnerability, but rather a remote execution service trust issue.
- If remote shards are used in validator production deployments, this attack vector is valid and must be mitigated.

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/coordinator_client.rs (L8-13)
```rust
// Interface to communicate from the executor shards to the block executor coordinator.
pub trait CoordinatorClient<S: StateView + Sync + Send + 'static>: Send + Sync {
    fn receive_execute_command(&self) -> ExecutorShardCommand<S>;

    fn send_execution_result(&self, result: Result<Vec<Vec<TransactionOutput>>, VMStatus>);
}
```

**File:** execution/executor-service/src/remote_cordinator_client.rs (L79-120)
```rust
impl CoordinatorClient<RemoteStateViewClient> for RemoteCoordinatorClient {
    fn receive_execute_command(&self) -> ExecutorShardCommand<RemoteStateViewClient> {
        match self.command_rx.recv() {
            Ok(message) => {
                let _rx_timer = REMOTE_EXECUTOR_TIMER
                    .with_label_values(&[&self.shard_id.to_string(), "cmd_rx"])
                    .start_timer();
                let bcs_deser_timer = REMOTE_EXECUTOR_TIMER
                    .with_label_values(&[&self.shard_id.to_string(), "cmd_rx_bcs_deser"])
                    .start_timer();
                let request: RemoteExecutionRequest = bcs::from_bytes(&message.data).unwrap();
                drop(bcs_deser_timer);

                match request {
                    RemoteExecutionRequest::ExecuteBlock(command) => {
                        let init_prefetch_timer = REMOTE_EXECUTOR_TIMER
                            .with_label_values(&[&self.shard_id.to_string(), "init_prefetch"])
                            .start_timer();
                        let state_keys = Self::extract_state_keys(&command);
                        self.state_view_client.init_for_block(state_keys);
                        drop(init_prefetch_timer);

                        let (sub_blocks, concurrency, onchain_config) = command.into();
                        ExecutorShardCommand::ExecuteSubBlocks(
                            self.state_view_client.clone(),
                            sub_blocks,
                            concurrency,
                            onchain_config,
                        )
                    },
                }
            },
            Err(_) => ExecutorShardCommand::Stop,
        }
    }

    fn send_execution_result(&self, result: Result<Vec<Vec<TransactionOutput>>, VMStatus>) {
        let remote_execution_result = RemoteExecutionResult::new(result);
        let output_message = bcs::to_bytes(&remote_execution_result).unwrap();
        self.result_tx.send(Message::new(output_message)).unwrap();
    }
}
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L164-175)
```rust
    fn get_output_from_shards(&self) -> Result<Vec<Vec<Vec<TransactionOutput>>>, VMStatus> {
        let _timer = WAIT_FOR_SHARDED_OUTPUT_SECONDS.start_timer();
        trace!("LocalExecutorClient Waiting for results");
        let mut results = vec![];
        for (i, rx) in self.result_rxs.iter().enumerate() {
            results.push(
                rx.recv()
                    .unwrap_or_else(|_| panic!("Did not receive output from shard {}", i))?,
            );
        }
        Ok(results)
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L259-267)
```rust
impl<S: StateView + Sync + Send + 'static> CoordinatorClient<S> for LocalCoordinatorClient<S> {
    fn receive_execute_command(&self) -> ExecutorShardCommand<S> {
        self.command_rx.recv().unwrap()
    }

    fn send_execution_result(&self, result: Result<Vec<Vec<TransactionOutput>>, VMStatus>) {
        self.result_tx.send(result).unwrap()
    }
}
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L215-273)
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
}
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
