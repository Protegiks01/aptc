# Audit Report

## Title
Sharded Block Executor: Missing Output Count Validation Enables Denial of Service via Malicious Shard

## Summary
The sharded block executor's aggregation logic in `execute_block()` does not validate that the number of transaction outputs returned by remote executor shards matches the number of input transactions. A malicious or compromised remote shard can return duplicate or extra transaction outputs, which will cause the validator node to panic and crash when the assertion in `TransactionsWithOutput::new()` detects the count mismatch.

## Finding Description
The vulnerability exists in the sharded block execution pipeline where a coordinator distributes transactions to multiple remote executor shards for parallel execution and then aggregates their results.

**Attack Flow:**

1. The coordinator partitions a block into transactions and sends them to remote executor shards via the `RemoteExecutorClient` [1](#0-0) 

2. A malicious remote shard receives the execution request, but instead of returning the correct number of outputs, it crafts a `RemoteExecutionResult` containing duplicate or extra `TransactionOutput` entries and sends it back over the network.

3. The coordinator receives and deserializes the malicious result without any validation [2](#0-1) 

4. The aggregation logic in `execute_block()` blindly appends all outputs from all shards without validating counts [3](#0-2) 

5. The aggregated outputs are passed to the parser, which attempts to create a `TransactionsWithOutput` object [4](#0-3) 

6. `TransactionsWithOutput::new()` contains assertions that enforce count equality [5](#0-4) 

7. When the assertion fails due to mismatched counts, the validator node panics and crashes, causing a denial of service.

**Missing Defense Layer:**

The critical flaw is that the coordinator trusts remote shard outputs without validation. The aggregation logic performs no checks to ensure the number of outputs matches the number of transactions sent to each shard.

## Impact Explanation
**Severity: High** (up to $50,000 per Aptos bug bounty criteria)

This vulnerability enables a **Denial of Service attack** that can crash validator nodes:

- **Validator node crashes**: The panic causes the validator process to terminate
- **Network availability degradation**: If multiple validators are running sharded execution with remote shards, an attacker who compromises or MITMs the shard communication can crash multiple validators simultaneously
- **Significant protocol violations**: The lack of validation violates defensive programming principles and the expectation that coordinator nodes validate shard outputs

While this doesn't directly cause loss of funds or consensus safety violations, it does impact network liveness and validator availability, which qualifies as "Validator node slowdowns" and "API crashes" under the High severity category.

## Likelihood Explanation
**Likelihood: Medium-High**

The attack requires one of the following conditions:
1. **Compromised remote executor shard**: An attacker gains control of a remote executor process
2. **Network MITM attack**: An attacker intercepts and modifies shard communication
3. **Buggy shard implementation**: A software bug in the shard causes incorrect output counts

The remote executor communication uses `NetworkController` which transmits raw bytes without cryptographic authentication of message contents [6](#0-5) 

While remote shards are typically operated by the validator itself, the lack of defense-in-depth validation makes the system vulnerable to insider threats, implementation bugs, or network attacks. The sharded execution feature appears to be actively used based on the codebase infrastructure.

## Recommendation
Add validation in the `execute_block()` function to verify that the total number of outputs matches the expected number of transactions:

```rust
pub fn execute_block(
    &self,
    state_view: Arc<S>,
    transactions: PartitionedTransactions,
    concurrency_level_per_shard: usize,
    onchain_config: BlockExecutorConfigFromOnchain,
) -> Result<Vec<TransactionOutput>, VMStatus> {
    // ... existing code ...
    
    let expected_txn_count = transactions.num_txns();
    let (sharded_output, global_output) = self
        .executor_client
        .execute_block(
            state_view,
            transactions,
            concurrency_level_per_shard,
            onchain_config,
        )?
        .into_inner();
    
    // ... aggregation logic ...
    
    // VALIDATE OUTPUT COUNT BEFORE RETURNING
    let actual_output_count = aggregated_results.len();
    if actual_output_count != expected_txn_count {
        return Err(VMStatus::Error {
            status_code: StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
            sub_status: Some(1001), // Custom sub-status for output count mismatch
            message: Some(format!(
                "Output count mismatch: expected {}, got {}",
                expected_txn_count, actual_output_count
            )),
        });
    }
    
    Ok(aggregated_results)
}
```

Additionally, consider:
1. Adding cryptographic authentication to remote shard messages
2. Implementing per-shard output count validation
3. Converting the panic assertion in `TransactionsWithOutput::new()` to a proper error return to enable graceful error handling

## Proof of Concept
This vulnerability can be demonstrated by:

1. Setting up a test with remote sharded execution enabled
2. Modifying a remote executor shard to return duplicate outputs
3. Observing the validator node panic

**Test scenario:**
```rust
#[test]
fn test_malicious_shard_duplicate_outputs() {
    // Setup: Create a remote executor with malicious shard
    let malicious_shard = create_malicious_shard_that_duplicates_outputs();
    
    // Create partitioned transactions (10 transactions)
    let transactions = create_partitioned_transactions(10);
    
    // Execute block - malicious shard returns 15 outputs instead of 10
    let result = sharded_executor.execute_block(
        state_view,
        transactions,
        concurrency_level,
        onchain_config
    );
    
    // Expected: Should return error, but instead panics at assertion
    // Actual: Node crashes with panic: "assertion failed: transactions.len() == transaction_outputs.len()"
}
```

The test would demonstrate that when a shard returns extra outputs (15 instead of 10), the node panics instead of returning a proper error, causing a DoS condition.

## Notes
This vulnerability highlights the importance of defense-in-depth validation in distributed systems. Even when remote shards are intended to be trusted components operated by the validator itself, implementation bugs, security compromises, or network attacks require that coordinators validate all inputs from distributed components. The current implementation assumes perfect shard behavior without validation, creating an exploitable attack surface for denial of service.

### Citations

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

**File:** execution/executor-service/src/remote_executor_client.rs (L180-212)
```rust
    fn execute_block(
        &self,
        state_view: Arc<S>,
        transactions: PartitionedTransactions,
        concurrency_level_per_shard: usize,
        onchain_config: BlockExecutorConfigFromOnchain,
    ) -> Result<ShardedExecutionOutput, VMStatus> {
        trace!("RemoteExecutorClient Sending block to shards");
        self.state_view_service.set_state_view(state_view);
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

        self.state_view_service.drop_state_view();
        Ok(ShardedExecutionOutput::new(execution_results, vec![]))
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/mod.rs (L102-115)
```rust
        for (shard_id, results_from_shard) in sharded_output.into_iter().enumerate() {
            for (round, result) in results_from_shard.into_iter().enumerate() {
                ordered_results[round * num_executor_shards + shard_id] = result;
            }
        }

        for result in ordered_results.into_iter() {
            aggregated_results.extend(result);
        }

        // Lastly append the global output
        aggregated_results.extend(global_output);

        Ok(aggregated_results)
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L210-222)
```rust
        Parser::parse(
            state_view.next_version(),
            PartitionedTransactions::flatten(transactions)
                .into_iter()
                .map(|t| t.into_txn().into_inner())
                .collect(),
            transaction_outputs,
            auxiliary_infos,
            parent_state,
            state_view,
            false, // prime_state_cache
            append_state_checkpoint_to_block.is_some(),
        )
```

**File:** execution/executor-types/src/transactions_with_output.rs (L23-35)
```rust
    pub fn new(
        transactions: Vec<Transaction>,
        transaction_outputs: Vec<TransactionOutput>,
        persisted_auxiliary_infos: Vec<PersistedAuxiliaryInfo>,
    ) -> Self {
        assert_eq!(transactions.len(), transaction_outputs.len());
        assert_eq!(transactions.len(), persisted_auxiliary_infos.len());
        Self {
            transactions,
            transaction_outputs,
            persisted_auxiliary_infos,
        }
    }
```

**File:** secure/net/src/network_controller/mod.rs (L84-113)
```rust
pub struct NetworkController {
    inbound_handler: Arc<Mutex<InboundHandler>>,
    outbound_handler: OutboundHandler,
    inbound_rpc_runtime: Runtime,
    outbound_rpc_runtime: Runtime,
    inbound_server_shutdown_tx: Option<oneshot::Sender<()>>,
    outbound_task_shutdown_tx: Option<Sender<Message>>,
    listen_addr: SocketAddr,
}

impl NetworkController {
    pub fn new(service: String, listen_addr: SocketAddr, timeout_ms: u64) -> Self {
        let inbound_handler = Arc::new(Mutex::new(InboundHandler::new(
            service.clone(),
            listen_addr,
            timeout_ms,
        )));
        let outbound_handler = OutboundHandler::new(service, listen_addr, inbound_handler.clone());
        info!("Network controller created for node {}", listen_addr);
        Self {
            inbound_handler,
            outbound_handler,
            inbound_rpc_runtime: Runtime::new().unwrap(),
            outbound_rpc_runtime: Runtime::new().unwrap(),
            // we initialize the shutdown handles when we start the network controller
            inbound_server_shutdown_tx: None,
            outbound_task_shutdown_tx: None,
            listen_addr,
        }
    }
```
