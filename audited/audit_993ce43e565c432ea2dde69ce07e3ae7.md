# Audit Report

## Title
Cross-Shard Execution Deadlock Leading to Validator Liveness Failure

## Summary
The sharded block executor lacks proper timeout and failure propagation mechanisms in cross-shard dependency handling. When one shard fails mid-execution before fulfilling cross-shard dependencies, dependent shards can deadlock indefinitely, causing validator nodes to hang and preventing consensus participation.

## Finding Description

The sharded execution system has a critical flaw in how it handles cross-shard dependencies when failures occur. The vulnerability exists in the interaction between three components:

1. **Cross-Shard State View Blocking**: [1](#0-0) 

When a transaction needs a cross-shard value, it blocks on a condition variable until the value is set. There is no timeout mechanism.

2. **Failure Propagation Gap**: [2](#0-1) 

When `execute_sub_block` returns an error via the `?` operator, the function exits early. However, this does not signal dependent shards about the failure.

3. **Missing Abort Handler**: [3](#0-2) 

The abort handler is unimplemented and will panic if called, providing no mechanism to notify dependent shards of execution failures.

**Attack Scenario:**
1. Block contains transactions partitioned across Shard 0 and Shard 1
2. Transaction T1 in Shard 1 depends on cross-shard read from T0 in Shard 0
3. T1 blocks on `RemoteStateValue::get_value()` waiting for the dependency
4. T0 encounters an error (e.g., `SPECULATIVE_EXECUTION_ABORT_ERROR`) before committing
5. Shard 0 returns error and exits without setting the cross-shard value
6. Shard 1's execution thread remains blocked indefinitely on the condition variable
7. The coordinator waits for results from Shard 1 that never arrive
8. The entire validator node deadlocks

While the `StopMsg` is sent after execution completes: [4](#0-3) 

This only stops the receiver thread, not the blocked execution threads waiting for cross-shard values.

## Impact Explanation

**Severity: High** (Validator node slowdowns / Total loss of liveness)

This vulnerability causes:
- **Validator Node Hangs**: Affected validators become unresponsive and cannot participate in consensus
- **Network Liveness Degradation**: If multiple validators deadlock, the network may struggle to maintain 2/3+ quorum
- **Non-deterministic Failures**: Different validators may deadlock at different times based on execution scheduling

However, this does NOT cause state divergence. The fail-stop behavior means validators either:
- Successfully execute the block and vote
- Deadlock and don't vote
- Return an error and don't vote

All successful validators compute the same state root, preserving consensus safety. The issue is liveness, not safety.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability triggers when:
1. Sharded execution is enabled (common in high-throughput scenarios)
2. Transactions have cross-shard dependencies (frequent in complex blocks)
3. A shard encounters an execution error mid-block (can occur from various VM errors)

The combination is realistic in production environments, though the specific ordering depends on parallel execution scheduling.

## Recommendation

Implement comprehensive timeout and failure propagation mechanisms:

1. **Add timeout to cross-shard reads**: Modify `RemoteStateValue::get_value()` to accept a timeout parameter and return an error if the deadline is exceeded.

2. **Implement abort handler**: Replace the `todo!()` in `on_execution_aborted` with proper failure notification to all dependent shards.

3. **Add cancellation mechanism**: When a shard fails, broadcast cancellation messages to all other shards so they can abort blocked operations.

4. **Implement watchdog**: Add a timeout monitor at the coordinator level that detects hung shards and forces termination.

Example fix for timeout mechanism:
```rust
pub fn get_value_with_timeout(&self, timeout: Duration) -> Result<Option<StateValue>, TimeoutError> {
    let (lock, cvar) = &*self.value_condition;
    let mut status = lock.lock().unwrap();
    let deadline = Instant::now() + timeout;
    while let RemoteValueStatus::Waiting = *status {
        let now = Instant::now();
        if now >= deadline {
            return Err(TimeoutError::CrossShardReadTimeout);
        }
        let remaining = deadline - now;
        let (new_status, timeout_result) = cvar.wait_timeout(status, remaining).unwrap();
        status = new_status;
        if timeout_result.timed_out() {
            return Err(TimeoutError::CrossShardReadTimeout);
        }
    }
    match &*status {
        RemoteValueStatus::Ready(value) => Ok(value.clone()),
        RemoteValueStatus::Waiting => unreachable!(),
    }
}
```

## Proof of Concept

Due to the complexity of the sharded execution environment, a full PoC requires:

1. Setting up multi-shard execution with cross-shard dependencies
2. Injecting a failure into one shard mid-execution using failpoints
3. Observing the dependent shard deadlock

However, the code analysis clearly shows the vulnerability path exists based on the cited code sections.

---

**Note**: While the original question asked about "network partition with different committed states," the actual vulnerability is a **liveness failure (deadlock)** rather than a **safety violation (state divergence)**. The sharded executor's fail-stop behavior preserves consensus safety but creates availability risks through deadlock scenarios.

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/remote_state_value.rs (L29-39)
```rust
    pub fn get_value(&self) -> Option<StateValue> {
        let (lock, cvar) = &*self.value_condition;
        let mut status = lock.lock().unwrap();
        while let RemoteValueStatus::Waiting = *status {
            status = cvar.wait(status).unwrap();
        }
        match &*status {
            RemoteValueStatus::Ready(value) => value.clone(),
            RemoteValueStatus::Waiting => unreachable!(),
        }
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L157-173)
```rust
                if let Some(shard_id) = shard_id {
                    trace!(
                        "executed sub block for shard {} and round {}",
                        shard_id,
                        round
                    );
                    // Send a self message to stop the cross-shard commit receiver.
                    cross_shard_client_clone.send_cross_shard_msg(
                        shard_id,
                        round,
                        CrossShardMsg::StopMsg,
                    );
                } else {
                    trace!("executed block for global shard and round {}", round);
                    // Send a self message to stop the cross-shard commit receiver.
                    cross_shard_client_clone.send_global_msg(CrossShardMsg::StopMsg);
                }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L185-213)
```rust
    fn execute_block(
        &self,
        transactions: SubBlocksForShard<AnalyzedTransaction>,
        state_view: &S,
        config: BlockExecutorConfig,
    ) -> Result<Vec<Vec<TransactionOutput>>, VMStatus> {
        let mut result = vec![];
        for (round, sub_block) in transactions.into_sub_blocks().into_iter().enumerate() {
            let _timer = SHARDED_BLOCK_EXECUTION_BY_ROUNDS_SECONDS
                .timer_with(&[&self.shard_id.to_string(), &round.to_string()]);
            SHARDED_BLOCK_EXECUTOR_TXN_COUNT.observe_with(
                &[&self.shard_id.to_string(), &round.to_string()],
                sub_block.transactions.len() as f64,
            );
            info!(
                "executing sub block for shard {} and round {}, number of txns {}",
                self.shard_id,
                round,
                sub_block.transactions.len()
            );
            result.push(self.execute_sub_block(sub_block, round, state_view, config.clone())?);
            trace!(
                "Finished executing sub block for shard {} and round {}",
                self.shard_id,
                round
            );
        }
        Ok(result)
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L149-151)
```rust
    fn on_execution_aborted(&self, _txn_idx: TxnIndex) {
        todo!("on_transaction_aborted not supported for sharded execution yet")
    }
```
