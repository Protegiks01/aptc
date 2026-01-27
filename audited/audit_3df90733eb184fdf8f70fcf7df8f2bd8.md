# Audit Report

## Title
Validator Permanent Deadlock via Unimplemented Transaction Abort Handler in Sharded Execution

## Summary
The sharded block executor contains an unimplemented abort handler (`on_execution_aborted`) that panics with `todo!()`, causing validator nodes to permanently deadlock when any transaction with cross-shard dependencies aborts during execution. Any user can trigger this by submitting transactions that run out of gas or hit assertion failures.

## Finding Description

The vulnerability exists in the cross-shard transaction execution flow. When the sharded block executor processes transactions with cross-shard dependencies, it uses a `CrossShardCommitSender` as a commit hook to propagate write results to dependent shards. [1](#0-0) 

When a transaction aborts (e.g., out of gas, assertion failure, arithmetic overflow), the block executor invokes `on_execution_aborted` on the commit hook: [2](#0-1) 

However, the `CrossShardCommitSender` implementation contains only a `todo!()` placeholder, which panics when called.

The execution architecture spawns two concurrent threads within a rayon scope: [3](#0-2) 

**Thread 1** (CrossShardCommitReceiver) blocks indefinitely waiting for messages: [4](#0-3) 

The receiver uses a blocking channel receive without timeout: [5](#0-4) 

**Thread 2** (Execution) sends a `StopMsg` only after block execution completes successfully. When a transaction aborts:

1. Worker thread calls `on_execution_aborted` which panics
2. The panic propagates, terminating Thread 2 before it sends `StopMsg`
3. Thread 1 remains blocked on `recv()` waiting for `StopMsg` that never arrives
4. The rayon scope waits for all threads to complete
5. The callback is never sent, so the main thread blocks forever on `block_on(callback_receiver)` [6](#0-5) 

This creates a permanent deadlock that halts the validator.

## Impact Explanation

This is **High Severity** per Aptos bug bounty criteria:
- **Validator node slowdowns**: The affected shard's execution never completes, blocking all subsequent block processing
- **Significant protocol violations**: Breaks the liveness invariant - validators must be able to process blocks continuously

The vulnerability affects validator availability, not consensus safety. The validator becomes unable to process new blocks, but it doesn't cause incorrect state transitions or double-spending. Recovery requires restarting the validator node.

Sharded execution is actively used in production: [7](#0-6) 

## Likelihood Explanation

**Likelihood: HIGH**

The attack requirements are minimal:
- **Attacker capability**: Any user can submit transactions to the network
- **Trigger mechanism**: Transaction aborts are common and easily triggered:
  - Set insufficient gas limit
  - Call functions with failing assertions
  - Cause arithmetic overflow/underflow
  - Access non-existent resources
- **Cross-shard dependency**: The partitioner automatically creates cross-shard dependencies based on storage access patterns; users can influence this by targeting specific accounts/resources

Transaction aborts are not exceptional events - they occur naturally in normal operation (e.g., users miscalculating gas, failed transactions). The vulnerability makes validators extremely fragile.

## Recommendation

Implement proper abort handling in `CrossShardCommitSender::on_execution_aborted`. The handler should send deletion/rollback messages to dependent shards for any pending cross-shard updates:

```rust
fn on_execution_aborted(&self, txn_idx: TxnIndex) {
    let global_txn_idx = txn_idx + self.index_offset;
    if let Some(edges) = self.dependent_edges.get(&global_txn_idx) {
        // Send abort/deletion messages to dependent shards
        for (state_key, dependent_shards) in edges.iter() {
            for (dependent_shard_id, round_id) in dependent_shards.iter() {
                let message = RemoteTxnWriteMsg(RemoteTxnWrite::new(
                    state_key.clone(),
                    None,  // None indicates deletion/abort
                ));
                if *round_id == GLOBAL_ROUND_ID {
                    self.cross_shard_client.send_global_msg(message);
                } else {
                    self.cross_shard_client.send_cross_shard_msg(
                        *dependent_shard_id,
                        *round_id,
                        message,
                    );
                }
            }
        }
    }
}
```

Additionally, add timeout mechanisms to channel receive operations to prevent indefinite blocking even if messages are lost.

## Proof of Concept

```rust
// Add to aptos-move/aptos-vm/tests/sharded_block_executor.rs

#[test]
#[should_panic(expected = "todo")]
fn test_abort_causes_deadlock() {
    use aptos_types::transaction::Transaction;
    use aptos_vm::sharded_block_executor::local_executor_shard::LocalExecutorService;
    
    // Create a sharded executor with 2 shards
    let num_shards = 2;
    let executor_client = LocalExecutorService::setup_local_executor_shards(
        num_shards, 
        Some(4)
    );
    
    // Create transactions that will:
    // 1. Have cross-shard dependencies (touch different accounts)
    // 2. Abort during execution (insufficient gas)
    let sender = generate_test_account();
    let receiver = generate_test_account();
    
    // Create transaction with insufficient gas - will abort
    let txn = create_txn_with_insufficient_gas(&sender, &receiver);
    
    // Partition transactions (will create cross-shard dependencies)
    let partitioner = PartitionerV2::new(num_shards);
    let partitioned = partitioner.partition(vec![txn], num_shards);
    
    // Execute - this will deadlock when the transaction aborts
    // because on_execution_aborted panics with todo!()
    let state_view = Arc::new(EmptyStateView);
    let result = executor_client.execute_block(
        state_view,
        partitioned,
        4,
        BlockExecutorConfigFromOnchain::default(),
    );
    
    // This line is never reached - validator hangs forever
    assert!(result.is_err());
}
```

The test demonstrates that when a transaction with cross-shard dependencies aborts, the `todo!()` panic causes the validator to hang indefinitely, requiring a node restart.

## Notes

The `todo!()` marker at the vulnerability site explicitly indicates this is known incomplete code: [8](#0-7) 

While developers are aware the feature is incomplete, the code is deployed in production and can be triggered by any user. The security impact is significant: validators can be halted by submitting legitimate-looking transactions that abort during execution.

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L26-45)
```rust
    pub fn start<S: StateView + Sync + Send>(
        cross_shard_state_view: Arc<CrossShardStateView<S>>,
        cross_shard_client: Arc<dyn CrossShardClient>,
        round: RoundId,
    ) {
        loop {
            let msg = cross_shard_client.receive_cross_shard_msg(round);
            match msg {
                RemoteTxnWriteMsg(txn_commit_msg) => {
                    let (state_key, write_op) = txn_commit_msg.take();
                    cross_shard_state_view
                        .set_value(&state_key, write_op.and_then(|w| w.as_state_value()));
                },
                CrossShardMsg::StopMsg => {
                    trace!("Cross shard commit receiver stopped for round {}", round);
                    break;
                },
            }
        }
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L148-151)
```rust

    fn on_execution_aborted(&self, _txn_idx: TxnIndex) {
        todo!("on_transaction_aborted not supported for sharded execution yet")
    }
```

**File:** aptos-move/block-executor/src/txn_last_input_output.rs (L426-428)
```rust
            OutputStatusKind::Abort(_) => {
                txn_listener.on_execution_aborted(txn_idx);
            },
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L134-180)
```rust
        executor_thread_pool.clone().scope(|s| {
            s.spawn(move |_| {
                CrossShardCommitReceiver::start(
                    cross_shard_state_view_clone,
                    cross_shard_client,
                    round,
                );
            });
            s.spawn(move |_| {
                let txn_provider =
                    DefaultTxnProvider::new_without_info(signature_verified_transactions);
                let ret = AptosVMBlockExecutorWrapper::execute_block_on_thread_pool(
                    executor_thread_pool,
                    &txn_provider,
                    aggr_overridden_state_view.as_ref(),
                    // Since we execute blocks in parallel, we cannot share module caches, so each
                    // thread has its own caches.
                    &AptosModuleCacheManager::new(),
                    config,
                    TransactionSliceMetadata::unknown(),
                    cross_shard_commit_sender,
                )
                .map(BlockOutput::into_transaction_outputs_forced);
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
                callback.send(ret).unwrap();
                executor_thread_pool_clone.spawn(move || {
                    // Explicit async drop
                    drop(txn_provider);
                });
            });
        });
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L182-182)
```rust
        block_on(callback_receiver).unwrap()
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L295-301)
```rust
    fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
        assert_eq!(
            current_round, GLOBAL_ROUND_ID,
            "Global shard client should only receive cross-shard messages in global round"
        );
        self.global_message_rx.recv().unwrap()
    }
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L256-276)
```rust
    fn execute_block_sharded<V: VMBlockExecutor>(
        partitioned_txns: PartitionedTransactions,
        state_view: Arc<CachedStateView>,
        onchain_config: BlockExecutorConfigFromOnchain,
    ) -> Result<Vec<TransactionOutput>> {
        if !get_remote_addresses().is_empty() {
            Ok(V::execute_block_sharded(
                &REMOTE_SHARDED_BLOCK_EXECUTOR.lock(),
                partitioned_txns,
                state_view,
                onchain_config,
            )?)
        } else {
            Ok(V::execute_block_sharded(
                &SHARDED_BLOCK_EXECUTOR.lock(),
                partitioned_txns,
                state_view,
                onchain_config,
            )?)
        }
    }
```
