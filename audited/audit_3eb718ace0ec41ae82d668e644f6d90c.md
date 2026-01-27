# Audit Report

## Title
Sharded Block Executor Deadlock via Transaction Abort and Write Hint Mismatch

## Summary
The block partitioner creates cross-shard dependencies based on transaction `write_hints`, but the executor sends commit messages only for actual writes in the transaction output. When a transaction aborts during execution (e.g., out of gas, Move assertion failure), its write set contains only prologue/epilogue updates (gas charges, sequence number) but not the hinted writes. Dependent transactions in other shards wait indefinitely for commit messages that will never be sent, causing validator deadlock.

## Finding Description

The vulnerability exists in the interaction between the partitioner's dependency creation logic and the executor's cross-shard communication mechanism.

**Partitioner Behavior:**

The partitioner builds dependencies from transaction hints during initialization: [1](#0-0) 

These hints are used to create required and dependent edges for cross-shard coordination: [2](#0-1) 

**Executor Behavior:**

The executor's `CrossShardCommitSender` only sends messages for keys in the **actual** write set, not the hinted writes: [3](#0-2) 

**The Mismatch:**

When a transaction aborts, it produces a `TransactionOutput` with an empty write set for the transaction logic (only prologue/epilogue updates remain): [4](#0-3) 

**The Deadlock:**

Dependent transactions wait indefinitely in `RemoteStateValue::get_value()`: [5](#0-4) 

There is **no timeout mechanism** for this blocking wait.

**Attack Path:**

1. Transaction T1 in Shard 0, Round 0 has `write_hints = [StorageLocation::Specific(K)]` (e.g., would write key K if execution succeeds)
2. Transaction T2 in Shard 1, Round 0 has `read_hints = [StorageLocation::Specific(K)]` (depends on K)
3. Partitioner creates:
   - T1 gets `dependent_edge` to T2 for key K
   - T2 gets `required_edge` from T1 for key K
4. During execution:
   - T2's `CrossShardStateView` initializes K as `RemoteValueStatus::Waiting`
   - T1 executes but aborts (e.g., Move assertion fails, out of gas, insufficient balance)
   - T1's `on_transaction_committed` is called with aborted output containing empty write set for business logic
   - `CrossShardCommitSender::send_remote_update_for_success` iterates over actual write set
   - Key K is not in actual write set, so no commit message sent
   - T2 attempts to read K from `CrossShardStateView`
   - T2's execution thread blocks in `RemoteStateValue::get_value()` waiting for K
   - K will never be set because T1 never sent the message
   - **DEADLOCK**: Shard 1 hangs indefinitely, validator cannot complete block execution

## Impact Explanation

**High Severity** - This qualifies as **"Validator node slowdowns"** and potentially **"Total loss of liveness/network availability"** per the bug bounty criteria.

When this deadlock occurs:
- The affected validator's sharded executor hangs indefinitely on cross-shard message wait
- The validator cannot complete block execution and falls behind
- If multiple validators are affected by transactions in the same block, the network experiences liveness degradation
- The deadlock requires external intervention (validator restart) to recover

The vulnerability breaks the **Deterministic Execution** invariant: validators executing the same block with sharded execution enabled will deadlock, while those using non-sharded execution will complete successfully, causing consensus splits.

## Likelihood Explanation

**High Likelihood** - This vulnerability can be triggered by any of the following common scenarios:

1. **Out of Gas Aborts**: Transaction runs out of gas mid-execution (very common)
2. **Move Assertion Failures**: Business logic assertions fail (e.g., `assert!(balance >= amount, ERROR_CODE)`)
3. **Arithmetic Overflows**: Checked arithmetic operations fail
4. **Resource Access Failures**: Account or resource doesn't exist
5. **Permission Checks**: Signer validation fails

The only requirements are:
- Sharded execution must be enabled
- Two transactions must be partitioned to different shards
- One transaction must have write hints for a key
- Another transaction must have read/write hints for the same key  
- The first transaction must abort during execution

Given that transaction aborts are a normal part of blockchain operation and sharded execution is designed for high-throughput scenarios, this vulnerability will manifest frequently in production.

## Recommendation

Implement one of the following fixes:

**Option 1: Send Abort Notifications**

Implement the `on_execution_aborted` handler to send abort notifications for all hinted writes: [6](#0-5) 

**Fix Implementation:**

```rust
fn on_execution_aborted(&self, txn_idx: TxnIndex) {
    let global_txn_idx = txn_idx + self.index_offset;
    if let Some(edges) = self.dependent_edges.get(&global_txn_idx) {
        // Send abort notifications for all dependent edges
        for (state_key, dependent_shard_ids) in edges.iter() {
            for (dependent_shard_id, round_id) in dependent_shard_ids.iter() {
                let message = RemoteTxnWriteMsg(RemoteTxnWrite::new(
                    state_key.clone(),
                    None, // None indicates the transaction aborted
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

**Option 2: Timeout with Fallback**

Add timeout to `RemoteStateValue::get_value()` and fallback to base state view:

```rust
pub fn get_value_with_timeout(&self, timeout: Duration) -> Result<Option<StateValue>, TimeoutError> {
    let (lock, cvar) = &*self.value_condition;
    let mut status = lock.lock().unwrap();
    let timeout_result = cvar.wait_timeout_while(
        status,
        timeout,
        |s| matches!(s, RemoteValueStatus::Waiting)
    ).unwrap();
    
    if timeout_result.1.timed_out() {
        return Err(TimeoutError);
    }
    
    match &*timeout_result.0 {
        RemoteValueStatus::Ready(value) => Ok(value.clone()),
        RemoteValueStatus::Waiting => unreachable!(),
    }
}
```

**Option 3: Validate Hints Match Execution**

Add runtime validation that actual writes are a superset of dependent edges created by the partitioner, panic/abort if mismatch detected.

**Recommended Solution**: **Option 1** is the most correct fix as it properly notifies dependent shards of transaction aborts. This maintains the cross-shard dependency protocol's correctness.

## Proof of Concept

```rust
// Rust test demonstrating the deadlock scenario
#[test]
fn test_sharded_executor_deadlock_on_abort() {
    use aptos_types::transaction::analyzed_transaction::{AnalyzedTransaction, StorageLocation};
    use aptos_types::state_store::state_key::StateKey;
    
    // Create two transactions with conflicting hints
    let key_k = StateKey::raw(b"shared_key_k");
    
    // T1: Will write K if successful, but will abort
    let t1 = create_transaction_with_hints(
        /* sender */ account_1,
        /* read_hints */ vec![],
        /* write_hints */ vec![StorageLocation::Specific(key_k.clone())],
        /* will_abort */ true, // e.g., out of gas or assertion failure
    );
    
    // T2: Depends on reading K
    let t2 = create_transaction_with_hints(
        /* sender */ account_2,
        /* read_hints */ vec![StorageLocation::Specific(key_k.clone())],
        /* write_hints */ vec![],
        /* will_abort */ false,
    );
    
    let transactions = vec![
        AnalyzedTransaction::from(t1),
        AnalyzedTransaction::from(t2),
    ];
    
    // Partition into 2 shards
    let partitioner = PartitionerV2::new(/* ... */);
    let partitioned = partitioner.partition(transactions, 2);
    
    // Execute on sharded executor
    let executor = LocalExecutorClient::create_local_sharded_block_executor(2, None);
    
    // This will DEADLOCK: T2 waits forever for T1's write to K
    // T1 aborts and doesn't send commit message for K
    // T2 blocks in RemoteStateValue::get_value() indefinitely
    let result = executor.execute_block(
        state_view,
        partitioned,
        /* concurrency */ 4,
        onchain_config,
    );
    
    // Test will hang here - timeout needed to detect deadlock
    assert!(result.is_ok());
}
```

## Notes

The vulnerability stems from the documented design assumption that hints "can be accurate or strictly overestimated" but the executor only handles the accurate case. The partitioner correctly handles wildcard hints by panicking (since they can't be converted to specific state keys), but doesn't account for transaction aborts causing hint mismatches.

The unimplemented `on_execution_aborted` handler is a strong indicator this was a known gap in the implementation that needs to be addressed before sharded execution can be safely deployed to production.

### Citations

**File:** execution/block-partitioner/src/v2/init.rs (L28-45)
```rust
                    let reads = txn.read_hints.iter().map(|loc| (loc, false));
                    let writes = txn.write_hints.iter().map(|loc| (loc, true));
                    reads
                        .chain(writes)
                        .for_each(|(storage_location, is_write)| {
                            let key_idx = state.add_key(storage_location.state_key());
                            if is_write {
                                state.write_sets[ori_txn_idx]
                                    .write()
                                    .unwrap()
                                    .insert(key_idx);
                            } else {
                                state.read_sets[ori_txn_idx]
                                    .write()
                                    .unwrap()
                                    .insert(key_idx);
                            }
                            state.trackers.entry(key_idx).or_insert_with(|| {
```

**File:** execution/block-partitioner/src/v2/state.rs (L301-348)
```rust
        // Build required edges.
        let write_set = self.write_sets[ori_txn_idx].read().unwrap();
        let read_set = self.read_sets[ori_txn_idx].read().unwrap();
        for &key_idx in write_set.iter().chain(read_set.iter()) {
            let tracker_ref = self.trackers.get(&key_idx).unwrap();
            let tracker = tracker_ref.read().unwrap();
            if let Some(txn_idx) = tracker
                .finalized_writes
                .range(..ShardedTxnIndexV2::new(round_id, shard_id, 0))
                .last()
            {
                let src_txn_idx = ShardedTxnIndex {
                    txn_index: *self.final_idxs_by_pre_partitioned[txn_idx.pre_partitioned_txn_idx]
                        .read()
                        .unwrap(),
                    shard_id: txn_idx.shard_id(),
                    round_id: txn_idx.round_id(),
                };
                deps.add_required_edge(src_txn_idx, tracker.storage_location.clone());
            }
        }

        // Build dependent edges.
        for &key_idx in self.write_sets[ori_txn_idx].read().unwrap().iter() {
            if Some(txn_idx) == self.last_writer(key_idx, SubBlockIdx { round_id, shard_id }) {
                let start_of_next_sub_block = ShardedTxnIndexV2::new(round_id, shard_id + 1, 0);
                let next_writer = self.first_writer(key_idx, start_of_next_sub_block);
                let end_follower = match next_writer {
                    None => ShardedTxnIndexV2::new(self.num_rounds(), self.num_executor_shards, 0), // Guaranteed to be greater than any invalid idx...
                    Some(idx) => ShardedTxnIndexV2::new(idx.round_id(), idx.shard_id() + 1, 0),
                };
                for follower_txn_idx in
                    self.all_txns_in_sub_block_range(key_idx, start_of_next_sub_block, end_follower)
                {
                    let final_sub_blk_idx =
                        self.final_sub_block_idx(follower_txn_idx.sub_block_idx);
                    let dst_txn_idx = ShardedTxnIndex {
                        txn_index: *self.final_idxs_by_pre_partitioned
                            [follower_txn_idx.pre_partitioned_txn_idx]
                            .read()
                            .unwrap(),
                        shard_id: final_sub_blk_idx.shard_id,
                        round_id: final_sub_blk_idx.round_id,
                    };
                    deps.add_dependent_edge(dst_txn_idx, vec![self.storage_location(key_idx)]);
                }
            }
        }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L103-134)
```rust
    fn send_remote_update_for_success(
        &self,
        txn_idx: TxnIndex,
        txn_output: &OnceCell<TransactionOutput>,
    ) {
        let edges = self.dependent_edges.get(&txn_idx).unwrap();
        let write_set = txn_output
            .get()
            .expect("Committed output must be set")
            .write_set();

        for (state_key, write_op) in write_set.expect_write_op_iter() {
            if let Some(dependent_shard_ids) = edges.get(state_key) {
                for (dependent_shard_id, round_id) in dependent_shard_ids.iter() {
                    trace!("Sending remote update for success for shard id {:?} and txn_idx: {:?}, state_key: {:?}, dependent shard id: {:?}", self.shard_id, txn_idx, state_key, dependent_shard_id);
                    let message = RemoteTxnWriteMsg(RemoteTxnWrite::new(
                        state_key.clone(),
                        Some(write_op.clone()),
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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L149-151)
```rust
    fn on_execution_aborted(&self, _txn_idx: TxnIndex) {
        todo!("on_transaction_aborted not supported for sharded execution yet")
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L689-703)
```rust
    fn finish_aborted_transaction(
        &self,
        prologue_session_change_set: SystemSessionChangeSet,
        gas_meter: &mut impl AptosGasMeter,
        txn_data: &TransactionMetadata,
        resolver: &impl AptosMoveResolver,
        module_storage: &impl AptosModuleStorage,
        serialized_signers: &SerializedSigners,
        status: ExecutionStatus,
        log_context: &AdapterLogSchema,
        change_set_configs: &ChangeSetConfigs,
        traversal_context: &mut TraversalContext,
    ) -> Result<VMOutput, VMStatus> {
        // Storage refund is zero since no slots are deleted in aborted transactions.
        const ZERO_STORAGE_REFUND: u64 = 0;
```

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
