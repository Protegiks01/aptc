# Audit Report

## Title
Unchecked Cross-Shard Message Processing Allows Validator Node Panics via Asymmetric Edge Creation

## Summary
The `CrossShardStateView::set_value()` method contains an unsafe `unwrap()` that will panic if a shard receives a cross-shard message for a state key not in its expected `cross_shard_data` HashMap. While the block partitioner is designed to create symmetric edges preventing this scenario, there is no runtime validation to detect or handle asymmetric edges if they occur due to partitioner bugs, creating a potential validator availability issue. [1](#0-0) 

## Finding Description

The sharded block executor uses cross-shard messaging to communicate transaction outputs between shards. When a transaction commits, the sending shard notifies dependent shards via `CrossShardCommitSender`, and receiving shards process these messages via `CrossShardCommitReceiver`.

The vulnerability exists in the message processing flow:

1. **Receiver Initialization**: The receiver creates a `CrossShardStateView` initialized with expected state keys from `required_edges`: [2](#0-1) 

2. **Message Reception**: When receiving cross-shard messages, the receiver blindly calls `set_value()` with the received state key: [3](#0-2) 

3. **Unsafe Unwrap**: The `set_value()` method contains an unchecked `unwrap()` that assumes the key exists: [1](#0-0) 

**Attack Scenario**: If the block partitioner has any bug causing asymmetric edge creation (sender has `dependent_edge` to receiver for key K, but receiver lacks corresponding `required_edge`), the following occurs:

1. Sender's `CrossShardCommitSender` is initialized with dependent edges including key K
2. Receiver's `CrossShardStateView` is initialized WITHOUT key K in `cross_shard_data`  
3. When the sender's transaction commits and writes to key K, it sends a message
4. Receiver attempts `cross_shard_data.get(K).unwrap()` and **panics**

The partitioner builds edges in `take_txn_with_dep()`: [4](#0-3) 

While tests verify edge symmetry in controlled scenarios: [5](#0-4) 

There is **no runtime validation** to detect asymmetric edges if they occur due to:
- Edge cases not covered by tests
- Subtle bugs in the parallel edge-building logic using `DashMap` and rayon
- Non-determinism in concurrent edge construction
- Boundary conditions in round/shard transitions

## Impact Explanation

**Severity: Medium** ($10,000 tier per Aptos Bug Bounty)

**Impact Category**: State inconsistencies requiring intervention / Validator node crashes

If triggered, this vulnerability causes:
- **Immediate validator node panic** (thread crash in executor shard)
- **Partial loss of network liveness** if multiple validators hit the same edge case
- **Consensus disruption** if enough validators crash simultaneously
- **Non-deterministic failures** across the validator set if partitioner has subtle bugs

This does not directly cause:
- Loss of funds (execution is halted before state commitment)
- Permanent network partition (nodes can restart)
- Consensus safety violations (crashed nodes simply don't vote)

However, it represents a **fail-unsafe** design where partitioner bugs cause validator crashes rather than graceful error handling, potentially affecting network availability.

## Likelihood Explanation

**Likelihood: Medium-Low**

**Factors Increasing Likelihood:**
- The partitioner uses complex parallel logic with `DashMap` and rayon threading
- Edge construction involves intricate read/write set analysis across rounds and shards
- The code makes strong assumptions about partitioner correctness without defensive validation
- Tests may not cover all edge cases (specific transaction patterns, boundary conditions)

**Factors Decreasing Likelihood:**
- The partitioner is extensively tested for correctness and determinism
- The edge-building logic appears sound in design
- No evidence of existing asymmetry bugs in current test coverage
- Would require specific transaction patterns to trigger

An attacker would need to:
1. Discover a specific pattern of transactions exposing a partitioner edge case
2. Submit these transactions to the network
3. Trigger asymmetric edge creation causing some validators to panic

This is feasible but requires finding the underlying partitioner bug first.

## Recommendation

**Add defensive validation in `CrossShardStateView::set_value()`:**

```rust
pub fn set_value(&self, state_key: &StateKey, state_value: Option<StateValue>) {
    match self.cross_shard_data.get(state_key) {
        Some(remote_value) => {
            remote_value.set_value(state_value);
        },
        None => {
            // Log error and skip - don't crash the node
            aptos_logger::error!(
                "Received cross-shard value for unexpected key: {:?}. \
                This indicates a partitioner bug creating asymmetric edges.",
                state_key
            );
            // Optionally: track metric for monitoring
        }
    }
}
```

**Additional hardening:**

1. Add runtime edge symmetry validation during partitioner execution (debug mode)
2. Add metrics to track unexpected cross-shard messages
3. Consider adding a validation phase before execution that checks edge consistency
4. Add integration tests with adversarial transaction patterns

## Proof of Concept

Due to the nature of this vulnerability (dependent on hypothetical partitioner bugs), a complete PoC requires first identifying a specific partitioner bug that creates asymmetric edges. However, here's a demonstration of the panic condition:

```rust
#[cfg(test)]
mod test_panic_scenario {
    use super::*;
    use aptos_types::state_store::{state_key::StateKey, state_value::StateValue};
    use std::collections::HashSet;

    struct MockStateView;
    impl TStateView for MockStateView {
        type Key = StateKey;
        fn get_state_value(&self, _: &StateKey) -> Result<Option<StateValue>, StateViewError> {
            Ok(None)
        }
        fn get_usage(&self) -> Result<StateStorageUsage, StateViewError> {
            Ok(StateStorageUsage::new_untracked())
        }
    }

    #[test]
    #[should_panic(expected = "called `Option::unwrap()` on a `None` value")]
    fn test_unexpected_key_causes_panic() {
        // Receiver expects only key1
        let mut expected_keys = HashSet::new();
        let key1 = StateKey::raw(b"expected_key");
        expected_keys.insert(key1.clone());
        
        let view = CrossShardStateView::new(expected_keys, &MockStateView);
        
        // But sender sends key2 (simulating asymmetric edges)
        let unexpected_key = StateKey::raw(b"unexpected_key");
        let value = StateValue::from(b"value".to_vec());
        
        // This will panic with unwrap()
        view.set_value(&unexpected_key, Some(value));
    }
}
```

This test demonstrates that an unexpected key causes a panic. A full exploitation would require crafting transactions that expose a partitioner bug, which cannot be demonstrated without first identifying that specific bug.

**Notes**

The vulnerability represents a **defensive programming failure** rather than a directly exploitable bug. The unsafe `unwrap()` creates a fragile system where any partitioner bugs (which may exist but are not yet discovered) would cause validator crashes rather than graceful error handling. This violates the principle of fail-safe design for consensus-critical systems.

The core assumption—that the partitioner always creates perfectly symmetric edges—is only validated in tests, not enforced at runtime. Given the complexity of parallel edge construction using concurrent data structures, this assumption should be treated as potentially fallible and defended against accordingly.

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_state_view.rs (L49-56)
```rust
    pub fn set_value(&self, state_key: &StateKey, state_value: Option<StateValue>) {
        self.cross_shard_data
            .get(state_key)
            .unwrap()
            .set_value(state_value);
        // uncomment the following line to debug waiting count
        // trace!("waiting count for shard id {} is {}", self.shard_id, self.waiting_count());
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_state_view.rs (L58-71)
```rust
    pub fn create_cross_shard_state_view(
        base_view: &'a S,
        transactions: &[TransactionWithDependencies<AnalyzedTransaction>],
    ) -> CrossShardStateView<'a, S> {
        let mut cross_shard_state_key = HashSet::new();
        for txn in transactions {
            for (_, storage_locations) in txn.cross_shard_dependencies.required_edges_iter() {
                for storage_location in storage_locations {
                    cross_shard_state_key.insert(storage_location.clone().into_state_key());
                }
            }
        }
        CrossShardStateView::new(cross_shard_state_key, base_view)
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L31-44)
```rust
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
```

**File:** execution/block-partitioner/src/v2/state.rs (L291-351)
```rust
    pub(crate) fn take_txn_with_dep(
        &self,
        round_id: RoundId,
        shard_id: ShardId,
        txn_idx: PrePartitionedTxnIdx,
    ) -> TransactionWithDependencies<AnalyzedTransaction> {
        let ori_txn_idx = self.ori_idxs_by_pre_partitioned[txn_idx];
        let txn = self.txns[ori_txn_idx].write().unwrap().take().unwrap();
        let mut deps = CrossShardDependencies::default();

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

        TransactionWithDependencies::new(txn, deps)
    }
```

**File:** execution/block-partitioner/src/test_utils.rs (L302-302)
```rust
    assert_eq!(edge_set_from_src_view, edge_set_from_dst_view);
```
