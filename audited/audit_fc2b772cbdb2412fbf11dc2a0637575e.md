# Audit Report

## Title
Cross-Shard Message Processing Panic Due to Unvalidated StateKeys

## Summary
The `receive_cross_shard_msg()` function in `RemoteCrossShardClient` deserializes cross-shard messages without validating that the contained `StateKey` matches expected cross-shard dependencies. When the message is processed, `CrossShardStateView::set_value()` performs an unchecked HashMap lookup with `.unwrap()`, causing a panic if the key is unexpected. This allows an attacker to crash the cross-shard commit receiver thread by sending messages with arbitrary StateKeys, including empty collections like `StateKey::Raw(vec![])` or `StateKey::TableItem` with empty key bytes. [1](#0-0) 

## Finding Description
The vulnerability exists in the cross-shard message processing pipeline used in sharded block execution. When a `CrossShardMsg::RemoteTxnWriteMsg` is received:

1. **Deserialization without validation**: The message is deserialized from BCS bytes without any validation of the contained `StateKey`: [1](#0-0) 

2. **Processing in CrossShardCommitReceiver**: The deserialized message is immediately processed without checking if the `StateKey` is in the expected set: [2](#0-1) 

3. **Unchecked HashMap access with panic**: The `set_value()` method performs an unchecked `.get().unwrap()` on the HashMap, which panics if the key doesn't exist: [3](#0-2) 

The expected StateKeys are determined by analyzing transaction dependencies during initialization: [4](#0-3) 

**Attack Scenario with Empty Collections:**
An attacker can craft messages containing:
- `StateKey::Raw(vec![])` - an empty raw state key
- `StateKey::TableItem { handle, key: vec![] }` - a table item with empty key bytes
- Any other StateKey not in the expected dependency set

These serialize/deserialize successfully via BCS but cause the panic when `set_value()` is called. [5](#0-4) 

## Impact Explanation
This is a **Medium severity** vulnerability per Aptos bug bounty criteria:

- **State inconsistencies requiring intervention**: The cross-shard commit receiver thread crashes, disrupting the synchronization of cross-shard state values. This causes incomplete state propagation between shards.
- **Validator node slowdowns**: The executor shard may fail to complete block execution correctly, requiring restart or manual intervention.
- **Availability impact**: While not a complete DoS, it disrupts the sharded execution mechanism, potentially causing transaction execution failures.

The vulnerability violates the **State Consistency** invariant (#4) and **Deterministic Execution** invariant (#1), as different shards may experience different crash behaviors based on attacker-controlled messages.

## Likelihood Explanation
**Likelihood: Medium-High**

- **Attacker requirements**: An attacker needs to send cross-shard messages to the target executor service. The exact authentication/authorization requirements depend on the network layer configuration, but the code itself performs no validation.
- **Complexity**: Low - the attack simply requires crafting a BCS-serialized `CrossShardMsg` with an unexpected `StateKey` (including empty collections) and sending it to the appropriate network channel.
- **Detection**: The panic would be logged, but might be difficult to distinguish from other operational issues.

## Recommendation
Add validation in `CrossShardStateView::set_value()` to handle unexpected StateKeys gracefully instead of panicking:

```rust
pub fn set_value(&self, state_key: &StateKey, state_value: Option<StateValue>) {
    match self.cross_shard_data.get(state_key) {
        Some(remote_value) => {
            remote_value.set_value(state_value);
        },
        None => {
            // Log the unexpected key and ignore it, or return an error
            aptos_logger::warn!(
                "Received cross-shard message for unexpected state key: {:?}",
                state_key
            );
            // Optionally, increment a metric for monitoring
        }
    }
}
```

Additionally, consider adding message authentication and validation in `RemoteCrossShardClient::receive_cross_shard_msg()` to verify the sender and message contents before processing.

## Proof of Concept
```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_types::state_store::state_key::StateKey;
    use aptos_types::state_store::state_value::StateValue;
    use std::collections::HashSet;
    
    #[test]
    #[should_panic(expected = "called `Option::unwrap()` on a `None` value")]
    fn test_unexpected_state_key_panic() {
        // Setup: Create a CrossShardStateView with one expected key
        let expected_key = StateKey::raw(b"expected_key");
        let mut expected_keys = HashSet::new();
        expected_keys.insert(expected_key.clone());
        
        struct EmptyView;
        impl TStateView for EmptyView {
            type Key = StateKey;
            fn get_state_value(&self, _: &StateKey) -> Result<Option<StateValue>, StateViewError> {
                Ok(None)
            }
            fn get_usage(&self) -> Result<StateStorageUsage, StateViewError> {
                unreachable!()
            }
        }
        
        let view = CrossShardStateView::new(expected_keys, &EmptyView);
        
        // Attack: Send a message with an unexpected empty StateKey
        let unexpected_key = StateKey::raw(vec![]); // Empty collection
        let value = Some(StateValue::from(b"attacker_value".to_vec()));
        
        // This panics because unexpected_key is not in the HashMap
        view.set_value(&unexpected_key, value);
    }
}
```

## Notes
- The vulnerability is not limited to empty collections - any unexpected `StateKey` triggers the panic. However, empty collections are valid BCS-serializable values that specifically exemplify the lack of input validation mentioned in the security question.
- The actual exploitability depends on network-layer authentication, but the code itself provides no defense against malformed cross-shard messages.
- This affects the remote execution mode specifically, as indicated by the file path `executor-service/src/remote_cross_shard_client.rs`.

### Citations

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L61-66)
```rust
    fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
        let rx = self.message_rxs[current_round].lock().unwrap();
        let message = rx.recv().unwrap();
        let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes()).unwrap();
        msg
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

**File:** types/src/state_store/state_key/inner.rs (L46-59)
```rust
#[derive(Clone, CryptoHasher, Eq, PartialEq, Serialize, Deserialize, Ord, PartialOrd, Hash)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(proptest_derive::Arbitrary))]
#[serde(rename = "StateKey")]
pub enum StateKeyInner {
    AccessPath(AccessPath),
    TableItem {
        handle: TableHandle,
        #[serde(with = "serde_bytes")]
        key: Vec<u8>,
    },
    // Only used for testing
    #[serde(with = "serde_bytes")]
    Raw(Vec<u8>),
}
```
