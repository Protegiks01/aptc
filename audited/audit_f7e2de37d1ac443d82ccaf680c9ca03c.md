# Audit Report

## Title
RemoteStateValue Lacks Idempotency Protection Allowing State Inconsistency in Distributed Sharded Execution

## Summary
The `RemoteStateValue::set_value()` method can be called multiple times without validation, allowing the stored value to be overwritten. In distributed sharded execution mode with network message duplication or a compromised coordinator, this can cause different executor threads to observe different state values for the same key, breaking the deterministic execution invariant and potentially causing consensus divergence.

## Finding Description

The `RemoteStateValue` struct is used to synchronize cross-shard state dependencies during sharded block execution. It implements a wait-notify pattern where threads can block on `get_value()` until another thread calls `set_value()`. However, the implementation has no protection against multiple `set_value()` calls: [1](#0-0) 

The method unconditionally overwrites the status from `Waiting` to `Ready` without checking if the value was already set. This violates the expected semantics where a `RemoteStateValue` should transition from `Waiting` → `Ready` exactly once.

**Vulnerable Usage Pattern 1: Remote State View**

In distributed execution mode, the `RemoteStateValueReceiver` processes incoming state value responses from the coordinator: [2](#0-1) 

Each incoming message triggers `set_state_value()`, which eventually calls `RemoteStateValue::set_value()`. There is no deduplication logic - if duplicate messages arrive (due to network retransmission, coordinator bugs, or malicious behavior), `set_value()` will be called multiple times with potentially different values.

**Vulnerable Usage Pattern 2: Cross-Shard State View**

In the local sharded executor, `CrossShardCommitReceiver` processes cross-shard commit messages: [3](#0-2) 

The receiver loops indefinitely, processing each message without validation. If duplicate messages arrive for the same state key, `set_value()` will overwrite the previous value.

**Attack Scenario:**

1. Shard A executes a sub-block with transactions T1 and T2, both requiring remote state key K
2. Both T1 and T2 call `get_value()` on the same `RemoteStateValue` for key K
3. T1 blocks waiting for the value
4. Coordinator (or cross-shard sender) sends value V1 for key K
5. `set_value(V1)` is called, T1 wakes up and proceeds with V1
6. Due to network duplication or malicious coordinator, value V2 is sent for the same key K
7. `set_value(V2)` overwrites the value to V2
8. T2 calls `get_value()` and immediately receives V2 (no wait since status is already `Ready`)
9. **Result**: T1 executed with V1, T2 executed with V2 for the same state key
10. Different execution results lead to state root mismatch and consensus failure

The shared `CrossShardStateView` is created per sub-block and used by all transactions: [4](#0-3) 

This means multiple transactions read from the same `RemoteStateValue` instance, making the race condition exploitable.

## Impact Explanation

This vulnerability breaks **Invariant #1: Deterministic Execution** - "All validators must produce identical state roots for identical blocks."

When different threads observe different values for the same state key within a single block execution:
- Transaction execution becomes non-deterministic
- Different validators could compute different state roots for the same block
- Consensus would fail to reach agreement on block commitment
- Network could experience liveness failures or require manual intervention

**Severity Assessment: Medium**

This qualifies as **Medium Severity** ($10,000 category) because it causes "State inconsistencies requiring intervention." While it doesn't directly cause fund loss, it breaks consensus determinism and could cause network disruption requiring validator coordination to recover.

The impact is constrained from Critical/High because:
- Requires distributed execution mode (not default deployment)
- Requires either network-layer message duplication or malicious coordinator behavior
- Would be detected via state root mismatches before finalization
- No direct fund theft or permanent state corruption

## Likelihood Explanation

**Likelihood: Medium-Low**

The vulnerability requires specific conditions:

1. **Distributed sharded execution mode**: Must use `RemoteExecutorClient` rather than `LocalExecutorClient`
2. **Message duplication**: Either:
   - Network layer duplicates/retransmits messages
   - Coordinator has bug causing duplicate sends
   - Malicious coordinator intentionally sends conflicting values
3. **Race timing**: Multiple transactions must be executing concurrently and reading the same remote state value

In production:
- Most deployments use local (in-process) sharded execution where message delivery is reliable
- Network protocols typically provide at-most-once or exactly-once delivery semantics
- Coordinators are trusted components operated by validator infrastructure

However, the lack of defensive programming means the vulnerability could manifest from:
- Future code changes that introduce message duplication
- Network-layer bugs or configuration issues
- Distributed deployment in untrusted environments

## Recommendation

Add idempotency protection to `RemoteStateValue::set_value()` to enforce single-assignment semantics:

```rust
#[derive(Clone)]
pub enum RemoteValueStatus {
    Ready(Option<StateValue>),
    Waiting,
}

pub fn set_value(&self, value: Option<StateValue>) -> Result<(), String> {
    let (lock, cvar) = &*self.value_condition;
    let mut status = lock.lock().unwrap();
    
    // Check if value was already set
    match &*status {
        RemoteValueStatus::Ready(existing_value) => {
            // Idempotent if setting the same value
            if existing_value == &value {
                return Ok(());
            }
            // Error if attempting to overwrite with different value
            return Err(format!(
                "Attempted to overwrite RemoteStateValue: existing={:?}, new={:?}",
                existing_value, value
            ));
        }
        RemoteValueStatus::Waiting => {
            // Normal case: transition from Waiting to Ready
            *status = RemoteValueStatus::Ready(value);
            cvar.notify_all();
            Ok(())
        }
    }
}
```

Additionally, update all call sites to handle the error:

```rust
// In CrossShardCommitReceiver::start
RemoteTxnWriteMsg(txn_commit_msg) => {
    let (state_key, write_op) = txn_commit_msg.take();
    if let Err(e) = cross_shard_state_view
        .try_set_value(&state_key, write_op.and_then(|w| w.as_state_value())) {
        // Log error and potentially terminate shard execution
        error!("Failed to set remote state value: {}", e);
        // Consider panicking or returning error to halt execution
    }
}
```

For defense-in-depth, add message deduplication at the receiver level:

```rust
// In RemoteStateValueReceiver
struct RemoteStateValueReceiver {
    processed_messages: DashMap<StateKey, StateValue>,
    // ... existing fields
}

fn handle_message(...) {
    response.inner.into_iter().for_each(|(state_key, state_value)| {
        // Deduplicate at receiver level
        if let Some(existing) = self.processed_messages.get(&state_key) {
            if existing.value() != &state_value {
                error!("Duplicate message with different value for key {:?}", state_key);
                return;
            }
        }
        self.processed_messages.insert(state_key.clone(), state_value.clone());
        state_view_lock.set_state_value(&state_key, state_value);
    });
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::{thread, time::Duration};
    use aptos_types::state_store::state_value::StateValue;

    #[test]
    fn test_remote_state_value_multiple_set_causes_inconsistency() {
        // Create a RemoteStateValue
        let remote_value = Arc::new(RemoteStateValue::waiting());
        
        // Simulate two transactions reading the same value
        let remote_value_clone1 = remote_value.clone();
        let remote_value_clone2 = remote_value.clone();
        
        let thread1 = thread::spawn(move || {
            // Transaction 1 waits for value
            let value = remote_value_clone1.get_value();
            (value, "T1")
        });
        
        // Ensure T1 is waiting
        thread::sleep(Duration::from_millis(10));
        
        let thread2 = thread::spawn(move || {
            // Transaction 2 will read after both sets
            thread::sleep(Duration::from_millis(60));
            let value = remote_value_clone2.get_value();
            (value, "T2")
        });
        
        // First message arrives with value1
        thread::sleep(Duration::from_millis(20));
        remote_value.set_value(Some(StateValue::from(vec![1, 2, 3])));
        
        // Second message arrives with value2 (duplicate/malicious)
        thread::sleep(Duration::from_millis(30));
        remote_value.set_value(Some(StateValue::from(vec![4, 5, 6])));
        
        let (value1, t1) = thread1.join().unwrap();
        let (value2, t2) = thread2.join().unwrap();
        
        println!("{} got value: {:?}", t1, value1);
        println!("{} got value: {:?}", t2, value2);
        
        // Assertion: Both transactions should see the same value
        // This assertion FAILS, demonstrating the vulnerability
        assert_eq!(value1, value2, 
            "Transactions observed different values! T1={:?}, T2={:?}", 
            value1, value2);
    }
}
```

**Notes**

This vulnerability exists in the sharded executor implementation but requires specific deployment conditions (distributed mode) and triggering conditions (message duplication) to manifest. While the current dependency analysis and message sending logic should prevent duplicate messages in correct operation, the lack of defensive validation means the code is vulnerable to network-layer issues, coordinator bugs, or future code changes that could introduce message duplication. The recommended fix enforces single-assignment semantics at the `RemoteStateValue` level, providing defense-in-depth against potential message handling bugs elsewhere in the system.

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/remote_state_value.rs (L22-27)
```rust
    pub fn set_value(&self, value: Option<StateValue>) {
        let (lock, cvar) = &*self.value_condition;
        let mut status = lock.lock().unwrap();
        *status = RemoteValueStatus::Ready(value);
        cvar.notify_all();
    }
```

**File:** execution/executor-service/src/remote_state_view.rs (L233-272)
```rust
    fn start(&self) {
        while let Ok(message) = self.kv_rx.recv() {
            let state_view = self.state_view.clone();
            let shard_id = self.shard_id;
            self.thread_pool.spawn(move || {
                Self::handle_message(shard_id, message, state_view);
            });
        }
    }

    fn handle_message(
        shard_id: ShardId,
        message: Message,
        state_view: Arc<RwLock<RemoteStateView>>,
    ) {
        let _timer = REMOTE_EXECUTOR_TIMER
            .with_label_values(&[&shard_id.to_string(), "kv_responses"])
            .start_timer();
        let bcs_deser_timer = REMOTE_EXECUTOR_TIMER
            .with_label_values(&[&shard_id.to_string(), "kv_resp_deser"])
            .start_timer();
        let response: RemoteKVResponse = bcs::from_bytes(&message.data).unwrap();
        drop(bcs_deser_timer);

        REMOTE_EXECUTOR_REMOTE_KV_COUNT
            .with_label_values(&[&shard_id.to_string(), "kv_responses"])
            .inc();
        let state_view_lock = state_view.read().unwrap();
        trace!(
            "Received state values for shard {} with size {}",
            shard_id,
            response.inner.len()
        );
        response
            .inner
            .into_iter()
            .for_each(|(state_key, state_value)| {
                state_view_lock.set_state_value(&state_key, state_value);
            });
    }
```

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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L115-118)
```rust
        let cross_shard_state_view = Arc::new(CrossShardStateView::create_cross_shard_state_view(
            state_view,
            &transactions,
        ));
```
