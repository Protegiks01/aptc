# Audit Report

## Title
Race Condition in Remote State View Causes Permanent Executor Shard Liveness Failure

## Summary
A critical race condition exists in the remote executor service's state view management that can cause the executor shard to permanently lose liveness. When `handle_message()` processes stale key-value responses after `init_for_block()` has reset the state view, a panic occurs that prevents state values from being set, causing transaction execution threads to block indefinitely.

## Finding Description

The vulnerability exists in the interaction between concurrent state view management operations in the remote executor service.

**The Race Condition Mechanism:**

When a new block arrives, `init_for_block()` completely replaces the `RemoteStateView` by acquiring a write lock and creating a new instance: [1](#0-0) 

This operation clears all existing state keys from the DashMap. Meanwhile, the `RemoteStateValueReceiver` continuously receives key-value responses and spawns tasks on a rayon thread pool: [2](#0-1) 

Each spawned task calls `handle_message()` which acquires a read lock and processes responses: [3](#0-2) 

**The Critical Vulnerability:**

The `set_state_value()` method contains an unsafe `.unwrap()` that assumes the state key exists: [4](#0-3) 

**Exploitation Flow:**

1. Block N is executing with state keys K1, K2, K3 requested
2. Response messages M1, M2, M3 arrive and are queued in the rayon thread pool
3. Before M2 and M3 are processed, block N+1 arrives
4. `init_for_block()` acquires write lock and replaces the state view with `RemoteStateView::new()` - clearing all keys
5. Queued task for M2 executes, acquires read lock, and sees the NEW (empty) state view
6. `set_state_value(&K2, value)` calls `.get(state_key).unwrap()` but K2 no longer exists
7. The `.unwrap()` panics

**Critical Impact:**

The panic occurs in a rayon thread pool task. Since the executor service does not set up a panic handler [5](#0-4) , rayon catches the panic internally and the task fails silently. This means `RemoteStateValue::set_value()` is never called.

The `RemoteStateValue` uses a condition variable to block threads waiting for values: [6](#0-5) 

Any transaction execution thread calling `get_value()` for the missing state key will block forever at line 33, since `cvar.notify_all()` (line 26) is never invoked due to the panic. The `RemoteStateViewClient` implements `TStateView` for transaction execution: [7](#0-6) 

## Impact Explanation

This vulnerability meets **Critical Severity** criteria per the Aptos bug bounty program under "Total loss of liveness/network availability":

- **Permanent executor shard failure**: The affected executor shard becomes unable to execute transactions. Transaction execution threads block indefinitely waiting for state values that will never arrive.

- **Non-recoverable without manual intervention**: Once triggered, the executor shard is permanently stuck. No timeout mechanism exists [8](#0-7) , so threads wait forever.

- **Affects consensus participation**: The production entry point shows sharded execution architecture [9](#0-8) . If executor shards fail, the coordinator cannot complete block execution, preventing consensus from progressing.

- **Cascading failure potential**: Multiple shards can experience this race simultaneously under high load, causing complete system failure.

The impact is severe because manual process restart is required, and the race can recur immediately under the same conditions.

## Likelihood Explanation

**HIGH Likelihood** - This race condition occurs naturally during normal blockchain operation:

**Triggering Conditions (All Normal):**
- Blocks arriving every 1-2 seconds (standard Aptos mainnet)
- Network latency in key-value response delivery (normal in distributed systems)
- Rayon thread pool task queuing (normal under load)
- Natural timing between block transitions

The execution flow confirms `init_for_block()` is called for every new block: [10](#0-9) 

Under normal load:
1. State key-value responses can be delayed by network latency
2. The rayon thread pool may have pending tasks waiting for CPU scheduling
3. When block N+1 arrives before all responses from block N are processed, the race occurs naturally

**No Attacker Required:** This is a timing vulnerability inherent to the concurrent architecture. The likelihood increases with higher transaction throughput, network congestion, and more shards.

## Recommendation

Implement one of the following fixes:

**Option 1: State Version Tracking**
Add a version/epoch counter to the state view and reject stale messages:

```rust
pub struct RemoteStateView {
    state_values: DashMap<StateKey, RemoteStateValue>,
    version: AtomicU64,
}

pub fn set_state_value(&self, state_key: &StateKey, state_value: Option<StateValue>, expected_version: u64) {
    if self.version.load(Ordering::Relaxed) != expected_version {
        // Stale message, ignore silently
        return;
    }
    if let Some(value) = self.state_values.get(state_key) {
        value.set_value(state_value);
    }
}
```

**Option 2: Graceful Panic Handling**
Replace `.unwrap()` with proper error handling:

```rust
pub fn set_state_value(&self, state_key: &StateKey, state_value: Option<StateValue>) {
    if let Some(remote_value) = self.state_values.get(state_key) {
        remote_value.set_value(state_value);
    } else {
        warn!("Attempted to set value for non-existent state key (likely stale message)");
    }
}
```

**Option 3: Drain Pending Messages**
Before resetting the state view, ensure all pending messages are processed or discarded.

## Proof of Concept

The vulnerability can be demonstrated with a test that simulates the race condition by:
1. Starting the executor service with a state view
2. Sending state value requests and queuing responses
3. Calling `init_for_block()` while responses are queued
4. Observing that subsequent responses trigger the panic

However, the vulnerability is evident from code analysis - the unsafe `.unwrap()` at line 47 will panic when processing stale messages after state reset, and no recovery mechanism exists for the blocked threads.

## Notes

This vulnerability is particularly severe because:
1. No panic handler is configured in the executor service, so panics fail silently
2. No timeout mechanism exists in the condition variable wait
3. The race window is significant under normal load conditions
4. Recovery requires manual intervention
5. The issue can cascade across multiple executor shards

### Citations

**File:** execution/executor-service/src/remote_state_view.rs (L44-49)
```rust
    pub fn set_state_value(&self, state_key: &StateKey, state_value: Option<StateValue>) {
        self.state_values
            .get(state_key)
            .unwrap()
            .set_value(state_value);
    }
```

**File:** execution/executor-service/src/remote_state_view.rs (L118-124)
```rust
    pub fn init_for_block(&self, state_keys: Vec<StateKey>) {
        *self.state_view.write().unwrap() = RemoteStateView::new();
        REMOTE_EXECUTOR_REMOTE_KV_COUNT
            .with_label_values(&[&self.shard_id.to_string(), "prefetch_kv"])
            .inc_by(state_keys.len() as u64);
        self.pre_fetch_state_values(state_keys, false);
    }
```

**File:** execution/executor-service/src/remote_state_view.rs (L186-204)
```rust
    fn get_state_value(&self, state_key: &StateKey) -> StateViewResult<Option<StateValue>> {
        let state_view_reader = self.state_view.read().unwrap();
        if state_view_reader.has_state_key(state_key) {
            // If the key is already in the cache then we return it.
            let _timer = REMOTE_EXECUTOR_TIMER
                .with_label_values(&[&self.shard_id.to_string(), "prefetch_wait"])
                .start_timer();
            return state_view_reader.get_state_value(state_key);
        }
        // If the value is not already in the cache then we pre-fetch it and wait for it to arrive.
        let _timer = REMOTE_EXECUTOR_TIMER
            .with_label_values(&[&self.shard_id.to_string(), "non_prefetch_wait"])
            .start_timer();
        REMOTE_EXECUTOR_REMOTE_KV_COUNT
            .with_label_values(&[&self.shard_id.to_string(), "non_prefetch_kv"])
            .inc();
        self.pre_fetch_state_values(vec![state_key.clone()], true);
        state_view_reader.get_state_value(state_key)
    }
```

**File:** execution/executor-service/src/remote_state_view.rs (L233-241)
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
```

**File:** execution/executor-service/src/remote_state_view.rs (L260-271)
```rust
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
```

**File:** execution/executor-service/src/main.rs (L27-48)
```rust
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

**File:** execution/executor-service/src/remote_cordinator_client.rs (L93-99)
```rust
                    RemoteExecutionRequest::ExecuteBlock(command) => {
                        let init_prefetch_timer = REMOTE_EXECUTOR_TIMER
                            .with_label_values(&[&self.shard_id.to_string(), "init_prefetch"])
                            .start_timer();
                        let state_keys = Self::extract_state_keys(&command);
                        self.state_view_client.init_for_block(state_keys);
                        drop(init_prefetch_timer);
```
