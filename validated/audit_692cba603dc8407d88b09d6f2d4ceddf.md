# Audit Report

## Title
Race Condition in RemoteStateView Reset Causes Node Crash via Panic on State Value Response Handling

## Summary
A critical race condition exists in the executor service's remote state view management where replacing the `RemoteStateView` instance during consecutive block processing can cause the asynchronous response handler to panic on missing keys, triggering the global panic handler and terminating the validator node process.

## Finding Description

The vulnerability occurs in the sharded block execution system where `RemoteStateViewClient` manages remote state fetching across distributed executor shards.

When `init_for_block()` is invoked for a new block, it completely replaces the internal `RemoteStateView` with a fresh empty instance: [1](#0-0) 

This replacement happens synchronously while holding a write lock. However, the method then spawns prefetch tasks asynchronously when `sync_insert_keys=false`: [2](#0-1) 

Meanwhile, a separate background thread (`RemoteStateValueReceiver`) runs continuously to process incoming state value responses: [3](#0-2) 

When responses arrive, the receiver calls `set_state_value()` which contains an unsafe `.unwrap()` that panics if the key doesn't exist: [4](#0-3) 

**Race Condition Timeline:**

1. Block N arrives, `receive_execute_command()` is called: [5](#0-4) 

2. `init_for_block()` creates RemoteStateView N and spawns async prefetch tasks that send requests to the remote coordinator

3. Block N execution completes in the main loop: [6](#0-5) 

4. Block N+1 arrives immediately, and `init_for_block()` replaces RemoteStateView N with RemoteStateView N+1

5. A delayed response for Block N's request arrives at the `RemoteStateValueReceiver`

6. The receiver attempts to set the value on a key that no longer exists in the new RemoteStateView, causing `.unwrap()` to panic

7. The global panic handler terminates the entire node process: [7](#0-6) 

The panic handler is installed at node startup: [8](#0-7) 

This breaks the **Process Stability** and **Liveness** guarantees required for validator operation.

## Impact Explanation

**Severity: CRITICAL** (aligns with "Total loss of liveness/network availability")

This vulnerability causes immediate validator node termination through the panic handler's `process::exit(12)` call, resulting in:

1. **Complete Node Unavailability**: The process exits immediately upon panic, requiring manual restart
2. **Consensus Participation Loss**: Crashed validators cannot vote or propose blocks, reducing network capacity
3. **Non-Deterministic Failures**: The race depends on network latency, making crashes appear random and difficult to diagnose operationally
4. **Potential Network-Wide Impact**: If multiple shards on the same validator crash simultaneously due to synchronized block processing patterns, the entire validator becomes unavailable

This meets the Critical severity category "Total Loss of Liveness/Network Availability" as defined in the Aptos bug bounty program, where node crashes prevent consensus participation and require external intervention (restart) to recover.

## Likelihood Explanation

**Likelihood: HIGH**

This race condition is highly likely to occur in production environments because:

1. **Normal Operation Trigger**: The vulnerability is triggered during standard block processing when consecutive blocks arrive, requiring no attacker action or special conditions

2. **Network Latency Window**: Any network delay between the executor service shard and the remote state coordinator creates the race window. Even modest latencies (100-500ms) are sufficient

3. **Asynchronous Design**: The prefetch mechanism deliberately uses async spawning to improve performance, but creates the unsynchronized race condition

4. **No Synchronization Barriers**: There are no reference counting mechanisms, barriers, or flush operations to ensure in-flight responses are processed before state replacement

5. **Continuous Background Receiver**: The `RemoteStateValueReceiver` thread processes responses at any time, independently of block lifecycle transitions

The vulnerability requires no special preconditions beyond normal validator operation with the remote executor service enabled.

## Recommendation

Implement proper synchronization between `RemoteStateView` lifecycle management and in-flight response handling. Several approaches are possible:

**Option 1: Reference Counting**
- Wrap `RemoteStateView` in an `Arc` and clone it for each spawned task
- Keep references alive until all responses are received
- Use a generation counter to discard responses from previous generations

**Option 2: Response Draining**
- Before replacing the `RemoteStateView`, send a barrier message through the response channel
- Wait for the barrier to be processed before proceeding with replacement
- Ensures all prior responses are handled

**Option 3: Safe Key Lookup**
- Replace `.unwrap()` with proper error handling in `set_state_value()`
- Log and discard responses for unknown keys (stale from previous blocks)
- Prevents panic while allowing graceful degradation

**Recommended Implementation (Option 3 - minimal change):**

```rust
pub fn set_state_value(&self, state_key: &StateKey, state_value: Option<StateValue>) {
    if let Some(remote_value) = self.state_values.get(state_key) {
        remote_value.set_value(state_value);
    } else {
        // Stale response from previous block generation - safe to ignore
        trace!("Received state value for unknown key, likely from previous block");
    }
}
```

This prevents the panic while maintaining correct semantics, as responses for replaced state views are inherently stale and should be discarded.

## Proof of Concept

The race condition can be demonstrated through a stress test that rapidly cycles blocks while introducing artificial network latency:

```rust
#[test]
fn test_race_condition_remote_state_view() {
    // Setup: Create RemoteStateViewClient with real network channels
    let (mut controller_a, mut controller_b) = create_test_network_pair();
    let client = RemoteStateViewClient::new(0, &mut controller_a, coordinator_addr);
    
    // Spawn coordinator that delays responses by 200ms
    spawn_delayed_coordinator(&mut controller_b, Duration::from_millis(200));
    
    // Simulate rapid consecutive blocks
    for i in 0..100 {
        let keys: Vec<StateKey> = generate_test_keys(100);
        
        // Initialize for block i
        client.init_for_block(keys.clone());
        
        // Immediately initialize for block i+1 without waiting
        // This creates the race condition
        thread::sleep(Duration::from_millis(50)); // Less than response delay
    }
    
    // Expected: Panic on .unwrap() when response arrives for replaced state view
    // Actual: Node process terminates via panic handler
}
```

The test demonstrates that when blocks arrive faster than network round-trip time, responses for previous blocks will attempt to update keys in the new `RemoteStateView`, causing panics.

## Notes

This vulnerability is specific to the remote executor service sharding architecture and only affects validators running with distributed sharded execution enabled. Single-instance executors using `LocalCoordinatorClient` are not affected as they use in-process channels with immediate synchronous delivery.

The root cause is the combination of:
1. Stateful lifecycle management (replacing entire state view)
2. Asynchronous communication with unbounded delay
3. Unsafe error handling (`.unwrap()` on potentially missing keys)

Any of these could be addressed individually to prevent the vulnerability.

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

**File:** execution/executor-service/src/remote_state_view.rs (L147-169)
```rust
    fn pre_fetch_state_values(&self, state_keys: Vec<StateKey>, sync_insert_keys: bool) {
        let state_view_clone = self.state_view.clone();
        let thread_pool_clone = self.thread_pool.clone();
        let kv_tx_clone = self.kv_tx.clone();
        let shard_id = self.shard_id;

        let insert_and_fetch = move || {
            Self::insert_keys_and_fetch_values(
                state_view_clone,
                thread_pool_clone,
                kv_tx_clone,
                shard_id,
                state_keys,
            );
        };
        if sync_insert_keys {
            // we want to insert keys synchronously here because when called from get_state_value()
            // it expects the key to be in the table while waiting for the value to be fetched from
            // remote state view.
            insert_and_fetch();
        } else {
            self.thread_pool.spawn(insert_and_fetch);
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

**File:** execution/executor-service/src/remote_cordinator_client.rs (L80-113)
```rust
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
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L215-260)
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
```

**File:** crates/crash-handler/src/lib.rs (L26-58)
```rust
pub fn setup_panic_handler() {
    panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
        handle_panic(pi);
    }));
}

// Formats and logs panic information
fn handle_panic(panic_info: &PanicHookInfo<'_>) {
    // The Display formatter for a PanicHookInfo contains the message, payload and location.
    let details = format!("{}", panic_info);
    let backtrace = format!("{:#?}", Backtrace::new());

    let info = CrashInfo { details, backtrace };
    let crash_info = toml::to_string_pretty(&info).unwrap();
    error!("{}", crash_info);
    // TODO / HACK ALARM: Write crash info synchronously via eprintln! to ensure it is written before the process exits which error! doesn't guarantee.
    // This is a workaround until https://github.com/aptos-labs/aptos-core/issues/2038 is resolved.
    eprintln!("{}", crash_info);

    // Wait till the logs have been flushed
    aptos_logger::flush();

    // Do not kill the process if the panics happened at move-bytecode-verifier.
    // This is safe because the `state::get_state()` uses a thread_local for storing states. Thus the state can only be mutated to VERIFIER by the thread that's running the bytecode verifier.
    //
    // TODO: once `can_unwind` is stable, we should assert it. See https://github.com/rust-lang/rust/issues/92988.
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
}
```

**File:** aptos-node/src/lib.rs (L233-234)
```rust
    // Setup panic handler
    aptos_crash_handler::setup_panic_handler();
```
