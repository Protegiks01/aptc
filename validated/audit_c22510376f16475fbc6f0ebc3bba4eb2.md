# Audit Report

## Title
Mutex Poisoning in gRPC Network Service Causes Permanent Node DoS

## Summary
The `simple_msg_exchange()` function in the gRPC network service contains a critical Mutex poisoning vulnerability. When a channel receiver is dropped but its sender remains registered in `inbound_handlers`, any incoming message triggers a panic while holding the shared Mutex lock. This permanently poisons the Mutex, causing all subsequent message processing for all message types to fail, resulting in a complete and permanent denial of service that requires node restart.

## Finding Description

The vulnerability exists in the message routing logic where the MutexGuard is held during the channel send operation: [1](#0-0) 

Due to Rust's temporary lifetime extension rules, the `MutexGuard` returned by `lock().unwrap()` is kept alive for the entire `if let` block because the reference `handler` borrows from it. This means the Mutex lock is held during the `handler.send(msg).unwrap()` call.

When a crossbeam channel receiver is dropped, subsequent `send()` operations return `SendError`. The `.unwrap()` call panics on this error while the thread holds the `inbound_handlers` Mutex lock. According to Rust's panic semantics, when a thread panics while holding a Mutex lock, the Mutex becomes poisoned. All future `lock().unwrap()` calls on this poisoned Mutex will panic, cascading the failure to all message types since they share the same Mutex.

**Attack Path:**

1. The `NetworkController` creates inbound channels for message routing: [2](#0-1) 

2. Components like `RemoteCoordinatorClient` receive these channel receivers: [3](#0-2) 

And `RemoteCrossShardClient`: [4](#0-3) 

3. If any component drops its receiver (due to panic, error handling, or early shutdown) while the NetworkController's gRPC server is still running, the channel closes but the sender remains in `inbound_handlers`

4. When a new message arrives for that message type, `simple_msg_exchange()` attempts to send, panics, and poisons the Mutex

5. All subsequent messages (of any type) fail permanently because the Mutex is poisoned

The same vulnerability exists in a second location: [5](#0-4) 

## Impact Explanation

This is **HIGH severity** per Aptos bug bounty criteria:

- **Validator node slowdowns**: The affected node cannot process any network messages, effectively removing it from the network. This aligns with the HIGH severity category "Validator Node Slowdowns (High): DoS through resource exhaustion"

- **API crashes**: All gRPC message handling crashes after the first panic. This aligns with the HIGH severity category "API Crashes (High): REST API crashes affecting network participation"

- **Significant protocol violations**: Breaks the availability invariant for network communication

The vulnerability affects the `ExecutorService` used for sharded block execution: [6](#0-5) 

Once triggered, the node requires a full restart to recover, as there is no runtime mechanism to clear Mutex poisoning. This converts a local component failure into a complete node failure.

## Likelihood Explanation

**MEDIUM-HIGH likelihood:**

- **Trigger conditions are realistic**: Component panics, error handling paths, or race conditions during shutdown can all cause receivers to be dropped
- **No special privileges required**: Any condition that drops a receiver while the network service is running will trigger it
- **Cascading failure**: A single panic in any message handler permanently disables the entire node's network layer
- **Production scenarios**: Thread panics, out-of-memory conditions, or bugs in executor service logic can trigger this

The vulnerability is particularly dangerous because it converts a local component failure into a complete node failure. The gRPC server remains running but cannot process any messages.

## Recommendation

Replace the `.unwrap()` pattern with proper error handling that doesn't panic while holding the mutex lock. The fix should:

1. Release the mutex lock before handling the send error
2. Handle poisoned mutex errors gracefully instead of panicking
3. Log and recover from channel disconnections

Example fix for `simple_msg_exchange()`:
```rust
let handler = {
    let guard = match self.inbound_handlers.lock() {
        Ok(g) => g,
        Err(poisoned) => {
            error!("Mutex poisoned, recovering...");
            poisoned.into_inner()
        }
    };
    guard.get(&message_type).cloned()
};

if let Some(handler) = handler {
    if let Err(e) = handler.send(msg) {
        error!("Failed to send message to handler: {:?}", e);
    }
} else {
    error!("No handler registered for msg type {:?}", message_type);
}
```

## Proof of Concept

The vulnerability can be demonstrated by:

1. Starting a `NetworkController` with registered handlers
2. Dropping one of the receiver channels
3. Sending a message for that message type through the gRPC service
4. Observing the panic and subsequent failure of all message processing

While a complete runnable PoC is not provided here, the vulnerability is clearly observable in the code structure and can be triggered through component lifecycle events (panics, early termination, error conditions) that cause receivers to be dropped while the gRPC server continues running.

### Citations

**File:** secure/net/src/grpc_network_service/mod.rs (L105-107)
```rust
        if let Some(handler) = self.inbound_handlers.lock().unwrap().get(&message_type) {
            // Send the message to the registered handler
            handler.send(msg).unwrap();
```

**File:** secure/net/src/network_controller/mod.rs (L128-137)
```rust
    pub fn create_inbound_channel(&mut self, message_type: String) -> Receiver<Message> {
        let (inbound_sender, inbound_receiver) = unbounded();

        self.inbound_handler
            .lock()
            .unwrap()
            .register_handler(message_type, inbound_sender);

        inbound_receiver
    }
```

**File:** execution/executor-service/src/remote_cordinator_client.rs (L32-36)
```rust
        let execute_command_type = format!("execute_command_{}", shard_id);
        let execute_result_type = format!("execute_result_{}", shard_id);
        let command_rx = controller.create_inbound_channel(execute_command_type);
        let result_tx =
            controller.create_outbound_channel(coordinator_address, execute_result_type);
```

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L36-41)
```rust
        // Create inbound channels for each round
        for round in 0..MAX_ALLOWED_PARTITIONING_ROUNDS {
            let message_type = format!("cross_shard_{}", round);
            let rx = controller.create_inbound_channel(message_type);
            message_rxs.push(Mutex::new(rx));
        }
```

**File:** secure/net/src/network_controller/inbound_handler.rs (L68-70)
```rust
        if let Some(handler) = self.inbound_handlers.lock().unwrap().get(message_type) {
            // Send the message to the registered handler
            handler.send(message).unwrap();
```

**File:** execution/executor-service/src/remote_executor_service.rs (L15-19)
```rust
pub struct ExecutorService {
    shard_id: ShardId,
    controller: NetworkController,
    executor_service: Arc<ShardedExecutorService<RemoteStateViewClient>>,
}
```
