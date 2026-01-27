# Audit Report

## Title
Memory Exhaustion via Unbounded Message Queue Size in Network Layer

## Summary
The Aptos network layer implements count-based limits on inbound message queues but lacks size-based memory limits, allowing an attacker to exhaust validator memory by flooding connections with maximum-sized RPC messages. While a single connection is limited to 100 concurrent RPCs (6.4 GiB), the system allows up to 100 inbound connections, enabling memory consumption of up to 640 GiB, far exceeding typical validator specifications (64-256 GB).

## Finding Description

The vulnerability exists in the interaction between three network layer components:

1. **Message Size Limits**: The network layer allows messages up to MAX_MESSAGE_SIZE = 64 MiB. [1](#0-0) 

2. **Per-Connection RPC Limits**: Each peer connection is limited to MAX_CONCURRENT_INBOUND_RPCS = 100 pending RPC tasks. [2](#0-1) 

3. **Connection Limits**: Validators accept up to MAX_INBOUND_CONNECTIONS = 100 concurrent inbound connections. [3](#0-2) 

The InboundRpcs handler enforces the per-connection limit by checking the number of pending tasks before accepting new requests: [4](#0-3) 

However, the actual message data (containing the full raw_request Vec<u8>) is immediately pushed to the application's inbound channel: [5](#0-4) 

The application inbound channels use PerKeyQueue with count-based limits (e.g., 1024 messages for consensus) but no size-based limits: [6](#0-5) 

The RPC request data is stored as Vec<u8> in the NetworkMessage: [7](#0-6) 

**Attack Flow:**
1. Attacker establishes 100 connections (different PeerIds for validator networks, or same for public networks)
2. From each connection, sends 100 maximum-sized (64 MiB) RPC requests rapidly
3. Messages are deserialized from wire into Vec<u8> buffers in memory
4. Each ReceivedMessage containing the full 64 MiB payload is queued in the application channel
5. If the application (consensus, mempool, etc.) is slow to process or under load, messages accumulate
6. Memory consumption: 100 connections × 100 messages × 64 MiB = 640 GiB

The system has no rate limiting enabled by default: [8](#0-7) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria:

- **Validator node crashes**: Memory exhaustion triggers OOM killer, terminating the validator process
- **Loss of liveness**: Crashed validators cannot participate in consensus, reducing network liveness
- **Protocol violations**: If multiple validators are attacked simultaneously, the network may lose quorum

While not directly causing "Total loss of liveness/network availability" (which requires taking down all validators), a coordinated attack on multiple validators could severely degrade network performance or cause temporary consensus failures.

The attack is more severe for public-facing networks (fullnodes, VFN endpoints) where connection authentication is weaker, but still feasible for validator networks if an attacker controls multiple validator identities.

## Likelihood Explanation

**For Public Networks (Fullnodes, VFNs):**
- **Likelihood: High**
- Establishing 100 connections requires no special privileges
- Sending large messages is trivial
- Attack can be executed with basic scripting

**For Validator Networks:**
- **Likelihood: Medium**
- Requires controlling multiple validator identities (up to 100)
- In practice, even 10-20 compromised validators could cause significant memory pressure
- If an attacker has compromised multiple validators' networking keys, this attack is straightforward

**Attack Complexity:** Low - requires only network access and ability to send large messages

**Preconditions:**
- Target validator/node must be accepting inbound connections
- Application layer (consensus/mempool) must be slow enough that messages queue up
- Under normal operation, applications may process messages quickly enough to prevent buildup
- Under load or DoS conditions, processing slows and queues fill

## Recommendation

Implement size-based memory limits on inbound message queues:

```rust
// In aptos_channel Config
pub struct Config {
    pub queue_style: QueueStyle,
    pub max_capacity: usize,
    pub max_total_bytes: Option<usize>,  // NEW: Total byte limit
    pub counters: Option<&'static IntCounterVec>,
}

// In PerKeyQueue
pub(crate) struct PerKeyQueue<K: Eq + Hash + Clone, T> {
    // ... existing fields ...
    max_total_bytes: Option<usize>,
    current_total_bytes: usize,
}

// Modify push to track bytes
pub(crate) fn push(&mut self, key: K, message: T) -> Option<T> 
where T: MessageWithSize {
    let message_size = message.size();
    
    // Check byte limit before count limit
    if let Some(max_bytes) = self.max_total_bytes {
        if self.current_total_bytes + message_size > max_bytes {
            // Drop message or oldest message based on queue style
            // Update metrics
            return Some(message);
        }
    }
    
    // ... existing count-based logic ...
    self.current_total_bytes += message_size;
    None
}
```

Additionally:
1. Enable rate limiting by default on validator networks
2. Implement admission control based on peer reputation
3. Add metrics for queue memory consumption
4. Consider implementing streaming RPC for large messages instead of buffering entirely
5. Set reasonable limits like max 10 GB total per application inbound queue

## Proof of Concept

```rust
// Rust test to demonstrate memory exhaustion
#[tokio::test]
async fn test_memory_exhaustion_attack() {
    const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; // 64 MiB
    const NUM_CONNECTIONS: usize = 100;
    const MSGS_PER_CONNECTION: usize = 100;
    
    // Setup validator node with network endpoints
    let (validator, network_handles) = setup_test_validator().await;
    
    // Track initial memory usage
    let initial_memory = get_process_memory();
    
    // Launch attack: establish multiple connections
    let mut attack_tasks = vec![];
    for peer_id in 0..NUM_CONNECTIONS {
        let handle = network_handles.clone();
        let task = tokio::spawn(async move {
            // Connect as unique peer
            let connection = connect_to_validator(peer_id, &handle).await;
            
            // Flood with max-sized RPC requests
            for _ in 0..MSGS_PER_CONNECTION {
                let large_payload = vec![0u8; MAX_MESSAGE_SIZE];
                let rpc_request = create_rpc_request(
                    ProtocolId::ConsensusRpcBcs,
                    large_payload,
                );
                
                // Send without waiting for response
                let _ = connection.send_rpc(rpc_request).await;
                
                // Small delay to avoid immediate backpressure
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        attack_tasks.push(task);
    }
    
    // Wait for all attack tasks
    for task in attack_tasks {
        task.await.unwrap();
    }
    
    // Measure memory consumption
    tokio::time::sleep(Duration::from_secs(5)).await;
    let final_memory = get_process_memory();
    let memory_consumed = final_memory - initial_memory;
    
    // Expected: ~640 GiB consumed (or node OOM killed before this point)
    // Actual typical validator: 64-256 GB RAM, leading to crash
    println!("Memory consumed: {} GiB", memory_consumed / (1024 * 1024 * 1024));
    
    // Verify node is still responsive (it shouldn't be)
    let is_alive = check_validator_liveness(&validator).await;
    assert!(!is_alive, "Validator should have crashed from OOM");
}
```

**Notes:**
- The vulnerability breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits"
- The network layer should enforce memory limits in addition to message count limits
- This is particularly critical for DDoS resistance and network stability under adversarial conditions

### Citations

**File:** network/framework/src/constants.rs (L15-15)
```rust
pub const MAX_CONCURRENT_INBOUND_RPCS: u32 = 100;
```

**File:** network/framework/src/constants.rs (L21-21)
```rust
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** config/src/config/network_config.rs (L44-44)
```rust
pub const MAX_INBOUND_CONNECTIONS: usize = 100;
```

**File:** config/src/config/network_config.rs (L158-159)
```rust
            inbound_rate_limit_config: None,
            outbound_rate_limit_config: None,
```

**File:** network/framework/src/protocols/rpc/mod.rs (L212-223)
```rust
        // Drop new inbound requests if our completion queue is at capacity.
        if self.inbound_rpc_tasks.len() as u32 == self.max_concurrent_inbound_rpcs {
            // Increase counter of declined requests
            counters::rpc_messages(
                network_context,
                REQUEST_LABEL,
                INBOUND_LABEL,
                DECLINED_LABEL,
            )
            .inc();
            return Err(RpcError::TooManyPending(self.max_concurrent_inbound_rpcs));
        }
```

**File:** network/framework/src/protocols/rpc/mod.rs (L246-253)
```rust
        // Forward request to PeerManager for handling.
        let (response_tx, response_rx) = oneshot::channel();
        request.rpc_replier = Some(Arc::new(response_tx));
        if let Err(err) = peer_notifs_tx.push((peer_id, protocol_id), request) {
            counters::rpc_messages(network_context, REQUEST_LABEL, INBOUND_LABEL, FAILED_LABEL)
                .inc();
            return Err(err.into());
        }
```

**File:** crates/channel/src/message_queues.rs (L134-150)
```rust
        if key_message_queue.len() >= self.max_queue_size.get() {
            if let Some(c) = self.counters.as_ref() {
                c.with_label_values(&["dropped"]).inc();
            }
            match self.queue_style {
                // Drop the newest message for FIFO
                QueueStyle::FIFO => Some(message),
                // Drop the oldest message for LIFO
                QueueStyle::LIFO | QueueStyle::KLAST => {
                    let oldest = key_message_queue.pop_front();
                    key_message_queue.push_back(message);
                    oldest
                },
            }
        } else {
            key_message_queue.push_back(message);
            None
```

**File:** network/framework/src/protocols/wire/messaging/v1/mod.rs (L118-128)
```rust
pub struct RpcRequest {
    /// `protocol_id` is a variant of the ProtocolId enum.
    pub protocol_id: ProtocolId,
    /// RequestId for the RPC Request.
    pub request_id: RequestId,
    /// Request priority in the range 0..=255.
    pub priority: Priority,
    /// Request payload. This will be parsed by the application-level handler.
    #[serde(with = "serde_bytes")]
    pub raw_request: Vec<u8>,
}
```
