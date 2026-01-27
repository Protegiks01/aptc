# Audit Report

## Title
Out-of-Bounds Array Access in RemoteStateViewService Message Routing Enables Denial of Service

## Summary
The `RemoteStateViewService::handle_message()` function uses an untrusted `shard_id` value from network messages as an array index without bounds validation, causing a panic when the `shard_id` exceeds the number of configured remote shards. This allows unauthenticated network attackers to crash the remote state view service and disrupt block execution.

## Finding Description

The security question asks whether `create_outbound_channel()` can fail causing partial initialization. Investigation reveals that `create_outbound_channel()` **cannot fail** - it always returns a valid `Sender<Message>` as the underlying `unbounded()` channel creation never fails. [1](#0-0) 

However, analysis of the message routing at line 121 reveals a **different critical vulnerability**: the `shard_id` extracted from incoming network messages is used as an array index without bounds checking.

The vulnerable code path is:

1. **Channel Creation (lines 40-45)**: Creates a vector of senders with length equal to `remote_shard_addresses.len()` [2](#0-1) 

2. **Message Deserialization (line 86)**: Deserializes `RemoteKVRequest` from untrusted network input [3](#0-2) 

3. **Shard ID Extraction (line 89)**: Extracts `shard_id` without validation [4](#0-3) 

4. **Unchecked Array Access (line 121)**: Uses `shard_id` directly as array index [5](#0-4) 

Since `ShardId` is defined as `usize`, an attacker can send arbitrary values: [6](#0-5) 

The GRPC network service accepts messages without authentication: [7](#0-6) 

**Attack Path:**
1. Attacker crafts `RemoteKVRequest` with `shard_id = usize::MAX` or any value `>= kv_tx.len()`
2. Serializes using BCS and sends to coordinator's GRPC endpoint on "remote_kv_request" message type
3. Service deserializes request and attempts `kv_tx[shard_id]`
4. Rust panics with out-of-bounds array access, crashing the service thread

This service is used for block execution when remote addresses are configured: [8](#0-7) 

## Impact Explanation

**Severity: High** per Aptos bug bounty criteria ("API crashes")

- **Availability Impact**: Crashes the `RemoteStateViewService` which handles state key-value requests for sharded block execution
- **Scope**: Affects validators using remote/distributed execution mode (when `get_remote_addresses()` returns non-empty)
- **Ease of Exploitation**: Trivial - single malicious message causes crash
- **No Authentication**: GRPC service accepts messages from any network peer
- **Violation**: Breaks resource limits invariant - allows unlimited service crashes

While not all validators may use remote execution, those that do would experience complete block processing failure.

## Likelihood Explanation

**Likelihood: Medium**

**Requirements for exploitation:**
- Attacker must reach the coordinator's GRPC endpoint (network connectivity)
- No authentication or authorization required
- Single crafted message sufficient

**Limiting factors:**
- Remote execution must be configured (`set_remote_addresses()` called with non-empty list)
- Not all deployments use distributed execution
- Typically used in performance-optimized setups

**Ease of attack:**
- Very simple to execute
- No complex setup or timing requirements
- Deterministic outcome

## Recommendation

Add bounds checking before using `shard_id` as an array index:

```rust
pub fn handle_message(
    message: Message,
    state_view: Arc<RwLock<Option<Arc<S>>>>,
    kv_tx: Arc<Vec<Sender<Message>>>,
) {
    // ... existing deserialization code ...
    let (shard_id, state_keys) = req.into();
    
    // ADD BOUNDS CHECK
    if shard_id >= kv_tx.len() {
        warn!(
            "Invalid shard_id {} received, expected < {}. Ignoring request.",
            shard_id,
            kv_tx.len()
        );
        return;
    }
    
    // ... rest of function ...
    kv_tx[shard_id].send(message).unwrap();
}
```

Additionally, consider adding authentication to the GRPC service to prevent unauthorized access.

## Proof of Concept

```rust
#[cfg(test)]
mod exploit_test {
    use super::*;
    use aptos_secure_net::network_controller::NetworkController;
    use aptos_config::utils;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    
    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn test_out_of_bounds_shard_id_causes_panic() {
        // Setup coordinator with 2 shards
        let coordinator_port = utils::get_available_port();
        let coordinator_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST), 
            coordinator_port
        );
        
        let shard_addrs = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), utils::get_available_port()),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), utils::get_available_port()),
        ];
        
        let mut controller = NetworkController::new(
            "test-coordinator".to_string(),
            coordinator_addr,
            5000,
        );
        
        let service = RemoteStateViewService::<CachedStateView>::new(
            &mut controller,
            shard_addrs.clone(),
            None,
        );
        
        // Craft malicious request with out-of-bounds shard_id
        let malicious_shard_id: usize = 999; // Far exceeds kv_tx.len() = 2
        let request = RemoteKVRequest::new(malicious_shard_id, vec![]);
        let message = Message::new(bcs::to_bytes(&request).unwrap());
        
        // This will panic with index out of bounds
        RemoteStateViewService::<CachedStateView>::handle_message(
            message,
            service.state_view.clone(),
            service.kv_tx.clone(),
        );
    }
}
```

**Notes:**
- The original question asked if `create_outbound_channel()` could fail causing partial initialization. Investigation shows it cannot fail (always succeeds).
- However, the same code location (line 121) contains a different vulnerability: missing bounds validation on the `shard_id` used for array indexing.
- This demonstrates the importance of thorough code review beyond the specific concern raised - the area was correctly identified as security-sensitive, just for a different reason than initially suspected.

### Citations

**File:** secure/net/src/network_controller/mod.rs (L115-126)
```rust
    pub fn create_outbound_channel(
        &mut self,
        remote_peer_addr: SocketAddr,
        message_type: String,
    ) -> Sender<Message> {
        let (outbound_sender, outbound_receiver) = unbounded();

        self.outbound_handler
            .register_handler(message_type, remote_peer_addr, outbound_receiver);

        outbound_sender
    }
```

**File:** execution/executor-service/src/remote_state_view_service.rs (L40-45)
```rust
        let command_txs = remote_shard_addresses
            .iter()
            .map(|address| {
                controller.create_outbound_channel(*address, kv_response_type.to_string())
            })
            .collect_vec();
```

**File:** execution/executor-service/src/remote_state_view_service.rs (L86-86)
```rust
        let req: RemoteKVRequest = bcs::from_bytes(&message.data).unwrap();
```

**File:** execution/executor-service/src/remote_state_view_service.rs (L89-89)
```rust
        let (shard_id, state_keys) = req.into();
```

**File:** execution/executor-service/src/remote_state_view_service.rs (L121-121)
```rust
        kv_tx[shard_id].send(message).unwrap();
```

**File:** types/src/block_executor/partitioner.rs (L16-16)
```rust
pub type ShardId = usize;
```

**File:** secure/net/src/grpc_network_service/mod.rs (L93-115)
```rust
    async fn simple_msg_exchange(
        &self,
        request: Request<NetworkMessage>,
    ) -> Result<Response<Empty>, Status> {
        let _timer = NETWORK_HANDLER_TIMER
            .with_label_values(&[&self.self_addr.to_string(), "inbound_msgs"])
            .start_timer();
        let remote_addr = request.remote_addr();
        let network_message = request.into_inner();
        let msg = Message::new(network_message.message);
        let message_type = MessageType::new(network_message.message_type);

        if let Some(handler) = self.inbound_handlers.lock().unwrap().get(&message_type) {
            // Send the message to the registered handler
            handler.send(msg).unwrap();
        } else {
            error!(
                "No handler registered for sender: {:?} and msg type {:?}",
                remote_addr, message_type
            );
        }
        Ok(Response::new(Empty {}))
    }
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L261-267)
```rust
        if !get_remote_addresses().is_empty() {
            Ok(V::execute_block_sharded(
                &REMOTE_SHARDED_BLOCK_EXECUTOR.lock(),
                partitioned_txns,
                state_view,
                onchain_config,
            )?)
```
