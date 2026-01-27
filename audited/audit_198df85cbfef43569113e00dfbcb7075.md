# Audit Report

## Title
Unbounded Shard ID in Network Messages Causes Array Index Out of Bounds and Node Crash

## Summary
The `RemoteStateViewService::handle_message()` function deserializes untrusted network messages containing a `shard_id` field and directly uses it to index an array without bounds validation, allowing any network peer to crash validator nodes by sending messages with out-of-range shard IDs.

## Finding Description

The Aptos executor service implements a remote state view protocol where nodes can request key-value data from other shards via network messages. The vulnerability exists in the message handling path: [1](#0-0) 

The `RemoteKVRequest` structure contains a `shard_id` field defined as `ShardId` (which is a type alias for `usize`): [2](#0-1) [3](#0-2) 

After deserialization, the `shard_id` is extracted and used directly as an array index without validation: [4](#0-3) [5](#0-4) 

The `kv_tx` array is initialized with a length equal to the number of configured remote shard addresses, which typically matches `NUM_STATE_SHARDS` (16): [6](#0-5) 

**Attack Path:**
1. Attacker establishes network connection to victim validator node
2. Attacker sends a BCS-encoded `RemoteKVRequest` message with `shard_id = 1000` (or any value >= 16)
3. Victim node deserializes the message without validation
4. At line 121, the code attempts `kv_tx[1000].send(message)`
5. Rust panics with "index out of bounds: the len is 16 but the index is 1000"
6. The node crashes, causing denial of service

This violates the **Network Protocol Security** invariant - untrusted network inputs must be validated before use. The codebase shows awareness of this requirement in configuration parsing: [7](#0-6) 

However, this validation is missing from the network message handling path.

## Impact Explanation

This vulnerability allows **any network peer** (not just validators) to crash remote executor service nodes by sending a single malformed message. This falls under **High Severity** per the Aptos bug bounty program:

- **Validator node crashes**: Direct node crash via panic
- **API crashes**: Service becomes unavailable
- **Availability impact**: Affects network liveness if multiple nodes are targeted

While this doesn't directly compromise consensus safety or cause fund loss, it enables:
1. Targeted DoS attacks on specific validator nodes
2. Network-wide availability degradation if attackers target multiple nodes
3. Potential consensus liveness issues if sufficient validators are crashed during critical operations

The architectural constraint that sharding is based on nibbles (0-15) is documented in the codebase: [8](#0-7) [9](#0-8) 

This shows that `shard_id` values must be in range [0, 16), but this constraint is not enforced at network message deserialization boundaries.

## Likelihood Explanation

**Likelihood: HIGH**

- **Attacker Requirements**: Any network peer can send messages to executor service nodes
- **Exploit Complexity**: Trivial - just craft a BCS-encoded message with `shard_id >= 16`
- **Detection Difficulty**: Crashes are immediately visible but attacker attribution is difficult
- **Reproducibility**: 100% reliable - every malformed message causes a crash

The exploit requires no special privileges, no validator access, and no sophisticated cryptographic attacks. A simple Python script using BCS encoding can generate the attack message.

## Recommendation

Add bounds validation immediately after deserializing the `shard_id` from network messages:

```rust
pub fn handle_message(
    message: Message,
    state_view: Arc<RwLock<Option<Arc<S>>>>,
    kv_tx: Arc<Vec<Sender<Message>>>,
) {
    let _timer = REMOTE_EXECUTOR_TIMER
        .with_label_values(&["0", "kv_requests"])
        .start_timer();
    let bcs_deser_timer = REMOTE_EXECUTOR_TIMER
        .with_label_values(&["0", "kv_req_deser"])
        .start_timer();
    let req: RemoteKVRequest = bcs::from_bytes(&message.data).unwrap();
    drop(bcs_deser_timer);

    let (shard_id, state_keys) = req.into();
    
    // ADD VALIDATION HERE
    if shard_id >= kv_tx.len() {
        warn!(
            "Received invalid shard_id {} from network, expected < {}. Ignoring message.",
            shard_id,
            kv_tx.len()
        );
        return;
    }
    
    trace!(
        "remote state view service - received request for shard {} with {} keys",
        shard_id,
        state_keys.len()
    );
    // ... rest of function
}
```

Additionally, consider:
1. Using a bounded type for `ShardId` in network messages (e.g., `u8` with validation)
2. Adding similar validation to `RemoteCrossShardClient::send_cross_shard_msg()` where `shard_id` is used to index arrays
3. Creating a centralized validation function for shard_id values across the codebase

## Proof of Concept

```rust
#[test]
fn test_invalid_shard_id_causes_panic() {
    use aptos_types::state_store::state_key::StateKey;
    use crate::{RemoteKVRequest};
    
    // Create a malicious request with shard_id = 100 (out of bounds)
    let malicious_request = RemoteKVRequest::new(
        100,  // shard_id >> 16 (NUM_STATE_SHARDS)
        vec![StateKey::raw(b"test_key".to_vec())]
    );
    
    // Serialize it as would be sent over network
    let serialized = bcs::to_bytes(&malicious_request).unwrap();
    
    // Create a mock network controller with 16 shard addresses
    let shard_addresses: Vec<SocketAddr> = (0..16)
        .map(|i| format!("127.0.0.1:{}", 8000 + i).parse().unwrap())
        .collect();
    
    let mut controller = NetworkController::new(/* ... */);
    let service = RemoteStateViewService::new(
        &mut controller,
        shard_addresses,
        Some(1)
    );
    
    // Simulate receiving the malicious message
    let message = Message::new(serialized);
    
    // This will panic with "index out of bounds"
    // In production, this causes the entire node to crash
    RemoteStateViewService::handle_message(
        message,
        service.state_view.clone(),
        service.kv_tx.clone()
    );
    
    // Test never reaches here due to panic
}
```

**Notes**

While the codebase consistently uses `NUM_STATE_SHARDS = 16` throughout storage and state management layers, the vulnerability exists at the network protocol boundary where external, untrusted shard_id values enter the system without validation. The hardcoded value `16` appears in multiple array initializations, but the core issue is that network message deserialization bypasses the architectural constraint that shard IDs must correspond to valid nibble values (0-15).

### Citations

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

**File:** execution/executor-service/src/lib.rs (L68-71)
```rust
pub struct RemoteKVRequest {
    pub(crate) shard_id: ShardId,
    pub(crate) keys: Vec<StateKey>,
}
```

**File:** config/src/config/storage_config.rs (L65-68)
```rust
                ensure!(
                    shard_id < 16,
                    "Shard id ({shard_id}) is out of range [0, 16)."
                );
```

**File:** storage/jellyfish-merkle/src/lib.rs (L376-379)
```rust
        // We currently assume 16 shards in total, therefore the nibble path for the shard root
        // contains exact 1 nibble which is the shard id. `shard_id << 4` here is to put the shard
        // id as the first nibble of the first byte.
        let shard_root_nibble_path = NibblePath::new_odd(vec![shard_id << 4]);
```

**File:** types/src/nibble/mod.rs (L30-30)
```rust
        assert!(nibble < 16, "Nibble out of range: {}", nibble);
```
