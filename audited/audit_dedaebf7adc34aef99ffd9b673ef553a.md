# Audit Report

## Title
Unbounded BCS Serialization in Remote State View Service Enables Memory Exhaustion Attack

## Summary
The `RemoteStateViewService` in the executor-service lacks bounds checking on BCS serialization output size before attempting to serialize state value responses. An attacker can craft transactions that access many large state values, causing the remote executor coordinator to allocate excessive memory during serialization, potentially leading to out-of-memory conditions and denial of service.

## Finding Description

The `kv_resp_ser` metric tracks BCS serialization of remote key-value responses in the sharded block executor system. The vulnerability exists in the `handle_message` function where state value responses are serialized without validating the total output size beforehand. [1](#0-0) 

The code fetches all requested state values and serializes them using `bcs::to_bytes()` without any size validation. Each state value can be up to 1MB in size as enforced by the gas schedule's `max_bytes_per_write_op` parameter. [2](#0-1) 

The client-side batching uses `REMOTE_STATE_KEY_BATCH_SIZE = 200` keys per request: [3](#0-2) [4](#0-3) 

However, the server does not enforce this limit. The `RemoteKVRequest` structure contains an unbounded vector of state keys: [5](#0-4) 

While the gRPC network layer has a `MAX_MESSAGE_SIZE` limit of 80MB: [6](#0-5) 

This limit is only enforced **after** serialization completes, meaning memory allocation occurs before the size check.

**Attack Path:**
1. Attacker submits transactions that create many state values near the 1MB limit (costs gas but feasible)
2. Attacker crafts subsequent transactions that read these large state values
3. During sharded block execution, remote shards request these values from the coordinator
4. Coordinator's `RemoteStateViewService` fetches all values (200 keys × 1MB = 200MB potential)
5. `bcs::to_bytes()` attempts to serialize the entire 200MB response, allocating memory
6. gRPC layer rejects the oversized message (>80MB), but memory exhaustion has already occurred
7. Multiple concurrent requests amplify the impact, potentially causing OOM

The Rust BCS library provides `bcs::to_bytes_with_limit()` for bounded serialization, but the code uses the unbounded variant.

## Impact Explanation

This vulnerability breaks the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits."

**Impact Classification: High Severity** ("Validator node slowdowns")

The coordinator node performing block execution can experience:
- Memory exhaustion from allocating 200MB+ per oversized request
- CPU waste on serialization that will ultimately fail at the network layer
- Potential out-of-memory crashes under concurrent load
- Degraded validator performance affecting block production

While state values are created through legitimate gas-paying transactions (limiting the attack cost), the amplification occurs during serialization where a single batch request can trigger 200MB+ allocation without proportional resource charging.

## Likelihood Explanation

**Likelihood: Medium-High**

Prerequisites for exploitation:
1. **Cost**: Creating 200 state values at ~1MB each requires significant gas expenditure (~200 transactions with storage fees), but remains economically feasible for a determined attacker
2. **Trigger**: Transactions that access many large state values will naturally trigger batched remote requests during sharded execution
3. **Amplification**: A single malicious transaction accessing 200 large values can cause 200MB serialization attempts
4. **Concurrency**: Multiple concurrent blocks executing similar transactions multiply the memory pressure

The attack does not require validator privileges - any transaction sender can craft transactions that, when executed in sharded mode, trigger this vulnerability.

## Recommendation

Implement pre-serialization size validation to prevent unbounded memory allocation:

```rust
pub fn handle_message(
    message: Message,
    state_view: Arc<RwLock<Option<Arc<S>>>>,
    kv_tx: Arc<Vec<Sender<Message>>>,
) {
    // ... existing deserialization code ...
    
    let resp = state_keys
        .into_iter()
        .map(|state_key| {
            let state_value = state_view
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .get_state_value(&state_key)
                .unwrap();
            (state_key, state_value)
        })
        .collect_vec();
    
    // ADD: Validate total response size before serialization
    const MAX_RESPONSE_SIZE: usize = 80 * 1024 * 1024; // 80MB (gRPC limit)
    const MAX_KEYS_PER_REQUEST: usize = 200; // Enforce batch limit
    
    if resp.len() > MAX_KEYS_PER_REQUEST {
        error!("Request exceeds maximum keys: {} > {}", resp.len(), MAX_KEYS_PER_REQUEST);
        return; // Or send error response
    }
    
    let estimated_size: usize = resp.iter()
        .map(|(key, value_opt)| {
            key.size() + value_opt.as_ref().map_or(0, |v| v.size())
        })
        .sum();
    
    if estimated_size > MAX_RESPONSE_SIZE {
        error!("Response size exceeds limit: {} > {}", estimated_size, MAX_RESPONSE_SIZE);
        return; // Or send error response with size limit
    }
    
    let resp = RemoteKVResponse::new(resp);
    
    // Use bounded serialization as defense-in-depth
    let resp = bcs::to_bytes_with_limit(&resp, MAX_RESPONSE_SIZE)
        .expect("Serialization failed despite size check");
    
    // ... rest of the function ...
}
```

Additionally, validate the number of requested keys during deserialization to prevent malicious clients from bypassing the batch size limit.

## Proof of Concept

```rust
#[cfg(test)]
mod memory_exhaustion_test {
    use super::*;
    use aptos_types::state_store::{
        state_key::StateKey, state_value::StateValue,
    };
    use std::sync::{Arc, RwLock};
    
    #[test]
    fn test_unbounded_serialization_memory_allocation() {
        // Create a mock state view with 200 large state values (1MB each)
        let mut mock_state = std::collections::HashMap::new();
        let large_value = vec![0u8; 1024 * 1024]; // 1MB
        
        for i in 0..200 {
            let key = StateKey::raw(format!("key_{}", i).as_bytes());
            let value = StateValue::from(large_value.clone());
            mock_state.insert(key.clone(), Some(value));
        }
        
        // Create RemoteKVRequest with 200 keys
        let keys: Vec<StateKey> = mock_state.keys().cloned().collect();
        let request = RemoteKVRequest::new(0, keys);
        
        // Serialize request
        let request_bytes = bcs::to_bytes(&request).unwrap();
        assert!(request_bytes.len() < 1024 * 1024); // Request is small
        
        // Simulate server-side processing
        let values: Vec<(StateKey, Option<StateValue>)> = mock_state
            .into_iter()
            .collect();
        let response = RemoteKVResponse::new(values);
        
        // This serialization will attempt to allocate ~200MB
        let result = bcs::to_bytes(&response);
        
        // The serialization succeeds but allocates huge memory
        assert!(result.is_ok());
        let response_bytes = result.unwrap();
        
        // Response is approximately 200MB (exceeds 80MB gRPC limit)
        assert!(response_bytes.len() > 80 * 1024 * 1024);
        println!("Serialized response size: {} MB", response_bytes.len() / (1024 * 1024));
        
        // This demonstrates unbounded memory allocation before network-layer validation
    }
}
```

## Notes

This vulnerability demonstrates a defense-in-depth failure where the server trusts client-side batching limits without server-side enforcement. While individual state values are properly bounded at write time through gas schedule limits, the aggregate serialization size is not validated before memory allocation. The gRPC layer's 80MB limit provides eventual rejection but only after potentially excessive memory consumption has occurred.

### Citations

**File:** execution/executor-service/src/remote_state_view_service.rs (L95-113)
```rust
        let resp = state_keys
            .into_iter()
            .map(|state_key| {
                let state_value = state_view
                    .read()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .get_state_value(&state_key)
                    .unwrap();
                (state_key, state_value)
            })
            .collect_vec();
        let len = resp.len();
        let resp = RemoteKVResponse::new(resp);
        let bcs_ser_timer = REMOTE_EXECUTOR_TIMER
            .with_label_values(&["0", "kv_resp_ser"])
            .start_timer();
        let resp = bcs::to_bytes(&resp).unwrap();
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L154-157)
```rust
            max_bytes_per_write_op: NumBytes,
            { 5.. => "max_bytes_per_write_op" },
            1 << 20, // a single state item is 1MB max
        ],
```

**File:** execution/executor-service/src/remote_state_view.rs (L27-27)
```rust
pub static REMOTE_STATE_KEY_BATCH_SIZE: usize = 200;
```

**File:** execution/executor-service/src/remote_state_view.rs (L136-144)
```rust
        state_keys
            .chunks(REMOTE_STATE_KEY_BATCH_SIZE)
            .map(|state_keys_chunk| state_keys_chunk.to_vec())
            .for_each(|state_keys| {
                let sender = kv_tx.clone();
                thread_pool.spawn(move || {
                    Self::send_state_value_request(shard_id, sender, state_keys);
                });
            });
```

**File:** execution/executor-service/src/lib.rs (L68-81)
```rust
pub struct RemoteKVRequest {
    pub(crate) shard_id: ShardId,
    pub(crate) keys: Vec<StateKey>,
}

impl RemoteKVRequest {
    pub fn new(shard_id: ShardId, keys: Vec<StateKey>) -> Self {
        Self { shard_id, keys }
    }

    pub fn into(self) -> (ShardId, Vec<StateKey>) {
        (self.shard_id, self.keys)
    }
}
```

**File:** secure/net/src/grpc_network_service/mod.rs (L23-23)
```rust
const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 80;
```
