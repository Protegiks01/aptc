# Audit Report

## Title
Unchecked Shard ID Array Indexing Enables Service DoS and Response Misdirection in Remote State View Service

## Summary
The `handle_message()` function in `RemoteStateViewService` uses a shard_id field from deserialized, untrusted network data as an array index without bounds checking, allowing a malicious node to crash the service via out-of-bounds access or cause response misdirection by routing state values to incorrect shards.

## Finding Description

The vulnerability exists in the remote state view service's message handling logic. When the service receives a `RemoteKVRequest` over the network, it deserializes the request and extracts a `shard_id` field that indicates which shard should receive the response. [1](#0-0) 

The extracted `shard_id` is then used directly as an array index into the `kv_tx` vector without any validation: [2](#0-1) 

The `kv_tx` vector is constructed with a fixed length equal to the number of configured remote shard addresses: [3](#0-2) 

Since `ShardId` is defined as a type alias for `usize`, an attacker can supply any arbitrary value: [4](#0-3) 

**Attack Scenario 1 - Out of Bounds DoS:**
A malicious or compromised shard sends a `RemoteKVRequest` with `shard_id >= kv_tx.len()`. This causes an index-out-of-bounds panic in the service thread, crashing the state view service and blocking all shards from fetching state values needed for execution.

**Attack Scenario 2 - Response Misdirection:**
A malicious shard A sends a request but sets `shard_id = B` (where B is a valid but different shard). The response containing state values requested by shard A is routed to shard B instead. This causes:
- Shard B to crash when attempting to set values for state keys it never requested (the `unwrap()` in `set_state_value` panics)
- Shard A to hang indefinitely waiting for a response that never arrives
- Block execution to fail across all shards [5](#0-4) 

The vulnerability breaks the **Deterministic Execution** and **State Consistency** invariants, as shards cannot reliably fetch the state values they need for transaction execution.

This service is actively used in production when remote addresses are configured: [6](#0-5) 

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under the Aptos bug bounty criteria:

1. **Validator node slowdowns**: A single malicious request can crash the state view service, forcing all executor shards to wait indefinitely for state values, severely degrading validator performance.

2. **API crashes**: The unchecked array access causes panic crashes in the service thread, meeting the "API crashes" criterion.

3. **Significant protocol violations**: Block execution cannot proceed without state values, violating the protocol's liveness guarantees and potentially causing validators to fall out of sync.

While not reaching Critical severity (no direct funds loss or consensus safety violation), the impact is substantial enough for High severity given that a single malformed message can disable the parallel execution system.

## Likelihood Explanation

The likelihood is **MEDIUM to HIGH** because:

**Attack Prerequisites:**
- Attacker needs to send network messages to the coordinator's RemoteStateViewService endpoint
- If shards run as separate processes: A compromised shard process can trivially craft malicious requests
- If network-accessible: An attacker with access to the internal network can exploit this

**Attack Complexity:**
- Extremely low - simply serialize a `RemoteKVRequest` with `shard_id >= num_shards` 
- No authentication or authorization bypass required
- Single malicious message triggers the vulnerability

**Detection Difficulty:**
- The service will crash immediately with a clear panic trace
- However, distinguishing malicious from legitimate crashes may be difficult initially

The security question explicitly asks about "malicious node" manipulation, suggesting this attack vector is within scope. Even if the service is internal, a compromised component represents a realistic threat model.

## Recommendation

Add bounds checking before using `shard_id` as an array index:

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
        error!(
            "Invalid shard_id {} in RemoteKVRequest (valid range: 0-{})",
            shard_id,
            kv_tx.len() - 1
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

Additionally, consider implementing:
1. Authentication/authorization for shard-to-coordinator communication
2. Rate limiting per shard to prevent DoS
3. Structured logging of suspicious shard_id values for monitoring

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_types::state_store::state_key::StateKey;
    use crossbeam_channel::unbounded;
    
    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn test_out_of_bounds_shard_id_causes_panic() {
        // Setup: Create service with 2 shards
        let (tx1, _rx1) = unbounded();
        let (tx2, _rx2) = unbounded();
        let kv_tx = Arc::new(vec![tx1, tx2]);
        
        let state_view = Arc::new(RwLock::new(None));
        
        // Attack: Craft request with out-of-bounds shard_id
        let malicious_request = RemoteKVRequest::new(
            999, // shard_id way beyond bounds
            vec![StateKey::raw(vec![1, 2, 3])]
        );
        
        let message = Message::new(bcs::to_bytes(&malicious_request).unwrap());
        
        // This will panic due to out-of-bounds access at line 121
        RemoteStateViewService::<TestStateView>::handle_message(
            message,
            state_view,
            kv_tx
        );
    }
    
    #[test]
    fn test_wrong_shard_routing() {
        // Setup: Create service with 3 shards
        let (tx0, rx0) = unbounded();
        let (tx1, rx1) = unbounded(); 
        let (tx2, rx2) = unbounded();
        let kv_tx = Arc::new(vec![tx0, tx1, tx2]);
        
        let state_view = Arc::new(RwLock::new(None));
        
        // Attack: Shard 0 sends request but claims to be shard 2
        let malicious_request = RemoteKVRequest::new(
            2, // Wrong shard_id - response will go to shard 2 instead of 0
            vec![StateKey::raw(vec![1, 2, 3])]
        );
        
        let message = Message::new(bcs::to_bytes(&malicious_request).unwrap());
        
        RemoteStateViewService::<TestStateView>::handle_message(
            message,
            state_view,
            kv_tx
        );
        
        // Verify response went to wrong shard (shard 2 instead of intended shard 0)
        assert!(rx2.try_recv().is_ok()); // Shard 2 receives response
        assert!(rx0.try_recv().is_err()); // Shard 0 receives nothing
    }
}
```

**Notes:**

The vulnerability is a clear violation of secure coding practices - all array accesses using untrusted data must be bounds-checked. While the service appears designed for internal use within a validator's execution system, the lack of validation creates an exploitable attack surface for compromised components or network attackers. The fix is straightforward and should be applied immediately to prevent service crashes and response misdirection that could impact block execution.

### Citations

**File:** execution/executor-service/src/remote_state_view_service.rs (L40-48)
```rust
        let command_txs = remote_shard_addresses
            .iter()
            .map(|address| {
                controller.create_outbound_channel(*address, kv_response_type.to_string())
            })
            .collect_vec();
        Self {
            kv_rx: result_rx,
            kv_tx: Arc::new(command_txs),
```

**File:** execution/executor-service/src/remote_state_view_service.rs (L86-89)
```rust
        let req: RemoteKVRequest = bcs::from_bytes(&message.data).unwrap();
        drop(bcs_deser_timer);

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

**File:** execution/executor-service/src/remote_state_view.rs (L44-49)
```rust
    pub fn set_state_value(&self, state_key: &StateKey, state_value: Option<StateValue>) {
        self.state_values
            .get(state_key)
            .unwrap()
            .set_value(state_value);
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
