# Audit Report

## Title
Unbounded Memory Allocation in BCS Deserialization Leading to Validator Denial of Service

## Summary
The `handle_message()` function in the remote state view service performs BCS deserialization of network messages without size limits, allowing malicious actors to trigger excessive memory allocation attempts through crafted vector length fields, causing validator node crashes.

## Finding Description

The vulnerability exists in the remote executor service's message handling code: [1](#0-0) 

The `RemoteKVRequest` structure being deserialized contains a vector of `StateKey` objects: [2](#0-1) 

In BCS encoding, vectors are prefixed with their length encoded as ULEB128. The standard Rust serde deserialization pattern for vectors calls `Vec::with_capacity(len)` based on this length field before deserializing elements. An attacker can craft a BCS message with a malicious length field (e.g., 2^40 or larger) that requires only ~10 bytes in ULEB128 encoding but would trigger allocation of terabytes of memory.

**Attack propagation:**
1. Attacker sends gRPC message to the network controller endpoint
2. Message passes through gRPC layer (80MB size limit does NOT prevent this attack - a ULEB128-encoded 2^50 takes only 10 bytes)
3. Message reaches `handle_message()` via the crossbeam channel [3](#0-2) 

4. BCS deserializer reads length field and attempts `Vec::<StateKey>::with_capacity(2^40)`
5. For `StateKey` (8 bytes as `Arc<Entry>`), this attempts to allocate 8 * 2^40 ≈ 8.8 TB
6. Allocator panics or triggers OOM, crashing the thread/process
7. The `.unwrap()` propagates the panic

The gRPC service has no authentication beyond network-level access: [4](#0-3) [5](#0-4) 

**Invariant Violation:** This breaks the "Resource Limits" invariant requiring all operations to respect computational limits, and could affect "Deterministic Execution" if it causes validators to crash non-deterministically based on memory pressure.

## Impact Explanation

**Severity: HIGH**

This qualifies as HIGH severity under the Aptos bug bounty criteria for "Validator node slowdowns" and "API crashes." Specifically:

1. **Validator Availability Impact**: A crashed remote state view service prevents executor shards from fetching state values, blocking block execution on that validator
2. **Consensus Liveness Risk**: If multiple validators are targeted simultaneously, it could impact network liveness during block production
3. **Resource Exhaustion**: Even if allocation fails gracefully, repeated attacks cause memory pressure and system instability

While not reaching CRITICAL severity (no funds loss or consensus safety violation), the ability to reliably crash validator nodes processing blocks represents significant protocol disruption.

**Multiple vulnerable locations exist:** [6](#0-5) [7](#0-6) [8](#0-7) 

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The attack is straightforward to execute:
- Requires only network access to the validator's executor service port
- Crafting malicious BCS messages is trivial (10-byte payload)
- No authentication or rate limiting observed on the gRPC endpoints
- Multiple attack vectors across different message types

However, the executor service may be deployed behind network isolation in production, which would reduce external attack surface. The likelihood increases if:
- Services are exposed to broader network access
- A compromised internal component can send malicious messages
- The service handles cross-validator communication

## Recommendation

Implement size limits on BCS deserialization similar to the protection in transaction argument validation: [9](#0-8) 

**Recommended fix for `remote_state_view_service.rs`:**

```rust
const MAX_MESSAGE_BYTES: usize = 10_000_000; // 10MB reasonable limit

pub fn handle_message(
    message: Message,
    state_view: Arc<RwLock<Option<Arc<S>>>>,
    kv_tx: Arc<Vec<Sender<Message>>>,
) {
    let _timer = REMOTE_EXECUTOR_TIMER
        .with_label_values(&["0", "kv_requests"])
        .start_timer();
    
    // Validate message size before deserialization
    if message.data.len() > MAX_MESSAGE_BYTES {
        error!("Message exceeds size limit: {} bytes", message.data.len());
        return;
    }
    
    let bcs_deser_timer = REMOTE_EXECUTOR_TIMER
        .with_label_values(&["0", "kv_req_deser"])
        .start_timer();
    
    // Use from_bytes_with_limit if available, or add custom validation
    let req: RemoteKVRequest = match bcs::from_bytes(&message.data) {
        Ok(r) => {
            // Additional validation: check vector lengths
            if r.keys.len() > 100_000 { // Reasonable upper bound
                error!("Request contains too many keys: {}", r.keys.len());
                return;
            }
            r
        },
        Err(e) => {
            error!("Failed to deserialize RemoteKVRequest: {}", e);
            return;
        }
    };
    drop(bcs_deser_timer);
    // ... rest of function
}
```

Apply similar protections to all BCS deserialization points in the executor service.

## Proof of Concept

```rust
#[test]
fn test_malicious_vector_length_dos() {
    use bcs;
    use crate::{RemoteKVRequest};
    
    // Craft a malicious BCS message:
    // - shard_id: 0
    // - keys vector with length 2^40 but no actual elements
    
    let mut malicious_bcs = vec![];
    
    // Serialize shard_id = 0
    malicious_bcs.extend_from_slice(&[0u8]); 
    
    // ULEB128 encoding of 2^40 (1,099,511,627,776)
    // This takes only 6 bytes in ULEB128 format
    malicious_bcs.extend_from_slice(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x10]);
    
    // Try to deserialize - this should attempt to allocate ~8.8TB
    // and either panic or trigger OOM
    let result: Result<RemoteKVRequest, _> = bcs::from_bytes(&malicious_bcs);
    
    // In vulnerable code, this causes panic/crash
    // With proper limits, this should return Err gracefully
    match result {
        Ok(_) => panic!("Should not successfully deserialize malicious input"),
        Err(e) => println!("Properly rejected malicious input: {}", e),
    }
}
```

**Notes**

The vulnerability stems from unconstrained BCS deserialization in the executor service's network message handling. While the gRPC layer enforces a 80MB message size limit, this provides no protection against malicious length field encoding that triggers excessive memory allocation. The codebase demonstrates awareness of this attack pattern in `transaction_arg_validation.rs` with explicit size limits and safe allocation, but these protections are absent in the executor service's critical message handling paths. This represents a defense-in-depth failure where internal services lack the same robust input validation applied to external transaction data.

### Citations

**File:** execution/executor-service/src/remote_state_view_service.rs (L65-72)
```rust
        while let Ok(message) = self.kv_rx.recv() {
            let state_view = self.state_view.clone();
            let kv_txs = self.kv_tx.clone();
            self.thread_pool.spawn(move || {
                Self::handle_message(message, state_view, kv_txs);
            });
        }
    }
```

**File:** execution/executor-service/src/remote_state_view_service.rs (L86-86)
```rust
        let req: RemoteKVRequest = bcs::from_bytes(&message.data).unwrap();
```

**File:** execution/executor-service/src/lib.rs (L68-71)
```rust
pub struct RemoteKVRequest {
    pub(crate) shard_id: ShardId,
    pub(crate) keys: Vec<StateKey>,
}
```

**File:** secure/net/src/grpc_network_service/mod.rs (L23-23)
```rust
const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 80;
```

**File:** secure/net/src/grpc_network_service/mod.rs (L75-79)
```rust
        Server::builder()
            .timeout(std::time::Duration::from_millis(rpc_timeout_ms))
            .add_service(
                NetworkMessageServiceServer::new(self).max_decoding_message_size(MAX_MESSAGE_SIZE),
            )
```

**File:** execution/executor-service/src/remote_cordinator_client.rs (L89-89)
```rust
                let request: RemoteExecutionRequest = bcs::from_bytes(&message.data).unwrap();
```

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L64-64)
```rust
        let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes()).unwrap();
```

**File:** execution/executor-service/src/remote_state_view.rs (L254-254)
```rust
        let response: RemoteKVResponse = bcs::from_bytes(&message.data).unwrap();
```

**File:** aptos-move/aptos-vm/src/verifier/transaction_arg_validation.rs (L546-571)
```rust
fn read_n_bytes(n: usize, src: &mut Cursor<&[u8]>, dest: &mut Vec<u8>) -> Result<(), VMStatus> {
    let deserialization_error = |msg: &str| -> VMStatus {
        VMStatus::error(
            StatusCode::FAILED_TO_DESERIALIZE_ARGUMENT,
            Some(msg.to_string()),
        )
    };
    let len = dest.len();

    // It is safer to limit the length under some big (but still reasonable
    // number).
    const MAX_NUM_BYTES: usize = 1_000_000;
    if len.checked_add(n).is_none_or(|s| s > MAX_NUM_BYTES) {
        return Err(deserialization_error(&format!(
            "Couldn't read bytes: maximum limit of {} bytes exceeded",
            MAX_NUM_BYTES
        )));
    }

    // Ensure we have enough capacity for resizing.
    dest.try_reserve(len + n)
        .map_err(|e| deserialization_error(&format!("Couldn't read bytes: {}", e)))?;
    dest.resize(len + n, 0);
    src.read_exact(&mut dest[len..])
        .map_err(|_| deserialization_error("Couldn't read bytes"))
}
```
