# Audit Report

## Title
RemoteKVRequest Batch Size and Individual Key Size Bypass Enabling Resource Exhaustion DoS

## Summary
The `RemoteStateViewService` accepts and processes `RemoteKVRequest` messages with an arbitrary number of `StateKey` entries and arbitrarily large individual keys, bypassing the client-side `REMOTE_STATE_KEY_BATCH_SIZE` limit of 200. An attacker with network access to executor-service endpoints can exploit this to cause memory exhaustion, CPU saturation, and service disruption through oversized requests.

## Finding Description

The `REMOTE_STATE_KEY_BATCH_SIZE` constant is defined as 200 to limit the number of keys per request on the client side: [1](#0-0) 

The client correctly chunks requests using this limit: [2](#0-1) 

However, the `RemoteKVRequest` struct has no validation in its constructor: [3](#0-2) 

The server-side `RemoteStateViewService::handle_message` deserializes and processes ALL keys in a request without any validation: [4](#0-3) 

This creates **two distinct bypass vectors**:

**Vector 1: Batch Count Bypass**
An attacker can craft a `RemoteKVRequest` with thousands of `StateKey` entries (e.g., 10,000+), limited only by the gRPC message size limit of 80 MiB. The service will iterate through all keys, calling `get_state_value()` for each, causing CPU exhaustion and thread pool starvation. [5](#0-4) 

**Vector 2: Individual Key Size Bypass**
The `StateKey::decode()` function for `TableItem` variants has no size limit on the key `Vec<u8>`: [6](#0-5) 

An attacker can create `StateKey` instances with multi-megabyte keys (e.g., 40 keys × 2 MB = 80 MB total). The `StateKeyInner::TableItem` stores the key as an unbounded `Vec<u8>`: [7](#0-6) 

When deserialized by BCS, this allocates the full memory immediately. Multiple concurrent oversized requests can exhaust available memory, causing the executor service to crash or become unresponsive.

**Attack Scenario:**
1. Attacker identifies an executor-service endpoint (if exposed via misconfiguration or accessible on internal networks)
2. Crafts malicious `RemoteKVRequest` messages using either or both bypass vectors
3. Sends multiple concurrent requests to amplify impact
4. Service experiences memory exhaustion, CPU saturation, or thread pool starvation
5. Validator node's execution capability is disrupted, requiring manual intervention

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

This vulnerability is rated **Medium Severity** per the Aptos bug bounty criteria: "State inconsistencies requiring intervention."

While the attack causes resource exhaustion and service disruption requiring node restart, the impact is limited to:
- Single validator node running the optional remote execution feature
- Does NOT affect consensus safety or cause chain forks
- Does NOT allow theft or minting of funds
- Does NOT affect other validators in the network
- Does NOT compromise state integrity

The attack requires the `REMOTE_SHARDED_BLOCK_EXECUTOR` feature to be enabled via configuration: [8](#0-7) 

This is an optional distributed execution optimization, not a core consensus component.

## Likelihood Explanation

**Moderate likelihood** in specific configurations:

**Enabling Factors:**
- The `NetworkController` has no authentication or authorization mechanisms
- Services bind to addresses specified via command-line arguments without security warnings
- No rate limiting or request size validation at the application layer [9](#0-8) 

**Mitigating Factors:**
- Requires the optional remote execution feature to be explicitly enabled
- Executor-service endpoints are intended for internal cluster communication
- Standard validator deployments likely use proper network isolation
- gRPC message size limit of 80 MiB provides some boundary

The attack requires either:
1. Misconfiguration exposing internal services to untrusted networks
2. Network-adjacent attacker on the same internal network
3. Compromised shard process (insider threat)

## Recommendation

**Immediate Mitigations:**

1. Add server-side validation in `RemoteStateViewService::handle_message`:
   - Enforce maximum keys per request (e.g., reject if `state_keys.len() > REMOTE_STATE_KEY_BATCH_SIZE`)
   - Add maximum total request size check before processing

2. Add size validation in `StateKey::decode()` for `TableItem`:
   - Reject keys exceeding a reasonable maximum (e.g., 1 MB)
   - Return `StateKeyDecodeErr` for oversized keys

3. Implement rate limiting per remote peer address in `NetworkController`

4. Add authentication/authorization for executor-service endpoints, even for internal use

5. Add explicit documentation warning that these services must not be exposed to untrusted networks

**Example Fix for RemoteStateViewService:**

```rust
pub fn handle_message(
    message: Message,
    state_view: Arc<RwLock<Option<Arc<S>>>>,
    kv_tx: Arc<Vec<Sender<Message>>>,
) {
    let req: RemoteKVRequest = bcs::from_bytes(&message.data).unwrap();
    let (shard_id, state_keys) = req.into();
    
    // VALIDATION: Enforce batch size limit
    if state_keys.len() > REMOTE_STATE_KEY_BATCH_SIZE {
        error!("RemoteKVRequest exceeded batch size limit: {} > {}", 
               state_keys.len(), REMOTE_STATE_KEY_BATCH_SIZE);
        return; // or send error response
    }
    
    // VALIDATION: Check total request size
    let total_size: usize = state_keys.iter().map(|k| k.size()).sum();
    const MAX_TOTAL_SIZE: usize = 10 * 1024 * 1024; // 10 MB
    if total_size > MAX_TOTAL_SIZE {
        error!("RemoteKVRequest exceeded total size limit: {} > {}", 
               total_size, MAX_TOTAL_SIZE);
        return; // or send error response
    }
    
    // ... rest of processing
}
```

## Proof of Concept

```rust
use aptos_executor_service::{RemoteKVRequest, RemoteKVResponse};
use aptos_types::{
    block_executor::partitioner::ShardId,
    state_store::state_key::StateKey,
    state_store::table::TableHandle,
};

#[test]
fn test_batch_size_bypass() {
    // Create a RemoteKVRequest with 10,000 keys (50x the intended limit)
    let shard_id = ShardId::new(0);
    let mut oversized_keys = Vec::new();
    
    for i in 0..10_000 {
        let handle = TableHandle(aptos_crypto::HashValue::random());
        let key = format!("key_{}", i).as_bytes().to_vec();
        oversized_keys.push(StateKey::table_item(&handle, &key));
    }
    
    // This should be rejected but isn't
    let malicious_request = RemoteKVRequest::new(shard_id, oversized_keys);
    
    // Serialize to verify it fits within gRPC limits
    let serialized = bcs::to_bytes(&malicious_request).unwrap();
    println!("Malicious request size: {} bytes", serialized.len());
    
    // If this were sent to RemoteStateViewService, it would process all 10,000 keys
    assert_eq!(malicious_request.keys.len(), 10_000);
}

#[test]
fn test_individual_key_size_bypass() {
    // Create a RemoteKVRequest with oversized individual StateKeys
    let shard_id = ShardId::new(0);
    let mut oversized_keys = Vec::new();
    
    // Create 40 keys, each 2 MB (total ~80 MB, at gRPC limit)
    for i in 0..40 {
        let handle = TableHandle(aptos_crypto::HashValue::random());
        let huge_key = vec![0u8; 2 * 1024 * 1024]; // 2 MB key
        oversized_keys.push(StateKey::table_item(&handle, &huge_key));
    }
    
    let malicious_request = RemoteKVRequest::new(shard_id, oversized_keys);
    let serialized = bcs::to_bytes(&malicious_request).unwrap();
    println!("Oversized key request size: {} bytes", serialized.len());
    
    // This allocates ~80 MB of memory when deserialized
    // Multiple concurrent requests would exhaust memory
    assert!(serialized.len() > 70 * 1024 * 1024); // > 70 MB
}
```

## Notes

This vulnerability exists in the optional distributed execution feature (`REMOTE_SHARDED_BLOCK_EXECUTOR`) used for performance optimization in sharded block execution. The attack surface is limited to nodes that:
1. Enable remote execution via `get_remote_addresses()` configuration
2. Expose executor-service endpoints to accessible networks

Standard validator deployments using local execution (`SHARDED_BLOCK_EXECUTOR`) are not affected. The absence of authentication and validation suggests these services were designed assuming trusted internal networks, but the lack of explicit safeguards creates risk in misconfigured or complex network topologies.

### Citations

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

**File:** execution/executor-service/src/remote_state_view_service.rs (L86-107)
```rust
        let req: RemoteKVRequest = bcs::from_bytes(&message.data).unwrap();
        drop(bcs_deser_timer);

        let (shard_id, state_keys) = req.into();
        trace!(
            "remote state view service - received request for shard {} with {} keys",
            shard_id,
            state_keys.len()
        );
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
```

**File:** secure/net/src/grpc_network_service/mod.rs (L23-23)
```rust
const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 80;
```

**File:** types/src/state_store/state_key/mod.rs (L81-91)
```rust
            StateKeyTag::TableItem => {
                const HANDLE_SIZE: usize = std::mem::size_of::<TableHandle>();
                if val.len() < 1 + HANDLE_SIZE {
                    return Err(StateKeyDecodeErr::NotEnoughBytes {
                        tag,
                        num_bytes: val.len(),
                    });
                }
                let handle = bcs::from_bytes(&val[1..1 + HANDLE_SIZE])?;
                Self::table_item(&handle, &val[1 + HANDLE_SIZE..])
            },
```

**File:** types/src/state_store/state_key/inner.rs (L51-55)
```rust
    TableItem {
        handle: TableHandle,
        #[serde(with = "serde_bytes")]
        key: Vec<u8>,
    },
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

**File:** execution/executor-service/src/main.rs (L9-25)
```rust
#[derive(Debug, Parser)]
struct Args {
    #[clap(long, default_value_t = 8)]
    pub num_executor_threads: usize,

    #[clap(long)]
    pub shard_id: usize,

    #[clap(long)]
    pub num_shards: usize,

    #[clap(long, num_args = 1..)]
    pub remote_executor_addresses: Vec<SocketAddr>,

    #[clap(long)]
    pub coordinator_address: SocketAddr,
}
```
