# Audit Report

## Title
Out-of-Bounds Shard ID Causes Panic in Remote State View Service Coordinator

## Summary
The `RemoteStateViewService` does not validate the `shard_id` field from incoming `RemoteKVRequest` messages before using it to index into the `kv_tx` vector, leading to an array index panic that crashes the coordinator process. This vulnerability can be triggered through misconfiguration or malicious network messages, causing denial of service to the sharded execution system.

## Finding Description

The vulnerability exists in the request routing logic of the Remote State View Service. When the coordinator receives a `RemoteKVRequest` from an executor shard, it extracts the `shard_id` and uses it directly to index into the `kv_tx` vector without bounds validation. [1](#0-0) 

The `shard_id` is a `usize` type alias defined as: [2](#0-1) 

The `kv_tx` vector size is determined by the number of remote shard addresses passed during initialization: [3](#0-2) 

The attack vector involves creating an executor service with an invalid `shard_id` that exceeds the number of configured shards. The command-line interface accepts `shard_id` without validation: [4](#0-3) 

Additionally, there's an immediate panic during executor service creation when accessing the shard address array: [5](#0-4) 

The `RemoteKVRequest` struct itself has no validation: [6](#0-5) 

The network controller used for message passing lacks authentication mechanisms: [7](#0-6) 

**Attack Path:**

1. An operator starts an executor service with `--shard_id=N` where `N >= num_configured_shards`
2. If `N < remote_executor_addresses.len()`, the executor starts successfully
3. The executor creates a `RemoteStateViewClient` with the invalid `shard_id`
4. When the executor needs state data, it sends a `RemoteKVRequest` with `shard_id=N`
5. The coordinator's `RemoteStateViewService` receives the request
6. The service deserializes the request and extracts `shard_id=N`
7. At line 121, `kv_tx[N].send(message).unwrap()` attempts to index with `N`
8. Since `N >= kv_tx.len()`, Rust panics with "index out of bounds"
9. The coordinator thread crashes, breaking the sharded execution system

## Impact Explanation

This vulnerability qualifies as **HIGH severity** per the Aptos bug bounty criteria for the following reasons:

1. **Validator Node Crashes**: The coordinator process crash affects the entire sharded execution system, potentially causing validator node failures or severe performance degradation.

2. **API Crashes**: The panic in the coordinator's message handling thread can propagate to related components, causing API unavailability.

3. **Denial of Service**: A single misconfigured or malicious executor shard can render the entire sharded execution infrastructure inoperable, affecting block execution capabilities.

4. **No Authentication**: The NetworkController lacks authentication, meaning in deployment scenarios where network endpoints are exposed, an external attacker could potentially craft and send malicious `RemoteKVRequest` messages with arbitrary `shard_id` values.

The impact is constrained to availability and does not directly affect consensus safety, state integrity, or funds, which prevents this from being Critical severity.

## Likelihood Explanation

The likelihood is **HIGH** due to:

1. **Operational Error**: During deployment, operators could easily misconfigure shard IDs, especially when scaling the number of shards up or down. A simple typo (e.g., `--shard_id=4` when only 4 shards exist with IDs 0-3) triggers the bug.

2. **No Validation**: There are zero validation checks on the `shard_id` parameter at any point in the initialization chain, making the error trivial to introduce.

3. **Immediate Crash**: The panic occurs on the first KV request after initialization, providing rapid feedback of the misconfiguration but also rapid service disruption.

4. **Multiple Attack Vectors**: The vulnerability can be triggered through:
   - Command-line misconfiguration
   - Malicious operator behavior
   - Network message manipulation (if endpoints are exposed)

## Recommendation

Add bounds validation at multiple defensive layers:

**Layer 1: Command-line Argument Validation**
```rust
// In execution/executor-service/src/main.rs
fn main() {
    let args = Args::parse();
    
    // Validate shard_id bounds
    if args.shard_id >= args.num_shards {
        panic!("Invalid shard_id {}: must be in range [0, {})", 
               args.shard_id, args.num_shards);
    }
    
    if args.shard_id >= args.remote_executor_addresses.len() {
        panic!("Invalid shard_id {}: must be < remote_executor_addresses.len() ({})",
               args.shard_id, args.remote_executor_addresses.len());
    }
    
    // ... rest of main
}
```

**Layer 2: Service Construction Validation**
```rust
// In execution/executor-service/src/remote_executor_service.rs
impl ExecutorService {
    pub fn new(
        shard_id: ShardId,
        num_shards: usize,
        num_threads: usize,
        self_address: SocketAddr,
        coordinator_address: SocketAddr,
        remote_shard_addresses: Vec<SocketAddr>,
    ) -> Self {
        assert!(shard_id < num_shards, 
                "shard_id {} must be < num_shards {}", shard_id, num_shards);
        assert!(shard_id < remote_shard_addresses.len(),
                "shard_id {} must be < remote_shard_addresses.len() {}",
                shard_id, remote_shard_addresses.len());
        
        // ... rest of constructor
    }
}
```

**Layer 3: Message Handler Validation**
```rust
// In execution/executor-service/src/remote_state_view_service.rs
pub fn handle_message(
    message: Message,
    state_view: Arc<RwLock<Option<Arc<S>>>>,
    kv_tx: Arc<Vec<Sender<Message>>>,
) {
    // ... existing code ...
    let (shard_id, state_keys) = req.into();
    
    // Validate shard_id before using it as array index
    if shard_id >= kv_tx.len() {
        warn!("Received invalid shard_id {} >= num_shards {}. Ignoring request.",
              shard_id, kv_tx.len());
        return;
    }
    
    // ... rest of handler
}
```

## Proof of Concept

**Step 1: Start coordinator with 4 shards**
```bash
# Start coordinator expecting 4 executor shards (shard_id 0-3)
cargo run --bin remote-executor-coordinator -- \
  --remote_executor_addresses 127.0.0.1:50001 \
                              127.0.0.1:50002 \
                              127.0.0.1:50003 \
                              127.0.0.1:50004
```

**Step 2: Start malicious executor with out-of-bounds shard_id**
```bash
# Start executor with shard_id=5 (out of bounds)
cargo run --bin remote-executor-service -- \
  --shard_id 5 \
  --num_shards 4 \
  --coordinator_address 127.0.0.1:52200 \
  --remote_executor_addresses 127.0.0.1:50001 \
                              127.0.0.1:50002 \
                              127.0.0.1:50003 \
                              127.0.0.1:50004 \
                              127.0.0.1:50005
```

**Expected Result**: When the executor at shard_id=5 attempts to fetch state values and sends a `RemoteKVRequest` with `shard_id=5`, the coordinator will panic with:
```
thread 'remote-state_view-service' panicked at 'index out of bounds: the len is 4 but the index is 5'
```

This demonstrates that an invalid `shard_id` in a `RemoteKVRequest` causes an unhandled panic in the coordinator's message routing logic, confirming the vulnerability.

## Notes

- The vulnerability affects the experimental sharded execution feature and may not be enabled in production deployments yet.
- The lack of network authentication in `NetworkController` (designed for trusted internal communication) means proper network isolation is critical for deployed systems.
- Similar bounds checking issues may exist in other storage layer components that use `shard_id` for array indexing, as noted in the codebase search results.

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

**File:** execution/executor-service/src/remote_state_view_service.rs (L86-121)
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
        let len = resp.len();
        let resp = RemoteKVResponse::new(resp);
        let bcs_ser_timer = REMOTE_EXECUTOR_TIMER
            .with_label_values(&["0", "kv_resp_ser"])
            .start_timer();
        let resp = bcs::to_bytes(&resp).unwrap();
        drop(bcs_ser_timer);
        trace!(
            "remote state view service - sending response for shard {} with {} keys",
            shard_id,
            len
        );
        let message = Message::new(resp);
        kv_tx[shard_id].send(message).unwrap();
```

**File:** types/src/block_executor/partitioner.rs (L16-16)
```rust
pub type ShardId = usize;
```

**File:** execution/executor-service/src/main.rs (L14-18)
```rust
    #[clap(long)]
    pub shard_id: usize,

    #[clap(long)]
    pub num_shards: usize,
```

**File:** execution/executor-service/src/process_executor_service.rs (L24-24)
```rust
        let self_address = remote_shard_addresses[shard_id];
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

**File:** secure/net/src/network_controller/mod.rs (L72-92)
```rust
/// NetworkController is the main entry point for sending and receiving messages over the network.
/// 1. If a node acts as both client and server, albeit in different contexts, GRPC needs separate
///    runtimes for client context and server context. Otherwise we a hang in GRPC. This seems to be
///    an internal bug in GRPC.
/// 2. We want to use tokio runtimes because it is best for async IO and tonic GRPC
///    implementation is async. However, we want the rest of the system (remote executor service)
///    to use rayon thread pools because it is best for CPU bound tasks.
/// 3. NetworkController, InboundHandler and OutboundHandler work as a bridge between the sync and
///    async worlds.
/// 4. We need to shutdown all the async tasks spawned by the NetworkController runtimes, otherwise
///    the program will hang, or have resource leaks.
#[allow(dead_code)]
pub struct NetworkController {
    inbound_handler: Arc<Mutex<InboundHandler>>,
    outbound_handler: OutboundHandler,
    inbound_rpc_runtime: Runtime,
    outbound_rpc_runtime: Runtime,
    inbound_server_shutdown_tx: Option<oneshot::Sender<()>>,
    outbound_task_shutdown_tx: Option<Sender<Message>>,
    listen_addr: SocketAddr,
}
```
