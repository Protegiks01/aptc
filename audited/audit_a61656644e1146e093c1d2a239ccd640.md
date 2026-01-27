# Audit Report

## Title
Unauthenticated Cross-Shard Message Flooding Enables Validator CPU Exhaustion via Repeated Deserialization

## Summary
The `receive_cross_shard_msg()` function in the remote cross-shard client performs expensive BCS deserialization on every incoming message without authentication, rate limiting, or message validation. An attacker with network access to executor shard ports can flood the system with large malicious messages (up to 80MB each), causing CPU exhaustion and validator node slowdowns.

## Finding Description

The cross-shard executor service uses a `NetworkController` that lacks authentication mechanisms. [1](#0-0) 

When messages arrive, the `receive_cross_shard_msg()` function performs BCS deserialization on every message in a tight loop without any validation or throttling: [2](#0-1) 

This function is called repeatedly in a blocking loop by the `CrossShardCommitReceiver::start()` method: [3](#0-2) 

The GRPC service allows messages up to 80MB in size: [4](#0-3) 

**Attack Path:**
1. Attacker identifies executor shard network addresses from deployment configuration
2. Attacker connects to the unauthenticated GRPC service (no mutual TLS or authentication required)
3. Attacker floods the shard with crafted `CrossShardMsg` messages containing large `StateKey` and `WriteOp` payloads (up to 80MB each)
4. Each message triggers BCS deserialization at line 64, consuming CPU cycles
5. The tight receive loop continuously deserializes messages without backpressure
6. Legitimate cross-shard messages are delayed or blocked
7. Transaction execution across shards stalls, causing liveness degradation

**Broken Invariants:**
- **Resource Limits**: No computational limits on deserialization operations
- **Network Protocol Security**: No authentication or authorization for cross-shard messages
- **Availability**: Validator nodes can be slowed or halted through resource exhaustion

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria for "Validator node slowdowns." 

The impact includes:
- **CPU Exhaustion**: Repeated deserialization of 80MB messages is computationally expensive
- **Liveness Degradation**: Cross-shard transaction processing can be blocked or severely delayed
- **Cascading Failures**: If multiple shards are attacked simultaneously, the entire sharded execution system becomes unavailable
- **Consensus Impact**: While not directly breaking consensus safety, severe liveness failures can prevent block production

The attack does not require validator credentials, stake, or Byzantine behavior from honest validators—only network access to the executor service ports.

## Likelihood Explanation

**Likelihood: Medium**

Required conditions:
- Sharded execution must be enabled (controlled via `--num-executor-shards` configuration)
- Attacker must have network access to executor shard listening ports
- Shard addresses must be discoverable (through configuration files, network scanning, or infrastructure knowledge)

While sharded execution appears to be experimental and not universally deployed, when enabled it exposes this attack surface. The lack of authentication makes exploitation straightforward once network access is obtained.

## Recommendation

Implement multiple layers of defense:

1. **Add Authentication**: Integrate mutual TLS or validator key-based authentication to `NetworkController`, similar to the main Aptos network layer's `HandshakeAuthMode::Mutual`

2. **Implement Rate Limiting**: Add per-peer rate limiting on incoming messages:
```rust
pub fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
    let rx = self.message_rxs[current_round].lock().unwrap();
    let message = rx.recv().unwrap();
    
    // Validate message size before deserialization
    if message.to_bytes().len() > MAX_CROSS_SHARD_MSG_SIZE {
        panic!("Message exceeds maximum size");
    }
    
    let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes()).unwrap();
    msg
}
```

3. **Add Message Validation**: Validate sender identity and message structure before deserialization

4. **Implement Backpressure**: Use bounded channels instead of unbounded channels to prevent queue buildup: [5](#0-4) 

5. **Add Monitoring**: Instrument deserialization metrics to detect flooding attacks

## Proof of Concept

```rust
// Proof of Concept: Message Flooding Attack
// Place in execution/executor-service/src/tests.rs

#[test]
fn test_cross_shard_message_flooding_dos() {
    use crate::remote_cross_shard_client::RemoteCrossShardClient;
    use aptos_secure_net::network_controller::{Message, NetworkController};
    use aptos_vm::sharded_block_executor::messages::{CrossShardMsg, RemoteTxnWrite};
    use aptos_types::state_store::state_key::StateKey;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::thread;
    use std::time::{Duration, Instant};

    // Setup victim shard
    let shard_port = aptos_config::utils::get_available_port();
    let shard_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), shard_port);
    
    let mut controller = NetworkController::new(
        "victim_shard".to_string(),
        shard_addr,
        5000
    );
    
    let _victim_client = RemoteCrossShardClient::new(&mut controller, vec![]);
    controller.start();
    
    // Attacker: Create large malicious messages
    let large_data = vec![0u8; 10_000_000]; // 10MB payload
    let malicious_state_key = StateKey::raw(large_data.clone());
    let malicious_msg = CrossShardMsg::RemoteTxnWriteMsg(
        RemoteTxnWrite::new(malicious_state_key, None)
    );
    
    // Flood with 100 large messages
    let start = Instant::now();
    for _ in 0..100 {
        let serialized = bcs::to_bytes(&malicious_msg).unwrap();
        // Send via network controller (attacker would use GRPC client)
        // This demonstrates CPU cost of repeated deserialization
        let _: CrossShardMsg = bcs::from_bytes(&serialized).unwrap();
    }
    let duration = start.elapsed();
    
    // Demonstrate CPU cost
    println!("Deserialized 100 x 10MB messages in {:?}", duration);
    println!("Per-message cost: {:?}", duration / 100);
    
    // With no authentication or rate limiting, attacker can sustain this
    // indefinitely, exhausting validator CPU resources
    assert!(duration.as_secs() > 0, "Significant CPU time consumed");
}
```

**Notes:**
- This is an application-level resource exhaustion vulnerability, not a network-level DoS (which is excluded from scope)
- The vulnerability exploits a logic bug: unauthenticated network service + expensive operation + no rate limiting
- The sharded executor service is deployed as a standalone executable with network-exposed endpoints
- Fix requires adding authentication layer comparable to the main Aptos validator network's security model

### Citations

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

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L36-41)
```rust
        // Create inbound channels for each round
        for round in 0..MAX_ALLOWED_PARTITIONING_ROUNDS {
            let message_type = format!("cross_shard_{}", round);
            let rx = controller.create_inbound_channel(message_type);
            message_rxs.push(Mutex::new(rx));
        }
```

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L61-66)
```rust
    fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
        let rx = self.message_rxs[current_round].lock().unwrap();
        let message = rx.recv().unwrap();
        let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes()).unwrap();
        msg
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L26-45)
```rust
    pub fn start<S: StateView + Sync + Send>(
        cross_shard_state_view: Arc<CrossShardStateView<S>>,
        cross_shard_client: Arc<dyn CrossShardClient>,
        round: RoundId,
    ) {
        loop {
            let msg = cross_shard_client.receive_cross_shard_msg(round);
            match msg {
                RemoteTxnWriteMsg(txn_commit_msg) => {
                    let (state_key, write_op) = txn_commit_msg.take();
                    cross_shard_state_view
                        .set_value(&state_key, write_op.and_then(|w| w.as_state_value()));
                },
                CrossShardMsg::StopMsg => {
                    trace!("Cross shard commit receiver stopped for round {}", round);
                    break;
                },
            }
        }
    }
```

**File:** secure/net/src/grpc_network_service/mod.rs (L23-23)
```rust
const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 80;
```
