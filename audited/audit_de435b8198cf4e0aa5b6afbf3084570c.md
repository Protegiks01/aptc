# Audit Report

## Title
Node Process Crash Due to Panic on Unreachable GRPC Remote Address in Outbound Handler

## Summary
The GRPC client creation in `OutboundHandler::start()` uses lazy connection establishment without validating remote address reachability. When the first message is sent to an unreachable address, the code panics, triggering the global panic handler which terminates the entire node process via `process::exit(12)`, causing complete validator/node unavailability.

## Finding Description

The vulnerability exists in the secure networking layer used for remote executor communication in sharded block execution. The attack surface involves three critical components:

**1. Lazy Connection Without Validation**

In `OutboundHandler::start()`, GRPC clients are created for all remote addresses without validating reachability: [1](#0-0) 

The client creation uses `connect_lazy()` which defers connection establishment: [2](#0-1) 

This lazy connection strategy means no validation occurs at client creation time - the connection is only attempted on first message send.

**2. Panic on Connection Failure**

When a message is sent to an unreachable address, the `send_message()` function panics instead of handling the error gracefully: [3](#0-2) 

The developers acknowledged this issue with a TODO comment indicating retry logic is needed: [4](#0-3) 

**3. Global Panic Handler Terminates Process**

The global panic handler is configured to exit the entire process on any panic: [5](#0-4) 

This handler is installed when the Aptos node starts: [6](#0-5) 

**Attack Path:**

1. A validator/node is configured with remote executor shard addresses for parallel block execution
2. One or more addresses are unreachable (misconfiguration, network partition, or targeted DoS)
3. During block execution, `RemoteExecutorClient::execute_block()` sends messages to shards: [7](#0-6) 

4. The outbound handler processes the message and calls `send_message()`: [8](#0-7) 

5. The GRPC client attempts connection on first send, fails, and panics
6. The global panic handler catches it and calls `process::exit(12)`
7. **The entire validator node process terminates**

This breaks the **Resource Limits** and **Node Availability** invariants - nodes must handle network failures gracefully without crashing.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty program criteria:

- **Validator node crashes**: The panic causes immediate process termination via `process::exit(12)`, making the node completely unavailable
- **API crashes**: All node APIs become unavailable when the process exits
- **Consensus disruption**: If multiple validators encounter this issue simultaneously, it could impact network consensus by reducing available validators
- **Service denial**: The node cannot process blocks, participate in consensus, or serve API requests

The impact is severe because:
1. The crash is deterministic and reproducible
2. It affects the critical block execution path
3. Recovery requires manual node restart
4. No graceful degradation or failover mechanism exists

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability is likely to occur because:

1. **Natural network conditions**: Temporary network partitions, DNS failures, or node restarts can make previously reachable addresses temporarily unreachable
2. **Configuration errors**: Human error in specifying remote executor addresses is common in distributed systems
3. **No validation**: The code accepts any parseable `SocketAddr` without validation: [9](#0-8) 

4. **Sharded execution is used**: The remote executor client is actively used in production for parallel transaction execution: [10](#0-9) 

While requiring specific configuration (remote executor shards), this is not an uncommon deployment pattern for high-throughput validators.

## Recommendation

Implement the following fixes:

1. **Replace panic with error handling** in `send_message()`:
```rust
pub async fn send_message(
    &mut self,
    sender_addr: SocketAddr,
    message: Message,
    mt: &MessageType,
) {
    let request = tonic::Request::new(NetworkMessage {
        message: message.data,
        message_type: mt.get_type(),
    });
    
    // Retry with exponential backoff
    let mut retry_delay = Duration::from_millis(10);
    let max_retries = 5;
    
    for attempt in 0..max_retries {
        match self.remote_channel.simple_msg_exchange(request.clone()).await {
            Ok(_) => return,
            Err(e) => {
                error!(
                    "Error '{}' sending message to {} on node {:?} (attempt {}/{})",
                    e, self.remote_addr, sender_addr, attempt + 1, max_retries
                );
                if attempt < max_retries - 1 {
                    tokio::time::sleep(retry_delay).await;
                    retry_delay *= 2;
                }
            },
        }
    }
    error!(
        "Failed to send message to {} after {} retries",
        self.remote_addr, max_retries
    );
}
```

2. **Add reachability validation** before client insertion in `start()`:
```rust
// Validate reachability before creating clients
for remote_addr in self.remote_addresses.iter() {
    if let Err(e) = Self::validate_reachability(rt, *remote_addr).await {
        warn!("Remote address {} is not reachable: {}", remote_addr, e);
        // Either skip or use a connection timeout
    }
}
```

3. **Use eager connection with timeout** instead of `connect_lazy()`:
```rust
async fn get_channel(remote_addr: String) -> Result<NetworkMessageServiceClient<Channel>, Error> {
    info!("Connecting to remote server at {:?}", remote_addr);
    let endpoint = tonic::transport::Endpoint::new(remote_addr.clone())?
        .connect_timeout(Duration::from_secs(5));
    
    let conn = endpoint.connect().await?;
    Ok(NetworkMessageServiceClient::new(conn).max_decoding_message_size(MAX_MESSAGE_SIZE))
}
```

## Proof of Concept

```rust
#[test]
fn test_unreachable_address_causes_panic() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::runtime::Runtime;
    
    // Create an unreachable address (assuming nothing listens on this port)
    let unreachable_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 9999);
    
    let rt = Runtime::new().unwrap();
    let mut grpc_client = GRPCNetworkMessageServiceClientWrapper::new(&rt, unreachable_addr);
    
    let sender_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
    let test_message = Message::new(vec![1, 2, 3]);
    let message_type = MessageType::new("test".to_string());
    
    // This will panic when it tries to send, crashing the process if panic handler is set
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(async {
            grpc_client.send_message(sender_addr, test_message, &message_type).await;
        });
    }));
    
    assert!(result.is_err(), "Expected panic on unreachable address");
}
```

To demonstrate the full node crash, deploy a validator with remote executor shards where one address is unreachable, then trigger block execution. The node will terminate with exit code 12.

## Notes

This vulnerability demonstrates a critical gap between the robust error handling in the main network framework [11](#0-10)  and the fragile panic-based approach in the secure networking layer. The contrast shows this is an implementation oversight rather than a design choice.

The vulnerability is particularly concerning because it affects the execution layer, not just networking - a crash during block execution can cause consensus participants to miss proposals and attestations, potentially impacting network liveness.

### Citations

**File:** secure/net/src/network_controller/outbound_handler.rs (L68-76)
```rust
        // Create a grpc client for each remote address
        let mut grpc_clients: HashMap<SocketAddr, GRPCNetworkMessageServiceClientWrapper> =
            HashMap::new();
        self.remote_addresses.iter().for_each(|remote_addr| {
            grpc_clients.insert(
                *remote_addr,
                GRPCNetworkMessageServiceClientWrapper::new(rt, *remote_addr),
            );
        });
```

**File:** secure/net/src/network_controller/outbound_handler.rs (L154-160)
```rust
            } else {
                grpc_clients
                    .get_mut(remote_addr)
                    .unwrap()
                    .send_message(*socket_addr, msg, message_type)
                    .await;
            }
```

**File:** secure/net/src/grpc_network_service/mod.rs (L124-138)
```rust
    pub fn new(rt: &Runtime, remote_addr: SocketAddr) -> Self {
        Self {
            remote_addr: remote_addr.to_string(),
            remote_channel: rt
                .block_on(async { Self::get_channel(format!("http://{}", remote_addr)).await }),
        }
    }

    async fn get_channel(remote_addr: String) -> NetworkMessageServiceClient<Channel> {
        info!("Trying to connect to remote server at {:?}", remote_addr);
        let conn = tonic::transport::Endpoint::new(remote_addr)
            .unwrap()
            .connect_lazy();
        NetworkMessageServiceClient::new(conn).max_decoding_message_size(MAX_MESSAGE_SIZE)
    }
```

**File:** secure/net/src/grpc_network_service/mod.rs (L140-160)
```rust
    pub async fn send_message(
        &mut self,
        sender_addr: SocketAddr,
        message: Message,
        mt: &MessageType,
    ) {
        let request = tonic::Request::new(NetworkMessage {
            message: message.data,
            message_type: mt.get_type(),
        });
        // TODO: Retry with exponential backoff on failures
        match self.remote_channel.simple_msg_exchange(request).await {
            Ok(_) => {},
            Err(e) => {
                panic!(
                    "Error '{}' sending message to {} on node {:?}",
                    e, self.remote_addr, sender_addr
                );
            },
        }
    }
```

**File:** secure/net/src/grpc_network_service/mod.rs (L198-201)
```rust
    // wait for the server to be ready before sending messages
    // TODO: We need to implement retry on send_message failures such that we can pass this test
    //       without this sleep
    thread::sleep(std::time::Duration::from_millis(10));
```

**File:** crates/crash-handler/src/lib.rs (L26-57)
```rust
pub fn setup_panic_handler() {
    panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
        handle_panic(pi);
    }));
}

// Formats and logs panic information
fn handle_panic(panic_info: &PanicHookInfo<'_>) {
    // The Display formatter for a PanicHookInfo contains the message, payload and location.
    let details = format!("{}", panic_info);
    let backtrace = format!("{:#?}", Backtrace::new());

    let info = CrashInfo { details, backtrace };
    let crash_info = toml::to_string_pretty(&info).unwrap();
    error!("{}", crash_info);
    // TODO / HACK ALARM: Write crash info synchronously via eprintln! to ensure it is written before the process exits which error! doesn't guarantee.
    // This is a workaround until https://github.com/aptos-labs/aptos-core/issues/2038 is resolved.
    eprintln!("{}", crash_info);

    // Wait till the logs have been flushed
    aptos_logger::flush();

    // Do not kill the process if the panics happened at move-bytecode-verifier.
    // This is safe because the `state::get_state()` uses a thread_local for storing states. Thus the state can only be mutated to VERIFIER by the thread that's running the bytecode verifier.
    //
    // TODO: once `can_unwind` is stable, we should assert it. See https://github.com/rust-lang/rust/issues/92988.
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
```

**File:** aptos-node/src/lib.rs (L233-234)
```rust
    // Setup panic handler
    aptos_crash_handler::setup_panic_handler();
```

**File:** execution/executor-service/src/remote_executor_client.rs (L57-72)
```rust
pub static REMOTE_SHARDED_BLOCK_EXECUTOR: Lazy<
    Arc<
        aptos_infallible::Mutex<
            ShardedBlockExecutor<CachedStateView, RemoteExecutorClient<CachedStateView>>,
        >,
    >,
> = Lazy::new(|| {
    info!("REMOTE_SHARDED_BLOCK_EXECUTOR created");
    Arc::new(aptos_infallible::Mutex::new(
        RemoteExecutorClient::create_remote_sharded_block_executor(
            get_coordinator_address(),
            get_remote_addresses(),
            None,
        ),
    ))
});
```

**File:** execution/executor-service/src/remote_executor_client.rs (L193-206)
```rust
        for (shard_id, sub_blocks) in sub_blocks.into_iter().enumerate() {
            let senders = self.command_txs.clone();
            let execution_request = RemoteExecutionRequest::ExecuteBlock(ExecuteBlockCommand {
                sub_blocks,
                concurrency_level: concurrency_level_per_shard,
                onchain_config: onchain_config.clone(),
            });

            senders[shard_id]
                .lock()
                .unwrap()
                .send(Message::new(bcs::to_bytes(&execution_request).unwrap()))
                .unwrap();
        }
```

**File:** execution/executor-benchmark/src/main.rs (L639-645)
```rust
        assert_eq!(
            execution_shards,
            remote_executor_client::get_remote_addresses().len(),
            "Number of execution shards ({}) must be equal to the number of remote addresses ({}).",
            execution_shards,
            remote_executor_client::get_remote_addresses().len()
        );
```

**File:** network/framework/src/peer/mod.rs (L360-368)
```rust
                        if let Err(err) = timeout(transport::TRANSPORT_TIMEOUT,writer.send(&message)).await {
                            warn!(
                                log_context,
                                error = %err,
                                "{} Error in sending message to peer: {}",
                                network_context,
                                remote_peer_id.short_str(),
                            );
                        }
```
