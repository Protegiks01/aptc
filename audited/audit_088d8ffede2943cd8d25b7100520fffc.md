# Audit Report

## Title 
Unauthenticated Remote Executor Service Allows Arbitrary Transaction Execution and Consensus Safety Violations

## Summary
The remote executor service network layer (`aptos-secure-net`) lacks sender authentication, allowing any network peer to send malicious execution commands to executor shards. This enables attackers to inject arbitrary transactions, break consensus determinism, and corrupt blockchain state without any authorization checks.

## Finding Description

The Aptos sharded execution architecture uses `aptos-secure-net::NetworkController` for communication between the coordinator and remote executor shards. This network layer has **no authentication or authorization mechanism** for incoming messages.

**Attack Flow:**

1. **Message Reception Without Authentication**: The gRPC service receives messages and extracts the sender's address but never uses it for verification. [1](#0-0) 

2. **Unauthenticated Message Routing**: Messages are routed to handlers based solely on `message_type` without any sender verification. The sender information is completely discarded. [2](#0-1) 

3. **Direct Execution of Untrusted Commands**: The `RemoteCoordinatorClient` receives messages and directly deserializes them into execution commands without verifying the sender is the authorized coordinator. [3](#0-2) 

4. **Arbitrary Transaction Execution**: The `ExecuteBlockCommand` contains arbitrary transactions that will be executed without any authorization. [4](#0-3) 

**Broken Invariants:**
- **Deterministic Execution**: Different shards can be sent different transactions, causing different state roots
- **Consensus Safety**: Attackers can inject transactions that break consensus by manipulating execution results
- **Access Control**: No verification that commands come from legitimate coordinator

**Why This Is Critical:**

The executor service is deployed as a production standalone process that accepts network connections. [5](#0-4) 

Any attacker who can reach the executor shard's network endpoint can:
- Send `RemoteExecutionRequest::ExecuteBlock` with malicious transactions
- Cause different shards to execute different transactions (breaking determinism)
- Inject unauthorized state changes
- Cause consensus failures by producing inconsistent execution results

## Impact Explanation

**Critical Severity** - This vulnerability meets multiple Critical impact categories per the Aptos Bug Bounty:

1. **Consensus/Safety Violations**: An attacker can cause different validator nodes (using different executor shards) to compute different state roots for the same block, violating consensus safety and potentially causing chain splits.

2. **State Integrity Compromise**: Arbitrary transactions can be injected into execution, allowing unauthorized state modifications that bypass all normal transaction validation.

3. **Loss of Deterministic Execution**: The fundamental invariant that all validators produce identical state roots for identical blocks is violated.

4. **Remote Code Execution Context**: While not traditional RCE, the attacker gains the ability to execute arbitrary transaction logic on remote executor processes.

This vulnerability affects the core execution layer and can compromise the entire blockchain's security model. In a production deployment with sharded execution, this would allow complete bypass of the consensus protocol's security guarantees.

## Likelihood Explanation

**High Likelihood** - The vulnerability is trivially exploitable:

1. **No Authentication Required**: No cryptographic signatures, no TLS/mTLS, no IP whitelisting
2. **Direct Network Access**: Executor shards listen on network sockets accessible to any peer
3. **Simple Attack Vector**: Attacker only needs to:
   - Discover the IP:port of an executor shard (from configuration or network scanning)
   - Send a gRPC message with a crafted `ExecuteBlockCommand`
   - The message will be processed without any checks

4. **Low Attacker Requirements**: 
   - No need for validator keys or stake
   - No need to compromise existing infrastructure
   - Only requires basic network access to the executor shard

The vulnerability exists by design in the current architecture - there are no authentication checks anywhere in the code path.

## Recommendation

**Immediate Actions:**

1. **Implement Mutual TLS Authentication**: Require mTLS for all executor service connections with certificate-based authentication.

2. **Add Message Signing**: Implement cryptographic signature verification for all incoming messages:

```rust
// In grpc_network_service/mod.rs - simple_msg_exchange method
async fn simple_msg_exchange(
    &self,
    request: Request<NetworkMessage>,
) -> Result<Response<Empty>, Status> {
    let remote_addr = request.remote_addr();
    let network_message = request.into_inner();
    
    // ADD: Verify message signature
    if !self.verify_sender_signature(&network_message, remote_addr) {
        return Err(Status::unauthenticated("Invalid sender signature"));
    }
    
    // ADD: Check sender is authorized coordinator
    if !self.is_authorized_coordinator(remote_addr) {
        return Err(Status::permission_denied("Unauthorized sender"));
    }
    
    // Existing message processing...
}
```

3. **Implement Sender Allowlist**: Maintain an allowlist of authorized coordinator addresses and reject connections from unknown peers.

4. **Use Existing AptosNet Layer**: Consider migrating from `aptos-secure-net` to the main `AptosNet` layer which already implements NoiseIK authentication and trusted peer sets. [6](#0-5) 

5. **Add Network Isolation**: Deploy executor shards in isolated network segments with strict firewall rules allowing only coordinator connections.

## Proof of Concept

```rust
// Malicious Client PoC - Sends unauthorized execution command to executor shard
use tonic::transport::Channel;
use aptos_protos::remote_executor::v1::{
    NetworkMessage,
    network_message_service_client::NetworkMessageServiceClient,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Target a remote executor shard
    let executor_shard_addr = "http://192.168.1.100:50051";
    
    // Create gRPC client - NO AUTHENTICATION REQUIRED
    let mut client = NetworkMessageServiceClient::connect(executor_shard_addr).await?;
    
    // Craft malicious execution command
    // In real attack, would contain carefully crafted transactions
    // to manipulate state or cause consensus divergence
    let malicious_command = create_malicious_execution_request();
    
    // Serialize to BCS
    let payload = bcs::to_bytes(&malicious_command)?;
    
    // Create network message with proper message type for shard 0
    let message = NetworkMessage {
        message: payload,
        message_type: "execute_command_0".to_string(),
    };
    
    // Send to executor shard - WILL BE ACCEPTED AND EXECUTED
    let request = tonic::Request::new(message);
    let response = client.simple_msg_exchange(request).await?;
    
    println!("Malicious command accepted: {:?}", response);
    Ok(())
}

fn create_malicious_execution_request() -> RemoteExecutionRequest {
    // Create ExecuteBlockCommand with malicious transactions
    // that would be executed without authorization
    use aptos_executor_service::{RemoteExecutionRequest, ExecuteBlockCommand};
    
    RemoteExecutionRequest::ExecuteBlock(ExecuteBlockCommand {
        sub_blocks: /* crafted sub-blocks */,
        concurrency_level: 8,
        onchain_config: /* default config */,
    })
}
```

**Expected Result**: The executor shard will accept the message, deserialize the command, and execute the contained transactions without any authentication check, demonstrating complete bypass of security controls.

**Notes**

This vulnerability exists because `aptos-secure-net` is a separate, simplified network layer distinct from the main AptosNet protocol. While AptosNet uses NoiseIK for authentication and maintains trusted peer sets, the executor service uses this custom gRPC-based layer with no security mechanisms.

The vulnerability affects any production deployment using sharded execution with remote executor processes. The issue is architectural rather than a simple coding bug - the entire `aptos-secure-net` module lacks authentication by design.

### Citations

**File:** secure/net/src/grpc_network_service/mod.rs (L93-114)
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
```

**File:** secure/net/src/network_controller/inbound_handler.rs (L66-74)
```rust
    pub fn send_incoming_message_to_handler(&self, message_type: &MessageType, message: Message) {
        // Check if there is a registered handler for the sender
        if let Some(handler) = self.inbound_handlers.lock().unwrap().get(message_type) {
            // Send the message to the registered handler
            handler.send(message).unwrap();
        } else {
            warn!("No handler registered for message type: {:?}", message_type);
        }
    }
```

**File:** execution/executor-service/src/remote_cordinator_client.rs (L80-113)
```rust
    fn receive_execute_command(&self) -> ExecutorShardCommand<RemoteStateViewClient> {
        match self.command_rx.recv() {
            Ok(message) => {
                let _rx_timer = REMOTE_EXECUTOR_TIMER
                    .with_label_values(&[&self.shard_id.to_string(), "cmd_rx"])
                    .start_timer();
                let bcs_deser_timer = REMOTE_EXECUTOR_TIMER
                    .with_label_values(&[&self.shard_id.to_string(), "cmd_rx_bcs_deser"])
                    .start_timer();
                let request: RemoteExecutionRequest = bcs::from_bytes(&message.data).unwrap();
                drop(bcs_deser_timer);

                match request {
                    RemoteExecutionRequest::ExecuteBlock(command) => {
                        let init_prefetch_timer = REMOTE_EXECUTOR_TIMER
                            .with_label_values(&[&self.shard_id.to_string(), "init_prefetch"])
                            .start_timer();
                        let state_keys = Self::extract_state_keys(&command);
                        self.state_view_client.init_for_block(state_keys);
                        drop(init_prefetch_timer);

                        let (sub_blocks, concurrency, onchain_config) = command.into();
                        ExecutorShardCommand::ExecuteSubBlocks(
                            self.state_view_client.clone(),
                            sub_blocks,
                            concurrency,
                            onchain_config,
                        )
                    },
                }
            },
            Err(_) => ExecutorShardCommand::Stop,
        }
    }
```

**File:** execution/executor-service/src/lib.rs (L44-65)
```rust
pub enum RemoteExecutionRequest {
    ExecuteBlock(ExecuteBlockCommand),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecuteBlockCommand {
    pub(crate) sub_blocks: SubBlocksForShard<AnalyzedTransaction>,
    pub(crate) concurrency_level: usize,
    pub(crate) onchain_config: BlockExecutorConfigFromOnchain,
}

impl ExecuteBlockCommand {
    pub fn into(
        self,
    ) -> (
        SubBlocksForShard<AnalyzedTransaction>,
        usize,
        BlockExecutorConfigFromOnchain,
    ) {
        (self.sub_blocks, self.concurrency_level, self.onchain_config)
    }
}
```

**File:** execution/executor-service/src/main.rs (L27-48)
```rust
fn main() {
    let args = Args::parse();
    aptos_logger::Logger::new().init();

    let (tx, rx) = crossbeam_channel::unbounded();
    ctrlc::set_handler(move || {
        tx.send(()).unwrap();
    })
    .expect("Error setting Ctrl-C handler");

    let _exe_service = ProcessExecutorService::new(
        args.shard_id,
        args.num_shards,
        args.num_executor_threads,
        args.coordinator_address,
        args.remote_executor_addresses,
    );

    rx.recv()
        .expect("Could not receive Ctrl-C msg from channel.");
    info!("Process executor service shutdown successfully.");
}
```

**File:** network/README.md (L22-34)
```markdown
The network component uses:

* TCP for reliable transport.
* [NoiseIK] for authentication and full end-to-end encryption.
* On-chain [`NetworkAddress`](../types/src/network_address/mod.rs) set for discovery, with
  optional seed peers in the [`NetworkConfig`]
  as a fallback.

Validators will only allow connections from other validators. Their identity and
public key information is provided by the [`validator-set-discovery`] protocol,
which updates the eligible member information on each consensus reconfiguration.
Each member of the validator network maintains a full membership view and connects
directly to all other validators in order to maintain a full-mesh network.
```
