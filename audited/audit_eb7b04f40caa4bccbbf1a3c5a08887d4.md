# Audit Report

## Title
Unauthenticated Remote Access to Distributed Block Execution Service via simple_msg_exchange

## Summary
The `simple_msg_exchange` gRPC endpoint in the remote executor service lacks any authentication or authorization mechanism, allowing any network peer that can establish a TCP connection to send arbitrary execution commands, fake execution results, or interfere with state synchronization. While `remote_addr()` is extracted from requests, it is only used for error logging and never for access control verification. [1](#0-0) 

## Finding Description

The remote executor service is designed to enable distributed block execution by sharding work across multiple processes that communicate via gRPC. The `GRPCNetworkMessageServiceServerWrapper` implements the `simple_msg_exchange` endpoint which receives `NetworkMessage` objects and routes them to registered handlers based on `message_type`.

**Critical Security Gap:**

The implementation extracts the remote address from the incoming request but never performs any authentication or authorization checks: [2](#0-1) 

The `remote_addr` is only used in error logging, not for verifying that the sender is an authorized coordinator or shard. Messages are routed to handlers based solely on the `message_type` string, with no verification of sender identity, no authentication tokens, no TLS client certificates, and no IP whitelisting.

**Attack Vector:**

An attacker who can establish a TCP connection to the gRPC server can:

1. Send malicious `ExecuteBlockCommand` messages to executor shards by crafting messages with `message_type` matching the pattern `"execute_command_{shard_id}"`
2. Send fake `RemoteExecutionResult` messages to the coordinator with `message_type` `"execute_result_{shard_id}"`
3. Interfere with state synchronization by sending malicious KV requests/responses
4. Disrupt cross-shard communication

The production deployment accepts arbitrary socket addresses via command-line arguments with no enforcement of localhost-only or trusted network restrictions: [3](#0-2) 

**Comparison with Other Services:**

Other gRPC services in the Aptos codebase DO implement authentication (e.g., the indexer service uses token-based authentication), highlighting that this omission is not a platform limitation but a missing security control.

The remote executor service is initialized without any authentication layer: [4](#0-3) 

No interceptor is added to validate credentials before messages reach the handler.

## Impact Explanation

**Severity: HIGH** - This vulnerability meets the "Significant protocol violations" criteria from the Aptos bug bounty program.

**Potential Impacts:**

1. **Block Execution Manipulation**: An attacker could send crafted execution commands to shards, potentially causing incorrect transaction execution or state corruption, violating the **Deterministic Execution** invariant.

2. **Consensus Integrity Risk**: By sending fake execution results to the coordinator, an attacker could cause validators to commit different state roots, potentially violating the **Consensus Safety** invariant.

3. **State Consistency Violation**: Malicious state view requests/responses could corrupt the distributed state view, violating the **State Consistency** invariant.

4. **Denial of Service**: Flooding the service with messages could degrade validator performance, meeting the "Validator node slowdowns" HIGH severity criterion.

5. **Access Control Failure**: The complete absence of authentication violates the **Access Control** invariant requiring protection of critical system components.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH** depending on deployment configuration.

**Factors Increasing Likelihood:**
- The service accepts arbitrary socket addresses including public IPs
- No code-level enforcement of localhost-only deployment
- No warnings in documentation about network security requirements
- Message types follow predictable patterns (`execute_command_0`, `execute_result_1`, etc.)
- BCS serialization format is publicly documented, enabling payload crafting

**Factors Decreasing Likelihood:**
- Service may be deployed behind firewalls in production environments
- Operators may use network-level access controls (though code doesn't enforce this)
- Attackers need network connectivity to the gRPC endpoints

**Critical Concern:** The lack of defense-in-depth means that a single network misconfiguration (exposed port, VPN failure, cloud security group error) immediately exposes the vulnerability.

## Recommendation

**Implement Multi-Layer Authentication:**

1. **Add gRPC Interceptor Authentication**: Implement a token-based or mTLS authentication interceptor to verify caller identity before processing any messages.

2. **Validate Remote Address Against Whitelist**: Even with authentication, validate that `remote_addr()` matches expected coordinator/shard addresses.

3. **Add Network-Level Restrictions**: Enforce localhost-only binding when shards run on the same host, or enforce VPN/private network requirements in documentation.

**Proposed Code Fix:**

```rust
// Add authentication interceptor
use tonic::metadata::MetadataValue;

fn authenticate_request(req: Request<()>) -> Result<Request<()>, Status> {
    let token = req.metadata()
        .get("authorization")
        .and_then(|t| t.to_str().ok());
    
    match token {
        Some(t) if validate_token(t) => Ok(req),
        _ => Err(Status::unauthenticated("Invalid credentials")),
    }
}

// Modify server setup
Server::builder()
    .timeout(std::time::Duration::from_millis(rpc_timeout_ms))
    .add_service(
        NetworkMessageServiceServer::with_interceptor(self, authenticate_request)
            .max_decoding_message_size(MAX_MESSAGE_SIZE),
    )
    // ...
```

4. **Validate Sender in Handler**: As an additional layer, verify the remote address in `simple_msg_exchange`:

```rust
async fn simple_msg_exchange(
    &self,
    request: Request<NetworkMessage>,
) -> Result<Response<Empty>, Status> {
    let remote_addr = request.remote_addr()
        .ok_or_else(|| Status::internal("No remote address"))?;
    
    // Validate remote_addr is in allowed peers list
    if !self.is_authorized_peer(&remote_addr) {
        return Err(Status::permission_denied("Unauthorized peer"));
    }
    
    // ... rest of implementation
}
```

## Proof of Concept

```rust
// Malicious client demonstrating unauthenticated access
use aptos_protos::remote_executor::v1::{
    network_message_service_client::NetworkMessageServiceClient,
    NetworkMessage,
};
use tonic::Request;

#[tokio::main]
async fn main() {
    // Connect to remote executor shard (no credentials needed)
    let target_shard = "http://victim-shard:52201";
    let mut client = NetworkMessageServiceClient::connect(target_shard)
        .await
        .expect("Failed to connect");
    
    // Craft malicious execution command (BCS-serialized payload)
    let malicious_command = vec![/* crafted BCS payload */];
    
    // Send unauthenticated message that will be processed
    let request = Request::new(NetworkMessage {
        message: malicious_command,
        message_type: "execute_command_0".to_string(), // Predictable pattern
    });
    
    // This succeeds with no authentication!
    client.simple_msg_exchange(request)
        .await
        .expect("Attack succeeded - no auth required");
    
    println!("Successfully sent malicious command without authentication");
}
```

**Notes:**
- This vulnerability represents a significant defense-in-depth failure even if deployed in "trusted" networks
- The complete absence of authentication in critical execution infrastructure is a HIGH severity issue per Aptos bug bounty criteria
- The code should enforce secure-by-default behavior rather than relying on operational security
- While `remote_addr()` itself is trustworthy (reflects actual TCP peer), the lack of any validation using it or other mechanisms is the core vulnerability

### Citations

**File:** secure/net/src/grpc_network_service/mod.rs (L75-79)
```rust
        Server::builder()
            .timeout(std::time::Duration::from_millis(rpc_timeout_ms))
            .add_service(
                NetworkMessageServiceServer::new(self).max_decoding_message_size(MAX_MESSAGE_SIZE),
            )
```

**File:** secure/net/src/grpc_network_service/mod.rs (L93-115)
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
    }
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
