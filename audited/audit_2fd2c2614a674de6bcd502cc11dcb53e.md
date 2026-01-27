# Audit Report

## Title
Unauthenticated Remote Executor Service Enables Protocol Downgrade and Denial-of-Service Attacks

## Summary
The `ExecutorService` exposes an unauthenticated gRPC endpoint that accepts and deserializes messages without any protocol version validation or authentication. This enables attackers to crash executor shards via malformed messages and creates the infrastructure for future protocol downgrade attacks when schema changes occur.

## Finding Description

The remote executor service implements a distributed execution architecture where a coordinator distributes transaction execution work to multiple executor shards. Communication between these components occurs over gRPC using BCS-serialized messages.

### Critical Security Gaps:

**1. No Authentication or TLS**

The gRPC server is started without any authentication or TLS configuration: [1](#0-0) 

The server builder lacks `.tls_config()` or any authentication middleware, meaning any network peer can connect and send messages to the executor shard.

**2. Unsafe Deserialization Without Version Validation**

When the coordinator client receives execution commands, it deserializes them directly without any version checking: [2](#0-1) 

The `.unwrap()` call means that any deserialization failure will cause a panic, crashing the executor shard.

**3. No Protocol Version Field**

The message structures lack any version identifier: [3](#0-2) 

Without version fields, there is no mechanism to:
- Detect protocol version mismatches
- Reject messages from older/incompatible protocol versions
- Negotiate compatible protocol versions during connection establishment
- Validate that all shards are using the same protocol version

**4. Security-Critical Configuration in Unversioned Messages**

The `ExecuteBlockCommand` carries `BlockExecutorConfigFromOnchain` which contains security-critical parameters including gas limits: [4](#0-3) 

If this structure evolves (e.g., adding new security fields), there's no protection against downgrade attacks where an attacker sends messages with an older schema that lacks these protections.

**5. gRPC Reflection Enabled**

The server enables gRPC reflection, allowing attackers to enumerate services and methods: [5](#0-4) 

### Attack Scenarios:

**Scenario 1: Immediate DoS Attack**
1. Attacker discovers the executor shard's socket address (configured via command line arguments)
2. Attacker connects to the unauthenticated gRPC endpoint
3. Attacker sends malformed BCS data in a `NetworkMessage`
4. The shard attempts to deserialize: `bcs::from_bytes(&message.data).unwrap()`
5. Deserialization fails, `.unwrap()` panics, shard process crashes
6. Block execution stalls, requiring manual shard restart

**Scenario 2: Future Protocol Downgrade Attack**
1. Aptos team patches a security vulnerability by adding a new field to `BlockExecutorConfigFromOnchain` (e.g., `max_execution_time_ms` to prevent infinite loops)
2. All shards are upgraded to the new protocol version
3. Attacker crafts a message using the OLD schema (without the new security field)
4. Shard receives and successfully deserializes the old-format message (BCS is permissive with extra/missing fields in some cases)
5. Execution proceeds without the new security protection
6. Attacker exploits the previously-patched vulnerability

**Scenario 3: Consensus Split via Version Heterogeneity**
1. During a rolling upgrade, some shards run version N, others run version N+1
2. Attacker sends version N messages to version N+1 shards
3. Different shards process the same transaction set with different protocol semantics
4. Shards produce different execution results for the same block
5. Consensus safety invariant is violated: "All validators must produce identical state roots for identical blocks"

## Impact Explanation

This vulnerability meets **HIGH severity** criteria per the Aptos bug bounty program:

- **Validator node crashes**: The DoS attack via malformed messages directly causes shard crashes, qualifying as "validator node slowdowns" or complete unavailability of the executor service
- **Significant protocol violations**: Lack of version validation enables future protocol violations when schema changes occur
- **Consensus risk**: If different shards process different protocol versions, they may produce different execution results, violating deterministic execution and potentially causing state divergence

While not immediately causing fund loss, the vulnerability creates conditions for:
- **Liveness failure**: Crashed shards prevent block execution
- **Safety violation risk**: Future version heterogeneity could cause state root mismatches
- **Exploitation of future CVEs**: Once a vulnerability is patched, attackers can force shards to process old-format messages that re-introduce the vulnerability

## Likelihood Explanation

**HIGH likelihood** due to:

1. **No authentication required**: Any network peer can connect to the gRPC endpoint
2. **Simple attack execution**: Standard gRPC tools can send malicious messages
3. **Discoverable endpoints**: Socket addresses are configuration parameters that may be exposed via logs, configuration files, or network scanning
4. **No defense in depth**: No rate limiting, authentication, or version validation provides any protection
5. **Production deployment**: The service has a standalone `main.rs` entry point with command-line argument parsing, indicating it's designed for production use: [6](#0-5) 

The only limiting factor is that the executor service may be deployed behind a firewall or on internal networks, but this is a weak security assumption that violates defense-in-depth principles.

## Recommendation

Implement a comprehensive security model for the remote executor service:

### 1. Add Protocol Version Validation

Add a version field to all message types and validate it during deserialization:

```rust
// In execution/executor-service/src/lib.rs
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RemoteExecutionRequest {
    pub protocol_version: u32,  // Add this field
    pub inner: RemoteExecutionRequestInner,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum RemoteExecutionRequestInner {
    ExecuteBlock(ExecuteBlockCommand),
}

const CURRENT_PROTOCOL_VERSION: u32 = 1;
const MIN_SUPPORTED_PROTOCOL_VERSION: u32 = 1;

impl RemoteExecutionRequest {
    pub fn validate_version(&self) -> Result<(), String> {
        if self.protocol_version < MIN_SUPPORTED_PROTOCOL_VERSION {
            return Err(format!(
                "Protocol version {} is too old. Minimum supported: {}",
                self.protocol_version, MIN_SUPPORTED_PROTOCOL_VERSION
            ));
        }
        if self.protocol_version > CURRENT_PROTOCOL_VERSION {
            return Err(format!(
                "Protocol version {} is too new. Current version: {}",
                self.protocol_version, CURRENT_PROTOCOL_VERSION
            ));
        }
        Ok(())
    }
}
```

### 2. Replace unwrap() with Graceful Error Handling

In `remote_cordinator_client.rs`, handle deserialization errors gracefully:

```rust
// In receive_execute_command()
let request: RemoteExecutionRequest = match bcs::from_bytes(&message.data) {
    Ok(req) => {
        // Validate protocol version
        if let Err(e) = req.validate_version() {
            error!("Invalid protocol version: {}", e);
            return ExecutorShardCommand::Stop;
        }
        req
    },
    Err(e) => {
        error!("Failed to deserialize execution request: {}", e);
        return ExecutorShardCommand::Stop;
    }
};
```

### 3. Implement mTLS Authentication

Add mutual TLS to the gRPC server (following the pattern from indexer services):

```rust
// In grpc_network_service/mod.rs
use tonic::transport::{Identity, ServerTlsConfig};

pub fn start_with_tls(
    self,
    rt: &Runtime,
    server_addr: SocketAddr,
    cert_path: &str,
    key_path: &str,
    client_ca_cert_path: &str,  // For mutual TLS
    server_shutdown_rx: oneshot::Receiver<()>,
) {
    let cert = std::fs::read(cert_path).expect("Failed to read cert");
    let key = std::fs::read(key_path).expect("Failed to read key");
    let identity = Identity::from_pem(cert, key);
    
    let client_ca_cert = std::fs::read(client_ca_cert_path)
        .expect("Failed to read client CA cert");
    
    let tls_config = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(tonic::transport::Certificate::from_pem(client_ca_cert));
    
    rt.spawn(async move {
        Server::builder()
            .tls_config(tls_config).unwrap()
            .add_service(NetworkMessageServiceServer::new(self))
            .serve_with_shutdown(server_addr, async {
                server_shutdown_rx.await.ok();
            })
            .await
            .unwrap();
    });
}
```

### 4. Disable gRPC Reflection in Production

Remove or make conditional the reflection service for production deployments.

### 5. Implement Connection-Level Version Negotiation

Add a handshake phase similar to the main Aptos network protocol where peers negotiate protocol versions before accepting execution commands.

## Proof of Concept

```rust
// DoS Attack PoC - Send malformed message to crash executor shard
use tonic::transport::Channel;
use aptos_protos::remote_executor::v1::{
    network_message_service_client::NetworkMessageServiceClient,
    NetworkMessage,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Target an executor shard (example address)
    let shard_address = "http://127.0.0.1:52201";
    
    // Connect to the unauthenticated endpoint
    let mut client = NetworkMessageServiceClient::connect(shard_address).await?;
    
    println!("Connected to executor shard at {}", shard_address);
    
    // Send malformed BCS data that will fail deserialization
    let malformed_message = NetworkMessage {
        message: vec![0xFF, 0xFF, 0xFF, 0xFF],  // Invalid BCS data
        message_type: "execute_command_0".to_string(),
    };
    
    // This will cause the shard to panic when it tries to deserialize
    match client.simple_msg_exchange(malformed_message).await {
        Ok(_) => println!("Message sent successfully - shard should crash soon"),
        Err(e) => println!("gRPC error: {}", e),
    }
    
    Ok(())
}

// Expected result: The executor shard will panic at:
// remote_cordinator_client.rs:89 - bcs::from_bytes(&message.data).unwrap()
// This causes the shard process to crash, halting execution for that shard
```

**Version Downgrade Attack PoC Scenario** (Future):
```rust
// Assumes BlockExecutorConfigFromOnchain evolves from V1 to V2
// V1: { block_gas_limit_type, enable_per_block_gas_limit }
// V2: { block_gas_limit_type, enable_per_block_gas_limit, per_block_gas_limit, gas_price_to_burn }

// Attacker crafts a V1 message even though shards expect V2
// Since there's no version checking, the shard may:
// 1. Deserialize with default values for missing fields
// 2. Process the execution with incomplete security configuration
// 3. Potentially exploit whatever vulnerability was fixed by adding those fields
```

## Notes

**Additional Context:**

1. **Deployment Model**: The ExecutorService is designed as a standalone process for distributed execution across shards, with command-line configuration for production deployment.

2. **Comparison with Main Network Layer**: The main Aptos P2P network (in `network/framework/`) implements proper authentication via Noise protocol and version negotiation via handshake messages. The executor service lacks these protections entirely.

3. **Current vs Future Risk**: While no older protocol versions exist today, the lack of version validation creates a **structural vulnerability** that will enable downgrade attacks whenever the protocol evolves. This is a violation of secure protocol design principles.

4. **Defense in Depth**: The vulnerability is exacerbated by the lack of defense layers:
   - No network-level authentication
   - No application-level version validation  
   - No graceful error handling
   - No rate limiting or anomaly detection

5. **Invariant Violations**:
   - **Deterministic Execution**: Different protocol versions could cause different execution results across shards
   - **State Consistency**: Version heterogeneity risks state divergence
   - **Resource Limits**: Malformed messages bypass normal validation, potentially affecting gas accounting

**Severity Justification**: This qualifies as **HIGH severity** under the Aptos bug bounty program because it enables "validator node slowdowns" (crashes via DoS) and "significant protocol violations" (lack of version validation enabling future exploits). While it doesn't immediately cause fund loss, it creates critical infrastructure weaknesses that undermine execution integrity.

### Citations

**File:** secure/net/src/grpc_network_service/mod.rs (L63-86)
```rust
        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
            .build_v1()
            .unwrap();

        info!("Starting Server async at {:?}", server_addr);
        // NOTE: (1) serve_with_shutdown() starts the server, if successful the task does not return
        //           till the server is shutdown. Hence this should be called as a separate
        //           non-blocking task. Signal handler 'server_shutdown_rx' is needed to shutdown
        //           the server
        //       (2) There is no easy way to know if/when the server has started successfully. Hence
        //           we may need to implement a healthcheck service to check if the server is up
        Server::builder()
            .timeout(std::time::Duration::from_millis(rpc_timeout_ms))
            .add_service(
                NetworkMessageServiceServer::new(self).max_decoding_message_size(MAX_MESSAGE_SIZE),
            )
            .add_service(reflection_service)
            .serve_with_shutdown(server_addr, async {
                server_shutdown_rx.await.ok();
                info!("Received signal to shutdown server at {:?}", server_addr);
            })
            .await
            .unwrap();
```

**File:** execution/executor-service/src/remote_cordinator_client.rs (L89-89)
```rust
                let request: RemoteExecutionRequest = bcs::from_bytes(&message.data).unwrap();
```

**File:** execution/executor-service/src/lib.rs (L43-53)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum RemoteExecutionRequest {
    ExecuteBlock(ExecuteBlockCommand),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecuteBlockCommand {
    pub(crate) sub_blocks: SubBlocksForShard<AnalyzedTransaction>,
    pub(crate) concurrency_level: usize,
    pub(crate) onchain_config: BlockExecutorConfigFromOnchain,
}
```

**File:** types/src/block_executor/config.rs (L84-90)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockExecutorConfigFromOnchain {
    pub block_gas_limit_type: BlockGasLimitType,
    enable_per_block_gas_limit: bool,
    per_block_gas_limit: Option<u64>,
    gas_price_to_burn: Option<u64>,
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
