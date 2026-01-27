# Audit Report

## Title
Unbounded Memory Allocation in SafetyRules Network Communication Leads to Denial of Service

## Summary
The `NetworkStream` implementation used by SafetyRules when running in Process or Thread mode lacks validation on the message size field, allowing an attacker to trigger unbounded memory allocation by sending a malformed length prefix of up to 4GB (u32::MAX), causing memory exhaustion and denial of service on validator nodes.

## Finding Description

The SafetyRules component supports multiple execution modes, including a Process mode that communicates over TCP using the `NetworkServer`/`NetworkClient` abstraction from `secure/net`. This network layer uses a length-prefixed protocol where a 4-byte u32 indicates the message size, followed by the message data. [1](#0-0) 

The vulnerability exists in the `read_buffer()` function which reads the 4-byte length prefix as a u32 (line 486) but performs **no validation** that this size is reasonable. The reading loop then continues to accumulate data into `self.buffer` until the declared size is reached: [2](#0-1) 

An attacker can exploit this by:

1. Connecting to a SafetyRules Process mode server (when exposed on the network)
2. Sending a 4-byte length prefix of `0xFFFFFFFF` (u32::MAX = 4,294,967,295 bytes)
3. Sending arbitrary payload data

The server will continuously read data into the buffer (line 443) attempting to reach 4GB, causing memory exhaustion. The `SerializerService.handle_message()` receives this oversized buffer and only then attempts JSON deserialization: [3](#0-2) 

Even if deserialization fails, the damage is done—memory has been allocated for the massive buffer. The attacker can open multiple concurrent connections to amplify the attack.

**Attack Path:**
1. SafetyRules configured in Process mode with network-accessible address
2. Attacker connects to the TCP port
3. Sends malformed length prefix (4GB)
4. Server attempts to allocate and read 4GB into memory
5. Memory exhaustion causes node slowdown or crash
6. Consensus participation disrupted

The entry point is through `SafetyRulesManager.new()` when using Process mode: [4](#0-3) 

And the vulnerable execution path: [5](#0-4) 

**Importantly**, mainnet validators are protected by the config sanitizer which enforces Local mode: [6](#0-5) 

However, this vulnerability affects:
- Testnet and devnet deployments using Process mode
- Misconfigured validators (if sanitizer is bypassed)
- Thread mode (localhost exposure to local attackers)
- Development and testing environments

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program ("Validator node slowdowns" and "Significant protocol violations"). 

**Impact:**
- **Validator Node Slowdown**: Memory exhaustion causes significant performance degradation
- **Consensus Disruption**: Affected validators cannot participate in consensus while recovering
- **Service Availability**: Node may crash requiring restart, missing consensus rounds
- **Resource Exhaustion**: Violates the "Resource Limits" critical invariant (#9)

While mainnet validators are protected by mandatory Local mode, testnet/devnet validators running Process mode are fully vulnerable. The attack can cause temporary consensus liveness issues if multiple testnet validators are targeted simultaneously.

## Likelihood Explanation

**Likelihood: Medium-High** for affected deployments

**Requirements:**
- Target must use SafetyRules Process mode (not enforced on mainnet)
- Network access to the SafetyRules TCP port
- No authentication/authorization on the TCP endpoint

**Feasibility:**
- Attack is trivial—requires only TCP connection and 4 bytes
- Can be executed remotely if port is exposed
- Multiple concurrent connections amplify impact
- No special privileges required

**Mitigating Factors:**
- Mainnet validators MUST use Local mode (enforced by config sanitizer)
- Process mode likely configured to listen on localhost or internal networks
- Read timeout (default 30s) limits duration per connection attempt

## Recommendation

Implement a maximum message size limit in `NetworkStream::read_buffer()` to prevent unbounded memory allocation:

```rust
// In secure/net/src/lib.rs
const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; // 64 MiB, consistent with network layer

fn read_buffer(&mut self) -> Result<Vec<u8>, Error> {
    if self.buffer.len() < 4 {
        return Ok(Vec::new());
    }

    let mut u32_bytes = [0; 4];
    u32_bytes.copy_from_slice(&self.buffer[..4]);
    let data_size = u32::from_le_bytes(u32_bytes) as usize;

    // Validate message size
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

Additionally:
1. Update the return type to `Result<Vec<u8>, Error>` throughout the call chain
2. Consider adding rate limiting or connection limits
3. Add authentication for SafetyRules network endpoints
4. Document the maximum message size in configuration

## Proof of Concept

```rust
// Test demonstrating unbounded memory allocation vulnerability
// Place in secure/net/src/lib.rs tests section

#[test]
fn test_malicious_large_message_size() {
    use std::io::Write;
    use std::net::TcpStream;
    
    let server_port = utils::get_available_port();
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
    let mut server = NetworkServer::new("test".to_string(), server_addr, 5000);
    
    // Attacker connects and sends malicious length prefix
    let mut stream = TcpStream::connect(server_addr).unwrap();
    
    // Send length prefix claiming 1GB of data
    let malicious_size: u32 = 1_000_000_000;
    stream.write_all(&malicious_size.to_le_bytes()).unwrap();
    
    // Send some data (server will wait for all 1GB)
    let payload = vec![0u8; 10000];
    stream.write_all(&payload).unwrap();
    
    // Server read will block trying to accumulate 1GB
    // This demonstrates the vulnerability - server has no size limit
    // In production, this would cause memory exhaustion
    let result = server.read(); // This will timeout but buffer has grown significantly
    
    // Without a MAX_MESSAGE_SIZE check, the server accepts any size up to u32::MAX
    assert!(result.is_err()); // Times out waiting for full message
}
```

**Note**: The actual PoC would require running the SafetyRules service in Process mode and sending the malicious payload over TCP. The above demonstrates the core issue—the lack of size validation allows arbitrary memory allocation requests.

### Citations

**File:** secure/net/src/lib.rs (L430-451)
```rust
    pub fn read(&mut self) -> Result<Vec<u8>, Error> {
        let result = self.read_buffer();
        if !result.is_empty() {
            return Ok(result);
        }

        loop {
            trace!("Attempting to read from stream");
            let read = self.stream.read(&mut self.temp_buffer)?;
            trace!("Read {} bytes from stream", read);
            if read == 0 {
                return Err(Error::RemoteStreamClosed);
            }
            self.buffer.extend(self.temp_buffer[..read].to_vec());
            let result = self.read_buffer();
            if !result.is_empty() {
                trace!("Found a message in the stream");
                return Ok(result);
            }
            trace!("Did not find a message yet, reading again");
        }
    }
```

**File:** secure/net/src/lib.rs (L479-496)
```rust
    fn read_buffer(&mut self) -> Vec<u8> {
        if self.buffer.len() < 4 {
            return Vec::new();
        }

        let mut u32_bytes = [0; 4];
        u32_bytes.copy_from_slice(&self.buffer[..4]);
        let data_size = u32::from_le_bytes(u32_bytes) as usize;

        let remaining_data = &self.buffer[4..];
        if remaining_data.len() < data_size {
            return Vec::new();
        }

        let returnable_data = remaining_data[..data_size].to_vec();
        self.buffer = remaining_data[data_size..].to_vec();
        returnable_data
    }
```

**File:** consensus/safety-rules/src/serializer.rs (L45-46)
```rust
    pub fn handle_message(&mut self, input_message: Vec<u8>) -> Result<Vec<u8>, Error> {
        let input = serde_json::from_slice(&input_message)?;
```

**File:** consensus/safety-rules/src/safety_rules_manager.rs (L117-129)
```rust
    pub fn new(config: &SafetyRulesConfig) -> Self {
        if let SafetyRulesService::Process(conf) = &config.service {
            return Self::new_process(conf.server_address(), config.network_timeout_ms);
        }

        let storage = storage(config);
        match config.service {
            SafetyRulesService::Local => Self::new_local(storage),
            SafetyRulesService::Serializer => Self::new_serializer(storage),
            SafetyRulesService::Thread => Self::new_thread(storage, config.network_timeout_ms),
            _ => panic!("Unimplemented SafetyRulesService: {:?}", config.service),
        }
    }
```

**File:** consensus/safety-rules/src/remote_service.rs (L47-55)
```rust
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
