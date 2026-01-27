# Audit Report

## Title
Inbound Stream Message Size Limit Bypass via Unchecked Header Data Size

## Summary
The `InboundStream` implementation fails to validate the size of message data contained in the `StreamHeader`, and does not enforce `max_message_size` limits on the total accumulated message size after fragment assembly. This allows malicious peers to send oversized RPC responses that exceed configured memory limits, leading to memory exhaustion and potential node crashes.

## Finding Description

The streaming protocol in Aptos network framework is designed to split large messages into fragments for transmission. The system enforces limits through:
- `max_frame_size`: Maximum size of individual serialized frames (default: 4 MiB)
- `max_message_size`: Maximum total message size (default: 64 MiB)
- `max_fragments`: Calculated as `max_message_size / max_frame_size` (typically 16) [1](#0-0) 

**Vulnerability in Outbound Stream (Honest Sender):**

When sending a message, `OutboundStream::stream_message()` correctly validates the total message size and splits it properly. The first `max_frame_size` bytes remain in the header message, and the remainder is chunked into fragments: [2](#0-1) [3](#0-2) 

For a legitimate 64 MiB response: header contains 4 MiB, then 15 fragments of 4 MiB each = 64 MiB total.

**Vulnerability in Inbound Stream (Receiver):**

The receiver's `InboundStream::new()` validates that `num_fragments <= max_fragments`, but **does NOT validate the size of the message data already present in the header**: [4](#0-3) 

Subsequently, `append_fragment()` blindly appends fragment data to the response without tracking or validating total accumulated size: [5](#0-4) 

The critical append operation at line 207 has no size checks: [6](#0-5) 

**Attack Scenario:**

A malicious peer can exploit this by:

1. Sending a `StreamHeader` with:
   - `num_fragments = 16` (passes validation: 16 ≤ max_fragments)
   - `message = RpcResponse` with `raw_response` containing **4 MiB of data**
   - **No validation occurs on this initial 4 MiB**

2. Sending 16 `StreamFragment` messages, each with `raw_data` of approximately 4 MiB

3. The receiver appends: **4 MiB (header) + 16 × 4 MiB (fragments) = 68 MiB total**

4. This exceeds the configured `max_message_size` of 64 MiB by **4 MiB (6.25% overflow)**

The `max_fragments` calculation assumes fragments will account for ALL data, but fails to account for data already present in the header message. The receiver at peer initialization calculates: [7](#0-6) 

This calculation is flawed because it assumes the header contains no data, but in reality, the header can contain up to `max_frame_size` bytes of message data.

Furthermore, after fragment assembly completes, there is no post-assembly validation of the total message size. The assembled message is directly passed to `handle_inbound_network_message()` without size checks: [8](#0-7) [9](#0-8) 

## Impact Explanation

**Severity: Medium**

This vulnerability allows an attacker to bypass message size limits, leading to:

1. **Memory Exhaustion**: Each malicious response can exceed limits by up to `max_frame_size` (4 MiB with defaults). With concurrent requests, an attacker can amplify this to cause significant memory pressure.

2. **Node Instability**: Validator and fullnode memory exhaustion can lead to crashes, affecting network liveness and availability. This impacts the invariant: "Resource Limits: All operations must respect gas, storage, and computational limits."

3. **Amplified DoS**: An attacker can send multiple concurrent RPC requests and respond with oversized messages, multiplying the memory impact. With `MAX_CONCURRENT_INBOUND_RPCS = 100`, an attacker could force allocation of up to 6.8 GiB (100 × 68 MiB) of memory. [10](#0-9) 

This qualifies as **Medium severity** per the bug bounty criteria: "State inconsistencies requiring intervention" and can lead to validator node slowdowns or crashes, affecting network availability.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **No Special Privileges Required**: Any network peer can send RPC requests and craft malicious responses. No validator access or insider knowledge is needed.

2. **Simple Exploitation**: The attack requires only:
   - Connecting to a target node as a peer
   - Sending RPC requests 
   - Crafting responses with oversized headers and maximum fragments

3. **No Detection Mechanisms**: The current implementation has no logging or alerting for oversized messages, making the attack difficult to detect.

4. **Direct Network Exposure**: All Aptos nodes accept inbound connections from peers, exposing this vulnerability to any attacker on the network.

## Recommendation

Implement size validation at multiple layers:

**1. Validate header message data size in `InboundStream::new()`:**

```rust
fn new(header: StreamHeader, max_fragments: usize) -> anyhow::Result<Self> {
    // ... existing validation ...
    
    // NEW: Validate the initial message data size in header
    let header_data_len = match &header_message {
        NetworkMessage::RpcRequest(request) => request.raw_request.len(),
        NetworkMessage::RpcResponse(response) => response.raw_response.len(),
        NetworkMessage::DirectSendMsg(message) => message.raw_msg.len(),
        NetworkMessage::Error(_) => 0,
    };
    
    ensure!(
        header_data_len <= max_frame_size,
        "Header message data size {} exceeds max frame size {}!",
        header_data_len,
        max_frame_size
    );
    
    Ok(Self {
        request_id: header.request_id,
        num_fragments: header_num_fragments,
        received_fragment_id: 0,
        message: header_message,
    })
}
```

**2. Track and validate total accumulated size in `InboundStream::append_fragment()`:**

```rust
struct InboundStream {
    request_id: u32,
    num_fragments: u8,
    received_fragment_id: u8,
    message: NetworkMessage,
    accumulated_size: usize,  // NEW FIELD
    max_message_size: usize,  // NEW FIELD
}

fn append_fragment(&mut self, mut fragment: StreamFragment) -> anyhow::Result<bool> {
    // ... existing validation ...
    
    // NEW: Validate accumulated size before appending
    let new_accumulated_size = self.accumulated_size
        .checked_add(fragment.raw_data.len())
        .ok_or_else(|| anyhow::anyhow!("Accumulated size overflow!"))?;
    
    ensure!(
        new_accumulated_size <= self.max_message_size,
        "Total message size {} exceeds max message size {}!",
        new_accumulated_size,
        self.max_message_size
    );
    
    // Append the fragment data to the message
    let raw_data = &mut fragment.raw_data;
    match &mut self.message {
        // ... existing append logic ...
    }
    
    // Update accumulated size
    self.accumulated_size = new_accumulated_size;
    
    // Return whether the stream is complete
    let is_stream_complete = self.received_fragment_id == self.num_fragments;
    Ok(is_stream_complete)
}
```

**3. Pass `max_message_size` through the initialization chain:**

Update `InboundStreamBuffer::new()` and `InboundStream::new()` signatures to accept `max_message_size` parameter, and pass it from `Peer::new()`.

## Proof of Concept

```rust
#[cfg(test)]
mod test_overflow {
    use super::*;
    use crate::protocols::wire::messaging::v1::{RpcResponse, NetworkMessage};

    #[test]
    fn test_oversized_response_via_header_data() {
        // Configuration
        let max_message_size = 64 * 1024 * 1024; // 64 MiB
        let max_frame_size = 4 * 1024 * 1024;    // 4 MiB
        let max_fragments = max_message_size / max_frame_size; // 16
        
        // Create a malicious header with 4 MiB of data in raw_response
        let initial_data = vec![0u8; max_frame_size];
        let header = StreamHeader {
            request_id: 1,
            num_fragments: 16,  // Maximum allowed
            message: NetworkMessage::RpcResponse(RpcResponse {
                request_id: 1,
                priority: 0,
                raw_response: initial_data,  // 4 MiB already in header!
            }),
        };
        
        // Create stream buffer and start stream
        let mut buffer = InboundStreamBuffer::new(max_fragments);
        buffer.new_stream(header).expect("Header should be accepted");
        
        // Send 16 fragments of ~4 MiB each
        let mut total_size = max_frame_size; // Count header data
        for i in 1..=16 {
            let fragment = StreamFragment {
                request_id: 1,
                fragment_id: i,
                raw_data: vec![0u8; max_frame_size - 100], // ~4 MiB minus overhead
            };
            total_size += fragment.raw_data.len();
            
            let result = buffer.append_fragment(fragment);
            assert!(result.is_ok(), "Fragment {} should be accepted", i);
        }
        
        // Total size exceeds max_message_size!
        assert!(
            total_size > max_message_size,
            "Total size {} should exceed max_message_size {}",
            total_size,
            max_message_size
        );
        
        // This test demonstrates the vulnerability: all fragments were accepted
        // despite the total size exceeding the limit
    }
}
```

## Notes

This vulnerability affects all network message types (`RpcRequest`, `RpcResponse`, `DirectSendMsg`) that use the streaming protocol. The overflow amount is bounded by `max_frame_size`, but with concurrent connections and the ability to trigger multiple RPC requests, an attacker can amplify the memory exhaustion impact significantly. The fix should be implemented consistently across all message types and include proper initialization of tracking fields through the construction chain.

### Citations

**File:** config/src/config/network_config.rs (L49-50)
```rust
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024; /* 4 MiB large messages will be chunked into multiple frames and streamed */
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** network/framework/src/protocols/stream/mod.rs (L124-161)
```rust
    fn new(header: StreamHeader, max_fragments: usize) -> anyhow::Result<Self> {
        // Verify that max fragments is within reasonable bounds
        ensure!(
            max_fragments > 0,
            "Max fragments must be greater than zero!"
        );
        ensure!(
            max_fragments <= (u8::MAX as usize),
            "Max fragments exceeded the u8 limit: {} (max: {})!",
            max_fragments,
            u8::MAX
        );

        // Verify the header message type
        let header_message = header.message;
        ensure!(
            !matches!(header_message, NetworkMessage::Error(_)),
            "Error messages cannot be streamed!"
        );

        // Verify the number of fragments specified in the header
        let header_num_fragments = header.num_fragments;
        ensure!(
            header_num_fragments > 0,
            "Stream header must specify at least one fragment!"
        );
        ensure!(
            (header_num_fragments as usize) <= max_fragments,
            "Stream header exceeds max fragments limit!"
        );

        Ok(Self {
            request_id: header.request_id,
            num_fragments: header_num_fragments,
            received_fragment_id: 0,
            message: header_message,
        })
    }
```

**File:** network/framework/src/protocols/stream/mod.rs (L164-214)
```rust
    fn append_fragment(&mut self, mut fragment: StreamFragment) -> anyhow::Result<bool> {
        // Verify the stream request ID and fragment request ID
        ensure!(
            self.request_id == fragment.request_id,
            "Stream fragment from a different request! Expected {}, got {}.",
            self.request_id,
            fragment.request_id
        );

        // Verify the fragment ID
        let fragment_id = fragment.fragment_id;
        ensure!(fragment_id > 0, "Fragment ID must be greater than zero!");
        ensure!(
            fragment_id <= self.num_fragments,
            "Fragment ID {} exceeds number of fragments {}!",
            fragment_id,
            self.num_fragments
        );

        // Verify the fragment ID is the expected next fragment
        let expected_fragment_id = self.received_fragment_id.checked_add(1).ok_or_else(|| {
            anyhow::anyhow!(
                "Current fragment ID overflowed when adding 1: {}",
                self.received_fragment_id
            )
        })?;
        ensure!(
            expected_fragment_id == fragment_id,
            "Unexpected fragment ID, expected {}, got {}!",
            expected_fragment_id,
            fragment_id
        );

        // Update the received fragment ID
        self.received_fragment_id = expected_fragment_id;

        // Append the fragment data to the message
        let raw_data = &mut fragment.raw_data;
        match &mut self.message {
            NetworkMessage::Error(_) => {
                panic!("StreamHeader for NetworkMessage::Error(_) should be rejected!")
            },
            NetworkMessage::RpcRequest(request) => request.raw_request.append(raw_data),
            NetworkMessage::RpcResponse(response) => response.raw_response.append(raw_data),
            NetworkMessage::DirectSendMsg(message) => message.raw_msg.append(raw_data),
        }

        // Return whether the stream is complete
        let is_stream_complete = self.received_fragment_id == self.num_fragments;
        Ok(is_stream_complete)
    }
```

**File:** network/framework/src/protocols/stream/mod.rs (L267-273)
```rust
        let message_data_len = message.data_len();
        ensure!(
            message_data_len <= self.max_message_size,
            "Message length {} exceeds max message size {}!",
            message_data_len,
            self.max_message_size,
        );
```

**File:** network/framework/src/protocols/stream/mod.rs (L287-301)
```rust
        let rest = match &mut message {
            NetworkMessage::Error(_) => {
                unreachable!("NetworkMessage::Error(_) should always fit into a single frame!")
            },
            NetworkMessage::RpcRequest(request) => {
                request.raw_request.split_off(self.max_frame_size)
            },
            NetworkMessage::RpcResponse(response) => {
                response.raw_response.split_off(self.max_frame_size)
            },
            NetworkMessage::DirectSendMsg(message) => {
                message.raw_msg.split_off(self.max_frame_size)
            },
        };
        let chunks = rest.chunks(self.max_frame_size);
```

**File:** network/framework/src/peer/mod.rs (L168-168)
```rust
        let max_fragments = max_message_size / max_frame_size;
```

**File:** network/framework/src/peer/mod.rs (L532-538)
```rust
            NetworkMessage::RpcResponse(_) => {
                // non-reference cast identical to this match case
                let NetworkMessage::RpcResponse(response) = message else {
                    unreachable!("NetworkMessage type changed between match and let")
                };
                self.outbound_rpcs.handle_inbound_response(response)
            },
```

**File:** network/framework/src/protocols/rpc/mod.rs (L688-700)
```rust
    pub fn handle_inbound_response(&mut self, response: RpcResponse) {
        let network_context = &self.network_context;
        let peer_id = &self.remote_peer_id;
        let request_id = response.request_id;

        let is_canceled = if let Some((protocol_id, response_tx)) =
            self.pending_outbound_rpcs.remove(&request_id)
        {
            self.update_inbound_rpc_response_metrics(
                protocol_id,
                response.raw_response.len() as u64,
            );
            response_tx.send(response).is_err()
```

**File:** network/framework/src/constants.rs (L15-15)
```rust
pub const MAX_CONCURRENT_INBOUND_RPCS: u32 = 100;
```
