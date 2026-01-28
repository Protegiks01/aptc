# Audit Report

## Title
Message Size Limit Bypass via Fragment Assembly in Network Streaming Protocol

## Summary
The network streaming protocol fails to enforce the `max_message_size` limit during fragment assembly, allowing malicious authenticated peers to construct messages that exceed the configured maximum size by up to `max_frame_size` bytes (~4 MiB). This violates resource limit invariants and enables memory exhaustion attacks on validator nodes.

## Finding Description

The vulnerability exists in the fragment assembly logic where the `InboundStream` appends fragments to the header message without validating the total assembled message size.

The network layer defines `MAX_MESSAGE_SIZE` (64 MiB) and `MAX_FRAME_SIZE` (4 MiB) as configuration constants. [1](#0-0) 

When a `Peer` is created, `max_fragments` is calculated as `max_message_size / max_frame_size`, which equals 16 with default configuration. [2](#0-1) 

During legitimate outbound streaming, `OutboundStream::stream_message()` validates that the message data length does not exceed `max_message_size` before streaming. [3](#0-2) 

However, on the inbound side, `InboundStream::new()` only validates that `num_fragments` does not exceed `max_fragments`, but does NOT validate the actual size of the header's raw data. [4](#0-3) 

When fragments are appended, the code directly appends fragment raw data to the message without any size validation. [5](#0-4) 

The assembled message is then passed to `handle_inbound_network_message()` without re-validation of the total size. [6](#0-5) 

**Attack Scenario:**
1. Malicious authenticated peer sends a `StreamHeader` with `num_fragments = 16` and raw data sized ~4 MiB (constrained by frame-level codec)
2. Header passes validation since `num_fragments <= max_fragments`
3. Attacker sends 16 `StreamFragment` messages, each with raw data ~4 MiB
4. Total assembled message: ~4 MiB (header) + 16 × 4 MiB (fragments) = ~68 MiB
5. This exceeds the 64 MiB `max_message_size` limit by approximately 4 MiB

## Impact Explanation

This vulnerability has **Medium Severity** impact aligned with the Aptos Bug Bounty category "Limited Protocol Violations":

1. **Resource Limit Violation**: Malicious peers can force validator nodes to allocate memory exceeding configured limits by 6.25%, potentially degrading performance or causing memory pressure on validators with limited resources.

2. **DoS Amplification**: Multiple authenticated connections exploiting this vulnerability simultaneously could amplify memory exhaustion, potentially affecting validator node performance (which aligns with HIGH severity "Validator Node Slowdowns" if significant impact occurs).

3. **Protocol Invariant Breach**: Violates the resource limits invariant that message sizes should not exceed `max_message_size`.

**Mitigating Factors:**
- Impact is bounded: excess limited to one `max_frame_size` (4 MiB) per message
- Requires authenticated Noise protocol connection (any peer can establish, but provides attribution)
- Frame-level codec prevents unbounded growth
- Does not directly cause consensus failures or fund theft

## Likelihood Explanation

**Likelihood: Medium-High**

Requirements for exploitation:
- Attacker must establish an authenticated Noise protocol connection (achievable by any peer, not just validators)
- Attack is deterministic and easily automated
- No complex timing or race conditions required
- Can be triggered reliably on any validator node accepting peer connections

The vulnerability is straightforward to exploit once a connection is established. While authentication provides some barrier, any participant in the Aptos network can authenticate as a peer, making this more accessible than the report initially suggests.

## Recommendation

Add size validation in `InboundStream::new()` to check the header message size:

```rust
// After line 153 in stream/mod.rs, add:
let header_data_len = header_message.data_len();
ensure!(
    header_data_len <= max_message_size,
    "Stream header message size {} exceeds max message size {}!",
    header_data_len,
    max_message_size
);
```

Additionally, validate total accumulated size during fragment assembly in `append_fragment()`:

```rust
// Before line 200 in stream/mod.rs, add:
let current_size = self.message.data_len();
let new_size = current_size.checked_add(fragment.raw_data.len())
    .ok_or_else(|| anyhow::anyhow!("Message size overflow"))?;
ensure!(
    new_size <= max_message_size,
    "Assembled message size {} exceeds max message size {}!",
    new_size,
    max_message_size
);
```

## Proof of Concept

The vulnerability can be demonstrated by examining the code paths:

1. The frame-level codec enforces individual frame limits [7](#0-6) 

2. A malicious peer constructs a `StreamHeader` with maximum raw data fitting in one frame (~4 MiB) and `num_fragments = 16`

3. The validation only checks fragment count, allowing the oversized header [8](#0-7) 

4. Each subsequent fragment adds ~4 MiB more data without size checks [5](#0-4) 

5. Result: Total message size = header_size + (num_fragments × fragment_size) ≈ 4 MiB + (16 × 4 MiB) = 68 MiB, exceeding the 64 MiB limit

### Citations

**File:** config/src/config/network_config.rs (L49-50)
```rust
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024; /* 4 MiB large messages will be chunked into multiple frames and streamed */
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** network/framework/src/peer/mod.rs (L168-168)
```rust
        let max_fragments = max_message_size / max_frame_size;
```

**File:** network/framework/src/peer/mod.rs (L543-558)
```rust
    fn handle_inbound_stream_message(
        &mut self,
        message: StreamMessage,
    ) -> Result<(), PeerManagerError> {
        match message {
            StreamMessage::Header(header) => {
                self.inbound_stream.new_stream(header)?;
            },
            StreamMessage::Fragment(fragment) => {
                if let Some(message) = self.inbound_stream.append_fragment(fragment)? {
                    self.handle_inbound_network_message(message)?;
                }
            },
        }
        Ok(())
    }
```

**File:** network/framework/src/protocols/stream/mod.rs (L144-153)
```rust
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
```

**File:** network/framework/src/protocols/stream/mod.rs (L200-209)
```rust
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

**File:** network/framework/src/protocols/wire/messaging/v1/mod.rs (L197-200)
```rust
pub fn network_message_frame_codec(max_frame_size: usize) -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .max_frame_length(max_frame_size)
        .length_field_length(4)
```
