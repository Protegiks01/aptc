# Audit Report

## Title
DKG Transcript Request Replay Attack Enables Resource Exhaustion on Validator Nodes

## Summary
The `DKGTranscriptRequest` structure lacks replay prevention mechanisms (nonce, timestamp, or request tracking), allowing malicious validators to send unlimited duplicate requests to exhaust target validator resources through repeated transcript generation and transmission.

## Finding Description

The `DKGTranscriptRequest` structure contains only a `dealer_epoch` field with no freshness or uniqueness guarantees: [1](#0-0) 

When a validator receives a `DKGTranscriptRequest`, the `DKGManager::process_peer_rpc_msg` function checks only the epoch match and responds with the validator's transcript if in `InProgress` or `Finished` state: [2](#0-1) 

Critically, there is **no tracking of previous requests from the same sender**, meaning every request with a matching epoch triggers a full response. The response deduplication in `TranscriptAggregationState` only prevents duplicate responses from being counted twice during aggregation—it does not prevent requests from being processed multiple times: [3](#0-2) 

**Attack Flow:**
1. Malicious validator V₁ identifies target validator V₂ during an active DKG session (epoch N)
2. V₁ sends multiple `DKGTranscriptRequest(epoch=N)` messages to V₂ via RPC
3. Each request bypasses the epoch check and enters `process_peer_rpc_msg`
4. V₂ responds to each request by serializing and transmitting its full DKG transcript (~15-30 KB for 100-200 validators)
5. V₁ can send requests up to the concurrent RPC limit (100), and immediately send more once responses complete

The network configuration for DKG has no rate limiting configured: [4](#0-3) 

The only protection is the per-peer concurrent RPC limit of 100: [5](#0-4) 

This limit applies only to concurrent requests—once a request completes, the slot frees up for another request.

**Invariant Violation:** This breaks the "Resource Limits: All operations must respect gas, storage, and computational limits" invariant by allowing unbounded resource consumption without economic cost or rate limiting.

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos Bug Bounty criteria as it causes "Validator node slowdowns" through:

1. **CPU Exhaustion**: Repeated BCS serialization of large transcript objects
2. **Memory Pressure**: Creating response objects and buffering network sends
3. **Network Bandwidth Saturation**: Transmitting 15-30 KB responses repeatedly (transcript size = 96 + (n+1) × 144 bytes for n validators) [6](#0-5) 

For a validator set of 100 nodes, a malicious validator sending 1000 requests causes transmission of ~15 MB of redundant transcript data, plus CPU cycles for 1000 serializations. This can degrade consensus participation and block processing performance.

## Likelihood Explanation

**Likelihood: High**

This attack requires only:
- Attacker is a validator in the current epoch (Byzantine validator assumption)
- DKG session is active (occurs at every epoch transition when randomness is enabled)
- Ability to send RPC messages (standard validator networking capability)

No special timing, cryptographic operations, or complex state manipulation is required. The attack is trivially automatable and can be sustained throughout the DKG session duration.

## Recommendation

Implement request deduplication by tracking processed requests per peer per epoch:

```rust
// In DKGManager struct, add:
processed_requests: HashMap<AccountAddress, HashSet<u64>>, // peer -> set of epochs

// In process_peer_rpc_msg, add before line 464:
let peer_requests = self.processed_requests.entry(sender).or_default();
if msg.epoch() == self.epoch_state.epoch {
    if !peer_requests.insert(msg.epoch()) {
        // Already processed request from this peer for this epoch
        return Err(anyhow!("[DKG] duplicate request from peer"));
    }
}
```

**Alternative/Additional Mitigations:**
1. Add per-peer rate limiting in DKG network configuration (e.g., max 1 request per 5 seconds per peer)
2. Include a cryptographic nonce or timestamp in `DKGTranscriptRequest` and reject duplicates
3. Implement exponential backoff for repeated requests from the same peer

## Proof of Concept

```rust
// Test demonstrating the vulnerability
// Add to dkg/src/dkg_manager/tests.rs

#[tokio::test]
async fn test_dkg_request_replay_attack() {
    use crate::DKGMessage;
    use crate::types::DKGTranscriptRequest;
    
    // Setup DKGManager in InProgress state with epoch 5
    let (dkg_manager, test_harness) = setup_dkg_manager_with_epoch(5).await;
    
    let malicious_validator = test_harness.validators[1].address;
    let request = DKGTranscriptRequest::new(5);
    
    let mut response_sizes = Vec::new();
    
    // Send 100 duplicate requests from the same malicious validator
    for _ in 0..100 {
        let (response_tx, response_rx) = oneshot::channel();
        let incoming_request = IncomingRpcRequest {
            msg: DKGMessage::TranscriptRequest(request.clone()),
            sender: malicious_validator,
            response_sender: Box::new(TestResponseSender::new(response_tx)),
        };
        
        // Each request is processed without deduplication
        dkg_manager.process_peer_rpc_msg(incoming_request).await.unwrap();
        
        // Receive response
        let response = response_rx.await.unwrap().unwrap();
        if let DKGMessage::TranscriptResponse(transcript) = response {
            response_sizes.push(transcript.transcript_bytes.len());
        }
    }
    
    // Assert: All 100 requests received responses (no deduplication)
    assert_eq!(response_sizes.len(), 100);
    
    // Calculate total data transmitted
    let total_bytes: usize = response_sizes.iter().sum();
    println!("Total redundant data transmitted: {} bytes", total_bytes);
    
    // For 100 validators, expect ~15 KB per response × 100 = ~1.5 MB wasted
    assert!(total_bytes > 1_000_000, "Vulnerability confirmed: excessive data transmitted");
}
```

**Notes:**
- The vulnerability is exacerbated during epoch transitions when all validators simultaneously participate in DKG
- While the `max_concurrent_inbound_rpcs` limit of 100 provides some backpressure, it does not prevent the attack—it merely rate-limits it to 100 concurrent requests, which still represents significant resource waste
- The response deduplication in `TranscriptAggregationState` only prevents the requesting validator from double-counting responses in aggregation; it does not prevent the responding validator from processing duplicate requests
- This attack can be combined with targeting multiple validators simultaneously to amplify network-wide impact

### Citations

**File:** dkg/src/types.rs (L12-14)
```rust
pub struct DKGTranscriptRequest {
    dealer_epoch: u64,
}
```

**File:** dkg/src/dkg_manager/mod.rs (L454-478)
```rust
    async fn process_peer_rpc_msg(&mut self, req: IncomingRpcRequest) -> Result<()> {
        let IncomingRpcRequest {
            msg,
            mut response_sender,
            ..
        } = req;
        ensure!(
            msg.epoch() == self.epoch_state.epoch,
            "[DKG] msg not for current epoch"
        );
        let response = match (&self.state, &msg) {
            (InnerState::Finished { my_transcript, .. }, DKGMessage::TranscriptRequest(_))
            | (InnerState::InProgress { my_transcript, .. }, DKGMessage::TranscriptRequest(_)) => {
                Ok(DKGMessage::TranscriptResponse(my_transcript.clone()))
            },
            _ => Err(anyhow!(
                "[DKG] msg {:?} unexpected in state {:?}",
                msg.name(),
                self.state.variant_name()
            )),
        };

        response_sender.send(response);
        Ok(())
    }
```

**File:** dkg/src/transcript_aggregation/mod.rs (L92-94)
```rust
        if trx_aggregator.contributors.contains(&metadata.author) {
            return Ok(None);
        }
```

**File:** aptos-node/src/network.rs (L75-89)
```rust
pub fn dkg_network_configuration(node_config: &NodeConfig) -> NetworkApplicationConfig {
    let direct_send_protocols: Vec<ProtocolId> =
        aptos_dkg_runtime::network_interface::DIRECT_SEND.into();
    let rpc_protocols: Vec<ProtocolId> = aptos_dkg_runtime::network_interface::RPC.into();

    let network_client_config =
        NetworkClientConfig::new(direct_send_protocols.clone(), rpc_protocols.clone());
    let network_service_config = NetworkServiceConfig::new(
        direct_send_protocols,
        rpc_protocols,
        aptos_channel::Config::new(node_config.dkg.max_network_channel_size)
            .queue_style(QueueStyle::FIFO),
    );
    NetworkApplicationConfig::new(network_client_config, network_service_config)
}
```

**File:** network/framework/src/constants.rs (L14-15)
```rust
/// Limit on concurrent Inbound RPC requests before backpressure is applied
pub const MAX_CONCURRENT_INBOUND_RPCS: u32 = 100;
```

**File:** crates/aptos-crypto/src/blstrs/mod.rs (L28-31)
```rust
pub const G1_PROJ_NUM_BYTES: usize = 48;

/// The size in bytes of a compressed G2 point (efficiently deserializable into projective coordinates)
pub const G2_PROJ_NUM_BYTES: usize = 96;
```
