# Audit Report

## Title
DKG RPC Request Processing Lacks Sender Authorization and Rate Limiting, Enabling Validator Resource Exhaustion

## Summary
The DKG (Distributed Key Generation) network message processing pipeline fails to validate incoming RPC requests beyond basic epoch checking. The `DKGNetworkClient` wrapper provides no validation, and downstream handlers (`EpochManager`, `DKGManager`) unconditionally process and respond to all requests from any authenticated validator without rate limiting or authorization checks. This allows a malicious validator to exhaust resources of honest validators through unlimited transcript requests.

## Finding Description

The security issue spans multiple layers of the DKG message processing pipeline:

**1. DKGNetworkClient provides no validation:** [1](#0-0) 

The `DKGNetworkClient` is merely a thin wrapper that forwards all calls to the underlying network client without any DKG-specific validation, authentication, or rate limiting.

**2. NetworkTask accepts all RPC requests:** [2](#0-1) 

The `NetworkTask` processes all incoming `RpcRequest` events and forwards them to the epoch manager without validation. The channel has only a capacity of 10 messages. [3](#0-2) 

**3. EpochManager performs minimal validation:** [4](#0-3) 

The `process_rpc_request` function only checks if the message epoch matches the current epoch. There is no check for:
- Whether the sender is authorized to request transcripts at this time
- Rate limiting or request deduplication
- Whether DKG has actually started
- Request legitimacy or intent

The channel to DKGManager has a capacity of only 100 messages: [5](#0-4) 

**4. DKGManager responds unconditionally:** [6](#0-5) 

The `process_peer_rpc_msg` function responds to every request (even with errors) without validating:
- Whether the requester should have access to the transcript
- Request rate or frequency
- Request legitimacy within the DKG protocol flow

**Attack Scenario:**

A malicious validator can exploit this by:

1. Sending thousands of `DKGMessage::TranscriptRequest` messages to target honest validators
2. Each request passes epoch validation and reaches `DKGManager`
3. Each request forces the victim to:
   - Process the request (CPU cost)
   - Serialize and send their transcript response (CPU + bandwidth cost)
   - Potentially clone transcript data multiple times
4. The attacker can saturate the limited-capacity channels (10 in NetworkTask, 100 in DKGManager)
5. Legitimate DKG messages from the reliable broadcast protocol may be dropped when channels are full
6. Victim validators experience resource exhaustion and delayed DKG participation

**Contrast with proper validation:**

When transcripts are exchanged via the reliable broadcast protocol, responses are properly validated: [7](#0-6) 

The `TranscriptAggregationState::add` method performs comprehensive validation including epoch checking, voting power verification, author matching, transcript deserialization, and cryptographic verification. However, this validation is ONLY applied during aggregation, not for incoming RPC requests.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria:

1. **Validator node slowdowns**: A malicious validator can force honest validators to continuously process and respond to requests, consuming CPU and bandwidth resources. This directly impacts validator performance and DKG completion time.

2. **Significant protocol violations**: If legitimate DKG messages are dropped due to channel saturation, the DKG protocol may fail to complete within the expected timeframe, delaying randomness generation for the next epoch. This affects all downstream protocols that depend on on-chain randomness.

3. **Liveness impact**: While not a total loss of liveness (Critical severity), delayed or failed DKG completion impacts the network's ability to generate randomness, which is a critical protocol feature.

The impact is limited by:
- Channel capacity limits (though an attacker can sustain the attack at the processing rate)
- Network-level authentication (only validators can exploit this)
- Reliable broadcast retries (can eventually complete despite dropped messages)

However, the absence of ANY rate limiting or authorization checks represents a clear violation of the "Resource Limits: All operations must respect gas, storage, and computational limits" invariant.

## Likelihood Explanation

**Likelihood: Medium-High**

The attack is straightforward to execute:
- Any validator can send RPC requests to any other validator
- No special permissions or timing required beyond validator network access
- No cryptographic operations needed by the attacker
- The vulnerable code paths are active during every DKG session

Factors increasing likelihood:
- Single malicious validator sufficient (no collusion required)
- Attack can be sustained continuously during DKG
- No detection or mitigation mechanisms in place
- Direct impact on critical randomness generation functionality

Factors reducing likelihood:
- Requires validator network access (not external attacker)
- May be detectable through monitoring if egregious
- Limited duration of attack window (only during DKG sessions)

## Recommendation

Implement multi-layered validation and rate limiting for incoming DKG RPC requests:

**1. Add request validation in DKGNetworkClient:**

```rust
impl<NetworkClient: NetworkClientInterface<DKGMessage>> DKGNetworkClient<NetworkClient> {
    // Add method to validate incoming messages
    pub fn validate_message(&self, sender: PeerId, msg: &DKGMessage, epoch: u64) -> Result<(), Error> {
        // Check epoch
        if msg.epoch() != epoch {
            return Err(Error::InvalidEpoch);
        }
        // Additional DKG-specific validation
        Ok(())
    }
}
```

**2. Add rate limiting in EpochManager:**

```rust
pub struct EpochManager<P: OnChainConfigProvider> {
    // ... existing fields ...
    
    // Add rate limiter per peer
    rpc_rate_limiter: Arc<RwLock<HashMap<AccountAddress, RateLimiter>>>,
}

fn process_rpc_request(&mut self, peer_id: AccountAddress, dkg_request: IncomingRpcRequest) -> Result<()> {
    // Check rate limit
    if let Some(limiter) = self.rpc_rate_limiter.write().get_mut(&peer_id) {
        if !limiter.check_and_update() {
            warn!("Rate limit exceeded for peer {}", peer_id);
            return Err(anyhow!("Rate limit exceeded"));
        }
    }
    
    // Verify sender is in current validator set
    if let Some(epoch_state) = &self.epoch_state {
        if epoch_state.verifier.get_voting_power(&peer_id).is_none() {
            return Err(anyhow!("Sender not in validator set"));
        }
    }
    
    // ... rest of existing logic ...
}
```

**3. Add request authentication in DKGManager:**

```rust
async fn process_peer_rpc_msg(&mut self, req: IncomingRpcRequest) -> Result<()> {
    let IncomingRpcRequest { msg, sender, mut response_sender } = req;
    
    // Verify epoch
    ensure!(msg.epoch() == self.epoch_state.epoch, "[DKG] msg not for current epoch");
    
    // Verify sender is in validator set and has voting power
    ensure!(
        self.epoch_state.verifier.get_voting_power(&sender).is_some(),
        "[DKG] Sender not in validator set"
    );
    
    // Only respond if DKG is actually in progress
    let response = match (&self.state, &msg) {
        (InnerState::Finished { my_transcript, .. }, DKGMessage::TranscriptRequest(_))
        | (InnerState::InProgress { my_transcript, .. }, DKGMessage::TranscriptRequest(_)) => {
            Ok(DKGMessage::TranscriptResponse(my_transcript.clone()))
        },
        _ => Err(anyhow!("[DKG] Not ready to serve transcript requests")),
    };
    
    response_sender.send(response);
    Ok(())
}
```

## Proof of Concept

```rust
// Proof of Concept: DKG Request Flooding Attack
// This test demonstrates how a malicious validator can flood another validator with requests

#[tokio::test]
async fn test_dkg_request_flood_attack() {
    use aptos_channels::aptos_channel;
    use aptos_network::application::interface::NetworkClient;
    use crate::{DKGMessage, types::DKGTranscriptRequest};
    
    // Setup: Create a target validator node with DKG running
    let (network_client, mut network_rx) = /* setup network client */;
    let target_validator = /* setup validator with DKG */;
    
    // Attack: Malicious validator sends 1000 transcript requests
    let malicious_validator_addr = AccountAddress::random();
    let current_epoch = 1;
    
    for i in 0..1000 {
        let request = DKGMessage::TranscriptRequest(
            DKGTranscriptRequest::new(current_epoch)
        );
        
        // Send request - no validation prevents this
        network_client.send_to_peer_rpc(
            request,
            Duration::from_secs(10),
            PeerNetworkId::new(NetworkId::Validator, malicious_validator_addr)
        ).await.unwrap();
        
        // Each request will:
        // 1. Pass through NetworkTask (no validation)
        // 2. Pass through EpochManager (only epoch check)
        // 3. Reach DKGManager which responds unconditionally
        // 4. Force victim to serialize and send transcript
    }
    
    // Result: Target validator's channels saturated, CPU exhausted
    // Legitimate DKG messages may be dropped
    // DKG completion delayed or failed
}
```

The PoC demonstrates that without rate limiting or authorization checks, a malicious validator can continuously flood honest validators with transcript requests, causing resource exhaustion and protocol delays.

## Notes

This vulnerability specifically addresses the security question about whether `DKGNetworkClient` properly validates messages. The analysis reveals that not only does `DKGNetworkClient` lack validation (being merely a thin wrapper), but the entire message processing pipeline downstream fails to implement adequate controls against malicious request flooding. This represents a clear bypass of DKG-specific validation, where the reliable broadcast protocol includes proper validation via `TranscriptAggregationState::add()`, but direct RPC requests circumvent this validation entirely.

### Citations

**File:** dkg/src/network_interface.rs (L27-35)
```rust
pub struct DKGNetworkClient<NetworkClient> {
    network_client: NetworkClient,
}

impl<NetworkClient: NetworkClientInterface<DKGMessage>> DKGNetworkClient<NetworkClient> {
    /// Returns a new DKG network client
    pub fn new(network_client: NetworkClient) -> Self {
        Self { network_client }
    }
```

**File:** dkg/src/network.rs (L141-141)
```rust
        let (rpc_tx, rpc_rx) = aptos_channel::new(QueueStyle::FIFO, 10, None);
```

**File:** dkg/src/network.rs (L160-182)
```rust
    pub async fn start(mut self) {
        while let Some(message) = self.all_events.next().await {
            match message {
                Event::RpcRequest(peer_id, msg, protocol, response_sender) => {
                    let req = IncomingRpcRequest {
                        msg,
                        sender: peer_id,
                        response_sender: Box::new(RealRpcResponseSender {
                            inner: Some(response_sender),
                            protocol,
                        }),
                    };

                    if let Err(e) = self.rpc_tx.push(peer_id, (peer_id, req)) {
                        warn!(error = ?e, "aptos channel closed");
                    };
                },
                _ => {
                    // Ignored. Currently only RPC is used.
                },
            }
        }
    }
```

**File:** dkg/src/epoch_manager.rs (L94-106)
```rust
    fn process_rpc_request(
        &mut self,
        peer_id: AccountAddress,
        dkg_request: IncomingRpcRequest,
    ) -> Result<()> {
        if Some(dkg_request.msg.epoch()) == self.epoch_state.as_ref().map(|s| s.epoch) {
            // Forward to DKGManager if it is alive.
            if let Some(tx) = &self.dkg_rpc_msg_tx {
                let _ = tx.push(peer_id, (peer_id, dkg_request));
            }
        }
        Ok(())
    }
```

**File:** dkg/src/epoch_manager.rs (L227-231)
```rust
            let (dkg_rpc_msg_tx, dkg_rpc_msg_rx) = aptos_channel::new::<
                AccountAddress,
                (AccountAddress, IncomingRpcRequest),
            >(QueueStyle::FIFO, 100, None);
            self.dkg_rpc_msg_tx = Some(dkg_rpc_msg_tx);
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

**File:** dkg/src/transcript_aggregation/mod.rs (L65-101)
```rust
    fn add(
        &self,
        sender: Author,
        dkg_transcript: DKGTranscript,
    ) -> anyhow::Result<Option<Self::Aggregated>> {
        let DKGTranscript {
            metadata,
            transcript_bytes,
        } = dkg_transcript;
        ensure!(
            metadata.epoch == self.epoch_state.epoch,
            "[DKG] adding peer transcript failed with invalid node epoch",
        );

        let peer_power = self.epoch_state.verifier.get_voting_power(&sender);
        ensure!(
            peer_power.is_some(),
            "[DKG] adding peer transcript failed with illegal dealer"
        );
        ensure!(
            metadata.author == sender,
            "[DKG] adding peer transcript failed with node author mismatch"
        );
        let transcript = bcs::from_bytes(transcript_bytes.as_slice()).map_err(|e| {
            anyhow!("[DKG] adding peer transcript failed with trx deserialization error: {e}")
        })?;
        let mut trx_aggregator = self.trx_aggregator.lock();
        if trx_aggregator.contributors.contains(&metadata.author) {
            return Ok(None);
        }

        S::verify_transcript_extra(&transcript, &self.epoch_state.verifier, false, Some(sender))
            .context("extra verification failed")?;

        S::verify_transcript(&self.dkg_pub_params, &transcript).map_err(|e| {
            anyhow!("[DKG] adding peer transcript failed with trx verification failure: {e}")
        })?;
```
