# Audit Report

## Title
DKG Transcript Request Replay Attack Enables Resource Exhaustion on Honest Validators

## Summary
The `send_rpc()` function in the DKG network interface lacks replay protection mechanisms (nonces, timestamps, or request IDs). A Byzantine validator can repeatedly replay identical `DKGTranscriptRequest` messages, forcing honest validators to waste CPU cycles and network bandwidth by re-sending their transcripts for each replayed request, enabling resource exhaustion attacks.

## Finding Description

The DKG (Distributed Key Generation) protocol uses RPC requests to collect transcripts from validators. The request message structure contains only an epoch number with no replay protection: [1](#0-0) 

The `send_rpc()` function is a simple wrapper with no replay protection: [2](#0-1) 

When an honest validator receives a `DKGTranscriptRequest`, the `process_peer_rpc_msg()` function checks only the epoch and current state before responding: [3](#0-2) 

The critical vulnerability is on lines 464-467: whenever the validator is in `InProgress` or `Finished` state and receives a `TranscriptRequest` with matching epoch, it **always** responds with `my_transcript.clone()`. There is no tracking of:
- Which peers have already requested the transcript
- How many times the same request has been processed
- Request IDs, nonces, or timestamps to identify replays

While the transcript aggregation logic prevents duplicate transcripts from the same validator from being counted twice: [4](#0-3) 

This deduplication only prevents double-counting in aggregation, not the repeated processing and response generation.

**Attack Scenario:**
1. Byzantine validator sends `DKGTranscriptRequest(epoch: N)` to honest validator
2. Honest validator responds with their DKG transcript
3. Byzantine validator replays the same `DKGTranscriptRequest(epoch: N)` 1,000+ times
4. Honest validator processes each request, cloning and serializing their transcript each time
5. Each response consumes CPU (serialization), memory (buffers), and network bandwidth (transcript transmission)

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The lack of application-level replay protection allows a single Byzantine validator to cause unbounded resource consumption on honest validators.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program category of "Validator node slowdowns."

**Impact quantification:**
- **Affected nodes:** All honest validators in the epoch
- **Resource consumption per replayed request:**
  - CPU: Deserialization of request, cloning of transcript object, serialization of response
  - Memory: RPC buffers, serialization buffers
  - Network: Full transcript transmission (contains cryptographic material for all validators, can be several KB)
- **Attack scalability:** A single Byzantine validator can target all honest validators simultaneously
- **DKG protocol impact:** Resource exhaustion may delay DKG completion, potentially extending epoch transitions

While this does not break consensus safety or steal funds, it enables a denial-of-service attack that can degrade validator performance and potentially delay critical DKG operations needed for epoch transitions.

## Likelihood Explanation

**Likelihood: HIGH**

This attack is highly likely because:
1. **Low barrier to entry:** Requires only one Byzantine validator (no collusion needed)
2. **Easy to execute:** Simply replay the same message repeatedly
3. **No special privileges required:** Any validator can send RPC requests to any other validator
4. **No detection mechanisms:** The system cannot distinguish legitimate retries from malicious replays
5. **Bounded by network-level rate limits only:** Generic network rate limiting may not be sufficient as the attacker can stay under global limits while still causing significant resource waste

The attack becomes especially potent during DKG phases when validators are actively processing transcript requests.

## Recommendation

Implement application-level replay protection by adding request tracking to `DKGManager`. The fix should:

1. **Add nonce/request ID to `DKGTranscriptRequest`:**
```rust
pub struct DKGTranscriptRequest {
    dealer_epoch: u64,
    request_id: u64,  // monotonic counter or random nonce
}
```

2. **Track processed requests per peer in `DKGManager`:**
```rust
pub struct DKGManager<DKG: DKGTrait> {
    // ... existing fields ...
    processed_requests: HashMap<AccountAddress, HashSet<u64>>,
}
```

3. **Check for duplicates before responding:**
```rust
async fn process_peer_rpc_msg(&mut self, req: IncomingRpcRequest) -> Result<()> {
    let IncomingRpcRequest { msg, sender, mut response_sender, .. } = req;
    
    ensure!(msg.epoch() == self.epoch_state.epoch, "[DKG] msg not for current epoch");
    
    // NEW: Check for replay
    if let DKGMessage::TranscriptRequest(ref tr) = msg {
        let seen = self.processed_requests
            .entry(sender)
            .or_insert_with(HashSet::new);
        if seen.contains(&tr.request_id) {
            return Err(anyhow!("[DKG] duplicate request ignored"));
        }
        seen.insert(tr.request_id);
    }
    
    let response = match (&self.state, &msg) {
        // ... existing response logic ...
    };
    
    response_sender.send(response);
    Ok(())
}
```

4. **Clear tracking on epoch transition** to prevent unbounded memory growth.

**Alternative:** Implement timestamp-based replay protection with a sliding window (e.g., only accept requests from the last 5 minutes).

## Proof of Concept

```rust
#[cfg(test)]
mod replay_attack_test {
    use super::*;
    use aptos_types::dkg::DKGTranscriptRequest;
    
    #[tokio::test]
    async fn test_transcript_request_replay_attack() {
        // Setup: Create a DKGManager in InProgress state with a transcript
        let (mut manager, network_sender) = setup_dkg_manager_in_progress().await;
        let byzantine_validator = AccountAddress::random();
        
        // Send the same transcript request 100 times
        let request = DKGTranscriptRequest::new(manager.epoch_state.epoch);
        let msg = DKGMessage::TranscriptRequest(request.clone());
        
        let mut response_count = 0;
        for _ in 0..100 {
            // Simulate receiving the same request
            let (response_tx, response_rx) = oneshot::channel();
            let incoming_req = IncomingRpcRequest {
                msg: msg.clone(),
                sender: byzantine_validator,
                response_sender: Box::new(TestResponseSender { tx: response_tx }),
            };
            
            // Process the request
            let result = manager.process_peer_rpc_msg(incoming_req).await;
            
            // Verify the manager responds (current behavior - vulnerable)
            if result.is_ok() && response_rx.await.is_ok() {
                response_count += 1;
            }
        }
        
        // Current implementation responds to all 100 identical requests
        // Expected: response_count == 100 (VULNERABLE)
        // After fix: response_count == 1 (only first request processed)
        assert_eq!(response_count, 100, "Replay attack successful - all requests processed");
        
        // Measure resource consumption
        // In a real attack: 100 * transcript_size bytes sent over network
        // For a 5KB transcript across 100 validators: 50MB of wasted bandwidth
    }
}
```

**Notes:**
- The generic network-level rate limiting and RPC concurrency limits provide some protection but are insufficient as they apply globally rather than per-request-type
- The transcript aggregation deduplication prevents consensus impact but does not prevent the resource exhaustion attack
- This vulnerability exists in the core DKG protocol implementation and affects all validators participating in DKG

### Citations

**File:** dkg/src/types.rs (L11-22)
```rust
#[derive(Clone, Serialize, Deserialize, CryptoHasher, Debug, PartialEq)]
pub struct DKGTranscriptRequest {
    dealer_epoch: u64,
}

impl DKGTranscriptRequest {
    pub fn new(epoch: u64) -> Self {
        Self {
            dealer_epoch: epoch,
        }
    }
}
```

**File:** dkg/src/network_interface.rs (L37-47)
```rust
    pub async fn send_rpc(
        &self,
        peer: PeerId,
        message: DKGMessage,
        rpc_timeout: Duration,
    ) -> Result<DKGMessage, Error> {
        let peer_network_id = self.get_peer_network_id_for_peer(peer);
        self.network_client
            .send_to_peer_rpc(message, rpc_timeout, peer_network_id)
            .await
    }
```

**File:** dkg/src/dkg_manager/mod.rs (L453-478)
```rust
    /// Process an RPC request from DKG peers.
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
