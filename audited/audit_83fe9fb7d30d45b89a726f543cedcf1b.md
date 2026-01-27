# Audit Report

## Title
DKG RPC Request Replay Attack: Missing Replay Protection Enables Validator Resource Exhaustion

## Summary
The `IncomingRpcRequest` struct in the DKG (Distributed Key Generation) network module lacks replay protection mechanisms. An attacker can capture and repeatedly replay legitimate `DKGTranscriptRequest` messages within the same epoch, forcing validators to re-process identical requests and waste computational resources, network bandwidth, and processing capacity during critical epoch transitions.

## Finding Description

The DKG protocol implements no replay protection for RPC requests at the application layer. The `IncomingRpcRequest` struct contains only the message, sender, and response channel, with no nonce, timestamp, or request identifier for deduplication. [1](#0-0) 

The `DKGMessage::TranscriptRequest` contains only an epoch number, providing no mechanism to distinguish between unique requests and replays within the same epoch. [2](#0-1) 

When processing RPC requests, `EpochManager::process_rpc_request` only validates that the message epoch matches the current epoch before forwarding to the DKG manager. [3](#0-2) 

The `DKGManager::process_peer_rpc_msg` similarly only checks the epoch and current state before responding with the node's transcript, with no tracking of previously seen requests. [4](#0-3) 

The `NetworkTask` forwards all incoming RPC requests without any deduplication or tracking of previously seen messages. [5](#0-4) 

**Attack Flow:**
1. Attacker captures a legitimate `DKGTranscriptRequest` from any validator during epoch N
2. Attacker replays this identical request to target validators multiple times
3. Each validator processes the request, checks epoch (passes), checks state (passes), and responds with full transcript
4. No deduplication occurs - each replay is treated as a new request
5. Repeated processing causes CPU overhead, bandwidth waste, and channel congestion

While the network layer enforces a limit of 100 concurrent inbound RPCs per connection, this does not prevent replay attacks - it only provides backpressure. An attacker can:
- Send sequential replays (wait for processing, send again)
- Establish multiple peer connections (each with separate RPC limits)
- Sustain attacks throughout the DKG phase [6](#0-5) 

## Impact Explanation

This vulnerability enables **Validator node slowdowns** during the critical DKG phase of epoch transitions, which qualifies as **HIGH severity** (up to $50,000) per the Aptos bug bounty program.

**Resource Exhaustion Impact:**
- **CPU overhead**: Repeated deserialization, state checks, and response serialization for identical requests
- **Network bandwidth**: Full DKG transcript (potentially kilobytes to megabytes) sent for each replay
- **Channel congestion**: FIFO queue in `epoch_manager` (size 100) can be flooded with replays
- **DKG phase disruption**: Resource waste during time-sensitive epoch transition when validators must complete DKG

The vulnerability breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The lack of replay protection allows unbounded processing of duplicate requests within an epoch.

## Likelihood Explanation

**HIGH likelihood** - The attack is trivial to execute:

**Attacker Requirements:**
- Network peer capability (any node can connect to validator network)
- Ability to capture one legitimate DKG RPC request (passive network observation)
- No validator privileges, cryptographic keys, or stake required

**Attack Complexity:**
- Low - Simply replay captured network message
- No cryptographic forgery needed (legitimate message from another validator)
- Works throughout entire epoch duration
- Can target multiple validators simultaneously

**Timing:**
- DKG occurs during every epoch transition
- Attack window is the entire DKG session duration
- Most effective during high-activity periods when validator resources are constrained

## Recommendation

Implement replay protection for DKG RPC requests by adding request deduplication. Options include:

**Option 1: Request Nonce (Recommended)**
Add a nonce field to `DKGTranscriptRequest` and track seen (sender, nonce) pairs:

```rust
pub struct DKGTranscriptRequest {
    dealer_epoch: u64,
    nonce: u64,  // Monotonically increasing per sender
}

// In DKGManager:
pub struct DKGManager<DKG: DKGTrait> {
    // ... existing fields ...
    seen_requests: HashMap<AccountAddress, HashSet<u64>>, // Track (sender, nonce)
}

async fn process_peer_rpc_msg(&mut self, req: IncomingRpcRequest) -> Result<()> {
    let IncomingRpcRequest { msg, sender, mut response_sender } = req;
    ensure!(msg.epoch() == self.epoch_state.epoch, "[DKG] msg not for current epoch");
    
    // Check for replay
    if let DKGMessage::TranscriptRequest(ref request) = msg {
        if !self.seen_requests.entry(sender)
            .or_insert_with(HashSet::new)
            .insert(request.nonce) {
            return Err(anyhow!("[DKG] replay attack detected"));
        }
    }
    
    // ... rest of processing ...
}
```

**Option 2: Timestamp-based Expiration**
Add timestamp to requests and reject requests older than a threshold, similar to the nonce validation pattern used for orderless transactions.

**Option 3: Per-peer Request Limiting**
Track request count per peer and rate-limit to one request per peer per epoch for `TranscriptRequest` messages.

## Proof of Concept

```rust
#[cfg(test)]
mod replay_attack_test {
    use super::*;
    use aptos_types::dkg::DKGTranscript;
    
    #[tokio::test]
    async fn test_dkg_request_replay_attack() {
        // Setup: Create DKG manager in InProgress state with transcript ready
        let (mut dkg_manager, epoch_state) = setup_dkg_manager_in_progress().await;
        
        // Attacker captures legitimate request
        let captured_request = DKGTranscriptRequest::new(epoch_state.epoch);
        let dkg_msg = DKGMessage::TranscriptRequest(captured_request.clone());
        
        let attacker_addr = AccountAddress::random();
        
        // First replay - succeeds
        let (tx1, _rx1) = oneshot::channel();
        let req1 = IncomingRpcRequest {
            msg: dkg_msg.clone(),
            sender: attacker_addr,
            response_sender: Box::new(create_dummy_response_sender(tx1)),
        };
        
        let result1 = dkg_manager.process_peer_rpc_msg(req1).await;
        assert!(result1.is_ok(), "First request should succeed");
        
        // Second replay - SHOULD FAIL but currently succeeds
        let (tx2, _rx2) = oneshot::channel();
        let req2 = IncomingRpcRequest {
            msg: dkg_msg.clone(),
            sender: attacker_addr,
            response_sender: Box::new(create_dummy_response_sender(tx2)),
        };
        
        let result2 = dkg_manager.process_peer_rpc_msg(req2).await;
        // VULNERABILITY: This succeeds when it should be rejected as replay
        assert!(result2.is_ok(), "Replay attack succeeds - vulnerability confirmed");
        
        // Can repeat N times - each time validator wastes resources responding
        for i in 0..100 {
            let (tx, _rx) = oneshot::channel();
            let req = IncomingRpcRequest {
                msg: dkg_msg.clone(),
                sender: attacker_addr,
                response_sender: Box::new(create_dummy_response_sender(tx)),
            };
            assert!(dkg_manager.process_peer_rpc_msg(req).await.is_ok(),
                "Replay {} should be rejected but succeeds", i);
        }
    }
}
```

**Notes**

The vulnerability exists because DKG protocol design prioritizes simplicity over replay protection. While transcript aggregation has deduplication for responses (preventing duplicate transcript contributions), there is no equivalent protection for requests. The network-layer concurrent RPC limits provide backpressure but do not prevent replay attacks - they merely slow the attack rate. An attacker can still cause significant resource waste through sequential replays or multiple peer connections, especially during the time-sensitive DKG phase of epoch transitions.

### Citations

**File:** dkg/src/network.rs (L30-34)
```rust
pub struct IncomingRpcRequest {
    pub msg: DKGMessage,
    pub sender: AccountAddress,
    pub response_sender: Box<dyn RpcResponseSender>,
}
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

**File:** network/framework/src/constants.rs (L15-15)
```rust
pub const MAX_CONCURRENT_INBOUND_RPCS: u32 = 100;
```
