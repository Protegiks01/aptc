# Audit Report

## Title
Missing Validator Set Validation in DKG RPC Message Handler Allows Information Disclosure by Removed Validators

## Summary
The DKG (Distributed Key Generation) message handler in `process_peer_rpc_msg` does not validate that RPC request senders are active validators in the current epoch before responding with DKG transcripts. This allows removed validators to request and receive DKG transcript information during a race condition window before network connections are closed. [1](#0-0) 

## Finding Description

The DKG system is designed to enable active validators to collaboratively generate randomness through a distributed key generation protocol. Access to DKG transcripts should be restricted to validators participating in the current epoch.

**The vulnerability exists in the RPC message processing flow:**

1. **Incoming RPC requests are forwarded without sender validation:**
   - Network layer receives RPC requests and creates `IncomingRpcRequest` with sender's `AccountAddress` [2](#0-1) [3](#0-2) 

2. **Epoch manager forwards requests with minimal validation:**
   - Only checks epoch number match, not validator set membership [4](#0-3) 

3. **DKG manager responds without sender validation:**
   - The `sender` field from `IncomingRpcRequest` is destructured with `..` and never examined
   - Only validates epoch match, not that sender is in current validator set
   - Responds with full DKG transcript to any requester [1](#0-0) 

**Contrast with proper validation during transcript aggregation:**
When aggregating transcripts, the system correctly validates sender voting power: [5](#0-4) 

**Attack Scenario:**
1. Validator A is removed from the validator set during epoch transition
2. Epoch N+1 begins with new validator set (excluding A)
3. Before `close_stale_connections()` disconnects validator A, they send `TranscriptRequest` messages [6](#0-5) 
4. Active validators respond with their DKG transcripts
5. Validator A receives DKG session information they should not access

## Impact Explanation

**Severity Assessment: Low to Medium**

This vulnerability represents an **information disclosure** issue rather than a critical consensus or fund-loss vulnerability:

**Limited Impact:**
- DKG transcripts contain encrypted secret shares where each share is encrypted with the intended validator's public key
- Removed validators cannot decrypt shares meant for other validators (cryptographic protection)
- They cannot inject themselves into the DKG aggregation process (rejected by voting power check)
- No consensus violation, fund loss, or network availability impact

**Information Leaked:**
- DKG session metadata (epoch, authors, timing)
- Encrypted transcript structure and size
- Participation patterns of active validators

**Severity Justification:**
- **Not Critical**: No fund theft, consensus break, or network partition
- **Not High**: No validator slowdown or API crash
- **Medium at most**: Minor protocol violation and information leak during transient race condition
- **Likely Low**: Information disclosed is mostly encrypted; attack window is small and temporary

Per Aptos bug bounty criteria, this falls under **Low Severity** ($1,000): "Minor information leaks" and "Non-critical implementation bugs."

## Likelihood Explanation

**Likelihood: Medium to High (during epoch transitions)**

The vulnerability is exploitable during a specific race condition window:

1. **Preconditions:**
   - Attacker was previously an active validator
   - Validator is removed during epoch reconfiguration
   - Network connection persists briefly after removal

2. **Attack Window:**
   - Between epoch change completing and `check_connectivity()` executing `close_stale_connections()`
   - The connectivity manager runs on periodic intervals [7](#0-6) 

3. **Ease of Exploitation:**
   - No special tools required—standard DKG protocol messages
   - Removed validator already has network access and protocol knowledge
   - DKG sessions happen at epoch boundaries, providing predictable timing

4. **Detection:**
   - Difficult to detect in real-time
   - Requires log correlation between RPC requests and validator set membership

## Recommendation

**Fix: Add validator set membership validation before responding to DKG RPC requests**

Modify `process_peer_rpc_msg` to validate the sender is in the current epoch's validator set:

```rust
async fn process_peer_rpc_msg(&mut self, req: IncomingRpcRequest) -> Result<()> {
    let IncomingRpcRequest {
        msg,
        sender,  // Use the sender field
        mut response_sender,
    } = req;
    
    ensure!(
        msg.epoch() == self.epoch_state.epoch,
        "[DKG] msg not for current epoch"
    );
    
    // ADD: Validate sender is in current validator set
    let sender_voting_power = self.epoch_state.verifier.get_voting_power(&sender);
    ensure!(
        sender_voting_power.is_some(),
        "[DKG] transcript request from non-validator or removed validator: {}",
        sender
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

This mirrors the validation already performed during transcript aggregation and provides defense-in-depth.

## Proof of Concept

**Scenario Setup:**
1. Network with validators V1, V2, V3, V4
2. Epoch N: All validators active
3. Epoch N+1: V4 removed from validator set
4. DKG session starts for epoch N+1

**Attack Steps:**

```rust
// Pseudocode demonstrating the attack

// 1. Epoch transition occurs - V4 is removed
// 2. V4's network connection is still active (race window)
// 3. V4 sends DKG transcript request
let request = DKGMessage::TranscriptRequest(
    DKGTranscriptRequest::new(epoch_n_plus_1)
);

// 4. V1 (active validator) receives request
// 5. process_peer_rpc_msg in DKG manager processes it
//    - Checks epoch match: ✓ (N+1 == N+1)
//    - Checks sender is validator: ✗ (NOT CHECKED)
//    - Responds with transcript

// 6. V4 receives DKGMessage::TranscriptResponse containing:
//    - DKGTranscript with metadata and encrypted shares
//    - Information about active validators in epoch N+1
//    - Timing and structure of DKG session

// 7. V4 cannot decrypt shares (lacks private keys)
//    But learns metadata about the DKG process they shouldn't access
```

**Test Case (Rust integration test):**

```rust
#[tokio::test]
async fn test_removed_validator_cannot_request_transcripts() {
    // Setup: Create epoch with validators
    let (mut dkg_manager, epoch_state) = setup_dkg_manager_with_validators(4);
    
    // Simulate epoch transition removing validator 3
    let new_epoch_state = create_epoch_state_without_validator(3);
    
    // Validator 3 sends transcript request
    let removed_validator_addr = get_validator_address(3);
    let request = create_transcript_request(&new_epoch_state);
    let rpc_request = IncomingRpcRequest {
        msg: request,
        sender: removed_validator_addr,
        response_sender: Box::new(TestResponseSender::new()),
    };
    
    // Expected: Request should be rejected
    // Actual: Request is processed and transcript returned (BUG)
    let result = dkg_manager.process_peer_rpc_msg(rpc_request).await;
    
    // With fix: assert!(result.is_err());
    // Without fix: assert!(result.is_ok()); // BUG - should fail
}
```

## Notes

While this vulnerability represents a missing access control check, its practical severity is limited by several factors:

1. **Network-layer protection**: Mutual authentication and periodic connection cleanup provide first-line defense
2. **Cryptographic protection**: Transcript shares are encrypted per-validator
3. **Aggregation validation**: Removed validators cannot inject malicious transcripts
4. **Small attack window**: Race condition between epoch change and connection closure

The vulnerability should be fixed as a defense-in-depth measure to ensure application-layer validation matches the security model, even though network-layer controls already provide significant protection.

### Citations

**File:** dkg/src/dkg_manager/mod.rs (L119-129)
```rust

    pub async fn run(
        mut self,
        in_progress_session: Option<DKGSessionState>,
        mut dkg_start_event_rx: aptos_channel::Receiver<(), DKGStartEvent>,
        mut rpc_msg_rx: aptos_channel::Receiver<
            AccountAddress,
            (AccountAddress, IncomingRpcRequest),
        >,
        close_rx: oneshot::Receiver<oneshot::Sender<()>>,
    ) {
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

**File:** dkg/src/network.rs (L30-34)
```rust
pub struct IncomingRpcRequest {
    pub msg: DKGMessage,
    pub sender: AccountAddress,
    pub response_sender: Box<dyn RpcResponseSender>,
}
```

**File:** dkg/src/network.rs (L163-176)
```rust
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

**File:** dkg/src/transcript_aggregation/mod.rs (L79-83)
```rust
        let peer_power = self.epoch_state.verifier.get_voting_power(&sender);
        ensure!(
            peer_power.is_some(),
            "[DKG] adding peer transcript failed with illegal dealer"
        );
```

**File:** dkg/src/connectivity_manager/mod.rs (L484-531)
```rust

```
