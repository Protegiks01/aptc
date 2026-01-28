# Audit Report

## Title
Critical Process Crash in Secret Share Verification Due to Missing Author Validation

## Summary
The secret sharing verification path lacks validation that the `author` field in received `SecretShare` messages matches the authenticated network sender. A malicious validator can send crafted messages with invalid author addresses, triggering a panic in `SecretShare::verify()` that crashes the entire validator process via the global crash handler.

## Finding Description

The vulnerability exists in the message handling flow where incoming secret share messages are not validated to ensure the message author matches the authenticated sender.

**Attack Path:**

1. Network layer receives `SecretShareMsg` and creates `IncomingSecretShareRequest` with authenticated `sender` field: [1](#0-0) 

2. The `sender` field is marked `#[allow(unused)]` and never validated against the message content: [2](#0-1) 

3. The `verification_task` deserializes and verifies messages without checking author matches sender: [3](#0-2) 

4. `SecretShareMessage::verify()` delegates to `share.verify(config)` without author validation: [4](#0-3) 

5. `SecretShare::verify()` calls `config.get_id(self.author())` which panics via `.expect()` if author is not in validator set: [5](#0-4) [6](#0-5) 

6. The panic triggers the global crash handler which exits the entire validator process: [7](#0-6) 

**Contrast with Reliable Broadcast Path:**

The reliable broadcast response path correctly validates author matches sender BEFORE calling verify: [8](#0-7) 

However, the direct message path in `verification_task` lacks this critical validation.

## Impact Explanation

**Severity: HIGH** (up to $50,000 per Aptos Bug Bounty criteria)

This vulnerability causes **complete validator process termination**, not just task failure:

1. **Validator Availability Impact**: A single malicious message crashes the entire validator process, not just the verification task. The validator cannot participate in consensus until the process is restarted by external supervision.

2. **Network-Wide Attack Surface**: Any single malicious validator can target all other validators simultaneously with crafted messages, causing coordinated network disruption.

3. **Consensus Liveness Risk**: If multiple validators are crashed simultaneously, the network may lose consensus liveness if below the 2/3 threshold required for progress.

4. **Repeated Attack Vector**: An attacker can continuously send malicious messages to prevent validator recovery, requiring additional mitigation measures beyond simple restart.

This qualifies as **HIGH Severity** under "Validator Node Slowdowns" and DoS categories, as it causes complete validator unavailability through a protocol-level input validation bug (distinct from infrastructure-level network DoS attacks).

## Likelihood Explanation

**Likelihood: HIGH**

The attack is easily exploitable by any malicious validator:

1. **Attacker Profile**: Any validator in the current epoch (untrusted actor per threat model)

2. **Trivial Exploitation**: Attacker only needs to craft a `SecretShare` with `author` field set to `AccountAddress::ZERO` or any non-validator address

3. **Authenticated Network Access**: Validators use mutual authentication, so malicious validators can reliably deliver messages

4. **No Detection**: The panic results in process termination with only crash logs, no runtime detection or prevention

5. **Single Message Impact**: One malformed message causes complete process crash

## Recommendation

Add author validation in `verification_task` before calling verify:

```rust
// In verification_task, after deserializing the message:
match bcs::from_bytes::<SecretShareMessage>(dec_msg.req.data()) {
    Ok(msg) => {
        // Add validation that message author matches authenticated sender
        if let SecretShareMessage::Share(share) = &msg {
            if share.author() != &dec_msg.sender {
                warn!("Author mismatch: message author {:?}, sender {:?}", 
                      share.author(), dec_msg.sender);
                return;
            }
        }
        if msg.verify(&epoch_state_clone, &config_clone).is_ok() {
            // ... rest of handling
        }
    },
    // ...
}
```

Additionally, consider defensive programming in `get_id()` to return `Result` instead of panicking:

```rust
pub fn get_id(&self, peer: &Author) -> Result<usize> {
    self.validator
        .address_to_validator_index()
        .get(peer)
        .copied()
        .ok_or_else(|| anyhow!("Peer not in validator set"))
}
```

## Proof of Concept

```rust
// Test demonstrating the vulnerability (pseudocode)
#[test]
fn test_invalid_author_causes_panic() {
    // Create SecretShare with author not in validator set
    let invalid_share = SecretShare::new(
        AccountAddress::ZERO,  // Invalid author
        metadata,
        share,
    );
    
    // Create message and attempt verification
    let msg = SecretShareMessage::Share(invalid_share);
    
    // This will panic in get_id() with .expect()
    // causing process termination via crash-handler
    let result = msg.verify(&epoch_state, &config);
    // Panic occurs before this line is reached
}
```

The vulnerability is confirmed by code inspection showing:
1. Missing author validation in verification_task
2. Panic-inducing `.expect()` in `get_id()`
3. Global crash handler that terminates process on panic
4. Contrast with reliable broadcast path that properly validates author

### Citations

**File:** consensus/src/network.rs (L155-161)
```rust
pub struct IncomingSecretShareRequest {
    pub req: SecretShareNetworkMessage,
    #[allow(unused)]
    pub sender: Author,
    pub protocol: ProtocolId,
    pub response_sender: oneshot::Sender<Result<Bytes, RpcError>>,
}
```

**File:** consensus/src/network.rs (L920-936)
```rust
                        ConsensusMsg::SecretShareMsg(req) => {
                            let (tx, _rx) = oneshot::channel();
                            let req_with_callback = IncomingRpcRequest::SecretShareRequest(
                                IncomingSecretShareRequest {
                                    req,
                                    sender: peer_id,
                                    protocol: RPC[0],
                                    response_sender: tx,
                                },
                            );
                            if let Err(e) = self.rpc_tx.push(
                                (peer_id, discriminant(&req_with_callback)),
                                (peer_id, req_with_callback),
                            ) {
                                warn!(error = ?e, "aptos channel closed");
                            };
                        },
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L205-235)
```rust
    async fn verification_task(
        epoch_state: Arc<EpochState>,
        mut incoming_rpc_request: aptos_channel::Receiver<Author, IncomingSecretShareRequest>,
        verified_msg_tx: UnboundedSender<SecretShareRpc>,
        config: SecretShareConfig,
        bounded_executor: BoundedExecutor,
    ) {
        while let Some(dec_msg) = incoming_rpc_request.next().await {
            let tx = verified_msg_tx.clone();
            let epoch_state_clone = epoch_state.clone();
            let config_clone = config.clone();
            bounded_executor
                .spawn(async move {
                    match bcs::from_bytes::<SecretShareMessage>(dec_msg.req.data()) {
                        Ok(msg) => {
                            if msg.verify(&epoch_state_clone, &config_clone).is_ok() {
                                let _ = tx.unbounded_send(SecretShareRpc {
                                    msg,
                                    protocol: dec_msg.protocol,
                                    response_sender: dec_msg.response_sender,
                                });
                            }
                        },
                        Err(e) => {
                            warn!("Invalid dec message: {}", e);
                        },
                    }
                })
                .await;
        }
    }
```

**File:** consensus/src/rand/secret_sharing/network_messages.rs (L28-38)
```rust
    pub fn verify(
        &self,
        epoch_state: &EpochState,
        config: &SecretShareConfig,
    ) -> anyhow::Result<()> {
        ensure!(self.epoch() == epoch_state.epoch);
        match self {
            SecretShareMessage::RequestShare(_) => Ok(()),
            SecretShareMessage::Share(share) => share.verify(config),
        }
    }
```

**File:** types/src/secret_sharing.rs (L75-82)
```rust
    pub fn verify(&self, config: &SecretShareConfig) -> anyhow::Result<()> {
        let index = config.get_id(self.author());
        let decryption_key_share = self.share().clone();
        // TODO(ibalajiarun): Check index out of bounds
        config.verification_keys[index]
            .verify_decryption_key_share(&self.metadata.digest, &decryption_key_share)?;
        Ok(())
    }
```

**File:** types/src/secret_sharing.rs (L172-178)
```rust
    pub fn get_id(&self, peer: &Author) -> usize {
        *self
            .validator
            .address_to_validator_index()
            .get(peer)
            .expect("Peer should be in the index!")
    }
```

**File:** crates/crash-handler/src/lib.rs (L26-58)
```rust
pub fn setup_panic_handler() {
    panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
        handle_panic(pi);
    }));
}

// Formats and logs panic information
fn handle_panic(panic_info: &PanicHookInfo<'_>) {
    // The Display formatter for a PanicHookInfo contains the message, payload and location.
    let details = format!("{}", panic_info);
    let backtrace = format!("{:#?}", Backtrace::new());

    let info = CrashInfo { details, backtrace };
    let crash_info = toml::to_string_pretty(&info).unwrap();
    error!("{}", crash_info);
    // TODO / HACK ALARM: Write crash info synchronously via eprintln! to ensure it is written before the process exits which error! doesn't guarantee.
    // This is a workaround until https://github.com/aptos-labs/aptos-core/issues/2038 is resolved.
    eprintln!("{}", crash_info);

    // Wait till the logs have been flushed
    aptos_logger::flush();

    // Do not kill the process if the panics happened at move-bytecode-verifier.
    // This is safe because the `state::get_state()` uses a thread_local for storing states. Thus the state can only be mutated to VERIFIER by the thread that's running the bytecode verifier.
    //
    // TODO: once `can_unwind` is stable, we should assert it. See https://github.com/rust-lang/rust/issues/92988.
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
}
```

**File:** consensus/src/rand/secret_sharing/reliable_broadcast_state.rs (L44-52)
```rust
    fn add(&self, peer: Author, share: Self::Response) -> anyhow::Result<Option<()>> {
        ensure!(share.author() == &peer, "Author does not match");
        ensure!(
            share.metadata() == &self.secret_share_metadata,
            "Metadata does not match: local {:?}, received {:?}",
            self.secret_share_metadata,
            share.metadata()
        );
        share.verify(&self.secret_share_config)?;
```
