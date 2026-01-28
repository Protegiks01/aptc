# Audit Report

## Title
Unvalidated Author Field in SecretShare Verification Causes Validator Node Crash via Panic

## Summary
A missing validation check in the SecretShare verification path allows any consensus network peer to crash validator nodes by sending messages with author addresses not in the validator set. The vulnerability exploits an unguarded `.expect()` call that panics and terminates the validator process.

## Finding Description
The `SecretShareManager::verification_task()` receives incoming secret share messages and verifies them without validating that the `author` field in the message matches the authenticated `sender`. This contrasts with the reliable broadcast path, which explicitly checks this invariant. [1](#0-0) 

The verification task deserializes incoming messages and calls `msg.verify()`, which invokes `SecretShare::verify()`: [2](#0-1) 

At line 76, `config.get_id(self.author())` is called without any prior validation that the author exists in the validator set. The `get_id()` implementation contains an unguarded `.expect()`: [3](#0-2) 

Notably, there is a TODO comment at line 78 acknowledging the missing bounds check: [4](#0-3) 

The `IncomingSecretShareRequest` struct contains a `sender` field that identifies the authenticated peer, but this field is marked `#[allow(unused)]` and never validated: [5](#0-4) 

In contrast, the reliable broadcast aggregation path **does** perform this validation: [6](#0-5) 

When the panic occurs in the spawned verification task, it triggers the global panic handler which calls `process::exit(12)`: [7](#0-6) 

The panic only bypasses process termination if it occurs in Move verifier/deserializer contexts, which is not the case here.

## Impact Explanation
This vulnerability constitutes **HIGH severity** under the Aptos Bug Bounty criteria as "API Crashes" and potentially **CRITICAL severity** as "Total loss of liveness/network availability":

1. **Complete Node Termination**: The validator process exits entirely via `process::exit(12)`, not just a thread or task crash
2. **Byzantine Fault Tolerance Violation**: One validator can crash another, violating the < 1/3 Byzantine assumption
3. **Coordinated Attack Potential**: Attacker can simultaneously crash multiple validators, causing network-wide liveness failure
4. **Rapid Re-exploitation**: Nodes remain vulnerable after restart with no rate limiting

While consensus network access is typically restricted to validators, one validator should not be able to crash others - this is a fundamental consensus safety requirement. The code inconsistency (validation present in one path but missing in another) confirms this is a genuine security bug rather than intentional design.

## Likelihood Explanation
**Likelihood: HIGH**

1. **Simple Exploitation**: Requires only crafting a single message with an invalid author field
2. **Wide Attack Surface**: All validators participating in secret sharing are vulnerable  
3. **No Defensive Measures**: No bounds checking, no rate limiting, no recovery mechanism
4. **Code Evidence of Bug**: The TODO comment and inconsistent validation patterns indicate this is an unintentional vulnerability

Even though only validators can send consensus messages, this violates Byzantine fault tolerance guarantees - malicious or compromised validators should not be able to crash honest validators with a single malformed message.

## Recommendation
Add validation in `SecretShareManager::verification_task()` to ensure the message author matches the authenticated sender before calling verification. Additionally, implement bounds checking in `get_id()` to return an error instead of panicking:

```rust
// In verification_task, after deserializing:
match msg {
    SecretShareMessage::Share(ref share) => {
        if share.author() != &sender {
            warn!("Author does not match sender");
            continue;
        }
    },
    _ => {}
}

// In SecretShareConfig::get_id():
pub fn get_id(&self, peer: &Author) -> anyhow::Result<usize> {
    self.validator
        .address_to_validator_index()
        .get(peer)
        .copied()
        .ok_or_else(|| anyhow::anyhow!("Peer not in validator set"))
}
```

## Proof of Concept
An attacker with validator network access can construct a SecretShareMessage with an arbitrary author field (e.g., `AccountAddress::ZERO` if not a validator) and send it to target validators. Upon receipt, the verification task will attempt to look up this author in the validator set, trigger the panic at the `.expect()` call, and cause the global panic handler to terminate the process with exit code 12.

The attack succeeds because the `sender` field from `IncomingSecretShareRequest` is never checked against the message's `author` field before `get_id()` is called.

## Notes
This vulnerability exploits a protocol-level bug (missing validation), not a network-level DoS attack. The inconsistent validation between the direct RPC path and the reliable broadcast path, combined with the explicit TODO comment acknowledging the missing bounds check, confirms this is a genuine security issue that violates Byzantine fault tolerance guarantees.

### Citations

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

**File:** consensus/src/network.rs (L154-161)
```rust
#[derive(Debug)]
pub struct IncomingSecretShareRequest {
    pub req: SecretShareNetworkMessage,
    #[allow(unused)]
    pub sender: Author,
    pub protocol: ProtocolId,
    pub response_sender: oneshot::Sender<Result<Bytes, RpcError>>,
}
```

**File:** consensus/src/rand/secret_sharing/reliable_broadcast_state.rs (L44-45)
```rust
    fn add(&self, peer: Author, share: Self::Response) -> anyhow::Result<Option<()>> {
        ensure!(share.author() == &peer, "Author does not match");
```

**File:** crates/crash-handler/src/lib.rs (L48-57)
```rust
    // Do not kill the process if the panics happened at move-bytecode-verifier.
    // This is safe because the `state::get_state()` uses a thread_local for storing states. Thus the state can only be mutated to VERIFIER by the thread that's running the bytecode verifier.
    //
    // TODO: once `can_unwind` is stable, we should assert it. See https://github.com/rust-lang/rust/issues/92988.
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
```
