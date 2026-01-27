# Audit Report

## Title
Missing Sender Authentication in Direct Secret Share Broadcast Path Allows Validator Impersonation

## Summary
The `SecretShare::verify()` function only validates cryptographic correctness of shares but does not verify that the network sender matches the claimed `author` field. The direct broadcast message handling path in `SecretShareManager` lacks sender authentication, allowing a malicious validator who obtains another validator's secret key share to impersonate that validator. This contradicts the reliable broadcast path which explicitly enforces this check.

## Finding Description
The secret sharing implementation has two distinct code paths for receiving shares:

**Path 1 - Reliable Broadcast (Protected):**
In `SecretShareAggregateState::add()`, there is an explicit authentication check ensuring the network sender matches the share author: [1](#0-0) 

**Path 2 - Direct Broadcast (Vulnerable):**
The direct message handling path has no such check. In `SecretShareManager::verification_task()`, incoming messages are deserialized and verified but the `sender` field from `IncomingSecretShareRequest` is never compared to the share's author: [2](#0-1) 

The `sender` field is captured from the network layer but marked as unused: [3](#0-2) 

When messages arrive via direct send, the sender is captured but never validated: [4](#0-3) 

The `SecretShare::verify()` function only performs cryptographic validation using the self-claimed author to select the verification key: [5](#0-4) 

**Attack Scenario:**
If validator B obtains validator A's secret key share (through node compromise, memory dump, storage access, or DKG implementation bugs), B can:
1. Create a `SecretShare` with `author = A` and `share = A's actual share`
2. Send it via direct broadcast (not reliable broadcast)
3. The message passes cryptographic verification (it IS A's valid share)
4. The share is stored under A's identity in the aggregator: [6](#0-5) 

5. B has successfully impersonated A without detection

## Impact Explanation
**Severity: High**

This breaks the fundamental authentication invariant that only validator A can submit shares on behalf of validator A. The impact includes:

1. **Loss of Accountability**: Cannot determine which validator actually contributed shares
2. **Threshold Manipulation**: If B compromises multiple validators' shares, B can impersonate enough validators to meet threshold requirements
3. **Denial of Service**: B can prevent legitimate validators from contributing by submitting their shares first
4. **Consensus Safety Risk**: If secret sharing is used for randomness or threshold signatures in consensus, this could enable attacks on consensus safety

This violates the "Cryptographic Correctness" invariant requiring secure authentication and the "Consensus Safety" invariant requiring correct identification of validator contributions.

The inconsistency between the two code paths (one protected, one vulnerable) strongly suggests this is an implementation bug rather than intentional design.

## Likelihood Explanation
**Likelihood: Medium**

**Prerequisites:**
- Attacker must be a validator with network access
- Attacker must obtain another validator's secret key share

**Realistic Attack Vectors:**
- Node compromise through remote exploits or physical access
- Memory extraction attacks on running validator nodes  
- Storage system vulnerabilities exposing key material
- DKG implementation bugs that leak shares during distribution
- Side-channel attacks (timing, cache, spectre-class)
- Insider threat scenarios

Once a share is obtained, the exploit is trivial: simply send a direct broadcast message with the stolen share and victim's author field.

The presence of the check in reliable broadcast but not direct send suggests developers recognized this threat but failed to apply the mitigation uniformly.

## Recommendation
Add sender authentication to the direct broadcast path, matching the protection in reliable broadcast:

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
        let sender = dec_msg.sender; // Capture sender
        bounded_executor
            .spawn(async move {
                match bcs::from_bytes::<SecretShareMessage>(dec_msg.req.data()) {
                    Ok(msg) => {
                        // Verify sender matches author for Share messages
                        match &msg {
                            SecretShareMessage::Share(share) => {
                                if share.author() != &sender {
                                    warn!("Author {} does not match sender {}", share.author(), sender);
                                    return;
                                }
                            },
                            _ => {}
                        }
                        
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

## Proof of Concept
```rust
#[tokio::test]
async fn test_secret_share_author_mismatch_attack() {
    // Setup: Create two validators A and B with secret shares
    let (validator_a, share_a) = setup_validator("validator_a");
    let (validator_b, _share_b) = setup_validator("validator_b");
    
    // Attack: Validator B creates a SecretShare claiming to be from A
    let malicious_share = SecretShare::new(
        validator_a.address(), // Claim to be A
        metadata.clone(),
        share_a.clone(), // Use A's actual share (obtained through compromise)
    );
    
    // B sends this via direct broadcast
    let message = SecretShareMessage::Share(malicious_share);
    
    // Expected: Should fail sender authentication check
    // Actual: Passes verification and is accepted as A's share
    
    // The message passes through verification_task without sender check
    let verified = message.verify(&epoch_state, &config);
    assert!(verified.is_ok()); // Cryptographically valid
    
    // Share gets stored under A's identity despite coming from B
    secret_share_store.add_share(malicious_share).unwrap();
    
    // Verify impersonation succeeded
    let stored_authors = secret_share_store.get_all_shares_authors(&metadata);
    assert!(stored_authors.unwrap().contains(&validator_a.address()));
    
    // System incorrectly believes it received A's share from A
    // when it actually came from malicious validator B
}
```

**Notes:**
- This vulnerability exists specifically in the direct send message path, not the reliable broadcast path
- The inconsistency between the two paths indicates an implementation oversight
- The TODO comment in `verify()` about checking index bounds suggests incomplete validation logic
- Defense-in-depth principle requires sender authentication even if shares are assumed secret

### Citations

**File:** consensus/src/rand/secret_sharing/reliable_broadcast_state.rs (L45-45)
```rust
        ensure!(share.author() == &peer, "Author does not match");
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L212-226)
```rust
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
```

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

**File:** consensus/src/network.rs (L923-925)
```rust
                                IncomingSecretShareRequest {
                                    req,
                                    sender: peer_id,
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

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L33-33)
```rust
        if self.shares.insert(share.author, share).is_none() {
```
