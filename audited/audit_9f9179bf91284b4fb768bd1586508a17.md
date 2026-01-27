# Audit Report

## Title
SecretShare Verification DoS: Malicious Validator Can Cause Excessive CPU Usage Through Invalid Decryption Key Flooding

## Summary
A malicious validator can flood other validators with invalid `SecretShare` messages, causing excessive CPU consumption through expensive BLS pairing operations that execute before cryptographic verification fails. The attack is rate-limited but not prevented by existing protections.

## Finding Description

The vulnerability exists in the secret sharing verification pipeline used for randomness generation in Aptos consensus. When a validator receives a `SecretShare` message, it undergoes verification that includes expensive cryptographic operations before determining if the share is valid.

**Attack Flow:**

1. **Message Reception**: A malicious validator crafts many `SecretShare` messages with their own valid author but invalid decryption key share data. [1](#0-0) 

2. **Verification Task Spawning**: Messages are pushed to the `rpc_tx` channel (capacity 10) and processed by the verification task, which spawns async tasks on a `BoundedExecutor` (capacity 16). [2](#0-1) 

3. **Cheap Checks Pass**: The verification performs epoch validation and author lookup, both of which are cheap operations that pass for the malicious messages. [3](#0-2) [4](#0-3) 

4. **Expensive Operations Execute**: The system then performs expensive BLS cryptographic operations including hash-to-curve and **two pairing operations** per share before detecting the share is invalid. [5](#0-4) 

5. **Amplification for Weighted Shares**: For weighted threshold encryption, the verification loops over multiple verification keys, multiplying the computational cost. [6](#0-5) 

**Missing Protections:**
- No per-peer rate limiting for secret share messages
- No cheap signature or proof-of-work check before expensive pairing operations
- No penalty mechanism for validators sending invalid shares repeatedly
- No deduplication of invalid shares from the same peer

## Impact Explanation

This vulnerability causes **validator node slowdowns**, which is classified as **High Severity** (up to $50,000) in the Aptos bug bounty program. However, due to existing mitigations (bounded executor capacity of 16, channel capacity of 10), the impact is somewhat limited, warranting a **Medium severity** classification:

- **CPU Resource Exhaustion**: Pairing operations on BLS12-381 curves consume 1-2ms each, and each verification performs two pairings plus hash-to-curve operations
- **Degraded Consensus Performance**: Validators waste CPU cycles on invalid shares instead of consensus operations
- **Amplification Effect**: Multiple malicious validators could coordinate attacks
- **Limited by Mitigations**: Bounded executor and channel capacity provide partial protection but don't eliminate the attack

The attack does NOT cause:
- Complete network halt (existing rate limiting prevents total liveness loss)
- Consensus safety violations
- Fund loss or theft [7](#0-6) 

## Likelihood Explanation

**Likelihood: Medium-High**

**Requirements for Attack:**
- Attacker must be an active validator (requires stake and election to active set)
- Attacker must maintain validator status throughout attack
- Attack is straightforward to execute once validator access is obtained

**Feasibility:**
- Crafting invalid shares is trivial (random data with correct epoch/author)
- No cryptographic complexity required
- Can be automated to continuously flood victims
- Multiple validators can coordinate for amplified impact

**Detection:**
- Attack may be detectable through metrics showing high verification failure rates
- Victim validators would observe CPU spikes
- Malicious validator identity is visible in messages

## Recommendation

Implement multi-layered defense against invalid share flooding:

**1. Add Per-Peer Rate Limiting**
```rust
// In SecretShareManager, add rate limiter per peer
struct SecretShareManager {
    // existing fields...
    peer_rate_limiters: HashMap<Author, RateLimiter>,
}

// In verification_task, check rate limit before spawning verification
if !rate_limiter.check_and_update(peer_id) {
    warn!("Rate limit exceeded for peer {:?}", peer_id);
    continue;
}
```

**2. Add Cheap Pre-Verification**
Before expensive pairing operations, add a signature check on the share message itself to prevent flooding with completely invalid data.

**3. Implement Penalty/Backoff for Invalid Shares**
Track invalid share counts per peer and apply exponential backoff for peers exceeding thresholds: [8](#0-7) 

**4. Add Bounds Checking**
Address the TODO comment to prevent index out of bounds panics: [4](#0-3) 

## Proof of Concept

```rust
#[cfg(test)]
mod dos_test {
    use super::*;
    use std::time::Instant;
    
    #[tokio::test]
    async fn test_invalid_share_verification_dos() {
        // Setup: Create validator config and epoch state
        let config = create_test_config();
        let epoch_state = create_test_epoch_state();
        
        // Craft invalid shares with valid epoch but invalid crypto
        let malicious_shares: Vec<SecretShare> = (0..100)
            .map(|_| SecretShare {
                author: valid_validator_address(),
                metadata: SecretShareMetadata {
                    epoch: current_epoch(),
                    round: 1,
                    timestamp: 0,
                    block_id: HashValue::zero(),
                    digest: valid_digest(),
                },
                share: random_invalid_share(), // Random data, will fail verification
            })
            .collect();
        
        // Measure CPU time for verification
        let start = Instant::now();
        let mut failures = 0;
        
        for share in malicious_shares {
            if share.verify(&config).is_err() {
                failures += 1;
            }
        }
        
        let duration = start.elapsed();
        
        // Verify that significant CPU time was wasted
        assert_eq!(failures, 100); // All shares should fail
        assert!(duration.as_millis() > 200); // Each pairing ~2ms, 100 shares × 2 pairings = 400ms minimum
        
        println!("DOS Attack Result: {} invalid shares consumed {:?} CPU time", 
                 failures, duration);
    }
}
```

**Notes:**
- This vulnerability requires the attacker to be a validator, representing an insider threat scenario
- The attack is partially mitigated by existing rate limiting but remains exploitable
- The issue breaks the "Resource Limits" invariant by allowing unbounded expensive operations without corresponding DoS protection

### Citations

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

**File:** crates/aptos-batch-encryption/src/shared/key_derivation.rs (L118-133)
```rust
fn verify_bls(
    verification_key_g2: G2Affine,
    digest: &Digest,
    offset: G2Affine,
    signature: G1Affine,
) -> Result<()> {
    let hashed_offset: G1Affine = symmetric::hash_g2_element(offset)?;

    if PairingSetting::pairing(digest.as_g1() + hashed_offset, verification_key_g2)
        == PairingSetting::pairing(signature, G2Affine::generator())
    {
        Ok(())
    } else {
        Err(anyhow::anyhow!("bls verification error"))
    }
}
```

**File:** crates/aptos-batch-encryption/src/schemes/fptx_weighted.rs (L149-169)
```rust
    pub fn verify_decryption_key_share(
        &self,
        digest: &Digest,
        dk_share: &WeightedBIBEDecryptionKeyShare,
    ) -> Result<()> {
        (self.vks_g2.len() == dk_share.1.len())
            .then_some(())
            .ok_or(BatchEncryptionError::DecryptionKeyVerifyError)?;

        self.vks_g2
            .iter()
            .map(|vk_g2| BIBEVerificationKey {
                mpk_g2: self.mpk_g2,
                vk_g2: *vk_g2,
                player: self.weighted_player, // arbitrary
            })
            .zip(&dk_share.1)
            .try_for_each(|(vk, dk_share)| {
                vk.verify_decryption_key_share(digest, &(self.weighted_player, dk_share.clone()))
            })
    }
```

**File:** config/src/config/consensus_config.rs (L379-379)
```rust
            num_bounded_executor_tasks: 16,
```
