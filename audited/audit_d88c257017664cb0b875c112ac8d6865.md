# Audit Report

## Title
Secret Share Verification DoS via Expensive Cryptographic Operations Without Rate Limiting

## Summary
A malicious validator can flood other validators with invalid `SecretShare` messages that pass lightweight checks but fail expensive BLS pairing verification, causing CPU exhaustion and degraded consensus performance. The expensive cryptographic verification occurs before cheap validation checks (round number, deduplication), enabling resource exhaustion attacks.

## Finding Description

The secret sharing protocol in Aptos consensus is vulnerable to CPU exhaustion attacks through maliciously crafted `SecretShare` messages. The vulnerability exists in the message verification pipeline where expensive cryptographic operations are performed before cheap input validation.

**Attack Flow:**

1. A malicious validator sends numerous `SecretShare` messages with:
   - Valid `author` field (their own validator address)
   - Valid `epoch` (current epoch, publicly known)
   - Arbitrary/invalid `round`, `digest`, and `share` data

2. Messages arrive at the victim validator's `verification_task`: [1](#0-0) 

3. Each message passes deserialization and enters the `BoundedExecutor` queue (capacity: 16 concurrent tasks)

4. The `verify()` method is called, which performs only a trivial epoch check before expensive cryptography: [2](#0-1) 

5. For each `Share` message, `share.verify()` executes expensive BLS verification: [3](#0-2) 

6. This calls `verify_decryption_key_share()` which performs **two pairing operations** (among the most expensive cryptographic operations): [4](#0-3) 

7. Invalid shares fail verification, but the CPU cycles are already wasted

**Critical Issue:** Cheap validation checks (round bounds, deduplication) only occur AFTER expensive verification in `SecretShareStore::add_share()`: [5](#0-4) 

The round validation at lines 263-266 could reject many attack messages cheaply but runs too late.

**Amplification Factors:**

- The `BoundedExecutor` has default capacity of only 16: [6](#0-5) 

- The aptos_channel uses `KLAST` eviction policy, dropping oldest messages when full: [7](#0-6) 

This means attacker messages can evict legitimate shares from the queue.

## Impact Explanation

**Severity: HIGH** - "Validator node slowdowns" per Aptos Bug Bounty criteria.

**Impact Details:**
- **CPU Exhaustion**: Each invalid share consumes ~2 pairing operations worth of CPU (milliseconds per verification)
- **Legitimate Message Loss**: Attack messages evict valid shares from the bounded channel (capacity 10 per peer)
- **Consensus Degradation**: Secret sharing protocol delays or stalls, affecting randomness beacon
- **Sustained Attack**: Malicious validator can continuously spam, maintaining degraded state
- **Byzantine Validator Cost**: Attack requires only 1 malicious validator in validator set (within BFT threat model)

The attack directly violates the **Resource Limits** invariant: operations do not respect computational limits before performing expensive cryptographic verification.

## Likelihood Explanation

**Likelihood: HIGH**

**Attacker Requirements:**
- Must be an authenticated validator in the active validator set
- No collusion required - single malicious validator can execute attack
- Attack is trivial to implement - just send shares with invalid data

**Ease of Exploitation:**
- Simple message construction (valid epoch + random data)
- No timing requirements or race conditions
- Attack is sustainable and repeatable
- Difficult to distinguish from legitimate network issues initially

**Detectability:**
- Requires monitoring cryptographic verification failure rates per validator
- Network-level rate limiting (100 KiB/s) is insufficient to prevent attack at protocol layer

## Recommendation

Implement cheap validation checks BEFORE expensive cryptographic operations:

1. **Move round validation to verify() method**:
   ```rust
   // In SecretShareMessage::verify()
   pub fn verify(&self, epoch_state: &EpochState, config: &SecretShareConfig, highest_known_round: u64) -> anyhow::Result<()> {
       ensure!(self.epoch() == epoch_state.epoch);
       match self {
           SecretShareMessage::RequestShare(_) => Ok(()),
           SecretShareMessage::Share(share) => {
               // CHEAP CHECKS FIRST
               ensure!(
                   share.metadata.round <= highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
                   "Share from future round"
               );
               // Now do expensive verification
               share.verify(config)
           }
       }
   }
   ```

2. **Implement per-validator rate limiting** for share messages at the channel ingress point

3. **Add share deduplication cache** before expensive verification (track seen message hashes)

4. **Consider signature-based authentication** on Share messages to prevent spoofing

5. **Increase BoundedExecutor capacity** to handle legitimate burst traffic (e.g., 32-64)

## Proof of Concept

```rust
// PoC: Malicious validator flooding attack
use aptos_types::secret_sharing::{SecretShare, SecretShareMetadata};
use aptos_crypto::hash::HashValue;

fn generate_spam_shares(malicious_validator: Author, epoch: u64, count: usize) -> Vec<SecretShare> {
    let mut shares = vec![];
    for i in 0..count {
        // Create share with valid epoch but invalid data
        let metadata = SecretShareMetadata::new(
            epoch,                      // Valid epoch - passes check
            999999999 + i as u64,      // Invalid future round
            0,                          // Arbitrary timestamp
            HashValue::random(),        // Random block_id
            Digest::random(),           // Random digest
        );
        
        // Random invalid share data - will fail pairing verification
        let share = SecretKeyShare::random();
        
        shares.push(SecretShare::new(malicious_validator, metadata, share));
    }
    shares
}

// Attack: Send shares continuously
async fn execute_dos_attack(network_sender: NetworkSender, victim: Author) {
    loop {
        let spam = generate_spam_shares(MY_ADDRESS, CURRENT_EPOCH, 100);
        for share in spam {
            network_sender.send_to(
                victim,
                SecretShareMessage::Share(share).into_network_message()
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
```

**Expected Result**: Victim validator's CPU saturates verifying invalid shares, legitimate secret shares are delayed or dropped, secret sharing protocol degrades.

## Notes

This vulnerability is particularly concerning because:

1. **Defense in depth failure**: Multiple protection layers (channel bounds, bounded executor, verification) all operate AFTER the expensive operation
2. **Byzantine resilience**: Attack requires only 1/n malicious validators, well within BFT safety assumptions  
3. **Protocol-level DoS**: Cannot be mitigated by network-layer rate limiting alone
4. **Cascading impact**: Degraded secret sharing affects randomness beacon and potentially consensus liveness

The fix requires reordering validation logic to perform cheap checks (epoch, round bounds, deduplication) before expensive cryptographic verification.

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

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L259-275)
```rust
    pub fn add_share(&mut self, share: SecretShare) -> anyhow::Result<bool> {
        let weight = self.secret_share_config.get_peer_weight(share.author());
        let metadata = share.metadata();
        ensure!(metadata.epoch == self.epoch, "Share from different epoch");
        ensure!(
            metadata.round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );

        let item = self
            .secret_share_map
            .entry(metadata.round)
            .or_insert_with(|| SecretShareItem::new(self.self_author));
        item.add_share(share, weight)?;
        item.try_aggregate(&self.secret_share_config, self.decision_tx.clone());
        Ok(item.has_decision())
    }
```

**File:** config/src/config/consensus_config.rs (L379-379)
```rust
            num_bounded_executor_tasks: 16,
```

**File:** crates/channel/src/message_queues.rs (L138-146)
```rust
            match self.queue_style {
                // Drop the newest message for FIFO
                QueueStyle::FIFO => Some(message),
                // Drop the oldest message for LIFO
                QueueStyle::LIFO | QueueStyle::KLAST => {
                    let oldest = key_message_queue.pop_front();
                    key_message_queue.push_back(message);
                    oldest
                },
```
