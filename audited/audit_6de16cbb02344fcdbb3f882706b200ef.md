# Audit Report

## Title
Batch Flooding Vulnerability via Repeated Signature Verification in SignedBatchInfoMsg

## Summary
An attacker can flood validators with computationally expensive signature verification work by repeatedly sending `SignedBatchInfoMsg` messages containing up to 20 batches (the `receiver_max_num_batches` limit). Each message triggers BLS signature verification for all batches before any deduplication occurs, allowing an attacker to cause significant CPU exhaustion on validator nodes without caching or per-message deduplication protection.

## Finding Description
The vulnerability exists in the message verification flow for `SignedBatchInfoMsg` in the consensus layer. When a validator receives a `SignedBatchInfoMsg`, the verification process performs the following steps:

1. The message is received and converted to an `UnverifiedEvent::SignedBatchInfo` [1](#0-0) 

2. The unverified event is spawned in a bounded executor for verification [2](#0-1) 

3. The `SignedBatchInfoMsg::verify()` method is called, which iterates through all batches (up to `max_num_batches = 20` by default) and performs signature verification on each one [3](#0-2) 

4. Each individual batch verification calls `validator.optimistic_verify()` which performs BLS signature verification [4](#0-3) 

5. Only AFTER successful verification is the message forwarded to the ProofCoordinator where deduplication occurs [5](#0-4) 

**Critical Issue:** Unlike `ProofOfStore` messages which utilize a `ProofCache` to avoid redundant verification [6](#0-5) , `SignedBatchInfo` messages have **no caching mechanism** and no pre-verification deduplication.

The default configuration allows 20 batches per message [7](#0-6) , and the bounded executor is limited to 16 concurrent tasks [8](#0-7) .

**Attack Scenario:**
An attacker can repeatedly send identical or varied `SignedBatchInfoMsg` messages with 20 batches each. Each message requires 20 expensive BLS signature verifications before being processed or deduplicated. By saturating the bounded executor with verification tasks, the attacker forces validators to continuously perform cryptographic operations, consuming significant CPU resources and potentially delaying legitimate consensus messages.

## Impact Explanation
This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program criteria:

- **Validator node slowdowns**: The attack causes validators to waste CPU cycles on redundant signature verifications, slowing down consensus processing
- **Resource exhaustion**: BLS signature verification is computationally expensive; 20 verifications per message multiplied by repeated messages can significantly impact node performance
- **Consensus performance degradation**: While not a complete DoS, the bounded executor backpressure and CPU exhaustion can delay block processing and affect overall network liveness

The vulnerability does not directly lead to consensus safety violations or fund loss, but it creates a viable attack vector for degrading validator performance, which aligns with the "Validator node slowdowns" category for High/Medium severity findings.

## Likelihood Explanation
The likelihood of exploitation is **HIGH**:

1. **Low attack complexity**: Any network peer can send `SignedBatchInfoMsg` messages to validators
2. **No authentication barrier**: While signatures must be valid, an attacker can create valid signatures as a validator or replay previously seen valid messages
3. **No rate limiting**: Application-level per-peer rate limiting for `SignedBatchInfo` messages is absent
4. **Bounded executor saturation**: With only 16 concurrent verification tasks, an attacker can easily saturate the verification pipeline
5. **No caching**: Each message is verified from scratch, even if identical to previously verified messages

## Recommendation
Implement a verification cache for `SignedBatchInfo` messages similar to the existing `ProofCache` used for `ProofOfStore` messages:

**Recommended Fix:**

1. Add a cache type for signed batch info verification:
```rust
pub type SignedBatchInfoCache = Cache<(BatchInfoExt, PeerId), ()>;
```

2. Modify `SignedBatchInfo::verify()` to check the cache before verification: [4](#0-3) 

The modified implementation should:
- Check if `(batch_info, signer)` tuple exists in cache
- Skip verification if cached entry found
- Insert into cache after successful verification
- Pass the cache through the verification chain from epoch_manager

3. Add per-peer rate limiting for quorum store messages at the application level, tracking the number of SignedBatchInfoMsg messages received per peer per time window.

4. Consider implementing message deduplication before verification by tracking message digests in a short-term cache.

## Proof of Concept
```rust
// Proof of Concept demonstrating the attack
// This would be run as a Rust integration test

use aptos_consensus_types::proof_of_store::{BatchInfo, SignedBatchInfo, SignedBatchInfoMsg};
use aptos_types::validator_verifier::ValidatorVerifier;
use std::time::Instant;

#[test]
fn test_batch_flooding_attack() {
    // Setup: Create validator verifier and legitimate signed batches
    let validator_verifier = create_test_validator_verifier();
    let max_num_batches = 20;
    
    // Create a valid SignedBatchInfoMsg with 20 batches
    let mut signed_batches = Vec::new();
    for i in 0..max_num_batches {
        let batch_info = create_test_batch_info(i);
        let signed_batch = create_valid_signed_batch(batch_info, &validator_signer);
        signed_batches.push(signed_batch);
    }
    let msg = SignedBatchInfoMsg::new(signed_batches);
    
    // Attack: Send the same message 100 times
    let start = Instant::now();
    for _ in 0..100 {
        // Each call performs 20 BLS signature verifications
        let result = msg.verify(
            peer_id,
            max_num_batches,
            max_batch_expiry_gap,
            &validator_verifier,
        );
        assert!(result.is_ok());
    }
    let elapsed = start.elapsed();
    
    // Demonstrate: 100 messages × 20 batches = 2000 signature verifications
    // With no caching, this takes significant time
    println!("Time for 2000 redundant verifications: {:?}", elapsed);
    // Expected: Several seconds of CPU time wasted on redundant work
    
    // Compare with cached approach (ProofOfStore)
    // Cached verification would only verify once, then use cache
}
```

**Notes:**
- The vulnerability is exploitable by any network peer that can send consensus messages
- The attack can be sustained by continuously sending messages with valid signatures
- Multiple attackers or compromised validators could amplify the impact
- The bounded executor provides some backpressure but is insufficient protection against this attack pattern

### Citations

**File:** consensus/src/epoch_manager.rs (L1587-1622)
```rust
            self.bounded_executor
                .spawn(async move {
                    match monitor!(
                        "verify_message",
                        unverified_event.clone().verify(
                            peer_id,
                            &epoch_state.verifier,
                            &proof_cache,
                            quorum_store_enabled,
                            peer_id == my_peer_id,
                            max_num_batches,
                            max_batch_expiry_gap_usecs,
                        )
                    ) {
                        Ok(verified_event) => {
                            Self::forward_event(
                                quorum_store_msg_tx,
                                round_manager_tx,
                                buffered_proposal_tx,
                                peer_id,
                                verified_event,
                                payload_manager,
                                pending_blocks,
                            );
                        },
                        Err(e) => {
                            error!(
                                SecurityEvent::ConsensusInvalidMessage,
                                remote_peer = peer_id,
                                error = ?e,
                                unverified_event = unverified_event
                            );
                        },
                    }
                })
                .await;
```

**File:** consensus/src/epoch_manager.rs (L1643-1643)
```rust
            | ConsensusMsg::SignedBatchInfo(_)
```

**File:** consensus/src/epoch_manager.rs (L1758-1762)
```rust
            quorum_store_event @ (VerifiedEvent::SignedBatchInfo(_)
            | VerifiedEvent::ProofOfStoreMsg(_)
            | VerifiedEvent::BatchMsg(_)) => {
                Self::forward_event_to(quorum_store_msg_tx, peer_id, (peer_id, quorum_store_event))
                    .context("quorum store sender")
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L363-381)
```rust
    pub fn verify(
        &self,
        sender: PeerId,
        max_num_batches: usize,
        max_batch_expiry_gap_usecs: u64,
        validator: &ValidatorVerifier,
    ) -> anyhow::Result<()> {
        ensure!(!self.signed_infos.is_empty(), "Empty message");
        ensure!(
            self.signed_infos.len() <= max_num_batches,
            "Too many batches: {} > {}",
            self.signed_infos.len(),
            max_num_batches
        );
        for signed_info in &self.signed_infos {
            signed_info.verify(sender, max_batch_expiry_gap_usecs, validator)?
        }
        Ok(())
    }
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L459-482)
```rust
    pub fn verify(
        &self,
        sender: PeerId,
        max_batch_expiry_gap_usecs: u64,
        validator: &ValidatorVerifier,
    ) -> anyhow::Result<()> {
        if sender != self.signer {
            bail!("Sender {} mismatch signer {}", sender, self.signer);
        }

        if self.expiration()
            > aptos_infallible::duration_since_epoch().as_micros() as u64
                + max_batch_expiry_gap_usecs
        {
            bail!(
                "Batch expiration too far in future: {} > {}",
                self.expiration(),
                aptos_infallible::duration_since_epoch().as_micros() as u64
                    + max_batch_expiry_gap_usecs
            );
        }

        Ok(validator.optimistic_verify(self.signer, &self.info, &self.signature)?)
    }
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L635-651)
```rust
    pub fn verify(&self, validator: &ValidatorVerifier, cache: &ProofCache) -> anyhow::Result<()> {
        let batch_info_ext: BatchInfoExt = self.info.clone().into();
        if let Some(signature) = cache.get(&batch_info_ext) {
            if signature == self.multi_signature {
                return Ok(());
            }
        }
        let result = validator
            .verify_multi_signatures(&self.info, &self.multi_signature)
            .context(format!(
                "Failed to verify ProofOfStore for batch: {:?}",
                self.info
            ));
        if result.is_ok() {
            cache.insert(batch_info_ext, self.multi_signature.clone());
        }
        result
```

**File:** config/src/config/quorum_store_config.rs (L122-122)
```rust
            receiver_max_num_batches: 20,
```

**File:** config/src/config/consensus_config.rs (L379-379)
```rust
            num_bounded_executor_tasks: 16,
```
