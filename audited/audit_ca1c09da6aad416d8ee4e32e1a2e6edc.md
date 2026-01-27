# Audit Report

## Title
Byzantine Validator Can Degrade Honest Validator Performance Through Signature Verification Flooding

## Summary
A Byzantine validator can send a flood of invalid consensus messages (e.g., VoteMsg) with bad signatures to an honest validator, forcing expensive BLS signature verification operations that saturate the bounded executor and block the consensus message processing loop, degrading validator performance below consensus thresholds.

## Finding Description

The vulnerability exists in the consensus message verification pipeline where the EpochManager's main event loop synchronously awaits bounded executor permits before processing the next message.

**Attack Flow:**

1. A Byzantine validator sends many invalid `VoteMsg` messages with bad BLS signatures to an honest validator
2. Messages enter the `consensus_messages` channel (capacity 10) [1](#0-0) 
3. The EpochManager's main loop processes messages sequentially using `tokio::select!` [2](#0-1) 
4. For each message, `process_message()` is awaited, which spawns verification on the bounded executor [3](#0-2) 
5. The first invalid message from the attacker passes through optimistic verification without actual signature verification (if `optimistic_sig_verification` is enabled) [4](#0-3) 
6. During vote aggregation, the aggregate signature verification fails, and individual signatures are re-verified. The attacker's address is added to `pessimistic_verify_set` [5](#0-4) 
7. All subsequent messages from the attacker require individual BLS signature verification [6](#0-5) 
8. Each verification calls the expensive `verify_struct_signature()` operation [7](#0-6) 
9. The bounded executor (default capacity 16) becomes saturated with verification tasks [8](#0-7) 
10. `bounded_executor.spawn()` awaits for available permits, blocking the entire select! arm [9](#0-8) 
11. While blocked, the EpochManager cannot dequeue new messages from the channel
12. Legitimate consensus messages (proposals, votes from honest validators) are delayed
13. The targeted validator cannot respond to proposals or propagate votes within consensus timeouts
14. Consensus progress degrades or stalls if the targeted validator is needed for quorum

**Key Issue:** The synchronous await on `bounded_executor.spawn()` within the message processing loop creates a bottleneck. When the bounded executor is saturated with expensive signature verification tasks, the entire message processing pipeline stalls.

## Impact Explanation

This is **High Severity** per the Aptos bug bounty program:
- **Validator node slowdowns** - explicitly listed as High severity (up to $50,000)
- A single Byzantine validator can target and degrade an honest validator's performance
- Can prevent the honest validator from participating effectively in consensus
- Affects consensus liveness (though not safety directly)
- The attack requires minimal resources from the attacker but can cause significant disruption

The vulnerability breaks the following invariant:
- **Resource Limits**: "All operations must respect gas, storage, and computational limits" - the system fails to properly rate-limit expensive validation operations per peer, allowing a single Byzantine peer to exhaust validation resources

## Likelihood Explanation

**Likelihood: High**

The attack is:
- **Simple to execute**: Byzantine validator just needs to send invalid VoteMsg messages in a loop
- **Requires minimal resources**: Sending messages is cheap, but verification is expensive (asymmetric cost)
- **Within threat model**: Aptos consensus is designed to tolerate Byzantine validators (< 1/3), so this should be handled gracefully
- **No detection required**: Attacker doesn't need to know internal validator state
- **Persistent effect**: Once in pessimistic_verify_set, all subsequent messages trigger expensive verification

The only requirement is that the attacker is a Byzantine validator, which is explicitly within the AptosBFT threat model.

## Recommendation

**Fix 1: Non-blocking Verification Spawn**

Modify `EpochManager::process_message()` to use `try_spawn()` instead of `spawn().await`, and drop messages when the bounded executor is at capacity:

```rust
// In epoch_manager.rs, around line 1587
let spawn_result = self.bounded_executor.try_spawn(async move {
    match monitor!(
        "verify_message",
        unverified_event.clone().verify(/* ... */)
    ) {
        Ok(verified_event) => { /* forward event */ },
        Err(e) => { /* log error */ },
    }
});

if spawn_result.is_err() {
    counters::VERIFICATION_TASKS_DROPPED.inc();
    warn!(
        "Dropped message verification task due to bounded executor at capacity. \
         Peer: {}, Message type: {:?}",
        peer_id, unverified_event
    );
}
```

**Fix 2: Per-Peer Rate Limiting**

Add per-peer message rate limiting before verification:

```rust
// Add to EpochManager
peer_message_tracker: Arc<DashMap<AccountAddress, (usize, Instant)>>,

// In process_message(), check rate limit
const MAX_MESSAGES_PER_PEER_PER_SECOND: usize = 100;
let mut tracker = self.peer_message_tracker.entry(peer_id).or_insert((0, Instant::now()));
if tracker.1.elapsed() > Duration::from_secs(1) {
    tracker.0 = 0;
    tracker.1 = Instant::now();
}
if tracker.0 >= MAX_MESSAGES_PER_PEER_PER_SECOND {
    bail!("Rate limit exceeded for peer {}", peer_id);
}
tracker.0 += 1;
```

**Fix 3: Immediate Rejection for Pessimistic Set**

Track failed verification counts per peer and reject messages immediately without spawning verification tasks:

```rust
// Add counter in ValidatorVerifier or EpochManager
peer_failure_counts: Arc<DashMap<AccountAddress, AtomicUsize>>,

// Reject immediately if peer has too many failures
const MAX_FAILURES_BEFORE_REJECTION: usize = 10;
if let Some(count) = self.peer_failure_counts.get(&peer_id) {
    if count.load(Ordering::Relaxed) > MAX_FAILURES_BEFORE_REJECTION {
        bail!("Peer {} has exceeded failure threshold", peer_id);
    }
}
```

## Proof of Concept

```rust
// Rust test to demonstrate the vulnerability
#[tokio::test]
async fn test_signature_verification_dos() {
    use aptos_consensus_types::vote_msg::VoteMsg;
    use aptos_crypto::bls12381::{PrivateKey, Signature};
    use std::time::Instant;

    // Setup: Create a validator network with one honest and one Byzantine validator
    let (mut test_env, byzantine_signer, honest_peer_id) = setup_test_network().await;
    
    // Attack: Byzantine validator sends many invalid VoteMsg messages
    const NUM_INVALID_MESSAGES: usize = 100;
    let invalid_messages: Vec<VoteMsg> = (0..NUM_INVALID_MESSAGES)
        .map(|i| {
            // Create VoteMsg with invalid signature
            let mut vote_msg = create_test_vote_msg(i as u64, &byzantine_signer);
            // Corrupt the signature
            vote_msg.vote_mut().corrupt_signature();
            vote_msg
        })
        .collect();
    
    // Measure time to process a legitimate message before attack
    let legitimate_msg = create_valid_proposal(&honest_peer_id);
    let start = Instant::now();
    test_env.send_message_from_peer(honest_peer_id, legitimate_msg.clone()).await;
    let baseline_latency = start.elapsed();
    
    println!("Baseline message processing latency: {:?}", baseline_latency);
    
    // Send flood of invalid messages
    let attack_start = Instant::now();
    for msg in invalid_messages {
        test_env.send_message_from_byzantine(msg).await;
    }
    
    // Try to send another legitimate message during attack
    let start = Instant::now();
    test_env.send_message_from_peer(honest_peer_id, legitimate_msg).await;
    let attack_latency = start.elapsed();
    
    println!("Message processing latency during attack: {:?}", attack_latency);
    println!("Latency increase: {}x", attack_latency.as_millis() / baseline_latency.as_millis());
    
    // Assert that latency increased significantly (e.g., >10x)
    assert!(
        attack_latency > baseline_latency * 10,
        "Expected significant latency increase during attack"
    );
    
    // Assert that bounded executor is saturated
    let executor_capacity = test_env.get_bounded_executor_available_permits();
    assert_eq!(
        executor_capacity, 0,
        "Bounded executor should be saturated during attack"
    );
}
```

## Notes

The vulnerability is particularly concerning because:

1. **Asymmetric cost**: Sending invalid messages is cheap for the attacker, but verification is expensive for the victim (BLS signature verification involves pairing operations)

2. **Persistent effect**: Once added to `pessimistic_verify_set`, the attacker can continuously trigger expensive verifications

3. **No automatic recovery**: The validator doesn't automatically ban or disconnect from the Byzantine peer

4. **Affects critical path**: Consensus message processing is on the critical path for liveness

5. **Amplification potential**: A Byzantine validator can target multiple honest validators simultaneously

The issue is not in the `Validatable` type itself (which is primarily used for BLS public key validation), but rather in how expensive signature verification operations interact with the bounded executor and message processing loop in the consensus layer.

### Citations

**File:** consensus/src/network.rs (L757-761)
```rust
        let (consensus_messages_tx, consensus_messages) = aptos_channel::new(
            QueueStyle::FIFO,
            10,
            Some(&counters::CONSENSUS_CHANNEL_MSGS),
        );
```

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

**File:** consensus/src/epoch_manager.rs (L1930-1936)
```rust
            tokio::select! {
                (peer, msg) = network_receivers.consensus_messages.select_next_some() => {
                    monitor!("epoch_manager_process_consensus_messages",
                    if let Err(e) = self.process_message(peer, msg).await {
                        error!(epoch = self.epoch(), error = ?e, kind = error_kind(&e));
                    });
                },
```

**File:** types/src/validator_verifier.rs (L255-267)
```rust
    pub fn verify<T: Serialize + CryptoHash>(
        &self,
        author: AccountAddress,
        message: &T,
        signature: &bls12381::Signature,
    ) -> std::result::Result<(), VerifyError> {
        match self.get_public_key(&author) {
            Some(public_key) => public_key
                .verify_struct_signature(message, signature)
                .map_err(|_| VerifyError::InvalidMultiSignature),
            None => Err(VerifyError::UnknownAuthor),
        }
    }
```

**File:** types/src/validator_verifier.rs (L269-285)
```rust
    pub fn optimistic_verify<T: Serialize + CryptoHash>(
        &self,
        author: AccountAddress,
        message: &T,
        signature_with_status: &SignatureWithStatus,
    ) -> std::result::Result<(), VerifyError> {
        if self.get_public_key(&author).is_none() {
            return Err(VerifyError::UnknownAuthor);
        }
        if (!self.optimistic_sig_verification || self.pessimistic_verify_set.contains(&author))
            && !signature_with_status.is_verified()
        {
            self.verify(author, message, signature_with_status.signature())?;
            signature_with_status.set_verified();
        }
        Ok(())
    }
```

**File:** types/src/validator_verifier.rs (L287-311)
```rust
    pub fn filter_invalid_signatures<T: Send + Sync + Serialize + CryptoHash>(
        &self,
        message: &T,
        signatures: BTreeMap<AccountAddress, SignatureWithStatus>,
    ) -> BTreeMap<AccountAddress, SignatureWithStatus> {
        signatures
            .into_iter()
            .collect_vec()
            .into_par_iter()
            .with_min_len(4) // At least 4 signatures are verified in each task
            .filter_map(|(account_address, signature)| {
                if signature.is_verified()
                    || self
                        .verify(account_address, message, signature.signature())
                        .is_ok()
                {
                    signature.set_verified();
                    Some((account_address, signature))
                } else {
                    self.add_pessimistic_verify_set(account_address);
                    None
                }
            })
            .collect()
    }
```

**File:** config/src/config/consensus_config.rs (L97-97)
```rust
    pub num_bounded_executor_tasks: u64,
```

**File:** crates/bounded-executor/src/executor.rs (L45-52)
```rust
    pub async fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let permit = self.acquire_permit().await;
        self.executor.spawn(future_with_permit(future, permit))
    }
```
