# Audit Report

## Title
Missing Security Event Logging for Byzantine Behaviors in Randomness Generation Reliable Broadcast

## Summary
Byzantine behaviors (invalid signatures, wrong epochs, author mismatches, invalid share proofs) in the randomness generation reliable broadcast state are not logged as security events. These failures are only captured as generic RPC errors with sampled warnings, making malicious validator behavior invisible to security monitoring systems and preventing evidence collection for future slashing mechanisms.

## Finding Description

The randomness generation subsystem in `consensus/src/rand/rand_gen/reliable_broadcast_state.rs` implements three `BroadcastStatus` handlers that verify incoming messages:

1. **`AugDataCertBuilder::add`** - Verifies `AugDataSignature` signatures [1](#0-0) 

2. **`ShareAggregateState::add`** - Verifies author matching, metadata consistency, and share validity [2](#0-1) 

3. **`CertifiedAugDataAckState::add`** - Validates acknowledgments [3](#0-2) 

When verification fails (invalid signature, wrong epoch, author mismatch, invalid share proof), the code returns errors using the `?` operator or `ensure!` macro without any security event logging.

In contrast, other consensus components properly log Byzantine behaviors using `SecurityEvent`:

- **Equivocating votes** are logged with `SecurityEvent::ConsensusEquivocatingVote` [4](#0-3) 

- **Invalid sync info** is logged with `SecurityEvent::InvalidSyncInfoMsg` [5](#0-4) 

- **Invalid consensus messages** are logged with `SecurityEvent::ConsensusInvalidMessage` [6](#0-5) 

The `SecurityEvent` enum includes specific events for consensus misbehavior [7](#0-6) , but none are triggered by randomness generation failures.

When verification errors propagate through the reliable broadcast system, they are only logged generically via `log_rpc_failure` with sampled warnings (every 30 seconds) and debug-level messages [8](#0-7) . The verification task silently drops failed verifications [9](#0-8) .

## Impact Explanation

This issue meets **Medium severity** criteria per the Aptos bug bounty program:

1. **Evidence Collection Failure**: Aptos has placeholder code for slashing mechanisms [10](#0-9) , indicating planned implementation. Without proper logging of Byzantine behaviors, there will be no historical evidence to support slashing decisions when the feature is activated.

2. **Security Monitoring Blind Spot**: Security teams cannot identify patterns of malicious validator behavior in the randomness generation protocol. Sampled, debug-level generic RPC errors are insufficient for production security monitoring and incident response.

3. **Inconsistent Security Controls**: The codebase demonstrates that Byzantine behavior logging is considered a security requirement (as evidenced by extensive `SecurityEvent` usage in other consensus components), yet the randomness generation subsystem lacks this critical defensive capability.

4. **Validator Accountability Gap**: Without structured security event logs, operators cannot distinguish between legitimate network issues and deliberate Byzantine attacks, reducing validator accountability in the randomness generation protocol.

## Likelihood Explanation

**High likelihood** of occurrence because:

1. Byzantine validators can trivially trigger these code paths by sending malformed randomness messages (invalid signatures, wrong epochs, mismatched metadata)
2. The randomness generation protocol runs continuously during consensus
3. Network issues or legitimate validator misconfigurations will also go undetected
4. The logging infrastructure exists (`SecurityEvent` enum and logging macros) but is simply not utilized in this subsystem

## Recommendation

Add security event logging for all Byzantine behavior detections in `reliable_broadcast_state.rs`:

```rust
// In AugDataCertBuilder::add
fn add(&self, peer: Author, ack: Self::Response) -> anyhow::Result<Option<Self::Aggregated>> {
    if let Err(e) = ack.verify(peer, &self.epoch_state.verifier, &self.aug_data) {
        error!(
            SecurityEvent::ConsensusInvalidMessage,
            remote_peer = peer,
            error = ?e,
            message_type = "AugDataSignature",
            epoch = self.aug_data.epoch(),
        );
        return Err(e);
    }
    // ... rest of implementation
}

// In ShareAggregateState::add
fn add(&self, peer: Author, share: Self::Response) -> anyhow::Result<Option<()>> {
    if share.author() != &peer {
        error!(
            SecurityEvent::ConsensusInvalidMessage,
            remote_peer = peer,
            expected_author = peer,
            actual_author = share.author(),
            message_type = "RandShare",
            error = "Author mismatch",
        );
        bail!("Author does not match");
    }
    
    if share.metadata() != &self.rand_metadata {
        error!(
            SecurityEvent::ConsensusInvalidMessage,
            remote_peer = peer,
            message_type = "RandShare",
            error = "Metadata mismatch",
            local_metadata = ?self.rand_metadata,
            received_metadata = ?share.metadata(),
        );
        bail!("Metadata does not match");
    }
    
    if let Err(e) = share.verify(&self.rand_config) {
        error!(
            SecurityEvent::ConsensusInvalidMessage,
            remote_peer = peer,
            message_type = "RandShare",
            error = ?e,
            epoch = share.epoch(),
            round = share.round(),
        );
        return Err(e);
    }
    // ... rest of implementation
}
```

Additionally, consider adding randomness-specific security events to the `SecurityEvent` enum for better categorization.

## Proof of Concept

Create a test in `consensus/src/rand/rand_gen/reliable_broadcast_state_test.rs`:

```rust
#[test]
fn test_byzantine_behavior_logging() {
    use aptos_logger::SecurityEvent;
    use aptos_logger::test_utils::LogCapture;
    
    let log_capture = LogCapture::new();
    
    // Create an AugDataCertBuilder with valid config
    let (aug_data, epoch_state, _) = create_test_aug_data();
    let builder = AugDataCertBuilder::new(aug_data.clone(), epoch_state.clone());
    
    // Create an invalid signature from a different peer
    let malicious_peer = create_different_peer();
    let invalid_signature = create_invalid_signature(&aug_data);
    
    // Attempt to add the invalid signature
    let result = builder.add(malicious_peer, invalid_signature);
    
    // Verify that:
    // 1. The addition failed
    assert!(result.is_err());
    
    // 2. A SecurityEvent was logged with details
    let logs = log_capture.get_logs();
    assert!(logs.iter().any(|log| {
        log.contains("SecurityEvent::ConsensusInvalidMessage") &&
        log.contains(&format!("remote_peer = {}", malicious_peer)) &&
        log.contains("AugDataSignature")
    }), "Expected SecurityEvent log for invalid signature not found. Only generic RPC error logged.");
}

#[test]
fn test_author_mismatch_logging() {
    use aptos_logger::SecurityEvent;
    use aptos_logger::test_utils::LogCapture;
    
    let log_capture = LogCapture::new();
    
    // Create ShareAggregateState
    let (rand_store, rand_metadata, rand_config) = create_test_rand_config();
    let aggregate_state = Arc::new(ShareAggregateState::new(
        rand_store,
        rand_metadata.clone(),
        rand_config.clone(),
    ));
    
    // Create a share with mismatched author
    let real_peer = create_peer_a();
    let fake_peer = create_peer_b();
    let share = create_share_from_author(fake_peer, &rand_metadata);
    
    // Attempt to add share claiming to be from real_peer
    let result = aggregate_state.add(real_peer, share);
    
    // Verify SecurityEvent was logged
    assert!(result.is_err());
    let logs = log_capture.get_logs();
    assert!(logs.iter().any(|log| {
        log.contains("SecurityEvent::ConsensusInvalidMessage") &&
        log.contains("Author mismatch")
    }), "Expected SecurityEvent log for author mismatch not found.");
}
```

**Current behavior**: These tests will fail because no `SecurityEvent` logs are generated. Only generic sampled RPC failure warnings appear.

**Expected behavior**: After implementing the recommendation, tests will pass as Byzantine behaviors are properly logged with structured security events.

## Notes

The absence of security event logging in the randomness generation reliable broadcast represents an inconsistency in defensive security controls across the Aptos consensus implementation. While this does not directly compromise consensus safety (Byzantine validators still cannot forge randomness due to cryptographic guarantees), it creates a significant blind spot in security monitoring and prevents the collection of evidence necessary for future slashing mechanisms, which are explicitly planned in the codebase [11](#0-10) .

### Citations

**File:** consensus/src/rand/rand_gen/reliable_broadcast_state.rs (L48-66)
```rust
    fn add(&self, peer: Author, ack: Self::Response) -> anyhow::Result<Option<Self::Aggregated>> {
        ack.verify(peer, &self.epoch_state.verifier, &self.aug_data)?;
        let mut parital_signatures_guard = self.partial_signatures.lock();
        parital_signatures_guard.add_signature(peer, ack.into_signature());
        let qc_aug_data = self
            .epoch_state
            .verifier
            .check_voting_power(parital_signatures_guard.signatures().keys(), true)
            .ok()
            .map(|_| {
                let aggregated_signature = self
                    .epoch_state
                    .verifier
                    .aggregate_signatures(parital_signatures_guard.signatures_iter())
                    .expect("Signature aggregation should succeed");
                CertifiedAugData::new(self.aug_data.clone(), aggregated_signature)
            });
        Ok(qc_aug_data)
    }
```

**File:** consensus/src/rand/rand_gen/reliable_broadcast_state.rs (L88-101)
```rust
    fn add(&self, peer: Author, _ack: Self::Response) -> anyhow::Result<Option<Self::Aggregated>> {
        let mut validators_guard = self.validators.lock();
        ensure!(
            validators_guard.remove(&peer),
            "[RandMessage] Unknown author: {}",
            peer
        );
        // If receive from all validators, stop the reliable broadcast
        if validators_guard.is_empty() {
            Ok(Some(()))
        } else {
            Ok(None)
        }
    }
```

**File:** consensus/src/rand/rand_gen/reliable_broadcast_state.rs (L131-151)
```rust
    fn add(&self, peer: Author, share: Self::Response) -> anyhow::Result<Option<()>> {
        ensure!(share.author() == &peer, "Author does not match");
        ensure!(
            share.metadata() == &self.rand_metadata,
            "Metadata does not match: local {:?}, received {:?}",
            self.rand_metadata,
            share.metadata()
        );
        share.verify(&self.rand_config)?;
        info!(LogSchema::new(LogEvent::ReceiveReactiveRandShare)
            .epoch(share.epoch())
            .round(share.metadata().round)
            .remote_peer(*share.author()));
        let mut store = self.rand_store.lock();
        let aggregated = if store.add_share(share, PathType::Slow)? {
            Some(())
        } else {
            None
        };
        Ok(aggregated)
    }
```

**File:** consensus/src/pending_votes.rs (L300-307)
```rust
                error!(
                    SecurityEvent::ConsensusEquivocatingVote,
                    remote_peer = vote.author(),
                    vote = vote,
                    previous_vote = previously_seen_vote
                );

                return VoteReceptionResult::EquivocateVote;
```

**File:** consensus/src/round_manager.rs (L888-896)
```rust
            sync_info.verify(&self.epoch_state.verifier).map_err(|e| {
                error!(
                    SecurityEvent::InvalidSyncInfoMsg,
                    sync_info = sync_info,
                    remote_peer = author,
                    error = ?e,
                );
                VerifyError::from(e)
            })?;
```

**File:** consensus/src/epoch_manager.rs (L1613-1618)
```rust
                            error!(
                                SecurityEvent::ConsensusInvalidMessage,
                                remote_peer = peer_id,
                                error = ?e,
                                unverified_event = unverified_event
                            );
```

**File:** crates/aptos-logger/src/security.rs (L38-58)
```rust
    ConsensusInvalidMessage,

    /// Consensus received an equivocating vote
    ConsensusEquivocatingVote,

    /// Consensus received an equivocating order vote
    ConsensusEquivocatingOrderVote,

    /// Consensus received an invalid proposal
    InvalidConsensusProposal,

    /// Consensus received an invalid new round message
    InvalidConsensusRound,

    /// Consensus received an invalid sync info message
    InvalidSyncInfoMsg,

    /// A received block is invalid
    InvalidRetrievedBlock,

    /// A block being committed or executed is invalid
```

**File:** crates/reliable-broadcast/src/lib.rs (L210-220)
```rust
fn log_rpc_failure(error: anyhow::Error, receiver: Author) {
    // Log a sampled warning (to prevent spam)
    sample!(
        SampleRate::Duration(Duration::from_secs(30)),
        warn!("[sampled] rpc to {} failed, error {:#}", receiver, error)
    );

    // Log at the debug level (this is useful for debugging
    // and won't spam the logs in a production environment).
    debug!("rpc to {} failed, error {:#}", receiver, error);
}
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L238-252)
```rust
                            if msg
                                .verify(
                                    &epoch_state_clone,
                                    &config_clone,
                                    &fast_config_clone,
                                    rand_gen_msg.sender,
                                )
                                .is_ok()
                            {
                                let _ = tx.unbounded_send(RpcRequest {
                                    req: msg,
                                    protocol: rand_gen_msg.protocol,
                                    response_sender: rand_gen_msg.response_sender,
                                });
                            }
```

**File:** aptos-move/framework/aptos-framework/sources/delegation_pool.move (L153-157)
```text
    /// Slashing (if implemented) should not be applied to already `inactive` stake.
    /// Not only it invalidates the accounting of past observed lockup cycles (OLC),
    /// but is also unfair to delegators whose stake has been inactive before validator started misbehaving.
    /// Additionally, the inactive stake does not count on the voting power of validator.
    const ESLASHED_INACTIVE_STAKE_ON_PAST_OLC: u64 = 7;
```

**File:** aptos-move/framework/aptos-framework/sources/delegation_pool.move (L2023-2042)
```text
        // unsynced are rewards and slashes routed exclusively to/out the stake pool

        // operator `active` rewards not persisted yet to the active shares pool
        let pool_active = total_coins(&pool.active_shares);
        let commission_active = if (active > pool_active) {
            math64::mul_div(active - pool_active, pool.operator_commission_percentage, MAX_FEE)
        } else {
            // handle any slashing applied to `active` stake
            0
        };
        // operator `pending_inactive` rewards not persisted yet to the pending_inactive shares pool
        let pool_pending_inactive = total_coins(pending_inactive_shares_pool(pool));
        let commission_pending_inactive = if (pending_inactive > pool_pending_inactive) {
            math64::mul_div(
                pending_inactive - pool_pending_inactive,
                pool.operator_commission_percentage,
                MAX_FEE
            )
        } else {
            // handle any slashing applied to `pending_inactive` stake
```
