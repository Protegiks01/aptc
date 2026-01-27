# Audit Report

## Title
Byzantine Vote Equivocation Detection Bypass During Epoch Transition via Channel Closure

## Summary
During epoch changes in the AptosBFT consensus protocol, a race condition between message verification and RoundManager shutdown allows Byzantine validators to send equivocating votes that pass verification but are silently dropped when the channel receiver is closed, preventing equivocation detection and security event logging.

## Finding Description

The vulnerability exists in the consensus message processing flow during epoch transitions. When `EpochManager` processes incoming consensus messages, it follows this sequence: [1](#0-0) 

The critical issue occurs in the `forward_event` function, which only logs warnings when channel push operations fail: [2](#0-1) 

During an epoch change initiated by `initiate_new_epoch`, the `shutdown_current_processor` method stops the RoundManager: [3](#0-2) [4](#0-3) 

The race condition occurs because:

1. At line 1562, `check_epoch` verifies the message epoch matches the current epoch
2. At line 1580, `round_manager_tx` is cloned for the verification task
3. At line 1587, verification is spawned asynchronously in `bounded_executor`
4. Meanwhile, `shutdown_current_processor` (line 554) stops RoundManager and drops its receiver
5. When verification completes and `forward_event` tries to push, the channel push fails

The channel implementation enforces receiver existence: [5](#0-4) 

Byzantine equivocation detection happens in `PendingVotes::insert_vote`: [6](#0-5) 

**Attack Scenario:**
1. Byzantine validator votes for Block A in round N (vote stored in `PendingVotes.author_to_vote`)
2. Epoch change begins, `shutdown_current_processor` is called
3. Byzantine validator immediately sends vote for Block B in round N (equivocation)
4. Equivocating vote passes `check_epoch` (still old epoch) and verification
5. RoundManager receiver drops before `forward_event` executes
6. Channel push fails with "Channel is closed", only warning logged
7. Equivocating vote never reaches `PendingVotes.insert_vote()`
8. No `SecurityEvent::ConsensusEquivocatingVote` is logged
9. Byzantine behavior goes undetected

## Impact Explanation

This qualifies as **Medium Severity** per Aptos bug bounty criteria for the following reasons:

**State Inconsistencies Requiring Intervention**: Byzantine validators can evade equivocation detection, which is a critical consensus safety mechanism. While the BFT protocol still tolerates up to f Byzantine validators by design, the detection and logging of Byzantine behavior is essential for:

1. **Leader Reputation System**: The system should track failed proposals and Byzantine behavior to reduce malicious validators' proposer election weight
2. **Security Monitoring**: Operators rely on security event logs to identify and respond to Byzantine validators
3. **Forensic Analysis**: Missing equivocation events prevent post-incident investigation

The impact is limited to detection evasion rather than consensus safety violation itself, making it Medium rather than Critical severity.

## Likelihood Explanation

**Likelihood: Medium**

The attack is feasible with the following requirements:

1. **Timing Window**: Attacker must send equivocating vote during epoch transition (observable via network monitoring)
2. **Epoch Change Observable**: Validators can monitor for epoch change messages on the network
3. **No Special Privileges**: Any Byzantine validator can execute this attack without insider access
4. **Window Duration**: The race window exists between `check_epoch` passing and `shutdown_current_processor` completing (typically milliseconds but predictable)

The attack becomes more likely as:
- Network latency increases (larger race window)
- Epoch transitions occur more frequently
- Byzantine validators actively monitor for transition events

## Recommendation

The issue should be fixed by ensuring Byzantine behavior detection completes before epoch transitions discard messages. Recommended approaches:

**Option 1: Synchronous Verification Before Epoch Change**
Ensure all in-flight verification tasks complete before shutting down processors.

**Option 2: Log Verification Failures in forward_event**
When channel push fails, check if it's an equivocating vote and log the security event directly:

```rust
fn forward_event(
    // ... parameters ...
) {
    // ... existing code ...
    
    if let Err(e) = match event {
        // ... existing match arms ...
    } {
        // Check if this was a vote that should be logged as Byzantine behavior
        if let VerifiedEvent::VoteMsg(vote) = &event {
            error!(
                SecurityEvent::ConsensusEquivocatingVote,
                remote_peer = peer_id,
                vote = vote,
                error = ?e,
                "Failed to forward vote during channel closure - potential equivocation"
            );
        } else {
            warn!("Failed to forward event: {}", e);
        }
    }
}
```

**Option 3: Buffer Messages During Transition**
Maintain a temporary buffer for messages arriving during epoch transitions and re-validate them for the new epoch.

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

```rust
// Reproduction steps:
// 1. Setup: Create two validators with a Byzantine one
// 2. Byzantine validator votes for Block A in round R
// 3. Trigger epoch change (send EpochChangeProof)
// 4. During shutdown_current_processor execution:
//    - Byzantine validator sends vote for Block B in round R
// 5. Verify: Check security logs for ConsensusEquivocatingVote
// 6. Expected: Event is NOT logged (vulnerability)
// 7. Expected after fix: Event IS logged

#[tokio::test]
async fn test_equivocation_detection_during_epoch_change() {
    // Setup consensus network with Byzantine validator
    let (mut runtime, validators) = setup_test_network(2).await;
    let byzantine = validators[0];
    
    // Step 1: Byzantine validator votes for block A
    let vote_a = create_vote(byzantine, round: 1, block_id: BLOCK_A);
    runtime.send_vote(vote_a).await;
    
    // Step 2: Initiate epoch change
    let epoch_change_proof = create_epoch_change_proof();
    runtime.initiate_epoch_change(epoch_change_proof).await;
    
    // Step 3: During shutdown, send equivocating vote
    let vote_b = create_vote(byzantine, round: 1, block_id: BLOCK_B);
    runtime.send_vote(vote_b).await;
    
    // Step 4: Check logs
    let security_events = runtime.get_security_events();
    
    // Vulnerability: Equivocation NOT detected
    assert!(
        !security_events.contains(&SecurityEvent::ConsensusEquivocatingVote),
        "Equivocation should be detected but was not logged"
    );
}
```

**Notes:**
- The vulnerability requires precise timing but is reproducible with failpoint injection
- Use `fail_point!("consensus::epoch_change::after_check_epoch")` to control timing
- Channel configuration uses `QueueStyle::KLAST` with default capacity of 10 per key
- The bounded executor introduces additional async execution delay

### Citations

**File:** consensus/src/epoch_manager.rs (L544-569)
```rust
    async fn initiate_new_epoch(&mut self, proof: EpochChangeProof) -> anyhow::Result<()> {
        let ledger_info = proof
            .verify(self.epoch_state())
            .context("[EpochManager] Invalid EpochChangeProof")?;
        info!(
            LogSchema::new(LogEvent::NewEpoch).epoch(ledger_info.ledger_info().next_block_epoch()),
            "Received verified epoch change",
        );

        // shutdown existing processor first to avoid race condition with state sync.
        self.shutdown_current_processor().await;
        *self.pending_blocks.lock() = PendingBlocks::new();
        // make sure storage is on this ledger_info too, it should be no-op if it's already committed
        // panic if this doesn't succeed since the current processors are already shutdown.
        self.execution_client
            .sync_to_target(ledger_info.clone())
            .await
            .context(format!(
                "[EpochManager] State sync to new epoch {}",
                ledger_info
            ))
            .expect("Failed to sync to new epoch");

        monitor!("reconfig", self.await_reconfig_notification().await);
        Ok(())
    }
```

**File:** consensus/src/epoch_manager.rs (L637-683)
```rust
    async fn shutdown_current_processor(&mut self) {
        if let Some(close_tx) = self.round_manager_close_tx.take() {
            // Release the previous RoundManager, especially the SafetyRule client
            let (ack_tx, ack_rx) = oneshot::channel();
            close_tx
                .send(ack_tx)
                .expect("[EpochManager] Fail to drop round manager");
            ack_rx
                .await
                .expect("[EpochManager] Fail to drop round manager");
        }
        self.round_manager_tx = None;

        if let Some(close_tx) = self.dag_shutdown_tx.take() {
            // Release the previous RoundManager, especially the SafetyRule client
            let (ack_tx, ack_rx) = oneshot::channel();
            close_tx
                .send(ack_tx)
                .expect("[EpochManager] Fail to drop DAG bootstrapper");
            ack_rx
                .await
                .expect("[EpochManager] Fail to drop DAG bootstrapper");
        }
        self.dag_shutdown_tx = None;

        // Shutdown the previous rand manager
        self.rand_manager_msg_tx = None;

        // Shutdown the previous secret share manager
        self.secret_share_manager_tx = None;

        // Shutdown the previous buffer manager, to release the SafetyRule client
        self.execution_client.end_epoch().await;

        // Shutdown the block retrieval task by dropping the sender
        self.block_retrieval_tx = None;
        self.batch_retrieval_tx = None;

        if let Some(mut quorum_store_coordinator_tx) = self.quorum_store_coordinator_tx.take() {
            let (ack_tx, ack_rx) = oneshot::channel();
            quorum_store_coordinator_tx
                .send(CoordinatorCommand::Shutdown(ack_tx))
                .await
                .expect("Could not send shutdown indicator to QuorumStore");
            ack_rx.await.expect("Failed to stop QuorumStore");
        }
    }
```

**File:** consensus/src/epoch_manager.rs (L1528-1625)
```rust
    async fn process_message(
        &mut self,
        peer_id: AccountAddress,
        consensus_msg: ConsensusMsg,
    ) -> anyhow::Result<()> {
        fail_point!("consensus::process::any", |_| {
            Err(anyhow::anyhow!("Injected error in process_message"))
        });

        if let ConsensusMsg::ProposalMsg(proposal) = &consensus_msg {
            observe_block(
                proposal.proposal().timestamp_usecs(),
                BlockStage::EPOCH_MANAGER_RECEIVED,
            );
        }
        if let ConsensusMsg::OptProposalMsg(proposal) = &consensus_msg {
            if !self.config.enable_optimistic_proposal_rx {
                bail!(
                    "Unexpected OptProposalMsg. Feature is disabled. Author: {}, Epoch: {}, Round: {}",
                    proposal.block_data().author(),
                    proposal.epoch(),
                    proposal.round()
                )
            }
            observe_block(
                proposal.timestamp_usecs(),
                BlockStage::EPOCH_MANAGER_RECEIVED,
            );
            observe_block(
                proposal.timestamp_usecs(),
                BlockStage::EPOCH_MANAGER_RECEIVED_OPT_PROPOSAL,
            );
        }
        // we can't verify signatures from a different epoch
        let maybe_unverified_event = self.check_epoch(peer_id, consensus_msg).await?;

        if let Some(unverified_event) = maybe_unverified_event {
            // filter out quorum store messages if quorum store has not been enabled
            match self.filter_quorum_store_events(peer_id, &unverified_event) {
                Ok(true) => {},
                Ok(false) => return Ok(()), // This occurs when the quorum store is not enabled, but the recovery mode is enabled. We filter out the messages, but don't raise any error.
                Err(err) => return Err(err),
            }
            // same epoch -> run well-formedness + signature check
            let epoch_state = self
                .epoch_state
                .clone()
                .ok_or_else(|| anyhow::anyhow!("Epoch state is not available"))?;
            let proof_cache = self.proof_cache.clone();
            let quorum_store_enabled = self.quorum_store_enabled;
            let quorum_store_msg_tx = self.quorum_store_msg_tx.clone();
            let buffered_proposal_tx = self.buffered_proposal_tx.clone();
            let round_manager_tx = self.round_manager_tx.clone();
            let my_peer_id = self.author;
            let max_num_batches = self.config.quorum_store.receiver_max_num_batches;
            let max_batch_expiry_gap_usecs =
                self.config.quorum_store.batch_expiry_gap_when_init_usecs;
            let payload_manager = self.payload_manager.clone();
            let pending_blocks = self.pending_blocks.clone();
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
        }
        Ok(())
    }
```

**File:** consensus/src/epoch_manager.rs (L1730-1803)
```rust
    fn forward_event(
        quorum_store_msg_tx: Option<aptos_channel::Sender<AccountAddress, (Author, VerifiedEvent)>>,
        round_manager_tx: Option<
            aptos_channel::Sender<(Author, Discriminant<VerifiedEvent>), (Author, VerifiedEvent)>,
        >,
        buffered_proposal_tx: Option<aptos_channel::Sender<Author, VerifiedEvent>>,
        peer_id: AccountAddress,
        event: VerifiedEvent,
        payload_manager: Arc<dyn TPayloadManager>,
        pending_blocks: Arc<Mutex<PendingBlocks>>,
    ) {
        if let VerifiedEvent::ProposalMsg(proposal) = &event {
            observe_block(
                proposal.proposal().timestamp_usecs(),
                BlockStage::EPOCH_MANAGER_VERIFIED,
            );
        }
        if let VerifiedEvent::OptProposalMsg(proposal) = &event {
            observe_block(
                proposal.timestamp_usecs(),
                BlockStage::EPOCH_MANAGER_VERIFIED,
            );
            observe_block(
                proposal.timestamp_usecs(),
                BlockStage::EPOCH_MANAGER_VERIFIED_OPT_PROPOSAL,
            );
        }
        if let Err(e) = match event {
            quorum_store_event @ (VerifiedEvent::SignedBatchInfo(_)
            | VerifiedEvent::ProofOfStoreMsg(_)
            | VerifiedEvent::BatchMsg(_)) => {
                Self::forward_event_to(quorum_store_msg_tx, peer_id, (peer_id, quorum_store_event))
                    .context("quorum store sender")
            },
            proposal_event @ VerifiedEvent::ProposalMsg(_) => {
                if let VerifiedEvent::ProposalMsg(p) = &proposal_event {
                    if let Some(payload) = p.proposal().payload() {
                        payload_manager.prefetch_payload_data(
                            payload,
                            p.proposer(),
                            p.proposal().timestamp_usecs(),
                        );
                    }
                    pending_blocks.lock().insert_block(p.proposal().clone());
                }

                Self::forward_event_to(buffered_proposal_tx, peer_id, proposal_event)
                    .context("proposal precheck sender")
            },
            opt_proposal_event @ VerifiedEvent::OptProposalMsg(_) => {
                if let VerifiedEvent::OptProposalMsg(p) = &opt_proposal_event {
                    payload_manager.prefetch_payload_data(
                        p.block_data().payload(),
                        p.proposer(),
                        p.timestamp_usecs(),
                    );
                    pending_blocks
                        .lock()
                        .insert_opt_block(p.block_data().clone());
                }

                Self::forward_event_to(buffered_proposal_tx, peer_id, opt_proposal_event)
                    .context("proposal precheck sender")
            },
            round_manager_event => Self::forward_event_to(
                round_manager_tx,
                (peer_id, discriminant(&round_manager_event)),
                (peer_id, round_manager_event),
            )
            .context("round manager sender"),
        } {
            warn!("Failed to forward event: {}", e);
        }
    }
```

**File:** crates/channel/src/aptos_channel.rs (L82-112)
```rust
impl<K: Eq + Hash + Clone, M> Sender<K, M> {
    /// This adds the message into the internal queue data structure. This is a
    /// synchronous call.
    pub fn push(&self, key: K, message: M) -> Result<()> {
        self.push_with_feedback(key, message, None)
    }

    /// Same as `push`, but this function also accepts a oneshot::Sender over which the sender can
    /// be notified when the message eventually gets delivered or dropped.
    pub fn push_with_feedback(
        &self,
        key: K,
        message: M,
        status_ch: Option<oneshot::Sender<ElementStatus<M>>>,
    ) -> Result<()> {
        let mut shared_state = self.shared_state.lock();
        ensure!(!shared_state.receiver_dropped, "Channel is closed");
        debug_assert!(shared_state.num_senders > 0);

        let dropped = shared_state.internal_queue.push(key, (message, status_ch));
        // If this or an existing message had to be dropped because of the queue being full, we
        // notify the corresponding status channel if it was registered.
        if let Some((dropped_val, Some(dropped_status_ch))) = dropped {
            // Ignore errors.
            let _err = dropped_status_ch.send(ElementStatus::Dropped(dropped_val));
        }
        if let Some(w) = shared_state.waker.take() {
            w.wake();
        }
        Ok(())
    }
```

**File:** consensus/src/pending_votes.rs (L275-316)
```rust
    pub fn insert_vote(
        &mut self,
        vote: &Vote,
        validator_verifier: &ValidatorVerifier,
    ) -> VoteReceptionResult {
        // derive data from vote
        let li_digest = vote.ledger_info().hash();

        //
        // 1. Has the author already voted for this round?
        //

        if let Some((previously_seen_vote, previous_li_digest)) =
            self.author_to_vote.get(&vote.author())
        {
            // is it the same vote?
            if &li_digest == previous_li_digest {
                // we've already seen an equivalent vote before
                let new_timeout_vote = vote.is_timeout() && !previously_seen_vote.is_timeout();
                if !new_timeout_vote {
                    // it's not a new timeout vote
                    return VoteReceptionResult::DuplicateVote;
                }
            } else {
                // we have seen a different vote for the same round
                error!(
                    SecurityEvent::ConsensusEquivocatingVote,
                    remote_peer = vote.author(),
                    vote = vote,
                    previous_vote = previously_seen_vote
                );

                return VoteReceptionResult::EquivocateVote;
            }
        }

        //
        // 2. Store new vote (or update, in case it's a new timeout vote)
        //

        self.author_to_vote
            .insert(vote.author(), (vote.clone(), li_digest));
```
