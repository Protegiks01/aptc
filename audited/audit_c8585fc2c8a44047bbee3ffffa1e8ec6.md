# Audit Report

## Title
Self-Message Verification Bypass Enables Byzantine Validator State Divergence

## Summary
When `peer_id == my_peer_id` in the consensus message processing flow, all cryptographic and structural verification is skipped, allowing a Byzantine validator to process its own invalid messages. This creates state divergence where the Byzantine validator accepts malformed blocks while honest validators reject them, potentially violating consensus safety invariants.

## Finding Description

The vulnerability exists in the message verification path when validators process their own broadcast messages. When a validator broadcasts a consensus message (proposal, vote, timeout), it also sends the message to itself via the `self_sender` channel for local processing. [1](#0-0) 

At line 1596, the code sets `peer_id == my_peer_id` which becomes the `self_message` parameter passed to verification: [2](#0-1) 

This flag completely bypasses all verification in `UnverifiedEvent::verify()`: [3](#0-2) 

When `self_message` is true, the following critical checks are skipped:
1. **Cryptographic signature validation** (lines 122, 131, 140, 149, 158, 168, 186, 200, 214, 223)
2. **Author-sender matching** - normally enforced in `ProposalMsg::verify()`: [4](#0-3) 

3. **Well-formedness checks** - including round consistency, parent block references, and timeout certificate validation
4. **Payload verification** - transaction batch and proof-of-store validation

**Attack Scenario:**

1. Byzantine validator B is the legitimate proposer for round R
2. B creates a proposal with **invalid signature** or **tampered block data** but correct author=B
3. B broadcasts the proposal to all validators including itself

**Honest validators:** Receive proposal → Verify signature → **FAIL** → Reject proposal → Do NOT add to block store

**Byzantine validator (self-message path):** Receive proposal → Skip ALL verification → Add to block store → Process proposal → Create and **broadcast vote**

4. The Byzantine validator now votes for a block that honest validators have rejected
5. The vote itself is properly signed, so honest validators accept the vote but have never seen/validated the underlying block
6. This creates state divergence: Byzantine validator believes block exists and is valid; honest validators have rejected it [5](#0-4) 

The Byzantine validator's vote propagates to honest validators who aggregate votes without checking if the corresponding block exists locally (vote aggregation in `pending_votes.rs` doesn't validate block existence): [6](#0-5) 

## Impact Explanation

This vulnerability violates the **Consensus Safety** invariant: "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine validators."

**Critical Severity** justification:
- **Consensus Safety Violation**: Enables Byzantine validators to vote for invalid blocks that honest validators have rejected, creating potential for chain splits
- **State Divergence**: Byzantine validator maintains different state than honest validators, violating deterministic execution invariant
- **Vote Aggregation Corruption**: Votes for non-existent or invalid blocks can be aggregated, potentially forming invalid QCs if multiple Byzantine validators collude
- **Liveness Degradation**: Honest validators may waste resources requesting and re-validating blocks they've already rejected

While a single Byzantine validator cannot force invalid blocks to be committed (requires 2f+1 votes), the state divergence enables second-order attacks and violates fundamental consensus invariants.

## Likelihood Explanation

**High likelihood** for the following reasons:
- The vulnerability is in a core consensus code path executed for every broadcast message
- Any Byzantine validator can exploit this without complex setup
- The verification bypass is unconditional when `peer_id == my_peer_id`
- No runtime detection of the state divergence between Byzantine and honest validators
- Could be triggered accidentally by software bugs in message creation, not just malicious intent

## Recommendation

Remove the self-message verification bypass. Validators should verify their own messages using the same cryptographic checks as external messages. While this adds computational overhead, it:
1. Ensures all messages in the system are cryptographically valid
2. Catches bugs in message creation before propagation
3. Maintains state consistency across all validators
4. Prevents Byzantine validators from processing invalid self-messages

**Code Fix:**

```rust
// In consensus/src/round_manager.rs, UnverifiedEvent::verify()
// Remove the self_message bypass and always verify:

pub fn verify(
    self,
    peer_id: PeerId,
    validator: &ValidatorVerifier,
    proof_cache: &ProofCache,
    quorum_store_enabled: bool,
    self_message: bool,  // Keep parameter for metrics/logging only
    max_num_batches: usize,
    max_batch_expiry_gap_usecs: u64,
) -> Result<VerifiedEvent, VerifyError> {
    let start_time = Instant::now();
    Ok(match self {
        UnverifiedEvent::ProposalMsg(p) => {
            // ALWAYS verify, even for self messages
            p.verify(peer_id, validator, proof_cache, quorum_store_enabled)?;
            counters::VERIFY_MSG
                .with_label_values(&["proposal", if self_message { "self" } else { "peer" }])
                .observe(start_time.elapsed().as_secs_f64());
            VerifiedEvent::ProposalMsg(p)
        },
        // Apply same fix to all other message types...
    })
}
```

## Proof of Concept

```rust
// Consensus test demonstrating the vulnerability
#[tokio::test]
async fn test_self_message_verification_bypass() {
    // Setup: Create epoch manager with validator
    let (mut epoch_manager, network_receivers, _) = create_test_epoch_manager();
    let byzantine_peer_id = epoch_manager.author;
    
    // Step 1: Byzantine validator creates proposal with INVALID signature
    let mut invalid_proposal = create_test_proposal(byzantine_peer_id);
    // Tamper with block data after signing (simulates invalid signature)
    invalid_proposal.proposal.block_data_mut().set_round(999);
    
    // Step 2: Broadcast to self via self_sender (simulating broadcast)
    let msg = ConsensusMsg::ProposalMsg(Box::new(invalid_proposal.clone()));
    epoch_manager.self_sender.send(Event::Message(byzantine_peer_id, msg.clone())).await.unwrap();
    
    // Step 3: Process the self-message
    // Should FAIL verification but currently BYPASSES due to peer_id == my_peer_id
    epoch_manager.process_message(byzantine_peer_id, msg).await.unwrap();
    
    // Step 4: Verify Byzantine validator accepted invalid proposal
    // (In production, this would lead to voting on invalid block)
    let block_store = epoch_manager.block_store.unwrap();
    assert!(block_store.block_exists(invalid_proposal.proposal().id()));
    
    // Step 5: Same proposal sent to honest validator fails verification
    let honest_peer_id = get_different_validator();
    let result = epoch_manager.process_message(honest_peer_id, msg).await;
    assert!(result.is_err()); // Signature verification fails
    
    // Result: STATE DIVERGENCE
    // Byzantine validator: Block exists and is valid
    // Honest validators: Block rejected due to invalid signature
}
```

**Notes:**
- The vulnerability bypasses all cryptographic integrity checks for self-messages
- Byzantine validators can exploit this to maintain divergent state from honest validators  
- While a single Byzantine validator cannot compromise consensus alone, this violates safety invariants and enables more sophisticated attacks with multiple Byzantine validators
- The performance optimization of skipping verification for self-messages is fundamentally unsafe in a Byzantine fault-tolerant system

### Citations

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

**File:** consensus/src/round_manager.rs (L108-231)
```rust
    pub fn verify(
        self,
        peer_id: PeerId,
        validator: &ValidatorVerifier,
        proof_cache: &ProofCache,
        quorum_store_enabled: bool,
        self_message: bool,
        max_num_batches: usize,
        max_batch_expiry_gap_usecs: u64,
    ) -> Result<VerifiedEvent, VerifyError> {
        let start_time = Instant::now();
        Ok(match self {
            UnverifiedEvent::ProposalMsg(p) => {
                if !self_message {
                    p.verify(peer_id, validator, proof_cache, quorum_store_enabled)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["proposal"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::ProposalMsg(p)
            },
            UnverifiedEvent::OptProposalMsg(p) => {
                if !self_message {
                    p.verify(peer_id, validator, proof_cache, quorum_store_enabled)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["opt_proposal"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::OptProposalMsg(p)
            },
            UnverifiedEvent::VoteMsg(v) => {
                if !self_message {
                    v.verify(peer_id, validator)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["vote"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::VoteMsg(v)
            },
            UnverifiedEvent::RoundTimeoutMsg(v) => {
                if !self_message {
                    v.verify(validator)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["timeout"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::RoundTimeoutMsg(v)
            },
            UnverifiedEvent::OrderVoteMsg(v) => {
                if !self_message {
                    v.verify_order_vote(peer_id, validator)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["order_vote"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::OrderVoteMsg(v)
            },
            UnverifiedEvent::SyncInfo(s) => VerifiedEvent::UnverifiedSyncInfo(s),
            UnverifiedEvent::BatchMsg(b) => {
                if !self_message {
                    b.verify(peer_id, max_num_batches, validator)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["batch"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::BatchMsg(Box::new((*b).into()))
            },
            UnverifiedEvent::BatchMsgV2(b) => {
                if !self_message {
                    b.verify(peer_id, max_num_batches, validator)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["batch_v2"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::BatchMsg(b)
            },
            UnverifiedEvent::SignedBatchInfo(sd) => {
                if !self_message {
                    sd.verify(
                        peer_id,
                        max_num_batches,
                        max_batch_expiry_gap_usecs,
                        validator,
                    )?;
                    counters::VERIFY_MSG
                        .with_label_values(&["signed_batch"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::SignedBatchInfo(Box::new((*sd).into()))
            },
            UnverifiedEvent::SignedBatchInfoMsgV2(sd) => {
                if !self_message {
                    sd.verify(
                        peer_id,
                        max_num_batches,
                        max_batch_expiry_gap_usecs,
                        validator,
                    )?;
                    counters::VERIFY_MSG
                        .with_label_values(&["signed_batch_v2"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::SignedBatchInfo(sd)
            },
            UnverifiedEvent::ProofOfStoreMsg(p) => {
                if !self_message {
                    p.verify(max_num_batches, validator, proof_cache)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["proof_of_store"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::ProofOfStoreMsg(Box::new((*p).into()))
            },
            UnverifiedEvent::ProofOfStoreMsgV2(p) => {
                if !self_message {
                    p.verify(max_num_batches, validator, proof_cache)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["proof_of_store_v2"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::ProofOfStoreMsg(p)
            },
        })
    }
```

**File:** consensus/src/round_manager.rs (L1382-1425)
```rust
    pub async fn process_verified_proposal(&mut self, proposal: Block) -> anyhow::Result<()> {
        let proposal_round = proposal.round();
        let parent_qc = proposal.quorum_cert().clone();
        let sync_info = self.block_store.sync_info();

        if proposal_round <= sync_info.highest_round() {
            sample!(
                SampleRate::Duration(Duration::from_secs(1)),
                warn!(
                    sync_info = sync_info,
                    proposal = proposal,
                    "Ignoring proposal. SyncInfo round is higher than proposal round."
                )
            );
            return Ok(());
        }

        let vote = self.create_vote(proposal).await?;
        self.round_state.record_vote(vote.clone());
        let vote_msg = VoteMsg::new(vote.clone(), self.block_store.sync_info());

        self.broadcast_fast_shares(vote.ledger_info().commit_info())
            .await;

        if self.local_config.broadcast_vote {
            info!(self.new_log(LogEvent::Vote), "{}", vote);
            PROPOSAL_VOTE_BROADCASTED.inc();
            self.network.broadcast_vote(vote_msg).await;
        } else {
            let recipient = self
                .proposer_election
                .get_valid_proposer(proposal_round + 1);
            info!(
                self.new_log(LogEvent::Vote).remote_peer(recipient),
                "{}", vote
            );
            self.network.send_vote(vote_msg, vec![recipient]).await;
        }

        if let Err(e) = self.start_next_opt_round(vote, parent_qc) {
            debug!("Cannot start next opt round: {}", e);
        };
        Ok(())
    }
```

**File:** consensus/consensus-types/src/proposal_msg.rs (L82-118)
```rust
    pub fn verify(
        &self,
        sender: Author,
        validator: &ValidatorVerifier,
        proof_cache: &ProofCache,
        quorum_store_enabled: bool,
    ) -> Result<()> {
        if let Some(proposal_author) = self.proposal.author() {
            ensure!(
                proposal_author == sender,
                "Proposal author {:?} doesn't match sender {:?}",
                proposal_author,
                sender
            );
        }
        let (payload_result, sig_result) = rayon::join(
            || {
                self.proposal().payload().map_or(Ok(()), |p| {
                    p.verify(validator, proof_cache, quorum_store_enabled)
                })
            },
            || {
                self.proposal()
                    .validate_signature(validator)
                    .map_err(|e| format_err!("{:?}", e))
            },
        );
        payload_result?;
        sig_result?;

        // if there is a timeout certificate, verify its signatures
        if let Some(tc) = self.sync_info.highest_2chain_timeout_cert() {
            tc.verify(validator).map_err(|e| format_err!("{:?}", e))?;
        }
        // Note that we postpone the verification of SyncInfo until it's being used.
        self.verify_well_formed()
    }
```

**File:** consensus/src/pending_votes.rs (L275-350)
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

        //
        // 3. Let's check if we can create a QC
        //

        let len = self.li_digest_to_votes.len() + 1;
        // obtain the ledger info with signatures associated to the vote's ledger info
        let (hash_index, status) = self.li_digest_to_votes.entry(li_digest).or_insert_with(|| {
            (
                len,
                VoteStatus::NotEnoughVotes(SignatureAggregator::new(vote.ledger_info().clone())),
            )
        });

        let validator_voting_power = validator_verifier.get_voting_power(&vote.author());

        if validator_voting_power.is_none() {
            warn!("Received vote from an unknown author: {}", vote.author());
            return VoteReceptionResult::UnknownAuthor(vote.author());
        }
        let validator_voting_power =
            validator_voting_power.expect("Author must exist in the validator set.");
        if validator_voting_power == 0 {
            warn!("Received vote with no voting power, from {}", vote.author());
        }
        let cur_epoch = vote.vote_data().proposed().epoch() as i64;
        let cur_round = vote.vote_data().proposed().round() as i64;
        counters::CONSENSUS_CURRENT_ROUND_QUORUM_VOTING_POWER
            .set(validator_verifier.quorum_voting_power() as f64);

        if !vote.is_timeout() {
            counters::CONSENSUS_CURRENT_ROUND_VOTED_POWER
                .with_label_values(&[&vote.author().to_string(), &hash_index_to_str(*hash_index)])
                .set(validator_voting_power as f64);
```
