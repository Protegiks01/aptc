# Audit Report

## Title
Lack of Vote Gossiping Enables Undetectable Byzantine Vote Equivocation Across Validator Subsets

## Summary
Byzantine validators can send different `VoteMsg` messages to different subsets of validators without global detection, creating inconsistent views of vote aggregation across the network. The consensus layer lacks vote gossiping and implements only local equivocation detection, allowing Byzantine validators to present conflicting votes to different validator subsets undetected.

## Finding Description

The Aptos consensus protocol allows Byzantine validators to send different vote messages to different validator subsets due to three architectural properties:

**1. No Vote Gossiping Mechanism**

When validators receive votes, they process them locally without forwarding or gossiping to other validators. In `consensus/src/round_manager.rs`, vote processing is purely local: [1](#0-0) 

**2. Network Interface Permits Selective Message Delivery**

The network interface provides methods that allow sending different messages to different peers: [2](#0-1) 

A Byzantine validator can bypass the honest `broadcast_vote` flow and directly call `send_to` or `send_to_many` with different vote payloads to different validator subsets.

**3. Local-Only Equivocation Detection**

Vote equivocation detection occurs only at the local validator level in `PendingVotes::insert_vote()`: [3](#0-2) 

This check only triggers if a **single validator** receives two different votes from the same author. If different validators receive different votes from a Byzantine author, each validator independently accepts its received vote without detecting the global equivocation.

**Attack Scenario:**

1. Byzantine validator creates two different votes for round R:
   - `Vote_A` with `LedgerInfo` containing `executed_state_id = X`
   - `Vote_B` with `LedgerInfo` containing `executed_state_id = Y`
   
2. Byzantine validator signs both votes with its private key

3. Byzantine validator sends:
   - `Vote_A` to validators {V1, V2, ..., V10}
   - `Vote_B` to validators {V11, V12, ..., V20}

4. Each validator processes only the vote it receives:
   - Validators V1-V10 aggregate votes including `Vote_A`
   - Validators V11-V20 aggregate votes including `Vote_B`
   - No validator detects equivocation

**Why Standard Broadcast Doesn't Prevent This:**

Even in broadcast mode, the Byzantine validator can implement custom consensus logic that bypasses the standard vote creation flow: [4](#0-3) 

A malicious implementation can skip this standard flow and directly manipulate the network layer.

## Impact Explanation

This vulnerability falls into **Medium Severity** according to Aptos bug bounty criteria for the following reasons:

**State Inconsistencies:** Different validators maintain inconsistent records of what Byzantine validators voted for, creating divergent views of the consensus state.

**Liveness Risk:** While this alone doesn't break consensus safety (due to the 2f+1 threshold requiring honest validator votes), it can affect liveness:
- Different validator subsets may aggregate different vote sets
- Some validators might form QCs while others timeout
- Network progress can be delayed or disrupted

**Lack of Accountability:** The equivocation is not detectably provable to all validators. The security event is only logged locally: [5](#0-4) 

There is no mechanism to share equivocation proofs or slash equivocating validators across the network.

**Enabler for Complex Attacks:** When combined with other Byzantine behaviors (network partitioning, coordinated attacks with multiple Byzantine validators), this can facilitate more severe attacks.

**Not Critical Because:** A single Byzantine validator equivocating doesn't directly violate consensus safety, as the protocol requires 2f+1 votes for QC formation, and honest validators (numbering at least 2f+1) vote consistently.

## Likelihood Explanation

**High Likelihood** for the following reasons:

1. **Easy to Execute:** A Byzantine validator only needs to implement custom consensus logic that bypasses standard vote broadcasting
2. **No Detection:** The equivocation remains undetected globally, with only local logging
3. **No Penalties:** There's no slashing or accountability mechanism
4. **Within Threat Model:** The protocol assumes up to f Byzantine validators, making this attack realistic

## Recommendation

Implement **vote gossiping and global equivocation detection**:

1. **Add Vote Relay Mechanism:** When validators receive votes, relay them to other validators to ensure all validators eventually see all votes.

2. **Implement Equivocation Proof Sharing:** When equivocation is detected, create and broadcast an equivocation proof containing both conflicting votes signed by the same author.

3. **Add Global Equivocation Registry:** Maintain a per-epoch registry of detected equivocations that can be verified by all validators.

4. **Enable Slashing:** Implement on-chain penalties for proven equivocations to disincentivize Byzantine behavior.

**Code Fix Approach:**

In `consensus/src/round_manager.rs`, after processing a vote, relay it to other validators:

```rust
// After line 1769 in process_vote
async fn process_vote(&mut self, vote: &Vote) -> anyhow::Result<()> {
    // ... existing validation ...
    
    let vote_reception_result = self
        .round_state
        .insert_vote(vote, &self.epoch_state.verifier);
    
    // NEW: Relay vote to other validators if not equivocating
    if !matches!(vote_reception_result, VoteReceptionResult::EquivocateVote) {
        self.relay_vote_to_peers(vote).await;
    }
    
    self.process_vote_reception_result(vote, vote_reception_result)
        .await
}
```

In `consensus/src/pending_votes.rs`, when equivocation is detected, broadcast proof:

```rust
// After line 307 in insert_vote
if &li_digest != previous_li_digest {
    error!(
        SecurityEvent::ConsensusEquivocatingVote,
        remote_peer = vote.author(),
        vote = vote,
        previous_vote = previously_seen_vote
    );
    
    // NEW: Broadcast equivocation proof
    let equivocation_proof = EquivocationProof::new(
        vote.clone(),
        previously_seen_vote.clone()
    );
    self.broadcast_equivocation_proof(equivocation_proof);
    
    return VoteReceptionResult::EquivocateVote;
}
```

## Proof of Concept

Due to the nature of this vulnerability requiring Byzantine validator behavior and network-level manipulation, a complete PoC would require:

1. Implementing a malicious consensus module that bypasses standard vote broadcasting
2. Network simulation with multiple validator nodes
3. Custom vote creation and selective distribution logic

**Conceptual PoC Steps:**

```rust
// Pseudocode for Byzantine validator attack
async fn byzantine_vote_attack(
    proposal: &Block,
    network: &NetworkSender,
    validators: &[Author],
) {
    // Create two different votes with different execution results
    let vote_a = create_vote(proposal, execution_result_x);
    let vote_b = create_vote(proposal, execution_result_y);
    
    // Split validators into subsets
    let subset_a = &validators[0..validators.len()/2];
    let subset_b = &validators[validators.len()/2..];
    
    // Send different votes to different subsets
    for validator in subset_a {
        network.send_to(*validator, ConsensusMsg::VoteMsg(Box::new(vote_a.clone()))).await;
    }
    
    for validator in subset_b {
        network.send_to(*validator, ConsensusMsg::VoteMsg(Box::new(vote_b.clone()))).await;
    }
    
    // Each subset will accept their respective vote without detecting equivocation
}
```

**Observable Evidence:**
- Monitor logs on different validators for `SecurityEvent::ConsensusEquivocatingVote`
- Only validators receiving both votes would log the event
- Different validators would have different `author_to_vote` mappings for the Byzantine validator
- Potential timeout or liveness issues if vote aggregation differs across validator subsets

### Citations

**File:** consensus/src/round_manager.rs (L1406-1419)
```rust
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
```

**File:** consensus/src/round_manager.rs (L1767-1772)
```rust
        let vote_reception_result = self
            .round_state
            .insert_vote(vote, &self.epoch_state.verifier);
        self.process_vote_reception_result(vote, vote_reception_result)
            .await
    }
```

**File:** consensus/src/network_interface.rs (L176-189)
```rust
    /// Send a single message to the destination peer
    pub fn send_to(&self, peer: PeerId, message: ConsensusMsg) -> Result<(), Error> {
        let peer_network_id = self.get_peer_network_id_for_peer(peer);
        self.network_client.send_to_peer(message, peer_network_id)
    }

    /// Send a single message to the destination peers
    pub fn send_to_many(&self, peers: Vec<PeerId>, message: ConsensusMsg) -> Result<(), Error> {
        let peer_network_ids: Vec<PeerNetworkId> = peers
            .into_iter()
            .map(|peer| self.get_peer_network_id_for_peer(peer))
            .collect();
        self.network_client.send_to_peers(message, peer_network_ids)
    }
```

**File:** consensus/src/pending_votes.rs (L287-309)
```rust
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
```
