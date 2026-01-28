# Audit Report

## Title
Optimistic Proposal Equivocation Attack via Missing Signature Validation and Buffer Overwriting

## Summary
`OptProposalMsg` lacks cryptographic signature validation and uses a buffer with overwrite semantics, allowing a malicious proposer to send conflicting proposals to different validators, causing vote splitting and consensus liveness failures.

## Finding Description

**Validation Gap Between ProposalMsg and OptProposalMsg:**

For regular proposals, `ProposalMsg` requires BLS signature verification through `validate_signature()`: [1](#0-0) 

In contrast, `OptProposalMsg` only verifies that the network-authenticated sender matches the claimed author, without cryptographic signature verification: [2](#0-1) 

When converted to a Block, optimistic proposals explicitly have no signature: [3](#0-2) 

Signature validation for `OptimisticProposal` blocks only verifies QCs, not the proposer's signature, as explicitly noted in the code comment: [4](#0-3) 

**Buffer Overwriting Vulnerability:**

OptProposalMsg messages for future rounds are buffered in a `BTreeMap<Round, OptBlockData>` structure: [5](#0-4) 

The critical issue is that `BTreeMap::insert()` overwrites any existing entry for the same round: [6](#0-5) 

Before buffering, only `is_valid_proposer()` is called, which checks if the author is the designated proposer but does NOT detect equivocation: [7](#0-6) 

The `is_valid_proposer()` implementation simply checks author equality: [8](#0-7) 

The equivocation detection logic in `UnequivocalProposerElection::is_valid_proposal()` tracks previously seen proposals and detects different block IDs for the same round: [9](#0-8) 

However, this check is only called later during `process_proposal()`, after the buffer has already been overwritten: [10](#0-9) 

Each validator only processes one proposal (whichever is in their buffer), so equivocation is never detected because the check is LOCAL to each validator.

**Attack Scenario:**

1. Malicious validator M is elected proposer for round R
2. M crafts two different OptProposalMsg (A and B) with different payloads
3. M uses selective network sending (not broadcast) to send OptProposalMsg_A to validators V1, V2 and OptProposalMsg_B to validators V3, V4: [11](#0-10) 
4. Different validators end up with different proposals in their buffers
5. When validators advance to round R, they process different blocks from their buffers
6. Votes split between the conflicting proposals
7. Neither achieves 2f+1 quorum, causing round timeout and liveness failure

This is **not possible** with regular ProposalMsg because they are processed immediately or discarded as stale, not buffered: [12](#0-11) 

## Impact Explanation

This vulnerability enables a **consensus liveness attack** with **High Severity** impact:

- **Significant Protocol Violation**: Malicious proposer can prevent consensus progress during their elected rounds
- **Repeated Attacks**: Can be executed every time the malicious validator is elected proposer
- **No Collusion Required**: Single malicious proposer (< 1/3 Byzantine assumption)
- **Temporary Network Unavailability**: Consensus cannot make progress during affected rounds, but recovers after timeout

According to Aptos bug bounty criteria, "Validator node slowdowns" and "Significant protocol violations" qualify as **High Severity** ($50,000). This fits the High category because it causes temporary liveness disruption but the network recovers after the round timeout.

## Likelihood Explanation

**High Likelihood** - This attack is realistic and straightforward:

1. **Attacker Requirements**: Only need to be a validator who occasionally gets elected as proposer
2. **Technical Complexity**: Low - simply craft two different OptProposalMsg and use selective network sending instead of broadcast
3. **Detection Difficulty**: Hard to distinguish from benign network delays or message reordering; no cryptographic proof of equivocation exists
4. **Frequency**: Occurs whenever malicious proposer is elected (probabilistic based on validator count)
5. **No Cryptographic Proof**: Unlike ProposalMsg equivocation (which leaves signed evidence), OptProposalMsg equivocation leaves no cryptographic trace, only network-level evidence

## Recommendation

Implement one or more of the following mitigations:

1. **Add Cryptographic Signatures**: Require proposers to sign OptProposalMsg content, enabling validators to prove equivocation cryptographically

2. **Equivocation Detection Before Buffering**: Move the `is_valid_proposal()` check before buffering and track ALL received proposals per round (not just the last one), allowing detection of conflicting proposals

3. **Proposal Gossiping**: Implement a mechanism where validators gossip received OptProposalMsg to peers, enabling detection of conflicting proposals across the network

4. **Buffer Multiple Proposals**: Modify the buffer to store multiple proposals per round (e.g., `BTreeMap<Round, Vec<OptBlockData>>`) and add logic to detect conflicts before processing

## Proof of Concept

A detailed PoC would require setting up a multi-validator test environment and demonstrating selective message delivery. The attack flow is:

```rust
// Pseudocode demonstrating the attack

// Malicious proposer creates two different proposals for round R
let opt_proposal_A = create_opt_proposal(round_R, payload_A, ...);
let opt_proposal_B = create_opt_proposal(round_R, payload_B, ...);

// Send to different validator subsets instead of broadcast
network.send_to_many(vec![V1, V2], opt_proposal_A);
network.send_to_many(vec![V3, V4], opt_proposal_B);

// V1, V2 buffer proposal_A; V3, V4 buffer proposal_B
// When round R arrives, votes split between block_A and block_B
// Neither achieves 2f+1 quorum → round timeout
```

## Notes

This vulnerability exploits the design decision to make optimistic proposals unsigned for performance reasons. While this improves latency, it creates an equivocation vulnerability that is not present in regular (signed) proposals. The lack of cryptographic signatures means validators cannot prove to each other that equivocation occurred, making the attack difficult to detect and attribute.

### Citations

**File:** consensus/consensus-types/src/proposal_msg.rs (L104-106)
```rust
                self.proposal()
                    .validate_signature(validator)
                    .map_err(|e| format_err!("{:?}", e))
```

**File:** consensus/consensus-types/src/opt_proposal_msg.rs (L103-108)
```rust
        ensure!(
            self.proposer() == sender,
            "OptProposal author {:?} doesn't match sender {:?}",
            self.proposer(),
            sender
        );
```

**File:** consensus/consensus-types/src/block.rs (L410-417)
```rust
    pub fn new_from_opt(opt_block_data: OptBlockData, quorum_cert: QuorumCert) -> Self {
        let block_data = BlockData::new_from_opt(opt_block_data, quorum_cert);
        Block {
            id: block_data.hash(),
            block_data,
            signature: None,
        }
    }
```

**File:** consensus/consensus-types/src/block.rs (L453-461)
```rust
            BlockType::OptimisticProposal(p) => {
                // Note: Optimistic proposal is not signed by proposer unlike normal proposal
                let (res1, res2) = rayon::join(
                    || p.grandparent_qc().verify(validator),
                    || self.quorum_cert().verify(validator),
                );
                res1?;
                res2
            },
```

**File:** consensus/src/round_manager.rs (L330-330)
```rust
    pending_opt_proposals: BTreeMap<Round, OptBlockData>,
```

**File:** consensus/src/round_manager.rs (L751-764)
```rust
        if in_correct_round {
            self.process_proposal(proposal_msg.take_proposal()).await
        } else {
            sample!(
                SampleRate::Duration(Duration::from_secs(30)),
                warn!(
                    "[sampled] Stale proposal {}, current round {}",
                    proposal_msg.proposal(),
                    self.round_state.current_round()
                )
            );
            counters::ERROR_COUNT.inc();
            Ok(())
        }
```

**File:** consensus/src/round_manager.rs (L825-830)
```rust
            ensure!(
                self.proposer_election
                    .is_valid_proposer(proposal_msg.proposer(), proposal_msg.round()),
                "[OptProposal] Not a valid proposer for round {}: {}",
                proposal_msg.round(),
                proposal_msg.proposer()
```

**File:** consensus/src/round_manager.rs (L832-833)
```rust
            self.pending_opt_proposals
                .insert(proposal_msg.round(), proposal_msg.take_block_data());
```

**File:** consensus/src/round_manager.rs (L1195-1200)
```rust
        ensure!(
            self.proposer_election.is_valid_proposal(&proposal),
            "[RoundManager] Proposer {} for block {} is not a valid proposer for this round or created duplicate proposal",
            author,
            proposal,
        );
```

**File:** consensus/src/liveness/proposer_election.rs (L14-16)
```rust
    fn is_valid_proposer(&self, author: Author, round: Round) -> bool {
        self.get_valid_proposer(round) == author
    }
```

**File:** consensus/src/liveness/unequivocal_proposer_election.rs (L46-87)
```rust
    pub fn is_valid_proposal(&self, block: &Block) -> bool {
        block.author().is_some_and(|author| {
            let valid_author = self.is_valid_proposer(author, block.round());
            if !valid_author {
                warn!(
                    SecurityEvent::InvalidConsensusProposal,
                    "Proposal is not from valid author {}, expected {} for round {} and id {}",
                    author,
                    self.get_valid_proposer(block.round()),
                    block.round(),
                    block.id()
                );

                return false;
            }
            let mut already_proposed = self.already_proposed.lock();
            // detect if the leader proposes more than once in this round
            match block.round().cmp(&already_proposed.0) {
                Ordering::Greater => {
                    already_proposed.0 = block.round();
                    already_proposed.1 = block.id();
                    true
                },
                Ordering::Equal => {
                    if already_proposed.1 != block.id() {
                        error!(
                            SecurityEvent::InvalidConsensusProposal,
                            "Multiple proposals from {} for round {}: {} and {}",
                            author,
                            block.round(),
                            already_proposed.1,
                            block.id()
                        );
                        false
                    } else {
                        true
                    }
                },
                Ordering::Less => false,
            }
        })
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
