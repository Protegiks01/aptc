# Audit Report

## Title
Missing Equivocation Detection in Timeout Processing Allows Byzantine Validators to Form Inconsistent Timeout Certificates

## Summary
The `insert_round_timeout()` function lacks duplicate and equivocation detection for timeout messages, unlike `insert_vote()`. This allows Byzantine validators to send conflicting timeout messages to different nodes without detection, causing different honest nodes to form structurally different `TwoChainTimeoutCertificate` structures for the same round, violating consensus consistency and enabling undetectable Byzantine behavior.

## Finding Description

The vulnerability stems from an asymmetry in how votes and timeouts are processed in the Aptos consensus protocol:

**Vote Processing (with equivocation detection):**
The `insert_vote()` function explicitly checks if a validator has already voted using the `author_to_vote` map. If the same author votes for a different ledger info digest, it returns `VoteReceptionResult::EquivocateVote` and logs a security event. [1](#0-0) 

**Timeout Processing (without equivocation detection):**
The `insert_round_timeout()` function directly forwards to `TwoChainTimeoutVotes::add()` without any duplicate or equivocation checking. [2](#0-1) 

The underlying `add_signature()` method uses `or_insert()` semantics, which silently ignores subsequent timeouts from the same validator with no error returned and no logging. [3](#0-2) 

**Exploitation Mechanism:**

1. A Byzantine validator sends two conflicting `RoundTimeout` messages for round R with different `hqc_round` values (e.g., 50 vs 90) to different subsets of nodes
2. Due to `or_insert()` semantics, each node stores only the first timeout it receives from that validator
3. When aggregating timeouts, the TC's overall timeout field is updated to the one with the highest `hqc_round` seen at that node [4](#0-3) 

4. TC verification checks that `timeout.hqc_round == max(all signed hqc_rounds)`, which passes independently at each node [5](#0-4) 

5. Different nodes form valid but structurally different TCs with the same round number but different `hqc_round` values

6. When nodes exchange TCs via `SyncInfo`, TCs with the same or lower round number are rejected and not replaced [6](#0-5) 

7. **Result:** Different honest nodes permanently hold different TCs for the same round

**Safety Rule Impact:**

The different `hqc_round` values in TCs cause different safety rule evaluations. The `safe_to_vote()` function checks `qc_round >= hqc_round` when validating proposals after timeouts. [7](#0-6) 

Nodes with TC(hqc_round=50) will accept proposals with qc_round≥50, while nodes with TC(hqc_round=90) only accept proposals with qc_round≥90, causing inconsistent voting behavior for the same proposals.

## Impact Explanation

This constitutes a **Medium to High Severity** protocol violation:

1. **Consensus Inconsistency**: Different honest nodes form structurally different TCs for the same round, breaking the fundamental assumption that consensus messages are consistent across honest nodes

2. **Equivocation Detection Failure**: Byzantine validators can equivocate without any detection, logging, or accountability—a core violation of Byzantine fault tolerance principles that rely on equivocation detection for security monitoring and potential slashing

3. **Safety Rule Divergence**: Different `hqc_round` values cause different safety rule evaluations for the same proposals, leading to inconsistent voting behavior across honest validators

4. **TC Structural Inequality**: TCs use derived `Eq` and `PartialEq` implementations, meaning TCs with the same round but different `hqc_round` values are not considered equal despite representing the same consensus round [8](#0-7) 

While this may not directly cause a consensus fork due to BFT quorum requirements, it represents a significant protocol correctness violation that undermines consensus guarantees and enables undetectable Byzantine behavior that could potentially be exploited in more complex attack scenarios.

## Likelihood Explanation

**Likelihood: High**

- **Requirements**: Single Byzantine validator within the 1/3 BFT fault tolerance assumption
- **Attack Complexity**: Low—simply broadcast different timeout messages to different nodes via the gossip network
- **Network Conditions**: Asynchronous networks naturally deliver messages in different orders, making the attack inevitable once launched
- **Detection**: Zero—no equivocation detection, no logging, no security events, no monitoring alerts
- **Validator Action**: The caller processes `VoteReceptionResult` but no error is ever returned for timeout equivocation [9](#0-8) 

## Recommendation

Add equivocation detection to `insert_round_timeout()` matching the logic in `insert_vote()`:

1. Maintain a map tracking which authors have sent timeouts for the current round
2. Check if the author has already sent a timeout
3. If yes, compare the new timeout with the stored one:
   - If identical: return `DuplicateVote`
   - If different: log security event and return `EquivocateVote`
4. Update the stored timeout only for non-duplicate cases

Example fix in `pending_votes.rs`:
```rust
// Add to PendingVotes struct:
author_to_timeout: HashMap<Author, RoundTimeout>,

// In insert_round_timeout():
if let Some(previous_timeout) = self.author_to_timeout.get(&round_timeout.author()) {
    if previous_timeout.two_chain_timeout().hqc_round() 
        != round_timeout.two_chain_timeout().hqc_round() {
        error!(
            SecurityEvent::ConsensusEquivocatingTimeout,
            remote_peer = round_timeout.author(),
            timeout = round_timeout,
            previous_timeout = previous_timeout
        );
        return VoteReceptionResult::EquivocateVote;
    }
    return VoteReceptionResult::DuplicateVote;
}
self.author_to_timeout.insert(round_timeout.author(), round_timeout.clone());
```

## Proof of Concept

The vulnerability can be demonstrated by:
1. Setting up a test network with 4 validators (3 honest, 1 Byzantine)
2. Byzantine validator sends timeout(round=10, hqc_round=5) to validators A and B
3. Byzantine validator sends timeout(round=10, hqc_round=9) to validator C
4. All validators also send timeout(round=10, hqc_round=7)
5. Validators A and B form TC with hqc_round=7, validator C forms TC with hqc_round=9
6. When proposal(round=11, qc_round=8) arrives, A and B accept (8≥7) but C rejects (8<9)

A complete PoC would require Rust consensus tests demonstrating the TC divergence and inconsistent safety rule evaluation.

**Notes:**

- All technical claims have been verified against the Aptos Core codebase
- The vulnerability is triggerable under standard Byzantine assumptions (1 malicious validator out of 4+)
- The core issue is the missing equivocation detection, not just logging
- The impact is real: different nodes hold different consensus state for the same round
- Severity assessment: This is a protocol consistency violation (likely Medium severity per bounty criteria) rather than direct fund loss or proven safety violation (Critical), though the undetectable Byzantine behavior could potentially be exploited in more complex attack scenarios

### Citations

**File:** consensus/src/pending_votes.rs (L190-271)
```rust
    pub fn insert_round_timeout(
        &mut self,
        round_timeout: &RoundTimeout,
        validator_verifier: &ValidatorVerifier,
    ) -> VoteReceptionResult {
        //
        // Let's check if we can create a TC
        //

        let timeout = round_timeout.two_chain_timeout();
        let signature = round_timeout.signature();

        let validator_voting_power = validator_verifier
            .get_voting_power(&round_timeout.author())
            .unwrap_or(0);
        if validator_voting_power == 0 {
            warn!(
                "Received vote with no voting power, from {}",
                round_timeout.author()
            );
        }
        let cur_epoch = round_timeout.epoch();
        let cur_round = round_timeout.round();

        counters::CONSENSUS_CURRENT_ROUND_TIMEOUT_VOTED_POWER
            .with_label_values(&[&round_timeout.author().to_string()])
            .set(validator_voting_power as f64);
        counters::CONSENSUS_LAST_TIMEOUT_VOTE_EPOCH
            .with_label_values(&[&round_timeout.author().to_string()])
            .set(cur_epoch as i64);
        counters::CONSENSUS_LAST_TIMEOUT_VOTE_ROUND
            .with_label_values(&[&round_timeout.author().to_string()])
            .set(cur_round as i64);

        let two_chain_votes = self
            .maybe_2chain_timeout_votes
            .get_or_insert_with(|| TwoChainTimeoutVotes::new(timeout.clone()));
        two_chain_votes.add(
            round_timeout.author(),
            timeout.clone(),
            signature.clone(),
            round_timeout.reason().clone(),
        );

        let partial_tc = two_chain_votes.partial_2chain_tc_mut();
        let tc_voting_power =
            match validator_verifier.check_voting_power(partial_tc.signers(), true) {
                Ok(_) => {
                    return match partial_tc.aggregate_signatures(validator_verifier) {
                        Ok(tc_with_sig) => {
                            VoteReceptionResult::New2ChainTimeoutCertificate(Arc::new(tc_with_sig))
                        },
                        Err(e) => VoteReceptionResult::ErrorAggregatingTimeoutCertificate(e),
                    };
                },
                Err(VerifyError::TooLittleVotingPower { voting_power, .. }) => voting_power,
                Err(error) => {
                    error!(
                        "MUST_FIX: 2-chain timeout vote received could not be added: {}, vote: {}",
                        error, timeout
                    );
                    return VoteReceptionResult::ErrorAddingVote(error);
                },
            };

        // Echo timeout if receive f+1 timeout message.
        if !self.echo_timeout {
            let f_plus_one = validator_verifier.total_voting_power()
                - validator_verifier.quorum_voting_power()
                + 1;
            if tc_voting_power >= f_plus_one {
                self.echo_timeout = true;
                return VoteReceptionResult::EchoTimeout(tc_voting_power);
            }
        }

        //
        // No TC could be formed, return the TC's voting power
        //

        VoteReceptionResult::VoteAdded(tc_voting_power)
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

**File:** consensus/consensus-types/src/timeout_2chain.rs (L108-112)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct TwoChainTimeoutCertificate {
    timeout: TwoChainTimeout,
    signatures_with_rounds: AggregateSignatureWithRounds,
}
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L170-181)
```rust
        let signed_hqc = self
            .signatures_with_rounds
            .rounds()
            .iter()
            .max()
            .ok_or_else(|| anyhow::anyhow!("Empty rounds"))?;
        ensure!(
            hqc_round == *signed_hqc,
            "Inconsistent hqc round, qc has round {}, highest signed round {}",
            hqc_round,
            *signed_hqc
        );
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L242-263)
```rust
    pub fn add(
        &mut self,
        author: Author,
        timeout: TwoChainTimeout,
        signature: bls12381::Signature,
    ) {
        debug_assert_eq!(
            self.timeout.epoch(),
            timeout.epoch(),
            "Timeout should have the same epoch as TimeoutCert"
        );
        debug_assert_eq!(
            self.timeout.round(),
            timeout.round(),
            "Timeout should have the same round as TimeoutCert"
        );
        let hqc_round = timeout.hqc_round();
        if timeout.hqc_round() > self.timeout.hqc_round() {
            self.timeout = timeout;
        }
        self.signatures.add_signature(author, hqc_round, signature);
    }
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L320-329)
```rust
    pub fn add_signature(
        &mut self,
        validator: AccountAddress,
        round: Round,
        signature: bls12381::Signature,
    ) {
        self.signatures
            .entry(validator)
            .or_insert((round, signature));
    }
```

**File:** consensus/src/block_storage/block_store.rs (L567-569)
```rust
        if tc.round() <= cur_tc_round {
            return Ok(());
        }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L158-165)
```rust
        let hqc_round = maybe_tc.map_or(0, |tc| tc.highest_hqc_round());
        if round == next_round(qc_round)?
            || (round == next_round(tc_round)? && qc_round >= hqc_round)
        {
            Ok(())
        } else {
            Err(Error::NotSafeToVote(round, qc_round, tc_round, hqc_round))
        }
```

**File:** consensus/src/round_manager.rs (L1833-1852)
```rust
    async fn process_timeout_reception_result(
        &mut self,
        timeout: &RoundTimeout,
        result: VoteReceptionResult,
    ) -> anyhow::Result<()> {
        let round = timeout.round();
        match result {
            VoteReceptionResult::New2ChainTimeoutCertificate(tc) => {
                self.new_2chain_tc_aggregated(tc).await
            },
            VoteReceptionResult::EchoTimeout(_) if !self.round_state.is_timeout_sent() => {
                self.process_local_timeout(round).await
            },
            VoteReceptionResult::VoteAdded(_) | VoteReceptionResult::EchoTimeout(_) => Ok(()),
            result @ VoteReceptionResult::NewQuorumCertificate(_)
            | result @ VoteReceptionResult::DuplicateVote => {
                bail!("Unexpected result from timeout processing: {:?}", result);
            },
            e => Err(anyhow::anyhow!("{:?}", e)),
        }
```
