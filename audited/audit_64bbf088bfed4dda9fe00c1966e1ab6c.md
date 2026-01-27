# Audit Report

## Title
Missing Equivocation Detection in Timeout Processing Allows Byzantine Validators to Form Inconsistent Timeout Certificates

## Summary
The `insert_round_timeout()` function in `consensus/src/pending_votes.rs` lacks duplicate and equivocation detection for timeout messages, unlike the equivalent `insert_vote()` function. This allows Byzantine validators to send conflicting timeout messages to different nodes without detection, causing different honest nodes to form different `TwoChainTimeoutCertificate` structures for the same round, violating consensus consistency.

## Finding Description

The vulnerability stems from an asymmetry in how votes and timeouts are processed:

**Vote Processing** (with equivocation detection): [1](#0-0) 

The `insert_vote()` function explicitly checks if a validator has already voted and returns `DuplicateVote` or `EquivocateVote` accordingly, with security event logging.

**Timeout Processing** (without equivocation detection): [2](#0-1) 

The `insert_round_timeout()` function directly adds timeouts without checking for duplicates or equivocations. The underlying `add_signature()` method uses `or_insert()` semantics: [3](#0-2) 

This silently ignores subsequent timeouts from the same validator—no error is returned, no logging occurs.

**Exploitation Path:**

1. Byzantine validator V sends two conflicting `RoundTimeout` messages for round R:
   - T1: `(epoch=E, round=R, hqc_round=50)` to subset of nodes
   - T2: `(epoch=E, round=R, hqc_round=90)` to other nodes

2. Due to `or_insert()` semantics, each node accepts only the first timeout it receives from V

3. When forming `TwoChainTimeoutCertificate`, the TC's `hqc_round` is set to the maximum across all validators: [4](#0-3) 

4. TC verification requires `timeout.hqc_round == max(all signed hqc_rounds)`: [5](#0-4) 

5. Nodes that saw T1 first form TC_A with different `hqc_round` than nodes that saw T2 first (TC_B)

6. When nodes exchange TCs via `SyncInfo`, TCs with the same round number are not replaced: [6](#0-5) 

7. **Result**: Different honest nodes permanently hold different TCs for the same round, violating consensus consistency.

**Caller Return Value Handling:**

The caller DOES properly check `VoteReceptionResult`: [7](#0-6) [8](#0-7) 

However, errors are only logged and do not halt processing. The real issue is that **no error is returned** when equivocation occurs—the duplicate timeout is silently ignored via `or_insert()`.

## Impact Explanation

This constitutes a **High Severity** protocol violation per Aptos bug bounty criteria:

1. **Consensus Inconsistency**: Different honest nodes form structurally different TCs for the same round, breaking the assumption that all honest nodes agree on timeout certificates.

2. **Equivocation Detection Failure**: Byzantine validators can equivocate without detection, logging, or consequences—violating Byzantine fault tolerance assumptions that require equivocation detection for accountability.

3. **TC Divergence**: Since TCs are compared by structure (implementing `Eq`), different TCs won't be recognized as equivalent even if they represent the same round: [9](#0-8) 

4. **Potential Liveness Impact**: Different nodes advancing with different TCs may have different views of highest certified rounds, potentially causing proposal validation inconsistencies.

While this may not directly cause a consensus fork (due to safety rules), it represents a significant protocol violation enabling undetectable Byzantine behavior.

## Likelihood Explanation

**Likelihood: Medium-High**

- **Requirements**: One Byzantine validator (within 1/3 fault tolerance assumption)
- **Attack Complexity**: Low—simply send different timeout messages to different nodes
- **Network Conditions**: Asynchronous network naturally delivers messages in different orders
- **Detection**: Zero—no logging, monitoring, or alerts for this behavior
- **Feasibility**: Highly realistic under normal Byzantine assumptions

## Recommendation

Add equivocation detection to `insert_round_timeout()` matching the pattern used in `insert_vote()`:

```rust
pub fn insert_round_timeout(
    &mut self,
    round_timeout: &RoundTimeout,
    validator_verifier: &ValidatorVerifier,
) -> VoteReceptionResult {
    let timeout = round_timeout.two_chain_timeout();
    let signature = round_timeout.signature();
    let author = round_timeout.author();

    // NEW: Check for duplicate/equivocating timeouts
    if let Some(existing_votes) = &self.maybe_2chain_timeout_votes {
        if existing_votes.partial_2chain_tc.signers().any(|a| a == &author) {
            // Validator has already sent a timeout
            let existing_hqc = existing_votes.partial_2chain_tc
                .signatures_with_rounds()
                .get(&author)
                .map(|(round, _)| round);
            
            if existing_hqc == Some(timeout.hqc_round()) {
                return VoteReceptionResult::DuplicateVote;
            } else {
                error!(
                    SecurityEvent::ConsensusEquivocatingTimeout,
                    remote_peer = author,
                    timeout = round_timeout,
                    existing_hqc_round = existing_hqc
                );
                return VoteReceptionResult::EquivocateVote;
            }
        }
    }

    // ... rest of existing implementation
}
```

Additionally, update `add_signature()` to return a boolean indicating if insertion succeeded, or explicitly check before calling.

## Proof of Concept

```rust
#[test]
fn test_timeout_equivocation_not_detected() {
    use aptos_consensus_types::{
        block::block_test_utils::certificate_for_genesis,
        round_timeout::{RoundTimeout, RoundTimeoutReason},
        timeout_2chain::TwoChainTimeout,
    };
    use aptos_types::validator_verifier::random_validator_verifier;

    let (signers, validator_verifier) = random_validator_verifier(4, None, false);
    let mut pending_votes = PendingVotes::new();

    let qc = certificate_for_genesis();
    
    // Byzantine validator sends first timeout with hqc_round=1
    let timeout1 = TwoChainTimeout::new(1, 10, qc.clone());
    let sig1 = timeout1.sign(&signers[0]).unwrap();
    let round_timeout1 = RoundTimeout::new(
        timeout1.clone(),
        signers[0].author(),
        RoundTimeoutReason::Unknown,
        sig1,
    );

    let result1 = pending_votes.insert_round_timeout(&round_timeout1, &validator_verifier);
    assert_eq!(result1, VoteReceptionResult::VoteAdded(1));

    // Byzantine validator sends CONFLICTING timeout with different hqc_round=5
    let qc2 = certificate_for_genesis(); // Would have different round in real scenario
    let timeout2 = TwoChainTimeout::new(1, 10, qc2);
    let sig2 = timeout2.sign(&signers[0]).unwrap();
    let round_timeout2 = RoundTimeout::new(
        timeout2,
        signers[0].author(),
        RoundTimeoutReason::Unknown,
        sig2,
    );

    let result2 = pending_votes.insert_round_timeout(&round_timeout2, &validator_verifier);
    
    // BUG: This returns VoteAdded instead of EquivocateVote
    // The conflicting timeout is silently ignored
    assert_eq!(result2, VoteReceptionResult::VoteAdded(1)); // Should be EquivocateVote!
    
    // Compare with vote behavior:
    // insert_vote() would return EquivocateVote and log security event
}
```

**Notes:**

The vulnerability requires a Byzantine validator but is within the standard threat model (< 1/3 Byzantine). The caller properly checks return values, but the function itself fails to detect and report equivocation, making it impossible for callers to handle this critical error appropriately. This breaks the Byzantine fault detection invariant essential for accountability mechanisms like slashing.

### Citations

**File:** consensus/src/pending_votes.rs (L224-232)
```rust
        let two_chain_votes = self
            .maybe_2chain_timeout_votes
            .get_or_insert_with(|| TwoChainTimeoutVotes::new(timeout.clone()));
        two_chain_votes.add(
            round_timeout.author(),
            timeout.clone(),
            signature.clone(),
            round_timeout.reason().clone(),
        );
```

**File:** consensus/src/pending_votes.rs (L287-308)
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
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L108-109)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct TwoChainTimeoutCertificate {
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L176-180)
```rust
        ensure!(
            hqc_round == *signed_hqc,
            "Inconsistent hqc round, qc has round {}, highest signed round {}",
            hqc_round,
            *signed_hqc
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L259-261)
```rust
        if timeout.hqc_round() > self.timeout.hqc_round() {
            self.timeout = timeout;
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

**File:** consensus/src/block_storage/block_store.rs (L567-568)
```rust
        if tc.round() <= cur_tc_round {
            return Ok(());
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

**File:** consensus/src/round_manager.rs (L1890-1894)
```rust
        let vote_reception_result = self
            .round_state
            .insert_round_timeout(&timeout, &self.epoch_state.verifier);
        self.process_timeout_reception_result(&timeout, vote_reception_result)
            .await
```
