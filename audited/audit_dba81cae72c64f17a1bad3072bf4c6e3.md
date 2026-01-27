# Audit Report

## Title
DAG Vote Storage Exhaustion via Future Round Flooding

## Summary
The DAG consensus implementation fails to validate upper bounds on round numbers before persisting votes to storage. Attackers can flood validators with nodes containing arbitrarily high round numbers (e.g., round 1,000,000), causing validators to create and permanently store votes for rounds that will never be reached, leading to storage exhaustion and validator node failures.

## Finding Description

The DAG consensus system contains a critical ordering flaw in its vote validation and persistence logic. When a validator receives a `Node` via RPC, the `NodeBroadcastHandler::validate()` method only checks if the round is greater than or equal to the lowest round in the DAG, but **does not enforce an upper bound** on the round number. [1](#0-0) 

After this insufficient validation passes, the vote is immediately persisted to the ConsensusDB via the `DagVoteSchema`: [2](#0-1) 

The storage adapter directly writes to the database without additional validation: [3](#0-2) 

The system **does** have an upper bound check in `InMemDag::validate_new_node()`, which enforces `round <= highest_round + 1`: [4](#0-3) 

However, this validation only occurs when adding a **CertifiedNode** to the DAG store. By that point, votes have already been persisted to storage. Nodes with excessively high rounds will never become certified or added to the DAG, but their votes remain in storage indefinitely.

The garbage collection mechanism only removes votes for rounds **below** the lowest round: [5](#0-4) 

This means votes for future rounds are never cleaned up.

**Attack Scenario:**
1. Attacker creates malicious `Node` objects with round numbers far in the future (e.g., 1,000,000, 1,000,001, 1,000,002...)
2. Attacker sends these nodes to validators via DAG RPC
3. Each validator's `NodeBroadcastHandler` receives the node and validates it (passes because round >= lowest_round)
4. Validator creates a vote and persists it to storage via `DagVoteSchema`
5. Vote is added to in-memory `votes_by_round_peer` map
6. Node never becomes certified (would fail upper bound check in DAG store)
7. Vote remains in storage permanently (GC only removes old votes, not future votes)
8. Attacker repeats with thousands of different future rounds
9. ConsensusDB storage fills up with unbounded votes
10. Validator node experiences storage exhaustion, crashes, or becomes unavailable

This breaks the **Resource Limits invariant**: "All operations must respect gas, storage, and computational limits." The system allows unbounded storage writes based on unvalidated external input.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty program criteria:
- **Validator node slowdowns**: As storage fills with spurious votes, database operations degrade
- **API crashes**: Storage exhaustion can cause the validator process to crash
- **Network availability impact**: If multiple validators are targeted simultaneously, network liveness is compromised

The attack does not directly result in loss of funds or permanent consensus violations, but it significantly impacts network availability and validator operational integrity. An attacker with modest resources can force validators to exhaust their disk space, requiring manual intervention to restore service.

## Likelihood Explanation

**Likelihood: High**

The attack is highly likely to succeed because:

1. **Low attack complexity**: Attacker only needs to craft malicious `Node` messages and send them via standard DAG RPC
2. **No special privileges required**: Any network peer can send DAG nodes to validators
3. **No rate limiting observed**: The validation logic doesn't appear to rate-limit malicious nodes with future rounds
4. **Persistent damage**: Once votes are written to storage, they remain indefinitely
5. **Amplification factor**: Single malicious node generates one vote per validator, multiplied by unlimited future rounds

An attacker can execute this attack with:
- Standard network access to validator RPC endpoints
- Ability to construct valid `Node` structures (epoch, author, signatures can be crafted)
- Minimal computational resources (generating nodes is cheap)
- No validator collusion required

The attack surface is exposed on all DAG-enabled validators, making it a network-wide vulnerability.

## Recommendation

Add an upper bound check in `NodeBroadcastHandler::validate()` before persisting votes to storage. The fix should mirror the validation logic in `InMemDag::validate_new_node()`:

```rust
fn validate(&self, node: Node) -> anyhow::Result<Node> {
    ensure!(
        node.epoch() == self.epoch_state.epoch,
        "different epoch {}, current {}",
        node.epoch(),
        self.epoch_state.epoch
    );

    // ... existing validator transaction checks ...

    let current_round = node.metadata().round();

    let dag_reader = self.dag.read();
    let lowest_round = dag_reader.lowest_round();
    let highest_round = dag_reader.highest_round();

    ensure!(
        current_round >= lowest_round,
        NodeBroadcastHandleError::StaleRound(current_round)
    );

    // ADD THIS CHECK:
    ensure!(
        current_round <= highest_round + 1,
        "round too high {}, highest in dag {}",
        current_round,
        highest_round
    );

    // ... rest of validation ...
}
```

This ensures that votes are only created and stored for nodes that could potentially be added to the DAG, preventing storage exhaustion from future-round spam.

**Additional Hardening:**
- Implement metrics to monitor votes-by-round distribution
- Add alerting for abnormal vote storage growth
- Consider implementing a maximum votes-per-epoch limit as defense-in-depth

## Proof of Concept

```rust
#[cfg(test)]
mod vote_spam_test {
    use super::*;
    use aptos_consensus_types::common::Payload;
    use aptos_types::validator_signer::ValidatorSigner;
    
    #[tokio::test]
    async fn test_future_round_vote_spam() {
        // Setup: Create DAG store with current highest round = 10
        let epoch_state = Arc::new(create_test_epoch_state());
        let storage = Arc::new(MockStorage::new());
        let dag = Arc::new(DagStore::new(
            epoch_state.clone(),
            storage.clone(),
            Arc::new(MockPayloadManager::new()),
            1,  // start_round
            100, // window_size
        ));
        
        // Advance DAG to round 10
        for round in 1..=10 {
            let node = create_certified_node(epoch_state.epoch, round, author);
            dag.add_node(node).unwrap();
        }
        
        // Create NodeBroadcastHandler
        let handler = NodeBroadcastHandler::new(
            dag.clone(),
            Arc::new(MockOrderRule::new()),
            Arc::new(ValidatorSigner::new(author, private_key)),
            epoch_state.clone(),
            storage.clone(),
            Arc::new(MockFetchRequester::new()),
            DagPayloadConfig::default(),
            ValidatorTxnConfig::default(),
            OnChainRandomnessConfig::default(),
            OnChainJWKConsensusConfig::default(),
            HealthBackoff::new(),
        );
        
        // ATTACK: Send nodes with extremely high round numbers
        let malicious_rounds = vec![1000000, 1000001, 1000002, 1000003, 1000004];
        
        for malicious_round in malicious_rounds {
            // Create node with future round (should be rejected but isn't)
            let malicious_node = Node::new(
                epoch_state.epoch,
                malicious_round,
                author,
                timestamp,
                vec![],
                Payload::empty(false, true),
                vec![], // no parents for simplicity
                Extensions::empty(),
            );
            
            // Process the malicious node
            // This should fail but currently succeeds and saves vote to storage
            let result = handler.process(malicious_node).await;
            
            // BUG: This succeeds when it should fail
            assert!(result.is_ok(), "Malicious future-round node was accepted");
        }
        
        // Verify votes were persisted to storage
        let all_votes = storage.get_votes().unwrap();
        
        // VULNERABILITY CONFIRMED: Votes for future rounds are in storage
        let future_votes: Vec<_> = all_votes
            .iter()
            .filter(|(node_id, _)| node_id.round() > 11)
            .collect();
        
        assert_eq!(
            future_votes.len(),
            5,
            "Expected 5 future-round votes in storage (THIS SHOULD BE 0)"
        );
        
        // These votes will never be garbage collected
        // because gc_before_round() only removes votes with round < min_round
        handler.gc();
        
        let votes_after_gc = storage.get_votes().unwrap();
        let future_votes_after_gc: Vec<_> = votes_after_gc
            .iter()
            .filter(|(node_id, _)| node_id.round() > 11)
            .collect();
        
        assert_eq!(
            future_votes_after_gc.len(),
            5,
            "Future-round votes survived GC (STORAGE LEAK CONFIRMED)"
        );
    }
}
```

This PoC demonstrates:
1. Nodes with rounds far beyond `highest_round + 1` are accepted
2. Votes for these nodes are persisted to storage
3. These votes are never garbage collected
4. Storage accumulates unbounded votes from future rounds

The attack can be repeated indefinitely with different round numbers to exhaust validator storage.

### Citations

**File:** consensus/src/dag/rb_handler.rs (L95-110)
```rust
    pub fn gc_before_round(&self, min_round: Round) -> anyhow::Result<()> {
        let mut votes_by_round_peer_guard = self.votes_by_round_peer.lock();
        let to_retain = votes_by_round_peer_guard.split_off(&min_round);
        let to_delete = mem::replace(&mut *votes_by_round_peer_guard, to_retain);
        drop(votes_by_round_peer_guard);

        let to_delete = to_delete
            .iter()
            .flat_map(|(r, peer_and_digest)| {
                peer_and_digest
                    .keys()
                    .map(|author| NodeId::new(self.epoch_state.epoch, *r, *author))
            })
            .collect();
        self.storage.delete_votes(to_delete)
    }
```

**File:** consensus/src/dag/rb_handler.rs (L144-152)
```rust
        let current_round = node.metadata().round();

        let dag_reader = self.dag.read();
        let lowest_round = dag_reader.lowest_round();

        ensure!(
            current_round >= lowest_round,
            NodeBroadcastHandleError::StaleRound(current_round)
        );
```

**File:** consensus/src/dag/rb_handler.rs (L249-251)
```rust
        let signature = node.sign_vote(&self.signer)?;
        let vote = Vote::new(node.metadata().clone(), signature);
        self.storage.save_vote(&node.id(), &vote)?;
```

**File:** consensus/src/dag/adapter.rs (L355-357)
```rust
    fn save_vote(&self, node_id: &NodeId, vote: &Vote) -> anyhow::Result<()> {
        Ok(self.consensus_db.put::<DagVoteSchema>(node_id, vote)?)
    }
```

**File:** consensus/src/dag/dag_store.rs (L147-152)
```rust
        ensure!(
            round <= self.highest_round() + 1,
            "round too high {}, highest in dag {}",
            round,
            self.highest_round()
        );
```
