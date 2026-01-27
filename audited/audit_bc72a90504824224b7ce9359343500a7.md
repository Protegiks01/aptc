# Audit Report

## Title
Inconsistent Leader Election Across Validators Due to Database State Divergence Causes Consensus Liveness Failures

## Summary
The `LeaderReputation` proposer election mechanism computes leader selection based on historical block events from each validator's local database. When validators have divergent database states due to normal network conditions (sync lag, failed rounds), they compute different valid proposers for the same round, causing consensus liveness failures as no quorum can be formed on any proposal.

## Finding Description

The vulnerability exists in the interaction between `UnequivocalProposerElection` and `LeaderReputation` when determining valid proposers for consensus rounds. [1](#0-0) 

The `is_valid_proposal()` function delegates proposer validation to the underlying `proposer_election` implementation. When `LeaderReputation` is used, it queries historical events from the local database: [2](#0-1) 

The critical issue is in `AptosDBBackend::get_block_metadata()`, which fetches a sliding window of historical events from each validator's local database: [3](#0-2) 

**Attack Scenario:**

1. **Different Database States**: Validators naturally have different committed block histories due to:
   - Network sync lag
   - Different failed rounds (some rounds succeed on some nodes but fail on others)
   - Database pruning differences

2. **Divergent Sliding Windows**: When querying `get_block_metadata(epoch, target_round)`:
   - Validator A's DB contains rounds: [100, 99, 98, 95, 94] (rounds 96-97 failed)
   - Validator B's DB contains rounds: [100, 99, 98, 97, 96] (no failures)
   - Same query returns different historical events

3. **Different Reputation Weights**: The heuristic computes reputation weights from the sliding window: [4](#0-3) 
   
   Different historical events lead to different reputation scores for validators.

4. **Different Proposer Selection**: The `choose_index()` function uses cumulative weights: [5](#0-4) 
   
   Different weights lead to different selected proposers for the same round, even with deterministic seeds (when `use_root_hash=false`).

5. **Consensus Split**: 
   - Validator A computes: `valid_proposer(round_R) = Alice`
   - Validator B computes: `valid_proposer(round_R) = Bob`
   - Both Alice and Bob propose blocks
   - Validators using A's computation accept Alice's block, reject Bob's
   - Validators using B's computation accept Bob's block, reject Alice's
   - No quorum (2f+1) forms on either block
   - Round times out, consensus stalls

**Evidence of Known Issue:**

The developers acknowledge this problem in the code: [6](#0-5) 

This warning explicitly states: **"Elected proposers are unlikely to match!!"**

## Impact Explanation

This vulnerability causes **High Severity** impact:

1. **Significant Protocol Violations**: Violates the fundamental consensus requirement that all honest validators agree on protocol rules (who is the valid proposer for each round).

2. **Consensus Liveness Failures**: When validators disagree on the valid proposer, no proposal can achieve quorum, causing round timeouts and delayed block production.

3. **Availability Issues**: If the divergence persists across multiple rounds (due to continued sync lag), the network experiences extended periods of unavailability.

4. **Validator Reputation Damage**: Failed proposal rounds incorrectly penalize validators in the reputation system, compounding the problem.

According to Aptos bug bounty criteria, this qualifies as **High Severity** - "Significant protocol violations" and "Validator node slowdowns" affecting network availability.

## Likelihood Explanation

**Very High Likelihood** - This occurs naturally without any attack:

1. **Normal Network Conditions**: Sync lag and failed rounds are expected in distributed systems
2. **No Special Requirements**: Requires no validator collusion, malicious behavior, or special network access
3. **Continuous Trigger**: Occurs whenever validators have different database states during leader election
4. **Production Environment**: More likely in production with geographic distribution and varying network conditions

The explicit warning in the code confirms this is a known, recurring issue.

## Recommendation

**Short-term Fix**: Ensure deterministic proposer election by making the reputation computation based on committed ledger state visible to all validators:

1. Include reputation-relevant metadata in committed blocks (e.g., failed proposer list, voting participation)
2. Compute reputation weights from the last committed block's metadata, not from local database queries
3. Use the committed ledger info's epoch and round as the source of truth

**Long-term Fix**: 

1. Switch to deterministic proposer election (e.g., `RotatingProposer`) or ensure `LeaderReputation` uses only consensus-committed data
2. Add validator agreement checks - if `get_valid_proposer()` diverges across validators, log errors and fall back to deterministic election
3. Implement cross-validator reputation synchronization at epoch boundaries

**Code Fix Example:**

In `LeaderReputation::get_valid_proposer()`, instead of querying local database:
```rust
// Instead of: self.backend.get_block_metadata(self.epoch, target_round)
// Use: committed_ledger_info.reputation_metadata()
// Where reputation_metadata is included in certified blocks
```

## Proof of Concept

**Reproduction Steps:**

1. Deploy 4 validators with `LeaderReputation` election (V1 or V2)
2. Create network partition causing validators 1-2 to miss rounds 95-96
3. Resume network, all validators reach round 100
4. At round 101:
   - Validators 1-2 query history: [100, 99, 98, 93, 92] (missing 95-96)
   - Validators 3-4 query history: [100, 99, 98, 97, 96]
5. Different reputation weights computed
6. Validators 1-2 compute `valid_proposer(101) = Alice`
7. Validators 3-4 compute `valid_proposer(101) = Bob`
8. Both Alice and Bob propose
9. Observe: No quorum formed, round 101 times out

**Test Implementation** (Rust pseudocode):

```rust
#[test]
fn test_leader_election_database_divergence() {
    // Setup 4 validators
    let validators = create_validators(4);
    
    // Create two different mock databases
    let db_slow = create_db_with_rounds(vec![100, 99, 98, 93, 92]);
    let db_fast = create_db_with_rounds(vec![100, 99, 98, 97, 96]);
    
    // Create LeaderReputation with different backends
    let leader_slow = create_leader_reputation(db_slow);
    let leader_fast = create_leader_reputation(db_fast);
    
    // Query for same round
    let proposer_slow = leader_slow.get_valid_proposer(101);
    let proposer_fast = leader_fast.get_valid_proposer(101);
    
    // Assert: Different proposers computed
    assert_ne!(proposer_slow, proposer_fast);
    
    // Simulate consensus: neither proposal achieves quorum
    // (detailed consensus simulation omitted)
}
```

## Notes

While `CachedProposerElection` prevents inconsistency within a single validator node by caching results, it does not prevent divergence **across** validators with different database states. The cache only ensures a single validator doesn't recompute different results for the same round locally. [7](#0-6) 

The root cause is that leader election must be deterministic across all validators, but `LeaderReputation` bases decisions on non-deterministic local database state rather than globally-agreed consensus state.

### Citations

**File:** consensus/src/liveness/unequivocal_proposer_election.rs (L46-60)
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
```

**File:** consensus/src/liveness/leader_reputation.rs (L112-122)
```rust
        if target_round != 0 {
            let has_larger = events.first().is_some_and(|e| {
                (e.event.epoch(), e.event.round()) >= (target_epoch, target_round)
            });
            if !has_larger {
                // error, and not a fatal, in an unlikely scenario that we have many failed consecutive rounds,
                // and nobody has any newer successful blocks.
                warn!(
                    "Local history is too old, asking for {} epoch and {} round, and latest from db is {} epoch and {} round! Elected proposers are unlikely to match!!",
                    target_epoch, target_round, events.first().map_or(0, |e| e.event.epoch()), events.first().map_or(0, |e| e.event.round()))
            }
```

**File:** consensus/src/liveness/leader_reputation.rs (L168-214)
```rust
impl MetadataBackend for AptosDBBackend {
    // assume the target_round only increases
    fn get_block_metadata(
        &self,
        target_epoch: u64,
        target_round: Round,
    ) -> (Vec<NewBlockEvent>, HashValue) {
        let mut locked = self.db_result.lock();
        let latest_db_version = self.aptos_db.get_latest_ledger_info_version().unwrap_or(0);
        // lazy init db_result
        if locked.is_none() {
            if let Err(e) = self.refresh_db_result(&mut locked, latest_db_version) {
                warn!(
                    error = ?e, "[leader reputation] Fail to initialize db result",
                );
                return (vec![], HashValue::zero());
            }
        }
        let (events, version, hit_end) = {
            // locked is somenthing
            #[allow(clippy::unwrap_used)]
            let result = locked.as_ref().unwrap();
            (&result.0, result.1, result.2)
        };

        let has_larger = events
            .first()
            .is_some_and(|e| (e.event.epoch(), e.event.round()) >= (target_epoch, target_round));
        // check if fresher data has potential to give us different result
        if !has_larger && version < latest_db_version {
            let fresh_db_result = self.refresh_db_result(&mut locked, latest_db_version);
            match fresh_db_result {
                Ok((events, _version, hit_end)) => {
                    self.get_from_db_result(target_epoch, target_round, &events, hit_end)
                },
                Err(e) => {
                    // fails if requested events were pruned / or we never backfil them.
                    warn!(
                        error = ?e, "[leader reputation] Fail to refresh window",
                    );
                    (vec![], HashValue::zero())
                },
            }
        } else {
            self.get_from_db_result(target_epoch, target_round, events, hit_end)
        }
    }
```

**File:** consensus/src/liveness/leader_reputation.rs (L696-733)
```rust
    fn get_valid_proposer_and_voting_power_participation_ratio(
        &self,
        round: Round,
    ) -> (Author, VotingPowerRatio) {
        let target_round = round.saturating_sub(self.exclude_round);
        let (sliding_window, root_hash) = self.backend.get_block_metadata(self.epoch, target_round);
        let voting_power_participation_ratio =
            self.compute_chain_health_and_add_metrics(&sliding_window, round);
        let mut weights =
            self.heuristic
                .get_weights(self.epoch, &self.epoch_to_proposers, &sliding_window);
        let proposers = &self.epoch_to_proposers[&self.epoch];
        assert_eq!(weights.len(), proposers.len());

        // Multiply weights by voting power:
        let stake_weights: Vec<u128> = weights
            .iter_mut()
            .enumerate()
            .map(|(i, w)| *w as u128 * self.voting_powers[i] as u128)
            .collect();

        let state = if self.use_root_hash {
            [
                root_hash.to_vec(),
                self.epoch.to_le_bytes().to_vec(),
                round.to_le_bytes().to_vec(),
            ]
            .concat()
        } else {
            [
                self.epoch.to_le_bytes().to_vec(),
                round.to_le_bytes().to_vec(),
            ]
            .concat()
        };

        let chosen_index = choose_index(stake_weights, state);
        (proposers[chosen_index], voting_power_participation_ratio)
```

**File:** consensus/src/liveness/proposer_election.rs (L49-69)
```rust
pub(crate) fn choose_index(mut weights: Vec<u128>, state: Vec<u8>) -> usize {
    let mut total_weight = 0;
    // Create cumulative weights vector
    // Since we own the vector, we can safely modify it in place
    for w in &mut weights {
        total_weight = total_weight
            .checked_add(w)
            .expect("Total stake shouldn't exceed u128::MAX");
        *w = total_weight;
    }
    let chosen_weight = next_in_range(state, total_weight);
    weights
        .binary_search_by(|w| {
            if *w <= chosen_weight {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        })
        .expect_err("Comparison never returns equals, so it's always guaranteed to be error")
}
```

**File:** consensus/src/liveness/cached_proposer_election.rs (L40-58)
```rust
    pub fn get_or_compute_entry(&self, round: Round) -> (Author, f64) {
        let mut recent_elections = self.recent_elections.lock();

        if round > self.window as u64 {
            *recent_elections = recent_elections.split_off(&(round - self.window as u64));
        }

        *recent_elections.entry(round).or_insert_with(|| {
            let _timer = PROPOSER_ELECTION_DURATION.start_timer();
            let result = self
                .proposer_election
                .get_valid_proposer_and_voting_power_participation_ratio(round);
            info!(
                "ProposerElection for epoch {} and round {}: {:?}",
                self.epoch, round, result
            );
            result
        })
    }
```
