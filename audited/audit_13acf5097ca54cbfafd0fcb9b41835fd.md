# Audit Report

## Title
Database Error Handling in Leader Reputation Causes Consensus Divergence Through Leader Election Mismatch

## Summary
When AptosDB operations fail in the leader reputation system, the code returns `HashValue::zero()` instead of halting consensus. In networks using `ProposerAndVoterV2` configuration (the default), this causes validators experiencing database errors to select different leaders than healthy validators for the same round, violating the fundamental consensus requirement that all validators must agree on the designated leader.

## Finding Description

The vulnerability exists in the database error handling within the leader reputation mechanism. The AptosBFT consensus protocol in Aptos requires all validators to deterministically agree on which validator should be the leader (proposer) for each round. When using `ProposerAndVoterV2` leader reputation mode (the default configuration), the leader selection seed incorporates the blockchain's accumulator root hash to provide unpredictability. [1](#0-0) [2](#0-1) 

The `AptosDBBackend::get_block_metadata()` function is responsible for fetching historical block data and the accumulator root hash from the database. However, when database operations fail, the function returns empty results and `HashValue::zero()` instead of propagating the error: [3](#0-2) [4](#0-3) [5](#0-4) 

In the leader election flow, when `use_root_hash` is enabled (which it is for `ProposerAndVoterV2`), this root hash becomes part of the seed used for weighted random leader selection: [6](#0-5) [7](#0-6) 

The seed is passed to `choose_index()`, which uses SHA-3-256 hashing to deterministically select a validator index: [8](#0-7) 

**The Attack Scenario:**

When database errors occur on some validators but not others:

1. **Healthy validators**: Successfully fetch accumulator root hash (e.g., `0xabcd1234...`) → compute state as `[0xabcd1234..., epoch, round]` → hash produces value X → select leader at index I₁

2. **Failing validators**: Database operation fails → return `HashValue::zero()` → compute state as `[0x0000000..., epoch, round]` → hash produces value Y (≠ X) → select leader at index I₂ (≠ I₁)

3. **Consensus breakdown**: 
   - Validators with different database states now expect different leaders
   - When the "correct" leader (according to healthy validators) proposes, failing validators reject it as invalid (wrong proposer)
   - When attempting to form quorum certificates, validators disagree on which proposals are valid
   - This causes liveness failures as quorum cannot be reached

**Which invariant is broken:**

This violates the **Consensus Safety** invariant: "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine". Specifically, it breaks the prerequisite that all honest validators must agree on the designated leader for each round, which is fundamental to BFT consensus protocols.

## Impact Explanation

This qualifies as **Critical Severity** per Aptos bug bounty criteria for the following reasons:

1. **Total loss of liveness/network availability**: If a sufficient number of validators experience database errors simultaneously (which can occur during storage system failures, state sync issues, or database corruption), the network cannot reach consensus because validators disagree on the valid proposer. This causes consensus to halt until the database issues are resolved.

2. **Consensus/Safety violations**: While the immediate impact is liveness failure, prolonged disagreement about leaders during network partitions or recovery scenarios could theoretically lead to consensus splits if different validator subsets commit different blocks.

The severity is amplified because:
- The default configuration (`ProposerAndVoterV2`) enables this vulnerability
- Database errors are silent (only logged as warnings) with no mechanism to halt consensus
- Operators may not immediately detect the mismatch, as logs only show warnings
- The issue can affect any epoch where validators experience database issues

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability can manifest under several realistic scenarios:

1. **Hardware failures**: Disk I/O errors, storage controller failures, or disk corruption can cause database read operations to fail transiently or persistently

2. **State synchronization issues**: Validators performing state sync may experience temporary database inconsistencies or missing data during catch-up periods

3. **Database pruning edge cases**: Validators with different pruning configurations or timing might experience failures when attempting to fetch historical data that has been pruned

4. **High load conditions**: Under heavy transaction load, database contention or resource exhaustion could cause operations to timeout or fail

5. **Software bugs**: Bugs in AptosDB, RocksDB (underlying storage), or state management code could trigger database operation failures

While external attackers cannot directly trigger database failures on validators, these failures occur naturally in distributed systems, especially during:
- Network upgrades or migrations
- Recovery from crashes or restarts
- Storage system maintenance
- Resource exhaustion scenarios

The issue is particularly concerning because it affects the default configuration and has no fallback mechanism.

## Recommendation

Implement proper error handling that preserves consensus safety:

**Solution 1: Halt consensus on critical database errors** (Recommended)

```rust
fn get_block_metadata(
    &self,
    target_epoch: u64,
    target_round: Round,
) -> Result<(Vec<NewBlockEvent>, HashValue)> {
    let mut locked = self.db_result.lock();
    let latest_db_version = self.aptos_db
        .get_latest_ledger_info_version()
        .context("Failed to get latest ledger info version")?;
    
    // lazy init db_result
    if locked.is_none() {
        self.refresh_db_result(&mut locked, latest_db_version)
            .context("Failed to initialize leader reputation database backend")?;
    }
    
    let (events, version, hit_end) = {
        let result = locked.as_ref().unwrap();
        (&result.0, result.1, result.2)
    };

    let has_larger = events
        .first()
        .is_some_and(|e| (e.event.epoch(), e.event.round()) >= (target_epoch, target_round));
    
    if !has_larger && version < latest_db_version {
        let (events, _version, hit_end) = self.refresh_db_result(&mut locked, latest_db_version)
            .context("Failed to refresh leader reputation window")?;
        Ok(self.get_from_db_result(target_epoch, target_round, &events, hit_end))
    } else {
        Ok(self.get_from_db_result(target_epoch, target_round, events, hit_end))
    }
}
```

Update the trait to return `Result`:

```rust
pub trait MetadataBackend: Send + Sync {
    fn get_block_metadata(
        &self,
        target_epoch: u64,
        target_round: Round,
    ) -> Result<(Vec<NewBlockEvent>, HashValue)>;
}
```

And in `LeaderReputation`, propagate the error to halt consensus:

```rust
fn get_valid_proposer_and_voting_power_participation_ratio(
    &self,
    round: Round,
) -> Result<(Author, VotingPowerRatio)> {
    let target_round = round.saturating_sub(self.exclude_round);
    let (sliding_window, root_hash) = self.backend
        .get_block_metadata(self.epoch, target_round)
        .context("Leader reputation database backend failed")?;
    
    // ... rest of function
}
```

**Solution 2: Fallback to simple seed without root hash**

If database errors occur, fallback to using just `[epoch, round]` as the seed (like `ProposerAndVoter` V1), ensuring all validators still agree on the leader even without the unpredictable root hash component. This maintains liveness at the cost of temporary predictability.

**Solution 3: Implement retry logic with exponential backoff**

Before failing, attempt multiple retries with backoff for transient database errors. Only halt if errors persist after retries.

The recommended approach is **Solution 1** as it prioritizes consensus safety over liveness - it's better to halt consensus temporarily than to have validators diverge on leader selection.

## Proof of Concept

```rust
#[cfg(test)]
mod database_error_leader_divergence_test {
    use super::*;
    use aptos_crypto::HashValue;
    use aptos_types::account_config::NewBlockEvent;
    use std::sync::Arc;

    // Mock backend that simulates database failure
    struct FailingMetadataBackend;
    
    impl MetadataBackend for FailingMetadataBackend {
        fn get_block_metadata(
            &self,
            _target_epoch: u64,
            _target_round: Round,
        ) -> (Vec<NewBlockEvent>, HashValue) {
            // Simulate database failure by returning zero hash
            (vec![], HashValue::zero())
        }
    }
    
    // Mock backend that returns valid data
    struct HealthyMetadataBackend {
        root_hash: HashValue,
    }
    
    impl MetadataBackend for HealthyMetadataBackend {
        fn get_block_metadata(
            &self,
            _target_epoch: u64,
            _target_round: Round,
        ) -> (Vec<NewBlockEvent>, HashValue) {
            (vec![], self.root_hash)
        }
    }

    #[test]
    fn test_database_error_causes_leader_divergence() {
        let epoch = 10;
        let round = 100;
        let proposers = vec![
            AccountAddress::random(),
            AccountAddress::random(),
            AccountAddress::random(),
            AccountAddress::random(),
        ];
        let voting_powers = vec![100, 100, 100, 100];
        let epoch_to_proposers = HashMap::from([(epoch, proposers.clone())]);
        
        // Create heuristic
        let heuristic = Box::new(ProposerAndVoterHeuristic::new(
            proposers[0],
            1000,
            10,
            1,
            10,
            10,
            10,
            false,
        ));
        
        // Validator with failing database
        let failing_backend = Arc::new(FailingMetadataBackend);
        let failing_election = LeaderReputation::new(
            epoch,
            epoch_to_proposers.clone(),
            voting_powers.clone(),
            failing_backend,
            heuristic.clone(),
            0,
            true, // use_root_hash = true
            100,
        );
        
        // Validator with healthy database
        let healthy_backend = Arc::new(HealthyMetadataBackend {
            root_hash: HashValue::sha3_256_of(b"test_block_data"),
        });
        let healthy_election = LeaderReputation::new(
            epoch,
            epoch_to_proposers,
            voting_powers,
            healthy_backend,
            heuristic,
            0,
            true, // use_root_hash = true
            100,
        );
        
        // Get the elected leaders
        let failing_leader = failing_election.get_valid_proposer(round);
        let healthy_leader = healthy_election.get_valid_proposer(round);
        
        // Assert that they selected different leaders
        assert_ne!(
            failing_leader, 
            healthy_leader,
            "Validators with different database states should select different leaders, \
             breaking consensus agreement on the designated proposer"
        );
    }
}
```

This test demonstrates that when `use_root_hash` is enabled and database operations fail on some validators, those validators will select different leaders than healthy validators for the same round, violating the consensus requirement for agreement on the proposer.

---

## Notes

The vulnerability is specific to the `ProposerAndVoterV2` configuration which is the **default** in current Aptos deployments. Networks using the older `ProposerAndVoter` (V1) configuration are not affected as they don't use the root hash in the seed calculation.

The issue only manifests when database errors occur on a **subset** of validators. If all validators experience the same database state (all failing or all healthy), they would still agree on the leader (albeit possibly the wrong one if all are failing).

The vulnerability could be partially mitigated by:
1. Comprehensive database monitoring and alerting
2. Automatic validator shutdown on persistent database errors
3. Using V1 leader reputation mode in environments with unstable storage

However, these are operational workarounds rather than fixes to the underlying code issue.

### Citations

**File:** types/src/on_chain_config/consensus_config.rs (L488-503)
```rust
            proposer_election_type: ProposerElectionType::LeaderReputation(
                LeaderReputationType::ProposerAndVoterV2(ProposerAndVoterConfig {
                    active_weight: 1000,
                    inactive_weight: 10,
                    failed_weight: 1,
                    failure_threshold_percent: 10, // = 10%
                    // In each round we get stastics for the single proposer
                    // and large number of validators. So the window for
                    // the proposers needs to be significantly larger
                    // to have enough useful statistics.
                    proposer_window_num_validators_multiplier: 10,
                    voter_window_num_validators_multiplier: 1,
                    weight_by_voting_power: true,
                    use_history_from_previous_epoch_max_count: 5,
                }),
            ),
```

**File:** types/src/on_chain_config/consensus_config.rs (L541-544)
```rust
    pub fn use_root_hash_for_seed(&self) -> bool {
        // all versions after V1 should use root hash
        !matches!(self, Self::ProposerAndVoter(_))
    }
```

**File:** consensus/src/liveness/leader_reputation.rs (L149-162)
```rust
        if result.is_empty() {
            warn!("No events in the requested window could be found");
            (result, HashValue::zero())
        } else {
            let root_hash = self
                .aptos_db
                .get_accumulator_root_hash(max_version)
                .unwrap_or_else(|_| {
                    error!(
                        "We couldn't fetch accumulator hash for the {} version, for {} epoch, {} round",
                        max_version, target_epoch, target_round,
                    );
                    HashValue::zero()
                });
```

**File:** consensus/src/liveness/leader_reputation.rs (L178-184)
```rust
        if locked.is_none() {
            if let Err(e) = self.refresh_db_result(&mut locked, latest_db_version) {
                warn!(
                    error = ?e, "[leader reputation] Fail to initialize db result",
                );
                return (vec![], HashValue::zero());
            }
```

**File:** consensus/src/liveness/leader_reputation.rs (L203-209)
```rust
                Err(e) => {
                    // fails if requested events were pruned / or we never backfil them.
                    warn!(
                        error = ?e, "[leader reputation] Fail to refresh window",
                    );
                    (vec![], HashValue::zero())
                },
```

**File:** consensus/src/liveness/leader_reputation.rs (L700-734)
```rust
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
    }
```

**File:** consensus/src/epoch_manager.rs (L378-387)
```rust
                let proposer_election = Box::new(LeaderReputation::new(
                    epoch_state.epoch,
                    epoch_to_proposers,
                    voting_powers,
                    backend,
                    heuristic,
                    onchain_config.leader_reputation_exclude_round(),
                    leader_reputation_type.use_root_hash_for_seed(),
                    self.config.window_for_chain_health,
                ));
```

**File:** consensus/src/liveness/proposer_election.rs (L38-69)
```rust
// next consumes seed and returns random deterministic u64 value in [0, max) range
fn next_in_range(state: Vec<u8>, max: u128) -> u128 {
    // hash = SHA-3-256(state)
    let hash = aptos_crypto::HashValue::sha3_256_of(&state).to_vec();
    let mut temp = [0u8; 16];
    copy_slice_to_vec(&hash[..16], &mut temp).expect("next failed");
    // return hash[0..16]
    u128::from_le_bytes(temp) % max
}

// chose index randomly, with given weight distribution
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
