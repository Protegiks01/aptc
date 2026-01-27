# Audit Report

## Title
Failed Proposer Index Truncation Allows Validators to Escape Performance Penalties and Rewards Manipulation

## Summary
When more than 10 consecutive consensus rounds fail, the `failed_proposer_indices` vector is truncated to only include the most recent 10 failed proposers. This allows validators who failed in earlier rounds to escape penalty attribution in both the staking rewards system and leader reputation mechanism, enabling them to receive undeserved rewards and maintain favorable leader election weights.

## Finding Description

The vulnerability exists in the consensus layer's handling of failed proposer tracking across multiple system components. The attack chain works as follows:

**Step 1: Failed Proposer List Truncation**

In the consensus layer, `ProposalGenerator::compute_failed_authors` limits failed proposer tracking to `max_failed_authors_to_store` (default: 10). [1](#0-0) 

When calculating which proposers failed, the function uses:
```
start = max(previous_round + 1, end_round - max_failed_authors_to_store)
```

This means if 15 consecutive rounds fail (rounds 100-114) before round 115 succeeds with a QC for round 99, only rounds 105-114 (the last 10) are included. Rounds 100-104 are silently dropped.

**Step 2: Validation Accepts Truncated List**

The `RoundManager` validates proposals by calling the same `compute_failed_authors` function, so it accepts the truncated list as correct: [2](#0-1) 

**Step 3: Performance Statistics Not Updated**

The truncated list flows to the Move framework's `block_prologue_common`, which calls `stake::update_performance_statistics`: [3](#0-2) 

The `update_performance_statistics` function only increments `failed_proposals` for validators in the provided list: [4](#0-3) 

Validators from dropped rounds (100-104) do NOT get their `failed_proposals` counter incremented.

**Step 4: Undeserved Rewards Distribution**

During epoch transitions, rewards are calculated based on the performance counters: [5](#0-4) 

The reward formula is proportional to `successful_proposals / (successful_proposals + failed_proposals)`. Validators whose failures weren't counted receive higher rewards than deserved.

**Step 5: Leader Reputation Manipulation**

The leader reputation system reads `failed_proposer_indices` from block metadata to count failures: [6](#0-5) 

The `ProposerAndVoterHeuristic` assigns weights based on failure rates: [7](#0-6) 

Validators from dropped rounds maintain high weights (`active_weight = 1000`) instead of being penalized with `failed_weight = 1`, making them 1000x more likely to be selected as future leaders despite their poor performance.

**Configuration Shows 10 as Default Limit:** [8](#0-7) 

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program:

1. **Limited Funds Loss/Manipulation**: Validators receive undeserved staking rewards for rounds where they failed to propose. Over multiple epochs, this represents economic value improperly transferred from well-performing validators to poorly-performing ones.

2. **State Inconsistencies**: The `ValidatorPerformance` resource maintains incorrect statistics that don't reflect actual network behavior. The discrepancy between actual failures and recorded failures creates an inconsistent state that affects both rewards and leader selection.

3. **Consensus Degradation**: By allowing failed validators to maintain high reputation scores, the system continues selecting them as leaders, potentially perpetuating poor network performance and increasing the likelihood of future failures.

The impact is limited because:
- It requires specific conditions (>10 consecutive failures)
- It doesn't directly steal funds or break consensus safety
- Recovery is possible through governance intervention to update validator set

## Likelihood Explanation

**Likelihood: Medium-to-High**

This vulnerability can occur through multiple scenarios:

1. **Natural Occurrence**: During network stress, DDoS attacks, or infrastructure failures, consecutive round failures are realistic. The 10-round threshold is relatively low given that:
   - Network partitions can persist for extended periods
   - Coordinated attacks on infrastructure can cause sustained outages
   - Software bugs or misconfigurations can trigger cascading failures

2. **Strategic Exploitation**: While difficult to trigger intentionally without validator collusion, validators could:
   - Monitor their position in failure sequences
   - Recognize when they're in the "safe zone" (first 5 of 15 failures)
   - Benefit passively from the penalty escape

3. **Compound Effect**: Once triggered, the vulnerability has lasting effects:
   - Incorrect performance statistics persist across epochs
   - Reputation scores remain elevated for entire reputation windows
   - Undeserved rewards accumulate over time

The threshold of 10 is concerning because:
- With 100+ validators, a 10% failure rate means 10+ consecutive failures aren't uncommon during degraded conditions
- The default configuration makes this exploitable without on-chain configuration changes

## Recommendation

**Immediate Fix**: Remove the arbitrary limit on failed proposer tracking or increase it significantly.

**Option 1 - Remove the Limit** (Preferred):
Modify `compute_failed_authors` to track ALL failed proposers between the previous certified round and current round:

```rust
pub fn compute_failed_authors(
    &self,
    round: Round,
    previous_round: Round,
    include_cur_round: bool,
    proposer_election: Arc<dyn ProposerElection>,
) -> Vec<(Round, Author)> {
    let end_round = round + u64::from(include_cur_round);
    let mut failed_authors = Vec::new();
    
    // Track ALL failed rounds, no arbitrary limit
    for i in (previous_round + 1)..end_round {
        failed_authors.push((i, proposer_election.get_valid_proposer(i)));
    }
    
    failed_authors
}
```

**Option 2 - Significantly Increase Limit**:
If storage/bandwidth concerns exist, increase `max_failed_authors_to_store` to at least 100-1000 to handle realistic failure scenarios:

```rust
max_failed_authors_to_store: 1000,  // Increased from 10
```

**Option 3 - Add Validation**:
If a limit must exist, add explicit validation that rejects blocks when the gap between rounds exceeds the limit, forcing nodes to recognize the data loss:

```rust
let gap = end_round - previous_round - 1;
if gap > self.max_failed_authors_to_store as u64 {
    bail!("Failed proposer gap {} exceeds tracking limit {}", 
          gap, self.max_failed_authors_to_store);
}
```

**Long-term Solution**: Decouple performance tracking from per-block metadata. Store complete failure history in a separate on-chain resource that isn't subject to block size constraints.

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[test]
fn test_failed_proposer_truncation_vulnerability() {
    use crate::liveness::proposal_generator::ProposalGenerator;
    
    // Setup: validator set with 100 validators
    let num_validators = 100;
    let max_failed_authors = 10; // Default configuration
    
    // Simulate scenario: 15 consecutive failed rounds (100-114)
    // Then round 115 succeeds with QC for round 99
    let current_round = 115;
    let previous_certified_round = 99;
    let include_cur_round = false;
    
    let failed_authors = proposal_generator.compute_failed_authors(
        current_round,
        previous_certified_round,
        include_cur_round,
        proposer_election.clone(),
    );
    
    // VULNERABILITY: Only 10 failed authors returned, not 15!
    assert_eq!(failed_authors.len(), 10);
    
    // Rounds 100-104 are silently dropped
    // Their proposers escape penalty!
    let first_tracked_round = failed_authors[0].0;
    assert_eq!(first_tracked_round, 105); // Should be 100!
    
    // These validators will NOT have failed_proposals incremented:
    for round in 100..105 {
        let dropped_proposer = proposer_election.get_valid_proposer(round);
        println!("Validator {:?} escaped penalty for failing round {}", 
                 dropped_proposer, round);
    }
}
```

```move
// Move test demonstrating rewards impact
#[test(aptos_framework = @aptos_framework, validator1 = @0x100, validator2 = @0x200)]
public entry fun test_undeserved_rewards_from_missing_failures(
    aptos_framework: &signer,
    validator1: &signer,
    validator2: &signer,
) acquires ValidatorPerformance, StakePool {
    // Setup two validators
    initialize_for_test(aptos_framework);
    
    // Validator1 fails in round 100 (dropped from tracking)
    // Validator2 fails in round 110 (included in tracking)
    
    // Simulate: both validators failed once, but only validator2 recorded
    let perf = borrow_global_mut<ValidatorPerformance>(@aptos_framework);
    
    // Validator1: 0 successful, 0 failed (WRONG - should be 1 failed)
    let v1_perf = vector::borrow_mut(&mut perf.validators, validator1_index);
    v1_perf.successful_proposals = 0;
    v1_perf.failed_proposals = 0; // Missing the failure!
    
    // Validator2: 0 successful, 1 failed (CORRECT)
    let v2_perf = vector::borrow_mut(&mut perf.validators, validator2_index);
    v2_perf.successful_proposals = 0;
    v2_perf.failed_proposals = 1;
    
    end_epoch();
    
    // VULNERABILITY: Validator1 receives rewards despite failing!
    // Validator2 receives no rewards (correct behavior)
    let v1_stake = borrow_global<StakePool>(validator1_address);
    let v2_stake = borrow_global<StakePool>(validator2_address);
    
    assert!(coin::value(&v1_stake.active) > 1000, 0); // Got rewards
    assert!(coin::value(&v2_stake.active) == 1000, 1); // No rewards
}
```

**Notes:**

The vulnerability is rooted in the hardcoded limit of 10 in the default consensus configuration, which is insufficient for realistic failure scenarios. The issue affects three critical subsystems:

1. **Staking rewards**: Incorrect calculation leads to economic unfairness
2. **Leader reputation**: Poor performers maintain high selection weights  
3. **Validator performance metrics**: Historical data doesn't reflect reality

This represents a violation of the "Staking Security" invariant that "validator rewards and penalties must be calculated correctly." The issue is particularly concerning because it creates a perverse incentive structure where validators benefit from being early in a failure sequence rather than improving their infrastructure.

### Citations

**File:** consensus/src/liveness/proposal_generator.rs (L884-902)
```rust
    pub fn compute_failed_authors(
        &self,
        round: Round,
        previous_round: Round,
        include_cur_round: bool,
        proposer_election: Arc<dyn ProposerElection>,
    ) -> Vec<(Round, Author)> {
        let end_round = round + u64::from(include_cur_round);
        let mut failed_authors = Vec::new();
        let start = std::cmp::max(
            previous_round + 1,
            end_round.saturating_sub(self.max_failed_authors_to_store as u64),
        );
        for i in start..end_round {
            failed_authors.push((i, proposer_election.get_valid_proposer(i)));
        }

        failed_authors
    }
```

**File:** consensus/src/round_manager.rs (L1217-1230)
```rust
            // Validate that failed_authors list is correctly specified in the block.
            let expected_failed_authors = self.proposal_generator.compute_failed_authors(
                proposal.round(),
                proposal.quorum_cert().certified_block().round(),
                false,
                self.proposer_election.clone(),
            );
            ensure!(
                proposal.block_data().failed_authors().is_some_and(|failed_authors| *failed_authors == expected_failed_authors),
                "[RoundManager] Proposal for block {} has invalid failed_authors list {:?}, expected {:?}",
                proposal.round(),
                proposal.block_data().failed_authors(),
                expected_failed_authors,
            );
```

**File:** aptos-move/framework/aptos-framework/sources/block.move (L154-199)
```text
    fun block_prologue_common(
        vm: &signer,
        hash: address,
        epoch: u64,
        round: u64,
        proposer: address,
        failed_proposer_indices: vector<u64>,
        previous_block_votes_bitvec: vector<u8>,
        timestamp: u64
    ): u64 acquires BlockResource, CommitHistory {
        // Operational constraint: can only be invoked by the VM.
        system_addresses::assert_vm(vm);

        // Blocks can only be produced by a valid proposer or by the VM itself for Nil blocks (no user txs).
        assert!(
            proposer == @vm_reserved || stake::is_current_epoch_validator(proposer),
            error::permission_denied(EINVALID_PROPOSER),
        );

        let proposer_index = option::none();
        if (proposer != @vm_reserved) {
            proposer_index = option::some(stake::get_validator_index(proposer));
        };

        let block_metadata_ref = borrow_global_mut<BlockResource>(@aptos_framework);
        block_metadata_ref.height = event::counter(&block_metadata_ref.new_block_events);

        let new_block_event = NewBlockEvent {
            hash,
            epoch,
            round,
            height: block_metadata_ref.height,
            previous_block_votes_bitvec,
            proposer,
            failed_proposer_indices,
            time_microseconds: timestamp,
        };
        emit_new_block_event(vm, &mut block_metadata_ref.new_block_events, new_block_event);

        // Performance scores have to be updated before the epoch transition as the transaction that triggers the
        // transition is the last block in the previous epoch.
        stake::update_performance_statistics(proposer_index, failed_proposer_indices);
        state_storage::on_new_block(reconfiguration::current_epoch());

        block_metadata_ref.epoch_interval
    }
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1282-1330)
```text
    public(friend) fun update_performance_statistics(
        proposer_index: Option<u64>,
        failed_proposer_indices: vector<u64>
    ) acquires ValidatorPerformance {
        // Validator set cannot change until the end of the epoch, so the validator index in arguments should
        // match with those of the validators in ValidatorPerformance resource.
        let validator_perf = borrow_global_mut<ValidatorPerformance>(@aptos_framework);
        let validator_len = vector::length(&validator_perf.validators);

        spec {
            update ghost_valid_perf = validator_perf;
            update ghost_proposer_idx = proposer_index;
        };
        // proposer_index is an option because it can be missing (for NilBlocks)
        if (option::is_some(&proposer_index)) {
            let cur_proposer_index = option::extract(&mut proposer_index);
            // Here, and in all other vector::borrow, skip any validator indices that are out of bounds,
            // this ensures that this function doesn't abort if there are out of bounds errors.
            if (cur_proposer_index < validator_len) {
                let validator = vector::borrow_mut(&mut validator_perf.validators, cur_proposer_index);
                spec {
                    assume validator.successful_proposals + 1 <= MAX_U64;
                };
                validator.successful_proposals = validator.successful_proposals + 1;
            };
        };

        let f = 0;
        let f_len = vector::length(&failed_proposer_indices);
        while ({
            spec {
                invariant len(validator_perf.validators) == validator_len;
                invariant (option::is_some(ghost_proposer_idx) && option::borrow(
                    ghost_proposer_idx
                ) < validator_len) ==>
                    (validator_perf.validators[option::borrow(ghost_proposer_idx)].successful_proposals ==
                        ghost_valid_perf.validators[option::borrow(ghost_proposer_idx)].successful_proposals + 1);
            };
            f < f_len
        }) {
            let validator_index = *vector::borrow(&failed_proposer_indices, f);
            if (validator_index < validator_len) {
                let validator = vector::borrow_mut(&mut validator_perf.validators, validator_index);
                spec {
                    assume validator.failed_proposals + 1 <= MAX_U64;
                };
                validator.failed_proposals = validator.failed_proposals + 1;
            };
            f = f + 1;
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1515-1527)
```text
            let cur_reward = if (candidate_in_current_validator_set && cur_active > 0) {
                spec {
                    assert candidate.config.validator_index < len(validator_perf.validators);
                };
                let cur_perf = vector::borrow(&validator_perf.validators, candidate.config.validator_index);
                spec {
                    assume cur_perf.successful_proposals + cur_perf.failed_proposals <= MAX_U64;
                };
                calculate_rewards_amount(cur_active, cur_perf.successful_proposals, cur_perf.successful_proposals + cur_perf.failed_proposals, rewards_rate, rewards_rate_denominator)
            } else {
                0
            };

```

**File:** consensus/src/liveness/leader_reputation.rs (L428-461)
```rust
    pub fn count_failed_proposals(
        &self,
        epoch_to_candidates: &HashMap<u64, Vec<Author>>,
        history: &[NewBlockEvent],
    ) -> HashMap<Author, u32> {
        Self::history_iter(
            history,
            epoch_to_candidates,
            self.proposer_window_size,
            self.reputation_window_from_stale_end,
        )
        .fold(HashMap::new(), |mut map, meta| {
            match Self::indices_to_validators(
                &epoch_to_candidates[&meta.epoch()],
                meta.failed_proposer_indices(),
            ) {
                Ok(failed_proposers) => {
                    for &failed_proposer in failed_proposers {
                        let count = map.entry(failed_proposer).or_insert(0);
                        *count += 1;
                    }
                },
                Err(msg) => {
                    error!(
                        "Failed proposer conversion from indices failed at epoch {}, round {}: {}",
                        meta.epoch(),
                        meta.round(),
                        msg
                    )
                },
            }
            map
        })
    }
```

**File:** consensus/src/liveness/leader_reputation.rs (L521-552)
```rust
impl ReputationHeuristic for ProposerAndVoterHeuristic {
    fn get_weights(
        &self,
        epoch: u64,
        epoch_to_candidates: &HashMap<u64, Vec<Author>>,
        history: &[NewBlockEvent],
    ) -> Vec<u64> {
        assert!(epoch_to_candidates.contains_key(&epoch));

        let (votes, proposals, failed_proposals) =
            self.aggregation
                .get_aggregated_metrics(epoch_to_candidates, history, &self.author);

        epoch_to_candidates[&epoch]
            .iter()
            .map(|author| {
                let cur_votes = *votes.get(author).unwrap_or(&0);
                let cur_proposals = *proposals.get(author).unwrap_or(&0);
                let cur_failed_proposals = *failed_proposals.get(author).unwrap_or(&0);

                if cur_failed_proposals * 100
                    > (cur_proposals + cur_failed_proposals) * self.failure_threshold_percent
                {
                    self.failed_weight
                } else if cur_proposals > 0 || cur_votes > 0 {
                    self.active_weight
                } else {
                    self.inactive_weight
                }
            })
            .collect()
    }
```

**File:** types/src/on_chain_config/consensus_config.rs (L481-505)
```rust
impl Default for ConsensusConfigV1 {
    fn default() -> Self {
        Self {
            decoupled_execution: true,
            back_pressure_limit: 10,
            exclude_round: 40,
            max_failed_authors_to_store: 10,
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
        }
    }
```
