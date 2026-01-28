# Audit Report

## Title
Epoch Boundary Consensus Liveness Failure Due to Inconsistent Historical Proposer Data

## Summary
At epoch transitions, validators with different historical data availability (due to pruning, fast sync, or database errors) can elect different proposers for the same round, causing a consensus liveness failure. The issue stems from fallback logic that silently uses only the current epoch when historical epoch data fetch fails, while other validators successfully use multiple epochs of history.

## Finding Description

The vulnerability exists in the leader reputation-based proposer election mechanism. When validators start a new epoch, the `extract_epoch_proposers` method attempts to fetch historical validator data from previous epochs to build an `epoch_to_proposers` map. [1](#0-0) 

The critical flaw occurs in the error handling. When `get_epoch_ending_ledger_infos` fails (due to pruned data, database corruption, or missing historical information), the code falls back to using **only the current epoch's validators** instead of propagating the error or ensuring consistency. [2](#0-1) 

This creates a divergence scenario where different validators construct different `epoch_to_proposers` maps. When calculating proposer weights via the reputation heuristic, the historical event filtering only considers events from epochs present in the `epoch_to_proposers` map. [3](#0-2) 

The filtering in `history_iter` at line 325 explicitly filters out events whose epochs are not in the map, causing validators with different epoch maps to count different historical events when aggregating metrics. [4](#0-3) 

This leads to different reputation weights being calculated for each validator. [5](#0-4) 

Even with identical seeds (constructed from epoch, round, and root hash), different weights result in different proposer selections via the deterministic `choose_index` function. [6](#0-5) [7](#0-6) 

When validators disagree on the expected proposer, each validator validates incoming proposals using `is_valid_proposal`, which rejects blocks from validators that don't match its expected proposer. [8](#0-7) [9](#0-8) 

**Exploitation Scenario:**
This occurs naturally when:
- The default ledger pruner window is 90,000,000 versions [10](#0-9) 
- The default `use_history_from_previous_epoch_max_count` is 5 epochs, which at ~5K TPS and 2-hour epochs equals approximately 180M versions - exceeding the pruning window
- Validators bootstrapping via fast sync lack full historical block event data
- Different validators have different pruning configurations

## Impact Explanation

This vulnerability constitutes a **CRITICAL SEVERITY** issue under the category "Total Loss of Liveness/Network Availability" per Aptos bug bounty criteria.

**Primary Impact**: Network Halt Due to Vote Splitting
1. Validators with different `epoch_to_proposers` maps calculate different expected proposers for the same round
2. When Validator A expects Alice as proposer but Validator B expects Bob, they reject each other's proposals
3. Neither block can achieve the required 2/3+1 quorum to commit
4. Consensus stalls indefinitely, halting the network

This is **NOT a safety violation** (double-spending/chain split) because:
- Only one proposer's block can achieve quorum (requires >2/3 agreement)
- Different validator groups cannot both have >2/3 of total voting power
- No conflicting blocks can both be committed

However, it is a **liveness failure** that completely halts network progress, requiring manual intervention to resolve. This matches the Critical severity category: "Network halts due to protocol bug".

## Likelihood Explanation

**LIKELIHOOD: HIGH**

This vulnerability has high likelihood because:

1. **Configuration Mismatch**: The default pruning window (90M versions) cannot cover 5 epochs of history (~180M versions at typical mainnet TPS), creating an inherent risk in default deployments.

2. **Heterogeneous Deployments**: Validators naturally have different operational configurations - archival nodes vs. regular validators, different join times, different pruning settings.

3. **Fast Sync Operations**: New validators bootstrapping via fast sync do not have full historical block event data, only epoch-ending ledger infos.

4. **Silent Failure**: The error is only logged, not propagated. [11](#0-10)  No mechanism alerts operators or prevents validators from continuing with inconsistent state.

5. **No Synchronization**: Each validator independently constructs its `epoch_to_proposers` map with no validation that all validators agree. [12](#0-11) 

The bug requires no attacker action - it emerges naturally from operational diversity.

## Recommendation

**Fix 1: Fail Fast on Historical Data Unavailability**
```rust
if epoch_state.epoch > first_epoch_to_consider {
    self.storage
        .aptos_db()
        .get_epoch_ending_ledger_infos(first_epoch_to_consider - 1, epoch_state.epoch)
        .map_err(Into::into)
        .and_then(|proof| {
            ensure!(
                proof.ledger_info_with_sigs.len() as u64
                    == (epoch_state.epoch - (first_epoch_to_consider - 1))
            );
            extract_epoch_to_proposers(proof, epoch_state.epoch, &proposers, needed_rounds)
        })
        // CHANGE: Propagate error instead of silent fallback
        .expect("CRITICAL: Cannot fetch required historical epoch data for leader reputation")
} else {
    HashMap::from([(epoch_state.epoch, proposers)])
}
```

**Fix 2: Adjust Default Configuration**
Set `use_history_from_previous_epoch_max_count` default to 2-3 epochs to fit within the 90M pruning window, or increase pruning window to 200M versions.

**Fix 3: Add Consistency Check**
Include the `epoch_to_proposers` key set in epoch state or consensus messages to detect divergence early.

## Proof of Concept

This vulnerability cannot be demonstrated with a simple unit test as it requires:
1. Multiple validator nodes with different storage states
2. Actual epoch transitions
3. Real pruning or fast-sync scenarios

However, the vulnerability can be verified by:
1. Setting up two validators, one with pruned history (e.g., only last 50M versions) and one archival
2. Waiting for an epoch transition
3. Observing the logged `epoch_to_proposers` maps differ between validators
4. Observing that validators reject each other's proposals with "Proposal is not from valid author" errors
5. Observing consensus stall

The code paths are production code paths that execute on every epoch transition in mainnet deployments.

## Notes

The report's terminology incorrectly labels this as a "consensus safety violation". More precisely, this is a **consensus liveness failure** - the network halts but does not commit conflicting blocks. However, this still qualifies as Critical severity under the "Total Loss of Liveness/Network Availability" category.

The vulnerability is particularly concerning because:
- It can occur with zero Byzantine validators
- Default configurations are vulnerable
- The failure mode is silent until consensus stalls
- Recovery requires manual coordination between validator operators

### Citations

**File:** consensus/src/epoch_manager.rs (L361-376)
```rust
                let epoch_to_proposers = self.extract_epoch_proposers(
                    epoch_state,
                    use_history_from_previous_epoch_max_count,
                    proposers,
                    (window_size + seek_len) as u64,
                );

                info!(
                    "Starting epoch {}: proposers across epochs for leader election: {:?}",
                    epoch_state.epoch,
                    epoch_to_proposers
                        .iter()
                        .map(|(epoch, proposers)| (epoch, proposers.len()))
                        .sorted()
                        .collect::<Vec<_>>()
                );
```

**File:** consensus/src/epoch_manager.rs (L409-449)
```rust
    fn extract_epoch_proposers(
        &self,
        epoch_state: &EpochState,
        use_history_from_previous_epoch_max_count: u32,
        proposers: Vec<AccountAddress>,
        needed_rounds: u64,
    ) -> HashMap<u64, Vec<AccountAddress>> {
        // Genesis is epoch=0
        // First block (after genesis) is epoch=1, and is the only block in that epoch.
        // It has no votes, so we skip it unless we are in epoch 1, as otherwise it will
        // skew leader elections for exclude_round number of rounds.
        let first_epoch_to_consider = std::cmp::max(
            if epoch_state.epoch == 1 { 1 } else { 2 },
            epoch_state
                .epoch
                .saturating_sub(use_history_from_previous_epoch_max_count as u64),
        );
        // If we are considering beyond the current epoch, we need to fetch validators for those epochs
        if epoch_state.epoch > first_epoch_to_consider {
            self.storage
                .aptos_db()
                .get_epoch_ending_ledger_infos(first_epoch_to_consider - 1, epoch_state.epoch)
                .map_err(Into::into)
                .and_then(|proof| {
                    ensure!(
                        proof.ledger_info_with_sigs.len() as u64
                            == (epoch_state.epoch - (first_epoch_to_consider - 1))
                    );
                    extract_epoch_to_proposers(proof, epoch_state.epoch, &proposers, needed_rounds)
                })
                .unwrap_or_else(|err| {
                    error!(
                        "Couldn't create leader reputation with history across epochs, {:?}",
                        err
                    );
                    HashMap::from([(epoch_state.epoch, proposers)])
                })
        } else {
            HashMap::from([(epoch_state.epoch, proposers)])
        }
    }
```

**File:** consensus/src/liveness/leader_reputation.rs (L297-326)
```rust
    fn history_iter<'a>(
        history: &'a [NewBlockEvent],
        epoch_to_candidates: &'a HashMap<u64, Vec<Author>>,
        window_size: usize,
        from_stale_end: bool,
    ) -> impl Iterator<Item = &'a NewBlockEvent> {
        let sub_history = if from_stale_end {
            let start = if history.len() > window_size {
                history.len() - window_size
            } else {
                0
            };

            &history[start..]
        } else {
            if let (Some(first), Some(last)) = (history.first(), history.last()) {
                assert!((first.epoch(), first.round()) >= (last.epoch(), last.round()));
            }
            let end = if history.len() > window_size {
                window_size
            } else {
                history.len()
            };

            &history[..end]
        };
        sub_history
            .iter()
            .filter(move |&meta| epoch_to_candidates.contains_key(&meta.epoch()))
    }
```

**File:** consensus/src/liveness/leader_reputation.rs (L328-351)
```rust
    pub fn get_aggregated_metrics(
        &self,
        epoch_to_candidates: &HashMap<u64, Vec<Author>>,
        history: &[NewBlockEvent],
        author: &Author,
    ) -> (
        HashMap<Author, u32>,
        HashMap<Author, u32>,
        HashMap<Author, u32>,
    ) {
        let votes = self.count_votes(epoch_to_candidates, history);
        let proposals = self.count_proposals(epoch_to_candidates, history);
        let failed_proposals = self.count_failed_proposals(epoch_to_candidates, history);

        COMMITTED_PROPOSALS_IN_WINDOW.set(*proposals.get(author).unwrap_or(&0) as i64);
        FAILED_PROPOSALS_IN_WINDOW.set(*failed_proposals.get(author).unwrap_or(&0) as i64);
        COMMITTED_VOTES_IN_WINDOW.set(*votes.get(author).unwrap_or(&0) as i64);

        LEADER_REPUTATION_ROUND_HISTORY_SIZE.set(
            proposals.values().sum::<u32>() as i64 + failed_proposals.values().sum::<u32>() as i64,
        );

        (votes, proposals, failed_proposals)
    }
```

**File:** consensus/src/liveness/leader_reputation.rs (L521-553)
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
}
```

**File:** consensus/src/liveness/leader_reputation.rs (L696-734)
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
    }
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

**File:** consensus/src/round_manager.rs (L1195-1200)
```rust
        ensure!(
            self.proposer_election.is_valid_proposal(&proposal),
            "[RoundManager] Proposer {} for block {} is not a valid proposer for this round or created duplicate proposal",
            author,
            proposal,
        );
```

**File:** config/src/config/storage_config.rs (L387-395)
```rust
impl Default for LedgerPrunerConfig {
    fn default() -> Self {
        LedgerPrunerConfig {
            enable: true,
            prune_window: 90_000_000,
            batch_size: 5_000,
            user_pruning_window_offset: 200_000,
        }
    }
```
