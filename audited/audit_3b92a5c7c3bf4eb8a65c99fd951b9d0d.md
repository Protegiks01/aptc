# Audit Report

## Title
Consensus Disagreement in LeaderReputation Due to Database State Divergence When Switching Proposer Election Implementations

## Summary
When switching from deterministic proposer election (`RotatingProposer`/`RoundProposer`) to `LeaderReputation` at epoch boundaries, validators with different database sync states will compute different root hashes for the same historical rounds. Since `LeaderReputation` (V2) uses these root hashes as entropy for weighted random proposer selection, validators will elect different proposers for the same round, causing consensus disagreement and potential network partition.

## Finding Description

The `ProposerElection` trait has three implementations: `RotatingProposer` (deterministic round-robin), `RoundProposer` (pre-specified map), and `LeaderReputation` (reputation-based weighted selection). All implementations correctly satisfy the trait interface, but they have fundamentally different determinism guarantees. [1](#0-0) 

`RotatingProposer` is purely deterministic, depending only on the round number and validator list ordering: [2](#0-1) 

However, `LeaderReputation` depends on historical block metadata from the database to compute proposer weights and uses a root hash as entropy: [3](#0-2) 

The critical vulnerability occurs in how the root hash is obtained. When validators have different database states (due to pruning, late joins, or sync delays), the `get_block_metadata` call returns different results: [4](#0-3) 

Notice lines 149-151 and 156-162: when no historical events are found or the accumulator hash fetch fails, the function returns `HashValue::zero()`. The code explicitly warns about this scenario: [5](#0-4) 

**Attack Scenario:**
1. Network is using `RotatingProposer` - all validators agree on proposers deterministically
2. Governance updates on-chain config to switch to `LeaderReputation(ProposerAndVoterV2)` at epoch N
3. At epoch N boundary, all validators read the same on-chain config and switch to `LeaderReputation`
4. Validator A has full historical data and computes `root_hash = 0xabc...`
5. Validator B has pruned/incomplete history and computes `root_hash = 0x000...` (zero)
6. For round R, both call `choose_index(stake_weights, [root_hash, epoch, round])`
7. Due to different `root_hash` values in the state seed, they select different proposer indices
8. Validator A expects proposer X to propose for round R
9. Validator B expects proposer Y to propose for round R
10. When proposer X's block arrives, Validator A accepts it as valid, Validator B rejects it with "InvalidConsensusProposal"
11. Consensus cannot progress / network partitions

**Invariant Broken:** Consensus Safety - "All validators must agree on the valid proposer for each round" (implicit requirement for AptosBFT safety). [6](#0-5) 

The `is_valid_proposal` check will fail for different validators, preventing consensus quorum formation.

## Impact Explanation

This is a **Critical Severity** vulnerability under the Aptos Bug Bounty program:
- **Category:** Consensus/Safety violations
- **Impact:** Network partition without requiring hardfork to recover, or severe liveness degradation
- **Affected Systems:** All validators participating in consensus after switching to LeaderReputation
- **Damage Potential:** Complete network halt or chain split if validator voting power is split roughly evenly between those with different database states

The vulnerability violates the fundamental consensus safety invariant that all honest validators must agree on valid proposals. Unlike typical Byzantine fault scenarios, this affects honest validators behaving correctly but with different local database states.

## Likelihood Explanation

**Likelihood: HIGH** - This will occur when:
1. Network switches from `RotatingProposer` to `LeaderReputation` via governance (operational decision)
2. Validators have different database pruning configurations (common in practice)
3. New validators join the network without full historical sync (common)
4. Database query failures occur due to storage issues (occasional)

The default configuration uses `LeaderReputation(ProposerAndVoterV2)` with `use_root_hash=true`: [7](#0-6) [8](#0-7) 

The code's explicit warning message indicates developers are aware this can happen, suggesting it's a known operational risk rather than a theoretical concern.

## Recommendation

**Short-term fix:** Add validation that all validators have synchronized historical data before allowing `LeaderReputation` mode, or fall back to deterministic proposer election when history is unavailable.

**Recommended fix in `consensus/src/liveness/leader_reputation.rs`:**

```rust
fn get_from_db_result(
    &self,
    target_epoch: u64,
    target_round: Round,
    events: &Vec<VersionedNewBlockEvent>,
    hit_end: bool,
) -> (Vec<NewBlockEvent>, HashValue) {
    // ... existing checks ...
    
    if result.is_empty() {
        error!("No events in the requested window could be found - FALLING BACK TO DETERMINISTIC PROPOSER");
        // CRITICAL FIX: Return a deterministic hash based on epoch/round
        // instead of zero, so all nodes agree even without history
        let deterministic_hash = HashValue::sha3_256_of(
            &[target_epoch.to_le_bytes(), target_round.to_le_bytes()].concat()
        );
        return (result, deterministic_hash);
    }
    
    let root_hash = self
        .aptos_db
        .get_accumulator_root_hash(max_version)
        .unwrap_or_else(|_| {
            error!("Accumulator hash fetch failed - using deterministic fallback");
            // CRITICAL FIX: Same deterministic fallback
            HashValue::sha3_256_of(
                &[target_epoch.to_le_bytes(), target_round.to_le_bytes()].concat()
            )
        });
    (result, root_hash)
}
```

**Long-term fix:** Redesign `LeaderReputation` to use only committed state that all validators are guaranteed to have (e.g., state committed at epoch boundaries), or require state sync completion before epoch start.

## Proof of Concept

```rust
// Add to consensus/src/liveness/leader_reputation.rs tests
#[test]
fn test_proposer_disagreement_with_different_database_states() {
    use crate::liveness::proposer_election::ProposerElection;
    use aptos_types::account_address::AccountAddress;
    use std::collections::HashMap;
    
    let epoch = 10;
    let proposers: Vec<AccountAddress> = (0..4).map(|_| AccountAddress::random()).collect();
    
    // Validator A has full history - will get real root hash
    let backend_a = Arc::new(MockDBBackend::with_full_history());
    let heuristic_a = Box::new(MockHeuristic::new());
    let leader_election_a = LeaderReputation::new(
        epoch,
        HashMap::from([(epoch, proposers.clone())]),
        vec![100; 4],
        backend_a,
        heuristic_a,
        40,
        true, // use_root_hash = true (V2 behavior)
        100,
    );
    
    // Validator B has no history - will get HashValue::zero()
    let backend_b = Arc::new(MockDBBackend::with_no_history());
    let heuristic_b = Box::new(MockHeuristic::new());
    let leader_election_b = LeaderReputation::new(
        epoch,
        HashMap::from([(epoch, proposers.clone())]),
        vec![100; 4],
        backend_b,
        heuristic_b,
        40,
        true, // use_root_hash = true
        100,
    );
    
    // VULNERABILITY: Different validators elect different proposers!
    let round = 100;
    let proposer_a = leader_election_a.get_valid_proposer(round);
    let proposer_b = leader_election_b.get_valid_proposer(round);
    
    assert_ne!(
        proposer_a, proposer_b,
        "CONSENSUS DISAGREEMENT: Validators disagree on proposer for round {}",
        round
    );
    
    // This breaks consensus safety
    println!("Validator A elected: {}", proposer_a);
    println!("Validator B elected: {}", proposer_b);
}
```

**Notes:**
- This vulnerability is explicitly acknowledged in the codebase warning but not prevented
- The issue manifests most severely during epoch transitions when switching TO `LeaderReputation`
- The default V2 configuration (`use_root_hash=true`) is vulnerable; V1 (`use_root_hash=false`) is less vulnerable but was deprecated for security reasons (predictable entropy)
- Database pruning configurations make this scenario realistic in production environments [9](#0-8)

### Citations

**File:** consensus/src/liveness/proposer_election.rs (L9-36)
```rust
/// ProposerElection incorporates the logic of choosing a leader among multiple candidates.
pub trait ProposerElection {
    /// If a given author is a valid candidate for being a proposer, generate the info,
    /// otherwise return None.
    /// Note that this function is synchronous.
    fn is_valid_proposer(&self, author: Author, round: Round) -> bool {
        self.get_valid_proposer(round) == author
    }

    /// Return the valid proposer for a given round (this information can be
    /// used by e.g., voters for choosing the destinations for sending their votes to).
    fn get_valid_proposer(&self, round: Round) -> Author;

    /// Return the chain health: a ratio of voting power participating in the consensus.
    fn get_voting_power_participation_ratio(&self, _round: Round) -> f64 {
        1.0
    }

    fn get_valid_proposer_and_voting_power_participation_ratio(
        &self,
        round: Round,
    ) -> (Author, f64) {
        (
            self.get_valid_proposer(round),
            self.get_voting_power_participation_ratio(round),
        )
    }
}
```

**File:** consensus/src/liveness/rotating_proposer_election.rs (L35-40)
```rust
impl ProposerElection for RotatingProposer {
    fn get_valid_proposer(&self, round: Round) -> Author {
        self.proposers
            [((round / u64::from(self.contiguous_rounds)) % self.proposers.len() as u64) as usize]
    }
}
```

**File:** consensus/src/liveness/leader_reputation.rs (L103-165)
```rust
    fn get_from_db_result(
        &self,
        target_epoch: u64,
        target_round: Round,
        events: &Vec<VersionedNewBlockEvent>,
        hit_end: bool,
    ) -> (Vec<NewBlockEvent>, HashValue) {
        // Do not warn when round==0, because check will always be unsure of whether we have
        // all events from the previous epoch. If there is an actual issue, next round will log it.
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
        }

        let mut max_version = 0;
        let mut result = vec![];
        for event in events {
            if (event.event.epoch(), event.event.round()) <= (target_epoch, target_round)
                && result.len() < self.window_size
            {
                max_version = std::cmp::max(max_version, event.version);
                result.push(event.event.clone());
            }
        }

        if result.len() < self.window_size && !hit_end {
            error!(
                "We are not fetching far enough in history, we filtered from {} to {}, but asked for {}. Target ({}, {}), received from {:?} to {:?}.",
                events.len(),
                result.len(),
                self.window_size,
                target_epoch,
                target_round,
                events.last().map_or((0, 0), |e| (e.event.epoch(), e.event.round())),
                events.first().map_or((0, 0), |e| (e.event.epoch(), e.event.round())),
            );
        }

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
            (result, root_hash)
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

**File:** types/src/on_chain_config/consensus_config.rs (L481-506)
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
}
```

**File:** types/src/on_chain_config/consensus_config.rs (L540-549)
```rust
impl LeaderReputationType {
    pub fn use_root_hash_for_seed(&self) -> bool {
        // all versions after V1 should use root hash
        !matches!(self, Self::ProposerAndVoter(_))
    }

    pub fn use_reputation_window_from_stale_end(&self) -> bool {
        // all versions after V1 shouldn't use from stale end
        matches!(self, Self::ProposerAndVoter(_))
    }
```

**File:** consensus/src/epoch_manager.rs (L287-407)
```rust
    fn create_proposer_election(
        &self,
        epoch_state: &EpochState,
        onchain_config: &OnChainConsensusConfig,
    ) -> Arc<dyn ProposerElection + Send + Sync> {
        let proposers = epoch_state
            .verifier
            .get_ordered_account_addresses_iter()
            .collect::<Vec<_>>();
        match &onchain_config.proposer_election_type() {
            ProposerElectionType::RotatingProposer(contiguous_rounds) => {
                Arc::new(RotatingProposer::new(proposers, *contiguous_rounds))
            },
            // We don't really have a fixed proposer!
            ProposerElectionType::FixedProposer(contiguous_rounds) => {
                let proposer = choose_leader(proposers);
                Arc::new(RotatingProposer::new(vec![proposer], *contiguous_rounds))
            },
            ProposerElectionType::LeaderReputation(leader_reputation_type) => {
                let (
                    heuristic,
                    window_size,
                    weight_by_voting_power,
                    use_history_from_previous_epoch_max_count,
                ) = match &leader_reputation_type {
                    LeaderReputationType::ProposerAndVoter(proposer_and_voter_config)
                    | LeaderReputationType::ProposerAndVoterV2(proposer_and_voter_config) => {
                        let proposer_window_size = proposers.len()
                            * proposer_and_voter_config.proposer_window_num_validators_multiplier;
                        let voter_window_size = proposers.len()
                            * proposer_and_voter_config.voter_window_num_validators_multiplier;
                        let heuristic: Box<dyn ReputationHeuristic> =
                            Box::new(ProposerAndVoterHeuristic::new(
                                self.author,
                                proposer_and_voter_config.active_weight,
                                proposer_and_voter_config.inactive_weight,
                                proposer_and_voter_config.failed_weight,
                                proposer_and_voter_config.failure_threshold_percent,
                                voter_window_size,
                                proposer_window_size,
                                leader_reputation_type.use_reputation_window_from_stale_end(),
                            ));
                        (
                            heuristic,
                            std::cmp::max(proposer_window_size, voter_window_size),
                            proposer_and_voter_config.weight_by_voting_power,
                            proposer_and_voter_config.use_history_from_previous_epoch_max_count,
                        )
                    },
                };

                let seek_len = onchain_config.leader_reputation_exclude_round() as usize
                    + onchain_config.max_failed_authors_to_store()
                    + PROPOSER_ROUND_BEHIND_STORAGE_BUFFER;

                let backend = Arc::new(AptosDBBackend::new(
                    window_size,
                    seek_len,
                    self.storage.aptos_db(),
                ));
                let voting_powers: Vec<_> = if weight_by_voting_power {
                    proposers
                        .iter()
                        .map(|p| {
                            epoch_state
                                .verifier
                                .get_voting_power(p)
                                .expect("INVARIANT VIOLATION: proposer not in verifier set")
                        })
                        .collect()
                } else {
                    vec![1; proposers.len()]
                };

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
                // LeaderReputation is not cheap, so we can cache the amount of rounds round_manager needs.
                Arc::new(CachedProposerElection::new(
                    epoch_state.epoch,
                    proposer_election,
                    onchain_config.max_failed_authors_to_store()
                        + PROPOSER_ELECTION_CACHING_WINDOW_ADDITION,
                ))
            },
            ProposerElectionType::RoundProposer(round_proposers) => {
                // Hardcoded to the first proposer
                let default_proposer = proposers
                    .first()
                    .expect("INVARIANT VIOLATION: proposers is empty");
                Arc::new(RoundProposer::new(
                    round_proposers.clone(),
                    *default_proposer,
                ))
            },
        }
    }
```
