> Searching codebase... [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** consensus/src/liveness/rotating_proposer_election.rs (L1-100)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use crate::liveness::proposer_election::ProposerElection;
use aptos_consensus_types::common::{Author, Round};

/// The rotating proposer maps a round to an author according to a round-robin rotation.
/// A fixed proposer strategy loses liveness when the fixed proposer is down. Rotating proposers
/// won't gather quorum certificates to machine loss/byzantine behavior on f/n rounds.
pub struct RotatingProposer {
    // Ordering of proposers to rotate through (all honest replicas must agree on this)
    proposers: Vec<Author>,
    // Number of contiguous rounds (i.e. round numbers increase by 1) a proposer is active
    // in a row
    contiguous_rounds: u32,
}

/// Choose a proposer that is going to be the single leader (relevant for a mock fixed proposer
/// election only).
pub fn choose_leader(peers: Vec<Author>) -> Author {
    // As it is just a tmp hack function, pick the min PeerId to be a proposer.
    peers.into_iter().min().expect("No trusted peers found!")
}

impl RotatingProposer {
    /// With only one proposer in the vector, it behaves the same as a fixed proposer strategy.
    pub fn new(proposers: Vec<Author>, contiguous_rounds: u32) -> Self {
        Self {
            proposers,
            contiguous_rounds,
        }
    }
}

impl ProposerElection for RotatingProposer {
    fn get_valid_proposer(&self, round: Round) -> Author {
        self.proposers
            [((round / u64::from(self.contiguous_rounds)) % self.proposers.len() as u64) as usize]
    }
}


```

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

**File:** consensus/consensus-types/src/block.rs (L619-638)
```rust
    fn failed_authors_to_indices(
        validators: &[AccountAddress],
        failed_authors: &[(Round, Author)],
    ) -> Vec<u32> {
        failed_authors
            .iter()
            .map(|(_round, failed_author)| {
                validators
                    .iter()
                    .position(|&v| v == *failed_author)
                    .unwrap_or_else(|| {
                        panic!(
                            "Failed author {} not in validator list {:?}",
                            *failed_author, validators
                        )
                    })
            })
            .map(|index| u32::try_from(index).expect("Index is out of bounds for u32"))
            .collect()
    }
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1310-1332)
```text
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
        };
    }
```

**File:** types/src/on_chain_config/consensus_config.rs (L480-490)
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
```
