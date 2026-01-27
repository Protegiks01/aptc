# Audit Report

## Title
Non-Deterministic Proposer Election Causes Consensus Disagreement Across Validators

## Summary
The `UnequivocalProposerElection` wrapper trusts its underlying `ProposerElection` implementation to be deterministic across all validator nodes. However, when using `LeaderReputation` with `use_root_hash=true` (the default for V2 configurations), proposer selection depends on the local database's root hash, which can differ across nodes. This causes different validators to compute different valid proposers for the same round, leading to consensus disagreements where some nodes accept and others reject the same legitimate proposal. [1](#0-0) 

## Finding Description

The vulnerability exists in the trust relationship between `UnequivocalProposerElection` and its wrapped `ProposerElection` implementation. The wrapper validates proposals by checking:

1. If the proposal's author matches the expected proposer via `is_valid_proposer()` 
2. If this is not a duplicate proposal for the same round [2](#0-1) 

The critical flaw is at lines 48 and 54, where `is_valid_proposer()` and `get_valid_proposer()` are called. These delegate to the underlying `ProposerElection` implementation without any validation that results are deterministic across nodes. [3](#0-2) 

When using `LeaderReputation` with `use_root_hash=true`, the proposer selection seed includes the database root hash: [4](#0-3) 

This root hash is derived from the local database's latest block events: [5](#0-4) 

The `get_latest_block_events()` call at line 78 queries the current database state, which varies across nodes based on commit progress, causing different nodes to compute different root hashes and thus different proposers. [6](#0-5) 

The `use_root_hash=true` configuration is the default for V2 and all modern deployments: [7](#0-6) [8](#0-7) 

When nodes disagree on the valid proposer:
- Node A computes Author X as valid proposer for round R (based on root_hash_A)
- Node B computes Author Y as valid proposer for round R (based on root_hash_B, where root_hash_A ≠ root_hash_B)
- Author X creates and broadcasts a proposal for round R
- Node A accepts it (matches expected proposer X)
- Node B rejects it (expects proposer Y, not X)

This is used in the consensus flow where nodes check if they should propose: [9](#0-8) 

And validate incoming proposals: [10](#0-9) 

## Impact Explanation

This is a **High Severity** vulnerability because it causes:

1. **Consensus Safety Violations**: Different nodes accept different blocks for the same round, violating the fundamental consensus invariant that all honest nodes must agree on the blockchain state.

2. **Liveness Failures**: Legitimate proposals from valid proposers are rejected by a subset of nodes, preventing the network from making progress. Rounds fail repeatedly as no proposal can achieve consensus.

3. **Network Fragmentation**: The network could split into factions based on which proposer each subset of nodes computed, requiring manual intervention or a hard fork to resolve.

According to the Aptos bug bounty criteria, this qualifies as "Significant protocol violations" under High Severity (up to $50,000), and potentially approaches Critical Severity due to consensus safety violations.

## Likelihood Explanation

This vulnerability has **HIGH likelihood** in production because:

1. **Default Configuration**: The `use_root_hash=true` setting is the default for all V2 configurations and DAG consensus
2. **Normal Operation**: Nodes naturally have slight database state differences due to network latency, block propagation delays, and processing speeds
3. **No Mitigation**: There are no safeguards in `UnequivocalProposerElection` to detect or prevent non-deterministic proposer selection
4. **Cached Results Persist**: Once a node caches a proposer for a round, it never recomputes, locking in the disagreement

The vulnerability triggers whenever:
- Nodes compute the proposer for round R at different times
- The database state (number of committed blocks) differs between those computations
- The resulting root hash difference causes `choose_index()` to select different validators

## Recommendation

**Immediate Fix**: Store the expected proposer author when accepting a proposal, and validate that duplicate proposals come from the same author:

```rust
pub struct UnequivocalProposerElection {
    proposer_election: Arc<dyn ProposerElection + Send + Sync>,
    already_proposed: Mutex<(Round, Author, HashValue)>, // Add Author
}

pub fn is_valid_proposal(&self, block: &Block) -> bool {
    block.author().is_some_and(|author| {
        let valid_author = self.is_valid_proposer(author, block.round());
        if !valid_author {
            warn!(...);
            return false;
        }
        let mut already_proposed = self.already_proposed.lock();
        match block.round().cmp(&already_proposed.0) {
            Ordering::Greater => {
                already_proposed.0 = block.round();
                already_proposed.1 = author; // Store author
                already_proposed.2 = block.id();
                true
            },
            Ordering::Equal => {
                // Validate author matches
                if already_proposed.1 != author {
                    error!("Different authors for same round: {} vs {}", 
                           already_proposed.1, author);
                    return false;
                }
                // Existing hash check
                if already_proposed.2 != block.id() { ... }
                true
            },
            Ordering::Less => false,
        }
    })
}
```

**Long-term Fix**: Make proposer election deterministic by either:
1. Using a committed ledger state (specific version) instead of "latest" for root hash computation
2. Including the root hash in the quorum certificate so all nodes use the same value
3. Defaulting to `use_root_hash=false` for V2 (predictable but secure with other randomness sources)

## Proof of Concept

```rust
// Simulation demonstrating the vulnerability
// This would be implemented as a consensus test with multiple validator nodes

// Setup: Two validator nodes with LeaderReputation (use_root_hash=true)

// Step 1: Node 1 has committed 1000 blocks (root_hash = H1)
let node1_db_state = MockDB::with_blocks(1000);
let node1_election = LeaderReputation::new(
    epoch, validators, voting_powers, 
    Arc::new(node1_db_state), heuristic,
    0, true, // use_root_hash=true
    100
);

// Step 2: Node 2 has committed 1001 blocks (root_hash = H2 ≠ H1)  
let node2_db_state = MockDB::with_blocks(1001);
let node2_election = LeaderReputation::new(
    epoch, validators, voting_powers,
    Arc::new(node2_db_state), heuristic,
    0, true, // use_root_hash=true
    100
);

// Step 3: Compute proposer for round R
let round = 100;
let proposer_node1 = node1_election.get_valid_proposer(round); // Returns Validator A
let proposer_node2 = node2_election.get_valid_proposer(round); // Returns Validator B

assert_ne!(proposer_node1, proposer_node2); // CONSENSUS DISAGREEMENT!

// Step 4: Validator A creates proposal
let proposal = create_proposal(proposer_node1, round, ...);

// Step 5: Validation diverges
let node1_wrapper = UnequivocalProposerElection::new(Arc::new(node1_election));
let node2_wrapper = UnequivocalProposerElection::new(Arc::new(node2_election));

assert!(node1_wrapper.is_valid_proposal(&proposal)); // Node 1 accepts
assert!(!node2_wrapper.is_valid_proposal(&proposal)); // Node 2 REJECTS

// Result: Consensus split - nodes disagree on valid proposal for same round
```

## Notes

This vulnerability demonstrates that wrapper security depends critically on the determinism guarantees of wrapped components. The `UnequivocalProposerElection` assumes its underlying `ProposerElection` produces consistent results across all nodes, but this assumption is violated by `LeaderReputation` when configured with `use_root_hash=true`. The caching in `CachedProposerElection` exacerbates the problem by permanently locking in the disagreement once computed. [11](#0-10) [12](#0-11)

### Citations

**File:** consensus/src/liveness/unequivocal_proposer_election.rs (L18-40)
```rust
pub struct UnequivocalProposerElection {
    proposer_election: Arc<dyn ProposerElection + Send + Sync>,
    already_proposed: Mutex<(Round, HashValue)>,
}

impl ProposerElection for UnequivocalProposerElection {
    fn get_valid_proposer(&self, round: Round) -> Author {
        self.proposer_election.get_valid_proposer(round)
    }

    fn get_voting_power_participation_ratio(&self, round: Round) -> f64 {
        self.proposer_election
            .get_voting_power_participation_ratio(round)
    }
}

impl UnequivocalProposerElection {
    pub fn new(proposer_election: Arc<dyn ProposerElection + Send + Sync>) -> Self {
        Self {
            proposer_election,
            already_proposed: Mutex::new((0, HashValue::zero())),
        }
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

**File:** consensus/src/liveness/proposer_election.rs (L10-16)
```rust
pub trait ProposerElection {
    /// If a given author is a valid candidate for being a proposer, generate the info,
    /// otherwise return None.
    /// Note that this function is synchronous.
    fn is_valid_proposer(&self, author: Author, round: Round) -> bool {
        self.get_valid_proposer(round) == author
    }
```

**File:** consensus/src/liveness/leader_reputation.rs (L70-101)
```rust
    fn refresh_db_result(
        &self,
        locked: &mut MutexGuard<'_, Option<(Vec<VersionedNewBlockEvent>, u64, bool)>>,
        latest_db_version: u64,
    ) -> Result<(Vec<VersionedNewBlockEvent>, u64, bool)> {
        // assumes target round is not too far from latest commit
        let limit = self.window_size + self.seek_len;

        let events = self.aptos_db.get_latest_block_events(limit)?;

        let max_returned_version = events.first().map_or(0, |first| first.transaction_version);

        let new_block_events = events
            .into_iter()
            .map(|event| {
                Ok(VersionedNewBlockEvent {
                    event: bcs::from_bytes::<NewBlockEvent>(event.event.event_data())?,
                    version: event.transaction_version,
                })
            })
            .collect::<Result<Vec<VersionedNewBlockEvent>, bcs::Error>>()?;

        let hit_end = new_block_events.len() < limit;

        let result = (
            new_block_events,
            std::cmp::max(latest_db_version, max_returned_version),
            hit_end,
        );
        **locked = Some(result.clone());
        Ok(result)
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

**File:** consensus/src/liveness/leader_reputation.rs (L717-733)
```rust
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

**File:** types/src/on_chain_config/consensus_config.rs (L527-550)
```rust
pub enum LeaderReputationType {
    // Proposer election based on whether nodes succeeded or failed
    // their proposer election rounds, and whether they voted.
    // Version 1:
    // * use reputation window from stale end
    // * simple (predictable) seed
    ProposerAndVoter(ProposerAndVoterConfig),
    // Version 2:
    // * use reputation window from recent end
    // * unpredictable seed, based on root hash
    ProposerAndVoterV2(ProposerAndVoterConfig),
}

impl LeaderReputationType {
    pub fn use_root_hash_for_seed(&self) -> bool {
        // all versions after V1 should use root hash
        !matches!(self, Self::ProposerAndVoter(_))
    }

    pub fn use_reputation_window_from_stale_end(&self) -> bool {
        // all versions after V1 shouldn't use from stale end
        matches!(self, Self::ProposerAndVoter(_))
    }
}
```

**File:** types/src/on_chain_config/consensus_config.rs (L590-608)
```rust
impl Default for DagConsensusConfigV1 {
    /// It is primarily used as `default_if_missing()`.
    fn default() -> Self {
        Self {
            dag_ordering_causal_history_window: 10,
            anchor_election_mode: AnchorElectionMode::LeaderReputation(
                LeaderReputationType::ProposerAndVoterV2(ProposerAndVoterConfig {
                    active_weight: 1000,
                    inactive_weight: 10,
                    failed_weight: 1,
                    failure_threshold_percent: 10,
                    proposer_window_num_validators_multiplier: 10,
                    voter_window_num_validators_multiplier: 1,
                    weight_by_voting_power: true,
                    use_history_from_previous_epoch_max_count: 5,
                }),
            ),
        }
    }
```

**File:** consensus/src/round_manager.rs (L420-447)
```rust
    async fn process_new_round_event(
        &mut self,
        new_round_event: NewRoundEvent,
    ) -> anyhow::Result<()> {
        let new_round = new_round_event.round;
        let is_current_proposer = self
            .proposer_election
            .is_valid_proposer(self.proposal_generator.author(), new_round);
        let prev_proposer = self
            .proposer_election
            .get_valid_proposer(new_round.saturating_sub(1));

        counters::CURRENT_ROUND.set(new_round_event.round as i64);
        counters::ROUND_TIMEOUT_MS.set(new_round_event.timeout.as_millis() as i64);
        match new_round_event.reason {
            NewRoundReason::QCReady => {
                counters::QC_ROUNDS_COUNT.inc();
            },
            NewRoundReason::Timeout(ref reason) => {
                counters::TIMEOUT_ROUNDS_COUNT.inc();
                counters::AGGREGATED_ROUND_TIMEOUT_REASON
                    .with_label_values(&[
                        &reason.to_string(),
                        prev_proposer.short_str().as_str(),
                        &is_current_proposer.to_string(),
                    ])
                    .inc();
                if is_current_proposer {
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

**File:** consensus/src/epoch_manager.rs (L378-394)
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
                // LeaderReputation is not cheap, so we can cache the amount of rounds round_manager needs.
                Arc::new(CachedProposerElection::new(
                    epoch_state.epoch,
                    proposer_election,
                    onchain_config.max_failed_authors_to_store()
                        + PROPOSER_ELECTION_CACHING_WINDOW_ADDITION,
                ))
```
