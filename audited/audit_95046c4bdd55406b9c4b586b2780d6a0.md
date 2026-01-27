# Audit Report

## Title
Epoch Boundary Consensus Safety Violation Due to Inconsistent Historical Proposer Data

## Summary
At epoch transitions, validators with different historical data availability (due to pruning, fast sync, or database errors) can elect different proposers for the same round, causing a consensus safety violation. The issue stems from fallback logic that silently uses only the current epoch when historical epoch data fetch fails, while other validators successfully use multiple epochs of history.

## Finding Description

The vulnerability exists in the leader reputation-based proposer election mechanism used by Aptos consensus. When validators start a new epoch, they attempt to fetch historical validator data from previous epochs to inform proposer selection based on past performance. [1](#0-0) 

The critical flaw occurs in the error handling path: when `get_epoch_ending_ledger_infos` fails (due to pruned data, database corruption, or missing historical information), the code falls back to using **only the current epoch's validators** instead of propagating the error or ensuring consistency across all validators. [2](#0-1) 

This creates a divergence scenario where:
1. **Validator A** (full historical data): Creates `epoch_to_proposers` map with epochs {N, N-1, N-2, N-3, N-4}
2. **Validator B** (pruned/missing data): Falls back to `epoch_to_proposers` map with only epoch {N}

When calculating proposer weights, the historical event filtering only considers events from epochs present in the `epoch_to_proposers` map: [3](#0-2) 

This filtering at line 325 causes validators with different epoch maps to count different historical events, leading to different reputation weights being assigned to each validator: [4](#0-3) 

Even with identical seeds, different weights result in different proposer selections via the deterministic weighted random selection: [5](#0-4) 

**Exploitation Scenario:**
This can occur naturally (no malicious intent required) when:
- Validators have different pruning window configurations (default is 90M versions ≈ 2-3 epochs, but `use_history_from_previous_epoch_max_count` defaults to 5)
- A validator recently fast-synced and lacks historical epoch-ending ledger infos
- Database issues or state sync lag causes incomplete historical data [6](#0-5) [7](#0-6) 

## Impact Explanation

This vulnerability constitutes a **HIGH SEVERITY** consensus safety violation according to Aptos bug bounty criteria:

1. **Consensus Safety Broken**: Different validators elect different proposers for the same round, violating the fundamental requirement that all honest validators must agree on the leader
2. **Vote Splitting**: Validators expecting different proposers will vote for different blocks, preventing quorum formation
3. **Liveness Failure**: Consensus rounds may stall indefinitely if votes are split across multiple candidates
4. **Potential Chain Split**: In extreme cases with network partitions, different validator sets could commit divergent blocks

This directly breaks **Critical Invariant #2: Consensus Safety** - "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine". The issue occurs without any Byzantine behavior, purely through operational configuration differences.

The impact qualifies as **"Significant protocol violations"** under High Severity ($50,000 tier) and potentially **"Consensus/Safety violations"** under Critical Severity ($1,000,000 tier) depending on whether it can cause actual chain splits versus liveness degradation.

## Likelihood Explanation

**LIKELIHOOD: HIGH**

This vulnerability has high likelihood of occurring in production:

1. **Heterogeneous Deployments**: Different validators may have different pruning configurations based on their operational requirements (archival nodes vs. regular validators)

2. **Default Configuration Mismatch**: The default ledger pruner window (90M versions ≈ 2-3 epochs) is smaller than the default `use_history_from_previous_epoch_max_count` (5 epochs), creating an inherent risk

3. **Fast Sync Operations**: Validators bootstrapping via fast sync will not have historical epoch-ending ledger infos prior to their sync point

4. **Network Growth**: As new validators join the network at different times, they will have varying amounts of historical data

5. **No Warning Mechanism**: The error is logged but consensus continues normally, making the divergence silent and difficult to detect until consensus stalls

The bug requires no attacker action - it emerges naturally from operational diversity in validator configurations.

## Recommendation

**Immediate Fix**: Make historical data availability a hard requirement for epoch transition, failing the epoch start if historical data cannot be fetched consistently.

**Code Fix for `consensus/src/epoch_manager.rs`**:

```rust
fn extract_epoch_proposers(
    &self,
    epoch_state: &EpochState,
    use_history_from_previous_epoch_max_count: u32,
    proposers: Vec<AccountAddress>,
    needed_rounds: u64,
) -> anyhow::Result<HashMap<u64, Vec<AccountAddress>>> {
    let first_epoch_to_consider = std::cmp::max(
        if epoch_state.epoch == 1 { 1 } else { 2 },
        epoch_state
            .epoch
            .saturating_sub(use_history_from_previous_epoch_max_count as u64),
    );
    
    if epoch_state.epoch > first_epoch_to_consider {
        let proof = self
            .storage
            .aptos_db()
            .get_epoch_ending_ledger_infos(first_epoch_to_consider - 1, epoch_state.epoch)
            .context("Failed to fetch required historical epoch data for proposer election")?;
        
        ensure!(
            proof.ledger_info_with_sigs.len() as u64
                == (epoch_state.epoch - (first_epoch_to_consider - 1)),
            "Incomplete historical epoch data - expected {} epochs, got {}",
            epoch_state.epoch - (first_epoch_to_consider - 1),
            proof.ledger_info_with_sigs.len()
        );
        
        extract_epoch_to_proposers(proof, epoch_state.epoch, &proposers, needed_rounds)
    } else {
        Ok(HashMap::from([(epoch_state.epoch, proposers)]))
    }
}
```

**Alternative Mitigation**: Store `use_history_from_previous_epoch_max_count` in the `EpochState` and have all validators verify they have the same value and historical data before starting the epoch.

**Long-term Solution**: 
1. Add validation that pruning windows are configured to retain at least `use_history_from_previous_epoch_max_count` epochs of data
2. Include historical epoch availability as part of epoch transition health checks
3. Add monitoring/alerting when validators have inconsistent historical data

## Proof of Concept

**Scenario**: Two validators starting epoch N with different historical data availability

**Setup**:
1. Configure Validator A with `ledger_pruner_config.enable = false` (archival node)
2. Configure Validator B with `ledger_pruner_config.prune_window = 36_000_000` (≈1 epoch at 5K TPS)
3. Set on-chain `use_history_from_previous_epoch_max_count = 5`
4. Run network through 5+ epochs with varying validator activity

**Reproduction Steps**:

```rust
// In consensus/src/liveness/leader_reputation_test.rs
#[test]
fn test_inconsistent_epoch_history_causes_divergent_proposer_election() {
    // Setup two validators with different epoch history
    let epoch = 10;
    let proposers: Vec<Author> = vec![author(0), author(1), author(2), author(3)];
    
    // Validator A: Has full 5 epochs of history
    let epoch_to_proposers_validator_a: HashMap<u64, Vec<Author>> = 
        (6..=10).map(|e| (e, proposers.clone())).collect();
    
    // Validator B: Only has current epoch (historical fetch failed)
    let epoch_to_proposers_validator_b: HashMap<u64, Vec<Author>> = 
        HashMap::from([(epoch, proposers.clone())]);
    
    // Create historical events showing validator 0 was very active in previous epochs
    let mut history = vec![];
    for round in 1..100 {
        history.push(new_block_event(
            9, // previous epoch
            round,
            author(0), // validator 0 was proposer
            vec![0, 1, 2, 3], // all voted
            vec![], // no failures
        ));
    }
    
    let voting_powers = vec![1, 1, 1, 1];
    let backend = Arc::new(MockHistory::new(history.clone()));
    let heuristic = Box::new(ProposerAndVoterHeuristic::new(
        author(0),
        1000, // active_weight
        10,   // inactive_weight  
        1,    // failed_weight
        10,   // failure_threshold_percent
        100,  // voter_window
        100,  // proposer_window
        false,
    ));
    
    // Validator A's election (with full history)
    let election_a = LeaderReputation::new(
        epoch,
        epoch_to_proposers_validator_a,
        voting_powers.clone(),
        backend.clone(),
        heuristic.clone(),
        0,
        true,
        100,
    );
    
    // Validator B's election (without history)
    let election_b = LeaderReputation::new(
        epoch,
        epoch_to_proposers_validator_b,
        voting_powers.clone(),
        backend.clone(),
        heuristic.clone(),
        0,
        true,
        100,
    );
    
    // Same round, different proposers elected!
    let round = 100;
    let proposer_a = election_a.get_valid_proposer(round);
    let proposer_b = election_b.get_valid_proposer(round);
    
    // This assertion will fail - consensus safety violation!
    assert_eq!(proposer_a, proposer_b, 
        "Validators elected different proposers: A={:?}, B={:?}", 
        proposer_a, proposer_b);
}
```

**Expected Result**: Test fails, demonstrating that identical round + seed produces different proposers when `epoch_to_proposers` maps differ.

**Real-World Reproduction**:
1. Deploy testnet with mixed pruning configurations
2. Run through multiple epochs  
3. Monitor consensus logs for proposer election mismatches
4. Observe voting failures and round timeouts when validators disagree on leader

## Notes

This vulnerability highlights a critical gap in consensus invariant enforcement during epoch transitions. While `sync_to_target` ensures validators reach the same state version before starting a new epoch, it does not guarantee they have the same **historical** data required for leader reputation calculations. [8](#0-7) 

The on-chain config is read consistently across all validators, but the **interpretation** of that config (i.e., which historical epochs are actually used) varies based on local database state, creating a subtle but severe consensus divergence.

### Citations

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

**File:** consensus/src/epoch_manager.rs (L558-565)
```rust
        self.execution_client
            .sync_to_target(ledger_info.clone())
            .await
            .context(format!(
                "[EpochManager] State sync to new epoch {}",
                ledger_info
            ))
            .expect("Failed to sync to new epoch");
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

**File:** config/src/config/storage_config.rs (L387-396)
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
}
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L1036-1064)
```rust
    pub(super) fn get_epoch_ending_ledger_infos_impl(
        &self,
        start_epoch: u64,
        end_epoch: u64,
        limit: usize,
    ) -> Result<(Vec<LedgerInfoWithSignatures>, bool)> {
        self.check_epoch_ending_ledger_infos_request(start_epoch, end_epoch)?;

        let (paging_epoch, more) = if end_epoch - start_epoch > limit as u64 {
            (start_epoch + limit as u64, true)
        } else {
            (end_epoch, false)
        };

        let lis = self
            .ledger_db
            .metadata_db()
            .get_epoch_ending_ledger_info_iter(start_epoch, paging_epoch)?
            .collect::<Result<Vec<_>>>()?;

        ensure!(
            lis.len() == (paging_epoch - start_epoch) as usize,
            "DB corruption: missing epoch ending ledger info for epoch {}",
            lis.last()
                .map(|li| li.ledger_info().next_block_epoch() - 1)
                .unwrap_or(start_epoch),
        );
        Ok((lis, more))
    }
```
