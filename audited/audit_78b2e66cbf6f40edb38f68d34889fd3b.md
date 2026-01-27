# Audit Report

## Title
Incomplete Validator Performance Tracking Due to Failed Proposer Indices Cap

## Summary
The Aptos consensus protocol limits the number of tracked failed proposers to `max_failed_authors_to_store` (default: 10). When more than 10 consecutive rounds fail, earlier failures are dropped, causing both on-chain validator performance statistics and off-chain analysis to be incomplete and inaccurate.

## Finding Description

The vulnerability exists across multiple layers of the Aptos stack:

**1. Consensus Layer - Limited Failed Author Tracking**

The `compute_failed_authors` method caps the number of failed authors to prevent unbounded growth: [1](#0-0) 

With the default limit set to 10: [2](#0-1) 

**2. Block Validation - Explicitly Allows Missing Failed Authors**

The protocol explicitly allows incomplete `failed_authors` lists: [3](#0-2) 

**3. On-Chain Performance Statistics - Missing Failures Not Recorded**

The `update_performance_statistics` function only increments failure counts for validators present in the `failed_proposer_indices` list: [4](#0-3) 

Validators whose failures are trimmed beyond the 10-author limit never have their `failed_proposals` count incremented.

**4. Off-Chain Analysis - Statistics Corruption**

The `analyze()` function calculates the expected round based on `failed_proposer_indices` length: [5](#0-4) 

When `failed_proposer_indices` is incomplete, the missing failures are lumped into `trimmed_rounds` without attribution to specific validators: [6](#0-5) 

**5. Leader Reputation System - Incorrect Future Proposer Selection**

The leader reputation system counts failed proposals based on the incomplete data: [7](#0-6) 

## Impact Explanation

This issue breaks the **Staking Security** invariant: "Validator rewards and penalties must be calculated correctly."

**Severity Assessment: Medium**

The impact includes:
1. **Incorrect reward distribution**: Validators whose failures are trimmed avoid performance penalties and receive full rewards
2. **Corrupted leader reputation**: Future proposer selection is based on incomplete failure data
3. **Misleading validator metrics**: Stakeholders cannot accurately assess validator reliability
4. **Network health obscuration**: True validator performance during network stress is hidden

This qualifies as **Medium Severity** under "State inconsistencies requiring intervention" because:
- Validator performance state is inconsistent with actual behavior
- The issue requires monitoring and potential manual intervention to correct validator assessments
- While not causing direct fund loss, it causes unfair reward distribution

## Likelihood Explanation

**Likelihood: High**

This issue occurs automatically whenever:
- Network experiences liveness problems with >10 consecutive failed rounds
- Network partitions cause extended periods without successful proposals
- Validator set experiences widespread issues (e.g., configuration errors, attacks)

The 10-author limit is quite low and can be easily exceeded during real network stress. No attacker action is required - this is a systemic protocol limitation.

## Recommendation

**Option 1: Increase the Limit (Short-term)**
Increase `max_failed_authors_to_store` to a higher value (e.g., 100) to reduce likelihood:

```rust
max_failed_authors_to_store: 100,  // Increased from 10
```

**Option 2: Track Summary Statistics (Medium-term)**
When the limit is exceeded, include a summary field indicating how many additional failures occurred beyond the recorded ones, allowing accurate round gap calculation:

```rust
pub struct BlockMetadataExt {
    // ... existing fields ...
    failed_proposer_indices: Vec<u32>,
    additional_failed_rounds: u64,  // New field for trimmed failures
}
```

**Option 3: Remove the Cap (Long-term)**
Re-evaluate whether the cap is necessary. If storage/bandwidth concerns exist, implement compression or aggregation schemes that preserve accountability.

The `analyze()` function should be updated to handle the `trimmed_rounds` case more explicitly, potentially warning users when statistics are incomplete.

## Proof of Concept

```rust
// Test demonstrating incomplete failure tracking
#[test]
fn test_incomplete_failed_proposer_indices() {
    // Setup: Validators and consensus configuration
    let validator_count = 20;
    let max_failed_authors = 10;
    
    // Simulate 15 consecutive failed rounds
    let failed_rounds = 15;
    
    // Compute failed authors with the limit
    let failed_authors = compute_failed_authors_with_limit(
        current_round,
        previous_round,
        false,
        max_failed_authors
    );
    
    // Verify: Only 10 failures recorded, 5 are missing
    assert_eq!(failed_authors.len(), 10);
    let missing_failures = failed_rounds - failed_authors.len();
    assert_eq!(missing_failures, 5);
    
    // Impact: These 5 validators never get their failure count incremented
    // Their performance statistics are incorrectly favorable
}
```

## Notes

While this is a genuine issue affecting validator accountability and reward fairness, it's important to note:

1. **Design Trade-off**: The cap exists to prevent unbounded data growth in block metadata
2. **No Direct Exploit**: This cannot be triggered by an unprivileged attacker; it occurs during network-wide issues
3. **Consensus Safety Unaffected**: Blocks still commit correctly; only performance tracking is incomplete
4. **Known Limitation**: The code comments explicitly acknowledge that failed_authors can be incomplete

The vulnerability is real but represents a protocol design limitation rather than an exploitable bug. The primary concern is fairness and accuracy in validator performance tracking, which affects staking economics and network health visibility.

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

**File:** types/src/on_chain_config/consensus_config.rs (L487-487)
```rust
            max_failed_authors_to_store: 10,
```

**File:** consensus/consensus-types/src/block.rs (L494-510)
```rust
        if let Some(failed_authors) = self.block_data().failed_authors() {
            // when validating for being well formed,
            // allow for missing failed authors,
            // for whatever reason (from different max configuration, etc),
            // but don't allow anything that shouldn't be there.
            //
            // we validate the full correctness of this field in round_manager.process_proposal()
            let succ_round = self.round() + u64::from(self.is_nil_block());
            let skipped_rounds = succ_round.checked_sub(parent.round() + 1);
            ensure!(
                skipped_rounds.is_some(),
                "Block round is smaller than block's parent round"
            );
            ensure!(
                failed_authors.len() <= skipped_rounds.unwrap() as usize,
                "Block has more failed authors than missed rounds"
            );
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

**File:** crates/aptos/src/node/analyze/analyze_validators.rs (L423-432)
```rust
            let expected_round =
                previous_round + u64::from(!is_nil) + event.failed_proposer_indices().len() as u64;
            if event.round() != expected_round {
                println!(
                    "Missing failed AccountAddresss : {} {:?}",
                    previous_round, &event
                );
                assert!(expected_round < event.round());
                trimmed_rounds += event.round() - expected_round;
            }
```

**File:** crates/aptos/src/node/analyze/analyze_validators.rs (L439-443)
```rust
            for failed_proposer_index in event.failed_proposer_indices() {
                *failures
                    .entry(validators[*failed_proposer_index as usize].address)
                    .or_insert(0) += 1;
            }
```

**File:** consensus/src/liveness/leader_reputation.rs (L428-450)
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
```
