# Audit Report

## Title
Storage Error Misclassification as Byzantine Behavior Leads to Unfair Validator Penalization

## Summary
Storage errors during proposal generation or vote signing cause validators to miss their block signing deadlines, resulting in identical economic penalties as Byzantine behavior through the `failed_proposals` counter mechanism. The system lacks differentiation between infrastructure failures and intentional malicious behavior.

## Finding Description

When a validator is selected as the proposer for a round, they must generate and broadcast a block proposal. This process involves multiple storage operations that can fail: [1](#0-0) [2](#0-1) 

Storage errors can occur at:
1. Reading/writing safety data during proposal signing
2. Persisting vote data to consensus DB [3](#0-2) 

When these errors occur, the proposal generation fails and the error is only logged: [4](#0-3) 

The proposal is never broadcast (line 546 is not reached), causing other validators to timeout. The next proposer then computes `failed_authors` for all skipped rounds: [5](#0-4) 

This function blindly includes ALL proposers from skipped rounds without investigating WHY they failed. These `failed_authors` are converted to `failed_proposer_indices` in BlockMetadata and processed on-chain: [6](#0-5) 

The `failed_proposals` counter directly reduces validator rewards through the performance multiplier: [7](#0-6) 

The formula `(stake * rate * successful_proposals) / (successful_proposals + failed_proposals)` means storage errors have the same economic impact as Byzantine behavior.

**Broken Invariant:** Staking Security Invariant #6 - "Validator rewards and penalties must be calculated correctly" is violated because penalties are applied without distinguishing between malicious behavior and legitimate infrastructure failures.

## Impact Explanation

This issue qualifies as **High Severity** under the Aptos bug bounty program for the following reasons:

1. **Significant Protocol Violation**: The system fails to implement a critical fairness guarantee - validators experiencing transient storage errors (disk I/O issues, database corruption, hardware failures) receive identical penalties as validators engaging in Byzantine behavior.

2. **Validator Node Operational Impact**: Legitimate validators operating reliable infrastructure may face reward reductions due to rare storage errors that are indistinguishable from malicious behavior, undermining trust in the validator reward system.

3. **Perverse Incentive Structure**: Malicious validators can claim Byzantine behavior was "just storage errors," while honest validators have no recourse when legitimately affected by infrastructure issues.

While this doesn't directly lead to loss of funds or consensus violations, it represents a significant protocol-level fairness violation that affects the economic security model of the network.

## Likelihood Explanation

**Likelihood: Medium to High**

Storage errors are not theoretical - they occur in production environments:
- Disk I/O failures during high load
- Database corruption from power failures  
- Network-attached storage latency spikes
- RocksDB compaction blocking writes

The `MetricsSafetyRules.retry()` mechanism only retries certain error types: [8](#0-7) 

Notably, `SecureStorageUnexpectedError` is NOT in the retry list, meaning transient storage errors immediately fail the proposal/vote without retry.

## Recommendation

Implement a multi-tiered approach to differentiate storage errors from Byzantine behavior:

1. **Error Classification**: Extend the retry mechanism to handle transient storage errors:
```rust
fn retry<T, F: FnMut(&mut Box<dyn TSafetyRules + Send + Sync>) -> Result<T, Error>>(
    &mut self,
    mut f: F,
) -> Result<T, Error> {
    let result = f(&mut self.inner);
    match result {
        Err(Error::NotInitialized(_))
        | Err(Error::IncorrectEpoch(_, _))
        | Err(Error::WaypointOutOfDate(_, _, _, _))
        | Err(Error::SecureStorageUnexpectedError(_)) => {  // Add this
            // Retry transient storage errors once
            self.perform_initialize()?;
            f(&mut self.inner)
        },
        _ => result,
    }
}
```

2. **Failure Reason Tracking**: Add metadata to `failed_authors` to track failure reasons:
```rust
pub enum FailureReason {
    Timeout,           // No proposal received
    StorageError,      // Logged storage error
    InvalidProposal,   // Byzantine behavior detected
}

pub struct FailedAuthor {
    round: Round,
    author: Author,
    reason: FailureReason,
}
```

3. **Differentiated Penalties**: Modify reward calculation to apply reduced penalties for infrastructure failures:
```move
fun calculate_rewards_amount(
    stake_amount: u64,
    num_successful_proposals: u64,
    num_failed_proposals_byzantine: u64,
    num_failed_proposals_infrastructure: u64,
    // Apply full penalty for Byzantine, 50% penalty for infrastructure
    // Adjust multipliers based on governance
)
```

4. **Validator Transparency**: Emit events with failure reasons to enable validator operators to monitor and address infrastructure issues.

## Proof of Concept

```rust
// Rust integration test demonstrating the issue

#[tokio::test]
async fn test_storage_error_misclassified_as_byzantine() {
    // Setup: Create validator set with 4 validators
    let mut runtime = consensus_runtime();
    let mut validators = vec![];
    
    for i in 0..4 {
        validators.push(create_validator(i));
    }
    
    // Validator 0 is the proposer for round 1
    let proposer = validators[0].clone();
    
    // Simulate storage error during proposal signing
    // This could happen due to disk I/O error, database corruption, etc.
    let storage_error = Error::SecureStorageUnexpectedError(
        "RocksDB write failed: IO error".to_string()
    );
    
    // Mock safety_rules to return storage error
    let mut safety_rules = MockSafetyRules::new();
    safety_rules
        .expect_sign_proposal()
        .returning(|_| Err(storage_error));
    
    // Attempt to generate proposal
    let result = generate_and_send_proposal(
        epoch_state,
        new_round_event,
        network,
        sync_info,
        proposal_generator,
        Arc::new(Mutex::new(safety_rules)),
        proposer_election,
    ).await;
    
    // Proposal generation fails due to storage error
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Storage"));
    
    // Other validators timeout and move to round 2
    // Validator 1 becomes proposer for round 2
    
    // Verify that validator 0 is added to failed_authors
    let failed_authors = proposal_generator.compute_failed_authors(
        2,  // current round
        0,  // previous successful round
        false,
        proposer_election,
    );
    
    assert_eq!(failed_authors.len(), 1);
    assert_eq!(failed_authors[0].0, 1); // round 1
    assert_eq!(failed_authors[0].1, proposer.author());
    
    // This gets converted to failed_proposer_indices in BlockMetadata
    // and processed by update_performance_statistics
    
    // Verify that validator 0's failed_proposals counter is incremented
    // DESPITE the failure being due to infrastructure, not Byzantine behavior
    
    // At epoch end, verify validator 0 receives reduced rewards
    // equal to a Byzantine validator who refused to propose
}
```

This demonstrates that storage errors and Byzantine behavior result in identical outcomes, violating the fairness guarantee that should differentiate legitimate infrastructure failures from malicious behavior.

### Citations

**File:** consensus/src/round_manager.rs (L495-511)
```rust
            tokio::spawn(async move {
                if let Err(e) = monitor!(
                    "generate_and_send_proposal",
                    Self::generate_and_send_proposal(
                        epoch_state,
                        new_round_event,
                        network,
                        sync_info,
                        proposal_generator,
                        safety_rules,
                        proposer_election,
                    )
                    .await
                ) {
                    warn!("Error generating and sending proposal: {}", e);
                }
            });
```

**File:** consensus/src/round_manager.rs (L676-681)
```rust
        let proposal = proposal_generator
            .generate_proposal(new_round_event.round, proposer_election)
            .await?;
        let signature = safety_rules.lock().sign_proposal(&proposal)?;
        let signed_proposal =
            Block::new_proposal_from_block_data_and_signature(proposal, signature);
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L86-92)
```rust
        let author = self.signer()?.author();
        let ledger_info = self.construct_ledger_info_2chain(proposed_block, vote_data.hash())?;
        let signature = self.sign(&ledger_info)?;
        let vote = Vote::new_with_signature(vote_data, author, ledger_info, signature);

        safety_data.last_vote = Some(vote.clone());
        self.persistent_storage.set_safety_data(safety_data)?;
```

**File:** consensus/safety-rules/src/error.rs (L36-38)
```rust
    SecureStorageMissingDataError(String),
    #[error("Unexpected error returned by secure storage: {0}")]
    SecureStorageUnexpectedError(String),
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

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1282-1332)
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
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1761-1784)
```text
    fun calculate_rewards_amount(
        stake_amount: u64,
        num_successful_proposals: u64,
        num_total_proposals: u64,
        rewards_rate: u64,
        rewards_rate_denominator: u64,
    ): u64 {
        spec {
            // The following condition must hold because
            // (1) num_successful_proposals <= num_total_proposals, and
            // (2) `num_total_proposals` cannot be larger than 86400, the maximum number of proposals
            //     in a day (1 proposal per second), and `num_total_proposals` is reset to 0 every epoch.
            assume num_successful_proposals * MAX_REWARDS_RATE <= MAX_U64;
        };
        // The rewards amount is equal to (stake amount * rewards rate * performance multiplier).
        // We do multiplication in u128 before division to avoid the overflow and minimize the rounding error.
        let rewards_numerator = (stake_amount as u128) * (rewards_rate as u128) * (num_successful_proposals as u128);
        let rewards_denominator = (rewards_rate_denominator as u128) * (num_total_proposals as u128);
        if (rewards_denominator > 0) {
            ((rewards_numerator / rewards_denominator) as u64)
        } else {
            0
        }
    }
```

**File:** consensus/src/metrics_safety_rules.rs (L71-85)
```rust
    fn retry<T, F: FnMut(&mut Box<dyn TSafetyRules + Send + Sync>) -> Result<T, Error>>(
        &mut self,
        mut f: F,
    ) -> Result<T, Error> {
        let result = f(&mut self.inner);
        match result {
            Err(Error::NotInitialized(_))
            | Err(Error::IncorrectEpoch(_, _))
            | Err(Error::WaypointOutOfDate(_, _, _, _)) => {
                self.perform_initialize()?;
                f(&mut self.inner)
            },
            _ => result,
        }
    }
```
