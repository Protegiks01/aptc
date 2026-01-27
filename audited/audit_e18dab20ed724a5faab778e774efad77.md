# Audit Report

## Title
Voting Participation Threshold Not Enforced: Validators Can Freeride on Rewards Without Contributing to Consensus Security

## Summary
The 30% voting participation threshold defined in `is_voting_enough()` is only used for monitoring/analysis and is not enforced in validator reward distribution or removal logic. Validators can vote minimally (or not at all) while still receiving full rewards as long as they successfully propose blocks, creating a misalignment between expected and actual behavior that degrades network resilience. [1](#0-0) 

## Finding Description
The Aptos staking system contains a critical design flaw in how validator performance is tracked and rewarded:

**1. The Monitoring Threshold Has No Enforcement**

The `is_voting_enough()` function checks if a validator votes in more than 30% of rounds, but this check is only used to determine `NodeState` for reporting purposes. [2](#0-1) 

**2. Rewards Are Based Only on Proposals, Not Votes**

Validator rewards are calculated using only `successful_proposals` and `failed_proposals`, with no consideration of voting participation: [3](#0-2) [4](#0-3) 

**3. Performance Tracking Excludes Voting**

The `update_performance_statistics()` function only tracks proposals, not votes: [5](#0-4) 

**4. No Automatic Removal for Low Voting**

Validators are only removed if their stake drops below the minimum, not for low participation: [6](#0-5) 

**Attack Path:**
1. A rational validator configures their node to minimize voting (vote rarely or not at all)
2. They continue proposing blocks successfully when selected as leader
3. They receive full rewards based on their successful proposals
4. Their voting power counts toward the total, but they don't contribute to forming quorum certificates
5. If enough validators adopt this strategy, effective voting power participation drops
6. Network Byzantine fault tolerance is reduced from f=33% to potentially much lower

## Impact Explanation
This vulnerability represents a **Medium severity** issue because it creates state inconsistencies that could require intervention:

- **Network Resilience Degradation**: If validators representing significant voting power (e.g., 40%) adopt this strategy, the effective participation drops to 60%, reducing the practical Byzantine fault tolerance from f=33% to approximately f=10%.

- **Liveness Risk**: If active voting power drops below the 2/3+1 quorum threshold due to widespread freeloading, consensus halts completely, requiring emergency intervention.

- **Incentive Misalignment**: Validators are economically incentivized to minimize resource usage (voting) while maximizing rewards (proposing), directly contradicting the security assumptions of BFT consensus.

While this doesn't immediately result in fund loss or safety violations, it undermines the fundamental security model of the network and could lead to catastrophic liveness failures if widely adopted.

## Likelihood Explanation
**Likelihood: Medium to High**

The attack is highly likely because:
1. **No technical barriers**: Any validator can simply configure their node to vote minimally
2. **Economic incentive**: Validators save computational resources and network bandwidth by not voting
3. **No detection or penalty**: The current system has no enforcement mechanism
4. **Rational behavior**: This is optimal strategy from an individual validator's perspective (tragedy of the commons)

The only barrier is that validator operators may not realize this optimization is possible, but once discovered, rational economic actors would adopt it.

## Recommendation

**Short-term fix**: Add voting participation to reward calculations:

```move
// In calculate_rewards_amount function in stake.move
fun calculate_rewards_amount(
    stake_amount: u64,
    num_successful_proposals: u64,
    num_total_proposals: u64,
    num_votes: u64,  // Add this parameter
    num_rounds: u64,  // Add this parameter
    rewards_rate: u64,
    rewards_rate_denominator: u64,
): u64 {
    // Calculate voting participation factor (0-100)
    let voting_participation = if (num_rounds > 0) {
        min((num_votes * 100) / num_rounds, 100)
    } else {
        100
    };
    
    // Reduce rewards if voting participation < 30%
    let voting_multiplier = if (voting_participation < 30) {
        voting_participation * 10000 / 30  // Linear reduction below 30%
    } else {
        10000  // Full rewards at 30% or above
    };
    
    let rewards_numerator = (stake_amount as u128) * (rewards_rate as u128) * 
                           (num_successful_proposals as u128) * (voting_multiplier as u128);
    let rewards_denominator = (rewards_rate_denominator as u128) * 
                             (num_total_proposals as u128) * 10000;
    
    if (rewards_denominator > 0) {
        ((rewards_numerator / rewards_denominator) as u64)
    } else {
        0
    }
}
```

**Long-term fix**: Track voting in `IndividualValidatorPerformance` and modify `update_performance_statistics()` to record votes from `previous_block_votes_bitvec`.

## Proof of Concept

```move
#[test(aptos_framework = @0x1, validator = @0x123)]
public fun test_validator_gets_rewards_without_voting(
    aptos_framework: &signer,
    validator: &signer,
) acquires ValidatorPerformance, StakePool, ValidatorConfig {
    // Setup validator with 100 stake
    initialize_test_validator(validator, 100);
    
    // Simulate an epoch where validator:
    // - Proposes 10 successful blocks (gets counted)
    // - Votes 0 times (not counted in rewards)
    let validator_index = 0;
    let perf = borrow_global_mut<ValidatorPerformance>(@aptos_framework);
    perf.validators[validator_index].successful_proposals = 10;
    perf.validators[validator_index].failed_proposals = 0;
    
    // Trigger epoch end and reward distribution
    on_new_epoch();
    
    // Validator receives FULL rewards despite 0% voting participation
    let (active_stake, _, _, _) = get_stake(@0x123);
    assert!(active_stake > 100, 0); // Stake increased from rewards
    
    // This demonstrates the vulnerability: rewards without voting
}
```

## Notes

The vulnerability stems from a fundamental disconnect between the monitoring layer (which tracks voting and defines a 30% threshold) and the enforcement layer (which only considers proposals for rewards). The `is_voting_enough()` function in the analysis tool creates a false impression that voting participation matters, when in reality it has zero impact on validator economics. This represents a violation of the **"Staking Security: Validator rewards and penalties must be calculated correctly"** invariant, as the current calculation fails to account for a critical aspect of validator duty (voting) that is essential for consensus security.

### Citations

**File:** crates/aptos/src/node/analyze/analyze_validators.rs (L49-52)
```rust
    // Whether node is voting well enough
    pub fn is_voting_enough(&self, rounds: u32) -> bool {
        self.votes as f32 > rounds as f32 * 0.3
    }
```

**File:** crates/aptos/src/node/analyze/analyze_validators.rs (L152-171)
```rust
    pub fn to_state(&self, validator: &AccountAddress) -> NodeState {
        self.validator_stats
            .get(validator)
            .map(|b| {
                if b.is_reliable() {
                    if b.is_voting_enough(self.total_rounds) {
                        NodeState::Reliable
                    } else {
                        NodeState::ReliableLowVotes
                    }
                } else if b.proposal_successes > 0 {
                    NodeState::AliveUnreliable
                } else if b.votes > 0 {
                    NodeState::OnlyVoting
                } else {
                    NodeState::NotParticipatingInConsensus
                }
            })
            .unwrap_or(NodeState::Absent)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1280-1332)
```text
    /// Update the validator performance (proposal statistics). This is only called by block::prologue().
    /// This function cannot abort.
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

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1390-1398)
```text
            // A validator needs at least the min stake required to join the validator set.
            if (new_validator_info.voting_power >= minimum_stake) {
                spec {
                    assume total_voting_power + new_validator_info.voting_power <= MAX_U128;
                };
                total_voting_power = total_voting_power + (new_validator_info.voting_power as u128);
                vector::push_back(&mut next_epoch_validators, new_validator_info);
            };
            i = i + 1;
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1760-1784)
```text
    /// Calculate the rewards amount.
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

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1787-1812)
```text
    fun distribute_rewards(
        stake: &mut Coin<AptosCoin>,
        num_successful_proposals: u64,
        num_total_proposals: u64,
        rewards_rate: u64,
        rewards_rate_denominator: u64,
    ): u64 acquires AptosCoinCapabilities {
        let stake_amount = coin::value(stake);
        let rewards_amount = if (stake_amount > 0) {
            calculate_rewards_amount(
                stake_amount,
                num_successful_proposals,
                num_total_proposals,
                rewards_rate,
                rewards_rate_denominator
            )
        } else {
            0
        };
        if (rewards_amount > 0) {
            let mint_cap = &borrow_global<AptosCoinCapabilities>(@aptos_framework).mint_cap;
            let rewards = coin::mint(rewards_amount, mint_cap);
            coin::merge(stake, rewards);
        };
        rewards_amount
    }
```
