# Audit Report

## Title
Division by Zero Panic in Proposer Election with Empty Validator Set Causes Total Network Halt

## Summary
The `choose_index()` function in `consensus/src/liveness/proposer_election.rs` performs an unchecked modulo operation with zero when the weights vector is empty, causing a panic. This occurs when the validator set becomes empty during epoch transitions, leading to complete consensus failure requiring a hard fork to recover.

## Finding Description

The `choose_index()` function performs weighted random selection for proposer election by computing `next_in_range(state, total_weight)`, where `total_weight` is the sum of all validator weights. [1](#0-0) 

When the weights vector is empty:
1. The for loop doesn't execute, leaving `total_weight = 0`
2. `next_in_range(state, 0)` is called
3. Inside `next_in_range()`, the function performs `u128::from_le_bytes(temp) % 0` [2](#0-1) 

This division by zero causes a Rust panic, crashing the consensus node.

The vulnerability is triggered when `LeaderReputation::get_valid_proposer_and_voting_power_participation_ratio()` calls `choose_index()` with empty `stake_weights`: [3](#0-2) 

The `stake_weights` vector derives from the validator set. An empty validator set is possible when all validators are filtered out during `on_new_epoch()` if their stake falls below `minimum_stake`: [4](#0-3) 

Critically, there is **no check** that `next_epoch_validators` is non-empty before assignment. The `LeaderReputation` constructor only validates equal lengths, not non-empty validators: [5](#0-4) 

Furthermore, `EpochState::empty()` explicitly supports empty validator sets: [6](#0-5) 

And `ValidatorVerifier::new()` accepts empty validator lists: [7](#0-6) 

## Impact Explanation

**Critical Severity** - This vulnerability causes **Total loss of liveness/network availability** requiring a hard fork to recover.

When the panic occurs:
- All validator nodes attempting to select a proposer for the next round will crash
- No new blocks can be produced
- The consensus protocol completely halts
- The network becomes permanently unavailable until validators are manually added through emergency intervention (hard fork)

This breaks the fundamental consensus invariant: **Consensus Safety - AptosBFT must prevent chain splits under < 1/3 Byzantine**. Without the ability to select proposers, consensus cannot proceed at all.

The impact qualifies as Critical per Aptos Bug Bounty criteria: "Total loss of liveness/network availability" and "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation

**Medium to High Likelihood** - While an empty validator set seems unlikely under normal operations, several realistic scenarios could trigger it:

1. **Governance Attack**: A malicious governance proposal raises `minimum_stake` above all current validators' stakes. On the next epoch, all validators are filtered out.

2. **Mass Validator Exit**: If all validators voluntarily leave simultaneously (coordinated or coincidental), the next epoch begins with zero validators.

3. **Stake Slashing Bug**: A bug in staking rewards/penalties could reduce all validators below the minimum threshold.

4. **Configuration Error**: During network upgrades, a misconfiguration could temporarily result in no validators meeting the requirements.

The vulnerability is deterministically exploitable once the empty validator set condition is met - every node will panic when attempting proposer selection.

## Recommendation

Add explicit validation to prevent empty validator sets at multiple levels:

**Level 1 - Validator Set Validation (stake.move)**
```move
// In on_new_epoch(), after line 1401
assert!(
    vector::length(&next_epoch_validators) > 0,
    error::invalid_state(EEMPTY_VALIDATOR_SET)
);
validator_set.active_validators = next_epoch_validators;
```

**Level 2 - Proposer Election Defense (proposer_election.rs)**
```rust
pub(crate) fn choose_index(mut weights: Vec<u128>, state: Vec<u8>) -> usize {
    assert!(!weights.is_empty(), "Cannot choose from empty weights vector");
    let mut total_weight = 0;
    // ... rest of function
}
```

**Level 3 - LeaderReputation Constructor Validation (leader_reputation.rs)**
```rust
pub fn new(
    epoch: u64,
    epoch_to_proposers: HashMap<u64, Vec<Author>>,
    voting_powers: Vec<u64>,
    // ... other params
) -> Self {
    assert!(epoch_to_proposers.contains_key(&epoch));
    let proposers = &epoch_to_proposers[&epoch];
    assert!(!proposers.is_empty(), "Validator set cannot be empty");
    assert_eq!(proposers.len(), voting_powers.len());
    // ... rest of constructor
}
```

**Level 4 - Staking Config Validation (staking_config.move)**
```move
// Add to StakingConfig
min_validators_required: u64,  // e.g., 4 for BFT safety with f=1

// Validate in on_new_epoch()
assert!(
    vector::length(&next_epoch_validators) >= config.min_validators_required,
    error::invalid_state(EINSUFFICIENT_VALIDATORS)
);
```

## Proof of Concept

```rust
// Test demonstrating panic with empty weights
#[test]
#[should_panic(expected = "attempt to calculate the remainder with a divisor of zero")]
fn test_choose_index_empty_weights_panics() {
    use consensus::liveness::proposer_election::choose_index;
    
    let empty_weights: Vec<u128> = vec![];
    let state = vec![1, 2, 3, 4]; // arbitrary seed
    
    // This will panic with division by zero
    let _ = choose_index(empty_weights, state);
}

// Scenario test: Empty validator set after epoch transition
#[test]
fn test_empty_validator_set_scenario() {
    // 1. Create epoch state with validators
    // 2. Set minimum_stake above all validators' stakes
    // 3. Trigger on_new_epoch()
    // 4. Observe all validators filtered out
    // 5. Attempt to call get_valid_proposer()
    // 6. Witness panic in choose_index()
    
    // Pseudocode - actual implementation would require full consensus setup
    assert!(validator_set.active_validators.is_empty());
    
    // This call chain leads to panic:
    // proposer_election.get_valid_proposer(round)
    //   -> LeaderReputation::get_valid_proposer_and_voting_power_participation_ratio()
    //     -> choose_index(empty_stake_weights, state)
    //       -> next_in_range(state, 0)
    //         -> hash % 0  // PANIC!
}
```

**Notes**

This vulnerability represents a catastrophic failure mode where the consensus layer lacks defensive validation against edge cases in the staking system. The assumption that validator sets are always non-empty is violated by the code itself, which explicitly supports empty `EpochState` and `ValidatorVerifier` instances. The lack of cross-layer validation between the Move staking framework and the Rust consensus implementation creates this critical gap.

The fix requires defense-in-depth: preventing empty validator sets at the source (Move staking), validating at the boundary (epoch manager), and defensive programming in the affected function (choose_index). All four recommended validation levels should be implemented to ensure network resilience.

### Citations

**File:** consensus/src/liveness/proposer_election.rs (L39-46)
```rust
fn next_in_range(state: Vec<u8>, max: u128) -> u128 {
    // hash = SHA-3-256(state)
    let hash = aptos_crypto::HashValue::sha3_256_of(&state).to_vec();
    let mut temp = [0u8; 16];
    copy_slice_to_vec(&hash[..16], &mut temp).expect("next failed");
    // return hash[0..16]
    u128::from_le_bytes(temp) % max
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

**File:** consensus/src/liveness/leader_reputation.rs (L569-592)
```rust
    pub fn new(
        epoch: u64,
        epoch_to_proposers: HashMap<u64, Vec<Author>>,
        voting_powers: Vec<u64>,
        backend: Arc<dyn MetadataBackend>,
        heuristic: Box<dyn ReputationHeuristic>,
        exclude_round: u64,
        use_root_hash: bool,
        window_for_chain_health: usize,
    ) -> Self {
        assert!(epoch_to_proposers.contains_key(&epoch));
        assert_eq!(epoch_to_proposers[&epoch].len(), voting_powers.len());

        Self {
            epoch,
            epoch_to_proposers,
            voting_powers,
            backend,
            heuristic,
            exclude_round,
            use_root_hash,
            window_for_chain_health,
        }
    }
```

**File:** consensus/src/liveness/leader_reputation.rs (L704-733)
```rust
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

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1372-1402)
```text
        let next_epoch_validators = vector::empty();
        let (minimum_stake, _) = staking_config::get_required_stake(&config);
        let vlen = vector::length(&validator_set.active_validators);
        let total_voting_power = 0;
        let i = 0;
        while ({
            spec {
                invariant spec_validators_are_initialized(next_epoch_validators);
                invariant i <= vlen;
            };
            i < vlen
        }) {
            let old_validator_info = vector::borrow_mut(&mut validator_set.active_validators, i);
            let pool_address = old_validator_info.addr;
            let validator_config = borrow_global<ValidatorConfig>(pool_address);
            let stake_pool = borrow_global<StakePool>(pool_address);
            let new_validator_info = generate_validator_info(pool_address, stake_pool, *validator_config);

            // A validator needs at least the min stake required to join the validator set.
            if (new_validator_info.voting_power >= minimum_stake) {
                spec {
                    assume total_voting_power + new_validator_info.voting_power <= MAX_U128;
                };
                total_voting_power = total_voting_power + (new_validator_info.voting_power as u128);
                vector::push_back(&mut next_epoch_validators, new_validator_info);
            };
            i = i + 1;
        };

        validator_set.active_validators = next_epoch_validators;
        validator_set.total_voting_power = total_voting_power;
```

**File:** types/src/epoch_state.rs (L32-37)
```rust
    pub fn empty() -> Self {
        Self {
            epoch: 0,
            verifier: Arc::new(ValidatorVerifier::new(vec![])),
        }
    }
```

**File:** types/src/validator_verifier.rs (L206-214)
```rust
    pub fn new(validator_infos: Vec<ValidatorConsensusInfo>) -> Self {
        let total_voting_power = sum_voting_power(&validator_infos);
        let quorum_voting_power = if validator_infos.is_empty() {
            0
        } else {
            total_voting_power * 2 / 3 + 1
        };
        Self::build_index(validator_infos, quorum_voting_power, total_voting_power)
    }
```
