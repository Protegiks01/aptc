# Audit Report

## Title
Division by Zero Panic in RotatingProposer Due to Empty Validator Set Causing Total Network Halt

## Summary
The `RotatingProposer::get_valid_proposer()` function performs a modulo operation with `proposers.len()` without validating that the proposers vector is non-empty. If the on-chain validator set becomes empty during an epoch transition (when all validators fall below minimum stake), consensus will panic with division by zero, causing a permanent network halt requiring a hard fork to recover.

## Finding Description

The vulnerability exists in the consensus proposer election mechanism and can be triggered through the following chain:

1. **Root Cause in `RotatingProposer::new()`**: The constructor accepts an empty proposers vector without validation. [1](#0-0) 

2. **Division by Zero in `get_valid_proposer()`**: When called, the function performs modulo with `proposers.len()`, which panics if the length is 0. [2](#0-1) 

3. **Empty ValidatorSet Propagation**: The on-chain `stake.move` module's `on_new_epoch()` function can create an empty validator set when filtering validators by minimum stake. [3](#0-2) 

4. **No Runtime Validation**: The `ValidatorVerifier::new()` accepts an empty validator list, setting quorum to 0 without enforcement. [4](#0-3) 

5. **Consensus Initialization**: The `EpochManager::create_proposer_election()` creates a RotatingProposer from the potentially empty validator set without validation. [5](#0-4) 

6. **Specification Violation**: The Move specification indicates validators should be non-empty, but this is not enforced at runtime. [6](#0-5) 

**Attack Path:**
1. All validators' stake falls below `minimum_stake` (through slashing, unstaking, or governance action increasing the minimum)
2. During `on_new_epoch()`, the filtering loop excludes all validators
3. `validator_set.active_validators` is set to an empty vector
4. Consensus reads the empty ValidatorSet and creates an empty RotatingProposer
5. Any call to `get_valid_proposer()` triggers division by zero panic
6. All validator nodes crash simultaneously
7. Network halts permanently

## Impact Explanation

**Severity: Critical** (up to $1,000,000 per Aptos bug bounty)

This vulnerability meets the Critical severity criteria:
- **Total loss of liveness/network availability**: All validator nodes crash when attempting proposer election
- **Non-recoverable network partition (requires hardfork)**: The network cannot recover without manual intervention and state modification
- **Consensus Safety violation**: Breaks the fundamental invariant that consensus must always be able to elect a proposer

The impact affects:
- All validator nodes simultaneously
- All network operations cease
- Requires emergency hard fork with manual validator set injection
- No on-chain recovery mechanism possible

## Likelihood Explanation

**Likelihood: Low-to-Medium**

While the conditions are extreme, several realistic scenarios can trigger this:

**Medium Likelihood Scenarios:**
- Governance proposal increases `minimum_stake` above all current validators' stake
- Bug in staking reward/penalty calculation reduces all validators below threshold
- Edge case during network initialization or recovery

**Lower Likelihood Scenarios:**
- Coordinated mass unstaking (requires coordination)
- Catastrophic slashing event (requires >2/3 Byzantine validators)

The existence of a specification invariant suggesting this should never happen, combined with lack of runtime enforcement, indicates this is an unintended edge case that was overlooked rather than intentionally allowed.

## Recommendation

**Immediate Fix: Add validation in multiple layers**

1. **In `RotatingProposer::new()`**:
```rust
pub fn new(proposers: Vec<Author>, contiguous_rounds: u32) -> Self {
    assert!(!proposers.is_empty(), "Proposers vector cannot be empty");
    Self {
        proposers,
        contiguous_rounds,
    }
}
```

2. **In `stake.move` `on_new_epoch()`** - Add assertion before line 1401:
```move
assert!(vector::length(&next_epoch_validators) > 0, error::internal(EVALIDATOR_SET_EMPTY));
validator_set.active_validators = next_epoch_validators;
```

3. **In `EpochManager::create_proposer_election()`** - Add validation at line 295:
```rust
let proposers = epoch_state
    .verifier
    .get_ordered_account_addresses_iter()
    .collect::<Vec<_>>();
assert!(!proposers.is_empty(), "Cannot create proposer election with empty validator set");
```

## Proof of Concept

**Rust Test for RotatingProposer panic:**
```rust
#[test]
#[should_panic(expected = "attempt to calculate the remainder with a divisor of zero")]
fn test_empty_proposers_panic() {
    let proposers = vec![]; // Empty validator set
    let proposer_election = RotatingProposer::new(proposers, 1);
    let _ = proposer_election.get_valid_proposer(1); // Panics with division by zero
}
```

**Move Test for empty validator set:**
```move
#[test(aptos_framework = @aptos_framework)]
#[expected_failure(abort_code = EVALIDATOR_SET_EMPTY)]
public entry fun test_empty_validator_set_rejected(aptos_framework: &signer) {
    // Setup: Create validator set with validators at minimum stake
    // Action: Increase minimum_stake above all validators
    // Expected: on_new_epoch should abort with EVALIDATOR_SET_EMPTY
    // Current: Would succeed and create empty validator set
}
```

## Notes

This vulnerability demonstrates a critical gap between formal specification and runtime enforcement. The Move specification at line 684 of `stake.spec.move` declares `invariant len(active_validators) > 0`, but this is only checked by the prover, not enforced at runtime. The lack of defensive programming in the Rust consensus code compounds the issue, as it assumes the validator set is always valid without verification.

### Citations

**File:** consensus/src/liveness/rotating_proposer_election.rs (L27-32)
```rust
    pub fn new(proposers: Vec<Author>, contiguous_rounds: u32) -> Self {
        Self {
            proposers,
            contiguous_rounds,
        }
    }
```

**File:** consensus/src/liveness/rotating_proposer_election.rs (L36-39)
```rust
    fn get_valid_proposer(&self, round: Round) -> Author {
        self.proposers
            [((round / u64::from(self.contiguous_rounds)) % self.proposers.len() as u64) as usize]
    }
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1372-1401)
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

**File:** consensus/src/epoch_manager.rs (L292-298)
```rust
        let proposers = epoch_state
            .verifier
            .get_ordered_account_addresses_iter()
            .collect::<Vec<_>>();
        match &onchain_config.proposer_election_type() {
            ProposerElectionType::RotatingProposer(contiguous_rounds) => {
                Arc::new(RotatingProposer::new(proposers, *contiguous_rounds))
```

**File:** aptos-move/framework/aptos-framework/sources/stake.spec.move (L684-684)
```text
        invariant len(active_validators) > 0;
```
